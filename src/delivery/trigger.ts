import type { GitHubReadCapability } from './github-read.js';
import type { CurrentPull } from './index.js';

const SHA_PATTERN = /^[a-f0-9]{40}$/u;
const MAX_FANOUT_BYTES = 4_000_000;
const MAX_FANOUT_ELAPSED_MILLISECONDS = 10_000;
const MAX_FANOUT_PAGES = 10;
const MAX_FANOUT_PULLS = 500;
const MAX_PULLS_PER_PAGE = 100;

export const REGISTERED_EVENTS = Object.freeze([
  'pull_request.opened',
  'pull_request.synchronize',
  'pull_request.reopened',
  'pull_request.edited',
  'push',
] as const);

type PullRequestAction = 'opened' | 'synchronize' | 'reopened' | 'edited';

export type VerifiedTrigger =
  | {
      kind: 'pull-request';
      action: PullRequestAction;
      comparisonRelevantEdit: boolean;
      deliveryId: string;
      installationId: number;
      repositoryId: number;
      pullNumber: number;
    }
  | {
      kind: 'push';
      baseRef: string;
      deliveryId: string;
      installationId: number;
      repositoryId: number;
    };

export interface AuthenticatedComparisonIdentity {
  installationId: number;
  repositoryId: number;
  pullNumber: number;
  baseRef: string;
  baseSha: string;
  headSha: string;
}

export type TriggerResolution =
  | { status: 'work'; work: AuthenticatedComparisonIdentity }
  | { status: 'fanout-work'; work: readonly AuthenticatedComparisonIdentity[] }
  | { status: 'no-op'; reason: 'edited-without-base-target-change' | 'pull-request-obsolete' }
  | { status: 'diagnostic-only'; reason: 'unsupported-topology' }
  | { status: 'trust-failure'; reason: 'repository-topology-mismatch' | 'trigger-read-failed' }
  | {
      status: 'fanout-incomplete';
      retryable: true;
      cause: 'duplicate-pull-request' | 'elapsed-limit' | 'page-limit' | 'page-read-failed' | 'page-shape' | 'pull-request-limit' | 'response-bytes-limit';
      frontier: number | null;
    };

export interface TriggerResolutionOptions {
  now?: () => number;
}

function positiveInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0;
}

function safeSha(value: unknown): value is string {
  return typeof value === 'string' && SHA_PATTERN.test(value);
}

function safeRef(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 256 && !value.includes('\0');
}

function object(value: unknown): Record<string, unknown> | null {
  return typeof value === 'object' && value !== null && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

/**
 * Reduces a Probot-verified payload to trigger provenance only. The payload's branch, SHA,
 * repository topology, and state are deliberately not copied: authenticated read responses
 * establish the comparison identity later.
 */
export function normalizeVerifiedTrigger(event: string, payload: unknown, deliveryId: unknown): VerifiedTrigger | null {
  if (typeof event !== 'string' || typeof deliveryId !== 'string' || deliveryId.length === 0 || deliveryId.length > 256) return null;
  const record = object(payload);
  if (record === null) return null;
  const installation = object(record.installation);
  const repository = object(record.repository);
  if (!positiveInteger(installation?.id) || !positiveInteger(repository?.id)) return null;
  if (event === 'pull_request') {
    const pull = object(record.pull_request);
    const action = record.action;
    if (!positiveInteger(pull?.number) || (action !== 'opened' && action !== 'synchronize' && action !== 'reopened' && action !== 'edited')) return null;
    const changes = object(record.changes);
    return Object.freeze({
      kind: 'pull-request',
      action,
      comparisonRelevantEdit: action === 'edited' && object(changes?.base) !== null,
      deliveryId,
      installationId: installation.id,
      repositoryId: repository.id,
      pullNumber: pull.number,
    });
  }
  if (event === 'push' && typeof record.ref === 'string' && record.ref.startsWith('refs/heads/') && safeRef(record.ref.slice('refs/heads/'.length))) {
    return Object.freeze({
      kind: 'push',
      baseRef: record.ref.slice('refs/heads/'.length),
      deliveryId,
      installationId: installation.id,
      repositoryId: repository.id,
    });
  }
  return null;
}

function fromCurrentPull(trigger: Extract<VerifiedTrigger, { kind: 'pull-request' }>, pull: CurrentPull): TriggerResolution {
  if (pull.state !== 'open' || pull.merged) return Object.freeze({ status: 'no-op', reason: 'pull-request-obsolete' });
  if (pull.number !== trigger.pullNumber || pull.repositoryId !== trigger.repositoryId || pull.base.repositoryId !== trigger.repositoryId) {
    return Object.freeze({ status: 'trust-failure', reason: 'repository-topology-mismatch' });
  }
  if (pull.head.repositoryId !== trigger.repositoryId) return Object.freeze({ status: 'diagnostic-only', reason: 'unsupported-topology' });
  if (!safeRef(pull.base.ref) || !safeSha(pull.base.sha) || !safeSha(pull.head.sha)) {
    return Object.freeze({ status: 'trust-failure', reason: 'repository-topology-mismatch' });
  }
  return Object.freeze({
    status: 'work',
    work: Object.freeze({
      installationId: trigger.installationId,
      repositoryId: trigger.repositoryId,
      pullNumber: pull.number,
      baseRef: pull.base.ref,
      baseSha: pull.base.sha,
      headSha: pull.head.sha,
    }),
  });
}

function fanoutIncomplete(
  cause: Extract<TriggerResolution, { status: 'fanout-incomplete' }>['cause'],
  frontier: number | null,
): TriggerResolution {
  return Object.freeze({ status: 'fanout-incomplete', retryable: true, cause, frontier });
}

async function resolvePushFanout(
  trigger: Extract<VerifiedTrigger, { kind: 'push' }>,
  read: GitHubReadCapability,
  now: () => number,
): Promise<TriggerResolution> {
  const started = now();
  if (!Number.isFinite(started)) return fanoutIncomplete('elapsed-limit', null);
  const pulls = new Map<number, AuthenticatedComparisonIdentity>();
  let consumedBytes = 0;
  let page = 1;
  for (let requests = 0; requests < MAX_FANOUT_PAGES; requests += 1) {
    const elapsed = now() - started;
    if (!Number.isFinite(elapsed) || elapsed < 0 || elapsed > MAX_FANOUT_ELAPSED_MILLISECONDS) return fanoutIncomplete('elapsed-limit', page);
    let result;
    try {
      result = await read.listOpenPullsByBase(trigger.baseRef, page);
    } catch {
      return fanoutIncomplete('page-read-failed', page);
    }
    const elapsedAfterRequest = now() - started;
    if (!Number.isFinite(elapsedAfterRequest) || elapsedAfterRequest < 0 || elapsedAfterRequest > MAX_FANOUT_ELAPSED_MILLISECONDS) {
      return fanoutIncomplete('elapsed-limit', page);
    }
    if (result.pulls.length > MAX_PULLS_PER_PAGE || !Number.isSafeInteger(result.normalizedBytes) || result.normalizedBytes < 0) {
      return fanoutIncomplete('page-shape', page);
    }
    consumedBytes += result.normalizedBytes;
    if (!Number.isSafeInteger(consumedBytes) || consumedBytes > MAX_FANOUT_BYTES) return fanoutIncomplete('response-bytes-limit', page);
    for (const pull of result.pulls) {
      if (pull.repositoryId !== trigger.repositoryId || pull.base.repositoryId !== trigger.repositoryId || pull.base.ref !== trigger.baseRef ||
        pull.head.repositoryId !== trigger.repositoryId || pull.state !== 'open' || pull.merged || !safeSha(pull.base.sha) || !safeSha(pull.head.sha)) {
        return fanoutIncomplete('page-shape', page);
      }
      const work = Object.freeze({
        installationId: trigger.installationId,
        repositoryId: trigger.repositoryId,
        pullNumber: pull.number,
        baseRef: pull.base.ref,
        baseSha: pull.base.sha,
        headSha: pull.head.sha,
      });
      const previous = pulls.get(work.pullNumber);
      if (previous !== undefined) {
        if (previous.baseSha !== work.baseSha || previous.headSha !== work.headSha || previous.baseRef !== work.baseRef) {
          return fanoutIncomplete('duplicate-pull-request', page);
        }
        return fanoutIncomplete('duplicate-pull-request', page);
      }
      pulls.set(work.pullNumber, work);
      if (pulls.size > MAX_FANOUT_PULLS) return fanoutIncomplete('pull-request-limit', page);
    }
    if (result.nextPage === null) {
      return Object.freeze({ status: 'fanout-work', work: Object.freeze([...pulls.values()].sort((left, right) => left.pullNumber - right.pullNumber)) });
    }
    if (result.nextPage !== page + 1 || requests + 1 >= MAX_FANOUT_PAGES) return fanoutIncomplete('page-limit', result.nextPage);
    page = result.nextPage;
  }
  return fanoutIncomplete('page-limit', page);
}

/** Resolves an already-verified trigger to current PR work; it does not schedule or acquire it. */
export async function resolveTriggerWork(
  trigger: VerifiedTrigger,
  read: GitHubReadCapability,
  options: TriggerResolutionOptions = {},
): Promise<TriggerResolution> {
  if (trigger.kind === 'push') return resolvePushFanout(trigger, read, options.now ?? (() => performance.now()));
  if (trigger.action === 'edited' && !trigger.comparisonRelevantEdit) {
    return Object.freeze({ status: 'no-op', reason: 'edited-without-base-target-change' });
  }
  try {
    return fromCurrentPull(trigger, await read.getCurrentPull(trigger.pullNumber));
  } catch {
    return Object.freeze({ status: 'trust-failure', reason: 'trigger-read-failed' });
  }
}
