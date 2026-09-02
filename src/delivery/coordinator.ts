import { SanitizedGitHubReadError, type SanitizedGitHubReadErrorKind } from './github-read.js';
import { validateWorkIdentity, type WorkIdentity } from './contract.js';

const MAX_ATTEMPTS = 3;
const MAX_ELAPSED_MILLISECONDS = 60_000;
const BACKOFFS = Object.freeze([250, 1_000]);

export interface WorkControl {
  isCancelled(): boolean;
  checkpoint(): 'continue' | 'cancelled';
}

export type CoordinatedWorkResult<T> =
  | { status: 'current'; value: T }
  | { status: 'superseded' | 'cancelled' | 'runtime-infrastructure-failure' };

interface ActiveWork<T> {
  identity: WorkIdentity;
  key: string;
  pullKey: string;
  cancelled: boolean;
  cancellation: 'cancelled' | 'superseded' | null;
  promise: Promise<CoordinatedWorkResult<T>>;
}

export interface BoundedReadOptions {
  now?: () => number;
  sleep?: (milliseconds: number) => Promise<void>;
  isCancelled?: () => boolean;
}

export type BoundedReadResult<T> =
  | { status: 'success'; value: T; attempts: number }
  | { status: 'cancelled'; attempts: number }
  | { status: 'not-retryable'; cause: SanitizedGitHubReadErrorKind; attempts: number }
  | { status: 'runtime-infrastructure-failure'; cause: 'transient-read-exhausted' | 'retry-budget-exhausted'; attempts: number };

function positive(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) > 0;
}

function elapsedMilliseconds(started: number, now: () => number): number | null {
  const current = now();
  const raw = current - started;
  if (!Number.isFinite(current) || !Number.isFinite(raw) || raw < 0 || raw > Number.MAX_SAFE_INTEGER) return null;
  return Math.floor(raw);
}

/** Stable key encoding has no delivery ID or mutable branch/ref input. */
export function createWorkKey(identity: WorkIdentity): string {
  validateWorkIdentity(identity);
  return JSON.stringify([identity.installationId, identity.repositoryId, identity.pullNumber, identity.baseSha, identity.headSha, identity.evaluatorIdentity]);
}

function pullKey(identity: WorkIdentity): string {
  return `${identity.installationId}:${identity.repositoryId}:${identity.pullNumber}`;
}

/** In-memory-only latest-wins coordination; restart state is intentionally empty. */
export class DeliveryCoordinator {
  private readonly activeByWork = new Map<string, ActiveWork<unknown>>();
  private readonly latestByPull = new Map<string, ActiveWork<unknown>>();

  submit<T>(identity: WorkIdentity, run: (control: WorkControl) => Promise<T>): Promise<CoordinatedWorkResult<T>> {
    const key = createWorkKey(identity);
    const existing = this.activeByWork.get(key) as ActiveWork<T> | undefined;
    if (existing !== undefined) return existing.promise;

    const perPull = pullKey(identity);
    const previous = this.latestByPull.get(perPull);
    if (previous !== undefined && previous.key !== key) {
      previous.cancelled = true;
      previous.cancellation = 'superseded';
    }

    const active: ActiveWork<T> = {
      identity: Object.freeze({ ...identity }), key, pullKey: perPull, cancelled: false, cancellation: null,
      promise: Promise.resolve({ status: 'cancelled' }) as Promise<CoordinatedWorkResult<T>>,
    };
    const control: WorkControl = Object.freeze({
      isCancelled: () => active.cancelled,
      checkpoint: () => active.cancelled ? 'cancelled' : 'continue',
    });
    active.promise = Promise.resolve()
      .then(async () => run(control))
      .then((value) => this.finish(active, value))
      .catch(() => this.finish(active, undefined as T, true));
    this.activeByWork.set(key, active as ActiveWork<unknown>);
    this.latestByPull.set(perPull, active as ActiveWork<unknown>);
    return active.promise;
  }

  cancel(identity: WorkIdentity): boolean {
    const active = this.activeByWork.get(createWorkKey(identity));
    if (active === undefined) return false;
    active.cancelled = true;
    active.cancellation = 'cancelled';
    return true;
  }

  snapshot(): { active: number; pending: 0; recovered: 0; delivered: 0 } {
    return Object.freeze({ active: this.activeByWork.size, pending: 0, recovered: 0, delivered: 0 });
  }

  private finish<T>(active: ActiveWork<T>, value: T, failed = false): CoordinatedWorkResult<T> {
    this.activeByWork.delete(active.key);
    if (this.latestByPull.get(active.pullKey) === active) this.latestByPull.delete(active.pullKey);
    if (active.cancellation === 'superseded' || this.latestByPull.has(active.pullKey)) return Object.freeze({ status: 'superseded' });
    if (active.cancellation === 'cancelled') return Object.freeze({ status: 'cancelled' });
    if (failed) return Object.freeze({ status: 'runtime-infrastructure-failure' });
    return Object.freeze({ status: 'current', value });
  }
}

function retryable(error: SanitizedGitHubReadError): boolean {
  return error.retryable && ['transient-transport', 'transient-service', 'rate-limited'].includes(error.kind);
}

/** Runs only an already-authorized idempotent read with one finite per-work retry budget. */
export async function runBoundedRead<T>(read: () => Promise<T>, options: BoundedReadOptions = {}): Promise<BoundedReadResult<T>> {
  const now = options.now ?? (() => performance.now());
  const sleep = options.sleep ?? (async (milliseconds: number) => new Promise<void>((resolve) => setTimeout(resolve, milliseconds)));
  const started = now();
  if (!Number.isFinite(started)) return Object.freeze({ status: 'runtime-infrastructure-failure', cause: 'retry-budget-exhausted', attempts: 0 });
  let attempts = 0;
  while (attempts < MAX_ATTEMPTS) {
    if (options.isCancelled?.()) return Object.freeze({ status: 'cancelled', attempts });
    const elapsed = elapsedMilliseconds(started, now);
    if (elapsed === null || elapsed > MAX_ELAPSED_MILLISECONDS) return Object.freeze({ status: 'runtime-infrastructure-failure', cause: 'retry-budget-exhausted', attempts });
    attempts += 1;
    try {
      return Object.freeze({ status: 'success', value: await read(), attempts });
    } catch (error) {
      const sanitized = error instanceof SanitizedGitHubReadError ? error : new SanitizedGitHubReadError('contract-invalid', false);
      if (!retryable(sanitized)) return Object.freeze({ status: 'not-retryable', cause: sanitized.kind, attempts });
      if (attempts === MAX_ATTEMPTS) return Object.freeze({ status: 'runtime-infrastructure-failure', cause: 'transient-read-exhausted', attempts });
      if (options.isCancelled?.()) return Object.freeze({ status: 'cancelled', attempts });
      const beforeSleep = elapsedMilliseconds(started, now);
      if (beforeSleep === null || beforeSleep >= MAX_ELAPSED_MILLISECONDS) return Object.freeze({ status: 'runtime-infrastructure-failure', cause: 'retry-budget-exhausted', attempts });
      const remaining = MAX_ELAPSED_MILLISECONDS - beforeSleep;
      const localBackoff = BACKOFFS[attempts - 1];
      if (localBackoff === undefined) {
        return Object.freeze({ status: 'runtime-infrastructure-failure', cause: 'retry-budget-exhausted', attempts });
      }
      const requested = sanitized.retryAfterMilliseconds ?? localBackoff;
      const delay = Math.min(requested, remaining);
      if (!positive(delay)) return Object.freeze({ status: 'runtime-infrastructure-failure', cause: 'retry-budget-exhausted', attempts });
      await sleep(delay);
    }
  }
  return Object.freeze({ status: 'runtime-infrastructure-failure', cause: 'transient-read-exhausted', attempts });
}
