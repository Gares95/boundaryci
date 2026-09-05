import { Probot } from 'probot';

import { validateDeliveryEnvelope, type DeliveryEnvelopeV1, type WorkIdentity } from './contract.js';
import { bindBoundedReadSession, createBoundedReadSession, DeliveryCoordinator } from './coordinator.js';
import { evaluateCurrentComparison, type LocalComparisonEvaluator } from './evaluate.js';
import { createProbotRepositoryReadCapability, type GitHubReadCapability } from './github-read.js';
import { emitDeliveryEvent, type DeliveryLogSink } from './logging.js';
import { acquireComparisonRoots } from './snapshot.js';
import { normalizeVerifiedTrigger, REGISTERED_EVENTS, resolveTriggerWork, type AuthenticatedComparisonIdentity, type TriggerResolution, type VerifiedTrigger } from './trigger.js';

const SILENT_PROBOT_LOGGER = {
  child: () => SILENT_PROBOT_LOGGER,
  trace: () => undefined,
  debug: () => undefined,
  info: () => undefined,
  warn: () => undefined,
  error: () => undefined,
  fatal: () => undefined,
} as never;

const DEFAULT_EVALUATOR_IDENTITY = 'boundaryci-evaluator-v1';
const GITHUB_ROUTE_SEGMENT = /^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/u;

export interface CreateBoundaryCiAppOptions {
  appId: number;
  privateKey: string;
  webhookSecret: string;
  evaluator?: LocalComparisonEvaluator;
  evaluatorIdentity?: string;
  coordinator?: DeliveryCoordinator;
  onEnvelope?(envelope: DeliveryEnvelopeV1): void | Promise<void>;
  logSink?: DeliveryLogSink;
}

function workIdentity(comparison: AuthenticatedComparisonIdentity, evaluatorIdentity: string): WorkIdentity {
  return Object.freeze({
    installationId: comparison.installationId,
    repositoryId: comparison.repositoryId,
    pullNumber: comparison.pullNumber,
    baseSha: comparison.baseSha,
    headSha: comparison.headSha,
    evaluatorIdentity,
  });
}

function verifiedRepositoryRoute(context: { repo(): { owner: unknown; repo: unknown } }): { owner: string; repo: string } | null {
  const route = context.repo();
  if (typeof route.owner !== 'string' || typeof route.repo !== 'string' ||
    !GITHUB_ROUTE_SEGMENT.test(route.owner) || !GITHUB_ROUTE_SEGMENT.test(route.repo)) return null;
  return Object.freeze({ owner: route.owner, repo: route.repo });
}

async function scheduleComparison(
  comparison: AuthenticatedComparisonIdentity,
  deliveryId: string,
  read: GitHubReadCapability,
  options: CreateBoundaryCiAppOptions,
  coordinator: DeliveryCoordinator,
): Promise<void> {
  const work = workIdentity(comparison, options.evaluatorIdentity ?? DEFAULT_EVALUATOR_IDENTITY);
  const scheduled = await coordinator.submit(work, async (control) => {
    // This session deliberately begins inside the coordinator run. Each comparison gets a
    // fresh cancellation-bound budget, including its final freshness read.
    const session = createBoundedReadSession({ isCancelled: control.isCancelled, signal: control.signal });
    const workRead = bindBoundedReadSession(read, session);
    try {
      return await evaluateCurrentComparison({
      work,
      baseRef: comparison.baseRef,
      triggerDeliveryIds: [deliveryId],
      acquire: async () => acquireComparisonRoots({
        capability: workRead,
        baseSha: comparison.baseSha,
        headSha: comparison.headSha,
        isCancelled: control.isCancelled,
      }),
      ...(options.evaluator === undefined ? {} : { evaluator: options.evaluator }),
      getCurrentPull: (pullNumber) => workRead.getCurrentPull(pullNumber),
      });
    } finally {
      session.close();
    }
  });
  if (scheduled.status === 'current') await options.onEnvelope?.(scheduled.value);
}

async function scheduleResolution(
  result: TriggerResolution,
  trigger: VerifiedTrigger,
  deliveryId: string,
  preWorkRead: GitHubReadCapability,
  read: GitHubReadCapability,
  options: CreateBoundaryCiAppOptions,
  coordinator: DeliveryCoordinator,
): Promise<void> {
  if (result.status === 'work') {
    await scheduleComparison(result.work, deliveryId, read, options, coordinator);
    return;
  }
  if (result.status === 'fanout-work') {
    await Promise.all(result.work.map(async (comparison) => scheduleComparison(comparison, deliveryId, read, options, coordinator)));
    return;
  }
  if (result.status === 'fanout-incomplete') {
    const envelope = Object.freeze({
      schemaVersion: 1 as const,
      lifecycle: 'fanout-incomplete' as const,
      handoff: 'none' as const,
      work: null,
      reason: `fanout-${result.cause}`,
    });
    validateDeliveryEnvelope(envelope);
    await options.onEnvelope?.(envelope);
    return;
  }
  if (result.status !== 'diagnostic-only' || trigger.kind !== 'pull-request') return;

  // ResolveTriggerWork already established a fork from authenticated state. Re-read immediately
  // before the handoff so this source-free diagnostic has the same current-identity discipline
  // as semantic results, without ever acquiring target bytes.
  const pull = await preWorkRead.getCurrentPull(trigger.pullNumber);
  if (pull.number !== trigger.pullNumber || pull.repositoryId !== trigger.repositoryId || pull.state !== 'open' || pull.merged ||
    pull.base.repositoryId !== trigger.repositoryId || pull.head.repositoryId === trigger.repositoryId ||
    typeof pull.base.ref !== 'string' || pull.base.ref.length === 0 || pull.base.ref.length > 256) return;
  const comparison: AuthenticatedComparisonIdentity = {
    installationId: trigger.installationId,
    repositoryId: trigger.repositoryId,
    pullNumber: trigger.pullNumber,
    baseRef: pull.base.ref,
    baseSha: pull.base.sha,
    headSha: pull.head.sha,
  };
  const work = workIdentity(comparison, options.evaluatorIdentity ?? DEFAULT_EVALUATOR_IDENTITY);
  const envelope = Object.freeze({
    schemaVersion: 1 as const,
    lifecycle: 'current' as const,
    handoff: 'diagnostic-only' as const,
    work,
    trigger: Object.freeze({ deliveryIds: Object.freeze([deliveryId]) }),
    diagnostic: Object.freeze({ code: 'unsupported-topology' as const }),
    phase6FreshnessRequired: true as const,
    phase6Match: Object.freeze({
      repositoryId: trigger.repositoryId,
      pullNumber: trigger.pullNumber,
      baseRepositoryId: trigger.repositoryId,
      baseRef: pull.base.ref,
      baseSha: pull.base.sha,
      headRepositoryId: pull.head.repositoryId,
      headSha: pull.head.sha,
      topology: 'unsupported-topology' as const,
      eligibility: 'open' as const,
    }),
  });
  validateDeliveryEnvelope(envelope);
  await options.onEnvelope?.(envelope);
}

/**
 * The one public Phase 5 transport and lifecycle entrypoint. Probot verifies original webhook
 * bytes before the handlers run. A verified event is only trigger provenance: every evaluation
 * is reconstructed from authenticated current state, acquired through immutable Git objects,
 * cleaned, freshness-checked, and returned as a delivery-neutral envelope. No Check write or
 * presentation decision occurs in this module.
 */
export function createBoundaryCiApp(options: CreateBoundaryCiAppOptions): Probot {
  const app = new Probot({
    appId: options.appId,
    privateKey: options.privateKey,
    secret: options.webhookSecret,
    webhookPath: '/api/github/webhooks',
    log: SILENT_PROBOT_LOGGER,
  });
  const coordinator = options.coordinator ?? new DeliveryCoordinator();
  const log = (
    outcome: 'accepted' | 'rejected',
    reason: 'verified-trigger' | 'invalid-trigger' | 'trigger-read-failed',
    trigger: { deliveryId: string; installationId: number; repositoryId: number; pullNumber?: number },
  ): void => {
    emitDeliveryEvent({
      stage: 'transport', outcome, reason,
      workId: `trigger:${trigger.installationId}:${trigger.repositoryId}:${trigger.pullNumber ?? 0}`,
      deliveryId: trigger.deliveryId,
      installationId: trigger.installationId,
      repositoryId: trigger.repositoryId,
      pullNumber: trigger.pullNumber ?? null,
      baseSha: null, headSha: null,
      count: 1, durationMilliseconds: 0, attempt: 0, delayMilliseconds: 0,
    }, options.logSink);
  };
  const handle = async (event: 'pull_request' | 'push', context: { payload: unknown; id: unknown; octokit: unknown; repo(): { owner: unknown; repo: unknown } }): Promise<void> => {
    const trigger = normalizeVerifiedTrigger(event, context.payload, context.id);
    if (trigger === null) return;
    log('accepted', 'verified-trigger', trigger);
    try {
      const route = verifiedRepositoryRoute(context);
      if (route === null) throw new TypeError('invalid verified repository route');
      const read = await createProbotRepositoryReadCapability(
        { installationId: trigger.installationId, repositoryId: trigger.repositoryId },
        context.octokit as Parameters<typeof createProbotRepositoryReadCapability>[1],
        route,
        options.logSink,
      );
      const session = createBoundedReadSession();
      const preWorkRead = bindBoundedReadSession(read, session);
      try {
        await scheduleResolution(await resolveTriggerWork(trigger, preWorkRead), trigger, trigger.deliveryId, preWorkRead, read, options, coordinator);
      } finally {
        session.close();
      }
    } catch {
      log('rejected', 'trigger-read-failed', trigger);
    }
  };
  app.on('pull_request.opened', async (context) => handle('pull_request', context));
  app.on('pull_request.synchronize', async (context) => handle('pull_request', context));
  app.on('pull_request.reopened', async (context) => handle('pull_request', context));
  app.on('pull_request.edited', async (context) => handle('pull_request', context));
  app.on('push', async (context) => handle('push', context));
  void REGISTERED_EVENTS;
  return app;
}
