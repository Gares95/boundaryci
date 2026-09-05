import { Probot } from 'probot';

import type { DeliveryEnvelopeV1, WorkIdentity } from './contract.js';
import { DeliveryCoordinator } from './coordinator.js';
import { evaluateCurrentComparison, type LocalComparisonEvaluator } from './evaluate.js';
import type { GitHubReadCapability } from './github-read.js';
import { emitDeliveryEvent, type DeliveryLogSink } from './logging.js';
import { acquireComparisonRoots } from './snapshot.js';
import { normalizeVerifiedTrigger, REGISTERED_EVENTS, resolveTriggerWork, type AuthenticatedComparisonIdentity, type TriggerResolution } from './trigger.js';

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

export interface CreateBoundaryCiAppOptions {
  appId: number;
  privateKey: string;
  webhookSecret: string;
  createReadCapability(identity: { installationId: number; repositoryId: number }): Promise<GitHubReadCapability>;
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

async function scheduleComparison(
  comparison: AuthenticatedComparisonIdentity,
  deliveryId: string,
  read: GitHubReadCapability,
  options: CreateBoundaryCiAppOptions,
  coordinator: DeliveryCoordinator,
): Promise<void> {
  const work = workIdentity(comparison, options.evaluatorIdentity ?? DEFAULT_EVALUATOR_IDENTITY);
  const scheduled = await coordinator.submit(work, async (control) => evaluateCurrentComparison({
    work,
    baseRef: comparison.baseRef,
    triggerDeliveryIds: [deliveryId],
    acquire: async () => acquireComparisonRoots({
      capability: read,
      baseSha: comparison.baseSha,
      headSha: comparison.headSha,
      isCancelled: control.isCancelled,
    }),
    ...(options.evaluator === undefined ? {} : { evaluator: options.evaluator }),
    getCurrentPull: (pullNumber) => read.getCurrentPull(pullNumber),
  }));
  if (scheduled.status === 'current') await options.onEnvelope?.(scheduled.value);
}

async function scheduleResolution(
  result: TriggerResolution,
  deliveryId: string,
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
  }
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
  const handle = async (event: 'pull_request' | 'push', context: { payload: unknown; id: unknown }): Promise<void> => {
    const trigger = normalizeVerifiedTrigger(event, context.payload, context.id);
    if (trigger === null) return;
    log('accepted', 'verified-trigger', trigger);
    try {
      const read = await options.createReadCapability({ installationId: trigger.installationId, repositoryId: trigger.repositoryId });
      await scheduleResolution(await resolveTriggerWork(trigger, read), trigger.deliveryId, read, options, coordinator);
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
