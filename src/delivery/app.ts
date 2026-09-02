import { Probot } from 'probot';

import type { GitHubReadCapability } from './github-read.js';
import { normalizeVerifiedTrigger, REGISTERED_EVENTS, resolveTriggerWork, type TriggerResolution } from './trigger.js';

const SILENT_PROBOT_LOGGER = {
  child: () => SILENT_PROBOT_LOGGER,
  trace: () => undefined,
  debug: () => undefined,
  info: () => undefined,
  warn: () => undefined,
  error: () => undefined,
  fatal: () => undefined,
} as never;

export interface CreateBoundaryCiAppOptions {
  appId: number;
  privateKey: string;
  webhookSecret: string;
  createReadCapability(identity: { installationId: number; repositoryId: number }): Promise<GitHubReadCapability>;
  onResolvedTrigger?(result: TriggerResolution): void | Promise<void>;
}

/**
 * The sole transport entrypoint. Probot verifies original webhook bytes before these handlers
 * run; this module retains only normalized IDs and never passes `context.octokit` downstream.
 */
export function createBoundaryCiApp(options: CreateBoundaryCiAppOptions): Probot {
  const app = new Probot({
    appId: options.appId,
    privateKey: options.privateKey,
    secret: options.webhookSecret,
    webhookPath: '/api/github/webhooks',
    log: SILENT_PROBOT_LOGGER,
  });
  const handle = async (event: 'pull_request' | 'push', context: { payload: unknown; id: unknown }): Promise<void> => {
    const trigger = normalizeVerifiedTrigger(event, context.payload, context.id);
    if (trigger === null) return;
    let result: TriggerResolution;
    try {
      const read = await options.createReadCapability({ installationId: trigger.installationId, repositoryId: trigger.repositoryId });
      result = await resolveTriggerWork(trigger, read);
    } catch {
      result = Object.freeze({ status: 'trust-failure', reason: 'trigger-read-failed' });
    }
    await options.onResolvedTrigger?.(result);
  };
  app.on('pull_request.opened', async (context) => handle('pull_request', context));
  app.on('pull_request.synchronize', async (context) => handle('pull_request', context));
  app.on('pull_request.reopened', async (context) => handle('pull_request', context));
  app.on('pull_request.edited', async (context) => handle('pull_request', context));
  app.on('push', async (context) => handle('push', context));
  void REGISTERED_EVENTS;
  return app;
}
