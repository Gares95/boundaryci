import { createHmac } from 'node:crypto';
import { createServer } from 'node:http';
import { lstat, readdir } from 'node:fs/promises';

import type { Probot } from 'probot';

import type { CurrentPull, GitBlob, GitCommit, GitHubReadCapability, GitTree } from '../../src/delivery/index.js';
import { blob, commit, currentPull, tree } from './fixtures/index.js';

export interface ReadFakeOptions {
  currentPull?: (pullNumber: number, call: number) => Promise<CurrentPull> | CurrentPull;
  list?: (baseRef: string, page: number) => Promise<{ pulls: readonly CurrentPull[]; nextPage: number | null; normalizedBytes: number }> | { pulls: readonly CurrentPull[]; nextPage: number | null; normalizedBytes: number };
  commit?: (sha: string) => Promise<GitCommit> | GitCommit;
  tree?: (sha: string) => Promise<GitTree> | GitTree;
  blob?: (sha: string) => Promise<GitBlob> | GitBlob;
  onCall?: (name: string) => void | Promise<void>;
}

export interface ProgrammableReadFake {
  capability: GitHubReadCapability;
  calls: readonly string[];
}

/**
 * A finite read-only GitHub fake. It has no generic request or write method, records order, and
 * offers one cancellation hook before each supported read for later coordinator tests.
 */
export function createGitHubReadFake(options: ReadFakeOptions = {}): ProgrammableReadFake {
  const calls: string[] = [];
  let pullReads = 0;
  const record = async (name: string): Promise<void> => {
    calls.push(name);
    await options.onCall?.(name);
  };
  const capability: GitHubReadCapability = {
    async getCurrentPull(pullNumber) {
      await record(`pull:${pullNumber}`);
      pullReads += 1;
      return options.currentPull?.(pullNumber, pullReads) ?? currentPull({ number: pullNumber });
    },
    async listOpenPullsByBase(baseRef, page) {
      await record(`list:${baseRef}:${page}`);
      const value = await options.list?.(baseRef, page) ?? { pulls: Object.freeze([]), nextPage: null, normalizedBytes: 0 };
      return Object.freeze(value);
    },
    async getCommit(sha) {
      await record(`commit:${sha}`);
      return options.commit?.(sha) ?? commit(sha);
    },
    async getTree(sha) {
      await record(`tree:${sha}`);
      return options.tree?.(sha) ?? tree(sha);
    },
    async getBlob(sha) {
      await record(`blob:${sha}`);
      return options.blob?.(sha) ?? blob(sha);
    },
  };
  return Object.freeze({ capability, calls });
}

export interface WebhookHarness {
  url: string;
  close(): Promise<void>;
}

/** Mounts Probot's actual verified Node middleware; callers supply original bytes and headers. */
export async function createWebhookHarness(app: Probot): Promise<WebhookHarness> {
  const middleware = await app.getNodeMiddleware({ path: '/api/github/webhooks' });
  const server = createServer((request, response) => {
    void middleware(request, response, () => {
      response.statusCode = 404;
      response.end();
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (address === null || typeof address === 'string') throw new Error('delivery test server did not bind a TCP address');
  return Object.freeze({
    url: `http://127.0.0.1:${address.port}/api/github/webhooks`,
    close: async () => new Promise<void>((resolve) => server.close(() => resolve())),
  });
}

export interface SafeEvent {
  stage: 'transport' | 'read' | 'evaluate' | 'cleanup';
  outcome: 'accepted' | 'rejected' | 'complete' | 'incomplete';
  repositoryId: number;
  pullNumber: number;
}

/** An exact-field test sink; a generic metadata object cannot be sent through it. */
export class AllowlistedSink {
  readonly events: SafeEvent[] = [];

  emit(event: SafeEvent): void {
    const keys = Object.keys(event).sort();
    if (keys.join(',') !== 'outcome,pullNumber,repositoryId,stage') throw new TypeError('unsafe delivery event shape');
    if (!Number.isSafeInteger(event.repositoryId) || !Number.isSafeInteger(event.pullNumber)) {
      throw new TypeError('unsafe delivery event identity');
    }
    this.events.push(Object.freeze({ ...event }));
  }
}

export interface TemporaryEntry {
  path: string;
  kind: 'directory' | 'file' | 'symlink' | 'other';
  mode: number;
}

/** Enumerates only lstat-visible entries and never traverses a symbolic link. */
export async function inspectTemporaryParent(parent: string): Promise<readonly TemporaryEntry[]> {
  const entries: TemporaryEntry[] = [];
  const visit = async (directory: string, relativePath: string): Promise<void> => {
    for (const name of (await readdir(directory)).sort()) {
      const path = `${directory}/${name}`;
      const display = relativePath === '' ? name : `${relativePath}/${name}`;
      const details = await lstat(path);
      const kind: TemporaryEntry['kind'] = details.isSymbolicLink()
        ? 'symlink'
        : details.isDirectory()
          ? 'directory'
          : details.isFile()
            ? 'file'
            : 'other';
      entries.push(Object.freeze({ path: display, kind, mode: details.mode & 0o777 }));
      if (kind === 'directory') await visit(path, display);
    }
  };
  await visit(parent, '');
  return Object.freeze(entries);
}

export function createRuntimeSentinels(): Readonly<Record<string, string>> {
  const seed = `${Date.now()}-${process.pid}`;
  return Object.freeze({
    webhookSecret: `runtime-webhook-${seed}`,
    appAuthentication: `runtime-app-auth-${seed}`,
    installationToken: `runtime-installation-${seed}`,
    authorizationHeader: `runtime-header-${seed}`,
    rawPayload: `runtime-payload-${seed}`,
    source: `runtime-source-${seed}`,
    config: `runtime-config-${seed}`,
    externalError: `runtime-external-error-${seed}`,
  });
}

/**
 * Produces case-labelled test-only values.  Callers deliberately keep these inputs separate
 * from the public observations they later scan, preventing a test from accidentally proving
 * only that its own injection fixture contains the expected value.
 */
export function createDeliveryCaseSentinels(caseId: string): Readonly<Record<string, string>> {
  if (!/^[a-z0-9-]+$/u.test(caseId)) throw new TypeError('unsafe lifecycle case identifier');
  const suffix = `${caseId}-${Date.now()}-${process.pid}`;
  return Object.freeze({
    webhookSecret: `lifecycle-webhook-${suffix}`,
    appAuthentication: `lifecycle-app-auth-${suffix}`,
    installationToken: `lifecycle-installation-${suffix}`,
    authorizationHeader: `lifecycle-header-${suffix}`,
    rawPayload: `lifecycle-payload-${suffix}`,
    source: `lifecycle-source-${suffix}`,
    config: `lifecycle-config-${suffix}`,
    externalError: `lifecycle-external-error-${suffix}`,
  });
}

/** Serializes only finite test observations; never pass injection fixtures to this helper. */
export function serializePublicDeliveryObservations(value: unknown): string {
  return JSON.stringify(value);
}

/** Signs the exact original JSON bytes supplied to Probot's real middleware. */
export function signOriginalWebhookBody(webhookSecret: string, body: string): string {
  return `sha256=${createHmac('sha256', webhookSecret).update(body).digest('hex')}`;
}
