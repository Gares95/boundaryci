import { generateKeyPairSync } from 'node:crypto';
import { access, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import type { BoundedReadOptions } from '../../src/delivery/coordinator.js';
import type { DeliveryEnvelopeV1, WorkIdentity } from '../../src/delivery/index.js';
import { currentPull, DELIVERY_FIXTURES } from './fixtures/index.js';
import {
  createDeliveryCaseSentinels,
  createGitHubReadFake,
  createWebhookHarness,
  inspectTemporaryParent,
  serializePublicDeliveryObservations,
  signOriginalWebhookBody,
  acquireDeliveryFetchScope,
} from './support.js';

const harnesses: Array<Awaited<ReturnType<typeof createWebhookHarness>>> = [];
const { baseSha, headSha, baseTreeSha, headTreeSha, baseBlobSha, headBlobSha } = DELIVERY_FIXTURES;
let releaseFetchScope: (() => void) | undefined;
let rowTemporaryBase: string | undefined;
const originalTemporaryEnvironment = {
  TMPDIR: process.env.TMPDIR,
  TEMP: process.env.TEMP,
  TMP: process.env.TMP,
};
const cleanupFault = { enabled: false };
const readSessionControl: { options: Partial<BoundedReadOptions> | undefined; sessions: number; fireDeadline: (() => void) | undefined } = { options: undefined, sessions: 0, fireDeadline: undefined };

beforeEach(async () => {
  releaseFetchScope = await acquireDeliveryFetchScope();
  rowTemporaryBase = await mkdtemp(join(tmpdir(), 'boundaryci-public-lifecycle-'));
});
afterEach(async () => {
  await Promise.all(harnesses.splice(0).map(async (harness) => harness.close()));
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  vi.doUnmock('../../src/delivery/snapshot.js');
  vi.doUnmock('../../src/delivery/coordinator.js');
  vi.resetModules();
  releaseFetchScope?.();
  releaseFetchScope = undefined;
  cleanupFault.enabled = false;
  readSessionControl.options = undefined;
  readSessionControl.sessions = 0;
  readSessionControl.fireDeadline = undefined;
  if (originalTemporaryEnvironment.TMPDIR === undefined) delete process.env.TMPDIR;
  else process.env.TMPDIR = originalTemporaryEnvironment.TMPDIR;
  if (originalTemporaryEnvironment.TEMP === undefined) delete process.env.TEMP;
  else process.env.TEMP = originalTemporaryEnvironment.TEMP;
  if (originalTemporaryEnvironment.TMP === undefined) delete process.env.TMP;
  else process.env.TMP = originalTemporaryEnvironment.TMP;
  if (rowTemporaryBase !== undefined) await rm(rowTemporaryBase, { force: true, recursive: true });
  rowTemporaryBase = undefined;
});

function privateKey(): string {
  return generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
}

function activateRowSnapshotParent(): void {
  process.env.TMPDIR = rowTemporaryBase;
  process.env.TEMP = rowTemporaryBase;
  process.env.TMP = rowTemporaryBase;
}

function pullBody(caseId: string, rawPayload: string): string {
  return JSON.stringify({
    boundaryci_test_ignored: rawPayload,
    action: 'opened',
    installation: { id: 42 },
    repository: { id: 7, name: 'target', owner: { login: 'owner' } },
    pull_request: { number: 19, base: { ref: 'main', sha: `event-base-${caseId}`, repo: { id: 7 } }, head: { sha: `event-head-${caseId}`, repo: { id: 7 } } },
  });
}

function pushBody(rawPayload: string): string {
  return JSON.stringify({ boundaryci_test_ignored: rawPayload, installation: { id: 42 }, repository: { id: 7, name: 'target', owner: { login: 'owner' } }, ref: 'refs/heads/main' });
}

function installFiniteHttpBoundary(read: ReturnType<typeof createGitHubReadFake>, token: string): { readonly authorizationHeaders: readonly string[] } {
  const nativeFetch = globalThis.fetch;
  const authorizationHeaders: string[] = [];
  const readOptions = (init?: RequestInit): { signal?: AbortSignal } => init?.signal === null || init?.signal === undefined ? {} : { signal: init.signal };
  const authorizationFrom = (headers: RequestInit['headers'] | undefined): string | null => {
    try {
      return new Headers(headers).get('authorization');
    } catch {
      return null;
    }
  };
  vi.stubGlobal('fetch', async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : input.toString());
    if (url.hostname === '127.0.0.1') return nativeFetch(input, init);
    const authorization = authorizationFrom(init?.headers);
    if (authorization !== null) authorizationHeaders.push(authorization);
    if (url.pathname === '/app/installations/42/access_tokens') {
      return new Response(JSON.stringify({ token, expires_at: '2099-01-01T00:00:00Z', permissions: {} }), { status: 201, headers: { 'content-type': 'application/json' } });
    }
    if (url.pathname === '/repos/owner/target/pulls') {
      const value = await read.capability.listOpenPullsByBase(url.searchParams.get('base') ?? '', Number(url.searchParams.get('page') ?? '1'), readOptions(init));
      return new Response(JSON.stringify(value.pulls.map((pull) => ({ number: pull.number, state: pull.state, draft: pull.draft, merged: pull.merged, base: { repo: { id: pull.base.repositoryId }, ref: pull.base.ref, sha: pull.base.sha }, head: { repo: { id: pull.head.repositoryId }, sha: pull.head.sha } }))), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    const pull = /^\/repos\/owner\/target\/pulls\/(\d+)$/u.exec(url.pathname);
    if (pull !== null) {
      try {
        const value = await read.capability.getCurrentPull(Number(pull[1]), readOptions(init));
        return new Response(JSON.stringify({ number: value.number, state: value.state, draft: value.draft, merged: value.merged, base: { repo: { id: value.base.repositoryId }, ref: value.base.ref, sha: value.base.sha }, head: { repo: { id: value.head.repositoryId }, sha: value.head.sha } }), { status: 200, headers: { 'content-type': 'application/json' } });
      } catch (error) {
        const record = error as { status?: unknown; body?: unknown };
        return new Response(JSON.stringify({ message: typeof record.body === 'string' ? record.body : 'sanitized-test-read-error' }), { status: typeof record.status === 'number' ? record.status : 503, headers: { 'content-type': 'application/json' } });
      }
    }
    const commit = /^\/repos\/owner\/target\/git\/commits\/([a-f0-9]{40})$/u.exec(url.pathname);
    if (commit !== null) {
      const value = await read.capability.getCommit(commit[1]!, readOptions(init));
      return new Response(JSON.stringify({ sha: value.sha, tree: { sha: value.treeSha } }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    const tree = /^\/repos\/owner\/target\/git\/trees\/([a-f0-9]{40})$/u.exec(url.pathname);
    if (tree !== null) {
      const value = await read.capability.getTree(tree[1]!, readOptions(init));
      return new Response(JSON.stringify({ sha: value.sha, tree: value.entries }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    const blob = /^\/repos\/owner\/target\/git\/blobs\/([a-f0-9]{40})$/u.exec(url.pathname);
    if (blob !== null) {
      const value = await read.capability.getBlob(blob[1]!, readOptions(init));
      return new Response(JSON.stringify(value), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    return new Response(JSON.stringify({ code: 'unexpected-route' }), { status: 404, headers: { 'content-type': 'application/json' } });
  });
  return Object.freeze({ authorizationHeaders });
}

const LIFECYCLE_ROWS = [
  'success', 'acquisition-failure', 'configuration-failure', 'evaluator-failure',
  'transient-exhaustion', 'elapsed-timeout', 'explicit-cancellation', 'newer-tuple-supersession',
  'stale-final-identity', 'cleanup-error', 'fanout-incomplete',
] as const;

function workIdentity(headShaValue = headSha): WorkIdentity {
  return { installationId: 42, repositoryId: 7, pullNumber: 19, baseSha, headSha: headShaValue, evaluatorIdentity: 'boundaryci-evaluator-v1' };
}

function accelerateKnownRetryDelays(): void {
  const nativeSetTimeout = globalThis.setTimeout;
  vi.spyOn(globalThis, 'setTimeout').mockImplementation(((callback: (...args: unknown[]) => void, delay?: number, ...args: unknown[]) => {
    const retryDelay = typeof delay === 'number' && delay >= 200 && delay <= 10_000;
    return nativeSetTimeout(callback, retryDelay ? 0 : delay, ...args);
  }) as typeof setTimeout);
}

async function loadDeliveryComposition(caseId: typeof LIFECYCLE_ROWS[number]): Promise<typeof import('../../src/delivery/index.js')> {
  vi.resetModules();
  if (caseId === 'cleanup-error') {
    vi.doMock('../../src/delivery/snapshot.js', async (importOriginal) => {
      const actual = await importOriginal<typeof import('../../src/delivery/snapshot.js')>();
      return {
        ...actual,
        cleanupComparisonRoots: async (...args: Parameters<typeof actual.cleanupComparisonRoots>) => {
          const cleaned = await actual.cleanupComparisonRoots(...args);
          return cleanupFault.enabled ? false : cleaned;
        },
      };
    });
  }
  if (caseId === 'elapsed-timeout' || caseId === 'transient-exhaustion') {
    vi.doMock('../../src/delivery/coordinator.js', async (importOriginal) => {
      const actual = await importOriginal<typeof import('../../src/delivery/coordinator.js')>();
      return {
        ...actual,
        createBoundedReadSession: (options: BoundedReadOptions = {}) => {
          readSessionControl.sessions += 1;
          return actual.createBoundedReadSession(readSessionControl.sessions === 2
            ? { ...options, ...readSessionControl.options }
            : options);
        },
      };
    });
  }
  return import('../../src/delivery/index.js');
}

describe.sequential('signed public delivery lifecycle matrix', () => {
  it.each(LIFECYCLE_ROWS)('contains case-distinct test sentinels at the composed public boundary: %s', async (caseId) => {
    const appPrivateKey = privateKey();
    const sentinels: Record<string, string> = {
      ...createDeliveryCaseSentinels(caseId),
      appAuthentication: appPrivateKey.slice(32, 80),
    };
    let pullReads = 0;
    const logs: unknown[] = [];
    cleanupFault.enabled = caseId === 'cleanup-error';
    if (caseId === 'elapsed-timeout') {
      readSessionControl.options = {
        setTimer: (callback) => {
          readSessionControl.fireDeadline = callback;
          return setTimeout(() => undefined, 60_000);
        },
      };
    } else if (caseId === 'transient-exhaustion') {
      readSessionControl.options = { sleep: async () => undefined };
      accelerateKnownRetryDelays();
    }
    const { createBoundaryCiApp, DeliveryCoordinator } = await loadDeliveryComposition(caseId);
    const coordinator = new DeliveryCoordinator();
    let blockedCommitOnce = false;
    let releaseBlockedCommit: (() => void) | undefined;
    let markBlockedCommit!: () => void;
    const blockedCommit = new Promise<void>((resolve) => { markBlockedCommit = resolve; });
    let markElapsedComparisonCommit!: () => void;
    const elapsedComparisonCommit = new Promise<void>((resolve) => { markElapsedComparisonCommit = resolve; });
    const sourceBytes = Buffer.from(`export const lifecycleCase = ${JSON.stringify(sentinels.source!)};\n`);
    const configBytes = Buffer.from(`invalid: [${sentinels.config!}\n`);
    const configBlobSha = '1'.repeat(40);
    const read = createGitHubReadFake({
      ...(caseId === 'fanout-incomplete'
        ? { list: () => ({ pulls: Object.freeze(Array.from({ length: 101 }, (_, index) => currentPull({ number: index + 1 }))), nextPage: null, normalizedBytes: 1 }) }
        : {}),
      currentPull: () => {
        pullReads += 1;
        if (pullReads === 1) activateRowSnapshotParent();
        if (caseId === 'transient-exhaustion' && pullReads > 1) {
          throw { status: 503, body: sentinels.externalError };
        }
        if (caseId === 'newer-tuple-supersession' && pullReads >= 2) {
          return currentPull({ head: { repositoryId: 7, sha: '8'.repeat(40) } });
        }
        return caseId === 'stale-final-identity' && pullReads > 1
          ? { number: 19, repositoryId: 7, state: 'open', draft: false, merged: false, base: { repositoryId: 7, ref: 'main', sha: baseSha }, head: { repositoryId: 7, sha: '9'.repeat(40) } }
          : currentPull();
      },
      ...(caseId === 'acquisition-failure'
        ? { tree: () => ({ sha: '0'.repeat(40), entries: [] }) as never }
        : {
            tree: (sha) => ({
              sha,
              entries: [
                { path: 'index.ts', mode: '100644', type: 'blob' as const, sha: sha === baseTreeSha ? baseBlobSha : headBlobSha, size: sourceBytes.byteLength },
                ...(caseId === 'configuration-failure' ? [{ path: '.boundaryci.yml', mode: '100644', type: 'blob' as const, sha: configBlobSha, size: configBytes.byteLength }] : []),
              ],
            }),
            blob: (sha) => ({
              sha,
              encoding: 'base64' as const,
              content: (sha === configBlobSha ? configBytes : sourceBytes).toString('base64'),
              size: (sha === configBlobSha ? configBytes : sourceBytes).byteLength,
            }),
          }),
      ...(caseId === 'elapsed-timeout' || caseId === 'explicit-cancellation' || caseId === 'newer-tuple-supersession'
        ? {
            commit: (_sha: string, readOptions?: { signal?: AbortSignal }) => new Promise((resolve, reject) => {
              if (caseId === 'elapsed-timeout') {
                markElapsedComparisonCommit();
                const abort = (): void => reject(readOptions?.signal?.reason ?? new Error('comparison deadline exceeded'));
                readOptions?.signal?.addEventListener('abort', abort, { once: true });
                return;
              }
              if (blockedCommitOnce) {
                resolve({ sha: _sha, treeSha: _sha === baseSha ? baseTreeSha : headTreeSha });
                return;
              }
              blockedCommitOnce = true;
              markBlockedCommit();
              const abort = (): void => reject(readOptions?.signal?.reason ?? new Error('comparison aborted'));
              readOptions?.signal?.addEventListener('abort', abort, { once: true });
              releaseBlockedCommit = () => resolve({ sha: _sha, treeSha: _sha === baseSha ? baseTreeSha : headTreeSha });
            }),
          }
        : {}),
    });
    const envelopes: DeliveryEnvelopeV1[] = [];
    const roots: string[] = [];
    const app = createBoundaryCiApp({
      appId: 1,
      privateKey: appPrivateKey,
      webhookSecret: sentinels.webhookSecret!,
      evaluator: async (baseRoot, headRoot) => {
        roots.push(baseRoot, headRoot);
        if (caseId === 'evaluator-failure') throw new Error(sentinels.externalError);
        return { status: 'input-configuration-failure', invalid: 'base', diagnostics: [] };
      },
      onEnvelope: (envelope) => { envelopes.push(envelope); },
      logSink: { emit: (event) => { logs.push(event); } },
      coordinator,
    });
    const http = installFiniteHttpBoundary(read, sentinels.installationToken!);
    const harness = await createWebhookHarness(app);
    harnesses.push(harness);
    const body = caseId === 'fanout-incomplete' ? pushBody(sentinels.rawPayload!) : pullBody(caseId, sentinels.rawPayload!);
    const responsePromise = fetch(harness.url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-github-event': caseId === 'fanout-incomplete' ? 'push' : 'pull_request',
        'x-github-delivery': `lifecycle-${caseId}`,
        'x-hub-signature-256': signOriginalWebhookBody(sentinels.webhookSecret!, body),
      },
      body,
    });
    if (caseId === 'elapsed-timeout') {
      await elapsedComparisonCommit;
      expect(readSessionControl.fireDeadline).toBeTypeOf('function');
      readSessionControl.fireDeadline!();
    }
    if (caseId === 'explicit-cancellation' || caseId === 'newer-tuple-supersession') {
      await blockedCommit;
      if (caseId === 'explicit-cancellation') {
        expect(coordinator.cancel(workIdentity())).toBe(true);
      } else {
        const nextBody = pullBody(`${caseId}-newer`, sentinels.rawPayload!);
        const nextResponse = await fetch(harness.url, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'x-github-event': 'pull_request',
            'x-github-delivery': `lifecycle-${caseId}-newer`,
            'x-hub-signature-256': signOriginalWebhookBody(sentinels.webhookSecret!, nextBody),
          },
          body: nextBody,
        });
        expect(nextResponse.status).toBe(200);
      }
    }
    const response = await responsePromise;
    expect(response.status).toBe(caseId === 'transient-exhaustion' ? 202 : 200);
    const responseText = await response.text();
    if (caseId === 'explicit-cancellation' || caseId === 'elapsed-timeout') {
      await expect.poll(() => coordinator.snapshot().active).toBe(0);
      if (caseId === 'explicit-cancellation') expect(envelopes).toEqual([]);
    } else {
      await expect.poll(() => envelopes.length + (read.calls.length > 0 ? 0 : -1)).toBeGreaterThan(0);
    }
    if (caseId === 'explicit-cancellation') {
      // The cancelled owner is suppressed before a Phase 5 handoff.
    } else if (caseId === 'elapsed-timeout') {
      expect(envelopes).toEqual([expect.objectContaining({ lifecycle: 'runtime-infrastructure-failure', handoff: 'none', reason: 'final-freshness-read-failed' })]);
    } else if (caseId === 'transient-exhaustion') {
      expect(envelopes).toEqual([expect.objectContaining({ lifecycle: 'runtime-infrastructure-failure', handoff: 'none', reason: 'final-freshness-read-failed' })]);
    } else if (caseId === 'fanout-incomplete') {
      expect(envelopes).toEqual([expect.objectContaining({ lifecycle: 'fanout-incomplete', handoff: 'none', reason: 'fanout-page-shape', work: null })]);
    } else if (caseId === 'stale-final-identity') {
      expect(envelopes).toEqual([expect.objectContaining({ lifecycle: 'stale', handoff: 'none', reason: 'authenticated-comparison-drift' })]);
    } else if (caseId === 'evaluator-failure') {
      expect(envelopes).toEqual([expect.objectContaining({ lifecycle: 'current', handoff: 'diagnostic-only', diagnostic: { code: 'evaluator-runtime-failure' } })]);
    } else if (caseId === 'acquisition-failure') {
      expect(envelopes).toEqual([expect.objectContaining({ lifecycle: 'current', handoff: 'diagnostic-only', diagnostic: { code: 'acquisition-runtime-failure' } })]);
    } else if (caseId === 'configuration-failure') {
      expect(envelopes).toEqual([expect.objectContaining({ lifecycle: 'current', handoff: 'diagnostic-only', diagnostic: { code: 'input-configuration-failure' } })]);
    } else if (caseId === 'cleanup-error') {
      expect(envelopes).toEqual([expect.objectContaining({ lifecycle: 'cleanup-failure', handoff: 'none', reason: 'private-root-cleanup-not-verified' })]);
    } else if (caseId === 'newer-tuple-supersession') {
      expect(envelopes).toEqual([expect.objectContaining({ lifecycle: 'current', handoff: 'publishable-semantic', work: expect.objectContaining({ headSha: '8'.repeat(40) }) })]);
      expect(coordinator.snapshot()).toEqual({ active: 0, pending: 0, recovered: 0, delivered: 0 });
    } else {
      expect(envelopes[0]).toMatchObject({ lifecycle: 'current', handoff: 'publishable-semantic' });
    }
    if (caseId === 'success') expect(read.calls).toEqual(['pull:19', `commit:${baseSha}`, `tree:${baseTreeSha}`, `commit:${headSha}`, `tree:${headTreeSha}`, `blob:${baseBlobSha}`, `blob:${headBlobSha}`, 'pull:19']);
    if (caseId === 'elapsed-timeout') {
      expect(read.calls).toContain('pull:19');
      expect(read.calls).toContain(`commit:${baseSha}`);
      expect(readSessionControl.sessions).toBe(2);
    }
    await expect.poll(() => coordinator.snapshot()).toEqual({ active: 0, pending: 0, recovered: 0, delivered: 0 });
    const installationAuthorization = http.authorizationHeaders.find((value) => value.includes(sentinels.installationToken!));
    expect(installationAuthorization).toBeTypeOf('string');
    sentinels.authorizationHeader = installationAuthorization!;
    const observations = serializePublicDeliveryObservations({ envelopes, logs, response: responseText, calls: read.calls });
    for (const sentinel of Object.values(sentinels)) expect(observations).not.toContain(sentinel);
    await Promise.all(roots.map(async (root) => expect(access(root)).rejects.toMatchObject({ code: 'ENOENT' })));
    const snapshotParent = join(rowTemporaryBase!, 'boundaryci-snapshot-v1');
    const retainedEntries = await inspectTemporaryParent(snapshotParent).catch((error: unknown) => {
      if (typeof error === 'object' && error !== null && (error as { code?: unknown }).code === 'ENOENT') return [];
      throw error;
    });
    expect(retainedEntries).toEqual([]);
  }, 20_000);
});
