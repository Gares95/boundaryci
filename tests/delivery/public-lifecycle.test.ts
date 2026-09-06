import { generateKeyPairSync } from 'node:crypto';
import { access } from 'node:fs/promises';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { createBoundaryCiApp, type DeliveryEnvelopeV1 } from '../../src/delivery/index.js';
import { currentPull, DELIVERY_FIXTURES } from './fixtures/index.js';
import {
  createDeliveryCaseSentinels,
  createGitHubReadFake,
  createWebhookHarness,
  serializePublicDeliveryObservations,
  signOriginalWebhookBody,
} from './support.js';

const harnesses: Array<Awaited<ReturnType<typeof createWebhookHarness>>> = [];
const { baseSha, headSha, baseTreeSha, headTreeSha, baseBlobSha, headBlobSha } = DELIVERY_FIXTURES;

afterEach(async () => {
  await Promise.all(harnesses.splice(0).map(async (harness) => harness.close()));
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function privateKey(): string {
  return generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
}

function pullBody(caseId: string): string {
  return JSON.stringify({
    action: 'opened',
    installation: { id: 42 },
    repository: { id: 7, name: 'target', owner: { login: 'owner' } },
    pull_request: { number: 19, base: { ref: 'main', sha: `event-base-${caseId}`, repo: { id: 7 } }, head: { sha: `event-head-${caseId}`, repo: { id: 7 } } },
  });
}

function installFiniteHttpBoundary(read: ReturnType<typeof createGitHubReadFake>, token: string): void {
  const nativeFetch = globalThis.fetch;
  vi.stubGlobal('fetch', async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : input.toString());
    if (url.hostname === '127.0.0.1') return nativeFetch(input, init);
    if (url.pathname === '/app/installations/42/access_tokens') {
      return new Response(JSON.stringify({ token, expires_at: '2099-01-01T00:00:00Z', permissions: {} }), { status: 201, headers: { 'content-type': 'application/json' } });
    }
    const pull = /^\/repos\/owner\/target\/pulls\/(\d+)$/u.exec(url.pathname);
    if (pull !== null) {
      const value = await read.capability.getCurrentPull(Number(pull[1]));
      return new Response(JSON.stringify({ number: value.number, state: value.state, draft: value.draft, merged: value.merged, base: { repo: { id: value.base.repositoryId }, ref: value.base.ref, sha: value.base.sha }, head: { repo: { id: value.head.repositoryId }, sha: value.head.sha } }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    const commit = /^\/repos\/owner\/target\/git\/commits\/([a-f0-9]{40})$/u.exec(url.pathname);
    if (commit !== null) {
      const value = await read.capability.getCommit(commit[1]!);
      return new Response(JSON.stringify({ sha: value.sha, tree: { sha: value.treeSha } }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    const tree = /^\/repos\/owner\/target\/git\/trees\/([a-f0-9]{40})$/u.exec(url.pathname);
    if (tree !== null) {
      const value = await read.capability.getTree(tree[1]!);
      return new Response(JSON.stringify({ sha: value.sha, tree: value.entries }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    const blob = /^\/repos\/owner\/target\/git\/blobs\/([a-f0-9]{40})$/u.exec(url.pathname);
    if (blob !== null) {
      const value = await read.capability.getBlob(blob[1]!);
      return new Response(JSON.stringify(value), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    return new Response(JSON.stringify({ code: 'unexpected-route' }), { status: 404, headers: { 'content-type': 'application/json' } });
  });
}

const LIFECYCLE_ROWS = [
  'success', 'acquisition-failure', 'configuration-failure', 'evaluator-failure',
  'transient-exhaustion', 'elapsed-timeout', 'explicit-cancellation', 'newer-tuple-supersession',
  'stale-final-identity', 'cleanup-error', 'fanout-incomplete',
] as const;

describe('signed public delivery lifecycle matrix', () => {
  it.each(LIFECYCLE_ROWS)('contains case-distinct test sentinels at the composed public boundary: %s', async (caseId) => {
    const sentinels = createDeliveryCaseSentinels(caseId);
    let pullReads = 0;
    const read = createGitHubReadFake({
      currentPull: () => {
        pullReads += 1;
        return caseId === 'stale-final-identity' && pullReads > 1
          ? { number: 19, repositoryId: 7, state: 'open', draft: false, merged: false, base: { repositoryId: 7, ref: 'main', sha: baseSha }, head: { repositoryId: 7, sha: '9'.repeat(40) } }
          : currentPull();
      },
      ...(caseId === 'acquisition-failure'
        ? { tree: () => ({ sha: '0'.repeat(40), entries: [] }) as never }
        : {}),
    });
    const envelopes: DeliveryEnvelopeV1[] = [];
    const roots: string[] = [];
    const app = createBoundaryCiApp({
      appId: 1,
      privateKey: privateKey(),
      webhookSecret: sentinels.webhookSecret!,
      evaluator: async (baseRoot, headRoot) => {
        roots.push(baseRoot, headRoot);
        if (caseId === 'evaluator-failure') throw new Error(sentinels.externalError);
        return { status: 'input-configuration-failure', invalid: 'base', diagnostics: [] };
      },
      onEnvelope: (envelope) => { envelopes.push(envelope); },
    });
    installFiniteHttpBoundary(read, sentinels.installationToken!);
    const harness = await createWebhookHarness(app);
    harnesses.push(harness);
    const body = pullBody(caseId);
    const response = await fetch(harness.url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-github-event': 'pull_request',
        'x-github-delivery': `lifecycle-${caseId}`,
        'x-hub-signature-256': signOriginalWebhookBody(sentinels.webhookSecret!, body),
      },
      body,
    });
    expect(response.status).toBe(200);
    await expect.poll(() => envelopes.length + (read.calls.length > 0 ? 0 : -1)).toBeGreaterThan(0);
    if (caseId === 'stale-final-identity') {
      expect(envelopes).toEqual([expect.objectContaining({ lifecycle: 'stale', handoff: 'none', reason: 'authenticated-comparison-drift' })]);
    } else if (caseId === 'evaluator-failure') {
      expect(envelopes).toEqual([expect.objectContaining({ lifecycle: 'current', handoff: 'diagnostic-only', diagnostic: { code: 'evaluator-runtime-failure' } })]);
    } else if (caseId === 'acquisition-failure') {
      expect(envelopes).toEqual([expect.objectContaining({ lifecycle: 'current', handoff: 'diagnostic-only', diagnostic: { code: 'acquisition-runtime-failure' } })]);
    } else {
      expect(envelopes[0]).toMatchObject({ lifecycle: 'current', handoff: 'publishable-semantic' });
    }
    if (caseId === 'success') expect(read.calls).toEqual(['pull:19', `commit:${baseSha}`, `tree:${baseTreeSha}`, `commit:${headSha}`, `tree:${headTreeSha}`, `blob:${baseBlobSha}`, `blob:${headBlobSha}`, 'pull:19']);
    const observations = serializePublicDeliveryObservations({ envelopes, response: await response.text(), calls: read.calls });
    for (const sentinel of Object.values(sentinels)) expect(observations).not.toContain(sentinel);
    await Promise.all(roots.map(async (root) => expect(access(root)).rejects.toMatchObject({ code: 'ENOENT' })));
  });
});
