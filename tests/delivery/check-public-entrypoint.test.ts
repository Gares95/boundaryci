import { generateKeyPairSync } from 'node:crypto';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { createBoundaryCiApp } from '../../src/delivery/index.js';
import { createCheckCoordinator, type CheckPublisher, type CurrentPullFreshnessReader } from '../../src/delivery/check-coordinator.js';
import type { CompletedCheckPayloadV1 } from '../../src/delivery/check-contract.js';
import { evaluateLocalComparison } from '../../src/runtime/evaluate.js';
import { DELIVERY_FIXTURES } from './fixtures/index.js';
import { acquireDeliveryFetchScope, createDeliveryCaseSentinels, createGitHubReadFake, createWebhookHarness, signOriginalWebhookBody } from './support.js';

const harnesses: Array<Awaited<ReturnType<typeof createWebhookHarness>>> = [];
let releaseFetchScope: (() => void) | undefined;

const READ_SOURCE = "import { Octokit } from 'octokit';\nconst client = new Octokit();\nclient.rest.issues.listForRepo({});\n";
const WRITE_SOURCE = "import { Octokit } from 'octokit';\nconst client = new Octokit();\nclient.rest.issues.create({});\n";

beforeEach(async () => { releaseFetchScope = await acquireDeliveryFetchScope(); });
afterEach(async () => {
  await Promise.all(harnesses.splice(0).map((harness) => harness.close()));
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  releaseFetchScope?.();
  releaseFetchScope = undefined;
});

function privateKey(): string {
  return generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
}

function signedBody(rawPayload: string): string {
  return JSON.stringify({
    boundaryci_test_ignored: rawPayload,
    action: 'opened', installation: { id: 42 }, repository: { id: 7, name: 'target', owner: { login: 'owner' } },
    pull_request: { number: 19, base: { ref: 'main', sha: 'event-base-not-authoritative', repo: { id: 7 } }, head: { sha: 'event-head-not-authoritative', repo: { id: 7 } } },
  });
}

function installPhase5Http(read: ReturnType<typeof createGitHubReadFake>, baseSource: string, headSource: string, installationToken: string): void {
  const nativeFetch = globalThis.fetch;
  vi.stubGlobal('fetch', async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : input.toString());
    if (url.hostname === '127.0.0.1') return nativeFetch(input, init);
    if (url.pathname === '/app/installations/42/access_tokens') {
      return new Response(JSON.stringify({ token: installationToken, expires_at: '2099-01-01T00:00:00Z', permissions: {} }), { status: 201, headers: { 'content-type': 'application/json' } });
    }
    const pull = /^\/repos\/owner\/target\/pulls\/(\d+)$/u.exec(url.pathname);
    if (pull !== null) {
      const value = await read.capability.getCurrentPull(Number(pull[1]));
      return new Response(JSON.stringify({ number: value.number, state: value.state, draft: value.draft, merged: value.merged, base: { repo: { id: value.base.repositoryId }, ref: value.base.ref, sha: value.base.sha }, head: { repo: { id: value.head.repositoryId }, sha: value.head.sha } }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    const commit = /^\/repos\/owner\/target\/git\/commits\/([a-f0-9]{40})$/u.exec(url.pathname);
    if (commit !== null) return new Response(JSON.stringify({ sha: commit[1], tree: { sha: commit[1] === DELIVERY_FIXTURES.baseSha ? DELIVERY_FIXTURES.baseTreeSha : DELIVERY_FIXTURES.headTreeSha } }), { status: 200, headers: { 'content-type': 'application/json' } });
    const tree = /^\/repos\/owner\/target\/git\/trees\/([a-f0-9]{40})$/u.exec(url.pathname);
    if (tree !== null) return new Response(JSON.stringify({ sha: tree[1], tree: [{ path: 'src/app.ts', mode: '100644', type: 'blob', sha: tree[1] === DELIVERY_FIXTURES.baseTreeSha ? DELIVERY_FIXTURES.baseBlobSha : DELIVERY_FIXTURES.headBlobSha, size: Buffer.byteLength(WRITE_SOURCE) }] }), { status: 200, headers: { 'content-type': 'application/json' } });
    const blob = /^\/repos\/owner\/target\/git\/blobs\/([a-f0-9]{40})$/u.exec(url.pathname);
    if (blob !== null) {
      const source = blob[1] === DELIVERY_FIXTURES.baseBlobSha ? baseSource : headSource;
      return new Response(JSON.stringify({ sha: blob[1], encoding: 'base64', content: Buffer.from(source).toString('base64'), size: Buffer.byteLength(source) }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    return new Response(JSON.stringify({ code: 'unexpected-route' }), { status: 404, headers: { 'content-type': 'application/json' } });
  });
}

function checkStore(current: { readonly headSha: string }): CheckPublisher & CurrentPullFreshnessReader & { readonly calls: string[]; readonly created: CompletedCheckPayloadV1[] } {
  const calls: string[] = [];
  const created: CompletedCheckPayloadV1[] = [];
  return Object.freeze({
    calls,
    created,
    async getCurrentPull(pullNumber) {
      calls.push(`fresh:${pullNumber}`);
      return Object.freeze({ number: pullNumber, repositoryId: 7, state: 'open' as const, draft: false, merged: false, base: { repositoryId: 7, ref: 'main', sha: DELIVERY_FIXTURES.baseSha }, head: { repositoryId: 7, sha: current.headSha } });
    },
    async lookupExact(identity) { calls.push(`lookup:${identity.correlationId}`); return Object.freeze([]); },
    async create(payload) { calls.push(`create:${payload.headSha}`); created.push(payload); return Object.freeze({ id: 101 }); },
    async update() { throw new Error('unexpected Check update'); },
  });
}

describe('signed BoundaryCI Check tracer', () => {
  it('turns a signed current Issues read-to-write expansion into one exact-head completed Check', async () => {
    const sentinels = createDeliveryCaseSentinels('check-tracer');
    const read = createGitHubReadFake();
    const store = checkStore({ headSha: DELIVERY_FIXTURES.headSha });
    const coordinator = createCheckCoordinator({ appId: 1, freshness: store, publisher: store });
    const app = createBoundaryCiApp({
      appId: 1, privateKey: privateKey(), webhookSecret: sentinels.webhookSecret!,
      evaluator: evaluateLocalComparison,
      onEnvelope: async (envelope) => { await coordinator.receive(envelope); },
    });
    installPhase5Http(read, READ_SOURCE, WRITE_SOURCE, sentinels.installationToken!);
    const harness = await createWebhookHarness(app);
    harnesses.push(harness);
    const body = signedBody(sentinels.rawPayload!);

    const response = await fetch(harness.url, { method: 'POST', headers: {
      'content-type': 'application/json', 'x-github-event': 'pull_request', 'x-github-delivery': 'check-tracer-1',
      'x-hub-signature-256': signOriginalWebhookBody(sentinels.webhookSecret!, body),
    }, body });

    expect(response.status).toBe(200);
    await expect.poll(() => store.created).toHaveLength(1);
    expect(store.calls).toHaveLength(3);
    expect(store.calls[0]).toBe('fresh:19');
    expect(store.calls[1]).toMatch(/^lookup:boundaryci:v1:[a-f0-9]{64}$/u);
    expect(store.calls[2]).toBe(`create:${DELIVERY_FIXTURES.headSha}`);
    expect(store.created[0]).toMatchObject({
      name: 'BoundaryCI', status: 'completed', headSha: DELIVERY_FIXTURES.headSha,
      conclusion: 'failure', title: 'Permission expansion requires review',
      annotations: [expect.objectContaining({ level: 'failure', title: 'Permission policy failure', path: 'src/app.ts', operationId: 'issues/create' })],
    });
    const observed = JSON.stringify({ calls: store.calls, created: store.created, result: coordinator.results });
    for (const sentinel of Object.values(sentinels)) expect(observed).not.toContain(sentinel);
  });
});
