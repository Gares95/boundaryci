import { generateKeyPairSync } from 'node:crypto';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { createBoundaryCiApp, type DeliveryEnvelopeV1 } from '../../src/delivery/index.js';
import { createCheckCoordinator, type CurrentPullFreshnessReader } from '../../src/delivery/check-coordinator.js';
import type { CheckPublisher } from '../../src/delivery/check-publish.js';
import { deriveCheckCorrelationId, type CompletedCheckPayloadV1 } from '../../src/delivery/check-contract.js';
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
    if (tree !== null) return new Response(JSON.stringify({ sha: tree[1], tree: [{ path: 'src/app.ts', mode: '100644', type: 'blob', sha: tree[1] === DELIVERY_FIXTURES.baseTreeSha ? DELIVERY_FIXTURES.baseBlobSha : DELIVERY_FIXTURES.headBlobSha, size: Buffer.byteLength(tree[1] === DELIVERY_FIXTURES.baseTreeSha ? baseSource : headSource) }] }), { status: 200, headers: { 'content-type': 'application/json' } });
    const blob = /^\/repos\/owner\/target\/git\/blobs\/([a-f0-9]{40})$/u.exec(url.pathname);
    if (blob !== null) {
      const source = blob[1] === DELIVERY_FIXTURES.baseBlobSha ? baseSource : headSource;
      return new Response(JSON.stringify({ sha: blob[1], encoding: 'base64', content: Buffer.from(source).toString('base64'), size: Buffer.byteLength(source) }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    return new Response(JSON.stringify({ code: 'unexpected-route' }), { status: 404, headers: { 'content-type': 'application/json' } });
  });
}

type CheckStore = CheckPublisher & CurrentPullFreshnessReader & {
  readonly calls: string[];
  readonly created: CompletedCheckPayloadV1[];
  readonly updates: Array<Omit<CompletedCheckPayloadV1, 'annotations'>>;
};

function checkStore(current: { readonly headSha: string }): CheckStore {
  const calls: string[] = [];
  const created: CompletedCheckPayloadV1[] = [];
  const updates: Array<Omit<CompletedCheckPayloadV1, 'annotations'>> = [];
  return Object.freeze({
    calls,
    created,
    updates,
    async getCurrentPull(pullNumber: number) {
      calls.push(`fresh:${pullNumber}`);
      return Object.freeze({ number: pullNumber, repositoryId: 7, state: 'open' as const, draft: false, merged: false, base: { repositoryId: 7, ref: 'main', sha: DELIVERY_FIXTURES.baseSha }, head: { repositoryId: 7, sha: current.headSha } });
    },
    async lookupExact(identity: Parameters<CheckPublisher['lookupExact']>[0]) {
      calls.push(`lookup:${identity.correlationId}`);
      return Object.freeze(created.length === 0 ? [] : [{ id: 101 }]);
    },
    async create(payload: CompletedCheckPayloadV1) { calls.push(`create:${payload.headSha}`); created.push(payload); return Object.freeze({ id: 101 }); },
    async update(checkId: number, payload: Omit<CompletedCheckPayloadV1, 'annotations'>) {
      calls.push(`update:${checkId}:${payload.headSha}`);
      updates.push(payload);
      return Object.freeze({ id: checkId });
    },
  });
}

describe('signed BoundaryCI Check tracer', () => {
  it('A01-A13/A39 keep none, stale, and unaddressable external-fork paths from mutating a Check', async () => {
    const store = checkStore({ headSha: DELIVERY_FIXTURES.headSha });
    const coordinator = createCheckCoordinator({ appId: 1, freshness: {
      async getCurrentPull(pullNumber) {
        const current = await store.getCurrentPull(pullNumber);
        return Object.freeze({ ...current, head: Object.freeze({ repositoryId: 8, sha: current.head.sha }) });
      },
    }, publisher: store });
    const unsupported: DeliveryEnvelopeV1 = Object.freeze({
      schemaVersion: 1, lifecycle: 'current', handoff: 'diagnostic-only',
      work: Object.freeze({ installationId: 42, repositoryId: 7, pullNumber: 19, baseSha: DELIVERY_FIXTURES.baseSha, headSha: DELIVERY_FIXTURES.headSha, evaluatorIdentity: 'boundaryci-evaluator-v1' }),
      trigger: Object.freeze({ deliveryIds: Object.freeze(['A08']) }),
      diagnostic: Object.freeze({ code: 'unsupported-topology' }), phase6FreshnessRequired: true,
      phase6Match: Object.freeze({ repositoryId: 7, pullNumber: 19, baseRepositoryId: 7, baseRef: 'main', baseSha: DELIVERY_FIXTURES.baseSha, headRepositoryId: 8, headSha: DELIVERY_FIXTURES.headSha, topology: 'unsupported-topology', eligibility: 'open' }),
    }) as DeliveryEnvelopeV1;
    const noAddressability = await coordinator.receive(unsupported);
    expect(noAddressability).toEqual({ status: 'not-published', reason: 'publication-failure' });
    expect(store.calls).toEqual(['fresh:19']);
    expect(store.created).toEqual([]);
    expect(store.updates).toEqual([]);
    // A01-A07/A09 and A39 are exercised by the signed semantic path below; A10-A13 have no write.
  });

  it('turns a signed current Issues read-to-write expansion into one exact-head completed Check', async () => {
    const sentinels = createDeliveryCaseSentinels('check-tracer');
    const read = createGitHubReadFake();
    const store = checkStore({ headSha: DELIVERY_FIXTURES.headSha });
    const coordinator = createCheckCoordinator({ appId: 1, freshness: store, publisher: store });
    let received: DeliveryEnvelopeV1 | undefined;
    const app = createBoundaryCiApp({
      appId: 1, privateKey: privateKey(), webhookSecret: sentinels.webhookSecret!,
      evaluator: evaluateLocalComparison,
      onEnvelope: async (envelope) => { received = envelope; await coordinator.receive(envelope); },
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
    await expect.poll(() => coordinator.results).toHaveLength(1);
    expect(coordinator.results).toEqual([expect.objectContaining({ status: 'created' })]);
    expect(store.created).toHaveLength(1);
    expect(store.calls).toHaveLength(3);
    expect(store.calls[0]).toBe('fresh:19');
    expect(store.calls[1]).toMatch(/^lookup:boundaryci:v1:[a-f0-9]{64}$/u);
    expect(store.calls[2]).toBe(`create:${DELIVERY_FIXTURES.headSha}`);
    expect(store.created[0]).toMatchObject({
      name: 'BoundaryCI', status: 'completed', headSha: DELIVERY_FIXTURES.headSha,
      conclusion: 'failure', title: 'Permission expansion requires review',
      annotations: [expect.objectContaining({ level: 'failure', title: 'Permission policy failure', path: 'src/app.ts', operationId: 'issues/create' })],
    });
    const redeliveryResponse = await fetch(harness.url, { method: 'POST', headers: {
      'content-type': 'application/json', 'x-github-event': 'pull_request', 'x-github-delivery': 'check-tracer-redelivery',
      'x-hub-signature-256': signOriginalWebhookBody(sentinels.webhookSecret!, body),
    }, body });
    expect(redeliveryResponse.status).toBe(200);
    await expect.poll(() => coordinator.results).toHaveLength(2);
    expect(coordinator.results[1]).toMatchObject({ status: 'updated', checkId: 101 });
    expect(store.created).toHaveLength(1);
    expect(store.updates).toEqual([expect.objectContaining({ headSha: DELIVERY_FIXTURES.headSha, status: 'completed' })]);
    expect(Object.hasOwn(store.updates[0]!, 'annotations')).toBe(false);
    expect(received).toMatchObject({ lifecycle: 'current', handoff: 'publishable-semantic' });
    if (received?.handoff !== 'publishable-semantic') throw new Error('signed tracer did not produce a semantic handoff');
    const identity = deriveCheckCorrelationId(received);
    expect(identity).toMatchObject({ version: 1, installationId: 42, repositoryId: 7, pullNumber: 19, baseSha: DELIVERY_FIXTURES.baseSha, headSha: DELIVERY_FIXTURES.headSha, topology: 'same-repository' });
    expect(identity.correlationId).toMatch(/^boundaryci:v1:[a-f0-9]{64}$/u);
    const redelivered = structuredClone(received);
    redelivered.trigger = { deliveryIds: ['check-tracer-redelivery'] };
    expect(deriveCheckCorrelationId(redelivered)).toEqual(identity);
    expect(JSON.stringify(identity)).not.toContain('deliveryIds');
    const staleStore = checkStore({ headSha: 'c'.repeat(40) });
    let releaseFreshness!: () => void;
    const freshnessBarrier = new Promise<void>((resolve) => { releaseFreshness = resolve; });
    const delayedFreshness: CurrentPullFreshnessReader = {
      async getCurrentPull(pullNumber) {
        await freshnessBarrier;
        return staleStore.getCurrentPull(pullNumber);
      },
    };
    const staleCoordinator = createCheckCoordinator({ appId: 1, freshness: delayedFreshness, publisher: staleStore });
    const obsolete = Promise.all([staleCoordinator.receive(received), staleCoordinator.receive(received)]);
    releaseFreshness();
    await expect(obsolete).resolves.toEqual([
      { status: 'not-published', reason: 'stale-comparison' },
      { status: 'not-published', reason: 'stale-comparison' },
    ]);
    expect(staleStore.calls).toEqual(['fresh:19', 'fresh:19']);
    expect(staleStore.created).toEqual([]);
    expect(staleStore.updates).toEqual([]);
    const observed = JSON.stringify({ calls: store.calls, created: store.created, result: coordinator.results });
    for (const sentinel of Object.values(sentinels)) expect(observed).not.toContain(sentinel);
  });

  it('rejects stale, no-handoff, and malformed envelopes before Check lookup or mutation', async () => {
    const none = Object.freeze({ schemaVersion: 1 as const, lifecycle: 'stale' as const, handoff: 'none' as const, work: { installationId: 42, repositoryId: 7, pullNumber: 19, baseSha: DELIVERY_FIXTURES.baseSha, headSha: DELIVERY_FIXTURES.headSha, evaluatorIdentity: 'boundaryci-evaluator-v1' }, reason: 'authenticated-comparison-drift' as const });
    const store = checkStore({ headSha: DELIVERY_FIXTURES.headSha });
    const coordinator = createCheckCoordinator({ appId: 1, freshness: store, publisher: store });
    await expect(coordinator.receive(none)).resolves.toEqual({ status: 'not-published', reason: 'no-handoff' });
    await expect(coordinator.receive({ schemaVersion: 1, lifecycle: 'current', handoff: 'publishable-semantic', unexpected: 'injected' })).resolves.toEqual({ status: 'not-published', reason: 'invalid-envelope' });
    expect(store.calls).toEqual([]);
  });
});
