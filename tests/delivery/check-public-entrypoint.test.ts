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
const INCOMPLETE_SOURCE = "import { Octokit } from 'octokit';\nconst client = new Octokit();\nclient.rest.pulls.list({});\n";
const CONFIG_BLOB_SHA = '1'.repeat(40);

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

function installPhase5Http(
  read: ReturnType<typeof createGitHubReadFake>,
  baseSource: string,
  headSource: string,
  installationToken: string,
  checkRequests?: string[],
  scopeRequests?: unknown[],
  configText?: string,
): void {
  const nativeFetch = globalThis.fetch;
  vi.stubGlobal('fetch', async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : input.toString());
    if (url.hostname === '127.0.0.1') return nativeFetch(input, init);
    if (url.pathname === '/app/installations/42/access_tokens') {
      const rawBody = input instanceof Request ? await input.clone().text() : typeof init?.body === 'string' ? init.body : '{}';
      const request = JSON.parse(rawBody) as { repository_ids?: unknown; permissions?: Record<string, string> };
      scopeRequests?.push({ repository_ids: request.repository_ids, permissions: request.permissions });
      return new Response(JSON.stringify({
        token: installationToken,
        expires_at: '2099-01-01T00:00:00Z',
        repositories: [{ id: 7, name: 'target' }],
        repository_selection: 'selected',
        permissions: { ...request.permissions, metadata: 'read' },
      }), { status: 201, headers: { 'content-type': 'application/json' } });
    }
    if (/^\/repos\/owner\/target\/commits\/[a-f0-9]{40}\/check-runs$/u.test(url.pathname)) {
      checkRequests?.push(`list:${url.searchParams.get('filter')}:${url.searchParams.get('per_page')}`);
      return new Response(JSON.stringify({ total_count: 0, check_runs: [] }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    if (url.pathname === '/repos/owner/target/check-runs') {
      checkRequests?.push('create');
      return new Response(JSON.stringify({ id: 101 }), { status: 201, headers: { 'content-type': 'application/json' } });
    }
    const pull = /^\/repos\/owner\/target\/pulls\/(\d+)$/u.exec(url.pathname);
    if (pull !== null) {
      const value = await read.capability.getCurrentPull(Number(pull[1]));
      return new Response(JSON.stringify({ number: value.number, state: value.state, draft: value.draft, merged: value.merged, base: { repo: { id: value.base.repositoryId }, ref: value.base.ref, sha: value.base.sha }, head: { repo: { id: value.head.repositoryId }, sha: value.head.sha } }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    const commit = /^\/repos\/owner\/target\/git\/commits\/([a-f0-9]{40})$/u.exec(url.pathname);
    if (commit !== null) return new Response(JSON.stringify({ sha: commit[1], tree: { sha: commit[1] === DELIVERY_FIXTURES.baseSha ? DELIVERY_FIXTURES.baseTreeSha : DELIVERY_FIXTURES.headTreeSha } }), { status: 200, headers: { 'content-type': 'application/json' } });
    const tree = /^\/repos\/owner\/target\/git\/trees\/([a-f0-9]{40})$/u.exec(url.pathname);
    if (tree !== null) {
      const isBase = tree[1] === DELIVERY_FIXTURES.baseTreeSha;
      const source = isBase ? baseSource : headSource;
      const entries = [{ path: 'src/app.ts', mode: '100644', type: 'blob', sha: isBase ? DELIVERY_FIXTURES.baseBlobSha : DELIVERY_FIXTURES.headBlobSha, size: Buffer.byteLength(source) }];
      if (configText !== undefined) entries.push({ path: '.boundaryci.yml', mode: '100644', type: 'blob', sha: CONFIG_BLOB_SHA, size: Buffer.byteLength(configText) });
      return new Response(JSON.stringify({ sha: tree[1], tree: entries }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    const blob = /^\/repos\/owner\/target\/git\/blobs\/([a-f0-9]{40})$/u.exec(url.pathname);
    if (blob !== null) {
      const source = blob[1] === CONFIG_BLOB_SHA ? configText ?? '' : blob[1] === DELIVERY_FIXTURES.baseBlobSha ? baseSource : headSource;
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

function diagnosticEnvelope(
  code: 'input-configuration-failure' | 'unsupported-topology' | 'acquisition-runtime-failure' | 'evaluator-runtime-failure',
): DeliveryEnvelopeV1 {
  const externalFork = code === 'unsupported-topology';
  return Object.freeze({
    schemaVersion: 1, lifecycle: 'current', handoff: 'diagnostic-only',
    work: Object.freeze({ installationId: 42, repositoryId: 7, pullNumber: 19, baseSha: DELIVERY_FIXTURES.baseSha, headSha: DELIVERY_FIXTURES.headSha, evaluatorIdentity: 'boundaryci-evaluator-v1' }),
    trigger: Object.freeze({ deliveryIds: Object.freeze([code]) }), diagnostic: Object.freeze({ code }), phase6FreshnessRequired: true,
    phase6Match: Object.freeze({
      repositoryId: 7, pullNumber: 19, baseRepositoryId: 7, baseRef: 'main',
      baseSha: DELIVERY_FIXTURES.baseSha, headRepositoryId: externalFork ? 8 : 7,
      headSha: DELIVERY_FIXTURES.headSha, topology: externalFork ? 'unsupported-topology' : 'same-repository', eligibility: 'open',
    }),
  }) as DeliveryEnvelopeV1;
}

async function postSigned(app: ReturnType<typeof createBoundaryCiApp>, sentinels: ReturnType<typeof createDeliveryCaseSentinels>, deliveryId: string): Promise<Response> {
  const harness = await createWebhookHarness(app); harnesses.push(harness); const body = signedBody(sentinels.rawPayload!);
  return fetch(harness.url, { method: 'POST', headers: {
    'content-type': 'application/json', 'x-github-event': 'pull_request', 'x-github-delivery': deliveryId,
    'x-hub-signature-256': signOriginalWebhookBody(sentinels.webhookSecret!, body),
  }, body });
}

describe('signed BoundaryCI Check tracer', () => {
  it('A39 composes the closed production Check path with separate private read and publication capabilities', async () => {
    const sentinels = createDeliveryCaseSentinels('a39'); const read = createGitHubReadFake(); const checks: string[] = []; const scopes: unknown[] = [];
    const app = createBoundaryCiApp({ appId: 1, privateKey: privateKey(), webhookSecret: sentinels.webhookSecret!, evaluator: evaluateLocalComparison, enableCheckPublication: true });
    installPhase5Http(read, READ_SOURCE, WRITE_SOURCE, sentinels.installationToken!, checks, scopes);
    const harness = await createWebhookHarness(app); harnesses.push(harness); const body = signedBody(sentinels.rawPayload!);
    const response = await fetch(harness.url, { method: 'POST', headers: {
      'content-type': 'application/json', 'x-github-event': 'pull_request', 'x-github-delivery': 'A39', 'x-hub-signature-256': signOriginalWebhookBody(sentinels.webhookSecret!, body),
    }, body });
    expect(response.status).toBe(200);
    await expect.poll(() => JSON.stringify({ checks, scopes })).toBe(JSON.stringify({
      checks: ['list:all:100', 'create'], scopes: [
        { repository_ids: [7], permissions: { contents: 'read', pull_requests: 'read' } },
        { repository_ids: [7], permissions: { checks: 'write' } },
      ],
    }));
    expect(JSON.stringify(checks)).not.toContain(sentinels.installationToken!);
  });

  it.each([
    ['A01', WRITE_SOURCE, WRITE_SOURCE, undefined, 'success', 'Permission boundary unchanged'],
    ['A02', WRITE_SOURCE, READ_SOURCE, undefined, 'success', 'Permission boundary reduced'],
    ['A03', READ_SOURCE, WRITE_SOURCE, 'version: 1\npolicy:\n  failOnExpansion: false\n', 'success', 'Permission expansion permitted'],
    ['A04', READ_SOURCE, WRITE_SOURCE, undefined, 'failure', 'Permission expansion requires review'],
    ['A05', READ_SOURCE, INCOMPLETE_SOURCE, 'version: 1\npolicy:\n  failOnIncomplete: false\n', 'neutral', 'Analysis incomplete'],
    ['A06', READ_SOURCE, INCOMPLETE_SOURCE, undefined, 'failure', 'Repository policy failed'],
  ] as const)('%s signed semantic handoff publishes the closed conclusion and title', async (caseId, base, head, config, conclusion, title) => {
    const sentinels = createDeliveryCaseSentinels(caseId.toLowerCase());
    const read = createGitHubReadFake();
    const store = checkStore({ headSha: DELIVERY_FIXTURES.headSha });
    const coordinator = createCheckCoordinator({ appId: 1, freshness: store, publisher: store });
    const app = createBoundaryCiApp({
      appId: 1, privateKey: privateKey(), webhookSecret: sentinels.webhookSecret!,
      evaluator: evaluateLocalComparison, checkCoordinator: coordinator,
    });
    installPhase5Http(read, base, head, sentinels.installationToken!, undefined, undefined, config);
    const harness = await createWebhookHarness(app); harnesses.push(harness);
    const body = signedBody(sentinels.rawPayload!);
    const response = await fetch(harness.url, { method: 'POST', headers: {
      'content-type': 'application/json', 'x-github-event': 'pull_request', 'x-github-delivery': caseId,
      'x-hub-signature-256': signOriginalWebhookBody(sentinels.webhookSecret!, body),
    }, body });
    expect(response.status).toBe(200);
    await expect.poll(() => coordinator.results).toHaveLength(1);
    expect(coordinator.results).toEqual([expect.objectContaining({ status: 'created' })]);
    expect(store.created).toEqual([expect.objectContaining({ conclusion, title, status: 'completed', name: 'BoundaryCI' })]);
    expect(store.calls[0]).toBe('fresh:19');
    expect(store.calls[1]).toMatch(/^lookup:boundaryci:v1:[a-f0-9]{64}$/u);
    expect(store.calls[2]).toBe(`create:${DELIVERY_FIXTURES.headSha}`);
    expect(JSON.stringify({ results: coordinator.results, created: store.created, calls: store.calls })).not.toContain(sentinels.installationToken!);
  });

  it.each([
    ['A07', 'input-configuration-failure'],
    ['A09 acquisition', 'acquisition-runtime-failure'],
    ['A09 evaluator', 'evaluator-runtime-failure'],
  ] as const)('%s signed diagnostic handoff publishes only action-required copy', async (caseId, code) => {
    const sentinels = createDeliveryCaseSentinels(caseId.replaceAll(' ', '-').toLowerCase());
    const read = createGitHubReadFake();
    const store = checkStore({ headSha: DELIVERY_FIXTURES.headSha });
    const coordinator = createCheckCoordinator({ appId: 1, freshness: store, publisher: store });
    const app = createBoundaryCiApp({
      appId: 1, privateKey: privateKey(), webhookSecret: sentinels.webhookSecret!, evaluator: evaluateLocalComparison,
      onEnvelope: async () => { await coordinator.receive(diagnosticEnvelope(code)); },
    });
    installPhase5Http(read, READ_SOURCE, WRITE_SOURCE, sentinels.installationToken!);
    expect((await postSigned(app, sentinels, caseId.replaceAll(' ', '-'))).status).toBe(200);
    await expect.poll(() => coordinator.results).toHaveLength(1);
    expect(coordinator.results).toEqual([expect.objectContaining({ status: 'created' })]);
    expect(store.created).toEqual([expect.objectContaining({ conclusion: 'action_required', title: 'BoundaryCI could not evaluate this change' })]);
    expect(JSON.stringify({ result: coordinator.results, created: store.created })).not.toContain(sentinels.rawPayload!);
  });

  it.each([
    ['addressable', true, 'created'],
    ['unaddressable', false, 'not-published'],
  ] as const)('A08 signed external-fork %s branch is explicit and never green', async (caseId, addressable, expectedStatus) => {
    const sentinels = createDeliveryCaseSentinels(`a08-${caseId}`);
    const read = createGitHubReadFake();
    const publisher = checkStore({ headSha: DELIVERY_FIXTURES.headSha });
    const coordinator = createCheckCoordinator({
      appId: 1,
      freshness: {
        async getCurrentPull(pullNumber) {
          const current = await publisher.getCurrentPull(pullNumber);
          return Object.freeze({ ...current, head: Object.freeze({ repositoryId: 8, sha: current.head.sha }) });
        },
        async addressHeadRepository(repositoryId, sha) {
          expect({ repositoryId, sha }).toEqual({ repositoryId: 8, sha: DELIVERY_FIXTURES.headSha });
          return addressable;
        },
      },
      publisher,
    });
    const app = createBoundaryCiApp({
      appId: 1, privateKey: privateKey(), webhookSecret: sentinels.webhookSecret!, evaluator: evaluateLocalComparison,
      onEnvelope: async () => { await coordinator.receive(diagnosticEnvelope('unsupported-topology')); },
    });
    installPhase5Http(read, READ_SOURCE, WRITE_SOURCE, sentinels.installationToken!);
    expect((await postSigned(app, sentinels, `A08-${caseId}`)).status).toBe(200);
    await expect.poll(() => coordinator.results).toHaveLength(1);
    expect(coordinator.results[0]).toMatchObject({ status: expectedStatus });
    if (addressable) {
      expect(publisher.created).toEqual([expect.objectContaining({ conclusion: 'action_required', title: 'BoundaryCI could not evaluate this change' })]);
    } else {
      expect(publisher.created).toEqual([]);
    }
    expect(publisher.created.every((payload) => payload.conclusion !== 'success')).toBe(true);
  });

  it('A10/A11 signed stale and untrusted freshness make zero Check lookup/write calls', async () => {
    const cases = [
      {
        id: 'A10',
        freshness: checkStore({ headSha: 'c'.repeat(40) }),
        expected: { status: 'not-published', reason: 'stale-comparison' },
      },
      {
        id: 'A11',
        freshness: { async getCurrentPull() { throw new Error('freshness-secret-sentinel'); } },
        expected: { status: 'not-published', reason: 'publication-failure' },
      },
    ] as const;
    for (const currentCase of cases) {
      const sentinels = createDeliveryCaseSentinels(currentCase.id.toLowerCase());
      const read = createGitHubReadFake();
      const publisher = checkStore({ headSha: DELIVERY_FIXTURES.headSha });
      const coordinator = createCheckCoordinator({ appId: 1, freshness: currentCase.freshness, publisher });
      const app = createBoundaryCiApp({
        appId: 1, privateKey: privateKey(), webhookSecret: sentinels.webhookSecret!, evaluator: evaluateLocalComparison,
        checkCoordinator: coordinator,
      });
      installPhase5Http(read, READ_SOURCE, WRITE_SOURCE, sentinels.installationToken!);
      expect((await postSigned(app, sentinels, currentCase.id)).status).toBe(200);
      await expect.poll(() => coordinator.results).toHaveLength(1);
      expect(coordinator.results).toEqual([currentCase.expected]);
      expect(publisher.calls).toEqual([]);
      expect(publisher.created).toEqual([]);
      expect(publisher.updates).toEqual([]);
      await harnesses.pop()?.close();
    }
  });

  it('A22 signed composition stops on multiple exact Check matches without mutation', async () => {
    const sentinels = createDeliveryCaseSentinels('a22');
    const read = createGitHubReadFake();
    const freshness = checkStore({ headSha: DELIVERY_FIXTURES.headSha });
    const calls: string[] = [];
    const publisher: CheckPublisher = Object.freeze({
      async lookupExact() { calls.push('lookup'); return Object.freeze([{ id: 1 }, { id: 2 }]); },
      async create() { calls.push('create'); return Object.freeze({ id: 3 }); },
      async update(id: number) { calls.push(`update:${id}`); return Object.freeze({ id }); },
    });
    const coordinator = createCheckCoordinator({ appId: 1, freshness, publisher });
    const app = createBoundaryCiApp({
      appId: 1, privateKey: privateKey(), webhookSecret: sentinels.webhookSecret!, evaluator: evaluateLocalComparison,
      checkCoordinator: coordinator,
    });
    installPhase5Http(read, READ_SOURCE, WRITE_SOURCE, sentinels.installationToken!);
    expect((await postSigned(app, sentinels, 'A22')).status).toBe(200);
    await expect.poll(() => coordinator.results).toHaveLength(1);
    expect(coordinator.results).toEqual([{ status: 'not-published', reason: 'publication-conflict' }]);
    expect(calls).toEqual(['lookup']);
  });

  it('A16 signed composition rechecks freshness before post-ambiguity reconciliation', async () => {
    const sentinels = createDeliveryCaseSentinels('a16-drift');
    const read = createGitHubReadFake();
    const current = checkStore({ headSha: DELIVERY_FIXTURES.headSha });
    let freshnessReads = 0;
    const calls: string[] = [];
    const publisher: CheckPublisher = Object.freeze({
      async lookupExact() {
        calls.push('lookup');
        return Object.freeze(calls.filter((call) => call === 'lookup').length === 1 ? [] : [{ id: 17 }]);
      },
      async create() { calls.push('create'); throw Object.assign(new Error('ambiguous'), { status: 503 }); },
      async update(id: number) { calls.push(`update:${id}`); return Object.freeze({ id }); },
    });
    const coordinator = createCheckCoordinator({
      appId: 1,
      freshness: {
        async getCurrentPull(pullNumber) {
          freshnessReads += 1;
          const observed = await current.getCurrentPull(pullNumber);
          return freshnessReads === 1 ? observed : Object.freeze({ ...observed, head: Object.freeze({ ...observed.head, sha: 'c'.repeat(40) }) });
        },
      },
      publisher,
    });
    const app = createBoundaryCiApp({
      appId: 1, privateKey: privateKey(), webhookSecret: sentinels.webhookSecret!, evaluator: evaluateLocalComparison,
      checkCoordinator: coordinator,
    });
    installPhase5Http(read, READ_SOURCE, WRITE_SOURCE, sentinels.installationToken!);
    expect((await postSigned(app, sentinels, 'A16-drift')).status).toBe(200);
    await expect.poll(() => coordinator.results).toHaveLength(1);
    expect(coordinator.results).toEqual([{ status: 'not-published', reason: 'stale-comparison' }]);
    expect(freshnessReads).toBe(2);
    expect(calls).toEqual(['lookup', 'create', 'lookup']);
  });

  it('keeps an unaddressable external-fork diagnostic from mutating a Check', async () => {
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
  });

  it('A14/A15 turn a signed expansion and redelivery into create then annotation-free update', async () => {
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
    await expect.poll(() => coordinator.results, { timeout: 5_000 }).toHaveLength(1);
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

  it('A12/A13 reject no-handoff and malformed envelopes before Check lookup or mutation', async () => {
    const none = Object.freeze({ schemaVersion: 1 as const, lifecycle: 'stale' as const, handoff: 'none' as const, work: { installationId: 42, repositoryId: 7, pullNumber: 19, baseSha: DELIVERY_FIXTURES.baseSha, headSha: DELIVERY_FIXTURES.headSha, evaluatorIdentity: 'boundaryci-evaluator-v1' }, reason: 'authenticated-comparison-drift' as const });
    const store = checkStore({ headSha: DELIVERY_FIXTURES.headSha });
    const coordinator = createCheckCoordinator({ appId: 1, freshness: store, publisher: store });
    await expect(coordinator.receive(none)).resolves.toEqual({ status: 'not-published', reason: 'no-handoff' });
    await expect(coordinator.receive({ schemaVersion: 1, lifecycle: 'current', handoff: 'publishable-semantic', unexpected: 'injected' })).resolves.toEqual({ status: 'not-published', reason: 'invalid-envelope' });
    expect(store.calls).toEqual([]);
  });
});
