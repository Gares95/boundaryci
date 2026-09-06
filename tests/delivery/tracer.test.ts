import { generateKeyPairSync } from 'node:crypto';
import { access, mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  createBoundaryCiApp,
  type DeliveryEnvelopeV1,
} from '../../src/delivery/index.js';
import { DELIVERY_FIXTURES } from './fixtures/index.js';
import { acquireDeliveryFetchScope, AllowlistedSink, createDeliveryCaseSentinels, createGitHubReadFake, createWebhookHarness, inspectTemporaryParent, signOriginalWebhookBody } from './support.js';

const WEBHOOK_SECRET = createDeliveryCaseSentinels('tracer').webhookSecret!;
const {
  baseSha: BASE_SHA,
  headSha: HEAD_SHA,
  baseTreeSha: BASE_TREE,
  headTreeSha: HEAD_TREE,
  baseBlobSha: BASE_BLOB,
  headBlobSha: HEAD_BLOB,
} = DELIVERY_FIXTURES;

const harnesses: Array<Awaited<ReturnType<typeof createWebhookHarness>>> = [];
let releaseFetchScope: (() => void) | undefined;

beforeEach(async () => { releaseFetchScope = await acquireDeliveryFetchScope(); });
afterEach(async () => {
  await Promise.all(harnesses.splice(0).map((harness) => harness.close()));
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  releaseFetchScope?.();
  releaseFetchScope = undefined;
});

function composeVerifiedContext(app: ReturnType<typeof createBoundaryCiApp>, read: ReturnType<typeof createGitHubReadFake>): void {
  void app;
  const nativeFetch = globalThis.fetch;
  vi.stubGlobal('fetch', async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : input.toString());
    if (url.hostname === '127.0.0.1') return nativeFetch(input, init);
    if (url.pathname === '/app/installations/42/access_tokens') {
      return new Response(JSON.stringify({ token: 'installation-token-test-only', expires_at: '2099-01-01T00:00:00Z', permissions: {} }), { status: 201, headers: { 'content-type': 'application/json' } });
    }
    if (url.pathname === '/repos/owner/target/pulls') {
      const value = await read.capability.listOpenPullsByBase(url.searchParams.get('base') ?? '', Number(url.searchParams.get('page') ?? '1'));
      return new Response(JSON.stringify(value.pulls.map((pull) => ({ number: pull.number, state: pull.state, draft: pull.draft, merged: pull.merged, base: { repo: { id: pull.base.repositoryId }, ref: pull.base.ref, sha: pull.base.sha }, head: { repo: { id: pull.head.repositoryId }, sha: pull.head.sha } }))), { status: 200, headers: { 'content-type': 'application/json' } });
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
      return new Response(JSON.stringify({ sha: value.sha, tree: value.entries, ...(value.truncated === undefined ? {} : { truncated: value.truncated }) }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    const blob = /^\/repos\/owner\/target\/git\/blobs\/([a-f0-9]{40})$/u.exec(url.pathname);
    if (blob !== null) {
      const value = await read.capability.getBlob(blob[1]!);
      return new Response(JSON.stringify(value), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    return new Response(JSON.stringify({ message: 'unexpected deterministic test route' }), { status: 404, headers: { 'content-type': 'application/json' } });
  });
}

function testPrivateKey(): string {
  return generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
}

function signedBody(): string {
  return JSON.stringify({
    action: 'opened',
    installation: { id: 42 },
    repository: { id: 7, name: 'target', owner: { login: 'owner' } },
    pull_request: {
      number: 19,
      base: { ref: 'main', sha: 'event-base-must-not-be-used', repo: { id: 7 } },
      head: { sha: 'event-head-must-not-be-used', repo: { id: 7 } },
    },
  });
}

function signature(body: string): string {
  return signOriginalWebhookBody(WEBHOOK_SECRET, body);
}

function forkSignedBody(): string {
  return JSON.stringify({
    action: 'opened',
    installation: { id: 42 },
    repository: { id: 7, name: 'target', owner: { login: 'owner' } },
    pull_request: {
      number: 19,
      base: { ref: 'main', sha: 'event-base-must-not-be-used', repo: { id: 7 } },
      head: { sha: 'event-head-must-not-be-used', repo: { id: 9 } },
    },
  });
}

function pushSignedBody(): string {
  return JSON.stringify({
    installation: { id: 42 },
    repository: { id: 7, name: 'target', owner: { login: 'owner' } },
    ref: 'refs/heads/main',
  });
}

describe('verified delivery tracer', () => {
  it('accepts only a correctly signed original body and emits a source-free cleanup-gated envelope', async () => {
    const read = createGitHubReadFake();
    const envelopes: DeliveryEnvelopeV1[] = [];
    const roots: string[] = [];
    const app = createBoundaryCiApp({
      appId: 1,
      privateKey: testPrivateKey(),
      webhookSecret: WEBHOOK_SECRET,
      evaluator: async (baseRoot, headRoot) => {
        roots.push(baseRoot, headRoot);
        return { status: 'input-configuration-failure', invalid: 'base', diagnostics: [] };
      },
      onEnvelope: (envelope) => { envelopes.push(envelope); },
    });
    composeVerifiedContext(app, read);
    const harness = await createWebhookHarness(app);
    harnesses.push(harness);

    const body = signedBody();
    const response = await fetch(harness.url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-github-event': 'pull_request',
        'x-github-delivery': 'delivery-1',
        'x-hub-signature-256': signature(body),
      },
      body,
    });

    expect(response.status).toBe(200);
    await expect.poll(() => envelopes).toHaveLength(1);
    await expect.poll(() => read.calls.length).toBe(8);
    expect(read.calls).toEqual([
      'pull:19', `commit:${BASE_SHA}`, `tree:${BASE_TREE}`, `commit:${HEAD_SHA}`, `tree:${HEAD_TREE}`, `blob:${BASE_BLOB}`, `blob:${HEAD_BLOB}`, 'pull:19',
    ]);
    expect(envelopes[0]).toMatchObject({
      schemaVersion: 1,
      lifecycle: 'current',
      handoff: 'publishable-semantic',
      work: { repositoryId: 7, pullNumber: 19, baseSha: BASE_SHA, headSha: HEAD_SHA },
    });
    expect(JSON.stringify(envelopes[0])).not.toContain(WEBHOOK_SECRET);
    expect(JSON.stringify(envelopes[0])).not.toContain('event-base-must-not-be-used');
    expect(JSON.stringify(envelopes[0])).not.toContain('export const app');
    expect(roots).toHaveLength(2);
    expect(roots[0]).not.toBe(roots[1]);
    await Promise.all(roots.map(async (root) => expect(access(root)).rejects.toMatchObject({ code: 'ENOENT' })));
  });

  it('rejects a wrong signature before any capability or evaluator invocation', async () => {
    const read = createGitHubReadFake();
    const envelopes: DeliveryEnvelopeV1[] = [];
    const app = createBoundaryCiApp({
      appId: 1,
      privateKey: testPrivateKey(),
      webhookSecret: WEBHOOK_SECRET,
      evaluator: async () => ({ status: 'input-configuration-failure', invalid: 'base', diagnostics: [] }),
      onEnvelope: (envelope) => { envelopes.push(envelope); },
    });
    composeVerifiedContext(app, read);
    const harness = await createWebhookHarness(app);
    harnesses.push(harness);

    const response = await fetch(harness.url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-github-event': 'pull_request',
        'x-github-delivery': 'delivery-invalid',
        'x-hub-signature-256': 'sha256=0'.padEnd(71, '0'),
      },
      body: signedBody(),
    });

    expect(response.ok).toBe(false);
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(read.calls).toEqual([]);
    expect(envelopes).toEqual([]);
  });

  it('hands off one current authenticated unsupported-topology diagnostic without acquiring fork source', async () => {
    const read = createGitHubReadFake({
      currentPull: () => ({
        number: 19,
        repositoryId: 7,
        state: 'open',
        draft: false,
        merged: false,
        base: { repositoryId: 7, ref: 'main', sha: BASE_SHA },
        head: { repositoryId: 9, sha: HEAD_SHA },
      }),
    });
    const envelopes: DeliveryEnvelopeV1[] = [];
    const app = createBoundaryCiApp({
      appId: 1,
      privateKey: testPrivateKey(),
      webhookSecret: WEBHOOK_SECRET,
      evaluator: async () => { throw new Error('fork source must not be evaluated'); },
      onEnvelope: (envelope) => { envelopes.push(envelope); },
    });
    composeVerifiedContext(app, read);
    const harness = await createWebhookHarness(app);
    harnesses.push(harness);
    const body = forkSignedBody();

    const response = await fetch(harness.url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-github-event': 'pull_request',
        'x-github-delivery': 'delivery-fork',
        'x-hub-signature-256': signature(body),
      },
      body,
    });

    expect(response.status).toBe(200);
    await expect.poll(() => envelopes).toHaveLength(1);
    expect(envelopes[0]).toMatchObject({
      lifecycle: 'current',
      handoff: 'diagnostic-only',
      diagnostic: { code: 'unsupported-topology' },
      phase6Match: { topology: 'unsupported-topology', headRepositoryId: 9 },
    });
    expect(read.calls).toEqual(['pull:19', 'pull:19']);
    expect(read.calls.some((call) => /^(blob|commit|tree):/u.test(call))).toBe(false);
  });

  it('emits one validated non-handoff lifecycle result for signed all-or-none push fanout failure', async () => {
    const read = createGitHubReadFake({
      list: () => ({
        pulls: Object.freeze(Array.from({ length: 101 }, (_, index) => ({
          number: index + 1,
          repositoryId: 7,
          state: 'open' as const,
          draft: false,
          merged: false,
          base: { repositoryId: 7, ref: 'main', sha: BASE_SHA },
          head: { repositoryId: 7, sha: HEAD_SHA },
        }))),
        nextPage: null,
        normalizedBytes: 1,
      }),
    });
    const envelopes: DeliveryEnvelopeV1[] = [];
    const evaluator = vi.fn(async () => ({ status: 'input-configuration-failure' as const, invalid: 'base' as const, diagnostics: [] }));
    const app = createBoundaryCiApp({
      appId: 1,
      privateKey: testPrivateKey(),
      webhookSecret: WEBHOOK_SECRET,
      evaluator,
      onEnvelope: (envelope) => { envelopes.push(envelope); },
    });
    composeVerifiedContext(app, read);
    const harness = await createWebhookHarness(app);
    harnesses.push(harness);
    const body = pushSignedBody();

    const response = await fetch(harness.url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-github-event': 'push',
        'x-github-delivery': 'delivery-fanout-incomplete',
        'x-hub-signature-256': signature(body),
      },
      body,
    });

    expect(response.status).toBe(200);
    await expect.poll(() => envelopes).toHaveLength(1);
    expect(envelopes).toEqual([{
      schemaVersion: 1,
      lifecycle: 'fanout-incomplete',
      handoff: 'none',
      work: null,
      reason: 'fanout-page-shape',
    }]);
    expect(read.calls).toEqual(['list:main:1']);
    expect(evaluator).not.toHaveBeenCalled();
  });

  it('keeps the reusable read fake, allowlisted sink, and temporary inspector bounded', async () => {
    const read = createGitHubReadFake();
    await read.capability.getCurrentPull(19);
    await read.capability.getCommit(BASE_SHA);
    expect(read.calls).toEqual(['pull:19', `commit:${BASE_SHA}`]);
    expect('request' in read.capability).toBe(false);
    expect('write' in read.capability).toBe(false);

    const sink = new AllowlistedSink();
    sink.emit({ stage: 'read', outcome: 'accepted', repositoryId: 7, pullNumber: 19 });
    expect(sink.events).toHaveLength(1);
    expect(() => sink.emit({ stage: 'read', outcome: 'accepted', repositoryId: 7, pullNumber: 19, metadata: {} } as never)).toThrow(
      'unsafe delivery event shape',
    );

    const parent = await mkdtemp(join(tmpdir(), 'boundaryci-delivery-inspector-'));
    try {
      await mkdir(join(parent, 'target'));
      await writeFile(join(parent, 'target', 'not-followed.txt'), 'inert');
      await symlink(join(parent, 'target'), join(parent, 'link'));
      const entries = await inspectTemporaryParent(parent);
      expect(entries).toContainEqual({ path: 'link', kind: 'symlink', mode: 0o777 });
      expect(entries.some((entry) => entry.path.startsWith('link/'))).toBe(false);
    } finally {
      await rm(parent, { force: true, recursive: true });
    }
  });
});
