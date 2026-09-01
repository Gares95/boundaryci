import { createHmac } from 'node:crypto';
import { access, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import { afterEach, describe, expect, it } from 'vitest';

import {
  createBoundaryCiApp,
  handleVerifiedTrigger,
  type DeliveryEnvelopeV1,
  type GitHubReadCapability,
} from '../../src/delivery/index.js';
import type { LocalComparisonResult } from '../../src/runtime/evaluate.js';

const WEBHOOK_SECRET = 'delivery-webhook-secret-sentinel';
const BASE_SHA = 'a'.repeat(40);
const HEAD_SHA = 'b'.repeat(40);
const BASE_TREE = 'c'.repeat(40);
const HEAD_TREE = 'd'.repeat(40);
const BASE_BLOB = 'e'.repeat(40);
const HEAD_BLOB = 'f'.repeat(40);
const SOURCE_BYTES = Buffer.from('export const app = () => {};\n');

const servers: ReturnType<typeof createServer>[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
});

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
  return `sha256=${createHmac('sha256', WEBHOOK_SECRET).update(body).digest('hex')}`;
}

function readCapability(calls: string[]): GitHubReadCapability {
  return {
    async getCurrentPull(number) {
      calls.push(`pull:${number}`);
      return {
        number,
        repositoryId: 7,
        state: 'open',
        draft: false,
        merged: false,
        base: { repositoryId: 7, ref: 'main', sha: BASE_SHA },
        head: { repositoryId: 7, sha: HEAD_SHA },
      };
    },
    async listOpenPullsByBase() { return []; },
    async getCommit(sha) {
      calls.push(`commit:${sha}`);
      return { sha, treeSha: sha === BASE_SHA ? BASE_TREE : HEAD_TREE };
    },
    async getTree(sha) {
      calls.push(`tree:${sha}`);
      return {
        sha,
        entries: [
          {
            path: 'index.ts',
            mode: '100644',
            type: 'blob',
            sha: sha === BASE_TREE ? BASE_BLOB : HEAD_BLOB,
            size: SOURCE_BYTES.byteLength,
          },
        ],
      };
    },
    async getBlob(sha) {
      calls.push(`blob:${sha}`);
      return { sha, encoding: 'base64', content: SOURCE_BYTES.toString('base64'), size: SOURCE_BYTES.byteLength };
    },
  };
}

describe('verified delivery tracer', () => {
  it('accepts only a correctly signed original body and emits a source-free cleanup-gated envelope', async () => {
    const calls: string[] = [];
    const envelopes: DeliveryEnvelopeV1[] = [];
    const roots: string[] = [];
    const app = createBoundaryCiApp({
      appId: 1,
      privateKey: '-----BEGIN PRIVATE KEY-----\nunused\n-----END PRIVATE KEY-----',
      webhookSecret: WEBHOOK_SECRET,
      createReadCapability: async () => readCapability(calls),
      evaluate: async (baseRoot, headRoot) => {
        roots.push(baseRoot, headRoot);
        return { status: 'input-configuration-failure', invalid: 'base', diagnostics: [] };
      },
      onEnvelope: (envelope) => { envelopes.push(envelope); },
    });
    const middleware = await app.getNodeMiddleware({ path: '/api/github/webhooks' });
    const server = createServer((request, response) => {
      void middleware(request, response, () => { response.statusCode = 404; response.end(); });
    });
    servers.push(server);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const address = server.address();
    if (address === null || typeof address === 'string') throw new Error('missing test address');

    const body = signedBody();
    const response = await fetch(`http://127.0.0.1:${address.port}/api/github/webhooks`, {
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
    expect(calls).toEqual([
      'pull:19', `commit:${BASE_SHA}`, `commit:${HEAD_SHA}`, `tree:${BASE_TREE}`, `tree:${HEAD_TREE}`, `blob:${BASE_BLOB}`, `blob:${HEAD_BLOB}`, 'pull:19',
    ]);
    expect(envelopes[0]).toMatchObject({
      schemaVersion: 1,
      lifecycle: 'current',
      publishable: true,
      comparison: { repositoryId: 7, pullNumber: 19, baseSha: BASE_SHA, headSha: HEAD_SHA },
    });
    expect(JSON.stringify(envelopes[0])).not.toContain(WEBHOOK_SECRET);
    expect(JSON.stringify(envelopes[0])).not.toContain('event-base-must-not-be-used');
    expect(JSON.stringify(envelopes[0])).not.toContain('export const app');
    expect(roots).toHaveLength(2);
    expect(roots[0]).not.toBe(roots[1]);
    await Promise.all(roots.map(async (root) => expect(access(root)).rejects.toMatchObject({ code: 'ENOENT' })));
  });

  it('rejects a wrong signature before any capability or evaluator invocation', async () => {
    const calls: string[] = [];
    const envelopes: DeliveryEnvelopeV1[] = [];
    const app = createBoundaryCiApp({
      appId: 1,
      privateKey: '-----BEGIN PRIVATE KEY-----\nunused\n-----END PRIVATE KEY-----',
      webhookSecret: WEBHOOK_SECRET,
      createReadCapability: async () => readCapability(calls),
      evaluate: async () => ({ status: 'input-configuration-failure', invalid: 'base', diagnostics: [] }),
      onEnvelope: (envelope) => { envelopes.push(envelope); },
    });
    const middleware = await app.getNodeMiddleware({ path: '/api/github/webhooks' });
    const server = createServer((request, response) => {
      void middleware(request, response, () => { response.statusCode = 404; response.end(); });
    });
    servers.push(server);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const address = server.address();
    if (address === null || typeof address === 'string') throw new Error('missing test address');

    const response = await fetch(`http://127.0.0.1:${address.port}/api/github/webhooks`, {
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
    expect(calls).toEqual([]);
    expect(envelopes).toEqual([]);
  });

  it('suppresses handoff on immutable-object mismatch, final comparison drift, and cleanup failure', async () => {
    const trigger = { deliveryId: 'delivery-direct', installationId: 42, repositoryId: 7, pullNumber: 19 };
    const evaluate = async (): Promise<LocalComparisonResult> => ({
      status: 'input-configuration-failure',
      invalid: 'base',
      diagnostics: [],
    });

    const mismatchCalls: string[] = [];
    const mismatchCapability = readCapability(mismatchCalls);
    mismatchCapability.getCommit = async (sha) => ({ sha: HEAD_SHA, treeSha: sha === BASE_SHA ? BASE_TREE : HEAD_TREE });
    await expect(handleVerifiedTrigger(trigger, { createReadCapability: async () => mismatchCapability, evaluate })).resolves.toMatchObject({
      lifecycle: 'runtime-failure',
      publishable: false,
    });

    const driftCalls: string[] = [];
    const driftCapability = readCapability(driftCalls);
    let pullReads = 0;
    const originalCurrentPull = driftCapability.getCurrentPull;
    driftCapability.getCurrentPull = async (number) => {
      const current = await originalCurrentPull(number);
      pullReads += 1;
      return pullReads === 2 ? { ...current, head: { ...current.head, sha: '1'.repeat(40) } } : current;
    };
    await expect(handleVerifiedTrigger(trigger, { createReadCapability: async () => driftCapability, evaluate })).resolves.toMatchObject({
      lifecycle: 'stale',
      publishable: false,
    });

    const cleanupCalls: string[] = [];
    const cleanupCapability = readCapability(cleanupCalls);
    let cleanupCount = 0;
    await expect(
      handleVerifiedTrigger(
        trigger,
        { createReadCapability: async () => cleanupCapability, evaluate },
        {
          cleanupRoot: async (root) => {
            cleanupCount += 1;
            await rm(root, { force: true, recursive: true });
            return cleanupCount !== 1;
          },
        },
      ),
    ).resolves.toMatchObject({ lifecycle: 'cleanup-failure', publishable: false });
  });
});
