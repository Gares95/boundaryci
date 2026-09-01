import { createHmac } from 'node:crypto';
import { access, mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';

import {
  createBoundaryCiApp,
  handleVerifiedTrigger,
  type DeliveryEnvelopeV1,
  type GitHubReadCapability,
} from '../../src/delivery/index.js';
import type { LocalComparisonResult } from '../../src/runtime/evaluate.js';
import { DELIVERY_FIXTURES } from './fixtures/index.js';
import { AllowlistedSink, createGitHubReadFake, createWebhookHarness, inspectTemporaryParent } from './support.js';

const WEBHOOK_SECRET = 'delivery-webhook-secret-sentinel';
const {
  baseSha: BASE_SHA,
  headSha: HEAD_SHA,
  baseTreeSha: BASE_TREE,
  headTreeSha: HEAD_TREE,
  baseBlobSha: BASE_BLOB,
  headBlobSha: HEAD_BLOB,
} = DELIVERY_FIXTURES;

const harnesses: Array<Awaited<ReturnType<typeof createWebhookHarness>>> = [];

afterEach(async () => {
  await Promise.all(harnesses.splice(0).map((harness) => harness.close()));
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

describe('verified delivery tracer', () => {
  it('accepts only a correctly signed original body and emits a source-free cleanup-gated envelope', async () => {
    const read = createGitHubReadFake();
    const envelopes: DeliveryEnvelopeV1[] = [];
    const roots: string[] = [];
    const app = createBoundaryCiApp({
      appId: 1,
      privateKey: '-----BEGIN PRIVATE KEY-----\nunused\n-----END PRIVATE KEY-----',
      webhookSecret: WEBHOOK_SECRET,
      createReadCapability: async () => read.capability,
      evaluate: async (baseRoot, headRoot) => {
        roots.push(baseRoot, headRoot);
        return { status: 'input-configuration-failure', invalid: 'base', diagnostics: [] };
      },
      onEnvelope: (envelope) => { envelopes.push(envelope); },
    });
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
    expect(read.calls).toEqual([
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
    const read = createGitHubReadFake();
    const envelopes: DeliveryEnvelopeV1[] = [];
    const app = createBoundaryCiApp({
      appId: 1,
      privateKey: '-----BEGIN PRIVATE KEY-----\nunused\n-----END PRIVATE KEY-----',
      webhookSecret: WEBHOOK_SECRET,
      createReadCapability: async () => read.capability,
      evaluate: async () => ({ status: 'input-configuration-failure', invalid: 'base', diagnostics: [] }),
      onEnvelope: (envelope) => { envelopes.push(envelope); },
    });
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

  it('suppresses handoff on immutable-object mismatch, final comparison drift, and cleanup failure', async () => {
    const trigger = { deliveryId: 'delivery-direct', installationId: 42, repositoryId: 7, pullNumber: 19 };
    const evaluate = async (): Promise<LocalComparisonResult> => ({
      status: 'input-configuration-failure',
      invalid: 'base',
      diagnostics: [],
    });

    const mismatchCapability = createGitHubReadFake().capability;
    mismatchCapability.getCommit = async (sha) => ({ sha: HEAD_SHA, treeSha: sha === BASE_SHA ? BASE_TREE : HEAD_TREE });
    await expect(handleVerifiedTrigger(trigger, { createReadCapability: async () => mismatchCapability, evaluate })).resolves.toMatchObject({
      lifecycle: 'runtime-failure',
      publishable: false,
    });

    const driftCapability = createGitHubReadFake().capability;
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

    const cleanupCapability = createGitHubReadFake().capability;
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
