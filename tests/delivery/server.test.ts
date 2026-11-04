import { generateKeyPairSync } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { mkdtemp, mkdir, rm, symlink, writeFile } from 'node:fs/promises';
import { request as httpRequest } from 'node:http';
import { createConnection } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { createCheckCoordinator, type CurrentPullFreshnessReader } from '../../src/delivery/check-coordinator.js';
import type { CompletedCheckPayloadV1 } from '../../src/delivery/check-contract.js';
import type { CheckPublisher } from '../../src/delivery/check-publish.js';
import {
  createBoundaryCiServer,
  loadServerConfig,
  ServerConfigError,
  startBoundaryCiServer,
  type BoundaryCiServer,
  type BoundaryCiServerConfig,
} from '../../src/delivery/server.js';
import { evaluateLocalComparison } from '../../src/runtime/evaluate.js';
import { DELIVERY_FIXTURES, currentPull } from './fixtures/index.js';
import { acquireDeliveryFetchScope, createDeliveryCaseSentinels, signOriginalWebhookBody } from './support.js';

const READ_SOURCE = "import { Octokit } from 'octokit';\nconst client = new Octokit();\nclient.rest.issues.listForRepo({});\n";
const WRITE_SOURCE = "import { Octokit } from 'octokit';\nconst client = new Octokit();\nclient.rest.issues.create({});\n";

let temporaryDirectory = '';
let privateKeyPath = '';
let privateKeyValue = '';
let releaseFetchScope: (() => void) | undefined;
const services: BoundaryCiServer[] = [];

beforeAll(async () => {
  temporaryDirectory = await mkdtemp(join(tmpdir(), 'boundaryci-server-test-'));
  privateKeyPath = join(temporaryDirectory, 'app-private-key.pem');
  privateKeyValue = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey
    .export({ format: 'pem', type: 'pkcs8' })
    .toString();
  await writeFile(privateKeyPath, privateKeyValue, { mode: 0o600 });
});

beforeEach(async () => {
  releaseFetchScope = await acquireDeliveryFetchScope();
});

afterEach(async () => {
  await Promise.all(services.splice(0).map(async (service) => service.shutdown()));
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  releaseFetchScope?.();
  releaseFetchScope = undefined;
});

afterAll(async () => {
  await rm(temporaryDirectory, { recursive: true, force: true });
});

function environment(overrides: Record<string, string | undefined> = {}): Record<string, string | undefined> {
  return {
    APP_ID: '1234',
    PRIVATE_KEY_PATH: privateKeyPath,
    WEBHOOK_SECRET: 'server-webhook-secret',
    PORT: '3000',
    ...overrides,
  };
}

function config(webhookSecret = 'server-webhook-secret'): BoundaryCiServerConfig {
  return Object.freeze({ appId: 1234, privateKey: privateKeyValue, webhookSecret, port: 3000 });
}

async function listen(
  runtimeConfig: BoundaryCiServerConfig,
  options: Parameters<typeof createBoundaryCiServer>[1] = {},
): Promise<{ service: BoundaryCiServer; origin: string }> {
  const service = await createBoundaryCiServer(runtimeConfig, { ...options, bindPort: 0 });
  services.push(service);
  const address = await service.listen();
  return { service, origin: `http://127.0.0.1:${address.port}` };
}

async function stableConfigFailure(
  runtimeEnvironment: Record<string, string | undefined>,
  expectedCode: ServerConfigError['code'],
  sentinels: readonly string[] = [],
): Promise<void> {
  let observed: unknown;
  try {
    await loadServerConfig(runtimeEnvironment);
  } catch (error) {
    observed = error;
  }
  expect(observed).toBeInstanceOf(ServerConfigError);
  expect(observed).toMatchObject({ message: `server-config:${expectedCode}`, code: expectedCode });
  const publicObservation = JSON.stringify({
    message: (observed as Error).message,
    json: (observed as ServerConfigError).toJSON(),
  });
  for (const sentinel of sentinels) expect(publicObservation).not.toContain(sentinel);
}

type CheckStore = CheckPublisher & CurrentPullFreshnessReader & {
  readonly created: CompletedCheckPayloadV1[];
  readonly calls: string[];
};

function checkStore(): CheckStore {
  const created: CompletedCheckPayloadV1[] = [];
  const calls: string[] = [];
  return Object.freeze({
    created,
    calls,
    async getCurrentPull(pullNumber: number) {
      calls.push(`fresh:${pullNumber}`);
      return currentPull({ number: pullNumber });
    },
    async lookupExact() {
      calls.push('lookup');
      return Object.freeze([]);
    },
    async create(payload: CompletedCheckPayloadV1) {
      calls.push('create');
      created.push(payload);
      return Object.freeze({ id: 101 });
    },
    async update(checkId: number) {
      calls.push('update');
      return Object.freeze({ id: checkId });
    },
  });
}

function testCheckCoordinator() {
  const store = checkStore();
  return createCheckCoordinator({ appId: 1234, freshness: store, publisher: store });
}

function signedPullRequestBody(rawPayloadSentinel: string): string {
  return JSON.stringify({
    boundaryci_test_ignored: rawPayloadSentinel,
    action: 'opened',
    installation: { id: DELIVERY_FIXTURES.installationId },
    repository: { id: DELIVERY_FIXTURES.repositoryId, name: 'target', owner: { login: 'owner' } },
    pull_request: {
      number: DELIVERY_FIXTURES.pullNumber,
      base: {
        ref: 'main',
        sha: 'event-base-not-authoritative',
        repo: { id: DELIVERY_FIXTURES.repositoryId },
      },
      head: { sha: 'event-head-not-authoritative', repo: { id: DELIVERY_FIXTURES.repositoryId } },
    },
  });
}

function installGitHubReadTransport(installationToken: string): void {
  const nativeFetch = globalThis.fetch;
  vi.stubGlobal('fetch', async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : input.toString());
    if (url.hostname === '127.0.0.1') return nativeFetch(input, init);
    if (url.pathname === `/app/installations/${DELIVERY_FIXTURES.installationId}/access_tokens`) {
      const rawBody = input instanceof Request
        ? await input.clone().text()
        : typeof init?.body === 'string'
          ? init.body
          : '{}';
      const request = JSON.parse(rawBody) as { repository_ids?: unknown; permissions?: Record<string, string> };
      expect(request.repository_ids).toEqual([DELIVERY_FIXTURES.repositoryId]);
      expect(request.permissions).toEqual({ contents: 'read', pull_requests: 'read' });
      return new Response(JSON.stringify({
        token: installationToken,
        expires_at: '2099-01-01T00:00:00Z',
        repositories: [{ id: DELIVERY_FIXTURES.repositoryId, name: 'target' }],
        repository_selection: 'selected',
        permissions: { ...request.permissions, metadata: 'read' },
      }), { status: 201, headers: { 'content-type': 'application/json' } });
    }
    if (url.pathname === `/repos/owner/target/pulls/${DELIVERY_FIXTURES.pullNumber}`) {
      const pull = currentPull();
      return new Response(JSON.stringify({
        number: pull.number,
        state: pull.state,
        draft: pull.draft,
        merged: pull.merged,
        base: { repo: { id: pull.base.repositoryId }, ref: pull.base.ref, sha: pull.base.sha },
        head: { repo: { id: pull.head.repositoryId }, sha: pull.head.sha },
      }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    const commit = /^\/repos\/owner\/target\/git\/commits\/([a-f0-9]{40})$/u.exec(url.pathname);
    if (commit !== null) {
      return new Response(JSON.stringify({
        sha: commit[1],
        tree: { sha: commit[1] === DELIVERY_FIXTURES.baseSha ? DELIVERY_FIXTURES.baseTreeSha : DELIVERY_FIXTURES.headTreeSha },
      }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    const tree = /^\/repos\/owner\/target\/git\/trees\/([a-f0-9]{40})$/u.exec(url.pathname);
    if (tree !== null) {
      const isBase = tree[1] === DELIVERY_FIXTURES.baseTreeSha;
      const source = isBase ? READ_SOURCE : WRITE_SOURCE;
      return new Response(JSON.stringify({
        sha: tree[1],
        tree: [{
          path: 'src/app.ts',
          mode: '100644',
          type: 'blob',
          sha: isBase ? DELIVERY_FIXTURES.baseBlobSha : DELIVERY_FIXTURES.headBlobSha,
          size: Buffer.byteLength(source),
        }],
      }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    const blob = /^\/repos\/owner\/target\/git\/blobs\/([a-f0-9]{40})$/u.exec(url.pathname);
    if (blob !== null) {
      const source = blob[1] === DELIVERY_FIXTURES.baseBlobSha ? READ_SOURCE : WRITE_SOURCE;
      return new Response(JSON.stringify({
        sha: blob[1],
        encoding: 'base64',
        content: Buffer.from(source).toString('base64'),
        size: Buffer.byteLength(source),
      }), { status: 200, headers: { 'content-type': 'application/json' } });
    }
    return new Response('{"code":"unexpected-route"}', {
      status: 404,
      headers: { 'content-type': 'application/json' },
    });
  });
}

describe('production server configuration', () => {
  it('loads exactly the bounded runtime settings and the private-key file', async () => {
    await expect(loadServerConfig(environment({ IGNORED_PROCESS_SETTING: 'unrelated' }))).resolves.toEqual({
      appId: 1234,
      privateKey: privateKeyValue,
      webhookSecret: 'server-webhook-secret',
      port: 3000,
    });
  });

  it.each([
    ['missing APP_ID', { APP_ID: undefined }, 'app-id'],
    ['zero APP_ID', { APP_ID: '0' }, 'app-id'],
    ['signed APP_ID', { APP_ID: '+1' }, 'app-id'],
    ['fractional APP_ID', { APP_ID: '1.5' }, 'app-id'],
    ['unsafe APP_ID', { APP_ID: '9007199254740992' }, 'app-id'],
    ['missing private key path', { PRIVATE_KEY_PATH: undefined }, 'private-key-path'],
    ['blank private key path', { PRIVATE_KEY_PATH: '   ' }, 'private-key-path'],
    ['missing webhook secret', { WEBHOOK_SECRET: undefined }, 'webhook-secret'],
    ['empty webhook secret', { WEBHOOK_SECRET: '' }, 'webhook-secret'],
    ['NUL webhook secret', { WEBHOOK_SECRET: 'bad\0secret' }, 'webhook-secret'],
    ['missing PORT', { PORT: undefined }, 'port'],
    ['zero PORT', { PORT: '0' }, 'port'],
    ['fractional PORT', { PORT: '3000.5' }, 'port'],
    ['large PORT', { PORT: '65536' }, 'port'],
  ] as const)('rejects %s with only its stable field code', async (_name, override, code) => {
    const sentinels = ['9007199254740992', 'bad\0secret', privateKeyPath, privateKeyValue];
    await stableConfigFailure(environment(override), code, sentinels);
  });

  it('rejects missing, directory, symlink, empty, and oversized private-key files without revealing paths', async () => {
    const directoryPath = join(temporaryDirectory, 'not-a-key-directory');
    const symlinkPath = join(temporaryDirectory, 'key-link.pem');
    const emptyPath = join(temporaryDirectory, 'empty.pem');
    const oversizedPath = join(temporaryDirectory, 'oversized.pem');
    await mkdir(directoryPath);
    await symlink(privateKeyPath, symlinkPath);
    await writeFile(emptyPath, '');
    await writeFile(oversizedPath, 'x'.repeat(4_097));
    for (const path of [join(temporaryDirectory, 'missing.pem'), directoryPath, symlinkPath, emptyPath, oversizedPath]) {
      await stableConfigFailure(environment({ PRIVATE_KEY_PATH: path }), 'private-key-file', [path, privateKeyPath]);
    }
  });

  it.each([
    [{ appId: 0 }, 'app-id'],
    [{ privateKey: '' }, 'private-key-file'],
    [{ webhookSecret: '' }, 'webhook-secret'],
    [{ port: 65_536 }, 'port'],
  ] as const)('rejects invalid programmatic config with the matching field code', async (override, code) => {
    await expect(createBoundaryCiServer({ ...config(), ...override })).rejects.toMatchObject({ code });
  });
});

describe('production HTTP surface', () => {
  it('serves exact source-free health bytes and fixed 404 responses everywhere else', async () => {
    const { origin } = await listen(config(), { checkCoordinator: testCheckCoordinator() });
    const health = await fetch(`${origin}/healthz`);
    expect({ status: health.status, type: health.headers.get('content-type'), cache: health.headers.get('cache-control') })
      .toEqual({ status: 200, type: 'application/json; charset=utf-8', cache: 'no-store' });
    expect(await health.text()).toBe('{"status":"ok"}');

    for (const [method, path] of [
      ['GET', '/'],
      ['POST', '/healthz'],
      ['GET', '/api/github/webhooks'],
      ['POST', '/api/github/webhooks/'],
      ['GET', '/diagnostics'],
    ] as const) {
      const response = await fetch(`${origin}${path}`, { method });
      expect(response.status).toBe(404);
      expect(await response.text()).toBe('{"error":"not-found"}');
    }
  });

  it('rejects an invalid signature at the real Probot middleware before coordinator work', async () => {
    const sentinels = createDeliveryCaseSentinels('server-invalid-signature');
    const store = checkStore();
    const coordinator = createCheckCoordinator({ appId: 1234, freshness: store, publisher: store });
    const { origin } = await listen(config(sentinels.webhookSecret!), { checkCoordinator: coordinator });
    const body = signedPullRequestBody(sentinels.rawPayload!);
    const response = await fetch(`${origin}/api/github/webhooks`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-github-delivery': 'server-invalid-signature',
        'x-github-event': 'pull_request',
        'x-hub-signature-256': 'sha256=invalid',
      },
      body,
    });
    expect(response.status).not.toBe(200);
    expect(coordinator.results).toEqual([]);
    expect(store.created).toEqual([]);
    expect(JSON.stringify({ status: response.status, response: await response.text() })).not.toContain(sentinels.rawPayload!);
  });

  it('accepts original signed bytes through the production listener into a real coordinator and fake Check roles', async () => {
    const sentinels = createDeliveryCaseSentinels('server-signed-composition');
    const store = checkStore();
    const coordinator = createCheckCoordinator({ appId: 1234, freshness: store, publisher: store });
    installGitHubReadTransport(sentinels.installationToken!);
    const { origin } = await listen(config(sentinels.webhookSecret!), {
      evaluator: evaluateLocalComparison,
      checkCoordinator: coordinator,
    });
    const body = signedPullRequestBody(sentinels.rawPayload!);
    const response = await fetch(`${origin}/api/github/webhooks`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-github-delivery': 'server-signed-composition',
        'x-github-event': 'pull_request',
        'x-hub-signature-256': signOriginalWebhookBody(sentinels.webhookSecret!, body),
      },
      body,
    });
    expect(response.status).toBe(200);
    await vi.waitFor(() => expect(coordinator.results).toEqual([expect.objectContaining({ status: 'created' })]));
    expect(store.created).toEqual([
      expect.objectContaining({
        conclusion: 'failure',
        headSha: DELIVERY_FIXTURES.headSha,
        name: 'BoundaryCI',
        status: 'completed',
        title: 'Permission expansion requires review',
      }),
    ]);
    expect(store.calls).toEqual(['fresh:19', 'lookup', 'fresh:19', 'create']);
    expect(JSON.stringify({ status: response.status, results: coordinator.results, checks: store.created }))
      .not.toContain(sentinels.installationToken!);
    expect(JSON.stringify({ status: response.status, results: coordinator.results, checks: store.created }))
      .not.toContain(sentinels.rawPayload!);
  });
});

describe('production server shutdown', () => {
  it('handles repeated SIGINT/SIGTERM and shutdown calls once, then removes both listeners', async () => {
    const signalSource = new EventEmitter();
    const service = await startBoundaryCiServer(environment(), {
      bindPort: 0,
      checkCoordinator: testCheckCoordinator(),
      signalSource,
    });
    services.push(service);
    expect(signalSource.listenerCount('SIGINT')).toBe(1);
    expect(signalSource.listenerCount('SIGTERM')).toBe(1);
    signalSource.emit('SIGINT');
    signalSource.emit('SIGTERM');
    await service.shutdown();
    await service.shutdown();
    expect(service.listening).toBe(false);
    expect(signalSource.listenerCount('SIGINT')).toBe(0);
    expect(signalSource.listenerCount('SIGTERM')).toBe(0);
  });

  it('destroys a remaining active socket at the configured deadline and resolves idempotently', async () => {
    const { service, origin } = await listen(config(), {
      checkCoordinator: testCheckCoordinator(),
      shutdownTimeoutMilliseconds: 25,
    });
    const port = Number(new URL(origin).port);
    const socket = createConnection({ host: '127.0.0.1', port });
    socket.on('error', () => undefined);
    socket.resume();
    await new Promise<void>((resolve) => socket.once('connect', resolve));
    socket.write(
      'POST /api/github/webhooks HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{',
    );
    const closed = new Promise<void>((resolve) => socket.once('close', () => resolve()));
    const started = Date.now();
    const first = service.shutdown();
    const second = service.shutdown();
    expect(second).toBe(first);
    await Promise.race([
      first,
      new Promise<never>((_resolve, reject) => setTimeout(() => reject(new Error('shutdown did not meet its deadline')), 500)),
    ]);
    await Promise.race([
      closed,
      new Promise<never>((_resolve, reject) => setTimeout(() => reject(new Error('tracked socket was not destroyed')), 500)),
    ]);
    expect(Date.now() - started).toBeLessThan(1_000);
    expect(service.listening).toBe(false);
  });
});

describe('production webhook body bound', () => {
  // GitHub caps webhook payloads at 25 MB; anything larger cannot be a genuine delivery.
  const WEBHOOK_BODY_LIMIT = 25 * 1024 * 1024;
  const webhookHeaders = {
    'content-type': 'application/json',
    'x-github-delivery': 'server-oversized-body',
    'x-github-event': 'pull_request',
    'x-hub-signature-256': 'sha256=unverified',
  } as const;

  /** Streams `totalBytes` without a declared length; resolves with the status or the transport failure. */
  function streamBody(origin: string, totalBytes: number, headers: Record<string, string>): Promise<number | 'connection-closed'> {
    return new Promise((resolve) => {
      const url = new URL(`${origin}/api/github/webhooks`);
      const outgoing = httpRequest({ host: url.hostname, port: url.port, path: url.pathname, method: 'POST', headers });
      let settled = false;
      const settle = (value: number | 'connection-closed'): void => {
        if (settled) return;
        settled = true;
        resolve(value);
      };
      outgoing.on('response', (response) => {
        response.resume();
        settle(response.statusCode ?? 0);
      });
      outgoing.on('error', () => settle('connection-closed'));
      const chunk = Buffer.alloc(1024 * 1024, 0x20);
      let sent = 0;
      const pump = (): void => {
        while (sent < totalBytes && !settled && !outgoing.destroyed) {
          const size = Math.min(chunk.byteLength, totalBytes - sent);
          sent += size;
          if (!outgoing.write(chunk.subarray(0, size))) {
            outgoing.once('drain', pump);
            return;
          }
        }
        if (!settled && !outgoing.destroyed) outgoing.end();
      };
      pump();
    });
  }

  it('rejects a declared oversized webhook body before buffering it or reaching the middleware', async () => {
    const store = checkStore();
    const coordinator = createCheckCoordinator({ appId: 1234, freshness: store, publisher: store });
    const { origin } = await listen(config(), { checkCoordinator: coordinator });
    const status = await new Promise<number | 'connection-closed'>((resolve) => {
      const url = new URL(`${origin}/api/github/webhooks`);
      const outgoing = httpRequest({
        host: url.hostname, port: url.port, path: url.pathname, method: 'POST',
        headers: { ...webhookHeaders, 'content-length': String(WEBHOOK_BODY_LIMIT + 1) },
      });
      outgoing.on('response', (response) => {
        response.resume();
        resolve(response.statusCode ?? 0);
      });
      outgoing.on('error', () => resolve('connection-closed'));
      // Only a token prefix is sent: the declared length alone must be enough to reject.
      outgoing.write('{}');
    });
    expect(status).toBe(413);
    expect(coordinator.results).toEqual([]);
    expect(store.calls).toEqual([]);
    expect((await fetch(`${origin}/healthz`)).status).toBe(200);
  });

  it('stops buffering an undeclared streamed webhook body at the bound and stays healthy', async () => {
    const store = checkStore();
    const coordinator = createCheckCoordinator({ appId: 1234, freshness: store, publisher: store });
    const { origin } = await listen(config(), { checkCoordinator: coordinator });
    const status = await streamBody(origin, WEBHOOK_BODY_LIMIT + (2 * 1024 * 1024), { ...webhookHeaders, 'transfer-encoding': 'chunked' });
    expect([413, 'connection-closed']).toContain(status);
    expect(coordinator.results).toEqual([]);
    expect(store.calls).toEqual([]);
    expect((await fetch(`${origin}/healthz`)).status).toBe(200);
  });

  it('still hands an in-bound streamed body to signature verification', async () => {
    const store = checkStore();
    const coordinator = createCheckCoordinator({ appId: 1234, freshness: store, publisher: store });
    const { origin } = await listen(config(), { checkCoordinator: coordinator });
    const status = await streamBody(origin, 2 * 1024 * 1024, { ...webhookHeaders, 'transfer-encoding': 'chunked' });
    // The real Probot middleware rejects the unverified signature; the bound did not intervene.
    expect(status).not.toBe(413);
    expect(status).not.toBe(200);
    expect(coordinator.results).toEqual([]);
  });
});
