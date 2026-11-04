import { constants as fileConstants } from 'node:fs';
import { open } from 'node:fs/promises';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { Socket } from 'node:net';
import { pathToFileURL } from 'node:url';

import type { LocalComparisonEvaluator } from './evaluate.js';
import type { CheckCoordinator } from './check-coordinator.js';
import type { DeliveryCoordinator } from './coordinator.js';
import { createBoundaryCiApp } from './app.js';
import type { DeliveryLogSink } from './logging.js';

const WEBHOOK_PATH = '/api/github/webhooks';
const HEALTH_PATH = '/healthz';
const HEALTH_BODY = '{"status":"ok"}';
const NOT_FOUND_BODY = '{"error":"not-found"}';
const PAYLOAD_TOO_LARGE_BODY = '{"error":"payload-too-large"}';
/**
 * GitHub caps webhook payloads at 25 MB, so a larger request cannot be a genuine delivery. The
 * bound is enforced before signature verification because the verifier needs the whole body.
 */
const MAX_WEBHOOK_BODY_BYTES = 25 * 1024 * 1024;
const DEFAULT_SHUTDOWN_TIMEOUT_MILLISECONDS = 10_000;

export type ServerConfigErrorCode = 'app-id' | 'private-key-path' | 'private-key-file' | 'webhook-secret' | 'port';

/** A stable configuration failure that never interpolates an environment value or file path. */
export class ServerConfigError extends Error {
  readonly name = 'ServerConfigError';

  constructor(readonly code: ServerConfigErrorCode) {
    super(`server-config:${code}`);
  }

  toJSON(): { code: ServerConfigErrorCode } {
    return { code: this.code };
  }
}

export interface BoundaryCiServerConfig {
  appId: number;
  privateKey: string;
  webhookSecret: string;
  port: number;
}

export interface BoundaryCiServerAddress {
  host: '0.0.0.0';
  port: number;
}

export interface BoundaryCiServer {
  readonly listening: boolean;
  listen(): Promise<BoundaryCiServerAddress>;
  shutdown(): Promise<void>;
}

interface SignalSource {
  on(event: 'SIGINT' | 'SIGTERM', listener: () => void): unknown;
  off(event: 'SIGINT' | 'SIGTERM', listener: () => void): unknown;
}

export interface CreateBoundaryCiServerOptions {
  /** A port override exists only so the test harness can request an ephemeral bind. */
  bindPort?: number;
  shutdownTimeoutMilliseconds?: number;
  evaluator?: LocalComparisonEvaluator;
  coordinator?: DeliveryCoordinator;
  checkCoordinator?: CheckCoordinator;
  logSink?: DeliveryLogSink;
  onStopped?(): void;
}

export interface StartBoundaryCiServerOptions extends Omit<CreateBoundaryCiServerOptions, 'onStopped'> {
  signalSource?: SignalSource;
}

function positiveInteger(value: string | undefined, maximum: number): number | null {
  if (value === undefined || !/^[1-9][0-9]*$/u.test(value)) return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed <= maximum ? parsed : null;
}

function boundedSecret(value: string | undefined): value is string {
  return value !== undefined && value.length > 0 && value.length <= 4_096 && !value.includes('\0');
}

async function loadPrivateKey(path: string): Promise<string> {
  let handle;
  try {
    handle = await open(path, fileConstants.O_RDONLY | fileConstants.O_NOFOLLOW);
    const details = await handle.stat();
    if (!details.isFile() || details.size <= 0 || details.size > 1_048_576) throw new ServerConfigError('private-key-file');
    const value = await handle.readFile({ encoding: 'utf8' });
    if (!boundedSecret(value)) throw new ServerConfigError('private-key-file');
    return value;
  } catch (error) {
    if (error instanceof ServerConfigError) throw error;
    throw new ServerConfigError('private-key-file');
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

/** Loads only the four required runtime settings and never embeds their values in failures. */
export async function loadServerConfig(
  environment: Readonly<Record<string, string | undefined>> = process.env,
): Promise<BoundaryCiServerConfig> {
  const appId = positiveInteger(environment.APP_ID, Number.MAX_SAFE_INTEGER);
  if (appId === null) throw new ServerConfigError('app-id');
  const privateKeyPath = environment.PRIVATE_KEY_PATH;
  if (!boundedSecret(privateKeyPath) || privateKeyPath.trim().length === 0) throw new ServerConfigError('private-key-path');
  if (!boundedSecret(environment.WEBHOOK_SECRET)) throw new ServerConfigError('webhook-secret');
  const port = positiveInteger(environment.PORT, 65_535);
  if (port === null) throw new ServerConfigError('port');
  const privateKey = await loadPrivateKey(privateKeyPath);
  return Object.freeze({ appId, privateKey, webhookSecret: environment.WEBHOOK_SECRET, port });
}

function writeJson(response: ServerResponse, statusCode: number, body: string): void {
  response.writeHead(statusCode, {
    'cache-control': 'no-store',
    'content-length': Buffer.byteLength(body),
    'content-type': 'application/json; charset=utf-8',
  });
  response.end(body);
}

/** Answers 413 once, closes the connection, and stops reading an over-bound webhook request. */
function rejectOversizedWebhook(request: IncomingMessage, response: ServerResponse): void {
  if (!response.headersSent) {
    response.setHeader('connection', 'close');
    writeJson(response, 413, PAYLOAD_TOO_LARGE_BODY);
  }
  response.once('finish', () => { request.destroy(); });
}

/**
 * Buffers one webhook request body up to {@link MAX_WEBHOOK_BODY_BYTES} before Probot's
 * middleware sees it. The exact received bytes are then handed over as `rawBody`, which
 * `@octokit/webhooks` verifies in place of reading the stream itself, so signature
 * verification still covers the original request bytes. An over-bound body never reaches the
 * middleware and is never retained.
 */
function bufferBoundedWebhook(
  request: IncomingMessage,
  response: ServerResponse,
  handOff: (request: IncomingMessage) => void,
): void {
  const declared = request.headers['content-length'];
  if (declared !== undefined && Number(declared) > MAX_WEBHOOK_BODY_BYTES) {
    rejectOversizedWebhook(request, response);
    return;
  }
  const chunks: Buffer[] = [];
  let received = 0;
  let rejected = false;
  request.on('data', (chunk: Buffer) => {
    if (rejected) return;
    received += chunk.byteLength;
    if (received > MAX_WEBHOOK_BODY_BYTES) {
      rejected = true;
      chunks.length = 0;
      rejectOversizedWebhook(request, response);
      return;
    }
    chunks.push(chunk);
  });
  request.on('error', () => {
    rejected = true;
    chunks.length = 0;
  });
  request.on('end', () => {
    if (rejected) return;
    const rawBody = Buffer.concat(chunks, received);
    chunks.length = 0;
    Object.defineProperties(request, {
      body: { value: Object.freeze({}), enumerable: false },
      rawBody: { value: rawBody, enumerable: false },
    });
    handOff(request);
  });
}

function assertRuntimeConfig(config: BoundaryCiServerConfig): void {
  if (!Number.isSafeInteger(config.appId) || config.appId < 1) throw new ServerConfigError('app-id');
  if (!boundedSecret(config.privateKey)) throw new ServerConfigError('private-key-file');
  if (!boundedSecret(config.webhookSecret)) throw new ServerConfigError('webhook-secret');
  if (!Number.isSafeInteger(config.port) || config.port < 1 || config.port > 65_535) throw new ServerConfigError('port');
}

/** Creates the fixed HTTP surface around the real Probot middleware without starting a listener. */
export async function createBoundaryCiServer(
  config: BoundaryCiServerConfig,
  options: CreateBoundaryCiServerOptions = {},
): Promise<BoundaryCiServer> {
  assertRuntimeConfig(config);
  const bindPort = options.bindPort ?? config.port;
  if (!Number.isSafeInteger(bindPort) || bindPort < 0 || bindPort > 65_535) throw new ServerConfigError('port');
  const shutdownTimeout = options.shutdownTimeoutMilliseconds ?? DEFAULT_SHUTDOWN_TIMEOUT_MILLISECONDS;
  if (!Number.isSafeInteger(shutdownTimeout) || shutdownTimeout < 1 || shutdownTimeout > DEFAULT_SHUTDOWN_TIMEOUT_MILLISECONDS) {
    throw new TypeError('server shutdown timeout is invalid');
  }
  const app = createBoundaryCiApp({
    appId: config.appId,
    privateKey: config.privateKey,
    webhookSecret: config.webhookSecret,
    ...(options.evaluator === undefined ? {} : { evaluator: options.evaluator }),
    ...(options.coordinator === undefined ? {} : { coordinator: options.coordinator }),
    ...(options.checkCoordinator === undefined ? { enableCheckPublication: true } : { checkCoordinator: options.checkCoordinator }),
    ...(options.logSink === undefined ? {} : { logSink: options.logSink }),
  });
  const middleware = await app.getNodeMiddleware({ path: WEBHOOK_PATH });
  const sockets = new Set<Socket>();
  const server: Server = createServer((request, response) => {
    if (request.method === 'GET' && request.url === HEALTH_PATH) {
      writeJson(response, 200, HEALTH_BODY);
      return;
    }
    if (request.method === 'POST' && request.url === WEBHOOK_PATH) {
      bufferBoundedWebhook(request, response, (buffered) => {
        void middleware(buffered, response, () => writeJson(response, 404, NOT_FOUND_BODY));
      });
      return;
    }
    writeJson(response, 404, NOT_FOUND_BODY);
  });
  server.on('connection', (socket) => {
    sockets.add(socket);
    socket.on('error', () => undefined);
    socket.once('close', () => { sockets.delete(socket); });
  });
  server.on('clientError', (_error, socket) => {
    if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
  });

  let address: BoundaryCiServerAddress | undefined;
  let shutdownPromise: Promise<void> | undefined;
  let stopped = false;
  const stopOnce = (): void => {
    if (stopped) return;
    stopped = true;
    options.onStopped?.();
  };
  const service: BoundaryCiServer = {
    get listening(): boolean { return server.listening; },
    async listen() {
      if (address !== undefined || server.listening) throw new TypeError('server listener already started');
      await new Promise<void>((resolve, reject) => {
        const onError = (): void => reject(new TypeError('server listener failed'));
        server.once('error', onError);
        server.listen(bindPort, '0.0.0.0', () => {
          server.off('error', onError);
          resolve();
        });
      });
      const bound = server.address();
      if (bound === null || typeof bound === 'string') throw new TypeError('server listener address is invalid');
      address = Object.freeze({ host: '0.0.0.0', port: bound.port });
      return address;
    },
    shutdown() {
      if (shutdownPromise !== undefined) return shutdownPromise;
      shutdownPromise = (async () => {
        let timeout: NodeJS.Timeout | undefined;
        const closed = new Promise<void>((resolve) => {
          if (!server.listening) { resolve(); return; }
          server.close(() => resolve());
        });
        const completedBeforeDeadline = await Promise.race([
          closed.then(() => true),
          new Promise<false>((resolve) => { timeout = setTimeout(() => resolve(false), shutdownTimeout); }),
        ]);
        if (timeout !== undefined) clearTimeout(timeout);
        if (!completedBeforeDeadline) {
          for (const socket of sockets) socket.destroy();
          server.closeAllConnections();
        }
        stopOnce();
      })();
      return shutdownPromise;
    },
  };
  return Object.freeze(service);
}

/** Loads runtime configuration, starts the listener, and owns idempotent signal cleanup. */
export async function startBoundaryCiServer(
  environment: Readonly<Record<string, string | undefined>> = process.env,
  options: StartBoundaryCiServerOptions = {},
): Promise<BoundaryCiServer> {
  const signalSource = options.signalSource ?? process as SignalSource;
  let cleaned = false;
  let onSignal: () => void = () => undefined;
  const cleanupSignals = (): void => {
    if (cleaned) return;
    cleaned = true;
    signalSource.off('SIGINT', onSignal);
    signalSource.off('SIGTERM', onSignal);
  };
  const { signalSource: _signalSource, ...createOptions } = options;
  const service = await createBoundaryCiServer(await loadServerConfig(environment), { ...createOptions, onStopped: cleanupSignals });
  onSignal = () => { void service.shutdown().catch(() => { process.exitCode = 1; }); };
  signalSource.on('SIGINT', onSignal);
  signalSource.on('SIGTERM', onSignal);
  try {
    await service.listen();
    return service;
  } catch (error) {
    cleanupSignals();
    throw error;
  }
}

const invokedPath = process.argv[1];
if (invokedPath !== undefined && import.meta.url === pathToFileURL(invokedPath).href) {
  void startBoundaryCiServer().catch((error: unknown) => {
    const code = error instanceof ServerConfigError ? error.code : 'startup';
    process.stderr.write(`boundaryci-server:${code}\n`);
    process.exitCode = 1;
  });
}
