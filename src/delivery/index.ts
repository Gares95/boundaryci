/**
 * The initial Phase 5 delivery seam.
 *
 * The sole receiving path is Probot's verified webhook middleware.  This module deliberately
 * has no configurable transport: a verified event is only a trigger, and all comparison
 * authority comes from the injected, repository-scoped read capability.  Later Phase 5 plans
 * extract the acquisition and lifecycle mechanics into narrower modules while retaining these
 * exports as the public entrypoint.
 */

import { access, chmod, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, relative } from 'node:path';

import { Probot } from 'probot';

import { evaluateLocalComparison } from '../runtime/evaluate.js';
import type { LocalComparisonResult } from '../runtime/evaluate.js';

const SHA_PATTERN = /^[a-f0-9]{40}$/;
const ROOT_PREFIX = 'boundaryci-delivery-';

/**
 * Probot's default development logger includes webhook error objects, which can retain original
 * untrusted payload bytes. Until the Phase 5 allowlisted operational sink is introduced, the
 * verified transport must therefore use a deliberately silent logger rather than forwarding
 * those objects across the delivery boundary.
 */
const SILENT_PROBOT_LOGGER = {
  child: () => SILENT_PROBOT_LOGGER,
  trace: () => undefined,
  debug: () => undefined,
  info: () => undefined,
  warn: () => undefined,
  error: () => undefined,
  fatal: () => undefined,
} as never;

/** A repository/PR identity that is safe to preserve in delivery evidence. */
export interface ComparisonIdentity {
  installationId: number;
  repositoryId: number;
  pullNumber: number;
  baseRef: string;
  baseSha: string;
  headSha: string;
}

/** The finite, credential-free current PR shape consumed by the delivery coordinator. */
export interface CurrentPull {
  number: number;
  repositoryId: number;
  state: 'open' | 'closed';
  draft: boolean;
  merged: boolean;
  base: { repositoryId: number; ref: string; sha: string };
  head: { repositoryId: number; sha: string };
}

/** A commit response reduced to the immutable identity required by the snapshot path. */
export interface GitCommit {
  sha: string;
  treeSha: string;
}

/** One non-recursive immutable Git tree response. */
export interface GitTree {
  sha: string;
  entries: readonly GitTreeEntry[];
  /** A GitHub response prefix is never a complete tree census. */
  truncated?: boolean;
}

/** One Git tree entry. Snapshot acquisition validates type/mode relationships before selection. */
export interface GitTreeEntry {
  path: string;
  mode: string;
  type: 'blob' | 'tree' | 'commit';
  sha: string;
  size?: number | null;
}

/** One exact base64 Git blob response. */
export interface GitBlob {
  sha: string;
  encoding: 'base64';
  content: string;
  size: number;
}

/**
 * The only GitHub-facing surface that crosses the authentication boundary in this module.
 * It deliberately exposes no token, client, headers, generic request method, or write path.
 */
export interface GitHubReadCapability {
  getCurrentPull(pullNumber: number): Promise<CurrentPull>;
  listOpenPullsByBase(baseRef: string): Promise<readonly CurrentPull[]>;
  getCommit(sha: string): Promise<GitCommit>;
  getTree(sha: string): Promise<GitTree>;
  getBlob(sha: string): Promise<GitBlob>;
}

/** A verified trigger normalized to stable non-secret identity fields only. */
export interface VerifiedPullRequestTrigger {
  deliveryId: string;
  installationId: number;
  repositoryId: number;
  pullNumber: number;
}

export type DeliveryEnvelopeV1 =
  | {
      schemaVersion: 1;
      lifecycle: 'current';
      publishable: true;
      comparison: ComparisonIdentity;
      evaluation: LocalComparisonResult;
    }
  | {
      schemaVersion: 1;
      lifecycle: 'stale' | 'obsolete' | 'acquisition-rejected' | 'cleanup-failure' | 'runtime-failure';
      publishable: false;
      comparison: ComparisonIdentity | null;
      reason: string;
    };

export interface CreateBoundaryCiAppOptions {
  appId: number;
  privateKey: string;
  webhookSecret: string;
  createReadCapability(identity: { installationId: number; repositoryId: number }): Promise<GitHubReadCapability>;
  evaluate?(baseRoot: string, headRoot: string): Promise<LocalComparisonResult>;
  onEnvelope?(envelope: DeliveryEnvelopeV1): void | Promise<void>;
}

interface TriggerDependencies {
  createReadCapability: CreateBoundaryCiAppOptions['createReadCapability'];
  evaluate: (baseRoot: string, headRoot: string) => Promise<LocalComparisonResult>;
}

/**
 * Test-only lifecycle hooks for the retained tracer. Production callers use the frozen default
 * implementation; keeping the hook beside the narrow trigger seam lets tests prove that a
 * cleanup failure suppresses handoff without exposing credentials or a transport alternative.
 */
export interface DeliveryRuntime {
  cleanupRoot(root: string): Promise<boolean>;
}

function isPositiveSafeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0;
}

function isSha(value: unknown): value is string {
  return typeof value === 'string' && SHA_PATTERN.test(value);
}

function isSafeRef(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 256;
}

function assertIdentity(identity: ComparisonIdentity): void {
  if (!isPositiveSafeInteger(identity.installationId)) throw new TypeError('invalid installation identity');
  if (!isPositiveSafeInteger(identity.repositoryId)) throw new TypeError('invalid repository identity');
  if (!isPositiveSafeInteger(identity.pullNumber)) throw new TypeError('invalid pull request identity');
  if (!isSafeRef(identity.baseRef)) throw new TypeError('invalid base target');
  if (!isSha(identity.baseSha) || !isSha(identity.headSha)) throw new TypeError('invalid immutable commit identity');
}

function comparisonFrom(trigger: VerifiedPullRequestTrigger, pull: CurrentPull): ComparisonIdentity {
  const identity: ComparisonIdentity = {
    installationId: trigger.installationId,
    repositoryId: trigger.repositoryId,
    pullNumber: pull.number,
    baseRef: pull.base.ref,
    baseSha: pull.base.sha,
    headSha: pull.head.sha,
  };
  assertIdentity(identity);
  if (pull.repositoryId !== trigger.repositoryId || pull.base.repositoryId !== trigger.repositoryId) {
    throw new TypeError('authenticated pull request base repository does not match the event repository');
  }
  if (pull.head.repositoryId !== trigger.repositoryId) {
    throw new TypeError('external pull request topology is not eligible for acquisition');
  }
  if (pull.number !== trigger.pullNumber) throw new TypeError('authenticated pull request number does not match trigger');
  return Object.freeze(identity);
}

function sameComparison(left: ComparisonIdentity, right: ComparisonIdentity): boolean {
  return (
    left.installationId === right.installationId &&
    left.repositoryId === right.repositoryId &&
    left.pullNumber === right.pullNumber &&
    left.baseRef === right.baseRef &&
    left.baseSha === right.baseSha &&
    left.headSha === right.headSha
  );
}

function lifecycle(
  name: Extract<DeliveryEnvelopeV1, { publishable: false }>['lifecycle'],
  comparison: ComparisonIdentity | null,
  reason: string,
): DeliveryEnvelopeV1 {
  return Object.freeze({ schemaVersion: 1, lifecycle: name, publishable: false, comparison, reason });
}

function validateRelativePath(path: string): void {
  if (path.length === 0 || path.includes('\\') || path.includes('\0') || path.startsWith('/')) {
    throw new TypeError('unsafe Git tree path');
  }
  const components = path.split('/');
  if (components.some((component) => component.length === 0 || component === '.' || component === '..')) {
    throw new TypeError('unsafe Git tree path');
  }
}

function decodeBlob(blob: GitBlob, expectedSha: string, expectedSize: number): Buffer {
  if (blob.sha !== expectedSha || blob.encoding !== 'base64' || !Number.isSafeInteger(blob.size) || blob.size < 0) {
    throw new TypeError('immutable blob response does not match its requested identity');
  }
  const bytes = Buffer.from(blob.content, 'base64');
  if (bytes.byteLength !== blob.size || bytes.byteLength !== expectedSize) {
    throw new TypeError('immutable blob bytes do not match declared size');
  }
  return bytes;
}

async function createPrivateRoot(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), ROOT_PREFIX));
  await chmod(root, 0o700);
  return root;
}

async function writePrivateBlob(root: string, path: string, bytes: Buffer): Promise<void> {
  validateRelativePath(path);
  const destination = join(root, ...path.split('/'));
  const parent = dirname(destination);
  const relativeDestination = relative(root, destination);
  if (relativeDestination === '' || relativeDestination.startsWith('..') || relativeDestination.includes('\\')) {
    throw new TypeError('materialized blob path escapes private root');
  }
  await mkdir(parent, { recursive: true, mode: 0o700 });
  await chmod(parent, 0o700);
  await writeFile(destination, bytes, { encoding: undefined, flag: 'wx', mode: 0o600 });
}

async function materializeSnapshot(capability: GitHubReadCapability, commitSha: string, root: string): Promise<void> {
  const commit = await capability.getCommit(commitSha);
  if (commit.sha !== commitSha || !isSha(commit.treeSha)) throw new TypeError('immutable commit response does not match request');
  const tree = await capability.getTree(commit.treeSha);
  if (tree.sha !== commit.treeSha || !Array.isArray(tree.entries)) throw new TypeError('immutable tree response does not match request');

  const entries = [...tree.entries].sort((left, right) => Buffer.compare(Buffer.from(left.path), Buffer.from(right.path)));
  const paths = new Set<string>();
  for (const entry of entries) {
    validateRelativePath(entry.path);
    if (paths.has(entry.path)) throw new TypeError('immutable tree contains duplicate path');
    paths.add(entry.path);
    if (entry.type !== 'blob' || (entry.mode !== '100644' && entry.mode !== '100755') || !isSha(entry.sha)) {
      throw new TypeError('unsupported immutable tree entry');
    }
    if (!Number.isSafeInteger(entry.size) || entry.size < 0) throw new TypeError('invalid immutable tree entry size');
    const blob = await capability.getBlob(entry.sha);
    await writePrivateBlob(root, entry.path, decodeBlob(blob, entry.sha, entry.size));
  }
}

async function cleanupRoot(root: string): Promise<boolean> {
  try {
    await rm(root, { force: true, recursive: true });
    await access(root);
    return false;
  } catch (error) {
    if (typeof error === 'object' && error !== null && (error as { code?: unknown }).code === 'ENOENT') return true;
    return false;
  }
}

const DEFAULT_RUNTIME: DeliveryRuntime = Object.freeze({ cleanupRoot });

/**
 * Runs the retained verified-trigger path. The webhook body and signature are already confined
 * to Probot at this point; only normalized trigger identifiers cross into the lifecycle.
 */
export async function handleVerifiedTrigger(
  trigger: VerifiedPullRequestTrigger,
  dependencies: TriggerDependencies,
  runtime: DeliveryRuntime = DEFAULT_RUNTIME,
): Promise<DeliveryEnvelopeV1> {
  if (!isPositiveSafeInteger(trigger.installationId) || !isPositiveSafeInteger(trigger.repositoryId) || !isPositiveSafeInteger(trigger.pullNumber)) {
    return lifecycle('acquisition-rejected', null, 'invalid-trigger-identity');
  }

  let comparison: ComparisonIdentity | null = null;
  let baseRoot: string | null = null;
  let headRoot: string | null = null;
  let evaluation: LocalComparisonResult | null = null;

  try {
    const capability = await dependencies.createReadCapability({
      installationId: trigger.installationId,
      repositoryId: trigger.repositoryId,
    });
    const initialPull = await capability.getCurrentPull(trigger.pullNumber);
    if (initialPull.state !== 'open' || initialPull.merged) return lifecycle('obsolete', null, 'pull-request-is-not-open');
    comparison = comparisonFrom(trigger, initialPull);

    baseRoot = await createPrivateRoot();
    headRoot = await createPrivateRoot();
    await Promise.all([
      materializeSnapshot(capability, comparison.baseSha, baseRoot),
      materializeSnapshot(capability, comparison.headSha, headRoot),
    ]);
    evaluation = await dependencies.evaluate(baseRoot, headRoot);

    const baseCleaned = await runtime.cleanupRoot(baseRoot);
    const headCleaned = await runtime.cleanupRoot(headRoot);
    const cleaned = baseCleaned && headCleaned;
    if (!cleaned) {
      // A reported cleanup fault is terminal for publication, but a best-effort trusted cleanup
      // still runs before relinquishing root ownership. The lifecycle remains a failure even
      // when this second removal proves the roots absent.
      await cleanupRoot(baseRoot);
      await cleanupRoot(headRoot);
    }
    baseRoot = null;
    headRoot = null;
    if (!cleaned) return lifecycle('cleanup-failure', comparison, 'private-root-cleanup-not-verified');

    const finalPull = await capability.getCurrentPull(trigger.pullNumber);
    const finalComparison = comparisonFrom(trigger, finalPull);
    if (finalPull.state !== 'open' || finalPull.merged || !sameComparison(comparison, finalComparison)) {
      return lifecycle('stale', comparison, 'authenticated-comparison-drift');
    }
    return Object.freeze({
      schemaVersion: 1,
      lifecycle: 'current',
      publishable: true,
      comparison,
      evaluation: structuredClone(evaluation),
    });
  } catch {
    return lifecycle('runtime-failure', comparison, 'bounded-delivery-operation-failed');
  } finally {
    if (baseRoot !== null) await runtime.cleanupRoot(baseRoot);
    if (headRoot !== null) await runtime.cleanupRoot(headRoot);
  }
}

function triggerFromPayload(payload: unknown, deliveryId: unknown): VerifiedPullRequestTrigger | null {
  if (typeof payload !== 'object' || payload === null || typeof deliveryId !== 'string' || deliveryId.length === 0) return null;
  const value = payload as {
    installation?: { id?: unknown };
    repository?: { id?: unknown };
    pull_request?: { number?: unknown };
  };
  const installationId = value.installation?.id;
  const repositoryId = value.repository?.id;
  const pullNumber = value.pull_request?.number;
  if (!isPositiveSafeInteger(installationId) || !isPositiveSafeInteger(repositoryId) || !isPositiveSafeInteger(pullNumber)) return null;
  return Object.freeze({ deliveryId, installationId, repositoryId, pullNumber });
}

/**
 * Creates the one Probot verified receiving boundary. The custom-transport assumption delta is
 * intentionally `no-change`: callers receive the Probot instance solely to mount its verified
 * Node middleware, and no alternate transport registration is exposed.
 */
export function createBoundaryCiApp(options: CreateBoundaryCiAppOptions): Probot {
  const app = new Probot({
    appId: options.appId,
    privateKey: options.privateKey,
    secret: options.webhookSecret,
    webhookPath: '/api/github/webhooks',
    log: SILENT_PROBOT_LOGGER,
  });
  const evaluate = options.evaluate ?? evaluateLocalComparison;

  app.on('pull_request.opened', async (context) => {
    const trigger = triggerFromPayload(context.payload, context.id);
    const envelope =
      trigger === null
        ? lifecycle('acquisition-rejected', null, 'invalid-verified-trigger')
        : await handleVerifiedTrigger(trigger, { createReadCapability: options.createReadCapability, evaluate });
    await options.onEnvelope?.(envelope);
  });
  return app;
}
