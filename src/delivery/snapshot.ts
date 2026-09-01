import { access, chmod, lstat, mkdir, mkdtemp, open, rm } from 'node:fs/promises';
import { constants } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative } from 'node:path';

import { compileLimitedGlob } from '../analyzer/discovery.js';
import { ANALYZER_SOURCE_EXTENSIONS } from '../analyzer/contract.js';
import { loadSnapshotConfig, selectAuthoritativeConfig } from '../config/load.js';
import type { EffectiveConfig } from '../config/model.js';
import type { GitBlob, GitHubReadCapability, GitTree, GitTreeEntry } from './index.js';
import type { AcquisitionCause, AcquisitionFailureReason, AcquisitionResult, SnapshotIdentity } from './contract.js';
import { DELIVERY_LIMITS_V1, type DeliveryLimits, validateDeliveryLimits } from './limits.js';

const CONFIG_PATH = '.boundaryci.yml';
const ROOT_PREFIX = 'boundaryci-snapshot-';
const SHA = /^[a-f0-9]{40}$/u;

export interface PrivateComparisonRoots {
  base: string;
  head: string;
}

export interface AcquiredComparisonRoots {
  result: AcquisitionResult;
  roots: PrivateComparisonRoots;
}

export interface AcquireComparisonRootsInput {
  capability: GitHubReadCapability;
  baseSha: string;
  headSha: string;
  limits?: DeliveryLimits;
  now?: () => number;
  isCancelled?: () => boolean;
}

interface EntryRecord {
  path: string;
  mode: string;
  type: GitTreeEntry['type'];
  sha: string;
  size: number | null;
}

interface ResolvedCommit {
  commitSha: string;
  treeSha: string;
  rootTree: GitTree;
}

class AcquisitionStop extends Error {
  constructor(
    readonly status: Extract<AcquisitionResult['status'], 'input-configuration-failure' | 'acquisition-security-failure' | 'runtime-infrastructure-failure'>,
    readonly reason: AcquisitionFailureReason,
  ) {
    super(reason);
  }
}

class SafeIncomplete extends Error {
  constructor(readonly cause: AcquisitionCause) {
    super(cause.code);
  }
}

function safeCount(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0;
}

function assertSha(value: unknown, label: string): asserts value is string {
  if (typeof value !== 'string' || !SHA.test(value)) throw new AcquisitionStop('acquisition-security-failure', 'immutable-object-mismatch');
}

function comparePathBytes(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

function assertPath(path: unknown): asserts path is string {
  if (typeof path !== 'string' || path.length === 0 || path.includes('\\') || path.includes('\0') || path.startsWith('/')) {
    throw new AcquisitionStop('acquisition-security-failure', 'unsafe-path');
  }
  if (Buffer.from(path, 'utf8').toString('utf8') !== path) throw new AcquisitionStop('acquisition-security-failure', 'unsafe-path');
  const components = path.split('/');
  if (components.some((component) => component.length === 0 || component === '.' || component === '..')) {
    throw new AcquisitionStop('acquisition-security-failure', 'unsafe-path');
  }
}

function validateEntry(entry: unknown): EntryRecord {
  if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
    throw new AcquisitionStop('acquisition-security-failure', 'malformed-object-relationship');
  }
  const record = entry as Record<string, unknown>;
  assertPath(record.path);
  assertSha(record.sha, 'tree entry SHA');
  if (typeof record.mode !== 'string' || typeof record.type !== 'string') {
    throw new AcquisitionStop('acquisition-security-failure', 'malformed-object-relationship');
  }
  const type = record.type;
  const mode = record.mode;
  const size = record.size;
  if (type === 'blob') {
    if (!['100644', '100755', '120000'].includes(mode) || !safeCount(size)) {
      throw new AcquisitionStop('acquisition-security-failure', 'malformed-object-relationship');
    }
    return { path: record.path, mode, type, sha: record.sha, size };
  }
  if (type === 'tree') {
    if (!['040000', '40000'].includes(mode) || (size !== undefined && size !== null)) {
      throw new AcquisitionStop('acquisition-security-failure', 'malformed-object-relationship');
    }
    return { path: record.path, mode, type, sha: record.sha, size: null };
  }
  if (type === 'commit') {
    if (mode !== '160000' || (size !== undefined && size !== null)) {
      throw new AcquisitionStop('acquisition-security-failure', 'malformed-object-relationship');
    }
    return { path: record.path, mode, type, sha: record.sha, size: null };
  }
  throw new AcquisitionStop('acquisition-security-failure', 'malformed-object-relationship');
}

function validateTree(tree: unknown, expectedSha: string): readonly EntryRecord[] {
  if (typeof tree !== 'object' || tree === null || Array.isArray(tree)) {
    throw new AcquisitionStop('acquisition-security-failure', 'immutable-object-mismatch');
  }
  const response = tree as GitTree;
  if (response.sha !== expectedSha || !Array.isArray(response.entries)) {
    throw new AcquisitionStop('acquisition-security-failure', 'immutable-object-mismatch');
  }
  return response.entries.map(validateEntry).sort((left, right) => comparePathBytes(left.path, right.path));
}

function validateBlob(blob: unknown, expectedSha: string, expectedSize: number): Buffer {
  if (typeof blob !== 'object' || blob === null || Array.isArray(blob)) {
    throw new AcquisitionStop('acquisition-security-failure', 'immutable-object-mismatch');
  }
  const response = blob as GitBlob;
  if (response.sha !== expectedSha || response.encoding !== 'base64' || !safeCount(response.size) || typeof response.content !== 'string') {
    throw new AcquisitionStop('acquisition-security-failure', 'immutable-object-mismatch');
  }
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(response.content)) {
    throw new AcquisitionStop('acquisition-security-failure', 'immutable-object-mismatch');
  }
  const bytes = Buffer.from(response.content, 'base64');
  if (bytes.toString('base64') !== response.content || bytes.byteLength !== response.size || bytes.byteLength !== expectedSize) {
    throw new AcquisitionStop('acquisition-security-failure', 'immutable-object-mismatch');
  }
  return bytes;
}

function relevantSource(path: string, config: EffectiveConfig): boolean {
  if (!ANALYZER_SOURCE_EXTENSIONS.some((extension) => path.endsWith(extension))) return false;
  const includes = config.include.map((pattern) => compileLimitedGlob(pattern));
  const excludes = config.exclude.map((pattern) => compileLimitedGlob(pattern));
  const segments = path.split('/');
  return includes.some((glob) => glob.test(segments)) && !excludes.some((glob) => glob.test(segments));
}

async function createPrivateRoot(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), ROOT_PREFIX));
  await chmod(root, 0o700);
  return root;
}

async function writeVerifiedBlob(root: string, path: string, bytes: Buffer): Promise<void> {
  assertPath(path);
  const destination = join(root, ...path.split('/'));
  const contained = relative(root, destination);
  if (contained === '' || contained.startsWith('..') || contained.includes('\\')) {
    throw new AcquisitionStop('acquisition-security-failure', 'unsafe-path');
  }
  const parent = dirname(destination);
  await mkdir(parent, { recursive: true, mode: 0o700 });
  const segments = contained.split('/');
  let cursor = root;
  for (const segment of segments.slice(0, -1)) {
    cursor = join(cursor, segment);
    const details = await lstat(cursor);
    if (!details.isDirectory() || details.isSymbolicLink()) throw new AcquisitionStop('acquisition-security-failure', 'unsafe-path');
    await chmod(cursor, 0o700);
  }
  const handle = await open(destination, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try {
    await handle.writeFile(bytes);
    await handle.chmod(0o600);
  } finally {
    await handle.close();
  }
}

class Budget {
  readonly started: number;
  treeEntries = 0;
  treeRequests = 0;
  blobRequests = 0;
  work = 0;
  sourceFiles = 0;
  sourceBytes = 0;

  constructor(
    readonly limits: DeliveryLimits,
    readonly now: () => number,
    readonly isCancelled: () => boolean,
  ) {
    this.started = now();
  }

  before(stage: 'request' | 'write'): void {
    if (this.isCancelled()) throw new AcquisitionStop('runtime-infrastructure-failure', 'cancelled');
    const elapsedRaw = this.now() - this.started;
    if (!Number.isFinite(elapsedRaw) || elapsedRaw < 0 || elapsedRaw > Number.MAX_SAFE_INTEGER) {
      throw new AcquisitionStop('runtime-infrastructure-failure', 'invalid-trusted-input');
    }
    // Node's monotonic clock may expose sub-millisecond precision. Limits are integer
    // milliseconds, so count only fully elapsed milliseconds deterministically.
    const elapsed = Math.floor(elapsedRaw);
    if (elapsed > this.limits.maxElapsedMilliseconds) {
      throw new SafeIncomplete({ code: 'elapsed-time-limit', frontier: null, configured: this.limits.maxElapsedMilliseconds, consumed: elapsed });
    }
    this.work += 1;
    if (!Number.isSafeInteger(this.work)) throw new AcquisitionStop('runtime-infrastructure-failure', 'invalid-trusted-input');
    if (this.work > this.limits.maxAcquisitionWork) {
      throw new SafeIncomplete({ code: 'acquisition-work-limit', frontier: null, configured: this.limits.maxAcquisitionWork, consumed: this.work });
    }
    void stage;
  }

  request(kind: 'tree' | 'blob'): void {
    this.before('request');
    if (kind === 'tree') {
      this.treeRequests += 1;
      if (this.treeRequests > this.limits.maxTreeRequests) {
        throw new SafeIncomplete({ code: 'acquisition-work-limit', frontier: null, configured: this.limits.maxTreeRequests, consumed: this.treeRequests });
      }
    } else {
      this.blobRequests += 1;
      if (this.blobRequests > this.limits.maxBlobRequests) {
        throw new SafeIncomplete({ code: 'acquisition-work-limit', frontier: null, configured: this.limits.maxBlobRequests, consumed: this.blobRequests });
      }
    }
  }

  entry(path: string): void {
    this.treeEntries += 1;
    if (this.treeEntries > this.limits.maxTreeEntries) {
      throw new SafeIncomplete({ code: 'tree-entry-limit', frontier: path, configured: this.limits.maxTreeEntries, consumed: this.treeEntries });
    }
  }

  source(path: string, size: number): void {
    if (size > this.limits.maxSourceFileBytes) {
      throw new SafeIncomplete({ code: 'source-file-bytes-limit', frontier: path, configured: this.limits.maxSourceFileBytes, consumed: size });
    }
    this.sourceFiles += 1;
    if (this.sourceFiles > this.limits.maxSourceFiles) {
      throw new SafeIncomplete({ code: 'source-file-limit', frontier: path, configured: this.limits.maxSourceFiles, consumed: this.sourceFiles });
    }
    this.sourceBytes += size;
    if (!Number.isSafeInteger(this.sourceBytes)) throw new AcquisitionStop('runtime-infrastructure-failure', 'invalid-trusted-input');
    if (this.sourceBytes > this.limits.maxTotalSourceBytes) {
      throw new SafeIncomplete({
        code: 'aggregate-source-bytes-limit', frontier: path, configured: this.limits.maxTotalSourceBytes, consumed: this.sourceBytes,
      });
    }
  }
}

async function resolveCommit(
  capability: GitHubReadCapability,
  sha: string,
  budget: Budget,
): Promise<ResolvedCommit> {
  assertSha(sha, 'requested commit SHA');
  budget.before('request');
  const commit = await capability.getCommit(sha);
  if (commit.sha !== sha) throw new AcquisitionStop('acquisition-security-failure', 'immutable-object-mismatch');
  assertSha(commit.treeSha, 'commit tree SHA');
  budget.request('tree');
  const rootTree = await capability.getTree(commit.treeSha);
  if (rootTree.truncated) throw new SafeIncomplete({ code: 'tree-response-truncated', frontier: null, configured: null, consumed: null });
  validateTree(rootTree, commit.treeSha);
  return { commitSha: sha, treeSha: commit.treeSha, rootTree };
}

async function getBlob(capability: GitHubReadCapability, sha: string, size: number, budget: Budget): Promise<Buffer> {
  budget.request('blob');
  return validateBlob(await capability.getBlob(sha), sha, size);
}

async function materializeConfig(
  root: string,
  commit: ResolvedCommit,
  capability: GitHubReadCapability,
  budget: Budget,
): Promise<void> {
  const entries = validateTree(commit.rootTree, commit.treeSha);
  // Count root entries while proving configuration presence/absence. The later full census
  // deliberately does not charge these same immutable entries again.
  for (const entry of entries) budget.entry(entry.path);
  const config = entries.find((entry) => entry.path === CONFIG_PATH);
  if (config === undefined) return;
  if (config.type !== 'blob' || !['100644', '100755'].includes(config.mode) || config.size === null) {
    throw new AcquisitionStop('input-configuration-failure', 'configuration-entry-invalid');
  }
  if (config.size > 256 * 1024) throw new AcquisitionStop('input-configuration-failure', 'configuration-object-invalid');
  const bytes = await getBlob(capability, config.sha, config.size, budget);
  budget.before('write');
  await writeVerifiedBlob(root, CONFIG_PATH, bytes);
}

async function censusEntries(
  capability: GitHubReadCapability,
  commit: ResolvedCommit,
  budget: Budget,
): Promise<readonly EntryRecord[]> {
  const all: EntryRecord[] = [];
  const visit = async (tree: GitTree, expectedTreeSha: string, prefix: string, rootAlreadyCharged: boolean): Promise<void> => {
    if (tree.truncated) throw new SafeIncomplete({ code: 'tree-response-truncated', frontier: prefix || null, configured: null, consumed: null });
    const entries = validateTree(tree, expectedTreeSha);
    for (const entry of entries) {
      const fullPath = prefix === '' ? entry.path : `${prefix}/${entry.path}`;
      assertPath(fullPath);
      if (!rootAlreadyCharged) budget.entry(fullPath);
      all.push({ ...entry, path: fullPath });
      if (entry.type === 'tree') {
        budget.request('tree');
        const child = await capability.getTree(entry.sha);
        await visit(child, entry.sha, fullPath, false);
      }
    }
  };
  await visit(commit.rootTree, commit.treeSha, '', true);
  all.sort((left, right) => comparePathBytes(left.path, right.path));
  let previous: EntryRecord | undefined;
  const seen = new Set<string>();
  for (const entry of all) {
    if (seen.has(entry.path)) throw new AcquisitionStop('acquisition-security-failure', 'malformed-object-relationship');
    seen.add(entry.path);
    if (previous !== undefined && entry.path.startsWith(`${previous.path}/`) && previous.type !== 'tree') {
      throw new AcquisitionStop('acquisition-security-failure', 'malformed-object-relationship');
    }
    previous = entry;
  }
  return all;
}

function unsupportedCause(entry: EntryRecord, config: EffectiveConfig): AcquisitionCause | null {
  const relevant = entry.path === CONFIG_PATH || relevantSource(entry.path, config);
  if (!relevant) return null;
  if (entry.type === 'commit') return { code: 'relevant-gitlink', frontier: entry.path, configured: null, consumed: null };
  if (entry.type === 'blob' && entry.mode === '120000') return { code: 'relevant-symlink', frontier: entry.path, configured: null, consumed: null };
  return { code: 'relevant-unsupported-object', frontier: entry.path, configured: null, consumed: null };
}

async function materializeSources(
  root: string,
  entries: readonly EntryRecord[],
  capability: GitHubReadCapability,
  config: EffectiveConfig,
  budget: Budget,
  causes: AcquisitionCause[],
): Promise<SnapshotIdentity> {
  let sourceFileCount = 0;
  let sourceBytes = 0;
  for (const entry of entries) {
    if (entry.path === CONFIG_PATH) continue;
    if (entry.type !== 'blob' || entry.mode === '120000' || entry.size === null) {
      const cause = unsupportedCause(entry, config);
      if (cause !== null) causes.push(cause);
      continue;
    }
    if (!['100644', '100755'].includes(entry.mode)) throw new AcquisitionStop('acquisition-security-failure', 'malformed-object-relationship');
    if (!relevantSource(entry.path, config)) continue;
    budget.source(entry.path, entry.size);
    const bytes = await getBlob(capability, entry.sha, entry.size as number, budget);
    budget.before('write');
    await writeVerifiedBlob(root, entry.path, bytes);
    sourceFileCount += 1;
    sourceBytes += bytes.byteLength;
  }
  return { commitSha: '', treeSha: '', sourceFileCount, sourceBytes };
}

function failure(status: AcquisitionStop['status'], reason: AcquisitionFailureReason): AcquisitionResult {
  return Object.freeze({ status, reason });
}

function dedupeCauses(causes: readonly AcquisitionCause[]): readonly AcquisitionCause[] {
  const ordered = [...causes].sort((left, right) => {
    const leftKey = `${left.code}\0${left.frontier ?? ''}\0${left.configured ?? ''}\0${left.consumed ?? ''}`;
    const rightKey = `${right.code}\0${right.frontier ?? ''}\0${right.configured ?? ''}\0${right.consumed ?? ''}`;
    return comparePathBytes(leftKey, rightKey);
  });
  const unique: AcquisitionCause[] = [];
  for (const cause of ordered) {
    const previous = unique.at(-1);
    if (
      previous !== undefined &&
      previous.code === cause.code &&
      previous.frontier === cause.frontier &&
      previous.configured === cause.configured &&
      previous.consumed === cause.consumed
    ) continue;
    unique.push(Object.freeze({ ...cause }));
  }
  return Object.freeze(unique);
}

/**
 * Acquires exact Git object snapshots. Returned root paths are an internal lifecycle handle and
 * never form part of the JSON-safe AcquisitionResult evidence.
 */
export async function acquireComparisonRoots(input: AcquireComparisonRootsInput): Promise<AcquiredComparisonRoots> {
  const roots = Object.freeze({ base: await createPrivateRoot(), head: await createPrivateRoot() });
  try {
    assertSha(input.baseSha, 'base commit SHA');
    assertSha(input.headSha, 'head commit SHA');
    const limits = input.limits ?? DELIVERY_LIMITS_V1;
    validateDeliveryLimits(limits);
    const budget = new Budget(limits, input.now ?? (() => performance.now()), input.isCancelled ?? (() => false));
    let base: ResolvedCommit;
    let head: ResolvedCommit;
    try {
      base = await resolveCommit(input.capability, input.baseSha, budget);
      await materializeConfig(roots.base, base, input.capability, budget);
      head = await resolveCommit(input.capability, input.headSha, budget);
      await materializeConfig(roots.head, head, input.capability, budget);
    } catch (error) {
      if (error instanceof SafeIncomplete) return Object.freeze({ result: failure('input-configuration-failure', 'configuration-census-incomplete'), roots });
      throw error;
    }

    const selection = selectAuthoritativeConfig(await loadSnapshotConfig(roots.base), await loadSnapshotConfig(roots.head));
    if (selection.status !== 'selected') return Object.freeze({ result: failure('input-configuration-failure', 'configuration-entry-invalid'), roots });

    const causes: AcquisitionCause[] = [];
    let baseEntries: readonly EntryRecord[] = [];
    let headEntries: readonly EntryRecord[] = [];
    try {
      baseEntries = await censusEntries(input.capability, base, budget);
      headEntries = await censusEntries(input.capability, head, budget);
      const baseIdentity = await materializeSources(roots.base, baseEntries, input.capability, selection.authority.config, budget, causes);
      const headIdentity = await materializeSources(roots.head, headEntries, input.capability, selection.authority.config, budget, causes);
      const snapshots = Object.freeze({
        base: Object.freeze({ ...baseIdentity, commitSha: base.commitSha, treeSha: base.treeSha }),
        head: Object.freeze({ ...headIdentity, commitSha: head.commitSha, treeSha: head.treeSha }),
      });
      if (causes.length === 0) {
        return Object.freeze({ result: Object.freeze({ status: 'complete', config: selection, snapshots, causes: Object.freeze([]), semanticUsability: 'complete' }), roots });
      }
      return Object.freeze({
        result: Object.freeze({
          status: 'incomplete', config: selection, snapshots, causes: dedupeCauses(causes), semanticUsability: 'positive-evidence-only',
          allowedClaims: Object.freeze(['present-observations', 'present-requirements']) as ['present-observations', 'present-requirements'],
        }),
        roots,
      });
    } catch (error) {
      if (error instanceof SafeIncomplete) {
        causes.push(error.cause);
        const snapshots = Object.freeze({
          base: Object.freeze({ commitSha: base.commitSha, treeSha: base.treeSha, sourceFileCount: budget.sourceFiles, sourceBytes: budget.sourceBytes }),
          head: Object.freeze({ commitSha: head.commitSha, treeSha: head.treeSha, sourceFileCount: budget.sourceFiles, sourceBytes: budget.sourceBytes }),
        });
        return Object.freeze({
          result: Object.freeze({
            status: 'incomplete', config: selection, snapshots, causes: dedupeCauses(causes), semanticUsability: 'positive-evidence-only',
            allowedClaims: Object.freeze(['present-observations', 'present-requirements']) as ['present-observations', 'present-requirements'],
          }),
          roots,
        });
      }
      throw error;
    }
  } catch (error) {
    if (error instanceof AcquisitionStop) return Object.freeze({ result: failure(error.status, error.reason), roots });
    return Object.freeze({ result: failure('runtime-infrastructure-failure', 'runtime-operation-failed'), roots });
  }
}

/** Deletes both owned roots and reports absence without exposing or trusting any residue. */
export async function cleanupComparisonRoots(acquired: Pick<AcquiredComparisonRoots, 'roots'>): Promise<boolean> {
  const cleanup = async (root: string): Promise<boolean> => {
    try {
      await rm(root, { recursive: true, force: true });
      await access(root);
      return false;
    } catch (error) {
      return typeof error === 'object' && error !== null && (error as { code?: unknown }).code === 'ENOENT';
    }
  };
  const [base, head] = await Promise.all([cleanup(acquired.roots.base), cleanup(acquired.roots.head)]);
  return base && head;
}
