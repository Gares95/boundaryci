import { randomBytes } from 'node:crypto';
import { chmodSync, closeSync, fsyncSync, lstatSync, mkdirSync, mkdtempSync, openSync, readdirSync, readFileSync, realpathSync, renameSync, rmSync, writeSync } from 'node:fs';
import { dirname, join } from 'node:path';

import {
  assertSafeStoreRoot,
  assertSupportedPlatform,
  assertVersionResult,
  capsuleDirectory,
  executeVerified,
  readPinnedFile,
  verifyCapsuleTree,
  verifyTool,
} from './capsule.mjs';
import { assertCapsuleClosure } from './elf.mjs';
import { fail, ToolchainError } from './errors.mjs';
import {
  canonicalJson,
  computeTreeSha256,
  findTool,
  MANIFEST_KIND,
  MANIFEST_PLATFORM,
  MAX_MANIFEST_BYTES,
  parseManifest,
  sha256Hex,
  validateManifest,
  validateToolEntry,
} from './manifest.mjs';

export const REQUEST_KIND = 'boundaryci-toolchain-qualification-request';
const MAX_REQUEST_BYTES = 256 * 1024;
const MAX_SOURCE_BYTES = 512 * 1024 * 1024;

/**
 * Reads an operator-selected host source. A source path may be a distribution symlink such as
 * libz.so.1; the bytes read are those of its resolved regular file, opened without following links.
 *
 * @param {string} from
 */
export function readQualificationSource(from) {
  if (typeof from !== 'string' || !from.startsWith('/')) fail('toolchain/manifest-path', 'qualification sources must be absolute host paths');
  let physical;
  try {
    physical = realpathSync(from);
  } catch {
    fail('toolchain/source-missing', `${from} does not exist`);
  }
  const stats = lstatSync(physical);
  if (!stats.isFile() || stats.size > MAX_SOURCE_BYTES) fail('toolchain/file-type', `${from} is not a bounded regular file`);
  return readPinnedFile(physical, stats);
}

/**
 * @param {unknown} value
 * @param {readonly string[]} keys
 * @param {string} label
 * @returns {asserts value is Record<string, unknown>}
 */
function exactRequestObject(value, keys, label) {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) fail('toolchain/request-schema', `${label} must be an object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) fail('toolchain/request-schema', `${label} has an unexpected key set`);
}

/**
 * Turns one reviewed request into a manifest tool entry by hashing the named sources once.
 * Nothing is executed during qualification.
 *
 * @param {unknown} request
 * @param {readonly import('./manifest.mjs').ToolEntry[]} currentTools
 */
export function qualifyToolEntry(request, currentTools) {
  exactRequestObject(request, ['schemaVersion', 'kind', 'qualifiedOn', 'tool'], 'request');
  if (request.schemaVersion !== 1 || request.kind !== REQUEST_KIND) fail('toolchain/request-schema', 'request header is unsupported');
  exactRequestObject(request.tool, ['id', 'entrypoint', 'files', 'invocation', 'environment', 'pathEntries', 'version'], 'request.tool');
  const spec = request.tool;
  if (!Array.isArray(spec.files) || spec.files.length === 0) fail('toolchain/request-schema', 'request.tool.files must be a non-empty array');

  /** @type {Map<string, Buffer>} */
  const bytesByPath = new Map();
  const files = [];
  const sources = [];
  for (const [index, file] of spec.files.entries()) {
    exactRequestObject(file, ['path', 'from', 'mode'], `request.tool.files[${index}]`);
    if (typeof file.path !== 'string' || bytesByPath.has(file.path)) fail('toolchain/request-schema', `request.tool.files[${index}].path is invalid or duplicated`);
    const bytes = readQualificationSource(/** @type {string} */ (file.from));
    bytesByPath.set(file.path, bytes);
    files.push({ path: file.path, sha256: sha256Hex(bytes), size: bytes.length, mode: file.mode });
    sources.push({ path: file.path, from: file.from });
  }
  const byPath = (/** @type { { path: string } } */ left, /** @type { { path: string } } */ right) => (left.path < right.path ? -1 : left.path > right.path ? 1 : 0);
  files.sort(byPath);
  sources.sort(byPath);

  let invocation = spec.invocation;
  if (typeof invocation === 'object' && invocation !== null && /** @type { { kind?: unknown } } */ (invocation).kind === 'interpreter') {
    exactRequestObject(invocation, ['kind', 'tool', 'script'], 'request.tool.invocation');
    const interpreter = currentTools.find((tool) => tool.id === invocation.tool);
    if (interpreter === undefined) fail('toolchain/request-schema', 'interpreted tools must name an already qualified interpreter');
    invocation = { ...invocation, toolTreeSha256: interpreter.treeSha256 };
  }

  /** @type {Record<string, unknown>} */
  const entry = {
    id: spec.id,
    entrypoint: spec.entrypoint,
    files,
    invocation,
    environment: spec.environment,
    pathEntries: spec.pathEntries,
    version: spec.version,
    qualification: { qualifiedOn: request.qualifiedOn, sources },
  };
  entry.treeSha256 = computeTreeSha256(entry);
  validateToolEntry(entry, `qualified ${String(spec.id)}`);
  assertCapsuleClosure(/** @type {import('./manifest.mjs').ToolEntry} */ (/** @type {unknown} */ (entry)), bytesByPath);
  return /** @type {import('./manifest.mjs').ToolEntry} */ (/** @type {unknown} */ (entry));
}

/**
 * @param {string} manifestPath
 * @returns {Buffer | null}
 */
function readExistingManifest(manifestPath) {
  const stats = lstatSync(manifestPath, { throwIfNoEntry: false });
  if (stats === undefined) return null;
  if (!stats.isFile() || stats.size > MAX_MANIFEST_BYTES) fail('toolchain/manifest-read', 'manifest is not a bounded regular file');
  return readPinnedFile(manifestPath, stats);
}

/**
 * Writes a requalified manifest. Replacing an existing manifest is a compare-and-swap: the caller
 * must name the exact current manifest digest. The result is a candidate for review, never an
 * implicit approval, and no capsule is touched.
 *
 * @param { { manifestPath: string, requests: readonly unknown[], replaceManifestSha256?: string | undefined } } options
 */
export function qualifyTools(options) {
  if (!Array.isArray(options.requests) || options.requests.length === 0) fail('toolchain/usage', 'at least one qualification request is required');
  const existing = readExistingManifest(options.manifestPath);
  const previousManifestSha256 = existing === null ? null : sha256Hex(existing);
  if (existing !== null && options.replaceManifestSha256 === undefined) {
    fail('toolchain/requalify-requires-explicit-replace', 'replacing the approved manifest requires its exact current digest');
  }
  if (options.replaceManifestSha256 !== undefined && options.replaceManifestSha256 !== previousManifestSha256) {
    fail('toolchain/requalify-base-mismatch', 'the named manifest digest is not the current manifest');
  }
  /** @type {import('./manifest.mjs').ToolEntry[]} */
  let tools = existing === null ? [] : JSON.parse(JSON.stringify(parseManifest(existing).manifest.tools));
  const previous = new Map(tools.map((tool) => [tool.id, tool.treeSha256]));
  const qualifiedIds = new Set();
  for (const request of options.requests) {
    const entry = qualifyToolEntry(request, tools);
    if (qualifiedIds.has(entry.id)) fail('toolchain/request-schema', `${entry.id} is qualified twice in one call`);
    qualifiedIds.add(entry.id);
    tools = [...tools.filter((tool) => tool.id !== entry.id), entry].sort((left, right) => (left.id < right.id ? -1 : 1));
  }
  const byId = new Map(tools.map((tool) => [tool.id, tool]));
  for (const tool of tools) {
    if (tool.invocation.kind === 'interpreter' && byId.get(tool.invocation.tool)?.treeSha256 !== tool.invocation.toolTreeSha256) {
      fail('toolchain/requalify-dependent', `${tool.id} must be requalified with its interpreter ${tool.invocation.tool}`);
    }
  }
  const manifest = { schemaVersion: 1, kind: MANIFEST_KIND, platform: MANIFEST_PLATFORM, tools };
  validateManifest(manifest);
  const bytes = Buffer.from(canonicalJson(manifest), 'utf8');

  const temporary = join(dirname(options.manifestPath), `.toolchain-manifest-${randomBytes(8).toString('hex')}.tmp`);
  const descriptor = openSync(temporary, 'wx', 0o644);
  try {
    writeSync(descriptor, bytes);
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
  try {
    const current = readExistingManifest(options.manifestPath);
    if ((current === null ? null : sha256Hex(current)) !== previousManifestSha256) fail('toolchain/requalify-base-mismatch', 'the manifest changed during qualification');
    renameSync(temporary, options.manifestPath);
  } catch (error) {
    rmSync(temporary, { force: true });
    throw error;
  }
  return Object.freeze({
    previousManifestSha256,
    manifestSha256: sha256Hex(bytes),
    changes: Object.freeze(tools
      .filter((tool) => qualifiedIds.has(tool.id))
      .map((tool) => Object.freeze({ id: tool.id, previousTreeSha256: previous.get(tool.id) ?? null, treeSha256: tool.treeSha256 }))),
  });
}

/**
 * @param {string} path
 */
function removeStaging(path) {
  const makeWritable = (/** @type {string} */ current) => {
    const stats = lstatSync(current, { throwIfNoEntry: false });
    if (stats === undefined || !stats.isDirectory() || stats.isSymbolicLink()) return;
    chmodSync(current, 0o700);
    for (const name of readdirSync(current)) makeWritable(join(current, name));
  };
  makeWritable(path);
  rmSync(path, { recursive: true, force: true });
}

/**
 * Materializes one approved tool into the content-addressed store from its recorded sources.
 * Sources must still hash to the approved identity; an existing identity directory is verified
 * and never overwritten.
 *
 * @param { { manifest: import('./manifest.mjs').ToolchainManifest, storeRoot: string, toolId: string, ownerPolicy?: string } } options
 */
export function materializeTool(options) {
  assertSupportedPlatform();
  const policy = options.ownerPolicy ?? 'self-or-root';
  const store = assertSafeStoreRoot(options.storeRoot, policy);
  const tool = findTool(options.manifest, options.toolId);
  const interpreterChain = () => (tool.invocation.kind === 'interpreter'
    ? verifyTool({ manifest: options.manifest, storeRoot: options.storeRoot, toolId: tool.invocation.tool, ownerPolicy: policy })
    : []);
  interpreterChain();

  const toolDirectory = join(store, tool.id);
  if (lstatSync(toolDirectory, { throwIfNoEntry: false }) === undefined) mkdirSync(toolDirectory, { mode: 0o755 });
  const toolStats = lstatSync(toolDirectory);
  if (toolStats.isSymbolicLink() || !toolStats.isDirectory() || (toolStats.mode & 0o022) !== 0) fail('toolchain/store-unsafe', `${tool.id} store directory is not protected`);

  const target = capsuleDirectory(store, tool);
  if (lstatSync(target, { throwIfNoEntry: false }) !== undefined) {
    try {
      verifyTool(options);
    } catch (error) {
      if (error instanceof ToolchainError) fail('toolchain/capsule-conflict', `${tool.id} ${tool.treeSha256} exists but does not verify (${error.code})`);
      throw error;
    }
    return Object.freeze({ status: 'already-materialized', directory: target });
  }

  const staging = mkdtempSync(join(toolDirectory, '.staging-'));
  try {
    const sources = new Map(tool.qualification.sources.map((source) => [source.path, source.from]));
    const directories = new Set();
    for (const file of tool.files) {
      const bytes = readQualificationSource(/** @type {string} */ (sources.get(file.path)));
      if (bytes.length !== file.size || sha256Hex(bytes) !== file.sha256) {
        fail('toolchain/source-drift', `${file.path} source no longer matches the approved identity; requalify explicitly`);
      }
      const destination = join(staging, ...file.path.split('/'));
      mkdirSync(dirname(destination), { recursive: true, mode: 0o700 });
      for (let current = dirname(destination); current.length > staging.length; current = dirname(current)) directories.add(current);
      const descriptor = openSync(destination, 'wx', 0o600);
      try {
        writeSync(descriptor, bytes);
        fsyncSync(descriptor);
      } finally {
        closeSync(descriptor);
      }
      chmodSync(destination, Number.parseInt(file.mode, 8));
    }
    for (const directory of [...directories].sort((left, right) => right.length - left.length)) chmodSync(directory, 0o555);
    chmodSync(staging, 0o555);

    // Probe from the staged tree through the same uncached verify → execute → verify path as `run`.
    const stagedChain = () => {
      const interpreter = interpreterChain();
      verifyCapsuleTree(staging, tool, policy);
      return [...interpreter, Object.freeze({ tool, directory: staging })];
    };
    assertVersionResult(tool, executeVerified(stagedChain, { toolId: tool.id, args: tool.version.args, env: {} }));

    try {
      renameSync(staging, target);
    } catch {
      fail('toolchain/capsule-conflict', `${tool.id} ${tool.treeSha256} appeared during materialization`);
    }
  } catch (error) {
    removeStaging(staging);
    throw error;
  }
  verifyTool(options);
  return Object.freeze({ status: 'materialized', directory: target });
}

/**
 * Informational only: compares qualification sources with the approved identity and lists stale
 * capsules. It never qualifies, materializes, deletes, or changes what `run` executes.
 *
 * @param { { manifest: import('./manifest.mjs').ToolchainManifest, storeRoot?: string | undefined, ownerPolicy?: string } } options
 */
export function driftReport(options) {
  const store = options.storeRoot === undefined ? null : assertSafeStoreRoot(options.storeRoot, options.ownerPolicy ?? 'self-or-root');
  return Object.freeze(options.manifest.tools.map((tool) => {
    const expected = new Map(tool.files.map((file) => [file.path, file.sha256]));
    const sources = tool.qualification.sources.map((source) => {
      let state;
      try {
        state = sha256Hex(readQualificationSource(source.from)) === expected.get(source.path) ? 'unchanged' : 'changed';
      } catch {
        state = 'unavailable';
      }
      return Object.freeze({ path: source.path, from: source.from, state });
    });
    let capsule = 'unknown';
    /** @type {string[]} */
    let stale = [];
    if (store !== null) {
      const toolDirectory = join(store, tool.id);
      const names = lstatSync(toolDirectory, { throwIfNoEntry: false })?.isDirectory() === true ? readdirSync(toolDirectory).sort() : [];
      capsule = names.includes(tool.treeSha256) ? 'present' : 'absent';
      stale = names.filter((name) => name !== tool.treeSha256 && /^[a-f0-9]{64}$/u.test(name));
    }
    return Object.freeze({ id: tool.id, treeSha256: tool.treeSha256, capsule, stale: Object.freeze(stale), sources: Object.freeze(sources) });
  }));
}

/**
 * @param {string} path
 */
export function readRequestFile(path) {
  const stats = lstatSync(path, { throwIfNoEntry: false });
  if (stats === undefined || !stats.isFile() || stats.size > MAX_REQUEST_BYTES) fail('toolchain/request-schema', 'request is not a bounded regular file');
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(readFileSync(path)));
  } catch {
    fail('toolchain/request-schema', 'request is not UTF-8 JSON');
  }
}
