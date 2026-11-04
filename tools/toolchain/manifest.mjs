import { createHash } from 'node:crypto';

import { fail } from './errors.mjs';

export const MANIFEST_KIND = 'boundaryci-toolchain-manifest';
export const MANIFEST_PLATFORM = 'linux-x64';
export const MAX_MANIFEST_BYTES = 4 * 1024 * 1024;
const MAX_FILES = 4096;
const MAX_TOOLS = 32;
const MAX_ARGS = 32;
const MAX_STRING = 4096;
const SHA256 = /^[a-f0-9]{64}$/u;
const TOOL_ID = /^[a-z][a-z0-9-]{0,31}$/u;
const ENV_NAME = /^[A-Z_][A-Z0-9_]{0,63}$/u;
const DATE = /^\d{4}-\d{2}-\d{2}$/u;
const SEGMENT = /^[A-Za-z0-9._+@-]{1,255}$/u;
export const FILE_MODES = Object.freeze(['0444', '0555']);
const INVOCATION_KINDS = Object.freeze(['direct', 'elf-loader', 'interpreter']);

/** Variables the runner owns or that can redirect native or interpreter loading; never declared or passed. */
export const RESERVED_ENV = /^(?:PATH|LD_[A-Z0-9_]*|GCONV_PATH|LOCPATH|NLSPATH|HOSTALIASES|RESOLV_HOST_CONF|MALLOC_[A-Z0-9_]*|GLIBC_TUNABLES|NODE_OPTIONS|NODE_PATH|NODE_EXTRA_CA_CERTS|COREPACK_[A-Z0-9_]*|BASH_ENV|ENV|IFS|PS4|SHELLOPTS)$/u;

/**
 * @param {Buffer | string} bytes
 */
export function sha256Hex(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

/**
 * @param {unknown} value
 * @returns {unknown}
 */
function sortKeys(value) {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (typeof value === 'object' && value !== null) {
    /** @type {Record<string, unknown>} */
    const sorted = {};
    for (const key of Object.keys(value).sort((left, right) => (left < right ? -1 : left > right ? 1 : 0))) {
      sorted[key] = sortKeys(/** @type {Record<string, unknown>} */ (value)[key]);
    }
    return sorted;
  }
  return value;
}

/** Canonical bytes: recursively sorted keys, two-space indentation, one final LF. */
export function canonicalJson(/** @type {unknown} */ value) {
  return `${JSON.stringify(sortKeys(value), null, 2)}\n`;
}

/**
 * @param {unknown} value
 * @param {readonly string[]} keys
 * @param {string} label
 * @returns {asserts value is Record<string, unknown>}
 */
function exactObject(value, keys, label) {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) fail('toolchain/manifest-schema', `${label} must be an object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail('toolchain/manifest-schema', `${label} has an unexpected key set`);
  }
}

/**
 * @param {unknown} value
 * @param {string} label
 * @returns {string}
 */
function boundedString(value, label) {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_STRING || /[\u0000-\u001f\u007f]/u.test(value.replaceAll('\n', ''))) {
    fail('toolchain/manifest-schema', `${label} must be a bounded string`);
  }
  return value;
}

/**
 * @param {unknown} value
 * @param {string} label
 * @param {number} [maximum]
 * @returns {unknown[]}
 */
function boundedArray(value, label, maximum = MAX_FILES) {
  if (!Array.isArray(value) || value.length > maximum) fail('toolchain/manifest-schema', `${label} must be a bounded array`);
  return value;
}

/**
 * A capsule-relative path: portable segments only, never absolute, empty, `.`, or `..`.
 *
 * @param {unknown} value
 * @param {string} label
 * @returns {string}
 */
export function assertCapsulePath(value, label) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 1024) fail('toolchain/manifest-path', `${label} is not a capsule path`);
  const segments = value.split('/');
  if (segments.some((segment) => segment === '.' || segment === '..' || !SEGMENT.test(segment))) {
    fail('toolchain/manifest-path', `${label} is not a portable capsule-relative path`);
  }
  return value;
}

/**
 * @param {readonly string[]} values
 * @param {string} label
 */
function assertSortedUnique(values, label) {
  for (let index = 1; index < values.length; index += 1) {
    if (/** @type {string} */ (values[index - 1]) >= /** @type {string} */ (values[index])) fail('toolchain/manifest-schema', `${label} must be sorted and unique`);
  }
}

/**
 * Directories implied by the file list. A capsule contains exactly these directories.
 *
 * @param {readonly { path: string }[]} files
 */
export function impliedDirectories(files) {
  const directories = new Set();
  for (const file of files) {
    const segments = file.path.split('/');
    for (let length = 1; length < segments.length; length += 1) directories.add(segments.slice(0, length).join('/'));
  }
  return directories;
}

/**
 * The fields that decide what executes. Qualification provenance is excluded so a moved source
 * path cannot change the identity, and the identity digest itself is excluded.
 *
 * @param {Record<string, unknown>} tool
 */
export function identityFields(tool) {
  return {
    entrypoint: tool.entrypoint,
    environment: tool.environment,
    files: tool.files,
    id: tool.id,
    invocation: tool.invocation,
    pathEntries: tool.pathEntries,
    version: tool.version,
  };
}

/** @param {Record<string, unknown>} tool */
export function computeTreeSha256(tool) {
  return sha256Hex(canonicalJson(identityFields(tool)));
}

/**
 * @param {unknown} value
 * @param {string} label
 */
function validateInvocation(value, label) {
  if (typeof value !== 'object' || value === null || !INVOCATION_KINDS.includes(/** @type { { kind?: unknown } } */ (value).kind)) {
    fail('toolchain/manifest-schema', `${label} kind is unsupported`);
  }
  const kind = /** @type { { kind: string } } */ (value).kind;
  if (kind === 'direct') {
    exactObject(value, ['kind'], label);
  } else if (kind === 'elf-loader') {
    exactObject(value, ['kind', 'loader', 'libraryPath'], label);
    assertCapsulePath(value.loader, `${label}.loader`);
    const libraryPath = boundedArray(value.libraryPath, `${label}.libraryPath`, 8);
    if (libraryPath.length === 0) fail('toolchain/manifest-schema', `${label}.libraryPath must not be empty`);
    libraryPath.forEach((entry, index) => assertCapsulePath(entry, `${label}.libraryPath[${index}]`));
    if (new Set(libraryPath).size !== libraryPath.length) fail('toolchain/manifest-schema', `${label}.libraryPath must be unique`);
  } else {
    exactObject(value, ['kind', 'tool', 'toolTreeSha256', 'script'], label);
    if (typeof value.tool !== 'string' || !TOOL_ID.test(value.tool)) fail('toolchain/manifest-schema', `${label}.tool is invalid`);
    if (typeof value.toolTreeSha256 !== 'string' || !SHA256.test(value.toolTreeSha256)) fail('toolchain/manifest-schema', `${label}.toolTreeSha256 is invalid`);
    assertCapsulePath(value.script, `${label}.script`);
  }
}

/**
 * Validates one tool entry against the closed schema and its own identity digest.
 *
 * @param {unknown} value
 * @param {string} label
 */
export function validateToolEntry(value, label) {
  exactObject(value, ['id', 'treeSha256', 'entrypoint', 'files', 'invocation', 'environment', 'pathEntries', 'version', 'qualification'], label);
  if (typeof value.id !== 'string' || !TOOL_ID.test(value.id)) fail('toolchain/manifest-schema', `${label}.id is invalid`);
  if (typeof value.treeSha256 !== 'string' || !SHA256.test(value.treeSha256)) fail('toolchain/manifest-schema', `${label}.treeSha256 is invalid`);

  const files = boundedArray(value.files, `${label}.files`);
  if (files.length === 0) fail('toolchain/manifest-schema', `${label}.files must not be empty`);
  files.forEach((file, index) => {
    const fileLabel = `${label}.files[${index}]`;
    exactObject(file, ['path', 'sha256', 'size', 'mode'], fileLabel);
    assertCapsulePath(file.path, `${fileLabel}.path`);
    if (typeof file.sha256 !== 'string' || !SHA256.test(file.sha256)) fail('toolchain/manifest-schema', `${fileLabel}.sha256 is invalid`);
    if (!Number.isSafeInteger(file.size) || /** @type {number} */ (file.size) < 0) fail('toolchain/manifest-schema', `${fileLabel}.size is invalid`);
    if (typeof file.mode !== 'string' || !FILE_MODES.includes(file.mode)) fail('toolchain/manifest-schema', `${fileLabel}.mode is invalid`);
  });
  const typedFiles = /** @type { { path: string, mode: string }[]} */ (files);
  const paths = typedFiles.map((file) => file.path);
  assertSortedUnique(paths, `${label}.files`);
  const directories = impliedDirectories(typedFiles);
  if (paths.some((path) => directories.has(path))) fail('toolchain/manifest-path', `${label} uses a path as both file and directory`);
  const fileModes = new Map(typedFiles.map((file) => [file.path, file.mode]));

  assertCapsulePath(value.entrypoint, `${label}.entrypoint`);
  validateInvocation(value.invocation, `${label}.invocation`);
  const invocation = /** @type { { kind: string, loader?: string, libraryPath?: string[], script?: string } } */ (value.invocation);
  if (invocation.kind === 'interpreter') {
    if (value.entrypoint !== invocation.script) fail('toolchain/manifest-path', `${label} interpreter script must be the entrypoint`);
    if (fileModes.get(/** @type {string} */ (value.entrypoint)) === undefined) fail('toolchain/manifest-path', `${label}.entrypoint is not a listed file`);
  } else if (fileModes.get(/** @type {string} */ (value.entrypoint)) !== '0555') {
    fail('toolchain/manifest-path', `${label}.entrypoint is not a listed executable file`);
  }
  if (invocation.kind === 'elf-loader') {
    if (fileModes.get(/** @type {string} */ (invocation.loader)) !== '0555') fail('toolchain/manifest-path', `${label} loader is not a listed executable file`);
    for (const directory of invocation.libraryPath ?? []) {
      if (!directories.has(directory)) fail('toolchain/manifest-path', `${label} library path ${directory} is not a capsule directory`);
    }
  }

  const environment = boundedArray(value.environment, `${label}.environment`, 64);
  environment.forEach((entry, index) => {
    const entryLabel = `${label}.environment[${index}]`;
    const keys = typeof entry === 'object' && entry !== null && 'capsulePath' in entry ? ['name', 'capsulePath'] : ['name', 'value'];
    exactObject(entry, keys, entryLabel);
    if (typeof entry.name !== 'string' || !ENV_NAME.test(entry.name) || RESERVED_ENV.test(entry.name)) {
      fail('toolchain/env-forbidden', `${entryLabel}.name is reserved or invalid`);
    }
    if ('capsulePath' in entry) assertCapsulePath(entry.capsulePath, `${entryLabel}.capsulePath`);
    else if (typeof entry.value !== 'string' || entry.value.length > MAX_STRING || /[\u0000-\u001f\u007f]/u.test(entry.value)) {
      fail('toolchain/manifest-schema', `${entryLabel}.value is invalid`);
    }
  });
  assertSortedUnique(environment.map((entry) => /** @type { { name: string } } */ (entry).name), `${label}.environment`);

  const pathEntries = boundedArray(value.pathEntries, `${label}.pathEntries`, 8);
  pathEntries.forEach((entry, index) => {
    assertCapsulePath(entry, `${label}.pathEntries[${index}]`);
    if (!directories.has(/** @type {string} */ (entry))) fail('toolchain/manifest-path', `${label}.pathEntries[${index}] is not a capsule directory`);
  });
  if (new Set(pathEntries).size !== pathEntries.length) fail('toolchain/manifest-schema', `${label}.pathEntries must be unique`);

  exactObject(value.version, ['args', 'stdout'], `${label}.version`);
  boundedArray(value.version.args, `${label}.version.args`, MAX_ARGS).forEach((arg, index) => boundedString(arg, `${label}.version.args[${index}]`));
  boundedString(value.version.stdout, `${label}.version.stdout`);

  exactObject(value.qualification, ['qualifiedOn', 'sources'], `${label}.qualification`);
  if (typeof value.qualification.qualifiedOn !== 'string' || !DATE.test(value.qualification.qualifiedOn) ||
    new Date(`${value.qualification.qualifiedOn}T00:00:00.000Z`).toISOString().slice(0, 10) !== value.qualification.qualifiedOn) {
    fail('toolchain/manifest-schema', `${label}.qualification.qualifiedOn is invalid`);
  }
  const sources = boundedArray(value.qualification.sources, `${label}.qualification.sources`);
  sources.forEach((source, index) => {
    const sourceLabel = `${label}.qualification.sources[${index}]`;
    exactObject(source, ['path', 'from'], sourceLabel);
    if (typeof source.path !== 'string' || !fileModes.has(source.path)) fail('toolchain/manifest-path', `${sourceLabel}.path is not a listed file`);
    const from = boundedString(source.from, `${sourceLabel}.from`);
    if (!from.startsWith('/') || from.split('/').includes('..')) fail('toolchain/manifest-path', `${sourceLabel}.from must be an absolute host path`);
  });
  const sourcePaths = sources.map((source) => /** @type { { path: string } } */ (source).path);
  assertSortedUnique(sourcePaths, `${label}.qualification.sources`);
  if (sourcePaths.length !== paths.length) fail('toolchain/manifest-schema', `${label} must record one qualification source per file`);

  if (computeTreeSha256(value) !== value.treeSha256) fail('toolchain/manifest-tree-mismatch', `${label} identity does not match its fields`);
}

/**
 * Validates a whole manifest object, including cross-tool interpreter bindings.
 *
 * @param {unknown} value
 */
export function validateManifest(value) {
  exactObject(value, ['schemaVersion', 'kind', 'platform', 'tools'], 'manifest');
  if (value.schemaVersion !== 1 || value.kind !== MANIFEST_KIND || value.platform !== MANIFEST_PLATFORM) {
    fail('toolchain/manifest-schema', 'manifest header is unsupported');
  }
  const tools = boundedArray(value.tools, 'manifest.tools', MAX_TOOLS);
  tools.forEach((tool, index) => validateToolEntry(tool, `manifest.tools[${index}]`));
  const typed = /** @type { { id: string, treeSha256: string, invocation: { kind: string, tool?: string, toolTreeSha256?: string } }[]} */ (tools);
  assertSortedUnique(typed.map((tool) => tool.id), 'manifest.tools');
  const byId = new Map(typed.map((tool) => [tool.id, tool]));
  for (const tool of typed) {
    if (tool.invocation.kind !== 'interpreter') continue;
    const interpreter = byId.get(/** @type {string} */ (tool.invocation.tool));
    if (interpreter === undefined || interpreter.invocation.kind === 'interpreter') {
      fail('toolchain/manifest-schema', `${tool.id} interpreter must be a native tool in the same manifest`);
    }
    if (interpreter.treeSha256 !== tool.invocation.toolTreeSha256) {
      fail('toolchain/manifest-tree-mismatch', `${tool.id} is bound to a different ${interpreter.id} identity`);
    }
  }
}

/**
 * Parses manifest bytes. When the caller pins `expectedSha256`, any other bytes are refused before parsing.
 *
 * @param {Buffer} bytes
 * @param { { expectedSha256?: string | undefined } } [options]
 */
export function parseManifest(bytes, options = {}) {
  if (bytes.length > MAX_MANIFEST_BYTES) fail('toolchain/manifest-read', 'manifest exceeds the byte limit');
  const manifestSha256 = sha256Hex(bytes);
  if (options.expectedSha256 !== undefined && options.expectedSha256 !== manifestSha256) {
    fail('toolchain/manifest-digest-mismatch', 'manifest bytes differ from the pinned digest');
  }
  let text;
  let parsed;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    parsed = JSON.parse(text);
  } catch {
    fail('toolchain/manifest-read', 'manifest is not UTF-8 JSON');
  }
  if (canonicalJson(parsed) !== text) fail('toolchain/manifest-noncanonical', 'manifest bytes are not canonical');
  validateManifest(parsed);
  return Object.freeze({ manifest: /** @type {ToolchainManifest} */ (deepFreeze(parsed)), manifestSha256 });
}

/**
 * @template T
 * @param {T} value
 * @returns {T}
 */
function deepFreeze(value) {
  if (typeof value === 'object' && value !== null) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

/**
 * @param {ToolchainManifest} manifest
 * @param {string} toolId
 * @returns {ToolEntry}
 */
export function findTool(manifest, toolId) {
  const tool = manifest.tools.find((entry) => entry.id === toolId);
  if (tool === undefined) fail('toolchain/unknown-tool', `tool ${String(toolId)} is not in the manifest`);
  return tool;
}

/**
 * @typedef { { path: string, sha256: string, size: number, mode: '0444' | '0555' } } ToolFile
 * @typedef { { kind: 'direct' } | { kind: 'elf-loader', loader: string, libraryPath: string[] } | { kind: 'interpreter', tool: string, toolTreeSha256: string, script: string } } Invocation
 * @typedef { { name: string, value: string } | { name: string, capsulePath: string } } EnvironmentEntry
 * @typedef { {
 *   id: string,
 *   treeSha256: string,
 *   entrypoint: string,
 *   files: ToolFile[],
 *   invocation: Invocation,
 *   environment: EnvironmentEntry[],
 *   pathEntries: string[],
 *   version: { args: string[], stdout: string },
 *   qualification: { qualifiedOn: string, sources: { path: string, from: string }[] },
 * } } ToolEntry
 * @typedef { { schemaVersion: 1, kind: string, platform: string, tools: ToolEntry[] } } ToolchainManifest
 */
