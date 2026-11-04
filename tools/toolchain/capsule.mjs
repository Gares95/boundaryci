import { spawnSync } from 'node:child_process';
import { closeSync, constants, fstatSync, lstatSync, openSync, readFileSync, readdirSync, realpathSync } from 'node:fs';
import { dirname, join, resolve, sep } from 'node:path';

import { assertCapsuleClosure } from './elf.mjs';
import { fail, ToolchainError } from './errors.mjs';
import { findTool, impliedDirectories, MANIFEST_PLATFORM, RESERVED_ENV, sha256Hex } from './manifest.mjs';

export const OWNER_POLICIES = Object.freeze(['self-or-root', 'root-only']);
const MAX_CAPSULE_FILE_BYTES = 512 * 1024 * 1024;
const MAX_CAPSULE_TOTAL_BYTES = 1024 * 1024 * 1024;
const MAX_CAPSULE_ENTRIES = 8192;
const DIRECTORY_MODE = 0o555;
const STICKY_BIT = 0o1000;
const ENV_NAME = /^[A-Z_][A-Z0-9_]{0,63}$/u;

export function assertSupportedPlatform() {
  if (`${process.platform}-${process.arch}` !== MANIFEST_PLATFORM) {
    fail('toolchain/platform', `capsules are qualified for ${MANIFEST_PLATFORM} only`);
  }
}

/**
 * @param {string} policy
 */
function assertOwnerPolicy(policy) {
  if (!OWNER_POLICIES.includes(policy)) fail('toolchain/usage', 'unknown owner policy');
}

/**
 * @param {import('node:fs').Stats} stats
 * @param {string} policy
 */
function ownerAllowed(stats, policy) {
  if (stats.uid === 0) return true;
  return policy === 'self-or-root' && typeof process.geteuid === 'function' && stats.uid === process.geteuid();
}

/**
 * The store root, its per-tool directory, and every ancestor must be real directories that no
 * other user can rewrite. Root-owned sticky directories such as /tmp are the only shared exception.
 *
 * @param {string} storeRoot
 * @param {string} policy
 * @returns {string}
 */
export function assertSafeStoreRoot(storeRoot, policy) {
  assertOwnerPolicy(policy);
  const absolute = resolve(storeRoot);
  let physical;
  try {
    physical = realpathSync(absolute);
  } catch {
    fail('toolchain/store-unsafe', 'store root does not exist');
  }
  if (physical !== absolute) fail('toolchain/store-unsafe', 'store root path contains a symbolic link');
  let current = physical;
  for (;;) {
    const stats = lstatSync(current);
    if (!stats.isDirectory() || stats.isSymbolicLink()) fail('toolchain/store-unsafe', `${current} is not a directory`);
    const sharedSticky = stats.uid === 0 && (stats.mode & STICKY_BIT) !== 0;
    if (!ownerAllowed(stats, current === physical ? policy : 'self-or-root')) fail('toolchain/store-unsafe', `${current} has an untrusted owner`);
    if ((stats.mode & 0o022) !== 0 && !sharedSticky) fail('toolchain/store-unsafe', `${current} is writable by other users`);
    const parent = dirname(current);
    if (parent === current) break;
    current = parent;
  }
  return physical;
}

/**
 * @param {string} storePhysical
 * @param { { id: string, treeSha256: string } } tool
 */
export function capsuleDirectory(storePhysical, tool) {
  return join(storePhysical, tool.id, tool.treeSha256);
}

/**
 * Reads one file without following links and proves the descriptor is the inspected inode.
 *
 * @param {string} absolutePath
 * @param {import('node:fs').Stats} linkStats
 */
export function readPinnedFile(absolutePath, linkStats) {
  let descriptor;
  try {
    descriptor = openSync(absolutePath, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch {
    fail('toolchain/file-type', `${absolutePath} cannot be opened without following links`);
  }
  try {
    const before = fstatSync(descriptor);
    if (before.dev !== linkStats.dev || before.ino !== linkStats.ino || !before.isFile()) fail('toolchain/file-changed', `${absolutePath} changed during inspection`);
    const bytes = readFileSync(descriptor);
    const after = fstatSync(descriptor);
    if (bytes.length !== before.size || after.size !== before.size || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs) {
      fail('toolchain/file-changed', `${absolutePath} changed while it was read`);
    }
    return bytes;
  } finally {
    closeSync(descriptor);
  }
}

/**
 * Verifies that `directory` holds exactly the tool's closed file tree with exact bytes, modes,
 * owners, and link counts. Nothing is cached; callers re-run this around every execution.
 *
 * @param {string} directory
 * @param {import('./manifest.mjs').ToolEntry} tool
 * @param {string} policy
 */
export function verifyCapsuleTree(directory, tool, policy) {
  assertOwnerPolicy(policy);
  let rootStats;
  try {
    rootStats = lstatSync(directory);
  } catch {
    fail('toolchain/not-materialized', `${tool.id} ${tool.treeSha256} is not materialized`);
  }
  if (rootStats.isSymbolicLink() || !rootStats.isDirectory()) fail('toolchain/file-type', `${tool.id} capsule root is not a real directory`);
  if ((rootStats.mode & 0o7777) !== DIRECTORY_MODE) fail('toolchain/dir-unsafe', `${tool.id} capsule root mode is not 0555`);
  if (!ownerAllowed(rootStats, policy)) fail('toolchain/file-owner', `${tool.id} capsule root owner is not trusted`);

  const expectedFiles = new Map(tool.files.map((file) => [file.path, file]));
  const expectedDirectories = impliedDirectories(tool.files);
  /** @type {Map<string, Buffer>} */
  const bytesByPath = new Map();
  let total = 0;
  let entries = 0;
  const visit = (/** @type {string} */ absolute, /** @type {string} */ relativePrefix) => {
    const names = readdirSync(absolute).sort();
    for (const name of names) {
      entries += 1;
      if (entries > MAX_CAPSULE_ENTRIES) fail('toolchain/unexpected-file', `${tool.id} capsule has too many entries`);
      const relativePath = relativePrefix === '' ? name : `${relativePrefix}/${name}`;
      const childPath = join(absolute, name);
      const stats = lstatSync(childPath);
      if (stats.isSymbolicLink()) fail('toolchain/file-type', `${relativePath} is a symbolic link`);
      if (stats.isDirectory()) {
        if (!expectedDirectories.has(relativePath)) fail('toolchain/unexpected-file', `${relativePath} is not in the manifest`);
        if ((stats.mode & 0o7777) !== DIRECTORY_MODE) fail('toolchain/dir-unsafe', `${relativePath} mode is not 0555`);
        if (!ownerAllowed(stats, policy)) fail('toolchain/file-owner', `${relativePath} owner is not trusted`);
        visit(childPath, relativePath);
        continue;
      }
      const expected = expectedFiles.get(relativePath);
      if (expected === undefined) fail('toolchain/unexpected-file', `${relativePath} is not in the manifest`);
      if (!stats.isFile()) fail('toolchain/file-type', `${relativePath} is not a regular file`);
      if (stats.nlink !== 1) fail('toolchain/file-hardlink', `${relativePath} has additional hard links`);
      if ((stats.mode & 0o7777) !== Number.parseInt(expected.mode, 8)) fail('toolchain/file-mode', `${relativePath} mode differs from ${expected.mode}`);
      if (!ownerAllowed(stats, policy)) fail('toolchain/file-owner', `${relativePath} owner is not trusted`);
      if (stats.size !== expected.size || stats.size > MAX_CAPSULE_FILE_BYTES) fail('toolchain/file-size', `${relativePath} size differs from the manifest`);
      total += stats.size;
      if (total > MAX_CAPSULE_TOTAL_BYTES) fail('toolchain/file-size', `${tool.id} capsule exceeds the byte budget`);
      const bytes = readPinnedFile(childPath, stats);
      if (sha256Hex(bytes) !== expected.sha256) fail('toolchain/file-digest', `${relativePath} bytes differ from the approved identity`);
      bytesByPath.set(relativePath, bytes);
    }
  };
  visit(directory, '');
  // Every implied directory contains a listed file, so a complete file set implies a complete tree.
  for (const path of expectedFiles.keys()) if (!bytesByPath.has(path)) fail('toolchain/file-missing', `${path} is missing from the capsule`);
  assertCapsuleClosure(tool, bytesByPath);
  return Object.freeze({ directory });
}

/**
 * Verifies one materialized tool, and for interpreted tools the bound interpreter capsule too.
 *
 * @param { { manifest: import('./manifest.mjs').ToolchainManifest, storeRoot: string, toolId: string, ownerPolicy?: string } } options
 */
export function verifyTool(options) {
  assertSupportedPlatform();
  const policy = options.ownerPolicy ?? 'self-or-root';
  const store = assertSafeStoreRoot(options.storeRoot, policy);
  const tool = findTool(options.manifest, options.toolId);
  /** @type {VerifiedCapsule[]} */
  const chain = [];
  const verifyOne = (/** @type {import('./manifest.mjs').ToolEntry} */ entry) => {
    const toolDirectory = join(store, entry.id);
    const toolStats = lstatSync(toolDirectory, { throwIfNoEntry: false });
    if (toolStats === undefined) fail('toolchain/not-materialized', `${entry.id} has no capsule directory`);
    if (toolStats.isSymbolicLink() || !toolStats.isDirectory()) fail('toolchain/store-unsafe', `${entry.id} store directory is not a real directory`);
    if ((toolStats.mode & 0o022) !== 0 || !ownerAllowed(toolStats, policy)) fail('toolchain/store-unsafe', `${entry.id} store directory is not protected`);
    const directory = capsuleDirectory(store, entry);
    verifyCapsuleTree(directory, entry, policy);
    chain.push(Object.freeze({ tool: entry, directory }));
  };
  if (tool.invocation.kind === 'interpreter') verifyOne(findTool(options.manifest, tool.invocation.tool));
  verifyOne(tool);
  return Object.freeze(chain);
}

/**
 * @param {string} root
 * @param {string} relativePath
 */
function inside(root, relativePath) {
  const absolute = join(root, ...relativePath.split('/'));
  if (!absolute.startsWith(`${root}${sep}`)) fail('toolchain/manifest-path', 'capsule path escapes its capsule');
  return absolute;
}

/**
 * Builds the exact command line and closed environment for a verified capsule chain. The child
 * environment starts empty: no inherited PATH, proxy, loader, or interpreter variables.
 *
 * @param {readonly VerifiedCapsule[]} chain
 * @param {readonly string[]} args
 * @param {Readonly<Record<string, string>>} [callerEnvironment]
 */
export function buildInvocation(chain, args, callerEnvironment = {}) {
  const target = chain[chain.length - 1];
  if (target === undefined) fail('toolchain/usage', 'empty capsule chain');
  if (!Array.isArray(args) || args.some((arg) => typeof arg !== 'string' || arg.includes('\0'))) fail('toolchain/usage', 'arguments must be strings');

  /** @type {Record<string, string>} */
  const environment = {};
  const pathDirectories = target.tool.pathEntries.map((entry) => inside(target.directory, entry));
  environment.PATH = pathDirectories.length > 0 ? pathDirectories.join(':') : target.directory;
  for (const entry of target.tool.environment) {
    environment[entry.name] = 'capsulePath' in entry ? inside(target.directory, entry.capsulePath) : entry.value;
  }
  for (const [name, value] of Object.entries(callerEnvironment)) {
    if (!ENV_NAME.test(name) || RESERVED_ENV.test(name) || Object.hasOwn(environment, name) || typeof value !== 'string' || value.includes('\0')) {
      fail('toolchain/env-forbidden', `caller environment variable ${name} is not allowed`);
    }
    environment[name] = value;
  }

  /**
   * @param {VerifiedCapsule} capsule
   * @param {string} program
   * @param {readonly string[]} programArgs
   */
  const native = (capsule, program, programArgs) => {
    const invocation = capsule.tool.invocation;
    if (invocation.kind === 'direct') return { file: program, argv: [...programArgs], argv0: program };
    if (invocation.kind !== 'elf-loader') fail('toolchain/usage', 'interpreter chains must end in a native tool');
    const loader = inside(capsule.directory, invocation.loader);
    const libraryPath = invocation.libraryPath.map((entry) => inside(capsule.directory, entry)).join(':');
    return { file: loader, argv: ['--inhibit-cache', '--library-path', libraryPath, '--argv0', program, program, ...programArgs], argv0: loader };
  };

  const program = inside(target.directory, target.tool.entrypoint);
  if (target.tool.invocation.kind === 'interpreter') {
    const interpreter = chain[0];
    if (chain.length !== 2 || interpreter === undefined) fail('toolchain/usage', 'interpreted tools need exactly one interpreter capsule');
    const command = native(interpreter, inside(interpreter.directory, interpreter.tool.entrypoint), [program, ...args]);
    return Object.freeze({ ...command, env: Object.freeze(environment) });
  }
  return Object.freeze({ ...native(target, program, args), env: Object.freeze(environment) });
}

/**
 * Runs an approved tool: verify the full chain, execute by absolute capsule path with a closed
 * environment, and verify again. A failed post-check discards the result.
 *
 * @param { {
 *   manifest: import('./manifest.mjs').ToolchainManifest,
 *   storeRoot: string,
 *   toolId: string,
 *   args: readonly string[],
 *   cwd?: string,
 *   env?: Readonly<Record<string, string>>,
 *   ownerPolicy?: string,
 *   timeoutMs?: number,
 *   maxBufferBytes?: number,
 * } } options
 */
export function runTool(options) {
  return executeVerified(() => verifyTool(options), options);
}

/**
 * Shared verify → execute → verify core. `verify` must perform a complete, uncached verification
 * each time it is called and return the capsule chain to execute.
 *
 * @param {() => readonly VerifiedCapsule[]} verify
 * @param { { toolId: string, args: readonly string[], cwd?: string, env?: Readonly<Record<string, string>>, timeoutMs?: number, maxBufferBytes?: number } } options
 */
export function executeVerified(verify, options) {
  const chain = verify();
  const command = buildInvocation(chain, options.args, options.env);
  const result = spawnSync(command.file, command.argv, {
    argv0: command.argv0,
    cwd: options.cwd ?? process.cwd(),
    env: command.env,
    shell: false,
    encoding: 'buffer',
    timeout: options.timeoutMs ?? 120_000,
    maxBuffer: options.maxBufferBytes ?? 64 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
  });
  try {
    verify();
  } catch (error) {
    if (error instanceof ToolchainError) fail('toolchain/changed-during-run', `${options.toolId} capsule changed while it ran (${error.code})`);
    throw error;
  }
  if (result.error !== undefined) fail('toolchain/spawn', `${options.toolId} could not be executed`);
  return Object.freeze({ status: result.status, signal: result.signal, stdout: result.stdout, stderr: result.stderr });
}

/**
 * Secondary check after byte identity: exact version output and a zero exit status. A matching
 * version string never establishes identity on its own.
 *
 * @param {Parameters<typeof runTool>[0]} options
 */
export function probeVersion(options) {
  const tool = findTool(options.manifest, options.toolId);
  return assertVersionResult(tool, runTool({ ...options, args: tool.version.args, env: {} }));
}

/**
 * @param {import('./manifest.mjs').ToolEntry} tool
 * @param {ReturnType<typeof runTool>} result
 */
export function assertVersionResult(tool, result) {
  if (result.status !== 0 || result.signal !== null || result.stdout.toString('utf8') !== tool.version.stdout) {
    fail('toolchain/version-mismatch', `${tool.id} version output differs from the qualified expectation`);
  }
  return result;
}

/**
 * @typedef { { tool: import('./manifest.mjs').ToolEntry, directory: string } } VerifiedCapsule
 */
