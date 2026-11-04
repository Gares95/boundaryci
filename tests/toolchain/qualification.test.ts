import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterEach, describe, expect, it } from 'vitest';

import { runTool, verifyTool } from '../../tools/toolchain/capsule.mjs';
import { parseManifest, sha256Hex } from '../../tools/toolchain/manifest.mjs';
import { driftReport, materializeTool, qualifyTools } from '../../tools/toolchain/qualify.mjs';
import { CAN_EXECUTE_SYNTHETIC_ELF, cleanupWorkspaces, dynamicElf, staticElf, workspace } from './fixtures.js';

const CLI = fileURLToPath(new URL('../../tools/toolchain/cli.mjs', import.meta.url));
const EXAMPLE = fileURLToPath(new URL('../../tools/toolchain/examples/git-ubuntu-noble.request.json', import.meta.url));
const V2430 = 'git version 2.43.0\n';
const APPROVED = staticElf(V2430);
const UBUNTU_REBUILD = staticElf(V2430, { padding: Buffer.from('1ubuntu7.5') });

afterEach(cleanupWorkspaces);

function codeOf(action: () => unknown): string {
  try {
    action();
  } catch (error) {
    return (error as { code?: string }).code ?? `uncoded: ${String(error)}`;
  }
  return 'no-error';
}

interface Host {
  root: string;
  store: string;
  manifestPath: string;
  hostGit: string;
}

/** A synthetic host: `usr/bin/git` plays the distribution-owned mutable path. */
function host(bytes: Buffer = APPROVED): Host {
  const root = workspace();
  const store = join(root, 'store');
  mkdirSync(store);
  chmodSync(store, 0o755);
  mkdirSync(join(root, 'usr', 'bin'), { recursive: true });
  const hostGit = join(root, 'usr', 'bin', 'git');
  writeFileSync(hostGit, bytes, { mode: 0o755 });
  return { root, store, manifestPath: join(root, 'toolchain.manifest.json'), hostGit };
}

function gitRequest(from: string, stdout = V2430): Record<string, unknown> {
  return {
    schemaVersion: 1,
    kind: 'boundaryci-toolchain-qualification-request',
    qualifiedOn: '2026-11-04',
    tool: {
      id: 'git',
      entrypoint: 'bin/git',
      files: [{ path: 'bin/git', from, mode: '0555' }],
      invocation: { kind: 'direct' },
      environment: [
        { name: 'GIT_CONFIG_GLOBAL', value: '/dev/null' },
        { name: 'GIT_CONFIG_NOSYSTEM', value: '1' },
        { name: 'GIT_EXEC_PATH', capsulePath: 'libexec/git-core' },
      ],
      pathEntries: ['bin'],
      version: { args: ['--version'], stdout },
    },
  };
}

function manifestOf(path: string) {
  return parseManifest(readFileSync(path)).manifest;
}

function cli(args: string[]) {
  return spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', env: {} });
}

describe('qualification', () => {
  it('records exact digests without executing the source', () => {
    const { manifestPath, hostGit } = host();
    // A non-executable source proves qualification hashes bytes and never runs them.
    chmodSync(hostGit, 0o644);
    const result = qualifyTools({ manifestPath, requests: [gitRequest(hostGit)] });
    const bytes = readFileSync(manifestPath);
    expect(result.previousManifestSha256).toBeNull();
    expect(result.manifestSha256).toBe(sha256Hex(bytes));
    const tool = parseManifest(bytes, { expectedSha256: result.manifestSha256 }).manifest.tools[0];
    expect(tool?.files).toEqual([{ path: 'bin/git', sha256: sha256Hex(APPROVED), size: APPROVED.length, mode: '0555' }]);
    expect(result.changes).toEqual([{ id: 'git', previousTreeSha256: null, treeSha256: tool?.treeSha256 }]);
  });

  it('refuses a dynamic or script source that would depend on host loaders', () => {
    const { manifestPath, hostGit } = host(Buffer.from('#!/bin/sh\necho "git version 2.43.0"\n'));
    expect(codeOf(() => qualifyTools({ manifestPath, requests: [gitRequest(hostGit)] }))).toBe('toolchain/closure');
    expect(existsSync(manifestPath)).toBe(false);
  });

  it('requires an explicit compare-and-swap digest to requalify', () => {
    const { manifestPath, hostGit } = host();
    const first = qualifyTools({ manifestPath, requests: [gitRequest(hostGit)] });
    const approvedBytes = readFileSync(manifestPath);
    writeFileSync(hostGit, UBUNTU_REBUILD);
    expect(codeOf(() => qualifyTools({ manifestPath, requests: [gitRequest(hostGit)] }))).toBe('toolchain/requalify-requires-explicit-replace');
    expect(codeOf(() => qualifyTools({ manifestPath, requests: [gitRequest(hostGit)], replaceManifestSha256: 'f'.repeat(64) }))).toBe('toolchain/requalify-base-mismatch');
    expect(readFileSync(manifestPath)).toEqual(approvedBytes);
    const second = qualifyTools({ manifestPath, requests: [gitRequest(hostGit)], replaceManifestSha256: first.manifestSha256 });
    expect(second.previousManifestSha256).toBe(first.manifestSha256);
    expect(second.changes[0]?.previousTreeSha256).toBe(first.changes[0]?.treeSha256);
    expect(second.changes[0]?.treeSha256).not.toBe(first.changes[0]?.treeSha256);
  });

  it('keeps the committed hardened git example qualifiable as a complete loader closure', () => {
    const { root, manifestPath } = host();
    const example = JSON.parse(readFileSync(EXAMPLE, 'utf8')) as { tool: { files: { path: string; from: string }[]; environment: Record<string, string>[] } };
    const standIns: Record<string, Buffer> = {
      'bin/git': dynamicElf({ interpreter: '/lib64/ld-linux-x86-64.so.2', needed: ['libpcre2-8.so.0', 'libz.so.1', 'libc.so.6'] }),
      'lib/ld-linux-x86-64.so.2': dynamicElf({}),
      'lib/libc.so.6': dynamicElf({ needed: ['ld-linux-x86-64.so.2'] }),
      'lib/libpcre2-8.so.0': dynamicElf({ needed: ['libc.so.6'] }),
      'lib/libz.so.1': dynamicElf({ needed: ['libc.so.6'] }),
    };
    for (const file of example.tool.files) {
      const replacement = join(root, file.path.replaceAll('/', '_'));
      writeFileSync(replacement, standIns[file.path] ?? Buffer.alloc(0));
      file.from = replacement;
    }
    const result = qualifyTools({ manifestPath, requests: [example] });
    const tool = parseManifest(readFileSync(manifestPath), { expectedSha256: result.manifestSha256 }).manifest.tools[0];
    expect(tool?.invocation).toEqual({ kind: 'elf-loader', loader: 'lib/ld-linux-x86-64.so.2', libraryPath: ['lib'] });
    const environment = Object.fromEntries((tool?.environment ?? []).map((entry) => [entry.name, 'value' in entry ? entry.value : `capsule:${entry.capsulePath}`]));
    const overrides = Object.fromEntries(
      Array.from({ length: Number(environment.GIT_CONFIG_COUNT) }, (_, index) => [environment[`GIT_CONFIG_KEY_${index}`], environment[`GIT_CONFIG_VALUE_${index}`]]),
    );
    expect(overrides).toMatchObject({ 'core.fsmonitor': 'false', 'core.hooksPath': '/dev/null', 'core.sshCommand': 'false', 'protocol.allow': 'never' });
    expect(environment).toMatchObject({ GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_EXEC_PATH: 'capsule:libexec/git-core', GIT_TERMINAL_PROMPT: '0' });
  });

  it('refuses to create a manifest when the caller expected one to exist', () => {
    const { manifestPath, hostGit } = host();
    expect(codeOf(() => qualifyTools({ manifestPath, requests: [gitRequest(hostGit)], replaceManifestSha256: 'a'.repeat(64) }))).toBe('toolchain/requalify-base-mismatch');
  });

  it('requires interpreted tools to be requalified with their interpreter', () => {
    const { root, manifestPath } = host();
    const nodePath = join(root, 'node');
    const pnpmPath = join(root, 'pnpm.cjs');
    writeFileSync(nodePath, staticElf('v24.19.0\n'));
    writeFileSync(pnpmPath, 'inert synthetic script\n');
    const nodeRequest = (stdout: string) => ({
      schemaVersion: 1,
      kind: 'boundaryci-toolchain-qualification-request',
      qualifiedOn: '2026-11-04',
      tool: { id: 'node', entrypoint: 'bin/node', files: [{ path: 'bin/node', from: nodePath, mode: '0555' }], invocation: { kind: 'direct' }, environment: [], pathEntries: [], version: { args: ['--version'], stdout } },
    });
    const pnpmRequest = {
      schemaVersion: 1,
      kind: 'boundaryci-toolchain-qualification-request',
      qualifiedOn: '2026-11-04',
      tool: {
        id: 'pnpm',
        entrypoint: 'dist/pnpm.cjs',
        files: [{ path: 'dist/pnpm.cjs', from: pnpmPath, mode: '0444' }],
        invocation: { kind: 'interpreter', tool: 'node', script: 'dist/pnpm.cjs' },
        environment: [{ name: 'COREPACK_ENABLE_STRICT', value: '1' }],
        pathEntries: [],
        version: { args: ['--version'], stdout: 'v24.19.0\n' },
      },
    };
    expect(codeOf(() => qualifyTools({ manifestPath, requests: [nodeRequest('v24.19.0\n'), pnpmRequest] }))).toBe('toolchain/env-forbidden');
    pnpmRequest.tool.environment = [];
    const first = qualifyTools({ manifestPath, requests: [nodeRequest('v24.19.0\n'), pnpmRequest] });
    writeFileSync(nodePath, staticElf('v24.19.1\n'));
    expect(codeOf(() => qualifyTools({ manifestPath, requests: [nodeRequest('v24.19.1\n')], replaceManifestSha256: first.manifestSha256 }))).toBe('toolchain/requalify-dependent');
    const both = qualifyTools({ manifestPath, requests: [nodeRequest('v24.19.1\n'), pnpmRequest], replaceManifestSha256: first.manifestSha256 });
    expect(both.changes.map((change) => change.id)).toEqual(['node', 'pnpm']);
  });
});

describe.runIf(CAN_EXECUTE_SYNTHETIC_ELF)('materialization and host drift', () => {
  it('materializes the approved bytes, probes the version, and is idempotent', () => {
    const { manifestPath, hostGit, store } = host();
    qualifyTools({ manifestPath, requests: [gitRequest(hostGit)] });
    const manifest = manifestOf(manifestPath);
    expect(materializeTool({ manifest, storeRoot: store, toolId: 'git' }).status).toBe('materialized');
    expect(materializeTool({ manifest, storeRoot: store, toolId: 'git' }).status).toBe('already-materialized');
    expect(readdirSync(join(store, 'git'))).toEqual([manifest.tools[0]?.treeSha256]);
    expect(runTool({ manifest, storeRoot: store, toolId: 'git', args: ['--version'] }).stdout.toString()).toBe(V2430);
  });

  it('keeps running the approved tool after the host /usr/bin/git changes', () => {
    const { manifestPath, hostGit, store } = host();
    qualifyTools({ manifestPath, requests: [gitRequest(hostGit)] });
    const approvedManifest = readFileSync(manifestPath);
    const manifest = manifestOf(manifestPath);
    materializeTool({ manifest, storeRoot: store, toolId: 'git' });

    // A distribution update: first a same-version rebuild, then a different release.
    writeFileSync(hostGit, UBUNTU_REBUILD);
    expect(() => verifyTool({ manifest, storeRoot: store, toolId: 'git' })).not.toThrow();
    writeFileSync(hostGit, staticElf('git version 2.43.1\n'));
    expect(runTool({ manifest, storeRoot: store, toolId: 'git', args: ['--version'] }).stdout.toString()).toBe(V2430);

    const report = driftReport({ manifest, storeRoot: store });
    expect(report[0]?.sources).toEqual([{ path: 'bin/git', from: hostGit, state: 'changed' }]);
    expect(report[0]?.capsule).toBe('present');
    expect(readFileSync(manifestPath)).toEqual(approvedManifest);
  });

  it('refuses to materialize from a source that drifted after qualification', () => {
    const { manifestPath, hostGit, store } = host();
    qualifyTools({ manifestPath, requests: [gitRequest(hostGit)] });
    const manifest = manifestOf(manifestPath);
    writeFileSync(hostGit, UBUNTU_REBUILD);
    expect(codeOf(() => materializeTool({ manifest, storeRoot: store, toolId: 'git' }))).toBe('toolchain/source-drift');
    expect(readdirSync(join(store, 'git'))).toEqual([]);
    expect(codeOf(() => runTool({ manifest, storeRoot: store, toolId: 'git', args: ['--version'] }))).toBe('toolchain/not-materialized');
  });

  it('refuses to materialize bytes whose version output differs from the reviewed expectation', () => {
    const { manifestPath, hostGit, store } = host();
    qualifyTools({ manifestPath, requests: [gitRequest(hostGit, 'git version 2.44.0\n')] });
    const manifest = manifestOf(manifestPath);
    expect(codeOf(() => materializeTool({ manifest, storeRoot: store, toolId: 'git' }))).toBe('toolchain/version-mismatch');
    expect(readdirSync(join(store, 'git'))).toEqual([]);
  });

  it('never overwrites an existing identity directory that fails verification', () => {
    const { manifestPath, hostGit, store } = host();
    qualifyTools({ manifestPath, requests: [gitRequest(hostGit)] });
    const manifest = manifestOf(manifestPath);
    const { directory } = materializeTool({ manifest, storeRoot: store, toolId: 'git' });
    chmodSync(join(directory, 'bin', 'git'), 0o755);
    expect(codeOf(() => materializeTool({ manifest, storeRoot: store, toolId: 'git' }))).toBe('toolchain/capsule-conflict');
  });

  it('adopts newer bytes only after explicit requalification and materialization, and rolls back by manifest', () => {
    const { manifestPath, hostGit, store } = host();
    const first = qualifyTools({ manifestPath, requests: [gitRequest(hostGit)] });
    const approvedManifest = readFileSync(manifestPath);
    materializeTool({ manifest: manifestOf(manifestPath), storeRoot: store, toolId: 'git' });

    writeFileSync(hostGit, staticElf('git version 2.43.1\n'));
    qualifyTools({ manifestPath, requests: [gitRequest(hostGit, 'git version 2.43.1\n')], replaceManifestSha256: first.manifestSha256 });
    const requalified = manifestOf(manifestPath);
    expect(codeOf(() => runTool({ manifest: requalified, storeRoot: store, toolId: 'git', args: ['--version'] }))).toBe('toolchain/not-materialized');
    materializeTool({ manifest: requalified, storeRoot: store, toolId: 'git' });
    expect(runTool({ manifest: requalified, storeRoot: store, toolId: 'git', args: ['--version'] }).stdout.toString()).toBe('git version 2.43.1\n');
    expect(driftReport({ manifest: requalified, storeRoot: store })[0]?.stale).toEqual([first.changes[0]?.treeSha256]);

    // Rollback restores the previous reviewed manifest; its capsule was never overwritten.
    const rolledBack = parseManifest(approvedManifest, { expectedSha256: first.manifestSha256 }).manifest;
    expect(runTool({ manifest: rolledBack, storeRoot: store, toolId: 'git', args: ['--version'] }).stdout.toString()).toBe(V2430);
  });

  it('runs an interpreted tool only through its verified interpreter capsule', () => {
    const { root, manifestPath, store } = host();
    const nodePath = join(root, 'node');
    const scriptPath = join(root, 'pnpm.cjs');
    writeFileSync(nodePath, staticElf('11.11.0\n'));
    writeFileSync(scriptPath, 'inert synthetic script\n');
    const request = (id: string, tool: Record<string, unknown>) => ({ schemaVersion: 1, kind: 'boundaryci-toolchain-qualification-request', qualifiedOn: '2026-11-04', tool: { id, environment: [], pathEntries: [], version: { args: ['--version'], stdout: '11.11.0\n' }, ...tool } });
    qualifyTools({
      manifestPath,
      requests: [
        request('node', { entrypoint: 'bin/node', files: [{ path: 'bin/node', from: nodePath, mode: '0555' }], invocation: { kind: 'direct' } }),
        request('pnpm', { entrypoint: 'dist/pnpm.cjs', files: [{ path: 'dist/pnpm.cjs', from: scriptPath, mode: '0444' }], invocation: { kind: 'interpreter', tool: 'node', script: 'dist/pnpm.cjs' } }),
      ],
    });
    const manifest = manifestOf(manifestPath);
    expect(codeOf(() => materializeTool({ manifest, storeRoot: store, toolId: 'pnpm' }))).toBe('toolchain/not-materialized');
    materializeTool({ manifest, storeRoot: store, toolId: 'node' });
    materializeTool({ manifest, storeRoot: store, toolId: 'pnpm' });
    expect(verifyTool({ manifest, storeRoot: store, toolId: 'pnpm' }).map((entry) => entry.tool.id)).toEqual(['node', 'pnpm']);
    const nodeDirectory = join(store, 'node', manifest.tools[0]?.treeSha256 ?? '');
    chmodSync(join(nodeDirectory, 'bin', 'node'), 0o755);
    expect(codeOf(() => runTool({ manifest, storeRoot: store, toolId: 'pnpm', args: ['--version'] }))).toBe('toolchain/file-mode');
  });
});

describe.runIf(CAN_EXECUTE_SYNTHETIC_ELF)('toolchain command line', () => {
  it('qualifies, materializes, verifies, runs, and reports drift with stable outcomes', () => {
    const { root, manifestPath, hostGit, store } = host();
    const requestPath = join(root, 'git.request.json');
    writeFileSync(requestPath, JSON.stringify(gitRequest(hostGit)));
    const qualified = cli(['qualify', '--manifest', manifestPath, '--request', requestPath]);
    expect(qualified.status).toBe(0);
    expect(qualified.stdout).toContain('toolchain:pass:qualify:review-required');
    const pinned = sha256Hex(readFileSync(manifestPath));

    expect(cli(['materialize', '--manifest', manifestPath, '--store', store, '--tool', 'git', '--manifest-sha256', pinned]).stdout).toBe('toolchain:pass:materialize:materialized\n');
    const verified = cli(['verify', '--manifest', manifestPath, '--store', store, '--probe', '--manifest-sha256', pinned]);
    expect(verified.status).toBe(0);
    expect(verified.stdout).toContain(`toolchain:pass:verify:${pinned}`);
    const ran = cli(['run', '--manifest', manifestPath, '--store', store, '--tool', 'git', '--', '--version']);
    expect([ran.status, ran.stdout]).toEqual([0, V2430]);

    writeFileSync(hostGit, UBUNTU_REBUILD);
    const drift = JSON.parse(cli(['drift', '--manifest', manifestPath, '--store', store]).stdout) as { tools: { sources: { state: string }[] }[] };
    expect(drift.tools[0]?.sources[0]?.state).toBe('changed');
    expect(cli(['run', '--manifest', manifestPath, '--store', store, '--tool', 'git', '--', '--version']).stdout).toBe(V2430);
  });

  it('fails closed with stable codes and never falls back to PATH', () => {
    const { root, manifestPath, hostGit, store } = host();
    const requestPath = join(root, 'git.request.json');
    writeFileSync(requestPath, JSON.stringify(gitRequest(hostGit)));
    cli(['qualify', '--manifest', manifestPath, '--request', requestPath]);
    const missing = spawnSync(process.execPath, [CLI, 'run', '--manifest', manifestPath, '--store', store, '--tool', 'git', '--', '--version'], {
      encoding: 'utf8',
      env: { PATH: join(root, 'usr', 'bin') },
    });
    expect(missing.status).toBe(1);
    expect(missing.stdout).toBe('');
    expect(missing.stderr).toMatch(/^toolchain\/not-materialized/u);
    const wrongPin = cli(['verify', '--manifest', manifestPath, '--store', store, '--manifest-sha256', '0'.repeat(64)]);
    expect([wrongPin.status, wrongPin.stderr.split(':')[0]]).toEqual([1, 'toolchain/manifest-digest-mismatch']);
    const requalify = cli(['qualify', '--manifest', manifestPath, '--request', requestPath]);
    expect([requalify.status, requalify.stderr.split(':')[0]]).toEqual([1, 'toolchain/requalify-requires-explicit-replace']);
    const usage = cli(['run', '--manifest', manifestPath, '--store', store]);
    expect(usage.status).toBe(2);
    expect(cli(['download', '--manifest', manifestPath]).status).toBe(2);
  });
});
