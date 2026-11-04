import { chmodSync, chownSync, linkSync, mkdirSync, readFileSync, readdirSync, renameSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterEach, describe, expect, it } from 'vitest';

import { buildInvocation, executeVerified, probeVersion, runTool, verifyTool } from '../../tools/toolchain/capsule.mjs';
import { ToolchainError } from '../../tools/toolchain/errors.mjs';
import { parseManifest } from '../../tools/toolchain/manifest.mjs';
import {
  CAN_EXECUTE_SYNTHETIC_ELF,
  cleanupWorkspaces,
  fixtureManifest,
  fixtureTool,
  layoutCapsule,
  manifestBytes,
  staticElf,
  withWritable,
  workspace,
  type FixtureFile,
} from './fixtures.js';

const TOOLCHAIN_DIRECTORY = fileURLToPath(new URL('../../tools/toolchain/', import.meta.url));
const VERSION = 'git version 2.43.0\n';
const APPROVED = staticElf(VERSION);
const REBUILT_SAME_VERSION = staticElf(VERSION, { padding: Buffer.from('ubuntu7.5') });

afterEach(cleanupWorkspaces);

function codeOf(action: () => unknown): string {
  try {
    action();
  } catch (error) {
    return (error as { code?: string }).code ?? `uncoded: ${String(error)}`;
  }
  return 'no-error';
}

function setup(files: FixtureFile[] = [{ path: 'bin/git', bytes: APPROVED }]) {
  const root = workspace();
  const store = join(root, 'store');
  mkdirSync(store, { mode: 0o755 });
  chmodSync(store, 0o755);
  const tool = fixtureTool({
    files,
    entrypoint: 'bin/git',
    pathEntries: ['bin'],
    environment: [
      { name: 'GIT_CONFIG_NOSYSTEM', value: '1' },
      { name: 'GIT_EXEC_PATH', capsulePath: 'libexec/git-core' },
    ],
  });
  const { manifest } = parseManifest(manifestBytes(fixtureManifest([tool])));
  const directory = layoutCapsule(store, tool, files);
  return { root, store, tool, manifest, directory, options: { manifest, storeRoot: store, toolId: 'git' } };
}

describe.runIf(CAN_EXECUTE_SYNTHETIC_ELF)('approved toolchain capsule', () => {
  it('verifies and runs the exact approved bytes by absolute capsule path', () => {
    const { options, directory } = setup();
    expect(verifyTool(options).map((entry) => entry.directory)).toEqual([directory]);
    const result = runTool({ ...options, args: ['--version'] });
    expect(result.status).toBe(0);
    expect(result.stdout.toString()).toBe(VERSION);
    expect(() => probeVersion(options)).not.toThrow();
  });

  it('refuses bytes that report the same version but differ from the approved identity', () => {
    const { options, directory } = setup();
    withWritable(join(directory, 'bin'), () => {
      unlinkSync(join(directory, 'bin', 'git'));
      writeFileSync(join(directory, 'bin', 'git'), REBUILT_SAME_VERSION, { mode: 0o555 });
      chmodSync(join(directory, 'bin', 'git'), 0o555);
    });
    expect(codeOf(() => verifyTool(options))).toBe('toolchain/file-size');
    expect(codeOf(() => runTool({ ...options, args: ['--version'] }))).toBe('toolchain/file-size');
    expect(codeOf(() => probeVersion(options))).toBe('toolchain/file-size');
  });

  it('refuses same-size replacement bytes by digest', () => {
    const sameSize = staticElf(VERSION, { padding: Buffer.from('a') });
    const { options, directory } = setup([{ path: 'bin/git', bytes: staticElf(VERSION, { padding: Buffer.from('b') }) }]);
    withWritable(join(directory, 'bin'), () => {
      unlinkSync(join(directory, 'bin', 'git'));
      writeFileSync(join(directory, 'bin', 'git'), sameSize);
      chmodSync(join(directory, 'bin', 'git'), 0o555);
    });
    expect(codeOf(() => verifyTool(options))).toBe('toolchain/file-digest');
  });

  it('refuses a symbolic link substituted for an approved file, even to identical bytes', () => {
    const { options, directory, root } = setup();
    const elsewhere = join(root, 'identical-git');
    writeFileSync(elsewhere, APPROVED, { mode: 0o555 });
    withWritable(join(directory, 'bin'), () => {
      unlinkSync(join(directory, 'bin', 'git'));
      symlinkSync(elsewhere, join(directory, 'bin', 'git'));
    });
    expect(codeOf(() => runTool({ ...options, args: ['--version'] }))).toBe('toolchain/file-type');
  });

  it('refuses a symbolic link substituted for a capsule directory', () => {
    const { options, directory, root } = setup();
    const elsewhere = join(root, 'bin-copy');
    mkdirSync(elsewhere);
    writeFileSync(join(elsewhere, 'git'), APPROVED, { mode: 0o555 });
    withWritable(directory, () => {
      renameSync(join(directory, 'bin'), join(root, 'old-bin'));
      symlinkSync(elsewhere, join(directory, 'bin'));
    });
    expect(codeOf(() => verifyTool(options))).toBe('toolchain/file-type');
  });

  it('re-verifies on every run so replacement after an earlier validation is caught', () => {
    const { options, directory } = setup();
    expect(runTool({ ...options, args: ['--version'] }).stdout.toString()).toBe(VERSION);
    withWritable(join(directory, 'bin'), () => {
      chmodSync(join(directory, 'bin', 'git'), 0o755);
      writeFileSync(join(directory, 'bin', 'git'), staticElf('owned\n', { padding: Buffer.alloc(VERSION.length - 6) }));
      chmodSync(join(directory, 'bin', 'git'), 0o555);
    });
    expect(codeOf(() => runTool({ ...options, args: ['--version'] }))).toBe('toolchain/file-digest');
  });

  it('discards the result when the capsule changes while the tool runs', () => {
    const { options } = setup();
    let calls = 0;
    const verify = () => {
      calls += 1;
      if (calls === 2) {
        throw new ToolchainError('toolchain/file-digest', 'simulated concurrent replacement');
      }
      return verifyTool(options);
    };
    expect(codeOf(() => executeVerified(verify, { toolId: 'git', args: ['--version'] }))).toBe('toolchain/changed-during-run');
    expect(calls).toBe(2);
  });

  it.each([
    ['group-writable file', (directory: string) => withWritable(join(directory, 'bin'), () => chmodSync(join(directory, 'bin', 'git'), 0o575)), 'toolchain/file-mode'],
    ['owner-writable file', (directory: string) => chmodSync(join(directory, 'bin', 'git'), 0o755), 'toolchain/file-mode'],
    ['setuid file', (directory: string) => chmodSync(join(directory, 'bin', 'git'), 0o4555), 'toolchain/file-mode'],
    ['writable capsule directory', (directory: string) => chmodSync(join(directory, 'bin'), 0o755), 'toolchain/dir-unsafe'],
    ['writable capsule root', (directory: string) => chmodSync(directory, 0o755), 'toolchain/dir-unsafe'],
  ])('refuses wrong modes: %s', (_name, mutate, code) => {
    const { options, directory } = setup();
    mutate(directory);
    expect(codeOf(() => verifyTool(options))).toBe(code);
  });

  it('refuses a store root or tool directory writable by other users', () => {
    const first = setup();
    chmodSync(first.store, 0o777);
    expect(codeOf(() => verifyTool(first.options))).toBe('toolchain/store-unsafe');
    const second = setup();
    chmodSync(join(second.store, 'git'), 0o775);
    expect(codeOf(() => verifyTool(second.options))).toBe('toolchain/store-unsafe');
  });

  it('refuses a store root reached through a symbolic link', () => {
    const { options, root, store } = setup();
    symlinkSync(store, join(root, 'store-link'));
    expect(codeOf(() => verifyTool({ ...options, storeRoot: join(root, 'store-link') }))).toBe('toolchain/store-unsafe');
  });

  it('refuses an untrusted owner', () => {
    const { options, directory } = setup();
    const uid = process.geteuid?.() ?? -1;
    if (uid === 0) {
      chownSync(join(directory, 'bin', 'git'), 4242, 4242);
      expect(codeOf(() => verifyTool(options))).toBe('toolchain/file-owner');
    } else {
      // A non-root invoker owns the store, which the root-only policy refuses.
      expect(codeOf(() => verifyTool({ ...options, ownerPolicy: 'root-only' }))).toBe('toolchain/store-unsafe');
    }
  });

  it('refuses an approved file that has another hard link', () => {
    const { options, directory, root } = setup();
    linkSync(join(directory, 'bin', 'git'), join(root, 'second-name'));
    expect(codeOf(() => verifyTool(options))).toBe('toolchain/file-hardlink');
  });

  it('refuses unlisted files that a loader or exec path could pick up', () => {
    const { options, directory } = setup();
    withWritable(directory, () => {
      mkdirSync(join(directory, 'libexec'));
      writeFileSync(join(directory, 'libexec', 'git-remote-https'), APPROVED, { mode: 0o555 });
      chmodSync(join(directory, 'libexec'), 0o555);
    });
    expect(codeOf(() => verifyTool(options))).toBe('toolchain/unexpected-file');
  });

  it('refuses a capsule missing an approved file', () => {
    const files: FixtureFile[] = [{ path: 'bin/git', bytes: APPROVED }, { path: 'share/notes.txt', bytes: Buffer.from('notes\n'), mode: '0444' }];
    const { options, directory } = setup(files);
    withWritable(join(directory, 'share'), () => unlinkSync(join(directory, 'share', 'notes.txt')));
    expect(codeOf(() => verifyTool(options))).toBe('toolchain/file-missing');
  });

  it('reports a missing tool without searching PATH or the network', () => {
    const { options, directory, store } = setup();
    withWritable(join(store, 'git'), () => renameSync(directory, join(store, 'moved')));
    const originalFetch = globalThis.fetch;
    let fetchCalls = 0;
    globalThis.fetch = (() => {
      fetchCalls += 1;
      throw new Error('network is forbidden');
    }) as typeof fetch;
    try {
      expect(codeOf(() => runTool({ ...options, args: ['--version'] }))).toBe('toolchain/not-materialized');
      expect(codeOf(() => runTool({ ...options, toolId: 'node', args: [] }))).toBe('toolchain/unknown-tool');
    } finally {
      globalThis.fetch = originalFetch;
    }
    expect(fetchCalls).toBe(0);
  });

  it('never uses a stale capsule left from a previous identity', () => {
    const previous = setup();
    const newer = fixtureTool({ files: [{ path: 'bin/git', bytes: REBUILT_SAME_VERSION }], entrypoint: 'bin/git', pathEntries: ['bin'] });
    const { manifest } = parseManifest(manifestBytes(fixtureManifest([newer])));
    expect(readdirSync(join(previous.store, 'git'))).toEqual([previous.tool.treeSha256]);
    expect(codeOf(() => runTool({ manifest, storeRoot: previous.store, toolId: 'git', args: ['--version'] }))).toBe('toolchain/not-materialized');
  });

  it('builds a closed environment that inherits nothing from the caller process', () => {
    const { options, directory } = setup();
    process.env.HTTPS_PROXY = 'http://proxy.invalid';
    try {
      const command = buildInvocation(verifyTool(options), ['status'], { GIT_DIR: '/work/.git' });
      expect(command.file).toBe(join(directory, 'bin', 'git'));
      expect(command.env).toEqual({
        GIT_CONFIG_NOSYSTEM: '1',
        GIT_DIR: '/work/.git',
        GIT_EXEC_PATH: join(directory, 'libexec', 'git-core'),
        PATH: join(directory, 'bin'),
      });
    } finally {
      delete process.env.HTTPS_PROXY;
    }
  });

  it.each(['PATH', 'LD_PRELOAD', 'LD_AUDIT', 'NODE_OPTIONS', 'GIT_EXEC_PATH', 'lowercase'])('refuses caller environment override %s', (name) => {
    const { options } = setup();
    expect(codeOf(() => buildInvocation(verifyTool(options), [], { [name]: '/tmp' }))).toBe('toolchain/env-forbidden');
  });

  it('runs loader-mode tools through the capsule loader with host fallback disabled', () => {
    const files: FixtureFile[] = [
      { path: 'bin/git', bytes: APPROVED },
      { path: 'lib/ld-linux-x86-64.so.2', bytes: staticElf('loader\n') },
    ];
    const root = workspace();
    const store = join(root, 'store');
    mkdirSync(store);
    chmodSync(store, 0o755);
    const tool = fixtureTool({ files, entrypoint: 'bin/git', invocation: { kind: 'elf-loader', loader: 'lib/ld-linux-x86-64.so.2', libraryPath: ['lib'] } });
    const { manifest } = parseManifest(manifestBytes(fixtureManifest([tool])));
    const directory = layoutCapsule(store, tool, files);
    const command = buildInvocation(verifyTool({ manifest, storeRoot: store, toolId: 'git' }), ['rev-parse', 'HEAD']);
    const program = join(directory, 'bin', 'git');
    expect(command.file).toBe(join(directory, 'lib', 'ld-linux-x86-64.so.2'));
    expect(command.argv).toEqual(['--inhibit-cache', '--library-path', join(directory, 'lib'), '--argv0', program, program, 'rev-parse', 'HEAD']);
  });
});

describe('frozen execution has no network path', () => {
  it('imports no network module and calls no fetch API', () => {
    const forbidden = /from\s+['"](?:node:)?(?:http|https|http2|net|tls|dns|dgram|undici)['"]|\bfetch\s*\(|\bWebSocket\b|\bXMLHttpRequest\b/u;
    const sources = readdirSync(TOOLCHAIN_DIRECTORY).filter((name) => name.endsWith('.mjs'));
    expect(sources.length).toBeGreaterThan(0);
    for (const name of sources) expect(forbidden.test(readFileSync(join(TOOLCHAIN_DIRECTORY, name), 'utf8')), name).toBe(false);
  });
});
