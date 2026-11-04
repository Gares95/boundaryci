import { describe, expect, it } from 'vitest';

import { assertCapsuleClosure, inspectElf } from '../../tools/toolchain/elf.mjs';
import { canonicalJson, computeTreeSha256, parseManifest, sha256Hex } from '../../tools/toolchain/manifest.mjs';
import { dynamicElf, fixtureManifest, fixtureTool, manifestBytes, staticElf } from './fixtures.js';

const GIT = staticElf('git version 2.43.0\n');

function gitTool(): ReturnType<typeof fixtureTool> {
  return fixtureTool({ files: [{ path: 'bin/git', bytes: GIT, from: '/usr/bin/git' }], entrypoint: 'bin/git', pathEntries: ['bin'] });
}

function codeOf(action: () => unknown): string {
  try {
    action();
  } catch (error) {
    return (error as { code?: string }).code ?? 'uncoded';
  }
  return 'no-error';
}

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

describe('toolchain manifest', () => {
  it('accepts canonical bytes and reports their exact digest', () => {
    const bytes = manifestBytes(fixtureManifest([gitTool()]));
    const parsed = parseManifest(bytes, { expectedSha256: sha256Hex(bytes) });
    expect(parsed.manifestSha256).toBe(sha256Hex(bytes));
    expect(parsed.manifest.tools[0]?.files[0]?.sha256).toBe(sha256Hex(GIT));
    expect(Object.isFrozen(parsed.manifest.tools[0])).toBe(true);
  });

  it('refuses bytes other than the pinned manifest before parsing them', () => {
    const bytes = manifestBytes(fixtureManifest([gitTool()]));
    expect(codeOf(() => parseManifest(bytes, { expectedSha256: '0'.repeat(64) }))).toBe('toolchain/manifest-digest-mismatch');
  });

  it('refuses semantically equal but non-canonical encodings', () => {
    const manifest = fixtureManifest([gitTool()]);
    expect(codeOf(() => parseManifest(Buffer.from(JSON.stringify(manifest))))).toBe('toolchain/manifest-noncanonical');
    expect(codeOf(() => parseManifest(Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`)))).toBe('toolchain/manifest-noncanonical');
    expect(codeOf(() => parseManifest(Buffer.from(canonicalJson(manifest).replace(/\n$/u, '\r\n'))))).toBe('toolchain/manifest-noncanonical');
  });

  it('refuses unknown fields and unsupported headers', () => {
    const extra = { ...fixtureManifest([gitTool()]), trusted: true };
    expect(codeOf(() => parseManifest(manifestBytes(extra)))).toBe('toolchain/manifest-schema');
    const platform = { ...fixtureManifest([gitTool()]), platform: 'linux-arm64' };
    expect(codeOf(() => parseManifest(manifestBytes(platform)))).toBe('toolchain/manifest-schema');
    expect(codeOf(() => parseManifest(Buffer.from([0xff, 0xfe])))).toBe('toolchain/manifest-read');
  });

  it('detects a tampered file digest whose identity was not recomputed', () => {
    const tool = clone(gitTool()) as { files: { sha256: string }[] };
    (tool.files[0] as { sha256: string }).sha256 = sha256Hex(staticElf('git version 2.43.0\n', { padding: Buffer.from([1]) }));
    expect(codeOf(() => parseManifest(manifestBytes(fixtureManifest([tool as never]))))).toBe('toolchain/manifest-tree-mismatch');
  });

  it('binds the version expectation, environment, and invocation into the identity', () => {
    const base = gitTool();
    for (const mutate of [
      (tool: Record<string, unknown>) => { tool.version = { args: ['--version'], stdout: 'git version 2.43.1\n' }; },
      (tool: Record<string, unknown>) => { tool.environment = [{ name: 'GIT_CONFIG_NOSYSTEM', value: '1' }]; },
      (tool: Record<string, unknown>) => { tool.pathEntries = []; },
    ]) {
      const tool = clone(base);
      mutate(tool);
      expect(computeTreeSha256(tool)).not.toBe(base.treeSha256);
      expect(codeOf(() => parseManifest(manifestBytes(fixtureManifest([tool]))))).toBe('toolchain/manifest-tree-mismatch');
    }
  });

  it('keeps qualification provenance outside the executable identity', () => {
    const tool = clone(gitTool()) as { qualification: { sources: { from: string }[] } };
    (tool.qualification.sources[0] as { from: string }).from = '/opt/other/git';
    expect(computeTreeSha256(tool as never)).toBe(gitTool().treeSha256);
  });

  it.each([
    ['parent traversal', '../bin/git'],
    ['absolute path', '/usr/bin/git'],
    ['empty segment', 'bin//git'],
    ['dot segment', './bin/git'],
    ['control character', 'bin/gi\nt'],
  ])('refuses an unexpected executable path: %s', (_name, path) => {
    const tool = fixtureTool({ files: [{ path, bytes: GIT }], entrypoint: path });
    expect(codeOf(() => parseManifest(manifestBytes(fixtureManifest([tool]))))).toBe('toolchain/manifest-path');
  });

  it('refuses an entrypoint that is not a listed executable file', () => {
    const unlisted = fixtureTool({ files: [{ path: 'bin/git', bytes: GIT }], entrypoint: 'bin/other' });
    expect(codeOf(() => parseManifest(manifestBytes(fixtureManifest([unlisted]))))).toBe('toolchain/manifest-path');
    const readOnly = fixtureTool({ files: [{ path: 'bin/git', bytes: GIT, mode: '0444' }], entrypoint: 'bin/git' });
    expect(codeOf(() => parseManifest(manifestBytes(fixtureManifest([readOnly]))))).toBe('toolchain/manifest-path');
  });

  it.each(['PATH', 'LD_PRELOAD', 'LD_LIBRARY_PATH', 'NODE_OPTIONS', 'GCONV_PATH', 'GLIBC_TUNABLES', 'COREPACK_HOME'])(
    'refuses a declared loader or runner variable: %s',
    (name) => {
      const tool = fixtureTool({ files: [{ path: 'bin/git', bytes: GIT }], entrypoint: 'bin/git', environment: [{ name, value: '/tmp' }] });
      expect(codeOf(() => parseManifest(manifestBytes(fixtureManifest([tool]))))).toBe('toolchain/env-forbidden');
    },
  );

  it('binds an interpreted tool to the exact interpreter identity', () => {
    const node = fixtureTool({ id: 'node', files: [{ path: 'bin/node', bytes: staticElf('v24.19.0\n') }], entrypoint: 'bin/node', version: { args: ['--version'], stdout: 'v24.19.0\n' } });
    const pnpm = (treeSha256: string) => fixtureTool({
      id: 'pnpm',
      files: [{ path: 'dist/pnpm.cjs', bytes: Buffer.from('inert\n'), mode: '0444' }],
      entrypoint: 'dist/pnpm.cjs',
      invocation: { kind: 'interpreter', tool: 'node', toolTreeSha256: treeSha256, script: 'dist/pnpm.cjs' },
      version: { args: ['--version'], stdout: '11.11.0\n' },
    });
    expect(parseManifest(manifestBytes(fixtureManifest([node, pnpm(node.treeSha256)]))).manifest.tools).toHaveLength(2);
    expect(codeOf(() => parseManifest(manifestBytes(fixtureManifest([node, pnpm('a'.repeat(64))]))))).toBe('toolchain/manifest-tree-mismatch');
    expect(codeOf(() => parseManifest(manifestBytes(fixtureManifest([pnpm(node.treeSha256)]))))).toBe('toolchain/manifest-schema');
  });
});

describe('ELF closure facts', () => {
  it('reads a synthetic static executable as self-contained', () => {
    expect(inspectElf(GIT)).toEqual({ elf: true, interpreter: null, needed: [], rpath: [], runpath: [] });
  });

  it('reads the interpreter, DT_NEEDED, and search paths of a dynamic executable', () => {
    const facts = inspectElf(dynamicElf({ interpreter: '/lib64/ld-linux-x86-64.so.2', needed: ['libz.so.1', 'libc.so.6'], runpath: ['/usr/lib/git'] }));
    expect(facts).toEqual({ elf: true, interpreter: '/lib64/ld-linux-x86-64.so.2', needed: ['libz.so.1', 'libc.so.6'], rpath: [], runpath: ['/usr/lib/git'] });
  });

  it('reports scripts as non-ELF', () => {
    expect(inspectElf(Buffer.from('#!/bin/sh\necho git\n'))).toEqual({ elf: false, shebang: true });
  });

  it.each([
    ['truncated header', (bytes: Buffer) => bytes.subarray(0, 40)],
    ['program headers outside the file', (bytes: Buffer) => { const copy = Buffer.from(bytes); copy.writeBigUInt64LE(1n << 40n, 32); return copy; }],
    ['other machine', (bytes: Buffer) => { const copy = Buffer.from(bytes); copy.writeUInt16LE(0xb7, 18); return copy; }],
    ['unterminated dynamic section', (bytes: Buffer) => bytes.subarray(0, bytes.length - 16)],
  ])('fails closed on malformed ELF: %s', (_name, mutate) => {
    const bytes = mutate(dynamicElf({ interpreter: '/lib64/ld-linux-x86-64.so.2', needed: ['libc.so.6'] }));
    expect(codeOf(() => inspectElf(bytes))).toBe('toolchain/closure');
  });

  const loader = dynamicElf({});
  const libc = dynamicElf({ needed: ['ld-linux-x86-64.so.2'] });
  const git = dynamicElf({ interpreter: '/lib64/ld-linux-x86-64.so.2', needed: ['libz.so.1', 'libc.so.6'] });
  const libz = dynamicElf({ needed: ['libc.so.6'] });
  const loaderTool = { entrypoint: 'bin/git', invocation: { kind: 'elf-loader', loader: 'lib/ld-linux-x86-64.so.2', libraryPath: ['lib'] } };
  const complete = new Map([
    ['bin/git', git],
    ['lib/ld-linux-x86-64.so.2', loader],
    ['lib/libc.so.6', libc],
    ['lib/libz.so.1', libz],
  ]);

  it('accepts a loader closure whose every DT_NEEDED resolves inside the capsule', () => {
    expect(() => assertCapsuleClosure(loaderTool, complete)).not.toThrow();
  });

  it('refuses a closure that would fall back to a host library', () => {
    const missing = new Map(complete);
    missing.delete('lib/libz.so.1');
    expect(codeOf(() => assertCapsuleClosure(loaderTool, missing))).toBe('toolchain/closure');
  });

  it('refuses embedded RPATH or RUNPATH that could redirect library search', () => {
    for (const library of [dynamicElf({ needed: ['libc.so.6'], runpath: ['/usr/lib'] }), dynamicElf({ needed: ['libc.so.6'], rpath: ['$ORIGIN/../host'] })]) {
      const closure = new Map(complete);
      closure.set('lib/libz.so.1', library);
      expect(codeOf(() => assertCapsuleClosure(loaderTool, closure))).toBe('toolchain/closure');
    }
  });

  it('refuses direct invocation of anything that would use a host loader or interpreter', () => {
    const direct = { entrypoint: 'bin/git', invocation: { kind: 'direct' } };
    expect(codeOf(() => assertCapsuleClosure(direct, new Map([['bin/git', git]])))).toBe('toolchain/closure');
    expect(codeOf(() => assertCapsuleClosure(direct, new Map([['bin/git', Buffer.from('#!/bin/sh\n')]])))).toBe('toolchain/closure');
    expect(() => assertCapsuleClosure(direct, new Map([['bin/git', GIT]]))).not.toThrow();
  });
});
