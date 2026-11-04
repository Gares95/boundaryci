import { chmodSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import { canonicalJson, computeTreeSha256, sha256Hex } from '../../tools/toolchain/manifest.mjs';

/** Linux x86-64 only: the synthetic executables below are raw x86-64 machine code. */
export const CAN_EXECUTE_SYNTHETIC_ELF = process.platform === 'linux' && process.arch === 'x64';

function u32(value: number): Buffer {
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32LE(value);
  return bytes;
}

/**
 * A complete static ELF64 executable that writes `message` to stdout and exits with `exitCode`.
 * `padding` bytes are appended after the message: they change the file identity without changing
 * observable behavior, which models a rebuilt package with an identical version string.
 */
export function staticElf(message: string, options: { exitCode?: number; padding?: Buffer } = {}): Buffer {
  const text = Buffer.from(message, 'utf8');
  const code = Buffer.concat([
    Buffer.from([0xb8, 0x01, 0x00, 0x00, 0x00]), // mov eax, 1 (write)
    Buffer.from([0xbf, 0x01, 0x00, 0x00, 0x00]), // mov edi, 1 (stdout)
    Buffer.from([0x48, 0x8d, 0x35]), // lea rsi, [rip + message]
    u32(36 - 17),
    Buffer.from([0xba]), // mov edx, length
    u32(text.length),
    Buffer.from([0x0f, 0x05]), // syscall
    Buffer.from([0xb8, 0x3c, 0x00, 0x00, 0x00]), // mov eax, 60 (exit)
    Buffer.from([0xbf, options.exitCode ?? 0, 0x00, 0x00, 0x00]), // mov edi, status
    Buffer.from([0x0f, 0x05]), // syscall
    text,
    options.padding ?? Buffer.alloc(0),
  ]);
  const total = 64 + 56 + code.length;
  const header = Buffer.alloc(120);
  header.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0]);
  header.writeUInt16LE(2, 16); // ET_EXEC
  header.writeUInt16LE(0x3e, 18); // x86-64
  header.writeUInt32LE(1, 20);
  header.writeBigUInt64LE(0x400000n + 120n, 24); // entry
  header.writeBigUInt64LE(64n, 32); // program headers
  header.writeUInt16LE(64, 52);
  header.writeUInt16LE(56, 54);
  header.writeUInt16LE(1, 56);
  header.writeUInt16LE(64, 58);
  header.writeUInt32LE(1, 64); // PT_LOAD
  header.writeUInt32LE(5, 68); // R + X
  header.writeBigUInt64LE(0n, 72);
  header.writeBigUInt64LE(0x400000n, 80);
  header.writeBigUInt64LE(0x400000n, 88);
  header.writeBigUInt64LE(BigInt(total), 96);
  header.writeBigUInt64LE(BigInt(total), 104);
  header.writeBigUInt64LE(0x1000n, 112);
  return Buffer.concat([header, code]);
}

/** A parse-only dynamic ELF64 with the requested interpreter, DT_NEEDED, and search paths. */
export function dynamicElf(options: { interpreter?: string; needed?: string[]; rpath?: string[]; runpath?: string[] }): Buffer {
  const base = 0x400000;
  const programCount = 3;
  const interpOffset = 64 + programCount * 56;
  const interp = options.interpreter === undefined ? Buffer.alloc(0) : Buffer.from(`${options.interpreter}\0`, 'latin1');
  const strings: Buffer[] = [Buffer.from([0])];
  let stringSize = 1;
  const addString = (value: string): number => {
    const offset = stringSize;
    const bytes = Buffer.from(`${value}\0`, 'latin1');
    strings.push(bytes);
    stringSize += bytes.length;
    return offset;
  };
  const dynamicEntries: [bigint, bigint][] = [];
  for (const name of options.needed ?? []) dynamicEntries.push([1n, BigInt(addString(name))]);
  for (const path of options.rpath ?? []) dynamicEntries.push([15n, BigInt(addString(path))]);
  for (const path of options.runpath ?? []) dynamicEntries.push([29n, BigInt(addString(path))]);
  const stringOffset = interpOffset + interp.length;
  const stringTable = Buffer.concat(strings);
  const dynamicOffset = Math.ceil((stringOffset + stringTable.length) / 8) * 8;
  dynamicEntries.push([5n, BigInt(base + stringOffset)], [10n, BigInt(stringTable.length)], [0n, 0n]);
  const total = dynamicOffset + dynamicEntries.length * 16;
  const bytes = Buffer.alloc(total);
  bytes.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0]);
  bytes.writeUInt16LE(3, 16); // ET_DYN
  bytes.writeUInt16LE(0x3e, 18);
  bytes.writeUInt32LE(1, 20);
  bytes.writeBigUInt64LE(64n, 32);
  bytes.writeUInt16LE(64, 52);
  bytes.writeUInt16LE(56, 54);
  bytes.writeUInt16LE(programCount, 56);
  const program = (index: number, type: number, offset: number, size: number): void => {
    const at = 64 + index * 56;
    bytes.writeUInt32LE(type, at);
    bytes.writeUInt32LE(4, at + 4);
    bytes.writeBigUInt64LE(BigInt(offset), at + 8);
    bytes.writeBigUInt64LE(BigInt(base + offset), at + 16);
    bytes.writeBigUInt64LE(BigInt(base + offset), at + 24);
    bytes.writeBigUInt64LE(BigInt(size), at + 32);
    bytes.writeBigUInt64LE(BigInt(size), at + 40);
  };
  program(0, 1, 0, total);
  // A file without an interpreter still carries the slot, retyped as PT_NULL.
  program(1, options.interpreter === undefined ? 0 : 3, interpOffset, interp.length);
  program(2, 2, dynamicOffset, dynamicEntries.length * 16);
  interp.copy(bytes, interpOffset);
  stringTable.copy(bytes, stringOffset);
  dynamicEntries.forEach(([tag, value], index) => {
    bytes.writeBigInt64LE(tag, dynamicOffset + index * 16);
    bytes.writeBigUInt64LE(value, dynamicOffset + index * 16 + 8);
  });
  return bytes;
}

export interface FixtureFile {
  path: string;
  bytes: Buffer;
  mode?: '0444' | '0555';
  from?: string;
}

export interface FixtureToolOptions {
  id?: string;
  files: FixtureFile[];
  entrypoint: string;
  invocation?: Record<string, unknown>;
  environment?: Record<string, string>[];
  pathEntries?: string[];
  version?: { args: string[]; stdout: string };
}

export type FixtureTool = Record<string, unknown> & { id: string; treeSha256: string };

export function fixtureTool(options: FixtureToolOptions): FixtureTool {
  const files = [...options.files]
    .sort((left, right) => (left.path < right.path ? -1 : 1))
    .map((file) => ({ path: file.path, sha256: sha256Hex(file.bytes), size: file.bytes.length, mode: file.mode ?? '0555' }));
  const tool: Record<string, unknown> = {
    id: options.id ?? 'git',
    entrypoint: options.entrypoint,
    files,
    invocation: options.invocation ?? { kind: 'direct' },
    environment: options.environment ?? [],
    pathEntries: options.pathEntries ?? [],
    version: options.version ?? { args: ['--version'], stdout: 'git version 2.43.0\n' },
    qualification: {
      qualifiedOn: '2026-11-04',
      sources: [...options.files]
        .sort((left, right) => (left.path < right.path ? -1 : 1))
        .map((file) => ({ path: file.path, from: file.from ?? `/synthetic/host/${file.path}` })),
    },
  };
  tool.treeSha256 = computeTreeSha256(tool);
  return tool as FixtureTool;
}

export function fixtureManifest(tools: FixtureTool[]): Record<string, unknown> {
  return { schemaVersion: 1, kind: 'boundaryci-toolchain-manifest', platform: 'linux-x64', tools: [...tools].sort((left, right) => (left.id < right.id ? -1 : 1)) };
}

export function manifestBytes(manifest: unknown): Buffer {
  return Buffer.from(canonicalJson(manifest), 'utf8');
}

const workspaces: string[] = [];

/** A private temporary directory that is removed by `cleanupWorkspaces`, even when made read-only. */
export function workspace(): string {
  const path = mkdtempSync(join(tmpdir(), 'boundaryci-toolchain-test-'));
  workspaces.push(path);
  return path;
}

function makeWritable(path: string): void {
  const stats = lstatSync(path, { throwIfNoEntry: false });
  if (stats === undefined || stats.isSymbolicLink()) return;
  if (stats.isDirectory()) {
    chmodSync(path, 0o700);
    for (const name of readdirSync(path)) makeWritable(join(path, name));
  }
}

export function cleanupWorkspaces(): void {
  for (const path of workspaces.splice(0)) {
    makeWritable(path);
    rmSync(path, { recursive: true, force: true });
  }
}

/** Writes a capsule tree exactly as materialization would: files at declared modes, directories 0555. */
export function layoutCapsule(store: string, tool: FixtureTool, files: FixtureFile[]): string {
  const directory = join(store, tool.id, tool.treeSha256);
  mkdirSync(join(store, tool.id), { recursive: true, mode: 0o755 });
  chmodSync(join(store, tool.id), 0o755);
  const created = new Set<string>();
  for (const file of files) {
    const target = join(directory, ...file.path.split('/'));
    mkdirSync(dirname(target), { recursive: true, mode: 0o755 });
    writeFileSync(target, file.bytes, { mode: 0o600 });
    chmodSync(target, Number.parseInt(file.mode ?? '0555', 8));
    let current = dirname(target);
    while (current.length >= directory.length) {
      created.add(current);
      current = dirname(current);
    }
  }
  for (const path of [...created].sort((left, right) => right.length - left.length)) chmodSync(path, 0o555);
  return directory;
}

/** Temporarily makes a capsule directory writable for a tamper step, then restores 0555. */
export function withWritable(directory: string, action: () => void): void {
  chmodSync(directory, 0o755);
  try {
    action();
  } finally {
    chmodSync(directory, 0o555);
  }
}
