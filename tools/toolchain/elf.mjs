import { fail } from './errors.mjs';

const ELF_MAGIC = [0x7f, 0x45, 0x4c, 0x46];
const ELFCLASS64 = 2;
const ELFDATA2LSB = 1;
const EM_X86_64 = 0x3e;
const PROGRAM_HEADER_SIZE = 56;
const MAX_PROGRAM_HEADERS = 128;
const MAX_DYNAMIC_ENTRIES = 4096;
const MAX_STRING_BYTES = 4096;
const PT_LOAD = 1;
const PT_DYNAMIC = 2;
const PT_INTERP = 3;
const DT_NULL = 0n;
const DT_NEEDED = 1n;
const DT_STRTAB = 5n;
const DT_STRSZ = 10n;
const DT_RPATH = 15n;
const DT_RUNPATH = 29n;

/**
 * @param {bigint} value
 * @param {string} label
 */
function toSafeNumber(value, label) {
  if (value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) fail('toolchain/closure', `ELF ${label} is out of range`);
  return Number(value);
}

/**
 * @param {Buffer} bytes
 * @param {number} offset
 * @param {number} length
 * @param {string} label
 */
function requireRange(bytes, offset, length, label) {
  if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(length) || offset < 0 || length < 0 || offset + length > bytes.length) {
    fail('toolchain/closure', `ELF ${label} exceeds the file`);
  }
}

/**
 * @param {Buffer} bytes
 * @param {number} offset
 * @param {number} limit
 * @param {string} label
 */
function readCString(bytes, offset, limit, label) {
  const end = bytes.indexOf(0, offset);
  if (end < 0 || end >= limit || end - offset > MAX_STRING_BYTES) fail('toolchain/closure', `ELF ${label} is not terminated`);
  const text = bytes.subarray(offset, end).toString('latin1');
  if (text.length === 0 || /[^\x21-\x7e]/u.test(text)) fail('toolchain/closure', `ELF ${label} is not printable`);
  return text;
}

/**
 * Parses only the bounded ELF64 facts that decide whether a file can reach outside its capsule:
 * the requested program interpreter, DT_NEEDED names, and DT_RPATH/DT_RUNPATH search paths.
 * Non-ELF input is reported, never guessed. Malformed ELF input fails closed.
 *
 * @param {Buffer} bytes
 * @returns { { elf: false, shebang: boolean } | { elf: true, interpreter: string | null, needed: string[], rpath: string[], runpath: string[] } }
 */
export function inspectElf(bytes) {
  if (bytes.length < 4 || ELF_MAGIC.some((value, index) => bytes[index] !== value)) {
    return Object.freeze({ elf: false, shebang: bytes.length >= 2 && bytes[0] === 0x23 && bytes[1] === 0x21 });
  }
  requireRange(bytes, 0, 64, 'header');
  if (bytes[4] !== ELFCLASS64 || bytes[5] !== ELFDATA2LSB || bytes.readUInt16LE(18) !== EM_X86_64) {
    fail('toolchain/closure', 'ELF is not little-endian x86-64');
  }
  const programOffset = toSafeNumber(bytes.readBigUInt64LE(32), 'program header offset');
  const programEntrySize = bytes.readUInt16LE(54);
  const programCount = bytes.readUInt16LE(56);
  if (programEntrySize !== PROGRAM_HEADER_SIZE || programCount > MAX_PROGRAM_HEADERS) fail('toolchain/closure', 'ELF program headers are unsupported');
  requireRange(bytes, programOffset, programCount * PROGRAM_HEADER_SIZE, 'program headers');

  /** @type { { type: number, offset: number, vaddr: number, filesz: number }[]} */
  const segments = [];
  for (let index = 0; index < programCount; index += 1) {
    const base = programOffset + index * PROGRAM_HEADER_SIZE;
    segments.push({
      type: bytes.readUInt32LE(base),
      offset: toSafeNumber(bytes.readBigUInt64LE(base + 8), 'segment offset'),
      vaddr: toSafeNumber(bytes.readBigUInt64LE(base + 16), 'segment address'),
      filesz: toSafeNumber(bytes.readBigUInt64LE(base + 32), 'segment size'),
    });
  }

  const interpreters = segments.filter((segment) => segment.type === PT_INTERP);
  if (interpreters.length > 1) fail('toolchain/closure', 'ELF declares multiple interpreters');
  let interpreter = null;
  if (interpreters[0] !== undefined) {
    const segment = interpreters[0];
    requireRange(bytes, segment.offset, segment.filesz, 'interpreter');
    interpreter = readCString(bytes, segment.offset, segment.offset + segment.filesz, 'interpreter');
  }

  const dynamics = segments.filter((segment) => segment.type === PT_DYNAMIC);
  if (dynamics.length > 1) fail('toolchain/closure', 'ELF declares multiple dynamic segments');
  /** @type {string[]} */
  const needed = [];
  /** @type {string[]} */
  const rpath = [];
  /** @type {string[]} */
  const runpath = [];
  if (dynamics[0] !== undefined) {
    const dynamic = dynamics[0];
    requireRange(bytes, dynamic.offset, dynamic.filesz, 'dynamic segment');
    /** @type { { tag: bigint, value: bigint }[]} */
    const entries = [];
    let terminated = false;
    for (let cursor = dynamic.offset; cursor + 16 <= dynamic.offset + dynamic.filesz; cursor += 16) {
      if (entries.length >= MAX_DYNAMIC_ENTRIES) fail('toolchain/closure', 'ELF dynamic section is too large');
      const tag = bytes.readBigInt64LE(cursor);
      if (tag === DT_NULL) {
        terminated = true;
        break;
      }
      entries.push({ tag, value: bytes.readBigUInt64LE(cursor + 8) });
    }
    if (!terminated) fail('toolchain/closure', 'ELF dynamic section is not terminated');
    const stringTables = entries.filter((entry) => entry.tag === DT_STRTAB);
    const stringSizes = entries.filter((entry) => entry.tag === DT_STRSZ);
    const references = entries.filter((entry) => entry.tag === DT_NEEDED || entry.tag === DT_RPATH || entry.tag === DT_RUNPATH);
    if (references.length > 0) {
      if (stringTables.length !== 1 || stringSizes.length !== 1) fail('toolchain/closure', 'ELF string table is ambiguous');
      const address = toSafeNumber(/** @type { { value: bigint } } */ (stringTables[0]).value, 'string table address');
      const size = toSafeNumber(/** @type { { value: bigint } } */ (stringSizes[0]).value, 'string table size');
      const load = segments.find((segment) => segment.type === PT_LOAD && address >= segment.vaddr && address + size <= segment.vaddr + segment.filesz);
      if (load === undefined) fail('toolchain/closure', 'ELF string table is not file-backed');
      const tableOffset = load.offset + (address - load.vaddr);
      requireRange(bytes, tableOffset, size, 'string table');
      for (const entry of references) {
        const relative = toSafeNumber(entry.value, 'string offset');
        if (relative >= size) fail('toolchain/closure', 'ELF string offset exceeds the table');
        const text = readCString(bytes, tableOffset + relative, tableOffset + size, 'dynamic string');
        if (entry.tag === DT_NEEDED) needed.push(text);
        else if (entry.tag === DT_RPATH) rpath.push(text);
        else runpath.push(text);
      }
    }
  }
  return Object.freeze({ elf: true, interpreter, needed: Object.freeze(needed), rpath: Object.freeze(rpath), runpath: Object.freeze(runpath) });
}

/**
 * @param {string} path
 */
function parentDirectory(path) {
  const index = path.lastIndexOf('/');
  return index < 0 ? '' : path.slice(0, index);
}

/**
 * @param {string} path
 */
function baseName(path) {
  return path.slice(path.lastIndexOf('/') + 1);
}

/**
 * Proves statically that executing the tool cannot load code from outside its capsule through the
 * ELF interpreter, DT_NEEDED resolution, or embedded search paths. Bytes must be the verified bytes.
 *
 * @param { { entrypoint: string, invocation: { kind: string, loader?: string, libraryPath?: string[], script?: string } } } tool
 * @param {ReadonlyMap<string, Buffer>} bytesByPath
 */
export function assertCapsuleClosure(tool, bytesByPath) {
  /** @type {Map<string, ReturnType<typeof inspectElf>>} */
  const facts = new Map();
  for (const [path, bytes] of bytesByPath) facts.set(path, inspectElf(bytes));
  const factFor = (/** @type {string} */ path) => {
    const value = facts.get(path);
    if (value === undefined) fail('toolchain/closure', `closure file ${path} is not listed`);
    return value;
  };
  for (const [path, value] of facts) {
    if (value.elf && (value.rpath.length > 0 || value.runpath.length > 0)) {
      fail('toolchain/closure', `${path} embeds a library search path`);
    }
  }

  const invocation = tool.invocation;
  if (invocation.kind === 'direct') {
    const entry = factFor(tool.entrypoint);
    if (!entry.elf) fail('toolchain/closure', `${tool.entrypoint} is not ELF; a script would run a host interpreter`);
    if (entry.interpreter !== null || entry.needed.length > 0) {
      fail('toolchain/closure', `${tool.entrypoint} is dynamic; direct invocation would use the host loader`);
    }
    return;
  }
  if (invocation.kind === 'interpreter') {
    factFor(/** @type {string} */ (invocation.script));
    return;
  }
  if (invocation.kind !== 'elf-loader') fail('toolchain/closure', 'unsupported invocation');

  const loaderPath = /** @type {string} */ (invocation.loader);
  const loader = factFor(loaderPath);
  if (!loader.elf || loader.interpreter !== null || loader.needed.length > 0) {
    fail('toolchain/closure', `${loaderPath} is not a self-contained ELF loader`);
  }
  const entry = factFor(tool.entrypoint);
  if (!entry.elf) fail('toolchain/closure', `${tool.entrypoint} is not ELF`);
  const libraryPath = invocation.libraryPath ?? [];
  /** @type {Map<string, string>} */
  const available = new Map();
  for (const directory of libraryPath) {
    for (const path of bytesByPath.keys()) {
      if (parentDirectory(path) === directory && !available.has(baseName(path))) available.set(baseName(path), path);
    }
  }
  const pending = [tool.entrypoint];
  const visited = new Set();
  while (pending.length > 0) {
    const path = /** @type {string} */ (pending.pop());
    if (visited.has(path)) continue;
    visited.add(path);
    const value = factFor(path);
    if (!value.elf) fail('toolchain/closure', `${path} is a non-ELF library`);
    for (const name of value.needed) {
      if (name.includes('/')) fail('toolchain/closure', `${path} needs a path-qualified library`);
      const resolved = available.get(name);
      if (resolved === undefined) fail('toolchain/closure', `${path} needs ${name}, which the capsule does not provide`);
      pending.push(resolved);
    }
  }
}
