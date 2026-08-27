/**
 * Byte-to-AST parsing and portable span evidence for the BoundaryCI static analyzer.
 *
 * This module is the only place that turns target bytes into syntax. It never opens a file:
 * it parses exactly the bytes `discoverSources` already read, under its own budget decisions,
 * and it deliberately imports no filesystem, process, module-resolution, or transpilation
 * capability. `ts.createSourceFile` is the entire interaction with target content — no
 * `Program`, no module resolver, no package or configuration discovery, no loader, and no
 * evaluation of any kind.
 *
 * Decoding is fatal. A file whose bytes are not valid UTF-8, and a file the TypeScript parser
 * reports any diagnostic for, is file-fatal: it contributes no AST, no candidate, and no
 * positive observation, and it returns exactly one source-scoped cause. Its raw
 * {@link RawSourceRecord} is still produced, because the file was discovered and its identity
 * is evidence regardless of whether it could be parsed. Per D-15 that is repository-
 * compositional: independently parsed files remain valid and the repository becomes
 * incomplete, never failed.
 *
 * `byteSize` and `contentSha256` describe the exact raw bytes, including a leading UTF-8
 * byte-order mark. One leading `EF BB BF` is encoding metadata and is removed from the text
 * handed to the parser, so every offset and span is relative to source text that never
 * contained it. A U+FEFF anywhere else is ordinary source text and is left alone.
 *
 * Spans follow {@link SPAN_CONVENTION_IDENTITY} exactly: 1-based line and column, a column
 * counts UTF-16 code units within its decoded line, `start` is inclusive, `end` is exclusive,
 * and `LF`, `CRLF`, and lone `CR` each terminate exactly one line. Nothing else terminates a
 * line under this convention — U+2028 and U+2029 are ordinary characters here — which is why
 * every span is computed from the exact parser text rather than from a compiler line map that
 * answers a slightly different question.
 */

import { createHash } from 'node:crypto';

import ts from 'typescript';

import type { SourceSpan } from '../permission-model/model.js';

import { ANALYSIS_SPAN_CONVENTION_ID, ANALYZER_SOURCE_EXTENSIONS } from './contract.js';
import type { AnalyzerCauseCode, SourceRecord } from './contract.js';

/** Span-convention identity, re-exported from the single canonical source of truth. */
export const SPAN_CONVENTION_IDENTITY = ANALYSIS_SPAN_CONVENTION_ID;

/** The exact ECMAScript target every analyzed source is parsed against. */
const ANALYZER_SCRIPT_TARGET = ts.ScriptTarget.ES2024;

/**
 * The exact extension-to-ScriptKind table, over the six discovered source extensions.
 *
 * `.mjs` and `.mts` differ from `.js` and `.ts` only in module semantics the parser does not
 * decide, so they select the same kind. Nothing outside this table has a ScriptKind: a path
 * the discovery universe cannot contain is not given a guessed parse mode.
 */
const SCRIPT_KIND_BY_EXTENSION: ReadonlyMap<string, ts.ScriptKind> = new Map([
  ['.js', ts.ScriptKind.JS],
  ['.mjs', ts.ScriptKind.JS],
  ['.jsx', ts.ScriptKind.JSX],
  ['.ts', ts.ScriptKind.TS],
  ['.mts', ts.ScriptKind.TS],
  ['.tsx', ts.ScriptKind.TSX],
]);

/** A fatal UTF-8 decoder. `ignoreBOM` keeps a leading U+FEFF visible so this module, not the decoder, decides its meaning. */
const UTF8_DECODER = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

const BYTE_ORDER_MARK: readonly number[] = [0xef, 0xbb, 0xbf];

/** One discovered source's identity and the exact bytes discovery read for it. */
export interface DiscoveredSourceBytes {
  readonly path: string;
  readonly bytes: Uint8Array;
}

/** Portable identity of one analyzed regular file, before the caller assigns its ordinal id. */
export type RawSourceRecord = Omit<SourceRecord, 'id'>;

/** The two file-fatal parse outcomes; both are source-scoped and both leave other files valid. */
export type SourceParseCauseCode = Extract<AnalyzerCauseCode, 'invalid-source-encoding' | 'source-parse-error'>;

/**
 * One file-fatal parse diagnostic.
 *
 * `detail` is analyzer-authored text about the analyzer's own boundary. It never embeds target
 * source text, target identifiers, host paths, or compiler diagnostic messages: a deterministic
 * count is the entire safe detail a parser failure can carry.
 */
export interface SourceParseCause {
  readonly code: SourceParseCauseCode;
  readonly scope: 'source';
  readonly path: string;
  readonly detail: string;
}

/** One successfully decoded and parsed source. */
export interface ParsedSource {
  readonly status: 'parsed';
  readonly record: RawSourceRecord;
  /** Whether the raw bytes began with `EF BB BF`, which is absent from {@link text}. */
  readonly hasByteOrderMark: boolean;
  /** The exact text handed to `ts.createSourceFile`, after byte-order-mark removal. */
  readonly text: string;
  readonly sourceFile: ts.SourceFile;
  /** UTF-16 offsets of every line start in {@link text}, retained so span lookup stays linear overall. */
  readonly lineStarts: readonly number[];
}

/** One file-fatal source: its raw identity survives, its syntax does not. */
export interface UnparsedSource {
  readonly status: 'unparsed';
  readonly record: RawSourceRecord;
  readonly cause: SourceParseCause;
}

export type SourceParseResult = ParsedSource | UnparsedSource;

/**
 * Returns the exact ScriptKind for one of the six discovered source extensions, or `null`.
 *
 * The match is on the literal path suffix and is case-sensitive, exactly like discovery's own
 * extension decision. `.cjs`, `.cts`, and every other suffix answer `null`: they are outside
 * the Phase 3 source universe and this analyzer does not invent a parse mode for them.
 */
export function scriptKindForPath(path: string): ts.ScriptKind | null {
  for (const [extension, kind] of SCRIPT_KIND_BY_EXTENSION) {
    if (path.endsWith(extension)) return kind;
  }
  return null;
}

function computeLineStarts(text: string): number[] {
  const starts: number[] = [0];
  for (let index = 0; index < text.length; index += 1) {
    const code = text.charCodeAt(index);
    if (code === 0x0d) {
      if (text.charCodeAt(index + 1) === 0x0a) index += 1;
      starts.push(index + 1);
    } else if (code === 0x0a) {
      starts.push(index + 1);
    }
  }
  return starts;
}

/** Finds the greatest line start at or before `offset`; `lineStarts` is sorted and non-empty. */
function lineIndexOf(lineStarts: readonly number[], offset: number): number {
  let low = 0;
  let high = lineStarts.length - 1;
  while (low < high) {
    const middle = low + Math.ceil((high - low) / 2);
    if ((lineStarts[middle] ?? 0) <= offset) low = middle;
    else high = middle - 1;
  }
  return low;
}

function assertOffset(value: number, limit: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 0 || value > limit) {
    throw new TypeError(`${label} must be a UTF-16 offset within the parsed source text`);
  }
}

function positionAt(text: string, lineStarts: readonly number[], offset: number): { line: number; column: number } {
  const index = lineIndexOf(lineStarts, offset);
  return { line: index + 1, column: offset - (lineStarts[index] ?? 0) + 1 };
}

/**
 * Converts a half-open UTF-16 offset range into a portable {@link SourceSpan}.
 *
 * `text` must be the exact text passed to `ts.createSourceFile`, after byte-order-mark
 * removal; an offset measured against any other string would describe a different file.
 * Out-of-range or inverted offsets are rejected rather than clamped, because a silently
 * repaired span would be evidence about a location that was never proven.
 */
export function toPortableSpan(text: string, startOffset: number, endOffset: number): SourceSpan {
  assertOffset(startOffset, text.length, 'a span start offset');
  assertOffset(endOffset, text.length, 'a span end offset');
  if (endOffset < startOffset) throw new TypeError('a span must not end before it starts');
  const lineStarts = computeLineStarts(text);
  return {
    start: positionAt(text, lineStarts, startOffset),
    end: positionAt(text, lineStarts, endOffset),
  };
}

/**
 * Converts one node of an already parsed source into a portable span.
 *
 * The start position skips leading trivia, so a span covers the node's own syntax rather than
 * the comments and whitespace in front of it.
 */
export function spanOfNode(parsed: ParsedSource, node: ts.Node): SourceSpan {
  const start = node.getStart(parsed.sourceFile);
  const end = node.getEnd();
  assertOffset(start, parsed.text.length, 'a node start offset');
  assertOffset(end, parsed.text.length, 'a node end offset');
  return {
    start: positionAt(parsed.text, parsed.lineStarts, start),
    end: positionAt(parsed.text, parsed.lineStarts, end),
  };
}

function hasByteOrderMark(bytes: Uint8Array): boolean {
  return bytes.byteLength >= BYTE_ORDER_MARK.length && BYTE_ORDER_MARK.every((byte, index) => bytes[index] === byte);
}

/**
 * Parses the exact bytes discovery already read for one included source.
 *
 * The caller must pass a discovered source path: a path outside the six analyzer extensions
 * has no ScriptKind and is a caller contract violation, not a parse outcome, so it is rejected
 * rather than parsed under a guessed mode. Every other outcome is data — either a parsed source
 * or one file-fatal cause — and in both cases the raw source record describes the exact bytes,
 * byte-order mark included.
 */
export function parseSourceRecord(source: DiscoveredSourceBytes): SourceParseResult {
  const scriptKind = scriptKindForPath(source.path);
  if (scriptKind === null) {
    throw new TypeError('parseSourceRecord requires a discovered analyzer source path');
  }

  const bytes = source.bytes;
  const record: RawSourceRecord = {
    path: source.path,
    byteSize: bytes.byteLength,
    contentSha256: createHash('sha256').update(bytes).digest('hex'),
  };

  let decoded: string;
  try {
    decoded = UTF8_DECODER.decode(bytes);
  } catch {
    return {
      status: 'unparsed',
      record,
      cause: {
        code: 'invalid-source-encoding',
        scope: 'source',
        path: source.path,
        detail: 'the source is not valid UTF-8 and was not parsed',
      },
    };
  }

  const bom = hasByteOrderMark(bytes);
  const text = bom ? decoded.slice(1) : decoded;
  const sourceFile = ts.createSourceFile(source.path, text, ANALYZER_SCRIPT_TARGET, false, scriptKind);
  const parseDiagnostics =
    (sourceFile as ts.SourceFile & { parseDiagnostics?: readonly ts.Diagnostic[] }).parseDiagnostics ?? [];
  if (parseDiagnostics.length > 0) {
    return {
      status: 'unparsed',
      record,
      cause: {
        code: 'source-parse-error',
        scope: 'source',
        path: source.path,
        detail: `the source produced ${String(parseDiagnostics.length)} parser diagnostics and contributed no observation`,
      },
    };
  }

  return { status: 'parsed', record, hasByteOrderMark: bom, text, sourceFile, lineStarts: computeLineStarts(text) };
}

/* ------------------------------------------------------------------ *
 * Finite relative-source candidate table.
 * ------------------------------------------------------------------ */

/** Identity of the finite relative-source candidate table below. */
export const RELATIVE_SOURCE_CANDIDATE_TABLE_ID = 'boundaryci/relative-source-candidates@1';

/**
 * One row of the fixed relative-specifier candidate table.
 *
 * `specifierExtension` is the literal suffix an explicitly named relative specifier ends with,
 * or the empty string for an extensionless specifier. `candidateExtensions` are the exact
 * suffixes that may be appended to (extensionless) or substituted for (explicit) that
 * specifier's named path, in this fixed order. `eligibleCandidateExtensions` is the subset that
 * the Phase 3 discovery universe can actually contain; a row whose eligible subset is empty can
 * never resolve to an included source.
 */
export interface RelativeSourceCandidateRule {
  readonly specifierExtension: string;
  readonly candidateExtensions: readonly string[];
  readonly eligibleCandidateExtensions: readonly string[];
}

function candidateRule(specifierExtension: string, candidateExtensions: readonly string[]): RelativeSourceCandidateRule {
  return Object.freeze({
    specifierExtension,
    candidateExtensions: Object.freeze([...candidateExtensions]),
    eligibleCandidateExtensions: Object.freeze(
      candidateExtensions.filter((extension) => ANALYZER_SOURCE_EXTENSIONS.includes(extension)),
    ),
  });
}

/**
 * The complete, immutable, case-sensitive candidate table for relative source specifiers.
 *
 * It encodes exactly D-25 and nothing else: exact-source matches, the authorized emitted-
 * JavaScript-to-TypeScript mappings, and extensionless probing of the six discovered
 * extensions at the explicitly named path. There is no directory or index resolution, no
 * package metadata, no `tsconfig` or build-tool alias, no Node-style precedence, and no
 * arbitrary extension: a specifier with an extension this table has no row for has no
 * candidates at all.
 *
 * `.cjs` keeps its documented `.cts` mapping, but neither suffix is in the Phase 3 discovery
 * universe, so that row is deliberately present with zero eligible candidates rather than
 * widening discovery. Plan 03-03 owns the consumer that turns these rows into resolved
 * sources, the uniqueness requirement, and the dependent incomplete cause when a specifier
 * yields zero or several included candidates; this module only states the table.
 */
export const RELATIVE_SOURCE_CANDIDATE_RULES: readonly RelativeSourceCandidateRule[] = Object.freeze([
  candidateRule('', ['.js', '.jsx', '.mjs', '.ts', '.tsx', '.mts']),
  candidateRule('.js', ['.js', '.ts', '.tsx']),
  candidateRule('.jsx', ['.jsx', '.tsx']),
  candidateRule('.mjs', ['.mjs', '.mts']),
  candidateRule('.ts', ['.ts']),
  candidateRule('.tsx', ['.tsx']),
  candidateRule('.mts', ['.mts']),
  candidateRule('.cjs', ['.cjs', '.cts']),
]);
