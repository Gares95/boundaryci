import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import ts from 'typescript';
import { afterEach, describe, expect, it } from 'vitest';

import { analyzeSourceTree } from '../../src/analyzer/analyze.js';
import {
  ANALYSIS_SPAN_CONVENTION_ID,
  ANALYZER_SOURCE_EXTENSIONS,
  DEFAULT_ANALYSIS_LIMITS,
} from '../../src/analyzer/contract.js';
import type { AnalysisRequest, AnalysisResult, IncompleteAnalysisResult } from '../../src/analyzer/contract.js';
import {
  RELATIVE_SOURCE_CANDIDATE_RULES,
  RELATIVE_SOURCE_CANDIDATE_TABLE_ID,
  SPAN_CONVENTION_IDENTITY,
  parseSourceRecord,
  scriptKindForPath,
  toPortableSpan,
} from '../../src/analyzer/parse.js';
import type { ParsedSource, SourceParseResult, UnparsedSource } from '../../src/analyzer/parse.js';
import type { SourceSpan } from '../../src/permission-model/model.js';

import { cleanupTempRoots, createTempRoot, writeRegularFile } from './helpers.js';
import parseCases from './fixtures/parse-cases.json' with { type: 'json' };

interface ScriptKindCase {
  name: string;
  path: string;
  scriptKind: string | null;
}

interface SpanOffsetCase {
  start: number;
  end: number;
  expected: { start: { line: number; column: number }; end: { line: number; column: number } };
}

interface SpanCase {
  name: string;
  text: string;
  offsets: SpanOffsetCase[];
}

interface CandidateRuleCase {
  name: string;
  specifierExtension: string;
  candidateExtensions: string[];
  eligibleCandidateExtensions: string[];
}

const cases = parseCases as {
  scriptKinds: ScriptKindCase[];
  spans: SpanCase[];
  candidateRules: CandidateRuleCase[];
};

/** The exact ScriptKind names the fixture may name, so a fixture typo cannot silently pass. */
const SCRIPT_KINDS: Readonly<Record<string, ts.ScriptKind>> = Object.freeze({
  JS: ts.ScriptKind.JS,
  JSX: ts.ScriptKind.JSX,
  TS: ts.ScriptKind.TS,
  TSX: ts.ScriptKind.TSX,
});

/** U+FEFF, U+2028, and one astral character, named so that no assertion depends on an invisible literal. */
const BYTE_ORDER_MARK = String.fromCharCode(0xfeff);
const LINE_SEPARATOR = String.fromCharCode(0x2028);
const ASTRAL_CHARACTER = String.fromCodePoint(0x1d4b3);

function bytesOf(text: string): Uint8Array {
  return new Uint8Array(Buffer.from(text, 'utf8'));
}

function expectParsed(result: SourceParseResult): ParsedSource {
  if (result.status !== 'parsed') {
    throw new Error(`expected a parsed source, received ${result.cause.code}`);
  }
  return result;
}

function expectUnparsed(result: SourceParseResult): UnparsedSource {
  if (result.status !== 'unparsed') throw new Error('expected a file-fatal parse outcome');
  return result;
}

function expectIncomplete(result: AnalysisResult): IncompleteAnalysisResult {
  if (result.status !== 'incomplete') throw new Error(`expected an incomplete result, received ${result.status}`);
  return result;
}

/**
 * Computes the expected span of a single-line snippet independently of the analyzer, under the
 * declared convention: 1-based line and column, `start` inclusive and `end` exclusive.
 */
function spanOfSnippet(source: string, snippet: string): SourceSpan {
  const index = source.indexOf(snippet);
  if (index < 0) throw new Error('the snippet is not present in the fixture');
  const before = source.slice(0, index);
  const line = before.split('\n').length;
  const column = index - (before.lastIndexOf('\n') + 1) + 1;
  return { start: { line, column }, end: { line, column: column + snippet.length } };
}

function requestFor(rootPath: string, overrides: Partial<AnalysisRequest> = {}): AnalysisRequest {
  return {
    rootPath,
    include: ['**/*.ts'],
    exclude: [],
    probotEntrypoints: [],
    limits: { ...DEFAULT_ANALYSIS_LIMITS },
    ...overrides,
  };
}

afterEach(async () => {
  await cleanupTempRoots();
});

describe('SPAN_CONVENTION_IDENTITY', () => {
  it('is the single canonical span-convention identity', () => {
    expect(SPAN_CONVENTION_IDENTITY).toBe(ANALYSIS_SPAN_CONVENTION_ID);
  });
});

describe('scriptKindForPath: the exact six-extension table', () => {
  for (const testCase of cases.scriptKinds) {
    it(`maps ${testCase.path}: ${testCase.name}`, () => {
      const expected = testCase.scriptKind === null ? null : SCRIPT_KINDS[testCase.scriptKind];
      expect(expected, `unknown fixture script kind ${String(testCase.scriptKind)}`).not.toBeUndefined();
      expect(scriptKindForPath(testCase.path)).toBe(expected);
    });
  }

  it('covers every extension the discovery universe can contain', () => {
    for (const extension of ANALYZER_SOURCE_EXTENSIONS) {
      expect(scriptKindForPath(`src/file${extension}`), extension).not.toBeNull();
    }
  });

  it('refuses to parse a path the discovery universe cannot contain, rather than guessing a parse mode', () => {
    expect(() => parseSourceRecord({ path: 'src/legacy.cjs', bytes: bytesOf('module.exports = {};\n') })).toThrow(
      TypeError,
    );
  });
});

describe('parseSourceRecord: extension-derived parse modes', () => {
  it('parses TypeScript-only syntax in every TypeScript extension', () => {
    for (const path of ['src/app.ts', 'src/app.mts', 'src/view.tsx']) {
      const parsed = expectParsed(parseSourceRecord({ path, bytes: bytesOf('const value: number = 1;\n') }));
      expect(parsed.sourceFile.statements.length, path).toBe(1);
    }
  });

  it('parses JSX syntax in every JSX-capable extension', () => {
    for (const path of ['src/view.jsx', 'src/view.tsx']) {
      const parsed = expectParsed(parseSourceRecord({ path, bytes: bytesOf('const element = <div />;\n') }));
      expect(parsed.sourceFile.statements.length, path).toBe(1);
    }
  });

  it('parses ordinary module syntax in every JavaScript extension', () => {
    for (const path of ['src/app.js', 'src/app.mjs']) {
      const parsed = expectParsed(parseSourceRecord({ path, bytes: bytesOf('export const value = 1;\n') }));
      expect(parsed.sourceFile.statements.length, path).toBe(1);
    }
  });

  it('distinguishes TS from TSX: a generic arrow function parses as TypeScript and fails as JSX', () => {
    const source = 'const identity = <T>(value: T): T => value;\n';
    expect(expectParsed(parseSourceRecord({ path: 'src/app.ts', bytes: bytesOf(source) })).status).toBe('parsed');
    expect(expectUnparsed(parseSourceRecord({ path: 'src/app.tsx', bytes: bytesOf(source) })).cause.code).toBe(
      'source-parse-error',
    );
  });

  it('parses an empty source successfully and finds nothing in it', () => {
    const parsed = expectParsed(parseSourceRecord({ path: 'src/empty.ts', bytes: new Uint8Array(0) }));
    expect(parsed.text).toBe('');
    expect(parsed.sourceFile.statements.length).toBe(0);
    expect(parsed.record).toEqual({
      path: 'src/empty.ts',
      byteSize: 0,
      contentSha256: createHash('sha256').update(new Uint8Array(0)).digest('hex'),
    });
  });

  it('parses bytes it was handed for a path that does not exist on disk, and never reopens a file', () => {
    const parsed = expectParsed(
      parseSourceRecord({ path: 'nowhere/never-written.ts', bytes: bytesOf('export const value = 1;\n') }),
    );
    expect(parsed.record.path).toBe('nowhere/never-written.ts');
    expect(parsed.sourceFile.statements.length).toBe(1);
  });
});

describe('parseSourceRecord: raw byte evidence', () => {
  it('describes the exact raw bytes, byte-order mark included, and keeps the mark out of the parser text', () => {
    const text = 'export const value = 1;\n';
    const raw = new Uint8Array([0xef, 0xbb, 0xbf, ...bytesOf(text)]);

    const parsed = expectParsed(parseSourceRecord({ path: 'src/bom.ts', bytes: raw }));

    expect(parsed.hasByteOrderMark).toBe(true);
    expect(parsed.text).toBe(text);
    expect(parsed.record).toEqual({
      path: 'src/bom.ts',
      byteSize: raw.byteLength,
      contentSha256: createHash('sha256').update(raw).digest('hex'),
    });
    // The digest describes the raw file, so it differs from the same source without the mark.
    expect(parsed.record.contentSha256).not.toBe(createHash('sha256').update(bytesOf(text)).digest('hex'));
  });

  it('reports no byte-order mark for a source that does not begin with one', () => {
    const parsed = expectParsed(parseSourceRecord({ path: 'src/plain.ts', bytes: bytesOf('const value = 1;\n') }));
    expect(parsed.hasByteOrderMark).toBe(false);
    expect(parsed.text).toBe('const value = 1;\n');
  });

  it('removes only one leading byte-order mark and keeps a second U+FEFF as source text', () => {
    const raw = new Uint8Array([0xef, 0xbb, 0xbf, 0xef, 0xbb, 0xbf, ...bytesOf('const value = 1;\n')]);

    const parsed = expectParsed(parseSourceRecord({ path: 'src/double-bom.ts', bytes: raw }));

    expect(parsed.text.charCodeAt(0)).toBe(0xfeff);
    expect(parsed.text).toBe(`${BYTE_ORDER_MARK}const value = 1;\n`);
  });

  it('keeps a U+FEFF that is not in leading position as ordinary source text', () => {
    const text = `const value = 1;${BYTE_ORDER_MARK}\n`;
    const parsed = expectParsed(parseSourceRecord({ path: 'src/interior-feff.ts', bytes: bytesOf(text) }));
    expect(parsed.text).toBe(text);
  });

  it('measures spans against the parser text, so a byte-order mark shifts no line or column', () => {
    const text = 'const value = 1;\n';
    const withMark = expectParsed(
      parseSourceRecord({ path: 'src/bom.ts', bytes: new Uint8Array([0xef, 0xbb, 0xbf, ...bytesOf(text)]) }),
    );
    const withoutMark = expectParsed(parseSourceRecord({ path: 'src/plain.ts', bytes: bytesOf(text) }));

    const markedStatement = withMark.sourceFile.statements[0];
    const plainStatement = withoutMark.sourceFile.statements[0];
    if (markedStatement === undefined || plainStatement === undefined) throw new Error('expected one statement');

    expect(toPortableSpan(withMark.text, markedStatement.getStart(withMark.sourceFile), markedStatement.getEnd())).toEqual(
      { start: { line: 1, column: 1 }, end: { line: 1, column: 17 } },
    );
    expect(
      toPortableSpan(withoutMark.text, plainStatement.getStart(withoutMark.sourceFile), plainStatement.getEnd()),
    ).toEqual({ start: { line: 1, column: 1 }, end: { line: 1, column: 17 } });
  });
});

describe('parseSourceRecord: fatal decoding', () => {
  const invalidByteSequences: ReadonlyArray<readonly [string, number[]]> = [
    ['a lone continuation byte', [0x63, 0x20, 0x80, 0x0a]],
    ['a truncated multi-byte sequence', [0x63, 0x20, 0xe2, 0x82, 0x0a]],
    ['an unpaired surrogate encoding', [0xed, 0xa0, 0x80]],
    ['a byte that can never begin a sequence', [0x63, 0xff, 0x0a]],
  ];

  for (const [label, sequence] of invalidByteSequences) {
    it(`is file-fatal for invalid UTF-8: ${label}`, () => {
      const raw = new Uint8Array(sequence);
      const unparsed = expectUnparsed(parseSourceRecord({ path: 'src/invalid.ts', bytes: raw }));

      expect(unparsed.cause).toEqual({
        code: 'invalid-source-encoding',
        scope: 'source',
        path: 'src/invalid.ts',
        detail: 'the source is not valid UTF-8 and was not parsed',
      });
      // The file was discovered, so its raw identity is evidence even though its syntax is not.
      expect(unparsed.record).toEqual({
        path: 'src/invalid.ts',
        byteSize: raw.byteLength,
        contentSha256: createHash('sha256').update(raw).digest('hex'),
      });
    });
  }

  it('accepts valid multi-byte UTF-8, including astral characters, as ordinary source text', () => {
    const text = 'export const label = "café 𝒳";\n';
    const parsed = expectParsed(parseSourceRecord({ path: 'src/unicode.ts', bytes: bytesOf(text) }));
    expect(parsed.text).toBe(text);
    expect(parsed.record.byteSize).toBe(Buffer.byteLength(text, 'utf8'));
  });
});

describe('parseSourceRecord: fatal parser diagnostics', () => {
  it('is file-fatal for malformed syntax and reports only a deterministic count', () => {
    const unparsed = expectUnparsed(
      parseSourceRecord({ path: 'src/broken.ts', bytes: bytesOf('const secretName = 1 +;\n') }),
    );

    expect(unparsed.cause.code).toBe('source-parse-error');
    expect(unparsed.cause.scope).toBe('source');
    expect(unparsed.cause.path).toBe('src/broken.ts');
    expect(unparsed.cause.detail).toMatch(/^the source produced \d+ parser diagnostics and contributed no observation$/);
    // No target source text, identifier, or compiler diagnostic message may leak into evidence.
    expect(unparsed.cause.detail).not.toContain('secretName');
  });

  it('produces the same cause for the same bytes on every run', () => {
    const bytes = bytesOf('function broken( {\n');
    const first = expectUnparsed(parseSourceRecord({ path: 'src/broken.ts', bytes }));
    const second = expectUnparsed(parseSourceRecord({ path: 'src/broken.ts', bytes }));
    expect(JSON.stringify(second.cause)).toBe(JSON.stringify(first.cause));
  });

  it('keeps unsupported but well-formed syntax inert rather than fatal', () => {
    const source = [
      'export class Widget {',
      '  accessor label = "x";',
      '}',
      'label: for (const value of []) { break label; }',
      'export default async function* generate(): AsyncGenerator<number> { yield 1; }',
      '',
    ].join('\n');
    const parsed = expectParsed(parseSourceRecord({ path: 'src/exotic.ts', bytes: bytesOf(source) }));
    expect(parsed.sourceFile.statements.length).toBe(3);
  });
});

describe('toPortableSpan: the versioned span convention', () => {
  for (const testCase of cases.spans) {
    it(`maps offsets to positions: ${testCase.name}`, () => {
      for (const offsetCase of testCase.offsets) {
        expect(
          toPortableSpan(testCase.text, offsetCase.start, offsetCase.end),
          `${testCase.name} [${String(offsetCase.start)}, ${String(offsetCase.end)})`,
        ).toEqual(offsetCase.expected);
      }
    });
  }

  it('uses the exact code units the fixture intends for its Unicode cases', () => {
    const astral = cases.spans.find((testCase) => testCase.text.startsWith(ASTRAL_CHARACTER));
    const lineSeparator = cases.spans.find((testCase) => testCase.text.includes(LINE_SEPARATOR));
    const interiorMark = cases.spans.find((testCase) => testCase.text.includes(BYTE_ORDER_MARK));
    expect(astral?.text).toBe(`${ASTRAL_CHARACTER}y\n`);
    expect(lineSeparator?.text).toBe(`a${LINE_SEPARATOR}b`);
    expect(interiorMark?.text).toBe(`a${BYTE_ORDER_MARK}b\n`);
  });

  it('agrees with a direct scan at every offset of a mixed-terminator source', () => {
    const text = Array.from({ length: 30 }, (_, index) => `line ${String(index)} value;`).join('\r\n') + '\rtail\ntail\n';

    /** The same convention computed by scanning, so the binary search cannot hide an off-by-one. */
    const scan = (offset: number): { line: number; column: number } => {
      let line = 1;
      let lineStart = 0;
      for (let index = 0; index < offset; index += 1) {
        const code = text.charCodeAt(index);
        if (code === 0x0d) {
          if (text.charCodeAt(index + 1) === 0x0a) index += 1;
          if (index < offset) {
            line += 1;
            lineStart = index + 1;
          }
        } else if (code === 0x0a) {
          line += 1;
          lineStart = index + 1;
        }
      }
      return { line, column: offset - lineStart + 1 };
    };

    for (let offset = 0; offset <= text.length; offset += 1) {
      expect(toPortableSpan(text, offset, offset), `offset ${String(offset)}`).toEqual({
        start: scan(offset),
        end: scan(offset),
      });
    }
  });

  it('rejects an offset outside the parsed text rather than clamping it', () => {
    expect(() => toPortableSpan('abc', 0, 4)).toThrow(TypeError);
    expect(() => toPortableSpan('abc', -1, 1)).toThrow(TypeError);
    expect(() => toPortableSpan('abc', 1.5, 2)).toThrow(TypeError);
  });

  it('rejects an inverted range rather than repairing it', () => {
    expect(() => toPortableSpan('abc', 2, 1)).toThrow(TypeError);
  });

  it('accepts an empty range at the end of the text', () => {
    expect(toPortableSpan('abc', 3, 3)).toEqual({ start: { line: 1, column: 4 }, end: { line: 1, column: 4 } });
  });
});

describe('analyzeSourceTree: file-fatal parsing is repository-compositional', () => {
  const PROVEN_SOURCE = [
    "import { Octokit } from 'octokit';",
    '',
    'const client = new Octokit();',
    '',
    'export async function createIssue(owner: string, repo: string): Promise<void> {',
    "  await client.rest.issues.create({ owner, repo, title: 'Boundary' });",
    '}',
    '',
  ].join('\n');

  it('keeps one raw record per discovered file, adds one cause per failure, and preserves proven evidence', async () => {
    const root = await createTempRoot();
    const invalidBytes = new Uint8Array([...bytesOf("const label = '"), 0xff, ...bytesOf("';\n")]);
    const brokenSource = 'const value = 1 +;\n';
    await writeRegularFile(root, 'src/a-proven.ts', PROVEN_SOURCE);
    await writeRegularFile(root, 'src/b-invalid-bytes.ts', invalidBytes);
    await writeRegularFile(root, 'src/c-broken-syntax.ts', brokenSource);

    const result = expectIncomplete(await analyzeSourceTree(requestFor(root)));

    expect(result.sources.map((source) => source.path)).toEqual([
      'src/a-proven.ts',
      'src/b-invalid-bytes.ts',
      'src/c-broken-syntax.ts',
    ]);
    expect(result.sources.map((source) => source.contentSha256)).toEqual([
      createHash('sha256').update(bytesOf(PROVEN_SOURCE)).digest('hex'),
      createHash('sha256').update(invalidBytes).digest('hex'),
      createHash('sha256').update(bytesOf(brokenSource)).digest('hex'),
    ]);
    expect(result.sources.map((source) => source.byteSize)).toEqual([
      Buffer.byteLength(PROVEN_SOURCE, 'utf8'),
      invalidBytes.byteLength,
      Buffer.byteLength(brokenSource, 'utf8'),
    ]);

    const parseCauses = result.causes.filter(
      (cause) => cause.code === 'invalid-source-encoding' || cause.code === 'source-parse-error',
    );
    expect(parseCauses.map((cause) => [cause.code, cause.path, cause.scope, cause.span, cause.resource])).toEqual([
      ['invalid-source-encoding', 'src/b-invalid-bytes.ts', 'source', null, null],
      ['source-parse-error', 'src/c-broken-syntax.ts', 'source', null, null],
    ]);

    // The independently proven operation in another file survives both failures.
    expect(result.observations.map((observation) => observation.operation.operationId)).toEqual(['issues/create']);
    expect(result.observations[0]?.source.path).toBe('src/a-proven.ts');
    // Neither failing file contributed a candidate or an observation.
    expect(result.candidates.map((candidate) => candidate.path)).toEqual(['src/a-proven.ts']);
  });

  it('is incomplete, never failed, when every discovered file fails to parse', async () => {
    const root = await createTempRoot();
    await writeRegularFile(root, 'src/a.ts', new Uint8Array([0xff, 0xfe, 0x0a]));
    await writeRegularFile(root, 'src/b.ts', 'const value = 1 +;\n');

    const result = expectIncomplete(await analyzeSourceTree(requestFor(root)));

    expect(result.candidates).toEqual([]);
    expect(result.observations).toEqual([]);
    expect(result.causes.map((cause) => cause.code)).toEqual(['invalid-source-encoding', 'source-parse-error']);
    expect(result.sources).toHaveLength(2);
  });

  it('parses an empty file and produces no candidate, cause, or observation from it', async () => {
    const root = await createTempRoot();
    await writeRegularFile(root, 'src/empty.ts', '');

    const result = await analyzeSourceTree(requestFor(root));
    if (result.status === 'failed') throw new Error('expected a non-failed result');

    expect(result.sources).toEqual([
      {
        id: 'source-0001',
        path: 'src/empty.ts',
        byteSize: 0,
        contentSha256: createHash('sha256').update(new Uint8Array(0)).digest('hex'),
      },
    ]);
    expect(result.candidates).toEqual([]);
    expect(result.observations).toEqual([]);
    expect(result.causes.filter((cause) => cause.path === 'src/empty.ts')).toEqual([]);
  });

  it('records spans over the parser text for CRLF sources and for byte-order-marked sources', async () => {
    const crlfRoot = await createTempRoot();
    await writeRegularFile(crlfRoot, 'src/app.ts', PROVEN_SOURCE.split('\n').join('\r\n'));
    const markedRoot = await createTempRoot();
    await writeRegularFile(markedRoot, 'src/app.ts', new Uint8Array([0xef, 0xbb, 0xbf, ...bytesOf(PROVEN_SOURCE)]));
    const plainRoot = await createTempRoot();
    await writeRegularFile(plainRoot, 'src/app.ts', PROVEN_SOURCE);

    const crlf = await analyzeSourceTree(requestFor(crlfRoot));
    const marked = await analyzeSourceTree(requestFor(markedRoot));
    const plain = await analyzeSourceTree(requestFor(plainRoot));
    if (crlf.status === 'failed' || marked.status === 'failed' || plain.status === 'failed') {
      throw new Error('expected non-failed results');
    }

    // Computed from the LF source independently of the analyzer: a column is measured within
    // its own line, so the CRLF and byte-order-marked copies must report the same position.
    const expectedSpan = spanOfSnippet(
      PROVEN_SOURCE,
      "client.rest.issues.create({ owner, repo, title: 'Boundary' })",
    );
    expect(plain.observations[0]?.source.span).toEqual(expectedSpan);
    expect(crlf.observations[0]?.source.span).toEqual(expectedSpan);
    expect(marked.observations[0]?.source.span).toEqual(expectedSpan);
  });
});

describe('the finite relative-source candidate table', () => {
  it('has a stable identity', () => {
    expect(RELATIVE_SOURCE_CANDIDATE_TABLE_ID).toBe('boundaryci/relative-source-candidates@1');
  });

  it('is exactly the fixture table, in order', () => {
    expect(RELATIVE_SOURCE_CANDIDATE_RULES).toEqual(
      cases.candidateRules.map((rule) => ({
        specifierExtension: rule.specifierExtension,
        candidateExtensions: rule.candidateExtensions,
        eligibleCandidateExtensions: rule.eligibleCandidateExtensions,
      })),
    );
  });

  for (const rule of cases.candidateRules) {
    it(`states one finite rule for "${rule.specifierExtension}": ${rule.name}`, () => {
      const actual = RELATIVE_SOURCE_CANDIDATE_RULES.find(
        (candidate) => candidate.specifierExtension === rule.specifierExtension,
      );
      expect(actual?.candidateExtensions).toEqual(rule.candidateExtensions);
      expect(actual?.eligibleCandidateExtensions).toEqual(rule.eligibleCandidateExtensions);
    });
  }

  it('yields zero eligible included candidates for the documented .cjs to .cts mapping', () => {
    const rule = RELATIVE_SOURCE_CANDIDATE_RULES.find((candidate) => candidate.specifierExtension === '.cjs');
    expect(rule?.candidateExtensions).toEqual(['.cjs', '.cts']);
    expect(rule?.eligibleCandidateExtensions).toEqual([]);
    for (const extension of rule?.candidateExtensions ?? []) {
      expect(ANALYZER_SOURCE_EXTENSIONS.includes(extension), extension).toBe(false);
      expect(scriptKindForPath(`src/module${extension}`), extension).toBeNull();
    }
  });

  it('never names an eligible candidate outside the discovered source universe', () => {
    for (const rule of RELATIVE_SOURCE_CANDIDATE_RULES) {
      for (const extension of rule.eligibleCandidateExtensions) {
        expect(ANALYZER_SOURCE_EXTENSIONS.includes(extension), extension).toBe(true);
      }
      expect(rule.eligibleCandidateExtensions).toEqual(
        rule.candidateExtensions.filter((extension) => ANALYZER_SOURCE_EXTENSIONS.includes(extension)),
      );
    }
  });

  it('has exactly one row per named specifier extension and no row for anything else', () => {
    const specifierExtensions = RELATIVE_SOURCE_CANDIDATE_RULES.map((rule) => rule.specifierExtension);
    expect(specifierExtensions).toEqual(['', '.js', '.jsx', '.mjs', '.ts', '.tsx', '.mts', '.cjs']);
    expect(new Set(specifierExtensions).size).toBe(specifierExtensions.length);
    for (const unmapped of ['.cts', '.json', '.node', '.wasm', '.d.ts', '.JS']) {
      expect(
        RELATIVE_SOURCE_CANDIDATE_RULES.some((rule) => rule.specifierExtension === unmapped),
        unmapped,
      ).toBe(false);
    }
  });

  it('encodes only extension candidates: no directory, index, package, or configuration behavior', () => {
    for (const rule of RELATIVE_SOURCE_CANDIDATE_RULES) {
      expect(Object.keys(rule).sort()).toEqual([
        'candidateExtensions',
        'eligibleCandidateExtensions',
        'specifierExtension',
      ]);
      for (const extension of rule.candidateExtensions) {
        expect(extension, extension).toMatch(/^\.[a-z]+$/);
      }
    }
    expect(JSON.stringify(RELATIVE_SOURCE_CANDIDATE_RULES)).not.toMatch(
      /index|package|node_modules|tsconfig|main|exports|imports/,
    );
  });

  it('is immutable', () => {
    expect(Object.isFrozen(RELATIVE_SOURCE_CANDIDATE_RULES)).toBe(true);
    for (const rule of RELATIVE_SOURCE_CANDIDATE_RULES) {
      expect(Object.isFrozen(rule)).toBe(true);
      expect(Object.isFrozen(rule.candidateExtensions)).toBe(true);
      expect(Object.isFrozen(rule.eligibleCandidateExtensions)).toBe(true);
    }
  });
});

/* ------------------------------------------------------------------ *
 * Import/isolation boundary.
 * ------------------------------------------------------------------ */

/**
 * The exact external modules the analyzer may import: the TypeScript parser plus Node byte,
 * digest, filesystem, and path primitives. Anything else — a module loader, a process
 * capability, a resolver, a bundler, a target dependency — is a boundary violation.
 */
const ALLOWED_EXTERNAL_MODULES: readonly string[] = ['node:crypto', 'node:fs/promises', 'node:path', 'typescript'];

/** Modules that would give the analyzer a resolution, loading, or execution capability. */
const FORBIDDEN_MODULES: readonly string[] = [
  'child_process',
  'module',
  'node:child_process',
  'node:module',
  'node:process',
  'node:repl',
  'node:v8',
  'node:vm',
  'node:worker_threads',
  'octokit',
  'probot',
  'ts-morph',
  'vm',
  'worker_threads',
];

/**
 * Names whose mere reachable use would mean the analyzer builds a program, resolves modules,
 * reads target configuration, transpiles, loads code, or runs a process.
 */
const FORBIDDEN_NAMES: readonly string[] = [
  'createCompilerHost',
  'createIncrementalProgram',
  'createLanguageService',
  'createProgram',
  'createRequire',
  'createSolutionBuilder',
  'createWatchProgram',
  'eval',
  'exec',
  'execFile',
  'execFileSync',
  'execSync',
  'executeCommandLine',
  'findConfigFile',
  'fork',
  'getParsedCommandLineOfConfigFile',
  'nodeModuleNameResolver',
  'parseConfigFileTextToJson',
  'parseJsonConfigFileContent',
  'process',
  'readConfigFile',
  'require',
  'resolveModuleName',
  'resolveModuleNameFromCache',
  'resolveTypeReferenceDirective',
  'spawn',
  'spawnSync',
  'sys',
  'transpile',
  'transpileDeclaration',
  'transpileModule',
];

interface ModuleBoundaryReport {
  moduleSpecifiers: string[];
  forbiddenNames: string[];
  dynamicImports: number;
}

/**
 * Reports one BoundaryCI source file's import and call boundary from its syntax alone.
 *
 * Every fact here comes from an AST node: a module specifier is a string literal in an import
 * or export clause, and a forbidden name is an identifier or a member name in real code. Text
 * inside a comment or a string literal is therefore never mistaken for a capability, which is
 * exactly what a substring scan would get wrong on this repository's own documentation.
 */
function inspectModuleBoundary(fileName: string, text: string): ModuleBoundaryReport {
  const sourceFile = ts.createSourceFile(fileName, text, ts.ScriptTarget.ES2024, false, ts.ScriptKind.TS);
  const moduleSpecifiers: string[] = [];
  const forbiddenNames = new Set<string>();
  let dynamicImports = 0;

  const recordSpecifier = (node: ts.Expression | undefined): void => {
    if (node !== undefined && ts.isStringLiteral(node)) moduleSpecifiers.push(node.text);
  };

  const visit = (node: ts.Node): void => {
    if (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) {
      recordSpecifier(node.moduleSpecifier);
    } else if (ts.isImportEqualsDeclaration(node) && ts.isExternalModuleReference(node.moduleReference)) {
      recordSpecifier(node.moduleReference.expression);
    } else if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) {
      dynamicImports += 1;
      recordSpecifier(node.arguments[0]);
    } else if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'require') {
      recordSpecifier(node.arguments[0]);
    } else if (ts.isImportTypeNode(node) && ts.isLiteralTypeNode(node.argument)) {
      const literal = node.argument.literal;
      if (ts.isStringLiteral(literal)) moduleSpecifiers.push(literal.text);
    }

    if (ts.isIdentifier(node)) {
      if (FORBIDDEN_NAMES.includes(node.text)) forbiddenNames.add(node.text);
    } else if (ts.isPropertyAccessExpression(node) && ts.isIdentifier(node.name)) {
      if (FORBIDDEN_NAMES.includes(node.name.text)) forbiddenNames.add(node.name.text);
    } else if (ts.isQualifiedName(node) && FORBIDDEN_NAMES.includes(node.right.text)) {
      forbiddenNames.add(node.right.text);
    }

    ts.forEachChild(node, visit);
  };

  visit(sourceFile);
  return { moduleSpecifiers, forbiddenNames: [...forbiddenNames].sort(), dynamicImports };
}

const ANALYZER_DIRECTORY = dirname(fileURLToPath(new URL('../../src/analyzer/analyze.ts', import.meta.url)));

/** Resolves one relative BoundaryCI import specifier back to the TypeScript file it names. */
function resolveLocalModule(fromFile: string, specifier: string): string {
  const target = resolve(dirname(fromFile), specifier);
  return target.endsWith('.js') ? `${target.slice(0, -'.js'.length)}.ts` : `${target}.ts`;
}

/** Reads the reachable BoundaryCI module closure from one entry file, following relative imports only. */
async function readReachableModules(entryFile: string): Promise<Map<string, ModuleBoundaryReport>> {
  const reports = new Map<string, ModuleBoundaryReport>();
  const queue = [entryFile];
  while (queue.length > 0) {
    const current = queue.shift();
    if (current === undefined || reports.has(current)) continue;
    const report = inspectModuleBoundary(current, await readFile(current, 'utf8'));
    reports.set(current, report);
    for (const specifier of report.moduleSpecifiers) {
      if (specifier.startsWith('.')) queue.push(resolveLocalModule(current, specifier));
    }
  }
  return reports;
}

describe('analyzer import boundary', () => {
  it('detects real capability use and ignores identical text in comments and strings', () => {
    const inert = [
      '// This module never calls ts.createProgram and never uses require().',
      "const note = 'child_process, transpileModule, and eval stay out of the analyzer';",
      'export const value = note.length;',
      '',
    ].join('\n');
    const inertReport = inspectModuleBoundary('inert.ts', inert);
    expect(inertReport.forbiddenNames).toEqual([]);
    expect(inertReport.moduleSpecifiers).toEqual([]);
    expect(inertReport.dynamicImports).toBe(0);

    const offending = [
      "import { spawnSync } from 'node:child_process';",
      'const program = ts.createProgram([], {});',
      "const loaded = require('node:module');",
      "const dynamic = await import('./target.js');",
      'export const used = [program, loaded, dynamic, spawnSync];',
      '',
    ].join('\n');
    const offendingReport = inspectModuleBoundary('offending.ts', offending);
    expect(offendingReport.forbiddenNames).toEqual(['createProgram', 'require', 'spawnSync']);
    expect(offendingReport.moduleSpecifiers).toEqual(['node:child_process', 'node:module', './target.js']);
    expect(offendingReport.dynamicImports).toBe(1);
  });

  it('reaches exactly the analyzer module closure from the analyzer entry point', async () => {
    const reports = await readReachableModules(resolve(ANALYZER_DIRECTORY, 'analyze.ts'));
    const reached = [...reports.keys()].map((path) => path.slice(path.indexOf('/src/') + 1)).sort();
    expect(reached).toEqual([
      'src/analyzer/analyze.ts',
      'src/analyzer/candidates.ts',
      'src/analyzer/contract.ts',
      'src/analyzer/discovery.ts',
      'src/analyzer/operations.ts',
      'src/analyzer/parse.ts',
      'src/analyzer/probot.ts',
      'src/analyzer/profile.ts',
      'src/analyzer/resolve.ts',
      'src/permission-model/bounded-catalog.ts',
      'src/permission-model/model.ts',
    ]);
  });

  it('imports only TypeScript, Node byte primitives, and local BoundaryCI modules', async () => {
    const reports = await readReachableModules(resolve(ANALYZER_DIRECTORY, 'analyze.ts'));
    const externals = new Set<string>();
    for (const [file, report] of reports) {
      for (const specifier of report.moduleSpecifiers) {
        if (specifier.startsWith('.')) {
          expect(specifier.endsWith('.js'), `${file} imports ${specifier}`).toBe(true);
          continue;
        }
        externals.add(specifier);
        expect(FORBIDDEN_MODULES.includes(specifier), `${file} imports ${specifier}`).toBe(false);
        expect(ALLOWED_EXTERNAL_MODULES.includes(specifier), `${file} imports ${specifier}`).toBe(true);
      }
    }
    expect([...externals].sort()).toEqual(['node:crypto', 'node:fs/promises', 'node:path', 'typescript']);
  });

  it('never reaches a program, resolver, config reader, transpiler, loader, or process capability', async () => {
    const reports = await readReachableModules(resolve(ANALYZER_DIRECTORY, 'analyze.ts'));
    for (const [file, report] of reports) {
      expect(report.forbiddenNames, file).toEqual([]);
      expect(report.dynamicImports, file).toBe(0);
    }
  });

  it('keeps the parser itself free of filesystem and process capability', async () => {
    const parseFile = resolve(ANALYZER_DIRECTORY, 'parse.ts');
    const report = inspectModuleBoundary(parseFile, await readFile(parseFile, 'utf8'));
    expect([...new Set(report.moduleSpecifiers)].sort()).toEqual([
      '../permission-model/model.js',
      './contract.js',
      'node:crypto',
      'typescript',
    ]);
    expect(report.forbiddenNames).toEqual([]);
    expect(report.dynamicImports).toBe(0);
  });

  it('parses target source only through ts.createSourceFile', async () => {
    const parseFile = resolve(ANALYZER_DIRECTORY, 'parse.ts');
    const sourceFile = ts.createSourceFile(
      parseFile,
      await readFile(parseFile, 'utf8'),
      ts.ScriptTarget.ES2024,
      false,
      ts.ScriptKind.TS,
    );
    const typescriptCalls: string[] = [];
    const visit = (node: ts.Node): void => {
      if (
        ts.isCallExpression(node) &&
        ts.isPropertyAccessExpression(node.expression) &&
        ts.isIdentifier(node.expression.expression) &&
        node.expression.expression.text === 'ts'
      ) {
        typescriptCalls.push(node.expression.name.text);
      }
      ts.forEachChild(node, visit);
    };
    visit(sourceFile);
    expect(typescriptCalls).toEqual(['createSourceFile']);
  });
});
