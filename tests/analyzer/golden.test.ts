import { access, readFile } from 'node:fs/promises';

import { afterEach, describe, expect, it } from 'vitest';

import { analyzeSourceTree } from '../../src/analyzer/analyze.js';
import { DEFAULT_ANALYSIS_LIMITS, validateAnalysisResult } from '../../src/analyzer/contract.js';
import type { AnalysisRequest, AnalysisResult, AnalyzerCauseCode } from '../../src/analyzer/contract.js';

import cases from './fixtures/golden-cases.json' with { type: 'json' };
import expectedResults from './fixtures/golden-results.json' with { type: 'json' };
import { cleanupTempRoots, createTempRoot, writeRegularFile } from './helpers.js';

interface GoldenCase {
  id: string;
  entrypoints?: string[];
  request?: Partial<AnalysisRequest>;
  files: Record<string, string>;
}

interface GoldenCoverage {
  requirements: string[];
  decisions: string[];
  causeCodes: string[];
  references: GoldenCoverageReference[];
}

interface GoldenCoverageReference {
  id: string;
  cases: string[];
  sources: string[];
  requirements: string[];
  decisions: string[];
  causeCodes: string[];
}

const matrix = cases as { coverage: GoldenCoverage; cases: GoldenCase[] };
const expected = expectedResults as Record<string, AnalysisResult>;
const REQUIRED_REQUIREMENTS = Array.from({ length: 14 }, (_, index) => `ANLZ-${String(index + 1).padStart(2, '0')}`).concat('QUAL-01');
const REQUIRED_DECISIONS = Array.from({ length: 53 }, (_, index) => `D-${String(index + 1).padStart(2, '0')}`);
const REQUIRED_CAUSE_CODES = [
  'ambiguous-relative-source',
  'ambiguous-endpoint-member',
  'ambiguous-request-route',
  'dynamic-request-route',
  'internal-analyzer-error',
  'invalid-analysis-request',
  'invalid-analysis-result',
  'invalid-source-encoding',
  'invalidated-private-field',
  'matching-non-regular-entry',
  'matching-source-symlink',
  'malformed-request-route',
  'mutable-provenance-binding',
  'permission-catalog-incomplete',
  'unsupported-probot-entrypoint-initializer',
  'unsupported-probot-handler-registration',
  'probot-entrypoint-unsupported',
  'relevant-directory-symlink',
  'relevant-resolution-cycle',
  'resolution-byte-limit',
  'resolution-depth-limit',
  'resolution-file-limit',
  'resolution-work-limit',
  'source-byte-limit',
  'source-discovery-error',
  'source-file-limit',
  'source-parse-error',
  'source-read-error',
  'source-work-limit',
  'unproven-octokit-origin',
  'unproven-receiver-provenance',
  'unresolvable-analysis-root',
  'unresolved-relative-source',
  'unknown-request-route',
  'unknown-endpoint-member',
  'unsupported-commonjs-form',
  'unsupported-dynamic-member-access',
  'unsupported-endpoint-extraction',
  'unsupported-endpoint-surface',
  'unsupported-export-form',
  'unsupported-import-form',
  'unsupported-object-state',
  'unsupported-octokit-constructor',
  'unsupported-optional-chain',
  'unsupported-probot-registration',
  'unsupported-request-grammar',
  'unsupported-request-object',
  'unsupported-static-member-access',
] as const satisfies readonly AnalyzerCauseCode[];
type MissingCauseCode = Exclude<AnalyzerCauseCode, (typeof REQUIRED_CAUSE_CODES)[number]>;
const CAUSE_CODE_VOCABULARY_IS_EXHAUSTIVE: MissingCauseCode extends never ? true : never = true;
const GOLDEN_RESULTS_URL = new URL('./fixtures/golden-results.json', import.meta.url);

afterEach(cleanupTempRoots);

async function analyzeGoldenCase(testCase: GoldenCase): Promise<AnalysisResult> {
  const rootPath = await createTempRoot(`boundaryci-golden-${testCase.id}-`);
  for (const [path, text] of Object.entries(testCase.files)) await writeRegularFile(rootPath, path, text);
  const request: AnalysisRequest = {
    rootPath,
    include: ['**/*.js', '**/*.jsx', '**/*.mjs', '**/*.ts', '**/*.tsx', '**/*.mts'],
    exclude: [],
    probotEntrypoints: testCase.entrypoints ?? [],
    limits: { ...DEFAULT_ANALYSIS_LIMITS },
    ...testCase.request,
  };
  return analyzeSourceTree(request);
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const object = value as Record<string, unknown>;
  return `{${Object.keys(object).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(object[key])}`).join(',')}}`;
}

describe('normative golden grammar matrix', () => {
  it('machine-accounts for every requirement, decision, cause, and golden case exactly once', async () => {
    expect(CAUSE_CODE_VOCABULARY_IS_EXHAUSTIVE).toBe(true);
    expect(matrix.coverage.requirements).toEqual(REQUIRED_REQUIREMENTS);
    expect(matrix.coverage.decisions).toEqual(REQUIRED_DECISIONS);
    expect(matrix.coverage.causeCodes).toEqual(REQUIRED_CAUSE_CODES);

    const caseIds = matrix.cases.map((entry) => entry.id);
    expect(caseIds.length).toBe(new Set(caseIds).size);
    expect(Object.keys(expected).sort()).toEqual([...caseIds].sort());

    const account = (key: 'requirements' | 'decisions' | 'causeCodes'): string[] =>
      matrix.coverage.references.flatMap((reference) => reference[key]);
    expect(account('requirements').sort()).toEqual([...REQUIRED_REQUIREMENTS].sort());
    expect(account('decisions').sort()).toEqual([...REQUIRED_DECISIONS].sort());
    expect(account('causeCodes').sort()).toEqual([...REQUIRED_CAUSE_CODES].sort());
    for (const key of ['requirements', 'decisions', 'causeCodes'] as const) {
      expect(account(key).length).toBe(new Set(account(key)).size);
    }

    const referencedCases = matrix.coverage.references.flatMap((reference) => reference.cases);
    expect(referencedCases.sort()).toEqual([...caseIds].sort());
    expect(referencedCases.length).toBe(new Set(referencedCases).size);
    for (const reference of matrix.coverage.references) {
      expect(reference.cases.length + reference.sources.length).toBeGreaterThan(0);
      for (const source of reference.sources) await expect(access(source)).resolves.toBeUndefined();
    }

    const fixtureBytes = await readFile(GOLDEN_RESULTS_URL, 'utf8');
    expect(fixtureBytes).toBe(`${JSON.stringify(expectedResults, null, 2)}\n`);
  });

  for (const testCase of matrix.cases) {
    it(testCase.id, async () => {
      const inputSnapshot = structuredClone(testCase);
      const actual = await analyzeGoldenCase(testCase);
      expect(() => validateAnalysisResult(actual)).not.toThrow();
      expect(JSON.stringify(actual)).toBe(JSON.stringify(expected[testCase.id]));
      expect(canonicalJson(actual)).toBe(canonicalJson(expected[testCase.id]));
      expect(JSON.parse(JSON.stringify(actual))).toEqual(actual);
      expect(JSON.stringify(await analyzeGoldenCase(testCase))).toBe(JSON.stringify(actual));
      expect(testCase).toEqual(inputSnapshot);
    });
  }

  it('is independent of reversed concurrent case scheduling', async () => {
    const reversed = [...matrix.cases].reverse();
    const results = await Promise.all(reversed.map(async (testCase) => [testCase.id, await analyzeGoldenCase(testCase)] as const));
    for (const [id, result] of results) expect(JSON.stringify(result)).toBe(JSON.stringify(expected[id]));
  });
});
