/**
 * Result accounting, causal deduplication, resource-frontier, determinism, and contract-validation
 * behavior of the real analyzer.
 *
 * Every scenario here drives the public `analyzeSourceTree` entrypoint over a bounded temporary
 * tree of inert bytes and validates whatever it produced with `validateAnalysisResult`. Nothing
 * in this file installs, imports, transpiles, or executes a fixture, and nothing reaches into
 * analyzer internals: the exact graph, provenance, and per-limit resource behavior is stated by
 * `provenance.test.ts` and `discovery.test.ts`, and is relied on here rather than restated.
 */

import { afterEach, describe, expect, it } from 'vitest';

import { analyzeSourceTree } from '../../src/analyzer/analyze.js';
import { DEFAULT_ANALYSIS_LIMITS, validateAnalysisResult } from '../../src/analyzer/contract.js';
import type {
  AnalysisLimits,
  AnalysisRequest,
  AnalysisResult,
  AnalyzerCause,
  CandidateClassification,
  CompleteAnalysisResult,
  IncompleteAnalysisResult,
} from '../../src/analyzer/contract.js';

import { cleanupTempRoots, createTempRoot, writeRegularFile } from './helpers.js';
import resultCases from './fixtures/result-cases.json' with { type: 'json' };

interface FixtureFile {
  path: string;
  text: string[];
}

interface ProvenOperationExpectation {
  path: string;
  operationId: string;
}

interface SharedCauseExpectation {
  candidateCount: number;
  causeCode: string;
}

interface ResultExpectation {
  status: string;
  classificationCounts: Record<string, number>;
  causeCodes: string[];
  causeCount: number;
  provenOperations?: ProvenOperationExpectation[];
  sharedCause?: SharedCauseExpectation;
}

interface ResultCase {
  name: string;
  files: FixtureFile[];
  expect: ResultExpectation;
}

/** A result that carries semantic evidence, as opposed to a diagnostic-only failed result. */
type EvidenceResult = CompleteAnalysisResult | IncompleteAnalysisResult;

const cases = resultCases as { cases: ResultCase[] };

const CLASSIFICATIONS: readonly CandidateClassification[] = ['incomplete', 'proven-irrelevant', 'proven-operation'];

afterEach(async () => {
  await cleanupTempRoots();
});

/**
 * Materializes one fixture tree of inert bytes and returns its temporary root.
 *
 * Each declared line array becomes a newline-terminated UTF-8 file; the analyzer only ever
 * reads those bytes back.
 */
async function materialize(files: readonly FixtureFile[]): Promise<string> {
  const root = await createTempRoot('boundaryci-analyzer-results-');
  for (const file of files) await writeRegularFile(root, file.path, `${file.text.join('\n')}\n`);
  return root;
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

function limitsFor(overrides: Partial<AnalysisLimits> = {}): AnalysisLimits {
  return { ...DEFAULT_ANALYSIS_LIMITS, ...overrides };
}

/** Asserts the analyzer produced trustworthy evidence, and that the evidence validates. */
function expectEvidence(result: AnalysisResult): EvidenceResult {
  if (result.status === 'failed') throw new Error(`expected an evidence result, received ${result.reason}`);
  expect(() => {
    validateAnalysisResult(result);
  }).not.toThrow();
  return result;
}

function fixtureCase(name: string): ResultCase {
  const found = cases.cases.find((entry) => entry.name === name);
  if (found === undefined) throw new Error(`the declared result case "${name}" is missing from the inventory`);
  return found;
}

async function analyzeFixtureCase(name: string): Promise<EvidenceResult> {
  const testCase = fixtureCase(name);
  const root = await materialize(testCase.files);
  return expectEvidence(await analyzeSourceTree(requestFor(root)));
}

function classificationCounts(result: EvidenceResult): Record<CandidateClassification, number> {
  const counts: Record<CandidateClassification, number> = {
    incomplete: 0,
    'proven-irrelevant': 0,
    'proven-operation': 0,
  };
  for (const candidate of result.candidates) counts[candidate.classification] += 1;
  return counts;
}

/** The full deduplication key of a cause: everything about it except its ordinal identifier. */
function causeBody(cause: AnalyzerCause): string {
  return JSON.stringify([cause.code, cause.scope, cause.path, cause.span, cause.resource, cause.detail]);
}

/**
 * Asserts the accounting invariants every evidence result must satisfy, whatever it found.
 *
 * These hold independently of the scenario: candidate totals are the disjoint classification
 * sum, no cause body appears twice, every link resolves, and every observation is resolved by
 * exactly one permission resolution.
 */
function expectTotalAccounting(result: EvidenceResult): void {
  const counts = classificationCounts(result);
  const total = CLASSIFICATIONS.reduce((sum, classification) => sum + counts[classification], 0);
  expect(total).toBe(result.candidates.length);

  const candidateIds = result.candidates.map((candidate) => candidate.id);
  expect(new Set(candidateIds).size).toBe(candidateIds.length);

  const causeIds = new Set(result.causes.map((cause) => cause.id));
  expect(causeIds.size).toBe(result.causes.length);
  const bodies = result.causes.map(causeBody);
  expect(new Set(bodies).size).toBe(bodies.length);

  const sourcePaths = new Set(result.sources.map((source) => source.path));
  for (const candidate of result.candidates) {
    expect(sourcePaths.has(candidate.path)).toBe(true);
    for (const id of candidate.causeIds) expect(causeIds.has(id)).toBe(true);
    if (candidate.classification === 'proven-operation') {
      expect(candidate.observationId).not.toBeNull();
      expect(candidate.causeIds).toEqual([]);
    } else {
      expect(candidate.observationId).toBeNull();
      if (candidate.classification === 'incomplete') expect(candidate.causeIds.length).toBeGreaterThan(0);
    }
  }

  expect(result.observations).toHaveLength(counts['proven-operation']);
  expect(result.permissionResolutions).toHaveLength(result.observations.length);
  expect(result.permissionResolutions.map((resolution) => resolution.observationId)).toEqual(
    result.observations.map((observation) => observation.id),
  );
  for (const observation of result.observations) {
    const owner = result.candidates.find((candidate) => candidate.id === observation.candidateId);
    expect(owner?.observationId).toBe(observation.id);
  }
}

describe('candidate accounting over the declared result inventory', () => {
  for (const testCase of cases.cases) {
    it(testCase.name, async () => {
      const root = await materialize(testCase.files);
      const result = expectEvidence(await analyzeSourceTree(requestFor(root)));

      expect(result.status).toBe(testCase.expect.status);
      expectTotalAccounting(result);
      expect(classificationCounts(result)).toEqual(testCase.expect.classificationCounts);
      expect(result.causes).toHaveLength(testCase.expect.causeCount);
      expect([...new Set(result.causes.map((cause) => cause.code))].sort()).toEqual(
        [...testCase.expect.causeCodes].sort(),
      );

      // An unproven receiver never becomes proof that the receiver was something else.
      const irrelevant = testCase.expect.classificationCounts['proven-irrelevant'] ?? 0;
      expect(result.candidates.filter((candidate) => candidate.classification === 'proven-irrelevant')).toHaveLength(
        irrelevant,
      );

      const provenOperations = testCase.expect.provenOperations ?? [];
      expect(
        result.observations
          .map((observation) => ({ path: observation.source.path, operationId: observation.operation.operationId }))
          .sort((left, right) => (JSON.stringify(left) < JSON.stringify(right) ? -1 : 1)),
      ).toEqual(
        [...provenOperations].sort((left, right) => (JSON.stringify(left) < JSON.stringify(right) ? -1 : 1)),
      );

      const shared = testCase.expect.sharedCause;
      if (shared !== undefined) {
        const matching = result.causes.filter((cause) => cause.code === shared.causeCode);
        expect(matching).toHaveLength(1);
        const sharedId = matching[0]?.id;
        expect(
          result.candidates.filter((candidate) => candidate.causeIds.includes(sharedId ?? '')),
        ).toHaveLength(shared.candidateCount);
      }
    });
  }
});

describe('scoped failure never withdraws independent evidence', () => {
  it('keeps an independently proven operation while a parse failure leaves the repository incomplete', async () => {
    const result = await analyzeFixtureCase(
      'a parse failure withdraws no evidence from an independently parsed proven file',
    );

    expect(result.status).toBe('incomplete');
    expect(result.sources.map((source) => source.path)).toEqual(['src/broken.ts', 'src/good.ts']);
    expect(result.observations.map((observation) => observation.source.path)).toEqual(['src/good.ts']);
    expect(result.permissionBoundary.status).toBe('complete');

    const parseCause = result.causes.find((cause) => cause.code === 'source-parse-error');
    expect(parseCause?.scope).toBe('source');
    expect(parseCause?.path).toBe('src/broken.ts');
    // The unparsed file is evidence about the repository, not a candidate that failed proof.
    expect(result.candidates.some((candidate) => candidate.path === 'src/broken.ts')).toBe(false);
  });

  it('blocks only the candidate that depended on a relevant resolution cycle', async () => {
    const result = await analyzeFixtureCase('a relevant resolution cycle blocks only its own dependent candidate');

    expect(result.status).toBe('incomplete');
    const proven = result.candidates.filter((candidate) => candidate.classification === 'proven-operation');
    const blocked = result.candidates.filter((candidate) => candidate.classification === 'incomplete');
    expect(proven).toHaveLength(1);
    expect(blocked).toHaveLength(1);
    expect(blocked[0]?.reason).toBe('unproven-receiver-provenance');

    const cycleCause = result.causes.find((cause) => cause.code === 'relevant-resolution-cycle');
    expect(cycleCause).toBeDefined();
    expect(blocked[0]?.causeIds).toEqual([cycleCause?.id]);
    expect(proven[0]?.causeIds).toEqual([]);
    expect(result.observations.map((observation) => observation.operation.operationId)).toEqual(['issues/create']);
  });

  it('links two dependent candidates to one deduplicated cause body with no duplicate cause identifier', async () => {
    const result = await analyzeFixtureCase(
      'two candidates fed by one unresolvable receiver dedupe to one shared cause body',
    );

    expect(result.causes).toHaveLength(1);
    const shared = result.causes[0];
    expect(shared?.code).toBe('unproven-octokit-origin');
    expect(result.candidates.map((candidate) => candidate.causeIds)).toEqual([[shared?.id], [shared?.id]]);
    expect(new Set(result.causes.map(causeBody)).size).toBe(1);
    expect(result.observations).toEqual([]);
  });
});

describe('scan-wide resource frontier', () => {
  const PROVEN_SOURCE = (method: string): string[] => [
    "import { Octokit } from 'octokit';",
    '',
    'const client = new Octokit();',
    '',
    `client.rest.issues.${method}({ owner: 'o', repo: 'r', title: 't' });`,
  ];

  async function frontierTree(): Promise<string> {
    return materialize([
      { path: 'src/a.ts', text: PROVEN_SOURCE('create') },
      { path: 'src/m.ts', text: PROVEN_SOURCE('listForRepo') },
      { path: 'src/z.ts', text: PROVEN_SOURCE('create') },
    ]);
  }

  it('records one aggregate work frontier, stops in sorted order, and retains completed prior evidence', async () => {
    const root = await frontierTree();

    // Four filesystem entries would be inspected: the `src` directory, then `a.ts`, `m.ts`, and
    // `z.ts` in bytewise order. Three work units stop the scan exactly at the `z.ts` frontier.
    const result = expectEvidence(await analyzeSourceTree(requestFor(root, { limits: limitsFor({ maxSourceWork: 3 }) })));

    expect(result.status).toBe('incomplete');
    expect(result.sources.map((source) => source.path)).toEqual(['src/a.ts', 'src/m.ts']);
    expect(result.candidates.map((candidate) => candidate.path)).toEqual(['src/a.ts', 'src/m.ts']);
    expect(result.candidates.map((candidate) => candidate.id)).toEqual(['candidate-0001', 'candidate-0002']);

    const resourceCauses = result.causes.filter((cause) => cause.resource !== null);
    expect(resourceCauses).toHaveLength(1);
    expect(resourceCauses[0]).toMatchObject({
      code: 'source-work-limit',
      scope: 'repository',
      path: null,
      resource: {
        limitKey: 'maxSourceWork',
        configured: 3,
        consumed: 3,
        frontier: 'src/z.ts',
        processedSources: 2,
        unprocessedSources: null,
      },
    });

    // Everything completed before the frontier keeps its full proof and permission evidence.
    expect(result.observations.map((observation) => observation.operation.operationId)).toEqual([
      'issues/create',
      'issues/list-for-repo',
    ]);
    expect(result.permissionResolutions.map((resolution) => resolution.finding.status)).toEqual([
      'resolved',
      'resolved',
    ]);
    expect(result.permissionBoundary.status).toBe('complete');

    const replay = await analyzeSourceTree(requestFor(root, { limits: limitsFor({ maxSourceWork: 3 }) }));
    expect(JSON.stringify(replay)).toBe(JSON.stringify(result));
  });

  it('keeps the exact and one-over source-file budgets complete and charges one budget below it', async () => {
    const root = await frontierTree();

    const exact = expectEvidence(await analyzeSourceTree(requestFor(root, { limits: limitsFor({ maxSourceFiles: 3 }) })));
    expect(exact.status).toBe('complete');
    expect(exact.causes).toEqual([]);
    expect(exact.sources.map((source) => source.path)).toEqual(['src/a.ts', 'src/m.ts', 'src/z.ts']);

    const oneOver = expectEvidence(
      await analyzeSourceTree(requestFor(root, { limits: limitsFor({ maxSourceFiles: 4 }) })),
    );
    expect(oneOver.status).toBe('complete');
    expect(oneOver.causes).toEqual([]);
    expect(oneOver.sources.map((source) => source.path)).toEqual(['src/a.ts', 'src/m.ts', 'src/z.ts']);
    // Only the declared budget differs, so the rest of the evidence is identical.
    expect(JSON.stringify({ ...oneOver, boundary: null })).toBe(JSON.stringify({ ...exact, boundary: null }));

    const oneUnder = expectEvidence(
      await analyzeSourceTree(requestFor(root, { limits: limitsFor({ maxSourceFiles: 2 }) })),
    );
    expect(oneUnder.status).toBe('incomplete');
    expect(oneUnder.sources.map((source) => source.path)).toEqual(['src/a.ts', 'src/m.ts']);
    expect(oneUnder.causes.filter((cause) => cause.code === 'source-file-limit')).toHaveLength(1);
    expect(oneUnder.observations.map((observation) => observation.operation.operationId)).toEqual([
      'issues/create',
      'issues/list-for-repo',
    ]);
  });
});

describe('serial and concurrent determinism', () => {
  it('serializes repeated serial calls and independent concurrent calls byte-identically', async () => {
    const multiple = fixtureCase('multiple candidates split into a disjoint proven/incomplete total');
    const cycle = fixtureCase('a relevant resolution cycle blocks only its own dependent candidate');

    const firstRoot = await materialize(multiple.files);
    const secondRoot = await materialize(multiple.files);
    const cycleRoot = await materialize(cycle.files);

    const serial: string[] = [];
    for (const root of [firstRoot, firstRoot, secondRoot]) {
      serial.push(JSON.stringify(await analyzeSourceTree(requestFor(root))));
    }
    expect(serial[1]).toBe(serial[0]);
    expect(serial[2]).toBe(serial[0]);
    expect(serial[0]).not.toContain(firstRoot);

    const cycleSerial = JSON.stringify(await analyzeSourceTree(requestFor(cycleRoot)));

    // Independent concurrent analyses share no mutable state: each one still serializes to
    // exactly what the same request produced on its own.
    const concurrent = await Promise.all([
      analyzeSourceTree(requestFor(cycleRoot)),
      analyzeSourceTree(requestFor(firstRoot)),
      analyzeSourceTree(requestFor(secondRoot)),
      analyzeSourceTree(requestFor(cycleRoot)),
    ]);
    const serialized = concurrent.map((result) => JSON.stringify(result));
    expect(serialized[0]).toBe(cycleSerial);
    expect(serialized[3]).toBe(cycleSerial);
    expect(serialized[1]).toBe(serial[0]);
    expect(serialized[2]).toBe(serial[0]);

    for (const result of concurrent) expectEvidence(result);
  });
});

describe('result contract validation', () => {
  /**
   * Analyzes the mixed proven/unproven inventory case, whose result carries every cross-reference
   * the validator has to defend: several candidates, two proven observations with their
   * resolutions, and one linked cause.
   */
  async function baseResult(): Promise<EvidenceResult> {
    const result = await analyzeFixtureCase('multiple candidates split into a disjoint proven/incomplete total');
    expect(result.candidates).toHaveLength(3);
    expect(result.observations).toHaveLength(2);
    expect(result.permissionResolutions).toHaveLength(2);
    expect(result.causes).toHaveLength(1);
    return result;
  }

  /** Applies one mutation to an independent deep copy, so mutations never interact. */
  function mutated(result: EvidenceResult, mutate: (draft: EvidenceResult) => void): EvidenceResult {
    const draft = structuredClone(result);
    mutate(draft);
    return draft;
  }

  function expectRejected(result: EvidenceResult, label: string, mutate: (draft: EvidenceResult) => void): void {
    const draft = mutated(result, mutate);
    expect(() => {
      validateAnalysisResult(draft);
    }, label).toThrow(TypeError);
  }

  it('rejects a contradictory classification, reason, observation, or cause shape', async () => {
    const result = await baseResult();

    expectRejected(result, 'proven with a cause', (draft) => {
      const proven = draft.candidates[0];
      if (proven !== undefined) proven.causeIds = [draft.causes[0]?.id ?? 'cause-0001'];
    });
    expectRejected(result, 'proven without an observation', (draft) => {
      const proven = draft.candidates[0];
      if (proven !== undefined) proven.observationId = null;
    });
    expectRejected(result, 'proven with a non-proof reason', (draft) => {
      const proven = draft.candidates[0];
      if (proven !== undefined) proven.reason = 'unproven-receiver-provenance';
    });
    expectRejected(result, 'incomplete with a proof reason', (draft) => {
      const blocked = draft.candidates[2];
      if (blocked !== undefined) blocked.reason = 'proven-direct-rest-member-call';
    });
    expectRejected(result, 'incomplete without a cause', (draft) => {
      const blocked = draft.candidates[2];
      if (blocked !== undefined) blocked.causeIds = [];
    });
    expectRejected(result, 'incomplete claiming an observation', (draft) => {
      const blocked = draft.candidates[2];
      if (blocked !== undefined) blocked.observationId = draft.observations[0]?.id ?? null;
    });

    // Failure to prove provenance is never re-labelled as proven irrelevance: the affirmative
    // shape requires its own reason, and no cause and no observation.
    expectRejected(result, 'irrelevant by relabelling an unproven candidate', (draft) => {
      const blocked = draft.candidates[2];
      if (blocked !== undefined) blocked.classification = 'proven-irrelevant';
    });
    expectRejected(result, 'irrelevant while keeping a cause', (draft) => {
      const blocked = draft.candidates[2];
      if (blocked !== undefined) {
        blocked.classification = 'proven-irrelevant';
        blocked.reason = 'proven-non-octokit-origin';
      }
    });
    expectRejected(result, 'irrelevant while keeping an observation', (draft) => {
      const proven = draft.candidates[0];
      if (proven !== undefined) {
        proven.classification = 'proven-irrelevant';
        proven.reason = 'proven-non-octokit-origin';
      }
    });
    expectRejected(result, 'complete status with an outstanding cause', (draft) => {
      draft.status = 'complete';
    });
  });

  it('rejects orphan, mismatched, or doubly claimed observations', async () => {
    const result = await baseResult();

    expectRejected(result, 'candidate referencing an unknown observation', (draft) => {
      const proven = draft.candidates[0];
      if (proven !== undefined) proven.observationId = 'operation-9999';
    });
    expectRejected(result, 'observation referencing an unknown candidate', (draft) => {
      const observation = draft.observations[0];
      if (observation !== undefined) observation.candidateId = 'candidate-9999';
    });
    expectRejected(result, 'observation and candidate not naming each other', (draft) => {
      const observation = draft.observations[0];
      if (observation !== undefined) observation.candidateId = draft.candidates[1]?.id ?? 'candidate-0002';
    });
    expectRejected(result, 'two candidates claiming one observation', (draft) => {
      const second = draft.candidates[1];
      const first = draft.candidates[0];
      if (second !== undefined && first !== undefined) second.observationId = first.observationId;
    });
    expectRejected(result, 'observation proving through an unanalyzed source', (draft) => {
      draft.sources = draft.sources.filter((source) => source.path !== 'src/app.ts');
    });
    expectRejected(result, 'candidate referencing an unanalyzed source', (draft) => {
      const blocked = draft.candidates[2];
      if (blocked !== undefined) blocked.path = 'src/never-analyzed.ts';
    });
    expectRejected(result, 'candidate referencing an unknown cause', (draft) => {
      const blocked = draft.candidates[2];
      if (blocked !== undefined) blocked.causeIds = ['cause-9999'];
    });
    expectRejected(result, 'candidate repeating one cause link', (draft) => {
      const blocked = draft.candidates[2];
      const causeId = blocked?.causeIds[0];
      if (blocked !== undefined && causeId !== undefined) blocked.causeIds = [causeId, causeId];
    });
  });

  it('rejects duplicate or missing permission-resolution coverage and duplicate identifiers', async () => {
    const result = await baseResult();

    expectRejected(result, 'one observation resolved twice', (draft) => {
      const second = draft.permissionResolutions[1];
      const first = draft.permissionResolutions[0];
      if (second !== undefined && first !== undefined) second.observationId = first.observationId;
    });
    expectRejected(result, 'an observation left unresolved', (draft) => {
      draft.permissionResolutions = draft.permissionResolutions.slice(0, 1);
    });
    expectRejected(result, 'a resolution of an unknown observation', (draft) => {
      const resolution = draft.permissionResolutions[0];
      if (resolution !== undefined) resolution.observationId = 'operation-9999';
    });

    expectRejected(result, 'duplicate source identifier', (draft) => {
      const second = draft.sources[1];
      const first = draft.sources[0];
      if (second !== undefined && first !== undefined) second.id = first.id;
    });
    expectRejected(result, 'duplicate candidate identifier', (draft) => {
      const second = draft.candidates[1];
      const first = draft.candidates[0];
      if (second !== undefined && first !== undefined) second.id = first.id;
    });
    expectRejected(result, 'duplicate observation identifier', (draft) => {
      const second = draft.observations[1];
      const first = draft.observations[0];
      if (second !== undefined && first !== undefined) second.id = first.id;
    });
    expectRejected(result, 'duplicate resolution identifier', (draft) => {
      const second = draft.permissionResolutions[1];
      const first = draft.permissionResolutions[0];
      if (second !== undefined && first !== undefined) second.id = first.id;
    });
    expectRejected(result, 'duplicate cause identifier', (draft) => {
      const cause = draft.causes[0];
      if (cause !== undefined) draft.causes = [cause, { ...cause }];
    });
    expectRejected(result, 'duplicate cause body under a distinct identifier', (draft) => {
      const cause = draft.causes[0];
      if (cause !== undefined) draft.causes = [cause, { ...structuredClone(cause), id: 'cause-9999' }];
    });
  });
});

describe('diagnostic-only failed results', () => {
  /** The exact key set a failed result may carry, taken from a real analyzer failure. */
  async function failedShape(): Promise<Record<string, unknown>> {
    const root = await materialize([{ path: 'src/plain.ts', text: ['export const value = 1;'] }]);
    const failure = await analyzeSourceTree(requestFor(root, { include: ['../escape/**/*.ts'] }));
    if (failure.status !== 'failed') throw new Error(`expected a failed result, received ${failure.status}`);
    expect(Object.keys(failure).sort()).toEqual(['causes', 'identity', 'reason', 'status']);
    return {
      status: 'failed',
      identity: failure.identity,
      reason: 'internal-analyzer-error',
      causes: [
        {
          id: 'cause-0001',
          code: 'internal-analyzer-error',
          scope: 'repository',
          path: null,
          span: null,
          resource: null,
          detail: 'the analyzer encountered an unexpected internal state and produced no trusted evidence',
        },
      ],
    };
  }

  it('validates an internal-analyzer-error result that carries only its diagnostic cause', async () => {
    const diagnostic = await failedShape();

    expect(() => {
      validateAnalysisResult(diagnostic);
    }).not.toThrow();

    expect(() => {
      validateAnalysisResult({ ...diagnostic, causes: [] });
    }).toThrow(TypeError);
  });

  it('rejects any semantic evidence attached to a failed result', async () => {
    const diagnostic = await failedShape();
    const evidence = expectEvidence(
      await analyzeFixtureCase('exactly one anchored candidate proves exactly one operation'),
    );

    const additions: Record<string, unknown>[] = [
      { sources: [] },
      { sources: evidence.sources },
      { candidates: [] },
      { candidates: evidence.candidates },
      { observations: evidence.observations },
      { permissionResolutions: evidence.permissionResolutions },
      { permissionBoundary: evidence.permissionBoundary },
      { boundary: evidence.boundary },
    ];

    for (const addition of additions) {
      expect(() => {
        validateAnalysisResult({ ...diagnostic, ...addition });
      }, Object.keys(addition).join(',')).toThrow(TypeError);
    }
  });
});
