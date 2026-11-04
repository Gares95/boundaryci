import { afterEach, describe, expect, it } from 'vitest';

import { analyzeSourceTree } from '../../src/analyzer/analyze.js';
import { DEFAULT_ANALYSIS_LIMITS } from '../../src/analyzer/contract.js';

import adversarial from './fixtures/adversarial-cases.json' with { type: 'json' };
import { cleanupTempRoots, createTempRoot, writeRegularFile } from './helpers.js';

/**
 * Adversarial analyzer tranche (TASK-2). Every case is a minimal synthetic attempt to make the
 * analyzer prove the wrong client, prove the wrong operation, or drop a real client's call:
 * lexical shadowing, reassignment and redeclaration, spreads, `Object.assign`, prototype and
 * getter tricks, look-alike objects later receiving a real client's surface, and near-miss
 * request routes. Each expectation pins the exact fail-closed classification released v1
 * already produced; the suite exists so a later change cannot silently weaken one of them.
 *
 * The global invariant checked for every case is stronger than its pinned bytes: no candidate
 * in this corpus may ever be classified `proven-irrelevant`, because each one is reachable by
 * a real authorized client or is a look-alike whose irrelevance the bounded grammar cannot
 * prove.
 */

interface AdversarialCase {
  group: string;
  name: string;
  files: Record<string, string>;
  expect: { status: string; candidates: string[]; operations: string[] };
}

const cases = (adversarial as { cases: AdversarialCase[] }).cases;

afterEach(async () => {
  await cleanupTempRoots();
});

describe('adversarial analyzer corpus', () => {
  it('covers every attack group with a meaningful number of cases', () => {
    const groups = new Map<string, number>();
    for (const testCase of cases) groups.set(testCase.group, (groups.get(testCase.group) ?? 0) + 1);
    expect([...groups.keys()].sort()).toEqual(['look-alike-mutation', 'request-route-grammar', 'shadowing-and-reassignment']);
    for (const count of groups.values()) expect(count).toBeGreaterThanOrEqual(10);
    expect(new Set(cases.map((testCase) => testCase.name)).size).toBe(cases.length);
  });

  it.each(cases)('$group: $name keeps its fail-closed classification', async ({ files, expect: expected }) => {
    const root = await createTempRoot('boundaryci-adversarial-');
    for (const [path, contents] of Object.entries(files)) await writeRegularFile(root, path, contents);
    const result = await analyzeSourceTree({
      rootPath: root,
      include: ['**/*.ts', '**/*.js', '**/*.mjs'],
      exclude: [],
      probotEntrypoints: [],
      limits: { ...DEFAULT_ANALYSIS_LIMITS },
    });
    if (result.status === 'failed') throw new Error('adversarial case must not fail analysis');
    const candidates = result.candidates.map((candidate) => `${candidate.kind}:${candidate.classification}:${candidate.reason}`);
    expect({
      status: result.status,
      candidates,
      operations: result.observations.map((observation) => observation.operation.operationId),
    }).toEqual(expected);
    expect(result.candidates.some((candidate) => candidate.classification === 'proven-irrelevant')).toBe(false);
    // `complete` is only acceptable when every candidate is a proven operation.
    if (result.status === 'complete') {
      expect(result.candidates.every((candidate) => candidate.classification === 'proven-operation')).toBe(true);
    }
  });
});
