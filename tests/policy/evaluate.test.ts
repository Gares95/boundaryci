import { describe, expect, it } from 'vitest';

import type { AnalysisFailureReason, AnalyzerCauseCode } from '../../src/analyzer/contract.js';
import { compareRevisionAnalyses } from '../../src/diff/revision.js';
import type { RevisionAnalysis, RevisionComparison } from '../../src/diff/revision.js';
import { evaluatePolicy } from '../../src/policy/evaluate.js';

import {
  CATALOG_GAP_CALL,
  CATALOG_GAP_CAUSE,
  READ_CALL,
  WRITE_CALL,
  patchRevision,
  revision,
} from '../diff/fixtures/scenarios.js';

const ALLOW_ALL = { failOnExpansion: false, failOnIncomplete: false } as const;
const FAIL_EXPANSION = { failOnExpansion: true, failOnIncomplete: false } as const;
const FAIL_INCOMPLETE = { failOnExpansion: false, failOnIncomplete: true } as const;
const FAIL_BOTH = { failOnExpansion: true, failOnIncomplete: true } as const;

function comparison(base: RevisionAnalysis, head: RevisionAnalysis): RevisionComparison {
  return compareRevisionAnalyses(base, head);
}

function runtimeFailureRevision(): RevisionAnalysis {
  return patchRevision(revision({}), (draft) => {
    const code: AnalyzerCauseCode = 'internal-analyzer-error';
    const reason: AnalysisFailureReason = 'internal-analyzer-error';
    draft.result = {
      status: 'failed',
      identity: structuredClone(draft.identity.analyzer),
      reason,
      causes: [
        {
          id: 'cause-0001',
          code,
          scope: 'repository',
          path: null,
          span: null,
          resource: null,
          detail: 'the analyzer encountered an unexpected internal state and produced no trusted evidence',
        },
      ],
    };
  });
}

describe('expansion policy', () => {
  it('passes or fails the same complete expansion without changing comparison evidence', () => {
    const input = comparison(revision({ calls: [READ_CALL] }), revision({ calls: [WRITE_CALL] }));
    expect(input.status).toBe('complete');
    const before = JSON.stringify(input);

    const allowed = evaluatePolicy(input, ALLOW_ALL);
    const denied = evaluatePolicy(input, FAIL_EXPANSION);

    expect(allowed).toMatchObject({ outcome: 'complete', check: 'pass', reasons: [] });
    expect(denied).toMatchObject({
      outcome: 'policy-failure',
      check: 'fail',
      reasons: ['expansion-not-permitted'],
    });
    expect(JSON.stringify(allowed.comparison)).toBe(before);
    expect(JSON.stringify(denied.comparison)).toBe(before);
    expect(JSON.stringify(input)).toBe(before);
  });

  it.each([
    {
      name: 'reduction',
      input: comparison(revision({ calls: [WRITE_CALL] }), revision({ calls: [READ_CALL] })),
    },
    {
      name: 'unchanged',
      input: comparison(revision({ calls: [READ_CALL] }), revision({ calls: [READ_CALL] })),
    },
  ])('passes a complete $name regardless of failOnExpansion', ({ input }) => {
    expect(evaluatePolicy(input, ALLOW_ALL)).toMatchObject({ outcome: 'complete', check: 'pass', reasons: [] });
    expect(evaluatePolicy(input, FAIL_EXPANSION)).toMatchObject({ outcome: 'complete', check: 'pass', reasons: [] });
  });
});

describe('incomplete and independent flag policy', () => {
  const incomplete = comparison(
    revision({ calls: [READ_CALL] }),
    revision({ calls: [WRITE_CALL, CATALOG_GAP_CALL], causes: [CATALOG_GAP_CAUSE] }),
  );

  it('keeps tolerated incomplete analysis visibly incomplete while passing', () => {
    const decision = evaluatePolicy(incomplete, ALLOW_ALL);
    expect(decision).toMatchObject({ outcome: 'incomplete', check: 'pass', reasons: [] });
    expect(decision.comparison.status).toBe('incomplete');
  });

  it('enforces incomplete analysis without recategorizing it as input or runtime failure', () => {
    const decision = evaluatePolicy(incomplete, FAIL_INCOMPLETE);
    expect(decision).toMatchObject({
      outcome: 'policy-failure',
      check: 'fail',
      reasons: ['incomplete-analysis-not-permitted'],
      comparison: { status: 'incomplete' },
    });
  });

  it.each([
    {
      name: 'neither flag',
      policy: ALLOW_ALL,
      outcome: 'incomplete',
      check: 'pass',
      reasons: [],
    },
    {
      name: 'expansion only',
      policy: FAIL_EXPANSION,
      outcome: 'policy-failure',
      check: 'fail',
      reasons: ['expansion-not-permitted'],
    },
    {
      name: 'incomplete only',
      policy: FAIL_INCOMPLETE,
      outcome: 'policy-failure',
      check: 'fail',
      reasons: ['incomplete-analysis-not-permitted'],
    },
    {
      name: 'both flags',
      policy: FAIL_BOTH,
      outcome: 'policy-failure',
      check: 'fail',
      reasons: ['expansion-not-permitted', 'incomplete-analysis-not-permitted'],
    },
  ])('applies $name independently and deterministically', ({ policy, outcome, check, reasons }) => {
    const decision = evaluatePolicy(incomplete, policy);
    expect(decision.outcome).toBe(outcome);
    expect(decision.check).toBe(check);
    expect(decision.reasons).toEqual(reasons);
  });
});

describe('non-policy outcomes', () => {
  it('passes an input/configuration failure through without policy evaluation', () => {
    const base = revision({});
    const incompatibleHead = patchRevision(revision({ calls: [WRITE_CALL] }), (draft) => {
      draft.identity.effectiveConfigSha256 = 'f'.repeat(64);
    });
    const input = comparison(base, incompatibleHead);
    expect(input.status).toBe('input-configuration-failure');

    const decision = evaluatePolicy(input, FAIL_BOTH);
    expect(decision).toMatchObject({
      outcome: 'input-configuration-failure',
      check: 'not-evaluated',
      reasons: [],
      comparison: { status: 'input-configuration-failure' },
    });
  });

  it('passes a runtime/infrastructure failure through without policy evaluation', () => {
    const input = comparison(revision({}), runtimeFailureRevision());
    expect(input.status).toBe('runtime-infrastructure-failure');

    const decision = evaluatePolicy(input, FAIL_BOTH);
    expect(decision).toMatchObject({
      outcome: 'runtime-infrastructure-failure',
      check: 'not-evaluated',
      reasons: [],
      comparison: { status: 'runtime-infrastructure-failure' },
    });
  });
});

describe('exact input, immutability, and determinism', () => {
  it.each([
    null,
    {},
    { failOnExpansion: true },
    { failOnExpansion: true, failOnIncomplete: true, unexpected: true },
    { failOnExpansion: 'yes', failOnIncomplete: true },
    { failOnExpansion: true, failOnIncomplete: 1 },
  ])('rejects malformed policy input %#', (policy) => {
    const input = comparison(revision({}), revision({ calls: [READ_CALL] }));
    expect(() => evaluatePolicy(input, policy as never)).toThrow(TypeError);
  });

  it('returns independent deterministic clones without mutating comparison or policy', () => {
    const input = comparison(revision({}), revision({ calls: [WRITE_CALL] }));
    const policy = { failOnExpansion: true, failOnIncomplete: false };
    const comparisonBefore = JSON.stringify(input);
    const policyBefore = JSON.stringify(policy);

    const first = evaluatePolicy(input, policy);
    const second = evaluatePolicy(input, policy);

    expect(JSON.stringify(second)).toBe(JSON.stringify(first));
    expect(JSON.stringify(input)).toBe(comparisonBefore);
    expect(JSON.stringify(policy)).toBe(policyBefore);
    expect(first.comparison).not.toBe(input);
    expect(first.policy).not.toBe(policy);
  });
});
