/**
 * Pure repository-policy evaluation over an already-produced {@link RevisionComparison}.
 *
 * `evaluatePolicy` only reads the facts `compareRevisionAnalyses` already proved: it never calls
 * the analyzer, the permission catalog, `aggregatePermissionFindings`, or
 * `comparePermissionBoundaries`, and it never mutates, drops, or reclassifies any evidence on the
 * comparison it retains. `failOnExpansion` and `failOnIncomplete` are applied independently, so
 * either, both, or neither reason can apply to one decision (D-09, D-16).
 */

import type { RevisionComparison } from '../diff/revision.js';

/** The exact policy configuration `evaluatePolicy` accepts; never the whole effective config. */
export interface PolicyInput {
  failOnExpansion: boolean;
  failOnIncomplete: boolean;
}

/** One deterministic reason a comparison failed policy. */
export type PolicyReason = 'expansion-not-permitted' | 'incomplete-analysis-not-permitted';

interface PolicyDecisionEnvelope {
  policy: PolicyInput;
}

/**
 * The policy outcome for one comparison.
 *
 * `outcome` is the CLI-facing result: `complete`/`incomplete` mean the check passed and the
 * comparison keeps its own analysis status, `policy-failure` means at least one enabled flag
 * matched, and the two failure outcomes are the comparison's own non-success status passed
 * through untouched. `check` is the same decision restated as pass/fail/not-evaluated so a
 * caller never has to test `outcome` against more than one string to find that out. Tolerated
 * incompleteness therefore reports `outcome: 'incomplete'`, `check: 'pass'` — still visibly
 * incomplete, not silently promoted to `complete`.
 */
export type PolicyDecision =
  | (PolicyDecisionEnvelope & {
      outcome: 'complete';
      check: 'pass';
      reasons: PolicyReason[];
      comparison: Extract<RevisionComparison, { status: 'complete' }>;
    })
  | (PolicyDecisionEnvelope & {
      outcome: 'incomplete';
      check: 'pass';
      reasons: PolicyReason[];
      comparison: Extract<RevisionComparison, { status: 'incomplete' }>;
    })
  | (PolicyDecisionEnvelope & {
      outcome: 'policy-failure';
      check: 'fail';
      reasons: PolicyReason[];
      comparison: Extract<RevisionComparison, { status: 'complete' | 'incomplete' }>;
    })
  | (PolicyDecisionEnvelope & {
      outcome: 'input-configuration-failure';
      check: 'not-evaluated';
      reasons: PolicyReason[];
      comparison: Extract<RevisionComparison, { status: 'input-configuration-failure' }>;
    })
  | (PolicyDecisionEnvelope & {
      outcome: 'runtime-infrastructure-failure';
      check: 'not-evaluated';
      reasons: PolicyReason[];
      comparison: Extract<RevisionComparison, { status: 'runtime-infrastructure-failure' }>;
    });

function assertPolicyInput(value: unknown): asserts value is PolicyInput {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new TypeError('policy input must be an object');
  }
  const actual = Object.keys(value).sort();
  const expected = ['failOnExpansion', 'failOnIncomplete'];
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new TypeError(`policy input has unknown or missing keys: ${actual.join(',')}`);
  }
  const record = value as Record<string, unknown>;
  if (typeof record.failOnExpansion !== 'boolean') {
    throw new TypeError('policy input.failOnExpansion must be a boolean');
  }
  if (typeof record.failOnIncomplete !== 'boolean') {
    throw new TypeError('policy input.failOnIncomplete must be a boolean');
  }
}

/**
 * Whether an expansion is already proven enforceable for this comparison.
 *
 * A complete comparison's `changes` are exact; an incomplete comparison only ever offers
 * `qualifiedChanges` as safe known changes (D-07). Neither array is recomputed here — only
 * filtered by the `change` field the comparison already assigned.
 */
function hasEnforceableExpansion(comparison: Extract<RevisionComparison, { status: 'complete' | 'incomplete' }>): boolean {
  return comparison.status === 'complete'
    ? comparison.changes.some((change) => change.change === 'expansion')
    : comparison.qualifiedChanges.some((change) => change.change === 'expansion');
}

/**
 * Evaluates `failOnExpansion` and `failOnIncomplete` independently over `comparison`.
 *
 * Both inputs are exact-validated and every returned decision carries an independent deep clone
 * of `comparison`, so neither the caller's comparison nor the policy input can be mutated by, or
 * mutate, the returned decision. Input/configuration and runtime/infrastructure comparisons are
 * returned as their own outcome with `check: 'not-evaluated'`, never judged by either flag.
 */
export function evaluatePolicy(comparison: RevisionComparison, policy: PolicyInput): PolicyDecision {
  assertPolicyInput(policy);
  const clonedComparison = structuredClone(comparison);
  const clonedPolicy = structuredClone(policy);

  if (clonedComparison.status === 'input-configuration-failure') {
    return {
      outcome: 'input-configuration-failure',
      check: 'not-evaluated',
      reasons: [],
      policy: clonedPolicy,
      comparison: clonedComparison,
    };
  }
  if (clonedComparison.status === 'runtime-infrastructure-failure') {
    return {
      outcome: 'runtime-infrastructure-failure',
      check: 'not-evaluated',
      reasons: [],
      policy: clonedPolicy,
      comparison: clonedComparison,
    };
  }

  const reasons: PolicyReason[] = [];
  if (clonedPolicy.failOnExpansion && hasEnforceableExpansion(clonedComparison)) {
    reasons.push('expansion-not-permitted');
  }
  if (clonedPolicy.failOnIncomplete && clonedComparison.status === 'incomplete') {
    reasons.push('incomplete-analysis-not-permitted');
  }
  reasons.sort();

  if (reasons.length > 0) {
    return { outcome: 'policy-failure', check: 'fail', reasons, policy: clonedPolicy, comparison: clonedComparison };
  }

  if (clonedComparison.status === 'complete') {
    return { outcome: 'complete', check: 'pass', reasons: [], policy: clonedPolicy, comparison: clonedComparison };
  }
  return { outcome: 'incomplete', check: 'pass', reasons: [], policy: clonedPolicy, comparison: clonedComparison };
}
