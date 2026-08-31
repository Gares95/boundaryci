/**
 * Revision analysis identity and conservative base/head comparison.
 *
 * `RevisionAnalysis` binds one already-validated {@link AnalysisResult} to the finite identity
 * it was produced under. `compareRevisionAnalyses` proves that identity is compatible between
 * base and head before it ever composes {@link comparePermissionBoundaries}: an identity
 * mismatch or a diagnostic-only `failed` analysis becomes an explicit non-success outcome
 * rather than a manufactured diff (D-06, D-07, D-08, D-09).
 */

import type { AnalysisResult, AnalyzerIdentity } from '../analyzer/contract.js';
import { validateAnalysisResult } from '../analyzer/contract.js';
import { BOUNDARYCI_PERMISSION_CATALOG_IDENTITY } from '../permission-model/bounded-catalog.js';
import type { BoundaryComparison } from '../permission-model/model.js';
import { comparePermissionBoundaries } from '../permission-model/model.js';

/** Identity of this revision-comparison engine, embedded in every wrapper. */
export const REVISION_ENGINE_ID = 'boundaryci/revision-engine@1';

/** The finite identity a revision analysis was produced under. */
export interface RevisionIdentity {
  engineId: string;
  analyzer: AnalyzerIdentity;
  catalogAuthorizedScopeSha256: string;
  effectiveConfigSha256: string;
}

/** One immutable, already-validated analysis bound to the identity that produced it. */
export interface RevisionAnalysis {
  identity: RevisionIdentity;
  result: AnalysisResult;
}

const SHA256 = /^[a-f0-9]{64}$/u;

function assertSha256(value: unknown, label: string): asserts value is string {
  if (typeof value !== 'string' || !SHA256.test(value)) throw new TypeError(`${label} must be a lowercase SHA-256`);
}

function assertPlainObject(value: unknown, label: string): asserts value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object`);
  }
}

function assertExactKeys(value: Record<string, unknown>, keys: readonly string[], label: string): void {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new TypeError(`${label} has unknown or missing keys: ${actual.join(',')}`);
  }
}

function assertNonEmptyString(value: unknown, label: string): asserts value is string {
  if (typeof value !== 'string' || value.length === 0) throw new TypeError(`${label} must be a non-empty string`);
}

type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

function canonicalJson(value: JsonValue): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((entry) => canonicalJson(entry)).join(',')}]`;
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key] as JsonValue)}`)
    .join(',')}}`;
}

/**
 * Exact-validates the public {@link RevisionAnalysis} wrapper: its own shape, its identity's
 * shape, the embedded {@link AnalysisResult} (via the authoritative analyzer validator), and
 * that the wrapper's `analyzer` identity is not silently contradicting the embedded result's
 * own identity (T-04-ID-01).
 */
function assertRevisionAnalysis(value: unknown, label: string): asserts value is RevisionAnalysis {
  assertPlainObject(value, label);
  assertExactKeys(value, ['identity', 'result'], label);
  assertPlainObject(value.identity, `${label}.identity`);
  assertExactKeys(
    value.identity,
    ['analyzer', 'catalogAuthorizedScopeSha256', 'effectiveConfigSha256', 'engineId'],
    `${label}.identity`,
  );
  assertNonEmptyString(value.identity.engineId, `${label}.identity.engineId`);
  assertSha256(value.identity.catalogAuthorizedScopeSha256, `${label}.identity.catalogAuthorizedScopeSha256`);
  assertSha256(value.identity.effectiveConfigSha256, `${label}.identity.effectiveConfigSha256`);
  validateAnalysisResult(value.result);
  if (
    canonicalJson(value.identity.analyzer as unknown as JsonValue) !==
    canonicalJson((value.result as AnalysisResult).identity as unknown as JsonValue)
  ) {
    throw new TypeError(`${label}.identity.analyzer must match ${label}.result.identity`);
  }
}

/**
 * Wraps one trusted {@link AnalysisResult} with the identity that produced it.
 *
 * The result is exact-validated and everything returned is an independent deep clone, so the
 * caller's `result` and this wrapper never alias each other's evidence.
 */
export function createRevisionAnalysis(result: AnalysisResult, effectiveConfigSha256: string): RevisionAnalysis {
  validateAnalysisResult(result);
  assertSha256(effectiveConfigSha256, 'effective configuration identity');
  return structuredClone({
    identity: {
      engineId: REVISION_ENGINE_ID,
      analyzer: result.identity,
      catalogAuthorizedScopeSha256: BOUNDARYCI_PERMISSION_CATALOG_IDENTITY.authorizedScopeSha256,
      effectiveConfigSha256,
    },
    result,
  });
}

interface RevisionComparisonEnvelope {
  base: RevisionAnalysis;
  head: RevisionAnalysis;
}

/**
 * The shared local outcome model: complete, incomplete-analysis, input/configuration failure,
 * and runtime/infrastructure failure (D-09). Policy failure is layered on top by the runtime,
 * not represented here.
 */
export type RevisionComparison =
  | (RevisionComparisonEnvelope & { status: 'complete'; boundary: Extract<BoundaryComparison, { status: 'complete' }> })
  | (RevisionComparisonEnvelope & { status: 'incomplete'; boundary: BoundaryComparison; reasons: string[] })
  | (RevisionComparisonEnvelope & { status: 'input-configuration-failure'; reasons: string[] })
  | (RevisionComparisonEnvelope & { status: 'runtime-infrastructure-failure'; reasons: string[] });

function identityMismatches(base: RevisionIdentity, head: RevisionIdentity): string[] {
  const reasons: string[] = [];
  if (base.engineId !== head.engineId) reasons.push('engine-identity-mismatch');
  if (canonicalJson(base.analyzer as unknown as JsonValue) !== canonicalJson(head.analyzer as unknown as JsonValue)) {
    reasons.push('analyzer-identity-mismatch');
  }
  if (base.catalogAuthorizedScopeSha256 !== head.catalogAuthorizedScopeSha256) reasons.push('catalog-identity-mismatch');
  if (base.effectiveConfigSha256 !== head.effectiveConfigSha256) reasons.push('effective-configuration-identity-mismatch');
  return reasons;
}

function isRuntimeFailure(result: AnalysisResult): boolean {
  return result.status === 'failed' && result.reason === 'internal-analyzer-error';
}

/**
 * Proves base/head identity compatibility, then composes {@link comparePermissionBoundaries}.
 *
 * Neither input is mutated: both are exact-validated and cloned before anything else runs.
 * An identity mismatch or a diagnostic-only `failed` analysis short-circuits into an explicit
 * non-success status. Otherwise the two permission boundaries are compared, and any residual
 * analysis-level incompleteness on either side forces an `incomplete` revision outcome even
 * when the resolved permission boundaries alone would already compare clean (D-07).
 */
export function compareRevisionAnalyses(base: RevisionAnalysis, head: RevisionAnalysis): RevisionComparison {
  assertRevisionAnalysis(base, 'base revision analysis');
  assertRevisionAnalysis(head, 'head revision analysis');
  const clonedBase = structuredClone(base);
  const clonedHead = structuredClone(head);

  const mismatches = identityMismatches(clonedBase.identity, clonedHead.identity);
  if (mismatches.length > 0) {
    return { status: 'input-configuration-failure', base: clonedBase, head: clonedHead, reasons: mismatches };
  }

  if (clonedBase.result.status === 'failed' || clonedHead.result.status === 'failed') {
    const runtimeFailure = isRuntimeFailure(clonedBase.result) || isRuntimeFailure(clonedHead.result);
    const reasons = [clonedBase.result, clonedHead.result]
      .filter((result): result is Extract<AnalysisResult, { status: 'failed' }> => result.status === 'failed')
      .map((result) => result.reason);
    return {
      status: runtimeFailure ? 'runtime-infrastructure-failure' : 'input-configuration-failure',
      base: clonedBase,
      head: clonedHead,
      reasons,
    };
  }

  const boundary = comparePermissionBoundaries(clonedBase.result.permissionBoundary, clonedHead.result.permissionBoundary);

  if (boundary.status === 'incomplete') {
    const reasons = new Set<string>(boundary.reasons);
    if (clonedBase.result.status === 'incomplete') reasons.add('incomplete-base-analysis');
    if (clonedHead.result.status === 'incomplete') reasons.add('incomplete-head-analysis');
    return { status: 'incomplete', base: clonedBase, head: clonedHead, boundary, reasons: [...reasons].sort() };
  }

  // The resolved permission boundaries alone compare clean, but residual analysis-level
  // incompleteness on either side (an unrelated unsupported candidate, for example) still means
  // an unseen call could exist, so this can never surface as an unqualified complete result (D-07).
  if (clonedBase.result.status === 'incomplete' || clonedHead.result.status === 'incomplete') {
    const reasons = new Set<string>();
    if (clonedBase.result.status === 'incomplete') reasons.add('incomplete-base-analysis');
    if (clonedHead.result.status === 'incomplete') reasons.add('incomplete-head-analysis');
    return { status: 'incomplete', base: clonedBase, head: clonedHead, boundary, reasons: [...reasons].sort() };
  }

  return { status: 'complete', base: clonedBase, head: clonedHead, boundary };
}
