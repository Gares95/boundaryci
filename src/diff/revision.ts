/**
 * Revision analysis identity and conservative base/head comparison.
 *
 * `RevisionAnalysis` binds one already-validated {@link AnalysisResult} to the finite identity
 * it was produced under. `compareRevisionAnalyses` proves that identity is compatible between
 * base and head before it ever composes {@link comparePermissionBoundaries}: an identity
 * mismatch or a diagnostic-only `failed` analysis becomes an explicit non-success outcome
 * rather than a manufactured diff (D-06, D-07, D-08, D-09).
 *
 * Beyond that gate this module only *attaches* evidence to what Phase 2 already decided. Every
 * permission level, join, and change classification comes from `aggregatePermissionFindings`
 * and `comparePermissionBoundaries`; nothing here ranks permissions, flattens an `allOf`,
 * selects an `anyOf` branch, reinterprets a complex expression, or invents a catalog fact
 * (D-01, D-03). An incomplete side therefore never receives an unqualified `changes` array:
 * it receives the retained evidence, a cause-level uncertainty delta, and at most the
 * qualified known changes that a complete boundary on the other side independently proves
 * (D-07).
 */

import type { AnalysisResult, AnalyzerCause, AnalyzerIdentity, AnalyzerProfileIdentity } from '../analyzer/contract.js';
import {
  ANALYSIS_DISCOVERY_PROFILE_ID,
  ANALYSIS_LIMIT_PROFILE_ID,
  ANALYSIS_SCHEMA_ID,
  ANALYSIS_SCHEMA_VERSION,
  ANALYSIS_SPAN_CONVENTION_ID,
  validateAnalysisResult,
} from '../analyzer/contract.js';
import { BOUNDARYCI_PERMISSION_CATALOG_IDENTITY } from '../permission-model/bounded-catalog.js';
import type {
  BoundaryComparison,
  PermissionBoundary,
  PermissionChange,
  RequirementFinding,
} from '../permission-model/model.js';
import { aggregatePermissionFindings, comparePermissionBoundaries } from '../permission-model/model.js';

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

function assertNonNegativeSafeInteger(value: unknown, label: string): asserts value is number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new TypeError(`${label} must be a non-negative safe integer`);
  }
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
 * Validates one analyzer identity as a comparable finite identity, without claiming it is the
 * identity implemented by this engine version.
 *
 * The complete analyzer-profile shape is validated below by `validateAnalysisResult` after the
 * five fixed current-engine identity fields are normalized. Keeping the original values here is
 * what lets Phase 4 report schema/span/discovery/limit drift as incompatible input rather than
 * throwing before the identity gate can run.
 */
function assertComparableAnalyzerIdentity(value: unknown, label: string): asserts value is AnalyzerIdentity {
  assertPlainObject(value, label);
  assertExactKeys(
    value,
    [
      'analyzerProfile',
      'discoveryProfileId',
      'limitProfileId',
      'permissionCatalogScopeSha256',
      'schemaId',
      'schemaVersion',
      'spanConventionId',
    ],
    label,
  );
  assertNonEmptyString(value.schemaId, `${label}.schemaId`);
  assertNonNegativeSafeInteger(value.schemaVersion, `${label}.schemaVersion`);
  assertNonEmptyString(value.spanConventionId, `${label}.spanConventionId`);
  assertNonEmptyString(value.discoveryProfileId, `${label}.discoveryProfileId`);
  assertNonEmptyString(value.limitProfileId, `${label}.limitProfileId`);
  assertSha256(value.permissionCatalogScopeSha256, `${label}.permissionCatalogScopeSha256`);
}

/**
 * Exact-validates the current serialized result shape while retaining a different declared
 * compatibility identity for Phase 4's identity gate.
 *
 * An identity mismatch means the semantic result must not be compared, but its envelope still
 * has to be structurally safe to retain in an explicit non-success result. Normalizing only the
 * fixed identity constants on an isolated clone lets the authoritative Phase 3 validator prove
 * that current shape. Analyzer-profile fields and catalog digests are not normalized, so their
 * own syntax and every evidence relationship are still checked exactly.
 */
function assertComparableAnalysisResult(value: unknown, label: string): asserts value is AnalysisResult {
  assertPlainObject(value, label);
  assertComparableAnalyzerIdentity(value.identity, `${label}.identity`);
  const normalized = structuredClone(value);
  assertPlainObject(normalized.identity, `${label}.identity`);
  normalized.identity = {
    ...normalized.identity,
    schemaId: ANALYSIS_SCHEMA_ID,
    schemaVersion: ANALYSIS_SCHEMA_VERSION,
    spanConventionId: ANALYSIS_SPAN_CONVENTION_ID,
    discoveryProfileId: ANALYSIS_DISCOVERY_PROFILE_ID,
    limitProfileId: ANALYSIS_LIMIT_PROFILE_ID,
  };
  validateAnalysisResult(normalized);
}

function jsonBytes(value: unknown): string {
  return canonicalJson(value as JsonValue);
}

function compareBytes(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

/** Orders any already-validated record collection by canonical bytes, never by arrival order. */
function sortByCanonicalBytes<T>(values: readonly T[]): T[] {
  return structuredClone([...values]).sort((left, right) => compareBytes(jsonBytes(left), jsonBytes(right)));
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
  assertComparableAnalysisResult(value.result, `${label}.result`);
  if (
    canonicalJson(value.identity.analyzer as unknown as JsonValue) !==
    canonicalJson((value.result as AnalysisResult).identity as unknown as JsonValue)
  ) {
    throw new TypeError(`${label}.identity.analyzer must match ${label}.result.identity`);
  }
}

/**
 * Exact-validates one public {@link RevisionAnalysis} value.
 *
 * This is the same gate `compareRevisionAnalyses` runs on each side, exported so a caller can
 * reject a malformed wrapper before it ever reaches comparison. A malformed internal shape —
 * an unknown key, a non-digest identity, or an analyzer identity that contradicts its own
 * embedded result — is rejected here rather than being reported as repository drift.
 */
export function validateRevisionAnalysis(value: unknown): asserts value is RevisionAnalysis {
  assertRevisionAnalysis(value, 'revision analysis');
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
 * One Phase 2 permission change plus the findings on each revision that contribute to it.
 *
 * `permission`, `base`, `head`, and `change` are exactly the record
 * {@link comparePermissionBoundaries} produced. The two contributor arrays are the resolved
 * {@link RequirementFinding} values the corresponding boundary already grouped under that
 * permission name, so a change can be explained by operation and source without any finding
 * being synthesized or matched by name. A side with no contributing finding carries an empty
 * array, which is absence of contribution rather than proof of absence.
 */
export interface RevisionPermissionChange extends PermissionChange {
  baseContributors: RequirementFinding[];
  headContributors: RequirementFinding[];
}

/**
 * Why one qualified known change is safe to claim while the comparison stays incomplete.
 *
 * - `complete-boundaries` — both permission boundaries are complete, so both levels are exact
 *   and every direction, including `unchanged`, is proven at the boundary level. The
 *   surrounding analysis is still incomplete, which is why the record stays qualified.
 * - `complete-base-boundary-and-known-head-floor` — the base level is exact and the head level
 *   is only a proven lower bound, so nothing but an expansion can follow from it.
 * - `complete-head-boundary-and-known-base-floor` — the head level is exact and the base level
 *   is only a proven lower bound, so nothing but a reduction can follow from it.
 */
export type QualifiedChangeBasis =
  | 'complete-base-boundary-and-known-head-floor'
  | 'complete-boundaries'
  | 'complete-head-boundary-and-known-base-floor';

/** A known change that survives incompleteness, labelled with the completeness that proves it. */
export interface QualifiedRevisionChange extends RevisionPermissionChange {
  basis: QualifiedChangeBasis;
}

/**
 * How the two revisions differ in what they left unproven.
 *
 * Causes are matched by canonical semantic body, never by ordinal ID, so a renumbered cause is
 * retained rather than reported as one resolved and one introduced. Both original side-specific
 * records, including their own IDs, are preserved.
 */
export interface UncertaintyDelta {
  introduced: AnalyzerCause[];
  resolved: AnalyzerCause[];
  retained: { base: AnalyzerCause; head: AnalyzerCause }[];
}

/**
 * The shared local outcome model: complete, incomplete-analysis, input/configuration failure,
 * and runtime/infrastructure failure (D-09). Policy failure is layered on top by the runtime,
 * not represented here.
 *
 * Only the `complete` outcome carries an unqualified `changes` array. The `incomplete` outcome
 * carries the retained Phase 2 boundary comparison, the cause-level uncertainty delta, and any
 * qualified known changes instead (D-07).
 */
export type RevisionComparison =
  | (RevisionComparisonEnvelope & {
      status: 'complete';
      boundary: Extract<BoundaryComparison, { status: 'complete' }>;
      changes: RevisionPermissionChange[];
    })
  | (RevisionComparisonEnvelope & {
      status: 'incomplete';
      boundary: BoundaryComparison;
      reasons: string[];
      qualifiedChanges: QualifiedRevisionChange[];
      uncertainty: UncertaintyDelta;
    })
  | (RevisionComparisonEnvelope & { status: 'input-configuration-failure'; reasons: string[] })
  | (RevisionComparisonEnvelope & { status: 'runtime-infrastructure-failure'; reasons: string[] });

/** Every analyzer-profile field, with the exact mismatch reason each one reports. */
const ANALYZER_PROFILE_MISMATCH_REASONS: Readonly<Record<keyof AnalyzerProfileIdentity, string>> = {
  artifactManifestSha256: 'analyzer-profile-artifact-manifest-mismatch',
  endpointMemberCount: 'analyzer-profile-endpoint-member-count-mismatch',
  endpointMethodsVersion: 'analyzer-profile-endpoint-methods-version-mismatch',
  inventoryContentSha256: 'analyzer-profile-inventory-content-mismatch',
  octokitVersion: 'analyzer-profile-octokit-version-mismatch',
  operationCount: 'analyzer-profile-operation-count-mismatch',
  profileId: 'analyzer-profile-id-mismatch',
  restApiVersion: 'analyzer-profile-rest-api-version-mismatch',
  schemaVersion: 'analyzer-profile-schema-version-mismatch',
};

const ANALYZER_PROFILE_FIELDS = Object.keys(ANALYZER_PROFILE_MISMATCH_REASONS).sort() as (keyof AnalyzerProfileIdentity)[];

/**
 * Names every compatibility field on which base and head disagree, in a fixed field order.
 *
 * Every group D-08 requires is compared: the engine, the analysis schema id and version, the
 * source-span convention, each analyzer-compatibility-profile field, the discovery and limit
 * profiles, the analyzer's permission-catalog scope, the wrapper's frozen-catalog scope, and
 * the effective configuration identity. The trailing canonical check is a safety net: if the
 * two analyzer identities differ in a way no named field caught, the difference is still
 * reported rather than silently compared as if it were absent.
 */
function identityMismatches(base: RevisionIdentity, head: RevisionIdentity): string[] {
  const reasons: string[] = [];
  if (base.engineId !== head.engineId) reasons.push('engine-identity-mismatch');
  if (base.analyzer.schemaId !== head.analyzer.schemaId) reasons.push('analysis-schema-id-mismatch');
  if (base.analyzer.schemaVersion !== head.analyzer.schemaVersion) reasons.push('analysis-schema-version-mismatch');
  if (base.analyzer.spanConventionId !== head.analyzer.spanConventionId) {
    reasons.push('source-span-convention-mismatch');
  }
  for (const field of ANALYZER_PROFILE_FIELDS) {
    if (base.analyzer.analyzerProfile[field] !== head.analyzer.analyzerProfile[field]) {
      reasons.push(ANALYZER_PROFILE_MISMATCH_REASONS[field]);
    }
  }
  if (base.analyzer.discoveryProfileId !== head.analyzer.discoveryProfileId) reasons.push('discovery-profile-mismatch');
  if (base.analyzer.limitProfileId !== head.analyzer.limitProfileId) reasons.push('limit-profile-mismatch');
  if (base.analyzer.permissionCatalogScopeSha256 !== head.analyzer.permissionCatalogScopeSha256) {
    reasons.push('analyzer-permission-catalog-scope-mismatch');
  }
  if (base.catalogAuthorizedScopeSha256 !== head.catalogAuthorizedScopeSha256) {
    reasons.push('catalog-authorized-scope-mismatch');
  }
  if (base.effectiveConfigSha256 !== head.effectiveConfigSha256) {
    reasons.push('effective-configuration-identity-mismatch');
  }
  if (reasons.length === 0 && jsonBytes(base.analyzer) !== jsonBytes(head.analyzer)) {
    reasons.push('analyzer-identity-mismatch');
  }
  return reasons;
}

type CompletePermissionBoundary = Extract<PermissionBoundary, { status: 'complete' }>;

/** The findings one boundary already grouped under `permission`, in canonical order. */
function contributorsFor(boundary: PermissionBoundary, permission: string): RequirementFinding[] {
  if (boundary.status !== 'complete') return [];
  const entry = boundary.permissions.find((candidate) => candidate.permission === permission);
  return entry === undefined ? [] : sortByCanonicalBytes(entry.contributors);
}

function withContributors(
  change: PermissionChange,
  base: PermissionBoundary,
  head: PermissionBoundary,
): RevisionPermissionChange {
  return {
    permission: change.permission,
    base: change.base,
    head: change.head,
    change: change.change,
    baseContributors: contributorsFor(base, change.permission),
    headContributors: contributorsFor(head, change.permission),
  };
}

/**
 * The simple permissions an incomplete boundary already proves, as a complete lower bound.
 *
 * Only root `permission` findings that Phase 2 already resolved are forwarded, and the join is
 * `aggregatePermissionFindings` itself, so no rank logic is duplicated here. A complex,
 * missing, unsupported, or invalid finding contributes nothing to the floor and stays visible
 * in the retained boundary it came from: the floor is a proven minimum, never a claim about
 * what the revision does not require (D-03, D-07).
 */
function knownSimpleFloor(boundary: PermissionBoundary): CompletePermissionBoundary | null {
  if (boundary.status !== 'incomplete') return null;
  const resolved = boundary.findings.filter(
    (finding) => finding.status === 'resolved' && finding.requirement.type === 'permission',
  );
  const floor = aggregatePermissionFindings(resolved);
  return floor.status === 'complete' ? floor : null;
}

/**
 * The known changes that remain provable while the comparison as a whole is incomplete.
 *
 * Both boundaries complete means every Phase 2 change record is exact and survives, including
 * `unchanged`. Otherwise exactly one direction is derivable: an expansion needs a complete base
 * boundary and a head floor that already proves a higher level, and a reduction needs a complete
 * head boundary and a base floor that already proves a higher level. Comparison records pointing
 * the other way are discarded because a floor is a lower bound, not an exact level. When neither
 * boundary is complete, nothing is claimed (T-04-DIFF-02).
 */
function qualifiedChanges(base: PermissionBoundary, head: PermissionBoundary): QualifiedRevisionChange[] {
  const label = (
    change: PermissionChange,
    left: PermissionBoundary,
    right: PermissionBoundary,
    basis: QualifiedChangeBasis,
  ): QualifiedRevisionChange => ({ ...withContributors(change, left, right), basis });
  if (base.status === 'complete' && head.status === 'complete') {
    const comparison = comparePermissionBoundaries(base, head);
    if (comparison.status !== 'complete') return [];
    return comparison.changes.map((change) => label(change, base, head, 'complete-boundaries'));
  }
  if (base.status === 'complete') {
    const floor = knownSimpleFloor(head);
    if (floor === null) return [];
    const comparison = comparePermissionBoundaries(base, floor);
    if (comparison.status !== 'complete') return [];
    return comparison.changes
      .filter((change) => change.change === 'expansion')
      .map((change) => label(change, base, floor, 'complete-base-boundary-and-known-head-floor'));
  }
  if (head.status === 'complete') {
    const floor = knownSimpleFloor(base);
    if (floor === null) return [];
    const comparison = comparePermissionBoundaries(floor, head);
    if (comparison.status !== 'complete') return [];
    return comparison.changes
      .filter((change) => change.change === 'reduction')
      .map((change) => label(change, floor, head, 'complete-head-boundary-and-known-base-floor'));
  }
  return [];
}

/**
 * Canonical semantic identity of one already-validated cause, excluding only its ordinal ID.
 *
 * This mirrors the analyzer's own cause-body identity: `assertCause` fixes the key set, so the
 * six fields below are the whole record apart from the ID the analyzer assigned in scan order.
 */
function causeBodyKey(cause: AnalyzerCause): string {
  return jsonBytes({
    code: cause.code,
    scope: cause.scope,
    path: cause.path,
    span: cause.span,
    resource: cause.resource,
    detail: cause.detail,
  });
}

/**
 * Compares the two cause sets by body.
 *
 * `validateAnalysisResult` already proved every cause body unique within one result, so one
 * body identifies at most one record per side. Ordering is by canonical body bytes and is
 * therefore independent of the order either analyzer emitted its causes in.
 */
function uncertaintyDelta(base: readonly AnalyzerCause[], head: readonly AnalyzerCause[]): UncertaintyDelta {
  const baseByBody = new Map(base.map((cause) => [causeBodyKey(cause), cause]));
  const headByBody = new Map(head.map((cause) => [causeBodyKey(cause), cause]));
  const byBody = (left: AnalyzerCause, right: AnalyzerCause) => compareBytes(causeBodyKey(left), causeBodyKey(right));
  const retained = [...baseByBody.entries()]
    .flatMap(([body, cause]) => {
      const counterpart = headByBody.get(body);
      return counterpart === undefined ? [] : [{ base: cause, head: counterpart }];
    })
    .sort((left, right) => byBody(left.base, right.base));
  return structuredClone({
    introduced: head.filter((cause) => !baseByBody.has(causeBodyKey(cause))).sort(byBody),
    resolved: base.filter((cause) => !headByBody.has(causeBodyKey(cause))).sort(byBody),
    retained,
  });
}

function isRuntimeFailure(result: AnalysisResult): boolean {
  return result.status === 'failed' && result.reason === 'internal-analyzer-error';
}

/**
 * Proves base/head identity compatibility, then composes {@link comparePermissionBoundaries}.
 *
 * Neither input is mutated: both are exact-validated and cloned before anything else runs, and
 * every record in the result is an independent clone of that evidence. An identity mismatch or
 * a diagnostic-only `failed` analysis short-circuits into an explicit non-success status.
 * Otherwise the two permission boundaries are compared, each resulting change is attached to
 * the findings that contribute to it, and any residual analysis-level incompleteness on either
 * side forces an `incomplete` revision outcome — carrying the retained comparison, the cause
 * uncertainty delta, and only qualified known changes — even when the resolved permission
 * boundaries alone would already compare clean (D-07).
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

  const baseBoundary = clonedBase.result.permissionBoundary;
  const headBoundary = clonedHead.result.permissionBoundary;
  const boundary = comparePermissionBoundaries(baseBoundary, headBoundary);

  const incompleteReasons = new Set<string>();
  if (clonedBase.result.status === 'incomplete') incompleteReasons.add('incomplete-base-analysis');
  if (clonedHead.result.status === 'incomplete') incompleteReasons.add('incomplete-head-analysis');

  // Residual analysis-level incompleteness on either side (an unrelated unsupported candidate,
  // for example) still means an unseen call could exist, so a clean boundary comparison can
  // never surface as an unqualified complete result on its own (D-07).
  if (boundary.status === 'incomplete' || incompleteReasons.size > 0) {
    const reasons =
      boundary.status === 'incomplete' ? new Set([...boundary.reasons, ...incompleteReasons]) : incompleteReasons;
    return {
      status: 'incomplete',
      base: clonedBase,
      head: clonedHead,
      boundary,
      reasons: [...reasons].sort(compareBytes),
      qualifiedChanges: qualifiedChanges(baseBoundary, headBoundary),
      uncertainty: uncertaintyDelta(clonedBase.result.causes, clonedHead.result.causes),
    };
  }

  return {
    status: 'complete',
    base: clonedBase,
    head: clonedHead,
    boundary,
    changes: boundary.changes.map((change) => withContributors(change, baseBoundary, headBoundary)),
  };
}
