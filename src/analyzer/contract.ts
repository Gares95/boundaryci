/**
 * Versioned request and result contracts for the BoundaryCI static analyzer.
 *
 * Every value defined here is JSON data. Nothing in this module reads a file, opens a
 * socket, or retains a parser, filesystem, framework, or `Error` object. The result is the
 * only thing the analyzer publishes, so it carries the identities needed to reproduce the
 * declared analysis boundary and the accounting needed to explain what was *not* proven.
 *
 * Three outcomes exist and they are structurally distinct:
 *
 * - `complete`   every obligation raised under the declared boundary was resolved;
 * - `incomplete` analysis ran safely, proven evidence is trustworthy, and at least one
 *                target-program question is unresolved;
 * - `failed`     the trusted request, discovery boundary, or analyzer state cannot support
 *                trustworthy semantic output. A failed result is diagnostic-only: it has no
 *                sources, candidates, observations, permission findings, or aggregate
 *                boundary, because none of those could be trusted.
 *
 * Completeness is relative to this contract, never to the whole program. A `complete`
 * result does not prove the absence of GitHub calls made through raw HTTP, GraphQL,
 * arbitrary wrappers, dynamic behaviour, runtime loaders, or interprocedural flows that
 * this analyzer deliberately does not interpret.
 */

import type {
  PermissionBoundary,
  RequirementFinding,
  RestOperationIdentity,
  SourceEvidence,
  SourceSpan,
} from '../permission-model/model.js';
import { validateRequirementExpression, validateSourceEvidence } from '../permission-model/model.js';

/** Identity of the result schema itself. */
export const ANALYSIS_SCHEMA_ID = 'boundaryci/analysis-result';

/** Version of the result schema. Any incompatible shape change increments this. */
export const ANALYSIS_SCHEMA_VERSION = 1;

/**
 * Identity of the source-span convention.
 *
 * Version 1 means: source bytes are decoded as UTF-8; a single leading U+FEFF byte-order
 * mark is removed before any offset is computed; `LF`, `CRLF`, and lone `CR` each terminate
 * one line; line and column are 1-based; a column counts UTF-16 code units within its
 * decoded line; `start` is inclusive and `end` is exclusive. `SourceRecord.contentSha256`
 * and `SourceRecord.byteSize` describe the raw file bytes including any byte-order mark.
 */
export const ANALYSIS_SPAN_CONVENTION_ID = 'boundaryci/source-span@1';

/**
 * Identity of the discovery and glob policy.
 *
 * Version 1 means: one canonicalized analysis root; case-sensitive, root-relative POSIX
 * paths; the effective set is `any(include) − any(exclude)` intersected with
 * {@link ANALYZER_SOURCE_EXTENSIONS}; patterns are declarative and unordered; `**` matches
 * zero or more whole path segments, `*` matches zero or more non-separator characters, `?`
 * matches exactly one non-separator character, and nothing else is interpreted; regular
 * files only; symbolic links are never followed and never read.
 */
export const ANALYSIS_DISCOVERY_PROFILE_ID = 'boundaryci/bounded-local-discovery@1';

/** Identity of the effective resource-limit profile shape. */
export const ANALYSIS_LIMIT_PROFILE_ID = 'boundaryci/analysis-limits@1';

/**
 * The executable source extensions that participate in analysis.
 *
 * Declaration files and target dependency trees never establish executable provenance and
 * are excluded by {@link ANALYSIS_DISCOVERY_PROFILE_ID}, not by this list.
 */
export const ANALYZER_SOURCE_EXTENSIONS: readonly string[] = Object.freeze([
  '.js',
  '.jsx',
  '.mjs',
  '.mts',
  '.ts',
  '.tsx',
]);

/**
 * Deterministic scan-wide bounds. Zero is a meaningful value and is not repaired.
 *
 * `maxSourceFiles` and `maxTotalSourceBytes` are scan-wide frontiers charged in bytewise
 * sorted source order. `maxSourceFileBytes` is a file-scoped budget: a file that exceeds it
 * is individually omitted and independent sorted files continue. `maxSourceWork` bounds
 * discovery itself — one work unit is one filesystem entry inspected during deterministic
 * no-follow traversal, charged before any file-count or byte budget.
 */
export interface AnalysisLimits {
  maxSourceFiles: number;
  maxSourceFileBytes: number;
  maxTotalSourceBytes: number;
  maxSourceWork: number;
}

/** Conservative defaults for callers that do not carry their own limit profile. */
export const DEFAULT_ANALYSIS_LIMITS: Readonly<AnalysisLimits> = Object.freeze({
  maxSourceFiles: 5000,
  maxSourceFileBytes: 2_000_000,
  maxTotalSourceBytes: 64_000_000,
  maxSourceWork: 50_000,
});

/**
 * Trusted analyzer input.
 *
 * `rootPath` is a host path supplied by the caller and never appears in a result.
 * `include`, `exclude`, and `probotEntrypoints` are case-sensitive root-relative POSIX
 * values. Contradictory trusted input is rejected rather than reinterpreted.
 */
export interface AnalysisRequest {
  rootPath: string;
  include: string[];
  exclude: string[];
  probotEntrypoints: string[];
  limits: AnalysisLimits;
}

export type AnalysisFailureReason =
  | 'analysis-root-not-a-directory'
  | 'invalid-analysis-request'
  | 'invalid-analysis-result'
  | 'probot-entrypoint-outside-source-universe'
  | 'unresolvable-analysis-root';

export type AnalyzerCauseCode =
  | 'invalid-analysis-request'
  | 'invalid-analysis-result'
  | 'matching-non-regular-entry'
  | 'matching-source-symlink'
  | 'permission-catalog-incomplete'
  | 'probot-entrypoint-unsupported'
  | 'relevant-directory-symlink'
  | 'source-byte-limit'
  | 'source-decode-failed'
  | 'source-discovery-error'
  | 'source-file-limit'
  | 'source-parse-diagnostics'
  | 'source-read-error'
  | 'source-work-limit'
  | 'unproven-receiver-provenance'
  | 'unresolvable-analysis-root'
  | 'unsupported-endpoint-surface'
  | 'unsupported-optional-chain'
  | 'unsupported-static-member-access';

export type AnalyzerCauseScope = 'candidate' | 'repository' | 'source';

/**
 * Machine-readable resource-frontier evidence for a resource-exhaustion cause.
 *
 * Present only on the three resource cause codes ({@link AnalyzerCauseCode}
 * `source-file-limit`, `source-byte-limit`, and `source-work-limit`); `null` everywhere else.
 * `frontier` is the normalized root-relative POSIX path where the budget stopped or omitted
 * work, when one is available. `processedSources`/`unprocessedSources` count known completed
 * and known-remaining sources; either is `null` when the count is not knowable, such as when
 * work exhaustion stopped traversal before the remaining universe could be enumerated.
 */
export interface AnalyzerCauseResource {
  limitKey: keyof AnalysisLimits;
  configured: number;
  consumed: number;
  frontier: string | null;
  processedSources: number | null;
  unprocessedSources: number | null;
}

/**
 * One deduplicated causal record.
 *
 * `detail` is analyzer-authored text describing the analyzer's own boundary. It never
 * embeds target source text, target identifiers, host paths, or third-party error strings.
 */
export interface AnalyzerCause {
  id: string;
  code: AnalyzerCauseCode;
  scope: AnalyzerCauseScope;
  path: string | null;
  span: SourceSpan | null;
  resource: AnalyzerCauseResource | null;
  detail: string;
}

export type CandidateKind = 'bracket-member-call' | 'client-endpoint-shorthand-call' | 'direct-rest-member-call';

export type CandidateClassification = 'incomplete' | 'proven-irrelevant' | 'proven-operation';

export type CandidateReason =
  | 'proven-direct-rest-member-call'
  | 'proven-non-octokit-origin'
  | 'unproven-receiver-provenance'
  | 'unsupported-endpoint-surface'
  | 'unsupported-optional-chain'
  | 'unsupported-static-member-access';

/**
 * One censused analysis obligation.
 *
 * The census runs before provenance evaluation, so every candidate reaches exactly one
 * terminal classification. Failure to prove Octokit provenance is recorded as `incomplete`;
 * it is never silently converted into proof that the receiver was something else.
 */
export interface CandidateRecord {
  id: string;
  kind: CandidateKind;
  anchor: string;
  spelling: string;
  path: string;
  span: SourceSpan;
  classification: CandidateClassification;
  reason: CandidateReason;
  observationId: string | null;
  causeIds: string[];
}

/** Portable identity of one analyzed regular file. */
export interface SourceRecord {
  id: string;
  path: string;
  byteSize: number;
  contentSha256: string;
}

/** The proof chain that authorized a receiver, retaining its original source spelling. */
export interface ReceiverProvenance {
  origin: 'octokit-package-named-import';
  packageSpecifier: string;
  exportName: string;
  constructorBinding: string;
  constructorAliasChain: string[];
  construction: 'direct-new';
  clientBinding: string;
  clientAliasChain: string[];
}

/** The pinned profile member that supplied the canonical operation identity. */
export interface ProfileMemberReference {
  profileId: string;
  memberId: string;
  scope: string;
  method: string;
}

/**
 * One proven canonical REST operation.
 *
 * Observations are produced before any permission lookup, so a proven operation survives an
 * absent catalog row.
 */
export interface OperationObservation {
  id: string;
  candidateId: string;
  callForm: CandidateKind;
  spelling: string;
  optional: boolean;
  member: ProfileMemberReference;
  operation: RestOperationIdentity;
  receiver: ReceiverProvenance;
  source: SourceEvidence;
}

/** One Phase 2 permission resolution, kept next to the observation that produced it. */
export interface PermissionResolutionRecord {
  id: string;
  observationId: string;
  finding: RequirementFinding;
}

/** The declared analysis boundary, sufficient to reproduce the run. */
export interface AnalysisBoundary {
  include: string[];
  exclude: string[];
  probotEntrypoints: string[];
  limits: AnalysisLimits;
  sourceExtensions: string[];
}

/**
 * Versioned identity of the pinned analyzer-compatibility profile, embedded in every result.
 *
 * This names the exact `octokit` and `@octokit/plugin-rest-endpoint-methods` surface, and the
 * exact reviewed inventory and artifact-manifest evidence, that {@link AnalyzerIdentity} makes
 * a source-compatibility claim about.
 */
export interface AnalyzerProfileIdentity {
  schemaVersion: number;
  profileId: string;
  octokitVersion: string;
  endpointMethodsVersion: string;
  restApiVersion: string;
  inventoryContentSha256: string;
  artifactManifestSha256: string;
  endpointMemberCount: number;
  operationCount: number;
}

/** The profile identity, the three other profile identities, and the permission-catalog identity used for comparison. */
export interface AnalyzerIdentity {
  schemaId: string;
  schemaVersion: number;
  spanConventionId: string;
  analyzerProfile: AnalyzerProfileIdentity;
  discoveryProfileId: string;
  limitProfileId: string;
  permissionCatalogScopeSha256: string;
}

interface AnalysisEvidence {
  identity: AnalyzerIdentity;
  boundary: AnalysisBoundary;
  sources: SourceRecord[];
  candidates: CandidateRecord[];
  causes: AnalyzerCause[];
  observations: OperationObservation[];
  permissionResolutions: PermissionResolutionRecord[];
  permissionBoundary: PermissionBoundary;
}

export interface CompleteAnalysisResult extends AnalysisEvidence {
  status: 'complete';
}

export interface IncompleteAnalysisResult extends AnalysisEvidence {
  status: 'incomplete';
}

/** Diagnostic-only outcome. It deliberately carries no semantic evidence at all. */
export interface FailedAnalysisResult {
  status: 'failed';
  identity: AnalyzerIdentity;
  reason: AnalysisFailureReason;
  causes: AnalyzerCause[];
}

export type AnalysisResult = CompleteAnalysisResult | FailedAnalysisResult | IncompleteAnalysisResult;

const SHA256 = /^[a-f0-9]{64}$/u;
const HTTP_METHOD = /^[A-Z]+$/u;
const NO_WHITESPACE = /^\S+$/u;
const ORDINAL_ID = /^[a-z]+-[0-9]{4,}$/u;
const POSIX_RELATIVE = /^[^/][^\0]*$/u;
const SEMANTIC_VERSION = /^[0-9]+\.[0-9]+\.[0-9]+$/u;
const DATED_API_VERSION = /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/u;

const FAILURE_REASONS: readonly AnalysisFailureReason[] = [
  'analysis-root-not-a-directory',
  'invalid-analysis-request',
  'invalid-analysis-result',
  'probot-entrypoint-outside-source-universe',
  'unresolvable-analysis-root',
];

const CAUSE_CODES: readonly AnalyzerCauseCode[] = [
  'invalid-analysis-request',
  'invalid-analysis-result',
  'matching-non-regular-entry',
  'matching-source-symlink',
  'permission-catalog-incomplete',
  'probot-entrypoint-unsupported',
  'relevant-directory-symlink',
  'source-byte-limit',
  'source-decode-failed',
  'source-discovery-error',
  'source-file-limit',
  'source-parse-diagnostics',
  'source-read-error',
  'source-work-limit',
  'unproven-receiver-provenance',
  'unresolvable-analysis-root',
  'unsupported-endpoint-surface',
  'unsupported-optional-chain',
  'unsupported-static-member-access',
];

/** Cause codes that carry a non-null {@link AnalyzerCauseResource}; every other code is null. */
const RESOURCE_CAUSE_CODES: readonly AnalyzerCauseCode[] = ['source-byte-limit', 'source-file-limit', 'source-work-limit'];

const CAUSE_SCOPES: readonly AnalyzerCauseScope[] = ['candidate', 'repository', 'source'];

const CANDIDATE_KINDS: readonly CandidateKind[] = [
  'bracket-member-call',
  'client-endpoint-shorthand-call',
  'direct-rest-member-call',
];

const CANDIDATE_CLASSIFICATIONS: readonly CandidateClassification[] = [
  'incomplete',
  'proven-irrelevant',
  'proven-operation',
];

const CANDIDATE_REASONS: readonly CandidateReason[] = [
  'proven-direct-rest-member-call',
  'proven-non-octokit-origin',
  'unproven-receiver-provenance',
  'unsupported-endpoint-surface',
  'unsupported-optional-chain',
  'unsupported-static-member-access',
];

const LIMIT_KEYS: readonly (keyof AnalysisLimits)[] = [
  'maxSourceFileBytes',
  'maxSourceFiles',
  'maxSourceWork',
  'maxTotalSourceBytes',
];

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

function assertStringArray(value: unknown, label: string): asserts value is string[] {
  if (!Array.isArray(value)) throw new TypeError(`${label} must be an array`);
  value.forEach((entry, index) => assertNonEmptyString(entry, `${label}[${index}]`));
}

function assertBudget(value: unknown, label: string): asserts value is number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw new TypeError(`${label} must be a non-negative safe integer`);
  }
}

function assertSha256(value: unknown, label: string): asserts value is string {
  if (typeof value !== 'string' || !SHA256.test(value)) throw new TypeError(`${label} must be a lowercase SHA-256`);
}

function assertOrdinalId(value: unknown, label: string): asserts value is string {
  if (typeof value !== 'string' || !ORDINAL_ID.test(value)) {
    throw new TypeError(`${label} must be a stable ordinal identifier`);
  }
}

/**
 * Accepts only a case-sensitive, root-relative POSIX path.
 *
 * Absolute paths, `.`/`..` segments, empty segments, backslashes, and NUL bytes are
 * rejected rather than normalized, because repairing a trusted path would silently move the
 * analysis boundary.
 */
function assertRootRelativePosixPath(value: unknown, label: string): asserts value is string {
  assertNonEmptyString(value, label);
  if (!POSIX_RELATIVE.test(value)) throw new TypeError(`${label} must be a root-relative POSIX path`);
  if (value.includes('\\')) throw new TypeError(`${label} must not contain a backslash`);
  const segments = value.split('/');
  for (const segment of segments) {
    if (segment.length === 0 || segment === '.' || segment === '..') {
      throw new TypeError(`${label} must not contain an empty, current, or parent segment`);
    }
  }
}

/**
 * Accepts only the finite glob grammar named by {@link ANALYSIS_DISCOVERY_PROFILE_ID}.
 *
 * Negation, brace expansion, character classes, extglobs, and absolute or traversing
 * patterns are rejected. `**` is only meaningful as a whole segment.
 */
function assertGlobPattern(value: unknown, label: string): asserts value is string {
  assertNonEmptyString(value, label);
  if (value.startsWith('/')) throw new TypeError(`${label} must be a root-relative pattern`);
  if (value.includes('\\')) throw new TypeError(`${label} must not contain a backslash`);
  if (/[!{}[\]()+@|]/u.test(value)) throw new TypeError(`${label} contains an uninterpreted glob operator`);
  const segments = value.split('/');
  for (const segment of segments) {
    if (segment.length === 0 || segment === '.' || segment === '..') {
      throw new TypeError(`${label} must not contain an empty, current, or parent segment`);
    }
    if (segment.includes('**') && segment !== '**') {
      throw new TypeError(`${label} may use ** only as a whole segment`);
    }
  }
}

function assertLimits(value: unknown, label: string): asserts value is AnalysisLimits {
  assertPlainObject(value, label);
  assertExactKeys(value, LIMIT_KEYS, label);
  for (const key of LIMIT_KEYS) assertBudget(value[key], `${label}.${key}`);
}

/**
 * Accepts only an exact-shape trusted analysis request.
 *
 * Unknown keys, arrays in object position, missing include patterns, malformed patterns,
 * non-integer or negative limits, and non-root-relative Probot entrypoints are rejected.
 * Nothing is coerced: an invalid request becomes a failed result, not a repaired one.
 */
export function validateAnalysisRequest(value: unknown): asserts value is AnalysisRequest {
  assertPlainObject(value, 'analysis request');
  assertExactKeys(value, ['exclude', 'include', 'limits', 'probotEntrypoints', 'rootPath'], 'analysis request');
  assertNonEmptyString(value.rootPath, 'analysis request rootPath');
  assertStringArray(value.include, 'analysis request include');
  assertStringArray(value.exclude, 'analysis request exclude');
  assertStringArray(value.probotEntrypoints, 'analysis request probotEntrypoints');
  if (value.include.length === 0) throw new TypeError('analysis request include must contain at least one pattern');
  value.include.forEach((pattern, index) => assertGlobPattern(pattern, `analysis request include[${index}]`));
  value.exclude.forEach((pattern, index) => assertGlobPattern(pattern, `analysis request exclude[${index}]`));
  value.probotEntrypoints.forEach((entry, index) =>
    assertRootRelativePosixPath(entry, `analysis request probotEntrypoints[${index}]`),
  );
  assertLimits(value.limits, 'analysis request limits');
}

function assertSpan(value: unknown, label: string): asserts value is SourceSpan {
  assertPlainObject(value, label);
  assertExactKeys(value, ['end', 'start'], label);
  for (const key of ['start', 'end'] as const) {
    const point: unknown = value[key];
    assertPlainObject(point, `${label}.${key}`);
    assertExactKeys(point, ['column', 'line'], `${label}.${key}`);
    for (const axis of ['line', 'column'] as const) {
      const coordinate: unknown = point[axis];
      if (typeof coordinate !== 'number' || !Number.isSafeInteger(coordinate) || coordinate < 1) {
        throw new TypeError(`${label}.${key}.${axis} must be a positive integer`);
      }
    }
  }
  const start = value.start as unknown as { line: number; column: number };
  const end = value.end as unknown as { line: number; column: number };
  if (end.line < start.line || (end.line === start.line && end.column < start.column)) {
    throw new TypeError(`${label} ends before it starts`);
  }
}

function assertOperationIdentity(value: unknown, label: string): asserts value is RestOperationIdentity {
  assertPlainObject(value, label);
  assertExactKeys(value, ['method', 'normalizedRoute', 'operationId'], label);
  assertNonEmptyString(value.method, `${label}.method`);
  assertNonEmptyString(value.normalizedRoute, `${label}.normalizedRoute`);
  assertNonEmptyString(value.operationId, `${label}.operationId`);
  if (!HTTP_METHOD.test(value.method)) throw new TypeError(`${label}.method must be an uppercase REST method`);
  if (!value.normalizedRoute.startsWith('/') || !NO_WHITESPACE.test(value.normalizedRoute)) {
    throw new TypeError(`${label}.normalizedRoute must be a normalized route path`);
  }
  if (!NO_WHITESPACE.test(value.operationId)) throw new TypeError(`${label}.operationId must not contain whitespace`);
}

function assertCatalogProvenance(value: unknown, label: string): void {
  assertPlainObject(value, label);
  const keys = [
    'artifactManifestSha256',
    'authorizedScopeSha256',
    'entrySha256',
    'expressionSha256',
    'supportPredicateSha256',
  ] as const;
  assertExactKeys(value, keys, label);
  for (const key of keys) assertSha256(value[key], `${label}.${key}`);
}

function assertRequirementFinding(value: unknown, label: string): asserts value is RequirementFinding {
  assertPlainObject(value, label);
  if (value.status === 'resolved') {
    assertExactKeys(value, ['operation', 'provenance', 'requirement', 'source', 'status'], label);
    assertOperationIdentity(value.operation, `${label}.operation`);
    validateSourceEvidence(value.source);
    validateRequirementExpression(value.requirement);
    assertCatalogProvenance(value.provenance, `${label}.provenance`);
    return;
  }
  if (value.status === 'unsupported') {
    assertExactKeys(value, ['operation', 'reason', 'source', 'status'], label);
    assertOperationIdentity(value.operation, `${label}.operation`);
    validateSourceEvidence(value.source);
    assertNonEmptyString(value.reason, `${label}.reason`);
    return;
  }
  if (value.status === 'missing') {
    assertExactKeys(value, ['operation', 'source', 'status'], label);
    assertOperationIdentity(value.operation, `${label}.operation`);
    validateSourceEvidence(value.source);
    return;
  }
  if (value.status === 'invalid') {
    assertExactKeys(value, ['detail', 'operation', 'reason', 'source', 'status'], label);
    if (value.operation !== null) assertOperationIdentity(value.operation, `${label}.operation`);
    if (value.source !== null) validateSourceEvidence(value.source);
    assertNonEmptyString(value.reason, `${label}.reason`);
    assertNonEmptyString(value.detail, `${label}.detail`);
    return;
  }
  throw new TypeError(`${label}.status is invalid`);
}

function assertPermissionBoundary(value: unknown, label: string): asserts value is PermissionBoundary {
  assertPlainObject(value, label);
  if (value.status === 'complete') {
    assertExactKeys(value, ['permissions', 'status'], label);
    if (!Array.isArray(value.permissions)) throw new TypeError(`${label}.permissions must be an array`);
    for (const [index, entry] of value.permissions.entries()) {
      const entryLabel = `${label}.permissions[${index}]`;
      assertPlainObject(entry, entryLabel);
      assertExactKeys(entry, ['contributors', 'level', 'permission'], entryLabel);
      assertNonEmptyString(entry.permission, `${entryLabel}.permission`);
      if (entry.level !== 'read' && entry.level !== 'write') throw new TypeError(`${entryLabel}.level is invalid`);
      if (!Array.isArray(entry.contributors) || entry.contributors.length === 0) {
        throw new TypeError(`${entryLabel}.contributors must be a non-empty array`);
      }
      entry.contributors.forEach((contributor: unknown, position: number) =>
        assertRequirementFinding(contributor, `${entryLabel}.contributors[${position}]`),
      );
    }
    return;
  }
  if (value.status === 'incomplete') {
    assertExactKeys(value, ['findings', 'reasons', 'status'], label);
    if (!Array.isArray(value.reasons) || value.reasons.length === 0) {
      throw new TypeError(`${label}.reasons must be a non-empty array`);
    }
    value.reasons.forEach((reason: unknown, index: number) =>
      assertNonEmptyString(reason, `${label}.reasons[${index}]`),
    );
    if (!Array.isArray(value.findings)) throw new TypeError(`${label}.findings must be an array`);
    value.findings.forEach((finding: unknown, index: number) =>
      assertRequirementFinding(finding, `${label}.findings[${index}]`),
    );
    return;
  }
  throw new TypeError(`${label}.status is invalid`);
}

/**
 * Accepts only an exact-shape {@link AnalyzerProfileIdentity}.
 *
 * This checks structural validity — types, formats, and non-negative safe-integer counts —
 * not the current pinned values, which only `analyzeSourceTree` is responsible for
 * constructing from the `ANALYZER_PROFILE_IDENTITY` constant in `./profile.js`.
 */
function assertAnalyzerProfileIdentity(value: unknown, label: string): asserts value is AnalyzerProfileIdentity {
  assertPlainObject(value, label);
  assertExactKeys(
    value,
    [
      'artifactManifestSha256',
      'endpointMemberCount',
      'endpointMethodsVersion',
      'inventoryContentSha256',
      'octokitVersion',
      'operationCount',
      'profileId',
      'restApiVersion',
      'schemaVersion',
    ],
    label,
  );
  if (typeof value.schemaVersion !== 'number' || !Number.isSafeInteger(value.schemaVersion) || value.schemaVersion < 1) {
    throw new TypeError(`${label}.schemaVersion must be a positive safe integer`);
  }
  assertNonEmptyString(value.profileId, `${label}.profileId`);
  assertNonEmptyString(value.octokitVersion, `${label}.octokitVersion`);
  if (!SEMANTIC_VERSION.test(value.octokitVersion)) {
    throw new TypeError(`${label}.octokitVersion must be a semantic version`);
  }
  assertNonEmptyString(value.endpointMethodsVersion, `${label}.endpointMethodsVersion`);
  if (!SEMANTIC_VERSION.test(value.endpointMethodsVersion)) {
    throw new TypeError(`${label}.endpointMethodsVersion must be a semantic version`);
  }
  assertNonEmptyString(value.restApiVersion, `${label}.restApiVersion`);
  if (!DATED_API_VERSION.test(value.restApiVersion)) {
    throw new TypeError(`${label}.restApiVersion must be a dated REST API version`);
  }
  assertSha256(value.inventoryContentSha256, `${label}.inventoryContentSha256`);
  assertSha256(value.artifactManifestSha256, `${label}.artifactManifestSha256`);
  assertBudget(value.endpointMemberCount, `${label}.endpointMemberCount`);
  assertBudget(value.operationCount, `${label}.operationCount`);
}

function assertIdentity(value: unknown, label: string): asserts value is AnalyzerIdentity {
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
  if (value.schemaId !== ANALYSIS_SCHEMA_ID) throw new TypeError(`${label}.schemaId is not this schema`);
  if (value.schemaVersion !== ANALYSIS_SCHEMA_VERSION) throw new TypeError(`${label}.schemaVersion is not this schema`);
  if (value.spanConventionId !== ANALYSIS_SPAN_CONVENTION_ID) {
    throw new TypeError(`${label}.spanConventionId is not this convention`);
  }
  if (value.discoveryProfileId !== ANALYSIS_DISCOVERY_PROFILE_ID) {
    throw new TypeError(`${label}.discoveryProfileId is not this policy`);
  }
  if (value.limitProfileId !== ANALYSIS_LIMIT_PROFILE_ID) {
    throw new TypeError(`${label}.limitProfileId is not this policy`);
  }
  assertAnalyzerProfileIdentity(value.analyzerProfile, `${label}.analyzerProfile`);
  assertSha256(value.permissionCatalogScopeSha256, `${label}.permissionCatalogScopeSha256`);
}

function assertCauseResource(value: unknown, label: string): asserts value is AnalyzerCauseResource {
  assertPlainObject(value, label);
  assertExactKeys(
    value,
    ['configured', 'consumed', 'frontier', 'limitKey', 'processedSources', 'unprocessedSources'],
    label,
  );
  if (!LIMIT_KEYS.includes(value.limitKey as keyof AnalysisLimits)) throw new TypeError(`${label}.limitKey is invalid`);
  assertBudget(value.configured, `${label}.configured`);
  assertBudget(value.consumed, `${label}.consumed`);
  if (value.frontier !== null) assertRootRelativePosixPath(value.frontier, `${label}.frontier`);
  if (value.processedSources !== null) assertBudget(value.processedSources, `${label}.processedSources`);
  if (value.unprocessedSources !== null) assertBudget(value.unprocessedSources, `${label}.unprocessedSources`);
}

/**
 * Accepts only the exact code/limitKey/scope/path pairing each resource cause may carry.
 *
 * `source-file-limit` and `source-work-limit` are always repository-scoped, scan-wide
 * frontiers with no cause path. `source-byte-limit` is file-scoped with a cause path equal to
 * its own frontier when it carries `maxSourceFileBytes`, and repository-scoped with no cause
 * path when it carries `maxTotalSourceBytes`. No other code/key pairing is valid.
 */
function assertResourceCauseSemantics(
  code: AnalyzerCauseCode,
  scope: AnalyzerCauseScope,
  path: string | null,
  resource: AnalyzerCauseResource,
  label: string,
): void {
  if (code === 'source-file-limit' || code === 'source-work-limit') {
    const expectedKey: keyof AnalysisLimits = code === 'source-file-limit' ? 'maxSourceFiles' : 'maxSourceWork';
    if (resource.limitKey !== expectedKey) throw new TypeError(`${label}.resource.limitKey must be ${expectedKey}`);
    if (scope !== 'repository') throw new TypeError(`${label} must be repository-scoped`);
    if (path !== null) throw new TypeError(`${label} must carry no path`);
    return;
  }
  if (resource.limitKey === 'maxSourceFileBytes') {
    if (scope !== 'source') throw new TypeError(`${label} must be source-scoped for maxSourceFileBytes`);
    if (path === null || path !== resource.frontier) {
      throw new TypeError(`${label} path must equal its resource frontier`);
    }
    return;
  }
  if (resource.limitKey === 'maxTotalSourceBytes') {
    if (scope !== 'repository') throw new TypeError(`${label} must be repository-scoped for maxTotalSourceBytes`);
    if (path !== null) throw new TypeError(`${label} must carry no path for maxTotalSourceBytes`);
    return;
  }
  throw new TypeError(`${label}.resource.limitKey is not valid for ${code}`);
}

function assertCause(value: unknown, label: string): asserts value is AnalyzerCause {
  assertPlainObject(value, label);
  assertExactKeys(value, ['code', 'detail', 'id', 'path', 'resource', 'scope', 'span'], label);
  assertOrdinalId(value.id, `${label}.id`);
  if (!CAUSE_CODES.includes(value.code as AnalyzerCauseCode)) throw new TypeError(`${label}.code is invalid`);
  if (!CAUSE_SCOPES.includes(value.scope as AnalyzerCauseScope)) throw new TypeError(`${label}.scope is invalid`);
  if (value.path !== null) assertRootRelativePosixPath(value.path, `${label}.path`);
  if (value.span !== null) assertSpan(value.span, `${label}.span`);
  if (value.span !== null && value.path === null) throw new TypeError(`${label}.span requires a path`);
  const isResourceCause = RESOURCE_CAUSE_CODES.includes(value.code as AnalyzerCauseCode);
  if (isResourceCause) {
    if (value.resource === null) throw new TypeError(`${label}.resource is required for a resource cause`);
    assertCauseResource(value.resource, `${label}.resource`);
    assertResourceCauseSemantics(
      value.code as AnalyzerCauseCode,
      value.scope as AnalyzerCauseScope,
      value.path as string | null,
      value.resource,
      label,
    );
  } else if (value.resource !== null) {
    throw new TypeError(`${label}.resource must be null for a non-resource cause`);
  }
  assertNonEmptyString(value.detail, `${label}.detail`);
}

function assertSourceRecord(value: unknown, label: string): asserts value is SourceRecord {
  assertPlainObject(value, label);
  assertExactKeys(value, ['byteSize', 'contentSha256', 'id', 'path'], label);
  assertOrdinalId(value.id, `${label}.id`);
  assertRootRelativePosixPath(value.path, `${label}.path`);
  assertBudget(value.byteSize, `${label}.byteSize`);
  assertSha256(value.contentSha256, `${label}.contentSha256`);
}

function assertCandidate(value: unknown, label: string): asserts value is CandidateRecord {
  assertPlainObject(value, label);
  assertExactKeys(
    value,
    ['anchor', 'causeIds', 'classification', 'id', 'kind', 'observationId', 'path', 'reason', 'spelling', 'span'],
    label,
  );
  assertOrdinalId(value.id, `${label}.id`);
  if (!CANDIDATE_KINDS.includes(value.kind as CandidateKind)) throw new TypeError(`${label}.kind is invalid`);
  assertNonEmptyString(value.anchor, `${label}.anchor`);
  assertNonEmptyString(value.spelling, `${label}.spelling`);
  assertRootRelativePosixPath(value.path, `${label}.path`);
  assertSpan(value.span, `${label}.span`);
  if (!CANDIDATE_CLASSIFICATIONS.includes(value.classification as CandidateClassification)) {
    throw new TypeError(`${label}.classification is invalid`);
  }
  if (!CANDIDATE_REASONS.includes(value.reason as CandidateReason)) throw new TypeError(`${label}.reason is invalid`);
  if (value.observationId !== null) assertOrdinalId(value.observationId, `${label}.observationId`);
  assertStringArray(value.causeIds, `${label}.causeIds`);
  value.causeIds.forEach((id, index) => assertOrdinalId(id, `${label}.causeIds[${index}]`));
  if (value.classification === 'proven-operation') {
    if (value.observationId === null) throw new TypeError(`${label} is proven without an observation`);
    if (value.reason !== 'proven-direct-rest-member-call') throw new TypeError(`${label}.reason is not a proof reason`);
  } else if (value.observationId !== null) {
    throw new TypeError(`${label} references an observation it did not prove`);
  }
  if (value.classification === 'incomplete' && value.causeIds.length === 0) {
    throw new TypeError(`${label} is incomplete without a cause`);
  }
}

function assertObservation(value: unknown, label: string): asserts value is OperationObservation {
  assertPlainObject(value, label);
  assertExactKeys(
    value,
    ['callForm', 'candidateId', 'id', 'member', 'operation', 'optional', 'receiver', 'source', 'spelling'],
    label,
  );
  assertOrdinalId(value.id, `${label}.id`);
  assertOrdinalId(value.candidateId, `${label}.candidateId`);
  if (!CANDIDATE_KINDS.includes(value.callForm as CandidateKind)) throw new TypeError(`${label}.callForm is invalid`);
  assertNonEmptyString(value.spelling, `${label}.spelling`);
  if (typeof value.optional !== 'boolean') throw new TypeError(`${label}.optional must be a boolean`);
  assertPlainObject(value.member, `${label}.member`);
  assertExactKeys(value.member, ['memberId', 'method', 'profileId', 'scope'], `${label}.member`);
  assertNonEmptyString(value.member.profileId, `${label}.member.profileId`);
  assertNonEmptyString(value.member.memberId, `${label}.member.memberId`);
  assertNonEmptyString(value.member.scope, `${label}.member.scope`);
  assertNonEmptyString(value.member.method, `${label}.member.method`);
  if (value.member.memberId !== `${String(value.member.scope)}.${String(value.member.method)}`) {
    throw new TypeError(`${label}.member.memberId does not match its scope and method`);
  }
  assertOperationIdentity(value.operation, `${label}.operation`);
  assertPlainObject(value.receiver, `${label}.receiver`);
  assertExactKeys(
    value.receiver,
    [
      'clientAliasChain',
      'clientBinding',
      'construction',
      'constructorAliasChain',
      'constructorBinding',
      'exportName',
      'origin',
      'packageSpecifier',
    ],
    `${label}.receiver`,
  );
  if (value.receiver.origin !== 'octokit-package-named-import') {
    throw new TypeError(`${label}.receiver.origin is not an authorized origin`);
  }
  if (value.receiver.construction !== 'direct-new') {
    throw new TypeError(`${label}.receiver.construction is not an authorized construction`);
  }
  assertNonEmptyString(value.receiver.packageSpecifier, `${label}.receiver.packageSpecifier`);
  assertNonEmptyString(value.receiver.exportName, `${label}.receiver.exportName`);
  assertNonEmptyString(value.receiver.constructorBinding, `${label}.receiver.constructorBinding`);
  assertNonEmptyString(value.receiver.clientBinding, `${label}.receiver.clientBinding`);
  assertStringArray(value.receiver.constructorAliasChain, `${label}.receiver.constructorAliasChain`);
  assertStringArray(value.receiver.clientAliasChain, `${label}.receiver.clientAliasChain`);
  validateSourceEvidence(value.source);
}

function assertPermissionResolution(value: unknown, label: string): asserts value is PermissionResolutionRecord {
  assertPlainObject(value, label);
  assertExactKeys(value, ['finding', 'id', 'observationId'], label);
  assertOrdinalId(value.id, `${label}.id`);
  assertOrdinalId(value.observationId, `${label}.observationId`);
  assertRequirementFinding(value.finding, `${label}.finding`);
}

function assertBoundaryRecord(value: unknown, label: string): asserts value is AnalysisBoundary {
  assertPlainObject(value, label);
  assertExactKeys(value, ['exclude', 'include', 'limits', 'probotEntrypoints', 'sourceExtensions'], label);
  assertStringArray(value.include, `${label}.include`);
  assertStringArray(value.exclude, `${label}.exclude`);
  assertStringArray(value.probotEntrypoints, `${label}.probotEntrypoints`);
  assertStringArray(value.sourceExtensions, `${label}.sourceExtensions`);
  if (value.include.length === 0) throw new TypeError(`${label}.include must contain at least one pattern`);
  assertLimits(value.limits, `${label}.limits`);
}

function assertUniqueIds(ids: readonly string[], label: string): void {
  if (new Set(ids).size !== ids.length) throw new TypeError(`${label} repeats an identifier`);
}

/**
 * Accepts only an exact-shape analysis result of one of the three declared variants.
 *
 * Beyond shape, this enforces the invariants that make the result trustworthy: identifiers
 * are unique, every cross-reference resolves, a `failed` result carries no semantic
 * evidence, and a `complete` result has no outstanding cause, unresolved candidate, or
 * incomplete permission boundary.
 */
export function validateAnalysisResult(value: unknown): asserts value is AnalysisResult {
  assertPlainObject(value, 'analysis result');
  assertIdentity((value as Record<string, unknown>).identity, 'analysis result identity');
  if (value.status === 'failed') {
    assertExactKeys(value, ['causes', 'identity', 'reason', 'status'], 'analysis result');
    if (!FAILURE_REASONS.includes(value.reason as AnalysisFailureReason)) {
      throw new TypeError('analysis result reason is invalid');
    }
    if (!Array.isArray(value.causes) || value.causes.length === 0) {
      throw new TypeError('a failed analysis result must carry at least one cause');
    }
    value.causes.forEach((cause: unknown, index: number) => assertCause(cause, `analysis result causes[${index}]`));
    assertUniqueIds(
      value.causes.map((cause: AnalyzerCause) => cause.id),
      'analysis result causes',
    );
    return;
  }
  if (value.status !== 'complete' && value.status !== 'incomplete') {
    throw new TypeError('analysis result status is invalid');
  }
  assertExactKeys(
    value,
    [
      'boundary',
      'candidates',
      'causes',
      'identity',
      'observations',
      'permissionBoundary',
      'permissionResolutions',
      'sources',
      'status',
    ],
    'analysis result',
  );
  assertBoundaryRecord(value.boundary, 'analysis result boundary');
  if (!Array.isArray(value.sources)) throw new TypeError('analysis result sources must be an array');
  if (!Array.isArray(value.candidates)) throw new TypeError('analysis result candidates must be an array');
  if (!Array.isArray(value.causes)) throw new TypeError('analysis result causes must be an array');
  if (!Array.isArray(value.observations)) throw new TypeError('analysis result observations must be an array');
  if (!Array.isArray(value.permissionResolutions)) {
    throw new TypeError('analysis result permissionResolutions must be an array');
  }
  value.sources.forEach((entry: unknown, index: number) =>
    assertSourceRecord(entry, `analysis result sources[${index}]`),
  );
  value.candidates.forEach((entry: unknown, index: number) =>
    assertCandidate(entry, `analysis result candidates[${index}]`),
  );
  value.causes.forEach((entry: unknown, index: number) => assertCause(entry, `analysis result causes[${index}]`));
  value.observations.forEach((entry: unknown, index: number) =>
    assertObservation(entry, `analysis result observations[${index}]`),
  );
  value.permissionResolutions.forEach((entry: unknown, index: number) =>
    assertPermissionResolution(entry, `analysis result permissionResolutions[${index}]`),
  );
  assertPermissionBoundary(value.permissionBoundary, 'analysis result permissionBoundary');

  const sources = value.sources as SourceRecord[];
  const candidates = value.candidates as CandidateRecord[];
  const causes = value.causes as AnalyzerCause[];
  const observations = value.observations as OperationObservation[];
  const resolutions = value.permissionResolutions as PermissionResolutionRecord[];

  assertUniqueIds(
    sources.map((entry) => entry.id),
    'analysis result sources',
  );
  assertUniqueIds(
    candidates.map((entry) => entry.id),
    'analysis result candidates',
  );
  assertUniqueIds(
    causes.map((entry) => entry.id),
    'analysis result causes',
  );
  assertUniqueIds(
    observations.map((entry) => entry.id),
    'analysis result observations',
  );
  assertUniqueIds(
    resolutions.map((entry) => entry.id),
    'analysis result permissionResolutions',
  );

  const sourcePaths = new Set(sources.map((entry) => entry.path));
  const causeIds = new Set(causes.map((entry) => entry.id));
  const candidateIds = new Set(candidates.map((entry) => entry.id));
  const observationIds = new Set(observations.map((entry) => entry.id));

  for (const candidate of candidates) {
    if (!sourcePaths.has(candidate.path)) throw new TypeError(`${candidate.id} references an unanalyzed source`);
    for (const id of candidate.causeIds) {
      if (!causeIds.has(id)) throw new TypeError(`${candidate.id} references an unknown cause`);
    }
    if (candidate.observationId !== null && !observationIds.has(candidate.observationId)) {
      throw new TypeError(`${candidate.id} references an unknown observation`);
    }
  }
  for (const observation of observations) {
    if (!candidateIds.has(observation.candidateId)) {
      throw new TypeError(`${observation.id} references an unknown candidate`);
    }
    if (!sourcePaths.has(observation.source.path)) {
      throw new TypeError(`${observation.id} references an unanalyzed source`);
    }
  }
  for (const resolution of resolutions) {
    if (!observationIds.has(resolution.observationId)) {
      throw new TypeError(`${resolution.id} references an unknown observation`);
    }
  }
  if (resolutions.length !== observations.length) {
    throw new TypeError('every observation must be resolved exactly once');
  }
  if (value.status === 'complete') {
    if (causes.length > 0) throw new TypeError('a complete analysis result must have no cause');
    if (candidates.some((candidate) => candidate.classification === 'incomplete')) {
      throw new TypeError('a complete analysis result must have no incomplete candidate');
    }
    if ((value.permissionBoundary as PermissionBoundary).status !== 'complete') {
      throw new TypeError('a complete analysis result must have a complete permission boundary');
    }
    return;
  }
  const boundaryIncomplete = (value.permissionBoundary as PermissionBoundary).status === 'incomplete';
  if (causes.length === 0 && !boundaryIncomplete) {
    throw new TypeError('an incomplete analysis result must record why it is incomplete');
  }
}
