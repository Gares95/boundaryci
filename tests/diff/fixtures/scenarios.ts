/**
 * Deterministic revision fixtures for the Plan 04-03 diff matrix.
 *
 * Every analysis result here is assembled from the authoritative contracts: catalog lookups go
 * through `resolveRequirementFinding`, permission boundaries through
 * `aggregatePermissionFindings`, and wrappers through `createRevisionAnalysis`, so a fixture
 * that would not survive `validateAnalysisResult` cannot be built by accident.
 *
 * The synthetic `allOf`/`anyOf` catalog below exists only to exercise the comparison contract
 * on complex expressions. It is a test-local value: nothing in `src/` imports this module, and
 * the frozen production catalog is consumed unchanged (D-01, D-19).
 */

import type {
  AnalysisResult,
  AnalyzerCause,
  AnalyzerCauseCode,
  AnalyzerCauseScope,
  AnalyzerIdentity,
  AnalyzerProfileIdentity,
  CandidateRecord,
  OperationObservation,
  PermissionResolutionRecord,
  ReceiverProvenance,
  SourceRecord,
} from '../../../src/analyzer/contract.js';
import {
  ANALYSIS_DISCOVERY_PROFILE_ID,
  ANALYSIS_LIMIT_PROFILE_ID,
  ANALYSIS_SCHEMA_ID,
  ANALYSIS_SCHEMA_VERSION,
  ANALYSIS_SPAN_CONVENTION_ID,
  ANALYZER_SOURCE_EXTENSIONS,
  DEFAULT_ANALYSIS_LIMITS,
} from '../../../src/analyzer/contract.js';
import { ANALYZER_PROFILE_IDENTITY } from '../../../src/analyzer/profile.js';
import { createRevisionAnalysis } from '../../../src/diff/revision.js';
import type { RevisionAnalysis } from '../../../src/diff/revision.js';
import {
  BOUNDARYCI_PERMISSION_CATALOG,
  BOUNDARYCI_PERMISSION_CATALOG_IDENTITY,
} from '../../../src/permission-model/bounded-catalog.js';
import type {
  CatalogProvenance,
  PermissionCatalogEntry,
  RequirementExpression,
  RequirementFinding,
  RestOperationIdentity,
  SourceEvidence,
} from '../../../src/permission-model/model.js';
import { aggregatePermissionFindings, resolveRequirementFinding } from '../../../src/permission-model/model.js';

/** Test-only digest material derived from a marker; never a production identity. */
export function digest(marker: string): string {
  let hex = '';
  for (const character of marker) hex += (character.codePointAt(0) ?? 0).toString(16).padStart(4, '0');
  return `${hex}${'0'.repeat(64)}`.slice(0, 64);
}

/** The one effective-configuration identity both revisions share unless a test changes it. */
export const CONFIG_DIGEST = digest('effective-config');

/** A second, equally valid configuration identity used only for identity-drift cases. */
export const OTHER_CONFIG_DIGEST = digest('other-effective-config');

const SYNTHETIC_PROVENANCE: CatalogProvenance = {
  authorizedScopeSha256: digest('synthetic-scope'),
  expressionSha256: digest('synthetic-expression'),
  entrySha256: digest('synthetic-entry'),
  artifactManifestSha256: digest('synthetic-manifest'),
  supportPredicateSha256: digest('synthetic-predicate'),
};

const CONTENTS_READ: RequirementExpression = { type: 'permission', permission: 'contents', level: 'read' };
const ISSUES_READ: RequirementExpression = { type: 'permission', permission: 'issues', level: 'read' };
const ISSUES_WRITE: RequirementExpression = { type: 'permission', permission: 'issues', level: 'write' };

/** Fixture-only complex expressions, already in the canonical child order Phase 2 requires. */
export const SYNTHETIC_ALL_OF: RequirementExpression = { type: 'allOf', requirements: [CONTENTS_READ, ISSUES_WRITE] };
export const SYNTHETIC_ANY_OF: RequirementExpression = { type: 'anyOf', requirements: [CONTENTS_READ, ISSUES_WRITE] };
export const SYNTHETIC_NESTED: RequirementExpression = {
  type: 'allOf',
  requirements: [ISSUES_READ, { type: 'anyOf', requirements: [CONTENTS_READ, ISSUES_WRITE] }],
};

function syntheticOperation(operationId: string, method: string): RestOperationIdentity {
  return { method, normalizedRoute: `/synthetic/${operationId.split('/')[1] ?? operationId}`, operationId };
}

function syntheticEntry(operationId: string, requirement: RequirementExpression): PermissionCatalogEntry {
  return {
    status: 'resolved',
    operation: syntheticOperation(operationId, 'POST'),
    requirement: structuredClone(requirement),
    provenance: { ...SYNTHETIC_PROVENANCE },
  };
}

/**
 * The fixture-only complex catalog.
 *
 * `synthetic/all-of` and `synthetic/all-of-alias` carry the identical canonical tree under two
 * different operations, so an equivalence claim has to survive the operation difference rather
 * than absorb it.
 */
export const SYNTHETIC_COMPLEX_CATALOG: readonly PermissionCatalogEntry[] = [
  syntheticEntry('synthetic/all-of', SYNTHETIC_ALL_OF),
  syntheticEntry('synthetic/all-of-alias', SYNTHETIC_ALL_OF),
  syntheticEntry('synthetic/any-of', SYNTHETIC_ANY_OF),
  syntheticEntry('synthetic/nested', SYNTHETIC_NESTED),
];

/** Every operation a fixture may call, including one deliberately outside the frozen catalog. */
const OPERATIONS: Readonly<Record<string, RestOperationIdentity>> = {
  'issues/create': { method: 'POST', normalizedRoute: '/repos/{owner}/{repo}/issues', operationId: 'issues/create' },
  'issues/list-for-repo': {
    method: 'GET',
    normalizedRoute: '/repos/{owner}/{repo}/issues',
    operationId: 'issues/list-for-repo',
  },
  'pulls/list': { method: 'GET', normalizedRoute: '/repos/{owner}/{repo}/pulls', operationId: 'pulls/list' },
  'synthetic/all-of': syntheticOperation('synthetic/all-of', 'POST'),
  'synthetic/all-of-alias': syntheticOperation('synthetic/all-of-alias', 'POST'),
  'synthetic/any-of': syntheticOperation('synthetic/any-of', 'POST'),
  'synthetic/nested': syntheticOperation('synthetic/nested', 'POST'),
};

/** One proven call site: which operation, where it was found. */
export interface CallSpec {
  operationId: string;
  path?: string;
  line?: number;
}

/** One open question the analysis recorded. */
export interface CauseSpec {
  code: AnalyzerCauseCode;
  detail: string;
  scope?: AnalyzerCauseScope;
  path?: string | null;
}

export interface AnalysisSpec {
  calls?: readonly CallSpec[];
  causes?: readonly CauseSpec[];
}

function ordinalId(prefix: string, index: number): string {
  return `${prefix}-${String(index + 1).padStart(4, '0')}`;
}

function operationOf(operationId: string): RestOperationIdentity {
  const operation = OPERATIONS[operationId];
  if (operation === undefined) throw new Error(`fixture operation ${operationId} is not declared`);
  return operation;
}

function catalogFor(operationId: string): readonly PermissionCatalogEntry[] {
  return operationId.startsWith('synthetic/') ? SYNTHETIC_COMPLEX_CATALOG : BOUNDARYCI_PERMISSION_CATALOG;
}

function memberOf(operationId: string): { scope: string; method: string } {
  const [scope, rest] = operationId.split('/');
  const parts = (rest ?? 'call').split('-');
  const method = parts
    .map((part, index) => (index === 0 ? part : `${(part[0] ?? '').toUpperCase()}${part.slice(1)}`))
    .join('');
  return { scope: scope ?? 'rest', method };
}

function spellingOf(operationId: string): string {
  const member = memberOf(operationId);
  return `client.rest.${member.scope}.${member.method}`;
}

function pathOf(call: CallSpec): string {
  return call.path ?? 'src/app.ts';
}

function sourceEvidence(call: CallSpec): SourceEvidence {
  const line = call.line ?? 1;
  return { path: pathOf(call), span: { start: { line, column: 3 }, end: { line, column: 40 } } };
}

function receiverProvenance(path: string, line: number): ReceiverProvenance {
  return {
    origin: 'octokit-package-named-import',
    packageSpecifier: 'octokit',
    exportName: 'Octokit',
    constructorBinding: 'Octokit',
    constructorAliasChain: [],
    construction: 'direct-new',
    clientBinding: 'client',
    clientAliasChain: [],
    access: 'local-binding',
    steps: [
      {
        kind: 'named-import',
        path,
        span: { start: { line, column: 1 }, end: { line, column: 30 } },
        binding: 'Octokit',
        specifier: 'octokit',
        resolvedPath: null,
        ruleId: null,
        ruleRow: null,
      },
    ],
  };
}

function identity(): AnalyzerIdentity {
  return {
    schemaId: ANALYSIS_SCHEMA_ID,
    schemaVersion: ANALYSIS_SCHEMA_VERSION,
    spanConventionId: ANALYSIS_SPAN_CONVENTION_ID,
    analyzerProfile: structuredClone(ANALYZER_PROFILE_IDENTITY) as AnalyzerProfileIdentity,
    discoveryProfileId: ANALYSIS_DISCOVERY_PROFILE_ID,
    limitProfileId: ANALYSIS_LIMIT_PROFILE_ID,
    permissionCatalogScopeSha256: BOUNDARYCI_PERMISSION_CATALOG_IDENTITY.authorizedScopeSha256,
  };
}

function sourceRecords(calls: readonly CallSpec[]): SourceRecord[] {
  const paths = [...new Set(calls.map(pathOf))].sort();
  return paths.map((path, index) => ({
    id: ordinalId('source', index),
    path,
    byteSize: 128 + index,
    contentSha256: digest(path),
  }));
}

function causeRecords(causes: readonly CauseSpec[]): AnalyzerCause[] {
  return causes.map((cause, index) => ({
    id: ordinalId('cause', index),
    code: cause.code,
    scope: cause.scope ?? 'repository',
    path: cause.path ?? null,
    span: null,
    resource: null,
    detail: cause.detail,
  }));
}

/**
 * Builds one exact-shape {@link AnalysisResult} from a short specification.
 *
 * Each call becomes a proven-operation candidate, its observation, and the Phase 2 permission
 * resolution for that observation; the aggregate boundary is whatever
 * `aggregatePermissionFindings` makes of those findings. The result is `complete` only when it
 * recorded no cause and the boundary itself is complete.
 */
export function analysisResult(spec: AnalysisSpec): AnalysisResult {
  const calls = spec.calls ?? [];
  const causes = causeRecords(spec.causes ?? []);
  const findings: RequirementFinding[] = calls.map((call) =>
    resolveRequirementFinding(catalogFor(call.operationId), operationOf(call.operationId), sourceEvidence(call)),
  );
  const candidates: CandidateRecord[] = calls.map((call, index) => ({
    id: ordinalId('candidate', index),
    kind: 'direct-endpoint',
    anchor: 'client.rest',
    spelling: spellingOf(call.operationId),
    path: pathOf(call),
    span: sourceEvidence(call).span,
    classification: 'proven-operation',
    reason: 'proven-direct-rest-member-call',
    observationId: ordinalId('observation', index),
    causeIds: [],
  }));
  const observations: OperationObservation[] = calls.map((call, index) => {
    const member = memberOf(call.operationId);
    return {
      id: ordinalId('observation', index),
      candidateId: ordinalId('candidate', index),
      callForm: 'direct-endpoint',
      spelling: spellingOf(call.operationId),
      optional: false,
      member: {
        profileId: ANALYZER_PROFILE_IDENTITY.profileId,
        memberId: `${member.scope}.${member.method}`,
        scope: member.scope,
        method: member.method,
      },
      operation: operationOf(call.operationId),
      receiver: receiverProvenance(pathOf(call), call.line ?? 1),
      source: sourceEvidence(call),
    };
  });
  const permissionResolutions: PermissionResolutionRecord[] = calls.map((call, index) => {
    const finding = findings[index];
    if (finding === undefined) throw new Error('fixture finding is missing');
    return { id: ordinalId('resolution', index), observationId: ordinalId('observation', index), finding };
  });
  const permissionBoundary = aggregatePermissionFindings(findings);
  const evidence = {
    identity: identity(),
    boundary: {
      include: ['**/*'],
      exclude: [],
      probotEntrypoints: [],
      limits: { ...DEFAULT_ANALYSIS_LIMITS },
      sourceExtensions: [...ANALYZER_SOURCE_EXTENSIONS],
    },
    sources: sourceRecords(calls),
    candidates,
    causes,
    observations,
    permissionResolutions,
    permissionBoundary,
  };
  return causes.length === 0 && permissionBoundary.status === 'complete'
    ? { status: 'complete', ...evidence }
    : { status: 'incomplete', ...evidence };
}

/** Wraps {@link analysisResult} in the validated revision wrapper the comparison consumes. */
export function revision(spec: AnalysisSpec, effectiveConfigSha256: string = CONFIG_DIGEST): RevisionAnalysis {
  return createRevisionAnalysis(analysisResult(spec), effectiveConfigSha256);
}

/** Returns an independent copy of `revision` with `patch` applied; the original is untouched. */
export function patchRevision(source: RevisionAnalysis, patch: (draft: RevisionAnalysis) => void): RevisionAnalysis {
  const draft = structuredClone(source);
  patch(draft);
  return draft;
}

/**
 * Applies one analyzer-identity change to both the wrapper and its embedded result.
 *
 * Patching both sides keeps the wrapper self-consistent, so the comparison sees genuine
 * identity drift between two well-formed revisions rather than a contradictory wrapper.
 */
export function withAnalyzerIdentity(source: RevisionAnalysis, patch: Partial<AnalyzerIdentity>): RevisionAnalysis {
  return patchRevision(source, (draft) => {
    const merged = { ...draft.identity.analyzer, ...patch };
    draft.identity.analyzer = merged;
    draft.result.identity = structuredClone(merged);
  });
}

/** Applies one analyzer-compatibility-profile field change coherently to both sides. */
export function withAnalyzerProfile(
  source: RevisionAnalysis,
  patch: Partial<AnalyzerProfileIdentity>,
): RevisionAnalysis {
  return withAnalyzerIdentity(source, { analyzerProfile: { ...source.identity.analyzer.analyzerProfile, ...patch } });
}

/** The frozen-catalog scenarios D-19 names, expressed as reusable call specifications. */
export const READ_CALL: CallSpec = { operationId: 'issues/list-for-repo', path: 'src/app.ts', line: 12 };
export const WRITE_CALL: CallSpec = { operationId: 'issues/create', path: 'src/app.ts', line: 20 };
export const MOVED_READ_CALL: CallSpec = { operationId: 'issues/list-for-repo', path: 'src/moved/app.ts', line: 77 };
export const CATALOG_GAP_CALL: CallSpec = { operationId: 'pulls/list', path: 'src/app.ts', line: 30 };
export const ALL_OF_CALL: CallSpec = { operationId: 'synthetic/all-of', path: 'src/app.ts', line: 40 };
export const ALL_OF_ALIAS_CALL: CallSpec = { operationId: 'synthetic/all-of-alias', path: 'src/app.ts', line: 41 };
export const ANY_OF_CALL: CallSpec = { operationId: 'synthetic/any-of', path: 'src/app.ts', line: 42 };
export const NESTED_CALL: CallSpec = { operationId: 'synthetic/nested', path: 'src/app.ts', line: 43 };

/** The cause a catalog gap raises: a proven operation whose permission stayed unresolved. */
export const CATALOG_GAP_CAUSE: CauseSpec = {
  code: 'permission-catalog-incomplete',
  scope: 'candidate',
  path: 'src/app.ts',
  detail: 'the proven operation has no authorized permission-catalog entry',
};

/** A cause unrelated to permission resolution, used for residual analysis incompleteness. */
export const UNSUPPORTED_CALL_CAUSE: CauseSpec = {
  code: 'unsupported-request-grammar',
  scope: 'source',
  path: 'src/other.ts',
  detail: 'the request call grammar is not interpreted by this analyzer',
};

/** A second unrelated cause, used to prove introduced/resolved/retained accounting. */
export const PARSE_CAUSE: CauseSpec = {
  code: 'source-parse-error',
  scope: 'source',
  path: 'src/unparsed.ts',
  detail: 'the source could not be parsed under the declared boundary',
};
