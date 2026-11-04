/**
 * The independently usable BoundaryCI source analyzer.
 *
 * This module orchestrates the analysis: `./discovery.js` establishes the bounded regular-file
 * source universe and reads its bytes, `./parse.js` turns exactly those bytes into portable
 * source records, syntax, and spans, `./candidates.js` censuses every anchored obligation in
 * each parsed file, and `./resolve.js` builds the request-local included-source graph and proves
 * each candidate's receiver against it. This module never installs, resolves, imports,
 * transpiles, builds, or executes anything from the analyzed repository, and it never reads the
 * target's package manifest, lockfile, `node_modules`, or build configuration. The only
 * interaction with target content is byte reading followed by syntactic parsing.
 *
 * The operation-proving slice of the Phase 3 grammar is deliberately finite:
 *
 *   import { Octokit } from 'octokit';   // exact named ESM import, exact specifier
 *   const client = new Octokit();        // direct `new` on an immutable binding
 *   client.rest.issues.create({ ... });  // exact pinned `scope.method` member
 *   client.request('GET /repos/{owner}/{repo}/issues'); // exact static pinned route
 *
 * `./candidates.js` also anchors a broader grammar — alternate endpoint surfaces, static/dynamic
 * bracket chains, uninvoked or destructured extractions, static `request()` shapes, and
 * designated Probot registrations — so that unsupported relevant sites stay visible as explicit
 * incomplete candidates rather than disappearing into a clean result. A proven receiver remains
 * necessary but never sufficient: the call grammar and exact pinned operation must also resolve.
 */

import { BOUNDARYCI_PERMISSION_CATALOG, BOUNDARYCI_PERMISSION_CATALOG_IDENTITY } from '../permission-model/bounded-catalog.js';
import { aggregatePermissionFindings, resolveRequirementFinding } from '../permission-model/model.js';
import type { PermissionBoundary, RequirementFinding, SourceEvidence, SourceSpan } from '../permission-model/model.js';

import type { CandidateSite } from './candidates.js';
import { censusCandidates } from './candidates.js';
import {
  ANALYSIS_DISCOVERY_PROFILE_ID,
  ANALYSIS_LIMIT_PROFILE_ID,
  ANALYSIS_SCHEMA_ID,
  ANALYSIS_SCHEMA_VERSION,
  ANALYSIS_SPAN_CONVENTION_ID,
  ANALYZER_SOURCE_EXTENSIONS,
  validateAnalysisRequest,
  validateAnalysisResult,
} from './contract.js';
import type {
  AnalysisBoundary,
  AnalysisFailureReason,
  AnalysisRequest,
  AnalysisResult,
  AnalyzerCause,
  AnalyzerCauseCode,
  AnalyzerCauseResource,
  AnalyzerCauseScope,
  AnalyzerIdentity,
  CandidateClassification,
  CandidateKind,
  CandidateRecord,
  CandidateReason,
  OperationObservation,
  PermissionResolutionRecord,
  ProfileMemberReference,
  ReceiverProvenance,
  SourceRecord,
} from './contract.js';
import { discoverSources } from './discovery.js';
import { parseSourceRecord } from './parse.js';
import type { ParsedSource } from './parse.js';
import { resolveOperationCandidate } from './operations.js';
import type { OperationCandidateResolution } from './operations.js';
import { proveProbotEntrypoint, proveProbotHandlerRegistration } from './probot.js';
import { ANALYZER_PROFILE_IDENTITY } from './profile.js';
import { buildSourceGraph, proveCandidateReceiver, RESOLUTION_LIMITS } from './resolve.js';
import type { ReceiverProofResult, ResolverCause, SourceGraph } from './resolve.js';

const ANALYZER_IDENTITY: Readonly<AnalyzerIdentity> = Object.freeze({
  schemaId: ANALYSIS_SCHEMA_ID,
  schemaVersion: ANALYSIS_SCHEMA_VERSION,
  spanConventionId: ANALYSIS_SPAN_CONVENTION_ID,
  analyzerProfile: ANALYZER_PROFILE_IDENTITY,
  discoveryProfileId: ANALYSIS_DISCOVERY_PROFILE_ID,
  limitProfileId: ANALYSIS_LIMIT_PROFILE_ID,
  permissionCatalogScopeSha256: BOUNDARYCI_PERMISSION_CATALOG_IDENTITY.authorizedScopeSha256,
});

interface PendingCause {
  code: AnalyzerCauseCode;
  scope: AnalyzerCauseScope;
  path: string | null;
  span: SourceSpan | null;
  resource: AnalyzerCauseResource | null;
  detail: string;
}

interface PendingObservation {
  callForm: CandidateKind;
  spelling: string;
  optional: boolean;
  member: ProfileMemberReference | null;
  operation: { method: string; normalizedRoute: string; operationId: string };
  receiver: ReceiverProvenance;
  source: SourceEvidence;
}

interface PendingCandidate {
  kind: CandidateKind;
  anchor: string;
  spelling: string;
  path: string;
  span: SourceSpan;
  classification: CandidateClassification;
  reason: CandidateReason;
  causes: PendingCause[];
  observation: PendingObservation | null;
}

function compareBytes(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

/** Normalizes a declarative pattern/path array so caller order and duplicates never leak into evidence. */
function sortedUnique(values: readonly string[]): string[] {
  return [...new Set(values)].sort(compareBytes);
}

function ordinalId(prefix: string, index: number): string {
  return `${prefix}-${String(index + 1).padStart(4, '0')}`;
}

function causeKey(cause: PendingCause): string {
  return JSON.stringify([cause.code, cause.path ?? '', cause.span, cause.scope, cause.resource, cause.detail]);
}

function causeOrder(cause: PendingCause): string {
  const span = cause.span;
  const coordinates = span === null ? [0, 0, 0, 0] : [span.start.line, span.start.column, span.end.line, span.end.column];
  return JSON.stringify([cause.path ?? '', ...coordinates.map((value) => String(value).padStart(9, '0')), cause.code, cause.detail]);
}

function candidateOrder(candidate: PendingCandidate): string {
  return JSON.stringify([
    candidate.path,
    String(candidate.span.start.line).padStart(9, '0'),
    String(candidate.span.start.column).padStart(9, '0'),
    String(candidate.span.end.line).padStart(9, '0'),
    String(candidate.span.end.column).padStart(9, '0'),
    candidate.kind,
    candidate.spelling,
  ]);
}

function failed(reason: AnalysisFailureReason, code: AnalyzerCauseCode, detail: string): AnalysisResult {
  return {
    status: 'failed',
    identity: ANALYZER_IDENTITY,
    reason,
    causes: [{ id: ordinalId('cause', 0), code, scope: 'repository', path: null, span: null, resource: null, detail }],
  };
}

function requestFailureDetail(error: unknown): string {
  const message = error instanceof TypeError ? error.message : 'the analysis request is not a valid object';
  return message.length > 200 ? `${message.slice(0, 200)}…` : message;
}

/* ------------------------------------------------------------------ *
 * Candidate classification.
 * ------------------------------------------------------------------ */

function anchoredIncomplete(
  site: CandidateSite,
  reason: CandidateReason,
  code: AnalyzerCauseCode,
  detail: string,
): PendingCandidate {
  return {
    kind: site.kind,
    anchor: site.anchor,
    spelling: site.spelling,
    path: site.path,
    span: site.span,
    classification: 'incomplete',
    reason,
    causes: [{ code, scope: 'candidate', path: site.path, span: site.span, resource: null, detail }],
    observation: null,
  };
}

function pendingCausesFromResolver(resolverCauses: readonly ResolverCause[]): PendingCause[] {
  return resolverCauses.map((cause) => ({
    code: cause.code,
    scope: 'candidate',
    path: cause.path,
    span: cause.span,
    resource: null,
    detail: cause.detail,
  }));
}

function unprovenCandidate(site: CandidateSite, resolverCauses: readonly ResolverCause[]): PendingCandidate {
  return {
    kind: site.kind,
    anchor: site.anchor,
    spelling: site.spelling,
    path: site.path,
    span: site.span,
    classification: 'incomplete',
    reason: 'unproven-receiver-provenance',
    causes: pendingCausesFromResolver(resolverCauses),
    observation: null,
  };
}

/**
 * Attaches the resolver's exact receiver-provenance causes to a candidate that is already
 * incomplete for an independent syntax reason, so an unsupported call grammar never hides an
 * unproven receiver behind its own cause.
 */
function withUnprovenReceiverCauses(candidate: PendingCandidate, proof: ReceiverProofResult): PendingCandidate {
  if (proof.status !== 'unproven') return candidate;
  return { ...candidate, causes: [...candidate.causes, ...pendingCausesFromResolver(proof.causes)] };
}

function normalizedCandidate(site: CandidateSite, resolution: OperationCandidateResolution): PendingCandidate {
  if (resolution.status === 'incomplete') {
    return {
      kind: site.kind,
      anchor: site.anchor,
      spelling: site.spelling,
      path: site.path,
      span: site.span,
      classification: 'incomplete',
      reason: resolution.reason,
      causes: resolution.causes.map((cause) => ({
        code: cause.code,
        scope: 'candidate',
        path: cause.path ?? site.path,
        span: cause.span ?? site.span,
        resource: null,
        detail: cause.detail,
      })),
      observation: null,
    };
  }
  return {
    kind: site.kind,
    anchor: site.anchor,
    spelling: site.spelling,
    path: site.path,
    span: site.span,
    classification: 'proven-operation',
    reason: resolution.reason,
    causes: [],
    observation: {
      callForm: site.kind,
      spelling: site.spelling,
      optional: resolution.optional,
      member: resolution.member,
      operation: resolution.operation,
      receiver: resolution.receiver,
      source: { path: site.path, span: site.span },
    },
  };
}

/** Classifies every anchored kind Plan 03-04 has not yet authorized an operation from. */
function classifyUnsupportedKind(site: CandidateSite): PendingCandidate {
  switch (site.kind) {
    case 'static-bracket-member':
      return anchoredIncomplete(
        site,
        'unsupported-static-member-access',
        'unsupported-static-member-access',
        'static bracket member access is outside the supported call grammar',
      );
    case 'dynamic-member':
      return anchoredIncomplete(
        site,
        'unsupported-dynamic-member-access',
        'unsupported-dynamic-member-access',
        'a computed member chain position is outside the supported call grammar',
      );
    case 'endpoint-extraction':
      return anchoredIncomplete(
        site,
        'unsupported-endpoint-extraction',
        'unsupported-endpoint-extraction',
        'an uninvoked or destructured endpoint member is outside the supported call grammar',
      );
    case 'positional-request':
    case 'object-request':
      return anchoredIncomplete(
        site,
        'unsupported-request-grammar',
        'unsupported-request-grammar',
        'the request() call grammar is outside the supported call grammar',
      );
    case 'probot-registration':
      return anchoredIncomplete(
        site,
        'unsupported-probot-registration',
        'unsupported-probot-registration',
        'Probot registration provenance is outside the supported call grammar',
      );
    case 'direct-endpoint':
      throw new Error('a direct-endpoint candidate must be classified by classifyCandidate, not classifyUnsupportedKind');
  }
}

function provenIrrelevantCandidate(
  site: CandidateSite,
  reason: 'proven-non-octokit-origin' | 'proven-probot-registration-contract' = 'proven-non-octokit-origin',
): PendingCandidate {
  return {
    kind: site.kind,
    anchor: site.anchor,
    spelling: site.spelling,
    path: site.path,
    span: site.span,
    classification: 'proven-irrelevant',
    reason,
    causes: [],
    observation: null,
  };
}

function classifyProbotRegistration(site: CandidateSite, graph: SourceGraph): PendingCandidate {
  const sources = new Map([...graph.files].map(([path, file]) => [path, file.parsed]));
  const result = proveProbotHandlerRegistration(
    sources,
    graph.probotEntrypoints,
    {
      path: site.path,
      start:
        site.span.start.line === 0
          ? 0
          : (sources
              .get(site.path)
              ?.sourceFile.getPositionOfLineAndCharacter(
                site.span.start.line - 1,
                site.span.start.column - 1,
              ) ?? 0),
      optional: site.optional,
    },
    RESOLUTION_LIMITS,
  );
  if (result.status === 'proven') return provenIrrelevantCandidate(site, 'proven-probot-registration-contract');
  if (result.status === 'irrelevant') return provenIrrelevantCandidate(site);
  return anchoredIncomplete(site, 'unsupported-probot-handler-registration', result.cause.code, result.cause.detail);
}

/**
 * Classifies one censused candidate into its exactly one terminal record.
 *
 * The receiver is proven independently of whether the call grammar is one this analyzer proves
 * an operation from: a proven receiver alone never emits an observation, and only the exact
 * pinned `.rest.<scope>.<method>(...)` anchor or its supported optional forms may.
 */
function classifyCandidate(site: CandidateSite, graph: SourceGraph): PendingCandidate | null {
  if (site.kind === 'probot-registration') return classifyProbotRegistration(site, graph);
  const proof = proveCandidateReceiver(graph, site);

  if (site.provenReceiverOnly === true) {
    // A detached request surface is an obligation only on a proven authorized client; it is
    // never proven into an operation, and any other receiver keeps its unanchored v1 status.
    if (proof.status !== 'proven') return null;
    return site.kind === 'positional-request'
      ? anchoredIncomplete(
          site,
          'unsupported-request-grammar',
          'unsupported-request-grammar',
          'paginate() on a proven Octokit client is outside the supported request grammar',
        )
      : anchoredIncomplete(
          site,
          'unsupported-endpoint-extraction',
          'unsupported-endpoint-extraction',
          'a detached rest, scope, or request surface of a proven Octokit client is outside the supported call grammar',
        );
  }

  if (site.kind === 'direct-endpoint' || site.kind === 'positional-request' || site.kind === 'object-request') {
    if (proof.status === 'unproven') return unprovenCandidate(site, proof.causes);
    return normalizedCandidate(site, resolveOperationCandidate(site, graph, proof.provenance));
  }
  return withUnprovenReceiverCauses(classifyUnsupportedKind(site), proof);
}

/* ------------------------------------------------------------------ *
 * Entrypoint.
 * ------------------------------------------------------------------ */

/**
 * Analyzes one trusted source root and returns deterministic JSON evidence.
 *
 * The returned value is `complete` only when every obligation raised under the declared
 * boundary was resolved, `incomplete` when analysis ran safely but something remains
 * unresolved, and `failed` when the request, root, or analyzer state cannot support
 * trustworthy semantic output. A `failed` result carries diagnostics and nothing else.
 *
 * Trusted request validation is the one boundary this function checks itself; everything past
 * it runs in {@link runAnalysis} under a closing catch, so an unexpected analyzer-state
 * exception — an internal invariant this module or one of its collaborators violated, never a
 * declared limit or cycle, both of which already return normally — still produces a
 * structurally diagnostic-only `failed` result instead of an unhandled rejection or a result
 * that serializes accumulated evidence no one has actually validated.
 */
export async function analyzeSourceTree(request: AnalysisRequest): Promise<AnalysisResult> {
  try {
    validateAnalysisRequest(request);
  } catch (error) {
    return failed('invalid-analysis-request', 'invalid-analysis-request', requestFailureDetail(error));
  }

  try {
    return await runAnalysis(request);
  } catch {
    return failed(
      'internal-analyzer-error',
      'internal-analyzer-error',
      'the analyzer encountered an unexpected internal state and produced no trusted evidence',
    );
  }
}

async function runAnalysis(request: AnalysisRequest): Promise<AnalysisResult> {
  const boundary: AnalysisBoundary = {
    include: sortedUnique(request.include),
    exclude: sortedUnique(request.exclude),
    probotEntrypoints: sortedUnique(request.probotEntrypoints),
    limits: { ...request.limits },
    sourceExtensions: [...ANALYZER_SOURCE_EXTENSIONS],
  };

  const discovery = await discoverSources(request.rootPath, boundary.include, boundary.exclude, boundary.limits);
  if (discovery.status === 'failed') {
    const causeCode: AnalyzerCauseCode = discovery.reason === 'invalid-analysis-request' ? 'invalid-analysis-request' : 'unresolvable-analysis-root';
    return failed(discovery.reason, causeCode, discovery.detail);
  }

  const discovered = new Set(discovery.effectiveSources);
  if (discovery.universeComplete) {
    for (const entrypoint of boundary.probotEntrypoints) {
      if (!discovered.has(entrypoint)) {
        return failed(
          'probot-entrypoint-outside-source-universe',
          'invalid-analysis-request',
          'a designated Probot entrypoint is not part of the effective included source set',
        );
      }
    }
  }

  const causes: PendingCause[] = discovery.causes.map((cause) => ({
    code: cause.code,
    scope: cause.scope,
    path: cause.path,
    span: null,
    resource: cause.resource,
    detail: cause.detail,
  }));
  const sources: SourceRecord[] = [];
  const parsedSources: ParsedSource[] = [];

  // Every discovered file becomes exactly one raw source record, whether or not its bytes can
  // be decoded and parsed: a file that fails is evidence about the repository, and its
  // file-fatal cause makes the repository incomplete without withdrawing any other file's
  // independently proven findings. Only successfully parsed sources enter the source graph, so a
  // chain that needed a failed file becomes incomplete rather than silently resolving elsewhere.
  for (const discoveredSource of discovery.sources) {
    const parsed = parseSourceRecord(discoveredSource);
    sources.push({ id: '', ...parsed.record });
    if (parsed.status === 'unparsed') {
      causes.push({ ...parsed.cause, span: null, resource: null });
      continue;
    }
    parsedSources.push(parsed);
  }

  const parsedByPath = new Map(parsedSources.map((source) => [source.record.path, source]));
  for (const entrypoint of boundary.probotEntrypoints) {
    const parsed = parsedByPath.get(entrypoint);
    if (parsed === undefined) continue;
    const proof = proveProbotEntrypoint(parsed);
    if (proof.status === 'incomplete') {
      causes.push({ code: proof.cause.code, scope: 'source', path: proof.cause.path, span: proof.cause.span, resource: null, detail: proof.cause.detail });
    }
  }

  const graph = buildSourceGraph(parsedSources, boundary.probotEntrypoints);
  const probotEntrypoints = new Set(boundary.probotEntrypoints);
  const candidates: PendingCandidate[] = [];
  for (const parsed of parsedSources) {
    const sites = censusCandidates(parsed, {
      probotEntrypoint: probotEntrypoints.has(parsed.record.path),
    });
    for (const site of sites) {
      const candidate = classifyCandidate(site, graph);
      if (candidate !== null) candidates.push(candidate);
    }
  }

  sources.sort((left, right) => compareBytes(left.path, right.path));
  sources.forEach((source, index) => {
    source.id = ordinalId('source', index);
  });

  candidates.sort((left, right) => compareBytes(candidateOrder(left), candidateOrder(right)));

  const candidateRecords: CandidateRecord[] = [];
  const observations: OperationObservation[] = [];
  candidates.forEach((candidate, index) => {
    const id = ordinalId('candidate', index);
    let observationId: string | null = null;
    if (candidate.observation !== null) {
      observationId = ordinalId('operation', observations.length);
      observations.push({
        id: observationId,
        candidateId: id,
        callForm: candidate.observation.callForm,
        spelling: candidate.observation.spelling,
        optional: candidate.observation.optional,
        member: candidate.observation.member === null ? null : { ...candidate.observation.member },
        operation: { ...candidate.observation.operation },
        receiver: candidate.observation.receiver,
        source: {
          path: candidate.observation.source.path,
          span: {
            start: { ...candidate.observation.source.span.start },
            end: { ...candidate.observation.source.span.end },
          },
        },
      });
    }
    candidateRecords.push({
      id,
      kind: candidate.kind,
      anchor: candidate.anchor,
      spelling: candidate.spelling,
      path: candidate.path,
      span: candidate.span,
      classification: candidate.classification,
      reason: candidate.reason,
      observationId,
      causeIds: [],
    });
    for (const cause of candidate.causes) causes.push(cause);
  });

  const findings: RequirementFinding[] = observations.map((observation) =>
    resolveRequirementFinding(BOUNDARYCI_PERMISSION_CATALOG, observation.operation, observation.source),
  );
  const permissionResolutions: PermissionResolutionRecord[] = findings.map((finding, index) => ({
    id: ordinalId('resolution', index),
    observationId: observations[index]?.id ?? ordinalId('operation', index),
    finding,
  }));
  const permissionBoundary: PermissionBoundary = aggregatePermissionFindings(findings);

  if (permissionBoundary.status === 'incomplete') {
    causes.push({
      code: 'permission-catalog-incomplete',
      scope: 'repository',
      path: null,
      span: null,
      resource: null,
      detail: `the bounded permission catalog could not resolve every proven operation: ${permissionBoundary.reasons.join(', ')}`,
    });
  }

  const uniqueCauses = new Map<string, PendingCause>();
  for (const cause of causes) uniqueCauses.set(causeKey(cause), cause);
  const orderedCauses = [...uniqueCauses.values()].sort((left, right) =>
    compareBytes(causeOrder(left), causeOrder(right)),
  );
  const causeIds = new Map<string, string>();
  const causeRecords: AnalyzerCause[] = orderedCauses.map((cause, index) => {
    const id = ordinalId('cause', index);
    causeIds.set(causeKey(cause), id);
    return {
      id,
      code: cause.code,
      scope: cause.scope,
      path: cause.path,
      span: cause.span,
      resource: cause.resource,
      detail: cause.detail,
    };
  });

  candidates.forEach((candidate, index) => {
    const record = candidateRecords[index];
    if (record === undefined) return;
    record.causeIds = candidate.causes
      .map((cause) => causeIds.get(causeKey(cause)))
      .filter((id): id is string => id !== undefined)
      .sort(compareBytes);
  });

  const evidence = {
    identity: ANALYZER_IDENTITY,
    boundary,
    sources,
    candidates: candidateRecords,
    causes: causeRecords,
    observations,
    permissionResolutions,
    permissionBoundary,
  };
  const everythingResolved =
    causeRecords.length === 0 &&
    permissionBoundary.status === 'complete' &&
    !candidateRecords.some((candidate) => candidate.classification === 'incomplete');
  const result: AnalysisResult = everythingResolved
    ? { status: 'complete', ...evidence }
    : { status: 'incomplete', ...evidence };

  try {
    validateAnalysisResult(result);
  } catch {
    return failed(
      'invalid-analysis-result',
      'invalid-analysis-result',
      'the analyzer produced a result that failed its own contract validation',
    );
  }
  return result;
}
