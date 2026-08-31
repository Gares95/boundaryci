/**
 * Local snapshot analysis and base/head evaluation orchestration.
 *
 * This module never installs, imports, builds, or executes anything from an analyzed
 * repository: it only turns one {@link EffectiveConfig} plus a local root path into an
 * {@link AnalysisRequest} for the existing Phase 3 {@link analyzeSourceTree} entrypoint, wraps
 * the result, and composes the existing Phase 2/4 comparison and policy decision on top (D-04).
 */

import { analyzeSourceTree } from '../analyzer/analyze.js';
import type { AnalysisFailureReason, AnalysisRequest, AnalyzerCause, AnalyzerIdentity } from '../analyzer/contract.js';
import { loadSnapshotConfig, selectAuthoritativeConfig } from '../config/load.js';
import type { AuthoritativeConfigSelection, ConfigDiagnostic } from '../config/load.js';
import { BUILTIN_CONFIG, effectiveConfigIdentity } from '../config/model.js';
import type { ConfigIdentity, EffectiveConfig, ExpectedPermissionDeclaration } from '../config/model.js';
import { compareRevisionAnalyses, createRevisionAnalysis } from '../diff/revision.js';
import type { RevisionAnalysis, RevisionComparison } from '../diff/revision.js';
import { evaluatePolicy } from '../policy/evaluate.js';
import type { PolicyDecision } from '../policy/evaluate.js';

function toAnalysisRequest(config: EffectiveConfig, rootPath: string): AnalysisRequest {
  return {
    rootPath,
    include: [...config.include],
    exclude: [...config.exclude],
    probotEntrypoints: [...config.probotEntrypoints],
    limits: { ...config.limits },
  };
}

/**
 * Analyzes one local source root under `config` and returns it as a {@link RevisionAnalysis}.
 *
 * `config` is the one authoritative base/default configuration for the whole comparison
 * (D-11, D-12): the only thing that varies between a base and head call is `rootPath`.
 */
export async function analyzeLocalSnapshot(rootPath: string, config: EffectiveConfig): Promise<RevisionAnalysis> {
  const request = toAnalysisRequest(config, rootPath);
  const result = await analyzeSourceTree(request);
  return createRevisionAnalysis(result, effectiveConfigIdentity(config));
}

/**
 * The exact result of {@link evaluateLocalComparison}.
 *
 * An `input-configuration-failure` member is the exact {@link AuthoritativeConfigSelection}
 * failure variant `selectAuthoritativeConfig` produced: no analysis ever runs and no
 * {@link RevisionComparison} is manufactured for it. `selected` is only reached once one
 * authority configuration has governed both revisions; it carries that authority's source and
 * identity, the separate prospective head configuration report, the resulting comparison, and
 * the policy decision layered over it.
 */
export type LocalComparisonResult =
  | Extract<AuthoritativeConfigSelection, { status: 'input-configuration-failure' }>
  | (Extract<AuthoritativeConfigSelection, { status: 'selected' }> & {
      status: 'selected';
      comparison: RevisionComparison;
      policy: PolicyDecision;
    });

/**
 * Loads and selects the one authoritative configuration for `basePath`/`headPath`, then analyzes
 * both roots under it, compares the analyses, and evaluates policy over the comparison
 * (D-04, D-11 through D-14).
 *
 * `selectAuthoritativeConfig` runs before either root is analyzed, so an invalid base or head
 * configuration fails closed without ever reading source. A valid head configuration never
 * governs this comparison: only the selected `authority` config is used for both
 * {@link analyzeLocalSnapshot} calls and for `evaluatePolicy`. Base and head are analyzed
 * independently, so their relative scheduling never affects the deterministic result.
 */
export async function evaluateLocalComparison(basePath: string, headPath: string): Promise<LocalComparisonResult> {
  const [baseState, headState] = await Promise.all([loadSnapshotConfig(basePath), loadSnapshotConfig(headPath)]);
  const selection = selectAuthoritativeConfig(baseState, headState);

  if (selection.status === 'input-configuration-failure') {
    return selection;
  }

  const { authority, head } = selection;
  const [base, headAnalysis] = await Promise.all([
    analyzeLocalSnapshot(basePath, authority.config),
    analyzeLocalSnapshot(headPath, authority.config),
  ]);
  const comparison = compareRevisionAnalyses(base, headAnalysis);
  const policy = evaluatePolicy(comparison, {
    failOnExpansion: authority.config.failOnExpansion,
    failOnIncomplete: authority.config.failOnIncomplete,
  });

  return Object.freeze({ status: 'selected', authority, head, comparison, policy });
}

/** Where the one effective configuration governing {@link analyzeConfiguredSnapshot} came from. */
export type ConfiguredSnapshotAuthoritySource = 'built-in-default' | 'snapshot';

/** The effective configuration's own identity plus where it came from, for a single-root analysis. */
export interface ConfiguredSnapshotAuthority {
  source: ConfiguredSnapshotAuthoritySource;
  identity: ConfigIdentity;
}

/**
 * The exact result of {@link analyzeConfiguredSnapshot}.
 *
 * `stage: 'configuration'` is the exact `loadSnapshotConfig` invalid diagnostics; the analyzer
 * never ran. `stage: 'analysis'` and `'analyzer-infrastructure-failure'` are both the analyzer's
 * own diagnostic-only `failed` result, split by {@link AnalysisFailureReason}: an
 * `internal-analyzer-error` describes a runtime/infrastructure failure, while every other
 * finite reason describes an unresolved question about the configured input, so only those two
 * carry the failure's `identity`/`reason`/`causes` and nothing else. `complete`/`incomplete`
 * carry the authority that governed the run, the configuration's own declared expected
 * permissions, and the full {@link RevisionAnalysis} evidence.
 */
export type AnalyzeConfiguredSnapshotResult =
  | { status: 'input-configuration-failure'; stage: 'configuration'; diagnostics: readonly ConfigDiagnostic[] }
  | {
      status: 'input-configuration-failure';
      stage: 'analysis';
      identity: AnalyzerIdentity;
      reason: AnalysisFailureReason;
      causes: AnalyzerCause[];
    }
  | {
      status: 'runtime-infrastructure-failure';
      identity: AnalyzerIdentity;
      reason: AnalysisFailureReason;
      causes: AnalyzerCause[];
    }
  | {
      status: 'complete';
      authority: ConfiguredSnapshotAuthority;
      declaredExpectedPermissions: ExpectedPermissionDeclaration[];
      analysis: RevisionAnalysis;
    }
  | {
      status: 'incomplete';
      authority: ConfiguredSnapshotAuthority;
      declaredExpectedPermissions: ExpectedPermissionDeclaration[];
      analysis: RevisionAnalysis;
    };

/**
 * Loads and selects the one effective configuration for `rootPath`, then analyzes that single
 * root under it, for the CLI `analyze` command.
 *
 * An invalid configuration fails closed before the analyzer ever runs (no source is read). An
 * absent configuration selects the exact versioned `BUILTIN_CONFIG`; a valid configuration
 * selects its own normalized configuration and identity. Unlike {@link evaluateLocalComparison},
 * this applies no comparison and no policy: it only reports one root's analysis under one
 * authority.
 */
export async function analyzeConfiguredSnapshot(rootPath: string): Promise<AnalyzeConfiguredSnapshotResult> {
  const state = await loadSnapshotConfig(rootPath);

  if (state.status === 'invalid') {
    return Object.freeze({
      status: 'input-configuration-failure',
      stage: 'configuration',
      diagnostics: Object.freeze(state.diagnostics.map((diagnostic) => Object.freeze({ ...diagnostic }))),
    });
  }

  const config: EffectiveConfig = state.status === 'valid' ? state.config : BUILTIN_CONFIG;
  const authority: ConfiguredSnapshotAuthority = Object.freeze({
    source: state.status === 'valid' ? 'snapshot' : 'built-in-default',
    identity: state.status === 'valid' ? state.identity : effectiveConfigIdentity(BUILTIN_CONFIG),
  });

  const analysis = await analyzeLocalSnapshot(rootPath, config);
  const { result } = analysis;

  if (result.status === 'failed') {
    if (result.reason === 'internal-analyzer-error') {
      return Object.freeze({
        status: 'runtime-infrastructure-failure',
        identity: result.identity,
        reason: result.reason,
        causes: [...result.causes],
      });
    }
    return Object.freeze({
      status: 'input-configuration-failure',
      stage: 'analysis',
      identity: result.identity,
      reason: result.reason,
      causes: [...result.causes],
    });
  }

  const declaredExpectedPermissions = [...config.declaredExpectedPermissions];

  if (result.status === 'complete') {
    return Object.freeze({ status: 'complete', authority, declaredExpectedPermissions, analysis });
  }
  return Object.freeze({ status: 'incomplete', authority, declaredExpectedPermissions, analysis });
}
