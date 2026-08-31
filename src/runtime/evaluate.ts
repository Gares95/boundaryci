/**
 * Local snapshot analysis and base/head evaluation orchestration.
 *
 * This module never installs, imports, builds, or executes anything from an analyzed
 * repository: it only turns one {@link EffectiveConfig} plus a local root path into an
 * {@link AnalysisRequest} for the existing Phase 3 {@link analyzeSourceTree} entrypoint, wraps
 * the result, and composes the existing Phase 2/4 comparison and policy decision on top (D-04).
 */

import { analyzeSourceTree } from '../analyzer/analyze.js';
import type { AnalysisRequest } from '../analyzer/contract.js';
import { effectiveConfigIdentity } from '../config/model.js';
import type { EffectiveConfig } from '../config/model.js';
import { compareRevisionAnalyses, createRevisionAnalysis } from '../diff/revision.js';
import type { RevisionAnalysis, RevisionComparison } from '../diff/revision.js';

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

export type PolicyDecision = 'pass' | 'fail' | 'not-evaluated';

/** The policy outcome layered over a {@link RevisionComparison}; it never rewrites or erases it. */
export interface PolicyOutcome {
  decision: PolicyDecision;
  reasons: string[];
}

/**
 * Decides pass/fail from `config.failOnExpansion` and `config.failOnIncomplete`.
 *
 * This never changes `comparison`: it only reads it. Input/configuration and
 * runtime/infrastructure failures are not policy questions, so they report `not-evaluated`
 * rather than a manufactured pass or fail.
 */
function evaluatePolicy(comparison: RevisionComparison, config: EffectiveConfig): PolicyOutcome {
  if (comparison.status === 'complete') {
    const expansions = comparison.boundary.changes.filter((change) => change.change === 'expansion');
    if (config.failOnExpansion && expansions.length > 0) {
      return { decision: 'fail', reasons: expansions.map((change) => `expansion:${change.permission}`) };
    }
    return { decision: 'pass', reasons: [] };
  }
  if (comparison.status === 'incomplete') {
    if (config.failOnIncomplete) return { decision: 'fail', reasons: ['incomplete-comparison'] };
    return { decision: 'pass', reasons: [] };
  }
  return { decision: 'not-evaluated', reasons: [comparison.status] };
}

export interface LocalComparisonOutcome {
  comparison: RevisionComparison;
  policy: PolicyOutcome;
}

/**
 * Analyzes both local roots under one effective configuration and evaluates policy over the
 * resulting comparison. Base and head are analyzed independently, so their relative scheduling
 * never affects the deterministic result.
 */
export async function evaluateLocalComparison(
  basePath: string,
  headPath: string,
  config: EffectiveConfig,
): Promise<LocalComparisonOutcome> {
  const [base, head] = await Promise.all([analyzeLocalSnapshot(basePath, config), analyzeLocalSnapshot(headPath, config)]);
  const comparison = compareRevisionAnalyses(base, head);
  return { comparison, policy: evaluatePolicy(comparison, config) };
}
