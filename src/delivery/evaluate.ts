import { cleanupComparisonRoots, type AcquiredComparisonRoots } from './snapshot.js';
import type { AcquisitionResult } from './contract.js';
import { validateAcquisitionResult } from './contract.js';
import { evaluateLocalComparison, type LocalComparisonResult } from '../runtime/evaluate.js';

/**
 * Source-free Phase 5 composition around the unchanged Phase 4 result. An acquisition limit
 * never changes Phase 4 evidence; it only limits the claims a delivery layer may make from it.
 */
export type AcquiredEvaluationResult =
  | {
      status: 'complete';
      acquisition: Extract<AcquisitionResult, { status: 'complete' }>;
      semanticUsability: 'complete';
      evaluation: LocalComparisonResult;
    }
  | {
      status: 'incomplete';
      acquisition: Extract<AcquisitionResult, { status: 'incomplete' }>;
      semanticUsability: 'positive-evidence-only';
      allowedClaims: readonly ['present-observations', 'present-requirements'];
      evaluation: LocalComparisonResult;
    }
  | { status: 'diagnostic-only'; acquisition: Exclude<AcquisitionResult, { status: 'complete' | 'incomplete' }> }
  | { status: 'cleanup-failure'; acquisition: AcquisitionResult };

export type LocalComparisonEvaluator = (baseRoot: string, headRoot: string) => Promise<LocalComparisonResult>;

/**
 * Evaluates materialized roots exactly once when, and only when, acquisition supplied trusted
 * configuration authority. Both private roots are removed before this function resolves; no
 * returned value retains a path, source byte, or temporary-root capability.
 */
export async function evaluateAcquiredComparison(
  acquired: AcquiredComparisonRoots,
  evaluator: LocalComparisonEvaluator = evaluateLocalComparison,
): Promise<AcquiredEvaluationResult> {
  validateAcquisitionResult(acquired.result);
  let result: AcquiredEvaluationResult;
  try {
    if (acquired.result.status !== 'complete' && acquired.result.status !== 'incomplete') {
      result = Object.freeze({ status: 'diagnostic-only', acquisition: structuredClone(acquired.result) });
    } else {
      const evaluation = await evaluator(acquired.roots.base, acquired.roots.head);
      if (acquired.result.status === 'complete') {
        result = Object.freeze({
          status: 'complete',
          acquisition: structuredClone(acquired.result),
          semanticUsability: 'complete',
          evaluation: structuredClone(evaluation),
        });
      } else {
        result = Object.freeze({
          status: 'incomplete',
          acquisition: structuredClone(acquired.result),
          semanticUsability: 'positive-evidence-only',
          allowedClaims: Object.freeze(['present-observations', 'present-requirements']) as ['present-observations', 'present-requirements'],
          evaluation: structuredClone(evaluation),
        });
      }
    }
  } catch {
    result = Object.freeze({
      status: 'diagnostic-only',
      acquisition: Object.freeze({ status: 'runtime-infrastructure-failure', reason: 'runtime-operation-failed' }),
    });
  }

  const cleaned = await cleanupComparisonRoots(acquired);
  if (!cleaned) return Object.freeze({ status: 'cleanup-failure', acquisition: structuredClone(acquired.result) });
  return result;
}
