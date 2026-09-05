import { cleanupComparisonRoots, type AcquiredComparisonRoots } from './snapshot.js';
import type { CurrentPull } from './types.js';
import type { AcquisitionResult, DeliveryEnvelopeV1, Phase6FreshnessMatch, WorkIdentity } from './contract.js';
import { validateAcquisitionResult, validateDeliveryEnvelope, validateWorkIdentity } from './contract.js';
import { validateLocalComparisonResult } from '../runtime/evaluate.js';
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

export interface EvaluateCurrentComparisonInput {
  work: WorkIdentity;
  baseRef: string;
  triggerDeliveryIds: readonly string[];
  acquire(): Promise<AcquiredComparisonRoots>;
  evaluator?: LocalComparisonEvaluator;
  getCurrentPull(pullNumber: number): Promise<CurrentPull>;
}

function freezeClone<T>(value: T): T {
  const cloned = structuredClone(value);
  const freeze = (item: unknown): void => {
    if (typeof item !== 'object' || item === null || Object.isFrozen(item)) return;
    for (const child of Object.values(item)) freeze(child);
    Object.freeze(item);
  };
  freeze(cloned);
  return cloned;
}

function freshnessMatch(work: WorkIdentity, baseRef: string): Phase6FreshnessMatch {
  return Object.freeze({
    repositoryId: work.repositoryId,
    pullNumber: work.pullNumber,
    baseRepositoryId: work.repositoryId,
    baseRef,
    baseSha: work.baseSha,
    headRepositoryId: work.repositoryId,
    headSha: work.headSha,
    topology: 'same-repository',
    eligibility: 'open',
  });
}

function currentMatches(work: WorkIdentity, baseRef: string, pull: CurrentPull): boolean {
  return pull.number === work.pullNumber && pull.repositoryId === work.repositoryId && pull.state === 'open' && !pull.merged &&
    pull.base.repositoryId === work.repositoryId && pull.base.ref === baseRef && pull.base.sha === work.baseSha &&
    pull.head.repositoryId === work.repositoryId && pull.head.sha === work.headSha;
}

function newestWork(work: WorkIdentity, pull: CurrentPull): WorkIdentity | undefined {
  if (pull.number !== work.pullNumber || pull.repositoryId !== work.repositoryId || pull.base.repositoryId !== work.repositoryId ||
    pull.head.repositoryId !== work.repositoryId || pull.state !== 'open' || pull.merged) return undefined;
  return Object.freeze({ ...work, baseSha: pull.base.sha, headSha: pull.head.sha });
}

function noHandoff(
  lifecycle: Exclude<DeliveryEnvelopeV1['lifecycle'], 'current'>,
  work: WorkIdentity | null,
  reason: string,
  newestIdentity?: WorkIdentity,
): DeliveryEnvelopeV1 {
  const envelope = Object.freeze({ schemaVersion: 1 as const, lifecycle, handoff: 'none' as const, work, reason, ...(newestIdentity === undefined ? {} : { newestIdentity }) });
  validateDeliveryEnvelope(envelope);
  return envelope;
}

function acquiredRootHandle(value: unknown): Pick<AcquiredComparisonRoots, 'roots'> | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null;
  const roots = (value as Record<string, unknown>).roots;
  if (typeof roots !== 'object' || roots === null || Array.isArray(roots)) return null;
  const record = roots as Record<string, unknown>;
  if (Object.keys(record).sort().join('\0') !== 'base\0head' || typeof record.base !== 'string' || typeof record.head !== 'string' ||
    record.base.length === 0 || record.head.length === 0) return null;
  return { roots: { base: record.base, head: record.head } };
}

function exactAcquiredComparisonRoots(value: unknown): asserts value is AcquiredComparisonRoots {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new TypeError('acquisition response must be an object');
  const record = value as Record<string, unknown>;
  if (Object.keys(record).sort().join('\0') !== 'result\0roots') throw new TypeError('acquisition response has an unsafe shape');
  if (acquiredRootHandle(value) === null) throw new TypeError('acquisition response roots are invalid');
}

/**
 * Builds only source-free Phase 6 evidence after acquisition/evaluation cleanup and a final
 * authenticated equality check. This module intentionally performs no Check presentation or write.
 */
export async function evaluateCurrentComparison(input: EvaluateCurrentComparisonInput): Promise<DeliveryEnvelopeV1> {
  let ownedRoots: Pick<AcquiredComparisonRoots, 'roots'> | undefined;
  try {
    validateWorkIdentity(input.work);
    if (typeof input.baseRef !== 'string' || input.baseRef.length === 0 || input.baseRef.length > 256) {
      return noHandoff('trust-failure', null, 'invalid-base-target');
    }
    if (!Array.isArray(input.triggerDeliveryIds)) return noHandoff('trust-failure', null, 'invalid-trigger-trace');
    const work = freezeClone(input.work);
    const trigger = freezeClone({ deliveryIds: [...input.triggerDeliveryIds] });
    const acquired = await input.acquire();
    const roots = acquiredRootHandle(acquired);
    if (roots === null) return noHandoff('trust-failure', work, 'invalid-acquisition-root-handle');
    ownedRoots = roots;
    exactAcquiredComparisonRoots(acquired);
    validateAcquisitionResult(acquired.result);
    const acquisition = freezeClone(acquired.result);
    let semantic: { status: 'complete' | 'incomplete'; semanticUsability: 'complete' | 'positive-evidence-only'; evaluation: LocalComparisonResult } | undefined;
    let evaluatorFailed = false;
    if (acquisition.status === 'complete' || acquisition.status === 'incomplete') {
      try {
        const evaluation = await (input.evaluator ?? evaluateLocalComparison)(acquired.roots.base, acquired.roots.head);
        validateLocalComparisonResult(evaluation);
        semantic = freezeClone({
          status: acquisition.status,
          semanticUsability: acquisition.semanticUsability,
          evaluation,
        });
      } catch {
        evaluatorFailed = true;
      }
    }
    const cleanupSucceeded = await cleanupComparisonRoots(acquired);
    ownedRoots = undefined;
    if (!cleanupSucceeded) return noHandoff('cleanup-failure', work, 'private-root-cleanup-not-verified');

    let current: CurrentPull;
    try {
      current = await input.getCurrentPull(work.pullNumber);
    } catch {
      return noHandoff('runtime-infrastructure-failure', work, 'final-freshness-read-failed');
    }
    if (!currentMatches(work, input.baseRef, current)) {
      return noHandoff('stale', work, 'authenticated-comparison-drift', newestWork(work, current));
    }

    const phase6Match = freshnessMatch(work, input.baseRef);
    if (semantic !== undefined) {
      const envelope = freezeClone({
        schemaVersion: 1 as const,
        lifecycle: 'current' as const,
        handoff: 'publishable-semantic' as const,
        work,
        trigger,
        acquisition,
        semantic,
        phase6FreshnessRequired: true as const,
        phase6Match,
      });
      validateDeliveryEnvelope(envelope);
      return envelope;
    }

    const diagnostic = evaluatorFailed
      ? 'evaluator-runtime-failure'
      : acquisition.status === 'input-configuration-failure'
      ? 'input-configuration-failure'
      : acquisition.status === 'runtime-infrastructure-failure'
        ? 'acquisition-runtime-failure'
        : acquisition.status === 'acquisition-security-failure'
          ? undefined
          : 'evaluator-runtime-failure';
    if (diagnostic === undefined) return noHandoff('trust-failure', work, 'acquisition-security-failure');
    const envelope = freezeClone({
      schemaVersion: 1 as const,
      lifecycle: 'current' as const,
      handoff: 'diagnostic-only' as const,
      work,
      trigger,
      diagnostic: { code: diagnostic },
      phase6FreshnessRequired: true as const,
      phase6Match,
    });
    validateDeliveryEnvelope(envelope);
    return envelope;
  } catch {
    return noHandoff('runtime-infrastructure-failure', null, 'delivery-lifecycle-operation-failed');
  } finally {
    if (ownedRoots !== undefined) await cleanupComparisonRoots(ownedRoots);
  }
}

/**
 * Evaluates materialized roots exactly once when, and only when, acquisition supplied trusted
 * configuration authority. Both private roots are removed before this function resolves; no
 * returned value retains a path, source byte, or temporary-root capability.
 */
export async function evaluateAcquiredComparison(
  acquired: AcquiredComparisonRoots,
  evaluator: LocalComparisonEvaluator = evaluateLocalComparison,
): Promise<AcquiredEvaluationResult> {
  const ownedRoots = acquiredRootHandle(acquired);
  if (ownedRoots === null) throw new TypeError('acquisition response roots are invalid');
  let result: AcquiredEvaluationResult;
  try {
    exactAcquiredComparisonRoots(acquired);
    validateAcquisitionResult(acquired.result);
    if (acquired.result.status !== 'complete' && acquired.result.status !== 'incomplete') {
      result = Object.freeze({ status: 'diagnostic-only', acquisition: structuredClone(acquired.result) });
    } else {
      const evaluation = await evaluator(acquired.roots.base, acquired.roots.head);
      validateLocalComparisonResult(evaluation);
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

  const cleaned = await cleanupComparisonRoots(ownedRoots);
  if (!cleaned) return Object.freeze({ status: 'cleanup-failure', acquisition: structuredClone(acquired.result) });
  return result;
}
