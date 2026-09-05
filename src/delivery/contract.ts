import type { AuthoritativeConfigSelection } from '../config/load.js';
import { validateAuthoritativeConfigSelection, validateLocalComparisonResult } from '../runtime/evaluate.js';
import type { LocalComparisonResult } from '../runtime/evaluate.js';

export type AcquisitionCauseCode =
  | 'acquisition-work-limit'
  | 'aggregate-source-bytes-limit'
  | 'elapsed-time-limit'
  | 'relevant-gitlink'
  | 'relevant-symlink'
  | 'relevant-unsupported-object'
  | 'source-file-bytes-limit'
  | 'source-file-limit'
  | 'tree-entry-limit'
  | 'tree-response-truncated';

export interface AcquisitionCause {
  code: AcquisitionCauseCode;
  frontier: string | null;
  configured: number | null;
  consumed: number | null;
}

/** Identity for one validated immutable commit/tree and its materialized source subset. */
export interface SnapshotIdentity {
  commitSha: string;
  treeSha: string;
  sourceFileCount: number;
  sourceBytes: number;
}

export type AcquisitionFailureReason =
  | 'cancelled'
  | 'configuration-census-incomplete'
  | 'configuration-entry-invalid'
  | 'configuration-object-invalid'
  | 'immutable-object-mismatch'
  | 'invalid-trusted-input'
  | 'malformed-object-relationship'
  | 'runtime-operation-failed'
  | 'unsafe-path';

export type AcquisitionResult =
  | {
      status: 'complete';
      config: Extract<AuthoritativeConfigSelection, { status: 'selected' }>;
      snapshots: { base: SnapshotIdentity; head: SnapshotIdentity };
      causes: readonly AcquisitionCause[];
      semanticUsability: 'complete';
    }
  | {
      status: 'incomplete';
      config: Extract<AuthoritativeConfigSelection, { status: 'selected' }>;
      snapshots: { base: SnapshotIdentity; head: SnapshotIdentity };
      causes: readonly AcquisitionCause[];
      semanticUsability: 'positive-evidence-only';
      allowedClaims: readonly ['present-observations', 'present-requirements'];
    }
  | { status: 'input-configuration-failure'; reason: AcquisitionFailureReason }
  | { status: 'acquisition-security-failure'; reason: AcquisitionFailureReason }
  | { status: 'runtime-infrastructure-failure'; reason: AcquisitionFailureReason };

function assertSha(value: unknown, label: string): void {
  if (typeof value !== 'string' || !/^[a-f0-9]{40}$/u.test(value)) throw new TypeError(`${label} must be a lowercase Git SHA`);
}

function assertSnapshot(value: unknown, label: string): asserts value is SnapshotIdentity {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new TypeError(`${label} must be an object`);
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  const expected = ['commitSha', 'sourceBytes', 'sourceFileCount', 'treeSha'];
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) throw new TypeError(`${label} has an unsafe shape`);
  assertSha(record.commitSha, `${label}.commitSha`);
  assertSha(record.treeSha, `${label}.treeSha`);
  for (const key of ['sourceFileCount', 'sourceBytes']) {
    if (!Number.isSafeInteger(record[key]) || (record[key] as number) < 0) throw new TypeError(`${label}.${key} must be a safe count`);
  }
}

function assertCause(value: unknown, label: string): asserts value is AcquisitionCause {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new TypeError(`${label} must be an object`);
  const record = value as Record<string, unknown>;
  if (!exactKeys(record, ['code', 'configured', 'consumed', 'frontier'])) throw new TypeError(`${label} has an unsafe shape`);
  if (![
    'acquisition-work-limit', 'aggregate-source-bytes-limit', 'elapsed-time-limit', 'relevant-gitlink', 'relevant-symlink',
    'relevant-unsupported-object', 'source-file-bytes-limit', 'source-file-limit', 'tree-entry-limit', 'tree-response-truncated',
  ].includes(record.code as string) || (record.frontier !== null && (typeof record.frontier !== 'string' || record.frontier.length > 4_096)) ||
    (record.configured !== null && (!Number.isSafeInteger(record.configured) || (record.configured as number) < 0)) ||
    (record.consumed !== null && (!Number.isSafeInteger(record.consumed) || (record.consumed as number) < 0))) {
    throw new TypeError(`${label} is invalid`);
  }
}

const ACQUISITION_FAILURE_REASONS: readonly AcquisitionFailureReason[] = Object.freeze([
  'cancelled', 'configuration-census-incomplete', 'configuration-entry-invalid', 'configuration-object-invalid',
  'immutable-object-mismatch', 'invalid-trusted-input', 'malformed-object-relationship', 'runtime-operation-failed', 'unsafe-path',
]);

/** Exact-validates portable acquisition evidence; roots and source bytes are deliberately absent. */
export function validateAcquisitionResult(value: unknown): asserts value is AcquisitionResult {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new TypeError('acquisition result must be an object');
  const record = value as Record<string, unknown>;
  if (record.status === 'complete' || record.status === 'incomplete') {
    const expected = record.status === 'complete'
      ? ['causes', 'config', 'semanticUsability', 'snapshots', 'status']
      : ['allowedClaims', 'causes', 'config', 'semanticUsability', 'snapshots', 'status'];
    if (!exactKeys(record, expected)) throw new TypeError('acquisition result has an unsafe shape');
    validateAuthoritativeConfigSelection(record.config, 'acquisition result config');
    if ((record.config as { status?: unknown }).status !== 'selected') throw new TypeError('acquisition result config is not selected');
    if (typeof record.snapshots !== 'object' || record.snapshots === null || Array.isArray(record.snapshots)) {
      throw new TypeError('acquisition result snapshots must be an object');
    }
    const snapshots = record.snapshots as Record<string, unknown>;
    if (!exactKeys(snapshots, ['base', 'head'])) throw new TypeError('acquisition result snapshots have an unsafe shape');
    assertSnapshot(snapshots.base, 'acquisition result snapshots.base');
    assertSnapshot(snapshots.head, 'acquisition result snapshots.head');
    if (!Array.isArray(record.causes)) throw new TypeError('acquisition result causes must be an array');
    record.causes.forEach((cause, index) => assertCause(cause, `acquisition result causes[${index}]`));
    if (record.status === 'complete' && record.semanticUsability !== 'complete') throw new TypeError('complete acquisition usability is invalid');
    if (record.status === 'incomplete') {
      if (record.semanticUsability !== 'positive-evidence-only') throw new TypeError('incomplete acquisition usability is invalid');
      if (JSON.stringify(record.allowedClaims) !== JSON.stringify(['present-observations', 'present-requirements'])) {
        throw new TypeError('incomplete acquisition allowed claims are invalid');
      }
    }
    return;
  }
  if (
    record.status !== 'input-configuration-failure' &&
    record.status !== 'acquisition-security-failure' &&
    record.status !== 'runtime-infrastructure-failure'
  ) {
    throw new TypeError('acquisition result status is invalid');
  }
  if (!exactKeys(record, ['reason', 'status']) || !ACQUISITION_FAILURE_REASONS.includes(record.reason as AcquisitionFailureReason)) {
    throw new TypeError('acquisition failure reason is invalid');
  }
}

/** The immutable comparison fields that define one in-process delivery evaluation (D-15). */
export interface WorkIdentity {
  installationId: number;
  repositoryId: number;
  pullNumber: number;
  baseSha: string;
  headSha: string;
  evaluatorIdentity: string;
}

export type DeliveryLifecycleOutcome =
  | 'current'
  | 'stale'
  | 'superseded'
  | 'cancelled'
  | 'obsolete'
  | 'trust-failure'
  | 'fanout-incomplete'
  | 'cleanup-failure'
  | 'runtime-infrastructure-failure';

export type DeliveryNoHandoffReason =
  | 'acquisition-security-failure'
  | 'authenticated-comparison-drift'
  | 'comparison-cancelled'
  | 'coalesced-delivery-overflow'
  | 'delivery-lifecycle-operation-failed'
  | 'final-freshness-read-failed'
  | 'invalid-acquisition-root-handle'
  | 'invalid-base-target'
  | 'invalid-trigger-trace'
  | 'newer-comparison-superseded'
  | 'private-root-cleanup-not-verified'
  | 'pull-request-obsolete'
  | 'fanout-duplicate-pull-request'
  | 'fanout-elapsed-limit'
  | 'fanout-page-limit'
  | 'fanout-page-read-failed'
  | 'fanout-page-shape'
  | 'fanout-pull-request-limit'
  | 'fanout-response-bytes-limit';

export interface Phase6FreshnessMatch {
  repositoryId: number;
  pullNumber: number;
  baseRepositoryId: number;
  baseRef: string;
  baseSha: string;
  headRepositoryId: number;
  headSha: string;
  /**
   * Semantic evaluation is restricted to same-repository PRs. A current authenticated fork is
   * nevertheless reportable as a source-free diagnostic, so Phase 6 must retain that distinct
   * topology while it performs its own freshness check.
   */
  topology: 'same-repository' | 'unsupported-topology';
  eligibility: 'open';
}

export type DeliveryEnvelopeV1 =
  | {
      schemaVersion: 1;
      lifecycle: 'current';
      handoff: 'publishable-semantic';
      work: WorkIdentity;
      trigger: { deliveryIds: readonly string[] };
      acquisition: AcquisitionResult;
      semantic: { status: 'complete' | 'incomplete'; semanticUsability: 'complete' | 'positive-evidence-only'; evaluation: LocalComparisonResult };
      phase6FreshnessRequired: true;
      phase6Match: Phase6FreshnessMatch;
    }
  | {
      schemaVersion: 1;
      lifecycle: 'current';
      handoff: 'diagnostic-only';
      work: WorkIdentity;
      trigger: { deliveryIds: readonly string[] };
      diagnostic: { code: 'input-configuration-failure' | 'acquisition-runtime-failure' | 'evaluator-runtime-failure' | 'unsupported-topology' };
      phase6FreshnessRequired: true;
      phase6Match: Phase6FreshnessMatch;
    }
  | {
      schemaVersion: 1;
      lifecycle: Exclude<DeliveryLifecycleOutcome, 'current'>;
      handoff: 'none';
      work: WorkIdentity | null;
      reason: DeliveryNoHandoffReason;
      newestIdentity?: WorkIdentity;
    };

function exactKeys(record: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(record).sort();
  const sorted = [...expected].sort();
  return actual.length === sorted.length && actual.every((key, index) => key === sorted[index]);
}

function assertPositiveInteger(value: unknown, label: string): asserts value is number {
  if (!Number.isSafeInteger(value) || (value as number) <= 0) throw new TypeError(`${label} must be a positive safe integer`);
}

/** Rejects unknown fields at the lifecycle boundary before an envelope can be serialized. */
export function validateWorkIdentity(value: unknown): asserts value is WorkIdentity {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new TypeError('work identity must be an object');
  const record = value as Record<string, unknown>;
  if (!exactKeys(record, ['baseSha', 'evaluatorIdentity', 'headSha', 'installationId', 'pullNumber', 'repositoryId'])) {
    throw new TypeError('work identity has an unsafe shape');
  }
  assertPositiveInteger(record.installationId, 'work identity installationId');
  assertPositiveInteger(record.repositoryId, 'work identity repositoryId');
  assertPositiveInteger(record.pullNumber, 'work identity pullNumber');
  assertSha(record.baseSha, 'work identity baseSha');
  assertSha(record.headSha, 'work identity headSha');
  if (typeof record.evaluatorIdentity !== 'string' || record.evaluatorIdentity.length === 0 || record.evaluatorIdentity.length > 256) {
    throw new TypeError('work identity evaluatorIdentity is invalid');
  }
}

function validateMatch(value: unknown): asserts value is Phase6FreshnessMatch {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new TypeError('freshness match must be an object');
  const record = value as Record<string, unknown>;
  if (!exactKeys(record, ['baseRef', 'baseRepositoryId', 'baseSha', 'eligibility', 'headRepositoryId', 'headSha', 'pullNumber', 'repositoryId', 'topology'])) {
    throw new TypeError('freshness match has an unsafe shape');
  }
  for (const key of ['repositoryId', 'pullNumber', 'baseRepositoryId', 'headRepositoryId']) assertPositiveInteger(record[key], `freshness match ${key}`);
  assertSha(record.baseSha, 'freshness match baseSha');
  assertSha(record.headSha, 'freshness match headSha');
  if (typeof record.baseRef !== 'string' || record.baseRef.length === 0 || record.baseRef.length > 256 ||
    (record.topology !== 'same-repository' && record.topology !== 'unsupported-topology') || record.eligibility !== 'open') {
    throw new TypeError('freshness match is invalid');
  }
}

function validateTrigger(value: unknown): void {
  if (typeof value !== 'object' || value === null || Array.isArray(value) || !exactKeys(value as Record<string, unknown>, ['deliveryIds'])) {
    throw new TypeError('delivery trigger evidence is invalid');
  }
  const { deliveryIds } = value as { deliveryIds: unknown };
  if (!Array.isArray(deliveryIds) || deliveryIds.length > 64 || deliveryIds.some((id) => typeof id !== 'string' || id.length === 0 || id.length > 256)) {
    throw new TypeError('delivery trigger identifiers are invalid');
  }
}

function validateSemantic(value: unknown): void {
  if (typeof value !== 'object' || value === null || Array.isArray(value) || !exactKeys(value as Record<string, unknown>, ['evaluation', 'semanticUsability', 'status'])) {
    throw new TypeError('semantic envelope evidence is invalid');
  }
  const record = value as Record<string, unknown>;
  if ((record.status !== 'complete' && record.status !== 'incomplete') ||
    (record.semanticUsability !== 'complete' && record.semanticUsability !== 'positive-evidence-only')) {
    throw new TypeError('semantic envelope status is invalid');
  }
  validateLocalComparisonResult(record.evaluation);
}

function validateDiagnostic(value: unknown): void {
  if (typeof value !== 'object' || value === null || Array.isArray(value) || !exactKeys(value as Record<string, unknown>, ['code'])) {
    throw new TypeError('delivery diagnostic is invalid');
  }
  if (!['input-configuration-failure', 'acquisition-runtime-failure', 'evaluator-runtime-failure', 'unsupported-topology'].includes((value as { code?: unknown }).code as string)) {
    throw new TypeError('delivery diagnostic code is invalid');
  }
}

/** Exact validates the portable, source-free Phase 5 to Phase 6 contract. */
export function validateDeliveryEnvelope(value: unknown): asserts value is DeliveryEnvelopeV1 {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new TypeError('delivery envelope must be an object');
  const record = value as Record<string, unknown>;
  if (record.schemaVersion !== 1 || typeof record.lifecycle !== 'string' || typeof record.handoff !== 'string') {
    throw new TypeError('delivery envelope header is invalid');
  }
  if (record.handoff === 'publishable-semantic') {
    if (!exactKeys(record, ['acquisition', 'handoff', 'lifecycle', 'phase6FreshnessRequired', 'phase6Match', 'schemaVersion', 'semantic', 'trigger', 'work']) ||
      record.lifecycle !== 'current' || record.phase6FreshnessRequired !== true) throw new TypeError('publishable delivery envelope is invalid');
    validateWorkIdentity(record.work);
    validateAcquisitionResult(record.acquisition);
    validateTrigger(record.trigger);
    validateSemantic(record.semantic);
    const acquisition = record.acquisition as AcquisitionResult;
    const semantic = record.semantic as { status: unknown; semanticUsability: unknown };
    if ((acquisition.status !== 'complete' && acquisition.status !== 'incomplete') ||
      acquisition.status !== semantic.status || acquisition.semanticUsability !== semantic.semanticUsability) {
      throw new TypeError('semantic evidence does not match acquisition completeness');
    }
    validateMatch(record.phase6Match);
    const match = record.phase6Match as Phase6FreshnessMatch;
    if (match.topology !== 'same-repository' || match.repositoryId !== record.work.repositoryId ||
      match.baseRepositoryId !== record.work.repositoryId || match.headRepositoryId !== record.work.repositoryId ||
      match.pullNumber !== record.work.pullNumber || match.baseSha !== record.work.baseSha || match.headSha !== record.work.headSha) {
      throw new TypeError('publishable semantic freshness match is invalid');
    }
    return;
  }
  if (record.handoff === 'diagnostic-only') {
    if (!exactKeys(record, ['diagnostic', 'handoff', 'lifecycle', 'phase6FreshnessRequired', 'phase6Match', 'schemaVersion', 'trigger', 'work']) ||
      record.lifecycle !== 'current' || record.phase6FreshnessRequired !== true) throw new TypeError('diagnostic delivery envelope is invalid');
    validateWorkIdentity(record.work);
    validateTrigger(record.trigger);
    validateDiagnostic(record.diagnostic);
    validateMatch(record.phase6Match);
    const match = record.phase6Match as Phase6FreshnessMatch;
    const diagnostic = record.diagnostic as { code: unknown };
    if (match.repositoryId !== record.work.repositoryId || match.baseRepositoryId !== record.work.repositoryId ||
      match.pullNumber !== record.work.pullNumber || match.baseSha !== record.work.baseSha || match.headSha !== record.work.headSha) {
      throw new TypeError('diagnostic freshness identity is invalid');
    }
    if (diagnostic.code === 'unsupported-topology') {
      if (match.topology !== 'unsupported-topology' || match.headRepositoryId === record.work.repositoryId) {
        throw new TypeError('unsupported topology diagnostic freshness match is invalid');
      }
    } else if (match.topology !== 'same-repository' || match.headRepositoryId !== record.work.repositoryId) {
      throw new TypeError('same-repository diagnostic freshness match is invalid');
    }
    return;
  }
  if (record.handoff === 'none') {
    const allowed: Readonly<Record<string, readonly DeliveryNoHandoffReason[]>> = {
      stale: ['authenticated-comparison-drift'],
      superseded: ['newer-comparison-superseded'],
      cancelled: ['comparison-cancelled'],
      obsolete: ['pull-request-obsolete'],
      'trust-failure': ['acquisition-security-failure', 'invalid-acquisition-root-handle', 'invalid-base-target', 'invalid-trigger-trace'],
      'fanout-incomplete': ['fanout-duplicate-pull-request', 'fanout-elapsed-limit', 'fanout-page-limit', 'fanout-page-read-failed', 'fanout-page-shape', 'fanout-pull-request-limit', 'fanout-response-bytes-limit'],
      'cleanup-failure': ['private-root-cleanup-not-verified'],
      'runtime-infrastructure-failure': ['coalesced-delivery-overflow', 'delivery-lifecycle-operation-failed', 'final-freshness-read-failed'],
    };
    if (!Object.hasOwn(allowed, record.lifecycle) || typeof record.reason !== 'string' ||
      !allowed[record.lifecycle]!.includes(record.reason as DeliveryNoHandoffReason)) throw new TypeError('non-handoff delivery envelope reason is invalid');
    const stale = record.lifecycle === 'stale';
    const fanout = record.lifecycle === 'fanout-incomplete';
    if (!exactKeys(record, stale && record.newestIdentity !== undefined
      ? ['handoff', 'lifecycle', 'newestIdentity', 'reason', 'schemaVersion', 'work']
      : ['handoff', 'lifecycle', 'reason', 'schemaVersion', 'work'])) throw new TypeError('non-handoff delivery envelope has an unsafe shape');
    if (fanout && record.work !== null) throw new TypeError('fanout-incomplete delivery envelope is invalid');
    const nullWork = (record.lifecycle === 'fanout-incomplete') ||
      (record.lifecycle === 'trust-failure' && ['invalid-base-target', 'invalid-trigger-trace'].includes(record.reason as string)) ||
      (record.lifecycle === 'runtime-infrastructure-failure' && record.reason === 'delivery-lifecycle-operation-failed');
    if (nullWork !== (record.work === null)) throw new TypeError('non-handoff delivery envelope work identity is invalid');
    if (!stale && record.newestIdentity !== undefined) throw new TypeError('non-stale delivery envelope newest identity is invalid');
    if (record.work !== null) validateWorkIdentity(record.work);
    if (stale && record.newestIdentity !== undefined) validateWorkIdentity(record.newestIdentity);
    return;
  }
  throw new TypeError('delivery envelope handoff is invalid');
}
