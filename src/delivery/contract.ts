import type { AuthoritativeConfigSelection } from '../config/load.js';

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

/** Exact-validates portable acquisition evidence; roots and source bytes are deliberately absent. */
export function validateAcquisitionResult(value: unknown): asserts value is AcquisitionResult {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new TypeError('acquisition result must be an object');
  const record = value as Record<string, unknown>;
  if (record.status === 'complete' || record.status === 'incomplete') {
    if (typeof record.snapshots !== 'object' || record.snapshots === null || Array.isArray(record.snapshots)) {
      throw new TypeError('acquisition result snapshots must be an object');
    }
    const snapshots = record.snapshots as Record<string, unknown>;
    assertSnapshot(snapshots.base, 'acquisition result snapshots.base');
    assertSnapshot(snapshots.head, 'acquisition result snapshots.head');
    if (!Array.isArray(record.causes)) throw new TypeError('acquisition result causes must be an array');
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
  if (typeof record.reason !== 'string') throw new TypeError('acquisition failure reason is invalid');
}
