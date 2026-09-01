/**
 * Immutable Git acquisition ceilings. These are transport safeguards, not target configuration:
 * repository configuration may narrow analyzer work but can never widen these values.
 */
export interface DeliveryLimits {
  maxTreeEntries: number;
  maxSourceFiles: number;
  maxSourceFileBytes: number;
  maxTotalSourceBytes: number;
  maxTreeRequests: number;
  maxBlobRequests: number;
  maxAcquisitionWork: number;
  maxElapsedMilliseconds: number;
}

/** The version-one finite, independently enforced acquisition profile. */
export const DELIVERY_LIMITS_V1: Readonly<DeliveryLimits> = Object.freeze({
  maxTreeEntries: 50_000,
  maxSourceFiles: 5_000,
  maxSourceFileBytes: 2_000_000,
  maxTotalSourceBytes: 64_000_000,
  maxTreeRequests: 2_000,
  maxBlobRequests: 5_002,
  maxAcquisitionWork: 70_000,
  maxElapsedMilliseconds: 60_000,
});

/** Rejects malformed trusted limit overrides before they influence any remote request. */
export function validateDeliveryLimits(value: unknown): asserts value is DeliveryLimits {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new TypeError('delivery limits must be an object');
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  const expected = Object.keys(DELIVERY_LIMITS_V1).sort();
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) {
    throw new TypeError('delivery limits have unknown or missing keys');
  }
  for (const key of expected) {
    const limit = record[key];
    if (!Number.isSafeInteger(limit) || (limit as number) < 0) {
      throw new TypeError(`delivery limit ${key} must be a non-negative safe integer`);
    }
  }
}
