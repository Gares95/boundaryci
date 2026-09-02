/**
 * The delivery layer only emits these finite, source-free operational fields.  No caller may
 * attach arbitrary details, external errors, credentials, request objects, or target content.
 */
export interface DeliveryLogEvent {
  stage: 'transport' | 'github-read' | 'snapshot' | 'evaluation' | 'cleanup';
  outcome: 'accepted' | 'rejected' | 'retry' | 'retry-exhausted' | 'complete' | 'incomplete' | 'failed';
  reason:
    | 'verified-trigger'
    | 'invalid-trigger'
    | 'trigger-read-failed'
    | 'read-capability-issued'
    | 'read-capability-rejected'
    | 'transient-read-retry'
    | 'transient-read-exhausted'
    | 'snapshot-complete'
    | 'snapshot-incomplete'
    | 'evaluation-complete'
    | 'evaluation-incomplete'
    | 'cleanup-failed';
  workId: string;
  deliveryId: string;
  installationId: number | null;
  repositoryId: number | null;
  pullNumber: number | null;
  baseSha: string | null;
  headSha: string | null;
  count: number;
  durationMilliseconds: number;
  attempt: number;
  delayMilliseconds: number;
}

export interface DeliveryLogSink {
  emit(event: DeliveryLogEvent): void;
}

const EVENT_KEYS = [
  'attempt', 'baseSha', 'count', 'delayMilliseconds', 'deliveryId', 'durationMilliseconds', 'headSha', 'installationId',
  'outcome', 'pullNumber', 'reason', 'repositoryId', 'stage', 'workId',
] as const;
const MAX_ID_LENGTH = 256;
const MAX_COUNT = 1_000_000;
const MAX_DURATION_MILLISECONDS = 60_000;
const MAX_ATTEMPTS = 8;
const MAX_DELAY_MILLISECONDS = 60_000;
const SHA = /^[a-f0-9]{40}$/u;
const STABLE_ID = /^[A-Za-z0-9._:-]+$/u;

const ALLOWED_REASONS: Readonly<Record<DeliveryLogEvent['stage'], readonly DeliveryLogEvent['reason'][]>> = {
  transport: ['verified-trigger', 'invalid-trigger', 'trigger-read-failed'],
  'github-read': ['read-capability-issued', 'read-capability-rejected', 'transient-read-retry', 'transient-read-exhausted'],
  snapshot: ['snapshot-complete', 'snapshot-incomplete'],
  evaluation: ['evaluation-complete', 'evaluation-incomplete'],
  cleanup: ['cleanup-failed'],
};

function exactKeys(value: Record<string, unknown>): boolean {
  const keys = Object.keys(value).sort();
  return keys.length === EVENT_KEYS.length && keys.every((key, index) => key === EVENT_KEYS[index]);
}

function safeOptionalIdentity(value: unknown): value is number | null {
  return value === null || (Number.isSafeInteger(value) && (value as number) > 0);
}

function safeCount(value: unknown, maximum: number): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0 && (value as number) <= maximum;
}

function safeId(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= MAX_ID_LENGTH && STABLE_ID.test(value);
}

/** Rejects anything outside the finite delivery operational vocabulary before a sink runs. */
export function validateDeliveryLogEvent(value: unknown): asserts value is DeliveryLogEvent {
  if (typeof value !== 'object' || value === null || Array.isArray(value) || !exactKeys(value as Record<string, unknown>)) {
    throw new TypeError('unsafe delivery log event');
  }
  const event = value as Record<string, unknown>;
  if (
    !['transport', 'github-read', 'snapshot', 'evaluation', 'cleanup'].includes(event.stage as string) ||
    !['accepted', 'rejected', 'retry', 'retry-exhausted', 'complete', 'incomplete', 'failed'].includes(event.outcome as string) ||
    !safeId(event.workId) || !safeId(event.deliveryId) ||
    !safeOptionalIdentity(event.installationId) || !safeOptionalIdentity(event.repositoryId) || !safeOptionalIdentity(event.pullNumber) ||
    (event.baseSha !== null && (typeof event.baseSha !== 'string' || !SHA.test(event.baseSha))) ||
    (event.headSha !== null && (typeof event.headSha !== 'string' || !SHA.test(event.headSha))) ||
    !safeCount(event.count, MAX_COUNT) || !safeCount(event.durationMilliseconds, MAX_DURATION_MILLISECONDS) ||
    !safeCount(event.attempt, MAX_ATTEMPTS) || !safeCount(event.delayMilliseconds, MAX_DELAY_MILLISECONDS)
  ) {
    throw new TypeError('unsafe delivery log event');
  }
  const reasons = ALLOWED_REASONS[event.stage as DeliveryLogEvent['stage']];
  if (!reasons.includes(event.reason as DeliveryLogEvent['reason'])) throw new TypeError('unsafe delivery log event');
}

function freezeClone(event: DeliveryLogEvent): DeliveryLogEvent {
  return Object.freeze({ ...event });
}

/**
 * Emits one validated, cloned, frozen event. A sink/telemetry failure is deliberately contained:
 * it cannot change delivery evidence, retries, cleanup, freshness, or handoff eligibility.
 */
export function emitDeliveryEvent(event: DeliveryLogEvent, sink: DeliveryLogSink | undefined): DeliveryLogEvent {
  validateDeliveryLogEvent(event);
  const safeEvent = freezeClone(event);
  try {
    sink?.emit(safeEvent);
  } catch {
    // Logging is observational only. The already-validated operational event remains usable.
  }
  return safeEvent;
}
