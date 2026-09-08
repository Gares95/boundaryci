import { createHash } from 'node:crypto';

import type { DeliveryEnvelopeV1 } from './contract.js';
import { validateDeliveryEnvelope } from './contract.js';

export const CHECK_NAME = 'BoundaryCI' as const;

export type CheckConclusion = 'success' | 'failure' | 'neutral' | 'action_required';
export type CheckTitle =
  | 'Permission boundary unchanged'
  | 'Permission boundary reduced'
  | 'Permission expansion permitted'
  | 'Permission expansion requires review'
  | 'Repository policy failed'
  | 'Analysis incomplete'
  | 'BoundaryCI could not evaluate this change';

export interface CheckIdentityV1 {
  version: 1;
  installationId: number;
  repositoryId: number;
  pullNumber: number;
  baseRepositoryId: number;
  baseRef: string;
  baseSha: string;
  headRepositoryId: number;
  headSha: string;
  topology: 'same-repository' | 'unsupported-topology';
  evaluatorIdentity: string;
  engineId: string;
  analyzer: Record<string, unknown>;
  catalogAuthorizedScopeSha256: string;
  effectiveConfigSha256: string;
  correlationId: string;
}

export interface CheckAnnotationV1 {
  path: string;
  startLine: number;
  endLine: number;
  level: 'notice' | 'warning' | 'failure';
  title: 'Permitted permission expansion' | 'Permission policy failure' | 'Incomplete analysis evidence' | 'BoundaryCI diagnostic';
  message: string;
  operationId: string;
}

export interface CompletedCheckPayloadV1 {
  name: typeof CHECK_NAME;
  headSha: string;
  status: 'completed';
  conclusion: CheckConclusion;
  title: CheckTitle;
  summary: string;
  text: string;
  externalId: string;
  annotations: readonly CheckAnnotationV1[];
}

export type CheckPublicationResultV1 =
  | { status: 'created'; correlationId: string; checkId: number }
  | { status: 'updated'; correlationId: string; checkId: number }
  | { status: 'not-published'; reason: 'invalid-envelope' | 'no-handoff' | 'stale-comparison' | 'publication-conflict' | 'publication-failure' };

const SHA = /^[a-f0-9]{40}$/u;
const DIGEST = /^[a-f0-9]{64}$/u;

type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

function canonicalJson(value: JsonValue): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((entry) => canonicalJson(entry)).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key] as JsonValue)}`).join(',')}}`;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const sorted = [...expected].sort();
  return actual.length === sorted.length && actual.every((key, index) => key === sorted[index]);
}

function safeString(value: unknown, limit = 4_096): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= limit && !value.includes('\0');
}

function positiveInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) > 0;
}

/** Derives the D-02 logical identity, excluding delivery trace and rendered result state. */
export function deriveCheckCorrelationId(envelope: DeliveryEnvelopeV1): CheckIdentityV1 {
  validateDeliveryEnvelope(envelope);
  if (envelope.handoff !== 'publishable-semantic') {
    throw new TypeError('only current reportable envelopes have a Check identity');
  }
  if (envelope.semantic.evaluation.status !== 'selected') throw new TypeError('tracer Check identity requires selected semantic evidence');
  const identity = envelope.semantic.evaluation.comparison.base.identity;
  const unsigned = {
    version: 1 as const,
    installationId: envelope.work.installationId,
    repositoryId: envelope.phase6Match.repositoryId,
    pullNumber: envelope.phase6Match.pullNumber,
    baseRepositoryId: envelope.phase6Match.baseRepositoryId,
    baseRef: envelope.phase6Match.baseRef,
    baseSha: envelope.phase6Match.baseSha,
    headRepositoryId: envelope.phase6Match.headRepositoryId,
    headSha: envelope.phase6Match.headSha,
    topology: envelope.phase6Match.topology,
    evaluatorIdentity: envelope.work.evaluatorIdentity,
    engineId: identity.engineId,
    analyzer: structuredClone(identity.analyzer),
    catalogAuthorizedScopeSha256: identity.catalogAuthorizedScopeSha256,
    effectiveConfigSha256: envelope.semantic.evaluation.authority.identity,
  };
  const correlationId = `boundaryci:v1:${createHash('sha256').update(canonicalJson(unsigned as unknown as JsonValue), 'utf8').digest('hex')}`;
  const result = Object.freeze({ ...unsigned, correlationId });
  validateCheckIdentity(result);
  return result;
}

export function validateCheckIdentity(value: unknown): asserts value is CheckIdentityV1 {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new TypeError('Check identity must be an object');
  const record = value as Record<string, unknown>;
  if (!exactKeys(record, ['analyzer', 'baseRef', 'baseRepositoryId', 'baseSha', 'catalogAuthorizedScopeSha256', 'correlationId', 'effectiveConfigSha256', 'engineId', 'evaluatorIdentity', 'headRepositoryId', 'headSha', 'installationId', 'pullNumber', 'repositoryId', 'topology', 'version'])) throw new TypeError('Check identity has an unsafe shape');
  if (record.version !== 1 || !positiveInteger(record.installationId) || !positiveInteger(record.repositoryId) || !positiveInteger(record.pullNumber) || !positiveInteger(record.baseRepositoryId) || !positiveInteger(record.headRepositoryId) || !safeString(record.baseRef, 256) || !SHA.test(record.baseSha as string) || !SHA.test(record.headSha as string) || (record.topology !== 'same-repository' && record.topology !== 'unsupported-topology') || !safeString(record.evaluatorIdentity, 256) || !safeString(record.engineId, 256) || typeof record.analyzer !== 'object' || record.analyzer === null || Array.isArray(record.analyzer) || !DIGEST.test(record.catalogAuthorizedScopeSha256 as string) || !DIGEST.test(record.effectiveConfigSha256 as string) || typeof record.correlationId !== 'string' || !/^boundaryci:v1:[a-f0-9]{64}$/u.test(record.correlationId)) throw new TypeError('Check identity is invalid');
}

/** Rejects raw/unknown fields before an API adapter is permitted to receive a Check payload. */
export function validateCompletedCheckPayload(value: unknown): asserts value is CompletedCheckPayloadV1 {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new TypeError('completed Check payload must be an object');
  const record = value as Record<string, unknown>;
  if (!exactKeys(record, ['annotations', 'conclusion', 'externalId', 'headSha', 'name', 'status', 'summary', 'text', 'title'])) throw new TypeError('completed Check payload has an unsafe shape');
  if (record.name !== CHECK_NAME || !SHA.test(record.headSha as string) || record.status !== 'completed' || !['success', 'failure', 'neutral', 'action_required'].includes(record.conclusion as string) || !['Permission boundary unchanged', 'Permission boundary reduced', 'Permission expansion permitted', 'Permission expansion requires review', 'Repository policy failed', 'Analysis incomplete', 'BoundaryCI could not evaluate this change'].includes(record.title as string) || !safeString(record.summary, 60_000) || Buffer.byteLength(record.summary, 'utf8') > 60_000 || typeof record.text !== 'string' || Buffer.byteLength(record.text, 'utf8') > 60_000 || typeof record.externalId !== 'string' || !/^boundaryci:v1:[a-f0-9]{64}$/u.test(record.externalId) || !Array.isArray(record.annotations) || record.annotations.length > 50) throw new TypeError('completed Check payload is invalid');
  for (const annotation of record.annotations) {
    if (typeof annotation !== 'object' || annotation === null || Array.isArray(annotation) || !exactKeys(annotation as Record<string, unknown>, ['endLine', 'level', 'message', 'operationId', 'path', 'startLine', 'title'])) throw new TypeError('Check annotation has an unsafe shape');
    const item = annotation as Record<string, unknown>;
    if (!safeString(item.path, 4_096) || !positiveInteger(item.startLine) || !positiveInteger(item.endLine) || (item.endLine as number) < (item.startLine as number) || !['notice', 'warning', 'failure'].includes(item.level as string) || !['Permitted permission expansion', 'Permission policy failure', 'Incomplete analysis evidence', 'BoundaryCI diagnostic'].includes(item.title as string) || !safeString(item.message, 60_000) || !safeString(item.operationId, 256)) throw new TypeError('Check annotation is invalid');
  }
}
