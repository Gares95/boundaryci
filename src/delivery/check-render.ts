import type { DeliveryEnvelopeV1 } from './contract.js';
import { validateDeliveryEnvelope } from './contract.js';
import type { LocalComparisonResult } from '../runtime/evaluate.js';
import {
  CHECK_NAME,
  type CheckAnnotationV1,
  type CheckConclusion,
  type CheckIdentityV1,
  type CheckTitle,
  type CompletedCheckPayloadV1,
  validateCompletedCheckPayload,
} from './check-contract.js';

export const CHECK_SUMMARY_UTF8_LIMIT = 60_000;
export const CHECK_DETAILS_UTF8_LIMIT = 60_000;
export const CHECK_DETAILS_RECORD_LIMIT = 500;
export const CHECK_ANNOTATION_LIMIT = 50;

type SemanticEnvelope = Extract<DeliveryEnvelopeV1, { handoff: 'publishable-semantic' }>;
type SelectedEvaluation = Extract<LocalComparisonResult, { status: 'selected' }>;

const annotationLevelOrder: Readonly<Record<CheckAnnotationV1['level'], number>> = {
  failure: 0,
  warning: 1,
  notice: 2,
};

function utf8Length(value: string): number {
  return Buffer.byteLength(value, 'utf8');
}

function compare(left: string | number, right: string | number): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function exactAnnotation(value: unknown): asserts value is CheckAnnotationV1 {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new TypeError('annotation must be an object');
  const record = value as Record<string, unknown>;
  const expected = ['endLine', 'level', 'message', 'operationId', 'path', 'startLine', 'title'];
  const keys = Object.keys(record).sort();
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) throw new TypeError('annotation has an unsafe shape');
  if (typeof record.path !== 'string' || record.path.length === 0 || record.path.length > 4_096 || record.path.includes('\0') || record.path.startsWith('/') || record.path.split('/').includes('..')) throw new TypeError('annotation path is invalid');
  if (!Number.isSafeInteger(record.startLine) || !Number.isSafeInteger(record.endLine) || (record.startLine as number) <= 0 || (record.endLine as number) < (record.startLine as number)) throw new TypeError('annotation span is invalid');
  if (record.level !== 'notice' && record.level !== 'warning' && record.level !== 'failure') throw new TypeError('annotation level is invalid');
  if (record.title !== 'Permitted permission expansion' && record.title !== 'Permission policy failure' && record.title !== 'Incomplete analysis evidence' && record.title !== 'BoundaryCI diagnostic') throw new TypeError('annotation title is invalid');
  if (typeof record.operationId !== 'string' || record.operationId.length === 0 || record.operationId.length > 256 || typeof record.message !== 'string' || record.message.length === 0 || utf8Length(record.message) > CHECK_DETAILS_UTF8_LIMIT) throw new TypeError('annotation text is invalid');
}

/** Selects the full normalized set deterministically before applying GitHub's one-create limit. */
export function selectCheckAnnotations(candidates: readonly CheckAnnotationV1[]): readonly CheckAnnotationV1[] {
  if (!Array.isArray(candidates)) throw new TypeError('annotation candidates must be an array');
  const sorted = candidates.map((candidate) => {
    exactAnnotation(candidate);
    return Object.freeze(structuredClone(candidate));
  }).sort((left, right) =>
    compare(annotationLevelOrder[left.level], annotationLevelOrder[right.level]) ||
    compare(left.path.normalize('NFC'), right.path.normalize('NFC')) ||
    compare(left.startLine, right.startLine) ||
    compare(left.endLine, right.endLine) ||
    compare(left.operationId, right.operationId) ||
    compare(left.message, right.message),
  );
  return Object.freeze(sorted.slice(0, CHECK_ANNOTATION_LIMIT));
}

function inlineCode(value: string): string {
  const runs = value.match(/`+/gu) ?? [];
  const delimiter = '`'.repeat(Math.max(0, ...runs.map((run) => run.length)) + 1);
  return value.startsWith('`') || value.endsWith('`') ? `${delimiter} ${value} ${delimiter}` : `${delimiter}${value}${delimiter}`;
}

function changeLine(change: { permission: string; base: string; head: string; change: string }): string {
  const direction = `${change.base} → ${change.head}`;
  const label = change.change === 'expansion' ? 'Expansion' : change.change === 'reduction' ? 'Reduction' : 'Unchanged';
  return `- ${label}: ${change.permission}: ${direction}.`;
}

function safeOperationId(value: unknown): value is string {
  return typeof value === 'string' && /^[a-z0-9][a-z0-9/-]{0,255}$/u.test(value);
}

function sourceAnnotation(
  contributor: { status: string; operation: { operationId: string } | null; source: { path: string; span: { start: { line: number }; end: { line: number } } } | null },
  level: CheckAnnotationV1['level'],
  title: CheckAnnotationV1['title'],
  message: string,
): CheckAnnotationV1 | null {
  if (contributor.source === null || contributor.operation === null || !safeOperationId(contributor.operation.operationId)) return null;
  const annotation: CheckAnnotationV1 = {
    path: contributor.source.path,
    startLine: contributor.source.span.start.line,
    endLine: contributor.source.span.end.line,
    level,
    title,
    message,
    operationId: contributor.operation.operationId,
  };
  try {
    exactAnnotation(annotation);
    return Object.freeze(annotation);
  } catch {
    return null;
  }
}

function requiredOutcome(evaluation: SelectedEvaluation): { conclusion: CheckConclusion; title: CheckTitle; result: string } {
  const { policy, comparison } = evaluation;
  if (policy.outcome === 'policy-failure') {
    const changes = comparison.status === 'complete' ? comparison.changes : comparison.status === 'incomplete' ? comparison.qualifiedChanges : [];
    if (changes.some((change) => change.change === 'expansion')) return { conclusion: 'failure', title: 'Permission expansion requires review', result: 'Repository policy rejects the observed permission expansion.' };
    return { conclusion: 'failure', title: 'Repository policy failed', result: 'Repository policy rejected the established result.' };
  }
  if (policy.outcome === 'incomplete') return { conclusion: 'neutral', title: 'Analysis incomplete', result: 'BoundaryCI could not prove a complete observed permission boundary.' };
  if (policy.outcome !== 'complete' || comparison.status !== 'complete') throw new TypeError('semantic outcome is not renderable');
  if (comparison.changes.some((change) => change.change === 'expansion')) return { conclusion: 'success', title: 'Permission expansion permitted', result: 'Repository policy permits the observed permission expansion; review the contributing evidence below.' };
  if (comparison.changes.some((change) => change.change === 'reduction')) return { conclusion: 'success', title: 'Permission boundary reduced', result: 'Observed permission-boundary reductions are listed below.' };
  return { conclusion: 'success', title: 'Permission boundary unchanged', result: 'No permission-boundary changes were observed.' };
}

function evidenceRecords(evaluation: SelectedEvaluation, failing: boolean): { readonly lines: readonly string[]; readonly annotations: readonly CheckAnnotationV1[] } {
  const { comparison } = evaluation;
  const changes = comparison.status === 'complete' ? comparison.changes : comparison.status === 'incomplete' ? comparison.qualifiedChanges : [];
  const records: Array<{ line: string; annotation: CheckAnnotationV1 | null }> = [];
  const seen = new Set<string>();
  const add = (contributor: { status: string; operation: { operationId: string } | null; source: { path: string; span: { start: { line: number }; end: { line: number } } } | null }, change?: { permission: string; base: string; head: string; change: string }, currentHead = true): void => {
    if (contributor.source === null || contributor.operation === null || !safeOperationId(contributor.operation.operationId)) return;
    const operationId = contributor.operation.operationId;
    const key = `${contributor.status}\0${operationId}\0${contributor.source.path}\0${contributor.source.span.start.line}\0${contributor.source.span.end.line}`;
    if (seen.has(key)) return;
    seen.add(key);
    const unresolved = contributor.status !== 'resolved';
    const eligible = currentHead && (unresolved || change?.change === 'expansion');
    const level: CheckAnnotationV1['level'] = unresolved ? (failing ? 'failure' : 'warning') : (failing ? 'failure' : 'notice');
    const title: CheckAnnotationV1['title'] = failing
      ? 'Permission policy failure'
      : unresolved ? 'Incomplete analysis evidence' : 'Permitted permission expansion';
    const statement = change === undefined
      ? `${operationId} could not be fully resolved: ${contributor.status}${failing ? ', which repository policy rejects.' : '.'}`
      : currentHead
        ? `${operationId} contributes to ${change.permission}: ${change.base} → ${change.head}${change.change === 'expansion' ? (failing ? ', which repository policy rejects.' : '; repository policy permits this expansion.') : '.'}`
        : `${operationId} is base-only evidence for ${change.permission}: ${change.base} → ${change.head}; no truthful current-head navigation location exists.`;
    records.push({
      line: `- ${statement} current-head evidence at ${inlineCode(contributor.source.path)}.`,
      annotation: eligible ? sourceAnnotation(contributor, level, title, statement) : null,
    });
  };
  for (const change of changes) {
    for (const contributor of change.headContributors) add(contributor, change);
    for (const contributor of change.baseContributors) add(contributor, change, false);
  }
  if (comparison.status === 'incomplete' && comparison.boundary.status === 'incomplete' && comparison.boundary.head.status === 'incomplete') {
    for (const contributor of comparison.boundary.head.findings) add(contributor);
  }
  records.sort((left, right) => compare(left.line, right.line));
  return Object.freeze({ lines: Object.freeze(records.map((record) => record.line)), annotations: Object.freeze(records.flatMap((record) => record.annotation === null ? [] : [record.annotation])) });
}

function boundedDetails(records: readonly string[]): string {
  const prefix = ['## Evidence details', '### Permission evidence'];
  const suffix = ['### Incomplete or diagnostic reasons', '- None.', '### Evidence not annotated', '- None.'];
  const included: string[] = [];
  let byteOmitted = false;
  for (const record of records) {
    const candidate = [...prefix, ...included, record, ...suffix].join('\n');
    if (included.length >= CHECK_DETAILS_RECORD_LIMIT || utf8Length(candidate) > CHECK_DETAILS_UTF8_LIMIT) {
      byteOmitted = included.length < CHECK_DETAILS_RECORD_LIMIT;
      break;
    }
    included.push(record);
  }
  const omitted = records.length - included.length;
  const lines = [...prefix, ...included, ...suffix];
  if (omitted > 0) lines.push('### Detail limits', `- Details truncated: ${omitted} complete record(s) omitted by the ${byteOmitted ? 'UTF-8 byte' : 'item'} bound.`);
  const text = lines.join('\n');
  if (utf8Length(text) > CHECK_DETAILS_UTF8_LIMIT) throw new TypeError('details cannot be rendered within the UTF-8 limit');
  return text;
}

/** Purely projects exact normalized semantic evidence into fixed, source-free Check copy. */
export function renderCompletedCheck(envelope: SemanticEnvelope, identity: CheckIdentityV1): CompletedCheckPayloadV1 {
  validateDeliveryEnvelope(envelope);
  if (envelope.handoff !== 'publishable-semantic' || envelope.semantic.evaluation.status !== 'selected') throw new TypeError('renderer accepts only validated semantic evidence');
  const evaluation = envelope.semantic.evaluation;
  const outcome = requiredOutcome(evaluation);
  const { comparison } = evaluation;
  const changes = comparison.status === 'complete' ? comparison.changes : comparison.status === 'incomplete' ? comparison.qualifiedChanges : [];
  const evidence = evidenceRecords(evaluation, outcome.conclusion === 'failure');
  const annotations = selectCheckAnnotations(evidence.annotations);
  const omitted = evidence.annotations.length - annotations.length;
  const aggregate = [...changes].sort((left, right) => compare(left.permission, right.permission) || compare(left.change, right.change)).map(changeLine);
  const { policy } = evaluation;
  const decision = policy.check === 'fail'
    ? policy.reasons.includes('expansion-not-permitted') ? 'fail-expansion' : 'fail-incomplete'
    : policy.outcome === 'incomplete' ? 'permit-incomplete' : 'pass';
  const summary = [
    '## BoundaryCI result', outcome.result, '',
    '## Policy', `- failOnExpansion: ${String(policy.policy.failOnExpansion)}`, `- failOnIncomplete: ${String(policy.policy.failOnIncomplete)}`, `- decision: ${decision}`, '',
    '## Aggregate permission changes', ...(aggregate.length === 0 ? ['- Known permission changes: none.'] : aggregate), `- Unresolved/incomplete operations: ${comparison.status === 'incomplete' ? comparison.reasons.length : 0}.`, '',
    '## Annotation coverage', `- Annotations: eligible ${evidence.annotations.length}; selected for an initial create ${annotations.length}; omitted ${omitted}.`, `- Selected: failure ${annotations.filter((item) => item.level === 'failure').length}; warning ${annotations.filter((item) => item.level === 'warning').length}; notice ${annotations.filter((item) => item.level === 'notice').length}.`, `- Classes: permitted expansion ${annotations.filter((item) => item.title === 'Permitted permission expansion').length}; policy failure ${annotations.filter((item) => item.title === 'Permission policy failure').length}; incomplete analysis ${annotations.filter((item) => item.title === 'Incomplete analysis evidence').length}; diagnostic 0.`, '',
    '## Comparison', `- base/head: ${envelope.phase6Match.baseSha} / ${envelope.phase6Match.headSha}`, `- correlation: ${identity.correlationId}`, '',
    '## Publication status', '- status: pending-upsert',
  ].join('\n');
  if (utf8Length(summary) > CHECK_SUMMARY_UTF8_LIMIT) throw new TypeError('aggregate summary exceeds the UTF-8 limit');
  const payload: CompletedCheckPayloadV1 = Object.freeze({
    name: CHECK_NAME,
    headSha: envelope.phase6Match.headSha,
    status: 'completed',
    conclusion: outcome.conclusion,
    title: outcome.title,
    summary,
    text: boundedDetails(evidence.lines),
    externalId: identity.correlationId,
    annotations,
  });
  validateCompletedCheckPayload(payload);
  return payload;
}
