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
  deriveCheckCorrelationId,
  validateCheckIdentity,
  validateCompletedCheckPayload,
} from './check-contract.js';

export const CHECK_SUMMARY_UTF8_LIMIT = 60_000;
export const CHECK_DETAILS_UTF8_LIMIT = 60_000;
export const CHECK_DETAILS_RECORD_LIMIT = 500;
export const CHECK_ANNOTATION_LIMIT = 50;

type SemanticEnvelope = Extract<DeliveryEnvelopeV1, { handoff: 'publishable-semantic' }>;
type DiagnosticEnvelope = Extract<DeliveryEnvelopeV1, { handoff: 'diagnostic-only' }>;
type RenderableEnvelope = SemanticEnvelope | DiagnosticEnvelope;
type DetailRecord = { section: 'permission' | 'not-annotated'; line: string };
type AnnotationCandidate = { annotation: CheckAnnotationV1; stableEvidenceId: string };
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
  if (typeof record.path !== 'string' || record.path.length === 0 || record.path.length > 4_096 || /[\u0000-\u001F\u007F]/u.test(record.path) || record.path.startsWith('/') || record.path.split('/').includes('..')) throw new TypeError('annotation path is invalid');
  if (!Number.isSafeInteger(record.startLine) || !Number.isSafeInteger(record.endLine) || (record.startLine as number) <= 0 || (record.endLine as number) < (record.startLine as number)) throw new TypeError('annotation span is invalid');
  if (record.level !== 'notice' && record.level !== 'warning' && record.level !== 'failure') throw new TypeError('annotation level is invalid');
  if (record.title !== 'Permitted permission expansion' && record.title !== 'Permission policy failure' && record.title !== 'Incomplete analysis evidence' && record.title !== 'BoundaryCI diagnostic') throw new TypeError('annotation title is invalid');
  if (typeof record.operationId !== 'string' || record.operationId.length === 0 || record.operationId.length > 256 || typeof record.message !== 'string' || record.message.length === 0 || utf8Length(record.message) > CHECK_DETAILS_UTF8_LIMIT) throw new TypeError('annotation text is invalid');
}

function selectAnnotationCandidates(candidates: readonly AnnotationCandidate[]): readonly CheckAnnotationV1[] {
  const sorted = candidates.map((candidate) => {
    exactAnnotation(candidate.annotation);
    if (typeof candidate.stableEvidenceId !== 'string' || candidate.stableEvidenceId.length === 0) throw new TypeError('annotation candidate identity is invalid');
    return Object.freeze({ annotation: Object.freeze(structuredClone(candidate.annotation)), stableEvidenceId: candidate.stableEvidenceId });
  }).sort((left, right) =>
    compare(annotationLevelOrder[left.annotation.level], annotationLevelOrder[right.annotation.level]) ||
    compare(left.annotation.path.normalize('NFC'), right.annotation.path.normalize('NFC')) ||
    compare(left.annotation.startLine, right.annotation.startLine) ||
    compare(left.annotation.endLine, right.annotation.endLine) ||
    compare(left.annotation.operationId, right.annotation.operationId) ||
    compare(left.stableEvidenceId, right.stableEvidenceId),
  );
  return Object.freeze(sorted.slice(0, CHECK_ANNOTATION_LIMIT).map((candidate) => candidate.annotation));
}

/** Selects the full normalized set deterministically before applying GitHub's one-create limit. */
export function selectCheckAnnotations(candidates: readonly CheckAnnotationV1[]): readonly CheckAnnotationV1[] {
  if (!Array.isArray(candidates)) throw new TypeError('annotation candidates must be an array');
  return selectAnnotationCandidates(candidates.map((annotation) => ({ annotation, stableEvidenceId: `${annotation.level}\0${annotation.title}\0${annotation.path}\0${annotation.startLine}\0${annotation.endLine}\0${annotation.operationId}` })));
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

function evidenceRecords(evaluation: SelectedEvaluation, failing: boolean): { readonly records: readonly DetailRecord[]; readonly candidates: readonly AnnotationCandidate[] } {
  const { comparison } = evaluation;
  const changes = comparison.status === 'complete' ? comparison.changes : comparison.status === 'incomplete' ? comparison.qualifiedChanges : [];
  const records: Array<DetailRecord & { annotation: CheckAnnotationV1 | null }> = [];
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
      section: currentHead ? 'permission' : 'not-annotated',
      line: currentHead
        ? `- ${operationId}: ${change === undefined ? `incomplete evidence (${contributor.status})` : `${change.permission} ${change.base} → ${change.head}`}; ${unresolved ? 'incomplete' : 'current-head'} evidence at ${inlineCode(contributor.source.path)}.`
        : `- ${statement} ${inlineCode(contributor.source.path)}.`,
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
  records.sort((left, right) => compare(left.section, right.section) || compare(left.line, right.line));
  return Object.freeze({ records: Object.freeze(records.map(({ section, line }) => Object.freeze({ section, line }))), candidates: Object.freeze(records.flatMap((record) => record.annotation === null ? [] : [{ annotation: record.annotation, stableEvidenceId: `${record.section}\0${record.line}` }])) });
}

function boundedDetails(records: readonly DetailRecord[]): string {
  const render = (included: readonly DetailRecord[], truncation?: string): string => {
    const permission = included.filter((record) => record.section === 'permission').map((record) => record.line);
    const notAnnotated = included.filter((record) => record.section === 'not-annotated').map((record) => record.line);
    return [
      '## Evidence details', '### Permission evidence', ...(permission.length === 0 ? ['- None.'] : permission),
      '### Incomplete or diagnostic reasons', '- None.',
      '### Evidence not annotated', ...(notAnnotated.length === 0 ? ['- None.'] : notAnnotated),
      ...(truncation === undefined ? [] : ['### Detail limits', truncation]),
    ].join('\n');
  };
  const included: DetailRecord[] = [];
  let bound: 'item' | 'UTF-8 byte' | undefined;
  for (const record of records) {
    if (included.length === CHECK_DETAILS_RECORD_LIMIT) {
      bound = 'item';
      break;
    }
    if (utf8Length(render([...included, record])) > CHECK_DETAILS_UTF8_LIMIT) {
      bound = 'UTF-8 byte';
      break;
    }
    included.push(record);
  }
  while (included.length < records.length) {
    const omitted = records.length - included.length;
    const marker = `- Details truncated: ${omitted} complete record(s) omitted by the ${bound ?? 'UTF-8 byte'} bound.`;
    if (utf8Length(render(included, marker)) <= CHECK_DETAILS_UTF8_LIMIT) return render(included, marker);
    if (included.length === 0) throw new TypeError('details cannot reserve a truncation record within the UTF-8 limit');
    included.pop();
    bound = 'UTF-8 byte';
  }
  const text = render(included);
  if (utf8Length(text) > CHECK_DETAILS_UTF8_LIMIT) throw new TypeError('details cannot be rendered within the UTF-8 limit');
  return text;
}

function validateRendererIdentity(envelope: RenderableEnvelope, identity: CheckIdentityV1): void {
  validateCheckIdentity(identity);
  const { phase6Match, work } = envelope;
  if (identity.installationId !== work.installationId || identity.repositoryId !== phase6Match.repositoryId || identity.pullNumber !== phase6Match.pullNumber || identity.baseRepositoryId !== phase6Match.baseRepositoryId || identity.baseRef !== phase6Match.baseRef || identity.baseSha !== phase6Match.baseSha || identity.headRepositoryId !== phase6Match.headRepositoryId || identity.headSha !== phase6Match.headSha || identity.topology !== phase6Match.topology || identity.evaluatorIdentity !== work.evaluatorIdentity) {
    throw new TypeError('Check identity does not match the current delivery envelope');
  }
  if (envelope.handoff === 'publishable-semantic' && deriveCheckCorrelationId(envelope).correlationId !== identity.correlationId) {
    throw new TypeError('Check correlation does not match semantic evidence');
  }
}

function diagnosticResult(envelope: DiagnosticEnvelope): { conclusion: CheckConclusion; title: CheckTitle; result: string; reason: string } {
  const prose: Readonly<Record<DiagnosticEnvelope['diagnostic']['code'], string>> = {
    'input-configuration-failure': 'The base BoundaryCI configuration is invalid. Correct the base configuration and rerun the pull request check.',
    'acquisition-runtime-failure': 'BoundaryCI could not acquire the bounded comparison input. Rerun the pull request check.',
    'evaluator-runtime-failure': 'BoundaryCI could not evaluate the bounded comparison input. Rerun the pull request check.',
    'unsupported-topology': 'External-fork source analysis is not supported for this pull request.',
  };
  return {
    conclusion: 'action_required',
    title: 'BoundaryCI could not evaluate this change',
    result: 'BoundaryCI could not establish a trustworthy policy result for this pull request.',
    reason: `- ${envelope.diagnostic.code}: ${prose[envelope.diagnostic.code]}`,
  };
}

/** Purely projects exact normalized semantic or diagnostic evidence into fixed, source-free Check copy. */
export function renderCompletedCheck(envelope: RenderableEnvelope, identity: CheckIdentityV1): CompletedCheckPayloadV1 {
  validateDeliveryEnvelope(envelope);
  validateRendererIdentity(envelope, identity);
  if (envelope.handoff === 'diagnostic-only') {
    const outcome = diagnosticResult(envelope);
    const summary = [
      '## BoundaryCI result', outcome.result, '',
      '## Policy', '- failOnExpansion: not-evaluated', '- failOnIncomplete: not-evaluated', '- decision: not-evaluated', '',
      '## Aggregate permission changes', '- Known permission changes: none.', '- Unresolved/incomplete operations: 0.', '',
      '## Annotation coverage', '- Annotations: eligible 0; selected for an initial create 0; omitted 0.', '- Selected: failure 0; warning 0; notice 0.', '- Omitted: failure 0; warning 0; notice 0.', '- Classes: permitted expansion 0; policy failure 0; incomplete analysis 0; diagnostic 0.', '',
      '## Comparison', `- base/head: ${envelope.phase6Match.baseSha} / ${envelope.phase6Match.headSha}`, `- correlation: ${identity.correlationId}`, '',
      '## Publication status', '- status: pending-upsert',
    ].join('\n');
    const payload: CompletedCheckPayloadV1 = Object.freeze({ name: CHECK_NAME, headSha: envelope.phase6Match.headSha, status: 'completed', conclusion: outcome.conclusion, title: outcome.title, summary, text: ['## Evidence details', '### Permission evidence', '- None.', '### Incomplete or diagnostic reasons', outcome.reason, '### Evidence not annotated', '- None.'].join('\n'), externalId: identity.correlationId, annotations: Object.freeze([]) });
    validateCompletedCheckPayload(payload);
    return payload;
  }
  if (envelope.semantic.evaluation.status !== 'selected') throw new TypeError('renderer accepts only selected semantic evidence');
  const evaluation = envelope.semantic.evaluation;
  const outcome = requiredOutcome(evaluation);
  const { comparison } = evaluation;
  const changes = comparison.status === 'complete' ? comparison.changes : comparison.status === 'incomplete' ? comparison.qualifiedChanges : [];
  const evidence = evidenceRecords(evaluation, outcome.conclusion === 'failure');
  const annotations = selectAnnotationCandidates(evidence.candidates);
  const omitted = evidence.candidates.length - annotations.length;
  const aggregate = [...changes].sort((left, right) => compare(left.permission, right.permission) || compare(left.change, right.change)).map(changeLine);
  const { policy } = evaluation;
  const decision = policy.check === 'fail'
    ? policy.reasons.includes('expansion-not-permitted') ? 'fail-expansion' : 'fail-incomplete'
    : policy.outcome === 'incomplete' ? 'permit-incomplete' : 'pass';
  const summary = [
    '## BoundaryCI result', outcome.result, '',
    '## Policy', `- failOnExpansion: ${String(policy.policy.failOnExpansion)}`, `- failOnIncomplete: ${String(policy.policy.failOnIncomplete)}`, `- decision: ${decision}`, '',
    '## Aggregate permission changes', ...(aggregate.length === 0 ? ['- Known permission changes: none.'] : aggregate), `- Unresolved/incomplete operations: ${comparison.status === 'incomplete' ? comparison.reasons.length : 0}.`, '',
    '## Annotation coverage', `- Annotations: eligible ${evidence.candidates.length}; selected for an initial create ${annotations.length}; omitted ${omitted}.`, `- Selected: failure ${annotations.filter((item) => item.level === 'failure').length}; warning ${annotations.filter((item) => item.level === 'warning').length}; notice ${annotations.filter((item) => item.level === 'notice').length}.`, `- Omitted: failure ${evidence.candidates.filter((item) => item.annotation.level === 'failure').length - annotations.filter((item) => item.level === 'failure').length}; warning ${evidence.candidates.filter((item) => item.annotation.level === 'warning').length - annotations.filter((item) => item.level === 'warning').length}; notice ${evidence.candidates.filter((item) => item.annotation.level === 'notice').length - annotations.filter((item) => item.level === 'notice').length}.`, `- Classes: permitted expansion ${annotations.filter((item) => item.title === 'Permitted permission expansion').length}; policy failure ${annotations.filter((item) => item.title === 'Permission policy failure').length}; incomplete analysis ${annotations.filter((item) => item.title === 'Incomplete analysis evidence').length}; diagnostic 0.`, '',
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
    text: boundedDetails(evidence.records),
    externalId: identity.correlationId,
    annotations,
  });
  validateCompletedCheckPayload(payload);
  return payload;
}
