import type { DeliveryEnvelopeV1 } from './contract.js';
import { CHECK_NAME, type CheckAnnotationV1, type CheckConclusion, type CheckIdentityV1, type CheckTitle, type CompletedCheckPayloadV1, validateCompletedCheckPayload } from './check-contract.js';

function changeLine(change: { permission: string; base: string; head: string; change: string }): string {
  const direction = `${change.base} → ${change.head}`;
  return `- ${change.change === 'expansion' ? 'Expansion' : change.change === 'reduction' ? 'Reduction' : 'Unchanged'}: ${change.permission}: ${direction}.`;
}

/** Purely projects validated semantic evidence into fixed Check copy; it never reads source or configuration. */
export function renderCompletedCheck(envelope: Extract<DeliveryEnvelopeV1, { handoff: 'publishable-semantic' }>, identity: CheckIdentityV1): CompletedCheckPayloadV1 {
  const evaluation = envelope.semantic.evaluation;
  if (evaluation.status !== 'selected' || evaluation.comparison.status !== 'complete') throw new TypeError('tracer renderer accepts only complete semantic evidence');
  const policy = evaluation.policy;
  const expansion = evaluation.comparison.changes.find((change) => change.change === 'expansion');
  if (policy.outcome !== 'policy-failure' || policy.check !== 'fail' || !policy.reasons.includes('expansion-not-permitted') || expansion === undefined) {
    throw new TypeError('tracer renderer accepts only policy-failing expansions');
  }
  const contributor = expansion.headContributors.find((finding) => finding.status === 'resolved');
  if (contributor === undefined) throw new TypeError('policy-failing expansion requires current-head resolved evidence');
  const annotation: CheckAnnotationV1 = Object.freeze({
    path: contributor.source.path,
    startLine: contributor.source.span.start.line,
    endLine: contributor.source.span.end.line,
    level: 'failure',
    title: 'Permission policy failure',
    message: `${contributor.operation.operationId} contributes to ${expansion.permission}: ${expansion.base} → ${expansion.head}, which repository policy rejects.`,
    operationId: contributor.operation.operationId,
  });
  const conclusion: CheckConclusion = 'failure';
  const title: CheckTitle = 'Permission expansion requires review';
  const summary = [
    '## BoundaryCI result', 'Repository policy rejects the observed permission expansion.', '',
    '## Policy', `- failOnExpansion: ${String(policy.policy.failOnExpansion)}`, `- failOnIncomplete: ${String(policy.policy.failOnIncomplete)}`, '- decision: fail-expansion', '',
    '## Aggregate permission changes', ...evaluation.comparison.changes.map(changeLine), '',
    '## Annotation coverage', '- Annotations: eligible 1; selected for an initial create 1; omitted 0.', '',
    '## Comparison', `- base/head: ${envelope.phase6Match.baseSha} / ${envelope.phase6Match.headSha}`, `- correlation: ${identity.correlationId}`, '',
    '## Publication status', '- status: pending-upsert',
  ].join('\n');
  const payload: CompletedCheckPayloadV1 = Object.freeze({
    name: CHECK_NAME, headSha: envelope.phase6Match.headSha, status: 'completed', conclusion, title, summary,
    text: ['## Evidence details', '### Permission evidence', `- ${contributor.operation.operationId}: current-head evidence contributes to ${expansion.permission}: ${expansion.base} → ${expansion.head}.`].join('\n'),
    externalId: identity.correlationId, annotations: Object.freeze([annotation]),
  });
  validateCompletedCheckPayload(payload);
  return payload;
}
