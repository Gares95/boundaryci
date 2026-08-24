import { canonicalJson, digestJson } from './artifact-sources.js';
import {
  assertExactKeys,
  assertPlainObject,
  assertSha256,
  type JsonValue,
} from './contracts.js';
import { validateSupportManifest, type SupportManifest } from './inventory.js';
import type { AuthorizedScopeMember, FeasibilityPacket } from './ledger.js';

export type FeasibilityOutcome = 'GO' | 'GO WITH BOUNDED SUPPORT' | 'NO-GO / RESCOPE';

export interface IndependentReviewInput {
  reviewer: string;
  reviewedAt: string;
  verdict: 'APPROVED';
  reviewResultSha256: string;
  reviewPromptSha256: string;
  highFindings: 0;
  blockingMediumFindings: 0;
  hardInvariantViolations: 0;
}

interface DecisionInputCommon {
  schemaVersion: 1;
  terminalDecision: FeasibilityOutcome;
  review: IndependentReviewInput;
  decisionMaker: string;
  decidedAt: string;
  feasibilityPacketSha256: string;
  supportPredicateSha256: string;
  selectionSha256: string;
  rationale: string;
  wordingAccepted: true;
}

export interface GoDecisionInput extends DecisionInputCommon {
  terminalDecision: 'GO';
  authorizedScopeSha256: string;
  usefulnessAccepted: true;
  usefulnessRationale: string;
}

export interface BoundedGoDecisionInput extends DecisionInputCommon {
  terminalDecision: 'GO WITH BOUNDED SUPPORT';
  authorizedScopeSha256: string;
  usefulnessAccepted: boolean;
  usefulnessRationale: string;
  excludedIncompleteClasses: string[];
}

export interface NoGoDecisionInput extends DecisionInputCommon {
  terminalDecision: 'NO-GO / RESCOPE';
  blockedRescopeRationale: string;
}

export type FeasibilityDecisionInput = GoDecisionInput | BoundedGoDecisionInput | NoGoDecisionInput;

export interface FeasibilityDecisionContext {
  packet: FeasibilityPacket;
  supportManifest: SupportManifest;
}

export interface FeasibilityDecisionRecord {
  schemaVersion: 1;
  outcome: FeasibilityOutcome;
  review: {
    reviewer: 'Independent feasibility reviewer';
    reviewedAt: string;
    verdict: 'APPROVED';
  };
  decisionMaker: string;
  decidedAt: string;
  evidence: {
    feasibilityPacketSha256: string;
    supportManifestSha256: string;
    supportPredicateSha256: string;
    selectionSha256: string;
  };
  rationale: string;
  wordingAccepted: true;
  usefulness: { accepted: true; rationale: string } | null;
  authorization:
    | {
        status: 'authorized-complete' | 'authorized-bounded';
        members: AuthorizedScopeMember[];
        authorizedScopeSha256: string;
      }
    | { status: 'blocked-rescope'; members: []; authorizedScopeSha256: null };
  excludedIncompleteClasses: string[];
  knownLimitations: string[];
  contentSha256: string;
}

const COMMON_INPUT_KEYS = [
  'schemaVersion',
  'terminalDecision',
  'review',
  'decisionMaker',
  'decidedAt',
  'feasibilityPacketSha256',
  'supportPredicateSha256',
  'selectionSha256',
  'rationale',
  'wordingAccepted',
] as const;

const PUBLIC_RECORD_KEYS = [
  'schemaVersion',
  'outcome',
  'review',
  'decisionMaker',
  'decidedAt',
  'evidence',
  'rationale',
  'wordingAccepted',
  'usefulness',
  'authorization',
  'excludedIncompleteClasses',
  'knownLimitations',
  'contentSha256',
] as const;

function assertNonemptyString(value: unknown, label: string): asserts value is string {
  if (typeof value !== 'string' || value.trim() !== value || value.length === 0) {
    throw new TypeError(`${label} must be a nonempty trimmed string`);
  }
  const placeholderWords = [['TO', 'DO'], ['T', 'BD'], ['FIX', 'ME']]
    .map((parts) => parts.join(''))
    .join('|');
  const placeholder = new RegExp(`\\b(?:${placeholderWords})\\b|<[^>]+>|\\{\\{[^}]+\\}\\}`, 'u');
  if (placeholder.test(value)) {
    throw new TypeError(`${label} contains a placeholder`);
  }
}

function assertIsoInstant(value: unknown, label: string): asserts value is string {
  assertNonemptyString(value, label);
  if (
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/u.test(value) ||
    new Date(value).toISOString().replace('.000Z', 'Z') !== value
  ) {
    throw new TypeError(`${label} must be a whole-second UTC ISO timestamp`);
  }
}

function assertStringArray(value: unknown, label: string): asserts value is string[] {
  if (!Array.isArray(value) || value.length === 0) throw new TypeError(`${label} must be a nonempty array`);
  const seen = new Set<string>();
  for (const entry of value) {
    assertNonemptyString(entry, `${label} entry`);
    if (seen.has(entry)) throw new TypeError(`${label} contains duplicate ${entry}`);
    seen.add(entry);
  }
}

function assertIndependentReview(value: unknown): asserts value is IndependentReviewInput {
  assertPlainObject(value, 'decision input.review');
  assertExactKeys(
    value,
    [
      'reviewer',
      'reviewedAt',
      'verdict',
      'reviewResultSha256',
      'reviewPromptSha256',
      'highFindings',
      'blockingMediumFindings',
      'hardInvariantViolations',
    ],
    'decision input.review',
  );
  assertNonemptyString(value.reviewer, 'decision input.review.reviewer');
  assertIsoInstant(value.reviewedAt, 'decision input.review.reviewedAt');
  if (value.verdict !== 'APPROVED') throw new TypeError('decision input review must be approved');
  assertSha256(value.reviewResultSha256, 'decision input review result digest');
  assertSha256(value.reviewPromptSha256, 'decision input review prompt digest');
  for (const key of ['highFindings', 'blockingMediumFindings', 'hardInvariantViolations'] as const) {
    if (value[key] !== 0) throw new Error(`decision input review has blocking ${key}`);
  }
}

function expectedExcludedClasses(packet: FeasibilityPacket): string[] {
  return [
    'permission-expression:allOf',
    'permission-expression:anyOf',
    'permission-evidence:ambiguous',
    'permission-evidence:conflicting',
    'permission-evidence:missing',
    'permission-evidence:unsupported',
    'freshness:stale-seed',
    'freshness:not-assessed',
    'credential:fine-grained-pat-only',
    'credential:none',
    'method-surface:v17-only',
    'method-surface:v18-only',
    'method-surface:surface-conflict',
    'operation-join:no-openapi-operation',
    'operation-join:duplicate-openapi-operation',
    ...packet.incompleteSemantics.reasons.map((reason) => `reason:${reason}`),
  ];
}

function assertContext(context: FeasibilityDecisionContext): void {
  validateSupportManifest(context.supportManifest);
  const packet = context.packet;
  assertSha256(packet.contentSha256, 'feasibility packet digest');
  const { contentSha256: _contentSha256, ...unsignedPacket } = packet;
  if (digestJson(unsignedPacket as unknown as JsonValue) !== packet.contentSha256) {
    throw new Error('feasibility packet content digest mismatch');
  }
  if (
    packet.support.strategy !== context.supportManifest.strategy ||
    packet.support.predicateSha256 !== context.supportManifest.predicate.ruleSha256 ||
    packet.support.preliminarySelectionSha256 !== context.supportManifest.selectionSha256
  ) {
    throw new Error('decision context support identity mismatch');
  }
  if (
    digestJson(packet.authorizedScopeCandidate.members as unknown as JsonValue) !==
    packet.authorizedScopeCandidate.authorizedScopeSha256
  ) {
    throw new Error('authorized scope candidate digest mismatch');
  }
  const selected = context.supportManifest.selectedMembers.map((member) => ({
    verb: member.verb,
    path: member.path,
    operationId: member.operationId,
    expressionSha256: member.expressionSha256,
    artifactManifestSha256: member.artifactManifestSha256,
    supportPredicateSha256: context.supportManifest.predicate.ruleSha256,
  }));
  for (const member of packet.authorizedScopeCandidate.members) {
    const match = selected.find((candidate) => candidate.operationId === member.operationId);
    if (
      match === undefined ||
      match.verb !== member.verb ||
      match.path !== member.path ||
      match.expressionSha256 !== member.expressionSha256 ||
      match.artifactManifestSha256 !== member.artifactManifestSha256 ||
      match.supportPredicateSha256 !== member.supportPredicateSha256
    ) {
      throw new Error(`authorized member ${member.operationId} does not match the support manifest`);
    }
  }
  if (selected.length !== packet.authorizedScopeCandidate.members.length) {
    throw new Error('authorized scope and selected-member cardinality mismatch');
  }
}

function assertCommonInput(value: Record<string, unknown>, context: FeasibilityDecisionContext): void {
  if (value.schemaVersion !== 1) throw new TypeError('decision input schema version mismatch');
  assertIndependentReview(value.review);
  assertNonemptyString(value.decisionMaker, 'decision input.decisionMaker');
  assertIsoInstant(value.decidedAt, 'decision input.decidedAt');
  if (new Date(value.review.reviewedAt).getTime() > new Date(value.decidedAt).getTime()) {
    throw new Error('decision cannot predate the independent review');
  }
  assertSha256(value.feasibilityPacketSha256, 'decision input packet digest');
  assertSha256(value.supportPredicateSha256, 'decision input predicate digest');
  assertSha256(value.selectionSha256, 'decision input selection digest');
  if (
    value.feasibilityPacketSha256 !== context.packet.contentSha256 ||
    value.supportPredicateSha256 !== context.supportManifest.predicate.ruleSha256 ||
    value.selectionSha256 !== context.supportManifest.selectionSha256
  ) {
    throw new Error('decision input does not bind the current reviewed evidence');
  }
  assertNonemptyString(value.rationale, 'decision input.rationale');
  if (value.wordingAccepted !== true) throw new TypeError('decision input wording must be accepted');
}

function assertExactExclusions(value: unknown, packet: FeasibilityPacket): asserts value is string[] {
  assertStringArray(value, 'decision input.excludedIncompleteClasses');
  if (canonicalJson(value as unknown as JsonValue) !== canonicalJson(expectedExcludedClasses(packet) as unknown as JsonValue)) {
    throw new Error('bounded decision must name every exact excluded and incomplete class');
  }
}

function parseDecisionInput(value: unknown, context: FeasibilityDecisionContext): FeasibilityDecisionInput {
  assertContext(context);
  assertPlainObject(value, 'decision input');
  const outcome = value.terminalDecision;
  if (outcome === 'GO') {
    assertExactKeys(
      value,
      [...COMMON_INPUT_KEYS, 'authorizedScopeSha256', 'usefulnessAccepted', 'usefulnessRationale'],
      'decision input',
    );
  } else if (outcome === 'GO WITH BOUNDED SUPPORT') {
    assertExactKeys(
      value,
      [
        ...COMMON_INPUT_KEYS,
        'authorizedScopeSha256',
        'usefulnessAccepted',
        'usefulnessRationale',
        'excludedIncompleteClasses',
      ],
      'decision input',
    );
  } else if (outcome === 'NO-GO / RESCOPE') {
    assertExactKeys(value, [...COMMON_INPUT_KEYS, 'blockedRescopeRationale'], 'decision input');
  } else {
    throw new TypeError('decision input has an illegal terminal outcome');
  }
  assertCommonInput(value, context);

  if (outcome === 'NO-GO / RESCOPE') {
    assertNonemptyString(value.blockedRescopeRationale, 'decision input.blockedRescopeRationale');
    return value as unknown as NoGoDecisionInput;
  }

  assertSha256(value.authorizedScopeSha256, 'decision input authorized scope digest');
  if (value.authorizedScopeSha256 !== context.packet.authorizedScopeCandidate.authorizedScopeSha256) {
    throw new Error('decision input substitutes a different authorized scope');
  }
  if (value.usefulnessAccepted !== true) throw new TypeError('GO requires explicit usefulness acceptance');
  assertNonemptyString(value.usefulnessRationale, 'decision input.usefulnessRationale');

  if (outcome === 'GO') {
    const counts = context.packet.ledger.operationCounts;
    if (counts.candidateSupported !== counts.total || counts.incomplete !== 0) {
      throw new Error('GO cannot be selected while the reviewed operation universe remains incomplete');
    }
    return value as unknown as GoDecisionInput;
  }

  assertExactExclusions(value.excludedIncompleteClasses, context.packet);
  return value as unknown as BoundedGoDecisionInput;
}

function unsignedDecision(
  input: FeasibilityDecisionInput,
  context: FeasibilityDecisionContext,
): Omit<FeasibilityDecisionRecord, 'contentSha256'> {
  const boundedOrGo = input.terminalDecision !== 'NO-GO / RESCOPE';
  return {
    schemaVersion: 1,
    outcome: input.terminalDecision,
    review: {
      reviewer: 'Independent feasibility reviewer',
      reviewedAt: input.review.reviewedAt,
      verdict: 'APPROVED',
    },
    decisionMaker: input.decisionMaker,
    decidedAt: input.decidedAt,
    evidence: {
      feasibilityPacketSha256: context.packet.contentSha256,
      supportManifestSha256: context.supportManifest.contentSha256,
      supportPredicateSha256: context.supportManifest.predicate.ruleSha256,
      selectionSha256: context.supportManifest.selectionSha256,
    },
    rationale: input.terminalDecision === 'NO-GO / RESCOPE' ? input.blockedRescopeRationale : input.rationale,
    wordingAccepted: true,
    usefulness: boundedOrGo ? { accepted: true, rationale: input.usefulnessRationale } : null,
    authorization: boundedOrGo
      ? {
          status: input.terminalDecision === 'GO' ? 'authorized-complete' : 'authorized-bounded',
          members: structuredClone(context.packet.authorizedScopeCandidate.members),
          authorizedScopeSha256: context.packet.authorizedScopeCandidate.authorizedScopeSha256,
        }
      : { status: 'blocked-rescope', members: [], authorizedScopeSha256: null },
    excludedIncompleteClasses:
      input.terminalDecision === 'GO' ? [] : expectedExcludedClasses(context.packet),
    knownLimitations: structuredClone(context.packet.knownLimitations),
  };
}

export function buildFeasibilityDecision(value: unknown, context: FeasibilityDecisionContext): FeasibilityDecisionRecord {
  const input = parseDecisionInput(value, context);
  const unsigned = unsignedDecision(input, context);
  const decision = { ...unsigned, contentSha256: digestJson(unsigned as unknown as JsonValue) };
  validateFeasibilityDecision(decision, context);
  return decision;
}

export function validateFeasibilityDecision(
  value: unknown,
  context: FeasibilityDecisionContext,
): asserts value is FeasibilityDecisionRecord {
  assertContext(context);
  assertPlainObject(value, 'feasibility decision');
  assertExactKeys(value, PUBLIC_RECORD_KEYS, 'feasibility decision');
  if (value.schemaVersion !== 1) throw new TypeError('feasibility decision schema version mismatch');
  if (!context.packet.legalTerminalOutcomes.includes(value.outcome as FeasibilityOutcome)) {
    throw new TypeError('feasibility decision has an illegal outcome');
  }
  assertPlainObject(value.review, 'feasibility decision.review');
  assertExactKeys(value.review, ['reviewer', 'reviewedAt', 'verdict'], 'feasibility decision.review');
  if (value.review.reviewer !== 'Independent feasibility reviewer' || value.review.verdict !== 'APPROVED') {
    throw new TypeError('feasibility decision review identity is invalid');
  }
  assertIsoInstant(value.review.reviewedAt, 'feasibility decision.review.reviewedAt');
  assertNonemptyString(value.decisionMaker, 'feasibility decision.decisionMaker');
  assertIsoInstant(value.decidedAt, 'feasibility decision.decidedAt');
  if (new Date(value.review.reviewedAt).getTime() > new Date(value.decidedAt).getTime()) {
    throw new Error('feasibility decision predates its review');
  }
  assertPlainObject(value.evidence, 'feasibility decision.evidence');
  assertExactKeys(
    value.evidence,
    ['feasibilityPacketSha256', 'supportManifestSha256', 'supportPredicateSha256', 'selectionSha256'],
    'feasibility decision.evidence',
  );
  for (const key of [
    'feasibilityPacketSha256',
    'supportManifestSha256',
    'supportPredicateSha256',
    'selectionSha256',
  ] as const) {
    assertSha256(value.evidence[key], `feasibility decision.evidence.${key}`);
  }
  if (
    value.evidence.feasibilityPacketSha256 !== context.packet.contentSha256 ||
    value.evidence.supportManifestSha256 !== context.supportManifest.contentSha256 ||
    value.evidence.supportPredicateSha256 !== context.supportManifest.predicate.ruleSha256 ||
    value.evidence.selectionSha256 !== context.supportManifest.selectionSha256
  ) {
    throw new Error('feasibility decision evidence identity mismatch');
  }
  assertNonemptyString(value.rationale, 'feasibility decision.rationale');
  if (value.wordingAccepted !== true) throw new TypeError('feasibility decision wording is not accepted');
  assertPlainObject(value.authorization, 'feasibility decision.authorization');
  assertExactKeys(value.authorization, ['status', 'members', 'authorizedScopeSha256'], 'feasibility decision.authorization');
  if (!Array.isArray(value.authorization.members)) throw new TypeError('feasibility decision members must be an array');
  assertStringArray(value.knownLimitations, 'feasibility decision.knownLimitations');
  if (canonicalJson(value.knownLimitations as unknown as JsonValue) !== canonicalJson(context.packet.knownLimitations as unknown as JsonValue)) {
    throw new Error('feasibility decision limitations do not match the reviewed packet');
  }

  if (value.outcome === 'NO-GO / RESCOPE') {
    if (
      value.authorization.status !== 'blocked-rescope' ||
      value.authorization.members.length !== 0 ||
      value.authorization.authorizedScopeSha256 !== null ||
      value.usefulness !== null
    ) {
      throw new Error('NO-GO decision must not authorize a scope or usefulness claim');
    }
    if (canonicalJson(value.excludedIncompleteClasses as JsonValue) !== canonicalJson(expectedExcludedClasses(context.packet) as JsonValue)) {
      throw new Error('NO-GO decision exclusions are incomplete');
    }
  } else {
    assertPlainObject(value.usefulness, 'feasibility decision.usefulness');
    assertExactKeys(value.usefulness, ['accepted', 'rationale'], 'feasibility decision.usefulness');
    if (value.usefulness.accepted !== true) throw new TypeError('feasibility decision usefulness is not accepted');
    assertNonemptyString(value.usefulness.rationale, 'feasibility decision.usefulness.rationale');
    const expectedStatus = value.outcome === 'GO' ? 'authorized-complete' : 'authorized-bounded';
    if (value.authorization.status !== expectedStatus) throw new Error('feasibility decision authorization status mismatch');
    assertSha256(value.authorization.authorizedScopeSha256, 'feasibility decision authorized scope digest');
    if (
      value.authorization.authorizedScopeSha256 !== context.packet.authorizedScopeCandidate.authorizedScopeSha256 ||
      canonicalJson(value.authorization.members as JsonValue) !==
        canonicalJson(context.packet.authorizedScopeCandidate.members as unknown as JsonValue)
    ) {
      throw new Error('feasibility decision authorizes a substituted member set');
    }
    const expectedExclusions = value.outcome === 'GO' ? [] : expectedExcludedClasses(context.packet);
    if (
      canonicalJson(value.excludedIncompleteClasses as JsonValue) !==
      canonicalJson(expectedExclusions as unknown as JsonValue)
    ) {
      throw new Error('feasibility decision exclusions mismatch');
    }
    if (value.outcome === 'GO') {
      const counts = context.packet.ledger.operationCounts;
      if (counts.candidateSupported !== counts.total || counts.incomplete !== 0) {
        throw new Error('GO is invalid for an incomplete reviewed universe');
      }
    }
  }

  assertSha256(value.contentSha256, 'feasibility decision content digest');
  const { contentSha256: _contentSha256, ...unsigned } = value;
  if (digestJson(unsigned as unknown as JsonValue) !== value.contentSha256) {
    throw new Error('feasibility decision content digest mismatch');
  }
}
