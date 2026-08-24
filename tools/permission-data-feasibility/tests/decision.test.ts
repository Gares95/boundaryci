import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { beforeAll, describe, expect, it } from 'vitest';

import { parseBoundedJson } from '../artifact-sources.js';
import {
  buildFeasibilityDecision,
  validateFeasibilityDecision,
  type BoundedGoDecisionInput,
  type FeasibilityDecisionRecord,
} from '../decision.js';
import { validateSupportManifest, type SupportManifest } from '../inventory.js';
import type { FeasibilityPacket } from '../ledger.js';

const PROJECT_ROOT = fileURLToPath(new URL('../../../', import.meta.url));
const ROOT = 'tools/permission-data-feasibility';

let packet: FeasibilityPacket;
let support: SupportManifest;

function read(path: string, maxBytes = 4 * 1024 * 1024): unknown {
  return parseBoundedJson(PROJECT_ROOT, `${ROOT}/${path}`, maxBytes);
}

function boundedInput(): BoundedGoDecisionInput {
  return {
    schemaVersion: 1,
    terminalDecision: 'GO WITH BOUNDED SUPPORT',
    review: {
      reviewer: 'Test independent reviewer',
      reviewedAt: '2026-08-24T13:51:35Z',
      verdict: 'APPROVED',
      reviewResultSha256: '1'.repeat(64),
      reviewPromptSha256: '2'.repeat(64),
      highFindings: 0,
      blockingMediumFindings: 0,
      hardInvariantViolations: 0,
    },
    decisionMaker: 'Gares95',
    decidedAt: '2026-08-24T13:58:34Z',
    feasibilityPacketSha256: packet.contentSha256,
    supportPredicateSha256: packet.support.predicateSha256,
    selectionSha256: packet.support.preliminarySelectionSha256,
    authorizedScopeSha256: packet.authorizedScopeCandidate.authorizedScopeSha256,
    rationale:
      'Authorize only the exact reviewer-backed Issues read/write member set while all other operations remain incomplete.',
    wordingAccepted: true,
    usefulnessAccepted: true,
    usefulnessRationale: 'The exact scope proves the flagship Issues read-to-write boundary change without guessing.',
    excludedIncompleteClasses: [
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
    ],
  };
}

beforeAll(() => {
  packet = read('evidence/feasibility-packet.json') as FeasibilityPacket;
  support = read('evidence/support-manifest.json') as SupportManifest;
  validateSupportManifest(support);
});

describe('terminal feasibility decision', () => {
  it('authorizes only the exact reviewed bounded member set', () => {
    const decision = buildFeasibilityDecision(boundedInput(), { packet, supportManifest: support });
    expect(() => validateFeasibilityDecision(decision, { packet, supportManifest: support })).not.toThrow();
    expect(decision.outcome).toBe('GO WITH BOUNDED SUPPORT');
    expect(decision.authorization).toEqual({
      status: 'authorized-bounded',
      members: packet.authorizedScopeCandidate.members,
      authorizedScopeSha256: packet.authorizedScopeCandidate.authorizedScopeSha256,
    });
    expect(decision.authorization.members.map((member) => member.operationId)).toEqual([
      'issues/create',
      'issues/list-for-repo',
    ]);
    expect(JSON.stringify(decision)).not.toMatch(/Claude|Codex|assistant/iu);
  });

  it('matches the committed decision record exactly', () => {
    const committed = read('evidence/decision-record.json') as FeasibilityDecisionRecord;
    expect(() => validateFeasibilityDecision(committed, { packet, supportManifest: support })).not.toThrow();
    expect(committed.evidence.feasibilityPacketSha256).toBe(packet.contentSha256);
    expect(committed.evidence.supportPredicateSha256).toBe(support.predicate.ruleSha256);
    expect(committed.evidence.selectionSha256).toBe(support.selectionSha256);
  });

  it('rejects digest substitution, incomplete review, missing usefulness, and altered exclusions', () => {
    const mutations: ((input: BoundedGoDecisionInput) => void)[] = [
      (input) => {
        input.feasibilityPacketSha256 = '0'.repeat(64);
      },
      (input) => {
        input.supportPredicateSha256 = '0'.repeat(64);
      },
      (input) => {
        input.selectionSha256 = '0'.repeat(64);
      },
      (input) => {
        input.authorizedScopeSha256 = '0'.repeat(64);
      },
      (input) => {
        input.review.highFindings = 1;
      },
      (input) => {
        input.review.blockingMediumFindings = 1;
      },
      (input) => {
        input.review.hardInvariantViolations = 1;
      },
      (input) => {
        input.usefulnessAccepted = false;
      },
      (input) => {
        input.usefulnessRationale = '';
      },
      (input) => {
        input.excludedIncompleteClasses.pop();
      },
    ];
    for (const mutate of mutations) {
      const input = boundedInput();
      mutate(input);
      expect(() => buildFeasibilityDecision(input, { packet, supportManifest: support })).toThrow();
    }
  });

  it('rejects automatic GO and illegal outcome-specific fields', () => {
    const automaticGo = { ...boundedInput(), terminalDecision: 'GO' };
    expect(() => buildFeasibilityDecision(automaticGo, { packet, supportManifest: support })).toThrow();

    const illegalNoGo = {
      ...boundedInput(),
      terminalDecision: 'NO-GO / RESCOPE',
      blockedRescopeRationale: 'No useful deterministic subset exists.',
    };
    expect(() => buildFeasibilityDecision(illegalNoGo, { packet, supportManifest: support })).toThrow();
  });

  it('rejects unknown fields and re-signed public-record drift', () => {
    const input = boundedInput() as BoundedGoDecisionInput & { unexpected?: boolean };
    input.unexpected = true;
    expect(() => buildFeasibilityDecision(input, { packet, supportManifest: support })).toThrow(/unexpected keys/u);

    const decision = buildFeasibilityDecision(boundedInput(), { packet, supportManifest: support });
    const changed = structuredClone(decision);
    changed.authorization.members[0]!.operationId = 'issues/other';
    expect(() => validateFeasibilityDecision(changed, { packet, supportManifest: support })).toThrow();
  });
});

