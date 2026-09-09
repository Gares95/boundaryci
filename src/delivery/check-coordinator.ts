import { createHash } from 'node:crypto';

import type { DeliveryEnvelopeV1, Phase6FreshnessMatch } from './contract.js';
import { validateDeliveryEnvelope } from './contract.js';
import { deriveCheckCorrelationId, type CheckIdentityV1, type CheckPublicationResultV1 } from './check-contract.js';
import { publishCompletedCheck, type CheckPublisher } from './check-publish.js';
import { renderCompletedCheck } from './check-render.js';
import type { CurrentPull } from './types.js';

export interface CurrentPullFreshnessReader {
  getCurrentPull(pullNumber: number): Promise<CurrentPull>;
  /** A bounded optional probe; omission is deliberately no-publication for an external fork. */
  addressHeadRepository?(repositoryId: number, sha: string): Promise<boolean>;
}

export interface CheckCoordinator {
  receive(envelope: unknown): Promise<CheckPublicationResultV1>;
  readonly results: readonly CheckPublicationResultV1[];
}

export interface CreateCheckCoordinatorOptions {
  appId: number;
  freshness: CurrentPullFreshnessReader;
  publisher: CheckPublisher;
}

function matchesFreshness(expected: Phase6FreshnessMatch, observed: CurrentPull): boolean {
  return observed.number === expected.pullNumber && observed.repositoryId === expected.repositoryId && observed.state === 'open' && !observed.merged &&
    observed.base.repositoryId === expected.baseRepositoryId && observed.base.ref === expected.baseRef && observed.base.sha === expected.baseSha &&
    observed.head.repositoryId === expected.headRepositoryId && observed.head.sha === expected.headSha &&
    expected.eligibility === 'open' &&
    (expected.topology === 'same-repository'
      ? observed.head.repositoryId === expected.repositoryId
      : observed.head.repositoryId !== expected.repositoryId);
}

function diagnosticIdentity(envelope: Extract<DeliveryEnvelopeV1, { handoff: 'diagnostic-only' }>): CheckIdentityV1 {
  const digest = createHash('sha256').update(JSON.stringify({
    version: 1, installationId: envelope.work.installationId, repositoryId: envelope.phase6Match.repositoryId,
    pullNumber: envelope.phase6Match.pullNumber, baseRepositoryId: envelope.phase6Match.baseRepositoryId,
    baseRef: envelope.phase6Match.baseRef, baseSha: envelope.phase6Match.baseSha,
    headRepositoryId: envelope.phase6Match.headRepositoryId, headSha: envelope.phase6Match.headSha,
    topology: envelope.phase6Match.topology, evaluatorIdentity: envelope.work.evaluatorIdentity,
    diagnostic: envelope.diagnostic.code,
  }), 'utf8').digest('hex');
  return Object.freeze({
    version: 1, installationId: envelope.work.installationId, repositoryId: envelope.phase6Match.repositoryId,
    pullNumber: envelope.phase6Match.pullNumber, baseRepositoryId: envelope.phase6Match.baseRepositoryId,
    baseRef: envelope.phase6Match.baseRef, baseSha: envelope.phase6Match.baseSha,
    headRepositoryId: envelope.phase6Match.headRepositoryId, headSha: envelope.phase6Match.headSha,
    topology: envelope.phase6Match.topology, evaluatorIdentity: envelope.work.evaluatorIdentity,
    engineId: 'boundaryci-diagnostic-v1', analyzer: Object.freeze({}),
    catalogAuthorizedScopeSha256: '0'.repeat(64), effectiveConfigSha256: '0'.repeat(64),
    correlationId: `boundaryci:v1:${digest}`,
  });
}

/** Composes exact envelope validation, immediate current-PR equality, pure render, and upsert. */
export function createCheckCoordinator(options: CreateCheckCoordinatorOptions): CheckCoordinator {
  if (!Number.isSafeInteger(options.appId) || options.appId <= 0) throw new TypeError('Check coordinator app ID is invalid');
  const results: CheckPublicationResultV1[] = [];
  const record = (result: CheckPublicationResultV1): CheckPublicationResultV1 => {
    const frozen = Object.freeze(structuredClone(result)) as CheckPublicationResultV1;
    results.push(frozen);
    return frozen;
  };
  return Object.freeze({
    get results(): readonly CheckPublicationResultV1[] { return Object.freeze([...results]); },
    async receive(value: unknown): Promise<CheckPublicationResultV1> {
      try {
        validateDeliveryEnvelope(value);
      } catch {
        return record({ status: 'not-published', reason: 'invalid-envelope' });
      }
      const envelope: DeliveryEnvelopeV1 = value;
      if (envelope.handoff === 'none') return record({ status: 'not-published', reason: 'no-handoff' });
      if (envelope.handoff !== 'publishable-semantic' && envelope.handoff !== 'diagnostic-only') return record({ status: 'not-published', reason: 'invalid-envelope' });
      let current: CurrentPull;
      try {
        current = await options.freshness.getCurrentPull(envelope.phase6Match.pullNumber);
      } catch {
        return record({ status: 'not-published', reason: 'publication-failure' });
      }
      if (!matchesFreshness(envelope.phase6Match, current)) return record({ status: 'not-published', reason: 'stale-comparison' });
      if (envelope.handoff === 'diagnostic-only' && envelope.diagnostic.code === 'unsupported-topology') {
        if (options.freshness.addressHeadRepository === undefined) return record({ status: 'not-published', reason: 'publication-failure' });
        try {
          if (!await options.freshness.addressHeadRepository(envelope.phase6Match.headRepositoryId, envelope.phase6Match.headSha)) {
            return record({ status: 'not-published', reason: 'publication-failure' });
          }
        } catch { return record({ status: 'not-published', reason: 'publication-failure' }); }
      }
      try {
        const identity = envelope.handoff === 'publishable-semantic' ? deriveCheckCorrelationId(envelope) : diagnosticIdentity(envelope);
        const payload = renderCompletedCheck(envelope, identity);
        return record(await publishCompletedCheck(options.publisher, options.appId, identity, payload));
      } catch {
        return record({ status: 'not-published', reason: 'invalid-envelope' });
      }
    },
  });
}
