import type { DeliveryEnvelopeV1, Phase6FreshnessMatch } from './contract.js';
import { validateDeliveryEnvelope } from './contract.js';
import { deriveCheckCorrelationId, type CheckPublicationResultV1 } from './check-contract.js';
import { publishCompletedCheck, type CheckPublisher } from './check-publish.js';
import { renderCompletedCheck } from './check-render.js';
import type { CurrentPull } from './types.js';

export interface CurrentPullFreshnessReader {
  getCurrentPull(pullNumber: number): Promise<CurrentPull>;
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
    expected.eligibility === 'open' && expected.topology === 'same-repository';
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
      if (envelope.handoff !== 'publishable-semantic') return record({ status: 'not-published', reason: 'invalid-envelope' });
      let current: CurrentPull;
      try {
        current = await options.freshness.getCurrentPull(envelope.phase6Match.pullNumber);
      } catch {
        return record({ status: 'not-published', reason: 'publication-failure' });
      }
      if (!matchesFreshness(envelope.phase6Match, current)) return record({ status: 'not-published', reason: 'stale-comparison' });
      try {
        const identity = deriveCheckCorrelationId(envelope);
        const payload = renderCompletedCheck(envelope, identity);
        return record(await publishCompletedCheck(options.publisher, options.appId, identity, payload));
      } catch {
        return record({ status: 'not-published', reason: 'invalid-envelope' });
      }
    },
  });
}
