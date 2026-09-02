import { describe, expect, it } from 'vitest';

import { emitDeliveryEvent, type DeliveryLogEvent } from '../../src/delivery/logging.js';
import { createRepositoryReadCapability, SanitizedGitHubReadError } from '../../src/delivery/github-read.js';
import { createRuntimeSentinels } from './support.js';

function validEvent(): DeliveryLogEvent {
  return {
    stage: 'github-read',
    outcome: 'retry-exhausted',
    reason: 'transient-read-exhausted',
    workId: 'work-19',
    deliveryId: 'delivery-19',
    installationId: 42,
    repositoryId: 7,
    pullNumber: 19,
    baseSha: 'a'.repeat(40),
    headSha: 'b'.repeat(40),
    count: 3,
    durationMilliseconds: 125,
    attempt: 3,
    delayMilliseconds: 1000,
  };
}

describe('Phase 5 non-leakage boundaries', () => {
  it('accepts only exact allowlisted operational events before the sink sees them', () => {
    const events: DeliveryLogEvent[] = [];
    const event = validEvent();
    const emitted = emitDeliveryEvent(event, { emit: (value) => events.push(value) });

    expect(events).toEqual([event]);
    expect(emitted).not.toBe(event);
    expect(Object.isFrozen(emitted)).toBe(true);
    expect(() => emitDeliveryEvent({ ...event, metadata: {} } as never, { emit: (value) => events.push(value) })).toThrow('unsafe delivery log event');
    expect(events).toHaveLength(1);
  });

  it('contains credential, payload, header, and raw external-error sentinels at the adapter and logging boundaries', async () => {
    const sentinels = createRuntimeSentinels();
    const provider = {
      async issue() {
        throw {
          status: 503,
          body: sentinels.externalError!,
          headers: { authorization: sentinels.authorizationHeader! },
          token: sentinels.installationToken!,
          payload: sentinels.rawPayload!,
          privateKey: sentinels.appAuthentication!,
          secret: sentinels.webhookSecret!,
        };
      },
    };

    await expect(createRepositoryReadCapability({ installationId: 42, repositoryId: 7 }, provider)).rejects.toSatisfy((error: unknown) => {
      expect(error).toBeInstanceOf(SanitizedGitHubReadError);
      const serialized = JSON.stringify(error);
      for (const value of Object.values(sentinels)) expect(serialized).not.toContain(value);
      return true;
    });

    const events: DeliveryLogEvent[] = [];
    expect(() => emitDeliveryEvent({ ...validEvent(), reason: sentinels.externalError } as never, { emit: (value) => events.push(value) })).toThrow(
      'unsafe delivery log event',
    );
    expect(events).toEqual([]);
  });

});
