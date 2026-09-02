import { describe, expect, it } from 'vitest';

import { DeliveryCoordinator, createWorkKey, runBoundedRead } from '../../src/delivery/coordinator.js';
import { SanitizedGitHubReadError } from '../../src/delivery/github-read.js';

const SHA = (letter: string): string => letter.repeat(40);
const work = (overrides: Partial<{
  installationId: number;
  repositoryId: number;
  pullNumber: number;
  baseSha: string;
  headSha: string;
  evaluatorIdentity: string;
}> = {}) => ({
  installationId: 1,
  repositoryId: 2,
  pullNumber: 3,
  baseSha: SHA('a'),
  headSha: SHA('b'),
  evaluatorIdentity: 'boundaryci-evaluator-v1',
  ...overrides,
});

describe('delivery coordinator', () => {
  it('keys every logical comparison field while excluding delivery trace identifiers', () => {
    const baseline = work();
    expect(createWorkKey(baseline)).toBe(createWorkKey({ ...baseline }));
    for (const field of ['installationId', 'repositoryId', 'pullNumber', 'baseSha', 'headSha', 'evaluatorIdentity'] as const) {
      const changed = field.endsWith('Sha') ? SHA(field === 'baseSha' ? 'c' : 'd') :
        field === 'evaluatorIdentity' ? 'boundaryci-evaluator-v2' : baseline[field] + 10;
      expect(createWorkKey(baseline)).not.toBe(createWorkKey({ ...baseline, [field]: changed }));
    }
  });

  it('coalesces exact work and suppresses an older comparison for the same pull request', async () => {
    const coordinator = new DeliveryCoordinator();
    let releases = 0;
    let releaseOlder!: () => void;
    const older = coordinator.submit(work(), async (control) => {
      await new Promise<void>((resolve) => { releaseOlder = resolve; });
      return control.isCancelled() ? 'cancelled-work' : 'older-work';
    });
    const duplicate = coordinator.submit(work(), async () => {
      releases += 1;
      return 'duplicate-work';
    });
    expect(duplicate).toBe(older);
    const newest = coordinator.submit(work({ headSha: SHA('c') }), async () => 'newest-work');
    await Promise.resolve();
    releaseOlder();
    await expect(older).resolves.toMatchObject({ status: 'superseded' });
    await expect(newest).resolves.toMatchObject({ status: 'current', value: 'newest-work' });
    expect(releases).toBe(0);
    expect(coordinator.snapshot()).toEqual({ active: 0, pending: 0, recovered: 0, delivered: 0 });
  });

  it('retries only transient sanitized reads under one bounded clock', async () => {
    let time = 0;
    const sleeps: number[] = [];
    let attempts = 0;
    const result = await runBoundedRead(async () => {
      attempts += 1;
      if (attempts < 3) throw new SanitizedGitHubReadError('transient-service', true);
      return 'ok';
    }, {
      now: () => time,
      sleep: async (milliseconds) => { sleeps.push(milliseconds); time += milliseconds; },
    });
    expect(result).toEqual({ status: 'success', value: 'ok', attempts: 3 });
    expect(sleeps).toEqual([250, 1_000]);
  });

  it('does not retry persistent or cancelled work and sanitizes transient exhaustion', async () => {
    const persistent = await runBoundedRead(async () => {
      throw new SanitizedGitHubReadError('authentication-authorization', false);
    });
    expect(persistent).toEqual({ status: 'not-retryable', cause: 'authentication-authorization', attempts: 1 });

    const exhausted = await runBoundedRead(async () => {
      throw new SanitizedGitHubReadError('rate-limited', true);
    }, { sleep: async () => undefined });
    expect(exhausted).toEqual({ status: 'runtime-infrastructure-failure', cause: 'transient-read-exhausted', attempts: 3 });

    const cancelled = await runBoundedRead(async () => 'never', { isCancelled: () => true });
    expect(cancelled).toEqual({ status: 'cancelled', attempts: 0 });
  });
});
