import { describe, expect, it } from 'vitest';

import { createBoundedReadSession, DeliveryCoordinator, createWorkKey, runBoundedRead } from '../../src/delivery/coordinator.js';
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
      const changed = field === 'baseSha' ? SHA('c') :
        field === 'headSha' ? SHA('d') :
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

  it('assigns one owner and retains every coalesced delivery identifier', async () => {
    const coordinator = new DeliveryCoordinator();
    let release!: () => void;
    const first = coordinator.submitWithOwnership(work(), 'delivery-a', async () => new Promise<string>((resolve) => { release = () => resolve('done'); }));
    const duplicate = coordinator.submitWithOwnership(work(), 'delivery-b', async () => 'duplicate');
    expect(first.owner).toBe(true);
    expect(duplicate.owner).toBe(false);
    expect(duplicate.result).toBe(first.result);
    await Promise.resolve();
    release();
    await expect(first.result).resolves.toMatchObject({ status: 'current', value: 'done' });
    expect(first.deliveryIds()).toEqual(['delivery-a', 'delivery-b']);
  });

  it('bounds coalesced provenance and reports deterministic overflow after 65 distinct deliveries', async () => {
    const coordinator = new DeliveryCoordinator();
    let release!: () => void;
    const owner = coordinator.submitWithOwnership(work(), 'delivery-0', async () => new Promise<string>((resolve) => { release = () => resolve('done'); }));
    for (let index = 1; index <= 64; index += 1) coordinator.submitWithOwnership(work(), `delivery-${index}`, async () => 'duplicate');
    await Promise.resolve();
    release();
    await expect(owner.result).resolves.toMatchObject({ status: 'current' });
    expect(owner.deliveryIds()).toHaveLength(64);
    expect(owner.overflowed()).toBe(true);
  });

  it('settles a long retry delay immediately when coordinator work is superseded', async () => {
    const coordinator = new DeliveryCoordinator();
    let releaseSleep!: () => void;
    let beganSleep!: () => void;
    const sleepBegun = new Promise<void>((resolve) => { beganSleep = resolve; });
    let control!: AbortSignal;
    const older = coordinator.submit(work(), async (workControl) => {
      control = workControl.signal;
      const session = createBoundedReadSession({ signal: workControl.signal, isCancelled: workControl.isCancelled, sleep: async () => new Promise<void>((resolve) => { beganSleep(); releaseSleep = resolve; }) });
      try {
        await session.read(async () => { throw new SanitizedGitHubReadError('rate-limited', true, 59_000); });
      } finally { session.close(); }
      return 'unreachable';
    });
    await sleepBegun;
    const newer = coordinator.submit(work({ headSha: SHA('c') }), async () => 'newer');
    await expect(older).resolves.toMatchObject({ status: 'superseded' });
    expect(control.aborted).toBe(true);
    await expect(newer).resolves.toMatchObject({ status: 'current', value: 'newer' });
    releaseSleep();
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

  it('shares retry accounting and one clock across a lifecycle session without a per-method reset', async () => {
    let time = 0;
    const session = createBoundedReadSession({
      now: () => time,
      sleep: async (milliseconds) => { time += milliseconds; },
    });
    await session.read(async () => {
      throw new SanitizedGitHubReadError('transient-service', true);
    }).catch(() => undefined);
    await session.read(async () => {
      throw new SanitizedGitHubReadError('rate-limited', true);
    }).catch(() => undefined);
    await expect(session.read(async () => {
      throw new SanitizedGitHubReadError('transient-transport', true);
    })).rejects.toThrow('bounded-read:runtime-infrastructure-failure');
    session.close();
  });

  it('aborts a never-settling in-flight read at its deadline and clears its timer', async () => {
    let deadline!: () => void;
    const cleared: unknown[] = [];
    const session = createBoundedReadSession({
      maxElapsedMilliseconds: 25,
      setTimer: (callback) => {
        deadline = callback;
        return 'deadline-timer' as unknown as ReturnType<typeof setTimeout>;
      },
      clearTimer: (timer) => { cleared.push(timer); },
    });
    let observedSignal: AbortSignal | undefined;
    const pending = session.read(async ({ signal }) => {
      observedSignal = signal;
      return new Promise<string>(() => undefined);
    });
    deadline();
    await expect(pending).rejects.toThrow('bounded-read:runtime-infrastructure-failure');
    expect(observedSignal?.aborted).toBe(true);
    expect(cleared).toEqual(['deadline-timer']);
    session.close();
  });
});
