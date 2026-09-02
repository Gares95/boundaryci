import { describe, expect, it } from 'vitest';

import type { GitHubPullPage, GitHubReadCapability } from '../../src/delivery/github-read.js';
import { REGISTERED_EVENTS, normalizeVerifiedTrigger, resolveTriggerWork } from '../../src/delivery/trigger.js';
import type { CurrentPull, GitBlob, GitCommit, GitTree } from '../../src/delivery/index.js';
import { DELIVERY_FIXTURES, blob, commit, currentPull, tree } from './fixtures/index.js';

function capability(options: {
  pull?: CurrentPull;
  page?: (page: number) => GitHubPullPage;
} = {}): { capability: GitHubReadCapability; calls: string[] } {
  const calls: string[] = [];
  return {
    calls,
    capability: {
      async getCurrentPull(pullNumber) {
        calls.push(`pull:${pullNumber}`);
        return options.pull ?? currentPull({ number: pullNumber });
      },
      async listOpenPullsByBase(baseRef, page) {
        calls.push(`list:${baseRef}:${page}`);
        return options.page?.(page) ?? Object.freeze({ pulls: Object.freeze([]), nextPage: null, normalizedBytes: 2 });
      },
      async getCommit(sha): Promise<GitCommit> { return commit(sha); },
      async getTree(sha): Promise<GitTree> { return tree(sha); },
      async getBlob(sha): Promise<GitBlob> { return blob(sha); },
    },
  };
}

function pullTrigger(action: 'opened' | 'synchronize' | 'reopened' | 'edited' = 'opened', changed = false) {
  return normalizeVerifiedTrigger('pull_request', {
    action,
    installation: { id: 42 },
    repository: { id: 7 },
    pull_request: { number: 19 },
    changes: changed ? { base: { ref: { from: 'old' } } } : undefined,
  }, 'delivery-1');
}

describe('verified trigger normalization and resolution', () => {
  it('allows only the locked Probot event/action registrations and normalizes no mutable comparison claims', () => {
    expect(REGISTERED_EVENTS).toEqual(['pull_request.opened', 'pull_request.synchronize', 'pull_request.reopened', 'pull_request.edited', 'push']);
    expect(pullTrigger()).toMatchObject({ kind: 'pull-request', action: 'opened', installationId: 42, repositoryId: 7, pullNumber: 19 });
    expect(normalizeVerifiedTrigger('pull_request', { action: 'closed' }, 'delivery-1')).toBeNull();
    expect(normalizeVerifiedTrigger('check_run', {}, 'delivery-1')).toBeNull();
    expect(normalizeVerifiedTrigger('pull_request', { action: 'opened' }, '')).toBeNull();
  });

  it('uses fresh PR state for same-repository draft eligibility and returns no work for an irrelevant edit', async () => {
    const trigger = pullTrigger();
    if (trigger === null) throw new Error('test trigger did not normalize');
    const read = capability({ pull: currentPull({ draft: true }) });
    await expect(resolveTriggerWork(trigger, read.capability)).resolves.toMatchObject({ status: 'work', work: { pullNumber: 19, baseSha: 'a'.repeat(40), headSha: 'b'.repeat(40) } });
    expect(read.calls).toEqual(['pull:19']);

    const edit = pullTrigger('edited', false);
    if (edit === null) throw new Error('test edit did not normalize');
    const untouched = capability();
    await expect(resolveTriggerWork(edit, untouched.capability)).resolves.toEqual({ status: 'no-op', reason: 'edited-without-base-target-change' });
    expect(untouched.calls).toEqual([]);
  });

  it('keeps forks diagnostic-only while uncertain topology and obsolete PRs create no handoff', async () => {
    const trigger = pullTrigger();
    if (trigger === null) throw new Error('test trigger did not normalize');
    await expect(resolveTriggerWork(trigger, capability({ pull: currentPull({ head: { repositoryId: 9, sha: 'b'.repeat(40) } }) }).capability))
      .resolves.toEqual({ status: 'diagnostic-only', reason: 'unsupported-topology' });
    await expect(resolveTriggerWork(trigger, capability({ pull: currentPull({ base: { repositoryId: 9, ref: 'main', sha: 'a'.repeat(40) } }) }).capability))
      .resolves.toEqual({ status: 'trust-failure', reason: 'repository-topology-mismatch' });
    await expect(resolveTriggerWork(trigger, capability({ pull: currentPull({ state: 'closed' }) }).capability))
      .resolves.toEqual({ status: 'no-op', reason: 'pull-request-obsolete' });
  });

  it('collects an entire bounded push fan-out before exposing deterministic numeric ordering', async () => {
    const trigger = normalizeVerifiedTrigger('push', { installation: { id: 42 }, repository: { id: 7 }, ref: 'refs/heads/main' }, 'delivery-push');
    if (trigger === null) throw new Error('test push did not normalize');
    const read = capability({ page: () => Object.freeze({
      pulls: Object.freeze([currentPull({ number: 20 }), currentPull({ number: 19 })]),
      nextPage: null,
      normalizedBytes: 128,
    }) });
    await expect(resolveTriggerWork(trigger, read.capability)).resolves.toMatchObject({ status: 'fanout-work', work: [{ pullNumber: 19 }, { pullNumber: 20 }] });
    expect(read.calls).toEqual(['list:main:1']);

    const overLimit = capability({ page: (page) => Object.freeze({
      pulls: Object.freeze(Array.from({ length: page === 6 ? 1 : 100 }, (_, index) => currentPull({ number: ((page - 1) * 100) + index + 1 }))),
      nextPage: page === 6 ? null : page + 1,
      normalizedBytes: 128,
    }) });
    await expect(resolveTriggerWork(trigger, overLimit.capability)).resolves.toMatchObject({ status: 'fanout-incomplete', retryable: true, cause: 'pull-request-limit' });
    expect(overLimit.calls).toEqual(['list:main:1', 'list:main:2', 'list:main:3', 'list:main:4', 'list:main:5', 'list:main:6']);
  });

  it('returns no subset when the bounded fan-out cannot establish every page', async () => {
    const trigger = normalizeVerifiedTrigger('push', { installation: { id: 42 }, repository: { id: 7 }, ref: 'refs/heads/main' }, 'delivery-push');
    if (trigger === null) throw new Error('test push did not normalize');

    const exactlyFiveHundred = capability({ page: (page) => Object.freeze({
      pulls: Object.freeze(Array.from({ length: 100 }, (_, index) => currentPull({ number: ((page - 1) * 100) + index + 1 }))),
      nextPage: page === 5 ? null : page + 1,
      normalizedBytes: 128,
    }) });
    await expect(resolveTriggerWork(trigger, exactlyFiveHundred.capability)).resolves.toMatchObject({
      status: 'fanout-work',
      work: expect.arrayContaining([expect.objectContaining({ pullNumber: 1 }), expect.objectContaining({ pullNumber: 500 })]),
    });
    expect(exactlyFiveHundred.calls).toHaveLength(5);

    const pageLimit = capability({ page: (page) => Object.freeze({
      pulls: Object.freeze([]),
      nextPage: page + 1,
      normalizedBytes: 2,
    }) });
    await expect(resolveTriggerWork(trigger, pageLimit.capability)).resolves.toEqual({
      status: 'fanout-incomplete', retryable: true, cause: 'page-limit', frontier: 11,
    });
    expect(pageLimit.calls).toHaveLength(10);

    const overBytes = capability({ page: () => Object.freeze({ pulls: Object.freeze([]), nextPage: null, normalizedBytes: 4_000_001 }) });
    await expect(resolveTriggerWork(trigger, overBytes.capability)).resolves.toEqual({
      status: 'fanout-incomplete', retryable: true, cause: 'response-bytes-limit', frontier: 1,
    });

    const transientPage = capability({ page: () => { throw new Error('temporary service failure'); } });
    await expect(resolveTriggerWork(trigger, transientPage.capability)).resolves.toEqual({
      status: 'fanout-incomplete', retryable: true, cause: 'page-read-failed', frontier: 1,
    });

    const timestamps = [0, 0, 10_001];
    const slowPage = capability();
    await expect(resolveTriggerWork(trigger, slowPage.capability, { now: () => timestamps.shift() ?? 10_001 })).resolves.toEqual({
      status: 'fanout-incomplete', retryable: true, cause: 'elapsed-limit', frontier: 1,
    });
    expect(slowPage.calls).toEqual(['list:main:1']);
  });
});
