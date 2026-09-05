import { access, mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';

import { emitDeliveryEvent, type DeliveryLogEvent } from '../../src/delivery/logging.js';
import { createRepositoryReadCapability, SanitizedGitHubReadError } from '../../src/delivery/github-read.js';
import { cleanupComparisonRoots, cleanupSnapshotResidue } from '../../src/delivery/snapshot.js';
import { validateDeliveryEnvelope } from '../../src/delivery/contract.js';
import { createRuntimeSentinels } from './support.js';

const temporaryParents: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryParents.splice(0).map(async (path) => rm(path, { force: true, recursive: true })));
});

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

  it('contains a logging sink failure without changing the validated operational event', () => {
    const event = validEvent();
    const emitted = emitDeliveryEvent(event, {
      emit: () => {
        throw new Error('sink-failure-must-not-cross-delivery-boundary');
      },
    });

    expect(emitted).toEqual(event);
    expect(Object.isFrozen(emitted)).toBe(true);
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

  it('rejects every credential-bearing or structurally publishable fanout-incomplete envelope', () => {
    const sentinels = createRuntimeSentinels();
    const valid = {
      schemaVersion: 1,
      lifecycle: 'fanout-incomplete',
      handoff: 'none',
      work: null,
      reason: 'fanout-page-read-failed',
    };
    expect(() => validateDeliveryEnvelope(valid)).not.toThrow();
    for (const candidate of [
      { ...valid, reason: sentinels.installationToken },
      { ...valid, newestIdentity: { installationId: 42, repositoryId: 7, pullNumber: 19, baseSha: 'a'.repeat(40), headSha: 'b'.repeat(40), evaluatorIdentity: 'boundaryci-evaluator-v1' } },
      { ...valid, work: { installationId: 42, repositoryId: 7, pullNumber: 19, baseSha: 'a'.repeat(40), headSha: 'b'.repeat(40), evaluatorIdentity: 'boundaryci-evaluator-v1' } },
      { ...valid, handoff: 'diagnostic-only' },
      { ...valid, source: sentinels.source },
    ]) expect(() => validateDeliveryEnvelope(candidate)).toThrow();
  });

  it('enforces finite source-free reasons and identity shapes for every non-handoff lifecycle', () => {
    const sentinels = createRuntimeSentinels();
    const work = { installationId: 42, repositoryId: 7, pullNumber: 19, baseSha: 'a'.repeat(40), headSha: 'b'.repeat(40), evaluatorIdentity: 'boundaryci-evaluator-v1' };
    const cases = [
      { lifecycle: 'stale', reason: 'authenticated-comparison-drift', work },
      { lifecycle: 'superseded', reason: 'newer-comparison-superseded', work },
      { lifecycle: 'cancelled', reason: 'comparison-cancelled', work },
      { lifecycle: 'obsolete', reason: 'pull-request-obsolete', work },
      { lifecycle: 'trust-failure', reason: 'invalid-acquisition-root-handle', work: null },
      { lifecycle: 'cleanup-failure', reason: 'private-root-cleanup-not-verified', work },
      { lifecycle: 'runtime-infrastructure-failure', reason: 'final-freshness-read-failed', work },
    ] as const;
    for (const candidate of cases) {
      const envelope = { schemaVersion: 1, handoff: 'none', ...candidate };
      expect(() => validateDeliveryEnvelope(envelope)).not.toThrow();
      expect(() => validateDeliveryEnvelope({ ...envelope, reason: sentinels.externalError })).toThrow();
      expect(() => validateDeliveryEnvelope({ ...envelope, newestIdentity: work })).toThrow();
    }
    expect(() => validateDeliveryEnvelope({ schemaVersion: 1, lifecycle: 'stale', handoff: 'none', work: null, reason: 'authenticated-comparison-drift' })).toThrow();
  });

  it('refuses cleanup targets outside the private snapshot parent', async () => {
    const sentinels = createRuntimeSentinels();
    const parent = await mkdtemp(join(tmpdir(), 'boundaryci-non-leakage-'));
    temporaryParents.push(parent);
    const base = join(parent, 'base');
    const head = join(parent, 'head');
    await Promise.all([mkdir(base), mkdir(head)]);
    await Promise.all([
      writeFile(join(base, 'source.ts'), sentinels.source!),
      writeFile(join(head, '.boundaryci.yml'), sentinels.config!),
    ]);

    const cleaned = await cleanupComparisonRoots(
      { roots: { base, head } },
      {
        removeRoot: async () => { throw new Error('unowned roots must never reach recursive cleanup'); },
      },
    );

    expect(cleaned).toBe(false);
    await expect(access(base)).resolves.toBeUndefined();
    await expect(access(head)).resolves.toBeUndefined();
  });

  it('deletes untrusted startup residue without following a symbolic link or retaining source bytes', async () => {
    const sentinels = createRuntimeSentinels();
    const parent = await mkdtemp(join(tmpdir(), 'boundaryci-residue-'));
    temporaryParents.push(parent);
    const external = await mkdtemp(join(tmpdir(), 'boundaryci-external-'));
    temporaryParents.push(external);
    await writeFile(join(parent, 'boundaryci-snapshot-stale-source'), sentinels.source!);
    await writeFile(join(external, 'outside'), sentinels.config!);
    await symlink(external, join(parent, 'boundaryci-snapshot-stale-link'));

    await expect(cleanupSnapshotResidue(parent)).resolves.toBe(true);
    await expect(access(join(parent, 'boundaryci-snapshot-stale-source'))).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(access(join(parent, 'boundaryci-snapshot-stale-link'))).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(access(join(external, 'outside'))).resolves.toBeUndefined();
  });
});
