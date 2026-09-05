import { access, chmod, mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';

import { SnapshotRollbackCleanupFailure, type AcquiredComparisonRoots } from '../../src/delivery/snapshot.js';
import { evaluateAcquiredComparison } from '../../src/delivery/evaluate.js';
import { evaluateCurrentComparison } from '../../src/delivery/evaluate.js';
import { BUILTIN_CONFIG, effectiveConfigIdentity } from '../../src/config/model.js';
import { evaluateLocalComparison, type LocalComparisonResult } from '../../src/runtime/evaluate.js';

const acquired: AcquiredComparisonRoots[] = [];

afterEach(async () => {
  await Promise.all(acquired.splice(0).map(async (entry) => {
    await import('../../src/delivery/snapshot.js').then(({ cleanupComparisonRoots }) => cleanupComparisonRoots(entry));
  }));
});

async function roots(): Promise<{ base: string; head: string }> {
  const parent = join(tmpdir(), 'boundaryci-snapshot-v1');
  await mkdir(parent, { recursive: true, mode: 0o700 });
  await chmod(parent, 0o700);
  const [base, head] = await Promise.all([
    mkdtemp(join(parent, 'boundaryci-snapshot-')),
    mkdtemp(join(parent, 'boundaryci-snapshot-')),
  ]);
  await Promise.all([chmod(base, 0o700), chmod(head, 0o700)]);
  await Promise.all([writeFile(join(base, '.boundaryci.yml'), 'version: 1\n'), writeFile(join(head, '.boundaryci.yml'), 'version: 1\n')]);
  return { base, head };
}

const evaluation: LocalComparisonResult = Object.freeze({
  status: 'input-configuration-failure',
  invalid: 'base',
  diagnostics: [],
});

function selectedConfig() {
  return {
    status: 'selected' as const,
    authority: {
      source: 'built-in-default' as const,
      config: structuredClone(BUILTIN_CONFIG),
      identity: effectiveConfigIdentity(BUILTIN_CONFIG),
    },
    head: { status: 'absent' as const },
  };
}

describe('acquisition-aware local evaluation', () => {
  it('preserves a complete acquisition evaluation unchanged and removes both private roots', async () => {
    const privateRoots = await roots();
    const entry = {
      roots: privateRoots,
      result: {
        status: 'complete',
        config: selectedConfig(),
        snapshots: {
          base: { commitSha: 'a'.repeat(40), treeSha: 'b'.repeat(40), sourceFileCount: 0, sourceBytes: 0 },
          head: { commitSha: 'c'.repeat(40), treeSha: 'd'.repeat(40), sourceFileCount: 0, sourceBytes: 0 },
        },
        causes: [],
        semanticUsability: 'complete',
      },
    } as unknown as AcquiredComparisonRoots;
    acquired.push(entry);

    const result = await evaluateAcquiredComparison(entry, async () => evaluation);
    expect(result).toMatchObject({ status: 'complete', semanticUsability: 'complete', evaluation });
    if (result.status !== 'complete') throw new Error('expected complete evaluation');
    expect(result.evaluation).toEqual(evaluation);
    expect(result).not.toHaveProperty('roots');
  });

  it('retains only present evidence claims for a safely incomplete acquisition', async () => {
    const privateRoots = await roots();
    const entry = {
      roots: privateRoots,
      result: {
        status: 'incomplete',
        config: selectedConfig(),
        snapshots: {
          base: { commitSha: 'a'.repeat(40), treeSha: 'b'.repeat(40), sourceFileCount: 1, sourceBytes: 1 },
          head: { commitSha: 'c'.repeat(40), treeSha: 'd'.repeat(40), sourceFileCount: 1, sourceBytes: 1 },
        },
        causes: [{ code: 'source-file-limit', frontier: 'src/app.ts', configured: 0, consumed: 1 }],
        semanticUsability: 'positive-evidence-only',
        allowedClaims: ['present-observations', 'present-requirements'],
      },
    } as unknown as AcquiredComparisonRoots;
    acquired.push(entry);

    const result = await evaluateAcquiredComparison(entry, async () => evaluation);
    expect(result).toMatchObject({
      status: 'incomplete', semanticUsability: 'positive-evidence-only', allowedClaims: ['present-observations', 'present-requirements'],
    });
    expect(JSON.stringify(result)).not.toMatch(/unchanged|reduction|removal|absence/u);
  });

  it('does not invoke the evaluator for configuration or acquisition security failures', async () => {
    const privateRoots = await roots();
    const entry = {
      roots: privateRoots,
      result: { status: 'acquisition-security-failure', reason: 'unsafe-path' },
    } as unknown as AcquiredComparisonRoots;
    acquired.push(entry);
    const evaluate = async (): Promise<LocalComparisonResult> => {
      throw new Error('evaluator must not be called');
    };

    await expect(evaluateAcquiredComparison(entry, evaluate)).resolves.toEqual({
      status: 'diagnostic-only', acquisition: { status: 'acquisition-security-failure', reason: 'unsafe-path' },
    });
  });
});

describe('Phase 6 handoff envelope', () => {
  const current = {
    number: 19,
    repositoryId: 7,
    state: 'open' as const,
    draft: false,
    merged: false,
    base: { repositoryId: 7, ref: 'main', sha: 'a'.repeat(40) },
    head: { repositoryId: 7, sha: 'b'.repeat(40) },
  };

  it('returns a sanitized cleanup-failure envelope when partial-root rollback cannot be verified', async () => {
    const result = await evaluateCurrentComparison({
      work: { installationId: 1, repositoryId: 7, pullNumber: 19, baseSha: 'a'.repeat(40), headSha: 'b'.repeat(40), evaluatorIdentity: 'boundaryci-evaluator-v1' },
      baseRef: 'main', triggerDeliveryIds: [],
      acquire: async () => { throw new SnapshotRollbackCleanupFailure(); },
      getCurrentPull: async () => current,
    });
    expect(result).toMatchObject({ lifecycle: 'cleanup-failure', handoff: 'none', reason: 'private-root-cleanup-not-verified', work: { pullNumber: 19 } });
  });

  it('only marks a source-free semantic envelope publishable after cleanup and final freshness', async () => {
    const privateRoots = await roots();
    const entry = {
      roots: privateRoots,
      result: {
        status: 'complete',
        config: selectedConfig(),
        snapshots: {
          base: { commitSha: 'a'.repeat(40), treeSha: 'b'.repeat(40), sourceFileCount: 0, sourceBytes: 0 },
          head: { commitSha: 'b'.repeat(40), treeSha: 'c'.repeat(40), sourceFileCount: 0, sourceBytes: 0 },
        }, causes: [], semanticUsability: 'complete',
      },
    } as unknown as AcquiredComparisonRoots;
    acquired.push(entry);
    let finalRead = false;
    const result = await evaluateCurrentComparison({
      work: { installationId: 1, repositoryId: 7, pullNumber: 19, baseSha: 'a'.repeat(40), headSha: 'b'.repeat(40), evaluatorIdentity: 'boundaryci-evaluator-v1' },
      baseRef: 'main',
      triggerDeliveryIds: ['delivery-1'],
      acquire: async () => entry,
      evaluator: async () => evaluation,
      getCurrentPull: async () => {
        finalRead = true;
        await expect(access(privateRoots.base)).rejects.toMatchObject({ code: 'ENOENT' });
        await expect(access(privateRoots.head)).rejects.toMatchObject({ code: 'ENOENT' });
        return current;
      },
    });
    expect(finalRead).toBe(true);
    expect(result).toMatchObject({ schemaVersion: 1, lifecycle: 'current', handoff: 'publishable-semantic', phase6FreshnessRequired: true });
    expect(JSON.stringify(result)).not.toContain(privateRoots.base);
    expect(JSON.stringify(result)).not.toContain(privateRoots.head);
  });

  it('returns stale without handoff when final authenticated identity drifts', async () => {
    const privateRoots = await roots();
    const entry = {
      roots: privateRoots,
      result: {
        status: 'runtime-infrastructure-failure', reason: 'runtime-operation-failed',
      },
    } as unknown as AcquiredComparisonRoots;
    acquired.push(entry);
    const result = await evaluateCurrentComparison({
      work: { installationId: 1, repositoryId: 7, pullNumber: 19, baseSha: 'a'.repeat(40), headSha: 'b'.repeat(40), evaluatorIdentity: 'boundaryci-evaluator-v1' },
      baseRef: 'main', triggerDeliveryIds: [],
      acquire: async () => entry,
      getCurrentPull: async () => ({ ...current, head: { ...current.head, sha: 'd'.repeat(40) } }),
    });
    expect(result).toMatchObject({ lifecycle: 'stale', handoff: 'none' });
  });

  it('keeps evaluator failure diagnostic-only after cleanup and current freshness', async () => {
    const privateRoots = await roots();
    const entry = {
      roots: privateRoots,
      result: {
        status: 'complete',
        config: selectedConfig(),
        snapshots: {
          base: { commitSha: 'a'.repeat(40), treeSha: 'b'.repeat(40), sourceFileCount: 0, sourceBytes: 0 },
          head: { commitSha: 'b'.repeat(40), treeSha: 'c'.repeat(40), sourceFileCount: 0, sourceBytes: 0 },
        }, causes: [], semanticUsability: 'complete',
      },
    } as unknown as AcquiredComparisonRoots;
    acquired.push(entry);
    const result = await evaluateCurrentComparison({
      work: { installationId: 1, repositoryId: 7, pullNumber: 19, baseSha: 'a'.repeat(40), headSha: 'b'.repeat(40), evaluatorIdentity: 'boundaryci-evaluator-v1' },
      baseRef: 'main', triggerDeliveryIds: [], acquire: async () => entry,
      evaluator: async () => { throw new Error('target-controlled detail must not escape'); },
      getCurrentPull: async () => current,
    });
    expect(result).toMatchObject({ lifecycle: 'current', handoff: 'diagnostic-only', diagnostic: { code: 'evaluator-runtime-failure' } });
    expect(result).not.toHaveProperty('semantic');
    expect(JSON.stringify(result)).not.toContain('target-controlled detail');
  });

  it('keeps acquisition-security failure as a non-handoff trust outcome', async () => {
    const privateRoots = await roots();
    const entry = { roots: privateRoots, result: { status: 'acquisition-security-failure', reason: 'unsafe-path' } } as unknown as AcquiredComparisonRoots;
    acquired.push(entry);
    const result = await evaluateCurrentComparison({
      work: { installationId: 1, repositoryId: 7, pullNumber: 19, baseSha: 'a'.repeat(40), headSha: 'b'.repeat(40), evaluatorIdentity: 'boundaryci-evaluator-v1' },
      baseRef: 'main', triggerDeliveryIds: [], acquire: async () => entry, getCurrentPull: async () => current,
    });
    expect(result).toMatchObject({ lifecycle: 'trust-failure', handoff: 'none', reason: 'acquisition-security-failure' });
  });

  it('cleans owned roots when malformed acquisition evidence is rejected before evaluation', async () => {
    const privateRoots = await roots();
    const secret = 'acquisition-result-secret-sentinel';
    const entry = {
      roots: privateRoots,
      result: { status: 'runtime-infrastructure-failure', reason: 'runtime-operation-failed', token: secret },
    } as unknown as AcquiredComparisonRoots;
    acquired.push(entry);
    let evaluatorCalled = false;
    const result = await evaluateCurrentComparison({
      work: { installationId: 1, repositoryId: 7, pullNumber: 19, baseSha: 'a'.repeat(40), headSha: 'b'.repeat(40), evaluatorIdentity: 'boundaryci-evaluator-v1' },
      baseRef: 'main', triggerDeliveryIds: [], acquire: async () => entry,
      evaluator: async () => {
        evaluatorCalled = true;
        return evaluation;
      },
      getCurrentPull: async () => current,
    });
    expect(evaluatorCalled).toBe(false);
    expect(result).toMatchObject({ lifecycle: 'runtime-infrastructure-failure', handoff: 'none' });
    expect(JSON.stringify(result)).not.toContain(secret);
    await expect(access(privateRoots.base)).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(access(privateRoots.head)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('never recursively removes an unowned acquisition path', async () => {
    const sentinelParent = await mkdtemp(join(tmpdir(), 'boundaryci-sentinel-'));
    const sentinel = join(sentinelParent, 'must-survive');
    await mkdir(sentinel);
    await writeFile(join(sentinel, 'sentinel.txt'), 'must-not-be-removed');
    const privateRoots = await roots();
    const entry = {
      roots: { base: sentinel, head: privateRoots.head },
      result: { status: 'runtime-infrastructure-failure', reason: 'runtime-operation-failed' },
    } as unknown as AcquiredComparisonRoots;
    const result = await evaluateCurrentComparison({
      work: { installationId: 1, repositoryId: 7, pullNumber: 19, baseSha: 'a'.repeat(40), headSha: 'b'.repeat(40), evaluatorIdentity: 'boundaryci-evaluator-v1' },
      baseRef: 'main', triggerDeliveryIds: [], acquire: async () => entry, getCurrentPull: async () => current,
    });
    expect(result).toMatchObject({ lifecycle: 'trust-failure', handoff: 'none', reason: 'invalid-acquisition-root-handle' });
    await expect(access(join(sentinel, 'sentinel.txt'))).resolves.toBeUndefined();
    await import('node:fs/promises').then(({ rm }) => rm(sentinelParent, { recursive: true, force: true }));
    await import('../../src/delivery/snapshot.js').then(({ cleanupComparisonRoots }) => cleanupComparisonRoots({ roots: privateRoots }));
  });

  it('turns evaluator output with an unknown field into a source-free diagnostic-only envelope', async () => {
    const privateRoots = await roots();
    const secret = 'evaluator-output-secret-sentinel';
    const entry = {
      roots: privateRoots,
      result: {
        status: 'complete', config: selectedConfig(),
        snapshots: {
          base: { commitSha: 'a'.repeat(40), treeSha: 'b'.repeat(40), sourceFileCount: 0, sourceBytes: 0 },
          head: { commitSha: 'b'.repeat(40), treeSha: 'c'.repeat(40), sourceFileCount: 0, sourceBytes: 0 },
        }, causes: [], semanticUsability: 'complete',
      },
    } as unknown as AcquiredComparisonRoots;
    acquired.push(entry);
    const result = await evaluateCurrentComparison({
      work: { installationId: 1, repositoryId: 7, pullNumber: 19, baseSha: 'a'.repeat(40), headSha: 'b'.repeat(40), evaluatorIdentity: 'boundaryci-evaluator-v1' },
      baseRef: 'main', triggerDeliveryIds: [], acquire: async () => entry,
      evaluator: async () => ({ ...evaluation, token: secret }) as never,
      getCurrentPull: async () => current,
    });
    expect(result).toMatchObject({ lifecycle: 'current', handoff: 'diagnostic-only', diagnostic: { code: 'evaluator-runtime-failure' } });
    expect(JSON.stringify(result)).not.toContain(secret);
  });

  it('rejects unknown nested comparison and policy evidence before it can become publishable', async () => {
    const sentinel = 'nested-comparison-policy-secret-sentinel';
    const mutate = [
      (value: Record<string, unknown>) => {
        const comparison = value.comparison as Record<string, unknown>;
        comparison.boundary = { ...(comparison.boundary as Record<string, unknown>), sentinel };
      },
      (value: Record<string, unknown>) => {
        const comparison = value.comparison as Record<string, unknown>;
        comparison.changes = [{ permission: 'issues', base: 'none', head: 'read', change: 'expansion', sentinel }];
      },
      (value: Record<string, unknown>) => {
        const policy = value.policy as Record<string, unknown>;
        policy.policy = { ...(policy.policy as Record<string, unknown>), sentinel };
      },
      (value: Record<string, unknown>) => {
        const policy = value.policy as Record<string, unknown>;
        policy.comparison = { ...(policy.comparison as Record<string, unknown>), sentinel };
      },
    ];

    for (const alter of mutate) {
      const privateRoots = await roots();
      const entry = {
        roots: privateRoots,
        result: {
          status: 'complete', config: selectedConfig(),
          snapshots: {
            base: { commitSha: 'a'.repeat(40), treeSha: 'b'.repeat(40), sourceFileCount: 0, sourceBytes: 0 },
            head: { commitSha: 'b'.repeat(40), treeSha: 'c'.repeat(40), sourceFileCount: 0, sourceBytes: 0 },
          }, causes: [], semanticUsability: 'complete',
        },
      } as unknown as AcquiredComparisonRoots;
      acquired.push(entry);
      const valid = await evaluateLocalComparison(privateRoots.base, privateRoots.head);
      if (valid.status !== 'selected' || valid.comparison.status !== 'complete') throw new Error('fixture must produce a selected complete comparison');
      const compromised = structuredClone(valid) as unknown as Record<string, unknown>;
      alter(compromised);
      const result = await evaluateCurrentComparison({
        work: { installationId: 1, repositoryId: 7, pullNumber: 19, baseSha: 'a'.repeat(40), headSha: 'b'.repeat(40), evaluatorIdentity: 'boundaryci-evaluator-v1' },
        baseRef: 'main', triggerDeliveryIds: [], acquire: async () => entry,
        evaluator: async () => compromised as LocalComparisonResult,
        getCurrentPull: async () => current,
      });
      expect(result).toMatchObject({ lifecycle: 'current', handoff: 'diagnostic-only', diagnostic: { code: 'evaluator-runtime-failure' } });
      expect(JSON.stringify(result)).not.toContain(sentinel);
    }
  });
});
