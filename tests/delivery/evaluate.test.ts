import { access, mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';

import type { AcquiredComparisonRoots } from '../../src/delivery/snapshot.js';
import { evaluateAcquiredComparison } from '../../src/delivery/evaluate.js';
import { evaluateCurrentComparison } from '../../src/delivery/evaluate.js';
import type { LocalComparisonResult } from '../../src/runtime/evaluate.js';

const acquired: AcquiredComparisonRoots[] = [];

afterEach(async () => {
  await Promise.all(acquired.splice(0).map(async (entry) => {
    await import('../../src/delivery/snapshot.js').then(({ cleanupComparisonRoots }) => cleanupComparisonRoots(entry));
  }));
});

async function roots(): Promise<{ base: string; head: string }> {
  const parent = await mkdtemp(join(tmpdir(), 'boundaryci-evaluate-test-'));
  const base = join(parent, 'base');
  const head = join(parent, 'head');
  await mkdir(base);
  await mkdir(head);
  await Promise.all([writeFile(join(base, '.boundaryci.yml'), 'version: 1\n'), writeFile(join(head, '.boundaryci.yml'), 'version: 1\n')]);
  return { base, head };
}

const evaluation: LocalComparisonResult = Object.freeze({
  status: 'input-configuration-failure',
  invalid: 'base',
  diagnostics: [],
});

describe('acquisition-aware local evaluation', () => {
  it('preserves a complete acquisition evaluation unchanged and removes both private roots', async () => {
    const privateRoots = await roots();
    const entry = {
      roots: privateRoots,
      result: {
        status: 'complete',
        config: { status: 'selected', authority: { source: 'built-in-default', config: {}, identity: 'a'.repeat(64) }, head: { status: 'absent' } },
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
        config: { status: 'selected', authority: { source: 'built-in-default', config: {}, identity: 'a'.repeat(64) }, head: { status: 'absent' } },
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

  it('only marks a source-free semantic envelope publishable after cleanup and final freshness', async () => {
    const privateRoots = await roots();
    const entry = {
      roots: privateRoots,
      result: {
        status: 'complete',
        config: { status: 'selected', authority: { source: 'built-in-default', config: {}, identity: 'a'.repeat(64) }, head: { status: 'absent' } },
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
        config: { status: 'selected', authority: { source: 'built-in-default', config: {}, identity: 'a'.repeat(64) }, head: { status: 'absent' } },
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
});
