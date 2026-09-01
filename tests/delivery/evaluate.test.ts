import { mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';

import type { AcquiredComparisonRoots } from '../../src/delivery/snapshot.js';
import { evaluateAcquiredComparison } from '../../src/delivery/evaluate.js';
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
