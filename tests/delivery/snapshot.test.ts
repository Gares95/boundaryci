import { access, readFile, readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { acquireComparisonRoots, cleanupComparisonRoots, SnapshotRollbackCleanupFailure } from '../../src/delivery/snapshot.js';
import { DELIVERY_LIMITS_V1 } from '../../src/delivery/limits.js';
import { createGitHubReadFake } from './support.js';
import { DELIVERY_FIXTURES, blob, commit, tree } from './fixtures/index.js';

const rootAllocation = vi.hoisted(() => ({ count: 0, failAt: 0, failRollback: false, failRollbackOnAllocation: false }));

vi.mock('node:fs/promises', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs/promises')>();
  return {
    ...actual,
    mkdtemp: async (...args: Parameters<typeof actual.mkdtemp>) => {
      rootAllocation.count += 1;
      if (rootAllocation.count === rootAllocation.failAt) {
        rootAllocation.failRollback = rootAllocation.failRollbackOnAllocation;
        throw new Error('second-allocation-failure');
      }
      return actual.mkdtemp(...args);
    },
    rm: async (...args: Parameters<typeof actual.rm>) => {
      if (rootAllocation.failRollback) throw new Error('rollback-removal-failure');
      return actual.rm(...args);
    },
  };
});

const roots: Array<Awaited<ReturnType<typeof acquireComparisonRoots>>> = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((acquired) => cleanupComparisonRoots(acquired)));
});

describe('immutable comparison snapshot acquisition', () => {
  it('removes the first private root if allocating the second root fails', async () => {
    const parent = join(tmpdir(), 'boundaryci-snapshot-v1');
    const before = new Set(await readdir(parent).catch(() => []));
    rootAllocation.failAt = rootAllocation.count + 2;
    await expect(acquireComparisonRoots({
      capability: createGitHubReadFake().capability,
      baseSha: DELIVERY_FIXTURES.baseSha,
      headSha: DELIVERY_FIXTURES.headSha,
    })).rejects.toThrow('second-allocation-failure');
    rootAllocation.failAt = 0;
    expect(new Set(await readdir(parent))).toEqual(before);
  });

  it('surfaces a fail-closed rollback cleanup failure when second allocation and removal both fail', async () => {
    rootAllocation.failRollbackOnAllocation = true;
    rootAllocation.failAt = rootAllocation.count + 2;
    await expect(acquireComparisonRoots({
      capability: createGitHubReadFake().capability,
      baseSha: DELIVERY_FIXTURES.baseSha,
      headSha: DELIVERY_FIXTURES.headSha,
    })).rejects.toBeInstanceOf(SnapshotRollbackCleanupFailure);
    rootAllocation.failAt = 0;
    rootAllocation.failRollback = false;
    rootAllocation.failRollbackOnAllocation = false;
  });

  it('bootstraps exact base/head configuration before selecting and materializing source blobs', async () => {
    const configBytes = Buffer.from('version: 1\nanalysis:\n  include: ["**/*.ts"]\n');
    const sourceBytes = Buffer.from('export const current = true;\n');
    const baseConfigSha = '1'.repeat(40);
    const headConfigSha = '2'.repeat(40);
    const baseSourceSha = '3'.repeat(40);
    const headSourceSha = '4'.repeat(40);
    const baseTreeSha = '5'.repeat(40);
    const headTreeSha = '6'.repeat(40);
    const baseSha = '7'.repeat(40);
    const headSha = '8'.repeat(40);
    const read = createGitHubReadFake({
      commit: (sha) => ({ sha, treeSha: sha === baseSha ? baseTreeSha : headTreeSha }),
      tree: (sha) => ({
        sha,
        entries: [
          { path: '.boundaryci.yml', mode: '100644', type: 'blob', sha: sha === baseTreeSha ? baseConfigSha : headConfigSha, size: configBytes.byteLength },
          { path: 'src/app.ts', mode: '100644', type: 'blob', sha: sha === baseTreeSha ? baseSourceSha : headSourceSha, size: sourceBytes.byteLength },
        ],
      }),
      blob: (sha) => {
        const bytes = sha === baseConfigSha || sha === headConfigSha ? configBytes : sourceBytes;
        return { sha, encoding: 'base64', content: bytes.toString('base64'), size: bytes.byteLength };
      },
    });

    const acquired = await acquireComparisonRoots({ capability: read.capability, baseSha, headSha });
    roots.push(acquired);

    expect(acquired.result.status).toBe('complete');
    if (acquired.result.status !== 'complete') throw new Error('expected complete acquisition');
    expect(acquired.result.config.authority.source).toBe('base');
    expect(await readFile(`${acquired.roots.base}/src/app.ts`, 'utf8')).toBe(sourceBytes.toString('utf8'));
    expect(await readFile(`${acquired.roots.head}/src/app.ts`, 'utf8')).toBe(sourceBytes.toString('utf8'));
    expect(read.calls).toEqual([
      `commit:${baseSha}`, `tree:${baseTreeSha}`, `blob:${baseConfigSha}`,
      `commit:${headSha}`, `tree:${headTreeSha}`, `blob:${headConfigSha}`,
      `blob:${baseSourceSha}`, `blob:${headSourceSha}`,
    ]);
  });

  it('keeps fully validated positive blobs but marks post-bootstrap truncation incomplete', async () => {
    const read = createGitHubReadFake({
      tree: (sha) => ({ ...tree(sha), truncated: true }),
    });
    const acquired = await acquireComparisonRoots({
      capability: read.capability,
      baseSha: DELIVERY_FIXTURES.baseSha,
      headSha: DELIVERY_FIXTURES.headSha,
    });
    roots.push(acquired);

    expect(acquired.result.status).toBe('input-configuration-failure');
    if (acquired.result.status !== 'input-configuration-failure') throw new Error('expected config failure');
    expect(acquired.result.reason).toBe('configuration-census-incomplete');
    expect(read.calls).toEqual([
      `commit:${DELIVERY_FIXTURES.baseSha}`,
      `tree:${DELIVERY_FIXTURES.baseTreeSha}`,
    ]);
  });

  it('fails closed on an unsafe path before scope filtering and cleans both roots', async () => {
    const unsafe = createGitHubReadFake({
      tree: (sha) => ({
        sha,
        entries: [{ path: '../outside.ts', mode: '100644', type: 'blob', sha: DELIVERY_FIXTURES.baseBlobSha, size: 1 }],
      }),
    });
    const acquired = await acquireComparisonRoots({
      capability: unsafe.capability,
      baseSha: DELIVERY_FIXTURES.baseSha,
      headSha: DELIVERY_FIXTURES.headSha,
    });
    roots.push(acquired);

    expect(acquired.result).toMatchObject({ status: 'acquisition-security-failure', reason: 'unsafe-path' });
    await cleanupComparisonRoots(acquired);
    await expect(access(acquired.roots.base)).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(access(acquired.roots.head)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('exposes frozen, checked transport ceilings', () => {
    expect(DELIVERY_LIMITS_V1).toEqual({
      maxTreeEntries: 50_000,
      maxSourceFiles: 5_000,
      maxSourceFileBytes: 2_000_000,
      maxTotalSourceBytes: 64_000_000,
      maxTreeRequests: 2_000,
      maxBlobRequests: 5_002,
      maxAcquisitionWork: 70_000,
      maxElapsedMilliseconds: 60_000,
    });
  });

  it('keeps the first validated source byte but returns positive-evidence-only at the next source-file boundary', async () => {
    const first = Buffer.from('export const first = true;\n');
    const second = Buffer.from('export const second = true;\n');
    const baseTree = '9'.repeat(40);
    const headTree = 'a'.repeat(40);
    const firstBlob = 'b'.repeat(40);
    const secondBlob = 'c'.repeat(40);
    const baseSha = 'd'.repeat(40);
    const headSha = 'e'.repeat(40);
    const read = createGitHubReadFake({
      commit: (sha) => ({ sha, treeSha: sha === baseSha ? baseTree : headTree }),
      tree: (sha) => ({
        sha,
        entries: [
          { path: 'a.ts', mode: '100644', type: 'blob', sha: firstBlob, size: first.byteLength },
          { path: 'b.ts', mode: '100644', type: 'blob', sha: secondBlob, size: second.byteLength },
        ],
      }),
      blob: (sha) => {
        const bytes = sha === firstBlob ? first : second;
        return { sha, encoding: 'base64', content: bytes.toString('base64'), size: bytes.byteLength };
      },
    });
    const acquired = await acquireComparisonRoots({
      capability: read.capability,
      baseSha,
      headSha,
      limits: { ...DELIVERY_LIMITS_V1, maxSourceFiles: 1 },
    });
    roots.push(acquired);

    expect(acquired.result).toMatchObject({
      status: 'incomplete', semanticUsability: 'positive-evidence-only', causes: [{ code: 'source-file-limit', frontier: 'b.ts' }],
    });
    expect(await readFile(`${acquired.roots.base}/a.ts`, 'utf8')).toBe(first.toString('utf8'));
    await expect(readFile(`${acquired.roots.base}/b.ts`, 'utf8')).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('records the actual materialized subset for each revision under a shared cutoff', async () => {
    const bytes = Buffer.from('export const present = true;\n');
    const baseTree = '1'.repeat(40);
    const headTree = '2'.repeat(40);
    const baseSha = '3'.repeat(40);
    const headSha = '4'.repeat(40);
    const ids = ['5', '6', '7', '8'].map((digit) => digit.repeat(40));
    const read = createGitHubReadFake({
      commit: (sha) => ({ sha, treeSha: sha === baseSha ? baseTree : headTree }),
      tree: (sha) => ({
        sha,
        entries: ids.map((id, index) => ({ path: `src/${index}.ts`, mode: '100644' as const, type: 'blob' as const, sha: id, size: bytes.byteLength })),
      }),
      blob: (sha) => ({ sha, encoding: 'base64' as const, content: bytes.toString('base64'), size: bytes.byteLength }),
    });
    const result = await acquireComparisonRoots({
      capability: read.capability, baseSha, headSha,
      limits: { ...DELIVERY_LIMITS_V1, maxSourceFiles: 5 },
    });
    roots.push(result);
    expect(result.result).toMatchObject({
      status: 'incomplete',
      snapshots: {
        base: { sourceFileCount: 4, sourceBytes: bytes.byteLength * 4 },
        head: { sourceFileCount: 1, sourceBytes: bytes.byteLength },
      },
    });
  });

  it('reports relevant symlinks as incomplete and rejects non-UTF8 path identities before any blob read', async () => {
    const symlink = createGitHubReadFake({
      tree: (sha) => ({ sha, entries: [{ path: 'src/link.ts', mode: '120000', type: 'blob', sha: DELIVERY_FIXTURES.baseBlobSha, size: 1 }] }),
    });
    const incomplete = await acquireComparisonRoots({
      capability: symlink.capability,
      baseSha: DELIVERY_FIXTURES.baseSha,
      headSha: DELIVERY_FIXTURES.headSha,
    });
    roots.push(incomplete);
    expect(incomplete.result).toMatchObject({ status: 'incomplete', causes: [{ code: 'relevant-symlink', frontier: 'src/link.ts' }] });
    expect(symlink.calls.some((call) => call.startsWith('blob:'))).toBe(false);

    const malformed = createGitHubReadFake({
      tree: (sha) => ({ sha, entries: [{ path: '\ud800.ts', mode: '100644', type: 'blob', sha: DELIVERY_FIXTURES.baseBlobSha, size: 1 }] }),
    });
    const failed = await acquireComparisonRoots({
      capability: malformed.capability,
      baseSha: DELIVERY_FIXTURES.baseSha,
      headSha: DELIVERY_FIXTURES.headSha,
    });
    roots.push(failed);
    expect(failed.result).toMatchObject({ status: 'acquisition-security-failure', reason: 'unsafe-path' });
  });
});
