import { access, readFile } from 'node:fs/promises';
import { afterEach, describe, expect, it } from 'vitest';

import { acquireComparisonRoots, cleanupComparisonRoots } from '../../src/delivery/snapshot.js';
import { DELIVERY_LIMITS_V1 } from '../../src/delivery/limits.js';
import { createGitHubReadFake } from './support.js';
import { DELIVERY_FIXTURES, blob, commit, tree } from './fixtures/index.js';

const roots: Array<Awaited<ReturnType<typeof acquireComparisonRoots>>> = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((acquired) => cleanupComparisonRoots(acquired)));
});

describe('immutable comparison snapshot acquisition', () => {
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
});
