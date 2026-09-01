import type { CurrentPull, GitBlob, GitCommit, GitTree } from '../../../src/delivery/index.js';

/** Stable, inert object identities for deterministic delivery tests. */
export const DELIVERY_FIXTURES = Object.freeze({
  installationId: 42,
  repositoryId: 7,
  pullNumber: 19,
  baseSha: 'a'.repeat(40),
  headSha: 'b'.repeat(40),
  baseTreeSha: 'c'.repeat(40),
  headTreeSha: 'd'.repeat(40),
  baseBlobSha: 'e'.repeat(40),
  headBlobSha: 'f'.repeat(40),
  sourcePath: 'index.ts',
  sourceBytes: Buffer.from('export const app = () => {};\n'),
});

export function currentPull(overrides: Partial<CurrentPull> = {}): CurrentPull {
  const base = { repositoryId: DELIVERY_FIXTURES.repositoryId, ref: 'main', sha: DELIVERY_FIXTURES.baseSha };
  const head = { repositoryId: DELIVERY_FIXTURES.repositoryId, sha: DELIVERY_FIXTURES.headSha };
  return Object.freeze({
    number: DELIVERY_FIXTURES.pullNumber,
    repositoryId: DELIVERY_FIXTURES.repositoryId,
    state: 'open',
    draft: false,
    merged: false,
    base,
    head,
    ...overrides,
  });
}

export function commit(sha: string): GitCommit {
  return Object.freeze({
    sha,
    treeSha: sha === DELIVERY_FIXTURES.baseSha ? DELIVERY_FIXTURES.baseTreeSha : DELIVERY_FIXTURES.headTreeSha,
  });
}

export function tree(sha: string): GitTree {
  return Object.freeze({
    sha,
    entries: Object.freeze([
      Object.freeze({
        path: DELIVERY_FIXTURES.sourcePath,
        mode: '100644',
        type: 'blob' as const,
        sha: sha === DELIVERY_FIXTURES.baseTreeSha ? DELIVERY_FIXTURES.baseBlobSha : DELIVERY_FIXTURES.headBlobSha,
        size: DELIVERY_FIXTURES.sourceBytes.byteLength,
      }),
    ]),
  });
}

export function blob(sha: string): GitBlob {
  return Object.freeze({
    sha,
    encoding: 'base64' as const,
    content: DELIVERY_FIXTURES.sourceBytes.toString('base64'),
    size: DELIVERY_FIXTURES.sourceBytes.byteLength,
  });
}

/** Deliberately malformed but non-secret values used by later boundary tests. */
export const MALFORMED_DELIVERY_FIXTURES = Object.freeze({
  malformedCommit: Object.freeze({ sha: 'not-a-sha', treeSha: null }),
  malformedTree: Object.freeze({ sha: null, entries: null }),
  malformedBlob: Object.freeze({ sha: null, encoding: 'utf8', content: null, size: -1 }),
  transientFailure: Object.freeze({ code: 'temporary-service-failure' }),
  persistentFailure: Object.freeze({ code: 'authorization-failure' }),
});
