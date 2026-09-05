import { describe, expect, it } from 'vitest';

import {
  MINIMUM_REGISTRATION_EQUIVALENT,
  createProbotRepositoryReadCapability,
  createRepositoryReadCapability,
  type RepositoryReadIssueRequest,
  type RepositoryReadProvider,
  SanitizedGitHubReadError,
} from '../../src/delivery/github-read.js';
import { DELIVERY_FIXTURES, blob, commit, currentPull, tree } from './fixtures/index.js';

const identity = Object.freeze({ installationId: DELIVERY_FIXTURES.installationId, repositoryId: DELIVERY_FIXTURES.repositoryId });

function provider(overrides: Partial<RepositoryReadProvider> = {}): RepositoryReadProvider {
  return Object.freeze({
    async issue(request: RepositoryReadIssueRequest) {
      return Object.freeze({
        credentialScope: 'issuance-narrowed' as const,
        repositoryIds: Object.freeze([request.repositoryIds[0]!]),
        permissions: Object.freeze({ contents: 'read', pull_requests: 'read' }),
        transport: Object.freeze({
          getCurrentPull: async (pullNumber: number) => currentPull({ number: pullNumber }),
          listOpenPullsByBase: async () => Object.freeze({ pulls: Object.freeze([]), nextPage: null, normalizedBytes: 2 }),
          getCommit: async (sha: string) => commit(sha),
          getTree: async (sha: string) => tree(sha),
          getBlob: async (sha: string) => blob(sha),
        }),
      });
    },
    ...overrides,
  });
}

describe('repository-scoped GitHub read capability', () => {
  it('adapts only the fixed minimum-registration-equivalent Probot REST surface', async () => {
    const calls: string[] = [];
    const octokit = {
      rest: {
        pulls: {
          get: async () => {
            calls.push('pulls.get');
            return { data: { number: 19, id: 7, state: 'open', draft: false, merged: false, base: { repo: { id: 7 }, ref: 'main', sha: DELIVERY_FIXTURES.baseSha }, head: { repo: { id: 7 }, sha: DELIVERY_FIXTURES.headSha } } };
          },
          list: async () => {
            calls.push('pulls.list');
            return { data: [] };
          },
        },
        git: {
          getCommit: async () => {
            calls.push('git.getCommit');
            return { data: { sha: DELIVERY_FIXTURES.baseSha, tree: { sha: DELIVERY_FIXTURES.baseTreeSha } } };
          },
          getTree: async () => {
            calls.push('git.getTree');
            return { data: { sha: DELIVERY_FIXTURES.baseTreeSha, tree: [] } };
          },
          getBlob: async () => {
            calls.push('git.getBlob');
            return { data: { sha: DELIVERY_FIXTURES.baseBlobSha, encoding: 'base64', content: '', size: 0 } };
          },
        },
      },
    };

    const read = await createProbotRepositoryReadCapability(identity, octokit, { owner: 'owner', repo: 'target' });
    expect(MINIMUM_REGISTRATION_EQUIVALENT).toEqual({ contents: 'read', pull_requests: 'read', metadata: 'read' });
    await read.getCurrentPull(19);
    await read.listOpenPullsByBase('main', 1);
    await read.getCommit(DELIVERY_FIXTURES.baseSha);
    await read.getTree(DELIVERY_FIXTURES.baseTreeSha);
    await read.getBlob(DELIVERY_FIXTURES.baseBlobSha);
    expect(calls).toEqual(['pulls.get', 'pulls.list', 'git.getCommit', 'git.getTree', 'git.getBlob']);
    expect(Object.keys(read).sort()).toEqual(['getBlob', 'getCommit', 'getCurrentPull', 'getTree', 'listOpenPullsByBase']);
  });

  it('issues only the exact repository/read role and rejects broadened or mismatched scope before a read', async () => {
    const requests: RepositoryReadIssueRequest[] = [];
    const read = await createRepositoryReadCapability(identity, provider({
      async issue(request) {
        requests.push(request);
        return provider().issue(request);
      },
    }));

    expect(requests).toEqual([{ installationId: 42, repositoryIds: [7], permissions: { contents: 'read', pull_requests: 'read' } }]);
    expect(Object.keys(read).sort()).toEqual(['getBlob', 'getCommit', 'getCurrentPull', 'getTree', 'listOpenPullsByBase']);
    await expect(read.getCurrentPull(19)).resolves.toMatchObject({ number: 19, repositoryId: 7 });

    await expect(createRepositoryReadCapability(identity, provider({
      async issue(request) {
        const issued = await provider().issue(request);
        return { ...issued, repositoryIds: [8] };
      },
    }))).rejects.toMatchObject({ kind: 'credential-scope-mismatch', retryable: false });

    await expect(createRepositoryReadCapability(identity, provider({
      async issue(request) {
        const issued = await provider().issue(request);
        return { ...issued, permissions: { ...issued.permissions, checks: 'write' } };
      },
    }))).rejects.toMatchObject({ kind: 'credential-scope-mismatch', retryable: false });
  });

  it('permits only documented metadata-read minimum equivalence and contains hostile external errors', async () => {
    await expect(createRepositoryReadCapability(identity, provider({
      async issue(request) {
        const issued = await provider().issue(request);
        return { ...issued, credentialScope: 'minimum-registration-equivalent' as const, permissions: { ...issued.permissions, metadata: 'read' } };
      },
    }))).resolves.toBeDefined();

    await expect(createRepositoryReadCapability(identity, provider({
      async issue() {
        throw { status: 403, body: 'credential-secret-sentinel', headers: { authorization: 'Bearer credential-secret-sentinel' } };
      },
    }))).rejects.toSatisfy((error: unknown) => {
      expect(error).toBeInstanceOf(SanitizedGitHubReadError);
      expect(error).toMatchObject({ kind: 'authentication-authorization', retryable: false });
      expect(JSON.stringify(error)).not.toContain('credential-secret-sentinel');
      return true;
    });
  });

  it('exposes finite retry classification without a raw client, route, token, header, or request escape hatch', async () => {
    const read = await createRepositoryReadCapability(identity, provider({
      async issue(request) {
        const issued = await provider().issue(request);
        return {
          ...issued,
          transport: {
            ...issued.transport,
            getCommit: async () => { throw { status: 503, body: 'hostile-body-sentinel' }; },
          },
        };
      },
    }));

    await expect(read.getCommit(DELIVERY_FIXTURES.baseSha)).rejects.toMatchObject({ kind: 'transient-service', retryable: true });
    await expect(read.getCommit(DELIVERY_FIXTURES.baseSha)).rejects.not.toThrow('hostile-body-sentinel');
    expect('request' in read).toBe(false);
    expect('token' in read).toBe(false);
    expect('headers' in read).toBe(false);
  });
});
