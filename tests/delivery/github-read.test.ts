import { describe, expect, it } from 'vitest';

import {
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
          listOpenPullsByBase: async () => Object.freeze([]),
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
