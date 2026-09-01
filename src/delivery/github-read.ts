import type { CurrentPull, GitBlob, GitCommit, GitTree } from './index.js';

export interface GitHubReadCapability {
  getCurrentPull(pullNumber: number): Promise<CurrentPull>;
  listOpenPullsByBase(baseRef: string): Promise<readonly CurrentPull[]>;
  getCommit(sha: string): Promise<GitCommit>;
  getTree(sha: string): Promise<GitTree>;
  getBlob(sha: string): Promise<GitBlob>;
}

export type SanitizedGitHubReadErrorKind =
  | 'authentication-authorization'
  | 'contract-invalid'
  | 'credential-narrowing-unsupported'
  | 'credential-scope-mismatch'
  | 'identity-mismatch'
  | 'not-found-obsolete'
  | 'rate-limited'
  | 'transient-service'
  | 'transient-transport';

/** A source-free, header-free error value permitted to leave the read adapter. */
export class SanitizedGitHubReadError extends Error {
  readonly name = 'SanitizedGitHubReadError';

  constructor(
    readonly kind: SanitizedGitHubReadErrorKind,
    readonly retryable: boolean,
    readonly retryAfterMilliseconds: number | null = null,
  ) {
    super(`github-read:${kind}`);
  }

  toJSON(): { kind: SanitizedGitHubReadErrorKind; retryable: boolean; retryAfterMilliseconds: number | null } {
    return { kind: this.kind, retryable: this.retryable, retryAfterMilliseconds: this.retryAfterMilliseconds };
  }
}

export interface RepositoryReadIdentity {
  installationId: number;
  repositoryId: number;
}

export interface RepositoryReadIssueRequest {
  installationId: number;
  repositoryIds: readonly [number];
  permissions: Readonly<{ contents: 'read'; pull_requests: 'read' }>;
}

interface RepositoryReadTransport {
  getCurrentPull(pullNumber: number): Promise<unknown>;
  listOpenPullsByBase(baseRef: string): Promise<unknown>;
  getCommit(sha: string): Promise<unknown>;
  getTree(sha: string): Promise<unknown>;
  getBlob(sha: string): Promise<unknown>;
}

interface IssuedRepositoryReadRole {
  credentialScope: 'issuance-narrowed' | 'minimum-registration-equivalent';
  repositoryIds: readonly number[];
  permissions: Readonly<Record<string, string>>;
  transport: RepositoryReadTransport;
}

/**
 * This interface belongs only at the credential boundary. Its result is immediately
 * scope-checked and converted into a five-operation capability; callers never receive a
 * token, client, request function, headers, or arbitrary route options.
 */
export interface RepositoryReadProvider {
  issue(request: RepositoryReadIssueRequest): Promise<IssuedRepositoryReadRole>;
}

const REQUEST_PERMISSIONS = Object.freeze({ contents: 'read' as const, pull_requests: 'read' as const });
const SHA_PATTERN = /^[a-f0-9]{40}$/u;

function safePositiveInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0;
}

function safeSha(value: unknown): value is string {
  return typeof value === 'string' && SHA_PATTERN.test(value);
}

function safeRef(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 256;
}

function exactKeys(record: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Object.keys(record).sort();
  const sortedExpected = [...expected].sort();
  return keys.length === sortedExpected.length && keys.every((key, index) => key === sortedExpected[index]);
}

function sanitizeFailure(error: unknown): SanitizedGitHubReadError {
  if (error instanceof SanitizedGitHubReadError) return error;
  if (typeof error !== 'object' || error === null) return new SanitizedGitHubReadError('transient-transport', true);
  const record = error as { status?: unknown; code?: unknown; retryAfterMilliseconds?: unknown };
  const retryAfterMilliseconds = Number.isSafeInteger(record.retryAfterMilliseconds) && (record.retryAfterMilliseconds as number) >= 0
    ? (record.retryAfterMilliseconds as number)
    : null;
  if (record.status === 401 || record.status === 403) return new SanitizedGitHubReadError('authentication-authorization', false);
  if (record.status === 404) return new SanitizedGitHubReadError('not-found-obsolete', false);
  if (record.status === 429) return new SanitizedGitHubReadError('rate-limited', true, retryAfterMilliseconds);
  if (typeof record.status === 'number' && record.status >= 500 && record.status <= 599) {
    return new SanitizedGitHubReadError('transient-service', true, retryAfterMilliseconds);
  }
  if (typeof record.code === 'string' && /(?:ECONN|ETIMEDOUT|ENOTFOUND|EAI_AGAIN)/u.test(record.code)) {
    return new SanitizedGitHubReadError('transient-transport', true, retryAfterMilliseconds);
  }
  return new SanitizedGitHubReadError('contract-invalid', false);
}

function validateIssuedRole(value: unknown, identity: RepositoryReadIdentity): IssuedRepositoryReadRole {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new SanitizedGitHubReadError('credential-narrowing-unsupported', false);
  }
  const issued = value as Record<string, unknown>;
  if (!exactKeys(issued, ['credentialScope', 'permissions', 'repositoryIds', 'transport'])) {
    throw new SanitizedGitHubReadError('credential-scope-mismatch', false);
  }
  if (issued.credentialScope !== 'issuance-narrowed' && issued.credentialScope !== 'minimum-registration-equivalent') {
    throw new SanitizedGitHubReadError('credential-narrowing-unsupported', false);
  }
  if (!Array.isArray(issued.repositoryIds) || issued.repositoryIds.length !== 1 || issued.repositoryIds[0] !== identity.repositoryId) {
    throw new SanitizedGitHubReadError('credential-scope-mismatch', false);
  }
  if (typeof issued.permissions !== 'object' || issued.permissions === null || Array.isArray(issued.permissions)) {
    throw new SanitizedGitHubReadError('credential-scope-mismatch', false);
  }
  const permissions = issued.permissions as Record<string, unknown>;
  const accepted = issued.credentialScope === 'issuance-narrowed'
    ? ['contents', 'pull_requests']
    : ['contents', 'metadata', 'pull_requests'];
  if (!exactKeys(permissions, accepted) || permissions.contents !== 'read' || permissions.pull_requests !== 'read' ||
    (issued.credentialScope === 'minimum-registration-equivalent' && permissions.metadata !== 'read')) {
    throw new SanitizedGitHubReadError('credential-scope-mismatch', false);
  }
  if (typeof issued.transport !== 'object' || issued.transport === null || Array.isArray(issued.transport)) {
    throw new SanitizedGitHubReadError('credential-narrowing-unsupported', false);
  }
  const transport = issued.transport as Record<string, unknown>;
  const methods = ['getBlob', 'getCommit', 'getCurrentPull', 'getTree', 'listOpenPullsByBase'];
  if (!exactKeys(transport, methods) || methods.some((method) => typeof transport[method] !== 'function')) {
    throw new SanitizedGitHubReadError('credential-narrowing-unsupported', false);
  }
  return issued as unknown as IssuedRepositoryReadRole;
}

function validatePull(value: unknown, requestedNumber: number, repositoryId: number): CurrentPull {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new SanitizedGitHubReadError('contract-invalid', false);
  const record = value as Record<string, unknown>;
  if (!exactKeys(record, ['base', 'draft', 'head', 'merged', 'number', 'repositoryId', 'state'])) {
    throw new SanitizedGitHubReadError('contract-invalid', false);
  }
  const base = record.base;
  const head = record.head;
  if (typeof base !== 'object' || base === null || Array.isArray(base) || typeof head !== 'object' || head === null || Array.isArray(head)) {
    throw new SanitizedGitHubReadError('contract-invalid', false);
  }
  const baseRecord = base as Record<string, unknown>;
  const headRecord = head as Record<string, unknown>;
  if (!exactKeys(baseRecord, ['ref', 'repositoryId', 'sha']) || !exactKeys(headRecord, ['repositoryId', 'sha']) ||
    record.number !== requestedNumber || record.repositoryId !== repositoryId || !safePositiveInteger(record.number) ||
    (record.state !== 'open' && record.state !== 'closed') || typeof record.draft !== 'boolean' || typeof record.merged !== 'boolean' ||
    baseRecord.repositoryId !== repositoryId || !safeRef(baseRecord.ref) || !safeSha(baseRecord.sha) ||
    !safePositiveInteger(headRecord.repositoryId) || !safeSha(headRecord.sha)) {
    throw new SanitizedGitHubReadError('identity-mismatch', false);
  }
  return Object.freeze({
    number: record.number,
    repositoryId,
    state: record.state,
    draft: record.draft,
    merged: record.merged,
    base: Object.freeze({ repositoryId, ref: baseRecord.ref, sha: baseRecord.sha }),
    head: Object.freeze({ repositoryId: headRecord.repositoryId, sha: headRecord.sha }),
  });
}

function validateCommit(value: unknown, requestedSha: string): GitCommit {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new SanitizedGitHubReadError('contract-invalid', false);
  const record = value as Record<string, unknown>;
  if (!exactKeys(record, ['sha', 'treeSha']) || record.sha !== requestedSha || !safeSha(record.sha) || !safeSha(record.treeSha)) {
    throw new SanitizedGitHubReadError('identity-mismatch', false);
  }
  return Object.freeze({ sha: record.sha, treeSha: record.treeSha });
}

function validateTree(value: unknown, requestedSha: string): GitTree {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new SanitizedGitHubReadError('contract-invalid', false);
  const record = value as Record<string, unknown>;
  if (!safeSha(record.sha) || record.sha !== requestedSha || !Array.isArray(record.entries)) {
    throw new SanitizedGitHubReadError('identity-mismatch', false);
  }
  if (!exactKeys(record, record.truncated === undefined ? ['entries', 'sha'] : ['entries', 'sha', 'truncated']) ||
    (record.truncated !== undefined && typeof record.truncated !== 'boolean')) {
    throw new SanitizedGitHubReadError('contract-invalid', false);
  }
  return Object.freeze({ sha: record.sha, entries: Object.freeze([...record.entries]) as GitTree['entries'], ...(record.truncated === undefined ? {} : { truncated: record.truncated }) });
}

function validateBlob(value: unknown, requestedSha: string): GitBlob {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new SanitizedGitHubReadError('contract-invalid', false);
  const record = value as Record<string, unknown>;
  if (!exactKeys(record, ['content', 'encoding', 'sha', 'size']) || record.sha !== requestedSha || !safeSha(record.sha) ||
    record.encoding !== 'base64' || typeof record.content !== 'string' || !Number.isSafeInteger(record.size) || (record.size as number) < 0) {
    throw new SanitizedGitHubReadError('identity-mismatch', false);
  }
  return Object.freeze({ sha: record.sha, encoding: 'base64', content: record.content, size: record.size as number });
}

function assertReadInput(value: unknown, kind: 'number' | 'sha' | 'ref'): void {
  if ((kind === 'number' && !safePositiveInteger(value)) || (kind === 'sha' && !safeSha(value)) || (kind === 'ref' && !safeRef(value))) {
    throw new SanitizedGitHubReadError('contract-invalid', false);
  }
}

/** Creates the sole downstream read surface after exact issuance scope validation. */
export async function createRepositoryReadCapability(
  identity: RepositoryReadIdentity,
  provider: RepositoryReadProvider,
): Promise<GitHubReadCapability> {
  if (!safePositiveInteger(identity.installationId) || !safePositiveInteger(identity.repositoryId)) {
    throw new SanitizedGitHubReadError('credential-scope-mismatch', false);
  }
  const request: RepositoryReadIssueRequest = Object.freeze({
    installationId: identity.installationId,
    repositoryIds: Object.freeze([identity.repositoryId]) as [number],
    permissions: REQUEST_PERMISSIONS,
  });
  let issued: IssuedRepositoryReadRole;
  try {
    issued = validateIssuedRole(await provider.issue(request), identity);
  } catch (error) {
    throw sanitizeFailure(error);
  }
  const operation = async <T>(call: () => Promise<unknown>, validate: (value: unknown) => T): Promise<T> => {
    try {
      return validate(await call());
    } catch (error) {
      throw sanitizeFailure(error);
    }
  };
  return Object.freeze({
    getCurrentPull: async (pullNumber: number) => {
      assertReadInput(pullNumber, 'number');
      return operation(() => issued.transport.getCurrentPull(pullNumber), (value) => validatePull(value, pullNumber, identity.repositoryId));
    },
    listOpenPullsByBase: async (baseRef: string) => {
      assertReadInput(baseRef, 'ref');
      return operation(() => issued.transport.listOpenPullsByBase(baseRef), (value) => {
        if (!Array.isArray(value)) throw new SanitizedGitHubReadError('contract-invalid', false);
        return Object.freeze(value.map((pull) => {
          if (typeof pull !== 'object' || pull === null || Array.isArray(pull) || !safePositiveInteger((pull as Record<string, unknown>).number)) {
            throw new SanitizedGitHubReadError('contract-invalid', false);
          }
          return validatePull(pull, (pull as Record<string, unknown>).number as number, identity.repositoryId);
        }));
      });
    },
    getCommit: async (sha: string) => {
      assertReadInput(sha, 'sha');
      return operation(() => issued.transport.getCommit(sha), (value) => validateCommit(value, sha));
    },
    getTree: async (sha: string) => {
      assertReadInput(sha, 'sha');
      return operation(() => issued.transport.getTree(sha), (value) => validateTree(value, sha));
    },
    getBlob: async (sha: string) => {
      assertReadInput(sha, 'sha');
      return operation(() => issued.transport.getBlob(sha), (value) => validateBlob(value, sha));
    },
  });
}
