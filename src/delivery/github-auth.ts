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

/** A source-free, header-free error value permitted to leave a GitHub adapter. */
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

export interface PublicProbotScopedAuth {
  auth(options: Readonly<Record<string, unknown>>): Promise<unknown>;
}

interface NarrowedInstallationRequest {
  installationId: number;
  repositoryIds: readonly [number];
  permissions: Readonly<Record<string, string>>;
}

interface NarrowedInstallationRole<T> {
  repositoryIds: readonly [number];
  permissions: Readonly<Record<string, string>>;
  transport: T;
}

function exactKeys(record: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Object.keys(record).sort();
  const sortedExpected = [...expected].sort();
  return keys.length === sortedExpected.length && keys.every((key, index) => key === sortedExpected[index]);
}

function sanitizeAuthFailure(error: unknown): SanitizedGitHubReadError {
  if (error instanceof SanitizedGitHubReadError) return error;
  if (typeof error !== 'object' || error === null) return new SanitizedGitHubReadError('transient-transport', true);
  const record = error as { status?: unknown; code?: unknown; retryAfterMilliseconds?: unknown };
  const retryAfterMilliseconds = Number.isSafeInteger(record.retryAfterMilliseconds) && (record.retryAfterMilliseconds as number) >= 0
    ? (record.retryAfterMilliseconds as number)
    : null;
  if (record.status === 401 || record.status === 403) return new SanitizedGitHubReadError('authentication-authorization', false);
  if (record.status === 404) return new SanitizedGitHubReadError('not-found-obsolete', false);
  if (record.status === 429) return new SanitizedGitHubReadError('rate-limited', true, retryAfterMilliseconds);
  if (typeof record.status === 'number' && record.status >= 500 && record.status <= 599) return new SanitizedGitHubReadError('transient-service', true, retryAfterMilliseconds);
  if (typeof record.code === 'string' && /(?:ECONN|ETIMEDOUT|ENOTFOUND|EAI_AGAIN)/u.test(record.code)) return new SanitizedGitHubReadError('transient-transport', true, retryAfterMilliseconds);
  return new SanitizedGitHubReadError('credential-narrowing-unsupported', false);
}

function validateNarrowedPermissions(
  value: unknown,
  requested: Readonly<Record<string, string>>,
): Readonly<Record<string, string>> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new SanitizedGitHubReadError('credential-scope-mismatch', false);
  }
  const permissions = value as Record<string, unknown>;
  const requestedKeys = Object.keys(requested).sort();
  const actualKeys = Object.keys(permissions).sort();
  const acceptedKeys = [requestedKeys, [...requestedKeys, 'metadata'].sort()];
  if (!acceptedKeys.some((keys) => exactKeys(permissions, keys)) ||
    requestedKeys.some((key) => permissions[key] !== requested[key]) ||
    (Object.hasOwn(permissions, 'metadata') && permissions.metadata !== 'read')) {
    throw new SanitizedGitHubReadError('credential-scope-mismatch', false);
  }
  return Object.freeze(Object.fromEntries(actualKeys.map((key) => [key, permissions[key] as string])));
}

/**
 * Uses the pinned Octokit App-auth subset issuance path, validates the effective token scope,
 * and lets an adapter project the resulting client before it can leave this credential closure.
 */
export async function issueNarrowedProbotRole<T>(
  octokit: PublicProbotScopedAuth,
  request: NarrowedInstallationRequest,
  project: (client: unknown) => T,
): Promise<NarrowedInstallationRole<T>> {
  let authentication: unknown;
  try {
    authentication = await octokit.auth(Object.freeze({
      type: 'installation',
      installationId: request.installationId,
      repositoryIds: [...request.repositoryIds],
      permissions: request.permissions,
    }));
  } catch (error) {
    throw sanitizeAuthFailure(error);
  }
  if (typeof authentication !== 'object' || authentication === null || Array.isArray(authentication)) {
    throw new SanitizedGitHubReadError('credential-narrowing-unsupported', false);
  }
  const issued = authentication as Record<string, unknown>;
  if (issued.type !== 'token' || issued.tokenType !== 'installation' ||
    issued.installationId !== request.installationId || typeof issued.token !== 'string' || issued.token.length === 0 ||
    !Array.isArray(issued.repositoryIds) || issued.repositoryIds.length !== 1 || issued.repositoryIds[0] !== request.repositoryIds[0]) {
    throw new SanitizedGitHubReadError('credential-scope-mismatch', false);
  }
  const permissions = validateNarrowedPermissions(issued.permissions, request.permissions);
  const token = issued.token;
  let client: unknown;
  try {
    client = await octokit.auth(Object.freeze({
      type: 'installation',
      installationId: request.installationId,
      repositoryIds: [...request.repositoryIds],
      permissions: request.permissions,
      factory: (factoryOptions: unknown): unknown => {
        if (typeof factoryOptions !== 'object' || factoryOptions === null || Array.isArray(factoryOptions)) {
          throw new SanitizedGitHubReadError('credential-narrowing-unsupported', false);
        }
        const options = factoryOptions as Record<string, unknown>;
        if (typeof options.octokit !== 'object' || options.octokit === null ||
          typeof options.octokitOptions !== 'object' || options.octokitOptions === null || Array.isArray(options.octokitOptions)) {
          throw new SanitizedGitHubReadError('credential-narrowing-unsupported', false);
        }
        const Constructor = (options.octokit as { constructor?: unknown }).constructor;
        if (typeof Constructor !== 'function') throw new SanitizedGitHubReadError('credential-narrowing-unsupported', false);
        return Reflect.construct(Constructor, [{ ...(options.octokitOptions as Record<string, unknown>), auth: { token } }]);
      },
    }));
  } catch (error) {
    throw error instanceof SanitizedGitHubReadError
      ? error
      : new SanitizedGitHubReadError('credential-narrowing-unsupported', false);
  }
  return Object.freeze({
    repositoryIds: Object.freeze([request.repositoryIds[0]]) as readonly [number],
    permissions,
    transport: project(client),
  });
}
