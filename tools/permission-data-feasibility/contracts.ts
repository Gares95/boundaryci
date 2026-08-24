export const SHA256_PATTERN = /^[a-f0-9]{64}$/u;

export type JsonPrimitive = boolean | number | string | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };

export type ArtifactRole =
  | 'appPermissions'
  | 'octokit'
  | 'openApi'
  | 'probot'
  | 'runtimeEndpointMethods'
  | 'standaloneEndpointMethods'
  | 'typescript';

export interface StaticDataFileIdentity {
  path: string;
  bytes: number;
  sha256: string;
}

export interface ArtifactIdentity {
  role: ArtifactRole;
  packageName: string;
  version: string;
  lockIdentity: string;
  integrity: string;
  repository: string;
  packageJson: StaticDataFileIdentity;
  dataFiles: StaticDataFileIdentity[];
}

export interface RuntimeEndpointConsumer {
  packageName: 'octokit' | 'probot';
  version: string;
  declaredRange: string;
  resolvedLockIdentity: string;
}

export interface ArtifactManifest {
  schemaVersion: 1;
  githubRestApiEvidenceVersion: '2022-11-28';
  documentationVersioning: 'unversioned-live';
  project: {
    packageManager: string;
    packageJson: StaticDataFileIdentity;
    lockfile: StaticDataFileIdentity;
  };
  artifacts: ArtifactIdentity[];
  runtimeEndpointSelection: {
    selectedRole: 'runtimeEndpointMethods';
    peerContext: '@octokit/core@7.0.7';
    consumers: [RuntimeEndpointConsumer, RuntimeEndpointConsumer];
  };
  contentSha256: string;
}

export type UnresolvedOperationReason =
  | 'artifact-manifest-digest-mismatch'
  | 'endpoint-method-duplicate'
  | 'endpoint-method-missing-runtime'
  | 'endpoint-method-missing-standalone'
  | 'endpoint-route-invalid'
  | 'openapi-operation-duplicate'
  | 'openapi-operation-missing'
  | 'permission-evidence-mismatch'
  | 'permission-evidence-missing'
  | 'permission-source-digest-mismatch'
  | 'runtime-surface-incompatibility';

export interface ResolvedOperation {
  status: 'resolved';
  scope: string;
  method: string;
  route: {
    verb: string;
    path: string;
  };
  operationId: string;
}

export interface UnresolvedOperation {
  status: 'unresolved';
  scope: string;
  method: string;
  reason: UnresolvedOperationReason;
}

export type OperationResolution = ResolvedOperation | UnresolvedOperation;

export interface PermissionFact {
  operationId: string;
  verb: string;
  path: string;
  requirement: {
    type: 'permission';
    permission: string;
    level: 'read' | 'write';
  };
  sourceUrl: string;
  evidenceSha256: string;
}

export interface PermissionSources {
  schemaVersion: 1;
  documentation: {
    sourceUrl: string;
    versioning: 'unversioned-live';
    retrievalStatus: 'captured';
    reviewStatus: 'reviewed';
    reviewedOn: string;
  };
  facts: PermissionFact[];
  contentSha256: string;
}

export interface CanonicalPermissionChain extends ResolvedOperation {
  requirement: PermissionFact['requirement'];
  evidence: {
    artifactManifestSha256: string;
    permissionSourcesSha256: string;
    permissionFactSha256: string;
  };
}

export interface CanonicalIssuesFixture {
  schemaVersion: 1;
  artifactManifestSha256: string;
  permissionSourcesSha256: string;
  chains: CanonicalPermissionChain[];
  contentSha256: string;
}

export function assertPlainObject(value: unknown, label: string): asserts value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object`);
  }
}

export function assertExactKeys(
  value: Record<string, unknown>,
  keys: readonly string[],
  label: string,
): void {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new TypeError(`${label} has unexpected keys: ${actual.join(',')}`);
  }
}

export function assertSha256(value: unknown, label: string): asserts value is string {
  if (typeof value !== 'string' || !SHA256_PATTERN.test(value)) {
    throw new TypeError(`${label} must be a lowercase SHA-256`);
  }
}

export function assertPortableRelativePath(value: unknown, label: string): asserts value is string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.startsWith('/') ||
    value.includes('\\') ||
    value.split('/').some((part) => part === '' || part === '.' || part === '..')
  ) {
    throw new TypeError(`${label} must be a normalized repository-relative path`);
  }
}
