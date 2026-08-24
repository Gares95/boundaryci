/**
 * The complete production permission catalog.
 *
 * Membership is authorized by a reviewed bounded-support decision and covers exactly two
 * GitHub REST operations. The literals below are a static projection of that reviewed
 * record: nothing here is read from a file, a package, or a network service at runtime,
 * and no operation may be added without a separately reviewed authorization update.
 */

import type { CatalogProvenance, PermissionCatalogEntry } from './model.js';

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === 'object') {
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

/** Digest of the authorized operation scope; shared by every authorized catalog row. */
const AUTHORIZED_SCOPE_SHA256 = '40c14243b7d1940d395ae9731ecd3fda962807aee297c9b72aeb591a3dd2b418';

/** Digest of the reviewed support predicate that each authorized row satisfied. */
const SUPPORT_PREDICATE_SHA256 = '6105e89cf161785569a465a573c25853a8354aaddaa6560d1bd38199a090c4fa';

/** Digest of the upstream artifact manifest the reviewed operation facts were taken from. */
const ARTIFACT_MANIFEST_SHA256 = 'ffe2270a26567042f146e0ec982a7343de51a1f6333f2de6fa0421aca1e4c94c';

/** Digest of the reviewed member selection. */
const SELECTION_SHA256 = 'c23e9c3017dd2d8d4ebe8d6f3e59c72895d8dd1e3d026286b7f5d82317fdde4d';

function provenance(expressionSha256: string, entrySha256: string): CatalogProvenance {
  return {
    authorizedScopeSha256: AUTHORIZED_SCOPE_SHA256,
    expressionSha256,
    entrySha256,
    artifactManifestSha256: ARTIFACT_MANIFEST_SHA256,
    supportPredicateSha256: SUPPORT_PREDICATE_SHA256,
  };
}

/**
 * Identity of the catalog itself.
 *
 * Base and head analysis must carry the same identity so a boundary comparison reflects
 * repository changes rather than catalog drift.
 */
export const BOUNDARYCI_PERMISSION_CATALOG_IDENTITY = deepFreeze({
  schemaVersion: 1,
  authorizationStatus: 'authorized-bounded',
  authorizedScopeSha256: AUTHORIZED_SCOPE_SHA256,
  selectionSha256: SELECTION_SHA256,
  supportPredicateSha256: SUPPORT_PREDICATE_SHA256,
  artifactManifestSha256: ARTIFACT_MANIFEST_SHA256,
  operationIds: ['issues/create', 'issues/list-for-repo'],
} as const);

/** The exact authorized production catalog: two resolved rows and nothing else. */
export const BOUNDARYCI_PERMISSION_CATALOG: readonly PermissionCatalogEntry[] = deepFreeze([
  {
    status: 'resolved',
    operation: {
      method: 'POST',
      normalizedRoute: '/repos/{owner}/{repo}/issues',
      operationId: 'issues/create',
    },
    requirement: { type: 'permission', permission: 'issues', level: 'write' },
    provenance: provenance(
      'bd8559d1ff1d3c8f74e8ff5f592324019a6031b90463a2c72ded97b6331d88f5',
      'f7ad7d4f8317a479d9ad55d96c651219e6227b55354e6e33d396d45388cabe09',
    ),
  },
  {
    status: 'resolved',
    operation: {
      method: 'GET',
      normalizedRoute: '/repos/{owner}/{repo}/issues',
      operationId: 'issues/list-for-repo',
    },
    requirement: { type: 'permission', permission: 'issues', level: 'read' },
    provenance: provenance(
      '9985fa2cfb60b1e5eb4cfd40fa575073ece6f7de52215bd854b65df4bbf4fb87',
      '59e29ecea924235615873a5740f9249e39be929d0fee4579d962afa1a6d2c740',
    ),
  },
] satisfies PermissionCatalogEntry[]);
