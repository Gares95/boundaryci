import { describe, expect, it } from 'vitest';

import {
  BOUNDARYCI_PERMISSION_CATALOG,
  BOUNDARYCI_PERMISSION_CATALOG_IDENTITY,
} from '../../src/permission-model/bounded-catalog.js';
import {
  aggregatePermissionFindings,
  comparePermissionBoundaries,
  lookupPermissionRequirement,
  resolveRequirementFinding,
  validatePermissionCatalog,
  type RestOperationIdentity,
  type SourceEvidence,
} from '../../src/permission-model/model.js';

const LIST_OPERATION: RestOperationIdentity = {
  method: 'GET',
  normalizedRoute: '/repos/{owner}/{repo}/issues',
  operationId: 'issues/list-for-repo',
};

const CREATE_OPERATION: RestOperationIdentity = {
  method: 'POST',
  normalizedRoute: '/repos/{owner}/{repo}/issues',
  operationId: 'issues/create',
};

const LIST_SOURCE: SourceEvidence = {
  path: 'src/app.ts',
  span: { start: { line: 12, column: 3 }, end: { line: 12, column: 44 } },
};

const CREATE_SOURCE: SourceEvidence = {
  path: 'src/app.ts',
  span: { start: { line: 20, column: 5 }, end: { line: 24, column: 6 } },
};

function readFinding() {
  return resolveRequirementFinding(BOUNDARYCI_PERMISSION_CATALOG, LIST_OPERATION, LIST_SOURCE);
}

function writeFinding() {
  return resolveRequirementFinding(BOUNDARYCI_PERMISSION_CATALOG, CREATE_OPERATION, CREATE_SOURCE);
}

describe('canonical Issues read-to-write tracer', () => {
  it('exports exactly the two authorized catalog rows with their Phase 1 identities', () => {
    expect(validatePermissionCatalog(BOUNDARYCI_PERMISSION_CATALOG)).toEqual({ status: 'valid', entryCount: 2 });
    expect(BOUNDARYCI_PERMISSION_CATALOG).toHaveLength(2);
    expect(BOUNDARYCI_PERMISSION_CATALOG.map((entry) => entry.status)).toEqual(['resolved', 'resolved']);
    expect(BOUNDARYCI_PERMISSION_CATALOG.map((entry) => entry.operation.operationId)).toEqual([
      'issues/create',
      'issues/list-for-repo',
    ]);
    expect(BOUNDARYCI_PERMISSION_CATALOG_IDENTITY).toEqual({
      schemaVersion: 1,
      authorizationStatus: 'authorized-bounded',
      authorizedScopeSha256: '40c14243b7d1940d395ae9731ecd3fda962807aee297c9b72aeb591a3dd2b418',
      selectionSha256: 'c23e9c3017dd2d8d4ebe8d6f3e59c72895d8dd1e3d026286b7f5d82317fdde4d',
      supportPredicateSha256: '6105e89cf161785569a465a573c25853a8354aaddaa6560d1bd38199a090c4fa',
      artifactManifestSha256: 'ffe2270a26567042f146e0ec982a7343de51a1f6333f2de6fa0421aca1e4c94c',
      operationIds: ['issues/create', 'issues/list-for-repo'],
    });
    for (const entry of BOUNDARYCI_PERMISSION_CATALOG) {
      expect(entry.provenance.authorizedScopeSha256).toBe(
        BOUNDARYCI_PERMISSION_CATALOG_IDENTITY.authorizedScopeSha256,
      );
      expect(entry.provenance.supportPredicateSha256).toBe(
        BOUNDARYCI_PERMISSION_CATALOG_IDENTITY.supportPredicateSha256,
      );
      expect(entry.provenance.artifactManifestSha256).toBe(
        BOUNDARYCI_PERMISSION_CATALOG_IDENTITY.artifactManifestSha256,
      );
    }
  });

  it('resolves the GET observation to the issues read atom with its evidence intact', () => {
    expect(lookupPermissionRequirement(BOUNDARYCI_PERMISSION_CATALOG, LIST_OPERATION)).toMatchObject({
      status: 'resolved',
      operation: LIST_OPERATION,
      requirement: { type: 'permission', permission: 'issues', level: 'read' },
    });
    expect(readFinding()).toEqual({
      status: 'resolved',
      operation: LIST_OPERATION,
      source: LIST_SOURCE,
      requirement: { type: 'permission', permission: 'issues', level: 'read' },
      provenance: {
        authorizedScopeSha256: '40c14243b7d1940d395ae9731ecd3fda962807aee297c9b72aeb591a3dd2b418',
        expressionSha256: '9985fa2cfb60b1e5eb4cfd40fa575073ece6f7de52215bd854b65df4bbf4fb87',
        entrySha256: '59e29ecea924235615873a5740f9249e39be929d0fee4579d962afa1a6d2c740',
        artifactManifestSha256: 'ffe2270a26567042f146e0ec982a7343de51a1f6333f2de6fa0421aca1e4c94c',
        supportPredicateSha256: '6105e89cf161785569a465a573c25853a8354aaddaa6560d1bd38199a090c4fa',
      },
    });
  });

  it('resolves the POST observation to the issues write atom with its evidence intact', () => {
    expect(writeFinding()).toEqual({
      status: 'resolved',
      operation: CREATE_OPERATION,
      source: CREATE_SOURCE,
      requirement: { type: 'permission', permission: 'issues', level: 'write' },
      provenance: {
        authorizedScopeSha256: '40c14243b7d1940d395ae9731ecd3fda962807aee297c9b72aeb591a3dd2b418',
        expressionSha256: 'bd8559d1ff1d3c8f74e8ff5f592324019a6031b90463a2c72ded97b6331d88f5',
        entrySha256: 'f7ad7d4f8317a479d9ad55d96c651219e6227b55354e6e33d396d45388cabe09',
        artifactManifestSha256: 'ffe2270a26567042f146e0ec982a7343de51a1f6333f2de6fa0421aca1e4c94c',
        supportPredicateSha256: '6105e89cf161785569a465a573c25853a8354aaddaa6560d1bd38199a090c4fa',
      },
    });
  });

  it('aggregates each finding into a complete single-atom boundary that retains its evidence', () => {
    const base = aggregatePermissionFindings([readFinding()]);
    expect(base).toEqual({
      status: 'complete',
      permissions: [{ permission: 'issues', level: 'read', contributors: [readFinding()] }],
    });
    const head = aggregatePermissionFindings([writeFinding()]);
    expect(head).toMatchObject({ status: 'complete', permissions: [{ permission: 'issues', level: 'write' }] });
    if (head.status !== 'complete') throw new Error('expected a complete head boundary');
    expect(head.permissions[0]?.contributors[0]).toMatchObject({
      operation: CREATE_OPERATION,
      source: CREATE_SOURCE,
    });
  });

  it('compares read base to write head as an expansion, reversed as a reduction, and identical as unchanged', () => {
    const read = aggregatePermissionFindings([readFinding()]);
    const write = aggregatePermissionFindings([writeFinding()]);
    expect(comparePermissionBoundaries(read, write)).toEqual({
      status: 'complete',
      changes: [{ permission: 'issues', base: 'read', head: 'write', change: 'expansion' }],
    });
    expect(comparePermissionBoundaries(write, read)).toEqual({
      status: 'complete',
      changes: [{ permission: 'issues', base: 'write', head: 'read', change: 'reduction' }],
    });
    expect(comparePermissionBoundaries(read, read)).toEqual({
      status: 'complete',
      changes: [{ permission: 'issues', base: 'read', head: 'read', change: 'unchanged' }],
    });
    expect(comparePermissionBoundaries(aggregatePermissionFindings([]), write)).toEqual({
      status: 'complete',
      changes: [{ permission: 'issues', base: 'none', head: 'write', change: 'expansion' }],
    });
  });

  it('treats the full operation triple as the lookup identity', () => {
    const mismatches: RestOperationIdentity[] = [
      { ...LIST_OPERATION, method: 'PUT' },
      { ...LIST_OPERATION, normalizedRoute: '/repos/{owner}/{repo}/issues/{issue_number}' },
      { ...LIST_OPERATION, operationId: 'issues/create' },
    ];
    for (const operation of mismatches) {
      expect(lookupPermissionRequirement(BOUNDARYCI_PERMISSION_CATALOG, operation)).toEqual({
        status: 'missing',
        operation,
      });
    }
  });

  it('produces byte-stable JSON for the whole lookup-to-comparison chain', () => {
    const run = () =>
      JSON.stringify(
        comparePermissionBoundaries(
          aggregatePermissionFindings([readFinding()]),
          aggregatePermissionFindings([writeFinding()]),
        ),
      );
    expect(run()).toBe(run());
    const finding = readFinding();
    expect(JSON.parse(JSON.stringify(finding))).toEqual(finding);
  });
});
