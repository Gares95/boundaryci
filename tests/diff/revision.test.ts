import { describe, expect, it } from 'vitest';

import { compareRevisionAnalyses, validateRevisionAnalysis } from '../../src/diff/revision.js';
import type { RevisionAnalysis } from '../../src/diff/revision.js';
import { BOUNDARYCI_PERMISSION_CATALOG } from '../../src/permission-model/bounded-catalog.js';

import {
  ALL_OF_ALIAS_CALL,
  ALL_OF_CALL,
  ANY_OF_CALL,
  CATALOG_GAP_CALL,
  CATALOG_GAP_CAUSE,
  CONFIG_DIGEST,
  MOVED_READ_CALL,
  NESTED_CALL,
  PARSE_CAUSE,
  READ_CALL,
  SYNTHETIC_ALL_OF,
  SYNTHETIC_ANY_OF,
  SYNTHETIC_NESTED,
  UNSUPPORTED_CALL_CAUSE,
  WRITE_CALL,
  digest,
  patchRevision,
  revision,
  withAnalyzerIdentity,
  withAnalyzerProfile,
} from './fixtures/scenarios.js';

function expectComplete(base: RevisionAnalysis, head: RevisionAnalysis) {
  const result = compareRevisionAnalyses(base, head);
  expect(result.status).toBe('complete');
  if (result.status !== 'complete') throw new Error('expected a complete revision comparison');
  return result;
}

function expectIncomplete(base: RevisionAnalysis, head: RevisionAnalysis) {
  const result = compareRevisionAnalyses(base, head);
  expect(result.status).toBe('incomplete');
  if (result.status !== 'incomplete') throw new Error('expected an incomplete revision comparison');
  return result;
}

describe('complete revision changes and contributors', () => {
  it.each([
    {
      name: 'empty to read',
      base: revision({}),
      head: revision({ calls: [READ_CALL] }),
      levels: ['none', 'read', 'expansion'],
      contributor: 'issues/list-for-repo',
    },
    {
      name: 'empty to write',
      base: revision({}),
      head: revision({ calls: [WRITE_CALL] }),
      levels: ['none', 'write', 'expansion'],
      contributor: 'issues/create',
    },
    {
      name: 'read to write',
      base: revision({ calls: [READ_CALL] }),
      head: revision({ calls: [WRITE_CALL] }),
      levels: ['read', 'write', 'expansion'],
      contributor: 'issues/create',
    },
  ])('reports $name as an evidence-bearing expansion', ({ base, head, levels, contributor }) => {
    const result = expectComplete(base, head);
    expect(result.changes).toHaveLength(1);
    expect(result.changes[0]).toMatchObject({
      permission: 'issues',
      base: levels[0],
      head: levels[1],
      change: levels[2],
    });
    expect(result.changes[0]?.headContributors).toHaveLength(1);
    expect(result.changes[0]?.headContributors[0]).toMatchObject({
      status: 'resolved',
      operation: { operationId: contributor },
      source: { path: 'src/app.ts' },
    });
  });

  it.each([
    {
      name: 'write to read',
      base: revision({ calls: [WRITE_CALL] }),
      head: revision({ calls: [READ_CALL] }),
      levels: ['write', 'read'],
      contributor: 'issues/create',
    },
    {
      name: 'read removal',
      base: revision({ calls: [READ_CALL] }),
      head: revision({}),
      levels: ['read', 'none'],
      contributor: 'issues/list-for-repo',
    },
    {
      name: 'write removal',
      base: revision({ calls: [WRITE_CALL] }),
      head: revision({}),
      levels: ['write', 'none'],
      contributor: 'issues/create',
    },
  ])('reports $name as an evidence-bearing reduction', ({ base, head, levels, contributor }) => {
    const result = expectComplete(base, head);
    expect(result.changes).toHaveLength(1);
    expect(result.changes[0]).toMatchObject({
      permission: 'issues',
      base: levels[0],
      head: levels[1],
      change: 'reduction',
    });
    expect(result.changes[0]?.baseContributors[0]).toMatchObject({
      status: 'resolved',
      operation: { operationId: contributor },
      source: { path: 'src/app.ts' },
    });
  });

  it('keeps source relocation as unchanged permission semantics with both contributors', () => {
    const result = expectComplete(revision({ calls: [READ_CALL] }), revision({ calls: [MOVED_READ_CALL] }));
    expect(result.changes).toHaveLength(1);
    expect(result.changes[0]).toMatchObject({
      permission: 'issues',
      base: 'read',
      head: 'read',
      change: 'unchanged',
    });
    expect(result.changes[0]?.baseContributors[0]).toMatchObject({ source: { path: 'src/app.ts' } });
    expect(result.changes[0]?.headContributors[0]).toMatchObject({ source: { path: 'src/moved/app.ts' } });
  });
});

describe('incomplete revision accounting', () => {
  it('retains a new catalog-gap operation and reports introduced uncertainty without unqualified changes', () => {
    const result = expectIncomplete(
      revision({}),
      revision({ calls: [CATALOG_GAP_CALL], causes: [CATALOG_GAP_CAUSE] }),
    );

    expect('changes' in result).toBe(false);
    expect(result.qualifiedChanges).toEqual([]);
    expect(result.uncertainty.introduced).toHaveLength(1);
    expect(result.uncertainty.introduced[0]).toMatchObject({
      code: 'permission-catalog-incomplete',
      path: 'src/app.ts',
    });
    expect(result.head.result.status).toBe('incomplete');
    if (result.head.result.status !== 'incomplete') throw new Error('expected incomplete head evidence');
    expect(result.head.result.observations[0]).toMatchObject({ operation: { operationId: 'pulls/list' } });
    expect(result.head.result.permissionResolutions[0]?.finding).toMatchObject({
      status: 'missing',
      operation: { operationId: 'pulls/list' },
    });
  });

  it('deduplicates causes by semantic body while retaining each side-specific cause ID', () => {
    const base = revision({ causes: [UNSUPPORTED_CALL_CAUSE, PARSE_CAUSE] });
    const head = revision({
      calls: [CATALOG_GAP_CALL],
      causes: [CATALOG_GAP_CAUSE, UNSUPPORTED_CALL_CAUSE],
    });
    const result = expectIncomplete(base, head);

    expect(result.uncertainty.introduced).toHaveLength(1);
    expect(result.uncertainty.introduced[0]).toMatchObject({ id: 'cause-0001', code: 'permission-catalog-incomplete' });
    expect(result.uncertainty.resolved).toHaveLength(1);
    expect(result.uncertainty.resolved[0]).toMatchObject({ id: 'cause-0002', code: 'source-parse-error' });
    expect(result.uncertainty.retained).toEqual([
      {
        base: expect.objectContaining({ id: 'cause-0001', code: 'unsupported-request-grammar' }),
        head: expect.objectContaining({ id: 'cause-0002', code: 'unsupported-request-grammar' }),
      },
    ]);
  });

  it('reports only a qualified expansion when base is complete and the incomplete head proves a higher floor', () => {
    const result = expectIncomplete(
      revision({ calls: [READ_CALL] }),
      revision({ calls: [WRITE_CALL, CATALOG_GAP_CALL], causes: [CATALOG_GAP_CAUSE] }),
    );
    expect(result.qualifiedChanges).toHaveLength(1);
    expect(result.qualifiedChanges[0]).toMatchObject({
      permission: 'issues',
      base: 'read',
      head: 'write',
      change: 'expansion',
      basis: 'complete-base-boundary-and-known-head-floor',
    });
    expect(result.qualifiedChanges[0]?.headContributors[0]).toMatchObject({
      operation: { operationId: 'issues/create' },
    });
  });

  it('reports only a qualified reduction when head is complete and the incomplete base proves a higher floor', () => {
    const result = expectIncomplete(
      revision({ calls: [WRITE_CALL, CATALOG_GAP_CALL], causes: [CATALOG_GAP_CAUSE] }),
      revision({ calls: [READ_CALL] }),
    );
    expect(result.qualifiedChanges).toHaveLength(1);
    expect(result.qualifiedChanges[0]).toMatchObject({
      permission: 'issues',
      base: 'write',
      head: 'read',
      change: 'reduction',
      basis: 'complete-head-boundary-and-known-base-floor',
    });
    expect(result.qualifiedChanges[0]?.baseContributors[0]).toMatchObject({
      operation: { operationId: 'issues/create' },
    });
  });

  it('qualifies unchanged only when both permission boundaries are complete', () => {
    const bothBoundariesComplete = expectIncomplete(
      revision({ calls: [READ_CALL], causes: [UNSUPPORTED_CALL_CAUSE] }),
      revision({ calls: [MOVED_READ_CALL], causes: [UNSUPPORTED_CALL_CAUSE] }),
    );
    expect(bothBoundariesComplete.qualifiedChanges).toEqual([
      expect.objectContaining({
        permission: 'issues',
        change: 'unchanged',
        basis: 'complete-boundaries',
      }),
    ]);

    const incompleteHeadBoundary = expectIncomplete(
      revision({ calls: [READ_CALL] }),
      revision({ calls: [READ_CALL, CATALOG_GAP_CALL], causes: [CATALOG_GAP_CAUSE] }),
    );
    expect(incompleteHeadBoundary.qualifiedChanges).toEqual([]);
  });
});

describe('complex expression preservation', () => {
  it.each([
    { name: 'allOf', call: ALL_OF_CALL, expression: SYNTHETIC_ALL_OF },
    { name: 'anyOf', call: ANY_OF_CALL, expression: SYNTHETIC_ANY_OF },
    { name: 'nested', call: NESTED_CALL, expression: SYNTHETIC_NESTED },
  ])('retains $name without selecting or flattening a branch', ({ call, expression }) => {
    const result = expectIncomplete(revision({}), revision({ calls: [call] }));
    expect(result.qualifiedChanges).toEqual([]);
    expect(result.head.result.status).toBe('incomplete');
    if (result.head.result.status !== 'incomplete') throw new Error('expected incomplete complex evidence');
    expect(result.head.result.permissionBoundary.status).toBe('incomplete');
    if (result.head.result.permissionBoundary.status !== 'incomplete') throw new Error('expected incomplete boundary');
    expect(result.head.result.permissionBoundary.findings[0]).toMatchObject({
      status: 'resolved',
      requirement: expression,
    });
  });

  it('preserves equivalent allOf trees while remaining incomplete', () => {
    const result = expectIncomplete(revision({ calls: [ALL_OF_CALL] }), revision({ calls: [ALL_OF_ALIAS_CALL] }));
    expect(result.qualifiedChanges).toEqual([]);
    if (result.base.result.status === 'failed' || result.head.result.status === 'failed') {
      throw new Error('expected trustworthy incomplete evidence');
    }
    expect(JSON.stringify(result.base.result.permissionBoundary)).toContain(JSON.stringify(SYNTHETIC_ALL_OF));
    expect(JSON.stringify(result.head.result.permissionBoundary)).toContain(JSON.stringify(SYNTHETIC_ALL_OF));
  });
});

describe('comparison identity gate', () => {
  const base = revision({ calls: [READ_CALL] });
  const compatibleHead = revision({ calls: [WRITE_CALL] });

  const cases: {
    name: string;
    reason: string;
    mutate: (source: RevisionAnalysis) => RevisionAnalysis;
  }[] = [
    {
      name: 'engine identity',
      reason: 'engine-identity-mismatch',
      mutate: (source) => patchRevision(source, (draft) => void (draft.identity.engineId = 'boundaryci/revision-engine@2')),
    },
    {
      name: 'analysis schema id',
      reason: 'analysis-schema-id-mismatch',
      mutate: (source) => withAnalyzerIdentity(source, { schemaId: 'boundaryci/analysis-result-next' }),
    },
    {
      name: 'analysis schema version',
      reason: 'analysis-schema-version-mismatch',
      mutate: (source) => withAnalyzerIdentity(source, { schemaVersion: source.identity.analyzer.schemaVersion + 1 }),
    },
    {
      name: 'source span convention',
      reason: 'source-span-convention-mismatch',
      mutate: (source) => withAnalyzerIdentity(source, { spanConventionId: 'boundaryci/source-span@2' }),
    },
    {
      name: 'discovery profile',
      reason: 'discovery-profile-mismatch',
      mutate: (source) => withAnalyzerIdentity(source, { discoveryProfileId: 'boundaryci/bounded-local-discovery@2' }),
    },
    {
      name: 'limit profile',
      reason: 'limit-profile-mismatch',
      mutate: (source) => withAnalyzerIdentity(source, { limitProfileId: 'boundaryci/analysis-limits@2' }),
    },
    {
      name: 'analyzer catalog scope',
      reason: 'analyzer-permission-catalog-scope-mismatch',
      mutate: (source) => withAnalyzerIdentity(source, { permissionCatalogScopeSha256: digest('analyzer-scope-next') }),
    },
    {
      name: 'wrapper catalog scope',
      reason: 'catalog-authorized-scope-mismatch',
      mutate: (source) =>
        patchRevision(source, (draft) => void (draft.identity.catalogAuthorizedScopeSha256 = digest('wrapper-scope-next'))),
    },
    {
      name: 'effective configuration',
      reason: 'effective-configuration-identity-mismatch',
      mutate: (source) =>
        patchRevision(source, (draft) => void (draft.identity.effectiveConfigSha256 = digest('config-next'))),
    },
  ];

  const profileCases: {
    field: Parameters<typeof withAnalyzerProfile>[1];
    name: string;
    reason: string;
  }[] = [
    { name: 'profile schema version', reason: 'analyzer-profile-schema-version-mismatch', field: { schemaVersion: 2 } },
    { name: 'profile id', reason: 'analyzer-profile-id-mismatch', field: { profileId: 'boundaryci/octokit@next' } },
    { name: 'Octokit version', reason: 'analyzer-profile-octokit-version-mismatch', field: { octokitVersion: '5.0.6' } },
    {
      name: 'endpoint methods version',
      reason: 'analyzer-profile-endpoint-methods-version-mismatch',
      field: { endpointMethodsVersion: '18.0.1' },
    },
    { name: 'REST API version', reason: 'analyzer-profile-rest-api-version-mismatch', field: { restApiVersion: '2022-11-29' } },
    {
      name: 'inventory content',
      reason: 'analyzer-profile-inventory-content-mismatch',
      field: { inventoryContentSha256: digest('inventory-next') },
    },
    {
      name: 'artifact manifest',
      reason: 'analyzer-profile-artifact-manifest-mismatch',
      field: { artifactManifestSha256: digest('manifest-next') },
    },
    {
      name: 'endpoint member count',
      reason: 'analyzer-profile-endpoint-member-count-mismatch',
      field: { endpointMemberCount: compatibleHead.identity.analyzer.analyzerProfile.endpointMemberCount + 1 },
    },
    {
      name: 'operation count',
      reason: 'analyzer-profile-operation-count-mismatch',
      field: { operationCount: compatibleHead.identity.analyzer.analyzerProfile.operationCount + 1 },
    },
  ];

  it.each([
    ...cases,
    ...profileCases.map(({ name, reason, field }) => ({
      name,
      reason,
      mutate: (source: RevisionAnalysis) => withAnalyzerProfile(source, field),
    })),
  ])('blocks $name mismatch before semantic comparison', ({ reason, mutate }) => {
    const result = compareRevisionAnalyses(base, mutate(compatibleHead));
    expect(result.status).toBe('input-configuration-failure');
    if (result.status !== 'input-configuration-failure') throw new Error('expected incompatible input');
    expect(result.reasons).toContain(reason);
    expect('changes' in result).toBe(false);
  });
});

describe('immutability and deterministic output', () => {
  it('exact-validates the public wrapper and rejects unknown identity keys', () => {
    const valid = revision({ calls: [READ_CALL] }, CONFIG_DIGEST);
    expect(() => validateRevisionAnalysis(valid)).not.toThrow();
    const malformed = structuredClone(valid);
    (malformed.identity as unknown as Record<string, unknown>).unexpected = true;
    expect(() => validateRevisionAnalysis(malformed)).toThrow(/unknown or missing keys/u);
  });

  it('does not mutate inputs, complex trees, or the frozen production catalog and repeats byte-identically', () => {
    const base = revision({ calls: [READ_CALL], causes: [UNSUPPORTED_CALL_CAUSE] });
    const head = revision({ calls: [ANY_OF_CALL, CATALOG_GAP_CALL], causes: [CATALOG_GAP_CAUSE] });
    const baseBefore = JSON.stringify(base);
    const headBefore = JSON.stringify(head);
    const expressionBefore = JSON.stringify(SYNTHETIC_ANY_OF);
    const catalogBefore = JSON.stringify(BOUNDARYCI_PERMISSION_CATALOG);

    const first = compareRevisionAnalyses(base, head);
    const second = compareRevisionAnalyses(base, head);

    expect(JSON.stringify(second)).toBe(JSON.stringify(first));
    expect(JSON.stringify(base)).toBe(baseBefore);
    expect(JSON.stringify(head)).toBe(headBefore);
    expect(JSON.stringify(SYNTHETIC_ANY_OF)).toBe(expressionBefore);
    expect(JSON.stringify(BOUNDARYCI_PERMISSION_CATALOG)).toBe(catalogBefore);
    expect(BOUNDARYCI_PERMISSION_CATALOG.map((entry) => entry.operation.operationId)).toEqual([
      'issues/create',
      'issues/list-for-repo',
    ]);
  });
});
