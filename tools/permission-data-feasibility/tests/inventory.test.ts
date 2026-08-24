import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { beforeAll, describe, expect, it } from 'vitest';

import {
  digestJson,
  parseBoundedJson,
  readBoundedArtifact,
  validateArtifactManifest,
} from '../artifact-sources.js';
import type { ArtifactIdentity, ArtifactManifest, JsonValue, PermissionSources } from '../contracts.js';
import { parseEndpointMethodTable, validatePermissionSources } from '../extract.js';
import {
  buildOperationInventory,
  evaluateSupportPredicate,
  validateOperationInventory,
  validateSupportManifest,
  type InventoryInputs,
  type OperationInventory,
  type SupportManifest,
} from '../inventory.js';

const PROJECT_ROOT = fileURLToPath(new URL('../../../', import.meta.url));
const MANIFEST_PATH = 'tools/permission-data-feasibility/evidence/artifact-manifest.json';
const PERMISSION_SOURCES_PATH = 'tools/permission-data-feasibility/evidence/permission-sources.json';
const INVENTORY_PATH = 'tools/permission-data-feasibility/evidence/operation-inventory.json';
const SUPPORT_PATH = 'tools/permission-data-feasibility/evidence/support-manifest.json';

let inventory: OperationInventory;
let support: SupportManifest;
let inputs: InventoryInputs;

function dataPath(manifest: ArtifactManifest, role: ArtifactIdentity['role']): string {
  const matches = manifest.artifacts.filter((entry) => entry.role === role);
  const file = matches[0]?.dataFiles[0];
  if (matches.length !== 1 || file === undefined) throw new Error(`missing ${role} data path`);
  return file.path;
}

beforeAll(() => {
  const manifestValue = parseBoundedJson(PROJECT_ROOT, MANIFEST_PATH, 2 * 1024 * 1024);
  validateArtifactManifest(manifestValue);
  const manifest = manifestValue;
  const permissionValue = parseBoundedJson(PROJECT_ROOT, PERMISSION_SOURCES_PATH, 2 * 1024 * 1024);
  validatePermissionSources(permissionValue);
  const permissionSources = permissionValue as PermissionSources;
  const runtimePath = dataPath(manifest, 'runtimeEndpointMethods');
  const standalonePath = dataPath(manifest, 'standaloneEndpointMethods');
  inputs = {
    artifactManifest: manifest,
    permissionSources,
    openApiDocument: parseBoundedJson(PROJECT_ROOT, dataPath(manifest, 'openApi'), 20 * 1024 * 1024),
    appPermissionsDocument: parseBoundedJson(PROJECT_ROOT, dataPath(manifest, 'appPermissions'), 4 * 1024 * 1024),
    runtimeEndpointMethods: parseEndpointMethodTable(
      readBoundedArtifact(PROJECT_ROOT, runtimePath, 4 * 1024 * 1024).toString('utf8'),
      runtimePath,
    ),
    standaloneEndpointMethods: parseEndpointMethodTable(
      readBoundedArtifact(PROJECT_ROOT, standalonePath, 4 * 1024 * 1024).toString('utf8'),
      standalonePath,
    ),
  };
  inventory = buildOperationInventory(inputs);
  support = evaluateSupportPredicate(inventory);
});

describe('two-universe evidence inventory', () => {
  it('reconciles every app-enabled operation and every endpoint method independently', () => {
    expect(() => validateOperationInventory(inventory)).not.toThrow();
    expect(inventory.operationUniverse.total).toBe(878);
    expect(Object.values(inventory.operationUniverse.classCounts).reduce((sum, count) => sum + count, 0)).toBe(878);
    expect(Object.values(inventory.operationUniverse.freshnessCounts).reduce((sum, count) => sum + count, 0)).toBe(878);
    expect(
      Object.values(inventory.operationUniverse.credentialApplicabilityCounts).reduce((sum, count) => sum + count, 0),
    ).toBe(878);
    expect(Object.values(inventory.methodUniverse.surfaceCounts).reduce((sum, count) => sum + count, 0)).toBe(
      inventory.methodUniverse.total,
    );
    expect(Object.values(inventory.methodUniverse.operationJoinCounts).reduce((sum, count) => sum + count, 0)).toBe(
      inventory.methodUniverse.total,
    );
    expect(new Set(inventory.operationRows.map((row) => `${row.verb} ${row.path}`)).size).toBe(878);
    expect(new Set(inventory.methodJoinRows.map((row) => `${row.scope}.${row.method}`)).size).toBe(
      inventory.methodUniverse.total,
    );
  });

  it('applies source precedence without promoting seed or PAT evidence to App authority', () => {
    const list = inventory.operationRows.find((row) => row.operationId === 'issues/list-for-repo');
    const create = inventory.operationRows.find((row) => row.operationId === 'issues/create');
    expect(list).toMatchObject({
      evidenceClass: 'single',
      freshness: 'current',
      credentialApplicability: 'github-app-reviewed',
      expression: { type: 'permission', permission: 'issues', level: 'read' },
      reasons: [],
    });
    expect(create).toMatchObject({
      evidenceClass: 'single',
      freshness: 'current',
      credentialApplicability: 'github-app-reviewed',
      expression: { type: 'permission', permission: 'issues', level: 'write' },
      reasons: [],
    });

    const patAnyOf = inventory.operationRows.find((row) => row.operationId === 'issues/list-comments');
    expect(patAnyOf).toMatchObject({
      evidenceClass: 'unsupported',
      credentialApplicability: 'fine-grained-pat-only',
      expression: null,
      observedExpression: { type: 'anyOf' },
      reasons: ['credential-equivalence-unproven'],
    });
    const seedOnly = inventory.operationRows.find((row) => row.operationId === 'repos/get-content');
    expect(seedOnly).toMatchObject({ evidenceClass: 'ambiguous', expression: null });
    expect(seedOnly?.rawSeedAssociations.length).toBeGreaterThan(1);
    const absent = inventory.operationRows.find((row) => row.operationId === 'git/get-tree');
    expect(absent).toMatchObject({
      evidenceClass: 'missing',
      expression: null,
      reasons: ['applicable-permission-evidence-missing'],
    });
  });

  it('marks lower-ranked seed disagreement stale and same-rank primary disagreement conflicting', () => {
    const staleSeedDocument = structuredClone(inputs.appPermissionsDocument) as {
      permissions: Record<string, { write?: string[] }>;
    };
    const contents = staleSeedDocument.permissions.contents;
    if (contents === undefined) throw new Error('test input lacks contents seed');
    contents.write = [...(contents.write ?? []), 'POST /repos/{owner}/{repo}/issues'];
    const staleInventory = buildOperationInventory({ ...inputs, appPermissionsDocument: staleSeedDocument });
    expect(staleInventory.operationRows.find((row) => row.operationId === 'issues/create')).toMatchObject({
      evidenceClass: 'single',
      freshness: 'stale-seed',
      reasons: ['seed-disagrees-with-primary-evidence'],
    });
    expect(() => evaluateSupportPredicate(staleInventory)).toThrow(/omitted required canonical operation issues\/create/u);

    const conflictingSources = structuredClone(inputs.permissionSources);
    const createFact = conflictingSources.facts.find((fact) => fact.operationId === 'issues/create');
    if (createFact === undefined) throw new Error('test input lacks create fact');
    conflictingSources.facts[0] = structuredClone(createFact);
    const { evidenceSha256: _factDigest, ...unsignedFact } = conflictingSources.facts[0];
    conflictingSources.facts[0].evidenceSha256 = digestJson(unsignedFact as unknown as JsonValue);
    const { contentSha256: _sourceDigest, ...unsignedSources } = conflictingSources;
    conflictingSources.contentSha256 = digestJson(unsignedSources as unknown as JsonValue);
    const conflictingInventory = buildOperationInventory({ ...inputs, permissionSources: conflictingSources });
    expect(conflictingInventory.operationRows.find((row) => row.operationId === 'issues/create')).toMatchObject({
      evidenceClass: 'conflicting',
      expression: null,
      reasons: ['multiple-applicable-primary-facts'],
    });
  });

  it('commits exactly the independently rebuilt inventory', () => {
    const committed = JSON.parse(readFileSync(`${PROJECT_ROOT}/${INVENTORY_PATH}`, 'utf8')) as unknown;
    expect(committed).toEqual(inventory);
    const mutated = structuredClone(inventory);
    mutated.operationUniverse.total -= 1;
    const { contentSha256: _contentSha256, ...unsigned } = mutated;
    mutated.contentSha256 = digestJson(unsigned as unknown as JsonValue);
    expect(() => validateOperationInventory(mutated)).toThrow(/total mismatch/u);
  });
});

describe('candidate support predicate', () => {
  it('selects both canonical Issues members through common-identical method aliases', () => {
    expect(() => validateSupportManifest(support)).not.toThrow();
    expect(support.requiredOperationIds).toEqual(['issues/create', 'issues/list-for-repo']);
    expect(support.selectedMembers.map((member) => member.operationId)).toEqual([
      'issues/create',
      'issues/list-for-repo',
    ]);
    expect(support.selectedMembers).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ operationId: 'issues/create', methodAliases: ['issues.create'] }),
        expect.objectContaining({ operationId: 'issues/list-for-repo', methodAliases: ['issues.listForRepo'] }),
      ]),
    );
    for (const member of support.selectedMembers) {
      expect(member.artifactManifestSha256).toBe(inventory.artifactManifestSha256);
      expect(member.permissionSourcesSha256).toBe(inventory.permissionSourcesSha256);
      expect(member.expressionSha256).toMatch(/^[a-f0-9]{64}$/u);
      expect(member.permissionEvidenceSha256).toMatch(/^[a-f0-9]{64}$/u);
    }
  });

  it('keeps predicate identity separate from selected-member identity and fails closed on mutation', () => {
    expect(support.predicate.ruleSha256).not.toBe(support.selectionSha256);
    const omitted = structuredClone(support);
    omitted.selectedMembers = omitted.selectedMembers.filter((member) => member.operationId !== 'issues/create');
    omitted.selectionSha256 = digestJson(omitted.selectedMembers as unknown as JsonValue);
    const { contentSha256: _contentSha256, ...unsignedOmitted } = omitted;
    omitted.contentSha256 = digestJson(unsignedOmitted as unknown as JsonValue);
    expect(() => validateSupportManifest(omitted)).toThrow(/omitted issues\/create/u);

    const badSource = structuredClone(support);
    const first = badSource.selectedMembers[0];
    if (first !== undefined) first.permissionSourcesSha256 = '0'.repeat(64);
    badSource.selectionSha256 = digestJson(badSource.selectedMembers as unknown as JsonValue);
    const { contentSha256: _badDigest, ...unsignedBadSource } = badSource;
    badSource.contentSha256 = digestJson(unsignedBadSource as unknown as JsonValue);
    expect(() => validateSupportManifest(badSource)).toThrow(/identity is invalid/u);
  });

  it('commits exactly the predeclared predicate and selected set', () => {
    const committed = JSON.parse(readFileSync(`${PROJECT_ROOT}/${SUPPORT_PATH}`, 'utf8')) as unknown;
    expect(committed).toEqual(support);
    expect(JSON.stringify(committed)).not.toMatch(/five.of.six/iu);
  });
});
