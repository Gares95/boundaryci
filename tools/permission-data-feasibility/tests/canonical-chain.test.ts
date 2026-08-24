import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { beforeAll, describe, expect, it } from 'vitest';

import {
  digestJson,
  parseBoundedJson,
  readBoundedArtifact,
  validateArtifactManifest,
} from '../artifact-sources.js';
import type {
  ArtifactManifest,
  JsonValue,
  PermissionFact,
  PermissionSources,
} from '../contracts.js';
import {
  buildCanonicalIssuesFixture,
  buildPermissionSources,
  parseEndpointMethodTable,
  parseOpenApiOperations,
  resolveCanonicalPermission,
  resolveOperation,
  validatePermissionSources,
  type OperationSources,
} from '../extract.js';

const PROJECT_ROOT = fileURLToPath(new URL('../../../', import.meta.url));
const MANIFEST_PATH = 'tools/permission-data-feasibility/evidence/artifact-manifest.json';
const PERMISSION_SOURCES_PATH = 'tools/permission-data-feasibility/evidence/permission-sources.json';
const FIXTURE_PATH = 'tools/permission-data-feasibility/fixtures/canonical-issues.json';

let manifest: ArtifactManifest;
let permissionSources: PermissionSources;
let sources: OperationSources;

function selectedPath(role: string): string {
  const artifact = manifest.artifacts.find((entry) => entry.role === role);
  const file = artifact?.dataFiles[0];
  if (file === undefined) throw new Error(`missing selected data file for ${role}`);
  return file.path;
}

function cloneSources(): {
  standaloneEndpointMethods: { scope: string; method: string; route: string }[];
  runtimeEndpointMethods: { scope: string; method: string; route: string }[];
  openApiOperations: { verb: string; path: string; operationId: string }[];
} {
  return {
    standaloneEndpointMethods: structuredClone([...sources.standaloneEndpointMethods]),
    runtimeEndpointMethods: structuredClone([...sources.runtimeEndpointMethods]),
    openApiOperations: structuredClone([...sources.openApiOperations]),
  };
}

function resignPermissionFact(fact: PermissionFact): void {
  const { evidenceSha256: _evidenceSha256, ...unsigned } = fact;
  fact.evidenceSha256 = digestJson(unsigned as unknown as JsonValue);
}

function resignPermissionSources(value: PermissionSources): void {
  const { contentSha256: _contentSha256, ...unsigned } = value;
  value.contentSha256 = digestJson(unsigned as unknown as JsonValue);
}

function resignManifest(value: ArtifactManifest): void {
  const { contentSha256: _contentSha256, ...unsigned } = value;
  value.contentSha256 = digestJson(unsigned as unknown as JsonValue);
}

function resolveCanonical(
  method: string,
  manifestValue: unknown = manifest,
  permissionValue: unknown = permissionSources,
  expectedPermissionSourcesSha256 = permissionSources.contentSha256,
) {
  return resolveCanonicalPermission(
    'issues',
    method,
    sources,
    manifestValue,
    permissionValue,
    manifest.contentSha256,
    expectedPermissionSourcesSha256,
  );
}

beforeAll(() => {
  const manifestValue = JSON.parse(readFileSync(`${PROJECT_ROOT}/${MANIFEST_PATH}`, 'utf8')) as unknown;
  validateArtifactManifest(manifestValue);
  manifest = manifestValue;
  const permissionValue = JSON.parse(readFileSync(`${PROJECT_ROOT}/${PERMISSION_SOURCES_PATH}`, 'utf8')) as unknown;
  validatePermissionSources(permissionValue);
  permissionSources = permissionValue;
  sources = {
    standaloneEndpointMethods: parseEndpointMethodTable(
      readBoundedArtifact(PROJECT_ROOT, selectedPath('standaloneEndpointMethods'), 4 * 1024 * 1024).toString('utf8'),
      selectedPath('standaloneEndpointMethods'),
    ),
    runtimeEndpointMethods: parseEndpointMethodTable(
      readBoundedArtifact(PROJECT_ROOT, selectedPath('runtimeEndpointMethods'), 4 * 1024 * 1024).toString('utf8'),
      selectedPath('runtimeEndpointMethods'),
    ),
    openApiOperations: parseOpenApiOperations(
      parseBoundedJson(PROJECT_ROOT, selectedPath('openApi'), 20 * 1024 * 1024),
    ),
  };
});

describe('canonical Issues permission chain', () => {
  it('joins both canonical methods only through exact v17, v18, and OpenAPI agreement', () => {
    expect(resolveOperation('issues', 'listForRepo', sources)).toEqual({
      status: 'resolved',
      scope: 'issues',
      method: 'listForRepo',
      route: { verb: 'GET', path: '/repos/{owner}/{repo}/issues' },
      operationId: 'issues/list-for-repo',
    });
    expect(resolveOperation('issues', 'create', sources)).toEqual({
      status: 'resolved',
      scope: 'issues',
      method: 'create',
      route: { verb: 'POST', path: '/repos/{owner}/{repo}/issues' },
      operationId: 'issues/create',
    });
    expect(resolveCanonical('listForRepo')).toMatchObject({
      status: 'resolved',
      requirement: { type: 'permission', permission: 'issues', level: 'read' },
    });
    expect(resolveCanonical('create')).toMatchObject({
      status: 'resolved',
      requirement: { type: 'permission', permission: 'issues', level: 'write' },
    });
  });

  it('matches the committed self-contained canonical fixture', () => {
    const built = buildCanonicalIssuesFixture(sources, manifest, permissionSources);
    const committed = JSON.parse(readFileSync(`${PROJECT_ROOT}/${FIXTURE_PATH}`, 'utf8')) as unknown;
    expect(committed).toEqual(built);
    expect(JSON.stringify(committed)).not.toMatch(/\/home\/|(?:UID|GID)|(?:token|secret|private[_-]?key)/iu);
  });

  it('returns stable unresolved reasons for method and route surface mutations', () => {
    const standaloneMissing = cloneSources();
    standaloneMissing.standaloneEndpointMethods = standaloneMissing.standaloneEndpointMethods.filter(
      (entry) => !(entry.scope === 'issues' && entry.method === 'create'),
    );
    expect(resolveOperation('issues', 'create', standaloneMissing)).toMatchObject({
      status: 'unresolved',
      reason: 'endpoint-method-missing-standalone',
    });

    const runtimeMissing = cloneSources();
    runtimeMissing.runtimeEndpointMethods = runtimeMissing.runtimeEndpointMethods.filter(
      (entry) => !(entry.scope === 'issues' && entry.method === 'create'),
    );
    expect(resolveOperation('issues', 'create', runtimeMissing)).toMatchObject({
      status: 'unresolved',
      reason: 'endpoint-method-missing-runtime',
    });

    const duplicate = cloneSources();
    const create = duplicate.runtimeEndpointMethods.find((entry) => entry.scope === 'issues' && entry.method === 'create');
    if (create !== undefined) duplicate.runtimeEndpointMethods.push({ ...create });
    expect(resolveOperation('issues', 'create', duplicate)).toMatchObject({
      status: 'unresolved',
      reason: 'endpoint-method-duplicate',
    });

    const mismatch = cloneSources();
    const runtimeCreate = mismatch.runtimeEndpointMethods.find((entry) => entry.scope === 'issues' && entry.method === 'create');
    if (runtimeCreate !== undefined) runtimeCreate.route = 'PUT /repos/{owner}/{repo}/issues';
    expect(resolveOperation('issues', 'create', mismatch)).toMatchObject({
      status: 'unresolved',
      reason: 'runtime-surface-incompatibility',
    });

    const invalidRoute = cloneSources();
    const standaloneCreate = invalidRoute.standaloneEndpointMethods.find(
      (entry) => entry.scope === 'issues' && entry.method === 'create',
    );
    const matchingRuntimeCreate = invalidRoute.runtimeEndpointMethods.find(
      (entry) => entry.scope === 'issues' && entry.method === 'create',
    );
    if (standaloneCreate !== undefined) standaloneCreate.route = 'post guessed-route';
    if (matchingRuntimeCreate !== undefined) matchingRuntimeCreate.route = 'post guessed-route';
    expect(resolveOperation('issues', 'create', invalidRoute)).toMatchObject({
      status: 'unresolved',
      reason: 'endpoint-route-invalid',
    });
  });

  it('returns stable unresolved reasons for OpenAPI operation mutations', () => {
    const missing = cloneSources();
    missing.openApiOperations = missing.openApiOperations.filter(
      (entry) => !(entry.verb === 'POST' && entry.path === '/repos/{owner}/{repo}/issues'),
    );
    expect(resolveOperation('issues', 'create', missing)).toMatchObject({
      status: 'unresolved',
      reason: 'openapi-operation-missing',
    });

    const duplicate = cloneSources();
    duplicate.openApiOperations.push({
      verb: 'POST',
      path: '/repos/{owner}/{repo}/issues',
      operationId: 'issues/create-duplicate',
    });
    expect(resolveOperation('issues', 'create', duplicate)).toMatchObject({
      status: 'unresolved',
      reason: 'openapi-operation-duplicate',
    });
  });

  it('rejects manifest, permission-source, and permission-fact mutations', () => {
    const badManifest = structuredClone(manifest);
    badManifest.contentSha256 = '0'.repeat(64);
    expect(resolveCanonical('create', badManifest)).toMatchObject({
      status: 'unresolved',
      reason: 'artifact-manifest-digest-mismatch',
    });

    const resignedManifestDrift = structuredClone(manifest);
    const openApi = resignedManifestDrift.artifacts.find((artifact) => artifact.role === 'openApi');
    if (openApi !== undefined) openApi.version = '22.0.1';
    resignManifest(resignedManifestDrift);
    expect(resolveCanonical('create', resignedManifestDrift)).toMatchObject({
      status: 'unresolved',
      reason: 'artifact-manifest-digest-mismatch',
    });

    const badSourceDigest = structuredClone(permissionSources);
    badSourceDigest.contentSha256 = '0'.repeat(64);
    expect(resolveCanonical('create', manifest, badSourceDigest)).toMatchObject({
      status: 'unresolved',
      reason: 'permission-source-digest-mismatch',
    });

    const mismatch = structuredClone(permissionSources);
    const create = mismatch.facts.find((fact) => fact.operationId === 'issues/create');
    if (create !== undefined) {
      create.path = '/repos/{owner}/{repo}/issues/{issue_number}';
      resignPermissionFact(create);
    }
    resignPermissionSources(mismatch);
    expect(resolveCanonical('create', manifest, mismatch, mismatch.contentSha256)).toMatchObject({
      status: 'unresolved',
      reason: 'permission-evidence-mismatch',
    });

    const wrongPermission = structuredClone(permissionSources);
    const wrongCreate = wrongPermission.facts.find((fact) => fact.operationId === 'issues/create');
    if (wrongCreate !== undefined) {
      wrongCreate.requirement.permission = 'contents';
      resignPermissionFact(wrongCreate);
    }
    resignPermissionSources(wrongPermission);
    expect(resolveCanonical('create', manifest, wrongPermission, wrongPermission.contentSha256)).toMatchObject({
      status: 'unresolved',
      reason: 'permission-evidence-mismatch',
    });

    const missing = buildPermissionSources();
    for (const fact of missing.facts) {
      fact.operationId = `other/${fact.requirement.level}`;
      resignPermissionFact(fact);
    }
    resignPermissionSources(missing);
    expect(resolveCanonical('create', manifest, missing, missing.contentSha256)).toMatchObject({
      status: 'unresolved',
      reason: 'permission-evidence-missing',
    });

    const duplicated = buildPermissionSources();
    duplicated.facts[0] = structuredClone(duplicated.facts[1] as PermissionFact);
    resignPermissionSources(duplicated);
    expect(resolveCanonical('create', manifest, duplicated, duplicated.contentSha256)).toMatchObject({
      status: 'unresolved',
      reason: 'permission-evidence-mismatch',
    });
  });
});
