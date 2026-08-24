import { mkdirSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

import {
  assertArtifactManifestMatchesProject,
  parseBoundedJson,
  readBoundedArtifact,
} from '../artifact-sources.js';
import type { ArtifactIdentity, ArtifactManifest } from '../contracts.js';
import {
  buildCanonicalIssuesFixture,
  buildPermissionSources,
  parseEndpointMethodTable,
  parseOpenApiOperations,
  validatePermissionSources,
} from '../extract.js';
import {
  buildOperationInventory,
  evaluateSupportPredicate,
  validateOperationInventory,
  validateSupportManifest,
} from '../inventory.js';
import { buildHeaderExpressionFixture, validateHeaderExpressionFixture } from '../source-evidence.js';

const PROJECT_ROOT = process.cwd();
const MANIFEST_PATH = 'tools/permission-data-feasibility/evidence/artifact-manifest.json';
const PERMISSION_SOURCES_PATH = 'tools/permission-data-feasibility/evidence/permission-sources.json';
const CANONICAL_FIXTURE_PATH = 'tools/permission-data-feasibility/fixtures/canonical-issues.json';
const HEADER_FIXTURE_PATH = 'tools/permission-data-feasibility/fixtures/header-expressions.json';
const INVENTORY_PATH = 'tools/permission-data-feasibility/evidence/operation-inventory.json';
const SUPPORT_PATH = 'tools/permission-data-feasibility/evidence/support-manifest.json';

function artifactByRole(manifest: ArtifactManifest, role: ArtifactIdentity['role']): ArtifactIdentity {
  const matches = manifest.artifacts.filter((artifact) => artifact.role === role);
  if (matches.length !== 1 || matches[0] === undefined) throw new Error(`manifest has no unique ${role} artifact`);
  return matches[0];
}

function selectedDataPath(manifest: ArtifactManifest, role: ArtifactIdentity['role']): string {
  const artifact = artifactByRole(manifest, role);
  if (artifact.dataFiles.length !== 1 || artifact.dataFiles[0] === undefined) {
    throw new Error(`${role} must bind exactly one data file`);
  }
  return artifact.dataFiles[0].path;
}

function writeJsonAtomically(path: string, value: unknown): void {
  const absolute = resolve(PROJECT_ROOT, path);
  const temporary = `${absolute}.tmp`;
  mkdirSync(dirname(absolute), { recursive: true });
  writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, { encoding: 'utf8', mode: 0o644 });
  renameSync(temporary, absolute);
}

const manifestValue = parseBoundedJson(PROJECT_ROOT, MANIFEST_PATH, 2 * 1024 * 1024);
assertArtifactManifestMatchesProject(PROJECT_ROOT, manifestValue);
const manifest = manifestValue as ArtifactManifest;

const standalonePath = selectedDataPath(manifest, 'standaloneEndpointMethods');
const runtimePath = selectedDataPath(manifest, 'runtimeEndpointMethods');
const openApiPath = selectedDataPath(manifest, 'openApi');
const appPermissionsPath = selectedDataPath(manifest, 'appPermissions');
const standaloneEndpointMethods = parseEndpointMethodTable(
  readBoundedArtifact(PROJECT_ROOT, standalonePath, 4 * 1024 * 1024).toString('utf8'),
  standalonePath,
);
const runtimeEndpointMethods = parseEndpointMethodTable(
  readBoundedArtifact(PROJECT_ROOT, runtimePath, 4 * 1024 * 1024).toString('utf8'),
  runtimePath,
);
const openApiDocument = parseBoundedJson(PROJECT_ROOT, openApiPath, 20 * 1024 * 1024);
const appPermissionsDocument = parseBoundedJson(PROJECT_ROOT, appPermissionsPath, 4 * 1024 * 1024);

const permissionSources = buildPermissionSources();
validatePermissionSources(permissionSources);
const headerFixture = buildHeaderExpressionFixture();
validateHeaderExpressionFixture(headerFixture);
const canonicalFixture = buildCanonicalIssuesFixture(
  {
    standaloneEndpointMethods,
    runtimeEndpointMethods,
    openApiOperations: parseOpenApiOperations(openApiDocument),
  },
  manifest,
  permissionSources,
);
const inventory = buildOperationInventory({
  artifactManifest: manifest,
  permissionSources,
  openApiDocument,
  appPermissionsDocument,
  runtimeEndpointMethods,
  standaloneEndpointMethods,
});
validateOperationInventory(inventory);
const support = evaluateSupportPredicate(inventory);
validateSupportManifest(support);

writeJsonAtomically(PERMISSION_SOURCES_PATH, permissionSources);
writeJsonAtomically(CANONICAL_FIXTURE_PATH, canonicalFixture);
writeJsonAtomically(HEADER_FIXTURE_PATH, headerFixture);
writeJsonAtomically(INVENTORY_PATH, inventory);
writeJsonAtomically(SUPPORT_PATH, support);
