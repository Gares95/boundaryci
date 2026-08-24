import { mkdirSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

import {
  buildArtifactManifest,
  parseBoundedJson,
  readBoundedArtifact,
  validateArtifactManifest,
} from '../artifact-sources.js';
import type { ArtifactIdentity, ArtifactManifest } from '../contracts.js';
import {
  buildCanonicalIssuesFixture,
  buildPermissionSources,
  parseEndpointMethodTable,
  parseOpenApiOperations,
  validatePermissionSources,
} from '../extract.js';

const PROJECT_ROOT = process.cwd();
const MANIFEST_PATH = 'tools/permission-data-feasibility/evidence/artifact-manifest.json';
const PERMISSION_SOURCES_PATH = 'tools/permission-data-feasibility/evidence/permission-sources.json';
const CANONICAL_FIXTURE_PATH = 'tools/permission-data-feasibility/fixtures/canonical-issues.json';

function artifactByRole(manifest: ArtifactManifest, role: ArtifactIdentity['role']): ArtifactIdentity {
  const matches = manifest.artifacts.filter((artifact) => artifact.role === role);
  if (matches.length !== 1 || matches[0] === undefined) throw new Error(`manifest has no unique ${role} artifact`);
  return matches[0];
}

function selectedDataFile(manifest: ArtifactManifest, role: ArtifactIdentity['role']): string {
  const artifact = artifactByRole(manifest, role);
  if (artifact.dataFiles.length !== 1 || artifact.dataFiles[0] === undefined) {
    throw new Error(`${role} must have exactly one selected data file`);
  }
  return artifact.dataFiles[0].path;
}

function writeJsonAtomically(relativePath: string, value: unknown): void {
  const absolutePath = resolve(PROJECT_ROOT, relativePath);
  const temporaryPath = `${absolutePath}.tmp`;
  mkdirSync(dirname(absolutePath), { recursive: true });
  writeFileSync(temporaryPath, `${JSON.stringify(value, null, 2)}\n`, { encoding: 'utf8', mode: 0o644 });
  renameSync(temporaryPath, absolutePath);
}

const manifest = buildArtifactManifest(PROJECT_ROOT);
validateArtifactManifest(manifest);

const standalonePath = selectedDataFile(manifest, 'standaloneEndpointMethods');
const runtimePath = selectedDataFile(manifest, 'runtimeEndpointMethods');
const openApiPath = selectedDataFile(manifest, 'openApi');
const sources = {
  standaloneEndpointMethods: parseEndpointMethodTable(
    readBoundedArtifact(PROJECT_ROOT, standalonePath, 4 * 1024 * 1024).toString('utf8'),
    standalonePath,
  ),
  runtimeEndpointMethods: parseEndpointMethodTable(
    readBoundedArtifact(PROJECT_ROOT, runtimePath, 4 * 1024 * 1024).toString('utf8'),
    runtimePath,
  ),
  openApiOperations: parseOpenApiOperations(parseBoundedJson(PROJECT_ROOT, openApiPath, 20 * 1024 * 1024)),
};
const permissionSources = buildPermissionSources();
validatePermissionSources(permissionSources);
const canonicalFixture = buildCanonicalIssuesFixture(sources, manifest, permissionSources);

writeJsonAtomically(MANIFEST_PATH, manifest);
writeJsonAtomically(PERMISSION_SOURCES_PATH, permissionSources);
writeJsonAtomically(CANONICAL_FIXTURE_PATH, canonicalFixture);
