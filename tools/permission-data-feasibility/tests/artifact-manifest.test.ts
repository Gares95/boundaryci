import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  assertArtifactManifestMatchesProject,
  buildArtifactManifest,
  digestJson,
  readBoundedArtifact,
  validateArtifactManifest,
} from '../artifact-sources.js';
import type { ArtifactManifest, JsonValue } from '../contracts.js';

const PROJECT_ROOT = fileURLToPath(new URL('../../../', import.meta.url));

function cloneManifest(manifest: ArtifactManifest): ArtifactManifest {
  return structuredClone(manifest);
}

function resign(manifest: ArtifactManifest): void {
  const { contentSha256: _contentSha256, ...unsigned } = manifest;
  manifest.contentSha256 = digestJson(unsigned as unknown as JsonValue);
}

describe('portable artifact manifest', () => {
  it('matches the committed manifest to the current project bytes', () => {
    const committed = JSON.parse(
      readFileSync(`${PROJECT_ROOT}/tools/permission-data-feasibility/evidence/artifact-manifest.json`, 'utf8'),
    ) as unknown;
    expect(() => assertArtifactManifestMatchesProject(PROJECT_ROOT, committed)).not.toThrow();
  });

  it('binds the selected static inputs and the runtime endpoint surface', () => {
    const manifest = buildArtifactManifest(PROJECT_ROOT);
    expect(() => validateArtifactManifest(manifest)).not.toThrow();
    expect(() => assertArtifactManifestMatchesProject(PROJECT_ROOT, manifest)).not.toThrow();

    expect(Object.fromEntries(manifest.artifacts.map((artifact) => [artifact.role, artifact.version]))).toEqual({
      appPermissions: '2.1.0',
      octokit: '5.0.5',
      openApi: '22.0.0',
      probot: '14.3.2',
      runtimeEndpointMethods: '17.0.0',
      standaloneEndpointMethods: '18.0.0',
      typescript: '6.0.2',
    });
    expect(manifest.runtimeEndpointSelection).toEqual({
      selectedRole: 'runtimeEndpointMethods',
      peerContext: '@octokit/core@7.0.7',
      consumers: [
        {
          packageName: 'octokit',
          version: '5.0.5',
          declaredRange: '^17.0.0',
          resolvedLockIdentity: '17.0.0(@octokit/core@7.0.7)',
        },
        {
          packageName: 'probot',
          version: '14.3.2',
          declaredRange: '^17.0.0',
          resolvedLockIdentity: '17.0.0(@octokit/core@7.0.7)',
        },
      ],
    });
  });

  it('contains only portable paths and public-neutral values', () => {
    const manifest = buildArtifactManifest(PROJECT_ROOT);
    const serialized = JSON.stringify(manifest);
    expect(serialized).not.toMatch(/\/home\/|(?:UID|GID)|(?:token|secret|private[_-]?key)/iu);
    for (const file of [
      manifest.project.packageJson,
      manifest.project.lockfile,
      ...manifest.artifacts.flatMap((artifact) => [artifact.packageJson, ...artifact.dataFiles]),
    ]) {
      expect(file.path).not.toMatch(/^\/|\\|(?:^|\/)\.\.(?:\/|$)/u);
      expect(file.sha256).toMatch(/^[a-f0-9]{64}$/u);
      expect(file.bytes).toBeGreaterThan(0);
    }
  });

  it('rejects drift in every identity-bearing field and unknown schema keys', () => {
    const baseline = buildArtifactManifest(PROJECT_ROOT);
    const mutations: ((manifest: ArtifactManifest) => void)[] = [
      (manifest) => {
        const artifact = manifest.artifacts.find((entry) => entry.role === 'openApi');
        if (artifact !== undefined) artifact.version = '22.0.1';
      },
      (manifest) => {
        const artifact = manifest.artifacts.find((entry) => entry.role === 'appPermissions');
        if (artifact !== undefined) artifact.integrity = `sha512-${'A'.repeat(88)}`;
      },
      (manifest) => {
        const artifact = manifest.artifacts.find((entry) => entry.role === 'standaloneEndpointMethods');
        const dataFile = artifact?.dataFiles[0];
        if (dataFile !== undefined) dataFile.path = 'node_modules/wrong/endpoints.js';
      },
      (manifest) => {
        const artifact = manifest.artifacts.find((entry) => entry.role === 'runtimeEndpointMethods');
        const dataFile = artifact?.dataFiles[0];
        if (dataFile !== undefined) dataFile.sha256 = '0'.repeat(64);
      },
      (manifest) => {
        (manifest as { githubRestApiEvidenceVersion: string }).githubRestApiEvidenceVersion = 'latest';
      },
    ];
    for (const mutate of mutations) {
      const changed = cloneManifest(baseline);
      mutate(changed);
      resign(changed);
      expect(() => assertArtifactManifestMatchesProject(PROJECT_ROOT, changed)).toThrow();
    }
    const extra = cloneManifest(baseline) as ArtifactManifest & { unexpected?: boolean };
    extra.unexpected = true;
    expect(() => validateArtifactManifest(extra)).toThrow(/unexpected keys/u);
  });

  it('fails closed for escaping, absent, and oversized paths', () => {
    expect(() => readBoundedArtifact(PROJECT_ROOT, '../package.json', 1024)).toThrow(/relative path|escapes/u);
    expect(() => readBoundedArtifact(PROJECT_ROOT, 'does-not-exist.json', 1024)).toThrow();
    expect(() => readBoundedArtifact(PROJECT_ROOT, 'pnpm-lock.yaml', 32)).toThrow(/byte limit/u);
  });

  it('has no runtime-package import, network, subprocess, or dynamic-import path', () => {
    const sourcePaths = [
      'tools/permission-data-feasibility/artifact-sources.ts',
      'tools/permission-data-feasibility/extract.ts',
      'tools/permission-data-feasibility/scripts/write-artifact-manifest.ts',
    ];
    const source = sourcePaths.map((path) => readFileSync(`${PROJECT_ROOT}/${path}`, 'utf8')).join('\n');
    expect(source).not.toMatch(/from\s+['"](?:octokit|probot|@octokit\/(?!openapi-types))/u);
    expect(source).not.toMatch(/node:(?:child_process|http|https|net|tls)|\bfetch\s*\(|\bimport\s*\(/u);
  });
});
