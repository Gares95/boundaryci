import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, readdirSync, realpathSync } from 'node:fs';
import { relative, resolve, sep } from 'node:path';

import {
  assertExactKeys,
  assertPlainObject,
  assertPortableRelativePath,
  assertSha256,
  type ArtifactIdentity,
  type ArtifactManifest,
  type ArtifactRole,
  type JsonValue,
  type StaticDataFileIdentity,
} from './contracts.js';

const MAX_PACKAGE_JSON_BYTES = 256 * 1024;
const MAX_LOCKFILE_BYTES = 4 * 1024 * 1024;

export const STATIC_ARTIFACT_SOURCES = {
  appPermissions: {
    packageName: '@octokit/app-permissions',
    version: '2.1.0',
    packagePath: 'node_modules/@octokit/app-permissions',
    dataPaths: ['generated/api.github.com.json'],
    maxDataBytes: 4 * 1024 * 1024,
  },
  octokit: {
    packageName: 'octokit',
    version: '5.0.5',
    packagePath: 'node_modules/octokit',
    dataPaths: [],
    maxDataBytes: 0,
  },
  openApi: {
    packageName: '@octokit/openapi',
    version: '22.0.0',
    packagePath: 'node_modules/@octokit/openapi',
    dataPaths: ['generated/api.github.com.json'],
    maxDataBytes: 20 * 1024 * 1024,
  },
  probot: {
    packageName: 'probot',
    version: '14.3.2',
    packagePath: 'node_modules/probot',
    dataPaths: [],
    maxDataBytes: 0,
  },
  standaloneEndpointMethods: {
    packageName: '@octokit/plugin-rest-endpoint-methods',
    version: '18.0.0',
    packagePath: 'node_modules/@octokit/plugin-rest-endpoint-methods',
    dataPaths: ['dist-src/generated/endpoints.js'],
    maxDataBytes: 4 * 1024 * 1024,
  },
  typescript: {
    packageName: 'typescript',
    version: '6.0.2',
    packagePath: 'node_modules/typescript',
    dataPaths: [],
    maxDataBytes: 0,
  },
} as const;

interface ParsedLockfile {
  directVersions: Map<string, string>;
  integrities: Map<string, string>;
  snapshots: Map<string, Map<string, string>>;
}

interface PackageJson {
  name: string;
  version: string;
  repository?: string | { url?: string };
  dependencies?: Record<string, string>;
}

function decodeYamlKey(raw: string): string {
  if (raw.startsWith("'") && raw.endsWith("'")) return raw.slice(1, -1).replaceAll("''", "'");
  return raw;
}

function headerKey(line: string, indent: number): string | undefined {
  if (!line.startsWith(' '.repeat(indent)) || line[indent] === ' ') return undefined;
  const body = line.slice(indent);
  if (!body.endsWith(':')) return undefined;
  return decodeYamlKey(body.slice(0, -1));
}

function parseInlineIntegrity(line: string): string | undefined {
  return /resolution: \{integrity: ([^,}]+)[,}]?/u.exec(line)?.[1];
}

export function parsePnpmLockfile(text: string): ParsedLockfile {
  if (Buffer.byteLength(text, 'utf8') > MAX_LOCKFILE_BYTES) throw new Error('lockfile exceeds byte limit');
  const lines = text.split(/\r?\n/u);
  if (lines[0] !== "lockfileVersion: '9.0'") throw new Error('unsupported pnpm lockfile version');

  const directVersions = new Map<string, string>();
  const integrities = new Map<string, string>();
  const snapshots = new Map<string, Map<string, string>>();

  const rootStart = lines.findIndex((line, index) => line === '  .:' && lines.slice(0, index).includes('importers:'));
  const packagesStart = lines.indexOf('packages:');
  const snapshotsStart = lines.indexOf('snapshots:');
  if (rootStart < 0 || packagesStart < 0 || snapshotsStart < 0 || packagesStart >= snapshotsStart) {
    throw new Error('lockfile is missing required sections');
  }

  for (let index = rootStart + 1; index < packagesStart; index += 1) {
    const dependency = headerKey(lines[index] ?? '', 6);
    if (dependency === undefined) continue;
    for (let cursor = index + 1; cursor < packagesStart; cursor += 1) {
      const line = lines[cursor] ?? '';
      if (headerKey(line, 6) !== undefined || headerKey(line, 2) !== undefined) break;
      const match = /^        version: (.+)$/u.exec(line);
      if (match?.[1] !== undefined) {
        if (directVersions.has(dependency)) throw new Error(`duplicate root dependency ${dependency}`);
        directVersions.set(dependency, decodeYamlKey(match[1]));
        break;
      }
    }
  }

  let currentPackage: string | undefined;
  for (let index = packagesStart + 1; index < snapshotsStart; index += 1) {
    const line = lines[index] ?? '';
    const key = headerKey(line, 2);
    if (key !== undefined) {
      currentPackage = key;
      continue;
    }
    if (currentPackage !== undefined && line.startsWith('    resolution:')) {
      const integrity = parseInlineIntegrity(line);
      if (integrity === undefined) throw new Error(`package ${currentPackage} lacks integrity`);
      integrities.set(currentPackage, integrity);
    }
  }

  let currentSnapshot: string | undefined;
  let inDependencies = false;
  for (let index = snapshotsStart + 1; index < lines.length; index += 1) {
    const line = lines[index] ?? '';
    const snapshot = headerKey(line, 2);
    if (snapshot !== undefined) {
      currentSnapshot = snapshot;
      snapshots.set(snapshot, new Map());
      inDependencies = false;
      continue;
    }
    if (currentSnapshot === undefined) continue;
    if (line === '    dependencies:') {
      inDependencies = true;
      continue;
    }
    if (line.startsWith('    ') && !line.startsWith('      ')) inDependencies = false;
    if (!inDependencies) continue;
    const inlineDependency = /^      (?:(?:'([^']+)')|([^:]+)): (.+)$/u.exec(line);
    if (inlineDependency !== null) {
      const name = inlineDependency[1] ?? inlineDependency[2];
      const version = inlineDependency[3];
      if (name === undefined || version === undefined) throw new Error(`malformed dependency in ${currentSnapshot}`);
      snapshots.get(currentSnapshot)?.set(name, decodeYamlKey(version));
      continue;
    }
    const dependency = headerKey(line, 6);
    if (dependency === undefined) continue;
    const valueLine = lines[index + 1] ?? '';
    const valueMatch = /^        (?:version: )?(.+)$/u.exec(valueLine);
    if (valueMatch?.[1] !== undefined) {
      snapshots.get(currentSnapshot)?.set(dependency, decodeYamlKey(valueMatch[1]));
      index += 1;
      continue;
    }
  }

  return { directVersions, integrities, snapshots };
}

export function sha256(bytes: Uint8Array | string): string {
  return createHash('sha256').update(bytes).digest('hex');
}

export function canonicalJson(value: JsonValue): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((entry) => canonicalJson(entry)).join(',')}]`;
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key] as JsonValue)}`)
    .join(',')}}`;
}

export function digestJson(value: JsonValue): string {
  return sha256(canonicalJson(value));
}

export function readBoundedArtifact(projectRoot: string, path: string, maxBytes: number): Buffer {
  assertPortableRelativePath(path, 'artifact path');
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) throw new TypeError('maxBytes must be positive');
  const absoluteRoot = realpathSync(projectRoot);
  const requested = resolve(absoluteRoot, path);
  const lexicalRelative = relative(absoluteRoot, requested);
  if (lexicalRelative.startsWith(`..${sep}`) || lexicalRelative === '..') throw new Error(`artifact path escapes project: ${path}`);
  const actual = realpathSync(requested);
  const actualRelative = relative(absoluteRoot, actual);
  if (actualRelative.startsWith(`..${sep}`) || actualRelative === '..') throw new Error(`artifact target escapes project: ${path}`);
  const stat = lstatSync(actual);
  if (!stat.isFile()) throw new Error(`artifact is not a regular file: ${path}`);
  if (stat.size > maxBytes) throw new Error(`artifact exceeds byte limit: ${path}`);
  const bytes = readFileSync(actual);
  if (bytes.byteLength !== stat.size) throw new Error(`artifact changed while reading: ${path}`);
  return bytes;
}

export function parseBoundedJson(projectRoot: string, path: string, maxBytes: number): unknown {
  const text = readBoundedArtifact(projectRoot, path, maxBytes).toString('utf8');
  try {
    return JSON.parse(text) as unknown;
  } catch (error) {
    throw new Error(`malformed JSON artifact: ${path}`, { cause: error });
  }
}

function asPackageJson(value: unknown, expectedName: string, expectedVersion: string, label: string): PackageJson {
  assertPlainObject(value, label);
  if (value.name !== expectedName || value.version !== expectedVersion) {
    throw new Error(`${label} identity mismatch`);
  }
  if (value.repository !== undefined && typeof value.repository !== 'string') {
    assertPlainObject(value.repository, `${label}.repository`);
    if (value.repository.url !== undefined && typeof value.repository.url !== 'string') {
      throw new TypeError(`${label}.repository.url must be a string`);
    }
  }
  if (value.dependencies !== undefined) {
    assertPlainObject(value.dependencies, `${label}.dependencies`);
    for (const dependency of Object.values(value.dependencies)) {
      if (typeof dependency !== 'string') throw new TypeError(`${label}.dependencies must contain strings`);
    }
  }
  return value as unknown as PackageJson;
}

function repositoryIdentity(packageJson: PackageJson): string {
  const repository = packageJson.repository;
  if (typeof repository === 'string') return repository;
  if (repository?.url !== undefined) return repository.url;
  throw new Error(`${packageJson.name} lacks repository identity`);
}

function fileIdentity(projectRoot: string, path: string, maxBytes: number): StaticDataFileIdentity {
  const bytes = readBoundedArtifact(projectRoot, path, maxBytes);
  return { path, bytes: bytes.byteLength, sha256: sha256(bytes) };
}

function requireMapValue(map: Map<string, string>, key: string, label: string): string {
  const value = map.get(key);
  if (value === undefined) throw new Error(`${label} is missing ${key}`);
  return value;
}

function baseLockIdentity(name: string, version: string): string {
  return `${name}@${version}`;
}

function createArtifactIdentity(
  projectRoot: string,
  lock: ParsedLockfile,
  role: ArtifactRole,
  source: {
    packageName: string;
    version: string;
    packagePath: string;
    dataPaths: readonly string[];
    maxDataBytes: number;
  },
): ArtifactIdentity {
  const packageJsonPath = `${source.packagePath}/package.json`;
  const packageJson = asPackageJson(
    parseBoundedJson(projectRoot, packageJsonPath, MAX_PACKAGE_JSON_BYTES),
    source.packageName,
    source.version,
    packageJsonPath,
  );
  const lockIdentity = baseLockIdentity(source.packageName, source.version);
  return {
    role,
    packageName: source.packageName,
    version: source.version,
    lockIdentity,
    integrity: requireMapValue(lock.integrities, lockIdentity, 'lock package records'),
    repository: repositoryIdentity(packageJson),
    packageJson: fileIdentity(projectRoot, packageJsonPath, MAX_PACKAGE_JSON_BYTES),
    dataFiles: source.dataPaths.map((entry) =>
      fileIdentity(projectRoot, `${source.packagePath}/${entry}`, source.maxDataBytes),
    ),
  };
}

function discoverRuntimeEndpointMethods(projectRoot: string, lock: ParsedLockfile): {
  artifact: ArtifactIdentity;
  peerContext: '@octokit/core@7.0.7';
} {
  const storePath = 'node_modules/.pnpm';
  const expectedDirectory = '@octokit+plugin-rest-endpoint-methods@17.0.0_@octokit+core@7.0.7';
  const matches = readdirSync(resolve(projectRoot, storePath), { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && entry.name.startsWith('@octokit+plugin-rest-endpoint-methods@17.0.0_'))
    .map((entry) => entry.name);
  if (matches.length !== 1 || matches[0] !== expectedDirectory) {
    throw new Error(`expected one endpoint-methods 17 runtime package, found ${matches.join(',') || 'none'}`);
  }
  const source = {
    packageName: '@octokit/plugin-rest-endpoint-methods',
    version: '17.0.0',
    packagePath: `${storePath}/${expectedDirectory}/node_modules/@octokit/plugin-rest-endpoint-methods`,
    dataPaths: ['dist-src/generated/endpoints.js'],
    maxDataBytes: 4 * 1024 * 1024,
  } as const;
  return {
    artifact: createArtifactIdentity(projectRoot, lock, 'runtimeEndpointMethods', source),
    peerContext: '@octokit/core@7.0.7',
  };
}

function stripContentSha256<T extends { contentSha256: string }>(value: T): Omit<T, 'contentSha256'> {
  const { contentSha256: _contentSha256, ...unsigned } = value;
  return unsigned;
}

export function buildArtifactManifest(projectRoot: string): ArtifactManifest {
  const packageJsonPath = 'package.json';
  const lockfilePath = 'pnpm-lock.yaml';
  const rootPackage = parseBoundedJson(projectRoot, packageJsonPath, MAX_PACKAGE_JSON_BYTES);
  assertPlainObject(rootPackage, 'package.json');
  if (typeof rootPackage.packageManager !== 'string') throw new TypeError('packageManager must be a string');
  assertPlainObject(rootPackage.devDependencies, 'package.json.devDependencies');

  const lockBytes = readBoundedArtifact(projectRoot, lockfilePath, MAX_LOCKFILE_BYTES);
  const lock = parsePnpmLockfile(lockBytes.toString('utf8'));
  const artifacts: ArtifactIdentity[] = [];
  for (const [role, source] of Object.entries(STATIC_ARTIFACT_SOURCES) as [
    keyof typeof STATIC_ARTIFACT_SOURCES,
    (typeof STATIC_ARTIFACT_SOURCES)[keyof typeof STATIC_ARTIFACT_SOURCES],
  ][]) {
    if (rootPackage.devDependencies[source.packageName] !== source.version) {
      throw new Error(`package.json version mismatch for ${source.packageName}`);
    }
    const rootVersion = requireMapValue(lock.directVersions, source.packageName, 'root lock importer');
    if (rootVersion !== source.version && !rootVersion.startsWith(`${source.version}(`)) {
      throw new Error(`root lock version mismatch for ${source.packageName}`);
    }
    artifacts.push(createArtifactIdentity(projectRoot, lock, role, source));
  }

  const runtime = discoverRuntimeEndpointMethods(projectRoot, lock);
  artifacts.push(runtime.artifact);
  artifacts.sort((left, right) => left.role.localeCompare(right.role));

  const consumers = (['octokit', 'probot'] as const).map((name) => {
    const source = STATIC_ARTIFACT_SOURCES[name];
    const packageJson = asPackageJson(
      parseBoundedJson(projectRoot, `${source.packagePath}/package.json`, MAX_PACKAGE_JSON_BYTES),
      name,
      source.version,
      `${name} package.json`,
    );
    const declaredRange = packageJson.dependencies?.['@octokit/plugin-rest-endpoint-methods'];
    if (declaredRange !== '^17.0.0') throw new Error(`${name} has unexpected endpoint-methods range`);
    const resolvedLockIdentity = lock.snapshots.get(`${name}@${source.version}`)?.get('@octokit/plugin-rest-endpoint-methods');
    if (resolvedLockIdentity !== '17.0.0(@octokit/core@7.0.7)') {
      throw new Error(`${name} has unexpected endpoint-methods lock edge`);
    }
    return { packageName: name, version: source.version, declaredRange, resolvedLockIdentity };
  }) as [
    {
      packageName: 'octokit';
      version: string;
      declaredRange: string;
      resolvedLockIdentity: string;
    },
    {
      packageName: 'probot';
      version: string;
      declaredRange: string;
      resolvedLockIdentity: string;
    },
  ];

  const unsigned: Omit<ArtifactManifest, 'contentSha256'> = {
    schemaVersion: 1,
    githubRestApiEvidenceVersion: '2022-11-28',
    documentationVersioning: 'unversioned-live',
    project: {
      packageManager: rootPackage.packageManager,
      packageJson: fileIdentity(projectRoot, packageJsonPath, MAX_PACKAGE_JSON_BYTES),
      lockfile: { path: lockfilePath, bytes: lockBytes.byteLength, sha256: sha256(lockBytes) },
    },
    artifacts,
    runtimeEndpointSelection: {
      selectedRole: 'runtimeEndpointMethods',
      peerContext: runtime.peerContext,
      consumers,
    },
  };
  return { ...unsigned, contentSha256: digestJson(unsigned as unknown as JsonValue) };
}

function validateFileIdentity(value: unknown, label: string): void {
  assertPlainObject(value, label);
  assertExactKeys(value, ['path', 'bytes', 'sha256'], label);
  assertPortableRelativePath(value.path, `${label}.path`);
  if (!Number.isSafeInteger(value.bytes) || (value.bytes as number) <= 0) throw new TypeError(`${label}.bytes is invalid`);
  assertSha256(value.sha256, `${label}.sha256`);
}

export function validateArtifactManifest(value: unknown): asserts value is ArtifactManifest {
  assertPlainObject(value, 'artifact manifest');
  assertExactKeys(
    value,
    [
      'schemaVersion',
      'githubRestApiEvidenceVersion',
      'documentationVersioning',
      'project',
      'artifacts',
      'runtimeEndpointSelection',
      'contentSha256',
    ],
    'artifact manifest',
  );
  if (value.schemaVersion !== 1 || value.githubRestApiEvidenceVersion !== '2022-11-28') {
    throw new TypeError('artifact manifest version mismatch');
  }
  if (value.documentationVersioning !== 'unversioned-live') throw new TypeError('documentation versioning mismatch');
  assertPlainObject(value.project, 'artifact manifest.project');
  assertExactKeys(value.project, ['packageManager', 'packageJson', 'lockfile'], 'artifact manifest.project');
  if (typeof value.project.packageManager !== 'string') throw new TypeError('packageManager must be a string');
  validateFileIdentity(value.project.packageJson, 'artifact manifest.project.packageJson');
  validateFileIdentity(value.project.lockfile, 'artifact manifest.project.lockfile');
  if (!Array.isArray(value.artifacts) || value.artifacts.length !== 7) throw new TypeError('artifact list must contain seven identities');
  const roles = new Set<string>();
  for (const [index, artifact] of value.artifacts.entries()) {
    assertPlainObject(artifact, `artifact[${index}]`);
    assertExactKeys(
      artifact,
      ['role', 'packageName', 'version', 'lockIdentity', 'integrity', 'repository', 'packageJson', 'dataFiles'],
      `artifact[${index}]`,
    );
    for (const key of ['role', 'packageName', 'version', 'lockIdentity', 'integrity', 'repository'] as const) {
      if (typeof artifact[key] !== 'string' || artifact[key].length === 0) throw new TypeError(`artifact[${index}].${key} is invalid`);
    }
    if (roles.has(artifact.role as string)) throw new TypeError(`duplicate artifact role ${String(artifact.role)}`);
    roles.add(artifact.role as string);
    validateFileIdentity(artifact.packageJson, `artifact[${index}].packageJson`);
    if (!Array.isArray(artifact.dataFiles)) throw new TypeError(`artifact[${index}].dataFiles must be an array`);
    artifact.dataFiles.forEach((file, fileIndex) => validateFileIdentity(file, `artifact[${index}].dataFiles[${fileIndex}]`));
  }
  assertPlainObject(value.runtimeEndpointSelection, 'runtimeEndpointSelection');
  assertExactKeys(value.runtimeEndpointSelection, ['selectedRole', 'peerContext', 'consumers'], 'runtimeEndpointSelection');
  if (
    value.runtimeEndpointSelection.selectedRole !== 'runtimeEndpointMethods' ||
    value.runtimeEndpointSelection.peerContext !== '@octokit/core@7.0.7' ||
    !Array.isArray(value.runtimeEndpointSelection.consumers) ||
    value.runtimeEndpointSelection.consumers.length !== 2
  ) {
    throw new TypeError('runtime endpoint selection mismatch');
  }
  for (const [index, consumer] of value.runtimeEndpointSelection.consumers.entries()) {
    assertPlainObject(consumer, `runtime consumer[${index}]`);
    assertExactKeys(consumer, ['packageName', 'version', 'declaredRange', 'resolvedLockIdentity'], `runtime consumer[${index}]`);
    if (!['octokit', 'probot'].includes(String(consumer.packageName))) throw new TypeError('runtime consumer name mismatch');
    if (consumer.declaredRange !== '^17.0.0' || consumer.resolvedLockIdentity !== '17.0.0(@octokit/core@7.0.7)') {
      throw new TypeError('runtime consumer edge mismatch');
    }
  }
  assertSha256(value.contentSha256, 'artifact manifest.contentSha256');
  const expected = digestJson(stripContentSha256(value as unknown as ArtifactManifest) as unknown as JsonValue);
  if (value.contentSha256 !== expected) throw new Error('artifact manifest content digest mismatch');
}

export function assertArtifactManifestMatchesProject(projectRoot: string, value: unknown): asserts value is ArtifactManifest {
  validateArtifactManifest(value);
  const expected = buildArtifactManifest(projectRoot);
  if (canonicalJson(value as unknown as JsonValue) !== canonicalJson(expected as unknown as JsonValue)) {
    throw new Error('artifact manifest does not match the current project artifacts');
  }
}
