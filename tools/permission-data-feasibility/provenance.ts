import { canonicalJson, digestJson } from './artifact-sources.js';
import {
  assertExactKeys,
  assertPlainObject,
  assertSha256,
  type ArtifactManifest,
  type JsonValue,
  type PermissionFact,
  type PermissionSources,
} from './contracts.js';
import type { OperationInventoryRow, SupportManifest, SupportMember } from './inventory.js';
import { expressionDigest, validateRequirementExpression, type RequirementExpression } from './requirement-expression.js';

export const SOURCE_PRECEDENCE_MATRIX = {
  version: 1,
  ranks: [
    {
      rank: 1,
      sourceKind: 'github-app-permission-documentation',
      applicability: 'authoritative-for-github-app-semantics',
    },
    {
      rank: 2,
      sourceKind: 'installation-token-response-header',
      applicability: 'operator-bearing-corroboration-or-conflict',
    },
    {
      rank: 3,
      sourceKind: 'fine-grained-pat-response-header',
      applicability: 'representable-but-not-github-app-applicable',
    },
    {
      rank: 4,
      sourceKind: 'app-permissions-inverse-association',
      applicability: 'seed-and-cross-check-only',
    },
  ],
} as const;

export const SOURCE_PRECEDENCE_SHA256 = digestJson(SOURCE_PRECEDENCE_MATRIX as unknown as JsonValue);

export interface UpstreamArtifactReference {
  role: string;
  packageName: string;
  version: string;
  integrity: string;
  packageJsonSha256: string;
  selectedDataFiles: { path: string; sha256: string }[];
}

export interface CatalogEvidenceEntry {
  schemaVersion: 1;
  operation: {
    verb: string;
    path: string;
    operationId: string;
    methodAliases: string[];
  };
  requirement: RequirementExpression;
  rawEvidence: Omit<PermissionFact, 'evidenceSha256'>;
  provenance: {
    sourceKind: 'github-app-permission-documentation';
    sourceUrl: string;
    sourceDisposition: 'authoritative-reviewed';
    sourcePrecedenceSha256: string;
    apiVersion: '2022-11-28';
    documentationVersioning: 'unversioned-live';
    credentialClass: 'github-app-installation-token';
    credentialApplicability: 'github-app-reviewed';
    upstreamArtifacts: UpstreamArtifactReference[];
    retrievalStatus: 'captured';
    reviewStatus: 'reviewed';
    reviewedOn: string;
    artifactManifestSha256: string;
    permissionSourcesSha256: string;
  };
  rawEvidenceSha256: string;
  expressionSha256: string;
  supportPredicateSha256: string;
  selectionSha256: string;
  entrySha256: string;
}

export interface CatalogEvidenceContext {
  row: OperationInventoryRow;
  member: SupportMember;
  fact: PermissionFact;
  artifactManifest: ArtifactManifest;
  permissionSources: PermissionSources;
  supportManifest: SupportManifest;
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function upstreamArtifacts(manifest: ArtifactManifest): UpstreamArtifactReference[] {
  return manifest.artifacts
    .map((artifact) => ({
      role: artifact.role,
      packageName: artifact.packageName,
      version: artifact.version,
      integrity: artifact.integrity,
      packageJsonSha256: artifact.packageJson.sha256,
      selectedDataFiles: artifact.dataFiles.map((file) => ({ path: file.path, sha256: file.sha256 })),
    }))
    .sort((left, right) => compareStrings(left.role, right.role));
}

export function buildCatalogEvidenceEntry(context: CatalogEvidenceContext): CatalogEvidenceEntry {
  const { row, member, fact, artifactManifest, permissionSources, supportManifest } = context;
  if (
    row.operationId !== member.operationId ||
    row.verb !== member.verb ||
    row.path !== member.path ||
    row.expression === null ||
    row.permissionEvidenceSha256 !== fact.evidenceSha256 ||
    row.credentialApplicability !== 'github-app-reviewed' ||
    row.freshness !== 'current' ||
    row.reasons.length !== 0
  ) {
    throw new Error(`operation ${member.operationId} does not satisfy the provenance preconditions`);
  }
  if (
    fact.operationId !== member.operationId ||
    fact.verb !== member.verb ||
    fact.path !== member.path ||
    fact.requirement.permission !== (row.expression.type === 'permission' ? row.expression.permission : undefined) ||
    fact.requirement.level !== (row.expression.type === 'permission' ? row.expression.level : undefined)
  ) {
    throw new Error(`permission fact mismatch for ${member.operationId}`);
  }
  const { evidenceSha256: _evidenceSha256, ...rawEvidence } = fact;
  const unsigned: Omit<CatalogEvidenceEntry, 'entrySha256'> = {
    schemaVersion: 1,
    operation: {
      verb: member.verb,
      path: member.path,
      operationId: member.operationId,
      methodAliases: [...member.methodAliases],
    },
    requirement: structuredClone(row.expression),
    rawEvidence,
    provenance: {
      sourceKind: 'github-app-permission-documentation',
      sourceUrl: fact.sourceUrl,
      sourceDisposition: 'authoritative-reviewed',
      sourcePrecedenceSha256: SOURCE_PRECEDENCE_SHA256,
      apiVersion: artifactManifest.githubRestApiEvidenceVersion,
      documentationVersioning: artifactManifest.documentationVersioning,
      credentialClass: 'github-app-installation-token',
      credentialApplicability: 'github-app-reviewed',
      upstreamArtifacts: upstreamArtifacts(artifactManifest),
      retrievalStatus: permissionSources.documentation.retrievalStatus,
      reviewStatus: permissionSources.documentation.reviewStatus,
      reviewedOn: permissionSources.documentation.reviewedOn,
      artifactManifestSha256: artifactManifest.contentSha256,
      permissionSourcesSha256: permissionSources.contentSha256,
    },
    rawEvidenceSha256: fact.evidenceSha256,
    expressionSha256: expressionDigest(row.expression),
    supportPredicateSha256: supportManifest.predicate.ruleSha256,
    selectionSha256: supportManifest.selectionSha256,
  };
  if (
    unsigned.expressionSha256 !== member.expressionSha256 ||
    unsigned.rawEvidenceSha256 !== member.permissionEvidenceSha256 ||
    unsigned.provenance.artifactManifestSha256 !== member.artifactManifestSha256 ||
    unsigned.provenance.permissionSourcesSha256 !== member.permissionSourcesSha256
  ) {
    throw new Error(`support member digest mismatch for ${member.operationId}`);
  }
  return { ...unsigned, entrySha256: digestJson(unsigned as unknown as JsonValue) };
}

function validateArtifactReference(value: unknown, label: string): void {
  assertPlainObject(value, label);
  assertExactKeys(
    value,
    ['role', 'packageName', 'version', 'integrity', 'packageJsonSha256', 'selectedDataFiles'],
    label,
  );
  for (const key of ['role', 'packageName', 'version', 'integrity'] as const) {
    if (typeof value[key] !== 'string' || value[key].length === 0) throw new TypeError(`${label}.${key} is invalid`);
  }
  assertSha256(value.packageJsonSha256, `${label}.packageJsonSha256`);
  if (!Array.isArray(value.selectedDataFiles)) throw new TypeError(`${label}.selectedDataFiles must be an array`);
  for (const [index, file] of value.selectedDataFiles.entries()) {
    assertPlainObject(file, `${label}.selectedDataFiles[${index}]`);
    assertExactKeys(file, ['path', 'sha256'], `${label}.selectedDataFiles[${index}]`);
    if (typeof file.path !== 'string' || file.path.length === 0) throw new TypeError(`${label} data path is invalid`);
    assertSha256(file.sha256, `${label}.selectedDataFiles[${index}].sha256`);
  }
}

export function validateCatalogEvidenceEntry(
  value: unknown,
  context: CatalogEvidenceContext,
): asserts value is CatalogEvidenceEntry {
  assertPlainObject(value, 'catalog evidence entry');
  assertExactKeys(
    value,
    [
      'schemaVersion',
      'operation',
      'requirement',
      'rawEvidence',
      'provenance',
      'rawEvidenceSha256',
      'expressionSha256',
      'supportPredicateSha256',
      'selectionSha256',
      'entrySha256',
    ],
    'catalog evidence entry',
  );
  if (value.schemaVersion !== 1) throw new TypeError('catalog evidence schema version mismatch');
  assertPlainObject(value.operation, 'catalog evidence operation');
  assertExactKeys(value.operation, ['verb', 'path', 'operationId', 'methodAliases'], 'catalog evidence operation');
  if (
    typeof value.operation.verb !== 'string' ||
    typeof value.operation.path !== 'string' ||
    typeof value.operation.operationId !== 'string' ||
    !Array.isArray(value.operation.methodAliases) ||
    !value.operation.methodAliases.every((alias) => typeof alias === 'string')
  ) {
    throw new TypeError('catalog evidence operation is invalid');
  }
  validateRequirementExpression(value.requirement);
  assertPlainObject(value.rawEvidence, 'catalog raw evidence');
  assertExactKeys(value.rawEvidence, ['operationId', 'verb', 'path', 'requirement', 'sourceUrl'], 'catalog raw evidence');
  assertPlainObject(value.provenance, 'catalog provenance');
  assertExactKeys(
    value.provenance,
    [
      'sourceKind',
      'sourceUrl',
      'sourceDisposition',
      'sourcePrecedenceSha256',
      'apiVersion',
      'documentationVersioning',
      'credentialClass',
      'credentialApplicability',
      'upstreamArtifacts',
      'retrievalStatus',
      'reviewStatus',
      'reviewedOn',
      'artifactManifestSha256',
      'permissionSourcesSha256',
    ],
    'catalog provenance',
  );
  if (!Array.isArray(value.provenance.upstreamArtifacts) || value.provenance.upstreamArtifacts.length === 0) {
    throw new TypeError('catalog provenance upstream artifacts are invalid');
  }
  value.provenance.upstreamArtifacts.forEach((artifact, index) =>
    validateArtifactReference(artifact, `catalog provenance upstreamArtifacts[${index}]`),
  );
  for (const key of [
    'sourcePrecedenceSha256',
    'artifactManifestSha256',
    'permissionSourcesSha256',
  ] as const) {
    assertSha256(value.provenance[key], `catalog provenance.${key}`);
  }
  for (const key of ['rawEvidenceSha256', 'expressionSha256', 'supportPredicateSha256', 'selectionSha256', 'entrySha256'] as const) {
    assertSha256(value[key], `catalog evidence.${key}`);
  }
  const expected = buildCatalogEvidenceEntry(context);
  if (canonicalJson(value as unknown as JsonValue) !== canonicalJson(expected as unknown as JsonValue)) {
    throw new Error(`catalog evidence entry does not match ${context.member.operationId}`);
  }
}
