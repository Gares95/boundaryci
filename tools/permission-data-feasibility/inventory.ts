import { digestJson } from './artifact-sources.js';
import {
  assertExactKeys,
  assertPlainObject,
  assertSha256,
  type ArtifactManifest,
  type JsonValue,
  type PermissionFact,
  type PermissionSources,
} from './contracts.js';
import {
  parseOpenApiOperations,
  validatePermissionSources,
  type EndpointMethodRecord,
  type OpenApiOperationRecord,
} from './extract.js';
import {
  expressionDigest,
  validateRequirementExpression,
  type RequirementExpression,
} from './requirement-expression.js';
import {
  parseAppPermissionSeedAssociations,
  validatePermissionSourceExtensions,
  type HeaderPermissionFact,
  type PermissionSourceExtensions,
  type RawPermissionSeedAssociation,
} from './source-evidence.js';

export type EvidenceClass = 'single' | 'allOf' | 'anyOf' | 'ambiguous' | 'conflicting' | 'missing' | 'unsupported';
export type FreshnessState = 'current' | 'stale-seed' | 'not-assessed';
export type CredentialApplicability = 'github-app-reviewed' | 'fine-grained-pat-only' | 'none';
export type SurfaceStatus = 'common-identical' | 'v17-only' | 'v18-only' | 'surface-conflict';
export type OperationJoinStatus = 'matched-operation' | 'no-openapi-operation' | 'duplicate-openapi-operation';

export interface AppEnabledOperation extends OpenApiOperationRecord {
  appEnabled: true;
}

export interface OperationInventoryRow extends AppEnabledOperation {
  evidenceClass: EvidenceClass;
  freshness: FreshnessState;
  credentialApplicability: CredentialApplicability;
  expression: RequirementExpression | null;
  observedExpression: RequirementExpression | null;
  permissionEvidenceSha256: string | null;
  rawSeedAssociations: RawPermissionSeedAssociation[];
  reasons: string[];
}

export interface MethodJoinRow {
  scope: string;
  method: string;
  v17Routes: string[];
  v18Routes: string[];
  surfaceStatus: SurfaceStatus;
  operationJoinStatus: OperationJoinStatus;
  operationIds: string[];
}

export interface OperationInventory {
  schemaVersion: 1;
  apiVersion: '2022-11-28';
  artifactManifestSha256: string;
  permissionSourcesSha256: string;
  strategy: 'generated-candidates-plus-reviewed-bounded-catalog';
  operationUniverse: {
    total: number;
    classCounts: Record<EvidenceClass, number>;
    freshnessCounts: Record<FreshnessState, number>;
    credentialApplicabilityCounts: Record<CredentialApplicability, number>;
  };
  methodUniverse: {
    total: number;
    surfaceCounts: Record<SurfaceStatus, number>;
    operationJoinCounts: Record<OperationJoinStatus, number>;
  };
  operationRows: OperationInventoryRow[];
  methodJoinRows: MethodJoinRow[];
  contentSha256: string;
}

export interface SupportMember {
  verb: string;
  path: string;
  operationId: string;
  methodAliases: string[];
  expressionSha256: string;
  permissionEvidenceSha256: string;
  permissionSourcesSha256: string;
  artifactManifestSha256: string;
}

export interface SupportManifest {
  schemaVersion: 1;
  strategy: 'generated-candidates-plus-reviewed-bounded-catalog';
  artifactManifestSha256: string;
  permissionSourcesSha256: string;
  predicate: {
    rule: {
      version: 1;
      conditions: string[];
    };
    ruleSha256: string;
  };
  requiredOperationIds: ['issues/create', 'issues/list-for-repo'];
  selectedMembers: SupportMember[];
  selectionSha256: string;
  contentSha256: string;
}

export interface InventoryInputs {
  artifactManifest: ArtifactManifest;
  permissionSources: PermissionSources;
  openApiDocument: unknown;
  appPermissionsDocument: unknown;
  runtimeEndpointMethods: readonly EndpointMethodRecord[];
  standaloneEndpointMethods: readonly EndpointMethodRecord[];
}

const CLASSES: readonly EvidenceClass[] = [
  'single',
  'allOf',
  'anyOf',
  'ambiguous',
  'conflicting',
  'missing',
  'unsupported',
];
const FRESHNESS: readonly FreshnessState[] = ['current', 'stale-seed', 'not-assessed'];
const CREDENTIALS: readonly CredentialApplicability[] = ['github-app-reviewed', 'fine-grained-pat-only', 'none'];
const SURFACES: readonly SurfaceStatus[] = ['common-identical', 'v17-only', 'v18-only', 'surface-conflict'];
const JOINS: readonly OperationJoinStatus[] = [
  'matched-operation',
  'no-openapi-operation',
  'duplicate-openapi-operation',
];
const SUPPORT_CONDITIONS = [
  'app-enabled-openapi-operation',
  'unique-method-route-operation-join',
  'direct-method-alias-common-identical-v17-v18',
  'reviewer-backed-github-app-applicable-expression',
  'supported-permission-vocabulary-and-access',
  'complete-artifact-source-api-and-integrity-provenance',
  'no-ambiguous-conflicting-stale-unsupported-or-credential-unproven-qualifier',
] as const;
const MAX_OPENAPI_PATHS = 4096;

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function countBy<T extends string>(values: readonly T[], members: readonly T[]): Record<T, number> {
  const counts = Object.fromEntries(members.map((member) => [member, 0])) as Record<T, number>;
  for (const value of values) counts[value] += 1;
  return counts;
}

function permissionExtensions(permissionSources: PermissionSources): PermissionSourceExtensions {
  const record = permissionSources as unknown as Record<string, unknown>;
  const extensions = {
    vocabulary: record.vocabulary,
    headerFacts: record.headerFacts,
    refusedProbes: record.refusedProbes,
  };
  validatePermissionSourceExtensions(extensions);
  return extensions;
}

export function parseAppEnabledOpenApiOperations(value: unknown): AppEnabledOperation[] {
  assertPlainObject(value, 'OpenAPI document');
  assertPlainObject(value.paths, 'OpenAPI paths');
  if (Object.keys(value.paths).length > MAX_OPENAPI_PATHS) throw new Error('OpenAPI path count is out of bounds');
  const allOperations = parseOpenApiOperations(value);
  const enabled = new Set<string>();
  for (const [path, pathItem] of Object.entries(value.paths)) {
    assertPlainObject(pathItem, `OpenAPI path ${path}`);
    for (const [verb, operation] of Object.entries(pathItem)) {
      if (!['delete', 'get', 'head', 'options', 'patch', 'post', 'put'].includes(verb)) continue;
      assertPlainObject(operation, `OpenAPI operation ${verb.toUpperCase()} ${path}`);
      assertPlainObject(operation['x-github'], `OpenAPI operation ${verb.toUpperCase()} ${path}.x-github`);
      if (operation['x-github'].enabledForGitHubApps === true) enabled.add(`${verb.toUpperCase()} ${path}`);
    }
  }
  return allOperations
    .filter((operation) => enabled.has(`${operation.verb} ${operation.path}`))
    .map((operation) => ({ ...operation, appEnabled: true as const }))
    .sort((left, right) =>
      compareStrings(
        `${left.verb} ${left.path}\0${left.operationId}`,
        `${right.verb} ${right.path}\0${right.operationId}`,
      ),
    );
}

function routeKey(verb: string, path: string): string {
  return `${verb} ${path}`;
}

function exactFactExpression(fact: PermissionFact): RequirementExpression {
  return {
    type: 'permission',
    permission: fact.requirement.permission,
    level: fact.requirement.level,
  };
}

function sameAtom(seed: RawPermissionSeedAssociation, fact: PermissionFact): boolean {
  return seed.permission === fact.requirement.permission && seed.level === fact.requirement.level;
}

function classifyOperation(
  operation: AppEnabledOperation,
  facts: readonly PermissionFact[],
  headers: readonly HeaderPermissionFact[],
  seeds: readonly RawPermissionSeedAssociation[],
  vocabulary: ReadonlySet<string>,
): OperationInventoryRow {
  const matchingFacts = facts.filter(
    (fact) => fact.operationId === operation.operationId && fact.verb === operation.verb && fact.path === operation.path,
  );
  const matchingHeaders = headers.filter(
    (fact) =>
      fact.operation.operationId === operation.operationId &&
      fact.operation.verb === operation.verb &&
      fact.operation.path === operation.path,
  );
  const matchingSeeds = seeds.filter((seed) => seed.verb === operation.verb && seed.path === operation.path);
  const unsupportedSeedVocabulary = matchingSeeds.some((seed) => !vocabulary.has(seed.permission));

  if (matchingFacts.length > 1) {
    return {
      ...operation,
      evidenceClass: 'conflicting',
      freshness: 'not-assessed',
      credentialApplicability: 'github-app-reviewed',
      expression: null,
      observedExpression: matchingHeaders[0]?.expression ?? null,
      permissionEvidenceSha256: null,
      rawSeedAssociations: matchingSeeds,
      reasons: ['multiple-applicable-primary-facts'],
    };
  }
  const fact = matchingFacts[0];
  if (fact !== undefined) {
    const exactSeed = matchingSeeds.filter((seed) => sameAtom(seed, fact));
    const staleSeed = matchingSeeds.length > 0 && (exactSeed.length !== matchingSeeds.length || unsupportedSeedVocabulary);
    return {
      ...operation,
      evidenceClass: 'single',
      freshness: staleSeed ? 'stale-seed' : 'current',
      credentialApplicability: 'github-app-reviewed',
      expression: exactFactExpression(fact),
      observedExpression: matchingHeaders[0]?.expression ?? null,
      permissionEvidenceSha256: fact.evidenceSha256,
      rawSeedAssociations: matchingSeeds,
      reasons: staleSeed ? ['seed-disagrees-with-primary-evidence'] : [],
    };
  }
  const header = matchingHeaders[0];
  if (header !== undefined) {
    const headerAtoms = new Set<string>();
    const visit = (expression: RequirementExpression): void => {
      if (expression.type === 'permission') headerAtoms.add(`${expression.permission}\0${expression.level}`);
      else expression.requirements.forEach(visit);
    };
    visit(header.expression);
    const staleSeed = matchingSeeds.some((seed) => !headerAtoms.has(`${seed.permission}\0${seed.level}`));
    return {
      ...operation,
      evidenceClass: 'unsupported',
      freshness: staleSeed ? 'stale-seed' : 'not-assessed',
      credentialApplicability: 'fine-grained-pat-only',
      expression: null,
      observedExpression: header.expression,
      permissionEvidenceSha256: header.expressionSha256,
      rawSeedAssociations: matchingSeeds,
      reasons: ['credential-equivalence-unproven'],
    };
  }
  if (matchingSeeds.length > 1) {
    return {
      ...operation,
      evidenceClass: 'ambiguous',
      freshness: unsupportedSeedVocabulary ? 'stale-seed' : 'not-assessed',
      credentialApplicability: 'none',
      expression: null,
      observedExpression: null,
      permissionEvidenceSha256: null,
      rawSeedAssociations: matchingSeeds,
      reasons: ['operator-missing-from-seed', ...(unsupportedSeedVocabulary ? ['unsupported-seed-vocabulary'] : [])],
    };
  }
  if (matchingSeeds.length === 1) {
    return {
      ...operation,
      evidenceClass: 'unsupported',
      freshness: unsupportedSeedVocabulary ? 'stale-seed' : 'not-assessed',
      credentialApplicability: 'none',
      expression: null,
      observedExpression: null,
      permissionEvidenceSha256: null,
      rawSeedAssociations: matchingSeeds,
      reasons: ['seed-not-authoritative', ...(unsupportedSeedVocabulary ? ['unsupported-seed-vocabulary'] : [])],
    };
  }
  return {
    ...operation,
    evidenceClass: 'missing',
    freshness: 'not-assessed',
    credentialApplicability: 'none',
    expression: null,
    observedExpression: null,
    permissionEvidenceSha256: null,
    rawSeedAssociations: [],
    reasons: ['applicable-permission-evidence-missing'],
  };
}

function recordsByMethod(records: readonly EndpointMethodRecord[]): Map<string, EndpointMethodRecord[]> {
  const result = new Map<string, EndpointMethodRecord[]>();
  for (const record of records) {
    const key = `${record.scope}.${record.method}`;
    const entries = result.get(key) ?? [];
    entries.push(record);
    result.set(key, entries);
  }
  return result;
}

function splitRoute(route: string): { verb: string; path: string } | undefined {
  const match = /^([A-Z]+) (\/.+)$/u.exec(route);
  return match?.[1] === undefined || match[2] === undefined ? undefined : { verb: match[1], path: match[2] };
}

function buildMethodRows(
  runtime: readonly EndpointMethodRecord[],
  standalone: readonly EndpointMethodRecord[],
  openApi: readonly OpenApiOperationRecord[],
): MethodJoinRow[] {
  const v17 = recordsByMethod(runtime);
  const v18 = recordsByMethod(standalone);
  const keys = [...new Set([...v17.keys(), ...v18.keys()])].sort();
  const openApiByRoute = new Map<string, OpenApiOperationRecord[]>();
  for (const operation of openApi) {
    const key = routeKey(operation.verb, operation.path);
    const entries = openApiByRoute.get(key) ?? [];
    entries.push(operation);
    openApiByRoute.set(key, entries);
  }
  return keys.map((key) => {
    const separator = key.indexOf('.');
    const scope = key.slice(0, separator);
    const method = key.slice(separator + 1);
    const v17Routes = (v17.get(key) ?? []).map((record) => record.route).sort();
    const v18Routes = (v18.get(key) ?? []).map((record) => record.route).sort();
    let surfaceStatus: SurfaceStatus;
    if (v17Routes.length === 0) surfaceStatus = 'v18-only';
    else if (v18Routes.length === 0) surfaceStatus = 'v17-only';
    else if (v17Routes.length === 1 && v18Routes.length === 1 && v17Routes[0] === v18Routes[0]) {
      surfaceStatus = 'common-identical';
    } else surfaceStatus = 'surface-conflict';

    const operationMatches = [...new Set([...v17Routes, ...v18Routes])]
      .flatMap((route) => {
        const parsed = splitRoute(route);
        return parsed === undefined ? [] : (openApiByRoute.get(routeKey(parsed.verb, parsed.path)) ?? []);
      })
      .filter((operation, index, entries) =>
        entries.findIndex((entry) => entry.operationId === operation.operationId && entry.verb === operation.verb && entry.path === operation.path) === index,
      );
    const operationJoinStatus: OperationJoinStatus =
      operationMatches.length === 0
        ? 'no-openapi-operation'
        : operationMatches.length === 1
          ? 'matched-operation'
          : 'duplicate-openapi-operation';
    return {
      scope,
      method,
      v17Routes,
      v18Routes,
      surfaceStatus,
      operationJoinStatus,
      operationIds: operationMatches.map((operation) => operation.operationId).sort(),
    };
  });
}

export function buildOperationInventory(inputs: InventoryInputs): OperationInventory {
  validatePermissionSources(inputs.permissionSources);
  const extensions = permissionExtensions(inputs.permissionSources);
  const vocabulary = new Set(extensions.vocabulary.map((entry) => entry.permission));
  const allOpenApi = parseOpenApiOperations(inputs.openApiDocument);
  const appEnabled = parseAppEnabledOpenApiOperations(inputs.openApiDocument);
  const seeds = parseAppPermissionSeedAssociations(inputs.appPermissionsDocument);
  const operationRows = appEnabled.map((operation) =>
    classifyOperation(operation, inputs.permissionSources.facts, extensions.headerFacts, seeds, vocabulary),
  );
  const methodJoinRows = buildMethodRows(inputs.runtimeEndpointMethods, inputs.standaloneEndpointMethods, allOpenApi);
  const unsigned: Omit<OperationInventory, 'contentSha256'> = {
    schemaVersion: 1,
    apiVersion: '2022-11-28',
    artifactManifestSha256: inputs.artifactManifest.contentSha256,
    permissionSourcesSha256: inputs.permissionSources.contentSha256,
    strategy: 'generated-candidates-plus-reviewed-bounded-catalog',
    operationUniverse: {
      total: operationRows.length,
      classCounts: countBy(operationRows.map((row) => row.evidenceClass), CLASSES),
      freshnessCounts: countBy(operationRows.map((row) => row.freshness), FRESHNESS),
      credentialApplicabilityCounts: countBy(
        operationRows.map((row) => row.credentialApplicability),
        CREDENTIALS,
      ),
    },
    methodUniverse: {
      total: methodJoinRows.length,
      surfaceCounts: countBy(methodJoinRows.map((row) => row.surfaceStatus), SURFACES),
      operationJoinCounts: countBy(methodJoinRows.map((row) => row.operationJoinStatus), JOINS),
    },
    operationRows,
    methodJoinRows,
  };
  return { ...unsigned, contentSha256: digestJson(unsigned as unknown as JsonValue) };
}

export function evaluateSupportPredicate(inventory: OperationInventory): SupportManifest {
  const selectedMembers: SupportMember[] = [];
  for (const row of inventory.operationRows) {
    if (
      row.evidenceClass !== 'single' ||
      row.expression === null ||
      row.permissionEvidenceSha256 === null ||
      row.freshness !== 'current' ||
      row.credentialApplicability !== 'github-app-reviewed' ||
      row.reasons.length !== 0
    ) {
      continue;
    }
    const aliases = inventory.methodJoinRows
      .filter(
        (method) =>
          method.surfaceStatus === 'common-identical' &&
          method.operationJoinStatus === 'matched-operation' &&
          method.operationIds.length === 1 &&
          method.operationIds[0] === row.operationId,
      )
      .map((method) => `${method.scope}.${method.method}`)
      .sort();
    if (aliases.length === 0) continue;
    selectedMembers.push({
      verb: row.verb,
      path: row.path,
      operationId: row.operationId,
      methodAliases: aliases,
      expressionSha256: expressionDigest(row.expression),
      permissionEvidenceSha256: row.permissionEvidenceSha256,
      permissionSourcesSha256: inventory.permissionSourcesSha256,
      artifactManifestSha256: inventory.artifactManifestSha256,
    });
  }
  selectedMembers.sort((left, right) => compareStrings(left.operationId, right.operationId));
  const requiredOperationIds: ['issues/create', 'issues/list-for-repo'] = [
    'issues/create',
    'issues/list-for-repo',
  ];
  for (const required of requiredOperationIds) {
    if (!selectedMembers.some((member) => member.operationId === required)) {
      throw new Error(`support predicate omitted required canonical operation ${required}`);
    }
  }
  const rule = { version: 1 as const, conditions: [...SUPPORT_CONDITIONS] };
  const withoutContent = {
    schemaVersion: 1 as const,
    strategy: 'generated-candidates-plus-reviewed-bounded-catalog' as const,
    artifactManifestSha256: inventory.artifactManifestSha256,
    permissionSourcesSha256: inventory.permissionSourcesSha256,
    predicate: { rule, ruleSha256: digestJson(rule as unknown as JsonValue) },
    requiredOperationIds,
    selectedMembers,
    selectionSha256: digestJson(selectedMembers as unknown as JsonValue),
  };
  return { ...withoutContent, contentSha256: digestJson(withoutContent as unknown as JsonValue) };
}

function assertStringArray(value: unknown, label: string): asserts value is string[] {
  if (!Array.isArray(value) || !value.every((entry) => typeof entry === 'string')) {
    throw new TypeError(`${label} must be a string array`);
  }
}

function assertCountRecord<T extends string>(
  value: Record<string, unknown>,
  members: readonly T[],
  observed: readonly T[],
  label: string,
): void {
  assertExactKeys(value, members, label);
  for (const member of members) {
    if (!Number.isSafeInteger(value[member]) || (value[member] as number) < 0) {
      throw new TypeError(`${label}.${member} is invalid`);
    }
  }
  const expected = countBy(observed, members);
  if (JSON.stringify(value) !== JSON.stringify(expected)) throw new Error(`${label} does not match rows`);
}

export function validateOperationInventory(value: unknown): asserts value is OperationInventory {
  assertPlainObject(value, 'operation inventory');
  assertExactKeys(
    value,
    [
      'schemaVersion',
      'apiVersion',
      'artifactManifestSha256',
      'permissionSourcesSha256',
      'strategy',
      'operationUniverse',
      'methodUniverse',
      'operationRows',
      'methodJoinRows',
      'contentSha256',
    ],
    'operation inventory',
  );
  if (
    value.schemaVersion !== 1 ||
    value.apiVersion !== '2022-11-28' ||
    value.strategy !== 'generated-candidates-plus-reviewed-bounded-catalog' ||
    !Array.isArray(value.operationRows) ||
    !Array.isArray(value.methodJoinRows)
  ) {
    throw new TypeError('operation inventory structure is invalid');
  }
  assertSha256(value.artifactManifestSha256, 'operation inventory artifact manifest digest');
  assertSha256(value.permissionSourcesSha256, 'operation inventory permission sources digest');
  assertPlainObject(value.operationUniverse, 'operation universe');
  assertExactKeys(
    value.operationUniverse,
    ['total', 'classCounts', 'freshnessCounts', 'credentialApplicabilityCounts'],
    'operation universe',
  );
  assertPlainObject(value.operationUniverse.classCounts, 'operation class counts');
  assertPlainObject(value.operationUniverse.freshnessCounts, 'operation freshness counts');
  assertPlainObject(value.operationUniverse.credentialApplicabilityCounts, 'operation credential counts');
  assertPlainObject(value.methodUniverse, 'method universe');
  assertExactKeys(value.methodUniverse, ['total', 'surfaceCounts', 'operationJoinCounts'], 'method universe');
  assertPlainObject(value.methodUniverse.surfaceCounts, 'surface counts');
  assertPlainObject(value.methodUniverse.operationJoinCounts, 'operation join counts');
  const operationKeys = new Set<string>();
  const observedClasses: EvidenceClass[] = [];
  const observedFreshness: FreshnessState[] = [];
  const observedCredentials: CredentialApplicability[] = [];
  for (const [index, row] of value.operationRows.entries()) {
    assertPlainObject(row, `operation row[${index}]`);
    assertExactKeys(
      row,
      [
        'verb',
        'path',
        'operationId',
        'appEnabled',
        'evidenceClass',
        'freshness',
        'credentialApplicability',
        'expression',
        'observedExpression',
        'permissionEvidenceSha256',
        'rawSeedAssociations',
        'reasons',
      ],
      `operation row[${index}]`,
    );
    if (
      typeof row.verb !== 'string' ||
      typeof row.path !== 'string' ||
      !row.path.startsWith('/') ||
      typeof row.operationId !== 'string' ||
      row.appEnabled !== true ||
      !CLASSES.includes(row.evidenceClass as EvidenceClass) ||
      !FRESHNESS.includes(row.freshness as FreshnessState) ||
      !CREDENTIALS.includes(row.credentialApplicability as CredentialApplicability) ||
      !Array.isArray(row.rawSeedAssociations)
    ) {
      throw new TypeError(`operation row[${index}] is invalid`);
    }
    if (row.expression !== null) validateRequirementExpression(row.expression);
    if (row.observedExpression !== null) validateRequirementExpression(row.observedExpression);
    if (row.permissionEvidenceSha256 !== null) {
      assertSha256(row.permissionEvidenceSha256, `operation row[${index}].permissionEvidenceSha256`);
    }
    assertStringArray(row.reasons, `operation row[${index}].reasons`);
    for (const [seedIndex, seed] of row.rawSeedAssociations.entries()) {
      assertPlainObject(seed, `operation row[${index}].rawSeedAssociations[${seedIndex}]`);
      assertExactKeys(
        seed,
        ['verb', 'path', 'permission', 'level'],
        `operation row[${index}].rawSeedAssociations[${seedIndex}]`,
      );
      if (
        seed.verb !== row.verb ||
        seed.path !== row.path ||
        typeof seed.permission !== 'string' ||
        !['read', 'write'].includes(String(seed.level))
      ) {
        throw new TypeError(`operation row[${index}] seed association is invalid`);
      }
    }
    const key = `${String(row.verb)} ${String(row.path)}`;
    if (operationKeys.has(key)) throw new Error(`duplicate operation row ${key}`);
    operationKeys.add(key);
    observedClasses.push(row.evidenceClass as EvidenceClass);
    observedFreshness.push(row.freshness as FreshnessState);
    observedCredentials.push(row.credentialApplicability as CredentialApplicability);
  }
  const methodKeys = new Set<string>();
  const observedSurfaces: SurfaceStatus[] = [];
  const observedJoins: OperationJoinStatus[] = [];
  for (const [index, row] of value.methodJoinRows.entries()) {
    assertPlainObject(row, `method join row[${index}]`);
    assertExactKeys(
      row,
      ['scope', 'method', 'v17Routes', 'v18Routes', 'surfaceStatus', 'operationJoinStatus', 'operationIds'],
      `method join row[${index}]`,
    );
    if (
      typeof row.scope !== 'string' ||
      typeof row.method !== 'string' ||
      !SURFACES.includes(row.surfaceStatus as SurfaceStatus) ||
      !JOINS.includes(row.operationJoinStatus as OperationJoinStatus)
    ) {
      throw new TypeError(`method join row[${index}] is invalid`);
    }
    assertStringArray(row.v17Routes, `method join row[${index}].v17Routes`);
    assertStringArray(row.v18Routes, `method join row[${index}].v18Routes`);
    assertStringArray(row.operationIds, `method join row[${index}].operationIds`);
    const key = `${String(row.scope)}.${String(row.method)}`;
    if (methodKeys.has(key)) throw new Error(`duplicate method join row ${key}`);
    methodKeys.add(key);
    observedSurfaces.push(row.surfaceStatus as SurfaceStatus);
    observedJoins.push(row.operationJoinStatus as OperationJoinStatus);
  }
  if (value.operationUniverse.total !== value.operationRows.length) throw new Error('operation universe total mismatch');
  assertCountRecord(value.operationUniverse.classCounts, CLASSES, observedClasses, 'operation class counts');
  assertCountRecord(value.operationUniverse.freshnessCounts, FRESHNESS, observedFreshness, 'operation freshness counts');
  assertCountRecord(
    value.operationUniverse.credentialApplicabilityCounts,
    CREDENTIALS,
    observedCredentials,
    'operation credential counts',
  );
  if (value.methodUniverse.total !== value.methodJoinRows.length) throw new Error('method universe total mismatch');
  assertCountRecord(value.methodUniverse.surfaceCounts, SURFACES, observedSurfaces, 'surface counts');
  assertCountRecord(value.methodUniverse.operationJoinCounts, JOINS, observedJoins, 'operation join counts');
  assertSha256(value.contentSha256, 'operation inventory content digest');
  const { contentSha256: _contentSha256, ...unsigned } = value;
  if (value.contentSha256 !== digestJson(unsigned as unknown as JsonValue)) {
    throw new Error('operation inventory content digest mismatch');
  }
}

export function validateSupportManifest(value: unknown): asserts value is SupportManifest {
  assertPlainObject(value, 'support manifest');
  assertExactKeys(
    value,
    [
      'schemaVersion',
      'strategy',
      'artifactManifestSha256',
      'permissionSourcesSha256',
      'predicate',
      'requiredOperationIds',
      'selectedMembers',
      'selectionSha256',
      'contentSha256',
    ],
    'support manifest',
  );
  if (
    value.schemaVersion !== 1 ||
    value.strategy !== 'generated-candidates-plus-reviewed-bounded-catalog' ||
    !Array.isArray(value.requiredOperationIds) ||
    JSON.stringify(value.requiredOperationIds) !== JSON.stringify(['issues/create', 'issues/list-for-repo']) ||
    !Array.isArray(value.selectedMembers)
  ) {
    throw new TypeError('support manifest structure is invalid');
  }
  assertSha256(value.artifactManifestSha256, 'support manifest artifact digest');
  assertSha256(value.permissionSourcesSha256, 'support manifest permission digest');
  assertPlainObject(value.predicate, 'support predicate');
  assertExactKeys(value.predicate, ['rule', 'ruleSha256'], 'support predicate');
  assertPlainObject(value.predicate.rule, 'support predicate rule');
  assertExactKeys(value.predicate.rule, ['version', 'conditions'], 'support predicate rule');
  if (
    value.predicate.rule.version !== 1 ||
    !Array.isArray(value.predicate.rule.conditions) ||
    JSON.stringify(value.predicate.rule.conditions) !== JSON.stringify(SUPPORT_CONDITIONS)
  ) {
    throw new TypeError('support predicate rule mismatch');
  }
  assertSha256(value.predicate.ruleSha256, 'support predicate rule digest');
  if (value.predicate.ruleSha256 !== digestJson(value.predicate.rule as unknown as JsonValue)) {
    throw new Error('support predicate rule digest mismatch');
  }
  const operationIds = new Set<string>();
  for (const member of value.selectedMembers) {
    assertPlainObject(member, 'support member');
    assertExactKeys(
      member,
      [
        'verb',
        'path',
        'operationId',
        'methodAliases',
        'expressionSha256',
        'permissionEvidenceSha256',
        'permissionSourcesSha256',
        'artifactManifestSha256',
      ],
      'support member',
    );
    if (
      typeof member.verb !== 'string' ||
      typeof member.path !== 'string' ||
      !member.path.startsWith('/') ||
      typeof member.operationId !== 'string' ||
      !Array.isArray(member.methodAliases) ||
      member.methodAliases.length === 0 ||
      !member.methodAliases.every((alias) => typeof alias === 'string' && alias.length > 0) ||
      new Set(member.methodAliases).size !== member.methodAliases.length ||
      JSON.stringify(member.methodAliases) !== JSON.stringify([...member.methodAliases].sort()) ||
      member.permissionSourcesSha256 !== value.permissionSourcesSha256 ||
      member.artifactManifestSha256 !== value.artifactManifestSha256
    ) {
      throw new TypeError('support member identity is invalid');
    }
    for (const key of ['expressionSha256', 'permissionEvidenceSha256', 'permissionSourcesSha256', 'artifactManifestSha256'] as const) {
      assertSha256(member[key], `support member ${String(member.operationId)}.${key}`);
    }
    if (operationIds.has(member.operationId)) throw new Error(`duplicate support member ${member.operationId}`);
    operationIds.add(member.operationId);
  }
  for (const required of value.requiredOperationIds) {
    if (!operationIds.has(String(required))) throw new Error(`support manifest omitted ${String(required)}`);
  }
  const sorted = [...value.selectedMembers].sort((left, right) =>
    compareStrings(
      String((left as Record<string, unknown>).operationId),
      String((right as Record<string, unknown>).operationId),
    ),
  );
  if (JSON.stringify(value.selectedMembers) !== JSON.stringify(sorted)) throw new Error('support members are not sorted');
  assertSha256(value.selectionSha256, 'support selection digest');
  if (value.selectionSha256 !== digestJson(value.selectedMembers as unknown as JsonValue)) {
    throw new Error('support selection digest mismatch');
  }
  assertSha256(value.contentSha256, 'support manifest content digest');
  const { contentSha256: _contentSha256, ...unsigned } = value;
  if (value.contentSha256 !== digestJson(unsigned as unknown as JsonValue)) {
    throw new Error('support manifest content digest mismatch');
  }
}
