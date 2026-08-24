import ts from 'typescript';

import {
  assertExactKeys,
  assertPlainObject,
  assertSha256,
  type ArtifactManifest,
  type CanonicalIssuesFixture,
  type CanonicalPermissionChain,
  type JsonValue,
  type OperationResolution,
  type PermissionFact,
  type PermissionSources,
  type ResolvedOperation,
  type UnresolvedOperation,
  type UnresolvedOperationReason,
} from './contracts.js';
import { digestJson, validateArtifactManifest } from './artifact-sources.js';
import { buildPermissionSourceExtensions, validatePermissionSourceExtensions } from './source-evidence.js';

export interface EndpointMethodRecord {
  scope: string;
  method: string;
  route: string;
}

export interface OpenApiOperationRecord {
  verb: string;
  path: string;
  operationId: string;
}

export interface OperationSources {
  standaloneEndpointMethods: readonly EndpointMethodRecord[];
  runtimeEndpointMethods: readonly EndpointMethodRecord[];
  openApiOperations: readonly OpenApiOperationRecord[];
}

const HTTP_VERBS = new Set(['DELETE', 'GET', 'HEAD', 'OPTIONS', 'PATCH', 'POST', 'PUT']);
const MAX_ENDPOINT_SCOPES = 128;
const MAX_ENDPOINT_METHODS = 4096;
const MAX_OPENAPI_PATHS = 4096;
const MAX_OPENAPI_OPERATIONS = 4096;
const GITHUB_APP_ISSUES_PERMISSION_URL =
  'https://docs.github.com/en/rest/authentication/permissions-required-for-github-apps#repository-permissions-for-issues';

function propertyName(node: ts.PropertyName, label: string): string {
  if (ts.isIdentifier(node) || ts.isStringLiteral(node)) return node.text;
  throw new Error(`${label} has a computed or unsupported property name`);
}

function assertStaticLiteral(node: ts.Expression, label: string): void {
  if (
    ts.isStringLiteral(node) ||
    ts.isNumericLiteral(node) ||
    node.kind === ts.SyntaxKind.TrueKeyword ||
    node.kind === ts.SyntaxKind.FalseKeyword ||
    node.kind === ts.SyntaxKind.NullKeyword
  ) {
    return;
  }
  if (ts.isArrayLiteralExpression(node)) {
    for (const [index, element] of node.elements.entries()) {
      if (ts.isSpreadElement(element)) throw new Error(`${label}[${index}] contains a spread`);
      assertStaticLiteral(element, `${label}[${index}]`);
    }
    return;
  }
  if (ts.isObjectLiteralExpression(node)) {
    const keys = new Set<string>();
    for (const property of node.properties) {
      if (!ts.isPropertyAssignment(property)) throw new Error(`${label} contains a non-literal property`);
      const key = propertyName(property.name, label);
      if (keys.has(key)) throw new Error(`${label} contains duplicate property ${key}`);
      keys.add(key);
      assertStaticLiteral(property.initializer, `${label}.${key}`);
    }
    return;
  }
  throw new Error(`${label} contains executable or unsupported syntax`);
}

function isGeneratedAliasStatement(statement: ts.Statement): boolean {
  if (!ts.isVariableStatement(statement) || statement.declarationList.declarations.length !== 1) return false;
  const declaration = statement.declarationList.declarations[0];
  return (
    declaration !== undefined &&
    ts.isIdentifier(declaration.name) &&
    declaration.name.text === 'endpoints_default' &&
    declaration.initializer !== undefined &&
    ts.isIdentifier(declaration.initializer) &&
    declaration.initializer.text === 'Endpoints'
  );
}

function isGeneratedExportStatement(statement: ts.Statement): boolean {
  if (!ts.isExportDeclaration(statement) || statement.moduleSpecifier !== undefined) return false;
  const clause = statement.exportClause;
  if (clause === undefined || !ts.isNamedExports(clause) || clause.elements.length !== 1) return false;
  const element = clause.elements[0];
  return element?.propertyName?.text === 'endpoints_default' && element.name.text === 'default';
}

export function parseEndpointMethodTable(sourceText: string, sourceName = 'endpoints.js'): EndpointMethodRecord[] {
  const source = ts.createSourceFile(sourceName, sourceText, ts.ScriptTarget.ES2024, false, ts.ScriptKind.JS);
  const diagnostics = (source as ts.SourceFile & { parseDiagnostics?: readonly ts.Diagnostic[] }).parseDiagnostics ?? [];
  if (diagnostics.length > 0) throw new Error(`${sourceName} contains JavaScript syntax errors`);

  let endpointsDeclaration: ts.VariableDeclaration | undefined;
  let endpointsStatement: ts.Statement | undefined;
  for (const statement of source.statements) {
    if (ts.isVariableStatement(statement)) {
      for (const declaration of statement.declarationList.declarations) {
        if (ts.isIdentifier(declaration.name) && declaration.name.text === 'Endpoints') {
          if (endpointsDeclaration !== undefined) throw new Error(`${sourceName} contains duplicate Endpoints declarations`);
          endpointsDeclaration = declaration;
          endpointsStatement = statement;
        }
      }
    }
  }
  if (endpointsDeclaration?.initializer === undefined || !ts.isObjectLiteralExpression(endpointsDeclaration.initializer)) {
    throw new Error(`${sourceName} lacks the generated Endpoints object`);
  }
  for (const statement of source.statements) {
    if (statement === endpointsStatement || isGeneratedAliasStatement(statement) || isGeneratedExportStatement(statement)) continue;
    throw new Error(`${sourceName} contains an unexpected executable statement`);
  }

  const records: EndpointMethodRecord[] = [];
  const scopeCount = endpointsDeclaration.initializer.properties.length;
  if (scopeCount === 0 || scopeCount > MAX_ENDPOINT_SCOPES) throw new Error(`${sourceName} scope count is out of bounds`);
  for (const scopeProperty of endpointsDeclaration.initializer.properties) {
    if (!ts.isPropertyAssignment(scopeProperty) || !ts.isObjectLiteralExpression(scopeProperty.initializer)) {
      throw new Error(`${sourceName} contains a non-literal scope`);
    }
    const scope = propertyName(scopeProperty.name, sourceName);
    for (const methodProperty of scopeProperty.initializer.properties) {
      if (!ts.isPropertyAssignment(methodProperty) || !ts.isArrayLiteralExpression(methodProperty.initializer)) {
        throw new Error(`${sourceName}.${scope} contains a non-literal method`);
      }
      const method = propertyName(methodProperty.name, `${sourceName}.${scope}`);
      if (methodProperty.initializer.elements.length === 0) throw new Error(`${sourceName}.${scope}.${method} has no route`);
      const route = methodProperty.initializer.elements[0];
      if (route === undefined || !ts.isStringLiteral(route)) throw new Error(`${sourceName}.${scope}.${method} route is not a string`);
      for (const [index, entry] of methodProperty.initializer.elements.entries()) {
        if (ts.isSpreadElement(entry)) throw new Error(`${sourceName}.${scope}.${method}[${index}] contains a spread`);
        assertStaticLiteral(entry, `${sourceName}.${scope}.${method}[${index}]`);
      }
      records.push({ scope, method, route: route.text });
      if (records.length > MAX_ENDPOINT_METHODS) throw new Error(`${sourceName} method count is out of bounds`);
    }
  }
  return records;
}

export function parseOpenApiOperations(value: unknown): OpenApiOperationRecord[] {
  assertPlainObject(value, 'OpenAPI document');
  assertPlainObject(value.paths, 'OpenAPI paths');
  const paths = Object.entries(value.paths);
  if (paths.length === 0 || paths.length > MAX_OPENAPI_PATHS) throw new Error('OpenAPI path count is out of bounds');
  const operations: OpenApiOperationRecord[] = [];
  for (const [path, pathItem] of paths) {
    if (!path.startsWith('/')) throw new Error(`OpenAPI path is invalid: ${path}`);
    assertPlainObject(pathItem, `OpenAPI path ${path}`);
    for (const [key, operation] of Object.entries(pathItem)) {
      const verb = key.toUpperCase();
      if (!HTTP_VERBS.has(verb)) continue;
      assertPlainObject(operation, `OpenAPI operation ${verb} ${path}`);
      if (typeof operation.operationId !== 'string' || operation.operationId.length === 0) {
        throw new Error(`OpenAPI operation ${verb} ${path} lacks operationId`);
      }
      operations.push({ verb, path, operationId: operation.operationId });
      if (operations.length > MAX_OPENAPI_OPERATIONS) throw new Error('OpenAPI operation count is out of bounds');
    }
  }
  return operations;
}

function unresolved(scope: string, method: string, reason: UnresolvedOperationReason): UnresolvedOperation {
  return { status: 'unresolved', scope, method, reason };
}

function exactMethod(records: readonly EndpointMethodRecord[], scope: string, method: string): EndpointMethodRecord[] {
  return records.filter((record) => record.scope === scope && record.method === method);
}

function parseRoute(route: string): { verb: string; path: string } | undefined {
  const match = /^([A-Z]+) (\/[!-~]+)$/u.exec(route);
  if (match?.[1] === undefined || match[2] === undefined || !HTTP_VERBS.has(match[1])) return undefined;
  return { verb: match[1], path: match[2] };
}

export function resolveOperation(
  scope: string,
  method: string,
  sources: OperationSources,
): OperationResolution {
  const standalone = exactMethod(sources.standaloneEndpointMethods, scope, method);
  const runtime = exactMethod(sources.runtimeEndpointMethods, scope, method);
  if (standalone.length === 0) return unresolved(scope, method, 'endpoint-method-missing-standalone');
  if (runtime.length === 0) return unresolved(scope, method, 'endpoint-method-missing-runtime');
  if (standalone.length !== 1 || runtime.length !== 1) return unresolved(scope, method, 'endpoint-method-duplicate');
  const standaloneRoute = standalone[0]?.route;
  const runtimeRoute = runtime[0]?.route;
  if (standaloneRoute !== runtimeRoute) return unresolved(scope, method, 'runtime-surface-incompatibility');
  if (standaloneRoute === undefined) return unresolved(scope, method, 'endpoint-route-invalid');
  const route = parseRoute(standaloneRoute);
  if (route === undefined) return unresolved(scope, method, 'endpoint-route-invalid');
  const openApi = sources.openApiOperations.filter(
    (operation) => operation.verb === route.verb && operation.path === route.path,
  );
  if (openApi.length === 0) return unresolved(scope, method, 'openapi-operation-missing');
  if (openApi.length !== 1) return unresolved(scope, method, 'openapi-operation-duplicate');
  const operationId = openApi[0]?.operationId;
  if (operationId === undefined) return unresolved(scope, method, 'openapi-operation-missing');
  return { status: 'resolved', scope, method, route, operationId };
}

function permissionFactDigest(fact: Omit<PermissionFact, 'evidenceSha256'>): string {
  return digestJson(fact as unknown as JsonValue);
}

export function buildPermissionSources(): PermissionSources {
  const factsWithoutDigest: Omit<PermissionFact, 'evidenceSha256'>[] = [
    {
      operationId: 'issues/list-for-repo',
      verb: 'GET',
      path: '/repos/{owner}/{repo}/issues',
      requirement: { type: 'permission', permission: 'issues', level: 'read' },
      sourceUrl: GITHUB_APP_ISSUES_PERMISSION_URL,
    },
    {
      operationId: 'issues/create',
      verb: 'POST',
      path: '/repos/{owner}/{repo}/issues',
      requirement: { type: 'permission', permission: 'issues', level: 'write' },
      sourceUrl: GITHUB_APP_ISSUES_PERMISSION_URL,
    },
  ];
  const facts = factsWithoutDigest.map((fact) => ({ ...fact, evidenceSha256: permissionFactDigest(fact) }));
  const unsigned = {
    schemaVersion: 1,
    documentation: {
      sourceUrl: GITHUB_APP_ISSUES_PERMISSION_URL,
      versioning: 'unversioned-live',
      retrievalStatus: 'captured',
      reviewStatus: 'reviewed',
      reviewedOn: '2026-08-24',
    },
    facts,
    ...buildPermissionSourceExtensions(),
  };
  return { ...unsigned, contentSha256: digestJson(unsigned as unknown as JsonValue) } as PermissionSources;
}

export function validatePermissionSources(value: unknown): asserts value is PermissionSources {
  assertPlainObject(value, 'permission sources');
  assertExactKeys(
    value,
    ['schemaVersion', 'documentation', 'facts', 'vocabulary', 'headerFacts', 'refusedProbes', 'contentSha256'],
    'permission sources',
  );
  if (value.schemaVersion !== 1) throw new TypeError('permission source schema version mismatch');
  assertPlainObject(value.documentation, 'permission sources.documentation');
  assertExactKeys(
    value.documentation,
    ['sourceUrl', 'versioning', 'retrievalStatus', 'reviewStatus', 'reviewedOn'],
    'permission sources.documentation',
  );
  if (
    value.documentation.sourceUrl !== GITHUB_APP_ISSUES_PERMISSION_URL ||
    value.documentation.versioning !== 'unversioned-live' ||
    value.documentation.retrievalStatus !== 'captured' ||
    value.documentation.reviewStatus !== 'reviewed' ||
    typeof value.documentation.reviewedOn !== 'string' ||
    !/^\d{4}-\d{2}-\d{2}$/u.test(value.documentation.reviewedOn)
  ) {
    throw new TypeError('permission source documentation metadata is invalid');
  }
  if (!Array.isArray(value.facts) || value.facts.length !== 2) throw new TypeError('permission sources must contain two facts');
  for (const [index, fact] of value.facts.entries()) {
    assertPlainObject(fact, `permission fact[${index}]`);
    assertExactKeys(fact, ['operationId', 'verb', 'path', 'requirement', 'sourceUrl', 'evidenceSha256'], `permission fact[${index}]`);
    for (const key of ['operationId', 'verb', 'path', 'sourceUrl'] as const) {
      if (typeof fact[key] !== 'string' || fact[key].length === 0) throw new TypeError(`permission fact[${index}].${key} is invalid`);
    }
    assertPlainObject(fact.requirement, `permission fact[${index}].requirement`);
    assertExactKeys(fact.requirement, ['type', 'permission', 'level'], `permission fact[${index}].requirement`);
    if (
      fact.requirement.type !== 'permission' ||
      typeof fact.requirement.permission !== 'string' ||
      !['read', 'write'].includes(String(fact.requirement.level))
    ) {
      throw new TypeError(`permission fact[${index}].requirement is invalid`);
    }
    assertSha256(fact.evidenceSha256, `permission fact[${index}].evidenceSha256`);
    const { evidenceSha256: _evidenceSha256, ...unsigned } = fact;
    if (fact.evidenceSha256 !== permissionFactDigest(unsigned as Omit<PermissionFact, 'evidenceSha256'>)) {
      throw new Error(`permission fact[${index}] digest mismatch`);
    }
  }
  validatePermissionSourceExtensions({
    vocabulary: value.vocabulary,
    headerFacts: value.headerFacts,
    refusedProbes: value.refusedProbes,
  });
  assertSha256(value.contentSha256, 'permission sources.contentSha256');
  const { contentSha256: _contentSha256, ...unsigned } = value;
  if (value.contentSha256 !== digestJson(unsigned as unknown as JsonValue)) {
    throw new Error('permission sources content digest mismatch');
  }
}

export function resolveCanonicalPermission(
  scope: string,
  method: string,
  sources: OperationSources,
  artifactManifest: unknown,
  permissionSources: unknown,
  expectedArtifactManifestSha256: string,
  expectedPermissionSourcesSha256: string,
): CanonicalPermissionChain | UnresolvedOperation {
  let manifest: ArtifactManifest;
  try {
    validateArtifactManifest(artifactManifest);
    manifest = artifactManifest;
  } catch {
    return unresolved(scope, method, 'artifact-manifest-digest-mismatch');
  }
  if (manifest.contentSha256 !== expectedArtifactManifestSha256) {
    return unresolved(scope, method, 'artifact-manifest-digest-mismatch');
  }
  let permissions: PermissionSources;
  try {
    validatePermissionSources(permissionSources);
    permissions = permissionSources;
  } catch {
    return unresolved(scope, method, 'permission-source-digest-mismatch');
  }
  if (permissions.contentSha256 !== expectedPermissionSourcesSha256) {
    return unresolved(scope, method, 'permission-source-digest-mismatch');
  }
  const operation = resolveOperation(scope, method, sources);
  if (operation.status === 'unresolved') return operation;
  const facts = permissions.facts.filter((fact) => fact.operationId === operation.operationId);
  if (facts.length === 0) return unresolved(scope, method, 'permission-evidence-missing');
  if (facts.length !== 1) return unresolved(scope, method, 'permission-evidence-mismatch');
  const fact = facts[0];
  if (
    fact === undefined ||
    fact.verb !== operation.route.verb ||
    fact.path !== operation.route.path ||
    fact.sourceUrl !== permissions.documentation.sourceUrl
  ) {
    return unresolved(scope, method, 'permission-evidence-mismatch');
  }
  const expectedCanonicalRequirement =
    operation.operationId === 'issues/list-for-repo'
      ? { permission: 'issues', level: 'read' as const }
      : operation.operationId === 'issues/create'
        ? { permission: 'issues', level: 'write' as const }
        : undefined;
  if (
    expectedCanonicalRequirement !== undefined &&
    (fact.requirement.permission !== expectedCanonicalRequirement.permission ||
      fact.requirement.level !== expectedCanonicalRequirement.level)
  ) {
    return unresolved(scope, method, 'permission-evidence-mismatch');
  }
  return {
    ...operation,
    requirement: fact.requirement,
    evidence: {
      artifactManifestSha256: manifest.contentSha256,
      permissionSourcesSha256: permissions.contentSha256,
      permissionFactSha256: fact.evidenceSha256,
    },
  };
}

export function buildCanonicalIssuesFixture(
  sources: OperationSources,
  artifactManifest: ArtifactManifest,
  permissionSources: PermissionSources,
): CanonicalIssuesFixture {
  const pairs = [
    ['issues', 'listForRepo'],
    ['issues', 'create'],
  ] as const;
  const chains = pairs.map(([scope, method]) => {
    const chain = resolveCanonicalPermission(
      scope,
      method,
      sources,
      artifactManifest,
      permissionSources,
      artifactManifest.contentSha256,
      permissionSources.contentSha256,
    );
    if (chain.status !== 'resolved' || !('requirement' in chain)) {
      throw new Error(`canonical operation ${scope}.${method} is unresolved: ${chain.reason}`);
    }
    return chain;
  });
  const unsigned: Omit<CanonicalIssuesFixture, 'contentSha256'> = {
    schemaVersion: 1,
    artifactManifestSha256: artifactManifest.contentSha256,
    permissionSourcesSha256: permissionSources.contentSha256,
    chains,
  };
  return { ...unsigned, contentSha256: digestJson(unsigned as unknown as JsonValue) };
}

export function assertResolved(value: OperationResolution): asserts value is ResolvedOperation {
  if (value.status !== 'resolved') throw new Error(`operation is unresolved: ${value.reason}`);
}
