/**
 * The independently usable BoundaryCI source analyzer.
 *
 * This module walks a trusted analysis root, reads bounded regular-file bytes, and parses
 * each included source with `ts.createSourceFile`. It never installs, resolves, imports,
 * transpiles, builds, or executes anything from the analyzed repository, and it never reads
 * the target's package manifest, lockfile, `node_modules`, or build configuration. The only
 * interaction with target content is byte reading followed by syntactic parsing.
 *
 * The retained slice of the Phase 3 grammar is deliberately narrow:
 *
 *   import { Octokit } from 'octokit';   // exact named ESM import, exact specifier
 *   const client = new Octokit();        // direct `new` on an immutable binding
 *   client.rest.issues.create({ ... });  // exact pinned `scope.method` member
 *
 * Immutable `const` aliases of the constructor and of the client are followed. Everything
 * else that *looks* like one of those calls is censused and recorded as an explicit
 * incomplete candidate: recognized-looking syntax alone never proves an operation, and an
 * unproved relevant candidate never disappears into a clean result.
 *
 * Operation recognition and permission inference are separate steps. Every proven
 * observation is emitted before the Phase 2 catalog is consulted, so an operation that the
 * bounded two-row catalog cannot authorize stays fully visible and merely makes the
 * permission side of the result incomplete.
 */

import { createHash } from 'node:crypto';
import { readFile, readdir, realpath, stat } from 'node:fs/promises';
import { join } from 'node:path';

import ts from 'typescript';

import { BOUNDARYCI_PERMISSION_CATALOG, BOUNDARYCI_PERMISSION_CATALOG_IDENTITY } from '../permission-model/bounded-catalog.js';
import { aggregatePermissionFindings, resolveRequirementFinding } from '../permission-model/model.js';
import type { PermissionBoundary, RequirementFinding, SourceEvidence, SourceSpan } from '../permission-model/model.js';

import {
  ANALYSIS_DISCOVERY_PROFILE_ID,
  ANALYSIS_LIMIT_PROFILE_ID,
  ANALYSIS_SCHEMA_ID,
  ANALYSIS_SCHEMA_VERSION,
  ANALYSIS_SPAN_CONVENTION_ID,
  ANALYZER_SOURCE_EXTENSIONS,
  validateAnalysisRequest,
  validateAnalysisResult,
} from './contract.js';
import type {
  AnalysisBoundary,
  AnalysisFailureReason,
  AnalysisRequest,
  AnalysisResult,
  AnalyzerCause,
  AnalyzerCauseCode,
  AnalyzerCauseScope,
  AnalyzerIdentity,
  CandidateClassification,
  CandidateKind,
  CandidateRecord,
  CandidateReason,
  OperationObservation,
  PermissionResolutionRecord,
  ProfileMemberReference,
  ReceiverProvenance,
  SourceRecord,
} from './contract.js';
import { ANALYZER_ENDPOINT_PROFILE, ANALYZER_PROFILE_IDENTITY } from './profile.js';
import type { EndpointMemberRecord } from './profile.js';

/** The exact package specifier that may export an authorized Octokit constructor. */
const AUTHORIZED_PACKAGE_SPECIFIER = 'octokit';

/** The exact named export that may become an authorized Octokit constructor. */
const AUTHORIZED_EXPORT_NAME = 'Octokit';

/** The single anchor class censused by this slice. */
const CANDIDATE_ANCHOR = 'pinned-endpoint-member-spelling';

/** Bound on alias-chain fixpoint iterations, so hostile source cannot spin the resolver. */
const MAX_ALIAS_PASSES = 32;

const MEMBER_INDEX: ReadonlyMap<string, EndpointMemberRecord> = new Map(
  ANALYZER_ENDPOINT_PROFILE.members.map((member) => [`${member.scope}.${member.method}`, member]),
);

const ANALYZER_IDENTITY: Readonly<AnalyzerIdentity> = Object.freeze({
  schemaId: ANALYSIS_SCHEMA_ID,
  schemaVersion: ANALYSIS_SCHEMA_VERSION,
  spanConventionId: ANALYSIS_SPAN_CONVENTION_ID,
  analyzerProfile: ANALYZER_PROFILE_IDENTITY,
  discoveryProfileId: ANALYSIS_DISCOVERY_PROFILE_ID,
  limitProfileId: ANALYSIS_LIMIT_PROFILE_ID,
  permissionCatalogScopeSha256: BOUNDARYCI_PERMISSION_CATALOG_IDENTITY.authorizedScopeSha256,
});

interface PendingCause {
  code: AnalyzerCauseCode;
  scope: AnalyzerCauseScope;
  path: string | null;
  span: SourceSpan | null;
  detail: string;
}

interface PendingObservation {
  callForm: CandidateKind;
  spelling: string;
  optional: boolean;
  member: ProfileMemberReference;
  operation: { method: string; normalizedRoute: string; operationId: string };
  receiver: ReceiverProvenance;
  source: SourceEvidence;
}

interface PendingCandidate {
  kind: CandidateKind;
  spelling: string;
  path: string;
  span: SourceSpan;
  classification: CandidateClassification;
  reason: CandidateReason;
  causes: PendingCause[];
  observation: PendingObservation | null;
}

function compareBytes(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function ordinalId(prefix: string, index: number): string {
  return `${prefix}-${String(index + 1).padStart(4, '0')}`;
}

function causeKey(cause: PendingCause): string {
  return JSON.stringify([cause.code, cause.path ?? '', cause.span, cause.scope, cause.detail]);
}

function causeOrder(cause: PendingCause): string {
  const span = cause.span;
  const coordinates = span === null ? [0, 0, 0, 0] : [span.start.line, span.start.column, span.end.line, span.end.column];
  return JSON.stringify([cause.path ?? '', ...coordinates.map((value) => String(value).padStart(9, '0')), cause.code, cause.detail]);
}

function candidateOrder(candidate: PendingCandidate): string {
  return JSON.stringify([
    candidate.path,
    String(candidate.span.start.line).padStart(9, '0'),
    String(candidate.span.start.column).padStart(9, '0'),
    String(candidate.span.end.line).padStart(9, '0'),
    String(candidate.span.end.column).padStart(9, '0'),
    candidate.kind,
    candidate.spelling,
  ]);
}

function failed(reason: AnalysisFailureReason, code: AnalyzerCauseCode, detail: string): AnalysisResult {
  return {
    status: 'failed',
    identity: ANALYZER_IDENTITY,
    reason,
    causes: [{ id: ordinalId('cause', 0), code, scope: 'repository', path: null, span: null, detail }],
  };
}

function requestFailureDetail(error: unknown): string {
  const message = error instanceof TypeError ? error.message : 'the analysis request is not a valid object';
  return message.length > 200 ? `${message.slice(0, 200)}…` : message;
}

/* ------------------------------------------------------------------ *
 * Limited glob grammar (see ANALYSIS_DISCOVERY_PROFILE_ID).
 * ------------------------------------------------------------------ */

const SEGMENT_CACHE = new Map<string, RegExp>();

function segmentMatcher(segment: string): RegExp {
  const cached = SEGMENT_CACHE.get(segment);
  if (cached !== undefined) return cached;
  let body = '';
  for (const character of segment) {
    if (character === '*') body += '[^/]*';
    else if (character === '?') body += '[^/]';
    else body += character.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
  }
  const matcher = new RegExp(`^${body}$`, 'u');
  SEGMENT_CACHE.set(segment, matcher);
  return matcher;
}

function matchSegments(patternSegments: readonly string[], pathSegments: readonly string[], p: number, s: number): boolean {
  if (p === patternSegments.length) return s === pathSegments.length;
  const segment = patternSegments[p];
  if (segment === '**') {
    for (let next = s; next <= pathSegments.length; next += 1) {
      if (matchSegments(patternSegments, pathSegments, p + 1, next)) return true;
    }
    return false;
  }
  if (s >= pathSegments.length) return false;
  const candidate = pathSegments[s];
  if (segment === undefined || candidate === undefined) return false;
  if (!segmentMatcher(segment).test(candidate)) return false;
  return matchSegments(patternSegments, pathSegments, p + 1, s + 1);
}

function matchesPattern(path: string, pattern: string): boolean {
  return matchSegments(pattern.split('/'), path.split('/'), 0, 0);
}

function matchesAny(path: string, patterns: readonly string[]): boolean {
  return patterns.some((pattern) => matchesPattern(path, pattern));
}

function hasSourceExtension(path: string): boolean {
  if (path.endsWith('.d.ts') || path.endsWith('.d.mts')) return false;
  return ANALYZER_SOURCE_EXTENSIONS.some((extension) => path.endsWith(extension));
}

/* ------------------------------------------------------------------ *
 * Bounded local discovery.
 * ------------------------------------------------------------------ */

interface Discovery {
  files: string[];
  causes: PendingCause[];
}

/**
 * Walks the canonicalized root, reading regular files only.
 *
 * Symbolic links are never followed and never read. A link or other non-regular entry that
 * could have contributed source becomes a scoped discovery cause instead of silent absence;
 * an explicitly excluded entry is irrelevant and does not affect completeness.
 */
async function discover(rootPath: string, include: readonly string[], exclude: readonly string[]): Promise<Discovery> {
  const files: string[] = [];
  const causes: PendingCause[] = [];

  const isExcluded = (path: string): boolean => matchesAny(path, exclude);
  const prunesDirectory = (path: string): boolean =>
    exclude.some((pattern) => pattern === path || pattern === `${path}/**` || matchesPattern(path, pattern));
  const isRelevantFile = (path: string): boolean =>
    hasSourceExtension(path) && matchesAny(path, include) && !isExcluded(path);

  const walk = async (absoluteDirectory: string, relativeDirectory: string): Promise<void> => {
    const entries = await readdir(absoluteDirectory, { withFileTypes: true });
    entries.sort((left, right) => compareBytes(left.name, right.name));
    for (const entry of entries) {
      const relative = relativeDirectory === '' ? entry.name : `${relativeDirectory}/${entry.name}`;
      if (entry.isSymbolicLink()) {
        if (prunesDirectory(relative)) continue;
        if (isRelevantFile(relative) || !hasSourceExtension(relative)) {
          causes.push({
            code: 'discovery-symlink-entry',
            scope: 'source',
            path: relative,
            span: null,
            detail: 'a symbolic link was not followed and not read',
          });
        }
        continue;
      }
      if (entry.isDirectory()) {
        if (prunesDirectory(relative)) continue;
        await walk(join(absoluteDirectory, entry.name), relative);
        continue;
      }
      if (!entry.isFile()) {
        if (isRelevantFile(relative)) {
          causes.push({
            code: 'discovery-non-regular-entry',
            scope: 'source',
            path: relative,
            span: null,
            detail: 'a non-regular filesystem entry was not read',
          });
        }
        continue;
      }
      if (isRelevantFile(relative)) files.push(relative);
    }
  };

  await walk(rootPath, '');
  files.sort(compareBytes);
  return { files, causes };
}

/* ------------------------------------------------------------------ *
 * Parsing and provenance.
 * ------------------------------------------------------------------ */

function scriptKindFor(path: string): ts.ScriptKind {
  if (path.endsWith('.tsx')) return ts.ScriptKind.TSX;
  if (path.endsWith('.jsx')) return ts.ScriptKind.JSX;
  if (path.endsWith('.ts') || path.endsWith('.mts')) return ts.ScriptKind.TS;
  return ts.ScriptKind.JS;
}

function spanOf(sourceFile: ts.SourceFile, node: ts.Node): SourceSpan {
  const start = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
  const end = sourceFile.getLineAndCharacterOfPosition(node.getEnd());
  return {
    start: { line: start.line + 1, column: start.character + 1 },
    end: { line: end.line + 1, column: end.character + 1 },
  };
}

function forEachNode(node: ts.Node, visit: (child: ts.Node) => void): void {
  visit(node);
  ts.forEachChild(node, (child) => {
    forEachNode(child, visit);
  });
}

interface ConstructorBinding {
  packageSpecifier: string;
  exportName: string;
  constructorBinding: string;
  constructorAliasChain: string[];
}

interface FileProvenance {
  constructors: Map<string, ConstructorBinding>;
  clients: Map<string, ReceiverProvenance>;
}

interface ConstDeclaration {
  name: string;
  aliasOf: string | null;
  constructedWith: string | null;
}

/**
 * Establishes the authorized receiver chain for one parsed file.
 *
 * A name is usable only when it is declared exactly once in the file and never assigned to.
 * That is deliberately coarse: shadowing or reassignment anywhere in the file withdraws the
 * binding rather than risking a receiver proof the analyzer cannot actually justify.
 */
function resolveProvenance(sourceFile: ts.SourceFile): FileProvenance {
  const declarationCounts = new Map<string, number>();
  const mutated = new Set<string>();
  const constDeclarations: ConstDeclaration[] = [];

  const countDeclaration = (name: string): void => {
    declarationCounts.set(name, (declarationCounts.get(name) ?? 0) + 1);
  };

  forEachNode(sourceFile, (node) => {
    if ((ts.isVariableDeclaration(node) || ts.isBindingElement(node) || ts.isParameter(node)) && ts.isIdentifier(node.name)) {
      countDeclaration(node.name.text);
    } else if ((ts.isFunctionDeclaration(node) || ts.isClassDeclaration(node)) && node.name !== undefined) {
      countDeclaration(node.name.text);
    } else if (ts.isImportSpecifier(node) || ts.isNamespaceImport(node)) {
      countDeclaration(node.name.text);
    } else if (ts.isImportClause(node) && node.name !== undefined) {
      countDeclaration(node.name.text);
    } else if (ts.isBinaryExpression(node) && ts.isIdentifier(node.left)) {
      const operator = node.operatorToken.kind;
      if (operator >= ts.SyntaxKind.FirstAssignment && operator <= ts.SyntaxKind.LastAssignment) {
        mutated.add(node.left.text);
      }
    } else if ((ts.isPrefixUnaryExpression(node) || ts.isPostfixUnaryExpression(node)) && ts.isIdentifier(node.operand)) {
      if (node.operator === ts.SyntaxKind.PlusPlusToken || node.operator === ts.SyntaxKind.MinusMinusToken) {
        mutated.add(node.operand.text);
      }
    }

    if (ts.isVariableDeclarationList(node) && (node.flags & ts.NodeFlags.Const) !== 0) {
      for (const declaration of node.declarations) {
        if (!ts.isIdentifier(declaration.name)) continue;
        const initializer = declaration.initializer;
        if (initializer === undefined) continue;
        if (ts.isIdentifier(initializer)) {
          constDeclarations.push({ name: declaration.name.text, aliasOf: initializer.text, constructedWith: null });
        } else if (ts.isNewExpression(initializer) && ts.isIdentifier(initializer.expression)) {
          constDeclarations.push({
            name: declaration.name.text,
            aliasOf: null,
            constructedWith: initializer.expression.text,
          });
        }
      }
    }
  });

  const usable = (name: string): boolean => declarationCounts.get(name) === 1 && !mutated.has(name);

  const constructors = new Map<string, ConstructorBinding>();
  for (const statement of sourceFile.statements) {
    if (!ts.isImportDeclaration(statement)) continue;
    const specifier = statement.moduleSpecifier;
    if (!ts.isStringLiteral(specifier) || specifier.text !== AUTHORIZED_PACKAGE_SPECIFIER) continue;
    const clause = statement.importClause;
    if (clause === undefined || clause.isTypeOnly) continue;
    const bindings = clause.namedBindings;
    if (bindings === undefined || !ts.isNamedImports(bindings)) continue;
    for (const element of bindings.elements) {
      if (element.isTypeOnly) continue;
      const imported = element.propertyName?.text ?? element.name.text;
      if (imported !== AUTHORIZED_EXPORT_NAME) continue;
      const local = element.name.text;
      if (!usable(local)) continue;
      constructors.set(local, {
        packageSpecifier: AUTHORIZED_PACKAGE_SPECIFIER,
        exportName: AUTHORIZED_EXPORT_NAME,
        constructorBinding: local,
        constructorAliasChain: [local],
      });
    }
  }

  for (let pass = 0; pass < MAX_ALIAS_PASSES; pass += 1) {
    let changed = false;
    for (const declaration of constDeclarations) {
      if (declaration.aliasOf === null) continue;
      if (constructors.has(declaration.name) || !usable(declaration.name)) continue;
      const source = constructors.get(declaration.aliasOf);
      if (source === undefined) continue;
      constructors.set(declaration.name, {
        ...source,
        constructorAliasChain: [...source.constructorAliasChain, declaration.name],
      });
      changed = true;
    }
    if (!changed) break;
  }

  const clients = new Map<string, ReceiverProvenance>();
  for (const declaration of constDeclarations) {
    if (declaration.constructedWith === null || !usable(declaration.name)) continue;
    const constructor = constructors.get(declaration.constructedWith);
    if (constructor === undefined) continue;
    clients.set(declaration.name, {
      origin: 'octokit-package-named-import',
      packageSpecifier: constructor.packageSpecifier,
      exportName: constructor.exportName,
      constructorBinding: constructor.constructorBinding,
      constructorAliasChain: [...constructor.constructorAliasChain],
      construction: 'direct-new',
      clientBinding: declaration.name,
      clientAliasChain: [declaration.name],
    });
  }

  for (let pass = 0; pass < MAX_ALIAS_PASSES; pass += 1) {
    let changed = false;
    for (const declaration of constDeclarations) {
      if (declaration.aliasOf === null) continue;
      if (clients.has(declaration.name) || !usable(declaration.name)) continue;
      const source = clients.get(declaration.aliasOf);
      if (source === undefined) continue;
      clients.set(declaration.name, {
        ...source,
        clientAliasChain: [...source.clientAliasChain, declaration.name],
      });
      changed = true;
    }
    if (!changed) break;
  }

  return { constructors, clients };
}

/* ------------------------------------------------------------------ *
 * Candidate census.
 * ------------------------------------------------------------------ */

function receiverSpelling(expression: ts.Expression): string {
  return ts.isIdentifier(expression) ? expression.text : '<expression>';
}

function literalTextOf(node: ts.Node): string | null {
  return ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node) ? node.text : null;
}

function memberFor(scope: string, method: string): EndpointMemberRecord | undefined {
  return MEMBER_INDEX.get(`${scope}.${method}`);
}

function incompleteCandidate(
  kind: CandidateKind,
  spelling: string,
  path: string,
  span: SourceSpan,
  reason: CandidateReason,
  code: AnalyzerCauseCode,
  detail: string,
): PendingCandidate {
  return {
    kind,
    spelling,
    path,
    span,
    classification: 'incomplete',
    reason,
    causes: [{ code, scope: 'candidate', path, span, detail }],
    observation: null,
  };
}

/**
 * Censuses every anchored endpoint-member call in one parsed file.
 *
 * The census is anchored on exact pinned member spellings, never on bare occurrences of
 * names such as `rest`, `octokit`, or `create`. Each anchored call receives exactly one
 * terminal classification here.
 */
function censusFile(sourceFile: ts.SourceFile, path: string, provenance: FileProvenance): PendingCandidate[] {
  const candidates: PendingCandidate[] = [];

  forEachNode(sourceFile, (node) => {
    if (!ts.isCallExpression(node)) return;
    const callee = node.expression;

    if (ts.isPropertyAccessExpression(callee) && ts.isIdentifier(callee.name)) {
      const scopeAccess = callee.expression;
      if (ts.isPropertyAccessExpression(scopeAccess) && ts.isIdentifier(scopeAccess.name)) {
        const restAccess = scopeAccess.expression;
        if (
          ts.isPropertyAccessExpression(restAccess) &&
          ts.isIdentifier(restAccess.name) &&
          restAccess.name.text === 'rest'
        ) {
          const member = memberFor(scopeAccess.name.text, callee.name.text);
          if (member !== undefined) {
            const receiver = restAccess.expression;
            const spelling = `${receiverSpelling(receiver)}.rest.${member.scope}.${member.method}`;
            const span = spanOf(sourceFile, node);
            const optional =
              restAccess.questionDotToken !== undefined ||
              scopeAccess.questionDotToken !== undefined ||
              callee.questionDotToken !== undefined ||
              node.questionDotToken !== undefined;
            if (optional) {
              candidates.push(
                incompleteCandidate(
                  'direct-rest-member-call',
                  spelling,
                  path,
                  span,
                  'unsupported-optional-chain',
                  'unsupported-optional-chain',
                  'optional member access or invocation is outside the supported call grammar',
                ),
              );
              return;
            }
            const client = ts.isIdentifier(receiver) ? provenance.clients.get(receiver.text) : undefined;
            if (client === undefined) {
              candidates.push(
                incompleteCandidate(
                  'direct-rest-member-call',
                  spelling,
                  path,
                  span,
                  'unproven-receiver-provenance',
                  'unproven-receiver-provenance',
                  'the receiver was not proven to originate from an authorized Octokit constructor',
                ),
              );
              return;
            }
            candidates.push({
              kind: 'direct-rest-member-call',
              spelling,
              path,
              span,
              classification: 'proven-operation',
              reason: 'proven-direct-rest-member-call',
              causes: [],
              observation: {
                callForm: 'direct-rest-member-call',
                spelling,
                optional: false,
                member: {
                  profileId: ANALYZER_ENDPOINT_PROFILE.identity.profileId,
                  memberId: `${member.scope}.${member.method}`,
                  scope: member.scope,
                  method: member.method,
                },
                operation: {
                  method: member.httpMethod,
                  normalizedRoute: member.normalizedRoute,
                  operationId: member.operationId,
                },
                receiver: { ...client, constructorAliasChain: [...client.constructorAliasChain], clientAliasChain: [...client.clientAliasChain] },
                source: { path, span },
              },
            });
            return;
          }
        }
        // `client.<scope>.<method>(...)`: a pinned member spelling on a proven client, but
        // DIRECT_SHORTHAND_AUTHORIZATIONS is empty, so no pinned surface proves equivalence.
        if (ts.isIdentifier(scopeAccess.expression) && provenance.clients.has(scopeAccess.expression.text)) {
          const member = memberFor(scopeAccess.name.text, callee.name.text);
          if (member !== undefined) {
            candidates.push(
              incompleteCandidate(
                'client-endpoint-shorthand-call',
                `${scopeAccess.expression.text}.${member.scope}.${member.method}`,
                path,
                spanOf(sourceFile, node),
                'unsupported-endpoint-surface',
                'unsupported-endpoint-surface',
                'no pinned client surface authorizes the direct endpoint shorthand',
              ),
            );
          }
        }
      }
      return;
    }

    if (ts.isElementAccessExpression(callee)) {
      const method = literalTextOf(callee.argumentExpression);
      const scopeAccess = callee.expression;
      if (method === null || !ts.isElementAccessExpression(scopeAccess)) return;
      const scope = literalTextOf(scopeAccess.argumentExpression);
      const restAccess = scopeAccess.expression;
      if (scope === null || !ts.isElementAccessExpression(restAccess)) return;
      if (literalTextOf(restAccess.argumentExpression) !== 'rest') return;
      const member = memberFor(scope, method);
      if (member === undefined) return;
      candidates.push(
        incompleteCandidate(
          'bracket-member-call',
          `${receiverSpelling(restAccess.expression)}["rest"]["${member.scope}"]["${member.method}"]`,
          path,
          spanOf(sourceFile, node),
          'unsupported-static-member-access',
          'unsupported-static-member-access',
          'static bracket member access is outside the supported call grammar',
        ),
      );
    }
  });

  return candidates;
}

/* ------------------------------------------------------------------ *
 * Entrypoint.
 * ------------------------------------------------------------------ */

/**
 * Analyzes one trusted source root and returns deterministic JSON evidence.
 *
 * The returned value is `complete` only when every obligation raised under the declared
 * boundary was resolved, `incomplete` when analysis ran safely but something remains
 * unresolved, and `failed` when the request, root, or analyzer state cannot support
 * trustworthy semantic output. A `failed` result carries diagnostics and nothing else.
 */
export async function analyzeSourceTree(request: AnalysisRequest): Promise<AnalysisResult> {
  try {
    validateAnalysisRequest(request);
  } catch (error) {
    return failed('invalid-analysis-request', 'invalid-analysis-request', requestFailureDetail(error));
  }

  let rootPath: string;
  try {
    rootPath = await realpath(request.rootPath);
    const rootStat = await stat(rootPath);
    if (!rootStat.isDirectory()) {
      return failed(
        'analysis-root-not-a-directory',
        'unresolvable-analysis-root',
        'the analysis root is not a directory',
      );
    }
  } catch {
    return failed(
      'unresolvable-analysis-root',
      'unresolvable-analysis-root',
      'the analysis root could not be canonicalized',
    );
  }

  const boundary: AnalysisBoundary = {
    include: [...request.include],
    exclude: [...request.exclude],
    probotEntrypoints: [...request.probotEntrypoints],
    limits: { ...request.limits },
    sourceExtensions: [...ANALYZER_SOURCE_EXTENSIONS],
  };

  let discovery: Discovery;
  try {
    discovery = await discover(rootPath, boundary.include, boundary.exclude);
  } catch {
    return failed(
      'unresolvable-analysis-root',
      'unresolvable-analysis-root',
      'the analysis root could not be traversed',
    );
  }

  const discovered = new Set(discovery.files);
  for (const entrypoint of boundary.probotEntrypoints) {
    if (!discovered.has(entrypoint)) {
      return failed(
        'probot-entrypoint-outside-source-universe',
        'invalid-analysis-request',
        'a designated Probot entrypoint is not part of the effective included source set',
      );
    }
  }

  const causes: PendingCause[] = [...discovery.causes];
  const sources: SourceRecord[] = [];
  const candidates: PendingCandidate[] = [];
  const limits = boundary.limits;
  let consumedFiles = 0;
  let consumedBytes = 0;

  for (const relative of discovery.files) {
    if (consumedFiles >= limits.maxSourceFiles) {
      causes.push({
        code: 'limit-file-count-exhausted',
        scope: 'repository',
        path: null,
        span: null,
        detail: `the source-file budget of ${String(limits.maxSourceFiles)} stopped analysis at source ${String(consumedFiles + 1)} of ${String(discovery.files.length)}`,
      });
      break;
    }
    let raw: Buffer;
    try {
      raw = await readFile(join(rootPath, relative));
    } catch {
      causes.push({
        code: 'discovery-non-regular-entry',
        scope: 'source',
        path: relative,
        span: null,
        detail: 'an included source could not be read as a regular file',
      });
      continue;
    }
    if (raw.byteLength > limits.maxSourceFileBytes) {
      causes.push({
        code: 'source-too-large',
        scope: 'source',
        path: relative,
        span: null,
        detail: `the source exceeds the per-file budget of ${String(limits.maxSourceFileBytes)} bytes`,
      });
      continue;
    }
    if (consumedBytes + raw.byteLength > limits.maxTotalSourceBytes) {
      causes.push({
        code: 'limit-byte-budget-exhausted',
        scope: 'repository',
        path: null,
        span: null,
        detail: `the scan byte budget of ${String(limits.maxTotalSourceBytes)} stopped analysis at source ${String(consumedFiles + 1)} of ${String(discovery.files.length)} after ${String(consumedBytes)} bytes`,
      });
      break;
    }
    consumedFiles += 1;
    consumedBytes += raw.byteLength;
    sources.push({
      id: '',
      path: relative,
      byteSize: raw.byteLength,
      contentSha256: createHash('sha256').update(raw).digest('hex'),
    });

    const decoded = raw.toString('utf8');
    if (!Buffer.from(decoded, 'utf8').equals(raw)) {
      causes.push({
        code: 'source-decode-failed',
        scope: 'source',
        path: relative,
        span: null,
        detail: 'the source is not valid UTF-8 and was not parsed',
      });
      continue;
    }
    const text = decoded.charCodeAt(0) === 0xfeff ? decoded.slice(1) : decoded;
    const sourceFile = ts.createSourceFile(relative, text, ts.ScriptTarget.Latest, false, scriptKindFor(relative));
    const parseDiagnostics =
      (sourceFile as ts.SourceFile & { parseDiagnostics?: readonly ts.Diagnostic[] }).parseDiagnostics ?? [];
    if (parseDiagnostics.length > 0) {
      causes.push({
        code: 'source-parse-diagnostics',
        scope: 'source',
        path: relative,
        span: null,
        detail: `the source produced ${String(parseDiagnostics.length)} parser diagnostics and contributed no observation`,
      });
      continue;
    }
    candidates.push(...censusFile(sourceFile, relative, resolveProvenance(sourceFile)));
  }

  for (const entrypoint of boundary.probotEntrypoints) {
    causes.push({
      code: 'probot-entrypoint-unsupported',
      scope: 'source',
      path: entrypoint,
      span: null,
      detail: 'Probot entrypoint provenance is not part of this analyzer grammar',
    });
  }

  sources.sort((left, right) => compareBytes(left.path, right.path));
  sources.forEach((source, index) => {
    source.id = ordinalId('source', index);
  });

  candidates.sort((left, right) => compareBytes(candidateOrder(left), candidateOrder(right)));

  const candidateRecords: CandidateRecord[] = [];
  const observations: OperationObservation[] = [];
  candidates.forEach((candidate, index) => {
    const id = ordinalId('candidate', index);
    let observationId: string | null = null;
    if (candidate.observation !== null) {
      observationId = ordinalId('operation', observations.length);
      observations.push({
        id: observationId,
        candidateId: id,
        callForm: candidate.observation.callForm,
        spelling: candidate.observation.spelling,
        optional: candidate.observation.optional,
        member: { ...candidate.observation.member },
        operation: { ...candidate.observation.operation },
        receiver: candidate.observation.receiver,
        source: {
          path: candidate.observation.source.path,
          span: {
            start: { ...candidate.observation.source.span.start },
            end: { ...candidate.observation.source.span.end },
          },
        },
      });
    }
    candidateRecords.push({
      id,
      kind: candidate.kind,
      anchor: CANDIDATE_ANCHOR,
      spelling: candidate.spelling,
      path: candidate.path,
      span: candidate.span,
      classification: candidate.classification,
      reason: candidate.reason,
      observationId,
      causeIds: [],
    });
    for (const cause of candidate.causes) causes.push(cause);
  });

  const findings: RequirementFinding[] = observations.map((observation) =>
    resolveRequirementFinding(BOUNDARYCI_PERMISSION_CATALOG, observation.operation, observation.source),
  );
  const permissionResolutions: PermissionResolutionRecord[] = findings.map((finding, index) => ({
    id: ordinalId('resolution', index),
    observationId: observations[index]?.id ?? ordinalId('operation', index),
    finding,
  }));
  const permissionBoundary: PermissionBoundary = aggregatePermissionFindings(findings);

  if (permissionBoundary.status === 'incomplete') {
    causes.push({
      code: 'permission-catalog-incomplete',
      scope: 'repository',
      path: null,
      span: null,
      detail: `the bounded permission catalog could not resolve every proven operation: ${permissionBoundary.reasons.join(', ')}`,
    });
  }

  const uniqueCauses = new Map<string, PendingCause>();
  for (const cause of causes) uniqueCauses.set(causeKey(cause), cause);
  const orderedCauses = [...uniqueCauses.values()].sort((left, right) =>
    compareBytes(causeOrder(left), causeOrder(right)),
  );
  const causeIds = new Map<string, string>();
  const causeRecords: AnalyzerCause[] = orderedCauses.map((cause, index) => {
    const id = ordinalId('cause', index);
    causeIds.set(causeKey(cause), id);
    return { id, code: cause.code, scope: cause.scope, path: cause.path, span: cause.span, detail: cause.detail };
  });

  candidates.forEach((candidate, index) => {
    const record = candidateRecords[index];
    if (record === undefined) return;
    record.causeIds = candidate.causes
      .map((cause) => causeIds.get(causeKey(cause)))
      .filter((id): id is string => id !== undefined)
      .sort(compareBytes);
  });

  const evidence = {
    identity: ANALYZER_IDENTITY,
    boundary,
    sources,
    candidates: candidateRecords,
    causes: causeRecords,
    observations,
    permissionResolutions,
    permissionBoundary,
  };
  const everythingResolved =
    causeRecords.length === 0 &&
    permissionBoundary.status === 'complete' &&
    !candidateRecords.some((candidate) => candidate.classification === 'incomplete');
  const result: AnalysisResult = everythingResolved
    ? { status: 'complete', ...evidence }
    : { status: 'incomplete', ...evidence };

  try {
    validateAnalysisResult(result);
  } catch {
    return failed(
      'invalid-analysis-result',
      'invalid-analysis-result',
      'the analyzer produced a result that failed its own contract validation',
    );
  }
  return result;
}
