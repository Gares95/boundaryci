/**
 * Bounded trusted-entrypoint Probot provenance.
 *
 * This module recognizes only the finite registration contract Phase 3 has authorized. It
 * never treats package imports, filenames, type annotations, names, or an arbitrary `.on()`
 * call as framework evidence. A caller supplies the trusted designated-entrypoint paths; this
 * module proves a default initializer, then a direct `app.on(event, handler)` relationship, and
 * finally the handler-local `Context` → `octokit` binding at a requested source position.
 */

import ts from 'typescript';

import type { SourceSpan } from '../permission-model/model.js';

import { RELATIVE_SOURCE_CANDIDATE_RULES, RELATIVE_SOURCE_CANDIDATE_TABLE_ID, spanOfNode } from './parse.js';
import type { ParsedSource } from './parse.js';

/** Versioned identity of the deliberately narrow Probot proof grammar. */
export const PROBOT_PROFILE_IDENTITY = 'boundaryci/probot-provenance@1';

export type ProbotProofCode =
  | 'ambiguous-relative-source'
  | 'relevant-resolution-cycle'
  | 'resolution-byte-limit'
  | 'resolution-depth-limit'
  | 'resolution-file-limit'
  | 'resolution-work-limit'
  | 'unresolved-relative-source'
  | 'unproven-octokit-origin'
  | 'unsupported-probot-entrypoint-initializer'
  | 'unsupported-probot-handler-registration';

export interface ProbotProofCause {
  readonly code: ProbotProofCode;
  readonly path: string;
  readonly span: SourceSpan;
  readonly detail: string;
}

export interface ProbotProofStep {
  readonly kind: 'probot-context-octokit' | 'probot-entrypoint' | 'probot-handler-registration' | 'relative-source-resolution';
  readonly path: string;
  readonly span: SourceSpan;
  readonly binding: string;
  readonly specifier: string | null;
  readonly resolvedPath: string | null;
  readonly ruleId: string | null;
  readonly ruleRow: number | null;
}

export interface ProbotEntrypointProof {
  readonly status: 'proven';
  readonly appName: string;
  readonly path: string;
  readonly initializer: ts.FunctionLikeDeclarationBase;
  readonly initializerSpan: SourceSpan;
  readonly appParameterSpan: SourceSpan;
}

/** The explicit limits mirror the finite source-graph policy rather than following arbitrary imports. */
export interface ProbotResolutionLimits {
  readonly maxDepth: number;
  readonly maxFiles: number;
  readonly maxBytes: number;
  readonly maxWork: number;
}

const DEFAULT_LIMITS: ProbotResolutionLimits = {
  maxDepth: 24,
  maxFiles: 48,
  maxBytes: 8_000_000,
  maxWork: 2048,
};

export interface ProbotEntrypointIncomplete {
  readonly status: 'incomplete';
  readonly cause: ProbotProofCause;
}

export type ProbotEntrypointResult = ProbotEntrypointIncomplete | ProbotEntrypointProof;

export interface ProbotHandlerContextProof {
  readonly status: 'proven';
  readonly clientBinding: string;
  readonly contextBinding: string;
  readonly steps: readonly ProbotProofStep[];
}

export interface ProbotHandlerContextIncomplete {
  readonly status: 'unproven';
  readonly causes: readonly ProbotProofCause[];
}

export type ProbotHandlerContextResult = ProbotHandlerContextIncomplete | ProbotHandlerContextProof;

export type ProbotRegistrationResult =
  | { readonly status: 'proven' }
  | { readonly status: 'irrelevant' }
  | { readonly status: 'incomplete'; readonly cause: ProbotProofCause };

interface HandlerReference {
  readonly path: string;
  readonly functionNode: ts.FunctionLikeDeclarationBase;
  readonly forwardingSteps: readonly ProbotProofStep[];
}

interface HandlerResolutionTrace {
  readonly files: Set<string>;
  bytes: number;
  work: number;
  cause: ProbotProofCause | null;
}

function handlerTrace(): HandlerResolutionTrace {
  return { files: new Set(), bytes: 0, work: 0, cause: null };
}

function recordHandlerCause(
  trace: HandlerResolutionTrace,
  source: ParsedSource,
  code: ProbotProofCode,
  detail: string,
  node: ts.Node = source.sourceFile,
): void {
  if (trace.cause !== null) return;
  trace.cause = {
    code,
    path: source.record.path,
    span: spanOfNode(source, node),
    detail,
  };
}

function functionParameterName(node: ts.FunctionLikeDeclarationBase): string | null {
  const parameter = node.parameters[0];
  return parameter !== undefined && ts.isIdentifier(parameter.name) ? parameter.name.text : null;
}

function firstParameterSpan(source: ParsedSource, node: ts.FunctionLikeDeclarationBase): SourceSpan | null {
  const parameter = node.parameters[0];
  return parameter === undefined ? null : spanOfNode(source, parameter);
}

function incomplete(source: ParsedSource, node: ts.Node, code: ProbotProofCode, detail: string): ProbotEntrypointIncomplete {
  return { status: 'incomplete', cause: { code, path: source.record.path, span: spanOfNode(source, node), detail } };
}

function topLevelFunction(source: ParsedSource, name: string): ts.FunctionDeclaration | null {
  const matches = source.sourceFile.statements.filter(
    (statement): statement is ts.FunctionDeclaration =>
      ts.isFunctionDeclaration(statement) && statement.name?.text === name,
  );
  return matches.length === 1 ? (matches[0] ?? null) : null;
}

function defaultExportForms(source: ParsedSource): ts.Node[] {
  const forms: ts.Node[] = [];
  for (const statement of source.sourceFile.statements) {
    if (ts.isExportAssignment(statement) && !statement.isExportEquals) forms.push(statement);
    if (ts.isFunctionDeclaration(statement)) {
      const modifiers = ts.getModifiers(statement) ?? [];
      if (modifiers.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword) && modifiers.some((modifier) => modifier.kind === ts.SyntaxKind.DefaultKeyword)) forms.push(statement);
    }
    if (ts.isExportDeclaration(statement) && statement.exportClause !== undefined && ts.isNamedExports(statement.exportClause)) {
      for (const element of statement.exportClause.elements) {
        if (!element.isTypeOnly && element.name.text === 'default') forms.push(element);
      }
    }
  }
  return forms;
}

function localNameForDefaultExportSpecifier(source: ParsedSource, target: ts.ExportSpecifier): string | null {
  for (const statement of source.sourceFile.statements) {
    if (
      !ts.isExportDeclaration(statement) ||
      statement.moduleSpecifier !== undefined ||
      statement.exportClause === undefined ||
      !ts.isNamedExports(statement.exportClause)
    ) {
      continue;
    }
    for (const element of statement.exportClause.elements) {
      if (element === target) return element.propertyName?.text ?? element.name.text;
    }
  }
  return null;
}

function forEachBindingIdentifier(name: ts.BindingName, visit: (identifier: ts.Identifier) => void): void {
  if (ts.isIdentifier(name)) {
    visit(name);
    return;
  }
  for (const element of name.elements) {
    if (!ts.isOmittedExpression(element)) forEachBindingIdentifier(element.name, visit);
  }
}

function assignmentContainsName(node: ts.Node, name: string): boolean {
  let found = false;
  const visit = (child: ts.Node): void => {
    if (found) return;
    if (ts.isIdentifier(child) && child.text === name) {
      found = true;
      return;
    }
    ts.forEachChild(child, visit);
  };
  visit(node);
  return found;
}

function isAssignmentOperator(kind: ts.SyntaxKind): boolean {
  return kind >= ts.SyntaxKind.FirstAssignment && kind <= ts.SyntaxKind.LastAssignment;
}

/**
 * Conservatively proves that one declaration remains the only binding and write target with
 * this spelling inside the finite owner. Rejecting an unrelated shadow is acceptable; proving a
 * shadowed or reassigned framework value is not.
 */
function bindingIsStable(source: ParsedSource, owner: ts.Node, name: string, declaration: ts.Identifier | undefined): boolean {
  if (declaration === undefined) return false;
  let stable = true;
  const declarationStart = declaration.getStart(source.sourceFile);
  const checkDeclaration = (identifier: ts.Identifier): void => {
    if (identifier.text === name && identifier.getStart(source.sourceFile) !== declarationStart) stable = false;
  };
  const visit = (node: ts.Node): void => {
    if (!stable) return;
    if (ts.isVariableDeclaration(node) || ts.isParameter(node)) {
      forEachBindingIdentifier(node.name, checkDeclaration);
    } else if (
      (ts.isFunctionDeclaration(node) ||
        ts.isFunctionExpression(node) ||
        ts.isClassDeclaration(node) ||
        ts.isClassExpression(node) ||
        ts.isEnumDeclaration(node) ||
        ts.isModuleDeclaration(node)) &&
      node.name !== undefined &&
      ts.isIdentifier(node.name) &&
      node !== owner
    ) {
      checkDeclaration(node.name);
    } else if (ts.isImportClause(node) && node.name !== undefined) {
      checkDeclaration(node.name);
    } else if (ts.isImportSpecifier(node) || ts.isNamespaceImport(node) || ts.isImportEqualsDeclaration(node)) {
      checkDeclaration(node.name);
    }

    if (ts.isBinaryExpression(node) && isAssignmentOperator(node.operatorToken.kind) && assignmentContainsName(node.left, name)) {
      stable = false;
      return;
    }
    if (
      (ts.isPrefixUnaryExpression(node) || ts.isPostfixUnaryExpression(node)) &&
      (node.operator === ts.SyntaxKind.PlusPlusToken || node.operator === ts.SyntaxKind.MinusMinusToken) &&
      assignmentContainsName(node.operand, name)
    ) {
      stable = false;
      return;
    }
    if (
      (ts.isForInStatement(node) || ts.isForOfStatement(node)) &&
      !ts.isVariableDeclarationList(node.initializer) &&
      assignmentContainsName(node.initializer, name)
    ) {
      stable = false;
      return;
    }
    ts.forEachChild(node, visit);
  };
  visit(owner);
  return stable;
}

function localVariable(source: ParsedSource, name: string): ts.VariableDeclaration | null {
  const declarations: ts.VariableDeclaration[] = [];
  for (const statement of source.sourceFile.statements) {
    if (!ts.isVariableStatement(statement) || (statement.declarationList.flags & ts.NodeFlags.Const) === 0) continue;
    for (const declaration of statement.declarationList.declarations) if (ts.isIdentifier(declaration.name) && declaration.name.text === name) declarations.push(declaration);
  }
  return declarations.length === 1 ? (declarations[0] ?? null) : null;
}

/** Proves only the designated file's supported default initializer grammar. */
export function proveProbotEntrypoint(source: ParsedSource): ProbotEntrypointResult {
  const forms = defaultExportForms(source);
  const only = forms.length === 1 ? (forms[0] ?? null) : null;
  const defaultAssignment = only !== null && ts.isExportAssignment(only) ? only : undefined;
  let initializer: ts.FunctionLikeDeclarationBase | null = null;

  if (only !== null && defaultAssignment !== undefined) {
    if (ts.isArrowFunction(defaultAssignment.expression) || ts.isFunctionExpression(defaultAssignment.expression)) {
      initializer = defaultAssignment.expression;
    } else if (ts.isIdentifier(defaultAssignment.expression)) {
      const functionBinding = topLevelFunction(source, defaultAssignment.expression.text);
      const variableBinding = localVariable(source, defaultAssignment.expression.text);
      if (functionBinding !== null && bindingIsStable(source, source.sourceFile, defaultAssignment.expression.text, functionBinding.name as ts.Identifier)) initializer = functionBinding;
      if (variableBinding !== null && variableBinding.initializer !== undefined && (ts.isArrowFunction(variableBinding.initializer) || ts.isFunctionExpression(variableBinding.initializer)) && bindingIsStable(source, source.sourceFile, defaultAssignment.expression.text, variableBinding.name as ts.Identifier)) initializer = variableBinding.initializer;
    }
  } else if (only !== null && ts.isExportSpecifier(only)) {
    const localName = localNameForDefaultExportSpecifier(source, only);
    if (localName !== null) {
      const functionBinding = topLevelFunction(source, localName);
      const variableBinding = localVariable(source, localName);
      if (
        functionBinding !== null &&
        bindingIsStable(source, source.sourceFile, localName, functionBinding.name as ts.Identifier)
      ) {
        initializer = functionBinding;
      }
      if (
        variableBinding !== null &&
        variableBinding.initializer !== undefined &&
        (ts.isArrowFunction(variableBinding.initializer) || ts.isFunctionExpression(variableBinding.initializer)) &&
        bindingIsStable(source, source.sourceFile, localName, variableBinding.name as ts.Identifier)
      ) {
        initializer = variableBinding.initializer;
      }
    }
  } else if (only !== null && ts.isFunctionDeclaration(only)) {
    initializer = only;
  }

  if (initializer === null) {
    return incomplete(
      source,
      only ?? source.sourceFile,
      'unsupported-probot-entrypoint-initializer',
      'the designated Probot entrypoint has no supported direct default initializer',
    );
  }
  const appName = functionParameterName(initializer);
  const appParameterSpan = firstParameterSpan(source, initializer);
  if (appName === null || appParameterSpan === null) {
    return incomplete(
      source,
      initializer,
      'unsupported-probot-entrypoint-initializer',
      'the supported default initializer does not expose a parameter-zero app binding',
    );
  }
  return {
    status: 'proven',
    appName,
    path: source.record.path,
    initializer,
    initializerSpan: spanOfNode(source, initializer),
    appParameterSpan,
  };
}

function normalizeRelative(fromPath: string, specifier: string): string | null {
  if (!specifier.startsWith('./') && !specifier.startsWith('../')) return null;
  const segments = fromPath.split('/').slice(0, -1);
  for (const part of specifier.split('/')) {
    if (part === '' || part === '.') continue;
    if (part === '..') {
      if (segments.length === 0) return null;
      segments.pop();
    } else {
      segments.push(part);
    }
  }
  return segments.length === 0 ? null : segments.join('/');
}

function resolveRelative(
  fromPath: string,
  specifier: string,
  sources: ReadonlyMap<string, ParsedSource>,
):
  | { readonly status: 'ambiguous' }
  | { readonly status: 'resolved'; readonly path: string; readonly ruleRow: number }
  | { readonly status: 'unresolved' } {
  const target = normalizeRelative(fromPath, specifier);
  if (target === null) return { status: 'unresolved' };
  const base = target.slice(target.lastIndexOf('/') + 1);
  const dot = base.lastIndexOf('.');
  const extension = dot > 0 ? base.slice(dot) : '';
  const ruleRow = RELATIVE_SOURCE_CANDIDATE_RULES.findIndex((rule) => rule.specifierExtension === extension);
  const rule = RELATIVE_SOURCE_CANDIDATE_RULES[ruleRow];
  if (rule === undefined) return { status: 'unresolved' };
  const stem = extension === '' ? target : target.slice(0, target.length - extension.length);
  const matches = rule.eligibleCandidateExtensions
    .map((suffix) => `${stem}${suffix}`)
    .filter((candidate) => sources.has(candidate));
  if (matches.length === 0) return { status: 'unresolved' };
  if (matches.length > 1) return { status: 'ambiguous' };
  return { status: 'resolved', path: matches[0] as string, ruleRow };
}

function relativeStep(
  source: ParsedSource,
  node: ts.Node,
  binding: string,
  specifier: string,
  resolution: { readonly status: 'resolved'; readonly path: string; readonly ruleRow: number },
): ProbotProofStep {
  return {
    kind: 'relative-source-resolution',
    path: source.record.path,
    span: spanOfNode(source, node),
    binding,
    specifier,
    resolvedPath: resolution.path,
    ruleId: RELATIVE_SOURCE_CANDIDATE_TABLE_ID,
    ruleRow: resolution.ruleRow,
  };
}

function recordRelativeFailure(
  trace: HandlerResolutionTrace,
  source: ParsedSource,
  node: ts.Node,
  resolution: { readonly status: 'ambiguous' | 'unresolved' },
): void {
  if (resolution.status === 'ambiguous') {
    recordHandlerCause(
      trace,
      source,
      'ambiguous-relative-source',
      'the handler specifier matched several included sources under the fixed candidate table',
      node,
    );
  } else {
    recordHandlerCause(
      trace,
      source,
      'unresolved-relative-source',
      'the handler specifier matched no included source under the fixed candidate table',
      node,
    );
  }
}

function localHandler(source: ParsedSource, name: string): ts.FunctionLikeDeclarationBase | null {
  const functionNode = topLevelFunction(source, name);
  if (functionNode !== null) return functionNode.name !== undefined && bindingIsStable(source, source.sourceFile, name, functionNode.name) ? functionNode : null;
  const declarations: ts.VariableDeclaration[] = [];
  for (const statement of source.sourceFile.statements) {
    if (!ts.isVariableStatement(statement) || (statement.declarationList.flags & ts.NodeFlags.Const) === 0) continue;
    for (const declaration of statement.declarationList.declarations) {
      if (ts.isIdentifier(declaration.name) && declaration.name.text === name) declarations.push(declaration);
    }
  }
  if (declarations.length !== 1) return null;
  const declaration = declarations[0];
  if (declaration === undefined) return null;
  const initializer = declaration.initializer;
  if (initializer !== undefined && (ts.isArrowFunction(initializer) || ts.isFunctionExpression(initializer)) && ts.isIdentifier(declaration.name) && bindingIsStable(source, source.sourceFile, name, declaration.name)) return initializer;
  return null;
}

function ownerStatements(owner: ts.Node): readonly ts.Statement[] {
  if (
    (ts.isFunctionDeclaration(owner) || ts.isFunctionExpression(owner) || ts.isArrowFunction(owner)) &&
    owner.body !== undefined &&
    ts.isBlock(owner.body)
  ) {
    return owner.body.statements;
  }
  return [];
}

function localHandlerInOwner(source: ParsedSource, owner: ts.Node, name: string): ts.FunctionLikeDeclarationBase | null {
  const matches: { node: ts.FunctionLikeDeclarationBase; declaration: ts.Identifier }[] = [];
  for (const statement of ownerStatements(owner)) {
    if (ts.isFunctionDeclaration(statement) && statement.name?.text === name) {
      matches.push({ node: statement, declaration: statement.name });
      continue;
    }
    if (!ts.isVariableStatement(statement) || (statement.declarationList.flags & ts.NodeFlags.Const) === 0) continue;
    for (const declaration of statement.declarationList.declarations) {
      if (
        ts.isIdentifier(declaration.name) &&
        declaration.name.text === name &&
        declaration.initializer !== undefined &&
        (ts.isArrowFunction(declaration.initializer) || ts.isFunctionExpression(declaration.initializer))
      ) {
        matches.push({ node: declaration.initializer, declaration: declaration.name });
      }
    }
  }
  if (matches.length !== 1) return null;
  const match = matches[0];
  return match !== undefined && bindingIsStable(source, owner, name, match.declaration) ? match.node : null;
}

function localAlias(source: ParsedSource, name: string): { readonly target: string; readonly node: ts.VariableDeclaration } | null {
  const declarations: ts.VariableDeclaration[] = [];
  for (const statement of source.sourceFile.statements) {
    if (!ts.isVariableStatement(statement) || (statement.declarationList.flags & ts.NodeFlags.Const) === 0) continue;
    for (const declaration of statement.declarationList.declarations) {
      if (ts.isIdentifier(declaration.name) && declaration.name.text === name) declarations.push(declaration);
    }
  }
  if (declarations.length !== 1) return null;
  const declaration = declarations[0];
  const initializer = declaration?.initializer;
  if (declaration === undefined || initializer === undefined || !ts.isIdentifier(initializer) || !ts.isIdentifier(declaration.name) || !bindingIsStable(source, source.sourceFile, name, declaration.name)) return null;
  return { target: initializer.text, node: declaration };
}

function localAliasInOwner(
  source: ParsedSource,
  owner: ts.Node,
  name: string,
): { readonly target: string; readonly node: ts.VariableDeclaration } | null {
  const matches: ts.VariableDeclaration[] = [];
  for (const statement of ownerStatements(owner)) {
    if (!ts.isVariableStatement(statement) || (statement.declarationList.flags & ts.NodeFlags.Const) === 0) continue;
    for (const declaration of statement.declarationList.declarations) {
      if (
        ts.isIdentifier(declaration.name) &&
        declaration.name.text === name &&
        declaration.initializer !== undefined &&
        ts.isIdentifier(declaration.initializer)
      ) {
        matches.push(declaration);
      }
    }
  }
  const declaration = matches.length === 1 ? matches[0] : undefined;
  if (
    declaration === undefined ||
    !ts.isIdentifier(declaration.name) ||
    declaration.initializer === undefined ||
    !ts.isIdentifier(declaration.initializer) ||
    !bindingIsStable(source, owner, name, declaration.name)
  ) {
    return null;
  }
  return { target: declaration.initializer.text, node: declaration };
}

function importedBinding(source: ParsedSource, name: string): { readonly imported: string; readonly specifier: string; readonly node: ts.ImportSpecifier } | null {
  const matches: { imported: string; specifier: string; node: ts.ImportSpecifier }[] = [];
  for (const statement of source.sourceFile.statements) {
    if (!ts.isImportDeclaration(statement) || !ts.isStringLiteral(statement.moduleSpecifier)) continue;
    const bindings = statement.importClause?.namedBindings;
    if (bindings === undefined || !ts.isNamedImports(bindings)) continue;
    for (const item of bindings.elements) {
      if (!item.isTypeOnly && item.name.text === name) {
        matches.push({ imported: item.propertyName?.text ?? item.name.text, specifier: statement.moduleSpecifier.text, node: item });
      }
    }
  }
  return matches.length === 1 ? (matches[0] ?? null) : null;
}

function exportedBinding(source: ParsedSource, name: string): { readonly local: string; readonly specifier: string | null; readonly node: ts.Node } | null {
  const matches: { local: string; specifier: string | null; node: ts.Node }[] = [];
  for (const statement of source.sourceFile.statements) {
    if (ts.isFunctionDeclaration(statement) && statement.name?.text === name && (ts.getModifiers(statement) ?? []).some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword)) {
      matches.push({ local: name, specifier: null, node: statement });
      continue;
    }
    if (
      ts.isVariableStatement(statement) &&
      (statement.declarationList.flags & ts.NodeFlags.Const) !== 0 &&
      (ts.getModifiers(statement) ?? []).some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword)
    ) {
      for (const declaration of statement.declarationList.declarations) {
        if (ts.isIdentifier(declaration.name) && declaration.name.text === name) {
          matches.push({ local: name, specifier: null, node: declaration });
        }
      }
      continue;
    }
    if (!ts.isExportDeclaration(statement) || statement.exportClause === undefined || !ts.isNamedExports(statement.exportClause)) continue;
    for (const item of statement.exportClause.elements) {
      if (!item.isTypeOnly && item.name.text === name) {
        matches.push({
          local: item.propertyName?.text ?? item.name.text,
          specifier: statement.moduleSpecifier !== undefined && ts.isStringLiteral(statement.moduleSpecifier) ? statement.moduleSpecifier.text : null,
          node: item,
        });
      }
    }
  }
  return matches.length === 1 ? (matches[0] ?? null) : null;
}

function resolveHandlerReference(
  sources: ReadonlyMap<string, ParsedSource>,
  path: string,
  name: string,
  seen: ReadonlySet<string> = new Set(),
  owner: ts.Node | null = null,
  limits: ProbotResolutionLimits = DEFAULT_LIMITS,
  trace: HandlerResolutionTrace = handlerTrace(),
  depth = 0,
): HandlerReference | null {
  const key = JSON.stringify([path, name]);
  const source = sources.get(path);
  if (source === undefined) return null;
  trace.work += 1;
  if (trace.work > limits.maxWork) {
    recordHandlerCause(trace, source, 'resolution-work-limit', 'the Probot handler proof exceeded its work limit');
    return null;
  }
  if (depth > limits.maxDepth) {
    recordHandlerCause(trace, source, 'resolution-depth-limit', 'the Probot handler proof exceeded its depth limit');
    return null;
  }
  if (seen.has(key)) {
    recordHandlerCause(trace, source, 'relevant-resolution-cycle', 'a handler-forwarding cycle blocked the required Probot provenance proof');
    return null;
  }
  if (!trace.files.has(path)) {
    if (trace.files.size + 1 > limits.maxFiles) {
      recordHandlerCause(trace, source, 'resolution-file-limit', 'the Probot handler proof exceeded its source-file limit');
      return null;
    }
    if (trace.bytes + source.record.byteSize > limits.maxBytes) {
      recordHandlerCause(trace, source, 'resolution-byte-limit', 'the Probot handler proof exceeded its source-byte limit');
      return null;
    }
    trace.files.add(path);
    trace.bytes += source.record.byteSize;
  }
  const nextSeen = new Set(seen);
  nextSeen.add(key);
  const direct = owner === null ? localHandler(source, name) : (localHandlerInOwner(source, owner, name) ?? localHandler(source, name));
  if (direct !== null) return { path, functionNode: direct, forwardingSteps: [] };
  const alias = owner === null ? localAlias(source, name) : (localAliasInOwner(source, owner, name) ?? localAlias(source, name));
  if (alias !== null) {
    const resolved = resolveHandlerReference(sources, path, alias.target, nextSeen, owner, limits, trace, depth + 1);
    if (resolved === null) return null;
    return {
      ...resolved,
      forwardingSteps: [{ kind: 'probot-handler-registration', path, span: spanOfNode(source, alias.node), binding: name, specifier: null, resolvedPath: null, ruleId: null, ruleRow: null }, ...resolved.forwardingSteps],
    };
  }
  const imported = importedBinding(source, name);
  if (imported === null) {
    const forwardedExport = exportedBinding(source, name);
    if (forwardedExport === null) return null;
    if (forwardedExport.specifier === null) {
      if (forwardedExport.local === name) return null;
      return resolveHandlerReference(
        sources,
        path,
        forwardedExport.local,
        nextSeen,
        owner,
        limits,
        trace,
        depth + 1,
      );
    }
    const forwarded = resolveRelative(path, forwardedExport.specifier, sources);
    if (forwarded.status !== 'resolved') {
      recordRelativeFailure(trace, source, forwardedExport.node, forwarded);
      return null;
    }
    const resolved = resolveHandlerReference(
      sources,
      forwarded.path,
      forwardedExport.local,
      nextSeen,
      null,
      limits,
      trace,
      depth + 1,
    );
    if (resolved === null) return null;
    return {
      ...resolved,
      forwardingSteps: [
        relativeStep(source, forwardedExport.node, name, forwardedExport.specifier, forwarded),
        ...resolved.forwardingSteps,
      ],
    };
  }
  const resolution = resolveRelative(path, imported.specifier, sources);
  if (resolution.status !== 'resolved') {
    recordRelativeFailure(trace, source, imported.node, resolution);
    return null;
  }
  const resolved = resolveHandlerReference(
    sources,
    resolution.path,
    imported.imported,
    nextSeen,
    null,
    limits,
    trace,
    depth + 1,
  );
  if (resolved === null) return null;
  return { ...resolved, forwardingSteps: [relativeStep(source, imported.node, name, imported.specifier, resolution), ...resolved.forwardingSteps] };
}

function functionAtOffset(source: ParsedSource, offset: number): ts.FunctionLikeDeclarationBase | null {
  let found: ts.FunctionLikeDeclarationBase | null = null;
  const visit = (node: ts.Node): void => {
    if (offset < node.getStart(source.sourceFile) || offset >= node.getEnd()) return;
    if (ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node) || ts.isArrowFunction(node)) found = node;
    ts.forEachChild(node, visit);
  };
  visit(source.sourceFile);
  return found;
}

function directDestructuredOctokitBinding(
  source: ParsedSource,
  handler: ts.FunctionLikeDeclarationBase,
  contextName: string,
  clientName: string,
): ts.BindingElement | null {
  const body = handler.body;
  if (body === undefined || !ts.isBlock(body)) return null;
  const matches: ts.BindingElement[] = [];
  for (const statement of body.statements) {
    if (!ts.isVariableStatement(statement) || (statement.declarationList.flags & ts.NodeFlags.Const) === 0) continue;
    for (const declaration of statement.declarationList.declarations) {
      const initializer = declaration.initializer;
      if (!ts.isObjectBindingPattern(declaration.name) || initializer === undefined || !ts.isIdentifier(initializer) || initializer.text !== contextName) continue;
      for (const element of declaration.name.elements) {
        if (element.dotDotDotToken !== undefined || element.initializer !== undefined || !ts.isIdentifier(element.name)) continue;
        const property = element.propertyName ?? element.name;
        if ((ts.isIdentifier(property) || ts.isStringLiteral(property)) && property.text === 'octokit' && element.name.text === clientName) matches.push(element);
      }
    }
  }
  return matches.length === 1 ? (matches[0] ?? null) : null;
}

/**
 * Proves a candidate receiver only when a trusted entrypoint's exact `app.on` registration
 * supplies the handler-local Context parameter that reaches it. This intentionally does not
 * propagate Context through nested callbacks or arbitrary calls.
 */
export function proveProbotHandlerContext(
  sources: ReadonlyMap<string, ParsedSource>,
  entrypoints: ReadonlySet<string>,
  target: { readonly path: string; readonly start: number; readonly contextName: string | null; readonly clientName: string | null },
  limits: ProbotResolutionLimits = DEFAULT_LIMITS,
): ProbotHandlerContextResult {
  const targetSource = sources.get(target.path);
  if (targetSource === undefined) return { status: 'unproven', causes: [] };
  const enclosing = functionAtOffset(targetSource, target.start);
  if (enclosing === null) return { status: 'unproven', causes: [] };

  const entrypointCauses: ProbotProofCause[] = [];
  const handlerCauses: ProbotProofCause[] = [];
  for (const entrypointPath of [...entrypoints].sort()) {
    const entrypointSource = sources.get(entrypointPath);
    if (entrypointSource === undefined) continue;
    const entrypoint = proveProbotEntrypoint(entrypointSource);
    if (entrypoint.status === 'incomplete') {
      entrypointCauses.push(entrypoint.cause);
      continue;
    }
    const visit = (node: ts.Node): ProbotHandlerContextProof | null => {
      if (node !== entrypoint.initializer && (ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node) || ts.isArrowFunction(node))) return null;
      if (ts.isCallExpression(node) && node.questionDotToken === undefined && ts.isPropertyAccessExpression(node.expression) && node.expression.questionDotToken === undefined && !ts.isPrivateIdentifier(node.expression.name) && node.expression.name.text === 'on' && ts.isIdentifier(node.expression.expression) && node.expression.expression.text === entrypoint.appName && node.arguments.length === 2 && bindingIsStable(entrypointSource, entrypoint.initializer, entrypoint.appName, entrypoint.initializer.parameters[0]?.name as ts.Identifier)) {
        const handlerArgument = node.arguments[1];
        let handler: HandlerReference | null = null;
        if (handlerArgument !== undefined && (ts.isFunctionExpression(handlerArgument) || ts.isArrowFunction(handlerArgument))) {
          handler = { path: entrypointPath, functionNode: handlerArgument, forwardingSteps: [] };
        } else if (handlerArgument !== undefined && ts.isIdentifier(handlerArgument)) {
          const trace = handlerTrace();
          handler = resolveHandlerReference(
            sources,
            entrypointPath,
            handlerArgument.text,
            new Set(),
            entrypoint.initializer,
            limits,
            trace,
          );
          if (handler === null && trace.cause !== null) handlerCauses.push(trace.cause);
        }
        if (handler !== null && handler.path === target.path && handler.functionNode === enclosing) {
          const parameter = handler.functionNode.parameters[0];
          const registrationStep: ProbotProofStep = { kind: 'probot-handler-registration', path: entrypointPath, span: spanOfNode(entrypointSource, node), binding: entrypoint.appName, specifier: null, resolvedPath: null, ruleId: null, ruleRow: null };
          const entrypointStep: ProbotProofStep = { kind: 'probot-entrypoint', path: entrypointPath, span: entrypoint.initializerSpan, binding: entrypoint.appName, specifier: null, resolvedPath: null, ruleId: null, ruleRow: null };
          if (parameter !== undefined && ts.isIdentifier(parameter.name) && target.contextName === parameter.name.text && bindingIsStable(targetSource, handler.functionNode, parameter.name.text, parameter.name)) {
            return { status: 'proven', clientBinding: `${parameter.name.text}.octokit`, contextBinding: parameter.name.text, steps: [entrypointStep, registrationStep, ...handler.forwardingSteps, { kind: 'probot-context-octokit', path: target.path, span: spanOfNode(targetSource, parameter), binding: `${parameter.name.text}.octokit`, specifier: null, resolvedPath: null, ruleId: null, ruleRow: null }] };
          }
          if (parameter !== undefined && ts.isObjectBindingPattern(parameter.name) && target.clientName !== null) {
            const octokit = parameter.name.elements.find((element) => {
              const property = element.propertyName ?? element.name;
              return element.dotDotDotToken === undefined && element.initializer === undefined && ts.isIdentifier(element.name) && element.name.text === target.clientName && (ts.isIdentifier(property) || ts.isStringLiteral(property)) && property.text === 'octokit';
            });
            if (octokit !== undefined && ts.isIdentifier(octokit.name) && bindingIsStable(targetSource, handler.functionNode, target.clientName, octokit.name)) {
              return { status: 'proven', clientBinding: target.clientName, contextBinding: '<destructured-context>', steps: [entrypointStep, registrationStep, ...handler.forwardingSteps, { kind: 'probot-context-octokit', path: target.path, span: spanOfNode(targetSource, octokit), binding: target.clientName, specifier: null, resolvedPath: null, ruleId: null, ruleRow: null }] };
            }
          }
          if (parameter !== undefined && ts.isIdentifier(parameter.name) && target.clientName !== null) {
            const octokit = directDestructuredOctokitBinding(targetSource, handler.functionNode, parameter.name.text, target.clientName);
            if (octokit !== null && ts.isIdentifier(octokit.name) && bindingIsStable(targetSource, handler.functionNode, target.clientName, octokit.name) && bindingIsStable(targetSource, handler.functionNode, parameter.name.text, parameter.name)) {
              return { status: 'proven', clientBinding: target.clientName, contextBinding: parameter.name.text, steps: [entrypointStep, registrationStep, ...handler.forwardingSteps, { kind: 'probot-context-octokit', path: target.path, span: spanOfNode(targetSource, octokit), binding: target.clientName, specifier: null, resolvedPath: null, ruleId: null, ruleRow: null }] };
            }
          }
        }
      }
      let result: ProbotHandlerContextProof | null = null;
      ts.forEachChild(node, (child) => { if (result === null) result = visit(child); });
      return result;
    };
    const result = visit(entrypoint.initializer);
    if (result !== null) return result;
  }
  return { status: 'unproven', causes: [...entrypointCauses, ...handlerCauses] };
}

/** Proves only a direct authorized `app.on(event, inline-or-immutable-handler)` registration. */
export function proveProbotHandlerRegistration(
  sources: ReadonlyMap<string, ParsedSource>,
  entrypoints: ReadonlySet<string>,
  target: { readonly path: string; readonly start: number; readonly optional?: boolean },
  limits: ProbotResolutionLimits = DEFAULT_LIMITS,
): ProbotRegistrationResult {
  const targetSource = sources.get(target.path);
  if (targetSource === undefined) {
    return { status: 'incomplete', cause: { code: 'unsupported-probot-handler-registration', path: target.path, span: { start: { line: 1, column: 1 }, end: { line: 1, column: 1 } }, detail: 'the Probot registration source was unavailable to the bounded proof' } };
  }
  for (const entrypointPath of [...entrypoints].sort()) {
    if (entrypointPath !== target.path) continue;
    const entrypoint = proveProbotEntrypoint(targetSource);
    if (entrypoint.status === 'incomplete') return { status: 'incomplete', cause: entrypoint.cause };
    let matching: ts.CallExpression | null = null;
    const visit = (node: ts.Node): void => {
      if (matching !== null) return;
      if (ts.isCallExpression(node) && node.getStart(targetSource.sourceFile) === target.start) matching = node;
      ts.forEachChild(node, visit);
    };
    visit(targetSource.sourceFile);
    const matched = matching as ts.CallExpression | null;
    if (matched === null) {
      return { status: 'irrelevant' };
    }
    const insideInitializer =
      matched.getStart(targetSource.sourceFile) >= entrypoint.initializer.getStart(targetSource.sourceFile) &&
      matched.getEnd() <= entrypoint.initializer.getEnd();
    if (
      !insideInitializer ||
      !ts.isPropertyAccessExpression(matched.expression) ||
      !ts.isIdentifier(matched.expression.expression) ||
      matched.expression.expression.text !== entrypoint.appName
    ) {
      return { status: 'irrelevant' };
    }
    if (target.optional === true || matched.questionDotToken !== undefined || matched.expression.questionDotToken !== undefined || matched.expression.name.text !== 'on' || matched.arguments.length !== 2 || !bindingIsStable(targetSource, entrypoint.initializer, entrypoint.appName, entrypoint.initializer.parameters[0]?.name as ts.Identifier)) {
      const node = matched ?? entrypoint.initializer;
      return { status: 'incomplete', cause: { code: 'unsupported-probot-handler-registration', path: target.path, span: spanOfNode(targetSource, node), detail: 'the registration is outside the direct authorized Probot app.on handler contract' } };
    }
    const handler = matched.arguments[1];
    const trace = handlerTrace();
    const supported =
      handler !== undefined &&
      (ts.isFunctionExpression(handler) ||
        ts.isArrowFunction(handler) ||
        (ts.isIdentifier(handler) &&
          resolveHandlerReference(
            sources,
            entrypointPath,
            handler.text,
            new Set(),
            entrypoint.initializer,
            limits,
            trace,
          ) !== null));
    if (!supported) {
      if (trace.cause !== null) return { status: 'incomplete', cause: trace.cause };
      return { status: 'incomplete', cause: { code: 'unsupported-probot-handler-registration', path: target.path, span: spanOfNode(targetSource, matched), detail: 'the registration handler is outside the supported inline or immutable named handler grammar' } };
    }
    return { status: 'proven' };
  }
  return { status: 'incomplete', cause: { code: 'unsupported-probot-handler-registration', path: target.path, span: { start: { line: 1, column: 1 }, end: { line: 1, column: 1 } }, detail: 'the registration is not in a trusted designated Probot entrypoint' } };
}
