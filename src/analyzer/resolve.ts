/**
 * The bounded included-source graph and the Octokit receiver-provenance evaluator.
 *
 * This module decides one question: does a censused site's receiver provably originate from an
 * authorized Octokit constructor? It answers with a replayable chain of proof steps or with
 * explicit causes, and it is deliberately incapable of answering "no": failing to prove
 * provenance is uncertainty about the target program, never evidence that the receiver was
 * something else.
 *
 * Names are resolved by lexical binding identity, never by identifier text. Every file gets a
 * finite syntactic scope tree — source file, function-like bodies and their parameters, blocks,
 * catch clauses, and class bodies — and every binding fact, every alias initializer, every
 * private-field write, and every candidate receiver is attached to the scope it actually sits
 * in. A name resolves only to the nearest binding visible along its own ancestor-scope chain, so
 * a declaration in a sibling function, a nested function, or a block the use is not inside can
 * never establish provenance. Duplicate declarations of one binding identity, and any assignment
 * that resolves to it, withdraw its provenance instead of guessing which one won. This is
 * syntax only: there is no type checker, no `Program`, no module resolution, no control-flow
 * evaluation, and no interprocedural propagation.
 *
 * It never opens a file. Its entire universe is the map of already parsed included sources
 * `analyze.ts` hands it, so a specifier that names anything outside that map — a package, a
 * `node_modules` path, a build alias, a directory index — simply has no candidates. There is no
 * compiler module resolution, no package manifest, no `tsconfig`, and no evaluation of target
 * code.
 *
 * The authorized origin is exact and finite: the literal package specifier `octokit` and the
 * exact named export `Octokit`, entering a file either as a named ESM import or as the narrow
 * top-level immutable CommonJS destructuring form with an unshadowed `require`. That identity
 * may then travel only through immutable local aliases and explicit named relative forwarding,
 * and only a direct `new` on it produces a client. Plugins, subclasses, factories, wrappers,
 * containers, namespace members, default and dynamic imports, parameters, and mutable bindings
 * are all outside the grammar and each one has a stable cause.
 *
 * Every traversal is bounded by {@link RESOLUTION_LIMITS}. A budget that runs out blocks only
 * the chains that depended on it; independently resolved chains stay proven. A cycle is an
 * ordinary graph condition and terminates silently — it becomes a `relevant-resolution-cycle`
 * cause only when it is what actually stopped a required proof from reaching an answer.
 */

import ts from 'typescript';

import type { SourceSpan } from '../permission-model/model.js';

import type { CandidateSite } from './candidates.js';
import type { AnalyzerCauseCode, ProvenanceStep, ReceiverAccess, ReceiverOrigin, ReceiverProvenance } from './contract.js';
import { RELATIVE_SOURCE_CANDIDATE_RULES, RELATIVE_SOURCE_CANDIDATE_TABLE_ID, spanOfNode } from './parse.js';
import type { ParsedSource } from './parse.js';

/** Identity of the resolution and provenance policy implemented here. */
export const RESOLUTION_POLICY_IDENTITY = 'boundaryci/bounded-source-resolution@1';

/** The exact package specifier that may export an authorized Octokit constructor. */
const AUTHORIZED_PACKAGE_SPECIFIER = 'octokit';

/** The exact named export that may become an authorized Octokit constructor. */
const AUTHORIZED_EXPORT_NAME = 'Octokit';

/** The exact CommonJS binding whose shadowing withdraws every `require` fact in a file. */
const REQUIRE_BINDING = 'require';

/**
 * Finite per-proof budgets, all safe integers.
 *
 * These bound one receiver proof, not the scan: exhausting them makes the chains that needed
 * them incomplete and leaves every independently completed chain untouched.
 */
export const RESOLUTION_LIMITS: Readonly<{
  maxDepth: number;
  maxFiles: number;
  maxBytes: number;
  maxWork: number;
}> = Object.freeze({
  maxDepth: 24,
  maxFiles: 48,
  maxBytes: 8_000_000,
  maxWork: 2048,
});

/** One resolver-authored cause. `detail` describes this analyzer's boundary, never target text. */
export interface ResolverCause {
  readonly code: AnalyzerCauseCode;
  readonly path: string | null;
  readonly span: SourceSpan | null;
  readonly detail: string;
}

/**
 * The fixed analyzer-authored explanation for each cause this module can raise.
 *
 * Details are constant per code so that two dependent candidates blocked by the same construct
 * link to one deduplicated cause instead of to two differently worded copies of it.
 */
const RESOLVER_CAUSE_DETAILS: Readonly<Partial<Record<AnalyzerCauseCode, string>>> = Object.freeze({
  'ambiguous-relative-source':
    'a relative specifier matched several included sources under the fixed candidate table and was not resolved',
  'invalidated-private-field':
    'a private client field received a second or unsupported write, which withdraws its provenance',
  'mutable-provenance-binding': 'the binding is reassigned or declared more than once and cannot carry provenance',
  'relevant-resolution-cycle': 'a resolution cycle prevented this provenance question from reaching a determinate answer',
  'resolution-byte-limit': 'the per-proof source-byte budget stopped this provenance chain',
  'resolution-depth-limit': 'the per-proof resolution-depth budget stopped this provenance chain',
  'resolution-file-limit': 'the per-proof source-file budget stopped this provenance chain',
  'resolution-work-limit': 'the per-proof resolution-work budget stopped this provenance chain',
  'unproven-octokit-origin': 'the value was not proven to originate from the authorized Octokit package export',
  'unresolved-relative-source':
    'a relative specifier matched no included source under the fixed candidate table and was not resolved',
  'unsupported-commonjs-form': 'the CommonJS form is outside the narrow top-level immutable require subset',
  'unsupported-export-form': 'the export form is outside the explicit named export and re-export grammar',
  'unsupported-import-form': 'the import form is outside the explicit named import grammar',
  'unsupported-object-state': 'object state other than a single-assignment private instance field cannot carry provenance',
  'unsupported-octokit-constructor': 'the constructor is derived rather than the authorized constructor applied with new',
});

function cause(code: AnalyzerCauseCode, path: string | null, span: SourceSpan | null): ResolverCause {
  return {
    code,
    span: path === null ? null : span,
    path,
    detail: RESOLVER_CAUSE_DETAILS[code] ?? 'this provenance question did not reach a determinate answer',
  };
}

/* ------------------------------------------------------------------ *
 * Lexical scopes.
 * ------------------------------------------------------------------ */

/** The ordinal of every file's source-file scope, which is also its module scope. */
const MODULE_SCOPE_ID = 0;

/**
 * The finite scope classes JavaScript and TypeScript lexical binding needs here.
 *
 * `function` covers every function-like body together with its parameter list, because a
 * parameter and a body binding of the same name are the same binding identity for this grammar.
 * `block` covers ordinary blocks and the three `for` headers, which bind their own `let`/`const`.
 * `class-body` exists because a named class expression binds its own name inside itself, and
 * because a field initializer is evaluated there.
 */
type ScopeKind = 'block' | 'catch-clause' | 'class-body' | 'function' | 'source-file';

/**
 * One lexical scope, identified by its ordinal in a file's deterministic pre-order walk.
 *
 * `start` and `end` are UTF-16 offsets into the exact parser text. Scopes nest strictly and
 * siblings never overlap, so the last scope in pre-order that contains an offset is the
 * innermost scope at that offset.
 */
interface ScopeRecord {
  readonly id: number;
  readonly parent: number | null;
  readonly kind: ScopeKind;
  readonly start: number;
  readonly end: number;
  /** Whether `var` and other function-scoped declarations land here. */
  readonly holdsVarDeclarations: boolean;
}

/* ------------------------------------------------------------------ *
 * Graph facts.
 * ------------------------------------------------------------------ */

/** What a binding was bound to, as far as this finite grammar describes it. */
type BindingFact =
  | { readonly kind: 'call'; readonly calleeName: string; readonly span: SourceSpan }
  | { readonly kind: 'construction'; readonly constructorName: string; readonly span: SourceSpan }
  | { readonly kind: 'local-alias'; readonly span: SourceSpan; readonly target: string }
  | { readonly kind: 'named-import'; readonly importedName: string; readonly span: SourceSpan; readonly specifier: string }
  | { readonly kind: 'private-alias'; readonly classStart: number | null; readonly field: string; readonly span: SourceSpan }
  | { readonly kind: 'require-named'; readonly importedName: string; readonly span: SourceSpan; readonly specifier: string }
  | { readonly kind: 'require-namespace'; readonly span: SourceSpan; readonly specifier: string }
  | { readonly kind: 'unsupported'; readonly code: AnalyzerCauseCode; readonly span: SourceSpan };

/**
 * One binding identity: a name declared in one scope.
 *
 * `declarations` counts every declaration of this identity, and `mutated` records whether any
 * assignment anywhere in the file resolved to it. Either one above its immutable value makes the
 * binding unusable for provenance, because this analyzer performs no control-flow or ordering
 * reasoning that could decide which value a later use would see.
 */
interface BindingRecord {
  readonly scopeId: number;
  readonly name: string;
  declarations: number;
  mutated: boolean;
  fact: BindingFact;
  readonly span: SourceSpan;
}

/** How a file explicitly exports one name. Anything not listed here is not an explicit export. */
type ExportFact =
  | { readonly kind: 'local'; readonly local: string; readonly span: SourceSpan }
  | { readonly kind: 'reexport'; readonly importedName: string; readonly span: SourceSpan; readonly specifier: string }
  | { readonly kind: 'unsupported'; readonly code: AnalyzerCauseCode; readonly span: SourceSpan };

/**
 * One write to a private instance field, and the shape of the value it wrote.
 *
 * `valueScope` is the scope the written expression was evaluated in, so a constructor-local
 * alias resolves against the constructor body rather than against the file.
 */
interface PrivateWrite {
  readonly form: 'constructor-assignment' | 'field-initializer' | 'unsupported-assignment';
  readonly value:
    | { readonly kind: 'identifier'; readonly name: string }
    | { readonly kind: 'new'; readonly name: string }
    | { readonly kind: 'unsupported' };
  readonly valueScope: number;
  readonly span: SourceSpan;
}

interface PrivateFieldFacts {
  declarations: number;
  isStatic: boolean;
  readonly writes: PrivateWrite[];
  span: SourceSpan;
}

interface ClassFacts {
  readonly start: number;
  readonly fields: Map<string, PrivateFieldFacts>;
}

interface FileFacts {
  readonly path: string;
  readonly parsed: ParsedSource;
  readonly byteSize: number;
  /** Every scope of this file, in deterministic pre-order; index equals {@link ScopeRecord.id}. */
  readonly scopes: ScopeRecord[];
  /** Binding identities, keyed by declaring scope and name. */
  readonly bindings: Map<string, BindingRecord>;
  readonly exports: Map<string, ExportFact>;
  readonly classes: Map<number, ClassFacts>;
  requireShadowed: boolean;
  usesCommonJsExports: boolean;
  hasExportStar: boolean;
}

/** The finite included-source graph one analysis request resolves against. */
export interface SourceGraph {
  readonly policyId: string;
  readonly files: ReadonlyMap<string, FileFacts>;
}

/* ------------------------------------------------------------------ *
 * Scope and binding lookup.
 * ------------------------------------------------------------------ */

/**
 * The key of one binding identity: a scope ordinal and a name.
 *
 * `:` cannot occur in a JavaScript identifier or private name, and a scope ordinal is decimal
 * digits, so the split point is unambiguous and the key stays ordinary printable source-safe
 * text rather than a control character embedded in this module's own source.
 */
function bindingKey(scopeId: number, name: string): string {
  return `${String(scopeId)}:${name}`;
}

/**
 * Builds one resolution-stack key from parts that may contain anything, including separators.
 *
 * Every part is length-prefixed, so no path, name, or ordinal can imitate the boundary between
 * two parts. A cycle key that could collide would either invent a cycle that does not exist or
 * miss one that does, and both would be wrong evidence about the target program.
 */
function stackKey(kind: string, ...parts: readonly string[]): string {
  let key = kind;
  for (const part of parts) key += `|${String(part.length)}:${part}`;
  return key;
}

/**
 * Returns the innermost scope containing `offset`.
 *
 * Scopes are recorded in pre-order and nest strictly, so the last containing scope is the
 * innermost one. An offset outside every scope answers the module scope, which is the file's
 * outermost binding environment.
 */
function scopeAtOffset(file: FileFacts, offset: number): number {
  let innermost = MODULE_SCOPE_ID;
  for (const scope of file.scopes) {
    if (offset >= scope.start && offset < scope.end) innermost = scope.id;
  }
  return innermost;
}

/**
 * Resolves one name to the nearest binding visible from `scopeId`, or `null` when the name is
 * not bound anywhere in its own ancestor-scope chain.
 *
 * This is the entire name-resolution rule. A declaration in a sibling scope, a descendant scope,
 * or an unrelated function is never visible here, so identifier text alone can never establish
 * provenance.
 */
function lookupBinding(file: FileFacts, scopeId: number, name: string): BindingRecord | null {
  let scope = scopeById(file, scopeId);
  while (scope !== undefined) {
    const record = file.bindings.get(bindingKey(scope.id, name));
    if (record !== undefined) return record;
    scope = parentScopeOf(file, scope);
  }
  return null;
}

/** The nearest scope that receives `var` and other function-scoped declarations. */
function variableScopeOf(file: FileFacts, scopeId: number): number {
  let scope = scopeById(file, scopeId);
  while (scope !== undefined) {
    if (scope.holdsVarDeclarations) return scope.id;
    scope = parentScopeOf(file, scope);
  }
  return MODULE_SCOPE_ID;
}

/** The scope with this ordinal, or `undefined` when the file has no such scope. */
function scopeById(file: FileFacts, scopeId: number): ScopeRecord | undefined {
  return file.scopes[scopeId];
}

/** The enclosing scope of `scope`, or `undefined` at the module scope, which has no parent. */
function parentScopeOf(file: FileFacts, scope: ScopeRecord): ScopeRecord | undefined {
  return scope.parent === null ? undefined : file.scopes[scope.parent];
}

/* ------------------------------------------------------------------ *
 * Graph construction.
 * ------------------------------------------------------------------ */

function isAssignmentOperator(kind: ts.SyntaxKind): boolean {
  return kind >= ts.SyntaxKind.FirstAssignment && kind <= ts.SyntaxKind.LastAssignment;
}

function stringLiteralText(node: ts.Node | undefined): string | null {
  if (node === undefined) return null;
  return ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node) ? node.text : null;
}

function hasModifier(node: ts.Node, kind: ts.SyntaxKind): boolean {
  return ts.canHaveModifiers(node) && (ts.getModifiers(node) ?? []).some((modifier) => modifier.kind === kind);
}

/** Recognizes `require('<literal>')` with exactly one string-literal argument. */
function requireSpecifier(expression: ts.Expression): string | null {
  if (!ts.isCallExpression(expression)) return null;
  if (!ts.isIdentifier(expression.expression) || expression.expression.text !== REQUIRE_BINDING) return null;
  if (expression.arguments.length !== 1) return null;
  return stringLiteralText(expression.arguments[0]);
}

/** Recognizes a dynamic `import('…')`, including one awaited in a declaration initializer. */
function isDynamicImport(expression: ts.Expression): boolean {
  const inner = ts.isAwaitExpression(expression) ? expression.expression : expression;
  return ts.isCallExpression(inner) && inner.expression.kind === ts.SyntaxKind.ImportKeyword;
}

function privateWriteValue(expression: ts.Expression): PrivateWrite['value'] {
  if (ts.isNewExpression(expression) && ts.isIdentifier(expression.expression)) {
    return { kind: 'new', name: expression.expression.text };
  }
  if (ts.isIdentifier(expression)) return { kind: 'identifier', name: expression.text };
  return { kind: 'unsupported' };
}

/** Visits every identifier a binding name introduces, through nested destructuring patterns. */
function forEachBoundName(name: ts.BindingName, visit: (identifier: ts.Identifier) => void): void {
  if (ts.isIdentifier(name)) {
    visit(name);
    return;
  }
  for (const element of name.elements) {
    if (ts.isOmittedExpression(element)) continue;
    forEachBoundName(element.name, visit);
  }
}

/** The scope class a node introduces, or `null` when it introduces no binding environment. */
function scopeKindFor(node: ts.Node): ScopeKind | null {
  if (ts.isSourceFile(node)) return 'source-file';
  if (
    ts.isFunctionDeclaration(node) ||
    ts.isFunctionExpression(node) ||
    ts.isArrowFunction(node) ||
    ts.isMethodDeclaration(node) ||
    ts.isConstructorDeclaration(node) ||
    ts.isGetAccessorDeclaration(node) ||
    ts.isSetAccessorDeclaration(node) ||
    ts.isClassStaticBlockDeclaration(node)
  ) {
    return 'function';
  }
  if (ts.isClassDeclaration(node) || ts.isClassExpression(node)) return 'class-body';
  if (ts.isCatchClause(node)) return 'catch-clause';
  if (
    ts.isBlock(node) ||
    ts.isModuleBlock(node) ||
    ts.isCaseBlock(node) ||
    ts.isForStatement(node) ||
    ts.isForInStatement(node) ||
    ts.isForOfStatement(node)
  ) {
    return 'block';
  }
  return null;
}

/** Traversal context: the enclosing scope, class body, and constructor body of a node. */
interface WalkContext {
  readonly scopeId: number;
  readonly classStart: number | null;
  readonly inConstructor: boolean;
}

/** One name-mutating use, resolved to its binding identity after the scope tree is complete. */
interface MutationUse {
  readonly scopeId: number;
  readonly name: string;
}

function collectFileFacts(parsed: ParsedSource): FileFacts {
  const facts: FileFacts = {
    path: parsed.record.path,
    parsed,
    byteSize: parsed.record.byteSize,
    scopes: [],
    bindings: new Map(),
    exports: new Map(),
    classes: new Map(),
    requireShadowed: false,
    usesCommonJsExports: false,
    hasExportStar: false,
  };
  const span = (node: ts.Node): SourceSpan => spanOfNode(parsed, node);
  const mutations: MutationUse[] = [];
  const createScope = (node: ts.Node, kind: ScopeKind, parent: number | null): number => {
    const id = facts.scopes.length;
    facts.scopes.push({
      id,
      parent,
      kind,
      start: kind === 'source-file' ? 0 : node.getStart(parsed.sourceFile),
      end: node.getEnd(),
      holdsVarDeclarations: kind === 'source-file' || kind === 'function',
    });
    return id;
  };

  const unsupportedFact = (code: AnalyzerCauseCode, node: ts.Node): BindingFact => ({
    kind: 'unsupported',
    code,
    span: span(node),
  });

  const declare = (scopeId: number, name: string, node: ts.Node, fact: BindingFact): void => {
    const key = bindingKey(scopeId, name);
    const existing = facts.bindings.get(key);
    if (existing === undefined) {
      facts.bindings.set(key, { scopeId, name, declarations: 1, mutated: false, fact, span: span(node) });
      return;
    }
    existing.declarations += 1;
  };

  /** Refines an already declared binding's fact; a duplicated identity keeps its conservative one. */
  const setFact = (scopeId: number, name: string, fact: BindingFact): void => {
    const record = facts.bindings.get(bindingKey(scopeId, name));
    if (record !== undefined && record.declarations === 1) record.fact = fact;
  };

  /** Records one explicit export name without selecting among duplicate declarations. */
  const recordExport = (name: string, fact: ExportFact): void => {
    if (facts.exports.has(name)) {
      facts.exports.set(name, {
        kind: 'unsupported',
        code: 'unsupported-export-form',
        span: fact.span,
      });
      return;
    }
    facts.exports.set(name, fact);
  };

  const fieldFacts = (classStart: number | null, field: string): PrivateFieldFacts | null => {
    if (classStart === null) return null;
    const classFacts = facts.classes.get(classStart);
    if (classFacts === undefined) return null;
    const existing = classFacts.fields.get(field);
    if (existing !== undefined) return existing;
    const created: PrivateFieldFacts = {
      declarations: 0,
      isStatic: false,
      writes: [],
      span: { start: { line: 1, column: 1 }, end: { line: 1, column: 1 } },
    };
    classFacts.fields.set(field, created);
    return created;
  };

  /** Records every name one assignment target writes, to be resolved to bindings afterwards. */
  const recordAssignmentTargets = (target: ts.Expression, scopeId: number): void => {
    if (ts.isIdentifier(target)) {
      mutations.push({ scopeId, name: target.text });
      return;
    }
    if (ts.isObjectLiteralExpression(target)) {
      for (const property of target.properties) {
        if (ts.isShorthandPropertyAssignment(property)) mutations.push({ scopeId, name: property.name.text });
        else if (ts.isPropertyAssignment(property)) recordAssignmentTargets(property.initializer, scopeId);
        else if (ts.isSpreadAssignment(property)) recordAssignmentTargets(property.expression, scopeId);
      }
      return;
    }
    if (ts.isArrayLiteralExpression(target)) {
      for (const element of target.elements) {
        if (!ts.isOmittedExpression(element)) recordAssignmentTargets(element, scopeId);
      }
      return;
    }
    if (ts.isSpreadElement(target)) {
      recordAssignmentTargets(target.expression, scopeId);
      return;
    }
    if (ts.isBinaryExpression(target) && target.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      recordAssignmentTargets(target.left, scopeId);
    }
  };

  /**
   * Records the immutable-binding shape of one `const` declarator in its declaring scope.
   *
   * `classStart` is the innermost class the declarator itself sits in, taken from the walk rather
   * than reconstructed later. A `const client = this.#client` alias is only meaningful together
   * with the class whose field it read, so the two facts are recorded at the same moment.
   */
  const bindConstDeclaration = (
    declaration: ts.VariableDeclaration,
    scopeId: number,
    classStart: number | null,
  ): void => {
    const initializer = declaration.initializer;
    if (initializer === undefined) return;
    const moduleScope = scopeId === MODULE_SCOPE_ID;

    if (ts.isObjectBindingPattern(declaration.name)) {
      const specifier = requireSpecifier(initializer);
      if (specifier === null) {
        if (!isDynamicImport(initializer)) return;
        for (const element of declaration.name.elements) {
          if (ts.isIdentifier(element.name)) {
            setFact(scopeId, element.name.text, unsupportedFact('unsupported-import-form', element));
          }
        }
        return;
      }
      for (const element of declaration.name.elements) {
        if (!ts.isIdentifier(element.name)) continue;
        const local = element.name.text;
        if (element.dotDotDotToken !== undefined || element.initializer !== undefined) {
          setFact(scopeId, local, unsupportedFact('unsupported-commonjs-form', element));
          continue;
        }
        const propertyName = element.propertyName ?? element.name;
        if (!ts.isIdentifier(propertyName) && !ts.isStringLiteral(propertyName)) {
          setFact(scopeId, local, unsupportedFact('unsupported-commonjs-form', element));
          continue;
        }
        // D-28 authorizes only the top-level form: a function-local `require` is not in the grammar.
        if (!moduleScope) {
          setFact(scopeId, local, unsupportedFact('unsupported-commonjs-form', element));
          continue;
        }
        setFact(scopeId, local, {
          kind: 'require-named',
          importedName: propertyName.text,
          specifier,
          span: span(element),
        });
      }
      return;
    }

    if (!ts.isIdentifier(declaration.name)) return;
    const local = declaration.name.text;

    const specifier = requireSpecifier(initializer);
    if (specifier !== null) {
      if (!moduleScope) setFact(scopeId, local, unsupportedFact('unsupported-commonjs-form', declaration));
      else setFact(scopeId, local, { kind: 'require-namespace', specifier, span: span(declaration) });
      return;
    }
    if (isDynamicImport(initializer)) {
      setFact(scopeId, local, unsupportedFact('unsupported-import-form', declaration));
      return;
    }
    if (ts.isIdentifier(initializer)) {
      setFact(scopeId, local, { kind: 'local-alias', target: initializer.text, span: span(declaration) });
      return;
    }
    if (ts.isNewExpression(initializer)) {
      if (ts.isIdentifier(initializer.expression)) {
        setFact(scopeId, local, {
          kind: 'construction',
          constructorName: initializer.expression.text,
          span: span(declaration),
        });
      } else {
        setFact(scopeId, local, unsupportedFact('unsupported-octokit-constructor', declaration));
      }
      return;
    }
    if (ts.isCallExpression(initializer) && ts.isIdentifier(initializer.expression)) {
      setFact(scopeId, local, { kind: 'call', calleeName: initializer.expression.text, span: span(declaration) });
      return;
    }
    // Only `this.#field` is an alias of bounded private state. A private access on any other
    // object is a different question this grammar does not answer, so it records no fact.
    if (
      ts.isPropertyAccessExpression(initializer) &&
      ts.isPrivateIdentifier(initializer.name) &&
      initializer.expression.kind === ts.SyntaxKind.ThisKeyword
    ) {
      setFact(scopeId, local, {
        kind: 'private-alias',
        field: initializer.name.text,
        classStart,
        span: span(declaration),
      });
    }
  };

  /** Declares every name one variable declaration list introduces, in its correct scope. */
  const declareVariableList = (
    list: ts.VariableDeclarationList,
    scopeId: number,
    classStart: number | null,
  ): void => {
    const isConst = (list.flags & ts.NodeFlags.Const) !== 0;
    const isLexical = isConst || (list.flags & ts.NodeFlags.Let) !== 0;
    const targetScope = isLexical ? scopeId : variableScopeOf(facts, scopeId);
    for (const declaration of list.declarations) {
      forEachBoundName(declaration.name, (identifier) => {
        declare(
          targetScope,
          identifier.text,
          identifier,
          unsupportedFact(isConst ? 'unproven-octokit-origin' : 'mutable-provenance-binding', identifier),
        );
      });
      if (isConst) bindConstDeclaration(declaration, targetScope, classStart);
    }
  };

  const visit = (node: ts.Node, context: WalkContext): void => {
    const kind = scopeKindFor(node);
    const scopeId =
      kind === null ? context.scopeId : createScope(node, kind, kind === 'source-file' ? null : context.scopeId);
    const classStart =
      ts.isClassDeclaration(node) || ts.isClassExpression(node) ? node.getStart(parsed.sourceFile) : context.classStart;

    if (ts.isClassDeclaration(node) || ts.isClassExpression(node)) {
      if (!facts.classes.has(classStart as number)) {
        facts.classes.set(classStart as number, { start: classStart as number, fields: new Map() });
      }
      // A class declaration binds its name outside itself; a class expression binds it within.
      if (node.name !== undefined) {
        const target = ts.isClassDeclaration(node) ? context.scopeId : scopeId;
        declare(target, node.name.text, node.name, unsupportedFact('unsupported-octokit-constructor', node.name));
      }
    } else if (ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node)) {
      if (node.name !== undefined) {
        const target = ts.isFunctionDeclaration(node) ? context.scopeId : scopeId;
        declare(target, node.name.text, node.name, unsupportedFact('unproven-octokit-origin', node.name));
      }
    } else if (ts.isParameter(node)) {
      forEachBoundName(node.name, (identifier) => {
        declare(scopeId, identifier.text, identifier, unsupportedFact('unproven-octokit-origin', identifier));
      });
    } else if (ts.isVariableDeclarationList(node)) {
      declareVariableList(node, scopeId, classStart);
    } else if (ts.isEnumDeclaration(node) || ts.isModuleDeclaration(node) || ts.isImportEqualsDeclaration(node)) {
      if (ts.isIdentifier(node.name)) {
        declare(context.scopeId, node.name.text, node.name, unsupportedFact('unproven-octokit-origin', node.name));
      }
    } else if (ts.isImportDeclaration(node)) {
      declareImport(node);
    }

    if (kind === 'catch-clause' && ts.isCatchClause(node) && node.variableDeclaration !== undefined) {
      forEachBoundName(node.variableDeclaration.name, (identifier) => {
        declare(scopeId, identifier.text, identifier, unsupportedFact('unproven-octokit-origin', identifier));
      });
    }

    if (ts.isBinaryExpression(node) && isAssignmentOperator(node.operatorToken.kind)) {
      recordAssignmentTargets(node.left, scopeId);
      if (ts.isPropertyAccessExpression(node.left) && ts.isPrivateIdentifier(node.left.name)) {
        const field = fieldFacts(context.classStart, node.left.name.text);
        if (field !== null) {
          const simple =
            node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
            node.left.expression.kind === ts.SyntaxKind.ThisKeyword &&
            context.inConstructor;
          field.writes.push({
            form: simple ? 'constructor-assignment' : 'unsupported-assignment',
            value: privateWriteValue(node.right),
            valueScope: scopeId,
            span: span(node),
          });
        }
      }
      // `module.exports = …` and `exports.name = …` are export semantics this analyzer does
      // not interpret; recording their presence keeps a dependent chain's cause exact.
      if (ts.isPropertyAccessExpression(node.left) && ts.isIdentifier(node.left.name)) {
        const target = node.left.expression;
        if (ts.isIdentifier(target) && (target.text === 'module' || target.text === 'exports')) {
          facts.usesCommonJsExports = true;
        }
      }
    } else if (
      (ts.isPrefixUnaryExpression(node) || ts.isPostfixUnaryExpression(node)) &&
      ts.isIdentifier(node.operand) &&
      (node.operator === ts.SyntaxKind.PlusPlusToken || node.operator === ts.SyntaxKind.MinusMinusToken)
    ) {
      mutations.push({ scopeId, name: node.operand.text });
    } else if (
      (ts.isForInStatement(node) || ts.isForOfStatement(node)) &&
      !ts.isVariableDeclarationList(node.initializer)
    ) {
      recordAssignmentTargets(node.initializer, scopeId);
    }

    if (ts.isPropertyDeclaration(node) && ts.isPrivateIdentifier(node.name)) {
      const field = fieldFacts(context.classStart, node.name.text);
      if (field !== null) {
        field.declarations += 1;
        field.isStatic = field.isStatic || hasModifier(node, ts.SyntaxKind.StaticKeyword);
        if (field.declarations === 1) field.span = span(node);
        if (node.initializer !== undefined) {
          field.writes.push({
            form: 'field-initializer',
            value: privateWriteValue(node.initializer),
            valueScope: scopeId,
            span: span(node),
          });
        }
      }
    }

    const next: WalkContext = {
      scopeId,
      classStart,
      // A write is constructor-local only in the constructor's own body. An arrow keeps `this`,
      // but its body runs somewhere this analyzer does not follow, so it is not that body.
      inConstructor: ts.isConstructorDeclaration(node)
        ? true
        : ts.isFunctionDeclaration(node) ||
            ts.isFunctionExpression(node) ||
            ts.isArrowFunction(node) ||
            ts.isMethodDeclaration(node) ||
            ts.isGetAccessorDeclaration(node) ||
            ts.isSetAccessorDeclaration(node) ||
            ts.isClassStaticBlockDeclaration(node) ||
            ts.isClassDeclaration(node) ||
            ts.isClassExpression(node)
          ? false
          : context.inConstructor,
    };

    ts.forEachChild(node, (child) => {
      visit(child, next);
    });
  };

  /** Declares the bindings of one import declaration in the module scope. */
  function declareImport(statement: ts.ImportDeclaration): void {
    const specifier = stringLiteralText(statement.moduleSpecifier);
    const clause = statement.importClause;
    if (clause === undefined || clause.isTypeOnly) return;
    if (clause.name !== undefined) {
      declare(
        MODULE_SCOPE_ID,
        clause.name.text,
        clause.name,
        unsupportedFact('unsupported-import-form', clause.name),
      );
    }
    const bindings = clause.namedBindings;
    if (bindings === undefined) return;
    if (ts.isNamespaceImport(bindings)) {
      declare(MODULE_SCOPE_ID, bindings.name.text, bindings.name, unsupportedFact('unsupported-import-form', bindings));
      return;
    }
    for (const element of bindings.elements) {
      if (element.isTypeOnly) continue;
      const fact: BindingFact =
        specifier === null
          ? unsupportedFact('unsupported-import-form', element)
          : {
              kind: 'named-import',
              specifier,
              importedName: element.propertyName?.text ?? element.name.text,
              span: span(element),
            };
      declare(MODULE_SCOPE_ID, element.name.text, element.name, fact);
    }
  }

  visit(parsed.sourceFile, { scopeId: MODULE_SCOPE_ID, classStart: null, inConstructor: false });

  for (const use of mutations) {
    const record = lookupBinding(facts, use.scopeId, use.name);
    if (record !== null) record.mutated = true;
  }

  // Module structure is read from top-level statements only: an export nested anywhere else is
  // not an export this analyzer interprets.
  for (const statement of parsed.sourceFile.statements) {
    if (ts.isExportDeclaration(statement)) {
      if (statement.isTypeOnly) continue;
      const specifier = stringLiteralText(statement.moduleSpecifier);
      const clause = statement.exportClause;
      if (clause === undefined) {
        facts.hasExportStar = true;
        continue;
      }
      if (ts.isNamespaceExport(clause)) {
        recordExport(clause.name.text, {
          kind: 'unsupported',
          code: 'unsupported-export-form',
          span: span(clause),
        });
        continue;
      }
      for (const element of clause.elements) {
        if (element.isTypeOnly) continue;
        const exported = element.name.text;
        const local = element.propertyName?.text ?? exported;
        if (specifier === null) recordExport(exported, { kind: 'local', local, span: span(element) });
        else recordExport(exported, { kind: 'reexport', specifier, importedName: local, span: span(element) });
      }
      continue;
    }

    if (ts.isExportAssignment(statement)) {
      recordExport('default', { kind: 'unsupported', code: 'unsupported-export-form', span: span(statement) });
      continue;
    }

    if (!hasModifier(statement, ts.SyntaxKind.ExportKeyword)) continue;
    const isDefault = hasModifier(statement, ts.SyntaxKind.DefaultKeyword);
    if (ts.isVariableStatement(statement)) {
      for (const declaration of statement.declarationList.declarations) {
        if (!ts.isIdentifier(declaration.name)) continue;
        recordExport(declaration.name.text, {
          kind: 'local',
          local: declaration.name.text,
          span: span(declaration),
        });
      }
      continue;
    }
    if (ts.isFunctionDeclaration(statement) || ts.isClassDeclaration(statement)) {
      if (isDefault || statement.name === undefined) {
        recordExport('default', { kind: 'unsupported', code: 'unsupported-export-form', span: span(statement) });
        continue;
      }
      recordExport(statement.name.text, { kind: 'local', local: statement.name.text, span: span(statement) });
    }
  }

  // Only a module-scope binding can shadow the top-level CommonJS binding at one of the
  // authorized top-level require sites. A same-named declaration in a nested sibling scope is
  // not visible there and must not withdraw otherwise valid provenance.
  facts.requireShadowed = facts.bindings.has(bindingKey(MODULE_SCOPE_ID, REQUIRE_BINDING));
  return facts;
}

/**
 * Builds the request-local source graph from exactly the successfully parsed included sources.
 *
 * Files that failed to decode or parse are absent by construction, so a chain that needed one
 * of them finds no candidate and becomes incomplete rather than silently resolving elsewhere.
 */
export function buildSourceGraph(sources: Iterable<ParsedSource>): SourceGraph {
  const files = new Map<string, FileFacts>();
  for (const parsed of sources) files.set(parsed.record.path, collectFileFacts(parsed));
  return { policyId: RESOLUTION_POLICY_IDENTITY, files };
}

/* ------------------------------------------------------------------ *
 * Relative-source resolution.
 * ------------------------------------------------------------------ */

type RelativeResolution =
  | { readonly status: 'ambiguous' }
  | { readonly status: 'resolved'; readonly path: string; readonly ruleRow: number }
  | { readonly status: 'unresolved' };

function isRelativeSpecifier(specifier: string): boolean {
  return specifier.startsWith('./') || specifier.startsWith('../');
}

/**
 * Normalizes a relative specifier against the importing file's directory.
 *
 * Returns `null` when the result would leave the analysis root, because a path above the root
 * is outside the declared source universe and there is nothing there to resolve against.
 */
function normalizeRelative(fromPath: string, specifier: string): string | null {
  const segments = fromPath.split('/').slice(0, -1);
  for (const part of specifier.split('/')) {
    if (part === '' || part === '.') continue;
    if (part === '..') {
      if (segments.length === 0) return null;
      segments.pop();
      continue;
    }
    segments.push(part);
  }
  return segments.length === 0 ? null : segments.join('/');
}

/**
 * Applies exactly one row of {@link RELATIVE_SOURCE_CANDIDATE_RULES} to a normalized target.
 *
 * The row is selected by the specifier's literal trailing extension, or by the extensionless
 * row when the final segment has none. An extension with no row yields no candidates at all —
 * there is no fallback, no Node-style precedence, and no directory or `index` probing.
 */
function candidatePathsFor(target: string): { readonly paths: readonly string[]; readonly ruleRow: number } | null {
  const base = target.slice(target.lastIndexOf('/') + 1);
  const dot = base.lastIndexOf('.');
  const extension = dot > 0 ? base.slice(dot) : '';
  const ruleRow = RELATIVE_SOURCE_CANDIDATE_RULES.findIndex((rule) => rule.specifierExtension === extension);
  const rule = RELATIVE_SOURCE_CANDIDATE_RULES[ruleRow];
  if (rule === undefined) return null;
  const stem = extension === '' ? target : target.slice(0, target.length - extension.length);
  return { paths: rule.eligibleCandidateExtensions.map((suffix) => `${stem}${suffix}`), ruleRow };
}

/**
 * Resolves one literal relative specifier to exactly one included source, or to nothing.
 *
 * Exactly one included candidate is required. Zero and several are different facts and stay
 * different causes, so a dependent chain never quietly picks a winner.
 */
function resolveRelativeSource(graph: SourceGraph, fromPath: string, specifier: string): RelativeResolution {
  const target = normalizeRelative(fromPath, specifier);
  if (target === null) return { status: 'unresolved' };
  const candidates = candidatePathsFor(target);
  if (candidates === null) return { status: 'unresolved' };
  const matches = candidates.paths.filter((path) => graph.files.has(path));
  if (matches.length > 1) return { status: 'ambiguous' };
  const only = matches[0];
  if (only === undefined) return { status: 'unresolved' };
  return { status: 'resolved', path: only, ruleRow: candidates.ruleRow };
}

/* ------------------------------------------------------------------ *
 * Static values and proof steps.
 * ------------------------------------------------------------------ */

/** An authorized constructor identity and the chain that carried it to one binding. */
export interface ConstructorProof {
  readonly origin: ReceiverOrigin;
  readonly packageSpecifier: string;
  readonly exportName: string;
  readonly binding: string;
  readonly aliasChain: readonly string[];
  readonly steps: readonly ProvenanceStep[];
}

/** A client proven by a direct `new` on an authorized constructor. */
export interface ClientProof {
  readonly constructor: ConstructorProof;
  readonly clientBinding: string;
  readonly clientAliasChain: readonly string[];
  readonly steps: readonly ProvenanceStep[];
}

/** The finite lattice one binding can resolve to. `unknown` is uncertainty, never irrelevance. */
export type StaticValue =
  | { readonly kind: 'octokit-client'; readonly client: ClientProof }
  | { readonly kind: 'octokit-constructor'; readonly constructor: ConstructorProof }
  | { readonly kind: 'unknown'; readonly causes: readonly ResolverCause[] };

function unknown(...causes: readonly ResolverCause[]): StaticValue {
  return { kind: 'unknown', causes };
}

function step(
  kind: ProvenanceStep['kind'],
  path: string,
  span: SourceSpan,
  binding: string,
  specifier: string | null = null,
): ProvenanceStep {
  return { kind, path, span, binding, specifier, resolvedPath: null, ruleId: null, ruleRow: null };
}

function relativeStep(
  path: string,
  span: SourceSpan,
  binding: string,
  specifier: string,
  resolvedPath: string,
  ruleRow: number,
): ProvenanceStep {
  return {
    kind: 'relative-source-resolution',
    path,
    span,
    binding,
    specifier,
    resolvedPath,
    ruleId: RELATIVE_SOURCE_CANDIDATE_TABLE_ID,
    ruleRow,
  };
}

/** Extends a resolved value with the local name that forwarded it, preserving the origin. */
function extendValue(value: StaticValue, localName: string, extraSteps: readonly ProvenanceStep[]): StaticValue {
  if (value.kind === 'octokit-constructor') {
    return {
      kind: 'octokit-constructor',
      constructor: {
        ...value.constructor,
        aliasChain: [...value.constructor.aliasChain, localName],
        steps: [...value.constructor.steps, ...extraSteps],
      },
    };
  }
  if (value.kind === 'octokit-client') {
    return {
      kind: 'octokit-client',
      client: {
        ...value.client,
        clientAliasChain: [...value.client.clientAliasChain, localName],
        steps: [...value.client.steps, ...extraSteps],
      },
    };
  }
  return value;
}

/* ------------------------------------------------------------------ *
 * Bounded resolution.
 * ------------------------------------------------------------------ */

interface Budget {
  work: number;
  bytes: number;
  readonly files: Set<string>;
}

function newBudget(): Budget {
  return { work: 0, bytes: 0, files: new Set() };
}

/** Charges one file's bytes and its slot the first time a proof enters it. */
function enterFile(file: FileFacts, budget: Budget): ResolverCause | null {
  if (budget.files.has(file.path)) return null;
  if (budget.files.size + 1 > RESOLUTION_LIMITS.maxFiles) return cause('resolution-file-limit', file.path, null);
  if (budget.bytes + file.byteSize > RESOLUTION_LIMITS.maxBytes) return cause('resolution-byte-limit', file.path, null);
  budget.files.add(file.path);
  budget.bytes += file.byteSize;
  return null;
}

interface ResolutionState {
  readonly graph: SourceGraph;
  readonly budget: Budget;
  readonly stack: string[];
}

function charge(state: ResolutionState, path: string): ResolverCause | null {
  state.budget.work += 1;
  if (state.budget.work > RESOLUTION_LIMITS.maxWork) return cause('resolution-work-limit', path, null);
  if (state.stack.length > RESOLUTION_LIMITS.maxDepth) return cause('resolution-depth-limit', path, null);
  return null;
}

/**
 * Resolves one name as seen from one lexical scope.
 *
 * The scope decides which binding the name denotes. A name that is not bound in that scope's own
 * ancestor chain is unresolved here even when the file declares it somewhere else entirely.
 */
function resolveName(state: ResolutionState, path: string, scopeId: number, name: string): StaticValue {
  const exhausted = charge(state, path);
  if (exhausted !== null) return unknown(exhausted);
  const file = state.graph.files.get(path);
  if (file === undefined) return unknown(cause('unresolved-relative-source', null, null));
  const blocked = enterFile(file, state.budget);
  if (blocked !== null) return unknown(blocked);

  const record = lookupBinding(file, scopeId, name);
  if (record === null) return unknown(cause('unproven-octokit-origin', path, null));

  const key = stackKey('binding', path, String(record.scopeId), name);
  if (state.stack.includes(key)) return unknown(cause('relevant-resolution-cycle', path, null));
  state.stack.push(key);
  try {
    return resolveBindingRecord(state, file, record);
  } finally {
    state.stack.pop();
  }
}

function resolveBindingRecord(state: ResolutionState, file: FileFacts, record: BindingRecord): StaticValue {
  const path = file.path;
  const name = record.name;
  // Several declarations of one binding identity, or any assignment that resolves to it, leave
  // this analyzer without a single immutable value to reason about.
  if (record.declarations > 1 || record.mutated) {
    return unknown(cause('mutable-provenance-binding', path, record.span));
  }

  const fact = record.fact;
  switch (fact.kind) {
    case 'named-import':
    case 'require-named': {
      const isRequire = fact.kind === 'require-named';
      if (isRequire && file.requireShadowed) return unknown(cause('unsupported-commonjs-form', path, fact.span));
      const stepKind = isRequire ? 'require-destructuring' : 'named-import';
      if (fact.specifier === AUTHORIZED_PACKAGE_SPECIFIER && fact.importedName === AUTHORIZED_EXPORT_NAME) {
        return {
          kind: 'octokit-constructor',
          constructor: {
            origin: isRequire ? 'octokit-package-require-destructuring' : 'octokit-package-named-import',
            packageSpecifier: AUTHORIZED_PACKAGE_SPECIFIER,
            exportName: AUTHORIZED_EXPORT_NAME,
            binding: name,
            aliasChain: [name],
            steps: [step(stepKind, path, fact.span, name, fact.specifier)],
          },
        };
      }
      if (!isRelativeSpecifier(fact.specifier)) return unknown(cause('unproven-octokit-origin', path, fact.span));
      const resolved = resolveRelativeSource(state.graph, path, fact.specifier);
      if (resolved.status !== 'resolved') {
        const code: AnalyzerCauseCode =
          resolved.status === 'ambiguous' ? 'ambiguous-relative-source' : 'unresolved-relative-source';
        return unknown(cause(code, path, fact.span));
      }
      const inner = resolveExport(state, resolved.path, fact.importedName);
      return extendValue(inner, name, [
        relativeStep(path, fact.span, fact.importedName, fact.specifier, resolved.path, resolved.ruleRow),
        step(stepKind, path, fact.span, name, fact.specifier),
      ]);
    }
    case 'require-namespace':
      return unknown(cause('unsupported-commonjs-form', path, fact.span));
    case 'local-alias': {
      const inner = resolveName(state, path, record.scopeId, fact.target);
      return extendValue(inner, name, [step('local-alias', path, fact.span, name)]);
    }
    case 'construction': {
      const inner = resolveName(state, path, record.scopeId, fact.constructorName);
      if (inner.kind === 'octokit-constructor') {
        return {
          kind: 'octokit-client',
          client: {
            constructor: inner.constructor,
            clientBinding: name,
            clientAliasChain: [name],
            steps: [...inner.constructor.steps, step('direct-new', path, fact.span, name)],
          },
        };
      }
      if (inner.kind === 'octokit-client') return unknown(cause('unsupported-octokit-constructor', path, fact.span));
      return inner;
    }
    case 'call': {
      const inner = resolveName(state, path, record.scopeId, fact.calleeName);
      // A proven constructor invoked without `new`, or wrapped in a factory, is not a client.
      if (inner.kind !== 'unknown') return unknown(cause('unsupported-octokit-constructor', path, fact.span));
      return unknown(cause('unproven-octokit-origin', path, fact.span));
    }
    case 'private-alias': {
      const inner = provePrivateField(state, path, fact.classStart, fact.field);
      return extendValue(inner, name, [step('private-field-access', path, fact.span, name)]);
    }
    case 'unsupported':
      return unknown(cause(fact.code, path, fact.span));
  }
}

function resolveExport(state: ResolutionState, path: string, exportName: string): StaticValue {
  const exhausted = charge(state, path);
  if (exhausted !== null) return unknown(exhausted);
  const file = state.graph.files.get(path);
  if (file === undefined) return unknown(cause('unresolved-relative-source', null, null));
  const blocked = enterFile(file, state.budget);
  if (blocked !== null) return unknown(blocked);

  const key = stackKey('export', path, exportName);
  if (state.stack.includes(key)) return unknown(cause('relevant-resolution-cycle', path, null));
  state.stack.push(key);
  try {
    const fact = file.exports.get(exportName);
    if (fact === undefined) {
      // No explicit named export carries this name. Reconstructing one from `export *` or from
      // CommonJS export mutation is outside the grammar, and each stays its own causal class.
      const code: AnalyzerCauseCode = file.usesCommonJsExports ? 'unsupported-commonjs-form' : 'unsupported-export-form';
      return unknown(cause(code, path, null));
    }
    if (fact.kind === 'unsupported') return unknown(cause(fact.code, path, fact.span));
    if (fact.kind === 'local') {
      const inner = resolveName(state, path, MODULE_SCOPE_ID, fact.local);
      if (inner.kind === 'unknown') return inner;
      return extendStepsOnly(inner, [step('named-export', path, fact.span, exportName)]);
    }
    if (!isRelativeSpecifier(fact.specifier)) return unknown(cause('unsupported-export-form', path, fact.span));
    const resolved = resolveRelativeSource(state.graph, path, fact.specifier);
    if (resolved.status !== 'resolved') {
      const code: AnalyzerCauseCode =
        resolved.status === 'ambiguous' ? 'ambiguous-relative-source' : 'unresolved-relative-source';
      return unknown(cause(code, path, fact.span));
    }
    const inner = resolveExport(state, resolved.path, fact.importedName);
    if (inner.kind === 'unknown') return inner;
    return extendStepsOnly(inner, [
      relativeStep(path, fact.span, fact.importedName, fact.specifier, resolved.path, resolved.ruleRow),
      step('named-reexport', path, fact.span, exportName),
    ]);
  } finally {
    state.stack.pop();
  }
}

/** Appends proof steps without adding an alias name, for edges that forward rather than rename. */
function extendStepsOnly(value: StaticValue, extraSteps: readonly ProvenanceStep[]): StaticValue {
  if (value.kind === 'octokit-constructor') {
    return {
      kind: 'octokit-constructor',
      constructor: { ...value.constructor, steps: [...value.constructor.steps, ...extraSteps] },
    };
  }
  if (value.kind === 'octokit-client') {
    return { kind: 'octokit-client', client: { ...value.client, steps: [...value.client.steps, ...extraSteps] } };
  }
  return value;
}

/**
 * Proves one ECMAScript private instance field, or explains exactly why it cannot be proven.
 *
 * The rule is deliberately narrow: the field must be declared once, non-static, in the class the
 * access sits in, and must receive exactly one supported write — a field initializer or a simple
 * `this.#field = …` assignment in that class's constructor — whose value already carries proven
 * Octokit provenance in the scope that write was evaluated in. A second write, or a write this
 * grammar does not describe, withdraws the provenance instead of tolerating it, and no
 * method-order or path-sensitive reasoning is used to argue that one write happens before
 * another.
 */
function provePrivateField(
  state: ResolutionState,
  path: string,
  classStart: number | null,
  field: string,
): StaticValue {
  const exhausted = charge(state, path);
  if (exhausted !== null) return unknown(exhausted);
  const file = state.graph.files.get(path);
  if (file === undefined) return unknown(cause('unresolved-relative-source', null, null));
  const blocked = enterFile(file, state.budget);
  if (blocked !== null) return unknown(blocked);

  const classFacts = classStart === null ? undefined : file.classes.get(classStart);
  const facts = classFacts?.fields.get(field);
  if (facts === undefined || facts.declarations !== 1 || facts.isStatic) {
    return unknown(cause('unsupported-object-state', path, facts?.span ?? null));
  }
  if (facts.writes.length > 1) return unknown(cause('invalidated-private-field', path, facts.span));
  const write = facts.writes[0];
  if (write === undefined) return unknown(cause('unproven-octokit-origin', path, facts.span));
  if (write.form === 'unsupported-assignment') return unknown(cause('invalidated-private-field', path, write.span));
  if (write.value.kind === 'unsupported') return unknown(cause('unsupported-object-state', path, write.span));

  const key = stackKey('field', path, String(classStart), field);
  if (state.stack.includes(key)) return unknown(cause('relevant-resolution-cycle', path, facts.span));
  state.stack.push(key);
  try {
    const inner = resolveName(state, path, write.valueScope, write.value.name);
    // The field's own form was supported; what stayed open is the value that was written into
    // it, so the written value's causes are the exact evidence and nothing is added to them.
    if (inner.kind === 'unknown') return inner;
    const assignment = step('private-field-assignment', path, write.span, field);
    if (write.value.kind === 'new') {
      if (inner.kind !== 'octokit-constructor') return unknown(cause('unsupported-octokit-constructor', path, write.span));
      return {
        kind: 'octokit-client',
        client: {
          constructor: inner.constructor,
          clientBinding: field,
          clientAliasChain: [field],
          steps: [...inner.constructor.steps, step('direct-new', path, write.span, field), assignment],
        },
      };
    }
    if (inner.kind !== 'octokit-client') return unknown(cause('unsupported-octokit-constructor', path, write.span));
    return extendValue(inner, field, [assignment]);
  } finally {
    state.stack.pop();
  }
}

/* ------------------------------------------------------------------ *
 * Public evaluation surface.
 * ------------------------------------------------------------------ */

/**
 * Resolves one module-scope name of one included source to the finite value lattice, under a
 * fresh per-call budget.
 *
 * The module scope is the only scope a caller outside this module can name portably; a name
 * bound inside a function or block is reached through {@link proveCandidateReceiver}, which
 * carries the exact position of the use. Every call is independent: no memo, frontier, or
 * counter survives it, so repeated and concurrent analyses cannot perturb one another's answers.
 */
export function resolveStaticValue(graph: SourceGraph, path: string, name: string): StaticValue {
  return resolveName({ graph, budget: newBudget(), stack: [] }, path, MODULE_SCOPE_ID, name);
}

/** The outcome of proving one censused site's receiver. */
export type ReceiverProofResult =
  | { readonly status: 'proven'; readonly provenance: ReceiverProvenance }
  | { readonly status: 'unproven'; readonly causes: readonly ResolverCause[] };

function provenanceOf(client: ClientProof, access: ReceiverAccess): ReceiverProvenance {
  return {
    origin: client.constructor.origin,
    packageSpecifier: client.constructor.packageSpecifier,
    exportName: client.constructor.exportName,
    constructorBinding: client.constructor.binding,
    constructorAliasChain: [...client.constructor.aliasChain],
    construction: 'direct-new',
    clientBinding: client.clientBinding,
    clientAliasChain: [...client.clientAliasChain],
    access,
    steps: client.steps.map((entry) => ({ ...entry })),
  };
}

/**
 * Proves the receiver of one censused site, independently of whether its call grammar is
 * supported.
 *
 * An identifier receiver is resolved from the innermost scope at the exact position the census
 * recorded for it, so the same spelling in two different scopes is two different questions.
 *
 * A proven receiver is necessary but never sufficient: the caller still has to establish an
 * authorized call grammar and an exact pinned operation identity before anything becomes an
 * observation.
 */
export function proveCandidateReceiver(graph: SourceGraph, site: CandidateSite): ReceiverProofResult {
  const state: ResolutionState = { graph, budget: newBudget(), stack: [] };
  const receiver = site.receiver;

  if (receiver.form === 'this-property') {
    return { status: 'unproven', causes: [cause('unsupported-object-state', site.path, site.span)] };
  }
  if (receiver.form === 'expression') {
    return { status: 'unproven', causes: [cause('unproven-octokit-origin', site.path, site.span)] };
  }

  const file = graph.files.get(site.path);
  const useScope = file === undefined ? MODULE_SCOPE_ID : scopeAtOffset(file, site.receiverStart);
  const value =
    receiver.form === 'identifier'
      ? resolveName(state, site.path, useScope, receiver.name)
      : provePrivateField(state, site.path, site.enclosingClassStart, receiver.field);

  if (value.kind === 'octokit-client') {
    const access: ReceiverAccess = receiver.form === 'private-field' ? 'private-instance-field' : 'local-binding';
    return { status: 'proven', provenance: provenanceOf(value.client, access) };
  }
  if (value.kind === 'octokit-constructor') {
    return { status: 'unproven', causes: [cause('unsupported-octokit-constructor', site.path, site.span)] };
  }
  return { status: 'unproven', causes: value.causes };
}
