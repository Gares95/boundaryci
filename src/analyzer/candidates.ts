/**
 * The independent anchored candidate census.
 *
 * This module answers one question: which syntactic sites in a parsed file raise an analysis
 * obligation? It answers it *before* any receiver is proven, and it never asks the resolver
 * anything, so a matcher gap in the provenance evaluator can never turn a relevant site into
 * silent absence. Every site it returns must later receive exactly one terminal classification.
 *
 * The census is anchored, not name-based. A bare `rest`, `request`, `octokit`, `create`, or
 * `on` somewhere in a file is not an obligation; the anchor is always a syntactic position:
 *
 * - `direct-endpoint`        `<receiver>.rest.<scope>.<method>(...)` with static member names;
 * - `static-bracket-member`  the same chain spelled with exact string-literal brackets;
 * - `dynamic-member`         the same chain with a computed link at a position that still lines
 *                            up with the pinned surface;
 * - `endpoint-extraction`    an uninvoked pinned member chain, or statically named destructuring
 *                            of a pinned member out of its scope object;
 * - `positional-request`     `<receiver>.request(route, parameters?)`;
 * - `object-request`         `<receiver>.request({ ... })`;
 * - `probot-registration`    `<receiver>.on(event, handler)` inside a *designated* Probot
 *                            entrypoint only — never an arbitrary `.on` call.
 *
 * Exact pinned membership comes only from {@link ANALYZER_ENDPOINT_PROFILE}. A fully static
 * `.rest.<scope>.<method>` chain is nevertheless retained when its pair is absent from that
 * profile: if receiver proof later establishes an authorized Octokit client, operation
 * normalization must report `unknown-endpoint-member` rather than silently dropping a newer or
 * unsupported surface. No endpoint identity is ever derived by camel-casing a name or guessing
 * a route, and censusing a site asserts nothing about whether its receiver is an Octokit client.
 *
 * Nothing here reads a file, resolves a module, or evaluates target code. It walks one already
 * parsed syntax tree and returns portable data.
 */

import ts from 'typescript';

import type { SourceSpan } from '../permission-model/model.js';

import type { CandidateKind } from './contract.js';
import { spanOfNode } from './parse.js';
import type { ParsedSource } from './parse.js';
import { ANALYZER_ENDPOINT_PROFILE } from './profile.js';

/** Identity of the anchor set and census policy implemented here. */
export const CANDIDATE_CENSUS_IDENTITY = 'boundaryci/anchored-candidate-census@1';

/** The exact member name that introduces a canonical endpoint chain. */
const REST_LINK = 'rest';

/** The exact member names that anchor the request and Probot-registration shapes. */
const REQUEST_LINK = 'request';
const REGISTRATION_LINK = 'on';

const ANCHOR_PINNED_MEMBER = 'pinned-endpoint-member-spelling';
const ANCHOR_STATIC_REST_MEMBER = 'static-rest-endpoint-member-spelling';
const ANCHOR_PINNED_ALTERNATE_SURFACE = 'pinned-endpoint-alternate-surface';
const ANCHOR_PINNED_BRACKET = 'pinned-endpoint-bracket-chain';
const ANCHOR_COMPUTED_CHAIN = 'computed-endpoint-chain-position';
const ANCHOR_PINNED_EXTRACTION = 'pinned-endpoint-member-extraction';
const ANCHOR_REQUEST_POSITIONAL = 'request-positional-route-argument';
const ANCHOR_REQUEST_OBJECT = 'request-object-argument';
const ANCHOR_REQUEST_BRACKET = 'request-static-bracket-access';
const ANCHOR_PROBOT_REGISTRATION = 'designated-probot-registration';

const MEMBER_IDS: ReadonlySet<string> = new Set(
  ANALYZER_ENDPOINT_PROFILE.members.map((member) => `${member.scope}.${member.method}`),
);

const MEMBER_SCOPES: ReadonlySet<string> = new Set(ANALYZER_ENDPOINT_PROFILE.members.map((member) => member.scope));

const MEMBER_METHODS: ReadonlySet<string> = new Set(ANALYZER_ENDPOINT_PROFILE.members.map((member) => member.method));

/**
 * How the receiver of an anchored site is spelled, described without retaining any syntax.
 *
 * This is a *description*, never a claim: `identifier` says the chain hangs off a plain name,
 * not that the name denotes an Octokit client. The provenance evaluator decides that
 * separately, and `expression` deliberately collapses every shape this analyzer's finite
 * grammar cannot even ask a question about.
 */
export type CandidateReceiver =
  | { readonly form: 'expression' }
  | { readonly form: 'identifier'; readonly name: string }
  | { readonly form: 'probot-context-octokit'; readonly contextName: string }
  | { readonly form: 'private-field'; readonly field: string }
  | { readonly form: 'this-property'; readonly name: string };

/** The exact pinned `scope.method` pair an anchored site named, when it named one. */
export interface CandidateMember {
  readonly scope: string;
  readonly method: string;
}

/** Portable syntax-only description of a positional `request()` route argument. */
export type CandidateRouteArgument =
  | { readonly kind: 'binding'; readonly name: string; readonly useStart: number }
  | { readonly kind: 'dynamic' }
  | { readonly kind: 'literal'; readonly value: string }
  | { readonly kind: 'missing' };

/** Exact route-defining subset of one fresh inline request object. */
export interface CandidateRequestObject {
  readonly supportedShape: boolean;
  readonly method: string | null;
  readonly url: string | null;
}

/** Internal request syntax retained until receiver proof and operation normalization. */
export type CandidateRequest =
  | { readonly form: 'object'; readonly object: CandidateRequestObject }
  | { readonly form: 'positional'; readonly argument: CandidateRouteArgument; readonly supportedArity: boolean };

/**
 * One censused obligation.
 *
 * `enclosingClassStart` is the UTF-16 start offset of the innermost class the site sits in, or
 * `null` outside a class body. It is an offset rather than an index so that the census and the
 * source graph identify the same class without sharing a traversal order.
 *
 * `receiverStart` is the UTF-16 start offset of the receiver expression itself, which is the
 * exact position the receiver name is *used* at. Recording it is what lets a later proof resolve
 * that name in its own lexical scope instead of by file-wide identifier text: the same spelling
 * in two scopes is two different questions, and only the position distinguishes them. Both
 * offsets describe the same parser text every span in this record was computed from.
 */
export interface CandidateSite {
  readonly kind: CandidateKind;
  readonly anchor: string;
  readonly spelling: string;
  readonly path: string;
  readonly span: SourceSpan;
  readonly optional: boolean;
  readonly receiver: CandidateReceiver;
  readonly receiverStart: number;
  readonly member: CandidateMember | null;
  /** The static route text of a positional `request()` argument, when it was a literal. */
  readonly route: string | null;
  /** Exact request syntax needed by the bounded Task 1 call grammar, or `null` otherwise. */
  readonly request: CandidateRequest | null;
  readonly enclosingClassStart: number | null;
}

/** Per-file census input the caller owns, because discovery — not syntax — designates a role. */
export interface CandidateCensusOptions {
  /** Whether the trusted request designated this exact path as a Probot entrypoint. */
  readonly probotEntrypoint: boolean;
}

/** One link of a member chain, whether it was spelled with a dot or with brackets. */
interface ChainLink {
  /** The exact static member text, or `null` when the link is computed at runtime. */
  readonly text: string | null;
  readonly bracket: boolean;
  readonly optional: boolean;
  readonly object: ts.Expression;
}

function literalTextOf(node: ts.Node): string | null {
  return ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node) ? node.text : null;
}

/**
 * Describes one member access link, or `null` when the expression is not a member access.
 *
 * A private-name access answers `null` on purpose: `this.#client` is a receiver this analyzer
 * has a bounded rule for, not a link of an endpoint chain.
 */
function accessOf(expression: ts.Expression): ChainLink | null {
  if (ts.isPropertyAccessExpression(expression)) {
    if (ts.isPrivateIdentifier(expression.name)) return null;
    return {
      text: expression.name.text,
      bracket: false,
      optional: expression.questionDotToken !== undefined,
      object: expression.expression,
    };
  }
  if (ts.isElementAccessExpression(expression)) {
    return {
      text: literalTextOf(expression.argumentExpression),
      bracket: true,
      optional: expression.questionDotToken !== undefined,
      object: expression.expression,
    };
  }
  return null;
}

function describeReceiver(expression: ts.Expression): CandidateReceiver {
  if (ts.isIdentifier(expression)) return { form: 'identifier', name: expression.text };
  if (
    ts.isPropertyAccessExpression(expression) &&
    !ts.isPrivateIdentifier(expression.name) &&
    expression.name.text === 'octokit' &&
    ts.isIdentifier(expression.expression)
  ) {
    return { form: 'probot-context-octokit', contextName: expression.expression.text };
  }
  if (ts.isPropertyAccessExpression(expression) && expression.expression.kind === ts.SyntaxKind.ThisKeyword) {
    if (ts.isPrivateIdentifier(expression.name)) return { form: 'private-field', field: expression.name.text };
    return { form: 'this-property', name: expression.name.text };
  }
  return { form: 'expression' };
}

function receiverSpelling(receiver: CandidateReceiver): string {
  if (receiver.form === 'identifier') return receiver.name;
  if (receiver.form === 'probot-context-octokit') return `${receiver.contextName}.octokit`;
  if (receiver.form === 'private-field') return `this.${receiver.field}`;
  if (receiver.form === 'this-property') return `this.${receiver.name}`;
  return '<expression>';
}

function linkSpelling(link: ChainLink): string {
  if (link.text === null) return '[<computed>]';
  return link.bracket ? `["${link.text}"]` : `.${link.text}`;
}

function isPinnedMember(scope: string, method: string): boolean {
  return MEMBER_IDS.has(`${scope}.${method}`);
}

/**
 * Decides whether a partially computed chain still lines up with the pinned endpoint surface.
 *
 * Every static link must be consistent with some pinned chain, and the chain must additionally
 * be anchored by either the literal `rest` link or a complete pinned `scope.method` pair.
 * Without that second requirement, any three-link chain ending in a common word would become a
 * candidate, which is exactly the name-based noise the census must not produce.
 */
function isPlausibleComputedChain(first: ChainLink, second: ChainLink, third: ChainLink): boolean {
  if (first.text !== null && first.text !== REST_LINK) return false;
  if (second.text !== null && !MEMBER_SCOPES.has(second.text)) return false;
  if (third.text !== null) {
    const known = second.text === null ? MEMBER_METHODS.has(third.text) : isPinnedMember(second.text, third.text);
    if (!known) return false;
  }
  if (first.text === REST_LINK) return true;
  return second.text !== null && third.text !== null;
}

export function censusCandidates(parsed: ParsedSource, options: CandidateCensusOptions): CandidateSite[] {
  const path = parsed.record.path;
  const sites: CandidateSite[] = [];
  /** Callee expressions of call sites, so an uninvoked chain is distinguishable from a call. */
  const invoked = new Set<ts.Node>();

  const push = (site: CandidateSite): void => {
    sites.push(site);
  };

  /**
   * The exact offset the receiver expression starts at, skipping leading trivia.
   *
   * This is a position, not a claim: it says where the receiver was written, which is the only
   * evidence a scope-based proof needs in order to ask about the right binding.
   */
  const receiverStartOf = (expression: ts.Expression): number => expression.getStart(parsed.sourceFile);

  /**
   * Censuses one three-link member chain, whether it was invoked or merely extracted.
   *
   * `callNode` is the call expression when the chain sits in callee position, and `null` when
   * the chain is a value being read. That distinction selects `direct-endpoint` versus
   * `endpoint-extraction`; it never changes whether the site is an obligation.
   */
  const censusChain = (
    chain: ts.Expression,
    callNode: ts.CallExpression | null,
    classStart: number | null,
  ): boolean => {
    const third = accessOf(chain);
    if (third === null) return false;
    const second = accessOf(third.object);
    if (second === null) return false;
    const first = accessOf(second.object);
    if (first === null) return false;

    const receiver = describeReceiver(first.object);
    const spelling = `${receiverSpelling(receiver)}${linkSpelling(first)}${linkSpelling(second)}${linkSpelling(third)}`;
    const span = spanOfNode(parsed, callNode ?? chain);
    const optional =
      first.optional ||
      second.optional ||
      third.optional ||
      (callNode !== null && callNode.questionDotToken !== undefined);

    const allStatic = first.text !== null && second.text !== null && third.text !== null;
    if (allStatic) {
      if (first.text !== REST_LINK) return false;
      const scope = second.text as string;
      const method = third.text as string;
      const pinned = isPinnedMember(scope, method);
      const bracketed = first.bracket || second.bracket || third.bracket;
      const kind: CandidateKind = bracketed
        ? 'static-bracket-member'
        : callNode !== null
          ? 'direct-endpoint'
          : 'endpoint-extraction';
      const anchor = bracketed
        ? ANCHOR_PINNED_BRACKET
        : callNode !== null
          ? pinned
            ? ANCHOR_PINNED_MEMBER
            : ANCHOR_STATIC_REST_MEMBER
          : ANCHOR_PINNED_EXTRACTION;
      push({
        kind,
        anchor,
        spelling,
        path,
        span,
        optional,
        receiver,
        receiverStart: receiverStartOf(first.object),
        member: { scope, method },
        route: null,
        request: null,
        enclosingClassStart: classStart,
      });
      return true;
    }

    if (!isPlausibleComputedChain(first, second, third)) return false;
    const member =
      second.text !== null && third.text !== null && isPinnedMember(second.text, third.text)
        ? { scope: second.text, method: third.text }
        : null;
    push({
      kind: 'dynamic-member',
      anchor: ANCHOR_COMPUTED_CHAIN,
      spelling,
      path,
      span,
      optional,
      receiver,
      receiverStart: receiverStartOf(first.object),
      member,
      route: null,
      request: null,
      enclosingClassStart: classStart,
    });
    return true;
  };

  /**
   * Censuses the exact two-link `receiver.scope.method` alternate spelling.
   *
   * The pinned `scope.method` pair makes this an accounting obligation, but the missing `rest`
   * link means the syntax is not an authorized endpoint surface. The analyzer may prove the
   * receiver independently; it must still classify the call grammar incomplete unless a future
   * pinned compatibility profile explicitly authorizes the spelling.
   */
  const censusAlternateSurface = (
    chain: ts.Expression,
    callNode: ts.CallExpression | null,
    classStart: number | null,
  ): boolean => {
    const methodLink = accessOf(chain);
    if (methodLink === null || methodLink.bracket || methodLink.text === null) return false;
    const scopeLink = accessOf(methodLink.object);
    if (scopeLink === null || scopeLink.bracket || scopeLink.text === null) return false;
    if (!isPinnedMember(scopeLink.text, methodLink.text)) return false;
    const receiver = describeReceiver(scopeLink.object);
    push({
      kind: callNode === null ? 'endpoint-extraction' : 'direct-endpoint',
      anchor: ANCHOR_PINNED_ALTERNATE_SURFACE,
      spelling: `${receiverSpelling(receiver)}${linkSpelling(scopeLink)}${linkSpelling(methodLink)}`,
      path,
      span: spanOfNode(parsed, callNode ?? chain),
      optional:
        scopeLink.optional || methodLink.optional || (callNode !== null && callNode.questionDotToken !== undefined),
      receiver,
      receiverStart: receiverStartOf(scopeLink.object),
      member: { scope: scopeLink.text, method: methodLink.text },
      route: null,
      request: null,
      enclosingClassStart: classStart,
    });
    return true;
  };

  /** Describes the exact fresh-inline object subset without retaining parser nodes. */
  const describeRequestObject = (object: ts.ObjectLiteralExpression): CandidateRequestObject => {
    let method: string | null = null;
    let url: string | null = null;
    let methodCount = 0;
    let urlCount = 0;
    let supportedShape = true;

    for (const property of object.properties) {
      if (ts.isSpreadAssignment(property) || ts.isGetAccessorDeclaration(property) || ts.isSetAccessorDeclaration(property)) {
        supportedShape = false;
        continue;
      }
      if (ts.isShorthandPropertyAssignment(property)) {
        if (property.name.text === 'method' || property.name.text === 'url') supportedShape = false;
        continue;
      }
      if (!ts.isPropertyAssignment(property)) {
        supportedShape = false;
        continue;
      }
      if (property.name.kind === ts.SyntaxKind.ComputedPropertyName) {
        supportedShape = false;
        continue;
      }
      const name =
        ts.isIdentifier(property.name) || ts.isStringLiteral(property.name) ? property.name.text : null;
      if (name === 'baseUrl') {
        supportedShape = false;
        continue;
      }
      if (name !== 'method' && name !== 'url') continue;
      const value = literalTextOf(property.initializer);
      if (name === 'method') {
        methodCount += 1;
        if (value === null) supportedShape = false;
        else method = value;
      } else {
        urlCount += 1;
        if (value === null) supportedShape = false;
        else url = value;
      }
    }

    if (methodCount !== 1 || urlCount !== 1 || method === null || url === null || /^(?:[a-z][a-z+.-]*:)?\/\//iu.test(url)) {
      supportedShape = false;
    }
    return { supportedShape, method, url };
  };

  const describeRouteArgument = (argument: ts.Expression | undefined): CandidateRouteArgument => {
    if (argument === undefined) return { kind: 'missing' };
    const literal = literalTextOf(argument);
    if (literal !== null) return { kind: 'literal', value: literal };
    if (ts.isIdentifier(argument)) {
      return { kind: 'binding', name: argument.text, useStart: argument.getStart(parsed.sourceFile) };
    }
    return { kind: 'dynamic' };
  };

  /** Censuses the two documented `request()` argument shapes and malformed empty calls. */
  const censusRequest = (node: ts.CallExpression, link: ChainLink, classStart: number | null): void => {
    const args = node.arguments;
    const receiver = describeReceiver(link.object);
    const base = `${receiverSpelling(receiver)}${linkSpelling(link)}`;
    const span = spanOfNode(parsed, node);
    const optional = link.optional || node.questionDotToken !== undefined;
    const first = args[0];
    if (link.bracket) {
      push({
        kind: 'static-bracket-member',
        anchor: ANCHOR_REQUEST_BRACKET,
        spelling: `${base}`,
        path,
        span,
        optional,
        receiver,
        receiverStart: receiverStartOf(link.object),
        member: null,
        route: null,
        request: null,
        enclosingClassStart: classStart,
      });
      return;
    }
    if (first !== undefined && ts.isObjectLiteralExpression(first)) {
      const object = describeRequestObject(first);
      push({
        kind: 'object-request',
        anchor: ANCHOR_REQUEST_OBJECT,
        spelling: `${base}({…})`,
        path,
        span,
        optional,
        receiver,
        receiverStart: receiverStartOf(link.object),
        member: null,
        route: null,
        request: {
          form: 'object',
          object: args.length === 1 ? object : { ...object, supportedShape: false },
        },
        enclosingClassStart: classStart,
      });
      return;
    }
    // Every exact dot-form `request()` call is an accounting obligation. Missing and over-arity
    // calls remain explicit even when the route itself is dynamic; provenance evaluation, not
    // the census, decides whether the receiver is actually authorized.
    const route = first === undefined ? null : literalTextOf(first);
    const argument = describeRouteArgument(first);
    const argumentSpelling =
      argument.kind === 'missing'
        ? ''
        : argument.kind === 'binding'
          ? argument.name
          : argument.kind === 'literal'
            ? argument.value
            : '<dynamic>';
    push({
      kind: 'positional-request',
      anchor: ANCHOR_REQUEST_POSITIONAL,
      spelling: `${base}(${argumentSpelling})`,
      path,
      span,
      optional,
      receiver,
      receiverStart: receiverStartOf(link.object),
      member: null,
      route,
      request: {
        form: 'positional',
        argument,
        supportedArity: args.length >= 1 && args.length <= 2,
      },
      enclosingClassStart: classStart,
    });
  };

  /**
   * Censuses registration-shaped calls only inside a designated Probot entrypoint.
   *
   * The later provenance rule accepts exactly `app.on(event, handler)`; this broader local
   * census deliberately retains `onAny` and malformed `.on` shapes as explicit incomplete
   * obligations rather than silently treating them as absent. The designation comes from
   * trusted input, never from a filename, import, or method name alone.
   */
  const censusRegistration = (node: ts.CallExpression, link: ChainLink, classStart: number | null): void => {
    if (!options.probotEntrypoint) return;
    const receiver = describeReceiver(link.object);
    push({
      kind: 'probot-registration',
      anchor: ANCHOR_PROBOT_REGISTRATION,
      spelling: `${receiverSpelling(receiver)}${linkSpelling(link)}`,
      path,
      span: spanOfNode(parsed, node),
      optional: link.optional || node.questionDotToken !== undefined,
      receiver,
      receiverStart: receiverStartOf(link.object),
      member: null,
      route: null,
      request: null,
      enclosingClassStart: classStart,
    });
  };

  /**
   * Censuses statically named destructuring of a pinned member out of its scope object.
   *
   * `const { create: open } = client.rest.issues;` names the exact pinned `issues.create`
   * member; a computed, rest, or defaulted element names no exact member and is not an anchor.
   */
  const censusDestructuring = (declaration: ts.VariableDeclaration, classStart: number | null): void => {
    const initializer = declaration.initializer;
    if (initializer === undefined || !ts.isObjectBindingPattern(declaration.name)) return;
    const scopeLink = accessOf(initializer);
    if (scopeLink === null || scopeLink.text === null) return;
    const restLink = accessOf(scopeLink.object);
    if (restLink === null || restLink.text !== REST_LINK) return;
    const scope = scopeLink.text;
    if (!MEMBER_SCOPES.has(scope)) return;
    const receiver = describeReceiver(restLink.object);
    const base = `${receiverSpelling(receiver)}${linkSpelling(restLink)}${linkSpelling(scopeLink)}`;
    for (const element of declaration.name.elements) {
      if (element.dotDotDotToken !== undefined) continue;
      const propertyName = element.propertyName ?? element.name;
      if (!ts.isIdentifier(propertyName) && !ts.isStringLiteral(propertyName)) continue;
      const method = propertyName.text;
      if (!isPinnedMember(scope, method)) continue;
      push({
        kind: 'endpoint-extraction',
        anchor: ANCHOR_PINNED_EXTRACTION,
        spelling: `${base}.${method}`,
        path,
        span: spanOfNode(parsed, element),
        optional: restLink.optional || scopeLink.optional,
        receiver,
        receiverStart: receiverStartOf(restLink.object),
        member: { scope, method },
        route: null,
        request: null,
        enclosingClassStart: classStart,
      });
    }
  };

  const visit = (node: ts.Node, classStart: number | null): void => {
    const innerClass =
      ts.isClassDeclaration(node) || ts.isClassExpression(node) ? node.getStart(parsed.sourceFile) : classStart;

    if (ts.isCallExpression(node)) {
      invoked.add(node.expression);
      if (
        !censusChain(node.expression, node, classStart) &&
        !censusAlternateSurface(node.expression, node, classStart)
      ) {
        const link = accessOf(node.expression);
        if (link !== null && link.text === REQUEST_LINK) censusRequest(node, link, classStart);
        else if (
          link !== null &&
          (link.text === REGISTRATION_LINK || (options.probotEntrypoint && link.text === 'onAny'))
        ) {
          censusRegistration(node, link, classStart);
        }
      }
    } else if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
      // An uninvoked pinned chain is an extraction obligation. Callee positions are excluded
      // because the enclosing call already censused them under its own kind.
      if (!invoked.has(node) && !censusChain(node, null, classStart)) {
        censusAlternateSurface(node, null, classStart);
      }
    } else if (ts.isVariableDeclaration(node)) {
      censusDestructuring(node, classStart);
    }

    ts.forEachChild(node, (child) => {
      visit(child, innerClass);
    });
  };

  visit(parsed.sourceFile, null);
  return sites;
}
