/**
 * Exact Task 1 Octokit call normalization.
 *
 * Receiver provenance is supplied by the bounded resolver and is never inferred here. This
 * module proves only the other two independent facts: the call uses one authorized syntax and
 * that syntax selects exactly one row of the pinned endpoint profile. Permission lookup is a
 * later concern, so an operation outside the bounded permission catalog remains a proven
 * operation.
 */

import type { RestOperationIdentity, SourceSpan } from '../permission-model/model.js';

import type { CandidateSite } from './candidates.js';
import type {
  AnalyzerCauseCode,
  CandidateReason,
  ProfileMemberReference,
  ReceiverProvenance,
} from './contract.js';
import { ANALYZER_ENDPOINT_PROFILE } from './profile.js';
import type { AnalyzerEndpointProfile, EndpointMemberRecord } from './profile.js';
import { resolveStaticRouteValueAtOffset } from './resolve.js';
import type { ResolverCause, SourceGraph } from './resolve.js';

/** Identity of the finite endpoint/request grammar implemented by this module. */
export const CALL_GRAMMAR_IDENTITY = 'boundaryci/octokit-call-grammar@1';

export type StaticRequestRouteParse =
  | { readonly status: 'malformed' }
  | { readonly status: 'parsed'; readonly method: string; readonly normalizedRoute: string };

export interface OperationGrammarCause {
  readonly code: AnalyzerCauseCode;
  readonly detail: string;
  readonly path?: string | null;
  readonly span?: SourceSpan | null;
}

type OperationIncompleteCode =
  | 'ambiguous-endpoint-member'
  | 'ambiguous-request-route'
  | 'dynamic-request-route'
  | 'malformed-request-route'
  | 'unknown-endpoint-member'
  | 'unknown-request-route'
  | 'unsupported-endpoint-surface'
  | 'unsupported-request-grammar'
  | 'unsupported-request-object';

export type OperationCandidateResolution =
  | {
      readonly status: 'incomplete';
      readonly reason: CandidateReason;
      readonly causes: readonly OperationGrammarCause[];
    }
  | {
      readonly status: 'proven';
      readonly reason: 'proven-direct-rest-member-call' | 'proven-static-request-call';
      readonly member: ProfileMemberReference | null;
      readonly operation: RestOperationIdentity;
      readonly optional: boolean;
      readonly receiver: ReceiverProvenance;
    };

const DETAILS: Readonly<Partial<Record<AnalyzerCauseCode, string>>> = Object.freeze({
  'ambiguous-endpoint-member': 'the endpoint member matched more than one pinned profile row',
  'ambiguous-request-route': 'the static request route matched more than one pinned canonical operation',
  'dynamic-request-route': 'the request route is not one exact supported immutable string value',
  'malformed-request-route': 'the request route does not satisfy the strict METHOD /path grammar',
  'unknown-request-route': 'the static request route does not match a pinned canonical operation',
  'unknown-endpoint-member': 'the endpoint member does not match a pinned profile row',
  'unsupported-endpoint-surface': 'no pinned client surface authorizes the direct endpoint shorthand',
  'unsupported-request-grammar': 'the request call is outside the authorized positional arity',
  'unsupported-request-object': 'the request object is outside the fresh inline literal method/url subset',
});

function incomplete(
  code: OperationIncompleteCode,
  dependentCauses: readonly ResolverCause[] = [],
): OperationCandidateResolution {
  const mapped = dependentCauses.map((cause) => ({
    code: cause.code,
    path: cause.path,
    span: cause.span,
    detail: cause.detail,
  }));
  const causes = dependentCauses.some((cause) => cause.code === code)
    ? mapped
    : [{ code, detail: DETAILS[code] ?? 'the operation call grammar did not reach one exact identity' }, ...mapped];
  return {
    status: 'incomplete',
    reason: code,
    causes,
  };
}

/**
 * Parses exactly one static Octokit request route.
 *
 * The grammar has one uppercase method, one ASCII space, and one root-relative canonical path.
 * Query strings, fragments, URL schemes, backslashes, empty segments, and dot segments are not
 * canonical route templates and are rejected before profile lookup.
 */
export function parseStaticRequestRoute(route: string): StaticRequestRouteParse {
  const match = route.match(/^([A-Z]+) (\/[^\s?#\\]*)$/u);
  if (match === null) return { status: 'malformed' };
  const method = match[1];
  const normalizedRoute = match[2];
  if (method === undefined || normalizedRoute === undefined || normalizedRoute.startsWith('//')) {
    return { status: 'malformed' };
  }
  const segments = normalizedRoute.slice(1).split('/');
  if (segments.some((segment) => segment.length === 0 || segment === '.' || segment === '..')) {
    return { status: 'malformed' };
  }
  return { status: 'parsed', method, normalizedRoute };
}

function profileMemberReference(profile: AnalyzerEndpointProfile, member: EndpointMemberRecord): ProfileMemberReference {
  return {
    profileId: profile.identity.profileId,
    memberId: `${member.scope}.${member.method}`,
    scope: member.scope,
    method: member.method,
  };
}

function directOperation(
  site: CandidateSite,
  receiver: ReceiverProvenance,
  profile: AnalyzerEndpointProfile,
): OperationCandidateResolution {
  if (site.anchor === 'pinned-endpoint-alternate-surface') return incomplete('unsupported-endpoint-surface');
  if (site.member === null) return incomplete('unknown-endpoint-member');
  const matches = profile.members.filter(
    (member) => member.scope === site.member?.scope && member.method === site.member.method,
  );
  if (matches.length === 0) return incomplete('unknown-endpoint-member');
  if (matches.length > 1) return incomplete('ambiguous-endpoint-member');
  const member = matches[0];
  if (member === undefined) return incomplete('unknown-endpoint-member');
  return {
    status: 'proven',
    reason: 'proven-direct-rest-member-call',
    member: profileMemberReference(profile, member),
    operation: {
      method: member.httpMethod,
      normalizedRoute: member.normalizedRoute,
      operationId: member.operationId,
    },
    optional: site.optional,
    receiver,
  };
}

function routeCauseFromResolver(
  causes: readonly ResolverCause[],
): 'ambiguous-request-route' | 'dynamic-request-route' {
  return causes.some((cause) => cause.code === 'ambiguous-relative-source')
    ? 'ambiguous-request-route'
    : 'dynamic-request-route';
}

function requestRouteText(site: CandidateSite, graph: SourceGraph): string | OperationCandidateResolution {
  const request = site.request;
  if (request === null) return incomplete('dynamic-request-route');
  if (request.form === 'object') {
    const object = request.object;
    if (!object.supportedShape || object.method === null || object.url === null) {
      return incomplete('unsupported-request-object');
    }
    return `${object.method} ${object.url}`;
  }

  const argument = request.argument;
  if (argument.kind === 'missing') return incomplete('malformed-request-route');
  if (!request.supportedArity) return incomplete('unsupported-request-grammar');
  if (argument.kind === 'dynamic') return incomplete('dynamic-request-route');
  if (argument.kind === 'literal') return argument.value;

  const value = resolveStaticRouteValueAtOffset(graph, site.path, argument.name, argument.useStart);
  if (value.kind === 'string') return value.value;
  if (value.kind === 'unsupported-object') return incomplete('unsupported-request-object');
  return incomplete(routeCauseFromResolver(value.causes), value.causes);
}

function requestOperation(
  site: CandidateSite,
  graph: SourceGraph,
  receiver: ReceiverProvenance,
  profile: AnalyzerEndpointProfile,
): OperationCandidateResolution {
  const route = requestRouteText(site, graph);
  if (typeof route !== 'string') return route;
  const parsed = parseStaticRequestRoute(route);
  if (parsed.status === 'malformed') return incomplete('malformed-request-route');
  const matches = profile.operations.filter(
    (operation) => operation.method === parsed.method && operation.normalizedRoute === parsed.normalizedRoute,
  );
  if (matches.length === 0) return incomplete('unknown-request-route');
  if (matches.length > 1) return incomplete('ambiguous-request-route');
  const operation = matches[0];
  if (operation === undefined) return incomplete('unknown-request-route');
  return {
    status: 'proven',
    reason: 'proven-static-request-call',
    member: null,
    operation: { ...operation },
    optional: site.optional,
    receiver,
  };
}

/**
 * Normalizes one already receiver-proven Task 1 candidate through the exact pinned profile.
 *
 * The optional `profile` parameter is deterministic test injection; production analysis always
 * passes the frozen {@link ANALYZER_ENDPOINT_PROFILE} default.
 */
export function resolveOperationCandidate(
  site: CandidateSite,
  graph: SourceGraph,
  receiver: ReceiverProvenance,
  profile: AnalyzerEndpointProfile = ANALYZER_ENDPOINT_PROFILE,
): OperationCandidateResolution {
  if (site.kind === 'direct-endpoint') return directOperation(site, receiver, profile);
  if (site.kind === 'positional-request' || site.kind === 'object-request') {
    return requestOperation(site, graph, receiver, profile);
  }
  throw new TypeError('resolveOperationCandidate received a candidate outside the Task 1 call grammar');
}
