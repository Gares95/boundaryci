/**
 * Pure permission requirement, evidence, catalog, aggregation, and comparison model.
 *
 * Every value in this module is JSON-safe data. Nothing here reads files, performs
 * network access, or depends on a parser, HTTP client, or web framework object.
 * Unprovable input never becomes a clean boundary claim: it becomes an explicit
 * `unsupported`, `missing`, `invalid`, or `incomplete` result that keeps its evidence.
 */

export type PermissionLevel = 'read' | 'write';

export type BoundaryLevel = 'none' | 'read' | 'write';

export type RequirementExpression =
  | { type: 'permission'; permission: string; level: PermissionLevel }
  | { type: 'allOf'; requirements: RequirementExpression[] }
  | { type: 'anyOf'; requirements: RequirementExpression[] };

export interface RestOperationIdentity {
  method: string;
  normalizedRoute: string;
  operationId: string;
}

export interface SourcePoint {
  line: number;
  column: number;
}

export interface SourceSpan {
  start: SourcePoint;
  end: SourcePoint;
}

export interface SourceEvidence {
  path: string;
  span: SourceSpan;
}

export interface CatalogProvenance {
  authorizedScopeSha256: string;
  expressionSha256: string;
  entrySha256: string;
  artifactManifestSha256: string;
  supportPredicateSha256: string;
}

type CatalogUnsupportedReason =
  | 'unsupported-access-level'
  | 'unsupported-permission-expression'
  | 'unsupported-permission-name'
  | 'unsupported-permission-qualifier';

type CatalogInvalidReason = 'conflicting-catalog-entry' | 'duplicate-catalog-entry' | 'malformed-catalog-entry';

type LookupInvalidReason = CatalogInvalidReason | 'invalid-operation-identity';

type FindingInvalidReason = LookupInvalidReason | 'invalid-source-evidence';

type BoundaryIncompleteReason =
  | 'complex-permission-expression'
  | 'invalid-permission-requirement'
  | 'missing-permission-requirement'
  | 'unsupported-permission-requirement';

type ComparisonIncompleteReason = BoundaryIncompleteReason | 'incomplete-base-boundary' | 'incomplete-head-boundary';

export interface ResolvedCatalogEntry {
  status: 'resolved';
  operation: RestOperationIdentity;
  requirement: RequirementExpression;
  provenance: CatalogProvenance;
}

export interface UnsupportedCatalogEntry {
  status: 'unsupported';
  operation: RestOperationIdentity;
  reason: CatalogUnsupportedReason;
  provenance: CatalogProvenance;
}

export type PermissionCatalogEntry = ResolvedCatalogEntry | UnsupportedCatalogEntry;

export type CatalogValidationResult =
  | { status: 'valid'; entryCount: number }
  | { status: 'invalid'; reason: CatalogInvalidReason; detail: string };

export type CatalogLookupResult =
  | {
      status: 'resolved';
      operation: RestOperationIdentity;
      requirement: RequirementExpression;
      provenance: CatalogProvenance;
    }
  | { status: 'unsupported'; operation: RestOperationIdentity; reason: CatalogUnsupportedReason }
  | { status: 'missing'; operation: RestOperationIdentity }
  | { status: 'invalid'; operation: RestOperationIdentity | null; reason: LookupInvalidReason; detail: string };

export type RequirementFinding =
  | {
      status: 'resolved';
      operation: RestOperationIdentity;
      source: SourceEvidence;
      requirement: RequirementExpression;
      provenance: CatalogProvenance;
    }
  | { status: 'unsupported'; operation: RestOperationIdentity; source: SourceEvidence; reason: CatalogUnsupportedReason }
  | { status: 'missing'; operation: RestOperationIdentity; source: SourceEvidence }
  | {
      status: 'invalid';
      operation: RestOperationIdentity | null;
      source: SourceEvidence | null;
      reason: FindingInvalidReason;
      detail: string;
    };

export type PermissionBoundary =
  | {
      status: 'complete';
      permissions: { permission: string; level: PermissionLevel; contributors: RequirementFinding[] }[];
    }
  | { status: 'incomplete'; reasons: BoundaryIncompleteReason[]; findings: RequirementFinding[] };

export interface PermissionChange {
  permission: string;
  base: BoundaryLevel;
  head: BoundaryLevel;
  change: 'expansion' | 'reduction' | 'unchanged';
}

export type BoundaryComparison =
  | { status: 'complete'; changes: PermissionChange[] }
  | {
      status: 'incomplete';
      reasons: ComparisonIncompleteReason[];
      base: PermissionBoundary;
      head: PermissionBoundary;
      structurallyEquivalent: boolean;
    };

type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

const SHA256 = /^[a-f0-9]{64}$/u;
const HTTP_METHOD = /^[A-Z]+$/u;
const NO_WHITESPACE = /^\S+$/u;

const CATALOG_UNSUPPORTED_REASONS: readonly CatalogUnsupportedReason[] = [
  'unsupported-access-level',
  'unsupported-permission-expression',
  'unsupported-permission-name',
  'unsupported-permission-qualifier',
];

const FINDING_INVALID_REASONS: readonly FindingInvalidReason[] = [
  'conflicting-catalog-entry',
  'duplicate-catalog-entry',
  'invalid-operation-identity',
  'invalid-source-evidence',
  'malformed-catalog-entry',
];

const BOUNDARY_INCOMPLETE_REASONS: readonly BoundaryIncompleteReason[] = [
  'complex-permission-expression',
  'invalid-permission-requirement',
  'missing-permission-requirement',
  'unsupported-permission-requirement',
];

const LEVEL_RANK: Readonly<Record<BoundaryLevel, number>> = { none: 0, read: 1, write: 2 };

function compareBytes(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function canonicalJson(value: JsonValue): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((entry) => canonicalJson(entry)).join(',')}]`;
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key] as JsonValue)}`)
    .join(',')}}`;
}

function jsonBytes(value: unknown): string {
  return canonicalJson(value as JsonValue);
}

function cloneJson<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function sortByCanonicalBytes<T>(values: readonly T[]): T[] {
  return [...values].sort((left, right) => compareBytes(jsonBytes(left), jsonBytes(right)));
}

function failureDetail(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function assertPlainObject(value: unknown, label: string): asserts value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object`);
  }
}

function assertExactKeys(value: Record<string, unknown>, keys: readonly string[], label: string): void {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new TypeError(`${label} has unknown or missing keys: ${actual.join(',')}`);
  }
}

function assertNonEmptyString(value: unknown, label: string): asserts value is string {
  if (typeof value !== 'string' || value.length === 0) throw new TypeError(`${label} must be a non-empty string`);
}

function assertSha256(value: unknown, label: string): asserts value is string {
  if (typeof value !== 'string' || !SHA256.test(value)) throw new TypeError(`${label} must be a lowercase SHA-256`);
}

function assertExpressionShape(value: unknown, label: string): asserts value is RequirementExpression {
  assertPlainObject(value, label);
  if (value.type === 'permission') {
    assertExactKeys(value, ['level', 'permission', 'type'], label);
    assertNonEmptyString(value.permission, `${label}.permission`);
    if (value.level !== 'read' && value.level !== 'write') throw new TypeError(`${label}.level is invalid`);
    return;
  }
  if (value.type !== 'allOf' && value.type !== 'anyOf') throw new TypeError(`${label}.type is invalid`);
  assertExactKeys(value, ['requirements', 'type'], label);
  if (!Array.isArray(value.requirements)) throw new TypeError(`${label}.requirements must be an array`);
  if (value.requirements.length < 2) throw new TypeError(`${label} must contain at least two requirements`);
  value.requirements.forEach((child, index) => assertExpressionShape(child, `${label}.requirements[${index}]`));
}

function canonicalizeShape(expression: RequirementExpression): RequirementExpression {
  if (expression.type === 'permission') {
    return { type: 'permission', permission: expression.permission, level: expression.level };
  }
  const requirements = expression.requirements.map(canonicalizeShape);
  requirements.sort((left, right) => compareBytes(jsonBytes(left), jsonBytes(right)));
  return { type: expression.type, requirements };
}

/**
 * Returns a deep copy whose group children are recursively ordered by canonical JSON bytes.
 *
 * Ordering is the only change: every node, nested group, child, and repeated child is
 * retained. Groups are never flattened, merged, selected from, or deduplicated.
 */
export function canonicalizeRequirementExpression(expression: RequirementExpression): RequirementExpression {
  assertExpressionShape(expression, 'requirement expression');
  return canonicalizeShape(expression);
}

/**
 * Accepts only an exact-shape expression that is already in canonical child order.
 *
 * Validation never repairs caller data: a noncanonical expression is rejected rather than
 * silently sorted. Repeated children are valid data and are not treated as errors.
 */
export function validateRequirementExpression(value: unknown): asserts value is RequirementExpression {
  assertExpressionShape(value, 'requirement expression');
  if (jsonBytes(value) !== jsonBytes(canonicalizeShape(value))) {
    throw new TypeError('requirement expression is not in canonical order');
  }
}

/** Serializes an expression to deterministic canonical JSON bytes. */
export function requirementExpressionJson(expression: RequirementExpression): string {
  return jsonBytes(canonicalizeRequirementExpression(expression));
}

/** Accepts only a JSON-safe source path with positive, ordered start/end line-column coordinates. */
export function validateSourceEvidence(value: unknown): asserts value is SourceEvidence {
  assertPlainObject(value, 'source evidence');
  assertExactKeys(value, ['path', 'span'], 'source evidence');
  assertNonEmptyString(value.path, 'source evidence path');
  assertPlainObject(value.span, 'source evidence span');
  assertExactKeys(value.span, ['end', 'start'], 'source evidence span');
  const points: SourcePoint[] = [];
  for (const key of ['start', 'end'] as const) {
    const point: unknown = value.span[key];
    assertPlainObject(point, `source evidence span.${key}`);
    assertExactKeys(point, ['column', 'line'], `source evidence span.${key}`);
    for (const axis of ['line', 'column'] as const) {
      const coordinate: unknown = point[axis];
      if (typeof coordinate !== 'number' || !Number.isSafeInteger(coordinate) || coordinate < 1) {
        throw new TypeError(`source evidence span.${key}.${axis} must be a positive integer`);
      }
    }
    points.push(point as unknown as SourcePoint);
  }
  const [start, end] = points;
  if (start === undefined || end === undefined) throw new TypeError('source evidence span is incomplete');
  if (end.line < start.line || (end.line === start.line && end.column < start.column)) {
    throw new TypeError('source evidence span end precedes its start');
  }
}

function assertOperationIdentity(value: unknown, label: string): asserts value is RestOperationIdentity {
  assertPlainObject(value, label);
  assertExactKeys(value, ['method', 'normalizedRoute', 'operationId'], label);
  assertNonEmptyString(value.method, `${label}.method`);
  assertNonEmptyString(value.normalizedRoute, `${label}.normalizedRoute`);
  assertNonEmptyString(value.operationId, `${label}.operationId`);
  if (!HTTP_METHOD.test(value.method)) throw new TypeError(`${label}.method must be an uppercase REST method`);
  if (!value.normalizedRoute.startsWith('/') || !NO_WHITESPACE.test(value.normalizedRoute)) {
    throw new TypeError(`${label}.normalizedRoute must be a normalized route path`);
  }
  if (!NO_WHITESPACE.test(value.operationId)) throw new TypeError(`${label}.operationId must not contain whitespace`);
}

function assertCatalogProvenance(value: unknown, label: string): asserts value is CatalogProvenance {
  assertPlainObject(value, label);
  assertExactKeys(
    value,
    ['artifactManifestSha256', 'authorizedScopeSha256', 'entrySha256', 'expressionSha256', 'supportPredicateSha256'],
    label,
  );
  for (const key of [
    'artifactManifestSha256',
    'authorizedScopeSha256',
    'entrySha256',
    'expressionSha256',
    'supportPredicateSha256',
  ] as const) {
    assertSha256(value[key], `${label}.${key}`);
  }
}

function assertCatalogEntry(value: unknown, label: string): asserts value is PermissionCatalogEntry {
  assertPlainObject(value, label);
  if (value.status === 'resolved') {
    assertExactKeys(value, ['operation', 'provenance', 'requirement', 'status'], label);
    assertOperationIdentity(value.operation, `${label}.operation`);
    validateRequirementExpression(value.requirement);
    assertCatalogProvenance(value.provenance, `${label}.provenance`);
    return;
  }
  if (value.status === 'unsupported') {
    assertExactKeys(value, ['operation', 'provenance', 'reason', 'status'], label);
    assertOperationIdentity(value.operation, `${label}.operation`);
    if (!CATALOG_UNSUPPORTED_REASONS.includes(value.reason as CatalogUnsupportedReason)) {
      throw new TypeError(`${label}.reason is not a supported unsupported-entry reason`);
    }
    assertCatalogProvenance(value.provenance, `${label}.provenance`);
    return;
  }
  throw new TypeError(`${label}.status is invalid`);
}

function identityKey(operation: RestOperationIdentity): string {
  return jsonBytes({
    method: operation.method,
    normalizedRoute: operation.normalizedRoute,
    operationId: operation.operationId,
  });
}

/**
 * Validates the complete catalog collection before any lookup may use it.
 *
 * A malformed entry, a repeated identity, or two entries that disagree about the same
 * operation triple invalidate the whole catalog rather than one row.
 */
export function validatePermissionCatalog(catalog: unknown): CatalogValidationResult {
  if (!Array.isArray(catalog)) {
    return { status: 'invalid', reason: 'malformed-catalog-entry', detail: 'catalog must be an array' };
  }
  const seen = new Map<string, string>();
  for (const [index, entry] of catalog.entries()) {
    const label = `catalog[${index}]`;
    try {
      assertCatalogEntry(entry, label);
    } catch (error) {
      return { status: 'invalid', reason: 'malformed-catalog-entry', detail: failureDetail(error) };
    }
    const key = identityKey(entry.operation);
    const body = jsonBytes(entry);
    const prior = seen.get(key);
    if (prior !== undefined) {
      return prior === body
        ? { status: 'invalid', reason: 'duplicate-catalog-entry', detail: `${label} repeats operation ${key}` }
        : { status: 'invalid', reason: 'conflicting-catalog-entry', detail: `${label} conflicts for operation ${key}` };
    }
    seen.set(key, body);
  }
  return { status: 'valid', entryCount: catalog.length };
}

/**
 * Resolves one exact `(method, normalizedRoute, operationId)` triple against a validated catalog.
 *
 * A damaged catalog is never partially queried; every failure mode is an explicit result.
 */
export function lookupPermissionRequirement(
  catalog: readonly PermissionCatalogEntry[],
  operation: RestOperationIdentity,
): CatalogLookupResult {
  let identity: RestOperationIdentity;
  try {
    assertOperationIdentity(operation, 'operation identity');
    identity = {
      method: operation.method,
      normalizedRoute: operation.normalizedRoute,
      operationId: operation.operationId,
    };
  } catch (error) {
    return { status: 'invalid', operation: null, reason: 'invalid-operation-identity', detail: failureDetail(error) };
  }
  const validation = validatePermissionCatalog(catalog);
  if (validation.status === 'invalid') {
    return { status: 'invalid', operation: identity, reason: validation.reason, detail: validation.detail };
  }
  const key = identityKey(identity);
  const match = catalog.find((entry) => identityKey(entry.operation) === key);
  if (match === undefined) return { status: 'missing', operation: identity };
  if (match.status === 'unsupported') {
    return { status: 'unsupported', operation: identity, reason: match.reason };
  }
  return {
    status: 'resolved',
    operation: identity,
    requirement: canonicalizeRequirementExpression(match.requirement),
    provenance: { ...match.provenance },
  };
}

/**
 * Attaches validated source evidence to one catalog lookup outcome.
 *
 * The returned finding always carries the outcome and its evidence; unusable input keeps
 * `null` in place of the field it could not validate instead of inventing a value.
 */
export function resolveRequirementFinding(
  catalog: readonly PermissionCatalogEntry[],
  operation: RestOperationIdentity,
  source: SourceEvidence,
): RequirementFinding {
  const lookup = lookupPermissionRequirement(catalog, operation);
  let evidence: SourceEvidence | null = null;
  let sourceDetail = '';
  try {
    validateSourceEvidence(source);
    evidence = {
      path: source.path,
      span: {
        start: { line: source.span.start.line, column: source.span.start.column },
        end: { line: source.span.end.line, column: source.span.end.column },
      },
    };
  } catch (error) {
    sourceDetail = failureDetail(error);
  }
  if (evidence === null) {
    return {
      status: 'invalid',
      operation: lookup.operation,
      source: null,
      reason: 'invalid-source-evidence',
      detail: sourceDetail,
    };
  }
  switch (lookup.status) {
    case 'resolved':
      return {
        status: 'resolved',
        operation: lookup.operation,
        source: evidence,
        requirement: lookup.requirement,
        provenance: lookup.provenance,
      };
    case 'unsupported':
      return { status: 'unsupported', operation: lookup.operation, source: evidence, reason: lookup.reason };
    case 'missing':
      return { status: 'missing', operation: lookup.operation, source: evidence };
    default:
      return {
        status: 'invalid',
        operation: lookup.operation,
        source: evidence,
        reason: lookup.reason,
        detail: lookup.detail,
      };
  }
}

function assertRequirementFinding(value: unknown, label: string): asserts value is RequirementFinding {
  assertPlainObject(value, label);
  if (value.status === 'resolved') {
    assertExactKeys(value, ['operation', 'provenance', 'requirement', 'source', 'status'], label);
    assertOperationIdentity(value.operation, `${label}.operation`);
    validateSourceEvidence(value.source);
    validateRequirementExpression(value.requirement);
    assertCatalogProvenance(value.provenance, `${label}.provenance`);
    return;
  }
  if (value.status === 'unsupported') {
    assertExactKeys(value, ['operation', 'reason', 'source', 'status'], label);
    assertOperationIdentity(value.operation, `${label}.operation`);
    validateSourceEvidence(value.source);
    if (!CATALOG_UNSUPPORTED_REASONS.includes(value.reason as CatalogUnsupportedReason)) {
      throw new TypeError(`${label}.reason is invalid`);
    }
    return;
  }
  if (value.status === 'missing') {
    assertExactKeys(value, ['operation', 'source', 'status'], label);
    assertOperationIdentity(value.operation, `${label}.operation`);
    validateSourceEvidence(value.source);
    return;
  }
  if (value.status === 'invalid') {
    assertExactKeys(value, ['detail', 'operation', 'reason', 'source', 'status'], label);
    if (value.operation !== null) assertOperationIdentity(value.operation, `${label}.operation`);
    if (value.source !== null) validateSourceEvidence(value.source);
    if (!FINDING_INVALID_REASONS.includes(value.reason as FindingInvalidReason)) {
      throw new TypeError(`${label}.reason is invalid`);
    }
    assertNonEmptyString(value.detail, `${label}.detail`);
    return;
  }
  throw new TypeError(`${label}.status is invalid`);
}

function joinLevel(left: PermissionLevel, right: PermissionLevel): PermissionLevel {
  return LEVEL_RANK[right] > LEVEL_RANK[left] ? right : left;
}

/**
 * Groups root permission atoms by exact permission name and joins `none < read < write`
 * only inside one name.
 *
 * Empty input is a complete empty boundary. Any complex expression or any unsupported,
 * missing, or invalid finding produces an incomplete boundary that retains every original
 * finding and stable reason instead of a partial simple boundary.
 */
export function aggregatePermissionFindings(findings: readonly RequirementFinding[]): PermissionBoundary {
  if (!Array.isArray(findings)) throw new TypeError('findings must be an array');
  findings.forEach((finding, index) => assertRequirementFinding(finding, `findings[${index}]`));
  const reasons = new Set<BoundaryIncompleteReason>();
  const atoms: { permission: string; level: PermissionLevel; finding: RequirementFinding }[] = [];
  for (const finding of findings) {
    if (finding.status === 'unsupported') reasons.add('unsupported-permission-requirement');
    else if (finding.status === 'missing') reasons.add('missing-permission-requirement');
    else if (finding.status === 'invalid') reasons.add('invalid-permission-requirement');
    else if (finding.requirement.type !== 'permission') reasons.add('complex-permission-expression');
    else atoms.push({ permission: finding.requirement.permission, level: finding.requirement.level, finding });
  }
  if (reasons.size > 0) {
    return {
      status: 'incomplete',
      reasons: BOUNDARY_INCOMPLETE_REASONS.filter((reason) => reasons.has(reason)),
      findings: sortByCanonicalBytes(cloneJson(findings) as RequirementFinding[]),
    };
  }
  const groups = new Map<string, { permission: string; level: PermissionLevel; contributors: RequirementFinding[] }>();
  for (const atom of atoms) {
    const existing = groups.get(atom.permission);
    if (existing === undefined) {
      groups.set(atom.permission, {
        permission: atom.permission,
        level: atom.level,
        contributors: [cloneJson(atom.finding)],
      });
      continue;
    }
    existing.level = joinLevel(existing.level, atom.level);
    existing.contributors.push(cloneJson(atom.finding));
  }
  const permissions = [...groups.values()]
    .sort((left, right) => compareBytes(left.permission, right.permission))
    .map((group) => ({
      permission: group.permission,
      level: group.level,
      contributors: sortByCanonicalBytes(group.contributors),
    }));
  return { status: 'complete', permissions };
}

function assertPermissionBoundary(value: unknown, label: string): asserts value is PermissionBoundary {
  assertPlainObject(value, label);
  if (value.status === 'complete') {
    assertExactKeys(value, ['permissions', 'status'], label);
    if (!Array.isArray(value.permissions)) throw new TypeError(`${label}.permissions must be an array`);
    const names: string[] = [];
    for (const [index, entry] of value.permissions.entries()) {
      const entryLabel = `${label}.permissions[${index}]`;
      assertPlainObject(entry, entryLabel);
      assertExactKeys(entry, ['contributors', 'level', 'permission'], entryLabel);
      assertNonEmptyString(entry.permission, `${entryLabel}.permission`);
      if (entry.level !== 'read' && entry.level !== 'write') throw new TypeError(`${entryLabel}.level is invalid`);
      if (!Array.isArray(entry.contributors) || entry.contributors.length === 0) {
        throw new TypeError(`${entryLabel}.contributors must be a non-empty array`);
      }
      const levels: PermissionLevel[] = [];
      for (const [position, contributor] of entry.contributors.entries()) {
        const contributorLabel = `${entryLabel}.contributors[${position}]`;
        assertRequirementFinding(contributor, contributorLabel);
        if (contributor.status !== 'resolved' || contributor.requirement.type !== 'permission') {
          throw new TypeError(`${contributorLabel} is not a resolved permission atom`);
        }
        if (contributor.requirement.permission !== entry.permission) {
          throw new TypeError(`${contributorLabel} contributes a different permission name`);
        }
        levels.push(contributor.requirement.level);
      }
      if (levels.reduce(joinLevel) !== entry.level) {
        throw new TypeError(`${entryLabel}.level does not match its contributors`);
      }
      names.push(entry.permission);
    }
    if (new Set(names).size !== names.length) throw new TypeError(`${label} repeats a permission name`);
    return;
  }
  if (value.status === 'incomplete') {
    assertExactKeys(value, ['findings', 'reasons', 'status'], label);
    if (!Array.isArray(value.reasons) || value.reasons.length === 0) {
      throw new TypeError(`${label}.reasons must be a non-empty array`);
    }
    for (const reason of value.reasons) {
      if (!BOUNDARY_INCOMPLETE_REASONS.includes(reason as BoundaryIncompleteReason)) {
        throw new TypeError(`${label}.reasons contains an unknown reason`);
      }
    }
    if (!Array.isArray(value.findings)) throw new TypeError(`${label}.findings must be an array`);
    value.findings.forEach((finding: unknown, index) =>
      assertRequirementFinding(finding, `${label}.findings[${index}]`),
    );
    return;
  }
  throw new TypeError(`${label}.status is invalid`);
}

function requirementProjection(boundary: PermissionBoundary): string[] {
  if (boundary.status !== 'incomplete') return [];
  return boundary.findings
    .filter((finding) => finding.status === 'resolved')
    .map((finding) => requirementExpressionJson(finding.requirement))
    .sort(compareBytes);
}

/**
 * Projects every retained finding to the evidence that a relocation must not change.
 *
 * Source coordinates and human-readable detail are omitted because moving a call is not a
 * boundary change; the outcome class, full operation triple, reason, canonical requirement,
 * and resolved catalog provenance are retained because a different or additional unprovable
 * operation, or a different accepted catalog record for the same requirement, is.
 */
function evidenceProjection(boundary: PermissionBoundary): string[] {
  if (boundary.status !== 'incomplete') return [];
  return boundary.findings
    .map((finding) =>
      jsonBytes({
        status: finding.status,
        operation: finding.operation,
        reason: 'reason' in finding ? finding.reason : null,
        requirement: finding.status === 'resolved' ? canonicalizeRequirementExpression(finding.requirement) : null,
        provenance: finding.status === 'resolved' ? finding.provenance : null,
      }),
    )
    .sort(compareBytes);
}

function isStructurallyEquivalent(base: PermissionBoundary, head: PermissionBoundary): boolean {
  if (base.status !== 'incomplete' || head.status !== 'incomplete') return false;
  if (jsonBytes(base.reasons) !== jsonBytes(head.reasons)) return false;
  if (requirementProjection(base).length === 0) return false;
  return jsonBytes(evidenceProjection(base)) === jsonBytes(evidenceProjection(head));
}

function levelOf(boundary: PermissionBoundary, permission: string): BoundaryLevel {
  if (boundary.status !== 'complete') return 'none';
  return boundary.permissions.find((entry) => entry.permission === permission)?.level ?? 'none';
}

/**
 * Compares two boundaries conservatively.
 *
 * Complete simple boundaries are compared by exact permission name with absence
 * represented as `none`. If either side is incomplete the comparison stays incomplete and
 * retains both boundaries; identical canonical complex evidence may only be reported
 * through the qualified `structurallyEquivalent` marker inside that incomplete result and
 * is never converted into a simple permission boundary.
 *
 * `structurallyEquivalent` is true only when both sides are incomplete for the same
 * reasons, at least one side carries a resolved requirement, and every retained finding
 * matches apart from its source location. A different or additional unprovable operation
 * therefore stays visible instead of being absorbed into an equivalence claim.
 */
export function comparePermissionBoundaries(
  base: PermissionBoundary,
  head: PermissionBoundary,
): BoundaryComparison {
  assertPermissionBoundary(base, 'base boundary');
  assertPermissionBoundary(head, 'head boundary');
  if (base.status === 'incomplete' || head.status === 'incomplete') {
    const reasons = new Set<ComparisonIncompleteReason>();
    if (base.status === 'incomplete') {
      reasons.add('incomplete-base-boundary');
      for (const reason of base.reasons) reasons.add(reason);
    }
    if (head.status === 'incomplete') {
      reasons.add('incomplete-head-boundary');
      for (const reason of head.reasons) reasons.add(reason);
    }
    return {
      status: 'incomplete',
      reasons: [...reasons].sort(compareBytes),
      base: cloneJson(base),
      head: cloneJson(head),
      structurallyEquivalent: isStructurallyEquivalent(base, head),
    };
  }
  const names = [...new Set([...base.permissions, ...head.permissions].map((entry) => entry.permission))].sort(
    compareBytes,
  );
  const changes = names.map((permission) => {
    const baseLevel = levelOf(base, permission);
    const headLevel = levelOf(head, permission);
    const change: PermissionChange['change'] =
      LEVEL_RANK[headLevel] > LEVEL_RANK[baseLevel]
        ? 'expansion'
        : LEVEL_RANK[headLevel] < LEVEL_RANK[baseLevel]
          ? 'reduction'
          : 'unchanged';
    return { permission, base: baseLevel, head: headLevel, change };
  });
  return { status: 'complete', changes };
}
