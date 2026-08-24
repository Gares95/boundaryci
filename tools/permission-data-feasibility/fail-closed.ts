import { digestJson } from './artifact-sources.js';
import { assertExactKeys, assertPlainObject, assertSha256, type JsonValue } from './contracts.js';
import type { UnresolvedOperationReason } from './contracts.js';
import type { MethodJoinRow, OperationInventoryRow } from './inventory.js';
import type { PermissionEvidenceIncompleteReason } from './requirement-expression.js';

export type IncompleteReason =
  | 'ambiguous-permission-data'
  | 'conflicting-permission-data'
  | 'credential-semantics-unproven'
  | 'duplicate-endpoint-method'
  | 'duplicate-openapi-operation'
  | 'duplicate-permission-data'
  | 'invalid-endpoint-route'
  | 'malformed-permission-evidence'
  | 'missing-credential-identity'
  | 'missing-operation-identity'
  | 'missing-permission-data'
  | 'missing-runtime-method'
  | 'missing-standalone-method'
  | 'no-openapi-operation'
  | 'runtime-method-surface-mismatch'
  | 'source-integrity-mismatch'
  | 'stale-permission-source'
  | 'unreviewed-permission-source'
  | 'unsupported-access-level'
  | 'unsupported-permission-expression'
  | 'unsupported-permission-name'
  | 'unsupported-permission-qualifier';

export interface IncompleteDescription {
  code: IncompleteReason;
  outcome: 'incomplete-analysis';
  summary: string;
  explanation: string;
}

export interface IncompleteSemantics {
  schemaVersion: 1;
  topLevelOutcome: 'incomplete-analysis';
  definitions: IncompleteDescription[];
  contentSha256: string;
}

export const INCOMPLETE_REASONS: readonly IncompleteReason[] = [
  'ambiguous-permission-data',
  'conflicting-permission-data',
  'credential-semantics-unproven',
  'duplicate-endpoint-method',
  'duplicate-openapi-operation',
  'duplicate-permission-data',
  'invalid-endpoint-route',
  'malformed-permission-evidence',
  'missing-credential-identity',
  'missing-operation-identity',
  'missing-permission-data',
  'missing-runtime-method',
  'missing-standalone-method',
  'no-openapi-operation',
  'runtime-method-surface-mismatch',
  'source-integrity-mismatch',
  'stale-permission-source',
  'unreviewed-permission-source',
  'unsupported-access-level',
  'unsupported-permission-expression',
  'unsupported-permission-name',
  'unsupported-permission-qualifier',
];

const COMMON_SUFFIX =
  'Known evidence is retained, but the full observed permission boundary cannot be proven for this item. No unqualified clean or no-change conclusion is available.';

function exhaustive(value: never): never {
  throw new Error(`unmapped incomplete reason: ${String(value)}`);
}

export function describeIncomplete(code: IncompleteReason): IncompleteDescription {
  let summary: string;
  switch (code) {
    case 'ambiguous-permission-data':
      summary = 'Permission associations exist without a proven logical operator.';
      break;
    case 'conflicting-permission-data':
      summary = 'Applicable permission evidence disagrees.';
      break;
    case 'credential-semantics-unproven':
      summary = 'Permission evidence was observed for a credential class not proven equivalent to a GitHub App installation token.';
      break;
    case 'duplicate-endpoint-method':
      summary = 'The endpoint-method surface contains a duplicate method identity.';
      break;
    case 'duplicate-openapi-operation':
      summary = 'The route maps to more than one OpenAPI operation.';
      break;
    case 'duplicate-permission-data':
      summary = 'The permission expression repeats an atom.';
      break;
    case 'invalid-endpoint-route':
      summary = 'The endpoint route cannot be normalized safely.';
      break;
    case 'malformed-permission-evidence':
      summary = 'The permission evidence is empty or malformed.';
      break;
    case 'missing-credential-identity':
      summary = 'The evidence does not identify the credential class.';
      break;
    case 'missing-operation-identity':
      summary = 'The evidence does not identify an exact REST operation.';
      break;
    case 'missing-permission-data':
      summary = 'No applicable reviewed permission evidence is available.';
      break;
    case 'missing-runtime-method':
      summary = 'The runtime endpoint-method surface does not contain this method.';
      break;
    case 'missing-standalone-method':
      summary = 'The standalone endpoint-method surface does not contain this method.';
      break;
    case 'no-openapi-operation':
      summary = 'The normalized route has no unique OpenAPI operation.';
      break;
    case 'runtime-method-surface-mismatch':
      summary = 'The compared endpoint-method surfaces do not agree.';
      break;
    case 'source-integrity-mismatch':
      summary = 'A required evidence source failed its identity or digest check.';
      break;
    case 'stale-permission-source':
      summary = 'A lower-ranked permission source disagrees with current reviewed evidence.';
      break;
    case 'unreviewed-permission-source':
      summary = 'The only available association is not authoritative for permission semantics.';
      break;
    case 'unsupported-access-level':
      summary = 'The evidence uses an access level outside the supported read/write model.';
      break;
    case 'unsupported-permission-expression':
      summary = 'The permission requirement cannot be represented safely by the supported expression contract.';
      break;
    case 'unsupported-permission-name':
      summary = 'The permission name is outside the reviewed vocabulary.';
      break;
    case 'unsupported-permission-qualifier':
      summary = 'The evidence contains a qualifier whose semantics are not modeled.';
      break;
    default:
      return exhaustive(code);
  }
  return { code, outcome: 'incomplete-analysis', summary, explanation: `${summary} ${COMMON_SUFFIX}` };
}

export function buildIncompleteSemantics(): IncompleteSemantics {
  const unsigned: Omit<IncompleteSemantics, 'contentSha256'> = {
    schemaVersion: 1,
    topLevelOutcome: 'incomplete-analysis',
    definitions: INCOMPLETE_REASONS.map(describeIncomplete),
  };
  return { ...unsigned, contentSha256: digestJson(unsigned as unknown as JsonValue) };
}

export function validateIncompleteSemantics(value: unknown): asserts value is IncompleteSemantics {
  assertPlainObject(value, 'incomplete semantics');
  assertExactKeys(value, ['schemaVersion', 'topLevelOutcome', 'definitions', 'contentSha256'], 'incomplete semantics');
  if (value.schemaVersion !== 1 || value.topLevelOutcome !== 'incomplete-analysis' || !Array.isArray(value.definitions)) {
    throw new TypeError('incomplete semantics structure is invalid');
  }
  const expected = buildIncompleteSemantics();
  if (JSON.stringify(value.definitions) !== JSON.stringify(expected.definitions)) {
    throw new Error('incomplete semantics definitions mismatch');
  }
  assertSha256(value.contentSha256, 'incomplete semantics content digest');
  const { contentSha256: _contentSha256, ...unsigned } = value;
  if (value.contentSha256 !== digestJson(unsigned as unknown as JsonValue)) {
    throw new Error('incomplete semantics content digest mismatch');
  }
}

const OPERATION_REASON_MAP: Record<UnresolvedOperationReason, IncompleteReason> = {
  'artifact-manifest-digest-mismatch': 'source-integrity-mismatch',
  'endpoint-method-duplicate': 'duplicate-endpoint-method',
  'endpoint-method-missing-runtime': 'missing-runtime-method',
  'endpoint-method-missing-standalone': 'missing-standalone-method',
  'endpoint-route-invalid': 'invalid-endpoint-route',
  'openapi-operation-duplicate': 'duplicate-openapi-operation',
  'openapi-operation-missing': 'no-openapi-operation',
  'permission-evidence-mismatch': 'conflicting-permission-data',
  'permission-evidence-missing': 'missing-permission-data',
  'permission-source-digest-mismatch': 'source-integrity-mismatch',
  'runtime-surface-incompatibility': 'runtime-method-surface-mismatch',
};

const EXPRESSION_REASON_MAP: Record<PermissionEvidenceIncompleteReason, IncompleteReason> = {
  'conflicting-permission-atom': 'conflicting-permission-data',
  'credential-class-missing': 'missing-credential-identity',
  'duplicate-permission-atom': 'duplicate-permission-data',
  'empty-alternative': 'malformed-permission-evidence',
  'empty-expression': 'malformed-permission-evidence',
  'malformed-atom': 'malformed-permission-evidence',
  'operation-missing': 'missing-operation-identity',
  'unknown-access-level': 'unsupported-access-level',
  'unknown-permission': 'unsupported-permission-name',
  'unsupported-qualifier': 'unsupported-permission-qualifier',
};

export function mapOperationResolutionReason(reason: UnresolvedOperationReason): IncompleteReason {
  return OPERATION_REASON_MAP[reason];
}

export function mapExpressionReason(reason: PermissionEvidenceIncompleteReason): IncompleteReason {
  return EXPRESSION_REASON_MAP[reason];
}

export function incompleteReasonForOperation(row: OperationInventoryRow): IncompleteReason {
  if (row.freshness === 'stale-seed') return 'stale-permission-source';
  if (row.credentialApplicability === 'fine-grained-pat-only') return 'credential-semantics-unproven';
  if (row.reasons.includes('unsupported-seed-vocabulary')) return 'unsupported-permission-name';
  switch (row.evidenceClass) {
    case 'ambiguous':
      return 'ambiguous-permission-data';
    case 'conflicting':
      return 'conflicting-permission-data';
    case 'missing':
      return 'missing-permission-data';
    case 'unsupported':
      return row.reasons.includes('seed-not-authoritative')
        ? 'unreviewed-permission-source'
        : 'unsupported-permission-expression';
    case 'allOf':
    case 'anyOf':
      return 'unsupported-permission-expression';
    case 'single':
      return 'runtime-method-surface-mismatch';
    default:
      return exhaustive(row.evidenceClass);
  }
}

export function incompleteReasonForMethod(row: MethodJoinRow): IncompleteReason | null {
  if (row.surfaceStatus !== 'common-identical') return 'runtime-method-surface-mismatch';
  if (row.operationJoinStatus === 'no-openapi-operation') return 'no-openapi-operation';
  if (row.operationJoinStatus === 'duplicate-openapi-operation') return 'duplicate-openapi-operation';
  return null;
}
