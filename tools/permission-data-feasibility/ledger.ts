import { canonicalJson, digestJson } from './artifact-sources.js';
import {
  assertExactKeys,
  assertPlainObject,
  assertSha256,
  type ArtifactManifest,
  type CanonicalIssuesFixture,
  type JsonValue,
  type PermissionSources,
} from './contracts.js';
import {
  describeIncomplete,
  incompleteReasonForMethod,
  incompleteReasonForOperation,
  validateIncompleteSemantics,
  type IncompleteReason,
  type IncompleteSemantics,
} from './fail-closed.js';
import {
  validateOperationInventory,
  validateSupportManifest,
  type MethodJoinRow,
  type OperationInventory,
  type OperationInventoryRow,
  type SupportManifest,
} from './inventory.js';
import {
  buildCatalogEvidenceEntry,
  SOURCE_PRECEDENCE_MATRIX,
  SOURCE_PRECEDENCE_SHA256,
  validateCatalogEvidenceEntry,
  type CatalogEvidenceEntry,
} from './provenance.js';

export interface LedgerOperationRow {
  verb: string;
  path: string;
  operationId: string;
  evidenceClass: OperationInventoryRow['evidenceClass'];
  disposition: 'candidate-supported' | 'incomplete';
  incompleteReason: IncompleteReason | null;
  inventoryReasons: string[];
  entry: CatalogEvidenceEntry | null;
}

export interface LedgerMethodRow extends MethodJoinRow {
  disposition: 'resolved' | 'incomplete';
  incompleteReason: IncompleteReason | null;
}

export interface AuthorizedScopeMember {
  verb: string;
  path: string;
  operationId: string;
  expressionSha256: string;
  entrySha256: string;
  artifactManifestSha256: string;
  supportPredicateSha256: string;
}

export interface AuthorizedScopeCandidate {
  members: AuthorizedScopeMember[];
  authorizedScopeSha256: string;
}

export interface OperationLedger {
  schemaVersion: 1;
  artifactManifestSha256: string;
  permissionSourcesSha256: string;
  inventorySha256: string;
  supportManifestSha256: string;
  supportPredicateSha256: string;
  preliminarySelectionSha256: string;
  sourcePrecedenceSha256: string;
  operationCounts: { total: number; candidateSupported: number; incomplete: number };
  methodCounts: { total: number; resolved: number; incomplete: number };
  operationRows: LedgerOperationRow[];
  methodJoinRows: LedgerMethodRow[];
  authorizedScopeCandidate: AuthorizedScopeCandidate;
  contentSha256: string;
}

export interface LedgerInputs {
  artifactManifest: ArtifactManifest;
  permissionSources: PermissionSources;
  inventory: OperationInventory;
  supportManifest: SupportManifest;
}

export interface FeasibilityPacket {
  schemaVersion: 1;
  artifactManifest: {
    contentSha256: string;
    apiVersion: '2022-11-28';
    artifacts: { role: string; packageName: string; version: string; integrity: string; dataFileSha256s: string[] }[];
  };
  canonicalIssues: {
    contentSha256: string;
    chains: CanonicalIssuesFixture['chains'];
  };
  inventory: {
    contentSha256: string;
    operationUniverse: OperationInventory['operationUniverse'];
    methodUniverse: OperationInventory['methodUniverse'];
  };
  support: {
    strategy: SupportManifest['strategy'];
    predicateSha256: string;
    preliminarySelectionSha256: string;
  };
  authorizedScopeCandidate: AuthorizedScopeCandidate;
  ledger: {
    contentSha256: string;
    operationCounts: OperationLedger['operationCounts'];
    methodCounts: OperationLedger['methodCounts'];
  };
  sourcePrecedence: {
    matrix: typeof SOURCE_PRECEDENCE_MATRIX;
    contentSha256: string;
  };
  incompleteSemantics: {
    contentSha256: string;
    reasons: IncompleteReason[];
  };
  knownLimitations: string[];
  legalTerminalOutcomes: ['GO', 'GO WITH BOUNDED SUPPORT', 'NO-GO / RESCOPE'];
  contentSha256: string;
}

export interface FeasibilityPacketInputs extends LedgerInputs {
  canonicalIssues: CanonicalIssuesFixture;
  ledger: OperationLedger;
  incompleteSemantics: IncompleteSemantics;
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function uniqueByOperation<T extends { operationId: string }>(entries: readonly T[], label: string): Map<string, T> {
  const result = new Map<string, T>();
  for (const entry of entries) {
    if (result.has(entry.operationId)) throw new Error(`duplicate ${label} ${entry.operationId}`);
    result.set(entry.operationId, entry);
  }
  return result;
}

export function buildOperationLedger(inputs: LedgerInputs): OperationLedger {
  validateOperationInventory(inputs.inventory);
  validateSupportManifest(inputs.supportManifest);
  if (
    inputs.inventory.artifactManifestSha256 !== inputs.artifactManifest.contentSha256 ||
    inputs.inventory.permissionSourcesSha256 !== inputs.permissionSources.contentSha256 ||
    inputs.supportManifest.artifactManifestSha256 !== inputs.artifactManifest.contentSha256 ||
    inputs.supportManifest.permissionSourcesSha256 !== inputs.permissionSources.contentSha256
  ) {
    throw new Error('ledger input identity mismatch');
  }
  const inventoryRows = uniqueByOperation(inputs.inventory.operationRows, 'inventory operation');
  const members = uniqueByOperation(inputs.supportManifest.selectedMembers, 'support member');
  const entries = new Map<string, CatalogEvidenceEntry>();
  for (const [operationId, member] of members) {
    const row = inventoryRows.get(operationId);
    const facts = inputs.permissionSources.facts.filter((fact) => fact.operationId === operationId);
    if (row === undefined || facts.length !== 1 || facts[0] === undefined) {
      throw new Error(`supported operation ${operationId} lacks one exact row and permission fact`);
    }
    const context = {
      row,
      member,
      fact: facts[0],
      artifactManifest: inputs.artifactManifest,
      permissionSources: inputs.permissionSources,
      supportManifest: inputs.supportManifest,
    };
    const entry = buildCatalogEvidenceEntry(context);
    validateCatalogEvidenceEntry(entry, context);
    entries.set(operationId, entry);
  }
  if (entries.size !== inputs.supportManifest.selectedMembers.length) {
    throw new Error('supported ledger entry count mismatch');
  }

  const operationRows: LedgerOperationRow[] = inputs.inventory.operationRows.map((row) => {
    const entry = entries.get(row.operationId) ?? null;
    return {
      verb: row.verb,
      path: row.path,
      operationId: row.operationId,
      evidenceClass: row.evidenceClass,
      disposition: entry === null ? 'incomplete' : 'candidate-supported',
      incompleteReason: entry === null ? incompleteReasonForOperation(row) : null,
      inventoryReasons: [...row.reasons],
      entry,
    };
  });
  const methodJoinRows: LedgerMethodRow[] = inputs.inventory.methodJoinRows.map((row) => {
    const reason = incompleteReasonForMethod(row);
    return {
      ...structuredClone(row),
      disposition: reason === null ? 'resolved' : 'incomplete',
      incompleteReason: reason,
    };
  });
  const authorizedMembers: AuthorizedScopeMember[] = [...entries.values()]
    .map((entry) => ({
      verb: entry.operation.verb,
      path: entry.operation.path,
      operationId: entry.operation.operationId,
      expressionSha256: entry.expressionSha256,
      entrySha256: entry.entrySha256,
      artifactManifestSha256: entry.provenance.artifactManifestSha256,
      supportPredicateSha256: entry.supportPredicateSha256,
    }))
    .sort((left, right) => compareStrings(left.operationId, right.operationId));
  const authorizedScopeCandidate: AuthorizedScopeCandidate = {
    members: authorizedMembers,
    authorizedScopeSha256: digestJson(authorizedMembers as unknown as JsonValue),
  };
  const unsigned: Omit<OperationLedger, 'contentSha256'> = {
    schemaVersion: 1,
    artifactManifestSha256: inputs.artifactManifest.contentSha256,
    permissionSourcesSha256: inputs.permissionSources.contentSha256,
    inventorySha256: inputs.inventory.contentSha256,
    supportManifestSha256: inputs.supportManifest.contentSha256,
    supportPredicateSha256: inputs.supportManifest.predicate.ruleSha256,
    preliminarySelectionSha256: inputs.supportManifest.selectionSha256,
    sourcePrecedenceSha256: SOURCE_PRECEDENCE_SHA256,
    operationCounts: {
      total: operationRows.length,
      candidateSupported: operationRows.filter((row) => row.disposition === 'candidate-supported').length,
      incomplete: operationRows.filter((row) => row.disposition === 'incomplete').length,
    },
    methodCounts: {
      total: methodJoinRows.length,
      resolved: methodJoinRows.filter((row) => row.disposition === 'resolved').length,
      incomplete: methodJoinRows.filter((row) => row.disposition === 'incomplete').length,
    },
    operationRows,
    methodJoinRows,
    authorizedScopeCandidate,
  };
  return { ...unsigned, contentSha256: digestJson(unsigned as unknown as JsonValue) };
}

export function validateOperationLedger(value: unknown, inputs: LedgerInputs): asserts value is OperationLedger {
  assertPlainObject(value, 'operation ledger');
  assertExactKeys(
    value,
    [
      'schemaVersion',
      'artifactManifestSha256',
      'permissionSourcesSha256',
      'inventorySha256',
      'supportManifestSha256',
      'supportPredicateSha256',
      'preliminarySelectionSha256',
      'sourcePrecedenceSha256',
      'operationCounts',
      'methodCounts',
      'operationRows',
      'methodJoinRows',
      'authorizedScopeCandidate',
      'contentSha256',
    ],
    'operation ledger',
  );
  if (value.schemaVersion !== 1 || !Array.isArray(value.operationRows) || !Array.isArray(value.methodJoinRows)) {
    throw new TypeError('operation ledger structure is invalid');
  }
  for (const key of [
    'artifactManifestSha256',
    'permissionSourcesSha256',
    'inventorySha256',
    'supportManifestSha256',
    'supportPredicateSha256',
    'preliminarySelectionSha256',
    'sourcePrecedenceSha256',
    'contentSha256',
  ] as const) {
    assertSha256(value[key], `operation ledger.${key}`);
  }
  assertPlainObject(value.authorizedScopeCandidate, 'authorized scope candidate');
  assertExactKeys(value.authorizedScopeCandidate, ['members', 'authorizedScopeSha256'], 'authorized scope candidate');
  if (!Array.isArray(value.authorizedScopeCandidate.members)) throw new TypeError('authorized scope members are invalid');
  assertSha256(value.authorizedScopeCandidate.authorizedScopeSha256, 'authorized scope candidate digest');
  const expected = buildOperationLedger(inputs);
  if (canonicalJson(value as unknown as JsonValue) !== canonicalJson(expected as unknown as JsonValue)) {
    throw new Error('operation ledger does not match its authoritative inputs');
  }
}

export function buildFeasibilityPacket(inputs: FeasibilityPacketInputs): FeasibilityPacket {
  validateOperationLedger(inputs.ledger, inputs);
  validateIncompleteSemantics(inputs.incompleteSemantics);
  if (
    inputs.canonicalIssues.artifactManifestSha256 !== inputs.artifactManifest.contentSha256 ||
    inputs.canonicalIssues.permissionSourcesSha256 !== inputs.permissionSources.contentSha256
  ) {
    throw new Error('canonical Issues fixture identity mismatch');
  }
  const reasons = inputs.incompleteSemantics.definitions.map((definition) => definition.code);
  const unsigned: Omit<FeasibilityPacket, 'contentSha256'> = {
    schemaVersion: 1,
    artifactManifest: {
      contentSha256: inputs.artifactManifest.contentSha256,
      apiVersion: inputs.artifactManifest.githubRestApiEvidenceVersion,
      artifacts: inputs.artifactManifest.artifacts.map((artifact) => ({
        role: artifact.role,
        packageName: artifact.packageName,
        version: artifact.version,
        integrity: artifact.integrity,
        dataFileSha256s: artifact.dataFiles.map((file) => file.sha256),
      })),
    },
    canonicalIssues: {
      contentSha256: inputs.canonicalIssues.contentSha256,
      chains: structuredClone(inputs.canonicalIssues.chains),
    },
    inventory: {
      contentSha256: inputs.inventory.contentSha256,
      operationUniverse: structuredClone(inputs.inventory.operationUniverse),
      methodUniverse: structuredClone(inputs.inventory.methodUniverse),
    },
    support: {
      strategy: inputs.supportManifest.strategy,
      predicateSha256: inputs.supportManifest.predicate.ruleSha256,
      preliminarySelectionSha256: inputs.supportManifest.selectionSha256,
    },
    authorizedScopeCandidate: structuredClone(inputs.ledger.authorizedScopeCandidate),
    ledger: {
      contentSha256: inputs.ledger.contentSha256,
      operationCounts: structuredClone(inputs.ledger.operationCounts),
      methodCounts: structuredClone(inputs.ledger.methodCounts),
    },
    sourcePrecedence: {
      matrix: structuredClone(SOURCE_PRECEDENCE_MATRIX),
      contentSha256: SOURCE_PRECEDENCE_SHA256,
    },
    incompleteSemantics: { contentSha256: inputs.incompleteSemantics.contentSha256, reasons },
    knownLimitations: [
      'The candidate scope contains only the two exact reviewer-backed canonical Issues operations.',
      'No reviewed GitHub App-applicable allOf expression is available in the retained evidence.',
      'Fine-grained personal access token anyOf observations do not prove installation-token semantics.',
      'The permission-package inverse index is incomplete, operator-less, and stale for some entries.',
      'The reviewed GitHub permission documentation is live and unversioned; its review date is retained.',
    ],
    legalTerminalOutcomes: ['GO', 'GO WITH BOUNDED SUPPORT', 'NO-GO / RESCOPE'],
  };
  return { ...unsigned, contentSha256: digestJson(unsigned as unknown as JsonValue) };
}

export function validateFeasibilityPacket(
  value: unknown,
  inputs: FeasibilityPacketInputs,
): asserts value is FeasibilityPacket {
  assertPlainObject(value, 'feasibility packet');
  assertExactKeys(
    value,
    [
      'schemaVersion',
      'artifactManifest',
      'canonicalIssues',
      'inventory',
      'support',
      'authorizedScopeCandidate',
      'ledger',
      'sourcePrecedence',
      'incompleteSemantics',
      'knownLimitations',
      'legalTerminalOutcomes',
      'contentSha256',
    ],
    'feasibility packet',
  );
  if (value.schemaVersion !== 1) throw new TypeError('feasibility packet schema version mismatch');
  if ('decision' in value || 'selectedOutcome' in value || 'terminalDecision' in value) {
    throw new TypeError('feasibility packet must not select a terminal outcome');
  }
  assertSha256(value.contentSha256, 'feasibility packet content digest');
  const expected = buildFeasibilityPacket(inputs);
  if (canonicalJson(value as unknown as JsonValue) !== canonicalJson(expected as unknown as JsonValue)) {
    throw new Error('feasibility packet does not match its authoritative inputs');
  }
}

export function knownIncompleteDescriptions(semantics: IncompleteSemantics): string[] {
  return semantics.definitions.map((definition) => describeIncomplete(definition.code).explanation);
}
