import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { beforeAll, describe, expect, it } from 'vitest';

import { digestJson, parseBoundedJson, validateArtifactManifest } from '../artifact-sources.js';
import type { ArtifactManifest, JsonValue, PermissionSources } from '../contracts.js';
import { validatePermissionSources } from '../extract.js';
import { validateIncompleteSemantics, type IncompleteSemantics } from '../fail-closed.js';
import {
  validateOperationInventory,
  validateSupportManifest,
  type OperationInventory,
  type SupportManifest,
} from '../inventory.js';
import {
  buildFeasibilityPacket,
  buildOperationLedger,
  validateFeasibilityPacket,
  validateOperationLedger,
  type FeasibilityPacketInputs,
  type OperationLedger,
} from '../ledger.js';
import { validateCatalogEvidenceEntry, type CatalogEvidenceEntry } from '../provenance.js';

const PROJECT_ROOT = fileURLToPath(new URL('../../../', import.meta.url));
const ROOT = 'tools/permission-data-feasibility';

let inputs: FeasibilityPacketInputs;
let ledger: OperationLedger;

function read(path: string, maxBytes: number): unknown {
  return parseBoundedJson(PROJECT_ROOT, `${ROOT}/${path}`, maxBytes);
}

function resignEntry(entry: CatalogEvidenceEntry): void {
  const { entrySha256: _entrySha256, ...unsigned } = entry;
  entry.entrySha256 = digestJson(unsigned as unknown as JsonValue);
}

function resignLedger(value: OperationLedger): void {
  const supported = value.operationRows.filter((row) => row.entry !== null);
  for (const row of supported) {
    if (row.entry === null) continue;
    resignEntry(row.entry);
    const member = value.authorizedScopeCandidate.members.find(
      (candidate) => candidate.operationId === row.operationId,
    );
    if (member !== undefined) {
      member.entrySha256 = row.entry.entrySha256;
      member.expressionSha256 = row.entry.expressionSha256;
      member.artifactManifestSha256 = row.entry.provenance.artifactManifestSha256;
      member.supportPredicateSha256 = row.entry.supportPredicateSha256;
    }
  }
  value.authorizedScopeCandidate.authorizedScopeSha256 = digestJson(
    value.authorizedScopeCandidate.members as unknown as JsonValue,
  );
  const { contentSha256: _contentSha256, ...unsigned } = value;
  value.contentSha256 = digestJson(unsigned as unknown as JsonValue);
}

beforeAll(() => {
  const manifestValue = read('evidence/artifact-manifest.json', 2 * 1024 * 1024);
  validateArtifactManifest(manifestValue);
  const permissionValue = read('evidence/permission-sources.json', 2 * 1024 * 1024);
  validatePermissionSources(permissionValue);
  const inventoryValue = read('evidence/operation-inventory.json', 4 * 1024 * 1024);
  validateOperationInventory(inventoryValue);
  const supportValue = read('evidence/support-manifest.json', 2 * 1024 * 1024);
  validateSupportManifest(supportValue);
  const incompleteValue = read('evidence/incomplete-semantics.json', 2 * 1024 * 1024);
  validateIncompleteSemantics(incompleteValue);
  const canonicalIssues = JSON.parse(readFileSync(`${PROJECT_ROOT}/${ROOT}/fixtures/canonical-issues.json`, 'utf8')) as
    FeasibilityPacketInputs['canonicalIssues'];
  inputs = {
    artifactManifest: manifestValue as ArtifactManifest,
    permissionSources: permissionValue as PermissionSources,
    inventory: inventoryValue as OperationInventory,
    supportManifest: supportValue as SupportManifest,
    canonicalIssues,
    ledger: {} as OperationLedger,
    incompleteSemantics: incompleteValue as IncompleteSemantics,
  };
  ledger = buildOperationLedger(inputs);
  inputs.ledger = ledger;
});

describe('operation provenance ledger', () => {
  it('reconciles both universes and gives every selected member complete provenance', () => {
    expect(() => validateOperationLedger(ledger, inputs)).not.toThrow();
    expect(ledger.operationCounts).toEqual({ total: 878, candidateSupported: 2, incomplete: 876 });
    expect(ledger.methodCounts.total).toBe(inputs.inventory.methodUniverse.total);
    expect(ledger.operationRows).toHaveLength(inputs.inventory.operationUniverse.total);
    expect(ledger.methodJoinRows).toHaveLength(inputs.inventory.methodUniverse.total);
    expect(new Set(ledger.operationRows.map((row) => `${row.verb} ${row.path}`)).size).toBe(878);
    expect(new Set(ledger.methodJoinRows.map((row) => `${row.scope}.${row.method}`)).size).toBe(
      inputs.inventory.methodUniverse.total,
    );
    const supported = ledger.operationRows.filter((row) => row.disposition === 'candidate-supported');
    expect(supported).toHaveLength(inputs.supportManifest.selectedMembers.length);
    for (const row of supported) {
      const entry = row.entry;
      const inventoryRow = inputs.inventory.operationRows.find((candidate) => candidate.operationId === row.operationId);
      const member = inputs.supportManifest.selectedMembers.find((candidate) => candidate.operationId === row.operationId);
      const fact = inputs.permissionSources.facts.find((candidate) => candidate.operationId === row.operationId);
      if (entry === null || inventoryRow === undefined || member === undefined || fact === undefined) {
        throw new Error(`test setup lacks provenance for ${row.operationId}`);
      }
      expect(() =>
        validateCatalogEvidenceEntry(entry, {
          row: inventoryRow,
          member,
          fact,
          artifactManifest: inputs.artifactManifest,
          permissionSources: inputs.permissionSources,
          supportManifest: inputs.supportManifest,
        }),
      ).not.toThrow();
      expect(entry.provenance.upstreamArtifacts).toHaveLength(7);
      expect(entry.rawEvidenceSha256).toBe(fact.evidenceSha256);
      expect(entry.provenance.reviewStatus).toBe('reviewed');
    }
  });

  it('commits the exact rebuilt ledger and a distinct authorized-scope digest', () => {
    const committed = read('evidence/operation-ledger.json', 8 * 1024 * 1024);
    expect(committed).toEqual(ledger);
    expect(ledger.authorizedScopeCandidate.members.map((member) => member.operationId)).toEqual([
      'issues/create',
      'issues/list-for-repo',
    ]);
    expect(ledger.authorizedScopeCandidate.authorizedScopeSha256).not.toBe(ledger.supportPredicateSha256);
    expect(ledger.authorizedScopeCandidate.authorizedScopeSha256).not.toBe(ledger.preliminarySelectionSha256);
  });

  it('rejects re-signed drift in every provenance and scope identity class', () => {
    const mutations: ((entry: CatalogEvidenceEntry) => void)[] = [
      (entry) => {
        entry.operation.methodAliases = ['issues.other'];
      },
      (entry) => {
        entry.requirement = { type: 'permission', permission: 'issues', level: 'write' };
        entry.expressionSha256 = digestJson(entry.requirement as unknown as JsonValue);
      },
      (entry) => {
        entry.rawEvidence.path = '/repos/{owner}/{repo}/other';
        entry.rawEvidenceSha256 = digestJson(entry.rawEvidence as unknown as JsonValue);
      },
      (entry) => {
        entry.provenance.sourceUrl = 'https://docs.github.com/en/rest';
      },
      (entry) => {
        entry.provenance.apiVersion = '2022-11-28';
        entry.provenance.documentationVersioning = 'unversioned-live';
        entry.provenance.sourceDisposition = 'authoritative-reviewed';
        entry.provenance.sourcePrecedenceSha256 = '0'.repeat(64);
      },
      (entry) => {
        entry.provenance.credentialApplicability = 'github-app-reviewed';
        entry.provenance.credentialClass = 'github-app-installation-token';
        entry.provenance.reviewedOn = '2026-08-23';
      },
      (entry) => {
        const artifact = entry.provenance.upstreamArtifacts[0];
        if (artifact !== undefined) artifact.version = '0.0.0';
      },
      (entry) => {
        entry.supportPredicateSha256 = '0'.repeat(64);
      },
      (entry) => {
        entry.selectionSha256 = '0'.repeat(64);
      },
    ];
    for (const mutate of mutations) {
      const changed = structuredClone(ledger);
      const entry = changed.operationRows.find((row) => row.entry !== null)?.entry;
      if (entry === null || entry === undefined) throw new Error('test setup lacks supported entry');
      mutate(entry);
      resignLedger(changed);
      expect(() => validateOperationLedger(changed, inputs)).toThrow(/authoritative inputs/u);
    }
  });

  it('rejects unknown fields, duplicate operations, and missing reviewer evidence', () => {
    const unknown = structuredClone(ledger) as OperationLedger & { extra?: boolean };
    unknown.extra = true;
    expect(() => validateOperationLedger(unknown, inputs)).toThrow(/unexpected keys/u);

    const duplicate = structuredClone(ledger);
    const first = duplicate.operationRows[0];
    if (first !== undefined) duplicate.operationRows.push(structuredClone(first));
    duplicate.operationCounts.total += 1;
    duplicate.operationCounts.incomplete += 1;
    resignLedger(duplicate);
    expect(() => validateOperationLedger(duplicate, inputs)).toThrow(/authoritative inputs/u);

    const missingReviewer = structuredClone(ledger);
    const entry = missingReviewer.operationRows.find((row) => row.entry !== null)?.entry as
      | (CatalogEvidenceEntry & { provenance: CatalogEvidenceEntry['provenance'] & { reviewStatus: string } })
      | undefined;
    if (entry === undefined) throw new Error('test setup lacks supported entry');
    (entry.provenance as unknown as { reviewStatus: string }).reviewStatus = '';
    resignLedger(missingReviewer);
    expect(() => validateOperationLedger(missingReviewer, inputs)).toThrow(/authoritative inputs/u);
  });
});

describe('decision-free feasibility packet', () => {
  it('rebuilds exactly and binds all evidence without selecting an outcome', () => {
    const packet = buildFeasibilityPacket(inputs);
    expect(() => validateFeasibilityPacket(packet, inputs)).not.toThrow();
    expect(read('evidence/feasibility-packet.json', 4 * 1024 * 1024)).toEqual(packet);
    expect(packet.legalTerminalOutcomes).toEqual(['GO', 'GO WITH BOUNDED SUPPORT', 'NO-GO / RESCOPE']);
    expect(packet).not.toHaveProperty('decision');
    expect(packet).not.toHaveProperty('selectedOutcome');
    expect(packet.authorizedScopeCandidate.authorizedScopeSha256).toBe(
      ledger.authorizedScopeCandidate.authorizedScopeSha256,
    );
  });
});
