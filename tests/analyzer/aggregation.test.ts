import { afterEach, describe, expect, it } from 'vitest';

import { analyzeSourceTree } from '../../src/analyzer/analyze.js';
import { DEFAULT_ANALYSIS_LIMITS } from '../../src/analyzer/contract.js';
import type { AnalysisRequest, CompleteAnalysisResult, IncompleteAnalysisResult } from '../../src/analyzer/contract.js';
import {
  aggregatePermissionFindings,
  resolveRequirementFinding,
  type CatalogProvenance,
  type PermissionCatalogEntry,
  type RequirementFinding,
  type RestOperationIdentity,
  type SourceEvidence,
} from '../../src/permission-model/model.js';

import { cleanupTempRoots, createTempRoot, writeRegularFile } from './helpers.js';

afterEach(cleanupTempRoots);

async function analyze(source: string): Promise<CompleteAnalysisResult | IncompleteAnalysisResult> {
  const rootPath = await createTempRoot('boundaryci-aggregation-');
  await writeRegularFile(rootPath, 'src/app.ts', source);
  const request: AnalysisRequest = {
    rootPath,
    include: ['**/*.ts'],
    exclude: [],
    probotEntrypoints: [],
    limits: { ...DEFAULT_ANALYSIS_LIMITS },
  };
  const result = await analyzeSourceTree(request);
  if (result.status === 'failed') throw new Error(`unexpected failed analysis: ${result.reason}`);
  return result;
}

const SYNTHETIC_PROVENANCE: CatalogProvenance = {
  authorizedScopeSha256: 'a'.repeat(64),
  expressionSha256: 'b'.repeat(64),
  entrySha256: 'c'.repeat(64),
  artifactManifestSha256: 'd'.repeat(64),
  supportPredicateSha256: 'e'.repeat(64),
};

function operation(operationId: string, method: string): RestOperationIdentity {
  return { method, normalizedRoute: `/repos/{owner}/{repo}/${operationId.replace('/', '-')}`, operationId };
}

function source(line: number): SourceEvidence {
  return { path: 'src/mixed.ts', span: { start: { line, column: 1 }, end: { line, column: 8 } } };
}

describe('production analyzer to Phase 2 contributor preservation', () => {
  it('returns a complete empty boundary for a source without observations', async () => {
    const result = await analyze('export const value = 1;\n');
    expect(result.status).toBe('complete');
    expect(result.observations).toEqual([]);
    expect(result.permissionBoundary).toEqual({ status: 'complete', permissions: [] });
  });

  it('retains every equal and adjacent contributor and joins Issues read/write to write', async () => {
    const result = await analyze([
      "import { Octokit } from 'octokit';",
      'const client = new Octokit();',
      'client.rest.issues.listForRepo({});',
      'client.rest.issues.listForRepo({});client.rest.issues.create({});',
      '',
    ].join('\n'));

    expect(result.status).toBe('complete');
    expect(result.observations).toHaveLength(3);
    expect(result.permissionResolutions).toHaveLength(3);
    expect(result.permissionBoundary).toMatchObject({ status: 'complete' });
    if (result.permissionBoundary.status !== 'complete') throw new Error('expected complete boundary');
    expect(result.permissionBoundary.permissions).toHaveLength(1);
    const issues = result.permissionBoundary.permissions[0];
    expect(issues).toMatchObject({ permission: 'issues', level: 'write' });
    expect(issues?.contributors).toHaveLength(3);
    expect(issues?.contributors.map((finding) => finding.operation?.operationId)).toEqual([
      'issues/list-for-repo',
      'issues/list-for-repo',
      'issues/create',
    ]);
    expect(issues?.contributors.map((finding) => finding.source?.span.start.line)).toEqual([3, 4, 4]);
  });

  it('retains a single observation as one exact contributor', async () => {
    const result = await analyze([
      "import { Octokit } from 'octokit';",
      'const client = new Octokit();',
      'client.rest.issues.listForRepo({});',
      '',
    ].join('\n'));

    expect(result.status).toBe('complete');
    expect(result.permissionBoundary).toMatchObject({ status: 'complete' });
    if (result.permissionBoundary.status !== 'complete') throw new Error('expected complete boundary');
    expect(result.permissionBoundary.permissions).toHaveLength(1);
    expect(result.permissionBoundary.permissions[0]).toMatchObject({ permission: 'issues', level: 'read' });
    expect(result.permissionBoundary.permissions[0]?.contributors).toHaveLength(1);
  });

  it('keeps the proven source operation when catalog resolution is incomplete', async () => {
    const result = await analyze([
      "import { Octokit } from 'octokit';",
      'const client = new Octokit();',
      'client.rest.pulls.list({});',
      '',
    ].join('\n'));
    expect(result.status).toBe('incomplete');
    expect(result.observations.map((entry) => entry.operation.operationId)).toEqual(['pulls/list']);
    expect(result.permissionBoundary.status).toBe('incomplete');
    if (result.permissionBoundary.status !== 'incomplete') throw new Error('expected incomplete boundary');
    expect(result.permissionBoundary.findings).toHaveLength(1);
    expect(result.permissionBoundary.findings[0]).toMatchObject({ status: 'missing' });
  });

  it('retains complex, unsupported, missing, invalid, and resolved findings in one stable incomplete boundary', () => {
    const atomOperation = operation('synthetic/atom', 'GET');
    const complexOperation = operation('synthetic/complex', 'POST');
    const unsupportedOperation = operation('synthetic/unsupported', 'PATCH');
    const catalog: readonly PermissionCatalogEntry[] = [
      {
        status: 'resolved',
        operation: atomOperation,
        requirement: { type: 'permission', permission: 'issues', level: 'read' },
        provenance: { ...SYNTHETIC_PROVENANCE },
      },
      {
        status: 'resolved',
        operation: complexOperation,
        requirement: {
          type: 'anyOf',
          requirements: [
            { type: 'permission', permission: 'contents', level: 'read' },
            { type: 'permission', permission: 'issues', level: 'write' },
          ],
        },
        provenance: { ...SYNTHETIC_PROVENANCE },
      },
      {
        status: 'unsupported',
        operation: unsupportedOperation,
        reason: 'unsupported-permission-qualifier',
        provenance: { ...SYNTHETIC_PROVENANCE },
      },
    ];

    const findings: RequirementFinding[] = [
      resolveRequirementFinding(catalog, atomOperation, source(1)),
      resolveRequirementFinding(catalog, complexOperation, source(2)),
      resolveRequirementFinding(catalog, unsupportedOperation, source(3)),
      resolveRequirementFinding(catalog, operation('synthetic/missing', 'GET'), source(4)),
      resolveRequirementFinding(
        [...catalog, { status: 'resolved' } as unknown as PermissionCatalogEntry],
        atomOperation,
        source(5),
      ),
    ];

    const boundary = aggregatePermissionFindings(findings);
    expect(boundary).toMatchObject({ status: 'incomplete' });
    if (boundary.status !== 'incomplete') throw new Error('expected incomplete boundary');
    expect(boundary.reasons).toEqual([
      'complex-permission-expression',
      'invalid-permission-requirement',
      'missing-permission-requirement',
      'unsupported-permission-requirement',
    ]);
    expect(boundary.findings).toHaveLength(5);
    expect(boundary.findings.map((finding) => finding.status).sort()).toEqual([
      'invalid',
      'missing',
      'resolved',
      'resolved',
      'unsupported',
    ]);
    expect(JSON.stringify(aggregatePermissionFindings([...findings].reverse()))).toBe(JSON.stringify(boundary));
    expect(boundary).not.toHaveProperty('permissions');
  });
});
