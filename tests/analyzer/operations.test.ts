import { afterAll, describe, expect, it } from 'vitest';

import { analyzeSourceTree } from '../../src/analyzer/analyze.js';
import type { CandidateSite } from '../../src/analyzer/candidates.js';
import { DEFAULT_ANALYSIS_LIMITS } from '../../src/analyzer/contract.js';
import type { AnalysisRequest, ReceiverProvenance } from '../../src/analyzer/contract.js';
import {
  CALL_GRAMMAR_IDENTITY,
  parseStaticRequestRoute,
  resolveOperationCandidate,
} from '../../src/analyzer/operations.js';
import { ANALYZER_ENDPOINT_PROFILE } from '../../src/analyzer/profile.js';
import { buildSourceGraph } from '../../src/analyzer/resolve.js';
import type { SourceSpan } from '../../src/permission-model/model.js';

import grammarCases from './fixtures/call-grammar-cases.json' with { type: 'json' };
import { cleanupTempRoots, createTempRoot, writeRegularFile } from './helpers.js';

afterAll(cleanupTempRoots);

function requestFor(rootPath: string): AnalysisRequest {
  return {
    rootPath,
    include: ['**/*.ts'],
    exclude: [],
    probotEntrypoints: [],
    limits: { ...DEFAULT_ANALYSIS_LIMITS },
  };
}

async function analyze(source: string) {
  const root = await createTempRoot('boundaryci-operations-');
  await writeRegularFile(root, 'src/app.ts', `${source}\n`);
  return analyzeSourceTree(requestFor(root));
}

function receiverProofForTest(span: SourceSpan): ReceiverProvenance {
  return {
    origin: 'octokit-package-named-import',
    packageSpecifier: 'octokit',
    exportName: 'Octokit',
    constructorBinding: 'Octokit',
    constructorAliasChain: ['Octokit'],
    construction: 'direct-new',
    clientBinding: 'client',
    clientAliasChain: ['client'],
    access: 'local-binding',
    steps: [{
      kind: 'named-import',
      path: 'src/app.ts',
      span,
      binding: 'Octokit',
      specifier: 'octokit',
      resolvedPath: null,
      ruleId: null,
      ruleRow: null,
    }],
  };
}

describe('exact endpoint operation normalization', () => {
  it('uses the versioned call grammar and strict static-route parser', () => {
    expect(CALL_GRAMMAR_IDENTITY).toBe('boundaryci/octokit-call-grammar@1');
    expect(parseStaticRequestRoute('GET /repos/{owner}/{repo}/issues')).toEqual({
      status: 'parsed',
      method: 'GET',
      normalizedRoute: '/repos/{owner}/{repo}/issues',
    });
    for (const route of [
      '',
      'get /repos/{owner}/{repo}/issues',
      'GET  /repos/{owner}/{repo}/issues',
      'GET https://api.github.com/repos/{owner}/{repo}/issues',
      'GET /repos/{owner}/{repo}/issues?state=open',
      'GET /repos/{owner}/{repo}/../issues',
    ]) {
      expect(parseStaticRequestRoute(route), route).toEqual({ status: 'malformed' });
    }
  });

  it('normalizes exact direct members and keeps catalog gaps visible', async () => {
    const result = await analyze([
      "import { Octokit } from 'octokit';",
      'const client = new Octokit();',
      'client.rest.issues.listForRepo({});',
      'client.rest.issues.create({});',
      'client.rest.pulls.list({});',
    ].join('\n'));

    expect(result.status).toBe('incomplete');
    if (result.status === 'failed') throw new Error('analysis unexpectedly failed');
    expect(result.observations.map((entry) => entry.operation)).toEqual(
      grammarCases.direct.map(({ method, normalizedRoute, operationId }) => ({ method, normalizedRoute, operationId })),
    );
    expect(result.permissionResolutions.map((entry) => entry.finding.status)).toEqual([
      'resolved',
      'resolved',
      'missing',
    ]);
    expect(result.causes.map((cause) => cause.code)).toContain('permission-catalog-incomplete');
  });

  it('retains optional access and invocation as conditional evidence only', async () => {
    const result = await analyze([
      "import { Octokit } from 'octokit';",
      'const client = new Octokit();',
      'client?.rest.issues.create({});',
      'client.rest?.issues.create({});',
      'client.rest.issues.create?.({});',
    ].join('\n'));

    expect(result.status).toBe('complete');
    if (result.status !== 'complete') throw new Error('optional calls did not resolve completely');
    expect(result.observations).toHaveLength(3);
    expect(result.observations.map((entry) => entry.optional)).toEqual([true, true, true]);
    expect(new Set(result.observations.map((entry) => JSON.stringify(entry.operation)))).toEqual(
      new Set([JSON.stringify({
        method: 'POST',
        normalizedRoute: '/repos/{owner}/{repo}/issues',
        operationId: 'issues/create',
      })]),
    );
    expect(result.permissionBoundary.status).toBe('complete');
  });

  it('does not let endpoint shape substitute for receiver provenance', async () => {
    const result = await analyze([
      'const client = { rest: { issues: { create() {} } } };',
      'client.rest.issues.create();',
    ].join('\n'));

    expect(result.status).toBe('incomplete');
    if (result.status === 'failed') throw new Error('analysis unexpectedly failed');
    expect(result.observations).toEqual([]);
    expect(result.candidates).toHaveLength(1);
    expect(result.candidates[0]).toMatchObject({
      classification: 'incomplete',
      reason: 'unproven-receiver-provenance',
    });
  });

  it('fails closed on unknown or ambiguous endpoint profile rows', () => {
    const site: CandidateSite = {
      kind: 'direct-endpoint',
      anchor: 'pinned-endpoint-member-spelling',
      spelling: 'client.rest.issues.create',
      path: 'src/app.ts',
      span: { start: { line: 1, column: 1 }, end: { line: 1, column: 34 } },
      optional: false,
      receiver: { form: 'identifier', name: 'client' },
      receiverStart: 0,
      member: { scope: 'issues', method: 'create' },
      route: null,
      request: null,
      enclosingClassStart: null,
    };
    const receiver = receiverProofForTest(site.span);
    const graph = buildSourceGraph([]);

    expect(resolveOperationCandidate({ ...site, member: { scope: 'issues', method: 'notReal' } }, graph, receiver))
      .toMatchObject({ status: 'incomplete', reason: 'unknown-endpoint-member' });

    const member = ANALYZER_ENDPOINT_PROFILE.members.find(
      (entry) => entry.scope === 'issues' && entry.method === 'create',
    );
    if (member === undefined) throw new Error('pinned issues.create member is missing');
    const ambiguousProfile = {
      identity: ANALYZER_ENDPOINT_PROFILE.identity,
      members: [member, { ...member, operationId: 'issues/create-alternate' }],
      operations: ANALYZER_ENDPOINT_PROFILE.operations,
    };
    expect(resolveOperationCandidate(site, graph, receiver, ambiguousProfile)).toMatchObject({
      status: 'incomplete',
      reason: 'ambiguous-endpoint-member',
    });
  });

  it('censuses static unknown endpoint members on proven clients instead of returning false-clean', async () => {
    const result = await analyze([
      "import { Octokit } from 'octokit';",
      'const client = new Octokit();',
      'client.rest.issues.futureMethod({});',
      'client.rest.futureScope.create({});',
    ].join('\n'));

    expect(result.status).toBe('incomplete');
    if (result.status === 'failed') throw new Error('analysis unexpectedly failed');
    expect(result.observations).toEqual([]);
    expect(result.candidates).toHaveLength(2);
    expect(result.candidates.map((candidate) => candidate.reason)).toEqual([
      'unknown-endpoint-member',
      'unknown-endpoint-member',
    ]);
    expect(result.candidates.map((candidate) => candidate.classification)).toEqual([
      'incomplete',
      'incomplete',
    ]);
    expect(result.causes.map((cause) => cause.code)).toEqual([
      'unknown-endpoint-member',
      'unknown-endpoint-member',
    ]);
  });

  it('fails closed when one exact static request route has ambiguous operation rows', () => {
    const site: CandidateSite = {
      kind: 'positional-request',
      anchor: 'request-positional-route-argument',
      spelling: 'client.request(route)',
      path: 'src/app.ts',
      span: { start: { line: 1, column: 1 }, end: { line: 1, column: 48 } },
      optional: false,
      receiver: { form: 'identifier', name: 'client' },
      receiverStart: 0,
      member: null,
      route: 'GET /repos/{owner}/{repo}/issues',
      request: {
        form: 'positional',
        argument: { kind: 'literal', value: 'GET /repos/{owner}/{repo}/issues' },
        supportedArity: true,
      },
      enclosingClassStart: null,
    };
    const operation = ANALYZER_ENDPOINT_PROFILE.operations.find(
      (entry) =>
        entry.method === 'GET' && entry.normalizedRoute === '/repos/{owner}/{repo}/issues',
    );
    if (operation === undefined) throw new Error('pinned issues/list-for-repo operation is missing');
    const ambiguousProfile = {
      identity: ANALYZER_ENDPOINT_PROFILE.identity,
      members: ANALYZER_ENDPOINT_PROFILE.members,
      operations: [operation, { ...operation, operationId: 'issues/list-for-repo-alternate' }],
    };

    expect(
      resolveOperationCandidate(site, buildSourceGraph([]), receiverProofForTest(site.span), ambiguousProfile),
    ).toMatchObject({ status: 'incomplete', reason: 'ambiguous-request-route' });
  });
});
