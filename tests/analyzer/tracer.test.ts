import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import { afterAll, describe, expect, it } from 'vitest';

import { analyzeSourceTree } from '../../src/analyzer/analyze.js';
import {
  ANALYSIS_DISCOVERY_PROFILE_ID,
  ANALYSIS_LIMIT_PROFILE_ID,
  ANALYSIS_SCHEMA_ID,
  ANALYSIS_SPAN_CONVENTION_ID,
  DEFAULT_ANALYSIS_LIMITS,
  validateAnalysisResult,
  type AnalysisRequest,
  type AnalysisResult,
  type CompleteAnalysisResult,
  type IncompleteAnalysisResult,
} from '../../src/analyzer/contract.js';
import {
  ANALYZER_ENDPOINT_PROFILE,
  ANALYZER_PROFILE_IDENTITY,
  DETACHED_ENDPOINT_AUTHORIZATIONS,
  DIRECT_SHORTHAND_AUTHORIZATIONS,
} from '../../src/analyzer/profile.js';
import { BOUNDARYCI_PERMISSION_CATALOG } from '../../src/permission-model/bounded-catalog.js';
import type { SourceSpan } from '../../src/permission-model/model.js';

const roots: string[] = [];

afterAll(async () => {
  for (const root of roots) await rm(root, { recursive: true, force: true });
});

/**
 * Materializes a source-only fixture tree.
 *
 * Every entry is written as byte content and is only ever read back as bytes: no fixture is
 * installed, imported, transpiled, built, or executed by these tests or by the analyzer.
 */
async function makeTree(files: Readonly<Record<string, string>>): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'boundaryci-analyzer-'));
  roots.push(root);
  for (const [relative, content] of Object.entries(files)) {
    const target = join(root, ...relative.split('/'));
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, content, 'utf8');
  }
  return root;
}

function requestFor(rootPath: string, overrides: Partial<AnalysisRequest> = {}): AnalysisRequest {
  return {
    rootPath,
    include: ['**/*.ts'],
    exclude: [],
    probotEntrypoints: [],
    limits: { ...DEFAULT_ANALYSIS_LIMITS },
    ...overrides,
  };
}

/**
 * Computes the expected span of a single-line snippet independently of the analyzer.
 *
 * This pins the declared span convention: 1-based line and column, `start` inclusive and
 * `end` exclusive.
 */
function spanOfSnippet(source: string, snippet: string): SourceSpan {
  const index = source.indexOf(snippet);
  if (index < 0) throw new Error('the snippet is not present in the fixture');
  const before = source.slice(0, index);
  const line = before.split('\n').length;
  const column = index - (before.lastIndexOf('\n') + 1) + 1;
  return { start: { line, column }, end: { line, column: column + snippet.length } };
}

function expectComplete(result: AnalysisResult): CompleteAnalysisResult {
  if (result.status !== 'complete') throw new Error(`expected a complete result, received ${result.status}`);
  return result;
}

function expectIncomplete(result: AnalysisResult): IncompleteAnalysisResult {
  if (result.status !== 'incomplete') throw new Error(`expected an incomplete result, received ${result.status}`);
  return result;
}

const ISSUES_SOURCE = [
  "import { Octokit } from 'octokit';",
  '',
  'const client = new Octokit();',
  '',
  'export async function listAndCreate(owner: string, repo: string): Promise<void> {',
  '  await client.rest.issues.listForRepo({ owner, repo });',
  "  await client.rest.issues.create({ owner, repo, title: 'Boundary' });",
  '}',
  '',
].join('\n');

const PULLS_SOURCE = [
  "import { Octokit } from 'octokit';",
  '',
  'const client = new Octokit();',
  '',
  'export async function listPulls(owner: string, repo: string): Promise<void> {',
  '  await client.rest.pulls.list({ owner, repo });',
  '}',
  '',
].join('\n');

const LOOKALIKE_SOURCE = [
  'const client = { rest: { issues: { create: async (): Promise<void> => undefined } } };',
  '',
  'export async function report(): Promise<void> {',
  '  await client.rest.issues.create();',
  '}',
  '',
].join('\n');

const WRONG_PACKAGE_SOURCE = [
  "import { Octokit } from 'octokit-lookalike';",
  '',
  'const forged = new Octokit();',
  '',
  'export async function forge(owner: string, repo: string): Promise<void> {',
  "  await forged.rest.issues.create({ owner, repo, title: 'Forged' });",
  '}',
  '',
].join('\n');

describe('pinned analyzer endpoint profile', () => {
  it('projects the reviewed inventory exactly and authorizes no extra surface', () => {
    expect(ANALYZER_PROFILE_IDENTITY).toEqual({
      schemaVersion: 1,
      profileId: 'boundaryci/octokit-analyzer-profile@1',
      octokitVersion: '5.0.5',
      endpointMethodsVersion: '18.0.0',
      restApiVersion: '2022-11-28',
      inventoryContentSha256: 'ce52c93c636e725b40dde745b9e435ef01e26cda39c53510842c43eaaa5c4ff4',
      artifactManifestSha256: 'ffe2270a26567042f146e0ec982a7343de51a1f6333f2de6fa0421aca1e4c94c',
      endpointMemberCount: 1010,
      operationCount: 878,
    });
    expect(ANALYZER_ENDPOINT_PROFILE.members).toHaveLength(1010);
    expect(ANALYZER_ENDPOINT_PROFILE.operations).toHaveLength(878);
    expect(Object.isFrozen(ANALYZER_ENDPOINT_PROFILE.members)).toBe(true);
    expect(Object.isFrozen(ANALYZER_ENDPOINT_PROFILE.operations)).toBe(true);

    const memberIds = ANALYZER_ENDPOINT_PROFILE.members.map((member) => `${member.scope}.${member.method}`);
    expect(new Set(memberIds).size).toBe(memberIds.length);
    expect([...memberIds].sort()).toEqual(memberIds);
    for (const member of ANALYZER_ENDPOINT_PROFILE.members) {
      expect(member.httpMethod).toMatch(/^[A-Z]+$/u);
      expect(member.normalizedRoute.startsWith('/')).toBe(true);
      expect(member.operationId.length).toBeGreaterThan(0);
    }

    const operationKeys = ANALYZER_ENDPOINT_PROFILE.operations.map(
      (operation) => `${operation.method} ${operation.normalizedRoute}`,
    );
    expect(new Set(operationKeys).size).toBe(operationKeys.length);

    expect(DIRECT_SHORTHAND_AUTHORIZATIONS).toEqual([]);
    expect(DETACHED_ENDPOINT_AUTHORIZATIONS).toEqual([]);
    expect(Object.isFrozen(DIRECT_SHORTHAND_AUTHORIZATIONS)).toBe(true);
    expect(Object.isFrozen(DETACHED_ENDPOINT_AUTHORIZATIONS)).toBe(true);
  });

  it('keeps profile membership separate from permission-catalog authority', () => {
    const profiled = ANALYZER_ENDPOINT_PROFILE.members.filter((member) => member.scope === 'issues');
    expect(profiled.length).toBeGreaterThan(2);
    expect(BOUNDARYCI_PERMISSION_CATALOG).toHaveLength(2);
    expect(BOUNDARYCI_PERMISSION_CATALOG.map((entry) => entry.operation.operationId)).toEqual([
      'issues/create',
      'issues/list-for-repo',
    ]);
  });

  it('maps the flagship members to their exact pinned routes rather than to a name heuristic', () => {
    const byId = new Map(ANALYZER_ENDPOINT_PROFILE.members.map((member) => [`${member.scope}.${member.method}`, member]));
    expect(byId.get('issues.listForRepo')).toEqual({
      scope: 'issues',
      method: 'listForRepo',
      httpMethod: 'GET',
      normalizedRoute: '/repos/{owner}/{repo}/issues',
      operationId: 'issues/list-for-repo',
    });
    expect(byId.get('issues.create')).toEqual({
      scope: 'issues',
      method: 'create',
      httpMethod: 'POST',
      normalizedRoute: '/repos/{owner}/{repo}/issues',
      operationId: 'issues/create',
    });
    expect(byId.get('pulls.list')).toEqual({
      scope: 'pulls',
      method: 'list',
      httpMethod: 'GET',
      normalizedRoute: '/repos/{owner}/{repo}/pulls',
      operationId: 'pulls/list',
    });
    expect(byId.get('issues.createForRepo')).toBeUndefined();
  });
});

describe('direct Octokit tracer', () => {
  it('proves both authorized Issues operations from real source bytes to one write aggregate', async () => {
    const root = await makeTree({ 'src/app.ts': ISSUES_SOURCE });
    const result = expectComplete(await analyzeSourceTree(requestFor(root)));

    expect(() => {
      validateAnalysisResult(result);
    }).not.toThrow();
    expect(result.causes).toEqual([]);
    expect(result.identity).toEqual({
      schemaId: ANALYSIS_SCHEMA_ID,
      schemaVersion: 1,
      spanConventionId: ANALYSIS_SPAN_CONVENTION_ID,
      analyzerProfile: ANALYZER_PROFILE_IDENTITY,
      discoveryProfileId: ANALYSIS_DISCOVERY_PROFILE_ID,
      limitProfileId: ANALYSIS_LIMIT_PROFILE_ID,
      permissionCatalogScopeSha256: '40c14243b7d1940d395ae9731ecd3fda962807aee297c9b72aeb591a3dd2b418',
    });

    expect(result.sources).toEqual([
      {
        id: 'source-0001',
        path: 'src/app.ts',
        byteSize: Buffer.byteLength(ISSUES_SOURCE, 'utf8'),
        contentSha256: expect.stringMatching(/^[a-f0-9]{64}$/u) as unknown as string,
      },
    ]);

    const listSpan = spanOfSnippet(ISSUES_SOURCE, 'client.rest.issues.listForRepo({ owner, repo })');
    const createSpan = spanOfSnippet(ISSUES_SOURCE, "client.rest.issues.create({ owner, repo, title: 'Boundary' })");

    expect(result.observations).toHaveLength(2);
    expect(result.observations[0]).toEqual({
      id: 'operation-0001',
      candidateId: 'candidate-0001',
      callForm: 'direct-rest-member-call',
      spelling: 'client.rest.issues.listForRepo',
      optional: false,
      member: {
        profileId: ANALYZER_PROFILE_IDENTITY.profileId,
        memberId: 'issues.listForRepo',
        scope: 'issues',
        method: 'listForRepo',
      },
      operation: {
        method: 'GET',
        normalizedRoute: '/repos/{owner}/{repo}/issues',
        operationId: 'issues/list-for-repo',
      },
      receiver: {
        origin: 'octokit-package-named-import',
        packageSpecifier: 'octokit',
        exportName: 'Octokit',
        constructorBinding: 'Octokit',
        constructorAliasChain: ['Octokit'],
        construction: 'direct-new',
        clientBinding: 'client',
        clientAliasChain: ['client'],
      },
      source: { path: 'src/app.ts', span: listSpan },
    });
    expect(result.observations[1]).toMatchObject({
      id: 'operation-0002',
      candidateId: 'candidate-0002',
      operation: {
        method: 'POST',
        normalizedRoute: '/repos/{owner}/{repo}/issues',
        operationId: 'issues/create',
      },
      source: { path: 'src/app.ts', span: createSpan },
    });

    expect(result.candidates.map((candidate) => candidate.classification)).toEqual([
      'proven-operation',
      'proven-operation',
    ]);
    expect(result.candidates.map((candidate) => candidate.anchor)).toEqual([
      'pinned-endpoint-member-spelling',
      'pinned-endpoint-member-spelling',
    ]);

    expect(result.permissionResolutions).toHaveLength(2);
    expect(result.permissionResolutions[0]).toMatchObject({
      id: 'resolution-0001',
      observationId: 'operation-0001',
      finding: { status: 'resolved', requirement: { type: 'permission', permission: 'issues', level: 'read' } },
    });
    expect(result.permissionResolutions[1]).toMatchObject({
      id: 'resolution-0002',
      observationId: 'operation-0002',
      finding: { status: 'resolved', requirement: { type: 'permission', permission: 'issues', level: 'write' } },
    });

    expect(result.permissionBoundary.status).toBe('complete');
    if (result.permissionBoundary.status !== 'complete') throw new Error('expected a complete boundary');
    expect(result.permissionBoundary.permissions).toHaveLength(1);
    const issues = result.permissionBoundary.permissions[0];
    expect(issues?.permission).toBe('issues');
    expect(issues?.level).toBe('write');
    expect(issues?.contributors).toHaveLength(2);
    expect(issues?.contributors.map((contributor) => contributor.source.span)).toEqual(
      expect.arrayContaining([listSpan, createSpan]),
    );
  });

  it('follows immutable constructor and client aliases without widening the authorized origin', async () => {
    const source = [
      "import { Octokit as GitHubClient } from 'octokit';",
      '',
      'const Constructor = GitHubClient;',
      'const primary = new Constructor();',
      'const github = primary;',
      '',
      'export async function create(owner: string, repo: string): Promise<void> {',
      "  await github.rest.issues.create({ owner, repo, title: 'Aliased' });",
      '}',
      '',
    ].join('\n');
    const root = await makeTree({ 'src/aliased.ts': source });
    const result = expectComplete(await analyzeSourceTree(requestFor(root)));

    expect(result.observations).toHaveLength(1);
    expect(result.observations[0]?.receiver).toEqual({
      origin: 'octokit-package-named-import',
      packageSpecifier: 'octokit',
      exportName: 'Octokit',
      constructorBinding: 'GitHubClient',
      constructorAliasChain: ['GitHubClient', 'Constructor'],
      construction: 'direct-new',
      clientBinding: 'primary',
      clientAliasChain: ['primary', 'github'],
    });
    expect(result.observations[0]?.operation.operationId).toBe('issues/create');
  });
});

describe('operation recognition independent of permission authority', () => {
  it('keeps an exact profiled operation visible when the bounded catalog has no row', async () => {
    const root = await makeTree({ 'src/pulls.ts': PULLS_SOURCE });
    const result = expectIncomplete(await analyzeSourceTree(requestFor(root)));

    expect(result.identity.analyzerProfile).toEqual(ANALYZER_PROFILE_IDENTITY);
    expect(result.observations).toHaveLength(1);
    expect(result.observations[0]).toMatchObject({
      spelling: 'client.rest.pulls.list',
      member: { memberId: 'pulls.list', scope: 'pulls', method: 'list' },
      operation: { method: 'GET', normalizedRoute: '/repos/{owner}/{repo}/pulls', operationId: 'pulls/list' },
      source: { path: 'src/pulls.ts', span: spanOfSnippet(PULLS_SOURCE, 'client.rest.pulls.list({ owner, repo })') },
    });
    expect(result.candidates.map((candidate) => candidate.classification)).toEqual(['proven-operation']);

    expect(result.permissionResolutions).toHaveLength(1);
    expect(result.permissionResolutions[0]?.finding).toMatchObject({
      status: 'missing',
      operation: { operationId: 'pulls/list' },
    });
    expect(result.permissionBoundary).toMatchObject({
      status: 'incomplete',
      reasons: ['missing-permission-requirement'],
    });
    expect(result.causes.map((cause) => cause.code)).toEqual(['permission-catalog-incomplete']);

    // The catalog gap never becomes a catalog row.
    expect(BOUNDARYCI_PERMISSION_CATALOG.map((entry) => entry.operation.operationId)).not.toContain('pulls/list');
  });

  it('preserves proven positive evidence when an unrelated candidate is unresolved', async () => {
    const root = await makeTree({ 'src/app.ts': ISSUES_SOURCE, 'src/lookalike.ts': LOOKALIKE_SOURCE });
    const result = expectIncomplete(await analyzeSourceTree(requestFor(root)));

    expect(result.observations.map((observation) => observation.operation.operationId)).toEqual([
      'issues/list-for-repo',
      'issues/create',
    ]);
    expect(result.permissionResolutions.map((resolution) => resolution.finding.status)).toEqual([
      'resolved',
      'resolved',
    ]);
    expect(result.permissionBoundary).toMatchObject({ status: 'complete' });
    expect(result.candidates.filter((candidate) => candidate.classification === 'incomplete')).toHaveLength(1);
    expect(result.causes.map((cause) => cause.code)).toEqual(['unproven-receiver-provenance']);
  });
});

describe('receiver provenance', () => {
  it('never proves a lookalike receiver and never reports it as a clean repository', async () => {
    const root = await makeTree({
      'src/lookalike.ts': LOOKALIKE_SOURCE,
      'src/wrong-package.ts': WRONG_PACKAGE_SOURCE,
    });
    const result = expectIncomplete(await analyzeSourceTree(requestFor(root)));

    expect(result.observations).toEqual([]);
    expect(result.permissionResolutions).toEqual([]);
    expect(result.permissionBoundary).toEqual({ status: 'complete', permissions: [] });

    expect(result.candidates).toHaveLength(2);
    for (const candidate of result.candidates) {
      expect(candidate.classification).toBe('incomplete');
      expect(candidate.reason).toBe('unproven-receiver-provenance');
      expect(candidate.observationId).toBeNull();
      expect(candidate.causeIds.length).toBeGreaterThan(0);
    }
    expect(result.candidates.map((candidate) => candidate.path)).toEqual([
      'src/lookalike.ts',
      'src/wrong-package.ts',
    ]);
    // Failure to prove Octokit provenance is never converted into proof of a non-Octokit origin.
    expect(result.candidates.some((candidate) => candidate.classification === 'proven-irrelevant')).toBe(false);
  });

  it('withdraws provenance from a reassigned or shadowed client binding', async () => {
    const source = [
      "import { Octokit } from 'octokit';",
      '',
      'let client = new Octokit();',
      '',
      'export async function run(owner: string, repo: string): Promise<void> {',
      "  await client.rest.issues.create({ owner, repo, title: 'Mutable' });",
      '}',
      '',
    ].join('\n');
    const root = await makeTree({ 'src/mutable.ts': source });
    const result = expectIncomplete(await analyzeSourceTree(requestFor(root)));

    expect(result.observations).toEqual([]);
    expect(result.candidates).toHaveLength(1);
    expect(result.candidates[0]?.reason).toBe('unproven-receiver-provenance');
  });

  it('records unsupported endpoint surfaces and static bracket chains instead of dropping them', async () => {
    const source = [
      "import { Octokit } from 'octokit';",
      '',
      'const client = new Octokit();',
      '',
      'export async function run(owner: string, repo: string): Promise<void> {',
      "  await client.issues.create({ owner, repo, title: 'Shorthand' });",
      "  await client['rest']['issues']['create']({ owner, repo, title: 'Bracket' });",
      '}',
      '',
    ].join('\n');
    const root = await makeTree({ 'src/unsupported.ts': source });
    const result = expectIncomplete(await analyzeSourceTree(requestFor(root)));

    expect(result.observations).toEqual([]);
    expect(result.candidates.map((candidate) => [candidate.kind, candidate.reason])).toEqual([
      ['client-endpoint-shorthand-call', 'unsupported-endpoint-surface'],
      ['bracket-member-call', 'unsupported-static-member-access'],
    ]);
    expect([...result.causes.map((cause) => cause.code)].sort()).toEqual([
      'unsupported-endpoint-surface',
      'unsupported-static-member-access',
    ]);
  });
});

describe('result determinism and diagnostic-only failure', () => {
  it('returns a diagnostic-only failed result for invalid trusted input', async () => {
    const root = await makeTree({ 'src/app.ts': ISSUES_SOURCE });
    const invalid: unknown[] = [
      null,
      [],
      { ...requestFor(root), include: [] },
      { ...requestFor(root), include: ['!(src)/**/*.ts'] },
      { ...requestFor(root), probotEntrypoints: ['../outside/app.ts'] },
      { ...requestFor(root), limits: { ...DEFAULT_ANALYSIS_LIMITS, maxSourceFiles: -1 } },
      { ...requestFor(root), extra: true },
    ];

    for (const candidate of invalid) {
      const result = await analyzeSourceTree(candidate as AnalysisRequest);
      if (result.status !== 'failed') throw new Error('expected a failed result');
      expect(Object.keys(result).sort()).toEqual(['causes', 'identity', 'reason', 'status']);
      expect(result).not.toHaveProperty('observations');
      expect(result).not.toHaveProperty('permissionResolutions');
      expect(result).not.toHaveProperty('permissionBoundary');
      expect(result).not.toHaveProperty('candidates');
      expect(result).not.toHaveProperty('sources');
      expect(result.reason).toBe('invalid-analysis-request');
      expect(result.identity.analyzerProfile).toEqual(ANALYZER_PROFILE_IDENTITY);
      expect(result.causes).toHaveLength(1);
      expect(result.causes[0]?.detail).not.toContain(root);
      expect(() => {
        validateAnalysisResult(result);
      }).not.toThrow();
    }
  });

  it('fails closed on an unresolvable analysis root and on a contradictory Probot entrypoint', async () => {
    const root = await makeTree({ 'src/app.ts': ISSUES_SOURCE });

    const missing = await analyzeSourceTree(requestFor(join(root, 'no-such-directory')));
    expect(missing).toMatchObject({
      status: 'failed',
      reason: 'unresolvable-analysis-root',
      identity: { analyzerProfile: ANALYZER_PROFILE_IDENTITY },
    });

    const file = await analyzeSourceTree(requestFor(join(root, 'src/app.ts')));
    expect(file).toMatchObject({
      status: 'failed',
      reason: 'analysis-root-not-a-directory',
      identity: { analyzerProfile: ANALYZER_PROFILE_IDENTITY },
    });

    const contradictory = await analyzeSourceTree(
      requestFor(root, { probotEntrypoints: ['src/not-discovered.ts'] }),
    );
    expect(contradictory).toMatchObject({
      status: 'failed',
      reason: 'probot-entrypoint-outside-source-universe',
      identity: { analyzerProfile: ANALYZER_PROFILE_IDENTITY },
    });
  });

  it('produces byte-identical JSON for identical normalized input under different host roots', async () => {
    const files = { 'src/app.ts': ISSUES_SOURCE, 'src/pulls.ts': PULLS_SOURCE, 'src/lookalike.ts': LOOKALIKE_SOURCE };
    const first = await makeTree(files);
    const second = await makeTree(files);

    const runs = await Promise.all([
      analyzeSourceTree(requestFor(first)),
      analyzeSourceTree(requestFor(first)),
      analyzeSourceTree(requestFor(second)),
    ]);
    const serialized = runs.map((run) => JSON.stringify(run));
    expect(serialized[1]).toBe(serialized[0]);
    expect(serialized[2]).toBe(serialized[0]);
    expect(serialized[0]).not.toContain(first);
    expect(serialized[0]).not.toContain(second);

    const parsed: unknown = JSON.parse(serialized[0] ?? '');
    expect(parsed).toEqual(runs[0]);
    expect(() => {
      validateAnalysisResult(parsed);
    }).not.toThrow();

    const failures = await Promise.all([
      analyzeSourceTree({ ...requestFor(first), include: [] }),
      analyzeSourceTree({ ...requestFor(second), include: [] }),
    ]);
    expect(JSON.stringify(failures[1])).toBe(JSON.stringify(failures[0]));
  });

  it('returns a complete empty result for a source universe with no anchored candidate', async () => {
    const root = await makeTree({ 'src/plain.ts': 'export const value = 1;\n' });
    const result = expectComplete(await analyzeSourceTree(requestFor(root)));

    expect(result.candidates).toEqual([]);
    expect(result.observations).toEqual([]);
    expect(result.causes).toEqual([]);
    expect(result.permissionBoundary).toEqual({ status: 'complete', permissions: [] });
    expect(result.sources.map((source) => source.path)).toEqual(['src/plain.ts']);
    expect(result.boundary).toEqual({
      include: ['**/*.ts'],
      exclude: [],
      probotEntrypoints: [],
      limits: { ...DEFAULT_ANALYSIS_LIMITS },
      sourceExtensions: ['.js', '.jsx', '.mjs', '.mts', '.ts', '.tsx'],
    });
  });

  it('rejects a result whose analyzer-profile identity is malformed or carries an unknown field', async () => {
    const root = await makeTree({ 'src/app.ts': ISSUES_SOURCE });
    const result = expectComplete(await analyzeSourceTree(requestFor(root)));
    const validProfile = result.identity.analyzerProfile as unknown as Record<string, unknown>;
    const { artifactManifestSha256: _omitted, ...profileWithoutDigest } = validProfile;

    const malformedProfiles: Record<string, unknown>[] = [
      { ...validProfile, octokitVersion: 'v5.0.5' },
      { ...validProfile, endpointMethodsVersion: '18.0' },
      { ...validProfile, restApiVersion: '2022-11-28T00:00:00Z' },
      { ...validProfile, inventoryContentSha256: 'not-a-lowercase-sha256' },
      profileWithoutDigest,
      { ...validProfile, endpointMemberCount: -1 },
      { ...validProfile, operationCount: 1.5 },
      { ...validProfile, profileId: '' },
      { ...validProfile, extraUnknownField: true },
    ];

    for (const analyzerProfile of malformedProfiles) {
      const malformed = { ...result, identity: { ...result.identity, analyzerProfile } };
      expect(() => {
        validateAnalysisResult(malformed);
      }).toThrow();
    }

    expect(() => {
      validateAnalysisResult({ ...result, identity: { ...result.identity, analyzerProfile: validProfile } });
    }).not.toThrow();
  });
});
