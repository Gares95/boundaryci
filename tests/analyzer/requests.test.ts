import { afterAll, describe, expect, it } from 'vitest';

import { analyzeSourceTree } from '../../src/analyzer/analyze.js';
import { DEFAULT_ANALYSIS_LIMITS } from '../../src/analyzer/contract.js';
import type { AnalysisRequest, AnalysisResult } from '../../src/analyzer/contract.js';

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

async function analyze(files: Readonly<Record<string, string>>): Promise<AnalysisResult> {
  const root = await createTempRoot('boundaryci-requests-');
  for (const [path, source] of Object.entries(files)) await writeRegularFile(root, path, `${source}\n`);
  return analyzeSourceTree(requestFor(root));
}

function evidence(result: AnalysisResult) {
  if (result.status === 'failed') throw new Error('analysis unexpectedly failed');
  return result;
}

const CLIENT = ["import { Octokit } from 'octokit';", 'const client = new Octokit();'];

describe('static positional request grammar', () => {
  it('accepts literals, no-substitution templates, local aliases, and explicit relative forwarding', async () => {
    const result = evidence(await analyze({
      'src/routes.ts': [
        "export const createRoute = 'POST /repos/{owner}/{repo}/issues';",
        'export { createRoute as forwardedRoute };',
      ].join('\n'),
      'src/app.ts': [
        ...CLIENT,
        "import { forwardedRoute } from './routes.js';",
        "const listRoute = 'GET /repos/{owner}/{repo}/issues';",
        'const listAlias = listRoute;',
        "client.request('GET /repos/{owner}/{repo}/issues');",
        'client.request(`POST /repos/{owner}/{repo}/issues`);',
        'client.request(listAlias);',
        'client.request(forwardedRoute);',
      ].join('\n'),
    }));

    expect(result.status).toBe('complete');
    expect(result.observations).toHaveLength(4);
    expect(result.observations.map((entry) => entry.member)).toEqual([null, null, null, null]);
    expect(result.observations.map((entry) => entry.operation.operationId)).toEqual([
      'issues/list-for-repo',
      'issues/create',
      'issues/list-for-repo',
      'issues/create',
    ]);
    expect(result.candidates.map((entry) => entry.reason)).toEqual([
      'proven-static-request-call',
      'proven-static-request-call',
      'proven-static-request-call',
      'proven-static-request-call',
    ]);
    expect(result.candidates.map((entry) => entry.spelling)).toContain('client.request(listAlias)');
  });

  it('distinguishes malformed, dynamic, and unknown routes without rewriting concrete paths', async () => {
    const result = evidence(await analyze({
      'src/app.ts': [
        ...CLIENT,
        "const dynamic = `GET /repos/${owner}/${repo}/issues`;",
        "client.request('get /repos/{owner}/{repo}/issues');",
        'client.request(dynamic);',
        "client.request('GET /repos/octo/example/issues');",
        'client.request(null);',
        "client.request('');",
        'client.request();',
        "client.request('GET /repos/{owner}/{repo}/issues', {}, 'extra');",
        'client.request(dynamic, {}, extra);',
      ].join('\n'),
    }));

    expect(result.status).toBe('incomplete');
    expect(result.observations).toEqual([]);
    expect(result.candidates.map((entry) => entry.reason)).toEqual([
      'malformed-request-route',
      'dynamic-request-route',
      'unknown-request-route',
      'dynamic-request-route',
      'malformed-request-route',
      'malformed-request-route',
      'unsupported-request-grammar',
      'unsupported-request-grammar',
    ]);
    expect(result.causes.map((cause) => cause.code)).toEqual([
      'dynamic-request-route',
      'malformed-request-route',
      'unknown-request-route',
      'dynamic-request-route',
      'malformed-request-route',
      'malformed-request-route',
      'unsupported-request-grammar',
      'unsupported-request-grammar',
    ]);
  });

  it('keeps repeated and concurrent analyses request-local and byte-identical', async () => {
    const files = {
      'src/app.ts': [
        ...CLIENT,
        "const route = 'POST /repos/{owner}/{repo}/issues';",
        'client.request(route);',
      ].join('\n'),
    };
    const first = await analyze(files);
    const replay = await analyze(files);
    const [left, right] = await Promise.all([analyze(files), analyze(files)]);
    const semantic = (result: AnalysisResult) => {
      if (result.status === 'failed') return result;
      return {
        status: result.status,
        candidates: result.candidates,
        causes: result.causes,
        observations: result.observations,
        permissionResolutions: result.permissionResolutions,
        permissionBoundary: result.permissionBoundary,
      };
    };
    expect(semantic(replay)).toEqual(semantic(first));
    expect(semantic(left)).toEqual(semantic(right));
  });

  it('retains optional request calls as the same conditional operations', async () => {
    const result = evidence(await analyze({
      'src/app.ts': [
        ...CLIENT,
        "client?.request('GET /repos/{owner}/{repo}/issues');",
        "client.request?.('POST /repos/{owner}/{repo}/issues');",
      ].join('\n'),
    }));
    expect(result.status).toBe('complete');
    expect(result.observations.map((entry) => entry.optional)).toEqual([true, true]);
    expect(result.observations.map((entry) => entry.operation.operationId)).toEqual([
      'issues/list-for-repo',
      'issues/create',
    ]);
  });

  it('does not treat a mutable route binding as immutable operation evidence', async () => {
    const result = evidence(await analyze({
      'src/app.ts': [
        ...CLIENT,
        "let route = 'GET /repos/{owner}/{repo}/issues';",
        'route = chooseRoute();',
        'client.request(route);',
      ].join('\n'),
    }));
    expect(result.status).toBe('incomplete');
    expect(result.observations).toEqual([]);
    expect(result.candidates).toHaveLength(1);
    expect(result.candidates[0]?.reason).toBe('dynamic-request-route');
    expect(result.causes.map((cause) => cause.code)).toEqual([
      'mutable-provenance-binding',
      'dynamic-request-route',
    ]);
  });

  it('does not rewrite encoded placeholders or trailing slashes to pinned templates', async () => {
    const result = evidence(await analyze({
      'src/app.ts': [
        ...CLIENT,
        "client.request('GET /repos/%7Bowner%7D/%7Brepo%7D/issues');",
        "client.request('GET /repos/{owner}/{repo}/issues/');",
      ].join('\n'),
    }));
    expect(result.status).toBe('incomplete');
    expect(result.observations).toEqual([]);
    expect(result.candidates.map((candidate) => candidate.reason)).toEqual([
      'unknown-request-route',
      'malformed-request-route',
    ]);
    expect(result.causes.map((cause) => cause.code)).toEqual([
      'unknown-request-route',
      'malformed-request-route',
    ]);
  });

  it('keeps literal bracket request access explicitly unsupported', async () => {
    const result = evidence(await analyze({
      'src/app.ts': [
        ...CLIENT,
        "client['request']('GET /repos/{owner}/{repo}/issues');",
      ].join('\n'),
    }));
    expect(result.status).toBe('incomplete');
    expect(result.observations).toEqual([]);
    expect(result.candidates).toHaveLength(1);
    expect(result.candidates[0]).toMatchObject({
      kind: 'static-bracket-member',
      classification: 'incomplete',
      reason: 'unsupported-static-member-access',
    });
    expect(result.causes.map((cause) => cause.code)).toEqual(['unsupported-static-member-access']);
  });
});

describe('fresh inline object request grammar', () => {
  it('accepts exact literal method/url properties and ignores unrelated parameter expressions', async () => {
    const result = evidence(await analyze({
      'src/app.ts': [
        ...CLIENT,
        "client.request({ method: 'POST', url: '/repos/{owner}/{repo}/issues', data: makePayload() });",
        'client.request({ url: `/repos/{owner}/{repo}/issues`, method: `GET`, headers: anything });',
      ].join('\n'),
    }));

    expect(result.status).toBe('complete');
    expect(result.observations.map((entry) => entry.operation.operationId)).toEqual([
      'issues/create',
      'issues/list-for-repo',
    ]);
    expect(result.observations.map((entry) => entry.member)).toEqual([null, null]);
  });

  it.each([
    ["client.request({ url: '/repos/{owner}/{repo}/issues' });", 'missing method'],
    ["client.request({ method: 'GET' });", 'missing url'],
    ["client.request({ method: 'GET', method: 'POST', url: '/repos/{owner}/{repo}/issues' });", 'duplicate'],
    ["client.request({ ['method']: 'GET', url: '/repos/{owner}/{repo}/issues' });", 'computed'],
    ["client.request({ get method() { return 'GET'; }, url: '/repos/{owner}/{repo}/issues' });", 'accessor'],
    ["client.request({ method, url: '/repos/{owner}/{repo}/issues' });", 'shorthand'],
    ["client.request({ ...options, method: 'GET', url: '/repos/{owner}/{repo}/issues' });", 'spread'],
    ["client.request({ method: 'GET', url: 'https://api.github.com/repos/{owner}/{repo}/issues' });", 'absolute'],
    ["client.request({ method: 'GET', url: '/repos/{owner}/{repo}/issues', baseUrl: other });", 'custom base'],
    ["client.request({ method: 'GET', url: '/repos/{owner}/{repo}/issues' }, {});", 'extra argument'],
  ])('rejects unsupported object shape: %s (%s)', async (call) => {
    const result = evidence(await analyze({ 'src/app.ts': [...CLIENT, call].join('\n') }));
    expect(result.status).toBe('incomplete');
    expect(result.observations).toEqual([]);
    expect(result.candidates).toHaveLength(1);
    expect(result.candidates[0]?.reason).toBe('unsupported-request-object');
    expect(result.causes.map((cause) => cause.code)).toEqual(['unsupported-request-object']);
  });

  it('rejects propagated request objects rather than treating them as route strings', async () => {
    const result = evidence(await analyze({
      'src/app.ts': [
        ...CLIENT,
        "const options = { method: 'GET', url: '/repos/{owner}/{repo}/issues' };",
        'client.request(options);',
      ].join('\n'),
    }));
    expect(result.status).toBe('incomplete');
    expect(result.observations).toEqual([]);
    expect(result.candidates[0]?.reason).toBe('unsupported-request-object');
  });
});
