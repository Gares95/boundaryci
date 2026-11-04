import { afterEach, describe, expect, it } from 'vitest';

import { analyzeSourceTree } from '../../src/analyzer/analyze.js';
import { DEFAULT_ANALYSIS_LIMITS } from '../../src/analyzer/contract.js';
import type { AnalysisResult } from '../../src/analyzer/contract.js';

import { cleanupTempRoots, createTempRoot, writeRegularFile } from './helpers.js';

/**
 * Adversarial false-clean regression: an authorized Octokit client's REST surface must never
 * disappear from the candidate census merely because it was detached before the call.
 *
 * Every incomplete case below was verified to issue a real write against the pinned
 * `octokit@5.0.5` runtime, yet released v1 reported `complete` with no candidate at all. The
 * analyzer must not *prove* these forms (endpoint extraction and the non-`request()` request
 * surfaces stay unsupported); it must report them as incomplete rather than silently clean.
 * Sites whose receiver is not a proven authorized client keep their v1 behavior exactly.
 */

const CLIENT = "import { Octokit } from 'octokit';\nconst client = new Octokit();\n";
const CALL = "({ owner: 'o', repo: 'r', title: 't' });\n";

afterEach(async () => {
  await cleanupTempRoots();
});

async function analyze(files: Readonly<Record<string, string>>, probotEntrypoints: readonly string[] = []): Promise<AnalysisResult> {
  const root = await createTempRoot('boundaryci-surface-extraction-');
  for (const [path, contents] of Object.entries(files)) await writeRegularFile(root, path, contents);
  return analyzeSourceTree({
    rootPath: root,
    include: ['**/*.ts'],
    exclude: [],
    probotEntrypoints: [...probotEntrypoints],
    limits: { ...DEFAULT_ANALYSIS_LIMITS },
  });
}

function summary(result: AnalysisResult): { status: string; candidates: string[]; operations: string[] } {
  if (result.status === 'failed') return { status: result.status, candidates: [], operations: [] };
  return {
    status: result.status,
    candidates: result.candidates.map((candidate) => `${candidate.kind}:${candidate.classification}:${candidate.reason}`),
    operations: result.observations.map((observation) => observation.operation.operationId),
  };
}

type DetachedCase = readonly [name: string, files: Readonly<Record<string, string>>, expectedCandidate: string, entrypoints?: readonly string[]];

const detachedSurfaces: readonly DetachedCase[] = [
  ['scope object alias', { 'a.ts': `${CLIENT}const issues = client.rest.issues;\nissues.create${CALL}` }, 'endpoint-extraction:incomplete:unsupported-endpoint-extraction'],
  ['bracketed scope object alias', { 'a.ts': `${CLIENT}const issues = client.rest['issues'];\nissues.create${CALL}` }, 'endpoint-extraction:incomplete:unsupported-endpoint-extraction'],
  ['rest object alias', { 'a.ts': `${CLIENT}const api = client.rest;\nconst { issues } = api;\nissues.create${CALL}` }, 'endpoint-extraction:incomplete:unsupported-endpoint-extraction'],
  ['scope destructured from rest', { 'a.ts': `${CLIENT}const { issues } = client.rest;\nissues.create${CALL}` }, 'endpoint-extraction:incomplete:unsupported-endpoint-extraction'],
  ['nested rest destructuring', { 'a.ts': `${CLIENT}const { rest: { issues } } = client;\nissues.create${CALL}` }, 'endpoint-extraction:incomplete:unsupported-endpoint-extraction'],
  ['scope object stored in a literal', { 'a.ts': `${CLIENT}const api = { i: client.rest.issues };\napi.i.create${CALL}` }, 'endpoint-extraction:incomplete:unsupported-endpoint-extraction'],
  ['scope object through a client alias', { 'a.ts': `${CLIENT}const github = client;\nconst issues = github.rest.issues;\nissues.create${CALL}` }, 'endpoint-extraction:incomplete:unsupported-endpoint-extraction'],
  [
    'scope object exported to another file',
    {
      'a.ts': `${CLIENT}export const issues = client.rest.issues;\n`,
      'b.ts': `import { issues } from './a.js';\nissues.create${CALL}`,
    },
    'endpoint-extraction:incomplete:unsupported-endpoint-extraction',
  ],
  ['request function alias', { 'a.ts': `${CLIENT}const send = client.request;\nsend('POST /repos/{owner}/{repo}/issues', { owner: 'o', repo: 'r', title: 't' });\n` }, 'endpoint-extraction:incomplete:unsupported-endpoint-extraction'],
  ['request function destructuring', { 'a.ts': `${CLIENT}const { request } = client;\nrequest('POST /repos/{owner}/{repo}/issues', { owner: 'o', repo: 'r', title: 't' });\n` }, 'endpoint-extraction:incomplete:unsupported-endpoint-extraction'],
  ['request defaults', { 'a.ts': `${CLIENT}const send = client.request.defaults({ owner: 'o' });\nsend('POST /repos/{owner}/{repo}/issues', { repo: 'r', title: 't' });\n` }, 'endpoint-extraction:incomplete:unsupported-endpoint-extraction'],
  ['paginate route', { 'a.ts': `${CLIENT}client.paginate('GET /repos/{owner}/{repo}/issues', { owner: 'o', repo: 'r' });\n` }, 'positional-request:incomplete:unsupported-request-grammar'],
  ['paginate iterator route', { 'a.ts': `${CLIENT}client.paginate.iterator('GET /repos/{owner}/{repo}/issues', { owner: 'o', repo: 'r' });\n` }, 'positional-request:incomplete:unsupported-request-grammar'],
  [
    'private field scope object',
    { 'a.ts': `import { Octokit } from 'octokit';\nclass Bot {\n  #client = new Octokit();\n  open() {\n    const issues = this.#client.rest.issues;\n    return issues.create${CALL}  }\n}\nnew Bot().open();\n` },
    'endpoint-extraction:incomplete:unsupported-endpoint-extraction',
  ],
  [
    'Probot context scope object',
    { 'app.ts': `export default (app: any) => {\n  app.on('issues.opened', async (context: any) => {\n    const issues = context.octokit.rest.issues;\n    await issues.create${CALL}  });\n};\n` },
    'endpoint-extraction:incomplete:unsupported-endpoint-extraction',
    ['app.ts'],
  ],
];

describe('detached authorized-client REST surfaces are never silently clean', () => {
  const cases = detachedSurfaces.map(([name, files, expectedCandidate, entrypoints]) => ({
    name, files, expectedCandidate, entrypoints: entrypoints ?? [],
  }));
  it.each(cases)('$name is incomplete, not complete', async ({ files, expectedCandidate, entrypoints }) => {
    const observed = summary(await analyze(files, entrypoints));
    expect(observed.status).toBe('incomplete');
    expect(observed.candidates).toContain(expectedCandidate);
    // Unsupported forms are never promoted to a proven operation.
    expect(observed.operations).toEqual([]);
  });
});

describe('the detached-surface obligation is anchored by proven provenance only', () => {
  it('keeps supported calls proven without adding obligations for their own chain prefixes', async () => {
    expect(summary(await analyze({
      'a.ts': `${CLIENT}client.rest.issues.create${CALL}client.request('POST /repos/{owner}/{repo}/issues', { owner: 'o', repo: 'r', title: 't' });\nclient.rest?.issues?.listForRepo({ owner: 'o', repo: 'r' });\n`,
    }))).toEqual({
      status: 'complete',
      candidates: [
        'direct-endpoint:proven-operation:proven-direct-rest-member-call',
        'positional-request:proven-operation:proven-static-request-call',
        'direct-endpoint:proven-operation:proven-direct-rest-member-call',
      ],
      operations: ['issues/create', 'issues/create', 'issues/list-for-repo'],
    });
  });

  it('adds nothing for look-alike objects whose receiver is proven non-Octokit', async () => {
    expect(summary(await analyze({
      'a.ts': [
        'const client = { rest: { issues: { create() { return null; } } }, request() { return null; }, paginate() { return null; } };',
        'const issues = client.rest.issues;',
        'const { rest } = client;',
        'const send = client.request;',
        "client.paginate('GET /repos/{owner}/{repo}/issues');",
        'export { issues, rest, send };',
        '',
      ].join('\n'),
    }))).toEqual({ status: 'complete', candidates: [], operations: [] });
  });

  it('adds nothing for unproven receivers that v1 never anchored', async () => {
    expect(summary(await analyze({
      'a.ts': [
        "import { request as httpsRequest } from 'node:https';",
        'export function handle(args: any, options: any) {',
        '  const { rest, request } = args;',
        '  const scope = options.rest.issues;',
        '  const send = options.request;',
        "  options.paginate('GET /anything');",
        '  return [rest, request, scope, send, httpsRequest];',
        '}',
        '',
      ].join('\n'),
    }))).toEqual({ status: 'complete', candidates: [], operations: [] });
  });
});
