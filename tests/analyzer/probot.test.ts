import { afterAll, describe, expect, it } from 'vitest';

import { analyzeSourceTree } from '../../src/analyzer/analyze.js';
import { DEFAULT_ANALYSIS_LIMITS } from '../../src/analyzer/contract.js';
import type { AnalysisRequest, AnalysisResult } from '../../src/analyzer/contract.js';
import { PROBOT_PROFILE_IDENTITY } from '../../src/analyzer/probot.js';

import { cleanupTempRoots, createTempRoot, writeRegularFile } from './helpers.js';

afterAll(cleanupTempRoots);

function requestFor(rootPath: string, probotEntrypoints: readonly string[]): AnalysisRequest {
  return {
    rootPath,
    include: ['**/*.ts', '**/*.tsx'],
    exclude: [],
    probotEntrypoints: [...probotEntrypoints],
    limits: { ...DEFAULT_ANALYSIS_LIMITS },
  };
}

async function analyze(
  files: Readonly<Record<string, string>>,
  probotEntrypoints: readonly string[] = ['src/app.ts'],
): Promise<AnalysisResult> {
  const root = await createTempRoot('boundaryci-probot-');
  for (const [path, source] of Object.entries(files)) await writeRegularFile(root, path, `${source}\n`);
  return analyzeSourceTree(requestFor(root, probotEntrypoints));
}

function evidence(result: AnalysisResult) {
  if (result.status === 'failed') throw new Error(`analysis unexpectedly failed: ${JSON.stringify(result)}`);
  return result;
}

describe('trusted Probot entrypoint provenance', () => {
  it('identifies the bounded profile', () => {
    expect(PROBOT_PROFILE_IDENTITY).toBe('boundaryci/probot-provenance@1');
  });

  it.each([
    [
      'direct default function',
      [
        'export default function app(app) {',
        "  app.on('issues.opened', (context) => context.octokit.rest.issues.create({}));",
        '}',
      ].join('\n'),
    ],
    [
      'direct default arrow',
      [
        'export default (app) => {',
        "  app.on('issues.opened', (context) => context.octokit.rest.issues.create({}));",
        '};',
      ].join('\n'),
    ],
    [
      'named default function',
      [
        'function initialize(app) {',
        "  app.on('issues.opened', (context) => context.octokit.rest.issues.create({}));",
        '}',
        'export default initialize;',
      ].join('\n'),
    ],
    [
      'explicit named default export',
      [
        'const initialize = (app) => {',
        "  app.on('issues.opened', (context) => context.octokit.rest.issues.create({}));",
        '};',
        'export { initialize as default };',
      ].join('\n'),
    ],
  ])('proves %s initializer and inline handler Context', async (_name, source) => {
    const result = evidence(await analyze({ 'src/app.ts': source }));
    expect(result.status).toBe('complete');
    expect(result.observations.map((entry) => entry.operation.operationId)).toEqual(['issues/create']);
    expect(result.observations[0]?.receiver.origin).toBe('probot-context-octokit');
  });

  it('proves immutable named handler aliases and top-level Context octokit destructuring', async () => {
    const result = evidence(await analyze({
      'src/app.ts': [
        'const handlerAlias = handler;',
        'function handler({ octokit: github }) {',
        '  github.rest.issues.listForRepo({});',
        '}',
        'export default function boot(application) {',
        "  application.on('issues.opened', handlerAlias);",
        '}',
      ].join('\n'),
    }));
    expect(result.status).toBe('complete');
    expect(result.observations.map((entry) => entry.operation.operationId)).toEqual(['issues/list-for-repo']);
    expect(result.observations[0]?.receiver.origin).toBe('probot-context-octokit');
  });

  it('follows one explicit named relative handler export without evaluating a module', async () => {
    const result = evidence(await analyze({
      'src/app.ts': [
        "import { forwardedHandler } from './handlers.js';",
        'export default function boot(app) {',
        "  app.on('issues.opened', forwardedHandler);",
        '}',
      ].join('\n'),
      'src/handlers.ts': [
        'function handler(context) {',
        '  context.octokit.rest.issues.create({});',
        '}',
        'export { handler as forwardedHandler };',
      ].join('\n'),
    }));
    expect(result.status).toBe('complete');
    expect(result.observations[0]?.receiver.steps.map((step) => step.kind)).toContain('relative-source-resolution');
  });

  it('supports a const default initializer and an initializer-local immutable handler', async () => {
    const result = evidence(await analyze({
      'src/app.ts': [
        'const initialize = (app) => {',
        '  const handler = (context) => context.octokit.rest.issues.create({});',
        "  app.on('issues.opened', handler);",
        '};',
        'export default initialize;',
      ].join('\n'),
    }));
    expect(result.status).toBe('complete');
    expect(result.observations.map((entry) => entry.operation.operationId)).toEqual(['issues/create']);
  });

  it('follows multiple explicit named relative forwarding hops', async () => {
    const result = evidence(await analyze({
      'src/app.ts': [
        "import { handler } from './relay-a.js';",
        'export default (app) => app.on("issues.opened", handler);',
      ].join('\n'),
      'src/relay-a.ts': "export { handler } from './relay-b.js';",
      'src/relay-b.ts': "export { handler } from './handlers.js';",
      'src/handlers.ts': [
        'export function handler(context) {',
        '  context.octokit.rest.issues.create({});',
        '}',
      ].join('\n'),
    }));
    expect(result.status).toBe('complete');
    expect(result.observations[0]?.receiver.steps.filter((step) => step.kind === 'relative-source-resolution')).toHaveLength(3);
  });

  it('reports a relevant handler-forwarding cycle instead of recursing or treating it as absence', async () => {
    const result = evidence(await analyze({
      'src/app.ts': [
        "import { handler } from './relay-a.js';",
        'export default (app) => app.on("issues.opened", handler);',
      ].join('\n'),
      'src/relay-a.ts': "export { handler } from './relay-b.js';",
      'src/relay-b.ts': "export { handler } from './relay-a.js';",
    }));
    expect(result.status).toBe('incomplete');
    expect(result.observations).toEqual([]);
    expect(result.causes.map((cause) => cause.code)).toContain('relevant-resolution-cycle');
  });

  it.each([
    [
      'unresolved',
      {
        'src/app.ts': [
          "import { handler } from './missing.js';",
          'export default (app) => app.on("issues.opened", handler);',
        ].join('\n'),
      },
      'unresolved-relative-source',
    ],
    [
      'ambiguous',
      {
        'src/app.ts': [
          "import { handler } from './handlers.js';",
          'export default (app) => app.on("issues.opened", handler);',
        ].join('\n'),
        'src/handlers.ts': 'export const handler = (context) => context.octokit.rest.issues.create({});',
        'src/handlers.tsx': 'export const handler = (context) => context.octokit.rest.issues.create({});',
      },
      'ambiguous-relative-source',
    ],
  ])('reports %s handler source resolution explicitly', async (_name, files, cause) => {
    const result = evidence(await analyze(files));
    expect(result.status).toBe('incomplete');
    expect(result.observations).toEqual([]);
    expect(result.causes.map((entry) => entry.code)).toContain(cause);
  });

  it('does not let a malformed designated entrypoint suppress independent direct Octokit evidence', async () => {
    const result = evidence(await analyze({
      'src/app.ts': 'export default createInitializer();',
      'src/client.ts': [
        "import { Octokit } from 'octokit';",
        'const client = new Octokit();',
        'client.rest.issues.create({});',
      ].join('\n'),
    }));
    expect(result.status).toBe('incomplete');
    expect(result.observations).toHaveLength(1);
    expect(result.observations[0]?.receiver.origin).toBe('octokit-package-named-import');
    expect(result.causes.map((cause) => cause.code)).toContain('unsupported-probot-entrypoint-initializer');
  });

  it('does not census unrelated event emitters in a designated entrypoint file', async () => {
    const result = evidence(await analyze({
      'src/app.ts': [
        'export default (app) => {',
        "  app.on('issues.opened', () => {});",
        "  emitter.on('custom', callback);",
        '};',
      ].join('\n'),
    }));
    expect(result.status).toBe('complete');
    expect(result.candidates).toHaveLength(2);
    expect(result.candidates.map((candidate) => candidate.reason)).toEqual([
      'proven-probot-registration-contract',
      'proven-non-octokit-origin',
    ]);
  });

  it('does not census a same-spelled module binding outside the proved initializer', async () => {
    const result = evidence(await analyze({
      'src/app.ts': [
        'const app = emitter;',
        "app.on('custom', callback);",
        'export default (app) => {',
        "  app.on('issues.opened', () => {});",
        '};',
      ].join('\n'),
    }));
    expect(result.status).toBe('complete');
    expect(result.candidates).toHaveLength(2);
    expect(result.candidates.map((candidate) => candidate.reason)).toEqual([
      'proven-non-octokit-origin',
      'proven-probot-registration-contract',
    ]);
  });

  it('does not infer entrypoint or Context provenance from lookalike syntax', async () => {
    const result = evidence(await analyze({
      'src/app.ts': [
        'function bootstrap(app) {',
        "  app.on('issues.opened', (context) => context.octokit.rest.issues.create({}));",
        '}',
        'bootstrap({ on() {} });',
      ].join('\n'),
    }, []));
    expect(result.status).toBe('incomplete');
    expect(result.observations).toEqual([]);
    expect(result.candidates[0]).toMatchObject({
      classification: 'incomplete',
      reason: 'unproven-receiver-provenance',
    });
  });

  it.each([
    ['unsupported initializer', 'export default makeApp();', 'unsupported-probot-entrypoint-initializer'],
    ['unsupported registration', 'export default (app) => app.onAny((context) => context.octokit.rest.issues.create({}));', 'unsupported-probot-handler-registration'],
    ['unresolved named handler', "export default (app) => app.on('issues.opened', unknownHandler);", 'unsupported-probot-handler-registration'],
    ['nested callback', "export default (app) => app.on('issues.opened', (context) => later(() => context.octokit.rest.issues.create({})));", 'unproven-receiver-provenance'],
  ])('records explicit incompleteness for %s', async (_name, source, reason) => {
    const result = evidence(await analyze({ 'src/app.ts': source }));
    expect(result.status).toBe('incomplete');
    expect(result.observations).toEqual([]);
    expect([...result.candidates.map((candidate) => candidate.reason), ...result.causes.map((cause) => cause.code)]).toContain(reason);
  });

  it.each([
    [
      'shadowed app parameter',
      [
        'export default function boot(app) {',
        '  { const app = emitter; app.on("issues.opened", handler); }',
        '}',
        'function handler(context) { context.octokit.rest.issues.create({}); }',
      ].join('\n'),
    ],
    [
      'reassigned app parameter',
      [
        'export default function boot(app) {',
        '  app = emitter;',
        '  app.on("issues.opened", handler);',
        '}',
        'function handler(context) { context.octokit.rest.issues.create({}); }',
      ].join('\n'),
    ],
    [
      'shadowed Context parameter',
      [
        'export default (app) => app.on("issues.opened", (context) => {',
        '  { const context = other; context.octokit.rest.issues.create({}); }',
        '});',
      ].join('\n'),
    ],
    [
      'reassigned Context parameter',
      [
        'export default (app) => app.on("issues.opened", (context) => {',
        '  context = other;',
        '  context.octokit.rest.issues.create({});',
        '});',
      ].join('\n'),
    ],
    [
      'compound-reassigned Context parameter',
      [
        'export default (app) => app.on("issues.opened", (context) => {',
        '  context &&= other;',
        '  context.octokit.rest.issues.create({});',
        '});',
      ].join('\n'),
    ],
    [
      'catch-shadowed Context parameter',
      [
        'export default (app) => app.on("issues.opened", (context) => {',
        '  try { throw other; } catch (context) { context.octokit.rest.issues.create({}); }',
        '});',
      ].join('\n'),
    ],
    [
      'destructuring-shadowed Context parameter',
      [
        'export default (app) => app.on("issues.opened", (context) => {',
        '  { const { context } = other; context.octokit.rest.issues.create({}); }',
        '});',
      ].join('\n'),
    ],
    [
      'shadowed destructured Octokit binding',
      [
        'export default (app) => app.on("issues.opened", (context) => {',
        '  const { octokit: github } = context;',
        '  { const github = other; github.rest.issues.create({}); }',
        '});',
      ].join('\n'),
    ],
    [
      'reassigned destructured Octokit binding',
      [
        'export default (app) => app.on("issues.opened", (context) => {',
        '  const { octokit: github } = context;',
        '  github = other;',
        '  github.rest.issues.create({});',
        '});',
      ].join('\n'),
    ],
    [
      'reassigned named handler',
      [
        'function handler(context) { context.octokit.rest.issues.create({}); }',
        'handler = otherHandler;',
        'export default (app) => app.on("issues.opened", handler);',
      ].join('\n'),
    ],
    [
      'optional app registration',
      [
        'function handler(context) { context.octokit.rest.issues.create({}); }',
        'export default (app) => app?.on("issues.opened", handler);',
      ].join('\n'),
    ],
  ])('fails closed on unstable %s', async (_name, source) => {
    const result = evidence(await analyze({ 'src/app.ts': source }));
    expect(result.status).toBe('incomplete');
    expect(result.observations).toEqual([]);
  });
});
