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

async function analyze(source: string): Promise<AnalysisResult> {
  const root = await createTempRoot('boundaryci-aliases-');
  await writeRegularFile(root, 'src/app.ts', `${source}\n`);
  return analyzeSourceTree(requestFor(root));
}

function evidence(result: AnalysisResult) {
  if (result.status === 'failed') throw new Error('analysis unexpectedly failed');
  return result;
}

const CLIENT = ["import { Octokit } from 'octokit';", 'const client = new Octokit();'];

describe('deferred Octokit call surfaces remain explicit incomplete candidates', () => {
  it.each([
    ['direct shorthand', 'client.issues.create({});', 'unsupported-endpoint-surface'],
    ['endpoint extraction', 'const createIssue = client.rest.issues.create; createIssue({});', 'unsupported-endpoint-extraction'],
    ['static bracket chain', "client['rest']['issues']['create']({});", 'unsupported-static-member-access'],
    ['dynamic member chain', "client.rest.issues[method]({});", 'unsupported-dynamic-member-access'],
  ])('does not prove %s', async (_name, call, reason) => {
    const result = evidence(await analyze([...CLIENT, call].join('\n')));
    expect(result.status).toBe('incomplete');
    expect(result.observations).toEqual([]);
    expect(result.candidates).toHaveLength(1);
    expect(result.candidates[0]).toMatchObject({ classification: 'incomplete', reason });
  });
});
