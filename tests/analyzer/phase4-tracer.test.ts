/**
 * Phase 4 Plan 04-01 Task 1 tracer: one local base-default read-to-write check traced through
 * configuration, the existing analyzer, revision comparison, policy, JSON serialization, and
 * the CLI exit path, plus proof that sentinel target source is never executed.
 */

import { afterEach, describe, expect, it } from 'vitest';

import {
  CHECK_RESULT_SCHEMA_ID,
  CHECK_RESULT_SCHEMA_VERSION,
  EXIT_CODE_POLICY_FAILURE,
  runCli,
} from '../../src/cli/main.js';
import type { CliIO } from '../../src/cli/main.js';
import { BOUNDARYCI_CONFIG_SCHEMA_VERSION, BUILTIN_CONFIG, effectiveConfigIdentity } from '../../src/config/model.js';
import { compareRevisionAnalyses } from '../../src/diff/revision.js';
import { analyzeLocalSnapshot, evaluateLocalComparison } from '../../src/runtime/evaluate.js';
import { BOUNDARYCI_PERMISSION_CATALOG, BOUNDARYCI_PERMISSION_CATALOG_IDENTITY } from '../../src/permission-model/bounded-catalog.js';

import { cleanupTempRoots, createTempRoot, writeRegularFile } from './helpers.js';

afterEach(cleanupTempRoots);

function recordingIo(): CliIO & { stdoutChunks: string[]; stderrChunks: string[] } {
  const stdoutChunks: string[] = [];
  const stderrChunks: string[] = [];
  return {
    stdoutChunks,
    stderrChunks,
    stdout: { write: (chunk: string) => stdoutChunks.push(chunk) },
    stderr: { write: (chunk: string) => stderrChunks.push(chunk) },
  };
}

const READ_SOURCE =
  "import { Octokit } from 'octokit';\nconst client = new Octokit();\nclient.rest.issues.listForRepo({});\n";
const WRITE_SOURCE = "import { Octokit } from 'octokit';\nconst client = new Octokit();\nclient.rest.issues.create({});\n";

describe('Phase 4 Task 1 tracer', () => {
  it('expands Issues: read to Issues: write with canonical operation and source contributors retained', async () => {
    const baseRoot = await createTempRoot('boundaryci-phase4-expansion-base-');
    const headRoot = await createTempRoot('boundaryci-phase4-expansion-head-');
    await writeRegularFile(baseRoot, 'src/app.ts', READ_SOURCE);
    await writeRegularFile(headRoot, 'src/app.ts', WRITE_SOURCE);

    const outcome = await evaluateLocalComparison(baseRoot, headRoot, BUILTIN_CONFIG);

    expect(outcome.comparison.status).toBe('complete');
    if (outcome.comparison.status !== 'complete') throw new Error('unreachable');
    expect(outcome.comparison.boundary.changes).toEqual([
      { permission: 'issues', base: 'read', head: 'write', change: 'expansion' },
    ]);

    const baseResult = outcome.comparison.base.result;
    const headResult = outcome.comparison.head.result;
    expect(baseResult.status).toBe('complete');
    expect(headResult.status).toBe('complete');
    if (baseResult.status !== 'complete' || headResult.status !== 'complete') throw new Error('unreachable');

    expect(baseResult.permissionBoundary).toEqual({
      status: 'complete',
      permissions: [
        {
          permission: 'issues',
          level: 'read',
          contributors: [
            expect.objectContaining({
              status: 'resolved',
              operation: { method: 'GET', normalizedRoute: '/repos/{owner}/{repo}/issues', operationId: 'issues/list-for-repo' },
              source: expect.objectContaining({ path: 'src/app.ts' }),
            }),
          ],
        },
      ],
    });
    expect(headResult.permissionBoundary).toEqual({
      status: 'complete',
      permissions: [
        {
          permission: 'issues',
          level: 'write',
          contributors: [
            expect.objectContaining({
              status: 'resolved',
              operation: { method: 'POST', normalizedRoute: '/repos/{owner}/{repo}/issues', operationId: 'issues/create' },
              source: expect.objectContaining({ path: 'src/app.ts' }),
            }),
          ],
        },
      ],
    });

    expect(baseResult.observations).toHaveLength(1);
    expect(baseResult.observations[0]?.operation.operationId).toBe('issues/list-for-repo');
    expect(headResult.observations).toHaveLength(1);
    expect(headResult.observations[0]?.operation.operationId).toBe('issues/create');

    // The frozen production catalog is consumed, never mutated.
    expect(BOUNDARYCI_PERMISSION_CATALOG).toHaveLength(2);
    expect(Object.isFrozen(BOUNDARYCI_PERMISSION_CATALOG)).toBe(true);
    expect(outcome.comparison.base.identity.catalogAuthorizedScopeSha256).toBe(
      BOUNDARYCI_PERMISSION_CATALOG_IDENTITY.authorizedScopeSha256,
    );
  });

  it('selects the same immutable built-in effective configuration and digest for both revisions absent .boundaryci.yml', async () => {
    const baseRoot = await createTempRoot('boundaryci-phase4-config-base-');
    const headRoot = await createTempRoot('boundaryci-phase4-config-head-');
    await writeRegularFile(baseRoot, 'src/base.ts', 'export const value = 1;\n');
    await writeRegularFile(headRoot, 'src/head.ts', 'export const value = 2;\n');

    expect(BUILTIN_CONFIG.schemaVersion).toBe(BOUNDARYCI_CONFIG_SCHEMA_VERSION);
    expect(BOUNDARYCI_CONFIG_SCHEMA_VERSION).toBe(1);
    expect(Object.isFrozen(BUILTIN_CONFIG)).toBe(true);
    expect(BUILTIN_CONFIG.failOnExpansion).toBe(true);
    expect(BUILTIN_CONFIG.failOnIncomplete).toBe(true);
    expect(BUILTIN_CONFIG.probotEntrypoints).toEqual([]);
    expect(BUILTIN_CONFIG.expectedPermissions).toEqual([]);

    const base = await analyzeLocalSnapshot(baseRoot, BUILTIN_CONFIG);
    const head = await analyzeLocalSnapshot(headRoot, BUILTIN_CONFIG);

    const expectedDigest = effectiveConfigIdentity(BUILTIN_CONFIG);
    expect(expectedDigest).toMatch(/^[a-f0-9]{64}$/u);
    expect(base.identity.effectiveConfigSha256).toBe(expectedDigest);
    expect(head.identity.effectiveConfigSha256).toBe(expectedDigest);
    expect(base.identity.effectiveConfigSha256).toBe(head.identity.effectiveConfigSha256);
    expect(effectiveConfigIdentity(BUILTIN_CONFIG)).toBe(expectedDigest);
  });

  it('check --base --head --format json emits one deterministic JSON envelope on stdout, keeps diagnostics on stderr, and returns the expansion-policy exit code', async () => {
    const baseRoot = await createTempRoot('boundaryci-phase4-cli-base-');
    const headRoot = await createTempRoot('boundaryci-phase4-cli-head-');
    await writeRegularFile(baseRoot, 'src/app.ts', READ_SOURCE);
    await writeRegularFile(headRoot, 'src/app.ts', WRITE_SOURCE);

    const io = recordingIo();
    const code = await runCli(['check', '--base', baseRoot, '--head', headRoot, '--format', 'json'], io);

    expect(code).toBe(EXIT_CODE_POLICY_FAILURE);
    expect(io.stderrChunks).toEqual([]);
    expect(io.stdoutChunks).toHaveLength(1);

    const envelope = JSON.parse(io.stdoutChunks[0] ?? '') as {
      schemaId: string;
      schemaVersion: number;
      comparison: { status: string };
      policy: { decision: string };
    };
    expect(envelope.schemaId).toBe(CHECK_RESULT_SCHEMA_ID);
    expect(envelope.schemaVersion).toBe(CHECK_RESULT_SCHEMA_VERSION);
    expect(envelope.comparison.status).toBe('complete');
    expect(envelope.policy.decision).toBe('fail');

    const secondIo = recordingIo();
    const secondCode = await runCli(['check', '--base', baseRoot, '--head', headRoot, '--format', 'json'], secondIo);
    expect(secondCode).toBe(code);
    expect(secondIo.stdoutChunks).toEqual(io.stdoutChunks);
  });

  it('parses sentinel target source as inert bytes and never imports, builds, spawns, or executes it', async () => {
    const baseRoot = await createTempRoot('boundaryci-phase4-sentinel-base-');
    const headRoot = await createTempRoot('boundaryci-phase4-sentinel-head-');
    const sentinelSource = `${WRITE_SOURCE}throw new Error('BOUNDARYCI_SENTINEL_EXECUTED_DO_NOT_RUN');\n`;
    await writeRegularFile(baseRoot, 'src/app.ts', 'export const value = 1;\n');
    await writeRegularFile(headRoot, 'src/app.ts', sentinelSource);

    // If the analyzer ever imported, built, spawned, or executed the target file, this call
    // would reject with the sentinel error above instead of resolving with parsed evidence.
    const outcome = await evaluateLocalComparison(baseRoot, headRoot, BUILTIN_CONFIG);

    expect(outcome.comparison.status).toBe('complete');
    if (outcome.comparison.status !== 'complete') throw new Error('unreachable');
    const headResult = outcome.comparison.head.result;
    expect(headResult.status).toBe('complete');
    if (headResult.status !== 'complete') throw new Error('unreachable');
    expect(headResult.observations.some((observation) => observation.operation.operationId === 'issues/create')).toBe(true);
  });

  it('rejects a RevisionAnalysis wrapper carrying unknown identity keys before comparison', async () => {
    const root = await createTempRoot('boundaryci-phase4-wrapper-shape-');
    await writeRegularFile(root, 'src/app.ts', READ_SOURCE);
    const revision = await analyzeLocalSnapshot(root, BUILTIN_CONFIG);

    const malformed = structuredClone(revision);
    (malformed.identity as unknown as Record<string, unknown>).extra = 'unexpected';

    expect(() => compareRevisionAnalyses(malformed, revision)).toThrow(/unknown or missing keys/u);
  });

  it('rejects a wrapper whose analyzer identity contradicts its embedded result identity before comparison', async () => {
    const root = await createTempRoot('boundaryci-phase4-wrapper-contradiction-');
    await writeRegularFile(root, 'src/app.ts', READ_SOURCE);
    const revision = await analyzeLocalSnapshot(root, BUILTIN_CONFIG);

    const contradictory = structuredClone(revision);
    contradictory.identity.analyzer = { ...contradictory.identity.analyzer, schemaVersion: contradictory.identity.analyzer.schemaVersion + 1 };

    expect(() => compareRevisionAnalyses(contradictory, revision)).toThrow(/identity\.analyzer must match/u);
  });
});
