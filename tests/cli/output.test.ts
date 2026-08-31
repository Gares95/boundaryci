import { afterEach, describe, expect, it } from 'vitest';

import { CLI_RESULT_SCHEMA_ID, CLI_RESULT_SCHEMA_VERSION } from '../../src/cli/render.js';
import { EXIT_CODE_INCOMPLETE, EXIT_CODE_OK, EXIT_CODE_POLICY_FAILURE, runCli } from '../../src/cli/main.js';
import type { CliIO } from '../../src/cli/main.js';
import { cleanupTempRoots, createTempRoot, writeRegularFile } from '../analyzer/helpers.js';

afterEach(cleanupTempRoots);

const READ_SOURCE =
  "import { Octokit } from 'octokit';\nconst client = new Octokit();\nclient.rest.issues.listForRepo({});\n";
const WRITE_SOURCE = "import { Octokit } from 'octokit';\nconst client = new Octokit();\nclient.rest.issues.create({});\n";
const PULLS_SOURCE = "import { Octokit } from 'octokit';\nconst client = new Octokit();\nclient.rest.pulls.list({});\n";

function recordingIo(): CliIO & { stdoutChunks: string[]; stderrChunks: string[] } {
  const stdoutChunks: string[] = [];
  const stderrChunks: string[] = [];
  return {
    stdoutChunks,
    stderrChunks,
    stdout: { write: (chunk) => stdoutChunks.push(chunk) },
    stderr: { write: (chunk) => stderrChunks.push(chunk) },
  };
}

async function output(argv: string[]): Promise<{ code: number; text: string }> {
  const io = recordingIo();
  const code = await runCli(argv, io);
  expect(io.stderrChunks).toEqual([]);
  expect(io.stdoutChunks).toHaveLength(1);
  return { code, text: io.stdoutChunks[0] as string };
}

function expectRecursivelySortedKeys(value: unknown): void {
  if (Array.isArray(value)) {
    for (const entry of value) expectRecursivelySortedKeys(entry);
    return;
  }
  if (typeof value !== 'object' || value === null) return;
  const keys = Object.keys(value);
  expect(keys).toEqual([...keys].sort());
  for (const entry of Object.values(value)) expectRecursivelySortedKeys(entry);
}

function expectNoOverclaim(text: string): void {
  expect(text).not.toMatch(/perfect least privilege/iu);
  expect(text).not.toMatch(/verified live/iu);
  expect(text).not.toMatch(/target runtime (?:is )?compatible/iu);
}

describe('human evidence rendering', () => {
  it('retains authority, prospective config, declared labels, changes, operations, and source spans', async () => {
    const base = await createTempRoot('boundaryci-output-human-base-');
    const head = await createTempRoot('boundaryci-output-human-head-');
    await writeRegularFile(
      base,
      '.boundaryci.yml',
      'version: 1\nexpectedPermissions:\n  issues: read\npolicy:\n  failOnExpansion: true\n',
    );
    await writeRegularFile(base, 'src/app.ts', READ_SOURCE);
    await writeRegularFile(head, '.boundaryci.yml', 'version: 1\npolicy:\n  failOnExpansion: false\n');
    await writeRegularFile(head, 'src/app.ts', WRITE_SOURCE);

    const run = await output(['diff', '--base', base, '--head', head]);
    expect(run.code).toBe(EXIT_CODE_OK);
    expect(run.text).toContain('BoundaryCI diff\noutcome: complete');
    expect(run.text).toMatch(/authority: base sha256=[a-f0-9]{64}/u);
    expect(run.text).toMatch(/prospective-head: changed sha256=[a-f0-9]{64}/u);
    expect(run.text).toContain('declared-permission: issues=read (declared, not observed or live)');
    expect(run.text).toContain('permission=issues base=read head=write direction=expansion');
    expect(run.text).toContain('GET /repos/{owner}/{repo}/issues (issues/list-for-repo)');
    expect(run.text).toContain('POST /repos/{owner}/{repo}/issues (issues/create)');
    expect(run.text).toMatch(/source=src\/app\.ts:\d+:\d+-\d+:\d+/u);
    expect(run.text).not.toContain(base);
    expect(run.text).not.toContain(head);
    expectNoOverclaim(run.text);
  });

  it('keeps a catalog gap visibly incomplete with its proven operation and cause', async () => {
    const root = await createTempRoot('boundaryci-output-human-gap-');
    await writeRegularFile(root, 'src/app.ts', PULLS_SOURCE);

    const run = await output(['analyze', root]);
    expect(run.code).toBe(EXIT_CODE_INCOMPLETE);
    expect(run.text).toContain('outcome: incomplete');
    expect(run.text).toContain('GET /repos/{owner}/{repo}/pulls (pulls/list)');
    expect(run.text).toContain('permission-resolution finding=missing');
    expect(run.text).toContain('permission-boundary=incomplete reasons=missing-permission-requirement');
    expect(run.text).toContain('cause=permission-catalog-incomplete');
    expect(run.text).not.toContain(root);
    expectNoOverclaim(run.text);
  });
});

describe('versioned JSON rendering', () => {
  it('is recursively key-sorted, deterministic, evidence-rich, and policy-bearing only for check', async () => {
    const base = await createTempRoot('boundaryci-output-json-base-');
    const head = await createTempRoot('boundaryci-output-json-head-');
    await writeRegularFile(base, 'src/app.ts', READ_SOURCE);
    await writeRegularFile(head, 'src/app.ts', WRITE_SOURCE);

    const argv = ['check', '--base', base, '--head', head, '--format', 'json'];
    const first = await output(argv);
    const second = await output(argv);
    expect(first.code).toBe(EXIT_CODE_POLICY_FAILURE);
    expect(second).toEqual(first);
    expect(first.text.endsWith('\n')).toBe(true);
    expect(first.text).not.toContain(base);
    expect(first.text).not.toContain(head);

    const document = JSON.parse(first.text) as Record<string, unknown>;
    expect(document).toMatchObject({
      command: 'check',
      outcome: 'policy-failure',
      schemaId: CLI_RESULT_SCHEMA_ID,
      schemaVersion: CLI_RESULT_SCHEMA_VERSION,
      evaluation: {
        status: 'selected',
        comparison: { status: 'complete' },
        policy: { outcome: 'policy-failure', reasons: ['expansion-not-permitted'] },
      },
    });
    expectRecursivelySortedKeys(document);
    expect(first.text).toContain('issues/create');
    expect(first.text).toContain('issues/list-for-repo');
    expect(first.text).toContain('src/app.ts');
    expectNoOverclaim(first.text);

    const diff = await output(['diff', '--base', base, '--head', head, '--format', 'json']);
    expect(diff.code).toBe(EXIT_CODE_OK);
    expect(diff.text).not.toContain('"policy"');
  });

  it('preserves tolerated incompleteness rather than rewriting it as complete', async () => {
    const base = await createTempRoot('boundaryci-output-tolerant-base-');
    const head = await createTempRoot('boundaryci-output-tolerant-head-');
    await writeRegularFile(base, '.boundaryci.yml', 'version: 1\npolicy:\n  failOnIncomplete: false\n');
    await writeRegularFile(base, 'src/app.ts', 'export const value = 1;\n');
    await writeRegularFile(head, 'src/app.ts', PULLS_SOURCE);

    const run = await output(['check', '--base', base, '--head', head, '--format', 'json']);
    expect(run.code).toBe(EXIT_CODE_OK);
    expect(JSON.parse(run.text)).toMatchObject({
      command: 'check',
      outcome: 'incomplete',
      evaluation: {
        comparison: { status: 'incomplete' },
        policy: { outcome: 'incomplete', check: 'pass', reasons: [] },
      },
    });
    expect(run.text).toContain('permission-catalog-incomplete');
  });
});
