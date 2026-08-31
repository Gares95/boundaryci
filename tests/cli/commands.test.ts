import { afterEach, describe, expect, it } from 'vitest';

import {
  EXIT_CODE_INCOMPLETE,
  EXIT_CODE_INPUT_CONFIGURATION_FAILURE,
  EXIT_CODE_OK,
  EXIT_CODE_POLICY_FAILURE,
  runCli,
} from '../../src/cli/main.js';
import type { CliIO } from '../../src/cli/main.js';
import { cleanupTempRoots, createTempRoot, writeRegularFile } from '../analyzer/helpers.js';

afterEach(cleanupTempRoots);

const READ_SOURCE =
  "import { Octokit } from 'octokit';\nconst client = new Octokit();\nclient.rest.issues.listForRepo({});\n";
const WRITE_SOURCE = "import { Octokit } from 'octokit';\nconst client = new Octokit();\nclient.rest.issues.create({});\n";
const PULLS_SOURCE = "import { Octokit } from 'octokit';\nconst client = new Octokit();\nclient.rest.pulls.list({});\n";
const EMPTY_SOURCE = 'export const value = 1;\n';

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

async function invoke(argv: string[]) {
  const io = recordingIo();
  const code = await runCli(argv, io);
  return { code, io };
}

function jsonDocument(io: ReturnType<typeof recordingIo>): Record<string, unknown> {
  expect(io.stderrChunks).toEqual([]);
  expect(io.stdoutChunks).toHaveLength(1);
  return JSON.parse(io.stdoutChunks[0] as string) as Record<string, unknown>;
}

describe('analyze command', () => {
  it('uses the snapshot/default config and supports human-default and JSON complete output', async () => {
    const root = await createTempRoot('boundaryci-cli-analyze-complete-');
    await writeRegularFile(root, 'src/app.ts', READ_SOURCE);

    const human = await invoke(['analyze', root]);
    expect(human.code).toBe(EXIT_CODE_OK);
    expect(human.io.stderrChunks).toEqual([]);
    expect(human.io.stdoutChunks[0]).toContain('BoundaryCI analyze\noutcome: complete');
    expect(human.io.stdoutChunks[0]).toContain('snapshot observed-permission=issues:read contributors=1');

    const json = await invoke(['analyze', root, '--format', 'json']);
    expect(json.code).toBe(EXIT_CODE_OK);
    expect(jsonDocument(json.io)).toMatchObject({
      command: 'analyze',
      outcome: 'complete',
      evaluation: { status: 'complete', authority: { source: 'built-in-default' } },
    });
  });

  it('returns the incomplete exit while retaining a profiled outside-catalog operation', async () => {
    const root = await createTempRoot('boundaryci-cli-analyze-incomplete-');
    await writeRegularFile(root, 'src/app.ts', PULLS_SOURCE);

    const run = await invoke(['analyze', root, '--format', 'json']);
    expect(run.code).toBe(EXIT_CODE_INCOMPLETE);
    const document = jsonDocument(run.io);
    expect(document).toMatchObject({ command: 'analyze', outcome: 'incomplete' });
    expect(JSON.stringify(document)).toContain('pulls/list');
    expect(JSON.stringify(document)).toContain('permission-catalog-incomplete');
  });
});

describe('diff and check policy separation', () => {
  it.each([
    {
      label: 'unchanged read boundary',
      baseSource: READ_SOURCE,
      headSource: READ_SOURCE,
      expectedChange: { base: 'read', change: 'unchanged', head: 'read', permission: 'issues' },
    },
    {
      label: 'read introduced',
      baseSource: EMPTY_SOURCE,
      headSource: READ_SOURCE,
      expectedChange: { base: 'none', change: 'expansion', head: 'read', permission: 'issues' },
    },
    {
      label: 'write introduced',
      baseSource: EMPTY_SOURCE,
      headSource: WRITE_SOURCE,
      expectedChange: { base: 'none', change: 'expansion', head: 'write', permission: 'issues' },
    },
    {
      label: 'read escalated to write',
      baseSource: READ_SOURCE,
      headSource: WRITE_SOURCE,
      expectedChange: { base: 'read', change: 'expansion', head: 'write', permission: 'issues' },
    },
    {
      label: 'write reduced to read',
      baseSource: WRITE_SOURCE,
      headSource: READ_SOURCE,
      expectedChange: { base: 'write', change: 'reduction', head: 'read', permission: 'issues' },
    },
    {
      label: 'write operation removed',
      baseSource: WRITE_SOURCE,
      headSource: EMPTY_SOURCE,
      expectedChange: { base: 'write', change: 'reduction', head: 'none', permission: 'issues' },
    },
  ])('covers the complete public comparison scenario: $label', async ({ baseSource, expectedChange, headSource }) => {
    const base = await createTempRoot('boundaryci-cli-matrix-base-');
    const head = await createTempRoot('boundaryci-cli-matrix-head-');
    await writeRegularFile(base, 'src/app.ts', baseSource);
    await writeRegularFile(head, 'src/app.ts', headSource);

    const run = await invoke(['diff', '--base', base, '--head', head, '--format', 'json']);
    expect(run.code).toBe(EXIT_CODE_OK);
    const document = jsonDocument(run.io) as {
      evaluation: { comparison: { changes: unknown[]; status: string } };
      outcome: string;
    };
    expect(document.outcome).toBe('complete');
    expect(document.evaluation.comparison.status).toBe('complete');
    expect(document.evaluation.comparison.changes).toEqual([expect.objectContaining(expectedChange)]);
  });

  it('keeps a source parse failure explicitly incomplete instead of reporting a clean diff', async () => {
    const base = await createTempRoot('boundaryci-cli-parse-base-');
    const head = await createTempRoot('boundaryci-cli-parse-head-');
    await writeRegularFile(base, 'src/app.ts', READ_SOURCE);
    await writeRegularFile(head, 'src/app.ts', `${READ_SOURCE}const broken = ;\n`);

    const run = await invoke(['diff', '--base', base, '--head', head, '--format', 'json']);
    expect(run.code).toBe(EXIT_CODE_INCOMPLETE);
    const serialized = JSON.stringify(jsonDocument(run.io));
    expect(serialized).toContain('"status":"incomplete"');
    expect(serialized).toContain('source-parse-error');
  });

  it('treats a source move as an unchanged permission boundary', async () => {
    const base = await createTempRoot('boundaryci-cli-move-base-');
    const head = await createTempRoot('boundaryci-cli-move-head-');
    await writeRegularFile(base, 'src/old.ts', READ_SOURCE);
    await writeRegularFile(head, 'src/new.ts', READ_SOURCE);

    const run = await invoke(['diff', '--base', base, '--head', head, '--format', 'json']);
    expect(run.code).toBe(EXIT_CODE_OK);
    const document = jsonDocument(run.io) as {
      evaluation: { comparison: { changes: { base: string; change: string; head: string; permission: string }[] } };
    };
    expect(document.evaluation.comparison.changes).toEqual([
      expect.objectContaining({ base: 'read', change: 'unchanged', head: 'read', permission: 'issues' }),
    ]);
    expect(JSON.stringify(document)).toContain('src/old.ts');
    expect(JSON.stringify(document)).toContain('src/new.ts');
  });

  it('reports a read-to-write diff without applying expansion policy', async () => {
    const base = await createTempRoot('boundaryci-cli-diff-base-');
    const head = await createTempRoot('boundaryci-cli-diff-head-');
    await writeRegularFile(base, 'src/app.ts', READ_SOURCE);
    await writeRegularFile(head, 'src/app.ts', WRITE_SOURCE);

    const run = await invoke(['diff', '--base', base, '--head', head, '--format', 'json']);
    expect(run.code).toBe(EXIT_CODE_OK);
    expect(jsonDocument(run.io)).toMatchObject({
      command: 'diff',
      outcome: 'complete',
      evaluation: { status: 'selected', comparison: { status: 'complete' } },
    });
    expect(run.io.stdoutChunks[0]).not.toContain('"policy"');
  });

  it('enforces expansion policy only for check', async () => {
    const base = await createTempRoot('boundaryci-cli-check-base-');
    const head = await createTempRoot('boundaryci-cli-check-head-');
    await writeRegularFile(base, 'src/app.ts', READ_SOURCE);
    await writeRegularFile(head, 'src/app.ts', WRITE_SOURCE);

    const run = await invoke(['check', '--base', base, '--head', head, '--format', 'json']);
    expect(run.code).toBe(EXIT_CODE_POLICY_FAILURE);
    expect(jsonDocument(run.io)).toMatchObject({
      command: 'check',
      outcome: 'policy-failure',
      evaluation: {
        status: 'selected',
        policy: { outcome: 'policy-failure', reasons: ['expansion-not-permitted'] },
      },
    });
  });

  it('enforces incomplete by default and tolerates it only under base-authoritative policy', async () => {
    const enforcedBase = await createTempRoot('boundaryci-cli-incomplete-base-');
    const enforcedHead = await createTempRoot('boundaryci-cli-incomplete-head-');
    await writeRegularFile(enforcedBase, 'src/app.ts', 'export const value = 1;\n');
    await writeRegularFile(enforcedHead, 'src/app.ts', PULLS_SOURCE);

    const enforced = await invoke(['check', '--base', enforcedBase, '--head', enforcedHead, '--format', 'json']);
    expect(enforced.code).toBe(EXIT_CODE_INCOMPLETE);
    expect(jsonDocument(enforced.io)).toMatchObject({
      outcome: 'policy-failure',
      evaluation: { policy: { reasons: ['incomplete-analysis-not-permitted'] } },
    });

    const tolerantBase = await createTempRoot('boundaryci-cli-tolerant-base-');
    const tolerantHead = await createTempRoot('boundaryci-cli-tolerant-head-');
    await writeRegularFile(
      tolerantBase,
      '.boundaryci.yml',
      'version: 1\npolicy:\n  failOnExpansion: true\n  failOnIncomplete: false\n',
    );
    await writeRegularFile(tolerantBase, 'src/app.ts', 'export const value = 1;\n');
    await writeRegularFile(tolerantHead, 'src/app.ts', PULLS_SOURCE);

    const tolerated = await invoke(['check', '--base', tolerantBase, '--head', tolerantHead, '--format', 'json']);
    expect(tolerated.code).toBe(EXIT_CODE_OK);
    expect(jsonDocument(tolerated.io)).toMatchObject({
      command: 'check',
      outcome: 'incomplete',
      evaluation: { policy: { outcome: 'incomplete', check: 'pass' } },
    });
  });
});

describe('configuration, argument, and isolation failures', () => {
  it('fails invalid base and invalid prospective head config before successful semantic output', async () => {
    const invalidBase = await createTempRoot('boundaryci-cli-invalid-base-');
    const validHead = await createTempRoot('boundaryci-cli-valid-head-');
    await writeRegularFile(invalidBase, '.boundaryci.yml', 'version: 2\n');
    await writeRegularFile(validHead, 'src/app.ts', READ_SOURCE);

    const baseRun = await invoke(['diff', '--base', invalidBase, '--head', validHead, '--format', 'json']);
    expect(baseRun.code).toBe(EXIT_CODE_INPUT_CONFIGURATION_FAILURE);
    expect(jsonDocument(baseRun.io)).toMatchObject({
      outcome: 'input-configuration-failure',
      evaluation: { status: 'input-configuration-failure', invalid: 'base' },
    });

    const validBase = await createTempRoot('boundaryci-cli-valid-base-');
    const invalidHead = await createTempRoot('boundaryci-cli-invalid-head-');
    await writeRegularFile(validBase, 'src/app.ts', READ_SOURCE);
    await writeRegularFile(invalidHead, '.boundaryci.yml', 'version: [1\n');

    const headRun = await invoke(['check', '--base', validBase, '--head', invalidHead, '--format', 'json']);
    expect(headRun.code).toBe(EXIT_CODE_INPUT_CONFIGURATION_FAILURE);
    expect(jsonDocument(headRun.io)).toMatchObject({
      outcome: 'input-configuration-failure',
      evaluation: { status: 'input-configuration-failure', invalid: 'head' },
    });
  });

  it('maps a nonexistent root to input/configuration failure', async () => {
    const parent = await createTempRoot('boundaryci-cli-missing-parent-');
    const missing = `${parent}/missing`;
    const run = await invoke(['analyze', missing, '--format', 'json']);
    expect(run.code).toBe(EXIT_CODE_INPUT_CONFIGURATION_FAILURE);
    expect(jsonDocument(run.io)).toMatchObject({ outcome: 'input-configuration-failure' });
  });

  it.each(
    [
      [],
      ['unknown'],
      ['analyze'],
      ['analyze', 'one', 'two'],
      ['analyze', 'one', '--format'],
      ['analyze', 'one', '--format', 'xml'],
      ['analyze', 'one', '--format', 'json', '--format', 'human'],
      ['diff', '--base', 'one'],
      ['diff', '--base', 'one', '--head', 'two', '--extra', 'value'],
      ['check', '--base', 'one', '--base', 'two', '--head', 'three'],
    ].map((argv) => ({ argv })),
  )('rejects malformed argv before runtime: $argv', async ({ argv }) => {
    const run = await invoke(argv);
    expect(run.code).toBe(EXIT_CODE_INPUT_CONFIGURATION_FAILURE);
    expect(run.io.stdoutChunks).toEqual([]);
    expect(run.io.stderrChunks).toHaveLength(1);
    expect(run.io.stderrChunks[0]).toMatch(/^boundaryci: /u);
  });

  it('is byte-identical across repeated calls and treats throwing target source as inert bytes', async () => {
    const base = await createTempRoot('boundaryci-cli-sentinel-base-');
    const head = await createTempRoot('boundaryci-cli-sentinel-head-');
    await writeRegularFile(base, 'src/app.ts', READ_SOURCE);
    await writeRegularFile(head, 'src/app.ts', `${WRITE_SOURCE}throw new Error('DO_NOT_EXECUTE');\n`);

    const first = await invoke(['diff', '--base', base, '--head', head, '--format', 'json']);
    const second = await invoke(['diff', '--base', base, '--head', head, '--format', 'json']);
    expect(first.code).toBe(EXIT_CODE_OK);
    expect(second.code).toBe(first.code);
    expect(second.io.stdoutChunks).toEqual(first.io.stdoutChunks);
    expect(first.io.stderrChunks).toEqual([]);
  });
});
