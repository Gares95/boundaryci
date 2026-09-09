import { access, mkdtemp, mkdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterEach, describe, expect, it } from 'vitest';

import { pruneRuntimeDependencyTree } from '../../tools/release/prune-runtime.mjs';
import {
  PROOF_KINDS,
  runCli,
  unsafeImageApplicationPath,
  validateProofFile,
  validateProofRecord,
  verifyRepositorySnapshot,
} from '../../tools/release/verify-release.mjs';

const PROJECT_ROOT = fileURLToPath(new URL('../../', import.meta.url));
const SHA = 'a'.repeat(40);
const DIGEST = `sha256:${'b'.repeat(64)}`;
const ASSISTANT_ATTRIBUTION_SENTINEL = ['Generated', 'by', String.fromCharCode(67, 108, 97, 117, 100, 101)].join(' ');
const TASK_MARKER_SENTINEL = ['TO', 'DO'].join('');
const LOCAL_PLANNING_PATH = ['.plan', 'ning'].join('');
const LOCAL_AGENT_PATH = ['.ag', 'ents'].join('');
const LOCAL_CODEX_PATH = ['.co', 'dex'].join('');
const GITHUB_TOKEN_PREFIX = ['github', 'pat', ''].join('_');
const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map(async (path) => rm(path, { recursive: true, force: true })));
});

const HEADINGS: Readonly<Record<string, readonly string[]>> = Object.freeze({
  'README.md': ['# BoundaryCI', '## Permission drift in pull requests', '## Issues read-to-write example', '## Install and use', '## What BoundaryCI can and cannot prove', '## Documentation', '## License'],
  'SECURITY.md': ['# Security policy', '## Reporting a vulnerability', '## Security boundaries', '## Disclosure and retention'],
  'CONTRIBUTING.md': ['# Contributing', '## Development setup', '## Required checks', '## Safe fixtures and contributions'],
  'docs/architecture.md': ['# Architecture', '## Deterministic layers', '## Comparison identity', '## Target isolation', '## GitHub delivery and scoped roles', '## Check lifecycle', '## Security invariants'],
  'docs/permission-model.md': ['# Permission model', '## Observed source evidence', '## Repository-declared configuration and policy', '## Permission expressions', '## Aggregation and comparison', '## Catalog assumptions', '## Live App permissions'],
  'docs/limitations.md': ['# Limitations', '## Supported v1 surface', '## Incomplete analysis', '## External forks', '## Explicit exclusions'],
  'docs/github-delivery.md': ['# GitHub App delivery', '## App registration and events', '## Scoped roles', '## Check identity and outcomes', '## Production server', '## Freshness and finite publication'],
  'docs/demo.md': ['# Demonstration', '## Local deterministic proof', '## Live same-repository proof', '## External-fork feasibility', '## Sanitized evidence'],
  'docs/release.md': ['# Release runbook', '## Preconditions', '## Canonical and Docker proof', '## Live GitHub proof', '## Verification and review', '## Destination preflight', '## Operator authorization', '## Non-destructive publication', '## Post-publication verification', '## Partial publication'],
});

const WORKFLOW = `name: CI

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          persist-credentials: false
      - uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4.4.0
        with:
          node-version: 24.19.0
      - run: corepack enable && corepack install
      - run: pnpm install --frozen-lockfile --ignore-scripts
      - run: npm run verify:release
`;

async function validSnapshot(): Promise<{ root: string; files: Map<string, string> }> {
  const root = await mkdtemp(join(tmpdir(), 'boundaryci-release-fixture-'));
  temporaryDirectories.push(root);
  const files = new Map<string, string>();
  files.set('.dockerignore', `**\n**/.git/**\n**/${LOCAL_PLANNING_PATH}/**\n**/${LOCAL_AGENT_PATH}/**\n**/${LOCAL_CODEX_PATH}/**\n**/.env.*\n**/*.pem\n**/tests/**\n**/fixtures/**\n**/node_modules/**\n**/dist/**\n`);
  files.set('.github/workflows/ci.yml', WORKFLOW);
  files.set('Dockerfile', `FROM node:24.19.0-bookworm-slim@sha256:3638d9a6fe4030bd716be989438248074489337ba3275657f93595428be4fc03 AS builder
RUN corepack enable && corepack install
RUN pnpm install --frozen-lockfile --ignore-scripts
RUN pnpm run build
RUN pnpm prune --prod --ignore-scripts
FROM node:24.19.0-bookworm-slim@sha256:3638d9a6fe4030bd716be989438248074489337ba3275657f93595428be4fc03 AS runtime
USER node
EXPOSE 3000
CMD ["node", "dist/delivery/server.js"]
`);
  files.set('LICENSE', await readFile(join(PROJECT_ROOT, 'LICENSE'), 'utf8'));
  files.set('package.json', `${JSON.stringify({ license: 'Apache-2.0', scripts: { start: 'node dist/delivery/server.js', 'verify:release': 'node tools/release/verify-release.mjs' } }, null, 2)}\n`);
  files.set('docs/analyzer.md', '# Analyzer\n');
  files.set('docs/cli.md', '# CLI\n');
  files.set('docs/configuration.md', '# Configuration\n');
  for (const [path, headings] of Object.entries(HEADINGS)) {
    const introduction = path === 'README.md'
      ? 'BoundaryCI makes permission drift visible before merge.\n\nIssues `read` → `write` produces `failure`, `Permission expansion requires review`, and `issues/create`.\n'
      : '';
    files.set(path, `${headings[0]}\n\n${introduction}${headings.slice(1).join('\n\nSafe text.\n\n')}\n\nSafe text.\n`);
  }
  files.set('docs/permission-model.md', `${files.get('docs/permission-model.md')}\nObserved source evidence is separate from Repository-declared configuration and policy. Unresolved analysis remains explicit. Independently verified live App permissions are outside the analyzer, which does not retrieve that state.\n`);
  files.set('README.md', `${files.get('README.md')}\n[Architecture](docs/architecture.md)\n[Security](SECURITY.md)\n`);
  for (const [path, text] of files) {
    const absolutePath = join(root, path);
    await mkdir(dirname(absolutePath), { recursive: true });
    await writeFile(absolutePath, text);
  }
  return { root, files };
}

function proof(kind: Exclude<(typeof PROOF_KINDS)[number], 'review'>): Record<string, unknown> {
  const checks: Record<string, unknown> = kind === 'docker'
    ? { canonical_gate: 'pass', image_digest: DIGEST, runtime_user: 'node', runtime_command: 'node dist/delivery/server.js', health: 'pass', signed_webhook: 'pass', invalid_signature: 'rejected', shutdown_milliseconds: 321, residue: 'absent', forbidden_material: 'absent' }
    : kind === 'ci'
      ? { workflow: '.github/workflows/ci.yml', run_id: 42, head_sha: SHA, conclusion: 'success', canonical_gate: 'pass' }
      : kind === 'same-repository'
        ? { repository: 'Gares95/boundaryci-proof', pull_number: 7, app_id: 8, check_id: 9, head_sha: SHA, conclusion: 'failure', title: 'Permission expansion requires review', operation: 'issues/create', annotation_path: 'src/app.ts', annotation_start: 4, annotation_end: 4, create_calls: 1, update_calls: 1, annotation_update_calls: 0, exact_check_count: 1, redelivery: 'converged', reconciliation: 'converged', stale_mutations: 0, duplicate_mutations: 0, no_expansion: 'pass' }
        : kind === 'external-fork'
          ? { repository: 'Gares95/boundaryci-proof', pull_number: 7, head_repository: 'contributor/boundaryci-proof', topology: 'unaddressable', outcome: 'not-published', conclusion: null, check_mutations: 0, source_acquisition: 0, never_green: true }
          : kind === 'phase-verification'
            ? { report: `${LOCAL_PLANNING_PATH}/phases/BCI-06-github-check-experience-release-proof/06-VERIFICATION.md`, requirements: 'pass', verification: 'pass', canonical_gate: 'pass', docker: 'pass', ci: 'pass', same_repository: 'pass', external_fork: 'pass', integrated_review: 'pass' }
            : kind === 'destination'
              ? { repository: 'Gares95/boundaryci', authenticated_owner: 'Gares95', visibility: 'absent', state: 'absent', eligible: true, main_sha: null, tag_sha: null, remote_tag_kind: 'absent', local_tag_kind: 'absent', gates: 'pass', clean_tree: true }
              : kind === 'publication'
                ? { repository: 'Gares95/boundaryci', branch: 'main', tag: 'v1.0.0', decision: 'approve-exact-release', operator: 'Gares95', decision_at: '2026-09-09T00:00:00.000Z', state: 'complete', main_outcome: 'published', tag_outcome: 'published', main_sha: SHA, tag_sha: SHA, tag_kind: 'annotated', non_force: true, deletions: 0 }
                : { repository: 'Gares95/boundaryci', visibility: 'public', default_branch: 'main', main_sha: SHA, tag_object_sha: 'c'.repeat(40), tag_target_sha: SHA, tag_kind: 'annotated', file_set_sha256: DIGEST, file_count: 141, documentation: 'pass', forbidden_material: 'absent' };
  return { schema_version: 1, kind, release_sha: SHA, captured_at: '2026-09-09T00:00:00.000Z', status: 'pass', checks };
}

describe('release repository verifier', () => {
  it('accepts a complete deterministic public fixture', async () => {
    const fixture = await validSnapshot();
    expect(verifyRepositorySnapshot(fixture.root, fixture.files.keys())).toEqual([]);
  });

  it.each([
    ['missing document', async (fixture: Awaited<ReturnType<typeof validSnapshot>>) => fixture.files.delete('SECURITY.md'), 'repository/required-file'],
    ['missing heading', async (fixture) => fixture.files.set('README.md', fixture.files.get('README.md')!.replace('## License', '## Licensing')), 'docs/required-heading'],
    ['broken link', async (fixture) => fixture.files.set('README.md', `${fixture.files.get('README.md')}[Missing](docs/missing.md)\n`), 'repository/broken-link'],
    ['forbidden path', async (fixture) => fixture.files.set(`${LOCAL_PLANNING_PATH}/private.md`, 'local\n'), 'repository/forbidden-path'],
    ['secret path', async (fixture) => fixture.files.set('.env.production', 'SAFE=false\n'), 'repository/secret-path'],
    ['secret material', async (fixture) => fixture.files.set('docs/analyzer.md', `${GITHUB_TOKEN_PREFIX}${'s'.repeat(40)}\n`), 'repository/secret-material'],
    ['task marker', async (fixture) => fixture.files.set('docs/analyzer.md', `${TASK_MARKER_SENTINEL} release later\n`), 'repository/task-marker'],
    ['assistant attribution', async (fixture) => fixture.files.set('docs/analyzer.md', `${ASSISTANT_ATTRIBUTION_SENTINEL} for this project.\n`), 'repository/assistant-attribution'],
    ['mutable action', async (fixture) => fixture.files.set('.github/workflows/ci.yml', WORKFLOW.replace('11bd71901bbe5b1630ceea73d27597364c9af683', 'v4')), 'ci/action-not-immutable'],
    ['write permission', async (fixture) => fixture.files.set('.github/workflows/ci.yml', WORKFLOW.replace('contents: read', 'contents: write')), 'ci/read-only'],
    ['publication command', async (fixture) => fixture.files.set('.github/workflows/ci.yml', WORKFLOW.replace('npm run verify:release', 'npm publish')), 'ci/mutation-or-secret'],
  ] as const)('rejects %s with stable path/code diagnostics only', async (_name, mutate, expectedCode) => {
    const fixture = await validSnapshot();
    await mutate(fixture);
    for (const [path, text] of fixture.files) {
      const absolutePath = join(fixture.root, path);
      await mkdir(dirname(absolutePath), { recursive: true });
      await writeFile(absolutePath, text);
    }
    const diagnostics = verifyRepositorySnapshot(fixture.root, fixture.files.keys());
    expect(diagnostics).toEqual(expect.arrayContaining([expect.objectContaining({ code: expectedCode })]));
    const serialized = JSON.stringify(diagnostics);
    expect(serialized).not.toContain(GITHUB_TOKEN_PREFIX);
    expect(serialized).not.toContain(ASSISTANT_ATTRIBUTION_SENTINEL);
    expect(serialized).not.toContain('SAFE=false');
  });

  it('rejects an invalid CLI surface without making an external call', () => {
    expect(runCli(['--repository-only', '--extra'], PROJECT_ROOT)).toEqual([{ code: 'usage' }]);
  });
});

describe('retained proof validators', () => {
  it.each(PROOF_KINDS.filter((kind) => kind !== 'review'))('accepts the closed %s JSON schema', (kind) => {
    expect(validateProofRecord(kind, proof(kind as Exclude<(typeof PROOF_KINDS)[number], 'review'>), SHA)).toEqual([]);
  });

  it('rejects a wrong SHA, extra field, and forbidden retained value without echoing any value', () => {
    const value = proof('docker');
    (value.checks as Record<string, unknown>).token = `${GITHUB_TOKEN_PREFIX}${'z'.repeat(40)}`;
    const diagnostics = validateProofRecord('docker', value, 'c'.repeat(40));
    expect(diagnostics.map((item) => item.code)).toEqual(expect.arrayContaining(['proof/common-schema', 'proof/forbidden-field']));
    expect(JSON.stringify(diagnostics)).not.toContain(GITHUB_TOKEN_PREFIX);
  });

  it('accepts exact structured integrated and closure review Markdown and rejects a high passing disposition', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'boundaryci-review-fixture-'));
    temporaryDirectories.push(directory);
    for (const kind of ['integrated', 'closure'] as const) {
      const file = join(directory, `${kind}.md`);
      await writeFile(file, `# Phase 6 ${kind} review\n\nRelease-SHA: ${SHA}\nReview-Kind: ${kind}\nStatus: pass\nHighest-Severity: none\n\n## Scope\n\nExact Phase 6 implementation.\n\n## Findings\n\nNone.\n\n## Security disposition\n\nPass.\n`);
      expect(validateProofFile('review', file, SHA)).toEqual([]);
    }
    const invalid = join(directory, 'invalid.md');
    await writeFile(invalid, `# Phase 6 integrated review\n\nRelease-SHA: ${SHA}\nReview-Kind: integrated\nStatus: pass\nHighest-Severity: high\n\n## Scope\n\nScope.\n\n## Findings\n\nFinding.\n\n## Security disposition\n\nPass.\n`);
    expect(validateProofFile('review', invalid, SHA)).toEqual([{ code: 'proof/review-format' }]);
  });
});

describe('runtime image path boundary', () => {
  it('allows a pinned dependency module name but rejects non-runtime directories and app-owned secret filenames', () => {
    expect(unsafeImageApplicationPath('app/node_modules/.pnpm/auth-module/dist/get-oauth-access-token.js')).toBe(false);
    expect(unsafeImageApplicationPath('app/node_modules/package/test/example.js')).toBe(true);
    expect(unsafeImageApplicationPath('app/node_modules/package/.claude/settings.json')).toBe(true);
    expect(unsafeImageApplicationPath('app/node_modules/package/.github/workflows/ci.yml')).toBe(true);
    expect(unsafeImageApplicationPath('app/private-key-backup.txt')).toBe(true);
  });

  it('removes fixed non-runtime directories and unlinks them without traversing outside the dependency root', async () => {
    const temporaryRoot = await mkdtemp(join(tmpdir(), 'boundaryci-runtime-prune-'));
    temporaryDirectories.push(temporaryRoot);
    const dependencyRoot = join(temporaryRoot, 'node_modules');
    const packageRoot = join(dependencyRoot, 'package');
    const outside = join(temporaryRoot, 'outside');
    await mkdir(join(packageRoot, 'tests'), { recursive: true });
    await mkdir(join(packageRoot, 'dist'), { recursive: true });
    await mkdir(outside);
    await writeFile(join(packageRoot, 'tests', 'example.js'), 'test\n');
    await writeFile(join(packageRoot, 'dist', 'index.js'), 'runtime\n');
    await writeFile(join(packageRoot, 'README.md'), 'example credential\n');
    await writeFile(join(packageRoot, 'LICENSE'), 'retained license\n');
    await writeFile(join(outside, 'retained.txt'), 'outside\n');
    await symlink(outside, join(packageRoot, '.claude'), 'dir');

    expect(await pruneRuntimeDependencyTree(dependencyRoot)).toBe(3);
    await expect(access(join(packageRoot, 'tests'))).rejects.toThrow();
    await expect(access(join(packageRoot, '.claude'))).rejects.toThrow();
    await expect(access(join(packageRoot, 'README.md'))).rejects.toThrow();
    await expect(readFile(join(packageRoot, 'dist', 'index.js'), 'utf8')).resolves.toBe('runtime\n');
    await expect(readFile(join(packageRoot, 'LICENSE'), 'utf8')).resolves.toBe('retained license\n');
    await expect(readFile(join(outside, 'retained.txt'), 'utf8')).resolves.toBe('outside\n');
  });
});
