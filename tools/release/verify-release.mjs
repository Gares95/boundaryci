import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, normalize, relative, resolve, sep } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';

const PROJECT_ROOT = realpathSync(fileURLToPath(new URL('../../', import.meta.url)));
const SHA_PATTERN = /^[a-f0-9]{40}$/u;
const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const ISO_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u;
const MAX_FILE_BYTES = 8 * 1024 * 1024;
const MAX_IMAGE_FILE_BYTES = 10 * 1024 * 1024;
const MAX_TOTAL_BYTES = 128 * 1024 * 1024;
const MAX_PROOF_BYTES = 128 * 1024;
const APACHE_2_SHA256 = 'cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30';
const IMAGE_REFERENCE = 'node:24.19.0-bookworm-slim@sha256:3638d9a6fe4030bd716be989438248074489337ba3275657f93595428be4fc03';

export const PROOF_KINDS = Object.freeze([
  'docker',
  'ci',
  'same-repository',
  'external-fork',
  'phase-verification',
  'review',
  'destination',
  'publication',
  'post-publication',
]);

const REQUIRED_HEADINGS = Object.freeze({
  'README.md': [
    '# BoundaryCI',
    '## Permission drift in pull requests',
    '## Issues read-to-write example',
    '## Install and use',
    '## What BoundaryCI can and cannot prove',
    '## Documentation',
    '## License',
  ],
  'SECURITY.md': ['# Security policy', '## Reporting a vulnerability', '## Security boundaries', '## Disclosure and retention'],
  'CONTRIBUTING.md': ['# Contributing', '## Development setup', '## Required checks', '## Safe fixtures and contributions'],
  'docs/architecture.md': ['# Architecture', '## Deterministic layers', '## Comparison identity', '## Target isolation', '## GitHub delivery and scoped roles', '## Check lifecycle', '## Security invariants'],
  'docs/permission-model.md': ['# Permission model', '## Observed source evidence', '## Repository-declared configuration and policy', '## Permission expressions', '## Aggregation and comparison', '## Catalog assumptions', '## Live App permissions'],
  'docs/limitations.md': ['# Limitations', '## Supported v1 surface', '## Incomplete analysis', '## External forks', '## Explicit exclusions'],
  'docs/github-delivery.md': ['# GitHub App delivery', '## App registration and events', '## Scoped roles', '## Check identity and outcomes', '## Production server', '## Freshness and finite publication'],
  'docs/demo.md': ['# Demonstration', '## Local deterministic proof', '## Live same-repository proof', '## External-fork feasibility', '## Sanitized evidence'],
  'docs/release.md': ['# Release runbook', '## Preconditions', '## Canonical and Docker proof', '## Live GitHub proof', '## Verification and review', '## Destination preflight', '## Operator authorization', '## Non-destructive publication', '## Post-publication verification', '## Partial publication'],
});

const REQUIRED_FILES = Object.freeze([
  '.dockerignore',
  '.github/workflows/ci.yml',
  'CONTRIBUTING.md',
  'Dockerfile',
  'LICENSE',
  'README.md',
  'SECURITY.md',
  'docs/analyzer.md',
  'docs/architecture.md',
  'docs/cli.md',
  'docs/configuration.md',
  'docs/demo.md',
  'docs/github-delivery.md',
  'docs/limitations.md',
  'docs/permission-model.md',
  'docs/release.md',
  'package.json',
]);

const FORBIDDEN_PATH = /(?:^|\/)(?:\.planning|\.agents|\.claude|\.codex|\.cursor|\.gemini|\.gsd|\.opencode)(?:\/|$)|(?:^|\/)(?:proofs?|reviews?|runtime-artifacts?)(?:\/|$)/iu;
const SECRET_PATH = /(?:^|\/)\.env(?:\..*)?$|\.(?:pem|key|p12|pfx|crt|cer)$|(?:^|\/)[^/]*(?:private[-_]?key|webhook[-_]?secret|access[-_]?token)[^/]*$/iu;
const TASK_WORDS = [['TO', 'DO'], ['T', 'BD'], ['FIX', 'ME'], ['X', 'XX']].map((parts) => parts.join('')).join('|');
const TASK_MARKER = new RegExp(`\\b(?:${TASK_WORDS})\\b|\\{\\{[^}\\n]+\\}\\}|<[A-Z][A-Z0-9_-]{2,}>`, 'u');
const ASSISTANT_ATTRIBUTION = /(?:generated|written|created|reviewed|implemented|authored|developed|co-authored)(?:\s|[-:]){1,4}.{0,50}\b(?:AI|Claude|Codex|ChatGPT|OpenAI|Anthropic)\b|\b(?:Claude|Codex|ChatGPT|OpenAI|Anthropic)\b.{0,50}(?:generated|authored|co-authored)/iu;
const SECRET_CONTENT = /github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|-----BEGIN (?:EC |OPENSSH |RSA )?PRIVATE KEY-----\n(?:[A-Za-z0-9+/]{20,}={0,2}\n){2,}-----END (?:EC |OPENSSH |RSA )?PRIVATE KEY-----/u;
const FORBIDDEN_RETAINED_KEY = /^(?:authorization|authorization_header|credential|credentials|private_key|raw|raw_body|raw_error|raw_payload|response|response_body|secret|source|source_text|token|tunnel_credential|webhook_secret)$/iu;
const SAFE_TEXT = /^[^\u0000-\u001f\u007f]{1,256}$/u;
const SAFE_REPOSITORY = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})\/[A-Za-z0-9._-]{1,100}$/u;
const SAFE_PATH = /^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9._/\-[\] ()@+]{1,512}$/u;

function compareBytes(left, right) {
  return Buffer.from(left).compare(Buffer.from(right));
}

function diagnostic(code, path) {
  return Object.freeze(path === undefined ? { code } : { code, path });
}

function exactKeys(value, keys) {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort(compareBytes);
  const expected = [...keys].sort(compareBytes);
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function isInteger(value, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) {
  return Number.isSafeInteger(value) && value >= minimum && value <= maximum;
}

function isIsoTimestamp(value) {
  if (typeof value !== 'string' || !ISO_PATTERN.test(value)) return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
}

function safeText(value, pattern = SAFE_TEXT) {
  return typeof value === 'string' && pattern.test(value);
}

function readBounded(root, path, budget, maximumFileBytes = MAX_FILE_BYTES) {
  const absolutePath = resolve(root, path);
  if (relative(root, absolutePath).startsWith(`..${sep}`) || absolutePath === root) throw new Error('repository/path');
  const details = statSync(absolutePath, { throwIfNoEntry: false });
  if (details === undefined || !details.isFile() || details.size > maximumFileBytes) throw new Error('repository/file');
  budget.total += details.size;
  if (budget.total > MAX_TOTAL_BYTES) throw new Error('repository/total-size');
  return readFileSync(absolutePath);
}

function trackedFiles(root) {
  const result = spawnSync('git', ['ls-files', '-z'], { cwd: root, encoding: 'buffer', timeout: 30_000 });
  if (result.status !== 0 || result.error !== undefined) throw new Error('repository/git-ls-files');
  return Object.freeze(
    result.stdout
      .toString('utf8')
      .split('\0')
      .filter(Boolean)
      .sort(compareBytes),
  );
}

function repositoryTextDiagnostics(path, text) {
  const diagnostics = [];
  const markerInput = path === 'tools/release/verify-release.mjs'
    ? text.replaceAll('{{.Server.Version}}', '').replaceAll('{{json .Config}}', '').replaceAll('{{.CreatedBy}}', '')
    : text;
  if (text.includes('\r')) diagnostics.push(diagnostic('repository/line-ending', path));
  if (!text.endsWith('\n')) diagnostics.push(diagnostic('repository/final-newline', path));
  if (TASK_MARKER.test(markerInput)) diagnostics.push(diagnostic('repository/task-marker', path));
  if (path !== 'tools/release/verify-release.mjs' && ASSISTANT_ATTRIBUTION.test(text)) {
    diagnostics.push(diagnostic('repository/assistant-attribution', path));
  }
  if (SECRET_CONTENT.test(text)) diagnostics.push(diagnostic('repository/secret-material', path));
  return diagnostics;
}

function markdownLinkDiagnostics(root, path, text, tracked) {
  const diagnostics = [];
  const links = text.matchAll(/\[[^\]\n]+\]\(([^)\n]+)\)/gu);
  for (const match of links) {
    const target = match[1]?.trim();
    if (target === undefined || target.startsWith('#') || /^(?:https?:|mailto:)/u.test(target)) continue;
    const withoutTitle = target.split(/\s+/u, 1)[0] ?? '';
    const decoded = decodeURIComponent(withoutTitle.split('#', 1)[0] ?? '');
    if (decoded.length === 0) continue;
    const resolved = normalize(join(dirname(path), decoded)).replaceAll('\\', '/');
    if (resolved.startsWith('../') || !tracked.has(resolved)) diagnostics.push(diagnostic('repository/broken-link', path));
  }
  return diagnostics;
}

function workflowDiagnostics(text) {
  const path = '.github/workflows/ci.yml';
  const diagnostics = [];
  const required = [
    ['ci/pull-request-trigger', /^  pull_request:\s*$/mu],
    ['ci/main-push-trigger', /push:\s*\n\s+branches:\s*\[main\]/u],
    ['ci/read-only', /^permissions:\s*\n  contents: read\s*$/mu],
    ['ci/single-job', /^  verify:\s*$/mu],
    ['ci/node-version', /node-version: ['"]?24\.19\.0['"]?/u],
    ['ci/generated-install-exclude', /run: printf '\/node_modules\/\\n' >> \.git\/info\/exclude/u],
    ['ci/frozen-install', /pnpm install --frozen-lockfile --ignore-scripts/u],
    ['ci/canonical-gate', /run: npm run verify:release/u],
    ['ci/no-checkout-credentials', /persist-credentials: false/u],
  ];
  for (const [code, pattern] of required) if (!pattern.test(text)) diagnostics.push(diagnostic(code, path));
  const actions = [...text.matchAll(/^\s*(?:-\s*)?uses:\s*([^\s#]+)(?:\s+#\s*(v[^\s]+))?\s*$/gmu)];
  if (actions.length !== 2) diagnostics.push(diagnostic('ci/action-count', path));
  for (const action of actions) {
    if (!/^actions\/(?:checkout|setup-node)@[a-f0-9]{40}$/u.test(action[1] ?? '') || !/^v\d+(?:\.\d+){1,2}$/u.test(action[2] ?? '')) {
      diagnostics.push(diagnostic('ci/action-not-immutable', path));
    }
  }
  const jobsText = text.slice(text.indexOf('\njobs:\n') + '\njobs:\n'.length);
  const jobMatches = [...jobsText.matchAll(/^  ([a-z][a-z0-9_-]*):\s*$/gmu)].map((match) => match[1]);
  if (jobMatches.join(',') !== 'verify') diagnostics.push(diagnostic('ci/job-surface', path));
  if (/\$\{\{\s*secrets\.|permissions:[\s\S]{0,100}\bwrite\b|\b(?:docker push|npm publish|gh release|deploy(?:ment)? action|publish action)\b/iu.test(text)) {
    diagnostics.push(diagnostic('ci/mutation-or-secret', path));
  }
  return diagnostics;
}

function dockerDiagnostics(dockerfile, dockerignore) {
  const diagnostics = [];
  const froms = [...dockerfile.matchAll(/^FROM\s+(\S+)/gmu)].map((match) => match[1]);
  if (froms.length !== 2 || froms.some((reference) => reference !== IMAGE_REFERENCE)) {
    diagnostics.push(diagnostic('docker/immutable-base', 'Dockerfile'));
  }
  const required = [
    ['docker/corepack', /RUN corepack enable && corepack install/u],
    ['docker/frozen-install', /pnpm install --frozen-lockfile --ignore-scripts/u],
    ['docker/build', /pnpm run build/u],
    ['docker/prune', /pnpm prune --prod --ignore-scripts/u],
    ['docker/non-root', /^USER node$/mu],
    ['docker/port', /^EXPOSE 3000$/mu],
    ['docker/command', /^CMD \["node", "dist\/delivery\/server\.js"\]$/mu],
  ];
  for (const [code, pattern] of required) if (!pattern.test(dockerfile)) diagnostics.push(diagnostic(code, 'Dockerfile'));
  if (/^(?:ARG|ENV)\s+(?:APP_ID|PRIVATE_KEY|PRIVATE_KEY_PATH|WEBHOOK_SECRET|GITHUB_TOKEN)\b/mu.test(dockerfile)) {
    diagnostics.push(diagnostic('docker/credential-input', 'Dockerfile'));
  }
  for (const requiredIgnore of ['**', '**/.git/**', '**/.planning/**', '**/.agents/**', '**/.codex/**', '**/.env.*', '**/*.pem', '**/tests/**', '**/fixtures/**', '**/node_modules/**', '**/dist/**']) {
    if (!dockerignore.split('\n').includes(requiredIgnore)) diagnostics.push(diagnostic('docker/context-rule', '.dockerignore'));
  }
  return diagnostics;
}

/** Verifies an explicit sorted snapshot; tests use this to exercise hostile temporary fixtures. */
export function verifyRepositorySnapshot(root, paths) {
  const diagnostics = [];
  const normalizedRoot = realpathSync(root);
  const tracked = new Set([...paths].sort(compareBytes));
  const budget = { total: 0 };
  const texts = new Map();
  for (const path of tracked) {
    if (path.startsWith('/') || path.includes('\\') || path.split('/').includes('..')) {
      diagnostics.push(diagnostic('repository/path-invalid', path));
      continue;
    }
    if (FORBIDDEN_PATH.test(path)) diagnostics.push(diagnostic('repository/forbidden-path', path));
    if (SECRET_PATH.test(path)) diagnostics.push(diagnostic('repository/secret-path', path));
    try {
      const bytes = readBounded(normalizedRoot, path, budget);
      const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
      texts.set(path, text);
      diagnostics.push(...repositoryTextDiagnostics(path, text));
      if (path.endsWith('.md')) diagnostics.push(...markdownLinkDiagnostics(normalizedRoot, path, text, tracked));
    } catch (error) {
      diagnostics.push(diagnostic(error instanceof Error && error.message.startsWith('repository/') ? error.message : 'repository/read', path));
    }
  }
  for (const path of REQUIRED_FILES) if (!tracked.has(path)) diagnostics.push(diagnostic('repository/required-file', path));
  for (const [path, headings] of Object.entries(REQUIRED_HEADINGS)) {
    const text = texts.get(path);
    if (text === undefined) continue;
    for (const heading of headings) if (!text.split('\n').includes(heading)) diagnostics.push(diagnostic('docs/required-heading', path));
  }
  const readme = texts.get('README.md') ?? '';
  if (!/^# BoundaryCI\n\n[^\n]*permission drift/iu.test(readme)) diagnostics.push(diagnostic('docs/value-proposition-first', 'README.md'));
  for (const phrase of ['Issues `read` → `write`', '`issues/create`', '`failure`', '`Permission expansion requires review`']) {
    if (!readme.includes(phrase)) diagnostics.push(diagnostic('docs/issues-demonstration', 'README.md'));
  }
  const publicClaims = [...texts.entries()].filter(([path]) => path.endsWith('.md')).map(([, text]) => text).join('\n');
  for (const phrase of ['Observed source evidence', 'Repository-declared configuration and policy', 'Unresolved analysis', 'independently verified live App permissions', 'does not retrieve']) {
    if (!publicClaims.toLowerCase().includes(phrase.toLowerCase())) diagnostics.push(diagnostic('docs/evidence-category', 'docs/permission-model.md'));
  }
  const license = texts.get('LICENSE');
  if (license !== undefined && createHash('sha256').update(license).digest('hex') !== APACHE_2_SHA256) {
    diagnostics.push(diagnostic('license/apache-2.0-bytes', 'LICENSE'));
  }
  const packageText = texts.get('package.json');
  if (packageText !== undefined) {
    try {
      const metadata = JSON.parse(packageText);
      if (metadata.license !== 'Apache-2.0') diagnostics.push(diagnostic('license/package-metadata', 'package.json'));
      if (metadata.scripts?.start !== 'node dist/delivery/server.js') diagnostics.push(diagnostic('repository/start-script', 'package.json'));
      if (metadata.scripts?.['verify:release'] !== 'node tools/release/verify-release.mjs') diagnostics.push(diagnostic('repository/release-script', 'package.json'));
    } catch {
      diagnostics.push(diagnostic('repository/package-json', 'package.json'));
    }
  }
  const workflows = [...tracked].filter((path) => path.startsWith('.github/workflows/'));
  if (workflows.join(',') !== '.github/workflows/ci.yml') diagnostics.push(diagnostic('ci/workflow-surface', '.github/workflows'));
  const workflow = texts.get('.github/workflows/ci.yml');
  if (workflow !== undefined) diagnostics.push(...workflowDiagnostics(workflow));
  const dockerfile = texts.get('Dockerfile');
  const dockerignore = texts.get('.dockerignore');
  if (dockerfile !== undefined && dockerignore !== undefined) diagnostics.push(...dockerDiagnostics(dockerfile, dockerignore));
  return Object.freeze(diagnostics.sort((left, right) => compareBytes(`${left.code}:${left.path ?? ''}`, `${right.code}:${right.path ?? ''}`)));
}

export function verifyRepository(root = PROJECT_ROOT) {
  try {
    return verifyRepositorySnapshot(root, trackedFiles(root));
  } catch (error) {
    return Object.freeze([diagnostic(error instanceof Error ? error.message : 'repository/failure')]);
  }
}

function retainedValueDiagnostics(value, path = '$') {
  const diagnostics = [];
  if (Array.isArray(value)) {
    value.forEach((entry, index) => diagnostics.push(...retainedValueDiagnostics(entry, `${path}[${index}]`)));
    return diagnostics;
  }
  if (typeof value !== 'object' || value === null) {
    if (typeof value === 'string' && (SECRET_CONTENT.test(value) || ASSISTANT_ATTRIBUTION.test(value))) {
      diagnostics.push(diagnostic('proof/forbidden-material'));
    }
    return diagnostics;
  }
  for (const [key, entry] of Object.entries(value)) {
    if (FORBIDDEN_RETAINED_KEY.test(key)) diagnostics.push(diagnostic('proof/forbidden-field'));
    diagnostics.push(...retainedValueDiagnostics(entry, `${path}.${key}`));
  }
  return diagnostics;
}

const PROOF_CHECK_KEYS = Object.freeze({
  docker: ['canonical_gate', 'image_digest', 'runtime_user', 'runtime_command', 'health', 'signed_webhook', 'invalid_signature', 'shutdown_milliseconds', 'residue', 'forbidden_material'],
  ci: ['workflow', 'run_id', 'head_sha', 'conclusion', 'canonical_gate'],
  'same-repository': ['repository', 'pull_number', 'app_id', 'check_id', 'head_sha', 'conclusion', 'title', 'operation', 'annotation_path', 'annotation_start', 'annotation_end', 'create_calls', 'update_calls', 'annotation_update_calls', 'exact_check_count', 'redelivery', 'reconciliation', 'stale_mutations', 'duplicate_mutations', 'no_expansion'],
  'external-fork': ['repository', 'pull_number', 'head_repository', 'topology', 'outcome', 'conclusion', 'check_mutations', 'source_acquisition', 'never_green'],
  'phase-verification': ['report', 'requirements', 'verification', 'canonical_gate', 'docker', 'ci', 'same_repository', 'external_fork', 'integrated_review'],
  destination: ['repository', 'authenticated_owner', 'visibility', 'state', 'eligible', 'main_sha', 'tag_sha', 'remote_tag_kind', 'local_tag_kind', 'gates', 'clean_tree'],
  publication: ['repository', 'branch', 'tag', 'decision', 'operator', 'decision_at', 'state', 'main_outcome', 'tag_outcome', 'main_sha', 'tag_sha', 'tag_kind', 'non_force', 'deletions'],
  'post-publication': ['repository', 'visibility', 'default_branch', 'main_sha', 'tag_object_sha', 'tag_target_sha', 'tag_kind', 'file_set_sha256', 'file_count', 'documentation', 'forbidden_material'],
});

function validCommonProof(kind, value, sha) {
  return exactKeys(value, ['schema_version', 'kind', 'release_sha', 'captured_at', 'status', 'checks']) &&
    value.schema_version === 1 && value.kind === kind && value.release_sha === sha && isIsoTimestamp(value.captured_at) &&
    typeof value.status === 'string' && typeof value.checks === 'object' && value.checks !== null && !Array.isArray(value.checks);
}

function validateChecks(kind, checks, sha) {
  if (!exactKeys(checks, PROOF_CHECK_KEYS[kind] ?? [])) return false;
  if (kind === 'docker') return checks.canonical_gate === 'pass' && DIGEST_PATTERN.test(checks.image_digest) && checks.runtime_user === 'node' && checks.runtime_command === 'node dist/delivery/server.js' && checks.health === 'pass' && checks.signed_webhook === 'pass' && checks.invalid_signature === 'rejected' && isInteger(checks.shutdown_milliseconds, 0, 10_000) && checks.residue === 'absent' && checks.forbidden_material === 'absent';
  if (kind === 'ci') return checks.workflow === '.github/workflows/ci.yml' && isInteger(checks.run_id, 1) && checks.head_sha === sha && checks.conclusion === 'success' && checks.canonical_gate === 'pass';
  if (kind === 'same-repository') return safeText(checks.repository, SAFE_REPOSITORY) && isInteger(checks.pull_number, 1) && isInteger(checks.app_id, 1) && isInteger(checks.check_id, 1) && SHA_PATTERN.test(checks.head_sha) && checks.conclusion === 'failure' && checks.title === 'Permission expansion requires review' && checks.operation === 'issues/create' && safeText(checks.annotation_path, SAFE_PATH) && isInteger(checks.annotation_start, 1) && isInteger(checks.annotation_end, checks.annotation_start) && isInteger(checks.create_calls, 1, 1) && isInteger(checks.update_calls) && checks.annotation_update_calls === 0 && checks.exact_check_count === 1 && checks.redelivery === 'converged' && checks.reconciliation === 'converged' && checks.stale_mutations === 0 && checks.duplicate_mutations === 0 && checks.no_expansion === 'pass';
  if (kind === 'external-fork') {
    const addressable = checks.topology === 'addressable';
    return safeText(checks.repository, SAFE_REPOSITORY) && safeText(checks.head_repository, SAFE_REPOSITORY) && isInteger(checks.pull_number, 1) && (addressable || checks.topology === 'unaddressable') && checks.outcome === (addressable ? 'action_required' : 'not-published') && checks.conclusion === (addressable ? 'action_required' : null) && checks.check_mutations === (addressable ? 1 : 0) && checks.source_acquisition === 0 && checks.never_green === true;
  }
  if (kind === 'phase-verification') return checks.report === '.planning/phases/BCI-06-github-check-experience-release-proof/06-VERIFICATION.md' && ['requirements', 'verification', 'canonical_gate', 'docker', 'ci', 'same_repository', 'external_fork', 'integrated_review'].every((key) => key === 'report' || checks[key] === 'pass');
  if (kind === 'destination') return checks.repository === 'Gares95/boundaryci' && checks.authenticated_owner === 'Gares95' && ['absent', 'public'].includes(checks.visibility) && ['absent', 'empty', 'complete', 'partial', 'conflict'].includes(checks.state) && typeof checks.eligible === 'boolean' && (checks.main_sha === null || checks.main_sha === sha) && (checks.tag_sha === null || checks.tag_sha === sha) && ['absent', 'annotated', 'conflict'].includes(checks.remote_tag_kind) && ['absent', 'annotated', 'conflict'].includes(checks.local_tag_kind) && checks.gates === 'pass' && checks.clean_tree === true;
  if (kind === 'publication') return checks.repository === 'Gares95/boundaryci' && checks.branch === 'main' && checks.tag === 'v1.0.0' && ['approve-exact-release', 'abort'].includes(checks.decision) && safeText(checks.operator) && isIsoTimestamp(checks.decision_at) && ['complete', 'partial', 'aborted', 'blocked'].includes(checks.state) && ['published', 'already-exact', 'not-attempted'].includes(checks.main_outcome) && ['published', 'already-exact', 'not-attempted'].includes(checks.tag_outcome) && (checks.main_sha === null || checks.main_sha === sha) && (checks.tag_sha === null || checks.tag_sha === sha) && ['annotated', 'absent'].includes(checks.tag_kind) && checks.non_force === true && checks.deletions === 0;
  if (kind === 'post-publication') return checks.repository === 'Gares95/boundaryci' && checks.visibility === 'public' && checks.default_branch === 'main' && checks.main_sha === sha && SHA_PATTERN.test(checks.tag_object_sha) && checks.tag_target_sha === sha && checks.tag_kind === 'annotated' && DIGEST_PATTERN.test(checks.file_set_sha256) && isInteger(checks.file_count, 1) && checks.documentation === 'pass' && checks.forbidden_material === 'absent';
  return false;
}

function validateReviewText(text, sha) {
  if (Buffer.byteLength(text) > MAX_PROOF_BYTES || text.includes('\r') || !text.endsWith('\n')) return false;
  const lines = text.split('\n');
  const title = lines[0];
  const releaseLine = lines[2];
  const kindLine = lines[3];
  const statusLine = lines[4];
  const severityLine = lines[5];
  const kind = kindLine?.replace('Review-Kind: ', '');
  const status = statusLine?.replace('Status: ', '');
  const severity = severityLine?.replace('Highest-Severity: ', '');
  const expectedTitle = kind === 'integrated' ? '# Phase 6 integrated review' : '# Phase 6 closure review';
  return title === expectedTitle && releaseLine === `Release-SHA: ${sha}` && ['integrated', 'closure'].includes(kind) && ['pass', 'fail'].includes(status) && ['none', 'low', 'medium', 'high', 'critical'].includes(severity) &&
    lines.includes('## Scope') && lines.includes('## Findings') && lines.includes('## Security disposition') &&
    !(status === 'pass' && ['high', 'critical'].includes(severity)) &&
    !/(?:^|[\s(])(?:\/home\/|\.planning\/|\.agents\/|\.claude\/|\.codex\/)/mu.test(text) &&
    retainedValueDiagnostics(text).length === 0;
}

export function validateProofRecord(kind, value, sha) {
  if (!PROOF_KINDS.includes(kind) || !SHA_PATTERN.test(sha)) return Object.freeze([diagnostic('proof/arguments')]);
  if (kind === 'review') return Object.freeze([diagnostic('proof/review-format')]);
  const diagnostics = retainedValueDiagnostics(value);
  if (!validCommonProof(kind, value, sha)) diagnostics.push(diagnostic('proof/common-schema'));
  else {
    const statuses = kind === 'destination'
      ? ['pass', 'blocked']
      : kind === 'publication'
        ? ['pass', 'partial', 'blocked']
        : ['pass'];
    if (!statuses.includes(value.status)) diagnostics.push(diagnostic('proof/status'));
    if (!validateChecks(kind, value.checks, sha)) diagnostics.push(diagnostic('proof/kind-schema'));
  }
  return Object.freeze(diagnostics.sort((left, right) => compareBytes(left.code, right.code)));
}

export function validateProofFile(kind, file, sha) {
  try {
    const details = statSync(file);
    if (!details.isFile() || details.size > MAX_PROOF_BYTES) return Object.freeze([diagnostic('proof/file')]);
    const text = readFileSync(file, 'utf8');
    if (kind === 'review') return validateReviewText(text, sha) ? Object.freeze([]) : Object.freeze([diagnostic('proof/review-format')]);
    return validateProofRecord(kind, JSON.parse(text), sha);
  } catch {
    return Object.freeze([diagnostic('proof/file')]);
  }
}

function runChecked(executable, args, cwd, code, options = {}) {
  const result = spawnSync(executable, args, {
    cwd,
    encoding: 'utf8',
    timeout: options.timeout ?? 600_000,
    stdio: options.inherit ? 'inherit' : 'pipe',
  });
  if (result.status !== 0 || result.error !== undefined) throw new Error(code);
  return result.stdout ?? '';
}

function listFiles(root, directory = root) {
  const result = [];
  for (const entry of readdirSync(directory, { withFileTypes: true }).sort((left, right) => compareBytes(left.name, right.name))) {
    const absolutePath = join(directory, entry.name);
    if (entry.isDirectory()) result.push(...listFiles(root, absolutePath));
    else if (entry.isFile()) result.push(relative(root, absolutePath).replaceAll('\\', '/'));
  }
  return result;
}

export function unsafeImageApplicationPath(path) {
  if (!path.startsWith('app/')) return true;
  if (FORBIDDEN_PATH.test(path) || /(?:^|\/)(?:\.github|tests?|fixtures?|coverage)(?:\/|$)/iu.test(path)) return true;
  return !path.startsWith('app/node_modules/') && SECRET_PATH.test(path);
}

function verifyDocker(root, sha) {
  for (const key of ['APP_ID', 'PRIVATE_KEY_PATH', 'WEBHOOK_SECRET']) if (process.env[key] !== undefined) throw new Error('docker/runtime-credential-present');
  runChecked('docker', ['version', '--format', '{{.Server.Version}}'], root, 'docker/unavailable');
  const tag = `boundaryci-release-verify:${sha}`;
  const container = `boundaryci-release-verify-${sha.slice(0, 12)}`;
  const temporary = mkdtempSync(join(tmpdir(), 'boundaryci-release-image-'));
  let created = false;
  try {
    const existingImage = spawnSync('docker', ['image', 'inspect', tag], { cwd: root, stdio: 'ignore', timeout: 30_000 });
    if (existingImage.status === 0) throw new Error('docker/tag-conflict');
    const existingContainer = spawnSync('docker', ['container', 'inspect', container], { cwd: root, stdio: 'ignore', timeout: 30_000 });
    if (existingContainer.status === 0) throw new Error('docker/container-conflict');
    runChecked('docker', ['build', '--rm', '--force-rm', '--label', `org.boundaryci.release-sha=${sha}`, '--tag', tag, '.'], root, 'docker/build', { timeout: 900_000, inherit: true });
    const configText = runChecked('docker', ['image', 'inspect', '--format', '{{json .Config}}', tag], root, 'docker/inspect');
    const imageConfig = JSON.parse(configText);
    if (imageConfig.User !== 'node' || JSON.stringify(imageConfig.Cmd) !== JSON.stringify(['node', 'dist/delivery/server.js'])) throw new Error('docker/runtime-contract');
    runChecked('docker', ['run', '--rm', '--entrypoint', 'node', tag, '--input-type=module', '--eval', "await import('./dist/delivery/server.js')"], root, 'docker/runtime-load');
    const history = runChecked('docker', ['history', '--no-trunc', '--format', '{{.CreatedBy}}', tag], root, 'docker/history');
    if (SECRET_CONTENT.test(history) || /\b(?:APP_ID|PRIVATE_KEY_PATH|WEBHOOK_SECRET)\b/u.test(history)) throw new Error('docker/history-material');
    runChecked('docker', ['create', '--name', container, tag], root, 'docker/create');
    created = true;
    const archive = join(temporary, 'filesystem.tar');
    runChecked('docker', ['export', '--output', archive, container], root, 'docker/export');
    const extracted = join(temporary, 'filesystem');
    runChecked('mkdir', ['-p', extracted], root, 'docker/extract-directory');
    runChecked('tar', ['-xf', archive, '-C', extracted], root, 'docker/extract');
    const applicationFiles = listFiles(extracted).filter((path) => path.startsWith('app/'));
    if (applicationFiles.some((path) => unsafeImageApplicationPath(path))) throw new Error('docker/filesystem-path');
    const budget = { total: 0 };
    for (const path of applicationFiles) {
      const bytes = readBounded(extracted, path, budget, MAX_IMAGE_FILE_BYTES);
      if (bytes.includes(0)) continue;
      const text = bytes.toString('utf8');
      if (SECRET_CONTENT.test(text) || ASSISTANT_ATTRIBUTION.test(text)) throw new Error('docker/filesystem-material');
    }
  } finally {
    if (created) spawnSync('docker', ['container', 'rm', '--force', container], { cwd: root, stdio: 'ignore', timeout: 30_000 });
    spawnSync('docker', ['image', 'rm', '--force', tag], { cwd: root, stdio: 'ignore', timeout: 60_000 });
    rmSync(temporary, { force: true, recursive: true });
  }
}

function printDiagnostics(diagnostics) {
  for (const item of diagnostics) process.stderr.write(`${item.code}${item.path === undefined ? '' : `:${item.path}`}\n`);
  if (diagnostics.length > 0) process.exitCode = 1;
}

function requireCleanSha(root) {
  const status = runChecked('git', ['status', '--porcelain', '--untracked-files=all'], root, 'full/git-status');
  if (status.length !== 0) throw new Error('full/dirty-tree');
  const sha = runChecked('git', ['rev-parse', 'HEAD'], root, 'full/git-sha').trim();
  if (!SHA_PATTERN.test(sha)) throw new Error('full/git-sha');
  return sha;
}

function runFull(root) {
  const sha = requireCleanSha(root);
  for (const [args, code] of [
    [['test'], 'full/tests'],
    [['run', 'typecheck'], 'full/typecheck'],
    [['run', 'lint'], 'full/lint'],
    [['run', 'format:check'], 'full/format'],
    [['run', 'build'], 'full/build'],
  ]) runChecked('npm', args, root, code, { inherit: true });
  const diagnostics = verifyRepository(root);
  if (diagnostics.length > 0) return diagnostics;
  verifyDocker(root, sha);
  return [];
}

function parseArguments(args) {
  if (args.length === 0) return { mode: 'full' };
  if (args.length === 1 && args[0] === '--repository-only') return { mode: 'repository-only' };
  if (args.length === 6 && args[0] === '--proof-kind' && args[2] === '--file' && args[4] === '--sha' && PROOF_KINDS.includes(args[1]) && SHA_PATTERN.test(args[5])) {
    return { mode: 'proof', kind: args[1], file: args[3], sha: args[5] };
  }
  return null;
}

export function runCli(args, root = PROJECT_ROOT) {
  const parsed = parseArguments(args);
  if (parsed === null) return Object.freeze([diagnostic('usage')]);
  if (parsed.mode === 'repository-only') return verifyRepository(root);
  if (parsed.mode === 'proof') return validateProofFile(parsed.kind, resolve(root, parsed.file), parsed.sha);
  try {
    return Object.freeze(runFull(root));
  } catch (error) {
    return Object.freeze([diagnostic(error instanceof Error ? error.message : 'full/failure')]);
  }
}

const invokedPath = process.argv[1];
if (invokedPath !== undefined && import.meta.url === pathToFileURL(invokedPath).href) {
  const parsed = parseArguments(process.argv.slice(2));
  const diagnostics = runCli(process.argv.slice(2));
  printDiagnostics(diagnostics);
  if (diagnostics.length === 0) process.stdout.write(`release-verifier:pass:${parsed?.mode ?? 'unknown'}\n`);
}
