import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, realpathSync, renameSync, writeFileSync } from 'node:fs';
import { relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const PROJECT_ROOT = realpathSync(fileURLToPath(new URL('../../../', import.meta.url)));
const REPORT_PATH = 'tools/permission-data-feasibility/evidence/verification-report.json';
const MAX_FILE_BYTES = 8 * 1024 * 1024;
const SHA256 = /^[a-f0-9]{64}$/u;

const JSON_CONTRACTS = {
  'tools/permission-data-feasibility/evidence/artifact-manifest.json': [
    'artifacts',
    'contentSha256',
    'documentationVersioning',
    'githubRestApiEvidenceVersion',
    'project',
    'runtimeEndpointSelection',
    'schemaVersion',
  ],
  'tools/permission-data-feasibility/evidence/permission-sources.json': [
    'contentSha256',
    'documentation',
    'facts',
    'headerFacts',
    'refusedProbes',
    'schemaVersion',
    'vocabulary',
  ],
  'tools/permission-data-feasibility/evidence/operation-inventory.json': [
    'apiVersion',
    'artifactManifestSha256',
    'contentSha256',
    'methodJoinRows',
    'methodUniverse',
    'operationRows',
    'operationUniverse',
    'permissionSourcesSha256',
    'schemaVersion',
    'strategy',
  ],
  'tools/permission-data-feasibility/evidence/support-manifest.json': [
    'artifactManifestSha256',
    'contentSha256',
    'permissionSourcesSha256',
    'predicate',
    'requiredOperationIds',
    'schemaVersion',
    'selectedMembers',
    'selectionSha256',
    'strategy',
  ],
  'tools/permission-data-feasibility/evidence/operation-ledger.json': [
    'artifactManifestSha256',
    'authorizedScopeCandidate',
    'contentSha256',
    'inventorySha256',
    'methodCounts',
    'methodJoinRows',
    'operationCounts',
    'operationRows',
    'permissionSourcesSha256',
    'preliminarySelectionSha256',
    'schemaVersion',
    'sourcePrecedenceSha256',
    'supportManifestSha256',
    'supportPredicateSha256',
  ],
  'tools/permission-data-feasibility/evidence/incomplete-semantics.json': [
    'contentSha256',
    'definitions',
    'schemaVersion',
    'topLevelOutcome',
  ],
  'tools/permission-data-feasibility/evidence/feasibility-packet.json': [
    'artifactManifest',
    'authorizedScopeCandidate',
    'canonicalIssues',
    'contentSha256',
    'incompleteSemantics',
    'inventory',
    'knownLimitations',
    'ledger',
    'legalTerminalOutcomes',
    'schemaVersion',
    'sourcePrecedence',
    'support',
  ],
  'tools/permission-data-feasibility/evidence/decision-record.json': [
    'authorization',
    'contentSha256',
    'decidedAt',
    'decisionMaker',
    'evidence',
    'excludedIncompleteClasses',
    'knownLimitations',
    'outcome',
    'rationale',
    'review',
    'schemaVersion',
    'usefulness',
    'wordingAccepted',
  ],
  'tools/permission-data-feasibility/fixtures/canonical-issues.json': [
    'artifactManifestSha256',
    'chains',
    'contentSha256',
    'permissionSourcesSha256',
    'schemaVersion',
  ],
  'tools/permission-data-feasibility/fixtures/header-expressions.json': [
    'cases',
    'contentSha256',
    'schemaVersion',
    'vocabulary',
  ],
};

const SOURCE_FILES = [
  'tools/permission-data-feasibility/artifact-sources.ts',
  'tools/permission-data-feasibility/contracts.ts',
  'tools/permission-data-feasibility/decision.ts',
  'tools/permission-data-feasibility/extract.ts',
  'tools/permission-data-feasibility/fail-closed.ts',
  'tools/permission-data-feasibility/inventory.ts',
  'tools/permission-data-feasibility/ledger.ts',
  'tools/permission-data-feasibility/provenance.ts',
  'tools/permission-data-feasibility/requirement-expression.ts',
  'tools/permission-data-feasibility/source-evidence.ts',
  'tools/permission-data-feasibility/scripts/build-evidence.ts',
  'tools/permission-data-feasibility/scripts/write-artifact-manifest.ts',
];

const PUBLIC_TEXT_FILES = ['tools/permission-data-feasibility/evidence/DECISION.md'];

function fail(message) {
  throw new Error(message);
}

function canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((entry) => canonicalJson(entry)).join(',')}]`;
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(',')}}`;
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function resolveFile(path) {
  if (path.startsWith('/') || path.includes('\\') || path.split('/').some((part) => part === '' || part === '.' || part === '..')) {
    fail(`non-portable path: ${path}`);
  }
  const requested = resolve(PROJECT_ROOT, path);
  const lexical = relative(PROJECT_ROOT, requested);
  if (lexical === '..' || lexical.startsWith(`..${sep}`)) fail(`path escapes project: ${path}`);
  const actual = realpathSync(requested);
  const physical = relative(PROJECT_ROOT, actual);
  if (physical === '..' || physical.startsWith(`..${sep}`)) fail(`path target escapes project: ${path}`);
  const stat = lstatSync(actual);
  if (!stat.isFile() || stat.size > MAX_FILE_BYTES) fail(`invalid bounded regular file: ${path}`);
  return { actual, stat };
}

function readText(path) {
  const { actual, stat } = resolveFile(path);
  const bytes = readFileSync(actual);
  if (bytes.byteLength !== stat.size) fail(`file changed while reading: ${path}`);
  return bytes.toString('utf8');
}

function readJson(path) {
  try {
    return JSON.parse(readText(path));
  } catch (error) {
    throw new Error(`malformed JSON: ${path}`, { cause: error });
  }
}

function exactKeys(value, keys, label) {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) fail(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail(`${label} has unknown or missing keys: ${actual.join(',')}`);
  }
}

function validateShaFields(value, label) {
  if (Array.isArray(value)) {
    value.forEach((entry, index) => validateShaFields(entry, `${label}[${index}]`));
    return;
  }
  if (typeof value !== 'object' || value === null) return;
  for (const [key, entry] of Object.entries(value)) {
    if (/sha256$/iu.test(key) && entry !== null && (typeof entry !== 'string' || !SHA256.test(entry))) {
      fail(`${label}.${key} is not a lowercase SHA-256`);
    }
    validateShaFields(entry, `${label}.${key}`);
  }
}

function validateContentDigest(value, label) {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) fail(`${label} must be an object`);
  const { contentSha256, ...unsigned } = value;
  if (typeof contentSha256 !== 'string' || !SHA256.test(contentSha256)) fail(`${label}.contentSha256 is invalid`);
  if (contentSha256 !== sha256(canonicalJson(unsigned))) fail(`${label}.contentSha256 does not match its content`);
}

function countValues(record) {
  return Object.values(record).reduce((sum, value) => {
    if (!Number.isSafeInteger(value) || value < 0) fail('count record contains an invalid value');
    return sum + value;
  }, 0);
}

function sameJson(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

const checks = [];
function check(id, action) {
  action();
  checks.push({ id, status: 'pass' });
}

const documents = {};

check('json-contracts-and-digests', () => {
  for (const [path, keys] of Object.entries(JSON_CONTRACTS)) {
    const value = readJson(path);
    exactKeys(value, keys, path);
    validateShaFields(value, path);
    validateContentDigest(value, path);
    documents[path] = value;
  }
});

check('format-and-final-newline', () => {
  for (const path of [
    ...Object.keys(JSON_CONTRACTS),
    ...SOURCE_FILES,
    ...PUBLIC_TEXT_FILES,
    'tools/permission-data-feasibility/scripts/quality-checks.mjs',
  ]) {
    const text = readText(path);
    if (!text.endsWith('\n')) fail(`missing final newline: ${path}`);
    const badLine = text.split('\n').findIndex((line) => /[\t ]+$/u.test(line));
    if (badLine !== -1) fail(`trailing whitespace: ${path}:${badLine + 1}`);
  }
});

check('no-target-code-execution', () => {
  const forbidden = [
    /node:child_process/u,
    /\bchild_process\b/u,
    /\beval\s*\(/u,
    /\bnew\s+Function\b/u,
    /\bimport\s*\(/u,
    /\brequire\s*\(/u,
    /\bcreateProgram\s*\(/u,
    /\bts-morph\b/u,
  ];
  for (const path of SOURCE_FILES) {
    const text = readText(path);
    const match = forbidden.find((pattern) => pattern.test(text));
    if (match !== undefined) fail(`forbidden execution or dynamic-import pattern in ${path}: ${match}`);
  }
});

check('public-neutral-content', () => {
  const localOnlyFragments = [
    `.${['plan', 'ning'].join('')}`,
    `.${['local', 'hooks'].join('-')}`,
    ['/ho', 'me/'].join(''),
  ];
  const attributionWords = [
    ['assist', 'ant'].join(''),
    ['anth', 'ropic'].join(''),
    ['clau', 'de'].join(''),
    ['co', 'dex'].join(''),
    ['open', 'ai'].join(''),
  ];
  const attribution = new RegExp(`\\b(?:${attributionWords.join('|')})\\b`, 'iu');
  const placeholders = new RegExp(`\\b(?:${[['TO', 'DO'], ['T', 'BD'], ['FIX', 'ME']]
    .map((parts) => parts.join(''))
    .join('|')})\\b`, 'u');
  const forbidden = [
    attribution,
    placeholders,
    /\{\{[^{}]+\}\}/u,
    /\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/u,
    /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/u,
  ];
  for (const path of [...Object.keys(JSON_CONTRACTS), ...PUBLIC_TEXT_FILES]) {
    const text = readText(path);
    const fragment = localOnlyFragments.find((candidate) => text.includes(candidate));
    if (fragment !== undefined) fail(`forbidden local-only content in ${path}`);
    const match = forbidden.find((pattern) => pattern.test(text));
    if (match !== undefined) fail(`forbidden public content in ${path}: ${match}`);
  }
});

check('inventory-ledger-reconciliation', () => {
  const inventory = documents['tools/permission-data-feasibility/evidence/operation-inventory.json'];
  const ledger = documents['tools/permission-data-feasibility/evidence/operation-ledger.json'];
  const support = documents['tools/permission-data-feasibility/evidence/support-manifest.json'];
  if (inventory.operationRows.length !== inventory.operationUniverse.total) fail('operation inventory row count mismatch');
  if (inventory.methodJoinRows.length !== inventory.methodUniverse.total) fail('method inventory row count mismatch');
  if (countValues(inventory.operationUniverse.classCounts) !== inventory.operationUniverse.total) fail('operation class counts mismatch');
  if (countValues(inventory.operationUniverse.freshnessCounts) !== inventory.operationUniverse.total) fail('operation freshness counts mismatch');
  if (countValues(inventory.operationUniverse.credentialApplicabilityCounts) !== inventory.operationUniverse.total) fail('credential counts mismatch');
  if (countValues(inventory.methodUniverse.surfaceCounts) !== inventory.methodUniverse.total) fail('method surface counts mismatch');
  if (countValues(inventory.methodUniverse.operationJoinCounts) !== inventory.methodUniverse.total) fail('method join counts mismatch');
  if (ledger.operationRows.length !== ledger.operationCounts.total) fail('ledger operation rows mismatch');
  if (ledger.methodJoinRows.length !== ledger.methodCounts.total) fail('ledger method rows mismatch');
  if (ledger.operationCounts.candidateSupported + ledger.operationCounts.incomplete !== ledger.operationCounts.total) fail('ledger operation counts mismatch');
  if (ledger.methodCounts.resolved + ledger.methodCounts.incomplete !== ledger.methodCounts.total) fail('ledger method counts mismatch');
  if (support.selectedMembers.length !== ledger.operationCounts.candidateSupported) fail('selected-member count mismatch');
  if (support.selectedMembers.length !== ledger.authorizedScopeCandidate.members.length) fail('authorized-scope count mismatch');
  if (ledger.authorizedScopeCandidate.authorizedScopeSha256 !== sha256(canonicalJson(ledger.authorizedScopeCandidate.members))) {
    fail('authorized-scope digest mismatch');
  }
});

check('cross-artifact-reconciliation', () => {
  const manifest = documents['tools/permission-data-feasibility/evidence/artifact-manifest.json'];
  const permission = documents['tools/permission-data-feasibility/evidence/permission-sources.json'];
  const inventory = documents['tools/permission-data-feasibility/evidence/operation-inventory.json'];
  const support = documents['tools/permission-data-feasibility/evidence/support-manifest.json'];
  const ledger = documents['tools/permission-data-feasibility/evidence/operation-ledger.json'];
  const incomplete = documents['tools/permission-data-feasibility/evidence/incomplete-semantics.json'];
  const packet = documents['tools/permission-data-feasibility/evidence/feasibility-packet.json'];
  const decision = documents['tools/permission-data-feasibility/evidence/decision-record.json'];
  const canonical = documents['tools/permission-data-feasibility/fixtures/canonical-issues.json'];
  if (inventory.artifactManifestSha256 !== manifest.contentSha256 || support.artifactManifestSha256 !== manifest.contentSha256 || ledger.artifactManifestSha256 !== manifest.contentSha256) fail('artifact-manifest identity mismatch');
  if (inventory.permissionSourcesSha256 !== permission.contentSha256 || support.permissionSourcesSha256 !== permission.contentSha256 || ledger.permissionSourcesSha256 !== permission.contentSha256) fail('permission-source identity mismatch');
  if (ledger.inventorySha256 !== inventory.contentSha256 || ledger.supportManifestSha256 !== support.contentSha256) fail('ledger input identity mismatch');
  if (ledger.supportPredicateSha256 !== support.predicate.ruleSha256 || ledger.preliminarySelectionSha256 !== support.selectionSha256) fail('support identity mismatch');
  if (packet.artifactManifest.contentSha256 !== manifest.contentSha256 || packet.canonicalIssues.contentSha256 !== canonical.contentSha256 || packet.inventory.contentSha256 !== inventory.contentSha256) fail('packet source identity mismatch');
  if (packet.support.predicateSha256 !== support.predicate.ruleSha256 || packet.support.preliminarySelectionSha256 !== support.selectionSha256) fail('packet support identity mismatch');
  if (packet.ledger.contentSha256 !== ledger.contentSha256 || !sameJson(packet.ledger.operationCounts, ledger.operationCounts) || !sameJson(packet.ledger.methodCounts, ledger.methodCounts)) fail('packet ledger mismatch');
  if (!sameJson(packet.authorizedScopeCandidate, ledger.authorizedScopeCandidate)) fail('packet scope mismatch');
  if (packet.incompleteSemantics.contentSha256 !== incomplete.contentSha256) fail('packet incomplete-semantics identity mismatch');
  const reasonCodes = incomplete.definitions.map((definition) => definition.code);
  if (!sameJson(packet.incompleteSemantics.reasons, reasonCodes)) fail('packet incomplete-reason mismatch');
  if (!sameJson(packet.legalTerminalOutcomes, ['GO', 'GO WITH BOUNDED SUPPORT', 'NO-GO / RESCOPE'])) fail('packet terminal outcomes mismatch');
  if ('decision' in packet || 'selectedOutcome' in packet || 'terminalDecision' in packet) fail('packet selects a terminal outcome');
  if (
    decision.evidence.feasibilityPacketSha256 !== packet.contentSha256 ||
    decision.evidence.supportManifestSha256 !== support.contentSha256 ||
    decision.evidence.supportPredicateSha256 !== support.predicate.ruleSha256 ||
    decision.evidence.selectionSha256 !== support.selectionSha256
  ) {
    fail('decision evidence identity mismatch');
  }
  if (
    decision.outcome !== 'GO WITH BOUNDED SUPPORT' ||
    decision.authorization.status !== 'authorized-bounded' ||
    decision.authorization.authorizedScopeSha256 !== ledger.authorizedScopeCandidate.authorizedScopeSha256 ||
    !sameJson(decision.authorization.members, ledger.authorizedScopeCandidate.members)
  ) {
    fail('decision authorized scope mismatch');
  }
});

const artifactDigests = Object.keys(JSON_CONTRACTS)
  .sort()
  .map((path) => ({ path, sha256: sha256(readFileSync(resolveFile(path).actual)) }));

const unsignedReport = {
  schemaVersion: 1,
  scope: 'evidence-integrity-only',
  checks,
  artifactDigests,
};
const report = { ...unsignedReport, contentSha256: sha256(canonicalJson(unsignedReport)) };

const args = process.argv.slice(2);
if (args.length > 1 || (args.length === 1 && args[0] !== '--write-report')) fail('usage: quality-checks.mjs [--write-report]');
if (args[0] === '--write-report') {
  const absolute = resolve(PROJECT_ROOT, REPORT_PATH);
  const temporary = `${absolute}.tmp`;
  writeFileSync(temporary, `${JSON.stringify(report, null, 2)}\n`, { encoding: 'utf8', mode: 0o644 });
  renameSync(temporary, absolute);
}

process.stdout.write(`evidence integrity checks passed (${checks.length})\n`);
