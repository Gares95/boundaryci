import {
  lstatSync,
  readFileSync,
  readdirSync,
  realpathSync,
} from 'node:fs';
import { extname, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import ts from 'typescript';

const PROJECT_ROOT = realpathSync(fileURLToPath(new URL('../../', import.meta.url)));
const MAX_FILE_BYTES = 8 * 1024 * 1024;
const MAX_TOTAL_BYTES = 64 * 1024 * 1024;
const DIRECTORY_RULES = [
  { path: 'docs', extensions: new Set(['.md']) },
  { path: 'src', extensions: new Set(['.ts']) },
  { path: 'tests', extensions: new Set(['.json', '.ts']) },
];
const EXACT_FILES = ['tools/analyzer/quality-checks.mjs'];
const FORBIDDEN_MODULES = new Set([
  'child_process',
  'module',
  'node:child_process',
  'node:module',
  'node:vm',
  'node:worker_threads',
  'vm',
  'worker_threads',
]);
const FORBIDDEN_TYPESCRIPT_PROGRAM_APIS = new Set([
  'createProgram',
  'resolveModuleName',
  'transpile',
  'transpileModule',
]);
const PHASE4_SOURCE_PREFIXES = ['src/cli/', 'src/config/', 'src/diff/', 'src/policy/', 'src/runtime/'];
const PHASE4_ALLOWED_CATALOG_IMPORT = 'BOUNDARYCI_PERMISSION_CATALOG_IDENTITY';
const PERMISSION_CATALOG_ENTRY_TYPE = 'PermissionCatalogEntry';
const DELIVERY_MODULE = /^(?:@octokit\/|octokit$|probot$)/u;
const DELIVERY_SOURCE_PREFIX = 'src/delivery/';
const DELIVERY_TRANSPORT_OWNERS = new Set(['src/delivery/app.ts', 'src/delivery/index.ts']);
const FORBIDDEN_DELIVERY_API_MEMBERS = new Set([
  'create', 'createCheckRun', 'delete', 'downloadArchive', 'getArchiveLink', 'getContent', 'getContents', 'graphql', 'request', 'update', 'updateCheckRun',
]);
const PLACEHOLDER_WORDS = [`${'FIX'}${'ME'}`, `${'T'}${'BD'}`, `${'TO'}${'DO'}`];
const PLACEHOLDER = new RegExp(`\\b(?:${PLACEHOLDER_WORDS.join('|')})\\b`, 'u');
const ASSISTANT_ATTRIBUTION = /\b(?:Anthropic|Claude|Codex|OpenAI)\b/u;
const LOCAL_WORKFLOW_PATH = /(?:^|[/'"`])\.(?:agents|codex|planning)(?:\/|$)/u;
const SECRET_MATERIAL = /(?:BEGIN (?:EC |OPENSSH |RSA )?PRIVATE KEY|github_pat_|gh[pousr]_|sk-ant-)/u;

function fail(message) {
  throw new Error(message);
}

function compareBytes(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function projectPath(absolutePath) {
  return relative(PROJECT_ROOT, absolutePath).split(sep).join('/');
}

function resolveOwnedPath(path) {
  if (path.startsWith('/') || path.includes('\\') || path.split('/').some((part) => part === '' || part === '.' || part === '..')) {
    fail(`quality/path: non-portable owned path ${path}`);
  }
  const absolutePath = resolve(PROJECT_ROOT, ...path.split('/'));
  const lexical = relative(PROJECT_ROOT, absolutePath);
  if (lexical === '..' || lexical.startsWith(`..${sep}`)) fail(`quality/path: owned path escapes project ${path}`);
  const stats = lstatSync(absolutePath);
  if (stats.isSymbolicLink()) fail(`quality/symlink: owned path is a symbolic link ${path}`);
  const physical = realpathSync(absolutePath);
  const physicalRelative = relative(PROJECT_ROOT, physical);
  if (physicalRelative === '..' || physicalRelative.startsWith(`..${sep}`)) {
    fail(`quality/path: owned path resolves outside project ${path}`);
  }
  return { absolutePath: physical, stats };
}

function collectDirectory(path, extensions, output) {
  const root = resolveOwnedPath(path);
  if (!root.stats.isDirectory()) fail(`quality/path: owned directory is not a directory ${path}`);
  const visit = (directory) => {
    const entries = readdirSync(directory, { withFileTypes: true }).sort((left, right) => compareBytes(left.name, right.name));
    for (const entry of entries) {
      const absolutePath = resolve(directory, entry.name);
      const relativePath = projectPath(absolutePath);
      const stats = lstatSync(absolutePath);
      if (stats.isSymbolicLink()) fail(`quality/symlink: owned tree contains a symbolic link ${relativePath}`);
      if (stats.isDirectory()) {
        visit(absolutePath);
        continue;
      }
      if (!stats.isFile()) fail(`quality/file-type: owned tree contains a non-regular entry ${relativePath}`);
      if (extensions.has(extname(entry.name))) output.push(relativePath);
    }
  };
  visit(root.absolutePath);
}

function ownedFiles() {
  const files = [];
  for (const rule of DIRECTORY_RULES) collectDirectory(rule.path, rule.extensions, files);
  for (const path of EXACT_FILES) {
    const resolved = resolveOwnedPath(path);
    if (!resolved.stats.isFile()) fail(`quality/file-type: owned path is not a regular file ${path}`);
    files.push(path);
  }
  const sorted = [...new Set(files)].sort(compareBytes);
  if (sorted.length !== files.length) fail('quality/inventory: owned file inventory contains duplicates');
  return sorted;
}

function readBounded(path, budget) {
  const resolved = resolveOwnedPath(path);
  if (!resolved.stats.isFile() || resolved.stats.size > MAX_FILE_BYTES) {
    fail(`quality/file-size: invalid bounded regular file ${path}`);
  }
  budget.total += resolved.stats.size;
  if (budget.total > MAX_TOTAL_BYTES) fail('quality/total-size: owned file inventory exceeds byte budget');
  const bytes = readFileSync(resolved.absolutePath);
  if (bytes.byteLength !== resolved.stats.size) fail(`quality/file-change: file changed while reading ${path}`);
  return bytes;
}

function decodeUtf8(bytes, path) {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return { diagnostic: `${path}:1:1 format/utf8: file is not valid UTF-8` };
  }
}

function formatDiagnostics(path, bytes) {
  const decoded = decodeUtf8(bytes, path);
  if (typeof decoded !== 'string') return [decoded.diagnostic];
  const diagnostics = [];
  if (decoded.includes('\r')) diagnostics.push(`${path}:1:1 format/line-ending: only LF line endings are allowed`);
  if (!decoded.endsWith('\n')) diagnostics.push(`${path}:1:1 format/final-newline: file must end with one LF`);
  else if (decoded.endsWith('\n\n')) diagnostics.push(`${path}:1:1 format/final-newline: file must end with exactly one LF`);
  const lines = decoded.split('\n');
  for (let index = 0; index < lines.length - 1; index += 1) {
    const line = lines[index] ?? '';
    if (/[ \t]+$/u.test(line)) diagnostics.push(`${path}:${index + 1}:1 format/trailing-space: trailing horizontal whitespace`);
    if (/^\t+/u.test(line)) diagnostics.push(`${path}:${index + 1}:1 format/tab-indent: tab indentation is not allowed`);
  }
  if (extname(path) === '.json') {
    try {
      const parsed = JSON.parse(decoded);
      if (`${JSON.stringify(parsed, null, 2)}\n` !== decoded) {
        diagnostics.push(`${path}:1:1 format/json: JSON must use deterministic two-space formatting`);
      }
    } catch {
      diagnostics.push(`${path}:1:1 format/json: JSON is malformed`);
    }
  }
  return diagnostics;
}

function scriptKind(path) {
  const extension = extname(path);
  if (extension === '.js' || extension === '.mjs') return ts.ScriptKind.JS;
  if (extension === '.jsx') return ts.ScriptKind.JSX;
  if (extension === '.tsx') return ts.ScriptKind.TSX;
  return ts.ScriptKind.TS;
}

function memberName(expression) {
  if (ts.isPropertyAccessExpression(expression)) return expression.name.text;
  if (ts.isElementAccessExpression(expression) && expression.argumentExpression !== undefined && ts.isStringLiteralLike(expression.argumentExpression)) {
    return expression.argumentExpression.text;
  }
  return null;
}

function rootReceiverName(expression) {
  let current = expression;
  while (ts.isPropertyAccessExpression(current) || ts.isElementAccessExpression(current)) current = current.expression;
  return ts.isIdentifier(current) ? current.text : null;
}

function resemblesGitHubReceiver(expression) {
  if (!ts.isPropertyAccessExpression(expression) && !ts.isElementAccessExpression(expression)) return false;
  const root = rootReceiverName(expression.expression);
  return root !== null && /(?:client|context|github|octokit)/iu.test(root);
}

function sourcePosition(sourceFile, node) {
  const point = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
  return `${point.line + 1}:${point.character + 1}`;
}

function objectPropertyNames(objectLiteral) {
  const names = new Set();
  for (const property of objectLiteral.properties) {
    if (
      (ts.isPropertyAssignment(property) || ts.isShorthandPropertyAssignment(property) || ts.isMethodDeclaration(property)) &&
      (ts.isIdentifier(property.name) || ts.isStringLiteralLike(property.name))
    ) {
      names.add(property.name.text);
    }
  }
  return names;
}

function resemblesPermissionCatalogEntry(objectLiteral) {
  const names = objectPropertyNames(objectLiteral);
  return names.has('status') && names.has('operation') && names.has('provenance') && (names.has('requirement') || names.has('reason'));
}

function lintDiagnostics(path, text) {
  const sourceFile = ts.createSourceFile(path, text, ts.ScriptTarget.ESNext, true, scriptKind(path));
  const diagnostics = sourceFile.parseDiagnostics.map((diagnostic) => {
    const start = diagnostic.start ?? 0;
    const point = sourceFile.getLineAndCharacterOfPosition(start);
    return `${path}:${point.line + 1}:${point.character + 1} lint/syntax: ${ts.flattenDiagnosticMessageText(diagnostic.messageText, ' ')}`;
  });
  const sourceCode = path.startsWith('src/');
  const phase4Source = PHASE4_SOURCE_PREFIXES.some((prefix) => path.startsWith(prefix));
  const deliverySource = path.startsWith(DELIVERY_SOURCE_PREFIX);
  if (!sourceCode) return diagnostics;

  const report = (node, rule, detail) => diagnostics.push(`${path}:${sourcePosition(sourceFile, node)} ${rule}: ${detail}`);
  const visit = (node) => {
    if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier) && FORBIDDEN_MODULES.has(node.moduleSpecifier.text)) {
      report(node, 'isolation/no-target-runtime-module', `forbidden runtime module ${node.moduleSpecifier.text}`);
    }
    if (
      phase4Source &&
      ts.isImportDeclaration(node) &&
      ts.isStringLiteral(node.moduleSpecifier) &&
      DELIVERY_MODULE.test(node.moduleSpecifier.text)
    ) {
      report(node, 'phase4/no-delivery-module', `delivery module is outside Phase 4: ${node.moduleSpecifier.text}`);
    }
    if (
      ts.isImportDeclaration(node) &&
      ts.isStringLiteral(node.moduleSpecifier) &&
      DELIVERY_MODULE.test(node.moduleSpecifier.text) &&
      !DELIVERY_TRANSPORT_OWNERS.has(path)
    ) {
      report(node, 'delivery/sdk-import-owner', `delivery SDK import is limited to transport/auth owners: ${node.moduleSpecifier.text}`);
    }
    if (
      !deliverySource &&
      ts.isImportDeclaration(node) &&
      ts.isStringLiteral(node.moduleSpecifier) &&
      /(?:^|\/)delivery(?:\/|$)/u.test(node.moduleSpecifier.text)
    ) {
      report(node, 'delivery/no-lower-layer-import', `lower product layer cannot import delivery: ${node.moduleSpecifier.text}`);
    }
    if (phase4Source && ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) {
      const bindings = node.importClause?.namedBindings;
      if (node.moduleSpecifier.text.endsWith('/permission-model/bounded-catalog.js')) {
        if (bindings === undefined || ts.isNamespaceImport(bindings)) {
          report(node, 'phase4/no-catalog-source', 'Phase 4 may import only the frozen catalog identity');
        } else {
          for (const specifier of bindings.elements) {
            const importedName = specifier.propertyName?.text ?? specifier.name.text;
            if (importedName !== PHASE4_ALLOWED_CATALOG_IMPORT) {
              report(specifier, 'phase4/no-catalog-source', `catalog import is outside the Phase 4 boundary: ${importedName}`);
            }
          }
        }
      }
      if (bindings !== undefined && ts.isNamedImports(bindings)) {
        for (const specifier of bindings.elements) {
          const importedName = specifier.propertyName?.text ?? specifier.name.text;
          if (importedName === PERMISSION_CATALOG_ENTRY_TYPE) {
            report(specifier, 'phase4/no-catalog-source', 'Phase 4 must not define permission catalog entries');
          }
        }
      }
    }
    if (phase4Source && ts.isObjectLiteralExpression(node) && resemblesPermissionCatalogEntry(node)) {
      report(node, 'phase4/no-catalog-source', 'catalog entry definitions belong only in the frozen bounded catalog');
    }
    if (
      ts.isImportDeclaration(node) &&
      ts.isStringLiteral(node.moduleSpecifier) &&
      node.moduleSpecifier.text === 'typescript' &&
      node.importClause !== undefined &&
      !node.importClause.isTypeOnly &&
      node.importClause.namedBindings !== undefined &&
      ts.isNamedImports(node.importClause.namedBindings)
    ) {
      for (const specifier of node.importClause.namedBindings.elements) {
        const importedName = specifier.propertyName?.text ?? specifier.name.text;
        if (!specifier.isTypeOnly && FORBIDDEN_TYPESCRIPT_PROGRAM_APIS.has(importedName)) {
          report(specifier, 'isolation/no-target-program', `${importedName} import is forbidden`);
        }
      }
    }
    if (
      ts.isImportEqualsDeclaration(node) &&
      ts.isExternalModuleReference(node.moduleReference) &&
      node.moduleReference.expression !== undefined &&
      ts.isStringLiteral(node.moduleReference.expression) &&
      FORBIDDEN_MODULES.has(node.moduleReference.expression.text)
    ) {
      report(node, 'isolation/no-target-runtime-module', `forbidden runtime module ${node.moduleReference.expression.text}`);
    }
    if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
      const name = memberName(node);
      if (name !== null && FORBIDDEN_TYPESCRIPT_PROGRAM_APIS.has(name)) {
        report(node, 'isolation/no-target-program', `${name} access is forbidden`);
      }
      if (name === 'createRequire' || name === 'dlopen') {
        report(node, 'isolation/no-target-module-load', `${name} access is forbidden`);
      }
    }
    if (ts.isCallExpression(node)) {
      const member = memberName(node.expression);
      if (deliverySource && member !== null && FORBIDDEN_DELIVERY_API_MEMBERS.has(member) && resemblesGitHubReceiver(node.expression)) {
        report(node, 'delivery/no-unsupported-github-api', `delivery cannot call ${member}()`);
      }
      if (node.expression.kind === ts.SyntaxKind.ImportKeyword) {
        report(node, 'isolation/no-target-module-load', 'dynamic import is forbidden');
      } else if (ts.isIdentifier(node.expression) && node.expression.text === 'require') {
        report(node, 'isolation/no-target-module-load', 'require() is forbidden');
      } else if (ts.isIdentifier(node.expression) && node.expression.text === 'eval') {
        report(node, 'isolation/no-code-evaluation', 'eval() is forbidden');
      }
    }
    if (ts.isNewExpression(node) && ts.isIdentifier(node.expression)) {
      if (node.expression.text === 'Function') report(node, 'isolation/no-code-evaluation', 'new Function() is forbidden');
      if (node.expression.text === 'Worker') report(node, 'isolation/no-target-runtime-module', 'Worker construction is forbidden');
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
  return diagnostics;
}

function publicTextDiagnostics(path, text) {
  if (!path.startsWith('docs/') && !path.startsWith('src/') && !path.startsWith('tests/')) return [];
  const diagnostics = [];
  if (PLACEHOLDER.test(text)) diagnostics.push(`${path}:1:1 hygiene/placeholder: resolvable placeholder token is forbidden`);
  if (ASSISTANT_ATTRIBUTION.test(text)) diagnostics.push(`${path}:1:1 hygiene/assistant-attribution: assistant attribution is forbidden`);
  if (LOCAL_WORKFLOW_PATH.test(text)) diagnostics.push(`${path}:1:1 hygiene/local-workflow: local workflow path is forbidden`);
  const inertTestKeyMarker = path.startsWith('tests/') && /-----BEGIN PRIVATE KEY-----\\nunused\\n-----END PRIVATE KEY-----/u.test(text);
  const secretMaterial = SECRET_MATERIAL.test(text) && !inertTestKeyMarker;
  if (secretMaterial) diagnostics.push(`${path}:1:1 hygiene/secret-material: possible secret material is forbidden`);
  return diagnostics;
}

function runLint() {
  const budget = { total: 0 };
  const diagnostics = [];
  for (const path of ownedFiles()) {
    if (!/\.(?:js|jsx|mjs|mts|ts|tsx)$/u.test(path)) continue;
    const bytes = readBounded(path, budget);
    const decoded = decodeUtf8(bytes, path);
    if (typeof decoded !== 'string') diagnostics.push(decoded.diagnostic);
    else diagnostics.push(...lintDiagnostics(path, decoded));
  }
  return diagnostics.sort(compareBytes);
}

function runFormatCheck() {
  const budget = { total: 0 };
  const diagnostics = [];
  for (const path of ownedFiles()) {
    const bytes = readBounded(path, budget);
    diagnostics.push(...formatDiagnostics(path, bytes));
    const decoded = decodeUtf8(bytes, path);
    if (typeof decoded === 'string') diagnostics.push(...publicTextDiagnostics(path, decoded));
  }
  return diagnostics.sort(compareBytes);
}

function assertSelfTest(condition, label) {
  if (!condition) fail(`self-test failed: ${label}`);
}

function runSelfTest() {
  assertSelfTest(lintDiagnostics('src/analyzer/valid.ts', "import ts from 'typescript';\nts.createSourceFile('x.ts', '', ts.ScriptTarget.ESNext);\n").length === 0, 'valid TypeScript');
  assertSelfTest(lintDiagnostics('src/analyzer/valid.js', 'export const value = 1;\n').length === 0, 'valid JavaScript');

  const lintMutations = [
    ['syntax', 'const = ;\n', 'lint/syntax'],
    ['require', "require('./target.js');\n", 'isolation/no-target-module-load'],
    ['dynamic import', "import('./target.js');\n", 'isolation/no-target-module-load'],
    ['createProgram', "import ts from 'typescript';\nts.createProgram([]);\n", 'isolation/no-target-program'],
    ['named createProgram import', "import { createProgram as build } from 'typescript';\nbuild([]);\n", 'isolation/no-target-program'],
    ['transpileModule', "import ts from 'typescript';\nts.transpileModule('x', {});\n", 'isolation/no-target-program'],
    ['resolveModuleName', "import ts from 'typescript';\nts.resolveModuleName('x', 'y', {}, {});\n", 'isolation/no-target-program'],
    ['subprocess module', "import { spawn } from 'node:child_process';\nspawn('x');\n", 'isolation/no-target-runtime-module'],
    ['vm module', "import vm from 'node:vm';\nvm.runInNewContext('x');\n", 'isolation/no-target-runtime-module'],
    ['worker module', "import { Worker } from 'node:worker_threads';\nnew Worker('x');\n", 'isolation/no-target-runtime-module'],
    ['import-equals subprocess', "import processApi = require('node:child_process');\nprocessApi.spawn('x');\n", 'isolation/no-target-runtime-module'],
    ['createRequire', "import module from 'node:module';\nmodule.createRequire(import.meta.url);\n", 'isolation/no-target-runtime-module'],
    ['eval', "eval('x');\n", 'isolation/no-code-evaluation'],
    ['Function', "new Function('x');\n", 'isolation/no-code-evaluation'],
    ['Worker', "new Worker('x');\n", 'isolation/no-target-runtime-module'],
    ['dlopen', "process.dlopen({}, 'x');\n", 'isolation/no-target-module-load'],
  ];
  for (const [name, source, rule] of lintMutations) {
    assertSelfTest(lintDiagnostics('src/analyzer/mutation.ts', source).some((diagnostic) => diagnostic.includes(rule)), name);
  }
  assertSelfTest(
    lintDiagnostics('src/runtime/mutation.ts', "import { spawn } from 'node:child_process';\nspawn('x');\n").some((diagnostic) =>
      diagnostic.includes('isolation/no-target-runtime-module'),
    ),
    'Phase 4 subprocess module',
  );
  assertSelfTest(
    lintDiagnostics('src/runtime/mutation.ts', "import { createBoundaryCiApp } from '../delivery/app.js';\nvoid createBoundaryCiApp;\n").some((diagnostic) =>
      diagnostic.includes('delivery/no-lower-layer-import'),
    ),
    'lower layer delivery import',
  );
  assertSelfTest(
    lintDiagnostics('src/delivery/mutation.ts', "import { Octokit } from 'octokit';\nvoid Octokit;\n").some((diagnostic) =>
      diagnostic.includes('delivery/sdk-import-owner'),
    ),
    'delivery SDK import owner',
  );
  assertSelfTest(
    lintDiagnostics('src/delivery/mutation.ts', 'client.request({});\n').some((diagnostic) =>
      diagnostic.includes('delivery/no-unsupported-github-api'),
    ),
    'delivery generic request',
  );
  assertSelfTest(
    lintDiagnostics('src/cli/mutation.ts', "import { Probot } from 'probot';\nvoid Probot;\n").some((diagnostic) =>
      diagnostic.includes('phase4/no-delivery-module'),
    ),
    'Phase 4 delivery module',
  );
  assertSelfTest(
    lintDiagnostics(
      'src/runtime/mutation.ts',
      "import { BOUNDARYCI_PERMISSION_CATALOG } from '../permission-model/bounded-catalog.js';\nvoid BOUNDARYCI_PERMISSION_CATALOG;\n",
    ).some((diagnostic) => diagnostic.includes('phase4/no-catalog-source')),
    'Phase 4 production catalog import',
  );
  assertSelfTest(
    lintDiagnostics(
      'src/runtime/mutation.ts',
      "const additionalCatalogRow = { status: 'resolved', operation: {}, requirement: {}, provenance: {} };\nvoid additionalCatalogRow;\n",
    ).some((diagnostic) => diagnostic.includes('phase4/no-catalog-source')),
    'Phase 4 catalog entry definition',
  );

  const encoder = new TextEncoder();
  assertSelfTest(formatDiagnostics('valid.ts', encoder.encode('export const value = 1;\n')).length === 0, 'valid text');
  assertSelfTest(formatDiagnostics('valid.json', encoder.encode('{\n  "value": 1\n}\n')).length === 0, 'valid JSON');
  const formatMutations = [
    ['invalid UTF-8', 'invalid.ts', Uint8Array.from([0xff]), 'format/utf8'],
    ['CRLF', 'invalid.ts', encoder.encode('const x = 1;\r\n'), 'format/line-ending'],
    ['missing final newline', 'invalid.ts', encoder.encode('const x = 1;'), 'format/final-newline'],
    ['trailing whitespace', 'invalid.ts', encoder.encode('const x = 1; \n'), 'format/trailing-space'],
    ['tab indentation', 'invalid.ts', encoder.encode('\tconst x = 1;\n'), 'format/tab-indent'],
    ['noncanonical JSON', 'invalid.json', encoder.encode('{"value":1}\n'), 'format/json'],
  ];
  for (const [name, path, bytes, rule] of formatMutations) {
    assertSelfTest(formatDiagnostics(path, bytes).some((diagnostic) => diagnostic.includes(rule)), name);
  }
  assertSelfTest(
    publicTextDiagnostics('tests/delivery/fixture.ts', "const inert = '-----BEGIN PRIVATE KEY-----\\nunused\\n-----END PRIVATE KEY-----';\n").length === 0,
    'inert delivery test key marker',
  );
  assertSelfTest(
    publicTextDiagnostics('src/delivery/unsafe.ts', '-----BEGIN PRIVATE KEY-----\n').some((diagnostic) => diagnostic.includes('hygiene/secret-material')),
    'delivery private key material',
  );
}

function printDiagnostics(diagnostics) {
  for (const diagnostic of diagnostics) console.error(diagnostic);
  if (diagnostics.length > 0) process.exitCode = 1;
}

const mode = process.argv[2];
if (process.argv.length !== 3 || !['format-check', 'lint', 'self-test'].includes(mode)) {
  console.error('usage: node tools/analyzer/quality-checks.mjs <lint|format-check|self-test>');
  process.exitCode = 2;
} else {
  try {
    if (mode === 'self-test') runSelfTest();
    else if (mode === 'lint') printDiagnostics(runLint());
    else printDiagnostics(runFormatCheck());
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
