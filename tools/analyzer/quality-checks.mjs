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
  { path: 'src/analyzer', extensions: new Set(['.ts']) },
  { path: 'tests/analyzer', extensions: new Set(['.json', '.ts']) },
];
const EXACT_FILES = [
  'docs/analyzer.md',
  'docs/permission-model.md',
  'tools/analyzer/quality-checks.mjs',
];
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

function sourcePosition(sourceFile, node) {
  const point = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
  return `${point.line + 1}:${point.character + 1}`;
}

function lintDiagnostics(path, text) {
  const sourceFile = ts.createSourceFile(path, text, ts.ScriptTarget.ESNext, true, scriptKind(path));
  const diagnostics = sourceFile.parseDiagnostics.map((diagnostic) => {
    const start = diagnostic.start ?? 0;
    const point = sourceFile.getLineAndCharacterOfPosition(start);
    return `${path}:${point.line + 1}:${point.character + 1} lint/syntax: ${ts.flattenDiagnosticMessageText(diagnostic.messageText, ' ')}`;
  });
  if (!path.startsWith('src/analyzer/')) return diagnostics;

  const report = (node, rule, detail) => diagnostics.push(`${path}:${sourcePosition(sourceFile, node)} ${rule}: ${detail}`);
  const visit = (node) => {
    if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier) && FORBIDDEN_MODULES.has(node.moduleSpecifier.text)) {
      report(node, 'analyzer/no-target-runtime-module', `forbidden runtime module ${node.moduleSpecifier.text}`);
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
          report(specifier, 'analyzer/no-target-program', `${importedName} import is forbidden`);
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
      report(node, 'analyzer/no-target-runtime-module', `forbidden runtime module ${node.moduleReference.expression.text}`);
    }
    if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
      const name = memberName(node);
      if (name !== null && FORBIDDEN_TYPESCRIPT_PROGRAM_APIS.has(name)) {
        report(node, 'analyzer/no-target-program', `${name} access is forbidden`);
      }
      if (name === 'createRequire' || name === 'dlopen') {
        report(node, 'analyzer/no-target-module-load', `${name} access is forbidden`);
      }
    }
    if (ts.isCallExpression(node)) {
      if (node.expression.kind === ts.SyntaxKind.ImportKeyword) {
        report(node, 'analyzer/no-target-module-load', 'dynamic import is forbidden');
      } else if (ts.isIdentifier(node.expression) && node.expression.text === 'require') {
        report(node, 'analyzer/no-target-module-load', 'require() is forbidden');
      } else if (ts.isIdentifier(node.expression) && node.expression.text === 'eval') {
        report(node, 'analyzer/no-code-evaluation', 'eval() is forbidden');
      }
    }
    if (ts.isNewExpression(node) && ts.isIdentifier(node.expression)) {
      if (node.expression.text === 'Function') report(node, 'analyzer/no-code-evaluation', 'new Function() is forbidden');
      if (node.expression.text === 'Worker') report(node, 'analyzer/no-target-runtime-module', 'Worker construction is forbidden');
    }
    ts.forEachChild(node, visit);
  };
  visit(sourceFile);
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
  for (const path of ownedFiles()) diagnostics.push(...formatDiagnostics(path, readBounded(path, budget)));
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
    ['require', "require('./target.js');\n", 'analyzer/no-target-module-load'],
    ['dynamic import', "import('./target.js');\n", 'analyzer/no-target-module-load'],
    ['createProgram', "import ts from 'typescript';\nts.createProgram([]);\n", 'analyzer/no-target-program'],
    ['named createProgram import', "import { createProgram as build } from 'typescript';\nbuild([]);\n", 'analyzer/no-target-program'],
    ['transpileModule', "import ts from 'typescript';\nts.transpileModule('x', {});\n", 'analyzer/no-target-program'],
    ['resolveModuleName', "import ts from 'typescript';\nts.resolveModuleName('x', 'y', {}, {});\n", 'analyzer/no-target-program'],
    ['subprocess module', "import { spawn } from 'node:child_process';\nspawn('x');\n", 'analyzer/no-target-runtime-module'],
    ['vm module', "import vm from 'node:vm';\nvm.runInNewContext('x');\n", 'analyzer/no-target-runtime-module'],
    ['worker module', "import { Worker } from 'node:worker_threads';\nnew Worker('x');\n", 'analyzer/no-target-runtime-module'],
    ['import-equals subprocess', "import processApi = require('node:child_process');\nprocessApi.spawn('x');\n", 'analyzer/no-target-runtime-module'],
    ['createRequire', "import module from 'node:module';\nmodule.createRequire(import.meta.url);\n", 'analyzer/no-target-runtime-module'],
    ['eval', "eval('x');\n", 'analyzer/no-code-evaluation'],
    ['Function', "new Function('x');\n", 'analyzer/no-code-evaluation'],
    ['Worker', "new Worker('x');\n", 'analyzer/no-target-runtime-module'],
    ['dlopen', "process.dlopen({}, 'x');\n", 'analyzer/no-target-module-load'],
  ];
  for (const [name, source, rule] of lintMutations) {
    assertSelfTest(lintDiagnostics('src/analyzer/mutation.ts', source).some((diagnostic) => diagnostic.includes(rule)), name);
  }

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
