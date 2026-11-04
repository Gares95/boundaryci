import { lstatSync, readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

import { OWNER_POLICIES, probeVersion, runTool, verifyTool } from './capsule.mjs';
import { fail, ToolchainError } from './errors.mjs';
import { MAX_MANIFEST_BYTES, parseManifest } from './manifest.mjs';
import { driftReport, materializeTool, qualifyTools, readRequestFile } from './qualify.mjs';

const SHA256 = /^[a-f0-9]{64}$/u;
const USAGE = [
  'usage: node tools/toolchain/cli.mjs verify --manifest FILE --store DIR [--tool ID]... [--probe] [--manifest-sha256 HEX] [--owner-policy self-or-root|root-only]',
  '       node tools/toolchain/cli.mjs run --manifest FILE --store DIR --tool ID [--manifest-sha256 HEX] [--owner-policy ...] -- ARGS...',
  '       node tools/toolchain/cli.mjs materialize --manifest FILE --store DIR --tool ID [--manifest-sha256 HEX] [--owner-policy ...]',
  '       node tools/toolchain/cli.mjs qualify --manifest FILE --request FILE... [--replace-manifest-sha256 HEX]',
  '       node tools/toolchain/cli.mjs drift --manifest FILE [--store DIR] [--manifest-sha256 HEX]',
].join('\n');

const OPTIONS = Object.freeze({
  verify: { single: ['--manifest', '--store', '--manifest-sha256', '--owner-policy'], repeated: ['--tool'], flags: ['--probe'], required: ['--manifest', '--store'] },
  run: { single: ['--manifest', '--store', '--tool', '--manifest-sha256', '--owner-policy'], repeated: [], flags: [], required: ['--manifest', '--store', '--tool'] },
  materialize: { single: ['--manifest', '--store', '--tool', '--manifest-sha256', '--owner-policy'], repeated: [], flags: [], required: ['--manifest', '--store', '--tool'] },
  qualify: { single: ['--manifest', '--replace-manifest-sha256'], repeated: ['--request'], flags: [], required: ['--manifest', '--request'] },
  drift: { single: ['--manifest', '--store', '--manifest-sha256'], repeated: [], flags: [], required: ['--manifest'] },
});

/**
 * @param {readonly string[]} argv
 */
export function parseCommandLine(argv) {
  const command = argv[0];
  if (command === undefined || !Object.hasOwn(OPTIONS, command)) fail('toolchain/usage');
  const spec = OPTIONS[/** @type {keyof typeof OPTIONS} */ (command)];
  /** @type {Map<string, string[]>} */
  const values = new Map();
  const flags = new Set();
  /** @type {string[]} */
  let rest = [];
  for (let index = 1; index < argv.length; index += 1) {
    const name = /** @type {string} */ (argv[index]);
    if (name === '--' && command === 'run') {
      rest = argv.slice(index + 1);
      break;
    }
    if (spec.flags.includes(name)) {
      if (flags.has(name)) fail('toolchain/usage', `${name} repeated`);
      flags.add(name);
      continue;
    }
    const value = argv[index + 1];
    if (!spec.single.includes(name) && !spec.repeated.includes(name)) fail('toolchain/usage', `unknown option ${name}`);
    if (value === undefined || value.startsWith('--')) fail('toolchain/usage', `${name} needs a value`);
    if (spec.single.includes(name) && values.has(name)) fail('toolchain/usage', `${name} repeated`);
    values.set(name, [...(values.get(name) ?? []), value]);
    index += 1;
  }
  for (const name of spec.required) if (!values.has(name)) fail('toolchain/usage', `${name} is required`);
  for (const name of ['--manifest-sha256', '--replace-manifest-sha256']) {
    const value = values.get(name)?.[0];
    if (value !== undefined && !SHA256.test(value)) fail('toolchain/usage', `${name} must be 64 lowercase hex characters`);
  }
  const policy = values.get('--owner-policy')?.[0];
  if (policy !== undefined && !OWNER_POLICIES.includes(policy)) fail('toolchain/usage', 'unknown owner policy');
  return Object.freeze({ command, values, flags, rest });
}

/**
 * @param {string} path
 * @param {string | undefined} expectedSha256
 */
function loadManifest(path, expectedSha256) {
  const stats = lstatSync(path, { throwIfNoEntry: false });
  if (stats === undefined || !stats.isFile() || stats.size > MAX_MANIFEST_BYTES) fail('toolchain/manifest-read', 'manifest is not a bounded regular file');
  return parseManifest(readFileSync(path), { expectedSha256 });
}

/**
 * Executes one CLI command. Returns the process exit status and the bytes to write.
 *
 * @param {readonly string[]} argv
 * @returns { { status: number, stdout: Buffer | string, stderr: Buffer | string } }
 */
export function runCommand(argv) {
  try {
    const { command, values, flags, rest } = parseCommandLine(argv);
    const one = (/** @type {string} */ name) => values.get(name)?.[0];
    if (command === 'qualify') {
      const result = qualifyTools({
        manifestPath: /** @type {string} */ (one('--manifest')),
        requests: (values.get('--request') ?? []).map(readRequestFile),
        replaceManifestSha256: one('--replace-manifest-sha256'),
      });
      return { status: 0, stdout: `${JSON.stringify(result, null, 2)}\ntoolchain:pass:qualify:review-required\n`, stderr: '' };
    }
    const { manifest, manifestSha256 } = loadManifest(/** @type {string} */ (one('--manifest')), one('--manifest-sha256'));
    const storeRoot = one('--store');
    const ownerPolicy = one('--owner-policy') ?? 'self-or-root';
    if (command === 'drift') {
      return { status: 0, stdout: `${JSON.stringify({ manifestSha256, tools: driftReport({ manifest, storeRoot, ownerPolicy }) }, null, 2)}\n`, stderr: '' };
    }
    const base = { manifest, storeRoot: /** @type {string} */ (storeRoot), ownerPolicy };
    if (command === 'verify') {
      const ids = values.get('--tool') ?? manifest.tools.map((tool) => tool.id);
      const lines = [];
      for (const toolId of ids) {
        if (flags.has('--probe')) probeVersion({ ...base, toolId, args: [] });
        const chain = verifyTool({ ...base, toolId });
        const target = chain[chain.length - 1];
        lines.push(`${toolId} ${target?.tool.treeSha256 ?? ''}`);
      }
      return { status: 0, stdout: `${lines.join('\n')}\ntoolchain:pass:verify:${manifestSha256}\n`, stderr: '' };
    }
    if (command === 'materialize') {
      const result = materializeTool({ ...base, toolId: /** @type {string} */ (one('--tool')) });
      return { status: 0, stdout: `toolchain:pass:materialize:${result.status}\n`, stderr: '' };
    }
    const result = runTool({ ...base, toolId: /** @type {string} */ (one('--tool')), args: rest, env: {} });
    return { status: result.status ?? 1, stdout: result.stdout, stderr: result.stderr };
  } catch (error) {
    if (error instanceof ToolchainError) {
      return { status: error.code === 'toolchain/usage' ? 2 : 1, stdout: '', stderr: `${error.message}\n${error.code === 'toolchain/usage' ? `${USAGE}\n` : ''}` };
    }
    return { status: 1, stdout: '', stderr: 'toolchain/internal\n' };
  }
}

const invokedPath = process.argv[1];
if (invokedPath !== undefined && import.meta.url === pathToFileURL(invokedPath).href) {
  const result = runCommand(process.argv.slice(2));
  process.stdout.write(result.stdout);
  process.stderr.write(result.stderr);
  process.exitCode = result.status;
}
