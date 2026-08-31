#!/usr/bin/env node

/**
 * Injectable CLI adapter for the `analyze`, `diff`, and `check` commands.
 *
 * Every permission, comparison, and policy decision lives in `../runtime/evaluate.js`, and every
 * normalization/rendering decision lives in `./render.js`; this module only parses argv,
 * dispatches to exactly one runtime call, normalizes and renders its result, separates stdout
 * from stderr, and returns a numeric exit code (D-17, D-18). It never calls `process.exit`, so a
 * caller stays in control of process lifecycle.
 */

import { pathToFileURL } from 'node:url';

import { analyzeConfiguredSnapshot, evaluateLocalComparison } from '../runtime/evaluate.js';
import {
  CLI_RESULT_SCHEMA_ID,
  CLI_RESULT_SCHEMA_VERSION,
  normalizeAnalyzeResult,
  normalizeComparisonResult,
  renderHuman,
  renderJson,
} from './render.js';
import type { CliResult } from './render.js';

export interface CliWritable {
  write(chunk: string): void;
}

export interface CliIO {
  stdout: CliWritable;
  stderr: CliWritable;
}

/** Compatibility alias for the shared renderer result-envelope schema identity. */
export const CHECK_RESULT_SCHEMA_ID = CLI_RESULT_SCHEMA_ID;

/** Compatibility alias for the shared renderer result-envelope schema version. */
export const CHECK_RESULT_SCHEMA_VERSION = CLI_RESULT_SCHEMA_VERSION;

export const EXIT_CODE_OK = 0;
export const EXIT_CODE_POLICY_FAILURE = 1;
export const EXIT_CODE_INCOMPLETE = 2;
export const EXIT_CODE_INPUT_CONFIGURATION_FAILURE = 3;
export const EXIT_CODE_RUNTIME_INFRASTRUCTURE_FAILURE = 4;

type OutputFormat = 'human' | 'json';

interface AnalyzeCommand {
  kind: 'analyze';
  path: string;
  format: OutputFormat;
}

interface ComparisonCommand {
  kind: 'diff' | 'check';
  base: string;
  head: string;
  format: OutputFormat;
}

type CliCommand = AnalyzeCommand | ComparisonCommand;

type ParsedCommand = { status: 'valid'; command: CliCommand } | { status: 'invalid'; detail: string };

type CollectedFlags =
  | { status: 'valid'; flags: Map<string, string>; positionals: string[] }
  | { status: 'invalid'; detail: string };

function collectFlags(rest: readonly string[], recognized: readonly string[]): CollectedFlags {
  const flags = new Map<string, string>();
  const positionals: string[] = [];
  let index = 0;
  while (index < rest.length) {
    const token = rest[index];
    if (token === undefined) throw new Error('unreachable argv index');
    if (token.startsWith('--')) {
      if (!recognized.includes(token)) return { status: 'invalid', detail: `unknown option ${token}` };
      if (flags.has(token)) return { status: 'invalid', detail: `duplicate flag ${token}` };
      const value = rest[index + 1];
      if (value === undefined) return { status: 'invalid', detail: `flag ${token} requires a value` };
      flags.set(token, value);
      index += 2;
    } else {
      positionals.push(token);
      index += 1;
    }
  }
  return { status: 'valid', flags, positionals };
}

type ResolvedFormat = { status: 'valid'; format: OutputFormat } | { status: 'invalid'; detail: string };

function resolveFormat(value: string | null): ResolvedFormat {
  if (value === null) return { status: 'valid', format: 'human' };
  if (value === 'human' || value === 'json') return { status: 'valid', format: value };
  return { status: 'invalid', detail: `unsupported --format value ${JSON.stringify(value)}` };
}

function parseAnalyzeArgs(rest: readonly string[]): ParsedCommand {
  const collected = collectFlags(rest, ['--format']);
  if (collected.status === 'invalid') return collected;
  const { flags, positionals } = collected;
  if (positionals.length === 0) return { status: 'invalid', detail: 'missing required argument <path>' };
  if (positionals.length > 1) return { status: 'invalid', detail: 'duplicate positional argument <path>' };
  const resolvedFormat = resolveFormat(flags.get('--format') ?? null);
  if (resolvedFormat.status === 'invalid') return resolvedFormat;
  return {
    status: 'valid',
    command: { kind: 'analyze', path: positionals[0] as string, format: resolvedFormat.format },
  };
}

function parseComparisonArgs(kind: 'diff' | 'check', rest: readonly string[]): ParsedCommand {
  const collected = collectFlags(rest, ['--base', '--head', '--format']);
  if (collected.status === 'invalid') return collected;
  const { flags, positionals } = collected;
  if (positionals.length > 0) return { status: 'invalid', detail: `unexpected argument ${positionals[0]}` };
  const base = flags.get('--base');
  const head = flags.get('--head');
  if (base === undefined) return { status: 'invalid', detail: 'missing required flag --base' };
  if (head === undefined) return { status: 'invalid', detail: 'missing required flag --head' };
  const resolvedFormat = resolveFormat(flags.get('--format') ?? null);
  if (resolvedFormat.status === 'invalid') return resolvedFormat;
  return { status: 'valid', command: { kind, base, head, format: resolvedFormat.format } };
}

function parseArgs(argv: readonly string[]): ParsedCommand {
  const [commandName, ...rest] = argv;
  if (commandName === 'analyze') return parseAnalyzeArgs(rest);
  if (commandName === 'diff' || commandName === 'check') return parseComparisonArgs(commandName, rest);
  return { status: 'invalid', detail: `unknown command ${JSON.stringify(commandName ?? '')}` };
}

function exitCodeFor(result: CliResult): number {
  if (result.outcome === 'complete') return EXIT_CODE_OK;
  if (result.outcome === 'input-configuration-failure') return EXIT_CODE_INPUT_CONFIGURATION_FAILURE;
  if (result.outcome === 'runtime-infrastructure-failure') return EXIT_CODE_RUNTIME_INFRASTRUCTURE_FAILURE;
  if (result.outcome === 'incomplete') return result.command === 'check' ? EXIT_CODE_OK : EXIT_CODE_INCOMPLETE;
  if (result.command !== 'check' || result.evaluation.status !== 'selected') {
    throw new Error('unreachable policy-failure outcome');
  }
  return result.evaluation.policy.reasons.includes('incomplete-analysis-not-permitted')
    ? EXIT_CODE_INCOMPLETE
    : EXIT_CODE_POLICY_FAILURE;
}

/**
 * Runs `analyze`, `diff`, or `check` against injected argv/stdout/stderr and returns its exit code.
 *
 * On a semantic result, exactly one document is written to `io.stdout` and nothing is written to
 * `io.stderr`. On a usage or unexpected runtime error, nothing is written to `io.stdout` and one
 * diagnostic line is written to `io.stderr`.
 */
export async function runCli(argv: readonly string[], io: CliIO): Promise<number> {
  const parsed = parseArgs(argv);
  if (parsed.status === 'invalid') {
    io.stderr.write(`boundaryci: ${parsed.detail}\n`);
    return EXIT_CODE_INPUT_CONFIGURATION_FAILURE;
  }

  try {
    const { command } = parsed;
    const normalized =
      command.kind === 'analyze'
        ? normalizeAnalyzeResult(await analyzeConfiguredSnapshot(command.path))
        : normalizeComparisonResult(command.kind, await evaluateLocalComparison(command.base, command.head));
    io.stdout.write(command.format === 'json' ? renderJson(normalized) : renderHuman(normalized));
    return exitCodeFor(normalized);
  } catch {
    io.stderr.write('boundaryci: unexpected runtime failure\n');
    return EXIT_CODE_RUNTIME_INFRASTRUCTURE_FAILURE;
  }
}

const invokedPath = process.argv[1];
if (invokedPath !== undefined && import.meta.url === pathToFileURL(invokedPath).href) {
  process.exitCode = await runCli(process.argv.slice(2), { stdout: process.stdout, stderr: process.stderr });
}
