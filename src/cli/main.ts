/**
 * Injectable CLI adapter for the single `check --base <dir> --head <dir> --format json` tracer.
 *
 * Every permission, comparison, and policy decision lives in `../runtime/evaluate.js`; this
 * module only parses argv, serializes the resulting versioned envelope, separates stdout from
 * stderr, and returns a numeric exit code (D-17, D-18). It never calls `process.exit`, so a
 * caller stays in control of process lifecycle.
 */

import { BUILTIN_CONFIG } from '../config/model.js';
import { evaluateLocalComparison } from '../runtime/evaluate.js';
import type { LocalComparisonOutcome } from '../runtime/evaluate.js';

export interface CliWritable {
  write(chunk: string): void;
}

export interface CliIO {
  stdout: CliWritable;
  stderr: CliWritable;
}

/** Identity of the CLI result envelope itself. */
export const CHECK_RESULT_SCHEMA_ID = 'boundaryci/check-result';

/** Version of the CLI result envelope shape. Any incompatible shape change increments this. */
export const CHECK_RESULT_SCHEMA_VERSION = 1;

export const EXIT_CODE_OK = 0;
export const EXIT_CODE_POLICY_FAILURE = 1;
export const EXIT_CODE_INCOMPLETE = 2;
export const EXIT_CODE_INPUT_CONFIGURATION_FAILURE = 3;
export const EXIT_CODE_RUNTIME_INFRASTRUCTURE_FAILURE = 4;

interface CheckArgs {
  base: string;
  head: string;
}

type ParsedArgs = { status: 'valid'; args: CheckArgs } | { status: 'invalid'; detail: string };

function parseCheckArgs(argv: readonly string[]): ParsedArgs {
  if (argv[0] !== 'check') return { status: 'invalid', detail: 'the only supported command is "check"' };

  let base: string | null = null;
  let head: string | null = null;
  let format: string | null = null;
  let index = 1;
  while (index < argv.length) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (value === undefined) return { status: 'invalid', detail: `flag ${String(flag)} requires a value` };
    if (flag === '--base') base = value;
    else if (flag === '--head') head = value;
    else if (flag === '--format') format = value;
    else return { status: 'invalid', detail: `unknown flag ${String(flag)}` };
    index += 2;
  }
  if (base === null) return { status: 'invalid', detail: 'missing required flag --base' };
  if (head === null) return { status: 'invalid', detail: 'missing required flag --head' };
  if (format !== 'json') return { status: 'invalid', detail: 'the only supported --format value is "json"' };
  return { status: 'valid', args: { base, head } };
}

function exitCodeFor(outcome: LocalComparisonOutcome): number {
  const { comparison, policy } = outcome;
  if (comparison.status === 'complete') return policy.decision === 'fail' ? EXIT_CODE_POLICY_FAILURE : EXIT_CODE_OK;
  if (comparison.status === 'incomplete') return policy.decision === 'fail' ? EXIT_CODE_INCOMPLETE : EXIT_CODE_OK;
  if (comparison.status === 'input-configuration-failure') return EXIT_CODE_INPUT_CONFIGURATION_FAILURE;
  if (comparison.status === 'runtime-infrastructure-failure') return EXIT_CODE_RUNTIME_INFRASTRUCTURE_FAILURE;
  const exhaustive: never = comparison;
  throw new Error(`unreachable comparison status: ${JSON.stringify(exhaustive)}`);
}

/**
 * Runs the `check` tracer against injected argv/stdout/stderr and returns its exit code.
 *
 * On success, exactly one JSON document is written to `io.stdout` and nothing is written to
 * `io.stderr`. On an argument or unexpected runtime error, nothing is written to `io.stdout`
 * and one diagnostic line is written to `io.stderr`.
 */
export async function runCli(argv: readonly string[], io: CliIO): Promise<number> {
  const parsed = parseCheckArgs(argv);
  if (parsed.status === 'invalid') {
    io.stderr.write(`boundaryci: ${parsed.detail}\n`);
    return EXIT_CODE_INPUT_CONFIGURATION_FAILURE;
  }

  try {
    const outcome = await evaluateLocalComparison(parsed.args.base, parsed.args.head, BUILTIN_CONFIG);
    const envelope = {
      schemaId: CHECK_RESULT_SCHEMA_ID,
      schemaVersion: CHECK_RESULT_SCHEMA_VERSION,
      comparison: outcome.comparison,
      policy: outcome.policy,
    };
    io.stdout.write(`${JSON.stringify(envelope, null, 2)}\n`);
    return exitCodeFor(outcome);
  } catch (error) {
    io.stderr.write(`boundaryci: unexpected runtime failure: ${error instanceof Error ? error.message : String(error)}\n`);
    return EXIT_CODE_RUNTIME_INFRASTRUCTURE_FAILURE;
  }
}
