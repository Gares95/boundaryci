/**
 * Bounded temporary-tree fixture helpers for analyzer tests.
 *
 * Every helper here writes or links bytes on disk and never reads a fixture back through
 * `require`, `import`, a transpiler, a build step, or a spawned process. Fixtures are inert
 * data: the analyzer and these tests only ever open them as bytes.
 */

import { mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve, sep } from 'node:path';

const trackedRoots: string[] = [];

/** Creates a fresh temporary directory and tracks it for {@link cleanupTempRoots}. */
export async function createTempRoot(prefix = 'boundaryci-analyzer-harness-'): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), prefix));
  trackedRoots.push(root);
  return root;
}

/** Removes every temporary root created by {@link createTempRoot} since the last cleanup. */
export async function cleanupTempRoots(): Promise<void> {
  const roots = trackedRoots.splice(0, trackedRoots.length);
  for (const root of roots) await rm(root, { recursive: true, force: true });
}

/**
 * Resolves `relativePath` beneath `root`, rejecting any path that would escape it.
 *
 * A fixture helper that could write or link outside its own temporary root would not be
 * bounded, so escaping segments are rejected rather than normalized away.
 */
function resolveWithinRoot(root: string, relativePath: string): string {
  const resolvedRoot = resolve(root);
  const target = resolve(root, ...relativePath.split('/'));
  if (target !== resolvedRoot && !target.startsWith(`${resolvedRoot}${sep}`)) {
    throw new Error('fixture path escapes its temporary root');
  }
  return target;
}

/**
 * Writes `contents` at `relativePath` beneath `root` as an exact byte sequence.
 *
 * `contents` is written verbatim: a `string` is UTF-8 encoded by `writeFile` with no other
 * transformation, and a `Uint8Array` is written as-is. Nothing here parses, transpiles, or
 * imports the written bytes.
 */
export async function writeRegularFile(
  root: string,
  relativePath: string,
  contents: string | Uint8Array,
): Promise<string> {
  const target = resolveWithinRoot(root, relativePath);
  await mkdir(dirname(target), { recursive: true });
  await writeFile(target, contents);
  return target;
}

/**
 * Creates an explicit symbolic link at `relativePath` beneath `root`, pointing at `linkTarget`.
 *
 * `linkTarget` is never resolved or read by this helper; the link is data for later
 * discovery tests to observe as a symlink, not a path the helper follows.
 */
export async function createSymlink(root: string, relativePath: string, linkTarget: string): Promise<string> {
  const target = resolveWithinRoot(root, relativePath);
  await mkdir(dirname(target), { recursive: true });
  await symlink(linkTarget, target);
  return target;
}
