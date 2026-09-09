import { lstat, readdir, realpath, rm } from 'node:fs/promises';
import { basename, relative, resolve, sep } from 'node:path';
import { pathToFileURL } from 'node:url';

const REMOVED_DIRECTORIES = new Set([
  '.agents',
  '.claude',
  '.codex',
  '.cursor',
  '.gemini',
  '.github',
  '.gsd',
  '.opencode',
  '.planning',
  'coverage',
  'fixture',
  'fixtures',
  'test',
  'tests',
]);
const REMOVED_PACKAGE_DOCUMENTATION_DIRECTORIES = new Set(['doc', 'docs']);
const REMOVED_DOCUMENT = /^(?:CHANGELOG|CONTRIBUTING|HISTORY|README|SECURITY)(?:\.[^/]*)?$/iu;

function contained(root, path) {
  const child = relative(root, path);
  return child !== '' && child !== '..' && !child.startsWith(`..${sep}`) && !child.startsWith('/');
}

/** Removes only fixed non-runtime directories from a realized production dependency tree. */
export async function pruneRuntimeDependencyTree(rootPath) {
  const root = await realpath(resolve(rootPath));
  const rootDetails = await lstat(root);
  if (!rootDetails.isDirectory() || rootDetails.isSymbolicLink()) throw new TypeError('runtime-prune/root');
  let removed = 0;
  const visit = async (directory) => {
    const entries = (await readdir(directory, { withFileTypes: true })).sort((left, right) => Buffer.compare(Buffer.from(left.name), Buffer.from(right.name)));
    const packageRoot = entries.some((entry) => entry.isFile() && entry.name === 'package.json');
    for (const entry of entries) {
      const path = resolve(directory, entry.name);
      if (!contained(root, path)) throw new TypeError('runtime-prune/path');
      const name = basename(path);
      const removableDirectory = REMOVED_DIRECTORIES.has(name) ||
        (packageRoot && REMOVED_PACKAGE_DOCUMENTATION_DIRECTORIES.has(name));
      if (removableDirectory || (!entry.isDirectory() && REMOVED_DOCUMENT.test(name))) {
        await rm(path, { force: true, recursive: true, maxRetries: 0 });
        removed += 1;
        continue;
      }
      if (entry.isSymbolicLink() || !entry.isDirectory()) continue;
      await visit(path);
    }
  };
  await visit(root);
  return removed;
}

const invokedPath = process.argv[1];
if (invokedPath !== undefined && import.meta.url === pathToFileURL(invokedPath).href) {
  if (process.argv.length !== 3) {
    process.stderr.write('runtime-prune/usage\n');
    process.exitCode = 2;
  } else {
    void pruneRuntimeDependencyTree(process.argv[2]).catch((error) => {
      process.stderr.write(`${error instanceof Error ? error.message : 'runtime-prune/failure'}\n`);
      process.exitCode = 1;
    });
  }
}
