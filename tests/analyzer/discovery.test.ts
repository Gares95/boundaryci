import { execFileSync } from 'node:child_process';
import { access, chmod, constants as fsConstants } from 'node:fs/promises';
import { join } from 'node:path';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { analyzeSourceTree } from '../../src/analyzer/analyze.js';
import { ANALYSIS_DISCOVERY_PROFILE_ID, DEFAULT_ANALYSIS_LIMITS } from '../../src/analyzer/contract.js';
import type { AnalysisLimits, AnalysisRequest } from '../../src/analyzer/contract.js';
import { DISCOVERY_POLICY_IDENTITY, compileLimitedGlob, discoverSources } from '../../src/analyzer/discovery.js';
import type { DiscoverySuccess } from '../../src/analyzer/discovery.js';

import { cleanupTempRoots, createSymlink, createTempRoot, writeRegularFile } from './helpers.js';
import discoveryCases from './fixtures/discovery-cases.json' with { type: 'json' };

/**
 * A deliberately narrow filesystem seam for the few facts that on-disk fixtures cannot state
 * deterministically: bytes that a read returns in spite of the size the earlier `lstat`
 * reported, and an entry or directory that cannot be inspected or listed regardless of the
 * privileges the test process happens to hold.
 *
 * Every hook is `null` by default and every call falls through to the real `node:fs/promises`,
 * so this exists only for the cases that explicitly set one; production code gains no test
 * hook, and discovery still runs against real temporary trees everywhere else.
 */
const fsHooks = vi.hoisted(() => ({
  readFile: null as ((absolutePath: string) => Buffer | null) | null,
  readdir: null as ((absolutePath: string) => Error | null) | null,
  lstat: null as ((absolutePath: string) => Error | null) | null,
}));

vi.mock('node:fs/promises', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs/promises')>();
  return {
    ...actual,
    readFile: async (absolutePath: string): Promise<Buffer> => {
      const replacement = fsHooks.readFile === null ? null : fsHooks.readFile(absolutePath);
      return replacement ?? (await actual.readFile(absolutePath));
    },
    readdir: async (absolutePath: string): Promise<string[]> => {
      const failure = fsHooks.readdir === null ? null : fsHooks.readdir(absolutePath);
      if (failure !== null) throw failure;
      return actual.readdir(absolutePath);
    },
    lstat: async (absolutePath: string) => {
      const failure = fsHooks.lstat === null ? null : fsHooks.lstat(absolutePath);
      if (failure !== null) throw failure;
      return actual.lstat(absolutePath);
    },
  };
});

/** Matches exactly one root-relative fixture path, whatever the platform separator is. */
function isFixture(absolutePath: string, relativePath: string): boolean {
  return absolutePath.endsWith(join(...relativePath.split('/')));
}

interface ValidPatternCase {
  name: string;
  pattern: string;
  matches: string[];
  nonMatches: string[];
}

interface InvalidPatternCase {
  name: string;
  pattern: string;
}

interface DirectoryFrontierCase {
  name: string;
  pattern: string;
  directory: string;
  coversDirectory: boolean;
}

interface SubtreeExclusionCase {
  name: string;
  pattern: string;
  directory: string;
  excludesSubtree: boolean;
}

const cases = discoveryCases as {
  validPatterns: ValidPatternCase[];
  invalidPatterns: InvalidPatternCase[];
  directoryFrontier: DirectoryFrontierCase[];
  subtreeExclusion: SubtreeExclusionCase[];
};

afterEach(async () => {
  fsHooks.readFile = null;
  fsHooks.readdir = null;
  fsHooks.lstat = null;
  await cleanupTempRoots();
});

function limitsFor(overrides: Partial<AnalysisLimits> = {}): AnalysisLimits {
  return { ...DEFAULT_ANALYSIS_LIMITS, ...overrides };
}

async function expectDiscovered(result: Awaited<ReturnType<typeof discoverSources>>): Promise<DiscoverySuccess> {
  if (result.status !== 'discovered') throw new Error(`expected a discovered result, received ${result.status}`);
  return result;
}

describe('DISCOVERY_POLICY_IDENTITY', () => {
  it('is the single canonical discovery/glob policy identity', () => {
    expect(DISCOVERY_POLICY_IDENTITY).toBe(ANALYSIS_DISCOVERY_PROFILE_ID);
  });
});

describe('compileLimitedGlob grammar', () => {
  for (const testCase of cases.validPatterns) {
    it(`compiles and matches: ${testCase.name}`, () => {
      const glob = compileLimitedGlob(testCase.pattern);
      for (const path of testCase.matches) {
        expect(glob.test(path.split('/')), `expected ${testCase.pattern} to match ${path}`).toBe(true);
      }
      for (const path of testCase.nonMatches) {
        expect(glob.test(path.split('/')), `expected ${testCase.pattern} not to match ${path}`).toBe(false);
      }
    });
  }

  for (const testCase of cases.invalidPatterns) {
    it(`rejects an invalid pattern: ${testCase.name}`, () => {
      expect(() => {
        compileLimitedGlob(testCase.pattern);
      }).toThrow(TypeError);
    });
  }

  for (const testCase of cases.directoryFrontier) {
    it(`evaluates directory frontier coverage: ${testCase.name}`, () => {
      const glob = compileLimitedGlob(testCase.pattern);
      expect(glob.coversDirectory(testCase.directory.split('/'))).toBe(testCase.coversDirectory);
    });
  }

  for (const testCase of cases.subtreeExclusion) {
    it(`evaluates whole-subtree exclusion: ${testCase.name}`, () => {
      const glob = compileLimitedGlob(testCase.pattern);
      expect(glob.excludesSubtree(testCase.directory.split('/'))).toBe(testCase.excludesSubtree);
    });
  }

  it('caches a compiled pattern rather than recompiling it', () => {
    const first = compileLimitedGlob('src/**/*.ts');
    const second = compileLimitedGlob('src/**/*.ts');
    expect(first).toBe(second);
  });
});

describe('discoverSources: exact source universe', () => {
  it('discovers exactly the six supported extensions and excludes declaration files, .cjs, .cts, and node_modules', async () => {
    const root = await createTempRoot();
    await writeRegularFile(root, 'src/a.js', 'export {};\n');
    await writeRegularFile(root, 'src/b.jsx', 'export {};\n');
    await writeRegularFile(root, 'src/c.mjs', 'export {};\n');
    await writeRegularFile(root, 'src/d.ts', 'export {};\n');
    await writeRegularFile(root, 'src/e.tsx', 'export {};\n');
    await writeRegularFile(root, 'src/f.mts', 'export {};\n');
    await writeRegularFile(root, 'src/g.cjs', 'module.exports = {};\n');
    await writeRegularFile(root, 'src/h.cts', 'export {};\n');
    await writeRegularFile(root, 'src/i.d.ts', 'export declare const x: number;\n');
    await writeRegularFile(root, 'src/j.d.mts', 'export declare const y: number;\n');
    await writeRegularFile(root, 'node_modules/pkg/index.ts', 'export {};\n');

    const include = ['**/*.js', '**/*.jsx', '**/*.mjs', '**/*.ts', '**/*.tsx', '**/*.mts', '**/*.cjs', '**/*.cts'];
    const result = await expectDiscovered(await discoverSources(root, include, [], limitsFor()));

    expect(result.effectiveSources).toEqual(['src/a.js', 'src/b.jsx', 'src/c.mjs', 'src/d.ts', 'src/e.tsx', 'src/f.mts']);
  });

  it('excludes every node_modules path segment regardless of include pattern breadth', async () => {
    const root = await createTempRoot();
    await writeRegularFile(root, 'src/app.ts', 'export {};\n');
    await writeRegularFile(root, 'node_modules/pkg/index.ts', 'export {};\n');
    await writeRegularFile(root, 'src/node_modules/nested/index.ts', 'export {};\n');

    const result = await expectDiscovered(await discoverSources(root, ['**/*.ts'], [], limitsFor()));

    expect(result.effectiveSources).toEqual(['src/app.ts']);
  });
});

describe('discoverSources: exclude pruning is decided per source path', () => {
  it('keeps a descendant file that no exclude pattern matches, even when an exclude matches its directory', async () => {
    const root = await createTempRoot();
    await writeRegularFile(root, 'src/top.ts', 'export {};\n');
    await writeRegularFile(root, 'src/nested/app.ts', 'export {};\n');

    // "src/*" matches the file "src/top.ts" and the directory "src/nested", but it does not
    // match "src/nested/app.ts", so that file is still in any(include) - any(exclude).
    const result = await expectDiscovered(
      await discoverSources(root, ['src/**/*.ts'], ['src/*'], limitsFor()),
    );

    expect(result.effectiveSources).toEqual(['src/nested/app.ts']);
    expect(result.causes).toEqual([]);
    expect(result.universeComplete).toBe(true);
  });

  it('prunes a directory whose whole subtree the exclude proves excluded, without inspecting anything beneath it', async () => {
    const root = await createTempRoot();
    await writeRegularFile(root, 'lib/keep.ts', 'export {};\n');
    await writeRegularFile(root, 'src/nested/app.ts', 'export {};\n');
    // Neither of these would be silent if the excluded subtree were traversed.
    await createSymlink(root, 'src/nested/link.ts', './app.ts');
    await createSymlink(root, 'src/nested/linked-dir', '../../lib');

    const result = await expectDiscovered(await discoverSources(root, ['**/*.ts'], ['src/**'], limitsFor()));

    expect(result.effectiveSources).toEqual(['lib/keep.ts']);
    expect(result.causes).toEqual([]);
    expect(result.universeComplete).toBe(true);
  });
});

describe('discoverSources: deterministic ordering', () => {
  it('sorts the discovered universe bytewise by full root-relative path, not by traversal shape', async () => {
    const root = await createTempRoot();
    // "lib.ts" sorts before "lib/inner.ts" bytewise ('.' = 0x2E < '/' = 0x2F), which is the
    // opposite of a directory-first depth-first traversal order.
    await writeRegularFile(root, 'lib.ts', 'export {};\n');
    await writeRegularFile(root, 'lib/inner.ts', 'export {};\n');

    const result = await expectDiscovered(await discoverSources(root, ['**/*.ts'], [], limitsFor()));

    expect(result.effectiveSources).toEqual(['lib.ts', 'lib/inner.ts']);
  });

  it('uses UTF-8 byte order for non-ASCII paths and its budget frontier', async () => {
    const root = await createTempRoot();
    await writeRegularFile(root, 'src/\u{10000}.ts', 'export {};\n');
    await writeRegularFile(root, 'src/\uE000.ts', 'export {};\n');

    const result = await expectDiscovered(
      await discoverSources(root, ['src/**/*.ts'], [], limitsFor({ maxSourceFiles: 1 })),
    );

    // UTF-8 encodes U+E000 as EE 80 80 and U+10000 as F0 90 80 80. JavaScript's default
    // UTF-16 ordering gives the opposite result because the supplementary code point begins
    // with a surrogate. The discovery contract is explicitly UTF-8 bytewise.
    expect(result.effectiveSources).toEqual(['src/\uE000.ts', 'src/\u{10000}.ts']);
    expect(result.sources.map((source) => source.path)).toEqual(['src/\uE000.ts']);
    expect(result.causes).toContainEqual(expect.objectContaining({
      code: 'source-file-limit',
      resource: expect.objectContaining({ frontier: 'src/\u{10000}.ts' }),
    }));
  });

  it('produces the same result regardless of include/exclude array order', async () => {
    const root = await createTempRoot();
    await writeRegularFile(root, 'src/a.ts', 'export {};\n');
    await writeRegularFile(root, 'src/b.ts', 'export {};\n');
    await writeRegularFile(root, 'src/skip.spec.ts', 'export {};\n');
    await writeRegularFile(root, 'docs/c.ts', 'export {};\n');

    const include = ['src/**/*.ts', 'docs/**/*.ts'];
    const exclude = ['**/*.spec.ts', 'docs/**'];

    const forward = await expectDiscovered(await discoverSources(root, include, exclude, limitsFor()));
    const reversed = await expectDiscovered(
      await discoverSources(root, [...include].reverse(), [...exclude].reverse(), limitsFor()),
    );

    expect(forward.effectiveSources).toEqual(['src/a.ts', 'src/b.ts']);
    expect(JSON.stringify(reversed.effectiveSources)).toBe(JSON.stringify(forward.effectiveSources));
    expect(JSON.stringify(reversed.causes)).toBe(JSON.stringify(forward.causes));
  });

  it('is unaffected by duplicate include/exclude declarations', async () => {
    const root = await createTempRoot();
    await writeRegularFile(root, 'src/a.ts', 'export {};\n');

    const withDuplicates = await expectDiscovered(
      await discoverSources(root, ['src/**/*.ts', 'src/**/*.ts', 'src/a.ts'], [], limitsFor()),
    );

    expect(withDuplicates.effectiveSources).toEqual(['src/a.ts']);
  });
});

describe('discoverSources: symlinks and non-regular entries', () => {
  it('does not follow or read a matching file symlink, and records one matching-source-symlink cause', async () => {
    const root = await createTempRoot();
    await writeRegularFile(root, 'src/target.ts', 'export {};\n');
    await createSymlink(root, 'src/link.ts', './target.ts');

    const result = await expectDiscovered(await discoverSources(root, ['src/**/*.ts'], [], limitsFor()));

    expect(result.effectiveSources).toEqual(['src/target.ts']);
    expect(result.causes).toEqual([
      {
        code: 'matching-source-symlink',
        scope: 'source',
        path: 'src/link.ts',
        resource: null,
        detail: 'a symbolic link matched the effective source pattern and was not followed or read',
      },
    ]);
  });

  it('does not follow a directory symlink whose frontier could contain an included source', async () => {
    const root = await createTempRoot();
    await writeRegularFile(root, 'external/thing.ts', 'export {};\n');
    await createSymlink(root, 'src/linked', '../external');

    const result = await expectDiscovered(await discoverSources(root, ['src/**/*.ts'], [], limitsFor()));

    expect(result.effectiveSources).toEqual([]);
    expect(result.causes).toEqual([
      {
        code: 'relevant-directory-symlink',
        scope: 'source',
        path: 'src/linked',
        resource: null,
        detail: 'a symbolic link directory frontier could contain an included source and was not followed',
      },
    ]);
  });

  it('stays silent for an excluded or irrelevant symlink', async () => {
    const root = await createTempRoot();
    await writeRegularFile(root, 'external/thing.ts', 'export {};\n');
    // Excluded by pattern: its own frontier is fully pruned.
    await createSymlink(root, 'ignored/linked', '../external');
    // Outside the declared include frontier entirely: no include pattern could ever reach it.
    await createSymlink(root, 'other/linked', '../external');
    await writeRegularFile(root, 'src/app.ts', 'export {};\n');

    const result = await expectDiscovered(
      await discoverSources(root, ['src/**/*.ts'], ['ignored/**'], limitsFor()),
    );

    expect(result.effectiveSources).toEqual(['src/app.ts']);
    expect(result.causes).toEqual([]);
  });

  it('flags an ambiguously-named in-frontier symlink rather than silently guessing its type', async () => {
    const root = await createTempRoot();
    await writeRegularFile(root, 'external/thing.ts', 'export {};\n');
    // Never followed, so its actual file/directory nature is unknown; its path nonetheless
    // falls within the declared include frontier ("src/**/*.ts" covers any depth under
    // "src/"), so it must not be silently dropped.
    await createSymlink(root, 'src/ambiguous', '../external');

    const result = await expectDiscovered(await discoverSources(root, ['src/**/*.ts'], [], limitsFor()));

    expect(result.effectiveSources).toEqual([]);
    expect(result.causes).toEqual([
      {
        code: 'relevant-directory-symlink',
        scope: 'source',
        path: 'src/ambiguous',
        resource: null,
        detail: 'a symbolic link directory frontier could contain an included source and was not followed',
      },
    ]);
  });

  it('does not read a matching non-regular entry, and records one matching-non-regular-entry cause', async () => {
    const root = await createTempRoot();
    const fifoPath = join(root, 'src', 'pipe.ts');
    await writeRegularFile(root, 'src/marker.ts', 'export {};\n');
    try {
      execFileSync('mkfifo', [fifoPath]);
    } catch {
      return; // FIFO creation is unavailable on this platform; nothing further to assert.
    }

    const result = await expectDiscovered(await discoverSources(root, ['src/**/*.ts'], [], limitsFor()));

    expect(result.effectiveSources).toEqual(['src/marker.ts']);
    expect(result.causes).toEqual([
      {
        code: 'matching-non-regular-entry',
        scope: 'source',
        path: 'src/pipe.ts',
        resource: null,
        detail: 'a non-regular filesystem entry matched the effective source pattern and was not read',
      },
    ]);
  });
});

describe('discoverSources: trusted root validation', () => {
  it('fails on a missing root', async () => {
    const root = await createTempRoot();
    const result = await discoverSources(join(root, 'does-not-exist'), ['**/*.ts'], [], limitsFor());
    expect(result).toEqual({
      status: 'failed',
      reason: 'unresolvable-analysis-root',
      detail: 'the analysis root could not be canonicalized',
    });
  });

  it('fails when the root is not a directory', async () => {
    const root = await createTempRoot();
    const filePath = await writeRegularFile(root, 'src/app.ts', 'export {};\n');
    const result = await discoverSources(filePath, ['**/*.ts'], [], limitsFor());
    expect(result).toEqual({
      status: 'failed',
      reason: 'analysis-root-not-a-directory',
      detail: 'the analysis root is not a directory',
    });
  });

  it('fails on a malformed include pattern reaching discovery directly', async () => {
    const root = await createTempRoot();
    const result = await discoverSources(root, ['!(src)/**/*.ts'], [], limitsFor());
    expect(result.status).toBe('failed');
    if (result.status !== 'failed') throw new Error('expected a failed result');
    expect(result.reason).toBe('invalid-analysis-request');
  });
});

describe('discoverSources: resource-limit boundaries', () => {
  it('stops file-count consumption at zero, one below, exact, and one above the limit', async () => {
    const root = await createTempRoot();
    await writeRegularFile(root, 'src/a.ts', 'export {};\n');
    await writeRegularFile(root, 'src/b.ts', 'export {};\n');
    await writeRegularFile(root, 'src/c.ts', 'export {};\n');

    const zero = await expectDiscovered(await discoverSources(root, ['src/**/*.ts'], [], limitsFor({ maxSourceFiles: 0 })));
    expect(zero.sources).toEqual([]);
    expect(zero.causes).toEqual([
      {
        code: 'source-file-limit',
        scope: 'repository',
        path: null,
        resource: {
          limitKey: 'maxSourceFiles',
          configured: 0,
          consumed: 0,
          frontier: 'src/a.ts',
          processedSources: 0,
          unprocessedSources: 3,
        },
        detail: 'the source-file budget of 0 stopped analysis before src/a.ts',
      },
    ]);

    const belowOne = await expectDiscovered(await discoverSources(root, ['src/**/*.ts'], [], limitsFor({ maxSourceFiles: 2 })));
    expect(belowOne.sources.map((source) => source.path)).toEqual(['src/a.ts', 'src/b.ts']);
    expect(belowOne.causes).toEqual([
      {
        code: 'source-file-limit',
        scope: 'repository',
        path: null,
        resource: {
          limitKey: 'maxSourceFiles',
          configured: 2,
          consumed: 2,
          frontier: 'src/c.ts',
          processedSources: 2,
          unprocessedSources: 1,
        },
        detail: 'the source-file budget of 2 stopped analysis before src/c.ts',
      },
    ]);

    const exact = await expectDiscovered(await discoverSources(root, ['src/**/*.ts'], [], limitsFor({ maxSourceFiles: 3 })));
    expect(exact.sources.map((source) => source.path)).toEqual(['src/a.ts', 'src/b.ts', 'src/c.ts']);
    expect(exact.causes).toEqual([]);

    const above = await expectDiscovered(await discoverSources(root, ['src/**/*.ts'], [], limitsFor({ maxSourceFiles: 4 })));
    expect(above.sources.map((source) => source.path)).toEqual(['src/a.ts', 'src/b.ts', 'src/c.ts']);
    expect(above.causes).toEqual([]);
  });

  it('omits an individually oversized file with a file-scoped cause at zero, one below, exact, and one above its size', async () => {
    const root = await createTempRoot();
    const content = 'export const value = "0123456789";\n';
    await writeRegularFile(root, 'src/only.ts', content);
    const byteSize = Buffer.byteLength(content, 'utf8');

    for (const [label, configured, accepted] of [
      ['zero', 0, false],
      ['one below', byteSize - 1, false],
      ['exact', byteSize, true],
      ['one above', byteSize + 1, true],
    ] as const) {
      const result = await expectDiscovered(
        await discoverSources(root, ['src/**/*.ts'], [], limitsFor({ maxSourceFileBytes: configured })),
      );
      if (accepted) {
        expect(result.sources, label).toEqual([
          { path: 'src/only.ts', byteSize, bytes: Buffer.from(content, 'utf8') },
        ]);
        expect(result.causes, label).toEqual([]);
      } else {
        expect(result.sources, label).toEqual([]);
        expect(result.causes, label).toEqual([
          {
            code: 'source-byte-limit',
            scope: 'source',
            path: 'src/only.ts',
            resource: {
              limitKey: 'maxSourceFileBytes',
              configured,
              consumed: byteSize,
              frontier: 'src/only.ts',
              processedSources: null,
              unprocessedSources: null,
            },
            detail: `the source exceeds the per-file byte budget of ${String(configured)} bytes`,
          },
        ]);
      }
    }
  });

  it('continues independent sorted files after a file-scoped byte omission', async () => {
    const root = await createTempRoot();
    const small = 'export const a = 1;\n';
    const big = `export const value = "${'x'.repeat(200)}";\n`;
    await writeRegularFile(root, 'src/a-small.ts', small);
    await writeRegularFile(root, 'src/b-big.ts', big);
    await writeRegularFile(root, 'src/c-small.ts', small);

    const result = await expectDiscovered(
      await discoverSources(root, ['src/**/*.ts'], [], limitsFor({ maxSourceFileBytes: Buffer.byteLength(small, 'utf8') })),
    );

    expect(result.sources.map((source) => source.path)).toEqual(['src/a-small.ts', 'src/c-small.ts']);
    expect(result.causes.map((cause) => cause.code)).toEqual(['source-byte-limit']);
    expect(result.causes[0]?.path).toBe('src/b-big.ts');
  });

  it('stops scan-wide byte consumption at zero, one below, exact, and one above the total', async () => {
    const root = await createTempRoot();
    const contentA = 'export const a = 1;\n';
    const contentB = 'export const b = 22;\n';
    await writeRegularFile(root, 'src/a.ts', contentA);
    await writeRegularFile(root, 'src/b.ts', contentB);
    const sizeA = Buffer.byteLength(contentA, 'utf8');
    const sizeB = Buffer.byteLength(contentB, 'utf8');
    const total = sizeA + sizeB;

    const zero = await expectDiscovered(await discoverSources(root, ['src/**/*.ts'], [], limitsFor({ maxTotalSourceBytes: 0 })));
    expect(zero.sources).toEqual([]);
    expect(zero.causes).toEqual([
      {
        code: 'source-byte-limit',
        scope: 'repository',
        path: null,
        resource: {
          limitKey: 'maxTotalSourceBytes',
          configured: 0,
          consumed: 0,
          frontier: 'src/a.ts',
          processedSources: 0,
          unprocessedSources: 2,
        },
        detail: 'the scan byte budget of 0 stopped analysis before src/a.ts after 0 bytes',
      },
    ]);

    const belowOne = await expectDiscovered(
      await discoverSources(root, ['src/**/*.ts'], [], limitsFor({ maxTotalSourceBytes: total - 1 })),
    );
    expect(belowOne.sources.map((source) => source.path)).toEqual(['src/a.ts']);
    expect(belowOne.causes).toEqual([
      {
        code: 'source-byte-limit',
        scope: 'repository',
        path: null,
        resource: {
          limitKey: 'maxTotalSourceBytes',
          configured: total - 1,
          consumed: sizeA,
          frontier: 'src/b.ts',
          processedSources: 1,
          unprocessedSources: 1,
        },
        detail: `the scan byte budget of ${String(total - 1)} stopped analysis before src/b.ts after ${String(sizeA)} bytes`,
      },
    ]);

    const exact = await expectDiscovered(
      await discoverSources(root, ['src/**/*.ts'], [], limitsFor({ maxTotalSourceBytes: total })),
    );
    expect(exact.sources.map((source) => source.path)).toEqual(['src/a.ts', 'src/b.ts']);
    expect(exact.causes).toEqual([]);

    const above = await expectDiscovered(
      await discoverSources(root, ['src/**/*.ts'], [], limitsFor({ maxTotalSourceBytes: total + 1 })),
    );
    expect(above.sources.map((source) => source.path)).toEqual(['src/a.ts', 'src/b.ts']);
    expect(above.causes).toEqual([]);
  });

  it('stops discovery work consumption at zero, one below, exact, and one above the traversal entry count', async () => {
    const root = await createTempRoot();
    await writeRegularFile(root, 'src/a.ts', 'export {};\n');
    // Exactly two filesystem entries are inspected: the "src" directory entry at the root,
    // then the "a.ts" file entry inside it.

    const zero = await expectDiscovered(await discoverSources(root, ['src/**/*.ts'], [], limitsFor({ maxSourceWork: 0 })));
    expect(zero.effectiveSources).toEqual([]);
    expect(zero.causes).toEqual([
      {
        code: 'source-work-limit',
        scope: 'repository',
        path: null,
        resource: {
          limitKey: 'maxSourceWork',
          configured: 0,
          consumed: 0,
          frontier: 'src',
          processedSources: 0,
          unprocessedSources: null,
        },
        detail: 'the discovery work budget of 0 stopped traversal after 0 filesystem entries',
      },
    ]);

    const belowOne = await expectDiscovered(await discoverSources(root, ['src/**/*.ts'], [], limitsFor({ maxSourceWork: 1 })));
    expect(belowOne.effectiveSources).toEqual([]);
    expect(belowOne.causes).toEqual([
      {
        code: 'source-work-limit',
        scope: 'repository',
        path: null,
        resource: {
          limitKey: 'maxSourceWork',
          configured: 1,
          consumed: 1,
          frontier: 'src/a.ts',
          processedSources: 0,
          unprocessedSources: null,
        },
        detail: 'the discovery work budget of 1 stopped traversal after 1 filesystem entries',
      },
    ]);

    const exact = await expectDiscovered(await discoverSources(root, ['src/**/*.ts'], [], limitsFor({ maxSourceWork: 2 })));
    expect(exact.effectiveSources).toEqual(['src/a.ts']);
    expect(exact.causes).toEqual([]);

    const above = await expectDiscovered(await discoverSources(root, ['src/**/*.ts'], [], limitsFor({ maxSourceWork: 3 })));
    expect(above.effectiveSources).toEqual(['src/a.ts']);
    expect(above.causes).toEqual([]);
  });

  it('never exposes a resource cause without its resource frontier, and never a non-resource cause with one', async () => {
    const root = await createTempRoot();
    await writeRegularFile(root, 'src/target.ts', '1');
    await createSymlink(root, 'src/link.ts', './target.ts');
    await writeRegularFile(root, 'src/oversized.ts', 'x'.repeat(64));

    const result = await expectDiscovered(
      await discoverSources(root, ['src/**/*.ts'], [], limitsFor({ maxSourceFileBytes: 8 })),
    );

    const resourceCauses = result.causes.filter((cause) => cause.code === 'source-byte-limit');
    const structuralCauses = result.causes.filter((cause) => cause.code === 'matching-source-symlink');
    expect(resourceCauses).toHaveLength(1);
    expect(resourceCauses[0]?.resource).not.toBeNull();
    expect(structuralCauses).toHaveLength(1);
    expect(structuralCauses[0]?.resource).toBeNull();
  });
});

describe('discoverSources: no-follow lstat classification and bound byte reads', () => {
  it('returns the exact bytes discovery itself read for an accepted source, bound to the accepted byte size', async () => {
    const root = await createTempRoot();
    const content = 'export const value = 1;\n';
    await writeRegularFile(root, 'src/app.ts', content);

    const result = await expectDiscovered(await discoverSources(root, ['src/**/*.ts'], [], limitsFor()));

    expect(result.sources).toEqual([
      { path: 'src/app.ts', byteSize: Buffer.byteLength(content, 'utf8'), bytes: Buffer.from(content, 'utf8') },
    ]);
  });

  it('classifies a dangling symlink via lstat rather than a following stat, without throwing', async () => {
    // A following `stat` on a dangling symlink would reject with ENOENT; `lstat` succeeds and
    // reports the link itself, so this proves discovery never follows a descendant link.
    const root = await createTempRoot();
    await createSymlink(root, 'src/dangling.ts', './does-not-exist.ts');

    const result = await expectDiscovered(await discoverSources(root, ['src/**/*.ts'], [], limitsFor()));

    expect(result.effectiveSources).toEqual([]);
    expect(result.causes).toEqual([
      {
        code: 'matching-source-symlink',
        scope: 'source',
        path: 'src/dangling.ts',
        resource: null,
        detail: 'a symbolic link matched the effective source pattern and was not followed or read',
      },
    ]);
  });

  it('records a source-read-error cause for an accepted source that can no longer be read, and preserves independent sources', async () => {
    const root = await createTempRoot();
    const target = await writeRegularFile(root, 'src/secret.ts', 'export {};\n');
    await writeRegularFile(root, 'src/visible.ts', 'export {};\n');
    await chmod(target, 0o000);
    try {
      await access(target, fsConstants.R_OK);
      await chmod(target, 0o644);
      return; // permission enforcement is unavailable in this environment (e.g. running as root)
    } catch {
      // expected: the file is genuinely unreadable, so the case below is exercised
    }

    try {
      const result = await expectDiscovered(await discoverSources(root, ['src/**/*.ts'], [], limitsFor()));

      expect(result.effectiveSources).toEqual(['src/secret.ts', 'src/visible.ts']);
      expect(result.sources.map((source) => source.path)).toEqual(['src/visible.ts']);
      expect(result.causes).toEqual([
        {
          code: 'source-read-error',
          scope: 'source',
          path: 'src/secret.ts',
          resource: null,
          detail: 'an accepted source could not be read as a regular file',
        },
      ]);
    } finally {
      await chmod(target, 0o644);
    }
  });

  it('records a source-discovery-error cause for a nested directory that cannot be traversed, and preserves independent sources', async () => {
    const root = await createTempRoot();
    await writeRegularFile(root, 'src/blocked/inner.ts', 'export {};\n');
    await writeRegularFile(root, 'src/visible.ts', 'export {};\n');
    const blockedDir = join(root, 'src', 'blocked');
    await chmod(blockedDir, 0o000);
    try {
      await access(blockedDir, fsConstants.R_OK);
      await chmod(blockedDir, 0o755);
      return; // permission enforcement is unavailable in this environment (e.g. running as root)
    } catch {
      // expected: the directory is genuinely unreadable, so the case below is exercised
    }

    try {
      const result = await expectDiscovered(await discoverSources(root, ['src/**/*.ts'], [], limitsFor()));

      expect(result.effectiveSources).toEqual(['src/visible.ts']);
      expect(result.causes).toEqual([
        {
          code: 'source-discovery-error',
          scope: 'source',
          path: 'src/blocked',
          resource: null,
          detail: 'a nested directory could not be traversed and was excluded from the discovered source universe',
        },
      ]);
    } finally {
      await chmod(blockedDir, 0o755);
    }
  });
});

describe('discoverSources: byte budgets bind to the bytes actually returned', () => {
  it('omits a source whose returned bytes exceed the per-file budget, reporting the returned byte count', async () => {
    const root = await createTempRoot();
    await writeRegularFile(root, 'src/only.ts', 'a');
    const returned = Buffer.from('x'.repeat(8), 'utf8');
    fsHooks.readFile = (absolutePath) => (isFixture(absolutePath, 'src/only.ts') ? returned : null);

    const result = await expectDiscovered(
      await discoverSources(root, ['src/**/*.ts'], [], limitsFor({ maxSourceFileBytes: 4 })),
    );

    expect(result.effectiveSources).toEqual(['src/only.ts']);
    expect(result.sources).toEqual([]);
    expect(result.causes).toEqual([
      {
        code: 'source-byte-limit',
        scope: 'source',
        path: 'src/only.ts',
        resource: {
          limitKey: 'maxSourceFileBytes',
          configured: 4,
          consumed: 8,
          frontier: 'src/only.ts',
          processedSources: null,
          unprocessedSources: null,
        },
        detail: 'the source exceeds the per-file byte budget of 4 bytes',
      },
    ]);
  });

  it('stops at the scan-wide byte frontier when the returned bytes would exceed the total budget', async () => {
    const root = await createTempRoot();
    await writeRegularFile(root, 'src/a.ts', 'a');
    await writeRegularFile(root, 'src/b.ts', 'b');
    const returned = Buffer.from('x'.repeat(8), 'utf8');
    fsHooks.readFile = (absolutePath) => (isFixture(absolutePath, 'src/a.ts') ? returned : null);

    const result = await expectDiscovered(
      await discoverSources(root, ['src/**/*.ts'], [], limitsFor({ maxSourceFileBytes: 16, maxTotalSourceBytes: 4 })),
    );

    expect(result.sources).toEqual([]);
    expect(result.causes).toEqual([
      {
        code: 'source-byte-limit',
        scope: 'repository',
        path: null,
        resource: {
          limitKey: 'maxTotalSourceBytes',
          configured: 4,
          consumed: 0,
          frontier: 'src/a.ts',
          processedSources: 0,
          unprocessedSources: 2,
        },
        detail: 'the scan byte budget of 4 stopped analysis before src/a.ts after 0 bytes',
      },
    ]);
  });

  it('charges the scan-wide budget with the returned bytes rather than the earlier reported sizes', async () => {
    const root = await createTempRoot();
    // Both files report one byte to `lstat`, so a scan budget of four bytes would accept both
    // if accounting trusted those sizes instead of the bytes each read actually returned.
    await writeRegularFile(root, 'src/a.ts', 'a');
    await writeRegularFile(root, 'src/b.ts', 'b');
    const firstBytes = Buffer.from('abc', 'utf8');
    const secondBytes = Buffer.from('de', 'utf8');
    fsHooks.readFile = (absolutePath) => {
      if (isFixture(absolutePath, 'src/a.ts')) return firstBytes;
      if (isFixture(absolutePath, 'src/b.ts')) return secondBytes;
      return null;
    };

    const result = await expectDiscovered(
      await discoverSources(root, ['src/**/*.ts'], [], limitsFor({ maxSourceFileBytes: 16, maxTotalSourceBytes: 4 })),
    );

    expect(result.sources).toEqual([{ path: 'src/a.ts', byteSize: 3, bytes: firstBytes }]);
    expect(result.causes).toEqual([
      {
        code: 'source-byte-limit',
        scope: 'repository',
        path: null,
        resource: {
          limitKey: 'maxTotalSourceBytes',
          configured: 4,
          consumed: 3,
          frontier: 'src/b.ts',
          processedSources: 1,
          unprocessedSources: 1,
        },
        detail: 'the scan byte budget of 4 stopped analysis before src/b.ts after 3 bytes',
      },
    ]);
  });
});

describe('discoverSources: work-frontier uncertainty', () => {
  it('reports an incomplete universe when the work budget stops traversal short of full enumeration', async () => {
    const root = await createTempRoot();
    await writeRegularFile(root, 'src/a.ts', 'export {};\n');
    await writeRegularFile(root, 'src/z.ts', 'export {};\n');

    const result = await expectDiscovered(
      await discoverSources(root, ['src/**/*.ts'], [], limitsFor({ maxSourceWork: 2 })),
    );

    expect(result.universeComplete).toBe(false);
    expect(result.effectiveSources).toEqual(['src/a.ts']);
  });

  it('reports a complete universe when the work budget was never exhausted', async () => {
    const root = await createTempRoot();
    await writeRegularFile(root, 'src/a.ts', 'export {};\n');

    const result = await expectDiscovered(await discoverSources(root, ['src/**/*.ts'], [], limitsFor()));

    expect(result.universeComplete).toBe(true);
  });
});

describe('discoverSources: discovery-error uncertainty', () => {
  it('reports an incomplete universe when a relevant nested directory cannot be traversed', async () => {
    const root = await createTempRoot();
    await writeRegularFile(root, 'src/blocked/inner.ts', 'export {};\n');
    await writeRegularFile(root, 'src/visible.ts', 'export {};\n');
    fsHooks.readdir = (absolutePath) =>
      isFixture(absolutePath, 'src/blocked') ? new Error('the directory could not be listed') : null;

    const result = await expectDiscovered(await discoverSources(root, ['src/**/*.ts'], [], limitsFor()));

    expect(result.effectiveSources).toEqual(['src/visible.ts']);
    expect(result.universeComplete).toBe(false);
    expect(result.causes).toEqual([
      {
        code: 'source-discovery-error',
        scope: 'source',
        path: 'src/blocked',
        resource: null,
        detail: 'a nested directory could not be traversed and was excluded from the discovered source universe',
      },
    ]);
  });

  it('reports an incomplete universe when a relevant entry cannot be inspected', async () => {
    const root = await createTempRoot();
    await writeRegularFile(root, 'src/a.ts', 'export {};\n');
    await writeRegularFile(root, 'src/z.ts', 'export {};\n');
    fsHooks.lstat = (absolutePath) =>
      isFixture(absolutePath, 'src/z.ts') ? new Error('the entry could not be inspected') : null;

    const result = await expectDiscovered(await discoverSources(root, ['src/**/*.ts'], [], limitsFor()));

    expect(result.effectiveSources).toEqual(['src/a.ts']);
    expect(result.universeComplete).toBe(false);
    expect(result.causes).toEqual([
      {
        code: 'source-discovery-error',
        scope: 'source',
        path: 'src/z.ts',
        resource: null,
        detail: 'a filesystem entry could not be inspected and was excluded from the discovered source universe',
      },
    ]);
  });

  it('keeps the universe complete when an uninspectable entry could never have been included', async () => {
    const root = await createTempRoot();
    await writeRegularFile(root, 'src/a.ts', 'export {};\n');
    await writeRegularFile(root, 'docs/notes.ts', 'export {};\n');
    fsHooks.lstat = (absolutePath) =>
      isFixture(absolutePath, 'docs/notes.ts') ? new Error('the entry could not be inspected') : null;

    const result = await expectDiscovered(await discoverSources(root, ['src/**/*.ts'], [], limitsFor()));

    expect(result.effectiveSources).toEqual(['src/a.ts']);
    expect(result.causes).toEqual([]);
    expect(result.universeComplete).toBe(true);
  });

  it('keeps the universe complete for a classified symlink, which is known not to participate', async () => {
    const root = await createTempRoot();
    await writeRegularFile(root, 'src/target.ts', 'export {};\n');
    await createSymlink(root, 'src/link.ts', './target.ts');

    const result = await expectDiscovered(await discoverSources(root, ['src/**/*.ts'], [], limitsFor()));

    expect(result.effectiveSources).toEqual(['src/target.ts']);
    expect(result.causes.map((cause) => cause.code)).toEqual(['matching-source-symlink']);
    expect(result.universeComplete).toBe(true);
  });
});

describe('analyzeSourceTree: declarative order independence and discovery uncertainty', () => {
  function requestFor(rootPath: string, overrides: Partial<AnalysisRequest> = {}): AnalysisRequest {
    return {
      rootPath,
      include: ['**/*.ts'],
      exclude: [],
      probotEntrypoints: [],
      limits: limitsFor(),
      ...overrides,
    };
  }

  it('produces byte-identical results for reversed and duplicated include, exclude, and Probot entrypoint arrays', async () => {
    const root = await createTempRoot();
    await writeRegularFile(root, 'src/a.ts', 'export {};\n');
    await writeRegularFile(root, 'src/b.ts', 'export {};\n');
    await writeRegularFile(root, 'docs/c.ts', 'export {};\n');

    const include = ['src/**/*.ts', 'docs/**/*.ts'];
    const exclude = ['**/*.spec.ts'];
    const probotEntrypoints = ['src/a.ts', 'src/b.ts'];

    const forward = await analyzeSourceTree(requestFor(root, { include, exclude, probotEntrypoints }));
    const reversedAndDuplicated = await analyzeSourceTree(
      requestFor(root, {
        include: [...include].reverse(),
        exclude: [...exclude, ...exclude],
        probotEntrypoints: [...probotEntrypoints].reverse().concat(probotEntrypoints),
      }),
    );

    expect(JSON.stringify(reversedAndDuplicated)).toBe(JSON.stringify(forward));
    if (forward.status === 'failed') throw new Error('expected a non-failed result');
    expect(forward.boundary.include).toEqual(['docs/**/*.ts', 'src/**/*.ts']);
    expect(forward.boundary.exclude).toEqual(['**/*.spec.ts']);
    expect(forward.boundary.probotEntrypoints).toEqual(['src/a.ts', 'src/b.ts']);
  });

  it('returns an incomplete, not failed, result for a designated Probot entrypoint beyond an exhausted work frontier', async () => {
    const root = await createTempRoot();
    await writeRegularFile(root, 'src/a.ts', 'export {};\n');
    await writeRegularFile(root, 'src/z.ts', 'export {};\n');

    const result = await analyzeSourceTree(
      requestFor(root, {
        probotEntrypoints: ['src/z.ts'],
        limits: limitsFor({ maxSourceWork: 2 }),
      }),
    );

    expect(result.status).toBe('incomplete');
    if (result.status !== 'incomplete') throw new Error('expected an incomplete result');
    expect(result.causes.some((cause) => cause.code === 'source-work-limit')).toBe(true);
  });

  it('returns an incomplete, not failed, result for a designated Probot entrypoint behind an unresolved discovery frontier', async () => {
    const root = await createTempRoot();
    await writeRegularFile(root, 'src/a.ts', 'export {};\n');
    await writeRegularFile(root, 'src/blocked/inner.ts', 'export {};\n');
    fsHooks.readdir = (absolutePath) =>
      isFixture(absolutePath, 'src/blocked') ? new Error('the directory could not be listed') : null;

    // Discovery could not prove this entrypoint absent, so it is not a contradictory request.
    const result = await analyzeSourceTree(requestFor(root, { probotEntrypoints: ['src/blocked/inner.ts'] }));

    expect(result.status).toBe('incomplete');
    if (result.status !== 'incomplete') throw new Error('expected an incomplete result');
    expect(result.causes.some((cause) => cause.code === 'source-discovery-error')).toBe(true);
  });

  it('still fails a contradictory Probot entrypoint when the source universe was fully enumerated', async () => {
    const root = await createTempRoot();
    await writeRegularFile(root, 'src/a.ts', 'export {};\n');

    const result = await analyzeSourceTree(requestFor(root, { probotEntrypoints: ['src/not-discovered.ts'] }));

    expect(result.status).toBe('failed');
    if (result.status !== 'failed') throw new Error('expected a failed result');
    expect(result.reason).toBe('probot-entrypoint-outside-source-universe');
  });
});
