/**
 * Deterministic bounded regular-file discovery for the BoundaryCI static analyzer.
 *
 * `discoverSources` canonicalizes a trusted root exactly once, then walks it by listing each
 * directory's entry names and inspecting every one of them with `lstat`: symbolic links are
 * identified without ever being followed, and a descendant path is never re-resolved with a
 * following `stat`. Only actual regular files, as `lstat` reports them, are read. Discovery
 * never inspects target package metadata, `tsconfig`, lockfiles, installed dependencies, or
 * runtime loaders, and it never executes, imports, transpiles, builds, or spawns anything
 * from the analyzed tree.
 *
 * The discovered source universe is exactly the six extensions named by
 * {@link ANALYZER_SOURCE_EXTENSIONS}: declaration files, `.cjs`, `.cts`, and every
 * `node_modules` path segment never participate. `.cjs -> .cts` is a resolver mapping owned
 * by a later plan; this module proves only that neither suffix enters discovery.
 *
 * File-count, byte, and work budgets are charged in bytewise-sorted root-relative POSIX
 * order, after the deterministic source universe has been established and before any file is
 * read for analysis. `maxSourceFileBytes` is a file-scoped budget: an oversized file is
 * individually omitted and independent sorted files continue. `maxSourceFiles`,
 * `maxTotalSourceBytes`, and `maxSourceWork` are scan-wide frontiers: once exhausted, already
 * accepted sources are preserved and later dependent work stops. Every frontier is recorded
 * as uncertainty, never as evidence that an unprocessed source is absent. An accepted regular
 * file's bytes are read here, once, after its budget decisions; the accepted byte size and
 * scan-wide byte accounting are bound to those bytes as actually returned, not to a stat size
 * a later reader might not see. Because a stat size is not a promise about what a later read
 * returns, both byte budgets are re-decided against the bytes `readFile` actually returned, so
 * no source is ever accepted or charged on a size the reader did not observe. No filesystem
 * race is guarded against.
 */

import { lstat, readFile, readdir, realpath, stat } from 'node:fs/promises';
import { join } from 'node:path';

import { ANALYSIS_DISCOVERY_PROFILE_ID, ANALYZER_SOURCE_EXTENSIONS } from './contract.js';
import type { AnalysisFailureReason, AnalysisLimits, AnalyzerCauseResource } from './contract.js';

/** Discovery/glob policy identity, re-exported from the single canonical source of truth. */
export const DISCOVERY_POLICY_IDENTITY = ANALYSIS_DISCOVERY_PROFILE_ID;

const UNINTERPRETED_GLOB_OPERATOR = /[!{}[\]()+@|]/u;

function compareBytes(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

function assertValidPatternSegments(pattern: string): readonly string[] {
  if (typeof pattern !== 'string' || pattern.length === 0) {
    throw new TypeError('a limited glob pattern must be a non-empty string');
  }
  if (pattern.startsWith('/')) throw new TypeError('a limited glob pattern must be root-relative');
  if (pattern.includes('\\')) throw new TypeError('a limited glob pattern must not contain a backslash');
  if (UNINTERPRETED_GLOB_OPERATOR.test(pattern)) {
    throw new TypeError('a limited glob pattern contains an uninterpreted glob operator');
  }
  const segments = pattern.split('/');
  for (const segment of segments) {
    if (segment.length === 0 || segment === '.' || segment === '..') {
      throw new TypeError('a limited glob pattern must not contain an empty, current, or parent segment');
    }
    if (segment.includes('**') && segment !== '**') {
      throw new TypeError('a limited glob pattern may use ** only as a whole segment');
    }
  }
  return segments;
}

/**
 * Matches one path segment against one pattern segment, given as code points, where `*` matches
 * zero or more non-separator code points and `?` exactly one; every other code point is literal.
 *
 * Patterns come from hostile repository configuration, so this deliberately avoids regular
 * expression backtracking: the classic single-resume wildcard scan only ever retries from the
 * most recent `*`, bounding work by pattern length times candidate length.
 */
function segmentMatches(pattern: readonly string[], candidate: string): boolean {
  if (candidate.includes('/')) return false;
  const text = Array.from(candidate);
  let p = 0;
  let t = 0;
  let star = -1;
  let resume = 0;
  while (t < text.length) {
    const token = pattern[p];
    if (token === '*') {
      star = p;
      resume = t;
      p += 1;
    } else if (token !== undefined && (token === '?' || token === text[t])) {
      p += 1;
      t += 1;
    } else if (star !== -1) {
      p = star + 1;
      resume += 1;
      t = resume;
    } else {
      return false;
    }
  }
  while (pattern[p] === '*') p += 1;
  return p === pattern.length;
}

/**
 * Whole-path matching where `**` absorbs zero or more complete segments. It tracks the set of
 * path prefixes each pattern prefix can reach instead of recursively re-exploring every `**`
 * split, so adjacent globstars cannot cause exponential work.
 */
function matchSegments(
  patternSegments: readonly string[],
  patternTokens: readonly (readonly string[])[],
  pathSegments: readonly string[],
): boolean {
  const width = pathSegments.length + 1;
  let reachable = new Array<boolean>(width).fill(false);
  reachable[0] = true;
  for (let p = 0; p < patternSegments.length; p += 1) {
    const next = new Array<boolean>(width).fill(false);
    if (patternSegments[p] === '**') {
      let running = false;
      for (let s = 0; s < width; s += 1) {
        running ||= reachable[s] === true;
        next[s] = running;
      }
    } else {
      const tokens = patternTokens[p];
      if (tokens === undefined) return false;
      for (let s = 0; s < pathSegments.length; s += 1) {
        const candidate = pathSegments[s];
        if (reachable[s] === true && candidate !== undefined && segmentMatches(tokens, candidate)) next[s + 1] = true;
      }
    }
    reachable = next;
  }
  return reachable[pathSegments.length] === true;
}

/**
 * Determines whether a directory reached during traversal could still contain a path that
 * `patternSegments` matches, without requiring the full remaining subtree to be enumerated.
 *
 * A `**` segment always answers "yes": it matches zero or more full segments and therefore
 * covers any depth beyond the directory it is evaluated at.
 */
function coversDirectoryPrefix(
  patternSegments: readonly string[],
  dirSegments: readonly string[],
  p: number,
  s: number,
): boolean {
  if (s === dirSegments.length) return p < patternSegments.length;
  if (p === patternSegments.length) return false;
  const segment = patternSegments[p];
  if (segment === '**') return true;
  if (s >= dirSegments.length) return false;
  const candidate = dirSegments[s];
  if (segment === undefined || candidate === undefined) return false;
  if (!segmentMatches(Array.from(segment), candidate)) return false;
  return coversDirectoryPrefix(patternSegments, dirSegments, p + 1, s + 1);
}

/** One compiled limited-glob pattern, per {@link DISCOVERY_POLICY_IDENTITY}. */
export interface CompiledGlob {
  readonly source: string;
  readonly segments: readonly string[];
  test(pathSegments: readonly string[]): boolean;
  coversDirectory(dirSegments: readonly string[]): boolean;
  /**
   * Whether this pattern proves that *every* path beneath `dirSegments` matches it.
   *
   * Under the limited grammar that holds exactly when the pattern ends in a whole-segment
   * `**` that already matches the directory itself: `**` absorbs the directory's remaining
   * segments and every deeper segment alike. A pattern such as `src/*` matches the directory
   * `src/nested` without matching `src/nested/app.ts`, so it proves nothing about the subtree
   * and answers `false`.
   */
  excludesSubtree(dirSegments: readonly string[]): boolean;
}

const COMPILED_GLOB_CACHE = new Map<string, CompiledGlob>();

/**
 * Compiles one pattern under the deliberately finite limited-glob grammar: literal path
 * characters; `*` and `?` within one segment; `**` only as a complete segment; and `/` as the
 * sole separator. Absolute patterns, traversal segments, backslashes, negation, braces,
 * character classes, extglobs, empty patterns, and malformed `**` placement are rejected.
 */
export function compileLimitedGlob(pattern: string): CompiledGlob {
  const cached = COMPILED_GLOB_CACHE.get(pattern);
  if (cached !== undefined) return cached;
  const segments = assertValidPatternSegments(pattern);
  const tokens = Object.freeze(segments.map((segment) => Object.freeze(Array.from(segment))));
  const compiled: CompiledGlob = {
    source: pattern,
    segments,
    test(pathSegments) {
      return matchSegments(segments, tokens, pathSegments);
    },
    coversDirectory(dirSegments) {
      return coversDirectoryPrefix(segments, dirSegments, 0, 0);
    },
    excludesSubtree(dirSegments) {
      return segments[segments.length - 1] === '**' && matchSegments(segments, tokens, dirSegments);
    },
  };
  COMPILED_GLOB_CACHE.set(pattern, compiled);
  return compiled;
}

function hasSourceExtension(path: string): boolean {
  if (path.endsWith('.d.ts') || path.endsWith('.d.mts')) return false;
  return ANALYZER_SOURCE_EXTENSIONS.some((extension) => path.endsWith(extension));
}

/**
 * Identifies one discovered, budget-approved regular source file.
 *
 * `bytes` are the exact bytes discovery itself read from this source, after its budget
 * decisions passed; `byteSize` is `bytes.byteLength`. Callers must not reopen the file.
 */
export interface DiscoveredSource {
  path: string;
  byteSize: number;
  bytes: Buffer;
}

export type DiscoveryCauseCode =
  | 'matching-non-regular-entry'
  | 'matching-source-symlink'
  | 'relevant-directory-symlink'
  | 'source-byte-limit'
  | 'source-discovery-error'
  | 'source-file-limit'
  | 'source-read-error'
  | 'source-work-limit';

/** One discovery-scoped diagnostic; carries no `id` or `span`, both assigned by the caller. */
export interface DiscoveryCause {
  code: DiscoveryCauseCode;
  scope: 'repository' | 'source';
  path: string | null;
  resource: AnalyzerCauseResource | null;
  detail: string;
}

export interface DiscoverySuccess {
  status: 'discovered';
  /** The canonicalized absolute root, resolved exactly once. */
  rootPath: string;
  /**
   * The complete deterministic, bytewise-sorted `any(include) - any(exclude)` regular-file
   * source universe, independent of file-count/byte/work budgets. Used to validate Probot
   * entrypoint membership against the declared boundary rather than against a
   * budget-truncated read list.
   */
  effectiveSources: readonly string[];
  /** The budget-approved subset of `effectiveSources`, in the same bytewise sorted order. */
  sources: readonly DiscoveredSource[];
  causes: readonly DiscoveryCause[];
  /**
   * `true` only when nothing prevented the complete `any(include) - any(exclude)` universe
   * beneath the root from being enumerated: neither `maxSourceWork` stopping traversal nor a
   * relevant entry or nested directory that could not be inspected or traversed. `false` means
   * `effectiveSources` is a partial view of an unknown universe: absence of a path from it is
   * uncertainty, never proof that the path does not exist.
   *
   * A symlink or non-regular entry that *was* classified does not make the universe uncertain:
   * the no-follow, regular-file-only policy positively establishes that it does not
   * participate, and its own cause already carries that fact.
   */
  universeComplete: boolean;
}

export interface DiscoveryFailure {
  status: 'failed';
  reason: AnalysisFailureReason;
  detail: string;
}

export type DiscoveryResult = DiscoverySuccess | DiscoveryFailure;

/** One entry that survived `lstat` classification as a matched regular file, with its size. */
interface MatchedSource {
  path: string;
  byteSize: number;
}

interface WalkState {
  matched: MatchedSource[];
  causes: DiscoveryCause[];
  workConsumed: number;
  workExhausted: boolean;
  workFrontier: string | null;
  /**
   * `true` once an entry or nested directory that could still have contributed an included
   * source could not be inspected or traversed, so the effective universe beneath it is
   * unknown rather than known to be empty.
   */
  enumerationBlocked: boolean;
}

/**
 * Walks one canonicalized directory tree in deterministic, bytewise-sorted-child order.
 *
 * Every entry inspected — file, directory, symlink, or other — charges one work unit before
 * it is classified. Once the work budget is exhausted, traversal stops immediately and the
 * entry that would have exceeded the budget becomes the deterministic frontier; it is not
 * itself charged, because it was never actually inspected.
 *
 * Every entry is classified with its own `lstat`, never a following `stat`, so a symbolic
 * link is identified without ever being resolved. An entry or nested directory that cannot be
 * inspected does not fail discovery: it is recorded as one scoped `source-discovery-error`
 * when its frontier could still be relevant, traversal continues with everything else, and
 * the enumerated universe becomes uncertain because nothing proves what that frontier held.
 *
 * A directory is pruned only when pruning cannot hide an included source: `node_modules`
 * never participates, and an exclude pattern prunes a directory only when it proves the whole
 * subtree excluded. Excludes that merely match the directory path are applied per source path
 * instead, because `any(include) - any(exclude)` is a predicate over files, not directories.
 */
async function walk(
  state: WalkState,
  absoluteDirectory: string,
  relativeDirectory: string,
  includeGlobs: readonly CompiledGlob[],
  excludeGlobs: readonly CompiledGlob[],
  maxSourceWork: number,
): Promise<void> {
  if (state.workExhausted) return;

  const isExcluded = (segments: readonly string[]): boolean => excludeGlobs.some((glob) => glob.test(segments));
  const prunesDirectory = (segments: readonly string[]): boolean => {
    if (segments.includes('node_modules')) return true;
    return excludeGlobs.some((glob) => glob.excludesSubtree(segments));
  };
  const isRelevantFile = (path: string, segments: readonly string[]): boolean =>
    hasSourceExtension(path) &&
    !segments.includes('node_modules') &&
    includeGlobs.some((glob) => glob.test(segments)) &&
    !isExcluded(segments);
  const isRelevantDirectoryFrontier = (segments: readonly string[]): boolean =>
    !prunesDirectory(segments) && includeGlobs.some((glob) => glob.coversDirectory(segments));

  const names = await readdir(absoluteDirectory);
  names.sort(compareBytes);

  for (const name of names) {
    if (state.workExhausted) return;
    state.workConsumed += 1;
    const relative = relativeDirectory === '' ? name : `${relativeDirectory}/${name}`;
    if (state.workConsumed > maxSourceWork) {
      state.workExhausted = true;
      state.workFrontier = relative;
      state.workConsumed -= 1;
      return;
    }

    const segments = relative.split('/');
    const absoluteEntry = join(absoluteDirectory, name);

    let entryStat: Awaited<ReturnType<typeof lstat>>;
    try {
      entryStat = await lstat(absoluteEntry);
    } catch {
      if (isRelevantFile(relative, segments) || isRelevantDirectoryFrontier(segments)) {
        state.enumerationBlocked = true;
        state.causes.push({
          code: 'source-discovery-error',
          scope: 'source',
          path: relative,
          resource: null,
          detail: 'a filesystem entry could not be inspected and was excluded from the discovered source universe',
        });
      }
      continue;
    }

    if (entryStat.isSymbolicLink()) {
      if (segments.includes('node_modules')) continue;
      if (isRelevantFile(relative, segments)) {
        state.causes.push({
          code: 'matching-source-symlink',
          scope: 'source',
          path: relative,
          resource: null,
          detail: 'a symbolic link matched the effective source pattern and was not followed or read',
        });
        continue;
      }
      if (isRelevantDirectoryFrontier(segments)) {
        state.causes.push({
          code: 'relevant-directory-symlink',
          scope: 'source',
          path: relative,
          resource: null,
          detail: 'a symbolic link directory frontier could contain an included source and was not followed',
        });
      }
      continue;
    }

    if (entryStat.isDirectory()) {
      if (prunesDirectory(segments)) continue;
      try {
        await walk(state, absoluteEntry, relative, includeGlobs, excludeGlobs, maxSourceWork);
      } catch {
        if (isRelevantDirectoryFrontier(segments)) {
          state.enumerationBlocked = true;
          state.causes.push({
            code: 'source-discovery-error',
            scope: 'source',
            path: relative,
            resource: null,
            detail: 'a nested directory could not be traversed and was excluded from the discovered source universe',
          });
        }
      }
      continue;
    }

    if (!entryStat.isFile()) {
      if (isRelevantFile(relative, segments)) {
        state.causes.push({
          code: 'matching-non-regular-entry',
          scope: 'source',
          path: relative,
          resource: null,
          detail: 'a non-regular filesystem entry matched the effective source pattern and was not read',
        });
      }
      continue;
    }

    if (isRelevantFile(relative, segments)) state.matched.push({ path: relative, byteSize: entryStat.size });
  }
}

/**
 * Discovers the exact deterministic regular-file source universe beneath a trusted root.
 *
 * The root is canonicalized exactly once; a missing, unresolvable, or non-directory root
 * fails. Traversal never follows a descendant symbolic link. File-count and byte budgets are
 * charged in bytewise-sorted order after the complete universe is known; the work budget is
 * charged per filesystem entry during traversal itself, so it can stop discovery before the
 * complete universe is known — in that case `effectiveSources` reflects only what traversal
 * reached before the frontier. A relevant entry that could not be inspected or traversed
 * leaves the universe equally unknown, and both cases report `universeComplete: false`.
 */
export async function discoverSources(
  rootPath: string,
  include: readonly string[],
  exclude: readonly string[],
  limits: Pick<AnalysisLimits, 'maxSourceFileBytes' | 'maxSourceFiles' | 'maxSourceWork' | 'maxTotalSourceBytes'>,
): Promise<DiscoveryResult> {
  let canonicalRoot: string;
  try {
    canonicalRoot = await realpath(rootPath);
  } catch {
    return { status: 'failed', reason: 'unresolvable-analysis-root', detail: 'the analysis root could not be canonicalized' };
  }
  let rootStat;
  try {
    rootStat = await stat(canonicalRoot);
  } catch {
    return { status: 'failed', reason: 'unresolvable-analysis-root', detail: 'the analysis root could not be canonicalized' };
  }
  if (!rootStat.isDirectory()) {
    return { status: 'failed', reason: 'analysis-root-not-a-directory', detail: 'the analysis root is not a directory' };
  }

  let includeGlobs: CompiledGlob[];
  let excludeGlobs: CompiledGlob[];
  try {
    includeGlobs = include.map((pattern) => compileLimitedGlob(pattern));
    excludeGlobs = exclude.map((pattern) => compileLimitedGlob(pattern));
  } catch (error) {
    const message = error instanceof TypeError ? error.message : 'an include or exclude pattern is invalid';
    return { status: 'failed', reason: 'invalid-analysis-request', detail: message };
  }

  const state: WalkState = {
    matched: [],
    causes: [],
    workConsumed: 0,
    workExhausted: false,
    workFrontier: null,
    enumerationBlocked: false,
  };
  try {
    await walk(state, canonicalRoot, '', includeGlobs, excludeGlobs, limits.maxSourceWork);
  } catch {
    return { status: 'failed', reason: 'unresolvable-analysis-root', detail: 'the analysis root could not be traversed' };
  }

  state.matched.sort((left, right) => compareBytes(left.path, right.path));

  if (state.workExhausted) {
    state.causes.push({
      code: 'source-work-limit',
      scope: 'repository',
      path: null,
      resource: {
        limitKey: 'maxSourceWork',
        configured: limits.maxSourceWork,
        consumed: state.workConsumed,
        frontier: state.workFrontier,
        processedSources: state.matched.length,
        unprocessedSources: null,
      },
      detail: `the discovery work budget of ${String(limits.maxSourceWork)} stopped traversal after ${String(state.workConsumed)} filesystem entries`,
    });
  }

  const accepted: DiscoveredSource[] = [];
  let consumedBytes = 0;

  /** File-scoped omission evidence, reporting the exact byte count the decision was made on. */
  const sourceByteLimitCause = (path: string, byteSize: number): DiscoveryCause => ({
    code: 'source-byte-limit',
    scope: 'source',
    path,
    resource: {
      limitKey: 'maxSourceFileBytes',
      configured: limits.maxSourceFileBytes,
      consumed: byteSize,
      frontier: path,
      processedSources: null,
      unprocessedSources: null,
    },
    detail: `the source exceeds the per-file byte budget of ${String(limits.maxSourceFileBytes)} bytes`,
  });

  /** Scan-wide byte frontier evidence, reporting the bytes actually accepted before the stop. */
  const totalByteLimitCause = (path: string): DiscoveryCause => ({
    code: 'source-byte-limit',
    scope: 'repository',
    path: null,
    resource: {
      limitKey: 'maxTotalSourceBytes',
      configured: limits.maxTotalSourceBytes,
      consumed: consumedBytes,
      frontier: path,
      processedSources: accepted.length,
      unprocessedSources: state.matched.length - accepted.length,
    },
    detail: `the scan byte budget of ${String(limits.maxTotalSourceBytes)} stopped analysis before ${path} after ${String(consumedBytes)} bytes`,
  });

  for (const candidate of state.matched) {
    const path = candidate.path;
    if (accepted.length >= limits.maxSourceFiles) {
      state.causes.push({
        code: 'source-file-limit',
        scope: 'repository',
        path: null,
        resource: {
          limitKey: 'maxSourceFiles',
          configured: limits.maxSourceFiles,
          consumed: accepted.length,
          frontier: path,
          processedSources: accepted.length,
          unprocessedSources: state.matched.length - accepted.length,
        },
        detail: `the source-file budget of ${String(limits.maxSourceFiles)} stopped analysis before ${path}`,
      });
      break;
    }

    // The stat size only prechecks: it avoids opening a file already known to be oversized,
    // and it is never the final decision, because it is not a promise about the bytes a later
    // read returns.
    if (candidate.byteSize > limits.maxSourceFileBytes) {
      state.causes.push(sourceByteLimitCause(path, candidate.byteSize));
      continue;
    }

    if (consumedBytes + candidate.byteSize > limits.maxTotalSourceBytes) {
      state.causes.push(totalByteLimitCause(path));
      break;
    }

    let bytes: Buffer;
    try {
      bytes = await readFile(join(canonicalRoot, ...path.split('/')));
    } catch {
      state.causes.push({
        code: 'source-read-error',
        scope: 'source',
        path,
        resource: null,
        detail: 'an accepted source could not be read as a regular file',
      });
      continue;
    }

    // Both byte budgets are decided again on the bytes actually returned, so nothing larger
    // than a configured limit is ever accepted or charged on a size no reader observed.
    if (bytes.byteLength > limits.maxSourceFileBytes) {
      state.causes.push(sourceByteLimitCause(path, bytes.byteLength));
      continue;
    }

    if (consumedBytes + bytes.byteLength > limits.maxTotalSourceBytes) {
      state.causes.push(totalByteLimitCause(path));
      break;
    }

    consumedBytes += bytes.byteLength;
    accepted.push({ path, byteSize: bytes.byteLength, bytes });
  }

  return {
    status: 'discovered',
    rootPath: canonicalRoot,
    effectiveSources: state.matched.map((entry) => entry.path),
    sources: accepted,
    causes: state.causes,
    universeComplete: !state.workExhausted && !state.enumerationBlocked,
  };
}
