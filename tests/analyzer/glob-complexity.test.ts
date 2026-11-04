import { describe, expect, it } from 'vitest';

import { compileLimitedGlob } from '../../src/analyzer/discovery.js';

/**
 * Hostile-configuration hardening for the limited glob grammar. Include and exclude patterns
 * come from a target repository's `.boundaryci.yml`, so matching must stay polynomial in the
 * pattern and path size: a short pattern must not be able to block the process synchronously,
 * where no elapsed-time budget can interrupt it.
 */

/** Deterministic xorshift32 so the property cases are reproducible without a seed file. */
function prng(seed: number): () => number {
  let state = seed >>> 0 || 1;
  return () => {
    state ^= state << 13;
    state >>>= 0;
    state ^= state >>> 17;
    state ^= state << 5;
    state >>>= 0;
    return state / 0x1_0000_0000;
  };
}

/**
 * Reference semantics: a verbatim copy of the released-v1 segment matcher (one anchored `u`
 * regular expression per segment, recursive `**` expansion). Only used on tiny inputs, where
 * its backtracking is cheap, to prove the hardened matcher accepts exactly the same language.
 */
function referenceSegment(segment: string): RegExp {
  let body = '';
  for (const character of segment) {
    if (character === '*') body += '[^/]*';
    else if (character === '?') body += '[^/]';
    else body += character.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
  }
  return new RegExp(`^${body}$`, 'u');
}

function referenceSegments(patternSegments: readonly string[], pathSegments: readonly string[], p: number, s: number): boolean {
  if (p === patternSegments.length) return s === pathSegments.length;
  const segment = patternSegments[p] as string;
  if (segment === '**') {
    for (let next = s; next <= pathSegments.length; next += 1) {
      if (referenceSegments(patternSegments, pathSegments, p + 1, next)) return true;
    }
    return false;
  }
  if (s >= pathSegments.length) return false;
  if (!referenceSegment(segment).test(pathSegments[s] as string)) return false;
  return referenceSegments(patternSegments, pathSegments, p + 1, s + 1);
}

function referenceMatch(pattern: string, segments: readonly string[]): boolean {
  return referenceSegments(pattern.split('/'), segments, 0, 0);
}

/** Verbatim released-v1 `coversDirectoryPrefix`, using the v1 segment regular expression. */
function referenceCovers(patternSegments: readonly string[], dirSegments: readonly string[], p: number, s: number): boolean {
  if (s === dirSegments.length) return p < patternSegments.length;
  if (p === patternSegments.length) return false;
  const segment = patternSegments[p];
  if (segment === '**') return true;
  if (s >= dirSegments.length) return false;
  const candidate = dirSegments[s];
  if (segment === undefined || candidate === undefined) return false;
  if (!referenceSegment(segment).test(candidate)) return false;
  return referenceCovers(patternSegments, dirSegments, p + 1, s + 1);
}

/** Every string of length 1..maxLength over `alphabet`. */
function allStrings(alphabet: readonly string[], maxLength: number): string[] {
  const out: string[] = [];
  let frontier = [''];
  for (let length = 1; length <= maxLength; length += 1) {
    frontier = frontier.flatMap((prefix) => alphabet.map((character) => prefix + character));
    out.push(...frontier);
  }
  return out;
}

function elapsed(run: () => void): number {
  const started = performance.now();
  run();
  return performance.now() - started;
}

describe('compileLimitedGlob matching complexity', () => {
  it('matches many in-segment stars against a long name without catastrophic backtracking', () => {
    const glob = compileLimitedGlob(`${'*a'.repeat(24)}*b`);
    const name = 'a'.repeat(250);
    let result = true;
    expect(elapsed(() => { result = glob.test([name]); })).toBeLessThan(1_000);
    expect(result).toBe(false);
    expect(glob.test([`${name}b`])).toBe(true);
  });

  it('matches many globstar segments against a deep path without exponential search', () => {
    const glob = compileLimitedGlob(`${Array.from({ length: 32 }, () => '**').join('/')}/z`);
    const path = Array.from({ length: 128 }, () => 'd');
    let result = true;
    expect(elapsed(() => { result = glob.test(path); })).toBeLessThan(1_000);
    expect(result).toBe(false);
    expect(glob.test([...path, 'z'])).toBe(true);
    let excludes = true;
    expect(elapsed(() => { excludes = compileLimitedGlob(`${Array.from({ length: 32 }, () => '**/x').join('/')}/**`).excludesSubtree(path); }))
      .toBeLessThan(1_000);
    expect(excludes).toBe(false);
  });

  it('keeps the existing limited-glob semantics on deterministic random cases', () => {
    const random = prng(0x5eed_2026);
    // Literal regex metacharacters the grammar still admits, case, astral and lone-surrogate
    // code points all exercise the v1 per-code-point `u`-mode semantics.
    const patternAlphabet = ['a', 'b', 'A', '*', '?', '.', '$', '^', '-', ' ', 'é', '\u{1f600}', '\ud800'];
    const nameAlphabet = ['a', 'b', 'A', '.', '$', '^', '-', ' ', 'é', '\u{1f600}', '\ud800', '\udc00'];
    const pick = <T>(values: readonly T[]): T => values[Math.floor(random() * values.length)] as T;
    let matches = 0;
    for (let index = 0; index < 4_000; index += 1) {
      const patternSegments = Array.from({ length: 1 + Math.floor(random() * 4) }, () => {
        if (random() < 0.25) return '**';
        return Array.from({ length: 1 + Math.floor(random() * 4) }, () => pick(patternAlphabet)).join('').replace(/\*\*+/gu, '*').replace(/^\.\.?$/u, 'a$&');
      });
      const pattern = patternSegments.join('/');
      const path = Array.from({ length: 1 + Math.floor(random() * 4) }, () =>
        Array.from({ length: 1 + Math.floor(random() * 4) }, () => pick(nameAlphabet)).join(''));
      const glob = compileLimitedGlob(pattern);
      const expected = referenceMatch(pattern, path);
      if (expected) matches += 1;
      expect({ pattern, path, matched: glob.test(path) }).toEqual({ pattern, path, matched: expected });
      const excludesSubtree = patternSegments.at(-1) === '**' && expected;
      expect({ pattern, path, excludesSubtree: glob.excludesSubtree(path) }).toEqual({ pattern, path, excludesSubtree });
      const dir = path.slice(0, Math.floor(random() * path.length));
      expect({ pattern, dir, covers: glob.coversDirectory(dir) })
        .toEqual({ pattern, dir, covers: referenceCovers(patternSegments, dir, 0, 0) });
    }
    // The generator must exercise both outcomes to be a meaningful equivalence check.
    expect(matches).toBeGreaterThan(200);
  });

  it('agrees with v1 on every single-segment pattern and name in a small exhaustive space', () => {
    // All patterns of length <= 4 over {a, b, *, ?} (single `*` runs only, since `**` inside a
    // segment is rejected) against every name of length <= 5 over {a, b}: 292 x 62 = 18,104 pairs.
    const patterns = allStrings(['a', 'b', '*', '?'], 4).filter((pattern) => !pattern.includes('**'));
    const names = allStrings(['a', 'b'], 5);
    let matched = 0;
    let mismatches = 0;
    for (const pattern of patterns) {
      const glob = compileLimitedGlob(pattern);
      for (const name of names) {
        const expected = referenceMatch(pattern, [name]);
        if (expected) matched += 1;
        if (glob.test([name]) !== expected) mismatches += 1;
      }
    }
    expect(patterns.length * names.length).toBe(18_104);
    expect(mismatches).toBe(0);
    expect(matched).toBeGreaterThan(1_000);
    expect(matched).toBeLessThan(patterns.length * names.length);
  });

  it('agrees with v1 on every multi-segment arrangement of a small pattern alphabet', () => {
    const segmentChoices = ['**', '*', 'a', '?', 'a*'];
    const patterns = allStrings(segmentChoices.map((segment) => `${segment}\0`), 4)
      .map((joined) => joined.slice(0, -1).split('\0').join('/'));
    const paths = allStrings(['a\0', 'b\0', 'ab\0'], 4).map((joined) => joined.slice(0, -1).split('\0'));
    let mismatches = 0;
    for (const pattern of patterns) {
      const glob = compileLimitedGlob(pattern);
      const segments = pattern.split('/');
      for (const path of paths) {
        if (glob.test(path) !== referenceMatch(pattern, path)) mismatches += 1;
        if (glob.coversDirectory(path) !== referenceCovers(segments, path, 0, 0)) mismatches += 1;
        if (glob.excludesSubtree(path) !== (segments.at(-1) === '**' && referenceMatch(pattern, path))) mismatches += 1;
      }
    }
    expect(patterns.length).toBe(780);
    expect(paths.length).toBe(120);
    expect(mismatches).toBe(0);
  });
});
