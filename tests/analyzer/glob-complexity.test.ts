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
    const patternAlphabet = ['a', 'b', '*', '?', '.', 'é', '\u{1f600}'];
    const nameAlphabet = ['a', 'b', '.', 'é', '\u{1f600}'];
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
    }
    // The generator must exercise both outcomes to be a meaningful equivalence check.
    expect(matches).toBeGreaterThan(200);
  });
});
