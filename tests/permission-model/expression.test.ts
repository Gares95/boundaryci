import { describe, expect, it } from 'vitest';

import {
  canonicalizeRequirementExpression,
  requirementExpressionJson,
  validateRequirementExpression,
  type RequirementExpression,
} from '../../src/permission-model/model.js';

const ISSUES_READ: RequirementExpression = { type: 'permission', permission: 'issues', level: 'read' };
const ISSUES_WRITE: RequirementExpression = { type: 'permission', permission: 'issues', level: 'write' };
const CONTENTS_READ: RequirementExpression = { type: 'permission', permission: 'contents', level: 'read' };
const METADATA_READ: RequirementExpression = { type: 'permission', permission: 'metadata', level: 'read' };

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function group(type: 'allOf' | 'anyOf', ...requirements: RequirementExpression[]): RequirementExpression {
  return { type, requirements };
}

function countAtoms(expression: RequirementExpression): number {
  return expression.type === 'permission'
    ? 1
    : expression.requirements.reduce((total, child) => total + countAtoms(child), 0);
}

describe('requirement expression canonicalization', () => {
  it('returns an equal deep copy of an atom without sharing the input reference', () => {
    const canonical = canonicalizeRequirementExpression(ISSUES_READ);
    expect(canonical).toEqual(ISSUES_READ);
    expect(canonical).not.toBe(ISSUES_READ);
  });

  it('orders children by canonical bytes recursively without flattening nested groups', () => {
    const canonical = canonicalizeRequirementExpression(
      group('allOf', group('anyOf', ISSUES_WRITE, CONTENTS_READ), ISSUES_READ, METADATA_READ),
    );
    expect(canonical).toEqual(
      group('allOf', ISSUES_READ, METADATA_READ, group('anyOf', CONTENTS_READ, ISSUES_WRITE)),
    );
    if (canonical.type !== 'allOf') throw new Error('expected an allOf root');
    expect(canonical.requirements).toHaveLength(3);
    expect(canonical.requirements[2]).toMatchObject({ type: 'anyOf' });
  });

  it('preserves repeated children and repeated identical groups', () => {
    const alternative = group('anyOf', ISSUES_READ, CONTENTS_READ);
    const canonical = canonicalizeRequirementExpression(
      group('allOf', ISSUES_WRITE, alternative, ISSUES_WRITE, clone(alternative), ISSUES_READ),
    );
    if (canonical.type !== 'allOf') throw new Error('expected an allOf root');
    expect(canonical.requirements).toHaveLength(5);
    expect(canonical.requirements).toEqual([
      ISSUES_READ,
      ISSUES_WRITE,
      ISSUES_WRITE,
      group('anyOf', CONTENTS_READ, ISSUES_READ),
      group('anyOf', CONTENTS_READ, ISSUES_READ),
    ]);
    expect(countAtoms(canonical)).toBe(7);
  });

  it('preserves every node of a deeply nested tree', () => {
    const deep = group(
      'anyOf',
      group('allOf', METADATA_READ, group('anyOf', ISSUES_WRITE, ISSUES_READ)),
      CONTENTS_READ,
      group('allOf', CONTENTS_READ, CONTENTS_READ),
    );
    const canonical = canonicalizeRequirementExpression(deep);
    expect(countAtoms(canonical)).toBe(countAtoms(deep));
    if (canonical.type !== 'anyOf') throw new Error('expected an anyOf root');
    expect(canonical.requirements[0]).toEqual(CONTENTS_READ);
    expect(canonical.requirements[1]).toEqual(group('allOf', CONTENTS_READ, CONTENTS_READ));
    expect(canonical.requirements[2]).toEqual(
      group('allOf', METADATA_READ, group('anyOf', ISSUES_READ, ISSUES_WRITE)),
    );
  });

  it('never mutates the caller expression while canonicalizing', () => {
    const input = group('allOf', ISSUES_WRITE, CONTENTS_READ, group('anyOf', METADATA_READ, ISSUES_READ));
    const before = JSON.stringify(input);
    canonicalizeRequirementExpression(input);
    expect(JSON.stringify(input)).toBe(before);
  });

  it('is idempotent and byte-stable across repeated execution and JSON reload', () => {
    const input = group('allOf', ISSUES_WRITE, group('anyOf', METADATA_READ, CONTENTS_READ), ISSUES_READ);
    const once = canonicalizeRequirementExpression(input);
    expect(canonicalizeRequirementExpression(once)).toEqual(once);
    const json = requirementExpressionJson(input);
    expect(requirementExpressionJson(input)).toBe(json);
    const reloaded: unknown = JSON.parse(JSON.stringify(once));
    validateRequirementExpression(reloaded);
    expect(requirementExpressionJson(reloaded)).toBe(json);
    expect(requirementExpressionJson(ISSUES_READ)).toBe('{"level":"read","permission":"issues","type":"permission"}');
  });
});

describe('requirement expression validation', () => {
  it('accepts canonical atoms, groups, and repeated children as valid data', () => {
    for (const value of [
      ISSUES_READ,
      ISSUES_WRITE,
      group('allOf', ISSUES_READ, ISSUES_READ),
      group('anyOf', CONTENTS_READ, ISSUES_WRITE),
      group('allOf', ISSUES_READ, ISSUES_WRITE, group('anyOf', CONTENTS_READ, METADATA_READ)),
    ]) {
      expect(() => validateRequirementExpression(clone(value))).not.toThrow();
    }
  });

  it('rejects a noncanonical order instead of silently canonicalizing it', () => {
    const noncanonical = group('allOf', ISSUES_WRITE, ISSUES_READ);
    const before = JSON.stringify(noncanonical);
    expect(() => validateRequirementExpression(noncanonical)).toThrow(TypeError);
    expect(JSON.stringify(noncanonical)).toBe(before);
    expect(() => canonicalizeRequirementExpression(noncanonical)).not.toThrow();
  });

  it('rejects a noncanonical order nested inside an otherwise canonical group', () => {
    expect(() =>
      validateRequirementExpression(group('allOf', ISSUES_READ, group('anyOf', ISSUES_WRITE, CONTENTS_READ))),
    ).toThrow(TypeError);
  });

  it('rejects every malformed shape for both validation and canonicalization', () => {
    const malformed: unknown[] = [
      null,
      undefined,
      'issues',
      42,
      [],
      [ISSUES_READ],
      {},
      { type: 'permission', permission: 'issues' },
      { type: 'permission', level: 'read' },
      { type: 'permission', permission: 'issues', level: 'read', scope: 'repository' },
      { type: 'permission', permission: '', level: 'read' },
      { type: 'permission', permission: 'issues', level: 'admin' },
      { type: 'permission', permission: 'issues', level: 'none' },
      { type: 'permission', permission: ['issues'], level: 'read' },
      { type: 'oneOf', requirements: [ISSUES_READ, ISSUES_WRITE] },
      { type: 'allOf' },
      { type: 'allOf', requirements: {} },
      { type: 'allOf', requirements: [] },
      { type: 'allOf', requirements: [ISSUES_READ] },
      { type: 'allOf', requirements: [ISSUES_READ, ISSUES_WRITE], label: 'combined' },
      { type: 'anyOf', requirements: [ISSUES_READ, { type: 'permission', permission: 'issues' }] },
      { type: 'anyOf', requirements: [ISSUES_READ, { type: 'allOf', requirements: [CONTENTS_READ] }] },
    ];
    for (const value of malformed) {
      expect(() => validateRequirementExpression(value)).toThrow(TypeError);
      expect(() => canonicalizeRequirementExpression(value as RequirementExpression)).toThrow(TypeError);
    }
  });

  it('reports a nested path in its rejection detail', () => {
    expect(() =>
      validateRequirementExpression({
        type: 'allOf',
        requirements: [ISSUES_READ, { type: 'anyOf', requirements: [CONTENTS_READ, { type: 'permission' }] }],
      }),
    ).toThrow(/requirements\[1\]\.requirements\[1\]/u);
  });
});
