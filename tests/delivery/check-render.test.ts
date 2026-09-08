import { describe, expect, it } from 'vitest';

import {
  CHECK_ANNOTATION_LIMIT,
  CHECK_DETAILS_RECORD_LIMIT,
  CHECK_DETAILS_UTF8_LIMIT,
  CHECK_SUMMARY_UTF8_LIMIT,
  renderCompletedCheck,
  selectCheckAnnotations,
} from '../../src/delivery/check-render.js';
import type { CheckAnnotationV1 } from '../../src/delivery/check-contract.js';

function annotation(index: number, level: CheckAnnotationV1['level'] = 'notice'): CheckAnnotationV1 {
  return {
    path: `src/${String(999 - index).padStart(3, '0')}-@[]#${index}.ts`,
    startLine: index + 1,
    endLine: index + 1,
    level,
    title: level === 'failure' ? 'Permission policy failure' : level === 'warning' ? 'Incomplete analysis evidence' : 'Permitted permission expansion',
    message: `issues/create annotation ${index}`,
    operationId: 'issues/create',
  };
}

describe('Phase 6 renderer matrix', () => {
  it('exports the finite renderer bounds and annotation selector', () => {
    expect(renderCompletedCheck).toBeTypeOf('function');
    expect(selectCheckAnnotations).toBeTypeOf('function');
    expect(CHECK_SUMMARY_UTF8_LIMIT).toBe(60_000);
    expect(CHECK_DETAILS_UTF8_LIMIT).toBe(60_000);
    expect(CHECK_DETAILS_RECORD_LIMIT).toBe(500);
    expect(CHECK_ANNOTATION_LIMIT).toBe(50);
  });

  it.each([0, 49, 50, 51, 250, 251])('selects the deterministic first 50 from %i eligible annotations', (count) => {
    const candidates = Array.from({ length: count }, (_, index) => annotation(index));
    const before = structuredClone(candidates);
    const selected = selectCheckAnnotations(candidates);

    expect(selected).toHaveLength(Math.min(count, CHECK_ANNOTATION_LIMIT));
    expect(candidates).toEqual(before);
    expect(selected.map((entry) => entry.path)).toEqual([...selected].map((entry) => entry.path).sort());
    expect(count - selected.length).toBe(Math.max(0, count - CHECK_ANNOTATION_LIMIT));
  });

  it('sorts by severity before normalized source navigation fields and does not retain caller references', () => {
    const candidates = [annotation(8, 'notice'), annotation(3, 'warning'), annotation(1, 'failure')];
    const selected = selectCheckAnnotations(candidates);

    expect(selected.map((entry) => entry.level)).toEqual(['failure', 'warning', 'notice']);
    expect(selected[0]).not.toBe(candidates[2]);
    expect(Object.isFrozen(selected)).toBe(true);
    expect(Object.isFrozen(selected[0])).toBe(true);
  });

  it('rejects unknown fields and non-truthful navigation paths rather than emitting them', () => {
    expect(() => selectCheckAnnotations([{ ...annotation(1), token: 'renderer-secret-sentinel' }] as unknown as CheckAnnotationV1[])).toThrow(TypeError);
    expect(() => selectCheckAnnotations([{ ...annotation(1), path: '../outside.ts' }])).toThrow(TypeError);
    expect(() => selectCheckAnnotations([{ ...annotation(1), path: '/absolute.ts' }])).toThrow(TypeError);
  });
});
