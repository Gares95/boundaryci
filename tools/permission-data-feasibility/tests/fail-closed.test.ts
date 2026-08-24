import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { parseBoundedJson } from '../artifact-sources.js';
import type { UnresolvedOperationReason } from '../contracts.js';
import {
  buildIncompleteSemantics,
  describeIncomplete,
  INCOMPLETE_REASONS,
  mapExpressionReason,
  mapOperationResolutionReason,
  validateIncompleteSemantics,
  type IncompleteReason,
} from '../fail-closed.js';
import type { PermissionEvidenceIncompleteReason } from '../requirement-expression.js';

const PROJECT_ROOT = fileURLToPath(new URL('../../../', import.meta.url));

describe('fail-closed incomplete semantics', () => {
  it('maps every reason to stable incomplete wording without a clean or supported result', () => {
    expect(new Set(INCOMPLETE_REASONS).size).toBe(INCOMPLETE_REASONS.length);
    for (const reason of INCOMPLETE_REASONS) {
      const description = describeIncomplete(reason);
      expect(description).toEqual({
        code: reason,
        outcome: 'incomplete-analysis',
        summary: expect.any(String),
        explanation: expect.stringContaining('cannot be proven'),
      });
      expect(description).not.toHaveProperty('requirement');
      expect(description.explanation).not.toMatch(/no permission changes|boundary is complete|least privilege is proven/iu);
      expect(description.explanation).toContain('No unqualified clean or no-change conclusion is available.');
      expect(description.explanation).not.toMatch(/infrastructure failure|runtime failure|configuration failure/iu);
    }
  });

  it('covers every operation-resolution and expression-parser reason', () => {
    const operationReasons: UnresolvedOperationReason[] = [
      'artifact-manifest-digest-mismatch',
      'endpoint-method-duplicate',
      'endpoint-method-missing-runtime',
      'endpoint-method-missing-standalone',
      'endpoint-route-invalid',
      'openapi-operation-duplicate',
      'openapi-operation-missing',
      'permission-evidence-mismatch',
      'permission-evidence-missing',
      'permission-source-digest-mismatch',
      'runtime-surface-incompatibility',
    ];
    const expressionReasons: PermissionEvidenceIncompleteReason[] = [
      'conflicting-permission-atom',
      'credential-class-missing',
      'duplicate-permission-atom',
      'empty-alternative',
      'empty-expression',
      'malformed-atom',
      'operation-missing',
      'unknown-access-level',
      'unknown-permission',
      'unsupported-qualifier',
    ];
    for (const reason of operationReasons) expect(INCOMPLETE_REASONS).toContain(mapOperationResolutionReason(reason));
    for (const reason of expressionReasons) expect(INCOMPLETE_REASONS).toContain(mapExpressionReason(reason));
  });

  it('commits exactly the exhaustive definition set and rejects unknown definitions', () => {
    const built = buildIncompleteSemantics();
    expect(() => validateIncompleteSemantics(built)).not.toThrow();
    const committed = parseBoundedJson(
      PROJECT_ROOT,
      'tools/permission-data-feasibility/evidence/incomplete-semantics.json',
      2 * 1024 * 1024,
    );
    expect(committed).toEqual(built);
    expect(() => describeIncomplete('future-unknown' as IncompleteReason)).toThrow(/unmapped incomplete reason/u);

    const mutated = structuredClone(built);
    const first = mutated.definitions[0];
    if (first !== undefined) first.outcome = 'incomplete-analysis';
    mutated.definitions.pop();
    expect(() => validateIncompleteSemantics(mutated)).toThrow(/definitions mismatch/u);
  });
});
