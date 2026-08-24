import { describe, expect, it } from 'vitest';

import {
  aggregatePermissionFindings,
  comparePermissionBoundaries,
  resolveRequirementFinding,
  type CatalogProvenance,
  type PermissionBoundary,
  type PermissionCatalogEntry,
  type PermissionLevel,
  type RequirementExpression,
  type RequirementFinding,
  type RestOperationIdentity,
  type SourceEvidence,
} from '../../src/permission-model/model.js';

/** Test-only digest material. These values are synthetic and never enter the production catalog. */
function digest(marker: string): string {
  return marker.repeat(64).slice(0, 64);
}

const SYNTHETIC_PROVENANCE: CatalogProvenance = {
  authorizedScopeSha256: digest('a1'),
  expressionSha256: digest('b2'),
  entrySha256: digest('c3'),
  artifactManifestSha256: digest('d4'),
  supportPredicateSha256: digest('e5'),
};

const CONTENTS_READ: RequirementExpression = { type: 'permission', permission: 'contents', level: 'read' };
const ISSUES_READ: RequirementExpression = { type: 'permission', permission: 'issues', level: 'read' };
const ISSUES_WRITE: RequirementExpression = { type: 'permission', permission: 'issues', level: 'write' };

const ANY_OF_REQUIREMENT: RequirementExpression = { type: 'anyOf', requirements: [CONTENTS_READ, ISSUES_WRITE] };
const ALL_OF_REQUIREMENT: RequirementExpression = { type: 'allOf', requirements: [CONTENTS_READ, ISSUES_WRITE] };
const NESTED_REQUIREMENT: RequirementExpression = {
  type: 'allOf',
  requirements: [ISSUES_READ, { type: 'anyOf', requirements: [CONTENTS_READ, ISSUES_WRITE] }],
};

function operation(operationId: string, method = 'GET'): RestOperationIdentity {
  return { method, normalizedRoute: `/repos/{owner}/{repo}/${operationId.replace('/', '-')}`, operationId };
}

function entry(operationId: string, requirement: RequirementExpression, method = 'GET'): PermissionCatalogEntry {
  return {
    status: 'resolved',
    operation: operation(operationId, method),
    requirement: JSON.parse(JSON.stringify(requirement)) as RequirementExpression,
    provenance: { ...SYNTHETIC_PROVENANCE },
  };
}

function atom(permission: string, level: PermissionLevel): RequirementExpression {
  return { type: 'permission', permission, level };
}

const CATALOG: readonly PermissionCatalogEntry[] = [
  entry('atom/issues-read', ISSUES_READ),
  entry('atom/issues-write', ISSUES_WRITE, 'POST'),
  entry('atom/issues-write-alias', ISSUES_WRITE, 'PUT'),
  entry('atom/contents-read', CONTENTS_READ),
  entry('atom/metadata-read', atom('metadata', 'read')),
  entry('atom/issues-capitalized', atom('Issues', 'read')),
  entry('atom/issues-suffixed', atom('issues_events', 'write'), 'POST'),
  entry('complex/any-of', ANY_OF_REQUIREMENT, 'POST'),
  entry('complex/all-of', ALL_OF_REQUIREMENT, 'POST'),
  entry('complex/nested', NESTED_REQUIREMENT, 'POST'),
  {
    status: 'unsupported',
    operation: operation('unsupported/qualifier', 'PATCH'),
    reason: 'unsupported-permission-qualifier',
    provenance: { ...SYNTHETIC_PROVENANCE },
  },
];

function source(line: number): SourceEvidence {
  return { path: 'src/synthetic.ts', span: { start: { line, column: 5 }, end: { line, column: 60 } } };
}

function finding(operationId: string, line: number, method?: string): RequirementFinding {
  const identity = method === undefined ? operation(operationId) : operation(operationId, method);
  return resolveRequirementFinding(CATALOG, identity, source(line));
}

const ISSUES_READ_FINDING = finding('atom/issues-read', 10);
const ISSUES_WRITE_FINDING = finding('atom/issues-write', 20, 'POST');
const ISSUES_WRITE_ALIAS_FINDING = finding('atom/issues-write-alias', 30, 'PUT');
const CONTENTS_READ_FINDING = finding('atom/contents-read', 40);
const METADATA_READ_FINDING = finding('atom/metadata-read', 50);
const CAPITALIZED_FINDING = finding('atom/issues-capitalized', 60);
const SUFFIXED_FINDING = finding('atom/issues-suffixed', 70, 'POST');
const ANY_OF_FINDING = finding('complex/any-of', 80, 'POST');
const ALL_OF_FINDING = finding('complex/all-of', 90, 'POST');
const NESTED_FINDING = finding('complex/nested', 100, 'POST');
const UNSUPPORTED_FINDING = finding('unsupported/qualifier', 110, 'PATCH');
const MISSING_FINDING = finding('atom/absent', 120);
const INVALID_CATALOG_FINDING = resolveRequirementFinding(
  [...CATALOG, { status: 'resolved' } as unknown as PermissionCatalogEntry],
  operation('atom/issues-read'),
  source(130),
);
const INVALID_SOURCE_FINDING = resolveRequirementFinding(
  CATALOG,
  operation('atom/issues-read'),
  null as unknown as SourceEvidence,
);

function completeBoundary(findings: readonly RequirementFinding[]): PermissionBoundary {
  const boundary = aggregatePermissionFindings(findings);
  if (boundary.status !== 'complete') throw new Error('expected a complete boundary');
  return boundary;
}

function incompleteBoundary(findings: readonly RequirementFinding[]): PermissionBoundary {
  const boundary = aggregatePermissionFindings(findings);
  if (boundary.status !== 'incomplete') throw new Error('expected an incomplete boundary');
  return boundary;
}

function simpleLevels(boundary: PermissionBoundary): Record<string, PermissionLevel> {
  if (boundary.status !== 'complete') throw new Error('expected a complete boundary');
  return Object.fromEntries(boundary.permissions.map((permission) => [permission.permission, permission.level]));
}

describe('simple aggregation', () => {
  it('treats no findings as a complete empty boundary', () => {
    expect(aggregatePermissionFindings([])).toEqual({ status: 'complete', permissions: [] });
  });

  it('joins none < read < write only inside one exact permission name', () => {
    expect(simpleLevels(completeBoundary([ISSUES_READ_FINDING, ISSUES_WRITE_FINDING]))).toEqual({ issues: 'write' });
    expect(simpleLevels(completeBoundary([ISSUES_WRITE_FINDING, ISSUES_READ_FINDING]))).toEqual({ issues: 'write' });
    expect(simpleLevels(completeBoundary([ISSUES_WRITE_FINDING, ISSUES_WRITE_ALIAS_FINDING]))).toEqual({
      issues: 'write',
    });
    expect(simpleLevels(completeBoundary([ISSUES_READ_FINDING]))).toEqual({ issues: 'read' });
  });

  it('never lets a different permission name raise another name', () => {
    expect(
      simpleLevels(
        completeBoundary([
          ISSUES_READ_FINDING,
          CONTENTS_READ_FINDING,
          METADATA_READ_FINDING,
          CAPITALIZED_FINDING,
          SUFFIXED_FINDING,
        ]),
      ),
    ).toEqual({ Issues: 'read', contents: 'read', issues: 'read', issues_events: 'write', metadata: 'read' });
  });

  it('orders permissions by exact name and keeps grouping case sensitive', () => {
    const boundary = completeBoundary([SUFFIXED_FINDING, CAPITALIZED_FINDING, ISSUES_READ_FINDING]);
    if (boundary.status !== 'complete') throw new Error('expected a complete boundary');
    expect(boundary.permissions.map((permission) => permission.permission)).toEqual([
      'Issues',
      'issues',
      'issues_events',
    ]);
  });

  it('retains every contributor, including repeated evidence, with its full triple and span', () => {
    const boundary = completeBoundary([ISSUES_READ_FINDING, ISSUES_WRITE_FINDING, ISSUES_READ_FINDING]);
    if (boundary.status !== 'complete') throw new Error('expected a complete boundary');
    const [issues] = boundary.permissions;
    if (issues === undefined) throw new Error('expected an issues permission');
    expect(issues.contributors).toHaveLength(3);
    expect(issues.contributors.filter((contributor) => contributor === ISSUES_READ_FINDING)).toHaveLength(0);
    expect(issues.contributors).toEqual(
      expect.arrayContaining([ISSUES_READ_FINDING, ISSUES_WRITE_FINDING, ISSUES_READ_FINDING]),
    );
    for (const contributor of issues.contributors) {
      expect(contributor).toMatchObject({
        status: 'resolved',
        operation: { method: expect.any(String) as string, normalizedRoute: expect.any(String) as string },
        source: { path: 'src/synthetic.ts' },
      });
    }
    const lines = issues.contributors.map((contributor) =>
      contributor.status === 'resolved' ? contributor.source.span.start.line : 0,
    );
    expect(lines).toEqual(expect.arrayContaining([10, 20]));
  });

  it('is order independent, deterministic, and JSON stable', () => {
    const forward = completeBoundary([ISSUES_READ_FINDING, CONTENTS_READ_FINDING, ISSUES_WRITE_FINDING]);
    const reversed = completeBoundary([ISSUES_WRITE_FINDING, CONTENTS_READ_FINDING, ISSUES_READ_FINDING]);
    expect(JSON.stringify(forward)).toBe(JSON.stringify(reversed));
    expect(JSON.parse(JSON.stringify(forward))).toEqual(forward);
  });

  it('never mutates the caller findings', () => {
    const findings = [ISSUES_READ_FINDING, ANY_OF_FINDING, MISSING_FINDING];
    const before = JSON.stringify(findings);
    aggregatePermissionFindings([ISSUES_READ_FINDING, ISSUES_WRITE_FINDING]);
    aggregatePermissionFindings(findings);
    expect(JSON.stringify(findings)).toBe(before);
  });

  it('rejects a structurally malformed finding instead of dropping it', () => {
    expect(() => aggregatePermissionFindings(null as unknown as RequirementFinding[])).toThrow(TypeError);
    expect(() => aggregatePermissionFindings([{} as unknown as RequirementFinding])).toThrow(TypeError);
    expect(() =>
      aggregatePermissionFindings([
        { ...(ISSUES_READ_FINDING as Record<string, unknown>), extra: true } as unknown as RequirementFinding,
      ]),
    ).toThrow(TypeError);
  });
});

describe('incomplete aggregation', () => {
  it('reports every incomplete class with its own stable reason', () => {
    const cases: [RequirementFinding, string][] = [
      [ANY_OF_FINDING, 'complex-permission-expression'],
      [ALL_OF_FINDING, 'complex-permission-expression'],
      [NESTED_FINDING, 'complex-permission-expression'],
      [UNSUPPORTED_FINDING, 'unsupported-permission-requirement'],
      [MISSING_FINDING, 'missing-permission-requirement'],
      [INVALID_CATALOG_FINDING, 'invalid-permission-requirement'],
      [INVALID_SOURCE_FINDING, 'invalid-permission-requirement'],
    ];
    for (const [entryFinding, reason] of cases) {
      const boundary = incompleteBoundary([entryFinding]);
      if (boundary.status !== 'incomplete') throw new Error('expected an incomplete boundary');
      expect(boundary.reasons).toEqual([reason]);
      expect(boundary.findings).toEqual([entryFinding]);
      expect(boundary).not.toHaveProperty('permissions');
    }
  });

  it('never exposes a partial simple boundary when a resolvable atom is mixed with an unprovable finding', () => {
    const boundary = incompleteBoundary([ISSUES_READ_FINDING, ANY_OF_FINDING, MISSING_FINDING, UNSUPPORTED_FINDING]);
    if (boundary.status !== 'incomplete') throw new Error('expected an incomplete boundary');
    expect(boundary.reasons).toEqual([
      'complex-permission-expression',
      'missing-permission-requirement',
      'unsupported-permission-requirement',
    ]);
    expect(boundary.findings).toHaveLength(4);
    expect(boundary.findings).toEqual(
      expect.arrayContaining([ISSUES_READ_FINDING, ANY_OF_FINDING, MISSING_FINDING, UNSUPPORTED_FINDING]),
    );
    expect(boundary).not.toHaveProperty('permissions');
  });

  it('reports each distinct reason once in a stable order and retains repeated findings', () => {
    const boundary = incompleteBoundary([
      MISSING_FINDING,
      INVALID_CATALOG_FINDING,
      ANY_OF_FINDING,
      UNSUPPORTED_FINDING,
      ANY_OF_FINDING,
      MISSING_FINDING,
    ]);
    if (boundary.status !== 'incomplete') throw new Error('expected an incomplete boundary');
    expect(boundary.reasons).toEqual([
      'complex-permission-expression',
      'invalid-permission-requirement',
      'missing-permission-requirement',
      'unsupported-permission-requirement',
    ]);
    expect(boundary.findings).toHaveLength(6);
    expect(JSON.stringify(incompleteBoundary([...boundary.findings].reverse()))).toBe(JSON.stringify(boundary));
  });

  it('keeps the complete anyOf expression intact inside the retained findings', () => {
    const boundary = incompleteBoundary([ANY_OF_FINDING]);
    if (boundary.status !== 'incomplete') throw new Error('expected an incomplete boundary');
    const [retained] = boundary.findings;
    if (retained === undefined || retained.status !== 'resolved') throw new Error('expected a resolved finding');
    expect(retained.requirement).toEqual(ANY_OF_REQUIREMENT);
    expect(retained.source).toEqual(source(80));
  });
});

describe('conservative boundary comparison', () => {
  it('compares complete simple boundaries by exact name with absence as none', () => {
    const read = completeBoundary([ISSUES_READ_FINDING]);
    const write = completeBoundary([ISSUES_WRITE_FINDING]);
    const empty = completeBoundary([]);
    const mixed = completeBoundary([ISSUES_READ_FINDING, CONTENTS_READ_FINDING]);
    expect(comparePermissionBoundaries(read, write)).toEqual({
      status: 'complete',
      changes: [{ permission: 'issues', base: 'read', head: 'write', change: 'expansion' }],
    });
    expect(comparePermissionBoundaries(write, read)).toEqual({
      status: 'complete',
      changes: [{ permission: 'issues', base: 'write', head: 'read', change: 'reduction' }],
    });
    expect(comparePermissionBoundaries(empty, empty)).toEqual({ status: 'complete', changes: [] });
    expect(comparePermissionBoundaries(write, empty)).toEqual({
      status: 'complete',
      changes: [{ permission: 'issues', base: 'write', head: 'none', change: 'reduction' }],
    });
    expect(comparePermissionBoundaries(read, mixed)).toEqual({
      status: 'complete',
      changes: [
        { permission: 'contents', base: 'none', head: 'read', change: 'expansion' },
        { permission: 'issues', base: 'read', head: 'read', change: 'unchanged' },
      ],
    });
  });

  it('never relates two different permission names to each other', () => {
    const issues = completeBoundary([ISSUES_WRITE_FINDING]);
    const suffixed = completeBoundary([SUFFIXED_FINDING]);
    expect(comparePermissionBoundaries(issues, suffixed)).toEqual({
      status: 'complete',
      changes: [
        { permission: 'issues', base: 'write', head: 'none', change: 'reduction' },
        { permission: 'issues_events', base: 'none', head: 'write', change: 'expansion' },
      ],
    });
  });

  it('stays incomplete and claims no change whenever either side is incomplete', () => {
    const complete = completeBoundary([ISSUES_WRITE_FINDING]);
    const incomplete = incompleteBoundary([ANY_OF_FINDING]);
    const baseIncomplete = comparePermissionBoundaries(incomplete, complete);
    expect(baseIncomplete.status).toBe('incomplete');
    if (baseIncomplete.status !== 'incomplete') throw new Error('expected an incomplete comparison');
    expect(baseIncomplete.reasons).toEqual(['complex-permission-expression', 'incomplete-base-boundary']);
    expect(baseIncomplete.base).toEqual(incomplete);
    expect(baseIncomplete.head).toEqual(complete);
    expect(baseIncomplete.structurallyEquivalent).toBe(false);
    expect(baseIncomplete).not.toHaveProperty('changes');

    const headIncomplete = comparePermissionBoundaries(complete, incomplete);
    if (headIncomplete.status !== 'incomplete') throw new Error('expected an incomplete comparison');
    expect(headIncomplete.reasons).toEqual(['complex-permission-expression', 'incomplete-head-boundary']);
    expect(headIncomplete.structurallyEquivalent).toBe(false);

    const bothIncomplete = comparePermissionBoundaries(
      incompleteBoundary([MISSING_FINDING]),
      incompleteBoundary([UNSUPPORTED_FINDING]),
    );
    if (bothIncomplete.status !== 'incomplete') throw new Error('expected an incomplete comparison');
    expect(bothIncomplete.reasons).toEqual([
      'incomplete-base-boundary',
      'incomplete-head-boundary',
      'missing-permission-requirement',
      'unsupported-permission-requirement',
    ]);
  });

  it('marks identical canonical complex evidence as structurally equivalent only inside an incomplete result', () => {
    const base = incompleteBoundary([ANY_OF_FINDING]);
    const head = incompleteBoundary([finding('complex/any-of', 400, 'POST')]);
    const comparison = comparePermissionBoundaries(base, head);
    if (comparison.status !== 'incomplete') throw new Error('expected an incomplete comparison');
    expect(comparison.structurallyEquivalent).toBe(true);
    expect(comparison.reasons).toEqual([
      'complex-permission-expression',
      'incomplete-base-boundary',
      'incomplete-head-boundary',
    ]);
    expect(comparison).not.toHaveProperty('changes');
    expect(comparison).not.toHaveProperty('permissions');
    expect(comparison.base).toEqual(base);
    expect(comparison.head).toEqual(head);
  });

  it('refuses to call different, added, or reclassified complex evidence equivalent', () => {
    const anyOf = incompleteBoundary([ANY_OF_FINDING]);
    const unequal: PermissionBoundary[] = [
      incompleteBoundary([ALL_OF_FINDING]),
      incompleteBoundary([NESTED_FINDING]),
      incompleteBoundary([ANY_OF_FINDING, ANY_OF_FINDING]),
      incompleteBoundary([ANY_OF_FINDING, ALL_OF_FINDING]),
    ];
    for (const head of unequal) {
      const comparison = comparePermissionBoundaries(anyOf, head);
      if (comparison.status !== 'incomplete') throw new Error('expected an incomplete comparison');
      expect(comparison.structurallyEquivalent).toBe(false);
    }
  });

  it('refuses to call boundaries equivalent when their unprovable evidence differs', () => {
    const base = incompleteBoundary([ANY_OF_FINDING, MISSING_FINDING]);
    const differentMissing = incompleteBoundary([ANY_OF_FINDING, finding('atom/other-absent', 500)]);
    const extraMissing = incompleteBoundary([ANY_OF_FINDING, MISSING_FINDING, finding('atom/other-absent', 500)]);
    for (const head of [differentMissing, extraMissing]) {
      const comparison = comparePermissionBoundaries(base, head);
      if (comparison.status !== 'incomplete') throw new Error('expected an incomplete comparison');
      expect(comparison.structurallyEquivalent).toBe(false);
    }
    const relocated = incompleteBoundary([
      finding('complex/any-of', 600, 'POST'),
      finding('atom/absent', 601),
    ]);
    const relocatedComparison = comparePermissionBoundaries(base, relocated);
    if (relocatedComparison.status !== 'incomplete') throw new Error('expected an incomplete comparison');
    expect(relocatedComparison.structurallyEquivalent).toBe(true);
  });

  it('refuses to call boundaries equivalent when resolved catalog provenance differs', () => {
    const base = incompleteBoundary([ANY_OF_FINDING]);
    const reprovenanced = finding('complex/any-of', 80, 'POST');
    if (reprovenanced.status !== 'resolved') throw new Error('expected a resolved finding');
    const head = incompleteBoundary([
      { ...reprovenanced, provenance: { ...SYNTHETIC_PROVENANCE, entrySha256: digest('f6') } },
    ]);
    const comparison = comparePermissionBoundaries(base, head);
    if (comparison.status !== 'incomplete') throw new Error('expected an incomplete comparison');
    expect(comparison.structurallyEquivalent).toBe(false);
  });

  it('does not claim equivalence when there is no resolved complex evidence to compare', () => {
    const comparison = comparePermissionBoundaries(
      incompleteBoundary([MISSING_FINDING]),
      incompleteBoundary([MISSING_FINDING]),
    );
    if (comparison.status !== 'incomplete') throw new Error('expected an incomplete comparison');
    expect(comparison.structurallyEquivalent).toBe(false);
  });

  it('never mutates either boundary and is deterministic across repeated execution', () => {
    const base = incompleteBoundary([ANY_OF_FINDING, MISSING_FINDING]);
    const head = completeBoundary([ISSUES_WRITE_FINDING]);
    const snapshot = JSON.stringify([base, head]);
    const first = comparePermissionBoundaries(base, head);
    const second = comparePermissionBoundaries(base, head);
    expect(JSON.stringify([base, head])).toBe(snapshot);
    expect(JSON.stringify(first)).toBe(JSON.stringify(second));
    expect(JSON.parse(JSON.stringify(first))).toEqual(first);
    if (first.status !== 'incomplete') throw new Error('expected an incomplete comparison');
    first.reasons.push('complex-permission-expression');
    expect(comparePermissionBoundaries(base, head)).toEqual(second);
  });

  it('rejects a malformed boundary instead of comparing it', () => {
    const complete = completeBoundary([ISSUES_WRITE_FINDING]);
    const malformed: unknown[] = [
      null,
      {},
      { status: 'complete' },
      { status: 'incomplete', reasons: [], findings: [] },
      { status: 'incomplete', reasons: ['unknown-reason'], findings: [] },
      { status: 'complete', permissions: [{ permission: 'issues', level: 'write', contributors: [] }] },
      {
        status: 'complete',
        permissions: [{ permission: 'issues', level: 'write', contributors: [ISSUES_READ_FINDING] }],
      },
      {
        status: 'complete',
        permissions: [{ permission: 'contents', level: 'read', contributors: [ISSUES_READ_FINDING] }],
      },
      {
        status: 'complete',
        permissions: [
          { permission: 'issues', level: 'read', contributors: [ISSUES_READ_FINDING] },
          { permission: 'issues', level: 'read', contributors: [ISSUES_READ_FINDING] },
        ],
      },
    ];
    for (const boundary of malformed) {
      expect(() => comparePermissionBoundaries(boundary as PermissionBoundary, complete)).toThrow(TypeError);
      expect(() => comparePermissionBoundaries(complete, boundary as PermissionBoundary)).toThrow(TypeError);
    }
  });
});
