import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import {
  BOUNDARYCI_PERMISSION_CATALOG,
  BOUNDARYCI_PERMISSION_CATALOG_IDENTITY,
} from '../../src/permission-model/bounded-catalog.js';
import {
  lookupPermissionRequirement,
  resolveRequirementFinding,
  validatePermissionCatalog,
  type CatalogProvenance,
  type PermissionCatalogEntry,
  type RequirementExpression,
  type RestOperationIdentity,
  type SourceEvidence,
  type UnsupportedCatalogEntry,
} from '../../src/permission-model/model.js';

type UnsupportedReason = UnsupportedCatalogEntry['reason'];

const UNSUPPORTED_REASONS: readonly UnsupportedReason[] = [
  'unsupported-access-level',
  'unsupported-permission-expression',
  'unsupported-permission-name',
  'unsupported-permission-qualifier',
];

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

const SIMPLE_OPERATION: RestOperationIdentity = {
  method: 'GET',
  normalizedRoute: '/repos/{owner}/{repo}/synthetic-simple',
  operationId: 'synthetic/simple',
};

const COMPLEX_OPERATION: RestOperationIdentity = {
  method: 'POST',
  normalizedRoute: '/repos/{owner}/{repo}/synthetic-complex',
  operationId: 'synthetic/complex',
};

const ABSENT_OPERATION: RestOperationIdentity = {
  method: 'DELETE',
  normalizedRoute: '/repos/{owner}/{repo}/synthetic-absent',
  operationId: 'synthetic/absent',
};

const COMPLEX_REQUIREMENT: RequirementExpression = {
  type: 'anyOf',
  requirements: [
    { type: 'permission', permission: 'contents', level: 'read' },
    { type: 'permission', permission: 'issues', level: 'write' },
  ],
};

const SOURCE: SourceEvidence = {
  path: 'src/synthetic.ts',
  span: { start: { line: 3, column: 1 }, end: { line: 3, column: 40 } },
};

function unsupportedOperation(reason: UnsupportedReason): RestOperationIdentity {
  return {
    method: 'PATCH',
    normalizedRoute: `/repos/{owner}/{repo}/synthetic-${reason}`,
    operationId: `synthetic/${reason}`,
  };
}

function unsupportedEntry(reason: UnsupportedReason): PermissionCatalogEntry {
  return {
    status: 'unsupported',
    operation: unsupportedOperation(reason),
    reason,
    provenance: { ...SYNTHETIC_PROVENANCE },
  };
}

function syntheticCatalog(): PermissionCatalogEntry[] {
  return [
    {
      status: 'resolved',
      operation: { ...SIMPLE_OPERATION },
      requirement: { type: 'permission', permission: 'metadata', level: 'read' },
      provenance: { ...SYNTHETIC_PROVENANCE },
    },
    {
      status: 'resolved',
      operation: { ...COMPLEX_OPERATION },
      requirement: JSON.parse(JSON.stringify(COMPLEX_REQUIREMENT)) as RequirementExpression,
      provenance: { ...SYNTHETIC_PROVENANCE },
    },
    ...UNSUPPORTED_REASONS.map(unsupportedEntry),
  ];
}

function productionCopy(): PermissionCatalogEntry[] {
  return JSON.parse(JSON.stringify(BOUNDARYCI_PERMISSION_CATALOG)) as PermissionCatalogEntry[];
}

function damaged(catalog: unknown): PermissionCatalogEntry[] {
  return catalog as PermissionCatalogEntry[];
}

function productionSource(file: string): string {
  return readFileSync(new URL(`../../src/permission-model/${file}`, import.meta.url), 'utf8');
}

describe('whole-catalog validation', () => {
  it('accepts an empty catalog and a mixed resolved/unsupported catalog', () => {
    expect(validatePermissionCatalog([])).toEqual({ status: 'valid', entryCount: 0 });
    expect(validatePermissionCatalog(syntheticCatalog())).toEqual({ status: 'valid', entryCount: 6 });
    expect(validatePermissionCatalog(BOUNDARYCI_PERMISSION_CATALOG)).toEqual({ status: 'valid', entryCount: 2 });
  });

  it('rejects every malformed catalog shape with an explanatory detail', () => {
    const malformed: unknown[] = [
      null,
      undefined,
      {},
      'catalog',
      [null],
      [{ status: 'unknown', operation: SIMPLE_OPERATION, provenance: SYNTHETIC_PROVENANCE }],
      [{ status: 'resolved', operation: SIMPLE_OPERATION, provenance: SYNTHETIC_PROVENANCE }],
      [
        {
          status: 'resolved',
          operation: SIMPLE_OPERATION,
          requirement: { type: 'permission', permission: 'metadata', level: 'read' },
          provenance: SYNTHETIC_PROVENANCE,
          note: 'extra',
        },
      ],
      [
        {
          status: 'resolved',
          operation: { ...SIMPLE_OPERATION, method: 'get' },
          requirement: { type: 'permission', permission: 'metadata', level: 'read' },
          provenance: SYNTHETIC_PROVENANCE,
        },
      ],
      [
        {
          status: 'resolved',
          operation: { ...SIMPLE_OPERATION, normalizedRoute: 'repos/{owner}/{repo}/synthetic-simple' },
          requirement: { type: 'permission', permission: 'metadata', level: 'read' },
          provenance: SYNTHETIC_PROVENANCE,
        },
      ],
      [
        {
          status: 'resolved',
          operation: { ...SIMPLE_OPERATION, operationId: 'synthetic simple' },
          requirement: { type: 'permission', permission: 'metadata', level: 'read' },
          provenance: SYNTHETIC_PROVENANCE,
        },
      ],
      [
        {
          status: 'resolved',
          operation: SIMPLE_OPERATION,
          requirement: {
            type: 'allOf',
            requirements: [
              { type: 'permission', permission: 'metadata', level: 'write' },
              { type: 'permission', permission: 'contents', level: 'read' },
            ],
          },
          provenance: SYNTHETIC_PROVENANCE,
        },
      ],
      [
        {
          status: 'unsupported',
          operation: SIMPLE_OPERATION,
          reason: 'not-a-reason',
          provenance: SYNTHETIC_PROVENANCE,
        },
      ],
      [
        {
          status: 'unsupported',
          operation: SIMPLE_OPERATION,
          reason: 'unsupported-access-level',
          provenance: { ...SYNTHETIC_PROVENANCE, entrySha256: digest('c3').toUpperCase() },
        },
      ],
      [
        {
          status: 'unsupported',
          operation: SIMPLE_OPERATION,
          reason: 'unsupported-access-level',
          provenance: { ...SYNTHETIC_PROVENANCE, entrySha256: 'c3c3' },
        },
      ],
    ];
    for (const catalog of malformed) {
      const result = validatePermissionCatalog(catalog);
      expect(result.status).toBe('invalid');
      if (result.status !== 'invalid') throw new Error('expected an invalid catalog');
      expect(result.reason).toBe('malformed-catalog-entry');
      expect(result.detail.length).toBeGreaterThan(0);
    }
  });

  it('rejects a catalog whose provenance omits a required digest binding', () => {
    for (const key of [
      'artifactManifestSha256',
      'authorizedScopeSha256',
      'entrySha256',
      'expressionSha256',
      'supportPredicateSha256',
    ] as const) {
      const catalog = syntheticCatalog();
      const entry = catalog[0];
      if (entry === undefined) throw new Error('expected a synthetic entry');
      const provenance: Record<string, string> = { ...entry.provenance };
      delete provenance[key];
      const broken = [{ ...entry, provenance }];
      expect(validatePermissionCatalog(broken)).toMatchObject({
        status: 'invalid',
        reason: 'malformed-catalog-entry',
      });
    }
  });

  it('reports a byte-identical repeated triple as a duplicate catalog entry', () => {
    const catalog = syntheticCatalog();
    const entry = catalog[0];
    if (entry === undefined) throw new Error('expected a synthetic entry');
    const result = validatePermissionCatalog([...catalog, JSON.parse(JSON.stringify(entry)) as PermissionCatalogEntry]);
    expect(result).toMatchObject({ status: 'invalid', reason: 'duplicate-catalog-entry' });
  });

  it('reports a disagreeing repeated triple as a conflicting catalog entry', () => {
    const catalog = syntheticCatalog();
    const entry = catalog[0];
    if (entry === undefined || entry.status !== 'resolved') throw new Error('expected a resolved synthetic entry');
    const conflicting: PermissionCatalogEntry = {
      ...entry,
      requirement: { type: 'permission', permission: 'metadata', level: 'write' },
    };
    expect(validatePermissionCatalog([...catalog, conflicting])).toMatchObject({
      status: 'invalid',
      reason: 'conflicting-catalog-entry',
    });
    const reclassified: PermissionCatalogEntry = {
      status: 'unsupported',
      operation: { ...SIMPLE_OPERATION },
      reason: 'unsupported-permission-name',
      provenance: { ...SYNTHETIC_PROVENANCE },
    };
    expect(validatePermissionCatalog([...catalog, reclassified])).toMatchObject({
      status: 'invalid',
      reason: 'conflicting-catalog-entry',
    });
  });
});

describe('exact-triple catalog lookup', () => {
  it('resolves simple and complex synthetic rows with their requirement and provenance', () => {
    expect(lookupPermissionRequirement(syntheticCatalog(), SIMPLE_OPERATION)).toEqual({
      status: 'resolved',
      operation: SIMPLE_OPERATION,
      requirement: { type: 'permission', permission: 'metadata', level: 'read' },
      provenance: SYNTHETIC_PROVENANCE,
    });
    expect(lookupPermissionRequirement(syntheticCatalog(), COMPLEX_OPERATION)).toEqual({
      status: 'resolved',
      operation: COMPLEX_OPERATION,
      requirement: COMPLEX_REQUIREMENT,
      provenance: SYNTHETIC_PROVENANCE,
    });
  });

  it('returns each explicit unsupported reason without inventing a requirement', () => {
    for (const reason of UNSUPPORTED_REASONS) {
      const result = lookupPermissionRequirement(syntheticCatalog(), unsupportedOperation(reason));
      expect(result).toEqual({ status: 'unsupported', operation: unsupportedOperation(reason), reason });
      expect(result).not.toHaveProperty('requirement');
    }
  });

  it('returns missing for an absent triple and for every single-field triple mismatch', () => {
    expect(lookupPermissionRequirement(syntheticCatalog(), ABSENT_OPERATION)).toEqual({
      status: 'missing',
      operation: ABSENT_OPERATION,
    });
    const mismatches: RestOperationIdentity[] = [
      { ...SIMPLE_OPERATION, method: 'HEAD' },
      { ...SIMPLE_OPERATION, normalizedRoute: '/repos/{owner}/{repo}/synthetic-simple/{id}' },
      { ...SIMPLE_OPERATION, operationId: 'synthetic/simple-v2' },
    ];
    for (const operation of mismatches) {
      expect(lookupPermissionRequirement(syntheticCatalog(), operation)).toEqual({ status: 'missing', operation });
    }
  });

  it('returns invalid without an operation when the requested identity is unusable', () => {
    const identities: unknown[] = [
      null,
      {},
      { ...SIMPLE_OPERATION, method: '' },
      { ...SIMPLE_OPERATION, method: 'Get' },
      { ...SIMPLE_OPERATION, normalizedRoute: '/repos/{owner}/{repo}/synthetic simple' },
      { ...SIMPLE_OPERATION, operationId: '' },
      { ...SIMPLE_OPERATION, extra: true },
    ];
    for (const identity of identities) {
      const result = lookupPermissionRequirement(syntheticCatalog(), identity as RestOperationIdentity);
      expect(result).toMatchObject({ status: 'invalid', operation: null, reason: 'invalid-operation-identity' });
    }
  });

  it('never selects a row out of a damaged catalog', () => {
    const malformedNeighbour = damaged([...syntheticCatalog(), { status: 'resolved' }]);
    expect(lookupPermissionRequirement(malformedNeighbour, SIMPLE_OPERATION)).toMatchObject({
      status: 'invalid',
      operation: SIMPLE_OPERATION,
      reason: 'malformed-catalog-entry',
    });
    const catalog = syntheticCatalog();
    const entry = catalog[0];
    if (entry === undefined) throw new Error('expected a synthetic entry');
    const duplicated = [...catalog, JSON.parse(JSON.stringify(entry)) as PermissionCatalogEntry];
    expect(lookupPermissionRequirement(duplicated, SIMPLE_OPERATION)).toMatchObject({
      status: 'invalid',
      operation: SIMPLE_OPERATION,
      reason: 'duplicate-catalog-entry',
    });
    expect(lookupPermissionRequirement(duplicated, ABSENT_OPERATION)).toMatchObject({
      status: 'invalid',
      operation: ABSENT_OPERATION,
      reason: 'duplicate-catalog-entry',
    });
  });

  it('returns copies so a caller cannot reach back into catalog data', () => {
    const catalog = syntheticCatalog();
    const first = lookupPermissionRequirement(catalog, COMPLEX_OPERATION);
    if (first.status !== 'resolved') throw new Error('expected a resolved lookup');
    if (first.requirement.type !== 'anyOf') throw new Error('expected an anyOf requirement');
    first.requirement.requirements.pop();
    first.provenance.entrySha256 = digest('0f');
    const second = lookupPermissionRequirement(catalog, COMPLEX_OPERATION);
    expect(second).toEqual({
      status: 'resolved',
      operation: COMPLEX_OPERATION,
      requirement: COMPLEX_REQUIREMENT,
      provenance: SYNTHETIC_PROVENANCE,
    });
  });
});

describe('requirement findings and source evidence', () => {
  it('retains the full REST triple and exact source span on a resolved finding', () => {
    expect(resolveRequirementFinding(syntheticCatalog(), COMPLEX_OPERATION, SOURCE)).toEqual({
      status: 'resolved',
      operation: COMPLEX_OPERATION,
      source: SOURCE,
      requirement: COMPLEX_REQUIREMENT,
      provenance: SYNTHETIC_PROVENANCE,
    });
  });

  it('retains source evidence on unsupported, missing, and invalid outcomes', () => {
    expect(
      resolveRequirementFinding(syntheticCatalog(), unsupportedOperation('unsupported-permission-name'), SOURCE),
    ).toEqual({
      status: 'unsupported',
      operation: unsupportedOperation('unsupported-permission-name'),
      source: SOURCE,
      reason: 'unsupported-permission-name',
    });
    expect(resolveRequirementFinding(syntheticCatalog(), ABSENT_OPERATION, SOURCE)).toEqual({
      status: 'missing',
      operation: ABSENT_OPERATION,
      source: SOURCE,
    });
    expect(
      resolveRequirementFinding(damaged([...syntheticCatalog(), { status: 'resolved' }]), SIMPLE_OPERATION, SOURCE),
    ).toMatchObject({
      status: 'invalid',
      operation: SIMPLE_OPERATION,
      source: SOURCE,
      reason: 'malformed-catalog-entry',
    });
  });

  it('rejects malformed source evidence instead of inventing coordinates', () => {
    const malformed: unknown[] = [
      null,
      {},
      { path: '', span: SOURCE.span },
      { path: 'src/synthetic.ts' },
      { path: 'src/synthetic.ts', span: SOURCE.span, note: 'extra' },
      { path: 'src/synthetic.ts', span: { start: SOURCE.span.start } },
      { path: 'src/synthetic.ts', span: { start: { line: 0, column: 1 }, end: { line: 1, column: 2 } } },
      { path: 'src/synthetic.ts', span: { start: { line: 1, column: 1.5 }, end: { line: 1, column: 2 } } },
      { path: 'src/synthetic.ts', span: { start: { line: 1, column: 1 }, end: { line: 1, column: '2' } } },
      { path: 'src/synthetic.ts', span: { start: { line: 4, column: 1 }, end: { line: 3, column: 1 } } },
      { path: 'src/synthetic.ts', span: { start: { line: 3, column: 9 }, end: { line: 3, column: 2 } } },
      { path: 'src/synthetic.ts', span: { start: { line: 1, column: 1, offset: 0 }, end: { line: 1, column: 2 } } },
    ];
    for (const source of malformed) {
      const finding = resolveRequirementFinding(syntheticCatalog(), SIMPLE_OPERATION, source as SourceEvidence);
      expect(finding).toMatchObject({
        status: 'invalid',
        operation: SIMPLE_OPERATION,
        source: null,
        reason: 'invalid-source-evidence',
      });
    }
  });

  it('keeps valid source evidence when only the operation identity is unusable', () => {
    const finding = resolveRequirementFinding(syntheticCatalog(), {} as RestOperationIdentity, SOURCE);
    expect(finding).toMatchObject({
      status: 'invalid',
      operation: null,
      source: SOURCE,
      reason: 'invalid-operation-identity',
    });
    if (finding.status !== 'invalid') throw new Error('expected an invalid finding');
    expect(finding.detail.length).toBeGreaterThan(0);
  });

  it('reports a null operation and a null source when neither input is usable', () => {
    expect(
      resolveRequirementFinding(syntheticCatalog(), {} as RestOperationIdentity, null as unknown as SourceEvidence),
    ).toMatchObject({ status: 'invalid', operation: null, source: null, reason: 'invalid-source-evidence' });
  });

  it('accepts a multi-line span and keeps its exact coordinates', () => {
    const multiLine: SourceEvidence = {
      path: 'packages/app/src/handlers/issues.ts',
      span: { start: { line: 118, column: 7 }, end: { line: 126, column: 4 } },
    };
    const finding = resolveRequirementFinding(syntheticCatalog(), SIMPLE_OPERATION, multiLine);
    expect(finding).toMatchObject({ status: 'resolved', source: multiLine });
    expect(JSON.parse(JSON.stringify(finding))).toEqual(finding);
  });
});

describe('the exact production catalog', () => {
  it('exports exactly the two authorized Issues rows and no synthetic or complex row', () => {
    expect(BOUNDARYCI_PERMISSION_CATALOG).toHaveLength(2);
    expect(BOUNDARYCI_PERMISSION_CATALOG.map((entry) => entry.operation.operationId)).toEqual([
      'issues/create',
      'issues/list-for-repo',
    ]);
    expect(BOUNDARYCI_PERMISSION_CATALOG_IDENTITY.operationIds).toEqual(['issues/create', 'issues/list-for-repo']);
    for (const entry of BOUNDARYCI_PERMISSION_CATALOG) {
      expect(entry.status).toBe('resolved');
      if (entry.status !== 'resolved') throw new Error('expected a resolved production row');
      expect(entry.requirement.type).toBe('permission');
      expect(entry.operation.normalizedRoute).toBe('/repos/{owner}/{repo}/issues');
      expect(entry.operation.operationId.startsWith('issues/')).toBe(true);
    }
    expect(
      BOUNDARYCI_PERMISSION_CATALOG.map((entry) =>
        entry.status === 'resolved' && entry.requirement.type === 'permission'
          ? `${entry.operation.method} ${entry.requirement.permission}:${entry.requirement.level}`
          : 'unexpected',
      ),
    ).toEqual(['POST issues:write', 'GET issues:read']);
  });

  it('keeps the five provenance digests distinct and non-interchangeable', () => {
    for (const entry of BOUNDARYCI_PERMISSION_CATALOG) {
      const values = Object.values(entry.provenance);
      expect(new Set(values).size).toBe(values.length);
      expect(entry.provenance.authorizedScopeSha256).not.toBe(entry.provenance.supportPredicateSha256);
      expect(entry.provenance.expressionSha256).not.toBe(entry.provenance.entrySha256);
      expect(entry.provenance.artifactManifestSha256).not.toBe(entry.provenance.expressionSha256);
    }
    const [create, list] = BOUNDARYCI_PERMISSION_CATALOG;
    if (create === undefined || list === undefined) throw new Error('expected two production rows');
    expect(create.provenance.expressionSha256).not.toBe(list.provenance.expressionSha256);
    expect(create.provenance.entrySha256).not.toBe(list.provenance.entrySha256);
    expect(create.provenance.authorizedScopeSha256).toBe(list.provenance.authorizedScopeSha256);
  });

  it('is deeply frozen so no caller can add, remove, or retarget an authorized row', () => {
    expect(Object.isFrozen(BOUNDARYCI_PERMISSION_CATALOG)).toBe(true);
    expect(Object.isFrozen(BOUNDARYCI_PERMISSION_CATALOG_IDENTITY)).toBe(true);
    const [first] = BOUNDARYCI_PERMISSION_CATALOG;
    if (first === undefined) throw new Error('expected a production row');
    expect(Object.isFrozen(first)).toBe(true);
    expect(Object.isFrozen(first.operation)).toBe(true);
    expect(Object.isFrozen(first.provenance)).toBe(true);
    expect(() => {
      (BOUNDARYCI_PERMISSION_CATALOG as PermissionCatalogEntry[]).push(unsupportedEntry('unsupported-access-level'));
    }).toThrow(TypeError);
    expect(() => {
      (first.operation as { operationId: string }).operationId = 'issues/update';
    }).toThrow(TypeError);
    expect(() => {
      (first.provenance as { entrySha256: string }).entrySha256 = digest('0f');
    }).toThrow(TypeError);
    expect(BOUNDARYCI_PERMISSION_CATALOG).toHaveLength(2);
  });

  it('carries mutated provenance through a copy without changing the exported catalog', () => {
    const mutated = productionCopy();
    const entry = mutated[0];
    if (entry === undefined) throw new Error('expected a copied row');
    entry.provenance.entrySha256 = digest('0f');
    expect(validatePermissionCatalog(mutated)).toEqual({ status: 'valid', entryCount: 2 });
    const lookup = lookupPermissionRequirement(mutated, entry.operation);
    expect(lookup).toMatchObject({ status: 'resolved', provenance: { entrySha256: digest('0f') } });
    const authentic = lookupPermissionRequirement(BOUNDARYCI_PERMISSION_CATALOG, entry.operation);
    expect(authentic).toMatchObject({
      status: 'resolved',
      provenance: { entrySha256: 'f7ad7d4f8317a479d9ad55d96c651219e6227b55354e6e33d396d45388cabe09' },
    });
  });

  it('invalidates the whole copied catalog when a provenance digest is corrupted', () => {
    const corrupted = productionCopy();
    const entry = corrupted[0];
    if (entry === undefined) throw new Error('expected a copied row');
    (entry.provenance as unknown as Record<string, unknown>).authorizedScopeSha256 = 'not-a-digest';
    expect(validatePermissionCatalog(corrupted)).toMatchObject({
      status: 'invalid',
      reason: 'malformed-catalog-entry',
    });
    expect(lookupPermissionRequirement(corrupted, entry.operation)).toMatchObject({
      status: 'invalid',
      reason: 'malformed-catalog-entry',
    });
  });

  it('survives a JSON round trip without losing a field', () => {
    const reloaded: unknown = JSON.parse(JSON.stringify(BOUNDARYCI_PERMISSION_CATALOG));
    expect(reloaded).toEqual(JSON.parse(JSON.stringify(BOUNDARYCI_PERMISSION_CATALOG)));
    expect(validatePermissionCatalog(reloaded)).toEqual({ status: 'valid', entryCount: 2 });
    expect(JSON.parse(JSON.stringify(BOUNDARYCI_PERMISSION_CATALOG_IDENTITY))).toEqual(
      BOUNDARYCI_PERMISSION_CATALOG_IDENTITY,
    );
  });
});

describe('production module boundary', () => {
  const files = ['model.ts', 'bounded-catalog.ts'];

  it('declares no import other than the type-only sibling module import', () => {
    const specifiers: string[] = [];
    for (const file of files) {
      for (const match of productionSource(file).matchAll(/\bfrom\s+'([^']*)'|\bimport\s+'([^']*)'/gu)) {
        specifiers.push(match[1] ?? match[2] ?? '');
      }
    }
    expect(specifiers).toEqual(['./model.js']);
  });

  it('contains no filesystem, network, framework, client, or feasibility-tool coupling', () => {
    const forbidden = [
      /\bnode:/u,
      /\brequire\s*\(/u,
      /\bimport\s*\(/u,
      /\bimport\.meta\b/u,
      /\bprocess\b/u,
      /\bglobalThis\b/u,
      /\bfetch\s*\(/u,
      /\boctokit\b/iu,
      /\bprobot\b/iu,
      /\bts-morph\b/u,
      /\btypescript\b/iu,
      /\beval\s*\(/u,
      /\bnew\s+Function\b/u,
      /\bMath\.random\b/u,
      /\bDate\.now\b/u,
      /\bnew\s+Date\b/u,
      /permission-data-feasibility/u,
    ];
    for (const file of files) {
      const text = productionSource(file);
      const match = forbidden.find((pattern) => pattern.test(text));
      expect(match, `${file} must not reference ${String(match)}`).toBeUndefined();
    }
  });
});
