import { createHash } from 'node:crypto';
import { lstat, readFile, stat } from 'node:fs/promises';

import { afterEach, describe, expect, it } from 'vitest';

import {
  ANALYSIS_DISCOVERY_PROFILE_ID,
  ANALYSIS_LIMIT_PROFILE_ID,
  ANALYSIS_SCHEMA_ID,
  ANALYSIS_SCHEMA_VERSION,
  ANALYSIS_SPAN_CONVENTION_ID,
  ANALYZER_SOURCE_EXTENSIONS,
  DEFAULT_ANALYSIS_LIMITS,
  validateAnalysisRequest,
  validateAnalysisResult,
  type AnalysisLimits,
  type AnalysisRequest,
  type AnalyzerCause,
  type AnalyzerCauseResource,
  type AnalyzerIdentity,
  type CandidateRecord,
  type CompleteAnalysisResult,
  type FailedAnalysisResult,
  type IncompleteAnalysisResult,
  type OperationObservation,
  type PermissionResolutionRecord,
  type SourceRecord,
} from '../../src/analyzer/contract.js';
import { ANALYZER_PROFILE_IDENTITY } from '../../src/analyzer/profile.js';
import { BOUNDARYCI_PERMISSION_CATALOG_IDENTITY } from '../../src/permission-model/bounded-catalog.js';
import type { RequirementFinding } from '../../src/permission-model/model.js';

import { cleanupTempRoots, createSymlink, createTempRoot, writeRegularFile } from './helpers.js';

afterEach(async () => {
  await cleanupTempRoots();
});

function sha256(seed: string): string {
  return createHash('sha256').update(seed).digest('hex');
}

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function nested(root: unknown, path: readonly (number | string)[]): Record<string, unknown> {
  let node: unknown = root;
  for (const segment of path) node = (node as Record<string, unknown>)[String(segment)];
  return node as Record<string, unknown>;
}

function validRequest(overrides: Partial<AnalysisRequest> = {}): AnalysisRequest {
  return {
    rootPath: '/does/not/need/to/exist/for/shape/validation',
    include: ['**/*.ts'],
    exclude: [],
    probotEntrypoints: [],
    limits: { ...DEFAULT_ANALYSIS_LIMITS },
    ...overrides,
  };
}

const IDENTITY: AnalyzerIdentity = {
  schemaId: ANALYSIS_SCHEMA_ID,
  schemaVersion: ANALYSIS_SCHEMA_VERSION,
  spanConventionId: ANALYSIS_SPAN_CONVENTION_ID,
  analyzerProfile: ANALYZER_PROFILE_IDENTITY,
  discoveryProfileId: ANALYSIS_DISCOVERY_PROFILE_ID,
  limitProfileId: ANALYSIS_LIMIT_PROFILE_ID,
  permissionCatalogScopeSha256: BOUNDARYCI_PERMISSION_CATALOG_IDENTITY.authorizedScopeSha256,
};

function emptyBoundary(): CompleteAnalysisResult['boundary'] {
  return {
    include: ['**/*.ts'],
    exclude: [],
    probotEntrypoints: [],
    limits: { ...DEFAULT_ANALYSIS_LIMITS },
    sourceExtensions: [...ANALYZER_SOURCE_EXTENSIONS],
  };
}

function emptyCompleteResult(): CompleteAnalysisResult {
  return {
    status: 'complete',
    identity: clone(IDENTITY),
    boundary: emptyBoundary(),
    sources: [],
    candidates: [],
    causes: [],
    observations: [],
    permissionResolutions: [],
    permissionBoundary: { status: 'complete', permissions: [] },
  };
}

function sourceRecord(overrides: Partial<SourceRecord> = {}): SourceRecord {
  return {
    id: 'source-0001',
    path: 'src/app.ts',
    byteSize: 42,
    contentSha256: sha256('source-0001'),
    ...overrides,
  };
}

function resolvedFinding(): RequirementFinding {
  return {
    status: 'resolved',
    operation: { method: 'GET', normalizedRoute: '/repos/{owner}/{repo}/issues', operationId: 'issues/list-for-repo' },
    source: { path: 'src/app.ts', span: { start: { line: 6, column: 3 }, end: { line: 6, column: 50 } } },
    requirement: { type: 'permission', permission: 'issues', level: 'read' },
    provenance: {
      authorizedScopeSha256: sha256('authorized-scope'),
      expressionSha256: sha256('expression'),
      entrySha256: sha256('entry'),
      artifactManifestSha256: sha256('artifact-manifest'),
      supportPredicateSha256: sha256('support-predicate'),
    },
  };
}

function observation(overrides: Partial<OperationObservation> = {}): OperationObservation {
  return {
    id: 'operation-0001',
    candidateId: 'candidate-0001',
    callForm: 'direct-endpoint',
    spelling: 'client.rest.issues.listForRepo',
    optional: false,
    member: {
      profileId: ANALYZER_PROFILE_IDENTITY.profileId,
      memberId: 'issues.listForRepo',
      scope: 'issues',
      method: 'listForRepo',
    },
    operation: { method: 'GET', normalizedRoute: '/repos/{owner}/{repo}/issues', operationId: 'issues/list-for-repo' },
    receiver: {
      origin: 'octokit-package-named-import',
      packageSpecifier: 'octokit',
      exportName: 'Octokit',
      constructorBinding: 'Octokit',
      constructorAliasChain: ['Octokit'],
      construction: 'direct-new',
      clientBinding: 'client',
      clientAliasChain: ['client'],
      access: 'local-binding',
      steps: [
        { kind: 'named-import', path: 'src/app.ts', span: { start: { line: 1, column: 9 }, end: { line: 1, column: 16 } }, binding: 'Octokit', specifier: 'octokit', resolvedPath: null, ruleId: null, ruleRow: null },
        { kind: 'direct-new', path: 'src/app.ts', span: { start: { line: 3, column: 7 }, end: { line: 3, column: 13 } }, binding: 'client', specifier: null, resolvedPath: null, ruleId: null, ruleRow: null },
      ],
    },
    source: { path: 'src/app.ts', span: { start: { line: 6, column: 3 }, end: { line: 6, column: 50 } } },
    ...overrides,
  };
}

function candidateRecord(overrides: Partial<CandidateRecord> = {}): CandidateRecord {
  return {
    id: 'candidate-0001',
    kind: 'direct-endpoint',
    anchor: 'pinned-endpoint-member-spelling',
    spelling: 'client.rest.issues.listForRepo',
    path: 'src/app.ts',
    span: { start: { line: 6, column: 3 }, end: { line: 6, column: 50 } },
    classification: 'proven-operation',
    reason: 'proven-direct-rest-member-call',
    observationId: 'operation-0001',
    causeIds: [],
    ...overrides,
  };
}

function causeRecord(overrides: Partial<AnalyzerCause> = {}): AnalyzerCause {
  return {
    id: 'cause-0001',
    code: 'unproven-receiver-provenance',
    scope: 'candidate',
    path: 'src/lookalike.ts',
    span: { start: { line: 1, column: 1 }, end: { line: 1, column: 10 } },
    resource: null,
    detail: 'the receiver origin could not be proven',
    ...overrides,
  };
}

function resourceOf(limitKey: keyof AnalysisLimits, overrides: Partial<AnalyzerCauseResource> = {}): AnalyzerCauseResource {
  return {
    limitKey,
    configured: 10,
    consumed: 10,
    frontier: 'src/app.ts',
    processedSources: 10,
    unprocessedSources: 5,
    ...overrides,
  };
}

function permissionResolution(overrides: Partial<PermissionResolutionRecord> = {}): PermissionResolutionRecord {
  return {
    id: 'resolution-0001',
    observationId: 'operation-0001',
    finding: resolvedFinding(),
    ...overrides,
  };
}

function populatedCompleteResult(): CompleteAnalysisResult {
  return {
    status: 'complete',
    identity: clone(IDENTITY),
    boundary: emptyBoundary(),
    sources: [sourceRecord()],
    candidates: [candidateRecord()],
    causes: [],
    observations: [observation()],
    permissionResolutions: [permissionResolution()],
    permissionBoundary: {
      status: 'complete',
      permissions: [{ permission: 'issues', level: 'read', contributors: [resolvedFinding()] }],
    },
  };
}

function populatedIncompleteResult(): IncompleteAnalysisResult {
  return {
    status: 'incomplete',
    identity: clone(IDENTITY),
    boundary: emptyBoundary(),
    sources: [sourceRecord({ path: 'src/lookalike.ts' })],
    candidates: [
      candidateRecord({
        id: 'candidate-0001',
        anchor: 'client-receiver-provenance',
        path: 'src/lookalike.ts',
        classification: 'incomplete',
        reason: 'unproven-receiver-provenance',
        observationId: null,
        causeIds: ['cause-0001'],
      }),
    ],
    causes: [causeRecord()],
    observations: [],
    permissionResolutions: [],
    permissionBoundary: { status: 'complete', permissions: [] },
  };
}

describe('exact-shape trusted-input validation', () => {
  it('accepts a well-formed trusted request', () => {
    expect(() => {
      validateAnalysisRequest(validRequest());
    }).not.toThrow();
  });

  it('rejects null', () => {
    expect(() => {
      validateAnalysisRequest(null);
    }).toThrow(TypeError);
  });

  it('rejects an array in request position', () => {
    expect(() => {
      validateAnalysisRequest([]);
    }).toThrow(TypeError);
  });

  it('rejects an unknown top-level key', () => {
    expect(() => {
      validateAnalysisRequest({ ...validRequest(), extra: true });
    }).toThrow(TypeError);
  });

  it('rejects a request with no include pattern', () => {
    expect(() => {
      validateAnalysisRequest(validRequest({ include: [] }));
    }).toThrow(TypeError);
  });

  it('rejects an uninterpreted glob operator', () => {
    expect(() => {
      validateAnalysisRequest(validRequest({ include: ['!(src)/**/*.ts'] }));
    }).toThrow(TypeError);
  });

  it('rejects a limits value that is not an object', () => {
    expect(() => {
      validateAnalysisRequest(validRequest({ limits: 3 as unknown as AnalysisRequest['limits'] }));
    }).toThrow(TypeError);
  });

  it('rejects limits missing a required key', () => {
    expect(() => {
      validateAnalysisRequest(
        validRequest({ limits: { maxSourceFiles: 1, maxSourceFileBytes: 1 } as unknown as AnalysisRequest['limits'] }),
      );
    }).toThrow(TypeError);
  });

  it('rejects a Probot entrypoint containing a parent segment', () => {
    expect(() => {
      validateAnalysisRequest(validRequest({ probotEntrypoints: ['../outside/app.ts'] }));
    }).toThrow(TypeError);
  });

  it('rejects an absolute Probot entrypoint', () => {
    expect(() => {
      validateAnalysisRequest(validRequest({ probotEntrypoints: ['/app.ts'] }));
    }).toThrow(TypeError);
  });
});

describe('numeric limit boundaries', () => {
  const cases: readonly [string, number, boolean][] = [
    ['zero', 0, true],
    ['the largest safe integer', Number.MAX_SAFE_INTEGER, true],
    ['one past the largest safe integer', Number.MAX_SAFE_INTEGER + 1, false],
    ['a negative integer', -1, false],
    ['a fractional value', 1.5, false],
    ['NaN', Number.NaN, false],
    ['positive Infinity', Number.POSITIVE_INFINITY, false],
    ['negative Infinity', Number.NEGATIVE_INFINITY, false],
  ];

  for (const [label, value, accepted] of cases) {
    it(`${accepted ? 'accepts' : 'rejects'} ${label} as a request limit`, () => {
      const request = validRequest({ limits: { ...DEFAULT_ANALYSIS_LIMITS, maxSourceFiles: value } });
      if (accepted) {
        expect(() => {
          validateAnalysisRequest(request);
        }).not.toThrow();
      } else {
        expect(() => {
          validateAnalysisRequest(request);
        }).toThrow(TypeError);
      }
    });

    it(`${accepted ? 'accepts' : 'rejects'} ${label} as a result boundary limit`, () => {
      const result = populatedCompleteResult();
      result.boundary.limits.maxTotalSourceBytes = value;
      if (accepted) {
        expect(() => {
          validateAnalysisResult(result);
        }).not.toThrow();
      } else {
        expect(() => {
          validateAnalysisResult(result);
        }).toThrow(TypeError);
      }
    });
  }
});

describe('complete, incomplete, and failed result validation', () => {
  it('accepts a well-formed complete result', () => {
    expect(() => {
      validateAnalysisResult(populatedCompleteResult());
    }).not.toThrow();
  });

  it('accepts a well-formed incomplete result', () => {
    expect(() => {
      validateAnalysisResult(populatedIncompleteResult());
    }).not.toThrow();
  });

  it('rejects a complete result carrying a cause', () => {
    const result: unknown = { ...populatedCompleteResult(), causes: [causeRecord()] };
    expect(() => {
      validateAnalysisResult(result);
    }).toThrow(TypeError);
  });

  it('rejects a complete result with an incomplete candidate', () => {
    const result = populatedCompleteResult();
    result.candidates = [
      candidateRecord({ classification: 'incomplete', observationId: null, reason: 'unproven-receiver-provenance', causeIds: [] }),
    ];
    expect(() => {
      validateAnalysisResult(result);
    }).toThrow(TypeError);
  });

  it('rejects a complete result with an incomplete permission boundary', () => {
    const result: unknown = {
      ...populatedCompleteResult(),
      permissionBoundary: { status: 'incomplete', reasons: ['missing-permission-requirement'], findings: [] },
    };
    expect(() => {
      validateAnalysisResult(result);
    }).toThrow(TypeError);
  });

  it('rejects an incomplete result with no cause and a complete permission boundary', () => {
    const result = populatedIncompleteResult();
    result.causes = [];
    result.candidates = [];
    expect(() => {
      validateAnalysisResult(result);
    }).toThrow(TypeError);
  });

  it('rejects a result whose resolutions do not cover every observation', () => {
    const result = populatedCompleteResult();
    result.permissionResolutions = [];
    expect(() => {
      validateAnalysisResult(result);
    }).toThrow(TypeError);
  });

  it('rejects a candidate referencing an unanalyzed source path', () => {
    const result = populatedCompleteResult();
    result.candidates = [candidateRecord({ path: 'src/missing.ts' })];
    expect(() => {
      validateAnalysisResult(result);
    }).toThrow(TypeError);
  });

  it('rejects a candidate referencing an unknown cause id', () => {
    const result = populatedIncompleteResult();
    const candidate = result.candidates[0];
    if (candidate === undefined) throw new Error('expected a candidate');
    candidate.causeIds = ['cause-9999'];
    expect(() => {
      validateAnalysisResult(result);
    }).toThrow(TypeError);
  });

  it('rejects an observation referencing an unknown candidate id', () => {
    const result = populatedCompleteResult();
    result.observations = [observation({ candidateId: 'candidate-9999' })];
    expect(() => {
      validateAnalysisResult(result);
    }).toThrow(TypeError);
  });

  it('rejects a permission resolution referencing an unknown observation id', () => {
    const result = populatedCompleteResult();
    result.permissionResolutions = [permissionResolution({ observationId: 'operation-9999' })];
    expect(() => {
      validateAnalysisResult(result);
    }).toThrow(TypeError);
  });

  it('accepts a well-formed failed result', () => {
    const failed: FailedAnalysisResult = {
      status: 'failed',
      identity: clone(IDENTITY),
      reason: 'invalid-analysis-request',
      causes: [causeRecord({ code: 'invalid-analysis-request', scope: 'repository', path: null, span: null })],
    };
    expect(() => {
      validateAnalysisResult(failed);
    }).not.toThrow();
  });

  it('rejects a failed result carrying a semantic evidence key', () => {
    const failed: unknown = {
      status: 'failed',
      identity: clone(IDENTITY),
      reason: 'invalid-analysis-request',
      causes: [causeRecord({ code: 'invalid-analysis-request', scope: 'repository', path: null, span: null })],
      observations: [],
    };
    expect(() => {
      validateAnalysisResult(failed);
    }).toThrow(TypeError);
  });

  it('rejects a failed result with no cause', () => {
    const failed: FailedAnalysisResult = {
      status: 'failed',
      identity: clone(IDENTITY),
      reason: 'invalid-analysis-request',
      causes: [],
    };
    expect(() => {
      validateAnalysisResult(failed);
    }).toThrow(TypeError);
  });

  it('rejects a failed result with an unrecognized reason', () => {
    const failed: unknown = {
      status: 'failed',
      identity: clone(IDENTITY),
      reason: 'not-a-real-reason',
      causes: [causeRecord({ code: 'invalid-analysis-request', scope: 'repository', path: null, span: null })],
    };
    expect(() => {
      validateAnalysisResult(failed);
    }).toThrow(TypeError);
  });

  it('rejects a result with an unrecognized status', () => {
    const result: unknown = { ...populatedCompleteResult(), status: 'unknown' };
    expect(() => {
      validateAnalysisResult(result);
    }).toThrow(TypeError);
  });
});

describe('resource cause code/limitKey/scope/path semantics', () => {
  function withCause(cause: AnalyzerCause): IncompleteAnalysisResult {
    return { ...populatedIncompleteResult(), causes: [cause] };
  }

  const accepted: readonly [string, AnalyzerCause][] = [
    [
      'source-file-limit with maxSourceFiles, repository scope, and no path',
      causeRecord({
        code: 'source-file-limit',
        scope: 'repository',
        path: null,
        span: null,
        resource: resourceOf('maxSourceFiles'),
      }),
    ],
    [
      'source-work-limit with maxSourceWork, repository scope, and no path',
      causeRecord({
        code: 'source-work-limit',
        scope: 'repository',
        path: null,
        span: null,
        resource: resourceOf('maxSourceWork'),
      }),
    ],
    [
      'source-byte-limit with maxSourceFileBytes, source scope, and a path equal to its frontier',
      causeRecord({
        code: 'source-byte-limit',
        scope: 'source',
        path: 'src/app.ts',
        span: null,
        resource: resourceOf('maxSourceFileBytes', { frontier: 'src/app.ts' }),
      }),
    ],
    [
      'source-byte-limit with maxTotalSourceBytes, repository scope, and no path',
      causeRecord({
        code: 'source-byte-limit',
        scope: 'repository',
        path: null,
        span: null,
        resource: resourceOf('maxTotalSourceBytes'),
      }),
    ],
  ];

  for (const [label, cause] of accepted) {
    it(`accepts ${label}`, () => {
      expect(() => {
        validateAnalysisResult(withCause(cause));
      }).not.toThrow();
    });
  }

  const rejected: readonly [string, AnalyzerCause][] = [
    [
      'source-file-limit carrying the maxSourceWork limit key',
      causeRecord({
        code: 'source-file-limit',
        scope: 'repository',
        path: null,
        span: null,
        resource: resourceOf('maxSourceWork'),
      }),
    ],
    [
      'source-file-limit scoped to source instead of repository',
      causeRecord({
        code: 'source-file-limit',
        scope: 'source',
        path: 'src/app.ts',
        span: null,
        resource: resourceOf('maxSourceFiles'),
      }),
    ],
    [
      'source-file-limit carrying a non-null path',
      causeRecord({
        code: 'source-file-limit',
        scope: 'repository',
        path: 'src/app.ts',
        span: null,
        resource: resourceOf('maxSourceFiles'),
      }),
    ],
    [
      'source-work-limit carrying the maxSourceFiles limit key',
      causeRecord({
        code: 'source-work-limit',
        scope: 'repository',
        path: null,
        span: null,
        resource: resourceOf('maxSourceFiles'),
      }),
    ],
    [
      'source-work-limit scoped to source instead of repository',
      causeRecord({
        code: 'source-work-limit',
        scope: 'source',
        path: 'src/app.ts',
        span: null,
        resource: resourceOf('maxSourceWork'),
      }),
    ],
    [
      'source-work-limit carrying a non-null path',
      causeRecord({
        code: 'source-work-limit',
        scope: 'repository',
        path: 'src/app.ts',
        span: null,
        resource: resourceOf('maxSourceWork'),
      }),
    ],
    [
      'per-file source-byte-limit scoped to repository instead of source',
      causeRecord({
        code: 'source-byte-limit',
        scope: 'repository',
        path: null,
        span: null,
        resource: resourceOf('maxSourceFileBytes', { frontier: 'src/app.ts' }),
      }),
    ],
    [
      'per-file source-byte-limit carrying no path',
      causeRecord({
        code: 'source-byte-limit',
        scope: 'source',
        path: null,
        span: null,
        resource: resourceOf('maxSourceFileBytes', { frontier: 'src/app.ts' }),
      }),
    ],
    [
      'per-file source-byte-limit whose path does not equal its own frontier',
      causeRecord({
        code: 'source-byte-limit',
        scope: 'source',
        path: 'src/other.ts',
        span: null,
        resource: resourceOf('maxSourceFileBytes', { frontier: 'src/app.ts' }),
      }),
    ],
    [
      'scan-wide source-byte-limit scoped to source instead of repository',
      causeRecord({
        code: 'source-byte-limit',
        scope: 'source',
        path: 'src/app.ts',
        span: null,
        resource: resourceOf('maxTotalSourceBytes'),
      }),
    ],
    [
      'scan-wide source-byte-limit carrying a non-null path',
      causeRecord({
        code: 'source-byte-limit',
        scope: 'repository',
        path: 'src/app.ts',
        span: null,
        resource: resourceOf('maxTotalSourceBytes'),
      }),
    ],
    [
      'source-byte-limit carrying a limit key that is neither byte budget',
      causeRecord({
        code: 'source-byte-limit',
        scope: 'repository',
        path: null,
        span: null,
        resource: resourceOf('maxSourceFiles'),
      }),
    ],
  ];

  for (const [label, cause] of rejected) {
    it(`rejects ${label}`, () => {
      expect(() => {
        validateAnalysisResult(withCause(cause));
      }).toThrow(TypeError);
    });
  }
});

describe('rejects unknown keys on nested result records', () => {
  const cases: readonly [string, () => CompleteAnalysisResult | IncompleteAnalysisResult, readonly (number | string)[]][] = [
    ['the result itself', populatedCompleteResult, []],
    ['identity', populatedCompleteResult, ['identity']],
    ['identity.analyzerProfile', populatedCompleteResult, ['identity', 'analyzerProfile']],
    ['boundary', populatedCompleteResult, ['boundary']],
    ['boundary.limits', populatedCompleteResult, ['boundary', 'limits']],
    ['sources[0]', populatedCompleteResult, ['sources', 0]],
    ['candidates[0]', populatedCompleteResult, ['candidates', 0]],
    ['candidates[0].span', populatedCompleteResult, ['candidates', 0, 'span']],
    ['candidates[0].span.start', populatedCompleteResult, ['candidates', 0, 'span', 'start']],
    ['observations[0]', populatedCompleteResult, ['observations', 0]],
    ['observations[0].member', populatedCompleteResult, ['observations', 0, 'member']],
    ['observations[0].receiver', populatedCompleteResult, ['observations', 0, 'receiver']],
    ['observations[0].operation', populatedCompleteResult, ['observations', 0, 'operation']],
    ['observations[0].source', populatedCompleteResult, ['observations', 0, 'source']],
    ['observations[0].source.span', populatedCompleteResult, ['observations', 0, 'source', 'span']],
    ['permissionResolutions[0]', populatedCompleteResult, ['permissionResolutions', 0]],
    ['permissionResolutions[0].finding', populatedCompleteResult, ['permissionResolutions', 0, 'finding']],
    [
      'permissionResolutions[0].finding.provenance',
      populatedCompleteResult,
      ['permissionResolutions', 0, 'finding', 'provenance'],
    ],
    [
      'permissionResolutions[0].finding.operation',
      populatedCompleteResult,
      ['permissionResolutions', 0, 'finding', 'operation'],
    ],
    ['permissionBoundary', populatedCompleteResult, ['permissionBoundary']],
    ['permissionBoundary.permissions[0]', populatedCompleteResult, ['permissionBoundary', 'permissions', 0]],
    ['causes[0]', populatedIncompleteResult, ['causes', 0]],
    ['causes[0].span', populatedIncompleteResult, ['causes', 0, 'span']],
    ['causes[0].span.start', populatedIncompleteResult, ['causes', 0, 'span', 'start']],
  ];

  for (const [label, factory, path] of cases) {
    it(`rejects an unknown key added to ${label}`, () => {
      const mutated: unknown = clone(factory());
      const node = nested(mutated, path);
      node.unexpectedField = true;
      expect(() => {
        validateAnalysisResult(mutated);
      }).toThrow(TypeError);
    });
  }
});

describe('empty-universe semantics', () => {
  it('validates a complete empty result carrying all four profile identities', () => {
    const result = emptyCompleteResult();
    expect(() => {
      validateAnalysisResult(result);
    }).not.toThrow();
    expect(result.identity.schemaId).toBe(ANALYSIS_SCHEMA_ID);
    expect(result.identity.spanConventionId).toBe(ANALYSIS_SPAN_CONVENTION_ID);
    expect(result.identity.discoveryProfileId).toBe(ANALYSIS_DISCOVERY_PROFILE_ID);
    expect(result.identity.limitProfileId).toBe(ANALYSIS_LIMIT_PROFILE_ID);
    expect(result.identity.analyzerProfile).toEqual(ANALYZER_PROFILE_IDENTITY);
    expect(result.identity.permissionCatalogScopeSha256).toBe(BOUNDARYCI_PERMISSION_CATALOG_IDENTITY.authorizedScopeSha256);
  });

  it('keeps the source-extension order stable in the empty boundary', () => {
    const result = emptyCompleteResult();
    expect(result.boundary.sourceExtensions).toEqual([...ANALYZER_SOURCE_EXTENSIONS]);
  });

  it('rejects an empty universe paired with an incomplete permission boundary', () => {
    const result: unknown = {
      ...emptyCompleteResult(),
      permissionBoundary: { status: 'incomplete', reasons: ['missing-permission-requirement'], findings: [] },
    };
    expect(() => {
      validateAnalysisResult(result);
    }).toThrow(TypeError);
  });
});

describe('JSON round-trip and canonical equality', () => {
  it('round-trips a populated complete result byte-for-byte', () => {
    const result = populatedCompleteResult();
    const serialized = JSON.stringify(result);
    const parsed: unknown = JSON.parse(serialized);
    expect(JSON.stringify(parsed)).toBe(serialized);
    expect(parsed).toEqual(result);
    expect(() => {
      validateAnalysisResult(parsed);
    }).not.toThrow();
  });

  it('round-trips a populated incomplete result byte-for-byte', () => {
    const result = populatedIncompleteResult();
    const serialized = JSON.stringify(result);
    const parsed: unknown = JSON.parse(serialized);
    expect(JSON.stringify(parsed)).toBe(serialized);
    expect(parsed).toEqual(result);
    expect(() => {
      validateAnalysisResult(parsed);
    }).not.toThrow();
  });

  it('round-trips an empty complete result byte-for-byte', () => {
    const result = emptyCompleteResult();
    const serialized = JSON.stringify(result);
    const parsed: unknown = JSON.parse(serialized);
    expect(JSON.stringify(parsed)).toBe(serialized);
    expect(parsed).toEqual(result);
    expect(() => {
      validateAnalysisResult(parsed);
    }).not.toThrow();
  });

  it('produces canonically equal JSON for independently constructed identical results', () => {
    const first = populatedCompleteResult();
    const second = populatedCompleteResult();
    expect(JSON.stringify(first)).toBe(JSON.stringify(second));
    expect(first).toEqual(second);
  });
});

describe('deterministic ordinal identifiers', () => {
  it('rejects an ordinal id missing its minimum digit width', () => {
    const result = populatedCompleteResult();
    const source = result.sources[0];
    if (source === undefined) throw new Error('expected a source');
    source.id = 'source-1';
    expect(() => {
      validateAnalysisResult(result);
    }).toThrow(TypeError);
  });

  it('rejects an ordinal id using an uppercase prefix', () => {
    const result = populatedCompleteResult();
    const source = result.sources[0];
    if (source === undefined) throw new Error('expected a source');
    source.id = 'Source-0001';
    expect(() => {
      validateAnalysisResult(result);
    }).toThrow(TypeError);
  });

  it('rejects duplicate ids among sources', () => {
    const result = populatedCompleteResult();
    result.sources = [sourceRecord(), sourceRecord({ path: 'src/other.ts' })];
    expect(() => {
      validateAnalysisResult(result);
    }).toThrow(TypeError);
  });

  it('rejects duplicate ids among candidates', () => {
    const result = populatedCompleteResult();
    result.candidates = [candidateRecord(), candidateRecord()];
    expect(() => {
      validateAnalysisResult(result);
    }).toThrow(TypeError);
  });

  it('rejects duplicate ids among causes', () => {
    const result = populatedIncompleteResult();
    result.causes = [causeRecord(), causeRecord()];
    expect(() => {
      validateAnalysisResult(result);
    }).toThrow(TypeError);
  });

  it('rejects duplicate ids among observations', () => {
    const result = populatedCompleteResult();
    result.observations = [observation(), observation()];
    expect(() => {
      validateAnalysisResult(result);
    }).toThrow(TypeError);
  });

  it('rejects duplicate ids among permission resolutions', () => {
    const result = populatedCompleteResult();
    result.permissionResolutions = [permissionResolution(), permissionResolution()];
    expect(() => {
      validateAnalysisResult(result);
    }).toThrow(TypeError);
  });
});

describe('source-only regular and symlink fixtures', () => {
  it('writes byte-exact regular file contents including multi-byte UTF-8 text', async () => {
    const root = await createTempRoot();
    const content = 'const emoji = "café 😀";\n';
    const target = await writeRegularFile(root, 'src/unicode.ts', content);
    const bytes = await readFile(target);
    expect(bytes.equals(Buffer.from(content, 'utf8'))).toBe(true);
    expect(bytes.byteLength).toBe(Buffer.byteLength(content, 'utf8'));
  });

  it('writes byte-exact contents for a raw byte payload', async () => {
    const root = await createTempRoot();
    const raw = new Uint8Array([0x00, 0x01, 0xff, 0x10, 0x20]);
    const target = await writeRegularFile(root, 'binary.dat', raw);
    const bytes = await readFile(target);
    expect(bytes.equals(Buffer.from(raw))).toBe(true);
  });

  it('creates an explicit dangling symlink that is never followed or read', async () => {
    const root = await createTempRoot();
    const target = await createSymlink(root, 'src/link.ts', './does-not-exist.ts');
    const linkStat = await lstat(target);
    expect(linkStat.isSymbolicLink()).toBe(true);
    expect(linkStat.isFile()).toBe(false);
    await expect(stat(target)).rejects.toThrow();
  });

  it('rejects a fixture path that would escape its temporary root', async () => {
    const root = await createTempRoot();
    await expect(writeRegularFile(root, '../outside.ts', 'export {};\n')).rejects.toThrow();
  });

  it('removes every tracked root on cleanup', async () => {
    const root = await createTempRoot();
    await writeRegularFile(root, 'src/app.ts', 'export {};\n');
    await cleanupTempRoots();
    await expect(stat(root)).rejects.toThrow();
  });
});

describe('fixture non-execution probes', () => {
  const sentinelKey = '__boundaryciAnalyzerFixtureExecuted__';

  afterEach(() => {
    delete (globalThis as Record<string, unknown>)[sentinelKey];
  });

  it('never evaluates hostile fixture text while writing it to disk', async () => {
    const root = await createTempRoot();
    const hostile = [`globalThis.${sentinelKey} = true;`, 'throw new Error("this fixture must never execute");'].join(
      '\n',
    );
    const target = await writeRegularFile(root, 'src/hostile.ts', hostile);
    expect((globalThis as Record<string, unknown>)[sentinelKey]).toBeUndefined();
    const onDisk = await readFile(target, 'utf8');
    expect(onDisk).toBe(hostile);
  });

  it('never evaluates hostile fixture text while creating a symlink to it', async () => {
    const root = await createTempRoot();
    await writeRegularFile(root, 'src/hostile.ts', `globalThis.${sentinelKey} = true;\n`);
    await createSymlink(root, 'src/hostile-link.ts', './hostile.ts');
    expect((globalThis as Record<string, unknown>)[sentinelKey]).toBeUndefined();
  });

  it('contains no import, require, transpile, build, or spawn behavior in its own source text', async () => {
    const helpersSource = await readFile(new URL('./helpers.ts', import.meta.url), 'utf8');
    const forbidden = [
      'require(',
      'import(',
      'node:child_process',
      "'child_process'",
      'eval(',
      'new Function(',
      'execSync',
      'spawn(',
      'transpileModule',
      'createProgram',
      'readFileSync',
      'readFile(',
    ];
    for (const token of forbidden) {
      expect(helpersSource).not.toContain(token);
    }
  });
});
