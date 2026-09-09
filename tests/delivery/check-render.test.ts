import { describe, expect, it } from 'vitest';
import { chmod, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

import {
  CHECK_ANNOTATION_LIMIT,
  CHECK_DETAILS_RECORD_LIMIT,
  CHECK_DETAILS_UTF8_LIMIT,
  CHECK_SUMMARY_UTF8_LIMIT,
  renderCompletedCheck,
  selectCheckAnnotations,
} from '../../src/delivery/check-render.js';
import type { CheckAnnotationV1 } from '../../src/delivery/check-contract.js';
import type { CheckIdentityV1 } from '../../src/delivery/check-contract.js';
import { deriveCheckCorrelationId } from '../../src/delivery/check-contract.js';
import { BUILTIN_CONFIG, effectiveConfigIdentity } from '../../src/config/model.js';
import { evaluateLocalComparison } from '../../src/runtime/evaluate.js';

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

const BASE_SHA = 'a'.repeat(40);
const HEAD_SHA = 'b'.repeat(40);
const identity: CheckIdentityV1 = {
  version: 1,
  installationId: 1,
  repositoryId: 2,
  pullNumber: 3,
  baseRepositoryId: 2,
  baseRef: 'main',
  baseSha: BASE_SHA,
  headRepositoryId: 2,
  headSha: HEAD_SHA,
  topology: 'same-repository',
  evaluatorIdentity: 'boundaryci-evaluator-v1',
  engineId: 'boundaryci/revision-engine@1',
  analyzer: {},
  catalogAuthorizedScopeSha256: 'c'.repeat(64),
  effectiveConfigSha256: 'd'.repeat(64),
  correlationId: `boundaryci:v1:${'e'.repeat(64)}`,
};

const READ_SOURCE = "import { Octokit } from 'octokit';\nconst client = new Octokit();\nclient.rest.issues.listForRepo({});\n";
const WRITE_SOURCE = "import { Octokit } from 'octokit';\nconst client = new Octokit();\nclient.rest.issues.create({});\n";
const INCOMPLETE_SOURCE = "import { Octokit } from 'octokit';\nconst client = new Octokit();\nclient.rest.pulls.list({});\n";
const EMPTY_SOURCE = 'export const boundaryciFixture = true;\n';

function writeCalls(count: number): string {
  return `import { Octokit } from 'octokit';\nconst client = new Octokit();\n${Array.from({ length: count }, () => 'client.rest.issues.create({});').join('\n')}\n`;
}

function selectedConfig() {
  return {
    status: 'selected' as const,
    authority: { source: 'built-in-default' as const, config: structuredClone(BUILTIN_CONFIG), identity: effectiveConfigIdentity(BUILTIN_CONFIG) },
    head: { status: 'absent' as const },
  };
}

async function roots(): Promise<{ base: string; head: string }> {
  const parent = join(tmpdir(), 'boundaryci-check-render-v1');
  await mkdir(parent, { recursive: true, mode: 0o700 });
  await chmod(parent, 0o700);
  const [base, head] = await Promise.all([mkdtemp(join(parent, 'boundaryci-snapshot-')), mkdtemp(join(parent, 'boundaryci-snapshot-'))]);
  await Promise.all([chmod(base, 0o700), chmod(head, 0o700)]);
  return { base, head };
}

async function rendered(baseSource: string, headSource: string, policy = '', sourcePath = 'app.ts') {
  const sourceRoots = await roots();
  try {
    await Promise.all([mkdir(join(sourceRoots.base, dirname(sourcePath)), { recursive: true }), mkdir(join(sourceRoots.head, dirname(sourcePath)), { recursive: true })]);
    await Promise.all([
      writeFile(join(sourceRoots.base, '.boundaryci.yml'), `version: 1\n${policy}`),
      writeFile(join(sourceRoots.head, '.boundaryci.yml'), 'version: 1\n'),
      writeFile(join(sourceRoots.base, sourcePath), baseSource),
      writeFile(join(sourceRoots.head, sourcePath), headSource),
    ]);
    const evaluation = await evaluateLocalComparison(sourceRoots.base, sourceRoots.head);
    if (evaluation.status !== 'selected') throw new Error('renderer fixture evaluation was not selected');
    const incomplete = evaluation.comparison.status === 'incomplete';
    const acquisition = incomplete
      ? { status: 'incomplete' as const, config: selectedConfig(), snapshots: { base: { commitSha: BASE_SHA, treeSha: 'c'.repeat(40), sourceFileCount: 2, sourceBytes: 1 }, head: { commitSha: HEAD_SHA, treeSha: 'd'.repeat(40), sourceFileCount: 2, sourceBytes: 1 } }, causes: [], semanticUsability: 'positive-evidence-only' as const, allowedClaims: ['present-observations', 'present-requirements'] as const }
      : { status: 'complete' as const, config: selectedConfig(), snapshots: { base: { commitSha: BASE_SHA, treeSha: 'c'.repeat(40), sourceFileCount: 2, sourceBytes: 1 }, head: { commitSha: HEAD_SHA, treeSha: 'd'.repeat(40), sourceFileCount: 2, sourceBytes: 1 } }, causes: [], semanticUsability: 'complete' as const };
    const envelope = {
      schemaVersion: 1 as const, lifecycle: 'current' as const, handoff: 'publishable-semantic' as const,
      work: { installationId: 1, repositoryId: 2, pullNumber: 3, baseSha: BASE_SHA, headSha: HEAD_SHA, evaluatorIdentity: 'boundaryci-evaluator-v1' },
      trigger: { deliveryIds: [] }, acquisition,
      semantic: { status: incomplete ? 'incomplete' as const : 'complete' as const, semanticUsability: incomplete ? 'positive-evidence-only' as const : 'complete' as const, evaluation },
      phase6FreshnessRequired: true as const,
      phase6Match: { repositoryId: 2, pullNumber: 3, baseRepositoryId: 2, baseRef: 'main', baseSha: BASE_SHA, headRepositoryId: 2, headSha: HEAD_SHA, topology: 'same-repository' as const, eligibility: 'open' as const },
    };
    return { envelope, payload: renderCompletedCheck(envelope, deriveCheckCorrelationId(envelope)) };
  } finally {
    await Promise.all([rm(sourceRoots.base, { recursive: true, force: true }), rm(sourceRoots.head, { recursive: true, force: true })]);
  }
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

  it('reports selected and omitted severity arithmetic for the exact 0/49/50/51/250/>250 boundary matrix', () => {
    for (const count of [0, 49, 50, 51, 250, 251]) {
      const candidates = Array.from({ length: count }, (_, index) => annotation(index, index % 3 === 0 ? 'failure' : index % 3 === 1 ? 'warning' : 'notice'));
      const selected = selectCheckAnnotations(candidates);
      const selectedByLevel = Object.fromEntries(['failure', 'warning', 'notice'].map((level) => [level, selected.filter((item) => item.level === level).length]));
      const omittedByLevel = Object.fromEntries(['failure', 'warning', 'notice'].map((level) => [level, candidates.filter((item) => item.level === level).length - selectedByLevel[level]! ]));

      expect(selected).toHaveLength(Math.min(count, 50));
      expect(Object.values(omittedByLevel).reduce((sum, value) => sum + value, 0)).toBe(count - selected.length);
    }
  });

  it('rejects unknown fields and non-truthful navigation paths rather than emitting them', () => {
    expect(() => selectCheckAnnotations([{ ...annotation(1), token: 'renderer-secret-sentinel' }] as unknown as CheckAnnotationV1[])).toThrow(TypeError);
    expect(() => selectCheckAnnotations([{ ...annotation(1), path: '../outside.ts' }])).toThrow(TypeError);
    expect(() => selectCheckAnnotations([{ ...annotation(1), path: '/absolute.ts' }])).toThrow(TypeError);
  });

  it.each([
    ['A07', 'input-configuration-failure'],
    ['A08', 'unsupported-topology'],
    ['A09 acquisition', 'acquisition-runtime-failure'],
    ['A09 evaluator', 'evaluator-runtime-failure'],
  ] as const)('%s renders diagnostic code %s with closed action-required copy and no fabricated location', (_case, code) => {
    const diagnostic = {
      schemaVersion: 1,
      lifecycle: 'current',
      handoff: 'diagnostic-only',
      work: { installationId: 1, repositoryId: 2, pullNumber: 3, baseSha: BASE_SHA, headSha: HEAD_SHA, evaluatorIdentity: 'boundaryci-evaluator-v1' },
      trigger: { deliveryIds: [] },
      diagnostic: { code },
      phase6FreshnessRequired: true,
      phase6Match: { repositoryId: 2, pullNumber: 3, baseRepositoryId: 2, baseRef: 'main', baseSha: BASE_SHA, headRepositoryId: code === 'unsupported-topology' ? 4 : 2, headSha: HEAD_SHA, topology: code === 'unsupported-topology' ? 'unsupported-topology' : 'same-repository', eligibility: 'open' },
    } as const;

    const diagnosticIdentity = code === 'unsupported-topology'
      ? { ...identity, headRepositoryId: 4, topology: 'unsupported-topology' as const }
      : identity;
    expect(renderCompletedCheck(diagnostic as never, diagnosticIdentity)).toMatchObject({
      conclusion: 'action_required',
      title: 'BoundaryCI could not evaluate this change',
      annotations: [],
    });
    expect(renderCompletedCheck(diagnostic as never, diagnosticIdentity).text).toContain(`- ${code}:`);
  });

  it.each([
    ['A01 complete unchanged', WRITE_SOURCE, WRITE_SOURCE, '', 'success', 'Permission boundary unchanged'],
    ['A02 complete reduction', WRITE_SOURCE, READ_SOURCE, '', 'success', 'Permission boundary reduced'],
    ['A03 permitted expansion', READ_SOURCE, WRITE_SOURCE, 'policy:\n  failOnExpansion: false\n', 'success', 'Permission expansion permitted'],
    ['A04 blocked expansion', READ_SOURCE, WRITE_SOURCE, '', 'failure', 'Permission expansion requires review'],
    ['A05 permitted incomplete', READ_SOURCE, INCOMPLETE_SOURCE, 'policy:\n  failOnIncomplete: false\n', 'neutral', 'Analysis incomplete'],
    ['A06 rejected incomplete', READ_SOURCE, INCOMPLETE_SOURCE, '', 'failure', 'Repository policy failed'],
  ])('%s maps to the closed Check conclusion and title', async (_name, base, head, policy, conclusion, title) => {
    const { payload } = await rendered(base, head, policy);

    expect(payload).toMatchObject({ conclusion, title, name: 'BoundaryCI', status: 'completed' });
    expect(payload.summary).toContain('## BoundaryCI result');
    expect(payload.summary).toContain('## Policy');
    expect(payload.summary).toContain('## Aggregate permission changes');
    expect(payload.summary).toContain('## Annotation coverage');
    expect(payload.summary).toContain('## Comparison');
    expect(payload.summary).toContain('## Publication status');
    expect(Buffer.byteLength(payload.summary, 'utf8')).toBeLessThanOrEqual(CHECK_SUMMARY_UTF8_LIMIT);
    expect(Buffer.byteLength(payload.text, 'utf8')).toBeLessThanOrEqual(CHECK_DETAILS_UTF8_LIMIT);
  });

  it('A10-A13 and identity mismatches fail closed without producing a Check payload', async () => {
    const { envelope } = await rendered(READ_SOURCE, WRITE_SOURCE);
    const identity = deriveCheckCorrelationId(envelope);

    expect(() => renderCompletedCheck(envelope, { ...identity, headSha: BASE_SHA })).toThrow(TypeError);
    expect(() => renderCompletedCheck(envelope, { ...identity, correlationId: `boundaryci:v1:${'f'.repeat(64)}` })).toThrow(TypeError);
    expect(() => renderCompletedCheck({ ...envelope, unexpected: 'renderer-secret-sentinel' } as never, identity)).toThrow(TypeError);
    expect(() => renderCompletedCheck({ schemaVersion: 1, lifecycle: 'stale', handoff: 'none', work: null, reason: 'authenticated-comparison-drift' } as never, identity)).toThrow(TypeError);
  });

  it('is byte-identical for repeated rendering, preserves input, and keeps base-only evidence out of current-head navigation', async () => {
    const { envelope, payload } = await rendered(WRITE_SOURCE, READ_SOURCE);
    const before = structuredClone(envelope);
    const first = renderCompletedCheck(envelope, deriveCheckCorrelationId(envelope));
    const second = renderCompletedCheck(envelope, deriveCheckCorrelationId(envelope));

    expect(first).toEqual(second);
    expect(payload.annotations).toEqual([]);
    expect(payload.text).toContain('### Evidence not annotated');
    expect(payload.text).toContain('no truthful current-head navigation location exists');
    expect(payload.text).not.toContain('base-only evidence for issues: write → read; no truthful current-head navigation location exists. current-head');
    expect(envelope).toEqual(before);
  });

  it('A36/A38 reject control-character path injection before selector or renderer Markdown can be emitted', async () => {
    expect(() => selectCheckAnnotations([{ ...annotation(1), path: 'src/ok.ts\n## injected' }])).toThrow(TypeError);
    expect(() => selectCheckAnnotations([{ ...annotation(1), path: 'src/ok.ts\u0000token' }])).toThrow(TypeError);
    await expect(rendered(EMPTY_SOURCE, WRITE_SOURCE, '', 'src/ok\u007f.ts')).rejects.toThrow(TypeError);
  });

  it('A03-A06 report exact aggregate contributor, unresolved-operation, and annotation-class counts', async () => {
    const permitted = await rendered(READ_SOURCE, WRITE_SOURCE, 'policy:\n  failOnExpansion: false\n');
    const incomplete = await rendered(READ_SOURCE, INCOMPLETE_SOURCE, 'policy:\n  failOnIncomplete: false\n');

    expect(permitted.payload.summary).toContain('1 contributing head-side operation');
    expect(permitted.payload.summary).toContain('Selected classes: permitted expansion 1; policy failure 0; incomplete analysis 0; diagnostic 0.');
    expect(incomplete.payload.summary).toContain('Unresolved/incomplete operations: 1.');
    expect(incomplete.payload.text).toContain('incomplete evidence');
  });

  it('A32-A35 retain exactly 500 whole detail records and append one bounded truncation record for the next record', async () => {
    const exact = await rendered(EMPTY_SOURCE, writeCalls(500));
    const over = await rendered(EMPTY_SOURCE, writeCalls(501));

    expect(exact.payload.text).not.toContain('### Detail limits');
    expect(over.payload.text).toContain('### Detail limits');
    expect(over.payload.text).toMatch(/Details truncated: 1 complete record\(s\) omitted by the item bound\./u);
    expect(over.payload.summary).toContain('Annotations: eligible 501; selected for an initial create 50; omitted 451.');
    expect(over.payload.summary).toContain('Omitted: failure 451; warning 0; notice 0.');
    expect(over.payload.text).toContain('annotation selection limit');
    expect(Buffer.byteLength(over.payload.text, 'utf8')).toBeLessThanOrEqual(CHECK_DETAILS_UTF8_LIMIT);
  });

  it('A34-A36 reserve the UTF-8 truncation marker around multibyte hostile inline-code paths', async () => {
    const hostilePath = `\`\`@[]<>|#/€/${Array.from({ length: 8 }, (_, index) => `${index}${'界'.repeat(40)}`).join('/')}/tail\`\`.ts`;
    const { payload } = await rendered(EMPTY_SOURCE, writeCalls(120), '', hostilePath);

    expect(Buffer.byteLength(payload.text, 'utf8')).toBeLessThanOrEqual(CHECK_DETAILS_UTF8_LIMIT);
    expect(payload.text).toContain('### Detail limits');
    expect(payload.text).toMatch(/Details truncated: \d+ complete record\(s\) omitted by the UTF-8 byte bound\./u);
    expect(payload.text).toContain('``` ``@[]<>|#/');
    expect(payload.text).not.toContain('\n## injected');
  });
});
