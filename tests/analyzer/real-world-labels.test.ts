import { createHash } from 'node:crypto';
import { lstat, readFile } from 'node:fs/promises';
import { isAbsolute, resolve, sep } from 'node:path';

import { beforeAll, describe, expect, it } from 'vitest';

import { analyzeSourceTree } from '../../src/analyzer/analyze.js';
import { DEFAULT_ANALYSIS_LIMITS } from '../../src/analyzer/contract.js';
import type { AnalysisResult, CandidateRecord, OperationObservation } from '../../src/analyzer/contract.js';
import type { SourceSpan } from '../../src/permission-model/model.js';

import frozenLabels from './fixtures/real-world-labels.json' with { type: 'json' };

type Confidence = 'certain' | 'uncertain';
type Relevance = 'non-octokit' | 'relevant';
type ExpectedLabel =
  | { kind: 'incomplete' }
  | { kind: 'irrelevant' }
  | { kind: 'operation'; method: string; normalizedRoute: string; operationId: string };

interface SiteLabel {
  id: string;
  path: string;
  span: SourceSpan;
  receiverClass: string;
  callClass: string;
  reportClasses: string[];
  confidence: Confidence;
  relevance: Relevance;
  insideSupportedGrammar: boolean;
  expected: ExpectedLabel;
  reviewerRole: string;
  labeledAt: string;
}

interface FileLabel {
  path: string;
  byteSize: number;
  sha256: string;
}

interface RepositoryLabels {
  fullName: string;
  clientStyle: string;
  language: string;
  sha: string;
  snapshotDigest: string;
  rootDir: string;
  includes: string[];
  probotEntrypoints: string[];
  files: FileLabel[];
  labels: SiteLabel[];
}

interface LabelManifest {
  schemaVersion: number;
  selection: {
    ruleVersion: string;
    rule: string;
    corpusManifestSha256: string;
    frozenAt: string;
  };
  reportClasses: string[];
  repositories: RepositoryLabels[];
  labelSetSha256: string;
}

interface CorpusRepository {
  fullName: string;
  clientStyle: string;
  language: string;
  sha: string;
  snapshotDigest: string;
  usageFiles: number;
  sourceBytes: number;
}

interface CorpusManifest {
  repositories: CorpusRepository[];
}

interface RepositoryRun {
  repository: RepositoryLabels;
  result: Exclude<AnalysisResult, { status: 'failed' }>;
}

interface LabelOutcome {
  label: SiteLabel;
  status: 'incomplete' | 'missed' | 'proven';
}

const manifest = frozenLabels as LabelManifest;
const corpusRootFromEnvironment = process.env.BOUNDARYCI_REAL_WORLD_CORPUS_ROOT;
const REQUIRED_REPORT_CLASSES = [
  'direct-constructed-client',
  'designated-probot-context',
  'ecmascript-private-field',
  'positional-request',
  'object-request',
  'direct-shorthand',
  'endpoint-extraction',
  'static-bracket',
  'dynamic-member-route',
  'unproved-relevant-receiver',
  'certain-non-octokit-decoy',
];

function sha256(bytes: string | Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const object = value as Record<string, unknown>;
  return `{${Object.keys(object)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(object[key])}`)
    .join(',')}}`;
}

function compareBytes(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function spanKey(path: string, span: SourceSpan): string {
  return JSON.stringify([
    path,
    span.start.line,
    span.start.column,
    span.end.line,
    span.end.column,
  ]);
}

function assertRelativePath(path: string, label: string): void {
  expect(isAbsolute(path), `${label} must be relative`).toBe(false);
  expect(path.split('/')).not.toContain('..');
  expect(path).not.toContain('\\');
}

function assertSpanInsideText(span: SourceSpan, text: string, label: string): void {
  const lines = text.split(/\r\n|\n|\r/u);
  const points = [span.start, span.end];
  for (const point of points) {
    expect(Number.isInteger(point.line), `${label} line must be an integer`).toBe(true);
    expect(Number.isInteger(point.column), `${label} column must be an integer`).toBe(true);
    expect(point.line, `${label} line`).toBeGreaterThanOrEqual(1);
    expect(point.line, `${label} line`).toBeLessThanOrEqual(lines.length);
    const line = lines[point.line - 1] ?? '';
    expect(point.column, `${label} column`).toBeGreaterThanOrEqual(1);
    expect(point.column, `${label} column`).toBeLessThanOrEqual(line.length + 1);
  }
  expect(
    span.end.line > span.start.line ||
      (span.end.line === span.start.line && span.end.column > span.start.column),
    `${label} must be a nonempty start-inclusive/end-exclusive span`,
  ).toBe(true);
}

function selectedRepositories(corpus: CorpusManifest): CorpusRepository[] {
  const strata = new Map<string, CorpusRepository[]>();
  for (const repository of corpus.repositories) {
    const key = JSON.stringify([repository.clientStyle, repository.language]);
    const current = strata.get(key) ?? [];
    current.push(repository);
    strata.set(key, current);
  }
  return [...strata.entries()]
    .sort(([left], [right]) => compareBytes(left, right))
    .map(([, repositories]) =>
      [...repositories].sort(
        (left, right) =>
          left.usageFiles - right.usageFiles ||
          left.sourceBytes - right.sourceBytes ||
          compareBytes(left.fullName, right.fullName),
      )[0],
    )
    .filter((entry): entry is CorpusRepository => entry !== undefined);
}

async function validateFrozenManifest(corpusRoot: string): Promise<void> {
  expect(manifest.schemaVersion).toBe(1);
  expect(manifest.selection.ruleVersion).toBe('boundaryci-real-world-strata@1');
  expect(manifest.reportClasses).toEqual(REQUIRED_REPORT_CLASSES);
  expect(new Set(manifest.reportClasses).size).toBe(manifest.reportClasses.length);

  const digestInput = structuredClone(manifest) as LabelManifest;
  delete (digestInput as Partial<LabelManifest>).labelSetSha256;
  expect(sha256(canonicalJson(digestInput))).toBe(manifest.labelSetSha256);

  const corpusPath = resolve(corpusRoot, 'corpus.json');
  const corpusBytes = await readFile(corpusPath);
  expect(sha256(corpusBytes)).toBe(manifest.selection.corpusManifestSha256);
  const corpus = JSON.parse(corpusBytes.toString('utf8')) as CorpusManifest;
  const selected = selectedRepositories(corpus);
  expect(manifest.repositories.map((repository) => repository.fullName)).toEqual(
    selected.map((repository) => repository.fullName),
  );

  const labelsSeen = new Set<string>();
  for (const repository of manifest.repositories) {
    const selectedRepository = selected.find((entry) => entry.fullName === repository.fullName);
    expect(selectedRepository).toBeDefined();
    expect(repository.clientStyle).toBe(selectedRepository?.clientStyle);
    expect(repository.language).toBe(selectedRepository?.language);
    expect(repository.sha).toBe(selectedRepository?.sha);
    expect(repository.snapshotDigest).toBe(selectedRepository?.snapshotDigest);
    assertRelativePath(repository.rootDir, `${repository.fullName} rootDir`);
    expect(repository.includes.length).toBeGreaterThan(0);
    expect(new Set(repository.includes).size).toBe(repository.includes.length);
    expect(new Set(repository.files.map((file) => file.path))).toEqual(new Set(repository.includes));
    for (const entrypoint of repository.probotEntrypoints) {
      expect(repository.includes).toContain(entrypoint);
    }

    const repositoryRoot = resolve(corpusRoot, ...repository.rootDir.split('/'));
    const rootPrefix = `${repositoryRoot}${sep}`;
    const sourceTexts = new Map<string, string>();
    for (const file of repository.files) {
      assertRelativePath(file.path, `${repository.fullName} file path`);
      const absolutePath = resolve(repositoryRoot, ...file.path.split('/'));
      expect(absolutePath.startsWith(rootPrefix)).toBe(true);
      const stats = await lstat(absolutePath);
      expect(stats.isSymbolicLink()).toBe(false);
      expect(stats.isFile()).toBe(true);
      const bytes = await readFile(absolutePath);
      expect(bytes.byteLength).toBe(file.byteSize);
      expect(sha256(bytes)).toBe(file.sha256);
      sourceTexts.set(file.path, bytes.toString('utf8'));
    }

    for (const label of repository.labels) {
      expect(labelsSeen.has(label.id), `duplicate label ${label.id}`).toBe(false);
      labelsSeen.add(label.id);
      expect(repository.includes).toContain(label.path);
      expect(label.reviewerRole).toBe('independent-source-reviewer');
      expect(label.labeledAt).toBe(manifest.selection.frozenAt);
      expect(['certain', 'uncertain']).toContain(label.confidence);
      expect(['non-octokit', 'relevant']).toContain(label.relevance);
      expect(label.reportClasses.length).toBeGreaterThan(0);
      for (const reportClass of label.reportClasses) expect(manifest.reportClasses).toContain(reportClass);
      if (label.insideSupportedGrammar) {
        expect(label.confidence).toBe('certain');
        expect(label.expected.kind).toBe('operation');
      }
      if (label.relevance === 'non-octokit') expect(label.expected.kind).toBe('irrelevant');
      const sourceText = sourceTexts.get(label.path);
      expect(sourceText).toBeDefined();
      assertSpanInsideText(label.span, sourceText ?? '', label.id);
    }
  }
}

function classifyLabel(
  label: SiteLabel,
  observations: ReadonlyMap<string, OperationObservation>,
  candidates: ReadonlyMap<string, CandidateRecord>,
): LabelOutcome {
  const key = spanKey(label.path, label.span);
  const observation = observations.get(key);
  const candidate = candidates.get(key);
  if (label.expected.kind === 'irrelevant') {
    return { label, status: observation === undefined ? 'proven' : 'missed' };
  }
  if (observation !== undefined) return { label, status: 'proven' };
  if (candidate?.classification === 'incomplete') return { label, status: 'incomplete' };
  return { label, status: 'missed' };
}

const runRealWorld = corpusRootFromEnvironment === undefined ? describe.skip : describe;

runRealWorld('independently labeled real-world corpus', () => {
  const runs: RepositoryRun[] = [];
  const outcomes: LabelOutcome[] = [];
  let falsePositiveProven = 0;
  let falseCleanCertain = 0;
  let supportedGrammarFailures = 0;

  beforeAll(async () => {
    const corpusRoot = resolve(corpusRootFromEnvironment as string);
    // This validation is intentionally completed before the first analyzer call. The frozen
    // labels, selected strata, source identities, and canonical label-set digest therefore form
    // an analyzer-independent denominator rather than a census-derived oracle.
    await validateFrozenManifest(corpusRoot);

    for (const repository of manifest.repositories) {
      const rootPath = resolve(corpusRoot, ...repository.rootDir.split('/'));
      const result = await analyzeSourceTree({
        rootPath,
        include: [...repository.includes],
        exclude: [],
        probotEntrypoints: [...repository.probotEntrypoints],
        limits: { ...DEFAULT_ANALYSIS_LIMITS },
      });
      if (result.status === 'failed') throw new Error(`${repository.fullName} analysis failed: ${result.reason}`);
      runs.push({ repository, result });

      const observations = new Map(
        result.observations.map((observation) => [spanKey(observation.source.path, observation.source.span), observation]),
      );
      const candidates = new Map(
        result.candidates.map((candidate) => [spanKey(candidate.path, candidate.span), candidate]),
      );
      const repositoryLabels = new Map(
        repository.labels.map((label) => [spanKey(label.path, label.span), label]),
      );

      for (const observation of result.observations) {
        const label = repositoryLabels.get(spanKey(observation.source.path, observation.source.span));
        if (
          label?.confidence !== 'certain' ||
          label.relevance !== 'relevant' ||
          label.expected.kind !== 'operation' ||
          label.expected.method !== observation.operation.method ||
          label.expected.normalizedRoute !== observation.operation.normalizedRoute ||
          label.expected.operationId !== observation.operation.operationId
        ) {
          falsePositiveProven += 1;
        }
      }

      for (const label of repository.labels) {
        const outcome = classifyLabel(label, observations, candidates);
        outcomes.push(outcome);
        if (label.confidence !== 'certain') continue;
        if (label.relevance === 'relevant' && outcome.status === 'missed') falseCleanCertain += 1;
        if (label.insideSupportedGrammar) {
          const observation = observations.get(spanKey(label.path, label.span));
          if (
            label.expected.kind !== 'operation' ||
            observation === undefined ||
            observation.operation.method !== label.expected.method ||
            observation.operation.normalizedRoute !== label.expected.normalizedRoute ||
            observation.operation.operationId !== label.expected.operationId
          ) {
            supportedGrammarFailures += 1;
          }
        }
      }
    }
  });

  it('binds selected repository, snapshot, file, source-span, reviewer, and label-set identities before comparison', () => {
    expect(runs).toHaveLength(manifest.repositories.length);
    expect(manifest.repositories.flatMap((repository) => repository.labels)).not.toHaveLength(0);
  });

  it('has zero false-positive proven operations and no operation for certain non-Octokit decoys', () => {
    expect(falsePositiveProven).toBe(0);
    const decoys = outcomes.filter((outcome) => outcome.label.relevance === 'non-octokit');
    expect(decoys).not.toHaveLength(0);
    expect(decoys.every((outcome) => outcome.status === 'proven')).toBe(true);
  });

  it('accounts for every certainly relevant site as proven or explicitly incomplete', () => {
    expect(falseCleanCertain).toBe(0);
  });

  it('proves every certain in-grammar site as the exact independently labeled operation', () => {
    expect(supportedGrammarFailures).toBe(0);
  });

  it('reports proven, incomplete, missed, and uncertain counts for every predeclared class', () => {
    const report = Object.fromEntries(
      manifest.reportClasses.map((reportClass) => {
        const classOutcomes = outcomes.filter((outcome) => outcome.label.reportClasses.includes(reportClass));
        return [
          reportClass,
          {
            denominator: classOutcomes.length,
            proven: classOutcomes.filter((outcome) => outcome.label.confidence === 'certain' && outcome.status === 'proven').length,
            incomplete: classOutcomes.filter(
              (outcome) => outcome.label.confidence === 'certain' && outcome.status === 'incomplete',
            ).length,
            missed: classOutcomes.filter((outcome) => outcome.label.confidence === 'certain' && outcome.status === 'missed').length,
            uncertain: classOutcomes.filter((outcome) => outcome.label.confidence === 'uncertain').length,
          },
        ];
      }),
    );
    expect(Object.keys(report)).toEqual(manifest.reportClasses);
    for (const value of Object.values(report)) {
      expect(value.proven + value.incomplete + value.missed + value.uncertain).toBe(value.denominator);
    }
    console.info(`BoundaryCI real-world class report ${JSON.stringify(report)}`);
  });
});
