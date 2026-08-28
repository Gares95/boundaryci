import { describe, expect, it } from 'vitest';

import { censusCandidates } from '../../src/analyzer/candidates.js';
import type { CandidateSite } from '../../src/analyzer/candidates.js';
import { parseSourceRecord } from '../../src/analyzer/parse.js';
import type { ParsedSource } from '../../src/analyzer/parse.js';
import {
  buildSourceGraph,
  proveCandidateReceiver,
  resolveStaticValue,
} from '../../src/analyzer/resolve.js';
import type { ReceiverProofResult, StaticValue } from '../../src/analyzer/resolve.js';

import provenanceCases from './fixtures/provenance-cases.json' with { type: 'json' };

interface FixtureFile {
  path: string;
  text: string[];
}

interface ResolutionExpectation {
  specifier: string;
  resolvedPath: string;
  ruleRow: number;
}

interface SiteExpectation {
  path: string;
  line: number;
  kind: CandidateSite['kind'];
  spelling: string;
  anchor?: string;
  member?: { scope: string; method: string };
  optional?: boolean;
  route?: string;
  status: ReceiverProofResult['status'];
  causes?: string[];
  origin?: string;
  access?: string;
  constructorBinding?: string;
  constructorAliasChain?: string[];
  clientBinding?: string;
  clientAliasChain?: string[];
  steps?: string[];
  resolution?: ResolutionExpectation;
}

interface ReceiverCase {
  name: string;
  entrypoints?: string[];
  files: FixtureFile[];
  sites: SiteExpectation[];
}

interface ValueExpectation {
  kind: StaticValue['kind'];
  causes?: string[];
  origin?: string;
  resolution?: ResolutionExpectation;
}

interface ValueCase {
  name: string;
  files: FixtureFile[];
  path: string;
  binding: string;
  expect: ValueExpectation;
}

const cases = provenanceCases as {
  receiverCases: ReceiverCase[];
  valueCases: ValueCase[];
};

function parseFiles(files: readonly FixtureFile[]): ParsedSource[] {
  return files.map((file) => {
    const text = `${file.text.join('\n')}\n`;
    const result = parseSourceRecord({ path: file.path, bytes: new Uint8Array(Buffer.from(text, 'utf8')) });
    if (result.status !== 'parsed') {
      throw new Error(`fixture ${file.path} did not parse: ${result.cause.code}`);
    }
    return result;
  });
}

function orderedCandidates(parsed: readonly ParsedSource[], entrypoints: ReadonlySet<string>): CandidateSite[] {
  return parsed.flatMap((source) =>
    censusCandidates(source, { probotEntrypoint: entrypoints.has(source.record.path) }),
  );
}

function findExpectedSite(sites: readonly CandidateSite[], expected: SiteExpectation): CandidateSite {
  const matches = sites.filter(
    (site) =>
      site.path === expected.path &&
      site.span.start.line === expected.line &&
      site.kind === expected.kind &&
      site.spelling === expected.spelling,
  );
  expect(matches, `${expected.path}:${String(expected.line)} ${expected.kind}`).toHaveLength(1);
  const match = matches[0];
  if (match === undefined) throw new Error('the uniquely matched candidate disappeared');
  return match;
}

function expectResolutionStep(
  steps: readonly { specifier: string | null; resolvedPath: string | null; ruleRow: number | null }[],
  expected: ResolutionExpectation,
): void {
  expect(steps).toContainEqual(
    expect.objectContaining({
      specifier: expected.specifier,
      resolvedPath: expected.resolvedPath,
      ruleRow: expected.ruleRow,
    }),
  );
}

function assertSiteExpectation(
  result: ReceiverProofResult,
  site: CandidateSite,
  expected: SiteExpectation,
): void {
  if (expected.member !== undefined) expect(site.member).toEqual(expected.member);
  if (expected.anchor !== undefined) expect(site.anchor).toBe(expected.anchor);
  if (expected.optional !== undefined) expect(site.optional).toBe(expected.optional);
  if (expected.route !== undefined) expect(site.route).toBe(expected.route);
  expect(result.status).toBe(expected.status);

  if (result.status === 'unproven') {
    expect(result.causes.map((cause) => cause.code)).toEqual(expected.causes ?? []);
    return;
  }

  expect(result.provenance.origin).toBe(expected.origin);
  expect(result.provenance.access).toBe(expected.access);
  if (expected.constructorBinding !== undefined) {
    expect(result.provenance.constructorBinding).toBe(expected.constructorBinding);
  }
  if (expected.constructorAliasChain !== undefined) {
    expect(result.provenance.constructorAliasChain).toEqual(expected.constructorAliasChain);
  }
  if (expected.clientBinding !== undefined) expect(result.provenance.clientBinding).toBe(expected.clientBinding);
  if (expected.clientAliasChain !== undefined) {
    expect(result.provenance.clientAliasChain).toEqual(expected.clientAliasChain);
  }
  if (expected.steps !== undefined) {
    expect(result.provenance.steps.map((step) => step.kind)).toEqual(expected.steps);
  }
  if (expected.resolution !== undefined) expectResolutionStep(result.provenance.steps, expected.resolution);
}

function assertValueExpectation(value: StaticValue, expected: ValueExpectation): void {
  expect(value.kind).toBe(expected.kind);
  if (value.kind === 'unknown') {
    expect(value.causes.map((cause) => cause.code)).toEqual(expected.causes ?? []);
    return;
  }

  const origin = value.kind === 'octokit-client' ? value.client.constructor.origin : value.constructor.origin;
  expect(origin).toBe(expected.origin);
  if (expected.resolution !== undefined) {
    const steps = value.kind === 'octokit-client' ? value.client.steps : value.constructor.steps;
    expectResolutionStep(steps, expected.resolution);
  }
}

describe('candidate census and bounded receiver provenance', () => {
  for (const testCase of cases.receiverCases) {
    it(testCase.name, () => {
      const parsed = parseFiles(testCase.files);
      const graph = buildSourceGraph(parsed);
      const sites = orderedCandidates(parsed, new Set(testCase.entrypoints ?? []));

      expect(sites).toHaveLength(testCase.sites.length);
      for (const expected of testCase.sites) {
        const site = findExpectedSite(sites, expected);
        assertSiteExpectation(proveCandidateReceiver(graph, site), site, expected);
      }

      const replaySites = orderedCandidates(parsed, new Set(testCase.entrypoints ?? []));
      const first = sites.map((site) => ({ site, proof: proveCandidateReceiver(graph, site) }));
      const replay = replaySites.map((site) => ({ site, proof: proveCandidateReceiver(graph, site) }));
      expect(JSON.stringify(replay)).toBe(JSON.stringify(first));
    });
  }
});

describe('finite relative-source and static-value resolution', () => {
  for (const testCase of cases.valueCases) {
    it(testCase.name, () => {
      const graph = buildSourceGraph(parseFiles(testCase.files));
      const value = resolveStaticValue(graph, testCase.path, testCase.binding);
      assertValueExpectation(value, testCase.expect);
      expect(resolveStaticValue(graph, testCase.path, testCase.binding)).toEqual(value);
    });
  }
});
