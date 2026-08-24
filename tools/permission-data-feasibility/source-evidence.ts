import { digestJson, sha256 } from './artifact-sources.js';
import { assertExactKeys, assertPlainObject, assertSha256, type JsonValue } from './contracts.js';
import {
  parsePermissionEvidence,
  validateRequirementExpression,
  type PermissionEvidenceIncompleteReason,
  type RequirementExpression,
} from './requirement-expression.js';

const HEADER_DOCUMENTATION_URL =
  'https://docs.github.com/en/rest/using-the-rest-api/troubleshooting-the-rest-api';
const ISSUES_PERMISSION_URL =
  'https://docs.github.com/en/rest/authentication/permissions-required-for-github-apps#repository-permissions-for-issues';
const PULL_REQUESTS_PERMISSION_URL =
  'https://docs.github.com/en/rest/authentication/permissions-required-for-github-apps#repository-permissions-for-pull-requests';
const CONTENTS_PERMISSION_URL =
  'https://docs.github.com/en/rest/authentication/permissions-required-for-github-apps#repository-permissions-for-contents';
const CHECKS_PERMISSION_URL =
  'https://docs.github.com/en/rest/authentication/permissions-required-for-github-apps#repository-permissions-for-checks';

export interface PermissionVocabularyEntry {
  permission: string;
  sourceUrl: string;
  reviewStatus: 'reviewed';
  reviewedOn: string;
}

export interface HeaderPermissionFact {
  sourceKind: 'x-accepted-github-permissions';
  sourceUrl: string;
  operation: { operationId: string; verb: string; path: string };
  apiVersion: '2022-11-28';
  claimedCredentialClass: 'fine-grained-personal-access-token';
  machineCredentialClass: 'classic-oauth-token';
  credentialApplicability: 'unproven-for-github-app-installation';
  repositoryScope: 'private-repository';
  trialIds: string[];
  retrievedAt: string;
  raw: string;
  rawSha256: string;
  sourceOrder: string[][];
  expression: RequirementExpression;
  expressionSha256: string;
  reviewerStatus: 'reviewed-credential-unproven';
}

export interface RefusedProbe {
  operationId: string;
  verb: 'PATCH' | 'POST' | 'PUT';
  path: string;
  outcome: 'not-probed-safety-policy';
}

export interface PermissionSourceExtensions {
  vocabulary: PermissionVocabularyEntry[];
  headerFacts: HeaderPermissionFact[];
  refusedProbes: RefusedProbe[];
}

export interface RawPermissionSeedAssociation {
  verb: string;
  path: string;
  permission: string;
  level: 'read' | 'write';
}

export interface HeaderExpressionFixtureCase {
  id: string;
  raw: string;
  operationId: string;
  credentialClass: string;
  expected:
    | {
        status: 'resolved';
        sourceOrder: string[][];
        expression: RequirementExpression;
      }
    | { status: 'incomplete'; reason: PermissionEvidenceIncompleteReason };
}

export interface HeaderExpressionFixture {
  schemaVersion: 1;
  vocabulary: string[];
  cases: HeaderExpressionFixtureCase[];
  contentSha256: string;
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

export function buildPermissionSourceExtensions(): PermissionSourceExtensions {
  const vocabulary: PermissionVocabularyEntry[] = [
    { permission: 'checks', sourceUrl: CHECKS_PERMISSION_URL, reviewStatus: 'reviewed', reviewedOn: '2026-08-24' },
    { permission: 'contents', sourceUrl: CONTENTS_PERMISSION_URL, reviewStatus: 'reviewed', reviewedOn: '2026-08-24' },
    { permission: 'issues', sourceUrl: ISSUES_PERMISSION_URL, reviewStatus: 'reviewed', reviewedOn: '2026-08-24' },
    {
      permission: 'pull_requests',
      sourceUrl: PULL_REQUESTS_PERMISSION_URL,
      reviewStatus: 'reviewed',
      reviewedOn: '2026-08-24',
    },
  ];
  const parsed = parsePermissionEvidence({
    raw: 'issues=read; pull_requests=read',
    operationId: 'issues/list-comments',
    credentialClass: 'fine-grained-personal-access-token',
    vocabulary: new Set(vocabulary.map((entry) => entry.permission)),
  });
  if (parsed.status !== 'resolved') throw new Error(`retained header evidence is invalid: ${parsed.reason}`);
  const raw = parsed.raw;
  const headerFacts: HeaderPermissionFact[] = [
    {
      sourceKind: 'x-accepted-github-permissions',
      sourceUrl: HEADER_DOCUMENTATION_URL,
      operation: {
        operationId: 'issues/list-comments',
        verb: 'GET',
        path: '/repos/{owner}/{repo}/issues/{issue_number}/comments',
      },
      apiVersion: '2022-11-28',
      claimedCredentialClass: 'fine-grained-personal-access-token',
      machineCredentialClass: 'classic-oauth-token',
      credentialApplicability: 'unproven-for-github-app-installation',
      repositoryScope: 'private-repository',
      trialIds: ['initial', 'reproducibility-1', 'reproducibility-2', 'reproducibility-3'],
      retrievedAt: '2026-08-16T21:32:49.948Z',
      raw,
      rawSha256: sha256(raw),
      sourceOrder: parsed.sourceOrder,
      expression: parsed.expression,
      expressionSha256: parsed.expressionSha256,
      reviewerStatus: 'reviewed-credential-unproven',
    },
  ];
  const refusedProbes: RefusedProbe[] = [
    {
      operationId: 'checks/create',
      verb: 'POST',
      path: '/repos/{owner}/{repo}/check-runs',
      outcome: 'not-probed-safety-policy',
    },
    {
      operationId: 'issues/create',
      verb: 'POST',
      path: '/repos/{owner}/{repo}/issues',
      outcome: 'not-probed-safety-policy',
    },
    {
      operationId: 'issues/create-comment',
      verb: 'POST',
      path: '/repos/{owner}/{repo}/issues/{issue_number}/comments',
      outcome: 'not-probed-safety-policy',
    },
    {
      operationId: 'issues/update',
      verb: 'PATCH',
      path: '/repos/{owner}/{repo}/issues/{issue_number}',
      outcome: 'not-probed-safety-policy',
    },
    {
      operationId: 'repos/create-or-update-file-contents',
      verb: 'PUT',
      path: '/repos/{owner}/{repo}/contents/{path}',
      outcome: 'not-probed-safety-policy',
    },
  ];
  refusedProbes.sort((left, right) => compareStrings(left.operationId, right.operationId));
  return { vocabulary, headerFacts, refusedProbes };
}

export function parseAppPermissionSeedAssociations(value: unknown): RawPermissionSeedAssociation[] {
  assertPlainObject(value, 'app-permissions document');
  assertPlainObject(value.permissions, 'app-permissions permissions');
  const associations = new Map<string, RawPermissionSeedAssociation>();
  for (const [permission, entry] of Object.entries(value.permissions)) {
    if (!/^[a-z][a-z0-9_]*$/u.test(permission)) throw new TypeError(`invalid seed permission ${permission}`);
    assertPlainObject(entry, `seed permission ${permission}`);
    for (const level of ['read', 'write'] as const) {
      const routes = entry[level];
      if (routes === undefined) continue;
      if (!Array.isArray(routes)) throw new TypeError(`seed permission ${permission}.${level} must be an array`);
      for (const route of routes) {
        if (typeof route !== 'string') throw new TypeError(`seed permission ${permission}.${level} has a non-string route`);
        const match = /^([A-Z]+) (\/.*)$/u.exec(route);
        if (match?.[1] === undefined || match[2] === undefined) throw new TypeError(`invalid seed route ${route}`);
        const association = { verb: match[1], path: match[2], permission, level };
        associations.set(`${association.verb} ${association.path}\0${permission}\0${level}`, association);
      }
    }
  }
  return [...associations.values()].sort((left, right) =>
    compareStrings(
      `${left.verb} ${left.path}\0${left.permission}\0${left.level}`,
      `${right.verb} ${right.path}\0${right.permission}\0${right.level}`,
    ),
  );
}

function assertIsoDate(value: unknown, label: string): asserts value is string {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/u.test(value)) throw new TypeError(`${label} is invalid`);
}

export function validatePermissionSourceExtensions(value: unknown): asserts value is PermissionSourceExtensions {
  assertPlainObject(value, 'permission source extensions');
  assertExactKeys(value, ['vocabulary', 'headerFacts', 'refusedProbes'], 'permission source extensions');
  if (!Array.isArray(value.vocabulary) || value.vocabulary.length < 1) throw new TypeError('vocabulary is invalid');
  const names = new Set<string>();
  for (const [index, entry] of value.vocabulary.entries()) {
    assertPlainObject(entry, `vocabulary[${index}]`);
    assertExactKeys(entry, ['permission', 'sourceUrl', 'reviewStatus', 'reviewedOn'], `vocabulary[${index}]`);
    if (
      typeof entry.permission !== 'string' ||
      !/^[a-z][a-z0-9_]*$/u.test(entry.permission) ||
      typeof entry.sourceUrl !== 'string' ||
      !entry.sourceUrl.startsWith('https://docs.github.com/') ||
      entry.reviewStatus !== 'reviewed'
    ) {
      throw new TypeError(`vocabulary[${index}] is invalid`);
    }
    assertIsoDate(entry.reviewedOn, `vocabulary[${index}].reviewedOn`);
    if (names.has(entry.permission)) throw new TypeError(`duplicate vocabulary entry ${entry.permission}`);
    names.add(entry.permission);
  }
  if (!Array.isArray(value.headerFacts) || value.headerFacts.length < 1) throw new TypeError('header facts are invalid');
  for (const [index, fact] of value.headerFacts.entries()) {
    assertPlainObject(fact, `headerFacts[${index}]`);
    assertExactKeys(
      fact,
      [
        'sourceKind',
        'sourceUrl',
        'operation',
        'apiVersion',
        'claimedCredentialClass',
        'machineCredentialClass',
        'credentialApplicability',
        'repositoryScope',
        'trialIds',
        'retrievedAt',
        'raw',
        'rawSha256',
        'sourceOrder',
        'expression',
        'expressionSha256',
        'reviewerStatus',
      ],
      `headerFacts[${index}]`,
    );
    assertPlainObject(fact.operation, `headerFacts[${index}].operation`);
    assertExactKeys(fact.operation, ['operationId', 'verb', 'path'], `headerFacts[${index}].operation`);
    if (
      fact.sourceKind !== 'x-accepted-github-permissions' ||
      fact.sourceUrl !== HEADER_DOCUMENTATION_URL ||
      fact.apiVersion !== '2022-11-28' ||
      fact.claimedCredentialClass !== 'fine-grained-personal-access-token' ||
      fact.machineCredentialClass !== 'classic-oauth-token' ||
      fact.credentialApplicability !== 'unproven-for-github-app-installation' ||
      fact.repositoryScope !== 'private-repository' ||
      fact.reviewerStatus !== 'reviewed-credential-unproven' ||
      typeof fact.operation.operationId !== 'string' ||
      typeof fact.operation.verb !== 'string' ||
      typeof fact.operation.path !== 'string' ||
      typeof fact.raw !== 'string' ||
      typeof fact.retrievedAt !== 'string' ||
      !/^\d{4}-\d{2}-\d{2}T/u.test(fact.retrievedAt) ||
      !Array.isArray(fact.trialIds) ||
      fact.trialIds.length === 0 ||
      !fact.trialIds.every((trial) => typeof trial === 'string' && trial.length > 0) ||
      !Array.isArray(fact.sourceOrder)
    ) {
      throw new TypeError(`headerFacts[${index}] is invalid`);
    }
    assertSha256(fact.rawSha256, `headerFacts[${index}].rawSha256`);
    assertSha256(fact.expressionSha256, `headerFacts[${index}].expressionSha256`);
    validateRequirementExpression(fact.expression);
    const parsed = parsePermissionEvidence({
      raw: fact.raw,
      operationId: fact.operation.operationId,
      credentialClass: fact.claimedCredentialClass,
      vocabulary: names,
    });
    if (
      parsed.status !== 'resolved' ||
      fact.rawSha256 !== sha256(fact.raw) ||
      fact.expressionSha256 !== parsed.expressionSha256 ||
      digestJson(fact.expression as unknown as JsonValue) !== parsed.expressionSha256 ||
      JSON.stringify(fact.sourceOrder) !== JSON.stringify(parsed.sourceOrder)
    ) {
      throw new Error(`headerFacts[${index}] evidence mismatch`);
    }
  }
  if (!Array.isArray(value.refusedProbes) || value.refusedProbes.length !== 5) {
    throw new TypeError('refused probes must contain five operations');
  }
  const operations = new Set<string>();
  for (const [index, probe] of value.refusedProbes.entries()) {
    assertPlainObject(probe, `refusedProbes[${index}]`);
    assertExactKeys(probe, ['operationId', 'verb', 'path', 'outcome'], `refusedProbes[${index}]`);
    if (
      typeof probe.operationId !== 'string' ||
      !['PATCH', 'POST', 'PUT'].includes(String(probe.verb)) ||
      typeof probe.path !== 'string' ||
      probe.outcome !== 'not-probed-safety-policy'
    ) {
      throw new TypeError(`refusedProbes[${index}] is invalid`);
    }
    if (operations.has(probe.operationId)) throw new TypeError(`duplicate refused probe ${probe.operationId}`);
    operations.add(probe.operationId);
  }
}

export function buildHeaderExpressionFixture(): HeaderExpressionFixture {
  const vocabulary = ['checks', 'contents', 'issues', 'pull_requests'];
  const cases: HeaderExpressionFixtureCase[] = [
    {
      id: 'single',
      raw: 'issues=read',
      operationId: 'fixture/single',
      credentialClass: 'installation-token',
      expected: {
        status: 'resolved',
        sourceOrder: [['issues=read']],
        expression: { type: 'permission', permission: 'issues', level: 'read' },
      },
    },
    {
      id: 'all-of',
      raw: 'pull_requests=write, issues=read',
      operationId: 'fixture/all-of',
      credentialClass: 'installation-token',
      expected: {
        status: 'resolved',
        sourceOrder: [['pull_requests=write', 'issues=read']],
        expression: {
          type: 'allOf',
          requirements: [
            { type: 'permission', permission: 'issues', level: 'read' },
            { type: 'permission', permission: 'pull_requests', level: 'write' },
          ],
        },
      },
    },
    {
      id: 'any-of',
      raw: 'pull_requests=read; issues=read',
      operationId: 'fixture/any-of',
      credentialClass: 'installation-token',
      expected: {
        status: 'resolved',
        sourceOrder: [['pull_requests=read'], ['issues=read']],
        expression: {
          type: 'anyOf',
          requirements: [
            { type: 'permission', permission: 'issues', level: 'read' },
            { type: 'permission', permission: 'pull_requests', level: 'read' },
          ],
        },
      },
    },
    {
      id: 'alternatives-of-groups',
      raw: 'pull_requests=write, issues=read; contents=write, checks=read',
      operationId: 'fixture/alternatives-of-groups',
      credentialClass: 'installation-token',
      expected: {
        status: 'resolved',
        sourceOrder: [
          ['pull_requests=write', 'issues=read'],
          ['contents=write', 'checks=read'],
        ],
        expression: {
          type: 'anyOf',
          requirements: [
            {
              type: 'allOf',
              requirements: [
                { type: 'permission', permission: 'checks', level: 'read' },
                { type: 'permission', permission: 'contents', level: 'write' },
              ],
            },
            {
              type: 'allOf',
              requirements: [
                { type: 'permission', permission: 'issues', level: 'read' },
                { type: 'permission', permission: 'pull_requests', level: 'write' },
              ],
            },
          ],
        },
      },
    },
  ];
  const unsigned = { schemaVersion: 1 as const, vocabulary, cases };
  return { ...unsigned, contentSha256: digestJson(unsigned as unknown as JsonValue) };
}

export function validateHeaderExpressionFixture(value: unknown): asserts value is HeaderExpressionFixture {
  assertPlainObject(value, 'header expression fixture');
  assertExactKeys(value, ['schemaVersion', 'vocabulary', 'cases', 'contentSha256'], 'header expression fixture');
  if (value.schemaVersion !== 1 || !Array.isArray(value.vocabulary) || !Array.isArray(value.cases)) {
    throw new TypeError('header expression fixture structure is invalid');
  }
  const vocabulary = new Set<string>();
  for (const entry of value.vocabulary) {
    if (typeof entry !== 'string') throw new TypeError('fixture vocabulary is invalid');
    vocabulary.add(entry);
  }
  for (const [index, entry] of value.cases.entries()) {
    assertPlainObject(entry, `fixture cases[${index}]`);
    assertExactKeys(entry, ['id', 'raw', 'operationId', 'credentialClass', 'expected'], `fixture cases[${index}]`);
    if (
      typeof entry.id !== 'string' ||
      typeof entry.raw !== 'string' ||
      typeof entry.operationId !== 'string' ||
      typeof entry.credentialClass !== 'string'
    ) {
      throw new TypeError(`fixture cases[${index}] identity is invalid`);
    }
    assertPlainObject(entry.expected, `fixture cases[${index}].expected`);
    const parsed = parsePermissionEvidence({
      raw: entry.raw,
      operationId: entry.operationId,
      credentialClass: entry.credentialClass,
      vocabulary,
    });
    if (entry.expected.status === 'resolved') {
      assertExactKeys(entry.expected, ['status', 'sourceOrder', 'expression'], `fixture cases[${index}].expected`);
      validateRequirementExpression(entry.expected.expression);
      if (
        parsed.status !== 'resolved' ||
        JSON.stringify(parsed.sourceOrder) !== JSON.stringify(entry.expected.sourceOrder) ||
        JSON.stringify(parsed.expression) !== JSON.stringify(entry.expected.expression)
      ) {
        throw new Error(`fixture cases[${index}] resolved expectation mismatch`);
      }
    } else {
      assertExactKeys(entry.expected, ['status', 'reason'], `fixture cases[${index}].expected`);
      if (parsed.status !== 'incomplete' || parsed.reason !== entry.expected.reason) {
        throw new Error(`fixture cases[${index}] incomplete expectation mismatch`);
      }
    }
  }
  assertSha256(value.contentSha256, 'header expression fixture contentSha256');
  const { contentSha256: _contentSha256, ...unsigned } = value;
  if (value.contentSha256 !== digestJson(unsigned as unknown as JsonValue)) {
    throw new Error('header expression fixture digest mismatch');
  }
}
