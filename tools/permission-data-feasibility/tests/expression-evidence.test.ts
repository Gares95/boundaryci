import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { parseBoundedJson } from '../artifact-sources.js';
import { buildPermissionSources, validatePermissionSources } from '../extract.js';
import {
  parsePermissionEvidence,
  validateRequirementExpression,
  type RequirementExpression,
} from '../requirement-expression.js';
import {
  buildHeaderExpressionFixture,
  parseAppPermissionSeedAssociations,
  validateHeaderExpressionFixture,
  validatePermissionSourceExtensions,
} from '../source-evidence.js';

const PROJECT_ROOT = fileURLToPath(new URL('../../../', import.meta.url));
const VOCABULARY = new Set(['checks', 'contents', 'issues', 'pull_requests']);

function parse(raw: string, operationId: string | undefined = 'fixture/operation', credentialClass: string | undefined = 'installation-token') {
  return parsePermissionEvidence({ raw, operationId, credentialClass, vocabulary: VOCABULARY });
}

describe('permission requirement expressions', () => {
  it('preserves atoms, all-of groups, alternatives, and alternatives of groups', () => {
    expect(parse('issues=read')).toMatchObject({
      status: 'resolved',
      sourceOrder: [['issues=read']],
      expression: { type: 'permission', permission: 'issues', level: 'read' },
    });
    expect(parse('pull_requests=write, issues=read')).toMatchObject({
      status: 'resolved',
      sourceOrder: [['pull_requests=write', 'issues=read']],
      expression: {
        type: 'allOf',
        requirements: [
          { type: 'permission', permission: 'issues', level: 'read' },
          { type: 'permission', permission: 'pull_requests', level: 'write' },
        ],
      },
    });
    expect(parse('pull_requests=read; issues=read')).toMatchObject({
      status: 'resolved',
      sourceOrder: [['pull_requests=read'], ['issues=read']],
      expression: {
        type: 'anyOf',
        requirements: [
          { type: 'permission', permission: 'issues', level: 'read' },
          { type: 'permission', permission: 'pull_requests', level: 'read' },
        ],
      },
    });
    expect(parse('pull_requests=write, issues=read; contents=write, checks=read')).toMatchObject({
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
    });
  });

  it('returns stable incomplete reasons without guessing malformed or unsupported input', () => {
    expect(parse('')).toMatchObject({ status: 'incomplete', reason: 'empty-expression' });
    expect(parse('issues=read;')).toMatchObject({ status: 'incomplete', reason: 'empty-alternative' });
    expect(parse('issues=read,')).toMatchObject({ status: 'incomplete', reason: 'malformed-atom' });
    expect(parse('issues')).toMatchObject({ status: 'incomplete', reason: 'malformed-atom' });
    expect(parse('issues=admin')).toMatchObject({ status: 'incomplete', reason: 'unknown-access-level' });
    expect(parse('metadata=read')).toMatchObject({ status: 'incomplete', reason: 'unknown-permission' });
    expect(parse('issues=read[conditional]')).toMatchObject({ status: 'incomplete', reason: 'unsupported-qualifier' });
    expect(parse('issues=read, issues=read')).toMatchObject({
      status: 'incomplete',
      reason: 'duplicate-permission-atom',
    });
    expect(parse('issues=read; issues=write')).toMatchObject({
      status: 'incomplete',
      reason: 'conflicting-permission-atom',
    });
    expect(
      parsePermissionEvidence({
        raw: 'issues=read',
        credentialClass: 'installation-token',
        vocabulary: VOCABULARY,
      }),
    ).toMatchObject({ status: 'incomplete', reason: 'operation-missing' });
    expect(
      parsePermissionEvidence({
        raw: 'issues=read',
        operationId: 'fixture/operation',
        vocabulary: VOCABULARY,
      }),
    ).toMatchObject({
      status: 'incomplete',
      reason: 'credential-class-missing',
    });
  });

  it('requires canonical child order, exact field names, and groups with at least two children', () => {
    const nonCanonical: RequirementExpression = {
      type: 'anyOf',
      requirements: [
        { type: 'permission', permission: 'pull_requests', level: 'read' },
        { type: 'permission', permission: 'issues', level: 'read' },
      ],
    };
    expect(() => validateRequirementExpression(nonCanonical)).toThrow(/canonical order/u);
    expect(() =>
      validateRequirementExpression({ type: 'allOf', requirements: [{ type: 'permission', permission: 'issues', level: 'read' }] }),
    ).toThrow(/at least two/u);
    expect(() =>
      validateRequirementExpression({ type: 'permission', permission: 'issues', level: 'read', guessed: true }),
    ).toThrow(/invalid/u);
  });
});

describe('source-grounded evidence', () => {
  it('uses one schema-compatible fixture contract for synthetic and retained records', () => {
    const built = buildHeaderExpressionFixture();
    expect(() => validateHeaderExpressionFixture(built)).not.toThrow();
    const committed = JSON.parse(
      readFileSync(`${PROJECT_ROOT}/tools/permission-data-feasibility/fixtures/header-expressions.json`, 'utf8'),
    ) as unknown;
    expect(committed).toEqual(built);
    const mutated = structuredClone(built) as unknown as { cases: { expected: Record<string, unknown> }[] };
    const first = mutated.cases[0];
    if (first !== undefined) first.expected.requirement = first.expected.expression;
    expect(() => validateHeaderExpressionFixture(mutated)).toThrow();
  });

  it('preserves the credential-label disagreement and refuses App applicability', () => {
    const value = parseBoundedJson(
      PROJECT_ROOT,
      'tools/permission-data-feasibility/evidence/permission-sources.json',
      2 * 1024 * 1024,
    );
    validatePermissionSources(value);
    expect(value).toEqual(buildPermissionSources());
    const record = value as unknown as Record<string, unknown>;
    const extensions = {
      vocabulary: record.vocabulary,
      headerFacts: record.headerFacts,
      refusedProbes: record.refusedProbes,
    };
    expect(() => validatePermissionSourceExtensions(extensions)).not.toThrow();
    const header = (extensions.headerFacts as { claimedCredentialClass: string; machineCredentialClass: string; credentialApplicability: string }[])[0];
    expect(header).toMatchObject({
      claimedCredentialClass: 'fine-grained-personal-access-token',
      machineCredentialClass: 'classic-oauth-token',
      credentialApplicability: 'unproven-for-github-app-installation',
    });
    expect(extensions.refusedProbes).toHaveLength(5);
    expect(JSON.stringify(extensions.refusedProbes)).toContain('not-probed-safety-policy');
  });

  it('keeps repeated app-permissions associations as operator-less raw seeds', () => {
    const source = parseBoundedJson(
      PROJECT_ROOT,
      'node_modules/@octokit/app-permissions/generated/api.github.com.json',
      4 * 1024 * 1024,
    );
    const associations = parseAppPermissionSeedAssociations(source).filter(
      (entry) => entry.verb === 'GET' && entry.path === '/repos/{owner}/{repo}/issues/{issue_number}/comments',
    );
    expect(associations).toEqual([
      {
        verb: 'GET',
        path: '/repos/{owner}/{repo}/issues/{issue_number}/comments',
        permission: 'issues',
        level: 'read',
      },
      {
        verb: 'GET',
        path: '/repos/{owner}/{repo}/issues/{issue_number}/comments',
        permission: 'pull_requests',
        level: 'read',
      },
    ]);
    expect(associations).not.toHaveProperty('type');
  });
});
