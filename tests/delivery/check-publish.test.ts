import { describe, expect, it } from 'vitest';

import { createCheckPublicationCapability, createProbotCheckPublicationCapability, publishCompletedCheck, type CheckPublicationProvider, type CheckPublisher, type ExistingBoundaryCiCheck } from '../../src/delivery/check-publish.js';
import { CHECK_NAME, type CheckIdentityV1, type CompletedCheckPayloadV1 } from '../../src/delivery/check-contract.js';
import { DELIVERY_FIXTURES } from './fixtures/index.js';

const identity: CheckIdentityV1 = Object.freeze({
  version: 1, installationId: 42, repositoryId: 7, pullNumber: 19, baseRepositoryId: 7,
  baseRef: 'main', baseSha: DELIVERY_FIXTURES.baseSha, headRepositoryId: 7,
  headSha: DELIVERY_FIXTURES.headSha, topology: 'same-repository', evaluatorIdentity: 'test',
  engineId: 'engine', analyzer: {}, catalogAuthorizedScopeSha256: 'a'.repeat(64),
  effectiveConfigSha256: 'b'.repeat(64), correlationId: `boundaryci:v1:${'c'.repeat(64)}`,
});
const payload: CompletedCheckPayloadV1 = Object.freeze({
  name: CHECK_NAME, headSha: identity.headSha, status: 'completed', conclusion: 'failure',
  title: 'Permission expansion requires review', summary: 'summary', text: 'text',
  externalId: identity.correlationId,
  annotations: Object.freeze(Array.from({ length: 50 }, (_, index) => Object.freeze({
    path: `src/${index}.ts`, startLine: 1, endLine: 1, level: 'failure' as const,
    title: 'Permission policy failure' as const, message: 'message', operationId: 'issues/create',
  }))),
});

function provider(steps: Array<readonly ExistingBoundaryCiCheck[] | Error>): CheckPublisher & { calls: string[]; updates: unknown[]; creates: unknown[] } {
  const calls: string[] = []; const updates: unknown[] = []; const creates: unknown[] = [];
  return {
    calls, updates, creates,
    async lookupExact() { calls.push('lookup'); const value = steps.shift() ?? []; if (value instanceof Error) throw value; return value; },
    async create(value) { calls.push('create'); creates.push(value); return Object.freeze({ id: 101 }); },
    async update(id, value) { calls.push(`update:${id}`); updates.push(value); return Object.freeze({ id }); },
  };
}

describe('A14-A22/A28-A30 bounded Check publisher', () => {
  it('A14 creates exactly once with the selected 0-50 annotations after zero exact matches', async () => {
    const publisher = provider([[]]);
    await expect(publishCompletedCheck(publisher, 1, identity, payload)).resolves.toEqual({ status: 'created', correlationId: identity.correlationId, checkId: 101 });
    expect(publisher.calls).toEqual(['lookup', 'create']);
    expect((publisher.creates[0] as CompletedCheckPayloadV1).annotations).toHaveLength(50);
  });

  it('A15 updates one exact match without an annotations property', async () => {
    const publisher = provider([[{ id: 17 }]]);
    await expect(publishCompletedCheck(publisher, 1, identity, payload)).resolves.toEqual({ status: 'updated', correlationId: identity.correlationId, checkId: 17 });
    expect(publisher.calls).toEqual(['lookup', 'update:17']);
    expect(Object.hasOwn(publisher.updates[0] as object, 'annotations')).toBe(false);
  });

  it('A16 reconciles one ambiguous create with one non-annotation update', async () => {
    const publisher = provider([[], [{ id: 17 }]]);
    publisher.create = async () => { publisher.calls.push('create'); throw Object.assign(new Error('temporary'), { status: 503 }); };
    await expect(publishCompletedCheck(publisher, 1, identity, payload)).resolves.toEqual({ status: 'updated', correlationId: identity.correlationId, checkId: 17 });
    expect(publisher.calls).toEqual(['lookup', 'create', 'lookup', 'update:17']);
    expect(Object.hasOwn(publisher.updates[0] as object, 'annotations')).toBe(false);
  });

  it('A17 retries only a transient ambiguous create after exact reconciliation finds zero', async () => {
    const publisher = provider([[], [], []]); let creates = 0;
    publisher.create = async (value) => { publisher.calls.push('create'); publisher.creates.push(value); creates += 1; if (creates === 1) throw Object.assign(new Error('temporary'), { status: 503 }); return Object.freeze({ id: 17 }); };
    await expect(publishCompletedCheck(publisher, 1, identity, payload)).resolves.toMatchObject({ status: 'created', checkId: 17 });
    expect(publisher.calls).toEqual(['lookup', 'create', 'lookup', 'create']);
  });

  it('A18 stops an ambiguous create when reconciliation finds multiple exact Checks', async () => {
    const publisher = provider([[], [{ id: 1 }, { id: 2 }]]);
    publisher.create = async () => { publisher.calls.push('create'); throw Object.assign(new Error('temporary'), { status: 503 }); };
    await expect(publishCompletedCheck(publisher, 1, identity, payload)).resolves.toEqual({ status: 'not-published', reason: 'publication-conflict' });
    expect(publisher.calls).toEqual(['lookup', 'create', 'lookup']);
  });

  it('A19 rejects a nontransient ambiguous create without retry or annotation replay', async () => {
    const publisher = provider([[], []]);
    publisher.create = async () => { publisher.calls.push('create'); throw Object.assign(new Error('refused'), { status: 400 }); };
    await expect(publishCompletedCheck(publisher, 1, identity, payload)).resolves.toEqual({ status: 'not-published', reason: 'publication-failure' });
    expect(publisher.calls).toEqual(['lookup', 'create', 'lookup']);
    expect(publisher.updates).toEqual([]);
  });

  it('A20 reconciles an ambiguous update with an annotation-free update only', async () => {
    const publisher = provider([[{ id: 17 }], [{ id: 17 }]]); let calls = 0;
    publisher.update = async (id, value) => { publisher.calls.push(`update:${id}`); publisher.updates.push(value); calls += 1; if (calls === 1) throw Object.assign(new Error('temporary'), { status: 503 }); return Object.freeze({ id }); };
    await expect(publishCompletedCheck(publisher, 1, identity, payload)).resolves.toEqual({ status: 'updated', correlationId: identity.correlationId, checkId: 17 });
    expect(publisher.calls).toEqual(['lookup', 'update:17', 'lookup', 'update:17']);
    expect(publisher.updates.every((value) => !Object.hasOwn(value as object, 'annotations'))).toBe(true);
  });

  it('A21 never switches an ambiguous update to create when reconciliation finds zero', async () => {
    const publisher = provider([[{ id: 17 }], []]);
    publisher.update = async (id, value) => { publisher.calls.push(`update:${id}`); publisher.updates.push(value); throw Object.assign(new Error('temporary'), { status: 503 }); };
    await expect(publishCompletedCheck(publisher, 1, identity, payload)).resolves.toEqual({ status: 'not-published', reason: 'publication-failure' });
    expect(publisher.calls).toEqual(['lookup', 'update:17', 'lookup', 'update:17']);
    expect(publisher.creates).toEqual([]);
    expect(publisher.updates.every((value) => !Object.hasOwn(value as object, 'annotations'))).toBe(true);
  });

  it('A22 stops ambiguous updates on multiple exact matches and the shared three-attempt/60-second budget', async () => {
    const duplicate = provider([[{ id: 17 }], [{ id: 1 }, { id: 2 }]]);
    duplicate.update = async () => { duplicate.calls.push('update:17'); throw Object.assign(new Error('temporary'), { status: 503 }); };
    await expect(publishCompletedCheck(duplicate, 1, identity, payload)).resolves.toEqual({ status: 'not-published', reason: 'publication-conflict' });
    expect(duplicate.calls).toEqual(['lookup', 'update:17', 'lookup']);
    const elapsed = provider([[]]); const moments = [0, 60_001];
    await expect(publishCompletedCheck(elapsed, 1, identity, payload, { now: () => moments.shift() ?? 60_001 })).resolves.toEqual({ status: 'not-published', reason: 'publication-failure' });
    expect(elapsed.calls).toEqual(['lookup']);
  });

  it('A28-A30 omit annotations from every normal, retry, and reconciliation update payload', async () => {
    const normal = provider([[{ id: 17 }]]);
    await publishCompletedCheck(normal, 1, identity, payload);
    const retry = provider([[{ id: 17 }], []]); let updateCalls = 0;
    retry.update = async (id, value) => { retry.calls.push(`update:${id}`); retry.updates.push(value); updateCalls += 1; if (updateCalls === 1) throw Object.assign(new Error('temporary'), { status: 503 }); return Object.freeze({ id }); };
    await publishCompletedCheck(retry, 1, identity, payload);
    for (const update of [...normal.updates, ...retry.updates]) expect(Object.hasOwn(update as object, 'annotations')).toBe(false);
  });

  it('rejects broad issuance, incomplete pagination, and hostile list records before mutation', async () => {
    const issue: CheckPublicationProvider = Object.freeze({
      async issue() { return { credentialScope: 'issuance-narrowed', repositoryIds: [7], permissions: { checks: 'write', pull_requests: 'read' }, transport: {} } as never; },
    });
    await expect(createCheckPublicationCapability({ installationId: 42, repositoryId: 7 }, issue)).rejects.toMatchObject({ kind: 'credential-scope-mismatch' });
  });

  it('issues exactly Checks write, accepts only implied metadata, and enumerates exact 0/1/many identities', async () => {
    const requests: unknown[] = []; const listCalls: unknown[] = [];
    const publication: CheckPublicationProvider = {
      async issue(request) {
        requests.push(request);
        return {
          credentialScope: 'minimum-registration-equivalent', repositoryIds: [7], permissions: { checks: 'write', metadata: 'read' },
          transport: {
            async listForRef(request) {
              listCalls.push(request);
              return { records: [
                { id: 1, appId: 1, name: 'BoundaryCI', headSha: identity.headSha, externalId: identity.correlationId },
                { id: 2, appId: 2, name: 'BoundaryCI', headSha: identity.headSha, externalId: identity.correlationId },
              ], nextPage: null };
            },
            async create() { return { id: 1 }; }, async update(id) { return { id }; },
          },
        };
      },
    };
    const capability = await createCheckPublicationCapability({ installationId: 42, repositoryId: 7 }, publication);
    await expect(capability.lookupExact({ appId: 1, headSha: identity.headSha, name: CHECK_NAME, correlationId: identity.correlationId })).resolves.toEqual([{ id: 1 }]);
    expect(requests).toEqual([{ installationId: 42, repositoryIds: [7], permissions: { checks: 'write' } }]);
    expect(listCalls).toEqual([expect.objectContaining({ filter: 'all', perPage: 100, page: 1, name: 'BoundaryCI', appId: 1 })]);
    expect(Object.keys(capability).sort()).toEqual(['create', 'lookupExact', 'update']);
  });

  it('fails closed on incomplete pages, over-1000 enumeration, hostile records, and transport sentinel errors', async () => {
    const make = (response: unknown): CheckPublicationProvider => ({
      async issue() { return { credentialScope: 'issuance-narrowed', repositoryIds: [7], permissions: { checks: 'write' }, transport: { async listForRef() { if (response instanceof Error) throw response; return response; }, async create() { return { id: 1 }; }, async update(id) { return { id }; } } }; },
    });
    const incomplete = await createCheckPublicationCapability({ installationId: 42, repositoryId: 7 }, make({ records: [], nextPage: 3 }));
    await expect(incomplete.lookupExact({ appId: 1, headSha: identity.headSha, name: CHECK_NAME, correlationId: identity.correlationId })).rejects.toMatchObject({ kind: 'contract-invalid' });
    const hostile = await createCheckPublicationCapability({ installationId: 42, repositoryId: 7 }, make({ records: [{ id: 1, hostile: 'publisher-secret-sentinel' }], nextPage: null }));
    await expect(hostile.lookupExact({ appId: 1, headSha: identity.headSha, name: CHECK_NAME, correlationId: identity.correlationId })).rejects.toSatisfy((error: unknown) => {
      expect(JSON.stringify(error)).not.toContain('publisher-secret-sentinel'); return true;
    });
    const pages = await createCheckPublicationCapability({ installationId: 42, repositoryId: 7 }, make({ records: [], nextPage: 2 }));
    await expect(pages.lookupExact({ appId: 1, headSha: identity.headSha, name: CHECK_NAME, correlationId: identity.correlationId })).rejects.toMatchObject({ kind: 'contract-invalid' });
  });

  it('adapts Probot through only list/create/update with exact Checks REST arguments', async () => {
    const calls: Array<{ name: string; input: Record<string, unknown> }> = [];
    const octokit = { rest: { checks: {
      async listForRef(input: Record<string, unknown>) { calls.push({ name: 'list', input }); return { data: { total_count: 0, check_runs: [] } }; },
      async create(input: Record<string, unknown>) { calls.push({ name: 'create', input }); return { data: { id: 71 } }; },
      async update(input: Record<string, unknown>) { calls.push({ name: 'update', input }); return { data: { id: input.check_run_id } }; },
    } } };
    const capability = await createProbotCheckPublicationCapability({ installationId: 42, repositoryId: 7 }, octokit, { owner: 'owner', repo: 'target' });
    await publishCompletedCheck(capability, 1, identity, payload);
    expect(calls).toEqual([
      { name: 'list', input: expect.objectContaining({ owner: 'owner', repo: 'target', ref: identity.headSha, check_name: 'BoundaryCI', app_id: 1, filter: 'all', per_page: 100, page: 1 }) },
      { name: 'create', input: expect.objectContaining({ owner: 'owner', repo: 'target', name: 'BoundaryCI', head_sha: identity.headSha, annotations: payload.annotations }) },
    ]);
    expect(Object.keys(capability).sort()).toEqual(['create', 'lookupExact', 'update']);
  });
});
