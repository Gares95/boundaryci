import { describe, expect, it } from 'vitest';

import { createCheckPublicationCapability, publishCompletedCheck, type CheckPublicationProvider, type CheckPublisher, type ExistingBoundaryCiCheck } from '../../src/delivery/check-publish.js';
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

  it('A18-A22 stops on duplicate matches, nontransient failure, hostile output, or exhausted retry budget', async () => {
    for (const steps of [[[ { id: 1 }, { id: 2 } ]], [[]], [[]]] as Array<Array<readonly ExistingBoundaryCiCheck[]>>) {
      const publisher = provider(steps); let mutations = 0;
      publisher.create = async () => { mutations += 1; throw Object.assign(new Error('failure'), { status: 400 }); };
      const result = await publishCompletedCheck(publisher, 1, identity, payload, { now: () => 61_000 });
      expect(result.status).toBe('not-published');
      expect(mutations).toBeLessThanOrEqual(1);
    }
  });

  it('rejects broad issuance, incomplete pagination, and hostile list records before mutation', async () => {
    const issue: CheckPublicationProvider = Object.freeze({
      async issue() { return { credentialScope: 'issuance-narrowed', repositoryIds: [7], permissions: { checks: 'write', pull_requests: 'read' }, transport: {} } as never; },
    });
    await expect(createCheckPublicationCapability({ installationId: 42, repositoryId: 7 }, issue)).rejects.toMatchObject({ kind: 'credential-scope-mismatch' });
  });
});
