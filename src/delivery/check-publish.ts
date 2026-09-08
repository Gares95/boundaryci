import type { CheckIdentityV1, CheckPublicationResultV1, CompletedCheckPayloadV1 } from './check-contract.js';
import { CHECK_NAME, validateCheckIdentity, validateCompletedCheckPayload } from './check-contract.js';

export interface ExistingBoundaryCiCheck {
  id: number;
}

/** A deliberately narrow publication role: exact lookup plus completed Check create/update only. */
export interface CheckPublisher {
  lookupExact(query: Readonly<{ appId: number; headSha: string; name: typeof CHECK_NAME; correlationId: string }>): Promise<readonly ExistingBoundaryCiCheck[]>;
  create(payload: CompletedCheckPayloadV1): Promise<ExistingBoundaryCiCheck>;
  update(checkId: number, payload: Omit<CompletedCheckPayloadV1, 'annotations'>): Promise<ExistingBoundaryCiCheck>;
}

function updatePayload(payload: CompletedCheckPayloadV1): Omit<CompletedCheckPayloadV1, 'annotations'> {
  const { annotations: _annotations, ...result } = payload;
  return Object.freeze(result);
}

/**
 * Executes only the completed-state zero/one/multiple upsert branch.  It deliberately has no
 * generic request client, annotation-listing capability, or retry/replay behaviour.
 */
export async function publishCompletedCheck(
  publisher: CheckPublisher,
  appId: number,
  identity: CheckIdentityV1,
  payload: CompletedCheckPayloadV1,
): Promise<CheckPublicationResultV1> {
  validateCheckIdentity(identity);
  validateCompletedCheckPayload(payload);
  if (!Number.isSafeInteger(appId) || appId <= 0 || payload.name !== CHECK_NAME || payload.headSha !== identity.headSha || payload.externalId !== identity.correlationId) {
    return Object.freeze({ status: 'not-published', reason: 'invalid-envelope' });
  }
  let matches: readonly ExistingBoundaryCiCheck[];
  try {
    matches = await publisher.lookupExact(Object.freeze({ appId, headSha: identity.headSha, name: CHECK_NAME, correlationId: identity.correlationId }));
  } catch {
    return Object.freeze({ status: 'not-published', reason: 'publication-failure' });
  }
  if (!Array.isArray(matches) || matches.some((match) => !Number.isSafeInteger(match?.id) || match.id <= 0)) {
    return Object.freeze({ status: 'not-published', reason: 'publication-failure' });
  }
  if (matches.length > 1) return Object.freeze({ status: 'not-published', reason: 'publication-conflict' });
  try {
    if (matches.length === 0) {
      const created = await publisher.create(payload);
      if (!Number.isSafeInteger(created?.id) || created.id <= 0) return Object.freeze({ status: 'not-published', reason: 'publication-failure' });
      return Object.freeze({ status: 'created', correlationId: identity.correlationId, checkId: created.id });
    }
    const updated = await publisher.update(matches[0]!.id, updatePayload(payload));
    if (!Number.isSafeInteger(updated?.id) || updated.id !== matches[0]!.id) return Object.freeze({ status: 'not-published', reason: 'publication-failure' });
    return Object.freeze({ status: 'updated', correlationId: identity.correlationId, checkId: updated.id });
  } catch {
    return Object.freeze({ status: 'not-published', reason: 'publication-failure' });
  }
}
