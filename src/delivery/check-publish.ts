import type { CheckIdentityV1, CheckPublicationResultV1, CompletedCheckPayloadV1 } from './check-contract.js';
import { CHECK_NAME, validateCheckIdentity, validateCompletedCheckPayload } from './check-contract.js';
import { issueNarrowedProbotRole, SanitizedGitHubReadError, type PublicProbotScopedAuth } from './github-auth.js';

const MAX_PAGES = 10;
const MAX_RECORDS = 1_000;
const MAX_ATTEMPTS = 3;
const MAX_ELAPSED_MILLISECONDS = 60_000;

export interface ExistingBoundaryCiCheck { id: number; }
export interface CheckPublicationIdentity { installationId: number; repositoryId: number; }
export interface CheckPublicationIssueRequest { installationId: number; repositoryIds: readonly [number]; permissions: Readonly<{ checks: 'write' }>; }
export interface CheckPublicationListRequest { appId: number; headSha: string; name: typeof CHECK_NAME; correlationId: string; filter: 'all'; perPage: 100; page: number; }
interface CheckPublicationTransport { listForRef(request: CheckPublicationListRequest): Promise<unknown>; create(payload: CompletedCheckPayloadV1): Promise<unknown>; update(checkId: number, payload: Omit<CompletedCheckPayloadV1, 'annotations'>): Promise<unknown>; }
interface IssuedCheckPublicationRole { credentialScope: 'issuance-narrowed'; repositoryIds: readonly number[]; permissions: Readonly<Record<string, string>>; transport: CheckPublicationTransport; }

/** Credential boundary for the Checks-only role. Its returned transport is validated immediately. */
export interface CheckPublicationProvider { issue(request: CheckPublicationIssueRequest): Promise<IssuedCheckPublicationRole>; }

/** A deliberately narrow publication role: exact lookup plus completed Check create/update only. */
export interface CheckPublisher {
  lookupExact(query: Readonly<{ appId: number; headSha: string; name: typeof CHECK_NAME; correlationId: string }>): Promise<readonly ExistingBoundaryCiCheck[]>;
  create(payload: CompletedCheckPayloadV1): Promise<ExistingBoundaryCiCheck>;
  update(checkId: number, payload: Omit<CompletedCheckPayloadV1, 'annotations'>): Promise<ExistingBoundaryCiCheck>;
}

interface PublicProbotChecksOctokit extends PublicProbotScopedAuth {
  rest: { checks: {
    listForRef(parameters: Readonly<Record<string, unknown>>): Promise<unknown>;
    create(parameters: Readonly<Record<string, unknown>>): Promise<unknown>;
    update(parameters: Readonly<Record<string, unknown>>): Promise<unknown>;
  } };
}

export interface CheckPublicationRoute { owner: string; repo: string; }

export interface PublishClock { now(): number; }
export type SubsequentMutationGuard = () => Promise<boolean>;
const SYSTEM_CLOCK: PublishClock = Object.freeze({ now: () => Date.now() });
const ALLOW_SUBSEQUENT_MUTATION: SubsequentMutationGuard = async () => true;
const PUBLICATION_PERMISSIONS = Object.freeze({ checks: 'write' as const });

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean { const actual = Object.keys(value).sort(); const wanted = [...expected].sort(); return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]); }
function positive(value: unknown): value is number { return typeof value === 'number' && Number.isSafeInteger(value) && value > 0; }
function isTransient(error: unknown): boolean {
  if (error instanceof SanitizedGitHubReadError) return error.retryable;
  if (typeof error !== 'object' || error === null) return false;
  const value = error as { status?: unknown; code?: unknown };
  return value.status === 408 || value.status === 429 || (typeof value.status === 'number' && value.status >= 500 && value.status <= 599) || (typeof value.code === 'string' && /^(?:ECONN|ETIMEDOUT|EAI_AGAIN)/u.test(value.code));
}
function validCheck(value: unknown, expectedId?: number): ExistingBoundaryCiCheck | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value) || !exactKeys(value as Record<string, unknown>, ['id'])) return null;
  const id = (value as { id: unknown }).id;
  return positive(id) && (expectedId === undefined || id === expectedId) ? Object.freeze({ id }) : null;
}
function updatePayload(payload: CompletedCheckPayloadV1): Omit<CompletedCheckPayloadV1, 'annotations'> { const { annotations: _annotations, ...result } = payload; return Object.freeze(result); }
function invalidResult(): CheckPublicationResultV1 { return Object.freeze({ status: 'not-published', reason: 'publication-failure' }); }
function conflictResult(): CheckPublicationResultV1 { return Object.freeze({ status: 'not-published', reason: 'publication-conflict' }); }

function validateIssuedRole(value: unknown, identity: CheckPublicationIdentity): IssuedCheckPublicationRole {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new SanitizedGitHubReadError('credential-narrowing-unsupported', false);
  const issued = value as Record<string, unknown>;
  if (!exactKeys(issued, ['credentialScope', 'permissions', 'repositoryIds', 'transport'])) throw new SanitizedGitHubReadError('credential-scope-mismatch', false);
  if (issued.credentialScope !== 'issuance-narrowed') throw new SanitizedGitHubReadError('credential-narrowing-unsupported', false);
  if (!Array.isArray(issued.repositoryIds) || issued.repositoryIds.length !== 1 || issued.repositoryIds[0] !== identity.repositoryId) throw new SanitizedGitHubReadError('credential-scope-mismatch', false);
  if (typeof issued.permissions !== 'object' || issued.permissions === null || Array.isArray(issued.permissions)) throw new SanitizedGitHubReadError('credential-scope-mismatch', false);
  const permissions = issued.permissions as Record<string, unknown>;
  if ((!exactKeys(permissions, ['checks']) && !exactKeys(permissions, ['checks', 'metadata'])) ||
    permissions.checks !== 'write' || (Object.hasOwn(permissions, 'metadata') && permissions.metadata !== 'read')) throw new SanitizedGitHubReadError('credential-scope-mismatch', false);
  if (typeof issued.transport !== 'object' || issued.transport === null || Array.isArray(issued.transport) || !exactKeys(issued.transport as Record<string, unknown>, ['create', 'listForRef', 'update'])) throw new SanitizedGitHubReadError('credential-narrowing-unsupported', false);
  const transport = issued.transport as Record<string, unknown>;
  if (['listForRef', 'create', 'update'].some((method) => typeof transport[method] !== 'function')) throw new SanitizedGitHubReadError('credential-narrowing-unsupported', false);
  return issued as unknown as IssuedCheckPublicationRole;
}

function normalizePage(value: unknown, page: number): { records: readonly Record<string, unknown>[]; nextPage: number | null; totalCount: number } {
  if (typeof value !== 'object' || value === null || Array.isArray(value) || !exactKeys(value as Record<string, unknown>, ['nextPage', 'records', 'totalCount'])) throw new SanitizedGitHubReadError('contract-invalid', false);
  const record = value as Record<string, unknown>;
  if (!Array.isArray(record.records) || record.records.length > 100 || !Number.isSafeInteger(record.totalCount) ||
    (record.totalCount as number) < 0 || (record.totalCount as number) > MAX_RECORDS ||
    (record.nextPage !== null && (!positive(record.nextPage) || record.nextPage !== page + 1)) ||
    record.records.some((entry) => typeof entry !== 'object' || entry === null || Array.isArray(entry))) throw new SanitizedGitHubReadError('contract-invalid', false);
  const seen = (page - 1) * 100 + record.records.length;
  const complete = seen === record.totalCount;
  if (seen > (record.totalCount as number) || (complete && record.nextPage !== null) ||
    (!complete && (record.records.length !== 100 || record.nextPage !== page + 1))) throw new SanitizedGitHubReadError('contract-invalid', false);
  return Object.freeze({ records: Object.freeze(record.records.map((entry) => entry as Record<string, unknown>)), nextPage: record.nextPage, totalCount: record.totalCount as number });
}
function exactMatches(records: readonly Record<string, unknown>[], query: Readonly<{ appId: number; headSha: string; name: typeof CHECK_NAME; correlationId: string }>): readonly ExistingBoundaryCiCheck[] {
  const matches: ExistingBoundaryCiCheck[] = [];
  for (const item of records) {
    if (!exactKeys(item, ['appId', 'externalId', 'headSha', 'id', 'name']) || !positive(item.id) || !positive(item.appId) || typeof item.headSha !== 'string' || typeof item.name !== 'string' || typeof item.externalId !== 'string') throw new SanitizedGitHubReadError('contract-invalid', false);
    if (item.appId === query.appId && item.headSha === query.headSha && item.name === query.name && item.externalId === query.correlationId) matches.push(Object.freeze({ id: item.id }));
  }
  return Object.freeze(matches);
}

/** Issues a repository-scoped Checks-only role and exposes no credential or arbitrary request path. */
export async function createCheckPublicationCapability(identity: CheckPublicationIdentity, provider: CheckPublicationProvider): Promise<CheckPublisher> {
  if (!positive(identity.installationId) || !positive(identity.repositoryId)) throw new SanitizedGitHubReadError('credential-scope-mismatch', false);
  const request: CheckPublicationIssueRequest = Object.freeze({ installationId: identity.installationId, repositoryIds: Object.freeze([identity.repositoryId]) as [number], permissions: PUBLICATION_PERMISSIONS });
  let issued: IssuedCheckPublicationRole;
  try { issued = validateIssuedRole(await provider.issue(request), identity); } catch (error) { throw error instanceof SanitizedGitHubReadError ? error : new SanitizedGitHubReadError('credential-narrowing-unsupported', false); }
  const capability: CheckPublisher = {
    async lookupExact(query: Readonly<{ appId: number; headSha: string; name: typeof CHECK_NAME; correlationId: string }>) {
      let page = 1; let seen = 0; let totalCount: number | undefined; const records: Record<string, unknown>[] = [];
      for (let pages = 0; pages < MAX_PAGES; pages += 1) {
        let current: { records: readonly Record<string, unknown>[]; nextPage: number | null; totalCount: number };
        try { current = normalizePage(await issued.transport.listForRef(Object.freeze({ ...query, filter: 'all', perPage: 100, page })), page); } catch (error) { throw error instanceof SanitizedGitHubReadError ? error : new SanitizedGitHubReadError('contract-invalid', false); }
        if (totalCount !== undefined && current.totalCount !== totalCount) throw new SanitizedGitHubReadError('contract-invalid', false);
        totalCount = current.totalCount;
        seen += current.records.length; if (seen > MAX_RECORDS) throw new SanitizedGitHubReadError('contract-invalid', false);
        records.push(...current.records); if (current.nextPage === null) return exactMatches(records, query); page = current.nextPage;
      }
      throw new SanitizedGitHubReadError('contract-invalid', false);
    },
    async create(value: CompletedCheckPayloadV1) { const result = validCheck(await issued.transport.create(value)); if (result === null) throw new SanitizedGitHubReadError('contract-invalid', false); return result; },
    async update(id: number, value: Omit<CompletedCheckPayloadV1, 'annotations'>) { const result = validCheck(await issued.transport.update(id, value), id); if (result === null) throw new SanitizedGitHubReadError('contract-invalid', false); return result; },
  };
  return Object.freeze(capability);
}

function responseData(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value) || !Object.hasOwn(value as Record<string, unknown>, 'data')) throw new SanitizedGitHubReadError('contract-invalid', false);
  const data = (value as { data: unknown }).data;
  if (typeof data !== 'object' || data === null || Array.isArray(data)) throw new SanitizedGitHubReadError('contract-invalid', false);
  return data as Record<string, unknown>;
}
function checkResponse(value: unknown): unknown {
  const data = responseData(value);
  return { id: data.id };
}
function createAnnotations(annotations: CompletedCheckPayloadV1['annotations']): readonly Readonly<Record<string, unknown>>[] {
  return annotations.map((annotation) => Object.freeze({
    path: annotation.path,
    start_line: annotation.startLine,
    end_line: annotation.endLine,
    annotation_level: annotation.level,
    title: annotation.title,
    message: annotation.message,
  }));
}
function listResponse(value: unknown, page: number): unknown {
  const data = responseData(value);
  if (!exactKeys(data, ['check_runs', 'total_count']) || !Array.isArray(data.check_runs) || !Number.isSafeInteger(data.total_count) || (data.total_count as number) < 0) throw new SanitizedGitHubReadError('contract-invalid', false);
  const records = data.check_runs.map((entry) => {
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) throw new SanitizedGitHubReadError('contract-invalid', false);
    const item = entry as Record<string, unknown>; const app = item.app;
    if (typeof app !== 'object' || app === null || Array.isArray(app)) throw new SanitizedGitHubReadError('contract-invalid', false);
    return { id: item.id, name: item.name, headSha: item.head_sha, externalId: item.external_id, appId: (app as Record<string, unknown>).id };
  });
  const totalCount = data.total_count as number;
  if (records.length > 100 || totalCount > MAX_RECORDS) throw new SanitizedGitHubReadError('contract-invalid', false);
  const seen = (page - 1) * 100 + records.length;
  if (seen > totalCount || (records.length < 100 && seen !== totalCount)) throw new SanitizedGitHubReadError('contract-invalid', false);
  return { records, totalCount, nextPage: seen < totalCount ? page + 1 : null };
}

/**
 * Issues and validates a repository-scoped Checks-write token, then projects only the three fixed
 * Checks operations. Neither the token nor its authenticated client leaves this adapter closure.
 */
export async function createProbotCheckPublicationCapability(
  identity: CheckPublicationIdentity,
  octokit: PublicProbotChecksOctokit,
  route: CheckPublicationRoute,
): Promise<CheckPublisher> {
  const provider: CheckPublicationProvider = Object.freeze({
    async issue(request: CheckPublicationIssueRequest) {
      if (request.installationId !== identity.installationId || request.repositoryIds[0] !== identity.repositoryId || !exactKeys(request.permissions, ['checks']) || request.permissions.checks !== 'write') throw new SanitizedGitHubReadError('credential-scope-mismatch', false);
      const narrowed = await issueNarrowedProbotRole(octokit, request, (client) => {
        if (typeof client !== 'object' || client === null ||
          typeof (client as { rest?: unknown }).rest !== 'object' || (client as { rest: unknown }).rest === null ||
          typeof (client as PublicProbotChecksOctokit).rest.checks !== 'object' || (client as PublicProbotChecksOctokit).rest.checks === null) {
          throw new SanitizedGitHubReadError('credential-narrowing-unsupported', false);
        }
        const checks = (client as PublicProbotChecksOctokit).rest.checks;
        if ([checks.listForRef, checks.create, checks.update].some((method) => typeof method !== 'function')) {
          throw new SanitizedGitHubReadError('credential-narrowing-unsupported', false);
        }
        const listForRef = checks.listForRef.bind(checks);
        const createCheck = checks.create.bind(checks);
        const updateCheck = checks.update.bind(checks);
        return Object.freeze({
          listForRef: async (query: CheckPublicationListRequest) => listResponse(await listForRef({ owner: route.owner, repo: route.repo, ref: query.headSha, check_name: query.name, app_id: query.appId, filter: query.filter, per_page: query.perPage, page: query.page }), query.page),
          create: async (payload: CompletedCheckPayloadV1) => checkResponse(await createCheck({ owner: route.owner, repo: route.repo, name: payload.name, head_sha: payload.headSha, status: payload.status, conclusion: payload.conclusion, output: { title: payload.title, summary: payload.summary, text: payload.text, annotations: createAnnotations(payload.annotations) }, external_id: payload.externalId })),
          update: async (checkId: number, payload: Omit<CompletedCheckPayloadV1, 'annotations'>) => checkResponse(await updateCheck({ owner: route.owner, repo: route.repo, check_run_id: checkId, status: payload.status, conclusion: payload.conclusion, output: { title: payload.title, summary: payload.summary, text: payload.text }, external_id: payload.externalId })),
        });
      });
      return Object.freeze({ credentialScope: 'issuance-narrowed' as const, ...narrowed });
    },
  });
  return createCheckPublicationCapability(identity, provider);
}

/** D-02/D-05 completed-state upsert with one bounded reconciliation and no annotation replay. */
export async function publishCompletedCheck(
  publisher: CheckPublisher,
  appId: number,
  identity: CheckIdentityV1,
  payload: CompletedCheckPayloadV1,
  clock: PublishClock = SYSTEM_CLOCK,
  beforeSubsequentMutation: SubsequentMutationGuard = ALLOW_SUBSEQUENT_MUTATION,
): Promise<CheckPublicationResultV1> {
  try { validateCheckIdentity(identity); validateCompletedCheckPayload(payload); } catch { return Object.freeze({ status: 'not-published', reason: 'invalid-envelope' }); }
  if (!positive(appId) || payload.name !== CHECK_NAME || payload.headSha !== identity.headSha || payload.externalId !== identity.correlationId) return Object.freeze({ status: 'not-published', reason: 'invalid-envelope' });
  const started = clock.now(); const inBudget = (attempts: number): boolean => attempts < MAX_ATTEMPTS && Number.isFinite(clock.now()) && clock.now() - started >= 0 && clock.now() - started <= MAX_ELAPSED_MILLISECONDS;
  const query = Object.freeze({ appId, headSha: identity.headSha, name: CHECK_NAME, correlationId: identity.correlationId });
  let matches: readonly ExistingBoundaryCiCheck[];
  try { matches = await publisher.lookupExact(query); } catch { return invalidResult(); }
  if (!Array.isArray(matches) || matches.some((match) => validCheck(match) === null)) return invalidResult();
  if (matches.length > 1) return conflictResult();
  const operation = matches.length === 0 ? 'create' as const : 'update' as const; const targetId = matches[0]?.id; let attempts = 0;
  const write = async (kind: typeof operation, id: number | undefined): Promise<ExistingBoundaryCiCheck> => { attempts += 1; return kind === 'create' ? publisher.create(payload) : publisher.update(id!, updatePayload(payload)); };
  try {
    if (!inBudget(attempts)) return invalidResult();
    const result = validCheck(await write(operation, targetId), operation === 'update' ? targetId : undefined);
    return result === null ? invalidResult() : Object.freeze({ status: operation === 'create' ? 'created' : 'updated', correlationId: identity.correlationId, checkId: result.id });
  } catch (writeError) {
    const retryable = isTransient(writeError); if (!inBudget(attempts)) return invalidResult(); attempts += 1;
    try { matches = await publisher.lookupExact(query); } catch { return invalidResult(); }
    if (!Array.isArray(matches) || matches.some((match) => validCheck(match) === null)) return invalidResult();
    if (matches.length > 1) return conflictResult();
    if (matches.length === 1) {
      if (!inBudget(attempts)) return invalidResult();
      try { if (!await beforeSubsequentMutation()) return Object.freeze({ status: 'not-published', reason: 'stale-comparison' }); } catch { return invalidResult(); }
      try { const result = validCheck(await publisher.update(matches[0]!.id, updatePayload(payload)), matches[0]!.id); return result === null ? invalidResult() : Object.freeze({ status: 'updated', correlationId: identity.correlationId, checkId: result.id }); } catch { return invalidResult(); }
    }
    if (!retryable || !inBudget(attempts)) return invalidResult();
    try { if (!await beforeSubsequentMutation()) return Object.freeze({ status: 'not-published', reason: 'stale-comparison' }); } catch { return invalidResult(); }
    try { const result = validCheck(await write(operation, targetId), operation === 'update' ? targetId : undefined); return result === null ? invalidResult() : Object.freeze({ status: operation === 'create' ? 'created' : 'updated', correlationId: identity.correlationId, checkId: result.id }); } catch { return invalidResult(); }
  }
}
