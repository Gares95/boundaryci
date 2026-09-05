import { SanitizedGitHubReadError, type SanitizedGitHubReadErrorKind } from './github-read.js';
import type { GitHubReadCapability } from './github-read.js';
import { validateWorkIdentity, type WorkIdentity } from './contract.js';

const MAX_ATTEMPTS = 3;
const MAX_ELAPSED_MILLISECONDS = 60_000;
const BACKOFFS = Object.freeze([250, 1_000]);

export interface WorkControl {
  isCancelled(): boolean;
  checkpoint(): 'continue' | 'cancelled';
  signal: AbortSignal;
}

export type CoordinatedWorkResult<T> =
  | { status: 'current'; value: T }
  | { status: 'superseded' | 'cancelled' | 'runtime-infrastructure-failure' };

interface ActiveWork<T> {
  identity: WorkIdentity;
  key: string;
  pullKey: string;
  cancelled: boolean;
  cancellation: 'cancelled' | 'superseded' | null;
  abort: AbortController;
  deliveryIds: Set<string>;
  deliveryOverflow: boolean;
  promise: Promise<CoordinatedWorkResult<T>>;
}

export interface CoordinatedSubmission<T> {
  owner: boolean;
  result: Promise<CoordinatedWorkResult<T>>;
  deliveryIds(): readonly string[];
  overflowed(): boolean;
}

export interface BoundedReadOptions {
  now?: () => number;
  sleep?: (milliseconds: number) => Promise<void>;
  isCancelled?: () => boolean;
  signal?: AbortSignal;
  maxElapsedMilliseconds?: number;
  setTimer?: (callback: () => void, milliseconds: number) => ReturnType<typeof setTimeout>;
  clearTimer?: (timer: ReturnType<typeof setTimeout>) => void;
}

/**
 * A non-resetting read budget. A session owns one monotonic deadline and one retry counter;
 * callers deliberately create it at a lifecycle boundary rather than around each REST call.
 */
export interface BoundedReadSession {
  read<T>(operation: (options: { signal: AbortSignal }) => Promise<T>): Promise<T>;
  close(): void;
}

export type BoundedReadResult<T> =
  | { status: 'success'; value: T; attempts: number }
  | { status: 'cancelled'; attempts: number }
  | { status: 'not-retryable'; cause: SanitizedGitHubReadErrorKind; attempts: number }
  | { status: 'runtime-infrastructure-failure'; cause: 'transient-read-exhausted' | 'retry-budget-exhausted'; attempts: number };

class BoundedReadSessionFailure extends Error {
  constructor(readonly result: Exclude<BoundedReadResult<never>, { status: 'success' }>) {
    super(`bounded-read:${result.status}`);
  }
}

function positive(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) > 0;
}

function elapsedMilliseconds(started: number, now: () => number): number | null {
  const current = now();
  const raw = current - started;
  if (!Number.isFinite(current) || !Number.isFinite(raw) || raw < 0 || raw > Number.MAX_SAFE_INTEGER) return null;
  return Math.floor(raw);
}

/** Stable key encoding has no delivery ID or mutable branch/ref input. */
export function createWorkKey(identity: WorkIdentity): string {
  validateWorkIdentity(identity);
  return JSON.stringify([identity.installationId, identity.repositoryId, identity.pullNumber, identity.baseSha, identity.headSha, identity.evaluatorIdentity]);
}

function pullKey(identity: WorkIdentity): string {
  return `${identity.installationId}:${identity.repositoryId}:${identity.pullNumber}`;
}

/** In-memory-only latest-wins coordination; restart state is intentionally empty. */
export class DeliveryCoordinator {
  private readonly activeByWork = new Map<string, ActiveWork<unknown>>();
  private readonly latestByPull = new Map<string, ActiveWork<unknown>>();

  submit<T>(identity: WorkIdentity, run: (control: WorkControl) => Promise<T>): Promise<CoordinatedWorkResult<T>> {
    return this.submitWithOwnership(identity, 'internal', run).result;
  }

  /** Coalesces exact work while preserving every verified delivery ID for the sole owner handoff. */
  submitWithOwnership<T>(identity: WorkIdentity, deliveryId: string, run: (control: WorkControl) => Promise<T>): CoordinatedSubmission<T> {
    const key = createWorkKey(identity);
    const existing = this.activeByWork.get(key) as ActiveWork<T> | undefined;
    if (existing !== undefined) {
      if (!existing.deliveryIds.has(deliveryId) && existing.deliveryIds.size >= 64) existing.deliveryOverflow = true;
      else existing.deliveryIds.add(deliveryId);
      return Object.freeze({ owner: false, result: existing.promise, deliveryIds: () => Object.freeze([...existing.deliveryIds]), overflowed: () => existing.deliveryOverflow });
    }

    const perPull = pullKey(identity);
    const previous = this.latestByPull.get(perPull);
    if (previous !== undefined && previous.key !== key) {
      previous.cancelled = true;
      previous.cancellation = 'superseded';
      previous.abort.abort();
    }

    const active: ActiveWork<T> = {
      identity: Object.freeze({ ...identity }), key, pullKey: perPull, cancelled: false, cancellation: null, abort: new AbortController(), deliveryIds: new Set([deliveryId]), deliveryOverflow: false,
      promise: Promise.resolve({ status: 'cancelled' }) as Promise<CoordinatedWorkResult<T>>,
    };
    const control: WorkControl = Object.freeze({
      isCancelled: () => active.cancelled,
      checkpoint: () => active.cancelled ? 'cancelled' : 'continue',
      signal: active.abort.signal,
    });
    active.promise = Promise.resolve()
      .then(async () => run(control))
      .then((value) => this.finish(active, value))
      .catch(() => this.finish(active, undefined as T, true));
    this.activeByWork.set(key, active as ActiveWork<unknown>);
    this.latestByPull.set(perPull, active as ActiveWork<unknown>);
    return Object.freeze({ owner: true, result: active.promise, deliveryIds: () => Object.freeze([...active.deliveryIds]), overflowed: () => active.deliveryOverflow });
  }

  cancel(identity: WorkIdentity): boolean {
    const active = this.activeByWork.get(createWorkKey(identity));
    if (active === undefined) return false;
    active.cancelled = true;
    active.cancellation = 'cancelled';
    active.abort.abort();
    return true;
  }

  snapshot(): { active: number; pending: 0; recovered: 0; delivered: 0 } {
    return Object.freeze({ active: this.activeByWork.size, pending: 0, recovered: 0, delivered: 0 });
  }

  private finish<T>(active: ActiveWork<T>, value: T, failed = false): CoordinatedWorkResult<T> {
    this.activeByWork.delete(active.key);
    if (this.latestByPull.get(active.pullKey) === active) this.latestByPull.delete(active.pullKey);
    if (active.cancellation === 'superseded' || this.latestByPull.has(active.pullKey)) return Object.freeze({ status: 'superseded' });
    if (active.cancellation === 'cancelled') return Object.freeze({ status: 'cancelled' });
    if (failed) return Object.freeze({ status: 'runtime-infrastructure-failure' });
    return Object.freeze({ status: 'current', value });
  }
}

function retryable(error: SanitizedGitHubReadError): boolean {
  return error.retryable && ['transient-transport', 'transient-service', 'rate-limited'].includes(error.kind);
}

async function sleepUntilAbortable(
  sleep: (milliseconds: number) => Promise<void>,
  milliseconds: number,
  signal: AbortSignal,
  failure: () => BoundedReadSessionFailure,
): Promise<void> {
  if (signal.aborted) throw failure();
  let rejectAbort!: (error: BoundedReadSessionFailure) => void;
  const aborted = new Promise<never>((_resolve, reject) => { rejectAbort = reject as (error: BoundedReadSessionFailure) => void; });
  const onAbort = (): void => rejectAbort(failure());
  signal.addEventListener('abort', onAbort, { once: true });
  try {
    await Promise.race([sleep(milliseconds), aborted]);
  } finally {
    signal.removeEventListener('abort', onAbort);
  }
}

/**
 * Starts a finite read session. Successful calls do not consume retry budget, while every
 * transient retry across every wrapped operation consumes the same session-owned allowance.
 */
export function createBoundedReadSession(options: BoundedReadOptions = {}): BoundedReadSession {
  const now = options.now ?? (() => performance.now());
  const sleep = options.sleep ?? (async (milliseconds: number) => new Promise<void>((resolve) => setTimeout(resolve, milliseconds)));
  const maxElapsedMilliseconds = options.maxElapsedMilliseconds ?? MAX_ELAPSED_MILLISECONDS;
  const setTimer = options.setTimer ?? ((callback, milliseconds) => setTimeout(callback, milliseconds));
  const clearTimer = options.clearTimer ?? ((timer) => clearTimeout(timer));
  const started = now();
  let attempts = 0;
  let retries = 0;
  let closed = false;
  const abort = new AbortController();
  const cancel = (): void => abort.abort();
  options.signal?.addEventListener('abort', cancel, { once: true });

  const failureForAbort = (): BoundedReadSessionFailure => new BoundedReadSessionFailure(
    options.isCancelled?.() || options.signal?.aborted
      ? { status: 'cancelled', attempts }
      : { status: 'runtime-infrastructure-failure', cause: 'retry-budget-exhausted', attempts },
  );

  return Object.freeze({
    async read<T>(operation: (readOptions: { signal: AbortSignal }) => Promise<T>): Promise<T> {
      if (!Number.isFinite(started)) {
        throw new BoundedReadSessionFailure({ status: 'runtime-infrastructure-failure', cause: 'retry-budget-exhausted', attempts });
      }
      while (true) {
        if (closed || options.isCancelled?.() || abort.signal.aborted) throw failureForAbort();
        const elapsed = elapsedMilliseconds(started, now);
        if (elapsed === null || elapsed >= maxElapsedMilliseconds) {
          throw new BoundedReadSessionFailure({ status: 'runtime-infrastructure-failure', cause: 'retry-budget-exhausted', attempts });
        }
        attempts += 1;
        const remaining = maxElapsedMilliseconds - elapsed;
        let timer: ReturnType<typeof setTimeout> | undefined;
        let rejectAbort!: (reason: BoundedReadSessionFailure) => void;
        const aborting = new Promise<never>((_resolve, reject) => {
          rejectAbort = reject as (reason: BoundedReadSessionFailure) => void;
        });
        const onAbort = (): void => rejectAbort(failureForAbort());
        abort.signal.addEventListener('abort', onAbort, { once: true });
        timer = setTimer(() => abort.abort(), remaining);
        try {
          return await Promise.race([operation({ signal: abort.signal }), aborting]);
        } catch (error) {
          if (error instanceof BoundedReadSessionFailure) throw error;
          const sanitized = error instanceof SanitizedGitHubReadError ? error : new SanitizedGitHubReadError('contract-invalid', false);
          if (!retryable(sanitized)) throw sanitized;
          retries += 1;
          if (retries >= MAX_ATTEMPTS) {
            throw new BoundedReadSessionFailure({ status: 'runtime-infrastructure-failure', cause: 'transient-read-exhausted', attempts });
          }
          if (options.isCancelled?.()) throw new BoundedReadSessionFailure({ status: 'cancelled', attempts });
          const beforeSleep = elapsedMilliseconds(started, now);
          if (beforeSleep === null || beforeSleep >= maxElapsedMilliseconds) {
            throw new BoundedReadSessionFailure({ status: 'runtime-infrastructure-failure', cause: 'retry-budget-exhausted', attempts });
          }
          const remaining = maxElapsedMilliseconds - beforeSleep;
          const localBackoff = BACKOFFS[retries - 1];
          if (localBackoff === undefined) {
            throw new BoundedReadSessionFailure({ status: 'runtime-infrastructure-failure', cause: 'retry-budget-exhausted', attempts });
          }
          const requested = sanitized.retryAfterMilliseconds ?? localBackoff;
          const delay = Math.min(requested, remaining);
          if (!positive(delay)) {
            throw new BoundedReadSessionFailure({ status: 'runtime-infrastructure-failure', cause: 'retry-budget-exhausted', attempts });
          }
          await sleepUntilAbortable(sleep, delay, abort.signal, failureForAbort);
        } finally {
          if (timer !== undefined) clearTimer(timer);
          abort.signal.removeEventListener('abort', onAbort);
        }
      }
    },
    close(): void {
      closed = true;
      options.signal?.removeEventListener('abort', cancel);
      abort.abort();
    },
  });
}

/** Wraps precisely the already-issued five-operation capability without adding a route escape hatch. */
export function bindBoundedReadSession(read: GitHubReadCapability, session: BoundedReadSession): GitHubReadCapability {
  return Object.freeze({
    getCurrentPull: (pullNumber: number) => session.read((options) => read.getCurrentPull(pullNumber, options)),
    listOpenPullsByBase: (baseRef: string, page: number) => session.read((options) => read.listOpenPullsByBase(baseRef, page, options)),
    getCommit: (sha: string) => session.read((options) => read.getCommit(sha, options)),
    getTree: (sha: string) => session.read((options) => read.getTree(sha, options)),
    getBlob: (sha: string) => session.read((options) => read.getBlob(sha, options)),
  });
}

/** Runs only an already-authorized idempotent read with one finite per-work retry budget. */
export async function runBoundedRead<T>(read: () => Promise<T>, options: BoundedReadOptions = {}): Promise<BoundedReadResult<T>> {
  const now = options.now ?? (() => performance.now());
  const sleep = options.sleep ?? (async (milliseconds: number) => new Promise<void>((resolve) => setTimeout(resolve, milliseconds)));
  const started = now();
  if (!Number.isFinite(started)) return Object.freeze({ status: 'runtime-infrastructure-failure', cause: 'retry-budget-exhausted', attempts: 0 });
  let attempts = 0;
  while (attempts < MAX_ATTEMPTS) {
    if (options.isCancelled?.()) return Object.freeze({ status: 'cancelled', attempts });
    const elapsed = elapsedMilliseconds(started, now);
    if (elapsed === null || elapsed > MAX_ELAPSED_MILLISECONDS) return Object.freeze({ status: 'runtime-infrastructure-failure', cause: 'retry-budget-exhausted', attempts });
    attempts += 1;
    try {
      return Object.freeze({ status: 'success', value: await read(), attempts });
    } catch (error) {
      const sanitized = error instanceof SanitizedGitHubReadError ? error : new SanitizedGitHubReadError('contract-invalid', false);
      if (!retryable(sanitized)) return Object.freeze({ status: 'not-retryable', cause: sanitized.kind, attempts });
      if (attempts === MAX_ATTEMPTS) return Object.freeze({ status: 'runtime-infrastructure-failure', cause: 'transient-read-exhausted', attempts });
      if (options.isCancelled?.()) return Object.freeze({ status: 'cancelled', attempts });
      const beforeSleep = elapsedMilliseconds(started, now);
      if (beforeSleep === null || beforeSleep >= MAX_ELAPSED_MILLISECONDS) return Object.freeze({ status: 'runtime-infrastructure-failure', cause: 'retry-budget-exhausted', attempts });
      const remaining = MAX_ELAPSED_MILLISECONDS - beforeSleep;
      const localBackoff = BACKOFFS[attempts - 1];
      if (localBackoff === undefined) {
        return Object.freeze({ status: 'runtime-infrastructure-failure', cause: 'retry-budget-exhausted', attempts });
      }
      const requested = sanitized.retryAfterMilliseconds ?? localBackoff;
      const delay = Math.min(requested, remaining);
      if (!positive(delay)) return Object.freeze({ status: 'runtime-infrastructure-failure', cause: 'retry-budget-exhausted', attempts });
      await sleep(delay);
    }
  }
  return Object.freeze({ status: 'runtime-infrastructure-failure', cause: 'transient-read-exhausted', attempts });
}
