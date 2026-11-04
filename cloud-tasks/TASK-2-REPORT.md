# TASK-2 adversarial audit report

Baseline: released v1 `4d00b78aafbf1b0faccaceaec97b876ec5c1757a` plus the contract commit `8befcda`.
Branch: `experiment/cloud-v1-adversarial` (not merged; `main` untouched).

`cloud-tasks/TASK-2.md` restates the experiment contract without a narrower objective, so this
experiment was executed as a bounded adversarial hardening audit within the allowed work list:
hostile-input regression tests, deterministic property testing, and narrow fixes inside existing
v1 semantics. No catalog, operation, grammar, provenance, client-family, or infrastructure scope
was added. All fixtures are synthetic.

## Confirmed defects (fixed, one commit each)

### 1. Catastrophic backtracking in limited-glob matching — `4828269`

- **Where:** `src/analyzer/discovery.ts` (`compileLimitedGlob`), used by local discovery,
  delivery snapshot relevance (`src/delivery/snapshot.ts`), and therefore every analysis.
- **Input authority:** `analysis.include` / `analysis.exclude` in a repository's
  `.boundaryci.yml`, i.e. hostile target input. Patterns were bounded only by the 256 KiB
  configuration size.
- **Failure:** each segment compiled to a backtracking regular expression, and `**` splits were
  re-explored recursively. Measured on v1: `*a*a*a*a*a*a*b` against a 60-character name took
  about 4 s; ten `**` segments against a 30-segment path took about 31 s, growing exponentially.
  Matching is synchronous, so the delivery elapsed-time budget cannot interrupt it, and a
  blocked event loop stalls every installation served by the process. A head-only pattern is
  compiled but never matched (base authority), so the trigger is a pattern present in base, or
  any local CLI run against such a repository.
- **Fix:** the same language through polynomial algorithms: a single-resume `*`/`?` scan over
  code points, plus a reachable-prefix table for `**`.
- **Tests:** `tests/analyzer/glob-complexity.test.ts`. Pathological in-segment and globstar
  patterns finish in milliseconds. A deterministic 4,000-case property test proves equivalence
  with a verbatim copy of the v1 matcher, including non-ASCII and astral code points.

### 2. Unbounded pre-authentication webhook body buffering — `5a805d2`

- **Where:** `src/delivery/server.ts` → Probot → `@octokit/webhooks` Node middleware
  (`getPayloadFromRequestStream`), which concatenates the whole body with no limit before
  verifying the signature.
- **Failure:** any client that can reach the listener could POST an arbitrarily large body with
  placeholder webhook headers, and the process would buffer all of it before rejecting the
  signature. That is memory exhaustion without authentication.
- **Fix:** the listener reads the webhook body itself under GitHub's documented 25 MB payload
  cap. An oversized declared `Content-Length` or streamed body gets a fixed JSON 413 and a closed
  connection, and never reaches Probot. An in-bound body is handed to the unchanged middleware as
  `rawBody`, which `@octokit/webhooks` verifies in place of the stream. Signature verification
  therefore still covers the exact original bytes; the existing signed end-to-end server test
  passes unchanged.
- **Tests:** `tests/delivery/server.test.ts` › `production webhook body bound`.
- **Docs:** one line added to the HTTP surface in `docs/github-delivery.md`.

## Hardening opportunities (not changed)

1. **Single tree-entry names containing `/`.** `validateEntry` in `src/delivery/snapshot.ts`
   applies the full-path `assertPath` to non-recursive tree entry names, so a (non-Git-conformant)
   response entry such as `src/app.ts` in a root tree is accepted and materialized. Containment,
   duplicate, and `..` checks still hold, and the remaining blob-versus-directory conflicts end in
   fail-closed runtime failure. Existing delivery fixtures deliberately rely on flattened names,
   so rejecting `/` would mean rewriting those fixtures. That is left as a maintainer decision.
2. **Delivery relevance versus local discovery.** `relevantSource` in the snapshot step does not
   apply discovery's `node_modules` and `.d.ts`/`.d.mts` exclusions. Under a custom configuration
   without those excludes, delivery can report a `relevant-symlink` or
   `relevant-unsupported-object` cause, or spend source budget, for entries the local analyzer
   would ignore. The divergence only moves toward *more* incompleteness, never toward a cleaner
   result.

## Behavior/documentation mismatch needing a maintainer decision

- **Push fan-out with an open external-fork pull request.** `docs/github-delivery.md` says a push
  triggers discovery "only for open same-repository pull requests". In
  `src/delivery/trigger.ts`, though, any listed pull request whose head repository differs makes
  the whole fan-out `fanout-incomplete` (`page-shape`). One open fork PR against a branch
  therefore deterministically suppresses push-triggered refreshes for every same-repository PR
  on that branch. This is fail-closed; nothing turns green. Skipping forks would change an
  explicit all-or-none design, so it was not changed here.

## Probed and found sound (negative results)

- **Snapshot acquisition:** path validation (traversal, absolute, backslash, NUL, lone
  surrogates), exact SHA binding, canonical/wrapped base64 with exact size, symlink and gitlink
  handling, `O_EXCL|O_NOFOLLOW` writes into owner-only roots, owned-root cleanup checks, and work,
  entry, byte, and time budgets.
- **Read adapter:** exact-key response validation, scope validation of issued roles, and
  sanitized errors.
- **Configuration loading:** 256 KiB bound, symlink/non-regular rejection, strict UTF-8, aliases
  disabled, duplicate keys and multiple documents rejected. 120k-deep flow nesting fails closed
  as `config-yaml-syntax` in under 1 s.
- **Analyzer on deeply nested hostile source** (20k nested parens/calls/arrows, 200k-term binary
  chain): stack exhaustion is caught and becomes a repository-scoped `internal-analyzer-error`
  with no trusted evidence (CLI exit 4). No crash and no clean result. A per-file cause would be
  more precise, but the current behavior is fail-closed.
- **Check rendering:** paths are inline-code-escaped with variable-length fences, control
  characters are rejected, permission and operation identities are allowlisted, and summary and
  details are bounded in UTF-8 bytes and record count.

## Speculative concerns

- Unicode bidirectional or confusable characters in source paths are allowed in rendered Check
  details and annotations; GitHub's own rendering governs how they display. Not exploitable for
  policy outcomes.
- The `rawBody` handoff relies on `@octokit/webhooks` honoring `rawBody` (true in the pinned
  14.2.0). If a future upgrade dropped it, requests would hang until the middleware's 202
  timeout without verification succeeding. That fails closed and the signed end-to-end server
  test would catch it.

## Validation

`npm test` (43 files passed, 1 skipped; 835 tests passed, 5 skipped), `npm run typecheck`,
`npm run lint`, `npm run format:check`, and `npm run build` all pass on Node 24.22.1 / pnpm 11.11.0.
