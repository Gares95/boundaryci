# TASK-2 adversarial audit report

- **Baseline:** released v1 `4d00b78aafbf1b0faccaceaec97b876ec5c1757a`. The contract commit `8befcda` follows it.
- **Branch:** `experiment/cloud-v1-adversarial`. It is not merged, and `main` is untouched.
- **Objective:** a deep adversarial security and correctness audit of released BoundaryCI v1, restricted to its existing supported semantics.
  - The highest-priority question is whether any supported input can produce a clean-looking, complete-looking, or otherwise misleading result when the existing grammar or catalog should have detected a permission-significant condition.
  - No product capability, catalog row, supported operation, grammar form, or infrastructure was added.
- **Fixtures:** all synthetic. Runtime checks used the pinned `octokit@5.0.5` with an offline recording `fetch`. No GitHub writes were made and no network calls were needed.

## Classification legend

**Status:**
- **CONFIRMED defect:** reproduced with a minimal synthetic input, and it violates documented v1 behavior.
- **Fixed defect:** a confirmed defect with a regression test written before the fix, and a narrow fix that restores intended v1 semantics.
- **Hardening opportunity:** real behavior that does not violate documented v1 semantics but could be tightened.
- **Operator decision:** behavior that conflicts with some documentation or intent while other v1 tests or docs make it deliberate. Changing it is a maintainer decision.
- **Unsupported by design:** documented as outside the v1 grammar or scope.
- **Rejected hypothesis:** attacked with a reproducer, and the code behaved correctly.

**Severity:** CRITICAL, HIGH, MEDIUM, LOW, OUT_OF_SCOPE_BY_DESIGN, NOT_A_DEFECT.

## Audit map and threat model

| Surface | Hostile input | Trust boundary reviewed |
| --- | --- | --- |
| Analyzer census and provenance (`src/analyzer/candidates.ts`, `analyze.ts`, `resolve.ts`) | target source | a relevant call must never become silent absence (false-clean) |
| Request and operation identity (`operations.ts`, profile) | route strings and objects | no wrong operation proven; near-misses stay incomplete |
| Comparison and policy (`src/diff/revision.ts`, `src/policy/evaluate.ts`) | analysis results | incompleteness never yields a pass; known positive evidence is retained |
| Discovery and globs (`src/analyzer/discovery.ts`) | file tree, `.boundaryci.yml` patterns | bounded work; no-follow symlinks; regular files only |
| Configuration (`src/config/*`) | `.boundaryci.yml` bytes | bounded YAML; canonical identity |
| Snapshot acquisition (`src/delivery/snapshot.ts`, `github-read.ts`) | GitHub API responses, Git paths | exact SHAs; path containment; private roots and cleanup |
| HTTP listener (`src/delivery/server.ts`) | unauthenticated requests | pre-verification resource bounds; original-byte signatures |
| Trigger and coordinator (`trigger.ts`, `coordinator.ts`, `check-coordinator.ts`) | signed payloads | authenticated current-state reads; freshness |
| Check rendering (`check-render.ts`) | repository-controlled paths | no injection; every accepted result is published |
| CLI rendering (`src/cli/render.ts`) | repository-controlled paths and names | line-oriented human output integrity |
| Process boundary (`src/cli/main.ts`, `server.ts`) | environment, argv | no subprocess, shell, `eval`, or dynamic loading |
| Envelope and evidence canonicalization (`contract.ts`, `src/runtime/evaluate.ts`) | tampered nested data | exact-shape validation; deterministic output |

## Confirmed and fixed defects

### F1 (HIGH, false-clean): detached authorized-client REST surface reported as clean — fixed in `c139520`

- **Path:** `censusCandidates` in `src/analyzer/candidates.ts`.
  - On a proven `new Octokit()` client, detaching the REST surface before the call left no candidate at all.
  - Analysis reported `complete` with an empty boundary.
- **Reproducers.** Each form was verified to send the real write with `octokit@5.0.5`:
  ```ts
  const issues = client.rest.issues;  issues.create({...});
  const { issues } = client.rest;     const { rest: { issues } } = client;
  const send = client.request;        const { request } = client;
  client.request.defaults({...});     client.paginate('GET /repos/{owner}/{repo}/issues');
  export const issues = client.rest.issues;   // called from another file
  ```
- **Impact:**
  - `boundaryci check` turned a genuine Issues `read -> write` expansion into `outcome: complete`, `direction=unchanged`, exit 0.
  - In delivery that is a green "Permission boundary unchanged" Check.
- **Violation:**
  - `docs/analyzer.md` states that endpoint extraction is unsupported.
  - It also states that an unsupported form at an anchored site "is incomplete rather than silently clean".
  - The census module states that a matcher gap "can never turn a relevant site into silent absence". No v1 fixture pinned these forms as clean.
- **Fix:**
  - The census records these detached-surface sites as proof-conditional.
  - Classification makes a site `incomplete` (`unsupported-endpoint-extraction` or `unsupported-request-grammar`) only when its receiver is independently proven to be an authorized client, and drops it otherwise.
  - No operation is ever proven from these forms, so the supported grammar does not widen.
  - All golden, real-world-label, and census fixtures are byte-identical to v1.
- **Tests:** `tests/analyzer/surface-extraction.test.ts` (18).
  - 15 detached forms, including private field, Probot context, client alias, and cross-file export.
  - Controls for supported calls, proven look-alikes, and unproven receivers.

### F2 (MEDIUM): a source file name could suppress the Check entirely — fixed in `274e013`

- **Path:**
  - `renderCompletedCheck` in `src/delivery/check-render.ts` threw `source path is not safe to render` for a Git-valid path containing a control character.
  - `createCheckCoordinator` then recorded `not-published` / `invalid-envelope`.
- **Reproducer:** this is the real coordinator path, for the same `read -> write` expansion.
  - For `src/app.ts`, a `failure` Check is created ("Permission expansion requires review").
  - For `src/a\nb.ts`, no Check is published.
- **Impact:**
  - A pull-request author could suppress BoundaryCI's failing Check by naming a file.
  - The suppression fails closed only when BoundaryCI is a required status check.
- **Violation:**
  - `docs/architecture.md`: "Every accepted result is rendered directly to one completed `BoundaryCI` Check".
  - `docs/github-delivery.md` gives the rule for non-locatable evidence.
- **Fix:**
  - An unsafe path becomes non-locatable evidence. The conclusion, title, and counts are unchanged.
  - There is no annotation, and the path never reaches the summary or details.
- **Tests:** `tests/delivery/check-render.test.ts`: newline, ESC, and tab paths, plus coordinator publication.
  - The third assertion of the existing A36/A38 test previously required the throw. It now asserts the protected property directly: no control-character path in the emitted Markdown.
  - The annotation selector still rejects unsafe paths.

### F3 (MEDIUM, availability): catastrophic backtracking in limited-glob matching — fixed in `4828269`; tests strengthened in `9804473`

- **Path:**
  - `compileLimitedGlob` in `src/analyzer/discovery.ts` used one backtracking regular expression per segment, with recursive `**` expansion.
  - Patterns come from `.boundaryci.yml` and were bounded only by its 256 KiB size.
- **Reproduced on the real v1 build:**
  - `*a*a*a*a*a*a*b` against a 60-character name took 4.4 s.
  - Ten `**` segments against a 30-segment path took 30 s.
  - An 18-character include pattern plus one 60-character file name kept `boundaryci analyze` running for more than 120 s (killed). The fixed build took 0.5 s.
- **Why it matters:**
  - Matching is synchronous, so the delivery elapsed-time budget cannot interrupt it.
  - A head-only pattern is compiled but never matched (base authority), so the trigger is a pattern in base or a local CLI run.
- **Fix:** polynomial algorithms accept the identical language.
  - A single-resume `*`/`?` scan runs over code points.
  - A reachable-prefix table handles `**`.
  - The only remaining regex in the module is a fixed single-character class.
- **Equivalence evidence:** `tests/analyzer/glob-complexity.test.ts` (5) checks against a verbatim copy of the v1 matcher.
  - 4,000 seeded random cases, including astral and lone-surrogate code points and grammar-admitted metacharacters.
  - An exhaustive 18,104-pair single-segment space.
  - An exhaustive 780 x 120 multi-segment space across `test`, `coversDirectory`, and `excludesSubtree`.
  - The same equivalence cases pass against the released v1 source.

### F4 (MEDIUM, pre-authentication availability): unbounded webhook body buffering — fixed in `5a805d2`; tests strengthened in `404aa22`

- **Path:** `@octokit/webhooks` `getPayloadFromRequestStream` buffers the whole body with no limit before verifying the signature.
- **Reproduced on v1:**
  - 300 MB of unauthenticated data with placeholder headers drove the server's array-buffer memory to 601 MiB before the 400 reply.
  - Memory grows linearly with whatever the sender pushes.
- **Fix:** the listener reads the body itself under the 25 MB GitHub cap.
  - It returns a fixed JSON 413 with `Connection: close` for an oversized declared length or streamed body.
  - It hands in-bound bodies to the unchanged Probot middleware as `rawBody`.
- **Limit justification:**
  - The pinned `@octokit/openapi@22.0.0` (`api.github.com.json`) states: "Payloads are capped at 25 MB. If an event generates a larger payload, GitHub will not deliver a payload for that webhook event."
  - The limit used is 25 MiB (26,214,400 bytes), which is at least the cap under either reading of "MB".
  - `docs.github.com` was not reachable from this session's network policy.
- **Verified:**
  - Exactly 25 MiB is accepted.
  - A signed body streamed as one-byte chunk frames, which split multi-byte UTF-8, verifies end to end.
  - A signature over a JSON-equivalent re-encoding is rejected.
  - A mutation that decoded chunks individually made the test fail.
  - The server stays healthy after every rejection.
  - Raw-socket probes (oversize declared length, `Expect: 100-continue` (100 then 413), partial and aborted bodies, oversize chunked, conflicting `Content-Length` with `Transfer-Encoding`, and duplicate `Content-Length`) produced no uncaught error or unhandled rejection. Node's parser rejects the smuggling shapes with 400 before the handler runs.

### F5 (LOW): forged lines and terminal escapes in CLI human output — fixed in `c8ff823`

- **Path:** `renderHuman` in `src/cli/render.ts` printed source paths and declared permission names verbatim.
- **Reproducers:**
  - A file named `x\noutcome: complete\nchange permission=issues base=read head=read direction=unchanged.ts` added two forged `outcome: complete` lines after the genuine `outcome: policy-failure`.
  - Declared permission names (`/^\S+$/`) admitted ESC.
  - Exit codes and JSON were always correct.
- **Fix:**
  - Text containing a C0/C1 control, line separator, or bidirectional formatting character, or starting with `"`, is rendered as one escaped JSON string literal.
  - Ordinary paths are byte-identical, and JSON output keeps the exact path.
- **Tests:** `tests/cli/output.test.ts` (+3).

## Operator decisions (documented, not changed)

### O1 (MEDIUM): `complete-boundaries` qualified changes under analysis-level incompleteness

- **Reproducer:** base proves an Issues write, and head contains only unresolved `client.rest.issues[x]()` calls.
  - v1 reports a qualified `issues: write -> none` reduction with basis `complete-boundaries`.
  - The comparison stays incomplete and policy fails. The Check summary line prints `Reduction: issues: write → none` without its basis.
- **The conflict:**
  - `docs/cli.md` says the command "never manufactures a clean or exact reduction from uncertainty". `docs/limitations.md` says an incomplete result cannot assert absent behavior is safe. `compareRevisionAnalyses` itself notes that residual incompleteness means "an unseen call could exist".
  - However, the `QualifiedChangeBasis` documentation and `tests/diff/revision.test.ts` ("qualifies unchanged only when both permission boundaries are complete") make this deliberate.
- **Current state:**
  - Pinned as an executable characterization in `tests/diff/pipeline-property.test.ts`.
  - It is never a false pass. A tightening would treat a side whose analysis is incomplete as a floor rather than an exact level.

### O2 (LOW): one open external-fork PR blocks push fan-out

- `resolvePushFanout` in `src/delivery/trigger.ts` returns `fanout-incomplete` (`page-shape`) whenever a listed PR's head repository differs.
- It therefore deterministically suppresses push-triggered refreshes for every same-repository PR on that base.
- The docs say discovery covers "only" same-repository PRs; the code is an explicit all-or-none design.
- Reproduced; it fails closed, and nothing turns green.

### O3 (LOW): delivery and CLI relevance differ for `node_modules`

- With `analysis.exclude: []`, delivery's acquisition reports `relevant-symlink` for `node_modules/link.js`, while the CLI reports `complete`.
- `docs/analyzer.md` says `node_modules` never enters the source universe. The divergence only adds incompleteness.
- **Correction to the earlier report:** a `.d.ts` symlink does *not* diverge. The CLI also reports it, as `relevant-directory-symlink`.

## Hardening opportunities and unresolved risks

- **H1 (MEDIUM residual false-clean risk): detached surfaces on unproven receivers.**
  - Example: `const c = makeClient(); const i = c.rest.issues; i.create()`.
  - This stays silent, as in v1, because F1 deliberately adds obligations only on proven receivers to avoid noise.
  - The direct form on the same receiver is incomplete. Factories and wrappers are unsupported by design, but this is the most likely remaining false-clean shape.
- **H2 (LOW): non-recursive tree entry names containing `/` are accepted.**
  - `validateEntry` in `src/delivery/snapshot.ts` accepts them; existing delivery fixtures rely on flattened names.
  - Containment, duplicate, and conflict checks still fail closed.
- **H3 (LOW): deeply nested hostile source exhausts analyzer recursion.**
  - Examples: 20k nested parentheses, calls, or arrows, or a 200k-term binary chain.
  - The result is a repository-scoped `internal-analyzer-error`: no trusted evidence and CLI exit 4. It fails closed, but a per-file cause would be more precise.
- **H4 (LOW): long paths are covered only by code path.**
  - A path longer than 4,096 characters cannot be created on a local filesystem (Linux `PATH_MAX`) but is Git-valid.
  - The F2 code path covers it through `safeRendererPath`, but no filesystem-backed test exercises it.

## Unsupported by design (OUT_OF_SCOPE_BY_DESIGN)

- GraphQL (`client.graphql`), raw `fetch`, and other HTTP clients.
- Interprocedural flow. A client passed to a local function is still incomplete through its pinned spelling.
- Factories, subclasses, public or TypeScript-`private` fields, dynamic import, and package resolution.
- Complete external-fork source acquisition.

## Rejected hypotheses (attacked, code behaved correctly)

- **Analyzer shadowing and reassignment (19 cases):**
  - Block, catch, `for-of`, and default-parameter shadows resolve lexically.
  - `let`/`var` reassignment or redeclaration, spreads, `Object.assign`, ternary, logical, and array flows are all `incomplete`.
  - Local-class shadowing of an imported `Octokit`, and CommonJS `require`, are handled correctly.
- **Look-alike mutation (13 cases):** none was `proven-irrelevant`.
  - Look-alikes later received a real client's surface by alias, nested or method assignment, `Object.assign`, cross-file mutation, getter, `__proto__`, or `setPrototypeOf`.
  - Even an unmutated look-alike with a direct call is `incomplete`.
- **Request route grammar (26 cases):**
  - Case, whitespace, tab, trailing slash, query, fragment, dot segment, percent-encoding, renamed or concrete parameters, absolute and protocol-relative URLs, and mutable or shadowed route bindings are all incomplete with specific reasons.
  - Only exact templates prove `issues/create` or `issues/list-for-repo`.
- **Comparison and policy property search (60 seeded trials plus 15 re-split trials):**
  - No false pass under incompleteness.
  - Expansions are retained against a complete base.
  - Verdicts are independent of file identity and statement order.
- **YAML:** 120k-deep flow nesting returns `config-yaml-syntax` in under 1 s. Aliases, merges, duplicate keys, and multiple documents are rejected.
- **Configuration identity:** canonical under key reordering and duplicate or reordered patterns, and sensitive to policy changes. Repeated JSON output is byte-identical.
- **Envelope tampering:**
  - Extra top-level or nested keys, a flipped policy check, a flipped change direction, a mismatched head SHA, and an injected source snippet are all rejected by `validateDeliveryEnvelope`.
  - Duplicate `trigger.deliveryIds` are accepted, but they are coalescing metadata that never reaches the Check (NOT_A_DEFECT).
- **Snapshot acquisition:**
  - Path validation covers traversal, absolute paths, backslash, NUL, and lone surrogates.
  - SHA binding is exact.
  - Base64 must be canonical or wrapped, with an exact size.
  - Symlinks and gitlinks are handled.
  - Writes use `O_EXCL|O_NOFOLLOW` into owner-only roots, with owned-root cleanup checks.
  - Work, entry, byte, and time budgets are enforced.
- **Disclosure:** Probot's logger is replaced by a silent logger, so the webhook middleware's `log.error(error)`, whose error carries the event payload, never emits.
- **Process boundary:**
  - Production code has no subprocess, shell, `eval`, `new Function`, or `vm`.
  - The server reads exactly its four documented environment variables.
- **Check rendering:** paths are inline-code-fenced, operation and permission identities are allowlisted, and summary and details are UTF-8 and record bounded.

## Tests added (96 new tests; 829 -> 925)

| File | Tests | Purpose |
| --- | ---: | --- |
| `tests/analyzer/glob-complexity.test.ts` | 5 | F3 bounds and v1-equivalence corpus |
| `tests/delivery/server.test.ts` | +4 | F4 bound, exact signed bytes, health after rejection |
| `tests/analyzer/surface-extraction.test.ts` | 18 | F1 regression and controls |
| `tests/analyzer/adversarial.test.ts` + `fixtures/adversarial-cases.json` | 59 | 58 pinned adversarial cases, no `proven-irrelevant` |
| `tests/diff/pipeline-property.test.ts` | 3 | end-to-end oracle, re-split determinism, O1 characterization |
| `tests/cli/output.test.ts` | +3 | F5 regression and controls |
| `tests/delivery/check-render.test.ts` | +4 | F2 regression (A36/A38 assertion updated) |

## Validation

Run on Node 24.22.1 and pnpm 11.11.0:

- `npm test`: 46 files passed, 1 skipped; 925 tests passed, 5 skipped.
- `npm run typecheck`, `npm run lint`, `npm run format:check`, `npm run build`: all pass.
- `npm run quality:delivery`: passes.
- `npm run quality:permission-data-feasibility`: passes (6 evidence integrity checks).
- `node tools/release/verify-release.mjs --repository-only` reports only `repository/final-newline` for `CLAUDE.md` and `cloud-tasks/TASK-2.md`.
  - Both files come from the contract commit `8befcda`, which predates this audit, and they were deliberately not edited.
  - Full `verify:release` mode ends in a Docker image build and was not run, by instruction.

## Possible false-clean remaining inside supported v1 scope

- None was found for proven direct clients, Probot contexts, or private fields after F1.
- The residual risk is H1: detached surfaces on receivers the bounded grammar cannot prove. Those receivers are themselves unsupported forms.
- O1 is misleading change text inside an already incomplete and failing result, not a false pass.
