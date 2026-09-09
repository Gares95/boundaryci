# Architecture

BoundaryCI separates deterministic analysis from delivery. The analyzer can run offline against bounded source files, while the GitHub App layer is an optional adapter that acquires immutable inputs and publishes a finite Check result.

## Deterministic layers

The v1 flow has explicit one-way layers:

1. The permission catalog maps a normalized REST operation to a reviewed permission expression or an explicit unresolved state.
2. The analyzer parses bounded JavaScript and TypeScript bytes with the TypeScript compiler API, proves supported Octokit provenance, and emits source-free normalized evidence.
3. The permission model aggregates evidence without losing `allOf` or `anyOf` structure.
4. The revision comparator evaluates base and head results under the same identity and reports expansions, reductions, unchanged requirements, and uncertainty.
5. Repository policy converts that comparison into a finite evaluation outcome.
6. The CLI renders local human or JSON output. Separately, delivery can render and publish one completed GitHub Check.

Production inference, comparison, and policy contain no LLM dependency. They do not depend on network state, generated prose, or a remote classification service.

## Comparison identity

A valid diff uses the same BoundaryCI engine, normalized permission-catalog version and integrity digest, and base-authoritative configuration for both revisions. A head configuration change is validated and reported as prospective evidence but cannot weaken the policy evaluating its own pull request.

GitHub delivery binds work to the installation, numeric repository and pull-request identity, exact base SHA, exact head repository and SHA, base ref, and evaluator identity. A deterministic correlation ID additionally binds the engine, catalog identity, and effective configuration. Mutable branch names and merge refs are not analyzed as substitutes for those immutable inputs.

## Target isolation

BoundaryCI treats target repositories as hostile input. It never installs their dependencies, resolves their modules, imports their code, transpiles it for execution, runs scripts, builds it, or executes tests. Local analysis discovers configured regular files under explicit size and count limits.

GitHub delivery reads only validated commit, non-recursive tree, and blob objects for exact SHAs. It rejects unsafe paths and malformed object relationships, never follows symlinks or gitlinks, and materializes base and head into separate owner-only temporary roots. Both roots must be absent before any publication handoff. No source bytes enter a delivery envelope, Check renderer, log event, or retained proof.

## GitHub delivery and scoped roles

The production listener exposes only `GET /healthz` and Probot's original-byte verified `POST /api/github/webhooks`. Verified event data triggers authenticated current-state reads; webhook fields are not comparison authority.

Each comparison uses two separately issued repository-scoped installation-token roles:

- a read role requesting only Contents read and Pull requests read, plus platform-implied Metadata read when present, projected to five fixed acquisition methods;
- a publication role requesting only Checks write, plus platform-implied Metadata read when present, projected to exact Check lookup, create, and update methods.

Token-bearing clients remain inside the private authentication module. The analyzer, renderer, coordinator contracts, public package surface, and logs never receive a token or generic authenticated client.

## Check lifecycle

Every accepted result is rendered directly to one completed `BoundaryCI` Check tied to the exact head SHA. The conclusion and title come from a closed outcome table. Summary counts cover the complete normalized result; bounded details stop only between whole records.

The first create may include the deterministic first 50 truthful changed-head annotations. Every existing-Check update, ambiguous-write reconciliation, and update retry omits annotations. BoundaryCI does not list, append, resume, repair, or replay prior annotation state.

Immediately before publication, the coordinator re-reads the current pull request and requires exact comparison equality. Exact lookup finds zero, one, or multiple matching Checks: zero creates, one updates, and multiple stop as a conflict. One bounded reconciliation follows an ambiguous write; there is no durable exactly-once claim.

## Security invariants

- Static analysis and policy are reproducible and independent of delivery credentials.
- Unknown, dynamic, unsupported, conflicting, or over-limit conditions remain explicit; they never become a guessed clean result.
- `anyOf` branches are never flattened or arbitrarily selected.
- Target paths and bytes cannot control execution, module loading, environment variables, credential paths, or subprocess commands.
- Webhook signatures are verified against original request bytes before business logic.
- Logs and retained evidence use closed source-free schemas; keys, tokens, signatures, headers, raw errors, payloads, and source content are forbidden.
- The production container runs as the built-in non-root `node` user from an immutable base-image digest.

See [GitHub delivery](github-delivery.md), [permission model](permission-model.md), and [limitations](limitations.md).
