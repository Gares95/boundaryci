# Permission model

BoundaryCI describes the GitHub App permission boundary observed in supported source code. It preserves evidence and uncertainty instead of claiming that static analysis has discovered every runtime behavior or an App's live configuration.

## Observed source evidence

For every supported GitHub REST call, an evidence record retains the HTTP method, normalized route, canonical operation identifier, repository-relative source path, and source span. Octokit method calls are normalized through pinned generated endpoint data, not name heuristics. Literal request routes and statically provable immutable route constants are supported; a dynamic route becomes an unresolved operation rather than a guess.

Evidence is an observation about analyzed source. It does not prove that a call executes at runtime, enumerate calls hidden behind unsupported behavior, or describe live installation settings.

## Repository-declared configuration and policy

`.boundaryci.yml` selects bounded source files, controls `failOnExpansion` and `failOnIncomplete`, and can declare expected repository permissions. Declared permissions are labeled as repository-declared configuration and policy. They are not presented as retrieved GitHub App settings.

For pull requests, the base revision's valid configuration is authoritative for both base and head analysis. A changed or newly added head configuration is reported as prospective evidence and becomes authoritative only after it is part of a future base. If an authoritative configuration is invalid or cannot be acquired safely, evaluation stops with an explicit input or acquisition outcome.

## Permission expressions

A catalog result is either resolved, unsupported, missing, or invalid/conflicting. A resolved requirement preserves one of these recursive forms:

- `permission`: one named GitHub App permission with `read` or `write` access;
- `allOf`: every child expression is required;
- `anyOf`: at least one child expression is sufficient, but BoundaryCI does not select an alternative;
- `unresolved`: available evidence cannot establish a supported requirement.

Only atoms for the same named permission use the order `none < read < write`. BoundaryCI never flattens `allOf` or `anyOf` into a one-route/one-permission map and never silently turns an alternative into a definite requirement.

## Aggregation and comparison

Aggregation groups identical simple permission atoms and retains every contributing operation and source location. Complex expressions remain structurally intact. Base-versus-head comparison reports proven expansions, reductions, removals, additions, and unchanged requirements.

Complex expressions are compared semantically only when their relationship is provable. Otherwise the expression and its evidence remain visible and the comparison is incomplete. Unresolved operations, relevant unsupported constructs, catalog gaps, conflicting entries, and safe resource-limit truncation likewise preserve known positive evidence while preventing an unqualified clean conclusion.

## Catalog assumptions

The production catalog is a reviewed, finite artifact with a normalized identity derived from its schema, upstream source versions, operation mapping, provenance URLs, and integrity hashes. Analysis never downloads live API data. Both sides of a comparison must use the same catalog identity.

A resolved row is evidence for the documented permission expression under that exact catalog revision. Missing, conflicting, or unsupported data remains a classified unresolved result. Catalog coverage is not a claim that all GitHub REST operations or future upstream changes are supported.

## Live App permissions

Independently verified live App permissions are a separate operational fact. An operator can inspect the intended GitHub App registration and installation during the live demonstration, but BoundaryCI does not retrieve the permissions of an unrelated target App and does not use `GET /app` to pretend otherwise.

The read and Check publication roles request and validate their own narrow installation-token scopes. That proves the permissions BoundaryCI uses for delivery; it does not turn observed source evidence or repository declarations into knowledge of another App's current settings.

See [configuration](configuration.md), [architecture](architecture.md), and [known limitations](limitations.md).
