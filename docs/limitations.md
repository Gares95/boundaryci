# Limitations

BoundaryCI deliberately favors explicit incomplete results over false confidence. The limits below are v1 trust boundaries, not a backlog hidden behind optimistic output.

## Supported v1 surface

The analyzer covers configured `.js`, `.jsx`, `.mjs`, `.ts`, `.tsx`, and `.mts` source. It recognizes explicitly supported Octokit and Probot REST patterns whose client provenance and operation identity can be established statically. Requests are normalized through pinned generated endpoint metadata and a reviewed finite permission catalog.

Local comparison uses immutable source snapshots supplied by the caller. GitHub delivery supports exact same-repository pull-request base and head SHAs acquired through bounded commit, tree, and blob reads. The Check presentation is finite and source-free.

## Incomplete analysis

BoundaryCI cannot prove a complete observed boundary when relevant behavior falls outside its supported grammar or trustworthy bounds. Examples include dynamic request routes, unsupported aliases or wrappers, catalog gaps or conflicts, unsupported permission expressions, relevant unsupported Git objects, malformed source that prevents analysis, and safe file, byte, work, or time limits.

An incomplete result retains established operations and known positive permission evidence. It cannot assert that absent behavior is safe, simplify a complex expression, or report an unqualified clean boundary. Repository policy independently decides whether incompleteness fails the check.

Static observations do not prove which branches execute at runtime. They also cannot find arbitrary behavior constructed through reflection, generated code, unsupported wrappers, or unrelated HTTP clients.

## External forks

Complete external-fork source acquisition is not supported in v1. A positively authenticated external-fork pull request receives an explicit unsupported-topology diagnostic without source acquisition.

Live feasibility is conditional on whether the base installation's narrow publication role can address the pull request's head identity. If addressable, BoundaryCI may publish an `action_required` diagnostic Check. If unaddressable, it publishes nothing. Neither branch can be green, and one observed topology is not generalized to every fork or installation arrangement.

## Explicit exclusions

BoundaryCI v1 does not provide:

- GitHub GraphQL inference;
- analysis of languages other than the documented JavaScript and TypeScript extensions;
- arbitrary custom HTTP-client or interprocedural wrapper inference;
- dependency installation, type resolution through a target project, dynamic imports, builds, tests, runtime tracing, or target-code execution;
- live downloads of permission data during analysis;
- discovery or certification of an unrelated target App's live permissions;
- automatic modification of a target App's permissions;
- archive, clone, checkout, codeload, Contents API, merge-ref, or GraphQL acquisition fallbacks;
- durable global exactly-once delivery, a persistent queue, or process-restart recovery;
- annotation listing, append, replay, repair, or recovery after the initial create;
- guaranteed complete external-fork analysis;
- permanent hosting, deployment automation, package publication, container publication, or a dashboard.

See [permission model](permission-model.md) for uncertainty semantics and [GitHub delivery](github-delivery.md) for operational limits.
