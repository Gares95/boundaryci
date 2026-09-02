# GitHub App delivery boundary

BoundaryCI can receive selected GitHub App events and evaluate the current base-versus-head
permission boundary for an open pull request in the same repository. This delivery layer is a
bounded source-acquisition and lifecycle service around the local analyzer. It does not publish a
GitHub Check or render a pull-request result; those actions require the separate Phase 6
publication boundary and its own final freshness validation.

## App registration and events

Use a GitHub App installation credential for the repository being evaluated. Phase 5 requests
only these read capabilities:

- Contents: read, for immutable Git commit, tree, and blob reads.
- Pull requests: read, for current pull-request identity and base-branch fan-out.
- Metadata: read only when the platform makes it unavoidable as part of the minimum registration
  or issuance surface.

The acquisition role and a future publication role are separate. This layer does not accept a
personal access token, OAuth token, workflow token, operator bearer token, or an environment
fallback. Installation credentials, authenticated clients, authorization headers, webhook
secrets, App private keys, and App JWTs stay inside their transport or adapter owner and are not
passed to the analyzer, evaluator, snapshot writer, envelope, or diagnostic contracts.

The verified Probot receiver subscribes only to:

- `pull_request.opened`
- `pull_request.synchronize`
- `pull_request.reopened`
- `pull_request.edited`, when the freshly authenticated state establishes a comparison-relevant
  base-target change
- `push`, for bounded discovery of open same-repository pull requests that use that branch as a
  base

Webhook payloads are authenticated triggers, not comparison authority. Before work begins, the
adapter reads the current pull request and binds the installation, numeric repository and pull
request identities, base target, base SHA, head repository, head SHA, topology, and eligibility.
Draft pull requests are eligible. Closed, merged, deleted, or obsolete pull requests are no-op
lifecycle outcomes. Positively identified external forks produce a current diagnostic-only
unsupported-topology outcome without source acquisition. Ambiguous repository or topology
identity fails closed.

## Immutable acquisition and configuration

BoundaryCI reads only exact Git objects:

1. Resolve each authenticated base and head commit SHA.
2. Census the corresponding non-recursive Git trees under finite limits.
3. Fetch selected regular blobs by their exact immutable object SHA.

It does not use the Contents API, archives, codeload, clone, checkout, merge refs, GraphQL, or
target-code execution. Every selected path, tree relationship, blob identity, decoded byte count,
and materialized destination is validated before use. Symlinks and gitlinks are never followed.
An unsupported object relevant to source or configuration scope is incomplete; an unsafe path or
object relationship is an acquisition-security failure regardless of exclusion scope.

Configuration bootstrap occurs before general source acquisition. For each revision, the exact
`.boundaryci.yml` entry must be proved absent or must be a validated regular blob. The built-in
default applies only after absence is proved. A configuration symlink, unsupported object,
ambiguity, unreadable object, or census uncertainty stops semantic evaluation as an input or
acquisition failure. Once bootstrap succeeds, the base configuration is authoritative for both
source selections; a head configuration remains prospective evidence under the local comparison
contract.

The version-one transport ceilings are:

| Boundary | Limit |
| --- | ---: |
| Tree entries | 50,000 |
| Tree requests | 2,000 |
| Blob requests | 5,002 |
| Source files | 5,000 |
| Bytes per source file | 2,000,000 |
| Aggregate source bytes | 64,000,000 |
| Acquisition work units | 70,000 |
| Acquisition elapsed time | 60,000 ms |
| Fan-out pages and requests | 10 each |
| Fan-out pull requests | 500 |
| Fan-out normalized response bytes | 4,000,000 |
| Fan-out elapsed time | 10,000 ms |
| Idempotent read attempts | 3 |
| Read retry elapsed time | 60,000 ms |

After configuration bootstrap, a safe source-census bound may retain only fully validated blobs
and mark acquisition incomplete. Such a result preserves known positive findings, but cannot
assert a clean boundary, absence, reduction, or removal. It is never treated as a complete
snapshot.

## Lifecycle, freshness, and retention

Base and head bytes are materialized into separate owner-only private temporary roots. Only
validated regular source/configuration bytes enter those roots. Target bytes never determine an
executable path, command, environment variable, credential location, or module load. Roots are
not a cache, journal, or restart mechanism.

The lifecycle constructs source-free structured evidence, removes both roots, verifies absence,
then re-reads the authenticated pull-request identity before any Phase 6 handoff. A stale,
superseded, cancelled, obsolete, unauthenticated, ambiguous, or cleanup-failed result has no
publication handoff. A cleanup error remains an operational security/runtime condition even when
the bounded emergency cleanup retry subsequently proves root absence.

In-process coordination keys work by installation, repository, pull request, exact base SHA,
exact head SHA, and evaluator identity. Duplicate current work coalesces; a newer authenticated
comparison supersedes older work for the same pull request. This is in-memory only: a process
restart does not resume snapshots, envelopes, queue state, or delivery history. A later valid
event can safely reconstruct current work.

Phase 6 must perform one additional authenticated identity lookup immediately before creating,
updating, or finalizing any GitHub Check. A mismatch suppresses publication and returns the newer
identity to normal latest-work scheduling. Phase 5 does not choose Check conclusions, summaries,
annotations, batches, or presentation wording.

## Diagnostics and operational data

Operational logging is an exact allowlist: stable work and delivery IDs, normalized numeric
identities, exact commit SHAs, finite stage/outcome/reason codes, bounded counts, durations, and
retry fields. Raw payloads, source/configuration bytes, credentials, headers, signatures, keys,
JWTs, authorization values, request/response objects, external error bodies, and generic metadata
are rejected before a log sink is called. Sink failure cannot alter evaluation, cleanup, retry,
freshness, or handoff behavior.

The delivery envelope is JSON-safe and source-free. It separates acquisition incompleteness from
analyzer or permission incompleteness while preserving the local comparison evidence that was
actually established. No source snapshots or envelopes are persisted by default.

## Deployment and UAT checklist

For a live deployment review, record only non-secret facts:

1. Confirm the GitHub App is installed for the intended repository and has Contents read and Pull
   requests read, plus Metadata read only if platform-implied.
2. Confirm the selected webhook events match the list above and the receiver verifies original
   webhook bytes before trigger normalization.
3. Observe one short-lived repository-scoped installation credential issuance and record only the
   numeric installation/repository identities and the requested permission names.
4. Confirm the receiver handles an open same-repository pull request and that no target source,
   credential, header, token, key, signature, or raw response is retained in operational output.
5. Before enabling Phase 6 publication, confirm its separate credential role and second freshness
   lookup are implemented and reviewed.

Never record credential values, token fragments, authorization headers, private keys, webhook
secrets, signatures, raw payloads, raw API responses, or source content in this checklist.

## Explicit exclusions

Phase 5 excludes external-fork acquisition, alternate acquisition mechanisms, GraphQL, generic
Octokit requests, arbitrary GitHub APIs, target dependency installation, imports, builds, tests,
or execution, durable queues/databases/journals/caches, target-App live permission discovery, and
all Check publication or presentation. These exclusions are capability boundaries, not inferred
absence claims about a target repository.
