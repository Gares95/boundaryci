# GitHub App delivery

BoundaryCI's optional delivery layer acquires exact same-repository pull-request snapshots, invokes the same deterministic analyzer used by the CLI, and publishes a finite completed GitHub Check. Analysis remains independently usable without Probot or a running service.

## App registration and events

Create a GitHub App for the BoundaryCI service and install it only on the intended repositories. The registration needs these repository permissions:

- Contents: read
- Pull requests: read
- Checks: write
- Metadata: read when GitHub includes it as an unavoidable platform permission

Subscribe only to `pull_request` and `push`. BoundaryCI handles pull-request `opened`, `synchronize`, `reopened`, and comparison-relevant `edited` actions. A push triggers bounded discovery only for open same-repository pull requests using the pushed branch as base.

Configure the webhook URL as the temporary or deployed HTTPS origin plus `/api/github/webhooks`. GitHub must deliver `application/json`. Probot verifies the signature against the original bytes before normalization. Payload identities trigger fresh authenticated reads; they are not used as comparison authority.

BoundaryCI does not accept a personal access token, OAuth token, workflow token, operator bearer token, or alternate webhook-verification route.

## Scoped roles

For each accepted event, the App-authenticated Probot context is used only to issue two separate repository-scoped installation roles:

1. The read role requests Contents read and Pull requests read for the exact repository. After validating the effective scope, it exposes only current-pull lookup, bounded open-pull listing, commit read, non-recursive tree read, and blob read.
2. The publication role requests Checks write for the exact repository. After validating the effective scope, it exposes only exact-head Check listing, completed Check create, and annotation-free completed Check update.

Platform-implied Metadata read may appear in either effective token response. Any other repository, permission, response shape, or inability to issue a narrowed token fails closed. Credentials and token-authenticated clients remain private to the authentication adapter and are not exported by the delivery package.

The acquisition role validates paths, identities, object shapes, pages, bytes, work, retries, and elapsed time. It never uses archives, clone, checkout, merge refs, the Contents API, GraphQL, or target execution. Temporary source roots are removed and their absence is verified before any Check handoff.

## Check identity and outcomes

The fixed Check name is `BoundaryCI`. Logical identity binds installation, repository, pull request, base repository/ref/SHA, head repository/SHA, topology, evaluator, engine, catalog digest, and effective base configuration into a deterministic correlation ID. Exact lookup also filters by BoundaryCI's App ID, head SHA, name, and correlation ID.

Finite outcomes map to these completed conclusions and titles:

| Evaluation | Conclusion | Title |
| --- | --- | --- |
| Complete and unchanged | `success` | `Permission boundary unchanged` |
| Complete reductions only | `success` | `Permission boundary reduced` |
| Policy-permitted expansion | `success` | `Permission expansion permitted` |
| Policy-rejected expansion | `failure` | `Permission expansion requires review` |
| Incomplete, allowed by policy | `neutral` | `Analysis incomplete` |
| Incomplete, rejected by policy | `failure` | `Repository policy failed` |
| Current input or runtime diagnostic | `action_required` | `BoundaryCI could not evaluate this change` |

The summary preserves aggregate expansions, reductions, unresolved operations, complex-expression changes, declared-boundary differences, and annotation counts. Details are deterministically bounded by records and UTF-8 bytes. Unknown outcomes and unknown reason codes fail closed.

Truthful changed-head evidence can become an annotation: expansion failures use `failure`, permitted expansions use `notice`, and actionable incompleteness uses `warning` or `failure` according to policy. Base-only, non-locatable, invalid-span, unchanged-file, and external-fork diagnostics remain in summary or details and never receive a fabricated location.

## Production server

Build the service with `npm run build` and start it with `npm start`, or run the production image. Runtime configuration has exactly four required settings:

- `APP_ID`: positive integer GitHub App ID
- `PRIVATE_KEY_PATH`: path to a nonempty readable regular private-key file
- `WEBHOOK_SECRET`: nonempty webhook secret
- `PORT`: integer from 1 through 65535

Invalid configuration emits only a stable field code. Values are never echoed. The key is read only at process startup and is not copied into the container image.

The HTTP surface is fixed:

- `GET /healthz` returns exactly `{"status":"ok"}` as JSON with no source or diagnostic fields.
- `POST /api/github/webhooks` invokes Probot's original-byte middleware.
- A webhook body larger than GitHub's 25 MB payload cap receives a fixed JSON 413 and a closed connection; it is never buffered beyond the cap and never reaches signature verification or delivery logic.
- Every other method and path returns the same fixed JSON 404.

SIGINT and SIGTERM stop acceptance, wait no more than ten seconds, destroy remaining tracked sockets at the deadline, remove signal listeners, and resolve idempotently.

## Freshness and finite publication

The delivery coordinator binds acquisition to an exact current pull-request comparison, cleans temporary roots, and performs a final authenticated read. Phase 6 performs another immediate exact-identity read before Check lookup or mutation. Drift, ambiguity, untrusted freshness, cancellation, supersession, or cleanup failure suppresses publication.

Exact lookup is bounded to ten pages and 1,000 records. Zero exact matches creates one completed Check. One match updates that Check. Multiple matches stop as a publication conflict. One bounded lookup can reconcile an ambiguous write, and freshness is checked again before any later mutation.

The initial create carries at most the deterministic first 50 eligible annotations inside the create output. Every update and update retry omits the annotation field. BoundaryCI does not list existing annotations, append batches, recover a prefix, replay annotations, replace a Check, or use an external report store.

Coordination is in-memory. Duplicate current work coalesces and newer authenticated work supersedes older work, but a process restart does not restore a queue, journal, snapshot, or exactly-once record. A later valid event reconstructs current work.

External-fork source acquisition is unsupported. A positively authenticated fork emits a source-free diagnostic, and publication remains conditional on exact head-repository addressability; inaccessible forks produce no mutation and never success.

See the [demonstration](demo.md), [architecture](architecture.md), [security policy](../SECURITY.md), and [limitations](limitations.md).
