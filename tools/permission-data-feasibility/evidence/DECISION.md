# Permission-data feasibility decision

## Outcome

BoundaryCI may proceed with **GO WITH BOUNDED SUPPORT**.

The authorized permission catalog is exactly the two reviewer-backed Issues operations listed below. The authorization is bound to scope digest `40c14243b7d1940d395ae9731ecd3fda962807aee297c9b72aeb591a3dd2b418`; applying the same predicate to future evidence does not authorize additional operations.

| Octokit method | REST operation | Required permission |
| --- | --- | --- |
| `issues.listForRepo` | `GET /repos/{owner}/{repo}/issues` | Issues: read |
| `issues.create` | `POST /repos/{owner}/{repo}/issues` | Issues: write |

This bounded set is useful because it proves the flagship Issues read-to-write boundary expansion without guessing. It does not establish a complete GitHub REST permission catalog and does not prove perfect least privilege.

## Evidence identity

- GitHub REST API evidence version: `2022-11-28`
- Artifact manifest: `ffe2270a26567042f146e0ec982a7343de51a1f6333f2de6fa0421aca1e4c94c`
- Feasibility packet: `6202c30b316f29885a6012b2e7703b0a1de018c5d2716c3cc7aa5a7d797fc0f8`
- Support manifest: `fe2b5abdd118769a2f8764a0bb0177a7bd68d7cc4fa7229e5c9c4ef1024da28d`
- Support predicate: `6105e89cf161785569a465a573c25853a8354aaddaa6560d1bd38199a090c4fa`
- Selected member set: `c23e9c3017dd2d8d4ebe8d6f3e59c72895d8dd1e3d026286b7f5d82317fdde4d`
- Decision record: `cd30436d22364842aaf2470ccfaf55ae1127e2b4a683be19a38ca3ec8aab0261`

The permission documentation evidence is live and unversioned. Its reviewed retrieval identity and dates are retained in `permission-sources.json`. Package versions, package and data-file hashes, lockfile identity, runtime endpoint-method selection, and REST API version are retained in `artifact-manifest.json`.

## Catalog strategy

The v1 catalog must use generated REST candidates plus a reviewed bounded permission catalog. A candidate is eligible only when all of these conditions are proven:

1. It is an App-enabled OpenAPI operation.
2. The method, route, and operation join is unique.
3. The direct method alias is identical in the reviewed runtime and standalone endpoint-method surfaces.
4. Its requirement expression has reviewer-backed GitHub App applicability.
5. Its permission name and access level are in the supported vocabulary.
6. Its artifact, source, API-version, and integrity provenance is complete.
7. It has no ambiguous, conflicting, stale, unsupported, or credential-unproven qualifier.

The current operation universe contains 878 App-enabled OpenAPI operations. Two satisfy the complete bounded predicate and 876 remain incomplete. The endpoint-method universe contains 1,053 method records: 1,010 have a resolved join and 43 remain incomplete.

Permission requirements retain their symbolic structure. BoundaryCI must never choose a branch of `anyOf`, convert an alternative into `allOf`, or flatten a complex expression to obtain a simple boundary. Complex expressions without adequate GitHub App evidence remain incomplete.

## Explicitly incomplete classes

The bounded authorization excludes these evidence and operation classes:

- Permission expressions: `allOf`, `anyOf`.
- Permission evidence: ambiguous, conflicting, missing, unsupported.
- Freshness: stale seed, not assessed.
- Credential applicability: fine-grained personal access token only, none.
- Endpoint-method surface: version 17 only, version 18 only, surface conflict.
- Operation joins: no OpenAPI operation, duplicate OpenAPI operation.

The stable incomplete-analysis reasons are:

- `ambiguous-permission-data`
- `conflicting-permission-data`
- `credential-semantics-unproven`
- `duplicate-endpoint-method`
- `duplicate-openapi-operation`
- `duplicate-permission-data`
- `invalid-endpoint-route`
- `malformed-permission-evidence`
- `missing-credential-identity`
- `missing-operation-identity`
- `missing-permission-data`
- `missing-runtime-method`
- `missing-standalone-method`
- `no-openapi-operation`
- `runtime-method-surface-mismatch`
- `source-integrity-mismatch`
- `stale-permission-source`
- `unreviewed-permission-source`
- `unsupported-access-level`
- `unsupported-permission-expression`
- `unsupported-permission-name`
- `unsupported-permission-qualifier`

An incomplete item may retain known evidence, but it cannot support an unqualified clean, no-change, expansion, or reduction conclusion.

## Known limitations

- The authorized set contains only the two canonical Issues operations.
- The retained evidence contains no reviewed GitHub App-applicable `allOf` expression.
- Fine-grained personal access token `anyOf` observations do not prove installation-token semantics.
- The permission-package inverse index is incomplete, does not encode logical operators, and is stale for some entries.
- The reviewed GitHub permission documentation is live and unversioned.

These limitations are constraints on the v1 production catalog. Operations outside the authorized member set must produce an explicit incomplete outcome until new evidence and a separately reviewed catalog update authorize them.

## Reproduction

With the exact dependencies from `pnpm-lock.yaml` already installed with lifecycle scripts disabled, rebuild the portable evidence using Node 24:

```sh
boundaryci_evidence_dir="$(mktemp -d /tmp/boundaryci-evidence-XXXXXX)"
node node_modules/typescript/bin/tsc --noEmit false --rootDir . --outDir "$boundaryci_evidence_dir" -p tsconfig.json
node "$boundaryci_evidence_dir/tools/permission-data-feasibility/scripts/write-artifact-manifest.js"
node "$boundaryci_evidence_dir/tools/permission-data-feasibility/scripts/build-evidence.js"
```

Then verify the complete retained evidence and decision:

```sh
node node_modules/vitest/vitest.mjs run --config vitest.config.ts --reporter=dot
node node_modules/typescript/bin/tsc --noEmit -p tsconfig.json
node tools/permission-data-feasibility/scripts/quality-checks.mjs
```

The rebuild is expected to preserve the semantic catalog only when the source identities and public project metadata are unchanged. Any digest change requires inspection; it must not be treated as automatic authorization for a new operation.
