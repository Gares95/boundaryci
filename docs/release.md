# Release runbook

This runbook is the only v1 publication path. It binds every automated, production, live, review, and publication observation to one clean 40-hex commit SHA. Any source, documentation, workflow, image, or release-tool change invalidates prior gates and requires a new clean candidate and fresh proof.

The fixed public destination is `Gares95/boundaryci`, its branch is `main`, and its annotated release tag is `v1.0.0`. Publication is a one-way operator-authorized action. Earlier proof never implies authorization.

## Preconditions

Prepare a Docker-enabled host, the same-repository Issues demonstration pull request, a separate external-fork feasibility pull request, a disposable test GitHub App installation, a temporary HTTPS callback, and read-only access to the actual CI result. Keep runtime credentials in provider facilities or process environment only. Never place them in repository files, container build arguments, compose files, captured commands, logs, or retained evidence.

Require a clean tracked and untracked tree. Record the exact candidate SHA once. Every proof record must use that SHA and a closed schema. Retain no environment dump, source text, patch, raw webhook, API request or response, external error body, authorization data, signature, key, installation credential, or callback credential.

## Canonical and Docker proof

Run `npm run verify:release` without App credentials on the Docker host. This is the sole release-acceptance command. It runs the complete tests, typecheck, lint, format check, build, public documentation/license/link/file-set inspection, tracked secret/placeholder/provenance inspection, and credential-free image build and inspection.

Repository-only mode can provide earlier feedback but cannot pass this checkpoint. Docker absence, a skipped image inspection, or component tests are blocking failures.

Separately run the built production image with runtime-only test credentials. Prove its non-root user, exact `node dist/delivery/server.js` command, exact health response, valid signed delivery through the real Probot composition, invalid-signature rejection, single startup/shutdown behavior, bounded SIGTERM completion, and absence of surviving container, image, or callback residue. Validate the sanitized Docker proof at the candidate SHA.

Confirm an actual successful run of the sole CI workflow at the same exact SHA and that it invoked `npm run verify:release`. A queued, skipped, neutral, cancelled, differently addressed, or component-only run does not pass.

## Live GitHub proof

Follow the [demonstration](demo.md) against the real same-repository pull request through the production container. Prove the base Issues read boundary and head Issues write expansion, completed failing `BoundaryCI` Check, exact title, `issues/create`, and a truthful changed-head annotation at the candidate SHA.

Prove fresh creation, redelivery convergence, one permitted annotation-free completed-state reconciliation, no-expansion behavior, duplicate-match refusal, and zero stale-head mutations. Mocks and composed tests remain prerequisites but cannot replace this live evidence.

Run the separate bounded external-fork feasibility observation. Retain either an addressable `action_required` diagnostic or an unaddressable zero-mutation result. Neither may be success, and the observation must not be generalized to other installation topologies.

Stop the temporary callback and production container and remove the disposable proof residue. Validate both live proof records with the release verifier.

## Verification and review

Run phase verification only after canonical, Docker, actual-CI, same-repository, and external-fork proofs pass at the same SHA. The verification record must show every Phase 6 requirement and highest required proof layer satisfied.

Then perform one fresh independent integrated implementation-conformance and security review. It reviews the actual candidate diff, authoritative Phase 6 contracts, threat models, prohibitions, code, tests, documentation, and sanitized proof. Any critical or high security finding blocks. At most one bounded semantic correction may address concrete findings; a correction creates a new candidate SHA and invalidates every SHA-bound proof that it affects.

After that correction, perform one disposition-only closure review of the original findings. It does not reopen a broad review. A new blocker after this closure requires operator direction. Validate both structured review records, require no remaining blocker or high finding, and confirm clean HEAD still equals every accepted proof SHA.

## Destination preflight

Preflight is read-only and immediately precedes the publication decision. Confirm:

- clean HEAD equals the candidate SHA in canonical, Docker, CI, live, verification, and review records;
- the authenticated non-secret account identity is `Gares95`;
- the exact destination is `Gares95/boundaryci`;
- destination state is absent, exact public and empty, exact complete, known exact partial, or conflict;
- remote `main` and `v1.0.0` identities, if present, resolve exactly as recorded;
- a local `v1.0.0`, if present, is annotated and resolves to the candidate SHA.

Initial publication is eligible only when the destination is absent or exact public and empty with zero refs. Exact complete state is an idempotent read-only result. A private repository, wrong identity, unexpected ref or content, different SHA, lightweight or conflicting tag, dirty tree, missing proof, or open high finding is a conflict and blocks. A known exact partial state requires a separate explicit recovery decision.

Record only identity, visibility/existence classification, exact ref object IDs, gate states, candidate SHA, stable outcomes, and timestamp. Validate the destination proof and rerun repository hygiene before presenting it to the operator.

## Operator authorization

Stop here and show the sanitized, current preflight. Approval must explicitly bind all of these values in one response:

- decision `approve-exact-release`;
- exact 40-hex candidate SHA;
- repository `Gares95/boundaryci`;
- branch `main`;
- annotated tag `v1.0.0`;
- accountable operator identity;
- current ISO-8601 decision time.

An abort, omission, mismatch, expired preflight, ambiguity, or conflict authorizes no mutation. Approval applies only to the exact state displayed and either the eligible initial release or the specifically identified non-destructive completion of a known exact partial state.

## Non-destructive publication

Perform no unrelated work after approval. Immediately before each individual mutation, re-read clean HEAD, the complete proof chain, authenticated identity, exact repository identity and public visibility, and the relevant remote ref.

If the approved destination was absent and remains absent, create exactly the public user repository `Gares95/boundaryci` with no initialized README, license, or ignore file, then verify its identity, visibility, and zero refs. Do not repurpose or rewrite an unexpected local remote; use only a separately named exact release remote or the exact destination URL.

Publish only the approved commit to `refs/heads/main` using an ordinary non-force single-ref push after proving the remote ref is absent. If it already equals the approved SHA, record an idempotent skip. Any other value stops.

Require local `v1.0.0` to be absent or an annotated tag resolving to the approved SHA. If absent, create that exact annotated tag with message `BoundaryCI v1.0.0`. Re-read the remote tag immediately before its ordinary non-force single-ref push. An existing exact annotated tag object and target is an idempotent skip; any other state stops.

Do not publish an npm package, container image, GitHub Release, deployment, asset, other branch, other tag, or other infrastructure. Never force-push, mirror, delete a ref or repository, change visibility, overwrite a conflicting ref, or silently retry an ambiguous operation.

## Post-publication verification

After a complete publication record, use independent read-only observations to verify:

- exact owner and repository name, public visibility, and default branch `main`;
- remote `main` equals the approved SHA;
- remote `v1.0.0` is an annotated tag object dereferencing to that same SHA;
- the public file-set digest and count match the canonical local tracked set;
- README, unmodified Apache-2.0 license, security, contributing, architecture, permission model, limitations, GitHub App, demo, release, and sole read-only CI documents are present and link-valid;
- environment files, key and certificate material, credentials, local workflow state, private proof or review records, resolvable markers, and development-process attribution are absent from both public refs.

Validate the sanitized post-publication record. Only this successful read-only postflight closes the public release requirements.

## Partial publication

If repository creation, main publication, local tag creation, or tag publication succeeds and a later action fails, record the exact successful and unattempted operations as partial and stop. Do not roll back public state, remove a ref, overwrite a destination, or automatically continue.

A new read-only preflight and a new explicit operator decision are required before any non-destructive completion attempt. Postflight never repairs public state; a failed observation leaves release completion blocked for operator review.
