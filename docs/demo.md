# Demonstration

The local demonstration proves deterministic behavior without credentials. The live demonstration is an operator-controlled release gate using a disposable GitHub App installation, temporary callback path, production container, and purpose-built public test repositories.

## Local deterministic proof

Install the pinned toolchain, build, and run the focused public-entrypoint and server composition tests:

```sh
corepack enable
corepack install
pnpm install --frozen-lockfile --ignore-scripts
npm run build
node_modules/vitest/vitest.mjs run --config vitest.config.ts --reporter=dot tests/delivery/check-public-entrypoint.test.ts tests/delivery/server.test.ts
```

The fixtures send original signed bytes through Probot, acquire fake immutable Git objects through the narrow read role, evaluate an Issues read-to-write change, perform immediate freshness validation, and publish through fake Check roles. They also prove invalid-signature rejection, stale zero-write behavior, annotation-free updates, fixed health output, and bounded socket shutdown.

This is composed-public-entrypoint evidence. It is not a substitute for the Docker-host or live-GitHub proof below.

## Live same-repository proof

Use one disposable same-repository pull request whose base source calls `octokit.rest.issues.listForRepo` and whose changed head line calls `octokit.rest.issues.create`. The base therefore observes Issues read while the head observes Issues write.

Before starting, bind every observation to one clean release commit SHA. Build the production image without runtime credentials, then supply the App ID, private-key path, webhook secret, and port only to the running container. Route GitHub through a temporary HTTPS callback to the production webhook endpoint.

The real signed delivery must produce exactly one completed Check named `BoundaryCI` on the tested head SHA with conclusion `failure`, title `Permission expansion requires review`, operation `issues/create`, and a failure annotation whose path and span are present in the changed head-file set. Inspect the base no-expansion boundary separately.

Redeliver the logical event and exercise the one permitted completed-state reconciliation. The Check ID must converge, and every update must omit annotations. Then change the current head before the final freshness read and confirm obsolete work makes zero create or update calls. A duplicate exact Check match must stop without mutation.

## External-fork feasibility

Use a separate disposable external-fork pull request. Confirm the base installation and head repository identities without acquiring fork source. Observe only the bounded publication-addressability decision:

- addressable: one explicit `action_required` unsupported-topology Check may be published;
- unaddressable: no Check mutation occurs.

Both outcomes are valid conditional observations and neither is success. Do not infer universal fork support from the result.

## Sanitized evidence

Retain only the exact release SHA, public repository and pull-request identities, numeric App and Check IDs, correlation identity, conclusion and title, operation, repository-relative annotation path and span, finite counts, stable outcomes, image digest, and timestamps required by the closed release-proof schemas.

Do not retain source lines, patches, raw payloads, API request or response bodies, external errors, logs with uncontrolled fields, authorization data, signatures, private keys, webhook secrets, installation credentials, tunnel credentials, or environment dumps. Stop and remove the temporary callback, container, image, and App/test residue after capture.

Follow the ordered [release runbook](release.md) for the blocking proof and review sequence.
