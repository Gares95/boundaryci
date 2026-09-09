# Contributing

Contributions should preserve BoundaryCI's conservative security claim: report what supported static evidence proves, and make every uncertainty explicit.

## Development setup

Use Node.js 24 and the pnpm release pinned by the root `packageManager` field.

```sh
corepack enable
corepack install
pnpm install --frozen-lockfile --ignore-scripts
npm run build
```

The workspace does not need target-project dependencies or credentials for analyzer, model, CLI, or fake-delivery tests. Do not install, import, build, or execute a fixture repository.

## Required checks

During implementation, run the focused test file for the component being changed. Before proposing a contribution, run:

```sh
npm test
npm run typecheck
npm run lint
npm run format:check
npm run build
```

Release-affecting changes also require `npm run verify:release` on a clean commit with Docker available. Its repository-only mode is useful feedback but is not release acceptance. The canonical gate checks the exact public file set, documentation, license, secrets and provenance, then builds and inspects the non-root production image.

Changes should be cohesive and use clear commit messages. Update tests and public documentation when a contract changes. Do not weaken a failure or incomplete result merely to make a fixture pass.

## Safe fixtures and contributions

- Fixtures are committed inert bytes. Tests may parse them but must not execute them or resolve their dependencies.
- Use obviously synthetic sentinels for credential-redaction tests and construct forbidden signatures without embedding usable credential material.
- Do not commit environment files, private keys, tokens, certificates, raw webhook or API captures, target source snapshots, local agent or workflow files, retained proof, or private review notes.
- Do not add resolvable task markers or template fields to committed files.
- Keep analyzer and policy decisions deterministic. A model or remote service cannot decide an operation, permission, comparison, or policy result.
- Preserve analyzer/delivery separation and the fixed minimum GitHub API surface. A broader API, language, GraphQL, or hosting feature requires its own reviewed design.

Security-sensitive reports should follow the [security policy](SECURITY.md). See [architecture](docs/architecture.md), [permission model](docs/permission-model.md), and [limitations](docs/limitations.md) before changing a trust boundary.
