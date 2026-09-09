# BoundaryCI

BoundaryCI makes GitHub App permission drift visible in pull requests before merge, while staying explicit about what static analysis cannot prove.

## Permission drift in pull requests

A GitHub App can gain a wider effective boundary when a code change starts calling a more privileged REST operation. BoundaryCI analyzes supported JavaScript and TypeScript Octokit patterns at the exact base and head revisions, compares the observed requirements, and applies repository policy. It preserves the operation and source location behind every finding instead of presenting an unexplained permission list.

BoundaryCI does not execute the target project, contact the network during local analysis, or certify perfect least privilege. Unsupported or dynamic behavior remains an explicit incomplete result.

## Issues read-to-write example

Suppose the base revision only lists issues, but the pull request creates one:

```diff
-octokit.rest.issues.listForRepo({ owner, repo });
+octokit.rest.issues.create({ owner, repo, title: 'Review permission drift' });
```

The observed Issues boundary changes from Issues `read` → `write`. With the default policy, the exact head commit receives a completed `BoundaryCI` Check with:

- conclusion: `failure`
- title: `Permission expansion requires review`
- operation: `issues/create`
- a failure annotation on the changed head-file line that introduced the call

The summary still contains aggregate counts if GitHub's annotation limit omits additional sites. Redelivery reconciles the same logical Check without replaying annotations, and a changed pull-request identity suppresses stale publication.

See the [reproducible demonstration](docs/demo.md) and [GitHub App delivery guide](docs/github-delivery.md).

## Install and use

BoundaryCI requires Node.js 24 and the pnpm version pinned in `package.json`.

```sh
corepack enable
corepack install
pnpm install --frozen-lockfile --ignore-scripts
npm run build
node dist/cli/main.js analyze ./repository
```

The CLI also supports deterministic base-versus-head `diff` and policy-enforcing `check` commands. See the [CLI guide](docs/cli.md), [configuration reference](docs/configuration.md), and [analyzer reference](docs/analyzer.md).

The static analyzer is independently usable. The CLI is a thin local interface over it. The optional GitHub App delivery layer acquires bounded immutable snapshots and publishes Checks through separately scoped roles; it is not required for local analysis.

| Surface | v1 support |
| --- | --- |
| Languages | JavaScript and TypeScript source extensions documented in the analyzer guide |
| GitHub API | REST operations through explicitly supported Octokit and Probot patterns |
| Permission expressions | `permission`, `allOf`, `anyOf`, and explicit unresolved outcomes |
| Comparison | Exact base/head identity, one engine and catalog identity, base-authoritative configuration |
| Pull requests | Same-repository analysis; external-fork handling is conditional and fail-closed |
| GraphQL | Not supported |

## What BoundaryCI can and cannot prove

BoundaryCI reports four different kinds of information without conflating them:

1. **Observed source evidence** identifies supported REST operations and locations found in analyzed source.
2. **Repository-declared configuration and policy** controls analysis and can declare an expected boundary; it is a repository assertion.
3. **Unresolved analysis** states where dynamic routes, unsupported constructs, catalog gaps, complex comparisons, or safe limits prevent a complete conclusion.
4. **Independently verified live App permissions** are operational facts established outside BoundaryCI. BoundaryCI does not retrieve or certify an unrelated target App's live permission settings.

See [permission model](docs/permission-model.md) and [known limitations](docs/limitations.md) for the exact semantics.

## Documentation

- [Architecture and security invariants](docs/architecture.md)
- [Permission model](docs/permission-model.md)
- [Analyzer behavior](docs/analyzer.md)
- [CLI and exit semantics](docs/cli.md)
- [Configuration and policy](docs/configuration.md)
- [GitHub App setup and delivery](docs/github-delivery.md)
- [Demonstration](docs/demo.md)
- [Known limitations](docs/limitations.md)
- [Security policy](SECURITY.md)
- [Contributing and local development](CONTRIBUTING.md)
- [Release runbook](docs/release.md)

## License

BoundaryCI is licensed under [Apache-2.0](LICENSE).
