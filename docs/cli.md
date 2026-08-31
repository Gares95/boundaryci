# BoundaryCI command-line interface

BoundaryCI's local CLI analyzes JavaScript and TypeScript source snapshots without installing,
importing, building, or executing code from those snapshots. It exposes three commands over the
same analyzer, permission, comparison, and policy domain layers.

```text
boundaryci analyze <path> [--format human|json]
boundaryci diff --base <path> --head <path> [--format human|json]
boundaryci check --base <path> --head <path> [--format human|json]
```

Each path must identify an existing local directory. Phase 4 does not resolve Git references or
acquire repositories: callers provide the already-materialized source directories. `human` is the
default format. Unknown commands, positionals, options, duplicate flags, missing flag values, and
unsupported formats are rejected before analysis.

## Commands

### `analyze`

`analyze` loads the snapshot's `.boundaryci.yml`, or the versioned built-in default when the file
is absent, and reports:

- the normalized configuration authority and identity;
- repository analysis completeness;
- every proven canonical REST operation and root-relative source span;
- permission-resolution records and the aggregate observed permission boundary;
- explicit causes for unresolved relevant source or permission evidence; and
- repository-declared expected permissions, clearly labelled as declarations.

It does not perform a revision comparison and does not apply `failOnExpansion` or
`failOnIncomplete`. An incomplete analysis therefore exits with code 2 even if the snapshot's
policy would tolerate incompleteness during `check`.

### `diff`

`diff` loads both configuration files before source analysis. The valid base configuration is
authoritative; if the base has no configuration, the built-in default is authoritative. That one
effective configuration governs both analyses. A valid head configuration is reported only as a
prospective value for a later comparison.

The command reports complete permission changes as `expansion`, `reduction`, or `unchanged`, with
the base and head operation/source contributors. If either side has unresolved relevant evidence,
the result remains `incomplete`; proven operations and qualified known changes survive, but the
command never manufactures a clean or exact reduction from uncertainty. `diff` reports facts and
does not apply repository policy.

### `check`

`check` performs the same base-authoritative comparison as `diff`, then applies the base policy's
two independent flags:

- `failOnExpansion` rejects a proven expansion;
- `failOnIncomplete` rejects an incomplete comparison.

Turning a flag off changes only the pass/fail decision. It never removes the expansion,
incompleteness, operations, contributors, or causes from output. A tolerated incomplete check has
outcome `incomplete`, check status `pass`, and exit code 0; it is not relabelled as complete.

## Output contracts

Successful semantic dispatch writes exactly one document to standard output. Usage failures and
unexpected CLI-adapter failures write one diagnostic line to standard error and no semantic
document.

Human output begins with the command and common outcome. It retains configuration authority,
prospective head state, policy reasons where applicable, permission changes, canonical REST
method/route/operation identity, root-relative source spans, contributor counts, and uncertainty
codes. It does not include absolute snapshot paths or source snippets.

JSON output uses the stable envelope:

```json
{
  "command": "analyze",
  "evaluation": {},
  "outcome": "complete",
  "schemaId": "boundaryci/cli-result",
  "schemaVersion": 1
}
```

`evaluation` contains the full command-specific domain result. Object keys are recursively sorted
and domain record arrays use their deterministic semantic order. Repeating a command over the same
bytes, configuration, and analyzer identities produces byte-identical JSON. `diff` output contains
no policy decision; `check` retains both the comparison and policy decision.

## Exit codes

| Code | Meaning |
| ---: | --- |
| 0 | Complete `analyze`/`diff`, a passing complete `check`, or an explicitly policy-tolerated incomplete `check` |
| 1 | `check` rejected a proven permission expansion and did not also reject incompleteness |
| 2 | Incomplete `analyze`/`diff`, or `check` rejected an incomplete comparison |
| 3 | Invalid command input, inaccessible/non-directory snapshot root, or invalid base/head configuration |
| 4 | Runtime/infrastructure failure or an unexpected CLI-adapter exception |

If a check rejects both a proven expansion and incompleteness, code 2 takes precedence while both
policy reasons remain in the semantic output. Exit status never replaces evidence: inspect the
human or JSON result to understand the exact outcome.

## Configuration and comparison identity

The complete configuration schema, defaults, and base-authoritative selection matrix are described
in [configuration.md](configuration.md). Base and head must carry compatible engine, analyzer
profile, permission-catalog, and effective-configuration identities. An incompatible identity is
an input/configuration result, never a guessed semantic diff.

## v1 support boundary and limitations

The production permission catalog is frozen at exactly:

- `issues/create` → `Issues: write`;
- `issues/list-for-repo` → `Issues: read`.

Operation recognition is broader than permission authorization. The analyzer can prove other REST
operations in its pinned compatibility profile, but an operation outside these two rows retains
its operation evidence and makes permission resolution explicitly incomplete.

BoundaryCI reports permissions observed through its declared, bounded source grammar. It does not
claim perfect least privilege, evaluate arbitrary wrappers or dynamic execution, or verify the
target repository's installed Octokit version. Repository-declared expected permissions are not
source observations and are not verified live permissions of an installed GitHub App.

Phase 4 is a local, non-interactive CLI. GitHub snapshot acquisition, authentication, webhook
handling, GitHub Check delivery, and rendered pull-request presentation are not implemented by
these commands.
