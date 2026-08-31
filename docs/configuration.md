# Repository configuration

BoundaryCI reads at most one repository configuration file, `.boundaryci.yml`. Version 1 controls the bounded source-discovery inputs used by the static analyzer, two local check-policy flags, and optional repository-declared permission expectations. It cannot add permission-catalog entries or change analyzer semantics.

## Version 1 schema

```yaml
version: 1

analysis:
  include:
    - "src/**/*.ts"
  exclude:
    - "**/generated/**"
  probotEntrypoints:
    - "src/app.ts"
  limits:
    maxSourceFiles: 5000
    maxSourceFileBytes: 2000000
    maxTotalSourceBytes: 64000000
    maxSourceWork: 50000

policy:
  failOnExpansion: true
  failOnIncomplete: true

expectedPermissions:
  issues: write
```

`version` is required and must be `1`. Every other section and field is optional. BoundaryCI rejects unknown keys rather than ignoring them.

`analysis.include` and `analysis.exclude` use the analyzer's finite, case-sensitive, root-relative POSIX glob grammar. `*` matches within one path segment, `?` matches one non-separator character, and `**` is supported only as a whole segment. Negation, brace expansion, character classes, extglobs, backslashes, absolute paths, and `.` or `..` path segments are not interpreted. A supplied `include` array must not be empty.

`analysis.probotEntrypoints` contains explicit root-relative POSIX source paths. It designates files eligible for the bounded Probot initializer grammar; filenames, manifests, imports, and method names never infer that role.

All four limits are non-negative safe integers. A zero limit is meaningful and is not replaced with a default. Crossing an analysis limit produces explicit incomplete evidence; it is never evidence that an operation is absent.

`policy.failOnExpansion` and `policy.failOnIncomplete` are independent. Turning a policy flag off permits the associated check condition but does not remove expansion or incomplete evidence from output.

`expectedPermissions` maps exact permission names to `read` or `write`. These are repository-declared expectations. They are not operations observed in source, permission requirements inferred by BoundaryCI, or independently verified live permissions of an installed GitHub App.

## Safe defaults

When the authoritative base revision has no `.boundaryci.yml`, BoundaryCI uses one versioned built-in configuration:

- include `**/*.js`, `**/*.jsx`, `**/*.mjs`, `**/*.mts`, `**/*.ts`, and `**/*.tsx`;
- exclude `**/build/**`, `**/dist/**`, and `**/node_modules/**`;
- designate no Probot entrypoints;
- allow at most 5,000 source files, 2,000,000 bytes per source file, 64,000,000 total source bytes, and 50,000 source-discovery work units;
- set both `failOnExpansion` and `failOnIncomplete` to `true`;
- declare no expected permissions.

Omitted fields within a present version-1 document receive the same field defaults. Arrays are deduplicated and ordered by UTF-8 bytes before use.

## Base-authoritative comparison

One effective configuration governs both base and head analysis and the policy decision. A pull request cannot weaken its own evaluation by changing the head configuration.

| Base `.boundaryci.yml` | Head `.boundaryci.yml` | Current authority | Result |
| --- | --- | --- | --- |
| valid | absent | base | comparison may proceed; head absence is reported prospectively |
| valid | valid | base | comparison may proceed; normalized head config and whether its identity changed are prospective evidence only |
| absent | absent | built-in default | comparison may proceed under the same built-in identity on both sides |
| absent | valid | built-in default | comparison may proceed; the head config is prospective only |
| invalid | any state | none | input/configuration failure before source analysis; no default or head fallback |
| valid or absent | invalid | base or built-in default | input/configuration failure before source analysis; selected authority and head diagnostics are retained, but no head fragment governs |

This prospective treatment means a configuration introduced or changed by a pull request can be reviewed without affecting the policy that judges that pull request. A later comparison may use it when it belongs to the base revision.

## Canonical identity

BoundaryCI computes the effective configuration identity as a lowercase SHA-256 over canonical, recursively key-sorted JSON containing every normalized value and default. YAML comments, map-key ordering, duplicate declarative array entries, array ordering, and explicitly spelling an otherwise omitted default do not change the identity. A semantic change to discovery, limits, policy, or declared expectations does.

Base and head source evidence may be compared only when they carry the same authoritative effective-configuration identity along with compatible engine, analyzer-profile, and permission-catalog identities. Incompatible identities produce an explicit input/configuration failure, not a manufactured boundary diff.

## Parsing and isolation

BoundaryCI reads only the exact `.boundaryci.yml` regular file beneath the local snapshot root. The file is limited to 256 KiB and must contain valid UTF-8 and one YAML 1.2 core-schema document. Symbolic links, non-regular entries, duplicate keys, aliases, merges, custom tags, multiple documents, unsupported versions, and malformed values are rejected with configuration diagnostics.

Configuration processing does not install dependencies, inspect target package metadata, import modules, build, transpile, or execute target repository code. Configuration controls only Phase 3 discovery inputs and Phase 4 local policy. It does not acquire GitHub snapshots, authenticate a GitHub App, or control GitHub Check presentation; those are delivery-layer concerns.

## Frozen v1 permission support

The v1 production permission catalog remains exactly:

- `issues/create` → `Issues: write`
- `issues/list-for-repo` → `Issues: read`

Configuration cannot add, override, or synthesize catalog rows. The analyzer may prove other profiled GitHub REST operations, but a proven operation outside these two authorized rows retains its operation evidence and produces explicit incomplete permission resolution.
