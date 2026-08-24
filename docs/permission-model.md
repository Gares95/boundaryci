# Permission model

BoundaryCI's permission model is the pure domain layer that turns an observed GitHub REST
operation into a permission requirement, keeps the evidence that justifies it, and compares
two observed boundaries without overstating what static analysis can prove.

Everything in this layer is plain JSON-safe data. It parses no source, reads no file, opens
no socket, and holds no client, framework, or AST object. Input that cannot be proved does
not become a smaller or cleaner claim: it becomes an explicit `unsupported`, `missing`,
`invalid`, or `incomplete` result that still carries its evidence.

## Modules and public API

### `src/permission-model/model.ts`

Types: `PermissionLevel`, `BoundaryLevel`, `RequirementExpression`, `RestOperationIdentity`,
`SourcePoint`, `SourceSpan`, `SourceEvidence`, `CatalogProvenance`, `ResolvedCatalogEntry`,
`UnsupportedCatalogEntry`, `PermissionCatalogEntry`, `CatalogValidationResult`,
`CatalogLookupResult`, `RequirementFinding`, `PermissionBoundary`, `PermissionChange`,
`BoundaryComparison`.

Functions:

| Function | Purpose |
|----------|---------|
| `canonicalizeRequirementExpression(expression)` | Returns a deep copy in canonical child order. |
| `validateRequirementExpression(value)` | Asserts an exact-shape expression already in canonical order. |
| `requirementExpressionJson(expression)` | Serializes an expression to deterministic canonical JSON bytes. |
| `validateSourceEvidence(value)` | Asserts a JSON-safe source path with positive, ordered coordinates. |
| `validatePermissionCatalog(catalog)` | Validates a complete catalog collection before any lookup may use it. |
| `lookupPermissionRequirement(catalog, operation)` | Resolves one exact operation triple against a validated catalog. |
| `resolveRequirementFinding(catalog, operation, source)` | Attaches validated source evidence to one lookup outcome. |
| `aggregatePermissionFindings(findings)` | Derives an observed permission boundary from findings. |
| `comparePermissionBoundaries(base, head)` | Compares a base boundary to a head boundary conservatively. |

### `src/permission-model/bounded-catalog.ts`

Exports `BOUNDARYCI_PERMISSION_CATALOG_IDENTITY` and `BOUNDARYCI_PERMISSION_CATALOG`. Both
values are deeply frozen.

No other public type, function, constant, or module belongs to this layer.

## Requirement expressions

A requirement is a recursive JSON record with exactly one of three shapes:

```json
{ "type": "permission", "permission": "issues", "level": "write" }
{ "type": "allOf", "requirements": [ /* two or more requirements */ ] }
{ "type": "anyOf", "requirements": [ /* two or more requirements */ ] }
```

- `permission` is a named GitHub App permission with `read` or `write` access.
- `allOf` means every child is required. It is never flattened into one permission.
- `anyOf` means the operation accepts alternatives. No alternative is ever selected,
  merged, or dropped.
- A group must contain at least two children. Nested groups are permitted at any depth.
- Repeated children are meaningful data. They are preserved exactly and are never
  deduplicated.

### Canonicalization is not validation

The two operations are deliberately separate.

`canonicalizeRequirementExpression` returns a deep copy whose group children are recursively
ordered by canonical JSON bytes. Ordering is its only effect: every node, nested group,
child, and repeated child survives, and the caller's value is never mutated.

`validateRequirementExpression` accepts only an exact-shape expression that is *already* in
canonical order. It repairs nothing. Unknown fields, a bad discriminant, a bad access level,
an empty or single-child group, a malformed nested child, and a noncanonical child order are
all rejected. Silently sorting a caller's value would hide the fact that the value did not
come from a canonical source.

`requirementExpressionJson` produces byte-stable canonical JSON: the same expression always
serializes to the same string, and a parse/validate/re-serialize cycle reproduces it.

## Source evidence

Every finding carries the full REST operation triple and the exact source location:

```json
{
  "method": "POST",
  "normalizedRoute": "/repos/{owner}/{repo}/issues",
  "operationId": "issues/create"
}
```

```json
{
  "path": "src/app.ts",
  "span": { "start": { "line": 20, "column": 5 }, "end": { "line": 24, "column": 6 } }
}
```

`method` must be an uppercase REST method, `normalizedRoute` must be a whitespace-free path
beginning with `/`, and `operationId` must be a non-empty whitespace-free identifier. Line
and column numbers must be positive safe integers, and the end position must not precede the
start position. Coordinates are preserved exactly through lookup, aggregation, and
comparison so an explanation can point at the responsible call.

## Catalog lookup

The lookup identity is the complete `(method, normalizedRoute, operationId)` triple. A
mismatch in any one field is not a resolved lookup.

`validatePermissionCatalog` validates the whole collection, not one row at a time. A
malformed entry, a repeated identity, or two entries that disagree about the same triple
invalidate the entire catalog:

| Result | Meaning |
|--------|---------|
| `valid` | Every entry has an exact shape, a valid triple, a canonical requirement, and complete provenance. |
| `invalid: malformed-catalog-entry` | Some entry has an unknown, missing, or unusable field. |
| `invalid: duplicate-catalog-entry` | A byte-identical entry repeats one operation triple. |
| `invalid: conflicting-catalog-entry` | Two entries disagree about one operation triple. |

`lookupPermissionRequirement` validates the complete catalog and the requested identity
before it reads any row, so a damaged catalog is never partially queried. It returns exactly
one of four classes:

| Class | Meaning |
|-------|---------|
| `resolved` | The triple maps to a canonical requirement expression with its provenance. |
| `unsupported` | The catalog explicitly records that the requirement cannot be represented. |
| `missing` | The catalog contains no entry for the triple. |
| `invalid` | The requested identity or the catalog itself is unusable. |

`resolveRequirementFinding` wraps one lookup outcome with validated source evidence. It
never invents a value it could not validate: an unusable operation identity or an unusable
source evidence record is reported as `null` in that field alongside an `invalid` status and
its detail.

Returned requirements and provenance are copies, so a consumer cannot reach back into
catalog data through a result.

## The production catalog

`BOUNDARYCI_PERMISSION_CATALOG` contains exactly two resolved rows and nothing else:

| Method | Normalized route | Operation | Requirement |
|--------|------------------|-----------|-------------|
| `POST` | `/repos/{owner}/{repo}/issues` | `issues/create` | `issues: write` |
| `GET` | `/repos/{owner}/{repo}/issues` | `issues/list-for-repo` | `issues: read` |

The literals are a static projection of reviewed evidence committed under
`tools/permission-data-feasibility/`. Nothing is read from a file, a package, or a network
service at runtime. Three inputs contribute, and their authority is ordered and *not*
interchangeable:

- `evidence/decision-record.json` alone authorizes catalog membership and supplies the
  authorized-scope digest.
- `evidence/support-manifest.json` binds the selected operation identities and their
  expression, artifact, predicate, and selection digests. It cannot authorize an additional
  operation.
- `fixtures/canonical-issues.json` supplies the exact method, normalized route, operation
  identifier, and permission values. It cannot authorize membership.

Each row therefore carries five distinct digests in `CatalogProvenance`:
`authorizedScopeSha256`, `expressionSha256`, `entrySha256`, `artifactManifestSha256`, and
`supportPredicateSha256`. They record different facts and are never substituted for one
another.

`BOUNDARYCI_PERMISSION_CATALOG_IDENTITY` names the catalog itself. Base and head analysis
must carry the same identity so a comparison reflects repository changes rather than catalog
drift.

**Adding an operation requires a separately reviewed authorization update.** The membership
of this catalog is not an implementation detail and cannot be widened by editing the module.

## Aggregation

`aggregatePermissionFindings` derives an observed boundary from findings.

A boundary is `complete` only when every finding resolved to a root permission atom. Atoms
are then grouped by *exact* permission name, and the rank `none < read < write` is applied
only inside one name. Permission names are compared byte for byte: `issues`, `Issues`, and
`issues_events` are three different permissions and never raise one another. Every
contributing finding is retained under its permission in canonical order, including repeated
evidence and several operations that require the same permission.

No findings at all is a complete empty boundary.

A boundary is `incomplete` when any finding is a complex expression (`allOf`, `anyOf`, or a
nested group) or has an `unsupported`, `missing`, or `invalid` status. The incomplete result
retains every original finding and a stable, deduplicated, ordered reason list:

- `complex-permission-expression`
- `invalid-permission-requirement`
- `missing-permission-requirement`
- `unsupported-permission-requirement`

An incomplete boundary never exposes a partial simple boundary. Resolvable atoms mixed with
one unprovable finding do not produce a "mostly complete" answer.

A structurally malformed finding is a programming error rather than an analysis outcome, so
it is rejected rather than dropped.

## Comparison

`comparePermissionBoundaries` compares two complete simple boundaries over the union of
their exact permission names, with absence represented as `none`, and reports `expansion`,
`reduction`, or `unchanged` per name.

If either side is incomplete, the comparison is incomplete. It retains both boundaries in
full, merges their reasons with `incomplete-base-boundary` and `incomplete-head-boundary`
markers, and produces no change list at all. An incomplete input can never yield an
unqualified expansion, reduction, or no-change claim.

Complex evidence is compared only where the relationship can be proven, and only as a
qualified marker inside an incomplete result. `structurallyEquivalent` is true only when

- both boundaries are incomplete for exactly the same reasons,
- at least one resolved requirement is present, and
- every retained finding matches on both sides apart from its source location.

Moving a call to a different line is therefore not a boundary change, while a different or
additional unprovable operation keeps the two sides distinguishable. Anything else —
different alternatives, a reclassified group, an added branch, or two boundaries whose only
evidence is unresolved — is left unproven. `anyOf` is never collapsed into a simple
permission boundary in order to force a comparison.

## Determinism and the runtime boundary

Every public value is JSON-safe: repeated execution produces identical output, and a
`JSON.stringify` / `JSON.parse` round trip reproduces an equal value. Ordering is derived
from canonical JSON bytes rather than from insertion order or locale collation.

The production modules import nothing except a type-only sibling import. They contain no
Node built-in, filesystem, network, client, framework, or analysis-tooling reference, and no
clock, random source, dynamic import, or code evaluation. The layer is usable anywhere a
plain JavaScript runtime is available and is verified by an automated import-boundary check.

## Test policy for synthetic data

Complex, unsupported, malformed, duplicate, and conflicting cases are exercised with
synthetic catalog rows that use the same exact-key operation, requirement, evidence, and
provenance shapes as real rows, with obviously synthetic routes and digests. Synthetic data
never enters the exported catalog, and an automated assertion keeps the production catalog
at exactly the two authorized rows.

## Limitations

- The production catalog covers two operations. Every other operation is a `missing` lookup,
  and an analysis that depends on one is incomplete rather than clean.
- No reviewed GitHub App-applicable `allOf` requirement is available in the current evidence
  set, so the production catalog contains no group requirement. The model represents,
  validates, and preserves groups so that a future reviewed catalog needs no semantic change.
- Alternative (`anyOf`) requirements are represented and preserved but are never resolved
  into a single permission, so any boundary that contains one stays incomplete.
- This layer does not discover operations in source, apply policy, or render output. It
  models requirements, evidence, and their relationships only.
