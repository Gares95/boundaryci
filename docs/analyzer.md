# Static analyzer

BoundaryCI's analyzer turns a trusted, bounded JavaScript/TypeScript source universe into
portable evidence about recognized GitHub REST operations and their observed GitHub App
permission requirements. It parses source bytes but never installs dependencies, resolves
packages, imports target modules, builds the target, or executes target code.

The analyzer is independently usable. GitHub delivery and base-versus-head policy consume
its JSON-safe result, but are separate layers.

## Analysis pipeline

The fixed Phase 3 pipeline is:

1. validate a trusted discovery request;
2. discover a deterministic regular-file source universe;
3. decode and parse each included source file;
4. census anchored Octokit/Probot operation candidates;
5. evaluate bounded source-local receiver provenance;
6. normalize supported calls to pinned REST operation identities;
7. resolve each proven operation through the bounded permission catalog;
8. return a deterministic `complete`, `incomplete`, or `failed` `AnalysisResult`.

Recognized-looking syntax is not enough to prove an operation. A proven observation needs
all three of an authorized receiver provenance chain, an authorized call grammar, and one
exact member or route in the pinned compatibility profile.

## Trusted discovery request

`analyzeSourceTree` accepts one `AnalysisRequest`:

- `rootPath`: the caller-supplied analysis root;
- `include`: at least one limited glob pattern;
- `exclude`: an explicit list, which may be empty;
- `probotEntrypoints`: explicitly designated included source paths;
- `limits`: explicit deterministic file, byte, and discovery-work limits.

The root is canonicalized once. Traversal underneath it does not follow symbolic links.
Only regular files participate. Matching source symlinks, relevant directory symlinks, and
matching non-regular entries become scoped incompleteness causes rather than being read.
`node_modules` and declaration files never enter the source universe.

Paths are normalized, case-sensitive, root-relative POSIX identities. The limited glob
grammar supports whole-segment `**`, non-separator `*`, and one-character `?`; it does not
interpret negation, manifests, package scripts, compiler configuration, or build-tool
semantics. The effective universe is `any(include) - any(exclude)`.

Exactly these executable extensions are discoverable:

- `.js`
- `.jsx`
- `.mjs`
- `.mts`
- `.ts`
- `.tsx`

Discovery and all budget consumption use deterministic bytewise path order. File, total-byte,
and work exhaustion are uncertainty conditions. Completed proof chains remain visible, while
the unprocessed frontier is represented by causal evidence.

## Parsing and source spans

Files are decoded as fatal UTF-8 and parsed independently with the TypeScript compiler API's
explicit `ScriptKind`. BoundaryCI uses `createSourceFile`; it does not create a target
`Program` or ask TypeScript to resolve modules.

The `boundaryci/source-span@1` convention is part of every result identity:

- raw byte size and SHA-256 include an optional byte-order mark;
- one leading U+FEFF is removed before offsets are measured;
- LF, CRLF, and lone CR each terminate a line;
- line and column values are one-based;
- columns count UTF-16 code units;
- span starts are inclusive and ends are exclusive.

An included file that cannot be decoded or parsed contributes no positive findings. Other
independently proven files remain usable, and the repository result becomes `incomplete`.

## Bounded relative source graph

Provenance follows only statically resolvable relative imports, named imports/exports,
explicit named re-exports, and immutable local aliases between included files. ESM is the
primary grammar. A narrow CommonJS form supports a top-level immutable literal-relative
`require()` and statically named destructuring or renaming when `require` is unshadowed.

Resolution uses the fixed `boundaryci/relative-source-candidates@1` table. Exact supported
source extensions remain exact; emitted JavaScript-family suffixes may map to their fixed
TypeScript counterparts; extensionless specifiers probe the six supported extensions at
the explicitly named path. Exactly one included candidate is required.

There is no implicit directory or `index` resolution. For example, `./client/index.js` may
map to `./client/index.ts`, but `./client` never becomes `./client/index.*`. The documented
`.cjs -> .cts` table row is deliberately unreachable because neither extension belongs to
the six-extension discovery universe.

The graph never resolves packages, `node_modules`, package exports, `package.json`, compiler
path aliases, runtime loaders, or build-tool configuration. `export *`, namespace re-exports,
general `module.exports` mutation, mutable aliases, ambiguous matches, and relevant cycles
that block proof become explicit incomplete chains.

## Authorized receiver provenance

Receiver shape and names are not evidence. A value named `octokit`, a property named
`octokit`, or an object exposing `.rest` is insufficient without an authorized origin.

### Direct Octokit clients

The direct constructor origin is exactly the named `Octokit` export/property from the
literal package specifier `octokit`, through either:

- `import { Octokit as X } from "octokit"`; or
- top-level immutable `const { Octokit: X } = require("octokit")`.

Supported immutable aliases and explicit named relative-source forwarding may carry that
constructor identity. Only direct `new <authorized-constructor>(...)` establishes a client.
Default or namespace imports, other `@octokit/*` packages, factories, plugins, subclasses,
wrappers, call-returned constructors, mutable bindings, and construction without `new` do
not establish provenance.

An ECMAScript private instance field such as `#client` may carry proven provenance when it
has exactly one supported direct assignment inside its declaring class. Unsupported or
additional writes invalidate dependent observations. Public/protected fields, TypeScript
`private` or `readonly`, constructor-parameter propagation, accessors, inheritance, and
general object-state tracking are outside the grammar.

### Probot context

Probot provenance begins only from a caller-designated entrypoint. A supported default
initializer gives parameter 0 `ProbotApp` provenance. On that proven receiver, the explicit
`app.on(event, handler)` registration contract gives its designated handler parameter
`Context` provenance. Inline callbacks, immutable named handlers, supported aliases, and
explicit relative-source forwarding are supported.

`context.octokit` and statically named top-level parameter destructuring such as
`{ octokit: github }` can then establish the client receiver. Filenames, imports, types,
identifier names, `.on()` shape on an unproven object, handler factories, wrappers, nested
callback propagation, arbitrary parameter passing, and other registration methods do not.

## Supported call grammar

Given an independently proven receiver, canonical endpoint calls use exactly
`receiver.rest.<scope>.<method>(...)`. The `scope.method` pair must map unambiguously through
the pinned endpoint-method profile. Direct shorthand `receiver.<scope>.<method>(...)` is not
inferred. The Phase 3 direct-shorthand authorization set is empty.

Positional `receiver.request(route, parameters)` accepts a strict static `METHOD /path`
route from a string literal, no-substitution template literal, or a proven immutable
source-local literal alias. No concatenation, interpolation, property lookup, call result,
or concrete-path-to-template inference is performed.

Object-form `receiver.request({...})` accepts only a fresh inline object with one explicit
literal `method` and one explicit literal `url`. Non-route parameter values may be arbitrary.
Spreads, duplicate or computed route keys, accessors, route shorthand, custom base URLs,
absolute URLs, and bound/imported/mutated option objects are incomplete.

Optional chaining at a supported receiver, member, or invocation position preserves the
same canonical operation as conditional evidence. It does not weaken permission aggregation:
the permission is required whenever the operation executes. Changing only direct versus
optional invocation does not change canonical operation identity.

Static bracket endpoint syntax is explicitly unsupported. Nonliteral computed access has a
separate dynamic-member cause. Endpoint function extraction is also unsupported because the
pinned evidence does not establish detachment-safe semantics; the Phase 3 detached-endpoint
authorization set is empty.

Detaching a larger part of a proven client's request surface is likewise unsupported and never
silently clean. On a receiver independently proven to be an authorized client, an uninvoked
`receiver.rest`, `receiver.rest.<scope>`, or `receiver.request` value (including
`request.defaults(...)`), top-level `rest` or `request` destructuring from the receiver, and
`receiver.paginate(...)` or `receiver.paginate.iterator(...)` each become an explicit incomplete
candidate. These sites never prove an operation. On any other receiver they raise no obligation,
so the words `rest`, `request`, and `paginate` alone still create no noise.

## Pinned compatibility profile

`boundaryci/octokit-analyzer-profile@1` is backed by the committed evidence for
`octokit@5.0.5`, `@octokit/plugin-rest-endpoint-methods@18.0.0`, and GitHub REST API version
`2022-11-28`. It contains 1,010 unambiguous endpoint members and 878 App-enabled canonical
REST operations.

This is an analyzer source-compatibility profile. BoundaryCI does not inspect, install,
resolve, or independently verify the target repository's installed Octokit version. Profile
membership proves only that the source spelling has the pinned semantics BoundaryCI is
authorized to recognize.

Operation recognition and permission resolution are separate. A profiled REST operation
outside the production permission catalog remains a proven operation, while its permission
finding and aggregate boundary are explicitly incomplete. The current permission catalog is
still exactly the two Issues operations documented in [the permission model](permission-model.md).

## Candidate accounting and results

The shallow candidate census is anchored by authorized provenance contexts, pinned endpoint
spellings, supported request shapes, and recognized unsupported equivalents. Raw names such
as `rest`, `request`, `octokit`, or `on` do not create obligations by themselves.

Every candidate ends in exactly one classification:

- `proven-operation`: receiver and canonical REST identity are established;
- `proven-irrelevant`: evidence proves the site is not an authorized Octokit operation;
- `incomplete`: the site remains plausibly relevant but the bounded grammar cannot prove or
  disprove the required provenance or operation identity.

Failure to prove receiver provenance is never proof of irrelevance.

`AnalysisResult` has three structurally distinct outcomes:

- `complete`: every relevant obligation raised under the declared discovery universe,
  grammar, profile, and limits was resolved;
- `incomplete`: analysis ran safely and positive findings remain trustworthy, but at least
  one target-program question or permission lookup remains unresolved;
- `failed`: trusted input, root-boundary establishment, profile selection, or analyzer state
  could not support a trustworthy semantic result.

A failed result contains failure diagnostics but no accumulated operation or permission
findings presented as trustworthy output. Complete and incomplete results retain normalized
boundary identity, source records, candidates, deduplicated causes, meaningful provenance
steps, operation observations, permission resolutions, and the aggregate permission boundary.

Cause records are deterministic, scoped, and linked from affected candidates. A normal graph
cycle is silent unless it prevents a required proof. Scan-wide budget exhaustion emits an
aggregate frontier cause rather than flooding output. No partially established observation
becomes proven merely because processing began before a cutoff.

All evidence uses root-relative POSIX paths. Source records retain byte size and content
SHA-256; source snippets, absolute host paths, parser objects, filesystem handles, framework
objects, errors, clocks, and random values are absent. Stable IDs are deterministic ordinals,
not cryptographic attestations.

## Validation evidence

Normative golden fixtures cover the declared grammar and important unsupported boundaries.
They assert exact result bytes, JSON round-tripping, portable evidence, non-mutation, and
repeat/reordered execution stability.

The original seven-repository, 32-label artifact remains an integrity-bound regression
fixture, but the available record does not establish that its labels were created
independently of analyzer output. BoundaryCI therefore does not use that artifact as its
accountable claim of analyzer-independent human validation.

That claim is supported by a fresh blind sample of 34 call sites, mechanically selected from
the same seven pinned repositories without reading analyzer output or the historical labels.
A human reviewed only the pinned source evidence and classified 14 sites as definite Octokit
operations and 20 as definite non-Octokit calls. Those answers were frozen byte-for-byte and
SHA-256 digested before comparison with BoundaryCI. The post-freeze comparison found:

- three human-positive sites resolved to the exact proven REST operation;
- eleven human-positive sites produced explicit incomplete outcomes at documented unsupported
  provenance or call-grammar boundaries;
- all 20 human-negative sites produced no analyzer operation;
- zero false-positive proven operations and zero false-clean relevant sites.

Neither the human answers nor analyzer behavior was changed to obtain agreement. Explicit
incompleteness for unsupported grammar or provenance is expected safe behavior, not an
analyzer error. These results are evidence about the bounded grammar, not a global coverage
percentage. Unsupported real-world classes may motivate future work only through a separately
reviewed scope decision.

## Contract-relative completeness and limitations

`complete` means complete only for the declared Phase 3 source universe, candidate census,
grammar, profile, and resource limits. It does not prove the absence of GitHub activity
through raw `fetch`, GraphQL, arbitrary wrappers, general CommonJS exports, dynamic loading,
package resolution, runtime-computed routes, arbitrary factories, public object fields,
interprocedural parameter/return flow, reachability, dead-code analysis, or other unsupported
mechanisms.

Those surfaces are not implicit implementation tasks for Phase 3. When an anchored relevant
site depends on one, the result is incomplete rather than silently clean. Expanding the
grammar, endpoint surface, or permission catalog requires new evidence and a separately
reviewed change.
