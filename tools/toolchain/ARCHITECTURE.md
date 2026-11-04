# Authenticated toolchain capsule (experimental)

Status: experimental prototype. It is not wired into `npm run verify:release`, CI, the Dockerfile, or any production path. Nothing in this directory changes analyzer, catalog, policy, or delivery semantics.

## Context

Evidence-sensitive BoundaryCI work has authenticated a host tool such as `/usr/bin/git` by exact SHA-256. When the distribution shipped a new package build of the same upstream release, the bytes at that path changed and the check correctly failed closed. The invariant was right; binding it to a mutable, package-manager-owned path was the fragile part.

Repository inspection also shows that a digest of `/usr/bin/git` never bound the full executable identity:

- The Ubuntu build of git is a dynamic ELF. Its behavior also depends on the host ELF interpreter (`ld-linux-x86-64.so.2`), `libc.so.6`, `libz.so.1`, and `libpcre2-8.so.0`, and on helpers under the host `git-core` exec directory. Any of those can change in a security update while `/usr/bin/git` stays byte-identical.
- The public release verifier resolves `git`, `npm`, `docker`, `tar`, and `mkdir` through `PATH` (`tools/release/verify-release.mjs`). CI uses `actions/setup-node` with a version string, and pnpm is pinned by the `packageManager` sha512 integrity that Corepack checks at download time. The production image pins Node by base-image digest.
- No native resource-limit helper (`prlimit`, `ulimit`, `setrlimit`) is used anywhere; analyzer limits are in-process byte, count, and time budgets. None is added.

So a host-path digest was too strict (it breaks on benign package updates) and too weak (it does not cover the code that actually runs).

## Decision

Add a BoundaryCI-owned toolchain capsule that separates the approved identity from the installed location:

1. A committed, reviewed **manifest** is the trust root. Per tool it lists the complete userland file closure by relative path, exact SHA-256, size, and mode, plus the invocation form, the closed environment, and the expected version output. Its `treeSha256` is the SHA-256 of the canonical identity fields.
2. A local, **content-addressed store** holds materialized capsules at `store/<tool>/<treeSha256>/`. The location comes from the identity, so a store can be moved, rebuilt, or shared without being trusted: any store whose bytes verify is acceptable.
3. A dependency-free **verifier and runner** (Node built-ins only, so it can run before `pnpm install`) re-verifies the whole closure immediately before and after every frozen invocation. It runs the tool by absolute capsule path with a closed environment, and never reads `PATH` or a host tool path.
4. **Qualification** is the only way a new identity enters the system. It is an explicit command that writes a candidate manifest, and it refuses to replace an existing manifest unless it is given that manifest's current SHA-256. The approval is the reviewed commit of the manifest change. Host paths are read only by qualification, materialization, and an informational drift report, never by `verify` or `run`.

Normal host updates therefore cannot change what BoundaryCI executes for frozen work. Adopting newer bytes is a deliberate, reviewable act. The desired outcome is explicitly **not** "update the expected SHA when Ubuntu upgrades Git".

## Tools are not managed identically

| Tool | Identity | Invocation | Acquisition in the prototype | Target acquisition |
| --- | --- | --- | --- | --- |
| git | Native closure: binary, ELF interpreter, every `DT_NEEDED` library | `elf-loader`: the capsule's own `ld-linux` with `--inhibit-cache --library-path <capsule>/lib --argv0`; `GIT_EXEC_PATH` pinned inside the capsule; system and global config disabled | Explicit import of operator-selected local files | Undecided: snapshot-archive `.deb` files by digest, or a reproducible source build. Needs its own supply-chain decision. |
| node | Native closure as for git, or a static build when available | `elf-loader` or `direct` | Explicit local import | Official release tarball authenticated against a digest recorded in the manifest, with release-key verification of the upstream checksum file as a separate reviewed decision |
| pnpm | JavaScript package tree run by the capsule's node | `interpreter` (references the node capsule) | Explicit local import of the Corepack-materialized tree | npm tarball authenticated by the sha512 already committed in `packageManager`, then extracted by BoundaryCI |
| docker, tar, npm | Not covered | Unchanged | Not applicable | Out of scope. Docker is a daemon whose identity a file capsule cannot bind. |

The production container keeps its existing immutable base-image digest. CI is unchanged.

## Analysis

### 1. Threat model

In scope:

- **Benign host drift.** Package updates change bytes at system paths or in shared libraries. Required result: frozen work keeps using the approved bytes, and the drift is reported, not adopted.
- **Path substitution.** `PATH` order, a symlink, a hard link, or a replacement file causes a different executable to run. Required result: execution never uses `PATH`, and every capsule entry is checked without following links.
- **Library and helper fallback.** The dynamic loader or git falls back to host libraries or helpers. Required result: a static closure check that every `DT_NEEDED` name resolves inside the capsule and that no `RPATH`/`RUNPATH` exists, plus `--inhibit-cache` and a pinned `GIT_EXEC_PATH`.
- **Post-validation tampering.** The capsule is modified after an earlier successful verification. Required result: no verification cache. Every run re-verifies before and after execution, and a failed post-check discards the result.
- **Manifest tampering.** Edits that are not reflected in the identity, non-canonical encodings, unknown fields, or a manifest other than the one the caller pinned. Required result: the closed schema, canonical bytes, recomputed `treeSha256`, and an optional caller-pinned manifest SHA-256 all fail closed.
- **Silent requalification.** Tooling quietly adopts the new host bytes. Required result: no code path from `verify`, `run`, or `drift` writes a manifest, and qualification needs an explicit compare-and-swap digest.
- **Network fallback.** A missing tool is fetched implicitly. Required result: the frozen modules import no network module, and a missing capsule is a terminal failure.

Out of scope, documented as residual risk:

- root or kernel compromise;
- a malicious Node interpreter running the verifier, since the verifier's own interpreter is in the trusted computing base;
- a same-user attacker who swaps bytes and restores them within the window between pre-verification and `execve` (mitigated by the post-run check and, on hosts that need it, a root-owned store);
- runtime `dlopen` of NSS or `gconv` modules by glibc. The prototype restricts the intended git use to repository-local plumbing (`ls-files`, `status`, `rev-parse`), which does not need them;
- programs that a verified tool itself spawns at runtime. This channel is real and is described under "Runtime subprocess channels" below.

The caller-supplied environment of the programmatic runner is trusted input from BoundaryCI code. It cannot override declared or reserved names. The CLI passes none.

BoundaryCI never runs git against target repositories; targets are acquired as GitHub blobs. That bounds the exposure of a deliberately frozen, older git.

### 2. Trust root

The manifest bytes at a reviewed commit. A caller that records evidence can additionally pin the manifest SHA-256 and the per-tool `treeSha256` in its own frozen record. Version strings are metadata. They are checked only after the bytes match, and they can never establish identity.

### 3. Acquisition and provisioning

The prototype implements only local import from explicit file mappings listed in a qualification request. It contains no download code. Authenticated download is the right long-term direction for node and pnpm, because the repository already relies on their upstream identities: the Node image digest and the pnpm sha512. Each download source still needs a reviewed decision on how upstream checksums are authenticated, so it stops at this design boundary. For git there is no first-party upstream Linux binary. Choosing between a snapshot-archive package and a source build is a supply-chain decision that repository evidence does not settle.

### 4. Initial qualification

The operator writes a qualification request: tool id, files mapped from source paths to capsule paths and modes, entrypoint, invocation, environment, PATH entries, and the expected version output. The `qualify` command reads each source once, hashes it, runs the static ELF closure check on the same bytes, computes `treeSha256`, and writes the manifest atomically. It executes nothing. `materialize` later copies the sources, refuses if any source no longer matches the manifest digest, verifies the staged tree, runs the version probe from the staged capsule, and atomically renames it into place.

### 5. Manifest format

The manifest is canonical JSON: keys sorted recursively, two-space indentation, one final LF. The file bytes must equal the canonical re-serialization. It uses a closed schema with `schemaVersion: 1`, `kind: "boundaryci-toolchain-manifest"`, `platform: "linux-x64"`, and `tools` sorted by id. Each tool records `id`, `treeSha256`, `files` (sorted `path`, `sha256`, `size`, `mode`), `entrypoint`, `invocation`, `environment`, `pathEntries`, `version`, and `qualification`. The `qualification` field holds informational source paths and a date, and it is excluded from the identity so that moving a source does not change what executes.

### 6. Exact binary and hash binding

Every file in the closure is bound by SHA-256 and size. Files are opened with `O_NOFOLLOW`. The file descriptor's device and inode must equal the earlier `lstat`, and the size and modification time must be unchanged after reading. ELF closure facts are parsed from the same buffer that was hashed. `treeSha256` binds the file set, the invocation, the environment, and the version expectation, so changing any of them is a new identity.

### 7. Executable path binding

The executable path is always `realpath(store)/<tool>/<treeSha256>/<entrypoint>`. Callers cannot supply a path. Manifest paths must be portable relative paths without `.`, `..`, empty, or absolute segments. The entrypoint, loader, and script must be listed files. `PATH` for the child is only the declared capsule directories.

### 8. Ownership, mode, symlinks, and hard links

Every capsule entry is checked with `lstat` and never followed:

- directories must be exactly mode `0555`;
- files must be regular, with the exact declared mode (`0555` or `0444`) and link count 1;
- the owner must be root or the invoking user, or only root under the `root-only` policy;
- the capsule must contain exactly the manifest's files and the directories they imply, so a planted library or helper is rejected.

The closed tree is load-bearing. A real loader trace shows that glibc probes `lib/glibc-hwcaps/x86-64-v4`, `v3`, and `v2` inside the library path before `lib` itself. Any unlisted directory, even an empty one, is refused.

The store root, the per-tool directory, and every ancestor must be real directories (no symlinked component), owned by root or the invoking user, and not group- or world-writable, unless they are root-owned sticky directories such as `/tmp`. Write-protection bits do not stop an owner who can `chmod`. That is why the `root-only` policy exists for hosts where the store is provisioned by an administrator.

### 9. Update and requalification

1. `drift` reports that a qualification source changed. This is informational only.
2. The operator decides to adopt newer bytes, for example for a security fix.
3. `qualify --replace-manifest-sha256 <current>` writes the new identity and prints the old and new tree identities.
4. The manifest change is reviewed and committed.
5. `materialize` creates the new capsule beside the old one.

Without the exact current digest, qualification refuses with `toolchain/requalify-requires-explicit-replace` or `toolchain/requalify-base-mismatch`.

### 10. Offline and reproducible operation

`verify` and `run` are fully offline and deterministic for a given manifest and store. `materialize` is offline from local sources. Only a future, separate acquisition step would use the network. The child environment is closed, so proxy variables and `LD_*` variables are not inherited.

### 11. CI behavior

CI is unchanged in this prototype. Host import cannot reproduce a capsule on ephemeral runners whose packages differ, so CI adoption depends on authenticated download (section 3). Until then CI must not claim frozen-toolchain evidence. The capsule test suite itself runs in CI with synthetic static ELF fixtures on Linux x64.

### 12. Developer machines

A developer runs `qualify` once from a reviewed request, or uses a committed manifest, then runs `materialize` into a store under their data directory. Host updates do not invalidate that store. Linux x64 is the only platform. Other platforms fail with `toolchain/platform` rather than falling back to host tools.

### 13. Interaction with OS security updates

Host updates continue to protect everything else on the host. They do not change the capsule. The cost is that a security fix reaches frozen work only through requalification. `drift` makes that gap visible and never closes it silently. Because git only touches BoundaryCI's own checkout, lagging a patch release is a bounded, reviewable risk rather than a silent one.

### 14. Rollback

Capsules are content-addressed and never overwritten, so the previous identity stays in the store. Rollback means reverting the manifest commit. If the old capsule is still materialized, it verifies immediately. Because host sources may already have changed, the materialized capsule is the only retained copy of host-imported bytes, so stores should be backed up until authenticated acquisition exists. Garbage collection is not implemented. `drift` lists stale capsules but never deletes them.

### 15. Supply-chain risks

- **Qualification imports whatever bytes the operator points at.** Review covers the request and the digests, not the provenance of the bytes. That is why qualification records source paths, and why authenticated acquisition is the recommended next step.
- **The verifier is first-party code that uses only Node built-ins.** It adds no dependencies and changes no lockfile.
- **No binary is committed, and nothing is downloaded.**
- **The capsule removes one supply-chain risk:** a compromised host package update cannot reach frozen work without passing review.

### 16. Vendoring binaries in Git

Unacceptable:

- Binaries cannot be reviewed meaningfully.
- They bloat history permanently, and a compromised binary cannot be removed from history.
- They carry redistribution obligations (git is GPL-2.0).
- They conflict with the deny-by-default Docker context.
- They would fail the canonical gate, which decodes every tracked file as strict UTF-8.

### 17. Downloading and authenticating packages

Yes, as the target state for node and pnpm, with digests recorded in the manifest and authenticated before materialization. Never as a fallback during frozen execution. Implementing it requires per-source decisions about upstream signatures that are outside this prototype.

### 18. Separating approved identity from installed location

Yes. This is the core of the design. Identity is `treeSha256` in the reviewed manifest. Location is derived from that identity and has no authority. A changed file at any location is a verification failure, never a new identity.

### 19. Not silently trusting a changed host executable

- `run` and `verify` never read host tool paths or `PATH`.
- The loader is forced to use only capsule libraries.
- The capsule tree is closed against extra files.
- There is no verification cache.
- Qualification needs an explicit compare-and-swap digest.
- `drift` only reports.

## Runtime subprocess channels

The ELF closure binds what is loaded. It does not bind what a verified tool chooses to execute later. Validation against the real Ubuntu git showed:

- **No hardening.** Even with a complete closure, git executed a host program named by repository-local `core.fsmonitor`. It also ran an explicitly invoked `!` alias through its compiled-in `/bin/sh`.
- **With the environment overrides in [the example request](examples/git-ubuntu-noble.request.json).** That request sets `GIT_CONFIG_COUNT` overrides for `core.fsmonitor`, `core.hooksPath`, `core.sshCommand`, `protocol.allow`, and `credential.helper`, plus `GIT_TERMINAL_PROMPT=0`. The fsmonitor channel was closed. An explicitly invoked shell alias still reached host `/bin/sh`, but only through the shell with a capsule-only `PATH`.

Git never lets an alias shadow a builtin, so the fixed plumbing commands BoundaryCI needs cannot reach that path. Integration must therefore:

- use the hardened git environment;
- invoke only a fixed allowlist of builtin subcommands through a git-specific wrapper;
- never forward a caller environment that can re-enable configuration, such as `GIT_CONFIG_PARAMETERS`.

## Operator workflow

```sh
node tools/toolchain/cli.mjs qualify --manifest MANIFEST --request tools/toolchain/examples/git-ubuntu-noble.request.json
# review and commit MANIFEST; later requalification adds --replace-manifest-sha256 CURRENT_DIGEST
node tools/toolchain/cli.mjs materialize --manifest MANIFEST --store STORE --tool git --manifest-sha256 PINNED
node tools/toolchain/cli.mjs verify --manifest MANIFEST --store STORE --probe --manifest-sha256 PINNED
node tools/toolchain/cli.mjs run --manifest MANIFEST --store STORE --tool git --manifest-sha256 PINNED -- rev-parse HEAD
node tools/toolchain/cli.mjs drift --manifest MANIFEST --store STORE
```

The example request names host paths only. It records no digest and grants no trust until a reviewer approves the resulting manifest.

## Validation on a real host

On Ubuntu 24.04 (`git 1:2.43.0-1ubuntu7.4`), the example request produced a five-file capsule:

- `git` itself;
- `ld-linux-x86-64.so.2`;
- `libc.so.6`, `libz.so.1`, and `libpcre2-8.so.0`.

Results:

- `rev-parse HEAD` and `ls-files` through the capsule matched the host git output exactly.
- An `LD_DEBUG=libs` trace showed every library resolved and initialized from the capsule only.
- A command that needs a `git-core` helper (`remote-https`) failed instead of falling back to the host helper.

The resulting manifest is not committed. Whether BoundaryCI should trust those distribution bytes is exactly the review decision the design reserves.

## Failure codes

- Command line and platform: `toolchain/usage`, `toolchain/platform`.
- Manifest: `toolchain/manifest-read`, `toolchain/manifest-digest-mismatch`, `toolchain/manifest-noncanonical`, `toolchain/manifest-schema`, `toolchain/manifest-path`, `toolchain/manifest-tree-mismatch`, `toolchain/closure`, `toolchain/unknown-tool`.
- Store and capsule tree: `toolchain/store-unsafe`, `toolchain/not-materialized`, `toolchain/dir-unsafe`, `toolchain/file-type`, `toolchain/file-hardlink`, `toolchain/file-mode`, `toolchain/file-owner`, `toolchain/file-size`, `toolchain/file-digest`, `toolchain/file-changed`, `toolchain/file-missing`, `toolchain/unexpected-file`.
- Execution: `toolchain/env-forbidden`, `toolchain/spawn`, `toolchain/version-mismatch`, `toolchain/changed-during-run`.
- Qualification and materialization: `toolchain/request-schema`, `toolchain/source-missing`, `toolchain/source-drift`, `toolchain/capsule-conflict`, `toolchain/requalify-requires-explicit-replace`, `toolchain/requalify-base-mismatch`, `toolchain/requalify-dependent`.

## Integration boundary

These steps are deliberately left for separate review:

- routing `verify-release.mjs` git calls through the runner, behind a fixed-subcommand git wrapper;
- any CI change;
- authenticated acquisition;
- garbage collection.

Each one changes either the release-acceptance gate or the supply chain.
