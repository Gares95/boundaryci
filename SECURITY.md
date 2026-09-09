# Security policy

BoundaryCI analyzes untrusted repositories and can hold short-lived GitHub App credentials. Security reports are welcome and should not include production credentials, private repository source, or raw webhook payloads.

## Reporting a vulnerability

Use the repository's [private vulnerability reporting form](https://github.com/Gares95/boundaryci/security/advisories/new). Include affected versions, the security boundary involved, a minimal reproduction using synthetic input, and the expected impact. Do not open a public issue for an unpatched credential-exposure, signature-verification, path-traversal, target-execution, permission-inference, or repository-publication vulnerability.

Maintainers will acknowledge a complete report, investigate it privately, and coordinate remediation and disclosure through the advisory. Public feature requests and non-sensitive defects can use the normal issue tracker.

## Security boundaries

- Webhook requests reach delivery logic only after Probot verifies the signature against the original request bytes.
- Analyzer input is parsed as bounded source. BoundaryCI never installs target dependencies, imports target modules, builds target projects, runs target scripts, or executes target tests.
- GitHub acquisition uses exact commit, tree, and blob identities. Unsafe paths and malformed relationships fail closed; symlinks and gitlinks are not followed.
- Base and head use the same engine and catalog identity and the base-authoritative configuration.
- Permission requirements retain `permission`, `allOf`, `anyOf`, and unresolved semantics. Dynamic routes and unsupported comparisons are not guessed.
- Delivery uses separate repository-scoped read and Checks-write installation roles. Credential-bearing clients remain inside private adapters.
- Check publication revalidates the current pull-request identity immediately before mutation and stops on drift or duplicate identity.
- The production image is built from an immutable base-image digest and runs as a non-root user.

These controls reduce risk; they do not make BoundaryCI a sandbox for executing repository code or a certification service for perfect least privilege.

## Disclosure and retention

BoundaryCI's normal structured logs contain only allowlisted numeric identities, commit SHAs, stable lifecycle codes, bounded counts, durations, and non-secret correlation identity. They exclude source and configuration bytes, authorization headers, installation credentials, App private keys, webhook secrets, signatures, raw request or response bodies, and arbitrary external errors.

GitHub snapshot roots are private and temporary. They must be removed before a publication handoff, and no source snapshot or delivery envelope is retained by default. Demonstration and release evidence uses closed source-free schemas; it records only the identifiers, outcomes, counts, paths, and spans required to prove behavior.

Never commit environment overrides, key or certificate files, credentials, local workflow state, retained live proof, or private review material. If credential exposure is suspected, revoke or rotate it through GitHub before sharing a sanitized report.
