# BoundaryCI Cloud Experiment Contract

This checkout is an isolated experimental hardening environment for BoundaryCI.

The private project checkout, private planning state, and unpublished benchmark work are intentionally NOT available here. There is no `.planning/` directory by design. Do not request it, reconstruct it, or infer unpublished decisions from its absence.

## Authority

Treat the committed BoundaryCI v1 source, tests, and public documentation in this repository as the only product authority available to this experiment.

The released-v1 commit used as the experimental baseline is:

`4d00b78aafbf1b0faccaceaec97b876ec5c1757a`

## Prohibited scope expansion

Do not:

- expand the production permission catalog;
- add supported GitHub operations;
- broaden analyzer grammar or provenance semantics;
- add wrappers/interprocedural analysis;
- add GraphQL, new languages, or new client families;
- build hosted/cloud/deployment infrastructure;
- add telemetry, accounts, databases, queues, dashboards, or billing;
- use unpublished benchmark/corpus data;
- search for or acquire third-party benchmark repositories;
- change behavior simply to make a test pass;
- weaken fail-closed behavior;
- weaken security/provenance checks.

Unsupported behavior must remain unsupported rather than being guessed.

## Experimental work allowed

The current `cloud-tasks/TASK-*.md` file defines the authorized experiment.

Security hardening, regression tests, property tests, deterministic fuzz-style testing, failure injection, and narrow fixes to confirmed bugs inside existing v1 semantics are allowed.

## Work preservation

Never leave substantial work only in the conversation.

Work in bounded slices.

For each coherent slice:

1. inspect the relevant code;
2. add or modify tests;
3. run focused validation;
4. inspect the diff;
5. commit the passing slice.

Do not wait until the end to make one giant commit.

For a confirmed defect, prefer:

`failing regression test → minimal fix → passing tests → commit`

Do not combine unrelated fixes in one commit.

## Safety

Use synthetic or first-party fixtures only.

Do not use real credentials.

Do not make destructive GitHub requests.

Do not publish Checks into third-party repositories.

Do not execute untrusted third-party source.

Do not change `main`.

Do not merge the experimental branch.

## Final validation

Before finishing:

- run relevant focused tests;
- run the complete repository test suite when feasible;
- run typecheck;
- run lint;
- run formatting checks;
- inspect the actual diff.

Clearly distinguish:

- confirmed defect;
- hardening opportunity;
- unsupported-by-design behavior;
- speculative concern;
- experimental prototype.

A useful negative audit result is acceptable. Do not invent defects to justify the task.