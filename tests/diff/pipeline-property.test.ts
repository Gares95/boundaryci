import { afterEach, describe, expect, it } from 'vitest';

import { evaluateLocalComparison, type LocalComparisonResult } from '../../src/runtime/evaluate.js';
import { cleanupTempRoots, createTempRoot, writeRegularFile } from '../analyzer/helpers.js';

/**
 * Deterministic end-to-end property test of analysis -> comparison -> policy (TASK-2
 * comparison/policy tranche). Seeded random base and head repositories are assembled from a
 * finite statement menu whose permission meaning is known independently of BoundaryCI, and an
 * independent oracle predicts the only acceptable verdicts:
 *
 * - no incompleteness anywhere: the comparison is complete and the Issues change direction and
 *   policy verdict follow the none < read < write level model exactly;
 * - any incompleteness on either side: the result is never `complete` and, under the default
 *   base policy (`failOnIncomplete: true`), never passes — no false-clean pathway;
 * - a complete base plus a head write above the base level always keeps a visible expansion,
 *   even when the head is otherwise incomplete (known positive evidence is never dropped), and
 *   every qualified change names one of the documented qualification bases;
 * - re-splitting and reordering the same statements across differently named files yields the
 *   same verdicts (no ordering or file-identity dependence).
 */

type Statement = 'read' | 'write' | 'write-request' | 'catalog-gap' | 'dynamic-member' | 'detached-surface' | 'noise';

const STATEMENTS: Readonly<Record<Statement, string>> = {
  read: "client.rest.issues.listForRepo({ owner: 'o', repo: 'r' });",
  write: "client.rest.issues.create({ owner: 'o', repo: 'r', title: 't' });",
  'write-request': "client.request('POST /repos/{owner}/{repo}/issues', { owner: 'o', repo: 'r', title: 't' });",
  // A proven operation outside the two-row production catalog: a permission-lookup gap.
  'catalog-gap': "client.rest.issues.update({ owner: 'o', repo: 'r', issue_number: 1 });",
  'dynamic-member': "client.rest.issues[String(Date.now())]({});",
  'detached-surface': "const detached = client.rest.issues; detached.create({ owner: 'o', repo: 'r', title: 't' });",
  noise: "const unrelated = { rest: 1, request: 2 }; void unrelated;",
};

const INCOMPLETE: ReadonlySet<Statement> = new Set(['catalog-gap', 'dynamic-member', 'detached-surface']);
const MENU = Object.keys(STATEMENTS) as Statement[];
const LEVEL = { none: 0, read: 1, write: 2 } as const;
type Level = keyof typeof LEVEL;

function prng(seed: number): () => number {
  let state = seed >>> 0 || 1;
  return () => {
    state ^= state << 13;
    state >>>= 0;
    state ^= state >>> 17;
    state ^= state << 5;
    state >>>= 0;
    return state / 0x1_0000_0000;
  };
}

afterEach(async () => {
  await cleanupTempRoots();
});

function levelOf(statements: readonly Statement[]): Level {
  if (statements.includes('write') || statements.includes('write-request')) return 'write';
  return statements.includes('read') ? 'read' : 'none';
}

/** Writes the statements into 1-3 files; each file declares its own module-local client. */
async function materialize(statements: readonly Statement[], random: () => number): Promise<string> {
  const root = await createTempRoot('boundaryci-pipeline-property-');
  const fileCount = 1 + Math.floor(random() * 3);
  const files: Statement[][] = Array.from({ length: fileCount }, () => []);
  for (const statement of statements) files[Math.floor(random() * fileCount)]?.push(statement);
  await Promise.all(files.map(async (fileStatements, index) => {
    const name = `src/${random() < 0.5 ? 'z' : 'a'}${index}-${Math.floor(random() * 1_000)}.ts`;
    const body = fileStatements.map((statement, offset) =>
      // Block-scope every statement so repeated `const` names never collide.
      `{ // ${offset}\n  ${STATEMENTS[statement]}\n}`).join('\n');
    await writeRegularFile(root, name, `import { Octokit } from 'octokit';\nconst client = new Octokit();\n${body}\n`);
  }));
  return root;
}

const QUALIFIED_BASES: ReadonlySet<string> = new Set([
  'complete-base-boundary-and-known-head-floor',
  'complete-boundaries',
  'complete-head-boundary-and-known-base-floor',
]);

function verdict(result: LocalComparisonResult): { outcome: string; check: string; directions: string[]; bases: string[] } {
  if (result.status !== 'selected') throw new Error(`unexpected ${result.status}`);
  const { comparison, policy } = result;
  const changes = comparison.status === 'complete'
    ? comparison.changes
    : comparison.status === 'incomplete' ? comparison.qualifiedChanges : [];
  return {
    outcome: policy.outcome,
    check: policy.check,
    directions: changes.map((change) => `${change.permission}:${change.base}->${change.head}:${change.change}`).sort(),
    bases: comparison.status === 'incomplete' ? comparison.qualifiedChanges.map((change) => change.basis).sort() : [],
  };
}

function randomRevision(random: () => number): Statement[] {
  const count = Math.floor(random() * 5);
  return Array.from({ length: count }, () => MENU[Math.floor(random() * MENU.length)] as Statement);
}

describe('analysis -> comparison -> policy properties', () => {
  it('matches the independent oracle and never produces a false-clean verdict', async () => {
    const random = prng(0x0b0d_2026);
    const seen = { complete: 0, incomplete: 0, expansion: 0, reduction: 0 };
    for (let trial = 0; trial < 60; trial += 1) {
      const base = randomRevision(random);
      const head = randomRevision(random);
      const result = await evaluateLocalComparison(await materialize(base, random), await materialize(head, random));
      const observed = verdict(result);
      const label = JSON.stringify({ trial, base, head, observed });
      const incomplete = [...base, ...head].some((statement) => INCOMPLETE.has(statement));
      const baseLevel = levelOf(base);
      const headLevel = levelOf(head);

      if (!incomplete) {
        seen.complete += 1;
        const expected: string[] = [];
        if (baseLevel !== 'none' || headLevel !== 'none') {
          const change = LEVEL[headLevel] > LEVEL[baseLevel] ? 'expansion' : LEVEL[headLevel] < LEVEL[baseLevel] ? 'reduction' : 'unchanged';
          if (change === 'expansion') seen.expansion += 1;
          if (change === 'reduction') seen.reduction += 1;
          expected.push(`issues:${baseLevel}->${headLevel}:${change}`);
        }
        const expansion = LEVEL[headLevel] > LEVEL[baseLevel];
        expect({ label, outcome: observed.outcome, check: observed.check, directions: observed.directions }).toEqual({
          label,
          outcome: expansion ? 'policy-failure' : 'complete',
          check: expansion ? 'fail' : 'pass',
          directions: expected,
        });
        continue;
      }

      seen.incomplete += 1;
      expect({ label, complete: observed.outcome === 'complete', check: observed.check }).toEqual({ label, complete: false, check: 'fail' });
      const baseComplete = !base.some((statement) => INCOMPLETE.has(statement));
      if (baseComplete && headLevel === 'write' && baseLevel !== 'write') {
        expect({ label, directions: observed.directions }).toEqual({ label, directions: [`issues:${baseLevel}->write:expansion`] });
      }
      // Released v1 deliberately keeps `complete-boundaries` qualified changes (every direction)
      // when both permission boundaries are complete but an analysis is incomplete; see the
      // TASK-2 report's operator decision. What must always hold is that each qualified change
      // carries one of the documented bases and that the verdict never passes.
      expect({ label, bases: observed.bases.every((basis) => QUALIFIED_BASES.has(basis)) }).toEqual({ label, bases: true });
    }
    // The generator must exercise every regime for the property to mean anything.
    expect(seen.complete).toBeGreaterThan(5);
    expect(seen.incomplete).toBeGreaterThan(15);
    expect(seen.expansion).toBeGreaterThan(1);
    expect(seen.reduction).toBeGreaterThan(1);
  }, 120_000);

  it('gives identical verdicts when the same statements are re-split across other files', async () => {
    const random = prng(0x5011_d1ff);
    for (let trial = 0; trial < 15; trial += 1) {
      const base = randomRevision(random);
      const head = randomRevision(random);
      const first = verdict(await evaluateLocalComparison(await materialize(base, random), await materialize(head, random)));
      const shuffle = (statements: Statement[]): Statement[] => [...statements].sort(() => random() - 0.5);
      const second = verdict(await evaluateLocalComparison(await materialize(shuffle(base), random), await materialize(shuffle(head), random)));
      expect({ base, head, verdict: second }).toEqual({ base, head, verdict: first });
    }
  }, 120_000);

  it('characterizes the v1 qualified complete-boundaries reduction left for an operator decision', async () => {
    // Base proves an Issues write; head only contains unresolved dynamic Issues calls, which
    // could themselves be writes. v1 keeps a qualified `write -> none` reduction on the
    // `complete-boundaries` basis while the comparison stays incomplete and policy fails.
    const random = prng(1);
    const result = await evaluateLocalComparison(
      await materialize(['write'], random),
      await materialize(['dynamic-member'], random),
    );
    expect(verdict(result)).toEqual({
      outcome: 'policy-failure',
      check: 'fail',
      directions: ['issues:write->none:reduction'],
      bases: ['complete-boundaries'],
    });
  });
});
