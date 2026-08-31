/**
 * Deterministic presentation adapters over Phase 4 runtime/domain results.
 *
 * This module never infers an operation, permission, comparison, or policy decision. It only
 * labels and serializes evidence the runtime already produced (D-03, D-09, D-15, D-17).
 */

import type { AnalysisResult, OperationObservation } from '../analyzer/contract.js';
import type { AuthoritativeConfigSelection } from '../config/load.js';
import type { RevisionComparison, RevisionPermissionChange } from '../diff/revision.js';
import type { RequirementFinding, SourceEvidence } from '../permission-model/model.js';
import type { PolicyDecision } from '../policy/evaluate.js';
import type { AnalyzeConfiguredSnapshotResult, LocalComparisonResult } from '../runtime/evaluate.js';

export const CLI_RESULT_SCHEMA_ID = 'boundaryci/cli-result';
export const CLI_RESULT_SCHEMA_VERSION = 1;

export type CommonOutcome =
  | 'complete'
  | 'incomplete'
  | 'policy-failure'
  | 'input-configuration-failure'
  | 'runtime-infrastructure-failure';

interface CliEnvelope {
  schemaId: typeof CLI_RESULT_SCHEMA_ID;
  schemaVersion: typeof CLI_RESULT_SCHEMA_VERSION;
}

type SelectedComparison = Extract<LocalComparisonResult, { status: 'selected' }>;
type ConfigurationFailure = Extract<AuthoritativeConfigSelection, { status: 'input-configuration-failure' }>;

export type DiffEvaluation =
  | ConfigurationFailure
  | {
      status: 'selected';
      authority: SelectedComparison['authority'];
      head: SelectedComparison['head'];
      comparison: RevisionComparison;
    };

export type CliResult =
  | (CliEnvelope & {
      command: 'analyze';
      outcome: Exclude<CommonOutcome, 'policy-failure'>;
      evaluation: AnalyzeConfiguredSnapshotResult;
    })
  | (CliEnvelope & { command: 'diff'; outcome: Exclude<CommonOutcome, 'policy-failure'>; evaluation: DiffEvaluation })
  | (CliEnvelope & { command: 'check'; outcome: CommonOutcome; evaluation: LocalComparisonResult });

function clone<T>(value: T): T {
  return structuredClone(value);
}

/** Normalizes one configured single-root result without altering its domain status or evidence. */
export function normalizeAnalyzeResult(result: AnalyzeConfiguredSnapshotResult): Extract<CliResult, { command: 'analyze' }> {
  return {
    schemaId: CLI_RESULT_SCHEMA_ID,
    schemaVersion: CLI_RESULT_SCHEMA_VERSION,
    command: 'analyze',
    outcome: result.status,
    evaluation: clone(result),
  };
}

function comparisonOutcome(comparison: RevisionComparison): Exclude<CommonOutcome, 'policy-failure'> {
  return comparison.status;
}

/** Normalizes a comparison for `diff` or `check`; only `check` retains and applies policy. */
export function normalizeComparisonResult(
  command: 'diff' | 'check',
  result: LocalComparisonResult,
): Extract<CliResult, { command: typeof command }> {
  if (result.status === 'input-configuration-failure') {
    return {
      schemaId: CLI_RESULT_SCHEMA_ID,
      schemaVersion: CLI_RESULT_SCHEMA_VERSION,
      command,
      outcome: 'input-configuration-failure',
      evaluation: clone(result),
    } as Extract<CliResult, { command: typeof command }>;
  }

  if (command === 'diff') {
    const evaluation: DiffEvaluation = clone({
      status: 'selected',
      authority: result.authority,
      head: result.head,
      comparison: result.comparison,
    });
    return {
      schemaId: CLI_RESULT_SCHEMA_ID,
      schemaVersion: CLI_RESULT_SCHEMA_VERSION,
      command,
      outcome: comparisonOutcome(result.comparison),
      evaluation,
    } as Extract<CliResult, { command: typeof command }>;
  }

  return {
    schemaId: CLI_RESULT_SCHEMA_ID,
    schemaVersion: CLI_RESULT_SCHEMA_VERSION,
    command,
    outcome: result.policy.outcome,
    evaluation: clone(result),
  } as Extract<CliResult, { command: typeof command }>;
}

type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

function canonicalize(value: JsonValue): JsonValue {
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map((entry) => canonicalize(entry));
  const ordered: { [key: string]: JsonValue } = {};
  for (const key of Object.keys(value).sort()) ordered[key] = canonicalize(value[key] as JsonValue);
  return ordered;
}

/** Renders one canonical, versioned JSON document and trailing newline. */
export function renderJson(result: CliResult): string {
  return `${JSON.stringify(canonicalize(result as unknown as JsonValue), null, 2)}\n`;
}

function span(source: SourceEvidence): string {
  const { start, end } = source.span;
  return `${source.path}:${start.line}:${start.column}-${end.line}:${end.column}`;
}

function operationLine(operation: OperationObservation, prefix: string): string {
  return `${prefix} ${operation.operation.method} ${operation.operation.normalizedRoute} (${operation.operation.operationId}) source=${span(operation.source)} optional=${String(operation.optional)}`;
}

function findingLine(finding: RequirementFinding, prefix: string): string {
  if (finding.operation === null || finding.source === null) return `${prefix} finding=${finding.status}`;
  return `${prefix} finding=${finding.status} ${finding.operation.method} ${finding.operation.normalizedRoute} (${finding.operation.operationId}) source=${span(finding.source)}`;
}

function renderAnalysisEvidence(lines: string[], result: AnalysisResult, prefix: string): void {
  lines.push(`${prefix} analysis=${result.status}`);
  if (result.status === 'failed') {
    lines.push(`${prefix} failure=${result.reason}`);
    for (const cause of result.causes) lines.push(`${prefix} cause=${cause.code}`);
    return;
  }
  lines.push(`${prefix} operations=${result.observations.length} permission-resolutions=${result.permissionResolutions.length} causes=${result.causes.length}`);
  for (const observation of result.observations) lines.push(operationLine(observation, `${prefix} operation`));
  for (const resolution of result.permissionResolutions) {
    lines.push(findingLine(resolution.finding, `${prefix} permission-resolution`));
  }
  if (result.permissionBoundary.status === 'complete') {
    for (const permission of result.permissionBoundary.permissions) {
      lines.push(
        `${prefix} observed-permission=${permission.permission}:${permission.level} contributors=${permission.contributors.length}`,
      );
    }
  } else {
    lines.push(`${prefix} permission-boundary=incomplete reasons=${result.permissionBoundary.reasons.join(',')}`);
  }
  for (const cause of result.causes) lines.push(`${prefix} cause=${cause.code}`);
}

function renderChange(lines: string[], change: RevisionPermissionChange, qualifier: string): void {
  lines.push(
    `${qualifier} permission=${change.permission} base=${change.base} head=${change.head} direction=${change.change} base-contributors=${change.baseContributors.length} head-contributors=${change.headContributors.length}`,
  );
  for (const finding of change.baseContributors) lines.push(findingLine(finding, `${qualifier} base-contributor`));
  for (const finding of change.headContributors) lines.push(findingLine(finding, `${qualifier} head-contributor`));
}

function renderComparison(lines: string[], comparison: RevisionComparison): void {
  lines.push(`comparison: ${comparison.status}`);
  if (comparison.status === 'complete') {
    lines.push(`changes: ${comparison.changes.length}`);
    for (const change of comparison.changes) renderChange(lines, change, 'change');
  } else if (comparison.status === 'incomplete') {
    lines.push(`reasons: ${comparison.reasons.join(',') || 'none'}`);
    lines.push(
      `uncertainty: introduced=${comparison.uncertainty.introduced.length} resolved=${comparison.uncertainty.resolved.length} retained=${comparison.uncertainty.retained.length}`,
    );
    for (const cause of comparison.uncertainty.introduced) lines.push(`uncertainty introduced=${cause.code}`);
    for (const cause of comparison.uncertainty.resolved) lines.push(`uncertainty resolved=${cause.code}`);
    for (const pair of comparison.uncertainty.retained) lines.push(`uncertainty retained=${pair.head.code}`);
    for (const change of comparison.qualifiedChanges) renderChange(lines, change, `qualified-change basis=${change.basis}`);
  } else {
    lines.push(`reasons: ${comparison.reasons.join(',') || 'none'}`);
  }
  renderAnalysisEvidence(lines, comparison.base.result, 'base');
  renderAnalysisEvidence(lines, comparison.head.result, 'head');
}

function renderConfigFailure(lines: string[], failure: ConfigurationFailure): void {
  lines.push(`configuration: invalid-${failure.invalid}`);
  if ('authority' in failure) {
    lines.push(`authority: ${failure.authority.source} sha256=${failure.authority.identity}`);
  }
  for (const diagnostic of failure.diagnostics) lines.push(`diagnostic: ${diagnostic.code} ${diagnostic.detail}`);
}

function renderSelectedConfig(
  lines: string[],
  selected: Pick<SelectedComparison, 'authority' | 'head'>,
): void {
  lines.push(`authority: ${selected.authority.source} sha256=${selected.authority.identity}`);
  if (selected.head.status === 'absent') lines.push('prospective-head: absent');
  else lines.push(`prospective-head: ${selected.head.change} sha256=${selected.head.identity}`);
  for (const declaration of selected.authority.config.declaredExpectedPermissions) {
    lines.push(`declared-permission: ${declaration.permission}=${declaration.level} (declared, not observed or live)`);
  }
}

function renderPolicy(lines: string[], policy: PolicyDecision): void {
  lines.push(`check: ${policy.check}`);
  lines.push(
    `policy: failOnExpansion=${String(policy.policy.failOnExpansion)} failOnIncomplete=${String(policy.policy.failOnIncomplete)} reasons=${policy.reasons.join(',') || 'none'}`,
  );
}

/** Renders concise deterministic text while retaining material evidence and uncertainty. */
export function renderHuman(result: CliResult): string {
  const lines = [`BoundaryCI ${result.command}`, `outcome: ${result.outcome}`];

  if (result.command === 'analyze') {
    const evaluation = result.evaluation;
    if (evaluation.status === 'complete' || evaluation.status === 'incomplete') {
      lines.push(`authority: ${evaluation.authority.source} sha256=${evaluation.authority.identity}`);
      for (const declaration of evaluation.declaredExpectedPermissions) {
        lines.push(`declared-permission: ${declaration.permission}=${declaration.level} (declared, not observed or live)`);
      }
      renderAnalysisEvidence(lines, evaluation.analysis.result, 'snapshot');
    } else if (evaluation.status === 'input-configuration-failure' && evaluation.stage === 'configuration') {
      for (const diagnostic of evaluation.diagnostics) lines.push(`diagnostic: ${diagnostic.code} ${diagnostic.detail}`);
    } else {
      lines.push(`failure: ${evaluation.reason}`);
      for (const cause of evaluation.causes) lines.push(`cause=${cause.code}`);
    }
    return `${lines.join('\n')}\n`;
  }

  const evaluation = result.evaluation;
  if (evaluation.status === 'input-configuration-failure') {
    renderConfigFailure(lines, evaluation);
    return `${lines.join('\n')}\n`;
  }

  renderSelectedConfig(lines, evaluation);
  renderComparison(lines, evaluation.comparison);
  if (result.command === 'check' && result.evaluation.status === 'selected') {
    renderPolicy(lines, result.evaluation.policy);
  }
  return `${lines.join('\n')}\n`;
}
