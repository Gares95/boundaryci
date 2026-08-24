import { canonicalJson, digestJson } from './artifact-sources.js';
import type { JsonValue } from './contracts.js';

export type PermissionLevel = 'read' | 'write';

export type RequirementExpression =
  | { type: 'permission'; permission: string; level: PermissionLevel }
  | { type: 'allOf'; requirements: RequirementExpression[] }
  | { type: 'anyOf'; requirements: RequirementExpression[] };

export type PermissionEvidenceIncompleteReason =
  | 'conflicting-permission-atom'
  | 'credential-class-missing'
  | 'duplicate-permission-atom'
  | 'empty-alternative'
  | 'empty-expression'
  | 'malformed-atom'
  | 'operation-missing'
  | 'unknown-access-level'
  | 'unknown-permission'
  | 'unsupported-qualifier';

export interface PermissionEvidenceInput {
  raw: string;
  operationId?: string;
  credentialClass?: string;
  vocabulary: ReadonlySet<string>;
}

export interface ResolvedPermissionEvidence {
  status: 'resolved';
  raw: string;
  sourceOrder: string[][];
  expression: RequirementExpression;
  normalizedJson: string;
  expressionSha256: string;
}

export interface IncompletePermissionEvidence {
  status: 'incomplete';
  raw: string;
  reason: PermissionEvidenceIncompleteReason;
}

export type PermissionEvidenceParseResult = ResolvedPermissionEvidence | IncompletePermissionEvidence;

function incomplete(raw: string, reason: PermissionEvidenceIncompleteReason): IncompletePermissionEvidence {
  return { status: 'incomplete', raw, reason };
}

function compareCanonicalBytes(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function canonicalExpression(expression: RequirementExpression): RequirementExpression {
  if (expression.type === 'permission') return { ...expression };
  const requirements = expression.requirements.map(canonicalExpression);
  requirements.sort((left, right) =>
    compareCanonicalBytes(
      canonicalJson(left as unknown as JsonValue),
      canonicalJson(right as unknown as JsonValue),
    ),
  );
  return { type: expression.type, requirements };
}

export function expressionJson(expression: RequirementExpression): string {
  return canonicalJson(canonicalExpression(expression) as unknown as JsonValue);
}

export function expressionDigest(expression: RequirementExpression): string {
  return digestJson(canonicalExpression(expression) as unknown as JsonValue);
}

export function parsePermissionEvidence(input: PermissionEvidenceInput): PermissionEvidenceParseResult {
  const { raw } = input;
  if (input.operationId === undefined || input.operationId.length === 0) return incomplete(raw, 'operation-missing');
  if (input.credentialClass === undefined || input.credentialClass.length === 0) {
    return incomplete(raw, 'credential-class-missing');
  }
  if (raw.length === 0 || raw.trim().length === 0) return incomplete(raw, 'empty-expression');

  const alternatives = raw.split(';');
  if (alternatives.some((alternative) => alternative.trim().length === 0)) {
    return incomplete(raw, 'empty-alternative');
  }

  const sourceOrder: string[][] = [];
  const groups: RequirementExpression[] = [];
  const seen = new Map<string, PermissionLevel>();
  for (const alternative of alternatives) {
    const rawAtoms = alternative.split(',');
    if (rawAtoms.some((atom) => atom.trim().length === 0)) return incomplete(raw, 'malformed-atom');
    const atoms: RequirementExpression[] = [];
    const ordered: string[] = [];
    for (const rawAtom of rawAtoms) {
      const atom = rawAtom.trim();
      ordered.push(atom);
      if (/[[\]{}()]/u.test(atom) || atom.includes(':')) return incomplete(raw, 'unsupported-qualifier');
      const split = /^([a-z][a-z0-9_]*)=([a-z]+)$/u.exec(atom);
      if (split === null || split[1] === undefined || split[2] === undefined) {
        return incomplete(raw, 'malformed-atom');
      }
      const permission = split[1];
      const level = split[2];
      if (level !== 'read' && level !== 'write') return incomplete(raw, 'unknown-access-level');
      if (!input.vocabulary.has(permission)) return incomplete(raw, 'unknown-permission');
      const prior = seen.get(permission);
      if (prior === level) return incomplete(raw, 'duplicate-permission-atom');
      if (prior !== undefined) return incomplete(raw, 'conflicting-permission-atom');
      seen.set(permission, level);
      atoms.push({ type: 'permission', permission, level });
    }
    sourceOrder.push(ordered);
    if (atoms.length === 1 && atoms[0] !== undefined) groups.push(atoms[0]);
    else groups.push({ type: 'allOf', requirements: atoms });
  }

  const expression: RequirementExpression =
    groups.length === 1 && groups[0] !== undefined ? groups[0] : { type: 'anyOf', requirements: groups };
  const normalized = canonicalExpression(expression);
  return {
    status: 'resolved',
    raw,
    sourceOrder,
    expression: normalized,
    normalizedJson: canonicalJson(normalized as unknown as JsonValue),
    expressionSha256: digestJson(normalized as unknown as JsonValue),
  };
}

export function validateRequirementExpression(value: unknown): asserts value is RequirementExpression {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new TypeError('requirement expression must be an object');
  }
  const record = value as Record<string, unknown>;
  if (record.type === 'permission') {
    if (
      Object.keys(record).sort().join(',') !== 'level,permission,type' ||
      typeof record.permission !== 'string' ||
      !['read', 'write'].includes(String(record.level))
    ) {
      throw new TypeError('permission atom is invalid');
    }
    return;
  }
  if (record.type !== 'allOf' && record.type !== 'anyOf') throw new TypeError('expression type is invalid');
  if (Object.keys(record).sort().join(',') !== 'requirements,type' || !Array.isArray(record.requirements)) {
    throw new TypeError('expression group is invalid');
  }
  if (record.requirements.length < 2) throw new TypeError('expression group must contain at least two requirements');
  for (const child of record.requirements) validateRequirementExpression(child);
  const normalized = canonicalExpression(value as RequirementExpression);
  if (canonicalJson(value as unknown as JsonValue) !== canonicalJson(normalized as unknown as JsonValue)) {
    throw new TypeError('expression group is not in canonical order');
  }
  const atoms: { permission: string; level: PermissionLevel }[] = [];
  const visit = (entry: RequirementExpression): void => {
    if (entry.type === 'permission') atoms.push(entry);
    else entry.requirements.forEach(visit);
  };
  visit(value as RequirementExpression);
  const seen = new Map<string, PermissionLevel>();
  for (const atom of atoms) {
    const prior = seen.get(atom.permission);
    if (prior === atom.level) throw new TypeError('expression contains a duplicate permission atom');
    if (prior !== undefined) throw new TypeError('expression contains conflicting permission atoms');
    seen.set(atom.permission, atom.level);
  }
}
