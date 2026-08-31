/**
 * Version-1 effective repository configuration and its canonical identity.
 *
 * This module defines only the immutable built-in default. Loading, validating, and merging
 * an actual `.boundaryci.yml` is Plan 04-02 work; nothing here reads a file.
 */

import { createHash } from 'node:crypto';

import { ANALYZER_SOURCE_EXTENSIONS, DEFAULT_ANALYSIS_LIMITS } from '../analyzer/contract.js';
import type { AnalysisLimits } from '../analyzer/contract.js';
import type { PermissionLevel } from '../permission-model/model.js';

/** Version of the effective-configuration shape. Any incompatible shape change increments this. */
export const BOUNDARYCI_CONFIG_SCHEMA_VERSION = 1;

/** A repository-declared expected permission label; never live installed-App or source state (D-15). */
export interface ExpectedPermissionDeclaration {
  permission: string;
  level: PermissionLevel;
}

/** The one authoritative configuration a comparison runs under (D-11, D-12). */
export interface EffectiveConfig {
  schemaVersion: number;
  include: string[];
  exclude: string[];
  probotEntrypoints: string[];
  limits: AnalysisLimits;
  failOnExpansion: boolean;
  failOnIncomplete: boolean;
  expectedPermissions: ExpectedPermissionDeclaration[];
}

/** Dependency and generated-output paths the built-in default excludes from analysis. */
const BUILTIN_EXCLUDES: readonly string[] = Object.freeze(['**/node_modules/**', '**/dist/**', '**/build/**']);

function sourceExtensionIncludes(): string[] {
  return ANALYZER_SOURCE_EXTENSIONS.map((extension) => `**/*${extension}`);
}

/**
 * The immutable built-in default selected when no `.boundaryci.yml` governs a comparison.
 *
 * It uses every Phase 3 source extension, excludes dependency and generated-output paths,
 * declares no Probot entrypoints, uses the Phase 3 default resource limits, fails closed on
 * both expansion and incompleteness, and declares no expected permissions.
 */
export const BUILTIN_CONFIG: Readonly<EffectiveConfig> = Object.freeze({
  schemaVersion: BOUNDARYCI_CONFIG_SCHEMA_VERSION,
  include: Object.freeze(sourceExtensionIncludes()) as string[],
  exclude: Object.freeze([...BUILTIN_EXCLUDES]) as string[],
  probotEntrypoints: Object.freeze([] as string[]) as string[],
  limits: Object.freeze({ ...DEFAULT_ANALYSIS_LIMITS }) as AnalysisLimits,
  failOnExpansion: true,
  failOnIncomplete: true,
  expectedPermissions: Object.freeze([] as ExpectedPermissionDeclaration[]) as ExpectedPermissionDeclaration[],
});

type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

function canonicalJson(value: JsonValue): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((entry) => canonicalJson(entry)).join(',')}]`;
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key] as JsonValue)}`)
    .join(',')}}`;
}

/**
 * The semantic configuration identity: a SHA-256 over the canonical key-sorted JSON
 * representation of `config`. This is an identity of what the configuration means, not a
 * digest of any source file.
 */
export function effectiveConfigIdentity(config: EffectiveConfig): string {
  return createHash('sha256').update(canonicalJson(config as unknown as JsonValue), 'utf8').digest('hex');
}
