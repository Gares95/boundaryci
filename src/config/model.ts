/**
 * Version-1 effective repository configuration, its strict external grammar, and its
 * canonical identity.
 *
 * `validateConfigValue` and `normalizeEffectiveConfig` never read a file: `src/config/load.ts`
 * owns turning an actual `.boundaryci.yml` into trusted generic JS before either function runs.
 */

import { createHash } from 'node:crypto';

import { compileLimitedGlob } from '../analyzer/discovery.js';
import { ANALYZER_SOURCE_EXTENSIONS, DEFAULT_ANALYSIS_LIMITS } from '../analyzer/contract.js';
import type { AnalysisLimits } from '../analyzer/contract.js';
import type { PermissionLevel } from '../permission-model/model.js';

/** Version of the effective-configuration shape. Any incompatible shape change increments this. */
export const BOUNDARYCI_CONFIG_SCHEMA_VERSION = 1;

/** The one supported value of the external document's required `version` key. */
export const BOUNDARYCI_CONFIG_DOCUMENT_VERSION = 1;

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
  declaredExpectedPermissions: ExpectedPermissionDeclaration[];
}

/** The identity of one normalized {@link EffectiveConfig}: a lowercase hex SHA-256. */
export type ConfigIdentity = string;

/** Optional `analysis.limits` fields of the external schema-version-1 document. */
export interface BoundaryCiAnalysisLimitsInput {
  maxSourceFiles?: number;
  maxSourceFileBytes?: number;
  maxTotalSourceBytes?: number;
  maxSourceWork?: number;
}

/** Optional `analysis` fields of the external schema-version-1 document. */
export interface BoundaryCiAnalysisInput {
  include?: string[];
  exclude?: string[];
  probotEntrypoints?: string[];
  limits?: BoundaryCiAnalysisLimitsInput;
}

/** Optional `policy` fields of the external schema-version-1 document. */
export interface BoundaryCiPolicyInput {
  failOnExpansion?: boolean;
  failOnIncomplete?: boolean;
}

/** `expectedPermissions` maps an exact declared permission name to its declared level. */
export type BoundaryCiExpectedPermissionsInput = Record<string, PermissionLevel>;

/** The one exact external schema-version-1 `.boundaryci.yml` document shape. */
export interface BoundaryCiConfig {
  version: 1;
  analysis?: BoundaryCiAnalysisInput;
  policy?: BoundaryCiPolicyInput;
  expectedPermissions?: BoundaryCiExpectedPermissionsInput;
}

/** Dependency and generated-output paths the built-in default excludes from analysis. */
const BUILTIN_EXCLUDES: readonly string[] = Object.freeze(['**/build/**', '**/dist/**', '**/node_modules/**']);

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
  declaredExpectedPermissions: Object.freeze([] as ExpectedPermissionDeclaration[]) as ExpectedPermissionDeclaration[],
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
export function effectiveConfigIdentity(config: EffectiveConfig): ConfigIdentity {
  return createHash('sha256').update(canonicalJson(config as unknown as JsonValue), 'utf8').digest('hex');
}

/** The stable diagnostic category a {@link ConfigValidationError} carries. */
export type ConfigValidationErrorCode = 'unsupported-version' | 'invalid-shape';

/**
 * Raised by {@link validateConfigValue} for every rejected document. `code` distinguishes an
 * unsupported/missing `version` from every other shape violation; `message` never echoes a
 * value taken from the document, only the structural label of the field it rejected.
 */
export class ConfigValidationError extends TypeError {
  readonly code: ConfigValidationErrorCode;

  constructor(code: ConfigValidationErrorCode, message: string) {
    super(message);
    this.name = 'ConfigValidationError';
    this.code = code;
  }
}

function compareBytes(left: string, right: string): number {
  const leftBuffer = Buffer.from(left, 'utf8');
  const rightBuffer = Buffer.from(right, 'utf8');
  return Buffer.compare(leftBuffer, rightBuffer);
}

function sortDedupBytes(values: readonly string[]): string[] {
  return Array.from(new Set(values)).sort(compareBytes);
}

const TOP_LEVEL_KEYS: readonly string[] = Object.freeze(['version', 'analysis', 'policy', 'expectedPermissions']);
const ANALYSIS_KEYS: readonly string[] = Object.freeze(['include', 'exclude', 'probotEntrypoints', 'limits']);
const POLICY_KEYS: readonly string[] = Object.freeze(['failOnExpansion', 'failOnIncomplete']);
const LIMIT_KEYS: readonly (keyof AnalysisLimits)[] = Object.freeze([
  'maxSourceFiles',
  'maxSourceFileBytes',
  'maxTotalSourceBytes',
  'maxSourceWork',
]);

/** A non-empty, non-whitespace declared permission name (CONF-01, D-15). */
const PERMISSION_NAME = /^\S+$/u;

/** The Phase 3 root-relative POSIX path grammar an entrypoint must satisfy. */
const POSIX_RELATIVE = /^[^/][^\0]*$/u;

function assertPlainObject(value: unknown, label: string): asserts value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new ConfigValidationError('invalid-shape', `${label} must be an object`);
  }
  const prototype = Object.getPrototypeOf(value) as unknown;
  if (prototype !== Object.prototype && prototype !== null) {
    throw new ConfigValidationError('invalid-shape', `${label} must be a plain object`);
  }
}

function assertKnownKeys(value: Record<string, unknown>, allowed: readonly string[], label: string): void {
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) throw new ConfigValidationError('invalid-shape', `${label} has an unknown key`);
  }
}

function assertNonEmptyString(value: unknown, label: string): asserts value is string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new ConfigValidationError('invalid-shape', `${label} must be a non-empty string`);
  }
}

function assertStringArray(value: unknown, label: string): asserts value is string[] {
  if (!Array.isArray(value)) throw new ConfigValidationError('invalid-shape', `${label} must be an array`);
  value.forEach((entry, index) => assertNonEmptyString(entry, `${label}[${index}]`));
}

function assertGlobPatternArray(values: readonly string[], label: string): void {
  values.forEach((pattern, index) => {
    try {
      compileLimitedGlob(pattern);
    } catch {
      throw new ConfigValidationError('invalid-shape', `${label}[${index}] is not a valid limited glob pattern`);
    }
  });
}

/**
 * Accepts only a case-sensitive, root-relative POSIX path, per {@link POSIX_RELATIVE} and the
 * exact segment rules `src/analyzer/contract.ts` enforces on a trusted `probotEntrypoints`
 * entry.
 */
function assertEntrypointPath(value: unknown, label: string): asserts value is string {
  assertNonEmptyString(value, label);
  if (!POSIX_RELATIVE.test(value) || value.includes('\\')) {
    throw new ConfigValidationError('invalid-shape', `${label} must be a root-relative POSIX path`);
  }
  for (const segment of value.split('/')) {
    if (segment.length === 0 || segment === '.' || segment === '..') {
      throw new ConfigValidationError('invalid-shape', `${label} must not contain an empty, current, or parent segment`);
    }
  }
}

function assertBudget(value: unknown, label: string): asserts value is number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw new ConfigValidationError('invalid-shape', `${label} must be a non-negative safe integer`);
  }
}

function assertPermissionName(value: string, label: string): void {
  if (!PERMISSION_NAME.test(value)) {
    throw new ConfigValidationError('invalid-shape', `${label} must be a non-empty name without whitespace`);
  }
}

function assertPermissionLevel(value: unknown, label: string): asserts value is PermissionLevel {
  if (value !== 'read' && value !== 'write') {
    throw new ConfigValidationError('invalid-shape', `${label} must be exactly "read" or "write"`);
  }
}

/**
 * Accepts only one exact external schema-version-1 `.boundaryci.yml` document.
 *
 * `value` must already be trusted generic JS produced from an accepted YAML document (D-04);
 * this function never parses YAML and never reads a file. Every rejection is a
 * {@link ConfigValidationError} whose message never echoes a value taken from `value`.
 */
export function validateConfigValue(value: unknown): asserts value is BoundaryCiConfig {
  assertPlainObject(value, 'configuration');
  assertKnownKeys(value, TOP_LEVEL_KEYS, 'configuration');

  if (value.version !== BOUNDARYCI_CONFIG_DOCUMENT_VERSION) {
    throw new ConfigValidationError('unsupported-version', 'configuration version is missing or unsupported');
  }

  const analysis = value.analysis;
  if (analysis !== undefined) {
    assertPlainObject(analysis, 'configuration.analysis');
    assertKnownKeys(analysis, ANALYSIS_KEYS, 'configuration.analysis');

    if (analysis.include !== undefined) {
      assertStringArray(analysis.include, 'configuration.analysis.include');
      if (analysis.include.length === 0) {
        throw new ConfigValidationError('invalid-shape', 'configuration.analysis.include must be a non-empty array');
      }
      assertGlobPatternArray(analysis.include, 'configuration.analysis.include');
    }
    if (analysis.exclude !== undefined) {
      assertStringArray(analysis.exclude, 'configuration.analysis.exclude');
      assertGlobPatternArray(analysis.exclude, 'configuration.analysis.exclude');
    }
    if (analysis.probotEntrypoints !== undefined) {
      assertStringArray(analysis.probotEntrypoints, 'configuration.analysis.probotEntrypoints');
      analysis.probotEntrypoints.forEach((entry, index) =>
        assertEntrypointPath(entry, `configuration.analysis.probotEntrypoints[${index}]`),
      );
    }
    if (analysis.limits !== undefined) {
      assertPlainObject(analysis.limits, 'configuration.analysis.limits');
      assertKnownKeys(analysis.limits, LIMIT_KEYS, 'configuration.analysis.limits');
      for (const key of LIMIT_KEYS) {
        const entry = analysis.limits[key];
        if (entry !== undefined) assertBudget(entry, `configuration.analysis.limits.${key}`);
      }
    }
  }

  const policy = value.policy;
  if (policy !== undefined) {
    assertPlainObject(policy, 'configuration.policy');
    assertKnownKeys(policy, POLICY_KEYS, 'configuration.policy');
    for (const key of POLICY_KEYS) {
      const entry = policy[key];
      if (entry !== undefined && typeof entry !== 'boolean') {
        throw new ConfigValidationError('invalid-shape', `configuration.policy.${key} must be a boolean`);
      }
    }
  }

  const expectedPermissions = value.expectedPermissions;
  if (expectedPermissions !== undefined) {
    assertPlainObject(expectedPermissions, 'configuration.expectedPermissions');
    for (const key of Object.keys(expectedPermissions)) {
      assertPermissionName(key, 'configuration.expectedPermissions key');
      assertPermissionLevel(expectedPermissions[key], `configuration.expectedPermissions.${key}`);
    }
  }
}

/**
 * Normalizes one already-{@link validateConfigValue}-accepted document into the complete
 * {@link EffectiveConfig}: every omitted section/field receives the {@link BUILTIN_CONFIG}
 * default, and every declarative array is bytewise sorted and deduplicated (CONF-01, CONF-02,
 * D-10, D-16). Re-validates `config` itself, so it is safe to call on untrusted input directly.
 */
export function normalizeEffectiveConfig(config: unknown): EffectiveConfig {
  validateConfigValue(config);

  const analysis = config.analysis ?? {};
  const limitsInput = analysis.limits ?? {};
  const policy = config.policy ?? {};
  const expectedPermissionsInput = config.expectedPermissions ?? {};

  const limits: AnalysisLimits = {
    maxSourceFiles: limitsInput.maxSourceFiles ?? DEFAULT_ANALYSIS_LIMITS.maxSourceFiles,
    maxSourceFileBytes: limitsInput.maxSourceFileBytes ?? DEFAULT_ANALYSIS_LIMITS.maxSourceFileBytes,
    maxTotalSourceBytes: limitsInput.maxTotalSourceBytes ?? DEFAULT_ANALYSIS_LIMITS.maxTotalSourceBytes,
    maxSourceWork: limitsInput.maxSourceWork ?? DEFAULT_ANALYSIS_LIMITS.maxSourceWork,
  };

  const declaredExpectedPermissions: ExpectedPermissionDeclaration[] = Object.entries(expectedPermissionsInput)
    .map(([permission, level]) => Object.freeze({ permission, level }))
    .sort((left, right) => compareBytes(left.permission, right.permission));

  return Object.freeze({
    schemaVersion: BOUNDARYCI_CONFIG_SCHEMA_VERSION,
    include: Object.freeze(sortDedupBytes(analysis.include ?? BUILTIN_CONFIG.include)) as string[],
    exclude: Object.freeze(sortDedupBytes(analysis.exclude ?? BUILTIN_CONFIG.exclude)) as string[],
    probotEntrypoints: Object.freeze(
      sortDedupBytes(analysis.probotEntrypoints ?? BUILTIN_CONFIG.probotEntrypoints),
    ) as string[],
    limits: Object.freeze(limits) as AnalysisLimits,
    failOnExpansion: policy.failOnExpansion ?? true,
    failOnIncomplete: policy.failOnIncomplete ?? true,
    declaredExpectedPermissions: Object.freeze(declaredExpectedPermissions) as ExpectedPermissionDeclaration[],
  }) as EffectiveConfig;
}
