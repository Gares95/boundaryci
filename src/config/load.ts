/**
 * Bounded, no-follow loading of one local `.boundaryci.yml` configuration entry.
 *
 * `loadSnapshotConfig` never inspects a target manifest, dependency, or any other filename: it
 * reads only the exact `.boundaryci.yml` entry beneath a caller-provided canonicalized local
 * snapshot root, never follows a symbolic link, and never accepts a non-regular entry. Its
 * result never echoes configuration source bytes or an absolute host path (D-04, D-13, D-18).
 *
 * `selectAuthoritativeConfig` decides what governs a comparison from two such results: the base
 * revision (or the versioned built-in default when base is absent) is the sole authority for
 * both revisions and for policy, while a head configuration is always reported separately as
 * prospective evidence and never governs the comparison that introduces it (D-11 through D-14).
 */

import { constants } from 'node:fs';
import { lstat, open, realpath, stat } from 'node:fs/promises';
import { join } from 'node:path';

import { parseDocument, visit } from 'yaml';
import type { DocumentOptions, ParseOptions, SchemaOptions } from 'yaml';
import type { FileHandle } from 'node:fs/promises';

import type { AnalysisLimits } from '../analyzer/contract.js';
import {
  BUILTIN_CONFIG,
  ConfigValidationError,
  effectiveConfigIdentity,
  normalizeEffectiveConfig,
  validateConfigValue,
} from './model.js';
import type { ConfigIdentity, EffectiveConfig, ExpectedPermissionDeclaration } from './model.js';

/** The one config entry name a snapshot root is ever read for. */
export const CONFIG_FILE_NAME = '.boundaryci.yml';

/** The finite configuration byte bound; larger entries are rejected unread beyond this size. */
export const MAX_CONFIG_BYTES = 256 * 1024;

/** The stable diagnostic vocabulary a rejected `.boundaryci.yml` load can report. */
export type ConfigDiagnosticCode =
  | 'config-root-invalid'
  | 'config-read-error'
  | 'config-non-regular'
  | 'config-symlink'
  | 'config-too-large'
  | 'config-yaml-syntax'
  | 'config-yaml-duplicate-key'
  | 'config-yaml-multiple-documents'
  | 'config-yaml-unsupported-tag'
  | 'config-yaml-alias-disabled'
  | 'config-unsupported-version'
  | 'config-shape-invalid';

/** One stable, actionable diagnostic. `detail` never contains configuration source bytes. */
export interface ConfigDiagnostic {
  code: ConfigDiagnosticCode;
  detail: string;
}

export type SnapshotConfigState =
  | { status: 'absent' }
  | { status: 'valid'; config: EffectiveConfig; identity: ConfigIdentity }
  | { status: 'invalid'; diagnostics: readonly ConfigDiagnostic[] };

function invalid(code: ConfigDiagnosticCode, detail: string): SnapshotConfigState {
  return Object.freeze({ status: 'invalid', diagnostics: Object.freeze([Object.freeze({ code, detail })]) });
}

function errorCode(error: unknown): string | undefined {
  if (typeof error !== 'object' || error === null) return undefined;
  const code = (error as { code?: unknown }).code;
  return typeof code === 'string' ? code : undefined;
}

/** Reads at most one byte beyond the configured ceiling, so growth after `lstat` stays bounded. */
async function readBounded(handle: FileHandle): Promise<Buffer> {
  const bytes = Buffer.allocUnsafe(MAX_CONFIG_BYTES + 1);
  let offset = 0;
  while (offset < bytes.byteLength) {
    const { bytesRead } = await handle.read(bytes, offset, bytes.byteLength - offset, offset);
    if (bytesRead === 0) break;
    offset += bytesRead;
  }
  return bytes.subarray(0, offset);
}

/**
 * The reviewed `yaml@2.9.0` parse profile: YAML 1.2 core schema, strict unique keys, no custom
 * tags, merge keys disabled, known YAML 1.1 tags disabled, and no source-position prose that
 * could otherwise leak byte offsets into a diagnostic.
 */
const YAML_PARSE_OPTIONS: ParseOptions & DocumentOptions & SchemaOptions = Object.freeze({
  version: '1.2',
  schema: 'core',
  strict: true,
  uniqueKeys: true,
  merge: false,
  resolveKnownTags: false,
  customTags: [],
  prettyErrors: false,
});

function documentHasAlias(doc: Parameters<typeof visit>[0]): boolean {
  let found = false;
  visit(doc, {
    Alias() {
      found = true;
      return visit.BREAK;
    },
  });
  return found;
}

/** Maps one `yaml@2.9.0` parse error/warning code to a stable configuration diagnostic. */
function yamlIssueDiagnostic(code: string): ConfigDiagnostic {
  if (code === 'DUPLICATE_KEY') {
    return { code: 'config-yaml-duplicate-key', detail: 'the configuration document has a duplicate map key' };
  }
  if (code === 'MULTIPLE_DOCS') {
    return { code: 'config-yaml-multiple-documents', detail: 'the configuration entry must contain one YAML document' };
  }
  if (code === 'TAG_RESOLVE_FAILED') {
    return { code: 'config-yaml-unsupported-tag', detail: 'the configuration document uses an unsupported YAML tag' };
  }
  return { code: 'config-yaml-syntax', detail: 'the configuration document is not valid YAML' };
}

/** Parses and validates configuration source bytes; never echoes them into a diagnostic. */
function parseAndValidateConfig(text: string): SnapshotConfigState {
  let doc: ReturnType<typeof parseDocument>;
  try {
    doc = parseDocument(text, YAML_PARSE_OPTIONS);
  } catch {
    return invalid('config-yaml-syntax', 'the configuration document is not valid YAML');
  }

  const [firstIssue] = [...doc.errors, ...doc.warnings];
  if (firstIssue !== undefined) {
    const diagnostic = yamlIssueDiagnostic(firstIssue.code);
    return invalid(diagnostic.code, diagnostic.detail);
  }
  if (documentHasAlias(doc)) {
    return invalid('config-yaml-alias-disabled', 'the configuration document must not use a YAML alias');
  }

  let value: unknown;
  try {
    value = doc.toJS({ mapAsMap: false, maxAliasCount: 0 });
  } catch {
    return invalid('config-yaml-syntax', 'the configuration document could not be converted safely');
  }

  try {
    validateConfigValue(value);
  } catch (error) {
    if (error instanceof ConfigValidationError && error.code === 'unsupported-version') {
      return invalid('config-unsupported-version', 'the configuration version is missing or unsupported');
    }
    if (error instanceof ConfigValidationError) {
      return invalid('config-shape-invalid', error.message);
    }
    return invalid('config-shape-invalid', 'the configuration document does not match the supported schema');
  }

  const config = normalizeEffectiveConfig(value);
  return Object.freeze({ status: 'valid', config, identity: effectiveConfigIdentity(config) });
}

/**
 * Loads the exact `.boundaryci.yml` entry beneath the canonicalized `rootPath`.
 *
 * The entry is never followed as a symbolic link and never read unless it remains an actual
 * regular file at the moment it is opened. Nothing beyond {@link MAX_CONFIG_BYTES} is read.
 */
export async function loadSnapshotConfig(rootPath: string): Promise<SnapshotConfigState> {
  let canonicalRoot: string;
  try {
    canonicalRoot = await realpath(rootPath);
  } catch {
    return invalid('config-root-invalid', 'the snapshot root could not be canonicalized');
  }
  try {
    if (!(await stat(canonicalRoot)).isDirectory()) {
      return invalid('config-root-invalid', 'the snapshot root must be a directory');
    }
  } catch {
    return invalid('config-root-invalid', 'the snapshot root could not be inspected');
  }

  const configPath = join(canonicalRoot, CONFIG_FILE_NAME);

  let entryStat: Awaited<ReturnType<typeof lstat>>;
  try {
    entryStat = await lstat(configPath);
  } catch (error) {
    if (errorCode(error) === 'ENOENT') {
      return Object.freeze({ status: 'absent' });
    }
    return invalid('config-read-error', 'the configuration entry could not be inspected');
  }

  if (entryStat.isSymbolicLink()) {
    return invalid('config-symlink', 'the configuration entry must not be a symbolic link');
  }
  if (!entryStat.isFile()) {
    return invalid('config-non-regular', 'the configuration entry must be a regular file');
  }
  if (entryStat.size > MAX_CONFIG_BYTES) {
    return invalid('config-too-large', 'the configuration entry exceeds the maximum configuration size');
  }

  let handle: FileHandle;
  try {
    handle = await open(configPath, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch (error) {
    if (errorCode(error) === 'ELOOP') {
      return invalid('config-symlink', 'the configuration entry must not be a symbolic link');
    }
    return invalid('config-read-error', 'the configuration entry could not be opened');
  }

  try {
    const fileStat = await handle.stat();
    if (!fileStat.isFile()) {
      return invalid('config-non-regular', 'the configuration entry must be a regular file');
    }
    if (fileStat.size > MAX_CONFIG_BYTES) {
      return invalid('config-too-large', 'the configuration entry exceeds the maximum configuration size');
    }

    const buffer = await readBounded(handle);
    if (buffer.byteLength > MAX_CONFIG_BYTES) {
      return invalid('config-too-large', 'the configuration entry exceeds the maximum configuration size');
    }

    let text: string;
    try {
      text = new TextDecoder('utf-8', { fatal: true }).decode(buffer);
    } catch {
      return invalid('config-yaml-syntax', 'the configuration entry must contain valid UTF-8 YAML');
    }

    return parseAndValidateConfig(text);
  } catch {
    return invalid('config-read-error', 'the configuration entry could not be read');
  } finally {
    await handle.close();
  }
}

/** Where one selected {@link AuthoritativeConfig} came from: a valid base, or the built-in default. */
export type AuthoritySource = 'base' | 'built-in-default';

/** The one effective configuration and identity that governs both revisions and policy. */
export interface AuthoritativeConfig {
  source: AuthoritySource;
  config: EffectiveConfig;
  identity: ConfigIdentity;
}

/** Whether a prospective head identity matches the authority it was compared against. */
export type ProspectiveHeadChange = 'unchanged' | 'changed';

/** A head configuration's own status and identity, retained for evidence only (D-14). */
export type ProspectiveHeadReport =
  | { status: 'absent' }
  | { status: 'valid'; config: EffectiveConfig; identity: ConfigIdentity; change: ProspectiveHeadChange };

/**
 * The exact result of {@link selectAuthoritativeConfig}.
 *
 * `selected` carries one authority plus a separate prospective head report. A base-invalid
 * failure carries no authority and no fallback at all. A head-invalid failure retains the
 * already-selected base/default authority alongside only the head's own diagnostics; no parsed
 * head fragment reaches either field.
 */
export type AuthoritativeConfigSelection =
  | { status: 'selected'; authority: AuthoritativeConfig; head: ProspectiveHeadReport }
  | { status: 'input-configuration-failure'; invalid: 'base'; diagnostics: readonly ConfigDiagnostic[] }
  | {
      status: 'input-configuration-failure';
      invalid: 'head';
      authority: AuthoritativeConfig;
      diagnostics: readonly ConfigDiagnostic[];
    };

/** An independent, deeply frozen copy of `config`, so a returned selection never aliases its input. */
function cloneEffectiveConfig(config: EffectiveConfig): EffectiveConfig {
  return Object.freeze({
    schemaVersion: config.schemaVersion,
    include: Object.freeze([...config.include]) as string[],
    exclude: Object.freeze([...config.exclude]) as string[],
    probotEntrypoints: Object.freeze([...config.probotEntrypoints]) as string[],
    limits: Object.freeze({ ...config.limits }) as AnalysisLimits,
    failOnExpansion: config.failOnExpansion,
    failOnIncomplete: config.failOnIncomplete,
    declaredExpectedPermissions: Object.freeze(
      config.declaredExpectedPermissions.map((declaration) => Object.freeze({ ...declaration })),
    ) as ExpectedPermissionDeclaration[],
  }) as EffectiveConfig;
}

/** An independent, deeply frozen copy of `diagnostics`. */
function cloneDiagnostics(diagnostics: readonly ConfigDiagnostic[]): readonly ConfigDiagnostic[] {
  return Object.freeze(diagnostics.map((diagnostic) => Object.freeze({ ...diagnostic })));
}

/** The sole authority for a valid base, or the versioned built-in default when base is absent. */
function selectAuthority(baseState: Extract<SnapshotConfigState, { status: 'absent' | 'valid' }>): AuthoritativeConfig {
  if (baseState.status === 'valid') {
    return Object.freeze({
      source: 'base',
      config: cloneEffectiveConfig(baseState.config),
      identity: baseState.identity,
    });
  }
  return Object.freeze({
    source: 'built-in-default',
    config: cloneEffectiveConfig(BUILTIN_CONFIG),
    identity: effectiveConfigIdentity(BUILTIN_CONFIG),
  });
}

/**
 * Decides the one authoritative configuration for a base/head comparison and reports the head
 * configuration's own state separately, without ever letting it govern (D-11 through D-14).
 *
 * A valid base is the sole authority for both revisions and policy; an absent base selects the
 * exact versioned {@link BUILTIN_CONFIG} instead. An invalid base fails closed with its own
 * diagnostics and no authority or fallback at all, regardless of head. Once authority is
 * selected, a valid head is reported prospective-only with its own normalized config, identity,
 * and `unchanged`/`changed` status relative to that authority; an absent head is reported
 * prospective-absent; an invalid head fails closed with the already-selected authority retained
 * and only the head's own diagnostics attached — no parsed head fragment ever governs the
 * comparison it was found in.
 *
 * This function is pure: it never reads a file, and every returned object, nested array, and
 * diagnostic is an independent deep copy, so `baseState` and `headState` are never mutated and
 * never aliased by the result.
 */
export function selectAuthoritativeConfig(
  baseState: SnapshotConfigState,
  headState: SnapshotConfigState,
): AuthoritativeConfigSelection {
  if (baseState.status === 'invalid') {
    return Object.freeze({
      status: 'input-configuration-failure',
      invalid: 'base',
      diagnostics: cloneDiagnostics(baseState.diagnostics),
    });
  }

  const authority = selectAuthority(baseState);

  if (headState.status === 'invalid') {
    return Object.freeze({
      status: 'input-configuration-failure',
      invalid: 'head',
      authority,
      diagnostics: cloneDiagnostics(headState.diagnostics),
    });
  }

  const head: ProspectiveHeadReport =
    headState.status === 'absent'
      ? Object.freeze({ status: 'absent' })
      : Object.freeze({
          status: 'valid',
          config: cloneEffectiveConfig(headState.config),
          identity: headState.identity,
          change: headState.identity === authority.identity ? 'unchanged' : 'changed',
        });

  return Object.freeze({ status: 'selected', authority, head });
}
