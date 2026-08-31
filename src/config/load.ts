/**
 * Bounded, no-follow loading of one local `.boundaryci.yml` configuration entry.
 *
 * `loadSnapshotConfig` never inspects a target manifest, dependency, or any other filename: it
 * reads only the exact `.boundaryci.yml` entry beneath a caller-provided canonicalized local
 * snapshot root, never follows a symbolic link, and never accepts a non-regular entry. Its
 * result never echoes configuration source bytes or an absolute host path (D-04, D-13, D-18).
 *
 * Selecting base/head authority from this result is Plan 04-02 Task 2 work; nothing here
 * decides what governs a comparison.
 */

import { constants } from 'node:fs';
import { lstat, open, realpath, stat } from 'node:fs/promises';
import { join } from 'node:path';

import { parseDocument, visit } from 'yaml';
import type { DocumentOptions, ParseOptions, SchemaOptions } from 'yaml';
import type { FileHandle } from 'node:fs/promises';

import {
  ConfigValidationError,
  effectiveConfigIdentity,
  normalizeEffectiveConfig,
  validateConfigValue,
} from './model.js';
import type { ConfigIdentity, EffectiveConfig } from './model.js';

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
