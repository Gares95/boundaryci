import { mkdtemp, mkdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { ANALYZER_SOURCE_EXTENSIONS, DEFAULT_ANALYSIS_LIMITS } from '../../src/analyzer/contract.js';
import {
  BOUNDARYCI_CONFIG_SCHEMA_VERSION,
  BUILTIN_CONFIG,
  ConfigValidationError,
  effectiveConfigIdentity,
  normalizeEffectiveConfig,
  validateConfigValue,
} from '../../src/config/model.js';
import {
  CONFIG_FILE_NAME,
  MAX_CONFIG_BYTES,
  loadSnapshotConfig,
  selectAuthoritativeConfig,
} from '../../src/config/load.js';

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { force: true, recursive: true })));
});

async function rootWith(contents?: string | Uint8Array): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'boundaryci-config-'));
  roots.push(root);
  if (contents !== undefined) await writeFile(join(root, CONFIG_FILE_NAME), contents);
  return root;
}

async function loadText(contents: string | Uint8Array) {
  return loadSnapshotConfig(await rootWith(contents));
}

function expectInvalidShape(value: unknown): void {
  try {
    validateConfigValue(value);
    throw new Error('expected configuration validation to fail');
  } catch (error) {
    expect(error).toBeInstanceOf(ConfigValidationError);
    expect((error as ConfigValidationError).code).toBe('invalid-shape');
  }
}

describe('defaults, normalization, and identity', () => {
  it('expands the minimal document to the exact safe built-in defaults', async () => {
    const state = await loadText('version: 1\n');
    expect(state.status).toBe('valid');
    if (state.status !== 'valid') throw new Error('expected valid configuration');

    expect(state.config).toEqual({
      schemaVersion: BOUNDARYCI_CONFIG_SCHEMA_VERSION,
      include: ANALYZER_SOURCE_EXTENSIONS.map((extension) => `**/*${extension}`),
      exclude: ['**/build/**', '**/dist/**', '**/node_modules/**'],
      probotEntrypoints: [],
      limits: DEFAULT_ANALYSIS_LIMITS,
      failOnExpansion: true,
      failOnIncomplete: true,
      declaredExpectedPermissions: [],
    });
    expect(state.config).toEqual(BUILTIN_CONFIG);
    expect(state.identity).toBe(effectiveConfigIdentity(state.config));
  });

  it('normalizes declarative sets and expected permissions by UTF-8 byte order', async () => {
    const state = await loadText(`
version: 1
analysis:
  include: ["src/**/*.ts", "**/*.js", "src/**/*.ts"]
  exclude: ["z/**", "a/**", "z/**"]
  probotEntrypoints: ["src/z.ts", "src/a.ts", "src/z.ts"]
  limits:
    maxSourceFiles: 12
policy:
  failOnExpansion: false
expectedPermissions:
  metadata: read
  issues: write
`);
    expect(state.status).toBe('valid');
    if (state.status !== 'valid') throw new Error('expected valid configuration');

    expect(state.config.include).toEqual(['**/*.js', 'src/**/*.ts']);
    expect(state.config.exclude).toEqual(['a/**', 'z/**']);
    expect(state.config.probotEntrypoints).toEqual(['src/a.ts', 'src/z.ts']);
    expect(state.config.limits).toEqual({ ...DEFAULT_ANALYSIS_LIMITS, maxSourceFiles: 12 });
    expect(state.config.failOnExpansion).toBe(false);
    expect(state.config.failOnIncomplete).toBe(true);
    expect(state.config.declaredExpectedPermissions).toEqual([
      { permission: 'issues', level: 'write' },
      { permission: 'metadata', level: 'read' },
    ]);
  });

  it('gives equivalent spelling the same identity and changed behavior a different identity', async () => {
    const minimal = await loadText('version: 1 # defaults\n');
    const explicit = await loadText(`
expectedPermissions: {}
policy: { failOnIncomplete: true, failOnExpansion: true }
analysis:
  limits:
    maxSourceWork: 50000
    maxTotalSourceBytes: 64000000
    maxSourceFileBytes: 2000000
    maxSourceFiles: 5000
  probotEntrypoints: []
  exclude: ["**/build/**", "**/dist/**", "**/node_modules/**", "**/build/**"]
  include: ["**/*.tsx", "**/*.ts", "**/*.mts", "**/*.mjs", "**/*.jsx", "**/*.js", "**/*.js"]
version: 1
`);
    const changed = await loadText('version: 1\npolicy:\n  failOnExpansion: false\n');
    expect(minimal.status).toBe('valid');
    expect(explicit.status).toBe('valid');
    expect(changed.status).toBe('valid');
    if (minimal.status !== 'valid' || explicit.status !== 'valid' || changed.status !== 'valid') {
      throw new Error('expected valid configurations');
    }
    expect(explicit.config).toEqual(minimal.config);
    expect(explicit.identity).toBe(minimal.identity);
    expect(changed.identity).not.toBe(minimal.identity);

    const repeated = await loadSnapshotConfig(await rootWith('version: 1\n'));
    const repeatedAgain = await loadSnapshotConfig(roots.at(-1) as string);
    expect(JSON.stringify(repeatedAgain)).toBe(JSON.stringify(repeated));
  });

  it('freezes the effective object and every mutable nested value', () => {
    const config = normalizeEffectiveConfig({ version: 1, expectedPermissions: { issues: 'write' } });
    expect(Object.isFrozen(config)).toBe(true);
    expect(Object.isFrozen(config.include)).toBe(true);
    expect(Object.isFrozen(config.exclude)).toBe(true);
    expect(Object.isFrozen(config.probotEntrypoints)).toBe(true);
    expect(Object.isFrozen(config.limits)).toBe(true);
    expect(Object.isFrozen(config.declaredExpectedPermissions)).toBe(true);
    expect(Object.isFrozen(config.declaredExpectedPermissions[0])).toBe(true);
    expect(() => config.include.push('src/**')).toThrow(TypeError);
    expect(() => {
      config.limits.maxSourceFiles = 1;
    }).toThrow(TypeError);
    expect(() => {
      const declaration = config.declaredExpectedPermissions[0];
      if (declaration !== undefined) declaration.level = 'read';
    }).toThrow(TypeError);
  });
});

describe('exact schema validation', () => {
  it.each([
    {},
    { version: 2 },
    { version: 1.5 },
  ])('rejects missing or unsupported version %#', (value) => {
    expect(() => validateConfigValue(value)).toThrow(ConfigValidationError);
    try {
      validateConfigValue(value);
    } catch (error) {
      expect((error as ConfigValidationError).code).toBe('unsupported-version');
    }
  });

  it.each([
    { version: 1, unknown: true },
    { version: 1, analysis: { unknown: true } },
    { version: 1, analysis: { limits: { unknown: 1 } } },
    { version: 1, policy: { unknown: true } },
    { version: 1, analysis: { include: [] } },
    { version: 1, analysis: { include: '**/*.ts' } },
    { version: 1, analysis: { include: ['../src/**/*.ts'] } },
    { version: 1, analysis: { include: ['src/**x/*.ts'] } },
    { version: 1, analysis: { probotEntrypoints: ['/src/app.ts'] } },
    { version: 1, analysis: { probotEntrypoints: ['src/../app.ts'] } },
    { version: 1, analysis: { limits: { maxSourceFiles: -1 } } },
    { version: 1, analysis: { limits: { maxSourceFiles: 1.5 } } },
    { version: 1, analysis: { limits: { maxSourceFiles: Number.MAX_SAFE_INTEGER + 1 } } },
    { version: 1, policy: { failOnExpansion: 'true' } },
    { version: 1, policy: { failOnIncomplete: 1 } },
    { version: 1, expectedPermissions: { '': 'read' } },
    { version: 1, expectedPermissions: { 'issues write': 'write' } },
    { version: 1, expectedPermissions: { issues: 'admin' } },
    new Date(),
  ])('rejects invalid or inexact shape %#', (value) => {
    expectInvalidShape(value);
  });

  it('returns an actionable structural diagnostic without echoing an invalid value', async () => {
    const state = await loadText('version: 1\nanalysis:\n  include: ["../private-token.ts"]\n');
    expect(state).toEqual({
      status: 'invalid',
      diagnostics: [
        {
          code: 'config-shape-invalid',
          detail: 'configuration.analysis.include[0] is not a valid limited glob pattern',
        },
      ],
    });
    expect(JSON.stringify(state)).not.toContain('private-token');
  });
});

describe('bounded YAML and filesystem boundary', () => {
  it.each([
    { name: 'syntax error', text: 'version: [1\n', code: 'config-yaml-syntax' },
    { name: 'duplicate key', text: 'version: 1\nversion: 1\n', code: 'config-yaml-duplicate-key' },
    {
      name: 'alias',
      text: 'version: 1\nanalysis: &analysis {}\npolicy: *analysis\n',
      code: 'config-yaml-alias-disabled',
    },
    {
      name: 'merge key',
      text: 'version: 1\nanalysis:\n  <<: { include: ["**/*.ts"] }\n',
      code: 'config-shape-invalid',
    },
    { name: 'custom tag', text: 'version: !boundaryci 1\n', code: 'config-yaml-unsupported-tag' },
    { name: 'multiple documents', text: 'version: 1\n---\nversion: 1\n', code: 'config-yaml-multiple-documents' },
  ])('rejects $name deterministically', async ({ text, code }) => {
    const state = await loadText(text);
    expect(state.status).toBe('invalid');
    if (state.status !== 'invalid') throw new Error('expected invalid configuration');
    expect(state.diagnostics[0]?.code).toBe(code);
  });

  it('rejects invalid UTF-8 and entries above the finite byte limit', async () => {
    const invalidUtf8 = await loadText(Uint8Array.from([0xff, 0xfe, 0xfd]));
    expect(invalidUtf8).toMatchObject({ status: 'invalid', diagnostics: [{ code: 'config-yaml-syntax' }] });

    const oversized = await loadText(new Uint8Array(MAX_CONFIG_BYTES + 1));
    expect(oversized).toMatchObject({ status: 'invalid', diagnostics: [{ code: 'config-too-large' }] });
  });

  it('distinguishes absent, symlink, non-regular, and invalid root states', async () => {
    expect(await loadSnapshotConfig(await rootWith())).toEqual({ status: 'absent' });

    const symlinkRoot = await rootWith();
    const target = join(symlinkRoot, 'actual.yml');
    await writeFile(target, 'version: 1\n');
    await symlink(target, join(symlinkRoot, CONFIG_FILE_NAME));
    expect(await loadSnapshotConfig(symlinkRoot)).toMatchObject({
      status: 'invalid',
      diagnostics: [{ code: 'config-symlink' }],
    });

    const directoryRoot = await rootWith();
    await mkdir(join(directoryRoot, CONFIG_FILE_NAME));
    expect(await loadSnapshotConfig(directoryRoot)).toMatchObject({
      status: 'invalid',
      diagnostics: [{ code: 'config-non-regular' }],
    });

    const fileRoot = join(await rootWith(), 'not-a-directory');
    await writeFile(fileRoot, 'not a root');
    expect(await loadSnapshotConfig(fileRoot)).toMatchObject({
      status: 'invalid',
      diagnostics: [{ code: 'config-root-invalid' }],
    });
    expect(await loadSnapshotConfig(join(tmpdir(), 'boundaryci-missing-root'))).toMatchObject({
      status: 'invalid',
      diagnostics: [{ code: 'config-root-invalid' }],
    });
  });

  it('reads only the exact config entry and never executes adjacent target files', async () => {
    const root = await rootWith('version: 1\n');
    const marker = join(root, 'executed');
    await writeFile(join(root, 'package.json'), '{ deliberately invalid target manifest');
    await writeFile(join(root, '.boundaryci.yaml'), 'version: !unsupported 1\n');
    await writeFile(join(root, 'target.mjs'), `await import('node:fs/promises').then(fs => fs.writeFile(${JSON.stringify(marker)}, 'bad'))`);

    const state = await loadSnapshotConfig(root);
    expect(state.status).toBe('valid');
    await expect(readFile(marker)).rejects.toMatchObject({ code: 'ENOENT' });
  });
});

describe('base authority and prospective head reporting', () => {
  it('selects the valid base for authority and reports a changed valid head as prospective only', async () => {
    const base = await loadText('version: 1\n');
    const head = await loadText('version: 1\npolicy:\n  failOnExpansion: false\n');
    if (base.status !== 'valid' || head.status !== 'valid') throw new Error('expected valid configurations');

    const selection = selectAuthoritativeConfig(base, head);
    expect(selection).toEqual({
      status: 'selected',
      authority: { source: 'base', config: base.config, identity: base.identity },
      head: { status: 'valid', config: head.config, identity: head.identity, change: 'changed' },
    });
  });

  it('reports an equivalent valid head as unchanged while it still stays prospective only', async () => {
    const base = await loadText('version: 1\n');
    const head = await loadText('version: 1 # comment\n');
    if (base.status !== 'valid' || head.status !== 'valid') throw new Error('expected valid configurations');

    const selection = selectAuthoritativeConfig(base, head);
    expect(selection).toEqual({
      status: 'selected',
      authority: { source: 'base', config: base.config, identity: base.identity },
      head: { status: 'valid', config: head.config, identity: head.identity, change: 'unchanged' },
    });
  });

  it('selects the built-in default for both revisions when base and head are both absent', () => {
    const selection = selectAuthoritativeConfig({ status: 'absent' }, { status: 'absent' });
    expect(selection).toEqual({
      status: 'selected',
      authority: {
        source: 'built-in-default',
        config: BUILTIN_CONFIG,
        identity: effectiveConfigIdentity(BUILTIN_CONFIG),
      },
      head: { status: 'absent' },
    });
  });

  it('selects the built-in default when base is absent and reports a valid head as prospective only', async () => {
    const head = await loadText('version: 1\npolicy:\n  failOnExpansion: false\n');
    if (head.status !== 'valid') throw new Error('expected valid configuration');

    const selection = selectAuthoritativeConfig({ status: 'absent' }, head);
    expect(selection).toEqual({
      status: 'selected',
      authority: {
        source: 'built-in-default',
        config: BUILTIN_CONFIG,
        identity: effectiveConfigIdentity(BUILTIN_CONFIG),
      },
      head: { status: 'valid', config: head.config, identity: head.identity, change: 'changed' },
    });
  });

  it('fails with no authority when base is invalid, regardless of a valid or absent head', async () => {
    const invalidBase = await loadText('version: [1\n');
    const validHead = await loadText('version: 1\n');
    if (invalidBase.status !== 'invalid' || validHead.status !== 'valid') throw new Error('expected fixtures');

    for (const headState of [validHead, { status: 'absent' } as const]) {
      const selection = selectAuthoritativeConfig(invalidBase, headState);
      expect(selection).toEqual({
        status: 'input-configuration-failure',
        invalid: 'base',
        diagnostics: invalidBase.diagnostics,
      });
      expect(selection).not.toHaveProperty('authority');
    }
  });

  it('fails before analysis when base is valid and head is invalid, retaining base authority and only head diagnostics', async () => {
    const base = await loadText('version: 1\n');
    const invalidHead = await loadText('version: 2\n');
    if (base.status !== 'valid' || invalidHead.status !== 'invalid') throw new Error('expected fixtures');

    const selection = selectAuthoritativeConfig(base, invalidHead);
    expect(selection).toEqual({
      status: 'input-configuration-failure',
      invalid: 'head',
      authority: { source: 'base', config: base.config, identity: base.identity },
      diagnostics: invalidHead.diagnostics,
    });
  });

  it('returns a deterministic, deeply immutable selection that never mutates either input', async () => {
    const base = await loadText('version: 1\n');
    const head = await loadText('version: 1\npolicy:\n  failOnExpansion: false\n');
    if (base.status !== 'valid' || head.status !== 'valid') throw new Error('expected valid configurations');

    const baseSnapshot = JSON.stringify(base);
    const headSnapshot = JSON.stringify(head);

    const first = selectAuthoritativeConfig(base, head);
    const second = selectAuthoritativeConfig(base, head);
    expect(JSON.stringify(first)).toBe(JSON.stringify(second));
    expect(first).not.toBe(second);
    expect(JSON.stringify(base)).toBe(baseSnapshot);
    expect(JSON.stringify(head)).toBe(headSnapshot);

    if (first.status !== 'selected') throw new Error('expected a selected authority');
    expect(Object.isFrozen(first)).toBe(true);
    expect(Object.isFrozen(first.authority)).toBe(true);
    expect(Object.isFrozen(first.authority.config)).toBe(true);
    expect(Object.isFrozen(first.authority.config.include)).toBe(true);
    expect(Object.isFrozen(first.authority.config.limits)).toBe(true);
    expect(Object.isFrozen(first.authority.config.declaredExpectedPermissions)).toBe(true);
    expect(Object.isFrozen(first.head)).toBe(true);
    expect(first.authority.config).not.toBe(base.config);
    if (first.head.status === 'valid') expect(first.head.config).not.toBe(head.config);

    expect(() => {
      (first as { authority: unknown }).authority = null;
    }).toThrow(TypeError);
    expect(() => {
      first.authority.config.include.push('mutated');
    }).toThrow(TypeError);
  });
});

describe('declared permission evidence separation', () => {
  it('labels declarations without manufacturing observed findings or boundaries', async () => {
    const state = await loadText('version: 1\nexpectedPermissions:\n  issues: write\n  metadata: read\n');
    expect(state.status).toBe('valid');
    if (state.status !== 'valid') throw new Error('expected valid configuration');

    expect(state.config.declaredExpectedPermissions).toEqual([
      { permission: 'issues', level: 'write' },
      { permission: 'metadata', level: 'read' },
    ]);
    expect(state.config).not.toHaveProperty('expectedPermissions');
    expect(state.config).not.toHaveProperty('permissionBoundary');
    expect(state.config).not.toHaveProperty('findings');
    expect(state.config).not.toHaveProperty('observations');
  });
});
