import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: [
      'tools/permission-data-feasibility/tests/**/*.test.ts',
      'tests/analyzer/**/*.test.ts',
      'tests/permission-model/**/*.test.ts',
      'tests/config/**/*.test.ts',
      'tests/diff/**/*.test.ts',
      'tests/policy/**/*.test.ts',
      'tests/cli/**/*.test.ts',
    ],
    watch: false,
  },
});
