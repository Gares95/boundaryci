import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Delivery fixtures intentionally exercise the production snapshot parent. Serial files keep
    // one worker's startup-residue cleanup from deleting another worker's active private roots;
    // concurrency within each lifecycle test remains explicit and unchanged.
    fileParallelism: false,
    include: [
      'tools/permission-data-feasibility/tests/**/*.test.ts',
      'tests/analyzer/**/*.test.ts',
      'tests/permission-model/**/*.test.ts',
      'tests/config/**/*.test.ts',
      'tests/diff/**/*.test.ts',
      'tests/policy/**/*.test.ts',
      'tests/cli/**/*.test.ts',
      'tests/delivery/**/*.test.ts',
      'tests/release/**/*.test.ts',
      'tests/toolchain/**/*.test.ts',
    ],
    watch: false,
  },
});
