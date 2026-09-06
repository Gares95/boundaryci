import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Delivery's signed Probot harness deliberately owns the process-global fetch boundary.
    // Run files serially so independent original-byte tests cannot replace each other's
    // finite GitHub transport while an asynchronous webhook handler is still in flight.
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
    ],
    watch: false,
  },
});
