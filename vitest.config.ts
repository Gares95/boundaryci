import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['tools/permission-data-feasibility/tests/**/*.test.ts'],
    watch: false,
  },
});
