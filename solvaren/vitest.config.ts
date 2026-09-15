import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['packages/**/*.test.ts', 'apps/**/*.test.ts'],
    environment: 'node',
    testTimeout: 30_000,
    hookTimeout: 30_000,
    coverage: {
      provider: 'v8',
      reportsDirectory: 'coverage',
      include: ['packages/*/src/**', 'apps/api/src/**'],
      exclude: ['**/*.test.ts', '**/test-harness.ts', '**/scripted-provider.ts'],
    },
  },
});
