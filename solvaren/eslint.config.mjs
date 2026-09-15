import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: ['**/dist/**', '**/node_modules/**', '**/*.js', '**/*.mjs', 'coverage/**'],
  },
  eslint.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  ...tseslint.configs.stylisticTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
      },
    },
    rules: {
      // The one that matters most on this codebase: a dropped `await` on an audit write
      // compiles, reviews cleanly, and loses the record of a payment.
      '@typescript-eslint/no-floating-promises': 'error',

      // Type-aware strictness kept, with reasons for each relaxation.
      '@typescript-eslint/no-non-null-assertion': 'error',
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/explicit-module-boundary-types': 'off', // route handlers are inferred by Hono's generics
      '@typescript-eslint/consistent-type-imports': ['error', { prefer: 'type-imports' }],
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],

      // Circularity risk in the kernel: the domain must stay import-clean.
      'import/no-cycle': 'off', // handled by package boundaries, not the linter
    },
  },
  {
    // Test files: expect()/unreachable() patterns are legitimate there.
    files: ['**/*.test.ts', '**/*.test.tsx'],
    rules: {
      '@typescript-eslint/no-unsafe-assignment': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
    },
  },
);
