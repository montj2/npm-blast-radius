import js from '@eslint/js';
import globals from 'globals';

export default [
  js.configs.recommended,
  {
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: 'module',
      globals: {
        ...globals.node,
        ...globals.es2023,
      },
    },
    rules: {
      'no-console': 'off',
      'no-unused-vars': ['warn', { args: 'none', ignoreRestSiblings: true }],
      'no-constant-binary-expression': 'error',
      'no-unreachable-loop': 'error',
      'no-var': 'error',
      'prefer-const': ['warn', { destructuring: 'all' }],
      'no-empty': ['error', { allowEmptyCatch: false }],
    },
    ignores: ['node_modules/**', 'out*.csv', 'out/**', 'coverage/**', 'dist/**'],
  },
];
