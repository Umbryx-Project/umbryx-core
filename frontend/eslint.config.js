import js from '@eslint/js';
import reactHooks from 'eslint-plugin-react-hooks';
import reactRefresh from 'eslint-plugin-react-refresh';
import globals from 'globals';

export default [
  { ignores: ['dist', 'node_modules'] },
  {
    // Vitest injects describe/it/expect/afterEach, so no-undef needs to know
    // about them in test files.
    files: ['**/*.test.{js,jsx}'],
    languageOptions: { globals: { ...globals.vitest } },
  },
  {
    files: ['**/*.{js,jsx}'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: {
        ...globals.browser,
        ...globals.es2022,
      },
      parserOptions: {
        ecmaFeatures: { jsx: true },
      },
    },
    plugins: {
      'react-hooks': reactHooks,
      'react-refresh': reactRefresh,
    },
    rules: {
      ...js.configs.recommended.rules,
      ...reactHooks.configs.recommended.rules,
      'react-refresh/only-export-components': ['warn', { allowConstantExport: true }],
      'no-unused-vars': ['warn', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
      'no-console': ['warn', { allow: ['warn', 'error'] }],
      // Two correctness rules from eslint's recommended set, which this
      // config never enabled. Both caught real bugs the day they went on:
      // a stray second comma in the Enterprise tab registry put a hole in
      // the array and crashed the whole Infrastructure page, and inpStyle
      // was referenced in the provisioning dialogs without being declared.
      // The rest of recommended is not on yet — it reports ~80 more, almost
      // all no-empty and no-useless-escape, which is a cleanup of its own.

    },
  },
];
