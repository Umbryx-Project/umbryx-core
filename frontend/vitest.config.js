import { defineConfig } from 'vitest/config';
import { edition, eeAlias } from './edition.config.js';

export default defineConfig({
  // No @vitejs/plugin-react here: plugin-react 6 targets vite 8 while
  // vitest bundles its own vite major, and the mismatch crashes the forks
  // worker bootstrap. esbuild's automatic JSX runtime covers test files.
  esbuild: { jsx: 'automatic' },
  // Same `@ee` resolution as the build (see edition.config.js): a test run
  // must not quietly resolve the Enterprise registry for a Community build.
  resolve: { alias: eeAlias },
  define: { __UMBRYX_EDITION__: JSON.stringify(edition) },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.js'],
    include: ['src/**/*.{test,spec}.{js,jsx}'],
    coverage: {
      provider: 'v8',
      reporter: ['text-summary', 'lcov'],
      reportsDirectory: './coverage',
      include: ['src/**/*.{js,jsx}'],
      exclude: [
        'src/**/*.{test,spec}.{js,jsx}',
        'src/test/**',
        'src/main.jsx',
      ],
    },
  },
});
