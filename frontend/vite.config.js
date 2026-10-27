import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { edition, eeAlias } from './edition.config.js'

export default defineConfig({
  plugins: [react()],
  resolve: { alias: eeAlias },
  define: { __UMBRYX_EDITION__: JSON.stringify(edition) },
  server: {
    proxy: {
      '/api': 'http://localhost:8000',
    },
  },
})
