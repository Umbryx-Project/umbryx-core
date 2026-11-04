/**
 * Which edition this frontend build is, and where `@ee` points.
 *
 * Shared by vite.config.js and vitest.config.js on purpose: the test run
 * must resolve `@ee` exactly the way the build does, or a Community build
 * could pass its tests against the Enterprise registry
 * (docs/modules/EDITIONS.md).
 *
 * UMBRYX_EDITION=ce forces Community. Otherwise the edition is whatever is
 * on disk — the Enterprise registry when src/ee/ is present, the stub once
 * scripts/build-ce.sh has removed it. Derived from the tree rather than
 * required as a variable, so a Community checkout cannot be built as
 * Enterprise by forgetting to set something.
 */
import { existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const here = (p) => fileURLToPath(new URL(p, import.meta.url))

export const EE_DIR = here('./src/ee')
export const EE_STUB_DIR = here('./src/ee-stub')

export const edition =
  process.env.UMBRYX_EDITION === 'ce' || !existsSync(EE_DIR) ? 'ce' : 'ee'

export const eeAlias = { '@ee': edition === 'ee' ? EE_DIR : EE_STUB_DIR }
