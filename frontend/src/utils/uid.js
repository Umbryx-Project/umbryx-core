/**
 * Random id that works everywhere.
 *
 * crypto.randomUUID() is only available in secure contexts (https or
 * localhost) — on the plain-http on-prem deployments it is undefined, and
 * every direct call crashed the calling code (toasts silently never
 * rendered; see Toast.jsx). Fall back to timestamp + Math.random.
 */
export function uid() {
  return globalThis.crypto?.randomUUID?.() || `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}
