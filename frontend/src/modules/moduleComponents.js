/**
 * Module component registry.
 *
 * Maps component names declared in manifest.yaml `extensions` → lazy-loaded
 * React components. This is the bridge between the backend's declarative
 * extension metadata and the frontend's actual rendering.
 *
 * Built-in module components are registered here statically.
 * Third-party modules would use dynamic import (future work).
 */

import { lazy } from 'react';

const registry = {};

export function registerComponent(name, component) {
  registry[name] = component;
}

export function getComponent(name) {
  return registry[name] || null;
}

export function hasComponent(name) {
  return name in registry;
}

// ── Built-in module components ──────────────────────────────────────────
// Each entry maps a manifest `component:` name to a lazy-loaded React component.

registerComponent('IOCWidget', lazy(() => import('./ext/ioc-tracker/IOCWidget.jsx')));
registerComponent('HostIOCTab', lazy(() => import('./ext/ioc-tracker/HostIOCTab.jsx')));
