/**
 * Extension store — fetches and caches extension point data from the backend.
 *
 * Modules declare their UI extensions (sidebar.nav, dashboard.widget, etc.)
 * in manifest.yaml. The backend aggregates these into the extension point
 * registry. This store fetches them and makes them available to React.
 */

import { useSyncExternalStore } from 'react';
import { api } from '../api.js';

let cache = {};
let loading = false;
let loaded = false;
const listeners = new Set();

function emit() {
  listeners.forEach((fn) => fn());
}

export async function loadExtensions() {
  if (loading || loaded) return;
  loading = true;
  try {
    const data = await api.listExtensions();
    cache = data.extensions || {};
    loaded = true;
    emit();
  } catch {
    // Best-effort
  } finally {
    loading = false;
  }
}

export function getExtensions(point) {
  return cache[point] || [];
}

export function getAllExtensions() {
  return cache;
}

export function isExtensionsLoaded() {
  return loaded;
}

function subscribe(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

function getSnapshot() {
  return cache;
}

export function useExtensions(point) {
  useSyncExternalStore(subscribe, getSnapshot);
  if (point) return cache[point] || [];
  return cache;
}

export function invalidateExtensions() {
  loaded = false;
  cache = {};
  emit();
}
