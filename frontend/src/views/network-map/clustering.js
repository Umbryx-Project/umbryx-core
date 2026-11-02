/**
 * Network map clustering — groups nodes by subnet/region for collapse.
 *
 * Features:
 * - Auto-collapse by node count threshold
 * - Zoom-aware collapse (collapse when zoomed out, expand when zoomed in)
 * - Manual zone overrides (assign nodes to custom zones)
 * - Settings persistence per network
 */

export const AUTO_COLLAPSE_THRESHOLD = 40;
export const DEFAULT_COLLAPSE_ZOOM = 0.55;
export const DEFAULT_EXPAND_ZOOM = 0.9;

/**
 * Default cluster settings.
 */
export function defaultSettings() {
  return {
    collapseThreshold: AUTO_COLLAPSE_THRESHOLD,
    collapseZoomLevel: DEFAULT_COLLAPSE_ZOOM,
    expandZoomLevel: DEFAULT_EXPAND_ZOOM,
    zoneOverrides: {},
    customZones: {},
    zoneLocks: {},
  };
}

/**
 * Determine if clusters should be auto-collapsed based on zoom + node count.
 * Returns: 'collapsed' | 'expanded' | 'manual'
 */
export function getAutoCollapseMode(zoom, nodeCount, settings) {
  const s = settings || defaultSettings();
  if (nodeCount < s.collapseThreshold) return 'manual';
  if (zoom < s.collapseZoomLevel) return 'collapsed';
  if (zoom >= s.expandZoomLevel) return 'expanded';
  return 'manual';
}

/**
 * Compute the effective set of collapsed cluster keys.
 * Per-zone locks override zoom-based auto behavior:
 * - zoneLocks[key] === 'collapsed' → always collapsed
 * - zoneLocks[key] === 'expanded' → never collapsed
 * - absent → follow autoMode
 */
export function getEffectiveCollapsed(clusters, autoMode, zoneLocks) {
  const result = new Set();
  const locks = zoneLocks || {};
  for (const c of clusters) {
    const lock = locks[c.key];
    if (lock === 'collapsed') {
      result.add(c.key);
    } else if (lock === 'expanded') {
      // never collapsed
    } else if (autoMode === 'collapsed') {
      result.add(c.key);
    }
  }
  return result;
}

/**
 * Cycle a zone lock: undefined → 'collapsed' → 'expanded' → undefined
 */
export function cycleZoneLock(zoneLocks, key) {
  const next = { ...(zoneLocks || {}) };
  const current = next[key];
  if (current === 'collapsed') {
    next[key] = 'expanded';
  } else if (current === 'expanded') {
    delete next[key];
  } else {
    next[key] = 'collapsed';
  }
  return next;
}

/**
 * Assign each node to a cluster key based on:
 * 1. Manual zone override (if exists in settings.zoneOverrides)
 * 2. Region containment (if node x/y falls inside a region rect)
 * 3. Subnet grouping (by /24 of node.ip)
 * 4. Custom zone assignment
 * 5. Fallback: "ungrouped"
 */
export function computeClusters(nodes, regions, settings) {
  const nodeClusters = new Map();
  const zoneOverrides = settings?.zoneOverrides || {};
  const customZones = settings?.customZones || {};

  // Reverse map: for each custom zone, what nodes are assigned to it
  const customZoneMembers = new Map();
  for (const [nodeId, zoneKey] of Object.entries(zoneOverrides)) {
    if (!customZoneMembers.has(zoneKey)) customZoneMembers.set(zoneKey, []);
    customZoneMembers.get(zoneKey).push(nodeId);
  }

  for (const node of nodes) {
    let key;

    // 1. Manual override takes priority
    if (zoneOverrides[node.id]) {
      key = zoneOverrides[node.id];
    }
    // 2. Region containment
    else {
      let assigned = false;
      for (const region of regions || []) {
        if (
          node.x >= region.x && node.x <= region.x + (region.w || 0) &&
          node.y >= region.y && node.y <= region.y + (region.h || 0)
        ) {
          key = `region:${region.id}`;
          assigned = true;
          break;
        }
      }
      // 3. Subnet grouping
      if (!assigned) {
        const subnet = node.subnet || _extractSubnet(node.ip);
        key = subnet ? `subnet:${subnet}` : 'ungrouped';
      }
    }

    nodeClusters.set(node.id, key);
  }

  // Build cluster objects
  const clusterMap = new Map();
  for (const node of nodes) {
    const key = nodeClusters.get(node.id);
    if (!clusterMap.has(key)) {
      clusterMap.set(key, {
        key,
        nodeIds: [],
        x: 0, y: 0,
        labels: new Set(),
        zoneTypes: new Set(),
        statuses: new Map(),
        errorCount: 0,
        hasFailover: false,
        isCustom: key.startsWith('custom:'),
      });
    }
    const c = clusterMap.get(key);
    c.nodeIds.push(node.id);
    c.x += node.x;
    c.y += node.y;
    if (node.label) c.labels.add(node.label);
    if (node.zone_type) c.zoneTypes.add(node.zone_type);
    const st = node.status || 'unknown';
    c.statuses.set(st, (c.statuses.get(st) || 0) + 1);
    if (st === 'failed' || st === 'error' || st === 'down') c.errorCount++;
  }

  const regionById = new Map((regions || []).map(r => [r.id, r]));

  const clusters = [];
  for (const [key, c] of clusterMap) {
    const n = c.nodeIds.length;
    c.x /= n;
    c.y /= n;

    let label, zoneType, color;
    if (key.startsWith('region:')) {
      const rid = key.slice(7);
      const region = regionById.get(rid);
      label = region?.label || 'Region';
      zoneType = region?.zone_type || [...c.zoneTypes][0];
      color = region?.stroke;
      if (region) {
        c.x = region.x + region.w / 2;
        c.y = region.y + region.h / 2;
      }
    } else if (key.startsWith('subnet:')) {
      label = key.slice(7);
      zoneType = [...c.zoneTypes][0];
    } else if (key.startsWith('custom:')) {
      const cz = customZones[key];
      label = cz?.label || key.slice(7);
      zoneType = cz?.zoneType || 'custom';
      color = cz?.color;
    } else {
      label = n === 1 ? (c.labels.values().next().value || 'Node') : `${n} nodes`;
      zoneType = [...c.zoneTypes][0];
    }

    clusters.push({
      key,
      label,
      x: c.x,
      y: c.y,
      nodeCount: n,
      errorCount: c.errorCount,
      zoneType: zoneType || null,
      hasFailover: c.hasFailover,
      nodeIds: c.nodeIds,
      isCustom: c.isCustom,
      color: color || null,
      topStatus: _topStatus(c.statuses),
    });
  }

  return { clusters, nodeClusters };
}

function _topStatus(statusMap) {
  const _RANK = { owned: 5, pwned: 5, access: 4, up: 3, scanned: 2, alive: 1, unknown: 0 };
  let best = null;
  let bestRank = -1;
  for (const [status, count] of statusMap) {
    const rank = _RANK[status] ?? 0;
    if (rank > bestRank) { bestRank = rank; best = status; }
  }
  return best;
}

function _extractSubnet(ip) {
  if (!ip || typeof ip !== 'string') return null;
  const parts = ip.split('.');
  if (parts.length === 4) {
    return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
  }
  return null;
}

/**
 * Compute inter-cluster edges (edges between nodes in different clusters).
 */
export function computeClusterEdges(edges, nodeClusters, clusters) {
  const clusterByKey = new Map(clusters.map(c => [c.key, c]));
  const seen = new Set();
  const countMap = new Map();
  const edgeMap = new Map();

  for (const edge of edges || []) {
    const fromKey = nodeClusters.get(edge.from);
    const toKey = nodeClusters.get(edge.to);
    if (!fromKey || !toKey || fromKey === toKey) continue;

    const pairKey = fromKey < toKey ? `${fromKey}|${toKey}` : `${toKey}|${fromKey}`;
    countMap.set(pairKey, (countMap.get(pairKey) || 0) + 1);

    if (seen.has(pairKey)) continue;
    seen.add(pairKey);

    const fromCluster = clusterByKey.get(fromKey);
    const toCluster = clusterByKey.get(toKey);
    if (!fromCluster || !toCluster) continue;

    edgeMap.set(pairKey, {
      id: `cluster-edge-${pairKey}`,
      fromKey, toKey,
      fromX: fromCluster.x, fromY: fromCluster.y,
      toX: toCluster.x, toY: toCluster.y,
      count: countMap.get(pairKey),
    });
  }

  return [...edgeMap.values()];
}

/**
 * Load/save cluster settings from localStorage.
 */
export function loadClusterSettings(networkId) {
  try {
    const raw = localStorage.getItem(`netmap-cluster-settings-${networkId}`);
    if (raw) return { ...defaultSettings(), ...JSON.parse(raw) };
  } catch { /* unreadable or stale JSON — fall through to the defaults */ }
  return defaultSettings();
}

export function saveClusterSettings(networkId, settings) {
  try {
    localStorage.setItem(`netmap-cluster-settings-${networkId}`, JSON.stringify(settings));
  } catch { /* storage full or blocked — cluster settings are a convenience */ }
}

export function loadCollapseState(networkId) {
  try {
    const raw = localStorage.getItem(`netmap-collapse-${networkId}`);
    if (raw) return new Set(JSON.parse(raw));
  } catch { /* unreadable or stale JSON — fall through to nothing collapsed */ }
  return null;
}

export function saveCollapseState(networkId, collapsedKeys) {
  try {
    localStorage.setItem(`netmap-collapse-${networkId}`, JSON.stringify([...collapsedKeys]));
  } catch { /* storage full or blocked — collapse state is a convenience */ }
}
