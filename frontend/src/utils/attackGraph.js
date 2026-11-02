export const STATUS_COLOR = {
  unknown: '#404550', up: '#5b8af5', alive: '#5b8af5', scanned: '#c07af0',
  access: '#f09a3a', pwned: '#cc2233', owned: '#39d353',
};

export const CRED_COLOR = {
  plain: '#39d353', hash: '#c07af0', ntlm: '#c07af0',
  key: '#5b8af5', kerberos: '#f09a3a',
};

export const ACCESS_COLOR = {
  verified: '#39d353',
  inferred: '#f09a3a',
  path: '#5b8af5',
  domain_admin: '#e8574a',
  pivot: '#c07af0',
  pivot_route: '#8060c0',
};

export const SEV_COLOR = {
  critical: '#cc2233', high: '#e8574a', medium: '#f09a3a', low: '#e8cc42', info: '#5b8af5',
};

export const NODE_W = 164;
export const NODE_H = 68;
export const CRED_W = 130;
export const CRED_H = 44;

// Type-aware half-dimensions: cred pills are smaller than host cards.
// Edge anchors MUST use these — a fixed NODE_W/2 anchor leaves cred edges
// detached from the pill by (NODE_W - CRED_W)/2 px.
export const nodeHalfW = n => (n && n.type === 'cred' ? CRED_W / 2 : NODE_W / 2);
export const nodeHalfH = n => (n && n.type === 'cred' ? CRED_H / 2 : NODE_H / 2);

// AG Phase 1: layered layout — columns are BFS depth from the attacker
// over ALL edge kinds (incl. cred chains), so the picture reads "how deep
// are we": 0 = attacker, 1 = creds we hold, 2 = hosts they open, ...
// Unreached nodes go to the last column ("not yet"). Manual positions
// still win (applyNodePos runs after this).
export function layoutNodes(raw, canvasH, edges = []) {
  const nodes = raw.map(n => ({ ...n }));
  const byId = new Map(nodes.map(n => [n.id, n]));

  const adjacency = new Map();
  for (const e of edges) {
    const f = String(e.from || ''), t = String(e.to || '');
    if (!byId.has(f) || !byId.has(t)) continue;
    if (!adjacency.has(f)) adjacency.set(f, []);
    adjacency.get(f).push(t);
  }

  const dist = new Map();
  const queue = [];
  for (const n of nodes) {
    if (n.type === 'attacker' || n.is_attacker) { dist.set(n.id, 0); queue.push(n.id); }
  }
  while (queue.length) {
    const cur = queue.shift();
    for (const nxt of adjacency.get(cur) || []) {
      if (dist.has(nxt)) continue;
      dist.set(nxt, dist.get(cur) + 1);
      queue.push(nxt);
    }
  }

  const maxDist = Math.max(0, ...[...dist.values()]);
  const columns = new Map();
  for (const n of nodes) {
    const d = dist.has(n.id) ? dist.get(n.id) : maxDist + 1;
    if (!columns.has(d)) columns.set(d, []);
    columns.get(d).push(n);
  }
  const colKeys = [...columns.keys()].sort((a, b) => a - b);

  // Initial order: hosts before cred pills, alphabetical inside each
  // band — readable starting point for the sweeps below.
  for (const key of colKeys) {
    columns.get(key).sort((a, b) =>
      ((a.type === 'cred') - (b.type === 'cred')) || String(a.label).localeCompare(String(b.label)));
  }

  // ── Crossing minimization (Sugiyama barycenter) ─────────────────────
  // Alphabetical columns ignore the edges entirely: a cred at the bottom
  // of its column reaches an alphabetical host at the top of the next —
  // every such edge is a tall S-curve crossing its neighbours
  // ("пируэты"). Repeated sweeps sort each column by the AVERAGE
  // position of its neighbours in the adjacent column, pulling connected
  // nodes level with each other. 3 down + 2 up sweeps converge well for
  // engagement-sized graphs; stable sort keeps isolated nodes put.
  const neighbours = new Map(); // id -> [{ id }]
  for (const e of edges) {
    const f = String(e.from || ''), t = String(e.to || '');
    if (!byId.has(f) || !byId.has(t)) continue;
    if (!neighbours.has(f)) neighbours.set(f, []);
    if (!neighbours.has(t)) neighbours.set(t, []);
    neighbours.get(f).push({ id: t });
    neighbours.get(t).push({ id: f });
  }
  const sweep = (k, dir) => {
    const layer = columns.get(colKeys[k]);
    const other = columns.get(colKeys[k + dir]);
    if (!other) return;
    const rank = new Map(other.map((n, i) => [n.id, i]));
    const keyed = layer.map((n, i) => {
      const ns = (neighbours.get(n.id) || []).filter(x => rank.has(x.id));
      const bary = ns.length ? ns.reduce((s, x) => s + rank.get(x.id), 0) / ns.length : i;
      return { n, bary, i };
    });
    keyed.sort((a, b) => (a.bary - b.bary) || (a.i - b.i));
    columns.set(colKeys[k], keyed.map(x => x.n));
  };
  for (let pass = 0; pass < 3; pass++) {
    for (let k = 1; k < colKeys.length; k++) sweep(k, -1); // down the flow
    for (let k = colKeys.length - 2; k >= 0; k--) sweep(k, +1); // and back up
  }

  const COL_W = 270, X0 = 150, TOP = 50, BOTTOM = 50;
  const usableH = Math.max(320, canvasH) - TOP - BOTTOM;
  for (const key of colKeys) {
    const bucket = columns.get(key);
    const rowH = Math.min(112, usableH / Math.max(1, bucket.length));
    const y0 = TOP + (usableH - rowH * (bucket.length - 1)) / 2;
    bucket.forEach((n, i) => {
      n.x = X0 + colKeys.indexOf(key) * COL_W;
      n.y = y0 + i * rowH;
    });
  }
  return nodes;
}

const POS_KEY = pid => `ag_pos_${pid}`;
export const loadPos = pid => { try { return JSON.parse(localStorage.getItem(POS_KEY(pid)) || '{}'); } catch { return {}; } };
export const savePos = (pid, pos) => { try { localStorage.setItem(POS_KEY(pid), JSON.stringify(pos)); } catch { /* storage full or blocked — saved positions are a convenience */ } };

function bezierPoint(x0, y0, x1, y1, x2, y2, x3, y3, t) {
  const u = 1 - t;
  return {
    x: u * u * u * x0 + 3 * u * u * t * x1 + 3 * u * t * t * x2 + t * t * t * x3,
    y: u * u * u * y0 + 3 * u * u * t * y1 + 3 * u * t * t * y2 + t * t * t * y3,
  };
}

// Edge routing v5 — pure fixed ports, no exceptions.
// Every edge leaves the right-face port and enters the left-face port:
// the anchor lives at a FIXED offset from its node's center, so while a
// node is dragged the attachment cannot slide around the border (the
// v2-v4 perimeter/blend anchors did — "крепление перебегает").
//  - forward (port-to-port gap > 24): single cubic S-curve
//  - backward / same column: two-cubic dome wrap over the top (bend < 0
//    wraps under), entering the left port horizontally from the left —
//    no single cubic can do that without cutting the cards between
export function edgeGeometry(src, tgt, bend = 0, columnBlocked = false) {
  const hwS = nodeHalfW(src), hhS = nodeHalfH(src);
  const hwT = nodeHalfW(tgt), hhT = nodeHalfH(tgt);
  const bendY = bend * 12;
  const sx = src.x + hwS;
  const sy = src.y + bendY;
  const tx = tgt.x - hwT;
  const ty = tgt.y + bendY;
  const gap = tx - sx;

  if (gap > 24) {
    const stem = Math.max(30, Math.min(130, gap * 0.45));
    const c1x = sx + stem, c1y = sy;
    const c2x = tx - stem, c2y = ty;
    return {
      d: `M ${sx} ${sy} C ${c1x} ${c1y} ${c2x} ${c2y} ${tx} ${ty}`,
      label: bezierPoint(sx, sy, c1x, c1y, c2x, c2y, tx, ty, 0.5),
    };
  }

  const sameColumn = Math.abs(tgt.x - src.x) < hwS + hwT + 20;

  if (sameColumn && columnBlocked) {
    // Cards sit between src and tgt in this column: approach from the
    // RIGHT — out past the column edge, level with the target, back into
    // its right port. Nothing between to cut; the arrow visibly enters
    // the card.
    const ex = tgt.x + hwT;
    const ey = ty;
    const outX = Math.max(sx, ex) + Math.max(50, Math.abs(sy - ty) * 0.25);
    const levelY = sy + (ty - sy) * 0.5;
    return {
      d: `M ${sx} ${sy} C ${outX} ${sy} ${outX} ${levelY} ${outX} ${(sy + levelY) / 2}`
        + ` C ${outX} ${ty} ${ex + 40} ${ey} ${ex} ${ey}`,
      label: { x: outX + 12, y: (sy + ty) / 2 },
    };
  }

  if (sameColumn) {
    // Adjacent rows, column clear between: compact loop into the LEFT
    // port, sized by the hop distance (the v5 dome used a fixed tall
    // clearance — a one-row hop drew a huge arc, "пируэт").
    const clearance = Math.max(28, Math.min(90, 28 + Math.abs(ty - sy) * 0.2));
    const over = bend >= 0;
    const by = over
      ? Math.min(src.y - hhS, tgt.y - hhT) - clearance
      : Math.max(src.y + hhS, tgt.y + hhT) + clearance;
    const stOut = 40;
    const stIn = 26;
    const midX = tx - stIn;
    const p1x = midX + 44;
    const d1 = `M ${sx} ${sy} C ${sx + stOut} ${sy} ${p1x + 18} ${by} ${p1x} ${by}`;
    const d2 = `C ${midX} ${by + (ty - by) * 0.4} ${midX} ${ty} ${tx} ${ty}`;
    return {
      d: `${d1} ${d2}`,
      label: { x: (p1x + midX) / 2, y: by },
    };
  }

  // inter-column backward edge: dome bridge over (or under for the twin)
  const over = bend >= 0;
  const clearance = Math.max(50, Math.min(110, 40 + Math.abs(ty - sy) * 0.2));
  const by = over
    ? Math.min(src.y - hhS, tgt.y - hhT) - clearance
    : Math.max(src.y + hhS, tgt.y + hhT) + clearance;
  const stOut = 46;
  const stIn = 30;
  const midX = tx - stIn;          // approach line: x just left of the port
  const p1x = midX + 60;           // dome corner (right of the approach)
  const d1 = `M ${sx} ${sy} C ${sx + stOut} ${sy} ${p1x + 24} ${by} ${p1x} ${by}`;
  const d2 = `C ${midX} ${by + (ty - by) * 0.45} ${midX} ${ty} ${tx} ${ty}`;
  return {
    d: `${d1} ${d2}`,
    label: { x: (p1x + midX) / 2, y: by },
  };
}

export function nodeOsShort(os) {
  if (!os) return '';
  if (os.includes('Windows')) return 'WIN';
  if (os.includes('Linux')) return 'LIN';
  return os.slice(0, 3).toUpperCase();
}

export function nodeReachBadge(reach) {
  if (reach.is_root) return null;
  if (reach.reachable_via_verified_path) return `v${reach.verified_distance}`;
  if (reach.reachable) return `r${reach.distance}`;
  return null;
}

export function nodeBorderColor(selected, isAttacker, onPath, isDA, sc) {
  if (selected) return '#ffffff';
  if (isAttacker) return '#cc2233';
  if (onPath && isDA) return '#e8574a';
  if (onPath) return '#e8cc42';
  return sc;
}

export function nodeBgFill(isAttacker, onPath, isDA) {
  if (isAttacker) return '#1a0a0a';
  if (onPath && isDA) return '#1a0a06';
  if (onPath) return '#141208';
  return '#0d0f14';
}

export function edgeColor(edge, isPrivPath, isPivotRoute, isPivot, isAccess, isDomainAdmin, isPath) {
  if (isPrivPath) return '#e8574a';
  if (edge.kind === 'credential') return '#5b8af5';
  if (edge.kind === 'credential_use') return '#39d353';
  if (isPivotRoute) return ACCESS_COLOR.pivot_route;
  if (isPivot) return ACCESS_COLOR.pivot;
  if (isAccess) {
    if (edge.access_type === 'exploit') return '#cc2233';
    if (isDomainAdmin) return ACCESS_COLOR.domain_admin;
    if (edge.access_type === 'lateral' || edge.access_type === 'pivot') return '#e8cc42';
    if (edge.access_type === 'tunnel') return '#5b8af5';
    return edge.verified ? ACCESS_COLOR.verified : ACCESS_COLOR.inferred;
  }
  if (isPath) return ACCESS_COLOR.path;
  return CRED_COLOR[edge.cred_type] || CRED_COLOR.plain;
}

export function edgeStrokeDash(isPrivPath, isPivotRoute, isPivot, isDomainAdmin, isAccess, isPath, verified) {
  if (isPrivPath) return '10 4';
  if (isPivotRoute) return '3 6';
  if (isPivot) return '5 3';
  if ((isDomainAdmin || isAccess) && !verified) return '6 4';
  if (isPath) return '3 5';
  return undefined;
}

export function edgeStrokeW(isPrivPath, isPivotRoute, isPivot, isDomainAdmin, isAccess) {
  if (isPrivPath) return 3;
  if (isDomainAdmin) return 2.5;
  if (isAccess) return 2.2;
  if (isPivot || isPivotRoute) return 1.8;
  return 1.5;
}

export function edgeOpacity(dimmed, isPrivPath, isPivotRoute, isAccess, isDomainAdmin) {
  if (dimmed) return 0.12;
  if (isPrivPath) return 1;
  if (isPivotRoute) return 0.45;
  if (isAccess || isDomainAdmin) return 0.8;
  return 0.55;
}

export function applyNodePos(rawNodes, nodePos) {
  return rawNodes.map(n => ({
    ...n,
    x: nodePos[n.id]?.x ?? n.x,
    y: nodePos[n.id]?.y ?? n.y,
  }));
}

export const DEFAULT_GRAPH_FILTERS = {
  creds: true,      // credential + credential_use edges
  access: true,     // access edges (network graph)
  verifiedOnly: false,
  pivots: true,     // pivot + pivot_route
  paths: false,     // Attack Path step edges (off by default — noise)
};

export function filterEdges(allEdges, filters) {
  if (!filters) return allEdges;
  return allEdges.filter(e => {
    if (e.kind === 'credential' || e.kind === 'credential_use') return filters.creds;
    if (e.kind === 'pivot' || e.kind === 'pivot_route') return filters.pivots;
    if (e.kind === 'path') return filters.paths;
    if (e.kind === 'access') {
      if (filters.verifiedOnly && !e.verified) return false;
      return filters.access;
    }
    return true;
  });
}

export function matchesSearch(node, q) {
  if (!q) return true;
  const needle = q.toLowerCase();
  return [node.label, node.ip, node.username, node.domain, node.hostname]
    .filter(Boolean).some(v => String(v).toLowerCase().includes(needle));
}

export function computeArrowColors(edges) {
  return [...new Set(edges.map(e => edgeColor(
    e, false,
    e.kind === 'pivot_route', e.kind === 'pivot', e.kind === 'access',
    e.kind === 'access' && e.access_type === 'domain_admin',
    e.kind === 'path',
  )))];
}

export function getSelectedNodeEdges(allEdges, selectedNode) {
  if (!selectedNode) return [];
  return allEdges.filter(e => e.from === selectedNode.id || e.to === selectedNode.id);
}

export function getLinkedCreds(allCreds, selectedNode) {
  if (!selectedNode) return [];
  return allCreds.filter(c => (c.host_ids || []).includes(selectedNode.id));
}

export function deriveGraphState(graphData, nodePos, canvasH, filters, selectedNode, allCreds, search) {
  const allEdges = graphData?.edges || [];
  const rawNodes = layoutNodes(graphData?.nodes || [], canvasH, allEdges);
  const nodes = applyNodePos(rawNodes, nodePos).map(n => ({
    ...n,
    dimmed: !!search && !matchesSearch(n, search),
  }));
  const edges = filterEdges(allEdges, filters);
  const arrowColors = computeArrowColors(edges);

  const stats = graphData?.stats || {};
  const privilegePaths = graphData?.privilege_paths || [];
  const privilegePathDetails = graphData?.privilege_path_details || [];
  const pivotChains = graphData?.pivot_chains || [];

  const selectedNodeEdges = getSelectedNodeEdges(allEdges, selectedNode);
  const linkedCreds = getLinkedCreds(allCreds, selectedNode);

  return {
    nodes, allEdges, edges, arrowColors, stats,
    privilegePaths, privilegePathDetails, pivotChains,
    selectedNodeEdges, linkedCreds,
  };
}

export function computeSelectedPathSets(selectedPathIdx, privilegePaths) {
  if (selectedPathIdx === null || !privilegePaths[selectedPathIdx]) return { nodeIds: null, edgePairs: null };
  const path = privilegePaths[selectedPathIdx];
  const nodeIds = new Set(path);
  const edgePairs = new Set();
  for (let i = 0; i < path.length - 1; i++) {
    edgePairs.add(`${path[i]}:${path[i + 1]}`);
    edgePairs.add(`${path[i + 1]}:${path[i]}`);
  }
  return { nodeIds, edgePairs };
}

export function computeLinkedFindings(selectedNode, allFindings) {
  if (!selectedNode) return [];
  const ip = (selectedNode.ip || '').toLowerCase();
  const hn = (selectedNode.label || selectedNode.hostname || '').toLowerCase();
  return allFindings.filter(f => {
    const t = `${f.title} ${f.description} ${f.proof}`.toLowerCase();
    return (ip && t.includes(ip)) || (hn && hn.length > 4 && t.includes(hn));
  });
}

export function isPivotEdge(e) { return e.kind === 'pivot' || e.kind === 'pivot_route'; }

export function computeEdgeDimmed(e, selectedPathEdgePairs) {
  if (selectedPathEdgePairs === null) return false;
  const isOnSelected = selectedPathEdgePairs.has(`${e.from}:${e.to}`) || selectedPathEdgePairs.has(`${e.to}:${e.from}`);
  return !isOnSelected && e.kind !== 'credential';
}

export function startNodeDrag(e, node, nodePos, zoom, { draggingNode, dragMoved, setNodePos, selectedProject, nodePosRef }) {
  e.stopPropagation();
  const nx = nodePos[node.id]?.x ?? node.x;
  const ny = nodePos[node.id]?.y ?? node.y;
  draggingNode.current = { nodeId: node.id, smx: e.clientX, smy: e.clientY, snx: nx, sny: ny };
  dragMoved.current = false;

  const onMove = ev => {
    const dn = draggingNode.current;
    if (!dn) return;
    const dx = (ev.clientX - dn.smx) / zoom;
    const dy = (ev.clientY - dn.smy) / zoom;
    if (Math.abs(dx) > 3 || Math.abs(dy) > 3) dragMoved.current = true;
    const id = dn.nodeId;
    setNodePos(prev => ({ ...prev, [id]: { x: dn.snx + dx, y: dn.sny + dy } }));
  };
  const onUp = () => {
    if (draggingNode.current && dragMoved.current) {
      // Save the LIVE map, not the drag-start closure: this function's
      // nodePos param is a snapshot from before the drag, so saving it
      // wrote pre-drag positions (drags never persisted across reload).
      savePos(selectedProject, nodePosRef ? nodePosRef.current : { ...nodePos });
    }
    draggingNode.current = null;
    globalThis.removeEventListener('mousemove', onMove);
    globalThis.removeEventListener('mouseup', onUp);
  };
  globalThis.addEventListener('mousemove', onMove);
  globalThis.addEventListener('mouseup', onUp);
}

export function startCanvasPan(e, pan, isPanning, panStart, setPan, draggingNode) {
  if (e.button !== 0 || draggingNode.current) return;
  isPanning.current = true;
  panStart.current = { x: e.clientX, y: e.clientY, px: pan.x, py: pan.y };

  const onMove = ev => {
    if (!isPanning.current || !panStart.current) return;
    setPan({ x: panStart.current.px + (ev.clientX - panStart.current.x), y: panStart.current.py + (ev.clientY - panStart.current.y) });
  };
  const onUp = () => {
    isPanning.current = false;
    globalThis.removeEventListener('mousemove', onMove);
    globalThis.removeEventListener('mouseup', onUp);
  };
  globalThis.addEventListener('mousemove', onMove);
  globalThis.addEventListener('mouseup', onUp);
}

export function renderChainNodeText(hid, si, chain, nodes, selectedNodeId) {
  const n = nodes.find(x => x.id === hid);
  const isSelf = hid === selectedNodeId;
  return { text: n?.label || n?.ip || hid.slice(0, 10), isSelf, isLast: si >= chain.length - 1 };
}

// ── AG Phase 2: comprehension helpers ──────────────────────────────────

// Shortest chain attacker → node over all edge kinds. Returns
// [{node, viaEdge}] or null when unreachable.
export function pathFromAttacker(nodes, edges, targetId) {
  const byId = new Map(nodes.map(n => [n.id, n]));
  const adjacency = new Map();
  for (const e of edges) {
    const f = String(e.from || ''), t = String(e.to || '');
    if (!byId.has(f) || !byId.has(t)) continue;
    if (!adjacency.has(f)) adjacency.set(f, []);
    adjacency.get(f).push({ to: t, edge: e });
  }
  const roots = nodes.filter(n => n.type === 'attacker' || n.is_attacker).map(n => n.id);
  const prev = new Map(roots.map(r => [r, null]));
  const queue = [...roots];
  while (queue.length) {
    const cur = queue.shift();
    if (cur === targetId) break;
    for (const { to, edge } of adjacency.get(cur) || []) {
      if (prev.has(to)) continue;
      prev.set(to, { from: cur, edge });
      queue.push(to);
    }
  }
  if (!prev.has(targetId)) return null;
  const chain = [];
  let cur = targetId;
  while (true) {
    const step = prev.get(cur);
    chain.unshift({ node: byId.get(cur), viaEdge: step ? step.edge : null });
    if (!step) break;
    cur = step.from;
  }
  return chain;
}

// What this node opens: direct successors, grouped by edge kind.
export function opensFrom(nodes, edges, nodeId) {
  const byId = new Map(nodes.map(n => [n.id, n]));
  return edges
    .filter(e => e.from === nodeId && byId.has(e.to))
    .map(e => ({ node: byId.get(e.to), edge: e }));
}

// Human label for an edge in a chain (cred nodes already carry the name).
export function chainEdgeLabel(edge) {
  if (!edge) return '';
  if (edge.kind === 'credential') return 'holds';
  if (edge.kind === 'credential_use') return 'opens';
  if (edge.kind === 'pivot' || edge.kind === 'pivot_route') return 'pivot';
  return (edge.access_type || edge.label || edge.kind || '').replace(/_/g, ' ');
}

// Pan/zoom that fits a set of nodes (a DA path, or the whole graph) into
// the viewport.
export function fitNodesToViewport(pathNodes, viewport, currentPan, currentZoom, maxZoom = 2, pad = 140) {
  if (!pathNodes || pathNodes.length === 0) return null;
  const xs = pathNodes.map(n => n.x), ys = pathNodes.map(n => n.y);
  const minX = Math.min(...xs), maxX = Math.max(...xs);
  const minY = Math.min(...ys), maxY = Math.max(...ys);
  const w = Math.max(320, maxX - minX + pad * 2);
  const h = Math.max(240, maxY - minY + pad * 2);
  const zoom = Math.min(maxZoom, Math.max(0.25, Math.min(viewport.width / w, viewport.height / h)));
  const cx = (minX + maxX) / 2, cy = (minY + maxY) / 2;
  return {
    zoom,
    pan: { x: viewport.width / 2 - cx * zoom, y: viewport.height / 2 - cy * zoom },
  };
}

// ── AG Phase 3: frontier & freshness ───────────────────────────────────

// Stale threshold: an access fact older than this stops being something
// you can rely on tonight (creds rotate, hosts get patched).
export const STALE_AFTER_DAYS = 14;

export function edgeFreshness(edge, nowMs = Date.now()) {
  if (!edge?.observed_at) return null;
  const t = Date.parse(edge.observed_at);
  if (Number.isNaN(t)) return null;
  const ageDays = (nowMs - t) / 86_400_000;
  return { ageDays, stale: ageDays > STALE_AFTER_DAYS, at: edge.observed_at };
}

// The attack frontier: facts we believe but haven't confirmed.
export function isFrontierEdge(edge) {
  if (!edge) return false;
  if (edge.kind === 'access' || edge.kind === 'pivot' || edge.kind === 'pivot_route') {
    return !edge.verified;
  }
  return false;
}

export function computeFrontierSets(nodes, edges) {
  const frontierEdges = new Set();
  const frontierNodes = new Set();
  for (const n of nodes) {
    if (n.type === 'cred' && n.frontier) frontierNodes.add(n.id);
  }
  const byId = new Map(nodes.map(n => [n.id, n]));
  for (const e of edges) {
    if (isFrontierEdge(e)) {
      frontierEdges.add(e.id);
      // a credential edge to a frontier cred also marks the frontier
      if (e.kind === 'credential') frontierEdges.add(e.id);
      const t = byId.get(String(e.to));
      if (t && t.type !== 'cred') frontierNodes.add(t.id);
    }
  }
  // credential edges INTO frontier cred nodes are part of the frontier
  for (const e of edges) {
    if (e.kind === 'credential' && frontierNodes.has(String(e.to))) frontierEdges.add(e.id);
  }
  return { frontierNodes, frontierEdges };
}

// Next-step suggestions for the frontier panel: what to validate next.
// Creds first (a validated cred can unlock a whole column), then
// unconfirmed access edges.
export function frontierSuggestions(nodes, edges, limit = 8) {
  const byId = new Map(nodes.map(n => [n.id, n]));
  const out = [];
  for (const n of nodes) {
    if (n.type !== 'cred' || !n.frontier) continue;
    out.push({
      kind: 'validate_cred',
      severity: n.cracked ? 2 : 1,
      title: n.label,
      hint: n.cracked
        ? 'never validated on any host — run a validation job'
        : 'hash not cracked — no usable secret yet',
      focus: n.id.replace(/^cnode_/, ''),
      tab: 'creds',
    });
  }
  for (const e of edges) {
    if (!isFrontierEdge(e)) continue;
    const src = byId.get(String(e.from));
    const tgt = byId.get(String(e.to));
    if (!src || !tgt) continue;
    out.push({
      kind: 'confirm_access',
      severity: 3,
      title: `${src.label} → ${tgt.label}`,
      hint: e.kind === 'access' ? 'inferred access — confirm it works' : 'unconfirmed pivot observation',
      focus: String(e.to),
      tab: 'network',
    });
  }
  out.sort((a, b) => a.severity - b.severity);
  return out.slice(0, limit);
}

// ── AG Phase 3: PNG snapshot export ────────────────────────────────────

// Serialize the live SVG to a standalone PNG (2x). Fonts fall back to
// system monospace — external fonts can't load inside the rasterizer.
export function exportGraphPng(svgEl, filename = 'attack-graph.png') {
  if (!svgEl || typeof document === 'undefined') return false;
  const w = svgEl.clientWidth || 1200;
  const h = svgEl.clientHeight || 800;
  const clone = svgEl.cloneNode(true);
  clone.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
  clone.setAttribute('width', w);
  clone.setAttribute('height', h);
  const bg = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
  bg.setAttribute('width', w);
  bg.setAttribute('height', h);
  bg.setAttribute('fill', '#090b0f');
  clone.insertBefore(bg, clone.firstChild);
  const markup = new XMLSerializer().serializeToString(clone);
  const blob = new Blob([markup], { type: 'image/svg+xml;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const img = new Image();
  img.onload = () => {
    const canvas = document.createElement('canvas');
    canvas.width = w * 2;
    canvas.height = h * 2;
    const ctx = canvas.getContext('2d');
    ctx.fillStyle = '#090b0f';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
    URL.revokeObjectURL(url);
    canvas.toBlob(pngBlob => {
      if (!pngBlob) return;
      const a = document.createElement('a');
      a.href = URL.createObjectURL(pngBlob);
      a.download = filename;
      a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 5000);
    }, 'image/png');
  };
  img.src = url;
  return true;
}
