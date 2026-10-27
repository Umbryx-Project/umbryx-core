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

export function layoutNodes(raw, canvasH) {
  const nodes = raw.map(n => ({ ...n }));
  const attackerIdx = nodes.findIndex(n => n.type === 'attacker' || n.is_attacker);

  if (attackerIdx >= 0) {
    nodes[attackerIdx] = { ...nodes[attackerIdx], x: 100, y: canvasH / 2, type: 'attacker' };
  }

  let col = 0, rowIdx = 0;
  const ROW_H = 96, COL_W = 200, ROWS = 5;

  nodes.forEach((n, i) => {
    if (i === attackerIdx) return;
    col = Math.floor(rowIdx / ROWS);
    const row = rowIdx % ROWS;
    n.x = 260 + col * COL_W;
    n.y = (canvasH / 2) - ((Math.min(ROWS, nodes.length - (attackerIdx >= 0 ? 1 : 0)) - 1) / 2) * ROW_H + row * ROW_H;
    rowIdx++;
  });

  return nodes;
}

const POS_KEY = pid => `ag_pos_${pid}`;
export const loadPos = pid => { try { return JSON.parse(localStorage.getItem(POS_KEY(pid)) || '{}'); } catch { return {}; } };
export const savePos = (pid, pos) => { try { localStorage.setItem(POS_KEY(pid), JSON.stringify(pos)); } catch { /* storage full or blocked — saved positions are a convenience */ } };

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

export function filterEdges(allEdges, showPivotRoutes) {
  if (showPivotRoutes) return allEdges;
  return allEdges.filter(e => e.kind !== 'pivot_route' && e.kind !== 'pivot');
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

export function deriveGraphState(graphData, nodePos, canvasH, showPivotRoutes, selectedNode, allCreds) {
  const rawNodes = layoutNodes(graphData?.nodes || [], canvasH);
  const nodes = applyNodePos(rawNodes, nodePos);
  const allEdges = graphData?.edges || [];
  const edges = filterEdges(allEdges, showPivotRoutes);
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

export function startNodeDrag(e, node, nodePos, zoom, { draggingNode, dragMoved, setNodePos, selectedProject }) {
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
    if (draggingNode.current && dragMoved.current) savePos(selectedProject, { ...nodePos });
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
