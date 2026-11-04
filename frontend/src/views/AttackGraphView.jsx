import PropTypes from 'prop-types';
import { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import { api } from '../api.js';
import { loadPos, savePos, deriveGraphState, computeSelectedPathSets, computeLinkedFindings, isPivotEdge, startNodeDrag, startCanvasPan, DEFAULT_GRAPH_FILTERS, filterEdges, pathFromAttacker, opensFrom, chainEdgeLabel, fitNodesToViewport, computeFrontierSets, frontierSuggestions, exportGraphPng } from '../utils/attackGraph.js';
import { GraphHeader, CanvasOverlay, GraphSvg, ZoomControls, GraphLegend, EmptyGraphOnboarding } from '../components/graph/GraphControls.jsx';
import { PathsPanel, NodeSidePanel, FrontierPanel, EdgeTooltip } from '../components/graph/GraphPanels.jsx';

export default function AttackGraphView({ selectedProject, accent, onNavigate, liveCreds, liveHosts, liveNetworks, onDeleteHost, onDeleteCred }) {
  const [graphData, setGraphData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [selectedNode, setSelectedNode] = useState(null);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [nodePos, setNodePos] = useState({});
  const [allCreds, setAllCreds] = useState([]);
  const [allFindings, setAllFindings] = useState([]);
  const [privMode, setPrivMode] = useState(false);
  const [frontierMode, setFrontierMode] = useState(false);
  const [filters, setFilters] = useState({ ...DEFAULT_GRAPH_FILTERS });
  const [search, setSearch] = useState('');
  const [showPathsPanel, setShowPathsPanel] = useState(false);
  const [hoverEdge, setHoverEdge] = useState(null);
  const [selectedPathIdx, setSelectedPathIdx] = useState(null);
  // Canvas height drives the layered layout — derive it from the real
  // viewport instead of a fixed 680px band (cramped on tall screens,
  // overflowing on short ones).
  const [canvasH, setCanvasH] = useState(() => Math.max(520, Math.min(1200, window.innerHeight - 230)));
  useEffect(() => {
    const onResize = () => setCanvasH(Math.max(520, Math.min(1200, window.innerHeight - 230)));
    window.addEventListener('resize', onResize);
    return () => window.removeEventListener('resize', onResize);
  }, []);

  const isPanning = useRef(false);
  // live nodePos for drag persistence: startNodeDrag's closure snapshots
  // the map at drag START, so mouseup must read the current state via ref
  const nodePosRef = useRef(nodePos);
  nodePosRef.current = nodePos;
  const panStart = useRef({ x: 0, y: 0, px: 0, py: 0 });
  const draggingNode = useRef(null);
  const dragMoved = useRef(false);

  const load = useCallback(async ({ silent } = {}) => {
    if (!selectedProject) return;
    if (!silent) setLoading(true);
    setError('');
    try {
      const data = await api.getAttackGraph(selectedProject);
      setGraphData(data);
      setNodePos(loadPos(selectedProject));
      if (silent) {
        // keep side-panel data in step with the re-derived graph
        api.getCreds(selectedProject).then(setAllCreds).catch(() => {});
      }
      // live reload: keep the selection if the node survived
      setSelectedNode(prev =>
        prev && (data.nodes || []).some(n => n.id === prev.id) ? prev : null);
    } catch (e) {
      if (!silent) setError(e.message || 'Failed to load attack graph');
    } finally {
      if (!silent) setLoading(false);
    }
  }, [selectedProject]);

  // AG Phase 3: live updates — creds/hosts arrive over WS in App state;
  // debounce and re-derive the graph (silent: no loading flash, keeps
  // selection and saved positions)
  const firstLive = useRef(true);
  useEffect(() => {
    if (firstLive.current) { firstLive.current = false; return; }
    const t = setTimeout(() => { load({ silent: true }); }, 700);
    return () => clearTimeout(t);
  }, [liveCreds, liveHosts, liveNetworks]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    if (!selectedProject) return;
    api.getCreds(selectedProject).then(setAllCreds).catch(() => {});
    api.getFindings(selectedProject, {}).then(data => {
      setAllFindings(Array.isArray(data) ? data : data?.findings || []);
    }).catch(() => {});
  }, [selectedProject]);

  const handleWheel = e => {
    e.preventDefault();
    setZoom(z => Math.max(0.15, Math.min(4, z * (e.deltaY > 0 ? 0.9 : 1.11))));
  };

  const handleNodeMouseDown = (e, node) => startNodeDrag(e, node, nodePos, zoom, { draggingNode, dragMoved, setNodePos, selectedProject, nodePosRef });

  const handleCanvasMouseDown = e => startCanvasPan(e, pan, isPanning, panStart, setPan, draggingNode);

  const handleNodeClick = node => {
    if (dragMoved.current) return;
    setSelectedNode(prev => prev?.id === node.id ? null : node);
  };

  // ── Derived state ─────────────────────────────────────────────────────────
  const {
    nodes, edges, arrowColors, stats,
    privilegePaths, privilegePathDetails, pivotChains,
    selectedNodeEdges, linkedCreds,
  } = deriveGraphState(graphData, nodePos, canvasH, filters, selectedNode, allCreds, search);

  const { edgePairs: selectedPathEdgePairs, nodeIds: selectedPathNodeIds } = useMemo(
    () => computeSelectedPathSets(selectedPathIdx, privilegePaths),
    [selectedPathIdx, privilegePaths],
  );

  // Fit the chosen DA path into the viewport (AG Phase 2)
  useEffect(() => {
    if (selectedPathIdx === null || !selectedPathNodeIds) return;
    const pathNodes = nodes.filter(n => selectedPathNodeIds.has(n.id));
    const fit = fitNodesToViewport(pathNodes, { width: window.innerWidth - (showPathsPanel ? 300 : 0) - 60, height: window.innerHeight - 200 }, pan, zoom);
    if (fit) { setZoom(fit.zoom); setPan(fit.pan); }
  }, [selectedPathIdx]); // eslint-disable-line react-hooks/exhaustive-deps

  // Fit the whole graph into the viewport (initial view + ⟳ button).
  // Capped at 1.1 so small graphs don't blow up to unreadable sizes.
  const fitAll = useCallback(ns => {
    const fit = fitNodesToViewport(
      ns || nodes,
      { width: window.innerWidth - (showPathsPanel ? 300 : 0) - 60, height: window.innerHeight - 200 },
      pan, zoom, 1.1, 90,
    );
    if (fit) { setZoom(fit.zoom); setPan(fit.pan); }
  }, [nodes, pan, zoom, showPathsPanel]);

  const didInitialFit = useRef(false);
  const refitAfterReset = useRef(false);
  useEffect(() => {
    if (!graphData || nodes.length === 0 || didInitialFit.current) return;
    didInitialFit.current = true;
    fitAll(nodes);
  }, [nodes]); // eslint-disable-line react-hooks/exhaustive-deps
  // after "reset layout" the fresh positions arrive on the next render —
  // refit then (the resetLayout closure would capture stale nodes)
  useEffect(() => {
    if (refitAfterReset.current && Object.keys(nodePos).length === 0 && nodes.length > 0) {
      refitAfterReset.current = false;
      fitAll(nodes);
    }
  }, [nodePos, nodes]); // eslint-disable-line react-hooks/exhaustive-deps

  const selectedNodeAccessEdges = selectedNodeEdges.filter(e => e.kind === 'access');
  const selectedNodePivotEdges = selectedNodeEdges.filter(isPivotEdge);
  // AG Phase 2: "how we got here" chain + "what it opens"
  const selectedChain = selectedNode ? pathFromAttacker(nodes, filterEdges(graphData?.edges || [], filters), selectedNode.id) : null;
  const selectedOpens = selectedNode ? opensFrom(nodes, filterEdges(graphData?.edges || [], filters), selectedNode.id) : [];
  const linkedFindings = computeLinkedFindings(selectedNode, allFindings);
  const canvasCursor = isPanning.current || draggingNode.current ? 'grabbing' : 'grab';

  // AG Phase 3: frontier sets + suggestions (what to validate next)
  const frontierSets = useMemo(
    () => computeFrontierSets(nodes, filterEdges(graphData?.edges || [], filters)),
    [nodes, graphData, filters],
  );
  const frontierNodes = useMemo(
    () => frontierMode
      ? nodes.map(n => ({ ...n, frontierDim: !frontierSets.frontierNodes.has(n.id) && !n.is_attacker && n.type !== 'attacker', frontierHost: frontierSets.frontierNodes.has(n.id) }))
      : nodes,
    [nodes, frontierMode, frontierSets],
  );
  const frontierEdges = useMemo(
    () => frontierMode
      ? edges.map(e => ({ ...e, frontierDim: !frontierSets.frontierEdges.has(e.id) }))
      : edges,
    [edges, frontierMode, frontierSets],
  );
  const suggestions = useMemo(
    () => frontierSuggestions(nodes, filterEdges(graphData?.edges || [], filters)),
    [nodes, graphData, filters],
  );
  const svgRef = useRef(null);
  // delete host/cred straight from the graph — the graph is derived, so
  // the entity disappearing removes its nodes/edges on the silent reload
  const handleDeleteNode = useCallback(async node => {
    if (!node) return;
    try {
      if (node.type === 'cred') {
        const credId = String(node.id).replace(/^cnode_/, '');
        if (onDeleteCred) await onDeleteCred(credId);
      } else if (node.type !== 'attacker' && !node.is_attacker) {
        if (onDeleteHost) await onDeleteHost(node.id);
      } else {
        return;
      }
      setSelectedNode(null);
      load({ silent: true });
    } catch (e) {
      setError(e.message || 'Failed to delete');
    }
  }, [onDeleteHost, onDeleteCred, load]);
  const handleExport = useCallback(() => {
    exportGraphPng(svgRef.current, `attack-graph-${selectedProject || 'export'}.png`);
  }, [selectedProject]);

  // Reset = REBUILD: clear saved positions and re-derive the graph from
  // the data (refetch), then fit. Previously it only cleared positions —
  // with none saved the click looked like a no-op ("он не перестроил").
  const resetLayout = () => {
    setNodePos({});
    savePos(selectedProject, {});
    refitAfterReset.current = true;
    load({ silent: true });
  };

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', background: '#090b0f' }}>

      {/* ── Header ── */}
      <GraphHeader
        graphData={graphData} stats={stats} privMode={privMode} setPrivMode={setPrivMode}
        showPathsPanel={showPathsPanel} setShowPathsPanel={setShowPathsPanel}
        privilegePaths={privilegePaths}
        resetLayout={resetLayout}
        load={load} loading={loading} accent={accent}
        filters={filters} setFilters={setFilters} search={search} setSearch={setSearch}
        frontierMode={frontierMode} setFrontierMode={setFrontierMode}
        onExport={handleExport}
        suggestions={suggestions}
        onSuggestion={s => { if (onNavigate) onNavigate(s.tab, s.focus); }}
      />

      <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>

        {/* ── Frontier panel (AG Phase 3) ── */}
        {frontierMode && (
          <FrontierPanel
            suggestions={suggestions}
            onSuggestion={s => { if (onNavigate) onNavigate(s.tab, s.focus); }}
            onClose={() => setFrontierMode(false)}
          />
        )}

        {/* ── Paths panel ── */}
        {showPathsPanel && privilegePathDetails.length > 0 && (
          <PathsPanel
            privilegePathDetails={privilegePathDetails}
            pivotChains={pivotChains}
            nodes={nodes}
            selectedPathIdx={selectedPathIdx}
            setSelectedPathIdx={setSelectedPathIdx}
            setShowPathsPanel={setShowPathsPanel}
          />
        )}

        {/* ── Canvas ── */}
        <button
          type="button"
          aria-label="Attack graph canvas"
          tabIndex={0}
          style={{
            flex: 1, overflow: 'hidden', position: 'relative',
            cursor: canvasCursor,
            userSelect: 'none',
            background: 'none', border: 'none', padding: 0,
            font: 'inherit', color: 'inherit', textAlign: 'left',
            display: 'flex', flexDirection: 'column', width: '100%',
          }}
          onWheel={handleWheel}
          onMouseDown={handleCanvasMouseDown}
          onKeyDown={e => { if (e.key === 'Tab') e.stopPropagation(); }}
          onKeyUp={() => {}}
        >
          <CanvasOverlay loading={loading} error={error} nodes={nodes} load={load} />
          {!loading && !error && stats.hosts <= 1 && (stats.cred_nodes || 0) === 0 && (
            <EmptyGraphOnboarding stats={stats} />
          )}
          {nodes.length > 0 && (
            <GraphSvg
              ref={svgRef}
              nodes={frontierNodes} edges={frontierEdges} arrowColors={arrowColors}
              pan={pan} zoom={zoom} privMode={privMode} selectedNode={selectedNode}
              selectedPathEdgePairs={selectedPathEdgePairs}
              handleNodeMouseDown={handleNodeMouseDown}
              handleNodeClick={handleNodeClick}
              frontierMode={frontierMode}
              onEdgeHover={(edge, src, tgt, pos) => setHoverEdge(edge ? { edge, src, tgt, pos } : null)}
            />
          )}
          <EdgeTooltip hover={hoverEdge} allCreds={allCreds} />
          <ZoomControls zoom={zoom} setZoom={setZoom} setPan={setPan} onFit={() => fitAll()} />
          {nodes.length > 0 && <GraphLegend privMode={privMode} selectedNode={selectedNode} />}
        </button>

        {/* ── Side panel ── */}
        {selectedNode && (
          <NodeSidePanel
            selectedNode={selectedNode}
            setSelectedNode={setSelectedNode}
            accent={accent}
            privilegePaths={privilegePaths}
            nodes={nodes}
            selectedNodeEdges={selectedNodeEdges}
            selectedNodeAccessEdges={selectedNodeAccessEdges}
            selectedNodePivotEdges={selectedNodePivotEdges}
            linkedCreds={linkedCreds}
            linkedFindings={linkedFindings}
            pivotChains={pivotChains}
            chain={selectedChain}
            opens={selectedOpens}
            onNavigate={onNavigate}
            onDelete={handleDeleteNode}
          />
        )}
      </div>
    </div>
  );
}
AttackGraphView.propTypes = {
  selectedProject: PropTypes.any,
  accent: PropTypes.any,
  onNavigate: PropTypes.func,
  liveCreds: PropTypes.array,
  liveHosts: PropTypes.array,
  liveNetworks: PropTypes.array,
  onDeleteHost: PropTypes.func,
  onDeleteCred: PropTypes.func,
};
