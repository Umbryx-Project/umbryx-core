import PropTypes from 'prop-types';
import { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import { api } from '../api.js';
import { loadPos, savePos, deriveGraphState, computeSelectedPathSets, computeLinkedFindings, isPivotEdge, startNodeDrag, startCanvasPan } from '../utils/attackGraph.js';
import { GraphHeader, CanvasOverlay, GraphSvg, ZoomControls, GraphLegend } from '../components/graph/GraphControls.jsx';
import { PathsPanel, NodeSidePanel } from '../components/graph/GraphPanels.jsx';

export default function AttackGraphView({ selectedProject, accent }) {
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
  const [showPivotRoutes, setShowPivotRoutes] = useState(true);
  const [showPathsPanel, setShowPathsPanel] = useState(false);
  const [selectedPathIdx, setSelectedPathIdx] = useState(null);

  const isPanning = useRef(false);
  const panStart = useRef({ x: 0, y: 0, px: 0, py: 0 });
  const draggingNode = useRef(null);
  const dragMoved = useRef(false);

  const canvasH = 680;

  const load = useCallback(async () => {
    if (!selectedProject) return;
    setLoading(true);
    setError('');
    try {
      const data = await api.getAttackGraph(selectedProject);
      setGraphData(data);
      setNodePos(loadPos(selectedProject));
    } catch (e) {
      setError(e.message || 'Failed to load attack graph');
    } finally {
      setLoading(false);
    }
  }, [selectedProject]);

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

  const handleNodeMouseDown = (e, node) => startNodeDrag(e, node, nodePos, zoom, { draggingNode, dragMoved, setNodePos, selectedProject });

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
  } = deriveGraphState(graphData, nodePos, canvasH, showPivotRoutes, selectedNode, allCreds);

  const { edgePairs: selectedPathEdgePairs } = useMemo(
    () => computeSelectedPathSets(selectedPathIdx, privilegePaths),
    [selectedPathIdx, privilegePaths],
  );

  const selectedNodeAccessEdges = selectedNodeEdges.filter(e => e.kind === 'access');
  const selectedNodePivotEdges = selectedNodeEdges.filter(isPivotEdge);
  const linkedFindings = computeLinkedFindings(selectedNode, allFindings);
  const canvasCursor = isPanning.current || draggingNode.current ? 'grabbing' : 'grab';

  const resetLayout = () => {
    setNodePos({});
    savePos(selectedProject, {});
    setZoom(1);
    setPan({ x: 0, y: 0 });
  };

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', background: '#090b0f' }}>

      {/* ── Header ── */}
      <GraphHeader
        graphData={graphData} stats={stats} privMode={privMode} setPrivMode={setPrivMode}
        showPathsPanel={showPathsPanel} setShowPathsPanel={setShowPathsPanel}
        privilegePaths={privilegePaths} showPivotRoutes={showPivotRoutes}
        setShowPivotRoutes={setShowPivotRoutes} resetLayout={resetLayout}
        load={load} loading={loading} accent={accent}
      />

      <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>

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
          {nodes.length > 0 && (
            <GraphSvg
              nodes={nodes} edges={edges} arrowColors={arrowColors}
              pan={pan} zoom={zoom} privMode={privMode} selectedNode={selectedNode}
              selectedPathEdgePairs={selectedPathEdgePairs}
              handleNodeMouseDown={handleNodeMouseDown}
              handleNodeClick={handleNodeClick}
            />
          )}
          <ZoomControls zoom={zoom} setZoom={setZoom} setPan={setPan} />
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
            selectedNodeAccessEdges={selectedNodeAccessEdges}
            selectedNodePivotEdges={selectedNodePivotEdges}
            linkedCreds={linkedCreds}
            linkedFindings={linkedFindings}
            pivotChains={pivotChains}
          />
        )}
      </div>
    </div>
  );
}
AttackGraphView.propTypes = {
  selectedProject: PropTypes.any,
  accent: PropTypes.any,
};
