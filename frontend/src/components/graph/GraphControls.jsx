import PropTypes from 'prop-types';
import { ACCESS_COLOR, computeEdgeDimmed } from '../../utils/attackGraph.js';
import HostNode from './GraphNodes.jsx';
import GraphEdge from './GraphEdges.jsx';
import { PALETTE, FONTS } from '../UI.jsx';

export function GraphBtn({ onClick, children, extra }) {
  return (
    <button onClick={onClick} style={{
      background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 5,
      padding: '5px 10px', cursor: 'pointer', color: PALETTE.textFaint, fontSize: 11,
      fontFamily: FONTS.mono, ...extra,
    }}>{children}</button>
  );
}
GraphBtn.propTypes = {
  onClick: PropTypes.any,
  children: PropTypes.any,
  extra: PropTypes.any,
};

export function GraphHeader({ graphData, stats, privMode, setPrivMode, showPathsPanel, setShowPathsPanel, privilegePaths, showPivotRoutes, setShowPivotRoutes, resetLayout, load, loading, accent }) {
  return (
    <div style={{ padding: '10px 18px', borderBottom: `1px solid ${PALETTE.borderSoft}`, display: 'flex', alignItems: 'center', gap: 12, flexShrink: 0, flexWrap: 'wrap' }}>
      <div style={{ fontSize: 13, fontWeight: 700, color: PALETTE.text, fontFamily: FONTS.display, flex: 1, minWidth: 100 }}>
        Attack Graph
      </div>
      {graphData && (
        <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
          {[
            { label: 'hosts', val: stats.hosts, c: PALETTE.textDim },
            { label: 'access', val: stats.access_edges, c: ACCESS_COLOR.verified },
            { label: 'verified', val: stats.verified_access_edges, c: ACCESS_COLOR.inferred },
            { label: 'reachable', val: stats.reachable_hosts, c: '#5b8af5' },
            { label: 'priv paths', val: stats.privilege_paths, c: '#e8574a' },
            { label: 'DA hosts', val: stats.da_capable_hosts, c: '#e8574a' },
            { label: 'pivot routes', val: stats.pivot_route_edges, c: ACCESS_COLOR.pivot_route },
            { label: 'pivot chains', val: stats.pivot_chains, c: ACCESS_COLOR.pivot },
          ].map(({ label, val, c }) => val > 0 && (
            <span key={label} style={{ fontSize: 11, color: '#505560', fontFamily: FONTS.mono }}>
              <span style={{ color: c }}>{val}</span> {label}
            </span>
          ))}
        </div>
      )}
      <div style={{ display: 'flex', gap: 6 }}>
        <GraphBtn onClick={() => { setPrivMode(v => !v); if (!privMode) setShowPathsPanel(true); }} extra={{ borderColor: privMode ? '#e8574a88' : PALETTE.border, color: privMode ? '#e8574a' : PALETTE.textFaint, background: privMode ? '#e8574a11' : 'transparent' }}>{privMode ? '● Priv Paths' : '○ Priv Paths'}</GraphBtn>
        {privilegePaths.length > 0 && <GraphBtn onClick={() => setShowPathsPanel(v => !v)} extra={{ borderColor: showPathsPanel ? '#e8574a88' : PALETTE.border, color: showPathsPanel ? '#e8574a' : PALETTE.textFaint, background: showPathsPanel ? '#e8574a11' : 'transparent' }}>{showPathsPanel ? '● Paths' : '○ Paths'}</GraphBtn>}
        <GraphBtn onClick={() => setShowPivotRoutes(v => !v)} extra={{ borderColor: showPivotRoutes ? ACCESS_COLOR.pivot_route + '88' : PALETTE.border, color: showPivotRoutes ? ACCESS_COLOR.pivot_route : PALETTE.textFaint, background: showPivotRoutes ? ACCESS_COLOR.pivot_route + '11' : 'transparent' }}>{showPivotRoutes ? '● Pivots' : '○ Pivots'}</GraphBtn>
        <GraphBtn onClick={resetLayout}>Reset</GraphBtn>
        <GraphBtn onClick={load} extra={{ borderColor: accent + '44', color: accent }}>{loading ? 'Loading…' : 'Refresh'}</GraphBtn>
      </div>
    </div>
  );
}
GraphHeader.propTypes = {
  graphData: PropTypes.any,
  stats: PropTypes.any,
  privMode: PropTypes.any,
  setPrivMode: PropTypes.any,
  showPathsPanel: PropTypes.any,
  setShowPathsPanel: PropTypes.any,
  privilegePaths: PropTypes.any,
  showPivotRoutes: PropTypes.any,
  setShowPivotRoutes: PropTypes.any,
  resetLayout: PropTypes.any,
  load: PropTypes.any,
  loading: PropTypes.any,
  accent: PropTypes.any,
};

export function CanvasOverlay({ loading, error, nodes, load }) {
  if (loading) {
    return (
      <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', color: PALETTE.textGhost, fontSize: 12, fontFamily: FONTS.mono }}>
        Loading graph…
      </div>
    );
  }
  if (error) {
    return (
      <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 10, color: PALETTE.danger, fontSize: 12, fontFamily: FONTS.mono }}>
        <span>⚠ {error}</span>
        <GraphBtn onClick={load} extra={{ borderColor: '#cc233344', color: PALETTE.danger }}>Retry</GraphBtn>
      </div>
    );
  }
  if (nodes.length === 0) {
    return (
      <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 10, color: PALETTE.textGhost, fontFamily: FONTS.mono, fontSize: 12 }}>
        <span style={{ fontSize: 30, opacity: 0.25 }}>◈</span>
        <span>No data — add hosts and access edges to build the graph</span>
      </div>
    );
  }
  return null;
}
CanvasOverlay.propTypes = {
  loading: PropTypes.any,
  error: PropTypes.any,
  nodes: PropTypes.any,
  load: PropTypes.any,
};

export function GraphSvg({ nodes, edges, arrowColors, pan, zoom, privMode, selectedNode, selectedPathEdgePairs, handleNodeMouseDown, handleNodeClick }) {
  return (
    <svg width="100%" height="100%" style={{ display: 'block' }}>
      <defs>
        {arrowColors.map(c => (
          <marker key={c} id={`arr-${c.replace('#', '')}`} markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto">
            <path d="M0,0 L0,7 L7,3.5 z" fill={c} opacity={0.75} />
          </marker>
        ))}
      </defs>
      <g transform={`translate(${pan.x},${pan.y}) scale(${zoom})`}>
        {edges.map((e, i) => (
          <GraphEdge key={e.id || `edge-${i}`} edge={e} nodes={nodes} privMode={privMode} dimmed={computeEdgeDimmed(e, selectedPathEdgePairs)} />
        ))}
        {nodes.map(n => (
          <HostNode
            key={n.id}
            node={n}
            selected={selectedNode?.id === n.id}
            privMode={privMode}
            onMouseDown={handleNodeMouseDown}
            onClick={handleNodeClick}
          />
        ))}
      </g>
    </svg>
  );
}
GraphSvg.propTypes = {
  nodes: PropTypes.any,
  edges: PropTypes.any,
  arrowColors: PropTypes.any,
  pan: PropTypes.any,
  zoom: PropTypes.any,
  privMode: PropTypes.any,
  selectedNode: PropTypes.any,
  selectedPathEdgePairs: PropTypes.any,
  handleNodeMouseDown: PropTypes.any,
  handleNodeClick: PropTypes.any,
};

export function ZoomControls({ zoom, setZoom, setPan }) {
  return (
    <div style={{ position: 'absolute', bottom: 14, left: 14, display: 'flex', flexDirection: 'column', gap: 3 }}>
      {[
        { lbl: '+', fn: () => setZoom(z => Math.min(4, z * 1.25)) },
        { lbl: '−', fn: () => setZoom(z => Math.max(0.15, z / 1.25)) },
        { lbl: '⟳', fn: () => { setZoom(1); setPan({ x: 0, y: 0 }); } },
      ].map(({ lbl, fn }) => (
        <button key={lbl} onClick={fn} style={{ background: PALETTE.bg2, border: '1px solid #1e2029', borderRadius: 4, width: 26, height: 26, cursor: 'pointer', color: '#808590', fontSize: 13, fontFamily: FONTS.mono, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>{lbl}</button>
      ))}
      <span style={{ fontSize: 9, color: '#353840', fontFamily: FONTS.mono, textAlign: 'center', marginTop: 2 }}>
        {Math.round(zoom * 100)}%
      </span>
    </div>
  );
}
ZoomControls.propTypes = {
  zoom: PropTypes.any,
  setZoom: PropTypes.any,
  setPan: PropTypes.any,
};

export function GraphLegend({ privMode, selectedNode }) {
  return (
    <div style={{ position: 'absolute', bottom: 14, right: selectedNode ? 298 : 14, display: 'flex', gap: 10, background: '#0d0f1499', backdropFilter: 'blur(4px)', border: '1px solid #1e2029', borderRadius: 6, padding: '5px 10px', flexWrap: 'wrap' }}>
      {[
        ['access', ACCESS_COLOR.verified],
        ['inferred', ACCESS_COLOR.inferred],
        ['domain admin', ACCESS_COLOR.domain_admin],
        ['pivot', ACCESS_COLOR.pivot],
        ['pivot route', ACCESS_COLOR.pivot_route],
        ['path', ACCESS_COLOR.path],
      ].map(([type, color]) => (
        <div key={type} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          <svg width={16} height={4}><rect width={16} height={2} y={1} rx={1} fill={color} /></svg>
          <span style={{ fontSize: 9, color: PALETTE.textGhost, fontFamily: FONTS.mono, textTransform: 'uppercase' }}>{type}</span>
        </div>
      ))}
      {privMode && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 4, paddingLeft: 6, borderLeft: `1px solid ${PALETTE.border}` }}>
          <svg width={12} height={12}><rect width={12} height={12} rx={3} fill="none" stroke="#e8574a" strokeWidth={2} /></svg>
          <span style={{ fontSize: 9, color: '#e8574a', fontFamily: FONTS.mono }}>DA PATH</span>
        </div>
      )}
    </div>
  );
}
GraphLegend.propTypes = {
  privMode: PropTypes.any,
  selectedNode: PropTypes.any,
};
