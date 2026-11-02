import PropTypes from 'prop-types';
import { forwardRef } from 'react';
import { ACCESS_COLOR, computeEdgeDimmed } from '../../utils/attackGraph.js';
import HostNode, { CredNode } from './GraphNodes.jsx';
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

export function GraphHeader({ graphData, stats, privMode, setPrivMode, showPathsPanel, setShowPathsPanel, privilegePaths, resetLayout, load, loading, accent, filters, setFilters, search, setSearch, frontierMode, setFrontierMode, onExport, suggestions, onSuggestion }) {
  const toggle = key => () => setFilters(f => ({ ...f, [key]: !f[key] }));
  const chip = (key, label, color) => (
    <GraphBtn onClick={toggle(key)} extra={{
      borderColor: filters[key] ? color + '88' : PALETTE.border,
      color: filters[key] ? color : PALETTE.textFaint,
      background: filters[key] ? color + '11' : 'transparent',
    }}>{(filters[key] ? '● ' : '○ ') + label}</GraphBtn>
  );
  const unvalidated = stats.unvalidated_creds || 0;
  const inferred = stats.inferred_access_edges || 0;
  return (
    <div style={{ borderBottom: `1px solid ${PALETTE.borderSoft}`, flexShrink: 0 }}>
      <div style={{ padding: '10px 18px 6px', display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
        <div style={{ fontSize: 13, fontWeight: 700, color: PALETTE.text, fontFamily: FONTS.display, minWidth: 100 }}>
          Attack Graph
        </div>
        <span style={{ fontSize: 10, color: PALETTE.textGhost, fontFamily: FONTS.mono }}>
          live map of compromise — built automatically from credentials, access checks and pivots
        </span>
        <div style={{ flex: 1 }} />
        {graphData && (
          <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
            {[
              { label: 'hosts', val: stats.hosts, c: PALETTE.textDim },
              { label: 'creds', val: stats.cred_nodes, c: '#39d353' },
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
      </div>
      <div style={{ padding: '4px 18px 10px', display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
        {chip('creds', 'Credentials', '#39d353')}
        {chip('access', 'Access', ACCESS_COLOR.verified)}
        {chip('verifiedOnly', 'Verified only', ACCESS_COLOR.inferred)}
        {chip('pivots', 'Pivots', ACCESS_COLOR.pivot)}
        {chip('paths', 'Attack Paths', ACCESS_COLOR.path)}
        <input
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="search host / user / domain…"
          style={{ marginLeft: 6, background: '#0a0c10', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '3px 10px', color: PALETTE.textDim, fontSize: 10, fontFamily: FONTS.mono, width: 190, outline: 'none' }}
        />
        <div style={{ flex: 1 }} />
        {(unvalidated + inferred) > 0 && (
          <GraphBtn onClick={() => setFrontierMode(v => !v)} extra={{
            borderColor: frontierMode ? '#f09a3a88' : PALETTE.border,
            color: frontierMode ? '#f09a3a' : PALETTE.textFaint,
            background: frontierMode ? '#f09a3a11' : 'transparent',
          }}>{frontierMode ? '● ' : '○ '}Frontier · {unvalidated + inferred}</GraphBtn>
        )}
        {suggestions.length > 0 && (
          <GraphBtn onClick={() => setFrontierMode(v => !v)} title="What to validate next" extra={{ borderColor: PALETTE.border, color: PALETTE.textFaint }}>
            Next {suggestions.length}
          </GraphBtn>
        )}
        <GraphBtn onClick={onExport} title="Export PNG snapshot" extra={{ borderColor: PALETTE.border, color: PALETTE.textFaint }}>PNG</GraphBtn>
        <GraphBtn onClick={() => { setPrivMode(v => !v); if (!privMode) setShowPathsPanel(true); }} extra={{ borderColor: privMode ? '#e8574a88' : PALETTE.border, color: privMode ? '#e8574a' : PALETTE.textFaint, background: privMode ? '#e8574a11' : 'transparent' }}>{privMode ? '● Priv Paths' : '○ Priv Paths'}</GraphBtn>
        {privilegePaths.length > 0 && <GraphBtn onClick={() => setShowPathsPanel(v => !v)} extra={{ borderColor: showPathsPanel ? '#e8574a88' : PALETTE.border, color: showPathsPanel ? '#e8574a' : PALETTE.textFaint, background: showPathsPanel ? '#e8574a11' : 'transparent' }}>{showPathsPanel ? '● Paths' : '○ Paths'}</GraphBtn>}
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
  resetLayout: PropTypes.any,
  load: PropTypes.any,
  loading: PropTypes.any,
  accent: PropTypes.any,
  frontierMode: PropTypes.any,
  setFrontierMode: PropTypes.func,
  onExport: PropTypes.func,
  suggestions: PropTypes.array,
  onSuggestion: PropTypes.func,
};

// AG Phase 2: onboarding for an empty graph — the graph is DERIVED, so
// "empty" always has a reason: name the missing source(s), offer the fix.
export function EmptyGraphOnboarding({ stats }) {
  const st = stats || {};
  const sources = [
    { ok: (st.cred_nodes || 0) > 0, label: 'credentials', hint: 'Import or capture credentials — each becomes a node once it opens a host', action: 'Creds → Import', tab: 'creds' },
    { ok: (st.access_edges || 0) > 0, label: 'access checks', hint: 'Validate credentials against hosts (NetExec spray, validation job) — validated access draws verified edges', action: 'Open Network Map', tab: 'network' },
    { ok: (st.pivot_route_edges || 0) > 0, label: 'pivots', hint: 'Active pivot observations (chisel/SSH -L) draw pivot routes to reachable segments', action: 'Pivots', tab: 'network' },
  ];
  const missing = sources.filter(x => !x.ok);
  const hasAnyHost = (st.hosts || 0) > 1;
  return (
    <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', pointerEvents: 'none' }}>
      <div style={{ maxWidth: 560, padding: 26, background: '#0d0f1499', border: `1px solid ${PALETTE.borderSoft}`, borderRadius: 10, pointerEvents: 'auto' }}>
        <div style={{ fontSize: 14, fontWeight: 700, color: PALETTE.text, fontFamily: FONTS.display, marginBottom: 8 }}>Attack Graph builds itself</div>
        <div style={{ fontSize: 11, color: PALETTE.textDim, lineHeight: 1.7, marginBottom: 14 }}>
          The graph is derived from your operational data — credentials, validated access and
          pivots. There is nothing to draw here yet{hasAnyHost ? ' because no source has produced edges:' : ':'}
        </div>
        {missing.map(x => (
          <div key={x.label} style={{ padding: '8px 10px', marginBottom: 6, background: '#0a0c10', border: `1px solid ${PALETTE.borderSoft}`, borderRadius: 6 }}>
            <div style={{ fontSize: 11, color: PALETTE.warn, fontFamily: FONTS.mono, marginBottom: 2 }}>○ no {x.label}</div>
            <div style={{ fontSize: 10, color: PALETTE.textGhost, fontFamily: FONTS.mono }}>{x.hint}</div>
          </div>
        ))}
        <div style={{ fontSize: 10, color: PALETTE.textGhost, fontFamily: FONTS.mono, marginTop: 4 }}>
          Attack Graph answers "where are we and how deep" — the Network Map documents the environment, Attack Path tells the story for the report.
        </div>
      </div>
    </div>
  );
}
EmptyGraphOnboarding.propTypes = { stats: PropTypes.any };

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

export const GraphSvg = forwardRef(function GraphSvg({ nodes, edges, arrowColors, pan, zoom, privMode, selectedNode, selectedPathEdgePairs, handleNodeMouseDown, handleNodeClick, frontierMode, onEdgeHover }, ref) {
  // Bidirectional pairs (A→B and B→A) get opposite bends so both arcs
  // stay visible instead of drawing exactly on top of each other.
  const pairKeys = new Set(edges.map(e => `${e.from}>${e.to}`));
  const bendOf = e => (pairKeys.has(`${e.to}>${e.from}`) ? (String(e.from) < String(e.to) ? 1 : -1) : 0);
  return (
    <svg ref={ref} width="100%" height="100%" style={{ display: 'block' }}>
      <defs>
        {arrowColors.map(c => (
          <marker key={c} id={`arr-${c.replace('#', '')}`} markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto">
            <path d="M0,0 L0,7 L7,3.5 z" fill={c} opacity={0.75} />
          </marker>
        ))}
      </defs>
      <g transform={`translate(${pan.x},${pan.y}) scale(${zoom})`}>
        {edges.map((e, i) => (
          <GraphEdge key={e.id || `edge-${i}`} edge={e} nodes={nodes} privMode={privMode} dimmed={computeEdgeDimmed(e, selectedPathEdgePairs)} selectedNode={selectedNode} bend={bendOf(e)} onHover={onEdgeHover} />
        ))}
        {nodes.map(n => (n.type === 'cred' ? (
          <CredNode
            key={n.id}
            node={n}
            selected={selectedNode?.id === n.id}
            privMode={privMode}
            frontierMode={frontierMode}
            onMouseDown={handleNodeMouseDown}
            onClick={handleNodeClick}
          />
        ) : (
          <HostNode
            key={n.id}
            node={n}
            selected={selectedNode?.id === n.id}
            privMode={privMode}
            frontierMode={frontierMode}
            onMouseDown={handleNodeMouseDown}
            onClick={handleNodeClick}
          />
        )))}
      </g>
    </svg>
  );
});
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

export function ZoomControls({ zoom, setZoom, setPan, onFit }) {
  return (
    <div style={{ position: 'absolute', bottom: 14, left: 14, display: 'flex', flexDirection: 'column', gap: 3 }}>
      {[
        { lbl: '+', fn: () => setZoom(z => Math.min(4, z * 1.25)) },
        { lbl: '−', fn: () => setZoom(z => Math.max(0.15, z / 1.25)) },
        { lbl: '⟳', fn: () => { if (onFit) { onFit(); } else { setZoom(1); setPan({ x: 0, y: 0 }); } } },
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
  onFit: PropTypes.func,
};

export function GraphLegend({ privMode, selectedNode }) {
  return (
    <div style={{ position: 'absolute', bottom: 14, right: selectedNode ? 298 : 14, display: 'flex', gap: 10, background: '#0d0f1499', backdropFilter: 'blur(4px)', border: '1px solid #1e2029', borderRadius: 6, padding: '5px 10px', flexWrap: 'wrap' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 4 }} title={'pivot/access fact older than 14 days — dimmed; re-check before relying on it'}>
        <svg width={14} height={8}><line x1={0} y1={4} x2={14} y2={4} stroke="#808590" strokeWidth={2} strokeOpacity={0.35} /></svg>
        <span style={{ fontSize: 9, color: PALETTE.textGhost, fontFamily: FONTS.mono }}>stale &gt;14d</span>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 4 }} title="credential we hold — attacker → key">
        <svg width={14} height={8}><line x1={0} y1={4} x2={14} y2={4} stroke="#5b8af5" strokeWidth={2} /></svg>
        <span style={{ fontSize: 9, color: PALETTE.textGhost, fontFamily: FONTS.mono }}>held cred</span>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 4 }} title="the credential opens this host">
        <svg width={14} height={8}><line x1={0} y1={4} x2={14} y2={4} stroke="#39d353" strokeWidth={2} /></svg>
        <span style={{ fontSize: 9, color: PALETTE.textGhost, fontFamily: FONTS.mono }}>cred opens</span>
      </div>
      {[
        ['verified access', ACCESS_COLOR.verified],
        ['inferred access', ACCESS_COLOR.inferred],
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
      <div style={{ display: 'flex', alignItems: 'center', gap: 4 }} title="key = working credential; dashed = hash not cracked yet">
        <svg width={14} height={9}><rect x={1} y={1} width={12} height={7} rx={3.5} fill="none" stroke="#39d353" strokeWidth={1.2} /><circle cx={4.5} cy={4.5} r={1.4} fill="none" stroke="#39d353" strokeWidth={1} /><line x1={6.5} y1={4.5} x2={11.5} y2={4.5} stroke="#39d353" strokeWidth={1} /></svg>
        <span style={{ fontSize: 9, color: PALETTE.textGhost, fontFamily: FONTS.mono }}>cred node</span>
      </div>
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
