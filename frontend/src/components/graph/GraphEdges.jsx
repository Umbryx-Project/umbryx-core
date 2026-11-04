import PropTypes from 'prop-types';
import { edgeColor, edgeStrokeDash, edgeStrokeW, edgeOpacity, edgeGeometry, edgeFreshness, nodeHalfW } from '../../utils/attackGraph.js';

export default function GraphEdge({ edge, nodes, privMode, dimmed, selectedNode, bend = 0, onHover }) {
  const src = nodes.find(n => n.id === (edge.source || edge.from));
  const tgt = nodes.find(n => n.id === (edge.target || edge.to));
  if (!src || !tgt || src === tgt) return null;

  const isAccess = edge.kind === 'access';
  const isPath = edge.kind === 'path';
  const isPivot = edge.kind === 'pivot';
  const isPivotRoute = edge.kind === 'pivot_route';
  const isDomainAdmin = isAccess && edge.access_type === 'domain_admin';
  const isPrivPath = privMode && edge.on_priv_path;

  const color = edgeColor(edge, isPrivPath, isPivotRoute, isPivot, isAccess, isDomainAdmin, isPath);

  const markerId = `arr-${color.replace('#', '')}`;

  // Same-column routing needs to know if OTHER cards sit between src and
  // tgt in that column: clear → compact loop into the left port; blocked
  // → approach from the right of the column (nothing to cut).
  const columnBlocked = Math.abs(tgt.x - src.x) < nodeHalfW(src) + nodeHalfW(tgt) + 20 && nodes.some(n => {
    if (n.id === src.id || n.id === tgt.id) return false;
    if (Math.abs(n.x - src.x) > nodeHalfW(src) + 20) return false;
    const lo = Math.min(src.y, tgt.y), hi = Math.max(src.y, tgt.y);
    return n.y > lo && n.y < hi;
  });
  const { d, label: labelPt } = edgeGeometry(src, tgt, bend, columnBlocked);
  const lx = labelPt.x;
  const ly = labelPt.y - 7;

  const strokeDash = edgeStrokeDash(isPrivPath, isPivotRoute, isPivot, isDomainAdmin, isAccess, isPath, edge.verified);
  const strokeW = edgeStrokeW(isPrivPath, isPivotRoute, isPivot, isDomainAdmin, isAccess);
  const fresh = edgeFreshness(edge);
  const faded = dimmed || edge.frontierDim;
  const opacity = Math.min(
    edgeOpacity(faded, isPrivPath, isPivotRoute, isAccess, isDomainAdmin),
    fresh?.stale ? 0.28 : 1,
  );

  return (
    <g
      onMouseEnter={e => onHover && onHover(edge, src, tgt, { x: e.clientX, y: e.clientY })}
      onMouseLeave={() => onHover && onHover(null)}
      style={{ cursor: onHover ? 'help' : 'default' }}
    >
      {/* invisible hit area so thin/dimmed edges stay hoverable */}
      <path d={d} fill="none" stroke="transparent" strokeWidth={11} strokeLinecap="round" />
      {isPrivPath && (
        <path d={d} fill="none" stroke="#e8574a" strokeWidth={8} strokeOpacity={0.12} strokeLinecap="round" />
      )}
      <path d={d} fill="none" stroke={color}
        strokeWidth={strokeW}
        strokeOpacity={opacity}
        strokeDasharray={strokeDash}
        markerEnd={`url(#${markerId})`}>
        {isPrivPath && (
          <animate attributeName="stroke-dashoffset" from="0" to="-28" dur="1.2s" repeatCount="indefinite" />
        )}
      </path>
      {/* AG Phase 1 de-clutter: labels render ONLY on the edges of the
          selected node (credential edges never — the cred node IS the
          label). Previously every edge labeled at once at the curve
          midpoint, overlapping each other on dense pairs. */}
      {(() => {
        if (!edge.label || isPivotRoute) return null;
        if (edge.kind === 'credential' || edge.kind === 'credential_use') return null;
        const touchesSelected = selectedNode && (edge.from === selectedNode.id || edge.to === selectedNode.id);
        if (!touchesSelected && !isPrivPath) return null;
        const displayLabel = edge.label.length > 14 ? edge.label.slice(0, 13) + '…' : edge.label;
        const boxW = Math.max(56, displayLabel.length * 5.2 + 12);
        return (
          <>
            <rect x={lx - boxW / 2} y={ly - 9} width={boxW} height={12} rx={3} fill="#07080b" opacity={0.92} stroke="#1e2430" strokeWidth={0.5} />
            <text x={lx} y={ly} textAnchor="middle" fontSize={8} fill={color} fontFamily="JetBrains Mono" opacity={dimmed ? 0.2 : 0.9}>
              {displayLabel}
            </text>
          </>
        );
      })()}
    </g>
  );
}
GraphEdge.propTypes = {
  edge: PropTypes.any,
  nodes: PropTypes.any,
  privMode: PropTypes.any,
  dimmed: PropTypes.any,
  selectedNode: PropTypes.any,
  bend: PropTypes.number,
  onHover: PropTypes.func,
};
