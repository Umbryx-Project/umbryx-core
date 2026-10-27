import PropTypes from 'prop-types';
import { NODE_W, ACCESS_COLOR, CRED_COLOR, edgeColor, edgeStrokeDash, edgeStrokeW, edgeOpacity, computeEdgeDimmed } from '../../utils/attackGraph.js';

export default function GraphEdge({ edge, nodes, privMode, dimmed }) {
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

  const goRight = tgt.x >= src.x;
  const sx = src.x + (goRight ? NODE_W / 2 : -NODE_W / 2);
  const sy = src.y;
  const tx = tgt.x + (goRight ? -NODE_W / 2 : NODE_W / 2);
  const ty = tgt.y;
  const mx = (sx + tx) / 2;
  const my = (sy + ty) / 2 - Math.abs(tx - sx) * 0.18;
  const d = `M ${sx} ${sy} Q ${mx} ${my} ${tx} ${ty}`;

  const t = 0.5;
  const lx = (1 - t) ** 2 * sx + 2 * (1 - t) * t * mx + t ** 2 * tx;
  const ly = (1 - t) ** 2 * sy + 2 * (1 - t) * t * my + t ** 2 * ty - 6;

  const strokeDash = edgeStrokeDash(isPrivPath, isPivotRoute, isPivot, isDomainAdmin, isAccess, isPath, edge.verified);
  const strokeW = edgeStrokeW(isPrivPath, isPivotRoute, isPivot, isDomainAdmin, isAccess);
  const opacity = edgeOpacity(dimmed, isPrivPath, isPivotRoute, isAccess, isDomainAdmin);

  return (
    <g>
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
      {edge.label && !isPivotRoute && (() => {
        const strippedCredLabel = edge.label.includes('\\') ? edge.label.split('\\').pop() : edge.label;
        const rawLabel = edge.kind === 'credential' ? strippedCredLabel : edge.label;
        const displayLabel = rawLabel.length > 14 ? rawLabel.slice(0, 13) + '…' : rawLabel;
        const boxW = Math.max(56, displayLabel.length * 5.2 + 12);
        return (
          <>
            <rect x={lx - boxW / 2} y={ly - 9} width={boxW} height={12} rx={3} fill="#07080b" opacity={0.9} />
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
};
