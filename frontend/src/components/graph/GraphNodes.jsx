import PropTypes from 'prop-types';
import { NODE_W, NODE_H, STATUS_COLOR, nodeOsShort, nodeReachBadge, nodeBorderColor, nodeBgFill } from '../../utils/attackGraph.js';
import { PALETTE, FONTS } from '../UI.jsx';

function NodeSecondaryLabel({ isAttacker, sublabel }) {
  if (isAttacker) {
    return <text x={NODE_W / 2} y={54} textAnchor="middle" fontSize={9} fill="#cc2233" fontFamily="JetBrains Mono" fontWeight={700}>◆ ATTACKER</text>;
  }
  if (sublabel) {
    return <text x={NODE_W / 2} y={54} textAnchor="middle" fontSize={9} fill="#505560" fontFamily="JetBrains Mono">{sublabel}</text>;
  }
  return null;
}
NodeSecondaryLabel.propTypes = {
  isAttacker: PropTypes.any,
  sublabel: PropTypes.any,
};

function NodeReachBadgeSvg({ reachBadge, reach }) {
  if (!reachBadge) return null;
  const color = reach.reachable_via_verified_path ? '#39d353' : '#5b8af5';
  return (
    <g>
      <rect x={4} y={NODE_H - 14} width={reachBadge.length * 6 + 6} height={11} rx={3} fill="#1a1c22" />
      <text x={7} y={NODE_H - 6} fontSize={8} fill={color} fontFamily="JetBrains Mono">{reachBadge}</text>
    </g>
  );
}
NodeReachBadgeSvg.propTypes = {
  reachBadge: PropTypes.any,
  reach: PropTypes.any,
};

function NodePortBadge({ isAttacker, node }) {
  if (isAttacker || !node.ports || node.ports.length === 0) return null;
  return (
    <g>
      <rect x={NODE_W - 30} y={NODE_H - 15} width={26} height={11} rx={3} fill="#1a1c22" />
      <text x={NODE_W - 17} y={NODE_H - 7} textAnchor="middle" fontSize={8} fill="#404550" fontFamily="JetBrains Mono">
        {node.ports.length}p
      </text>
    </g>
  );
}
NodePortBadge.propTypes = {
  isAttacker: PropTypes.any,
  node: PropTypes.any,
};

export default function HostNode({ node, selected, privMode, onMouseDown, onClick }) {
  const isAttacker = node.type === 'attacker' || node.is_attacker;
  const sc = STATUS_COLOR[node.status] || STATUS_COLOR.unknown;
  const priv = node.privilege_info || {};
  const reach = node.reachability || {};

  const isDA = priv.is_da_capable;
  const isDC = priv.is_dc;
  const onPath = privMode && priv.on_da_path;

  const borderColor = nodeBorderColor(selected, isAttacker, onPath, isDA, sc);
  const glowTint = isDA ? '#e8574a' : '#e8cc42';
  const glowColor = onPath ? glowTint : null;

  const label = node.label || node.hostname || node.ip || node.id || '';
  const sublabel = node.ip && label !== node.ip ? node.ip : '';
  const osShort = nodeOsShort(node.os);
  const reachBadge = nodeReachBadge(reach);
  const strokeW = selected || onPath ? 2 : 1.5;

  const x = node.x - NODE_W / 2;
  const y = node.y - NODE_H / 2;

  return (
    <g
      transform={`translate(${x},${y})`}
      onMouseDown={e => { e.stopPropagation(); onMouseDown(e, node); }}
      onClick={() => onClick(node)}
      style={{ cursor: 'pointer' }}
    >
      {glowColor && (
        <rect width={NODE_W} height={NODE_H} rx={10} ry={10}
          fill="none" stroke={glowColor} strokeWidth={6} strokeOpacity={0.18} />
      )}
      {selected && (
        <rect width={NODE_W} height={NODE_H} rx={9} ry={9}
          fill="none" stroke="#ffffff" strokeWidth={3} strokeOpacity={0.15} />
      )}
      <rect width={NODE_W} height={NODE_H} rx={8} ry={8}
        fill={nodeBgFill(isAttacker, onPath, isDA)}
        stroke={borderColor}
        strokeWidth={strokeW}
        strokeOpacity={selected ? 1 : 0.8}
      />
      <rect width={NODE_W} height={3} rx={2} ry={0} fill={borderColor} opacity={0.5} />

      <circle cx={10} cy={14} r={3.5} fill={sc} />
      <text x={18} y={18} fontSize={8.5} fill={sc} fontFamily="JetBrains Mono">
        {(node.status || (isAttacker ? 'attacker' : 'unknown')).toUpperCase()}
      </text>

      {osShort && (
        <text x={NODE_W - 7} y={18} fontSize={8} fill="#404550" fontFamily="JetBrains Mono" textAnchor="end">
          {osShort}
        </text>
      )}

      <text x={NODE_W / 2} y={39} textAnchor="middle" fontSize={12} fontWeight={600} fill="#e4e8f0"
        fontFamily={label.match(/^\d/) ? 'JetBrains Mono' : FONTS.display}>
        {label.length > 18 ? label.slice(0, 17) + '…' : label}
      </text>

      <NodeSecondaryLabel isAttacker={isAttacker} sublabel={sublabel} />

      {isDA && (
        <g transform={`translate(${NODE_W - 16}, ${NODE_H - 16})`}>
          <circle r={7} fill="#e8574a" opacity={0.9} />
          <text textAnchor="middle" dominantBaseline="middle" fontSize={8} fill="#fff" fontFamily="JetBrains Mono" fontWeight={700}>
            {isDC ? 'DC' : 'DA'}
          </text>
        </g>
      )}

      <NodeReachBadgeSvg reachBadge={reachBadge} reach={reach} />
      <NodePortBadge isAttacker={isAttacker} node={node} />
    </g>
  );
}
HostNode.propTypes = {
  node: PropTypes.any,
  selected: PropTypes.any,
  privMode: PropTypes.any,
  onMouseDown: PropTypes.any,
  onClick: PropTypes.any,
};
