/**
 * Memoized network node and edge render components.
 *
 * Extracted from NetworkCanvas to prevent full-tree re-renders
 * when only selection/pan/zoom changes.
 */
import { memo } from 'react';
import PropTypes from 'prop-types';
import { NodeShape } from './NodeVisuals.jsx';
import { renderRoleBadges, renderChip } from './GraphAlgorithms.jsx';
import { PALETTE, FONTS } from '../../components/UI.jsx';

const ZONE_COLORS = { internal: '#5b8af5', dmz: PALETTE.warn, external: PALETTE.danger, management: '#c07af0', scope_pivot: PALETTE.warn };
const TIER_COLORS = { 0: '#e8574a', 1: PALETTE.warn };

export const NetworkNodeView = memo(function NetworkNodeView({
  node, statusColor, isSelected, isDimmed, simplified,
  roleBadges, pivotInfo, overlayEntry, engagedBy, accent, onMouseDown,
}) {
  let displayIps = [];
  if (node.ips?.length > 0) displayIps = node.ips;
  else if (node.ip) displayIps = [node.ip];

  return (
    <g
      className={`map-node${isSelected ? ' map-node-sel' : ''}`}
      transform={`translate(${node.x - 20},${node.y - 20})`}
      onMouseDown={onMouseDown}
      style={{
        '--sc': statusColor,
        cursor: 'pointer',
        userSelect: 'none',
        opacity: isDimmed ? 0.15 : 1,
        filter: isDimmed ? 'grayscale(0.7)' : undefined,
        transition: 'opacity .2s, filter .2s',
      }}
    >
      {isSelected && <rect x="-5" y="-5" width="50" height="50" rx="10" fill={`${accent}18`} stroke={accent} strokeWidth="1.5" />}
      {overlayEntry && isSelected && <rect x="-5" y="-5" width="50" height="50" rx="10" fill={`${overlayEntry.color}33`} stroke={overlayEntry.color} strokeWidth="3" />}
      {overlayEntry && !isSelected && <rect x="-5" y="-5" width="50" height="50" rx="10" fill={`${overlayEntry.color}22`} stroke={overlayEntry.color} strokeWidth="2" strokeDasharray="4 2" opacity=".9" />}
      <rect className="node-hov" x="-3" y="-3" width="46" height="46" rx="9" fill="#ffffff08" stroke="var(--sc)" strokeWidth="1" style={{ pointerEvents: 'none' }} />
      <NodeShape type={node.type} status={node.status} size={40} selected={isSelected} accent={accent} />
      {overlayEntry && <circle cx="4" cy="4" r="5" fill={overlayEntry.color} opacity=".95" style={{ filter: `drop-shadow(0 0 4px ${overlayEntry.color})` }} />}
      <circle cx="36" cy="4" r="4" fill={statusColor} opacity=".9" style={{ filter: `drop-shadow(0 0 3px ${statusColor})` }} />
      {engagedBy && (() => {
        const ops = engagedBy.operators;
        const primary = ops.find(o => o.is_me) || ops[0];
        const chipColor = primary.is_me ? accent : PALETTE.warn;
        const shortName = primary.username.length > 12 ? `${primary.username.slice(0, 11)}…` : primary.username;
        const extra = ops.length - 1;
        const label = extra > 0 ? `${shortName}+${extra}` : shortName;
        const fontSize = 9;
        const height = 15;
        // JetBrains Mono advance width is ~0.6em; pad for the rounded plate.
        const w = label.length * fontSize * 0.62 + 10;
        const cx = 20;
        const cy = -23;
        return (
          <g transform={`translate(${cx - w / 2},${cy})`}>
            <title>{`Engaged: ${ops.map(o => `${o.username}${o.is_me ? ' (you)' : ''} [${o.sources.join('+')}]`).join(', ')}`}</title>
            {/* Opaque backdrop: a translucent plate let map edges show through
                and made the operator name unreadable. */}
            <rect x="0" y="0" width={w} height={height} rx="3.5" fill="#0b0d12" fillOpacity=".92" stroke={chipColor} strokeWidth="1" />
            <text x={w / 2} y={height * 0.72} textAnchor="middle" fontSize={fontSize} fill={chipColor} fontFamily="JetBrains Mono" fontWeight="700">{label}</text>
          </g>
        );
      })()}
      {pivotInfo && !simplified && (() => {
        const isSocks = pivotInfo.type === 'socks5' || pivotInfo.type === 'socks4';
        const label = isSocks ? 'SOCKS' : pivotInfo.type === 'route' ? 'ROUTE' : 'PIVOT';
        const pc = isSocks ? '#e8cc42' : PALETTE.warn;
        return renderChip(20, 41, label, pc, { fontSize: 5.5, height: 9 });
      })()}
      {(!simplified || isSelected) && (
        <text x="20" y="53" textAnchor="middle" fontSize="10" fill={isSelected ? '#f0f2f6' : PALETTE.textMute} fontFamily="JetBrains Mono" fontWeight={isSelected ? 600 : 400}>{node.label}</text>
      )}
      {!simplified && displayIps.map((ip, idx) => (
        <text key={ip || `ip-${idx}`} x="20" y={64 + idx * 9} textAnchor="middle" fontSize="8" fill={statusColor} fontFamily="JetBrains Mono" opacity=".8">{ip}</text>
      ))}
      {!simplified && (() => {
        const ipCount = displayIps.length;
        let badgeY = 64 + ipCount * 9 + 4;
        const roleElems = roleBadges?.length ? renderRoleBadges(roleBadges, badgeY) : null;
        if (roleBadges?.length) badgeY += 13;
        const zoneElem = node.zone_type && node.zone_type !== 'scope'
          ? renderChip(20, badgeY, node.zone_type.toUpperCase().slice(0, 4), ZONE_COLORS[node.zone_type] || '#606570')
          : null;
        const rawTier = node.tier ?? node.extra_json?.tier;
        const tierVal = (rawTier === 0 || rawTier === 1) ? rawTier : null;
        const tierElem = tierVal === null ? null : (() => {
          const tc = TIER_COLORS[tierVal];
          // Crown for Tier 0, shield for Tier 1 — the BloodHound convention
          // the audience reads instantly. Sits in the lower-left corner;
          // the status dot owns the top-right, the engaged chip the top.
          const isCrown = tierVal === 0;
          const shape = isCrown
            ? 'M2 12 L3 6 L6.5 9.5 L8 4 L9.5 9.5 L13 6 L14 12Z'
            : 'M8 1.5L2 4v4c0 3.31 2.67 5.74 6 6.5 3.33-.76 6-3.19 6-6.5V4L8 1.5z';
          return (
            <g>
              <g transform="translate(1,27) scale(0.7)">
                <path d={shape} fill="none" stroke={tc} strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" />
                {isCrown && <line x1="2" y1="14.5" x2="14" y2="14.5" stroke={tc} strokeWidth="2" strokeLinecap="round" />}
              </g>
              <title>{`Tier ${tierVal}`}</title>
            </g>
          );
        })();
        if (!roleElems && !zoneElem && !tierElem) return null;
        return <>{roleElems}{zoneElem}{tierElem}</>;
      })()}
    </g>
  );
});
NetworkNodeView.propTypes = {
  node: PropTypes.object.isRequired,
  statusColor: PropTypes.string.isRequired,
  isSelected: PropTypes.bool,
  isDimmed: PropTypes.bool,
  simplified: PropTypes.bool,
  roleBadges: PropTypes.array,
  pivotInfo: PropTypes.object,
  overlayEntry: PropTypes.object,
  engagedBy: PropTypes.object,
  accent: PropTypes.string,
  onMouseDown: PropTypes.func,
};

export const NetworkEdgeView = memo(function NetworkEdgeView({
  edge, fromX, fromY, toX, toY, strokeColor, strokeWidth, dashArray,
  markerEnd, isDimmed, showLabel, animateEdges, onContextMenu, strokeOpacity, title,
}) {
  const mx = (fromX + toX) / 2;
  const my = (fromY + toY) / 2;
  const edgeLabel = showLabel ? String(edge.label || '').trim() : '';
  return (
    <g style={{ opacity: isDimmed ? 0.06 : 1, transition: 'opacity .2s' }}>
      {title && <title>{title}</title>}
      <line x1={fromX} y1={fromY} x2={toX} y2={toY} stroke={strokeColor} strokeWidth={strokeWidth}
        strokeDasharray={dashArray} markerEnd={markerEnd} opacity={strokeOpacity ?? 0.9}
        style={animateEdges ? { animation: 'dash 1.5s linear infinite' } : undefined}
      />
      {edgeLabel && (
        <>
          <rect x={mx - edgeLabel.length * 3 - 4} y={my - 8} width={edgeLabel.length * 6 + 8} height="14" rx="3"
            fill="#0e1016" stroke={strokeColor} strokeWidth="0.5" opacity=".95" />
          <text x={mx} y={my + 3} textAnchor="middle" fontSize="9" fill={strokeColor} fontFamily="JetBrains Mono">{edgeLabel}</text>
        </>
      )}
      <line x1={fromX} y1={fromY} x2={toX} y2={toY} stroke="transparent" strokeWidth={14}
        style={{ cursor: 'default' }}
        onContextMenu={onContextMenu}
      />
    </g>
  );
});
NetworkEdgeView.propTypes = {
  edge: PropTypes.object.isRequired,
  fromX: PropTypes.number, fromY: PropTypes.number,
  toX: PropTypes.number, toY: PropTypes.number,
  strokeColor: PropTypes.string, strokeWidth: PropTypes.number,
  dashArray: PropTypes.string, markerEnd: PropTypes.string,
  isDimmed: PropTypes.bool, showLabel: PropTypes.bool, animateEdges: PropTypes.bool,
  onContextMenu: PropTypes.func, strokeOpacity: PropTypes.number, title: PropTypes.string,
};

// ── Cluster node (collapsed region) ───────────────────────────────────

export const ClusterNodeView = memo(function ClusterNodeView({
  cluster, isSelected, isExpanded, accent, onMouseDown, onToggle,
}) {
  const { x, y, label, nodeCount, errorCount, zoneType, hasFailover } = cluster;
  const w = 120;
  const h = 60;
  const hasError = errorCount > 0;
  const borderColor = hasError ? '#cc2233' : zoneType ? (ZONE_COLORS[zoneType] || accent) : accent;

  return (
    <g
      transform={`translate(${x - w / 2},${y - h / 2})`}
      onMouseDown={onMouseDown}
      onDoubleClick={onToggle}
      style={{ cursor: 'pointer', userSelect: 'none' }}
    >
      <rect x="0" y="0" width={w} height={h} rx="10"
        fill={`${borderColor}15`}
        stroke={borderColor}
        strokeWidth={isSelected ? 2.5 : 1.5}
        strokeDasharray={isExpanded ? undefined : '6 3'}
      />
      {/* Collapse/expand indicator */}
      <circle cx={w - 12} cy={12} r="7" fill={`${borderColor}33`} stroke={borderColor} strokeWidth="1" />
      <text x={w - 12} y={15} textAnchor="middle" fontSize="9" fill={borderColor} fontFamily="JetBrains Mono" fontWeight="700">
        {isExpanded ? '\u2212' : '+'}
      </text>
      {/* Label */}
      <text x={w / 2} y={20} textAnchor="middle" fontSize="11" fill="#e0e4ec" fontFamily="Space Grotesk" fontWeight="700">
        {label}
      </text>
      {/* Node count */}
      <text x={w / 2} y={36} textAnchor="middle" fontSize="9" fill="#808590" fontFamily="JetBrains Mono">
        {nodeCount} {nodeCount === 1 ? 'node' : 'nodes'}
      </text>
      {/* Error indicator */}
      {hasError && (
        <g transform={`translate(${w / 2 - 30},${44})`}>
          <circle cx="0" cy="0" r="4" fill="#cc2233" opacity=".9" style={{ filter: `drop-shadow(0 0 3px ${PALETTE.danger})` }} />
          <text x="8" y="3" fontSize="8" fill="#cc2233" fontFamily="JetBrains Mono" fontWeight="600">{errorCount} error{errorCount > 1 ? 's' : ''}</text>
        </g>
      )}
      {/* Failover indicator */}
      {hasFailover && (
        <g transform={`translate(${w / 2 + 10},${44})`}>
          <text x="0" y="3" fontSize="8" fill="#c07af0" fontFamily="JetBrains Mono" fontWeight="600">{'\u21C5'} failover</text>
        </g>
      )}
      {/* Zone type badge */}
      {zoneType && (
        <g transform={`translate(8,${h - 12})`}>
          <rect x="0" y="0" width={zoneType.length * 5.5 + 6} height="10" rx="2.5" fill={`${borderColor}22`} stroke={`${borderColor}55`} strokeWidth=".8" />
          <text x={(zoneType.length * 5.5 + 6) / 2} y="7.5" textAnchor="middle" fontSize="6" fill={borderColor} fontFamily="JetBrains Mono" fontWeight="700">{zoneType.toUpperCase()}</text>
        </g>
      )}
    </g>
  );
});
ClusterNodeView.propTypes = {
  cluster: PropTypes.object.isRequired,
  isSelected: PropTypes.bool,
  isExpanded: PropTypes.bool,
  accent: PropTypes.string,
  onMouseDown: PropTypes.func,
  onToggle: PropTypes.func,
};
