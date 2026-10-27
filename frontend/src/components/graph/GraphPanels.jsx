import PropTypes from 'prop-types';
import React from 'react';
import { STATUS_COLOR, ACCESS_COLOR, SEV_COLOR, renderChainNodeText, isPivotEdge } from '../../utils/attackGraph.js';
import { PALETTE, FONTS } from '../UI.jsx';

function PanelSection({ title, count, children }) {
  return (
    <div style={{ marginBottom: 16 }}>
      <div style={{ fontSize: 9, color: PALETTE.textGhost, textTransform: 'uppercase', letterSpacing: '0.12em', marginBottom: 6, display: 'flex', alignItems: 'center', gap: 6 }}>
        {title}
        {count !== undefined && (
          <span style={{ fontSize: 9, color: PALETTE.border, background: PALETTE.borderSoft, borderRadius: 8, padding: '0 5px', fontFamily: FONTS.mono }}>{count}</span>
        )}
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>{children}</div>
    </div>
  );
}
PanelSection.propTypes = {
  title: PropTypes.any,
  count: PropTypes.any,
  children: PropTypes.any,
};

function InfoRow({ label, value, color }) {
  if (!value) return null;
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '72px 1fr', gap: 4, fontSize: 11 }}>
      <span style={{ color: PALETTE.textGhost, fontFamily: FONTS.mono, fontSize: 9, textTransform: 'uppercase', letterSpacing: '0.08em', paddingTop: 1 }}>{label}</span>
      <span style={{ color: color || '#c8cdd6', fontFamily: FONTS.mono, wordBreak: 'break-all' }}>{value}</span>
    </div>
  );
}
InfoRow.propTypes = {
  label: PropTypes.any,
  value: PropTypes.any,
  color: PropTypes.any,
};

function NodeHostSection({ node, accent }) {
  const reach = node.reachability || {};
  return (
    <PanelSection title="Host">
      <InfoRow label="Role" value={node.role} />
      <InfoRow label="Zone" value={node.zone_type} />
      <InfoRow label="OS" value={node.os} />
      <InfoRow label="IP" value={node.ip} />
      {reach.is_root && <InfoRow label="Reach" value="attacker root" color="#cc2233" />}
      {!reach.is_root && reach.reachable && (
        <InfoRow label="Reach"
          color={reach.reachable_via_verified_path ? '#39d353' : '#5b8af5'}
          value={reach.reachable_via_verified_path
            ? `verified path · ${reach.verified_distance} hop`
            : `reachable · ${reach.distance} hop`} />
      )}
      {!reach.is_root && !reach.reachable && (
        <InfoRow label="Reach" value="unreachable" color="#404550" />
      )}
      {node.tags?.length > 0 && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3, marginTop: 2 }}>
          {node.tags.map(t => (
            <span key={t} style={{ fontSize: 9, background: accent + '1a', border: `1px solid ${accent}33`, borderRadius: 3, padding: '1px 5px', color: accent, fontFamily: FONTS.mono }}>{t}</span>
          ))}
        </div>
      )}
      {node.ports?.length > 0 && (
        <div style={{ marginTop: 4 }}>
          <div style={{ fontSize: 9, color: '#353840', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 3 }}>Ports</div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3 }}>
            {node.ports.slice(0, 20).map((p, i) => (
              <span key={`port-${i}-${typeof p === 'object' ? (p.port || p.number || p.portid) : p}`} style={{ fontSize: 9, background: PALETTE.borderSoft, border: `1px solid ${PALETTE.border}`, borderRadius: 3, padding: '1px 5px', color: PALETTE.textFaint, fontFamily: FONTS.mono }}>
                {typeof p === 'object' ? (p.port || p.number || p.portid) : p}
              </span>
            ))}
            {node.ports.length > 20 && <span style={{ fontSize: 9, color: PALETTE.textGhost, fontFamily: FONTS.mono }}>+{node.ports.length - 20}</span>}
          </div>
        </div>
      )}
    </PanelSection>
  );
}
NodeHostSection.propTypes = {
  node: PropTypes.any,
  accent: PropTypes.any,
};

function NodePrivilegeSection({ node, privilegePaths, nodes }) {
  const priv = node.privilege_info || {};
  if (!priv.is_da_capable && !priv.on_da_path) return null;
  return (
    <PanelSection title="Privilege">
      {priv.is_dc && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '5px 8px', background: '#e8574a11', border: '1px solid #e8574a44', borderRadius: 5 }}>
          <span style={{ fontSize: 10, color: '#e8574a', fontFamily: FONTS.mono, fontWeight: 700 }}>◆ Domain Controller</span>
        </div>
      )}
      {priv.is_da_capable && !priv.is_dc && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '5px 8px', background: '#e8574a11', border: '1px solid #e8574a44', borderRadius: 5 }}>
          <span style={{ fontSize: 10, color: '#e8574a', fontFamily: FONTS.mono, fontWeight: 700 }}>◆ Domain Admin target</span>
        </div>
      )}
      {priv.on_da_path && !priv.is_da_capable && (
        <InfoRow label="DA Path" value={`step ${(priv.da_path_distance ?? 0) + 1} of privilege chain`} color="#e8cc42" />
      )}
      {privilegePaths.length > 0 && priv.is_da_capable && (
        <div style={{ marginTop: 4 }}>
          {privilegePaths.filter(p => p[p.length - 1] === node.id).map((path, i) => {
            const pathNodes = path.map(id => nodes.find(n => n.id === id));
            return (
              <div key={`privpath-${path.join('-')}`} style={{ fontSize: 9, color: '#808590', fontFamily: FONTS.mono, marginBottom: 3 }}>
                {pathNodes.map(n => n?.label || n?.ip || '?').join(' → ')}
              </div>
            );
          })}
        </div>
      )}
    </PanelSection>
  );
}
NodePrivilegeSection.propTypes = {
  node: PropTypes.any,
  privilegePaths: PropTypes.any,
  nodes: PropTypes.any,
};

function NodeAccessSection({ edges, nodeId, nodes }) {
  return (
    <PanelSection title="Access" count={edges.length}>
      {edges.length === 0 ? (
        <div style={{ fontSize: 10, color: '#353840', fontFamily: FONTS.mono }}>No access edges for this host</div>
      ) : edges.slice(0, 8).map(edge => {
        const peerId = edge.from === nodeId ? edge.to : edge.from;
        const peer = nodes.find(n => n.id === peerId);
        const outgoing = edge.from === nodeId;
        const color = edge.verified ? ACCESS_COLOR.verified : ACCESS_COLOR.inferred;
        return (
          <div key={edge.id} style={{ background: '#0a0c10', border: `1px solid ${color}33`, borderRadius: 5, padding: '7px 9px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
              <span style={{ fontSize: 9, color, fontFamily: FONTS.mono, textTransform: 'uppercase' }}>{outgoing ? 'out' : 'in'}</span>
              <span style={{ fontSize: 10, color: PALETTE.textDim, fontWeight: 600 }}>{peer?.label || peer?.ip || peerId}</span>
            </div>
            <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginBottom: edge.reason ? 5 : 0 }}>
              <span style={{ fontSize: 8, color, background: color + '18', border: `1px solid ${color}33`, borderRadius: 3, padding: '1px 5px', fontFamily: FONTS.mono }}>{edge.access_type || edge.label}</span>
              <span style={{ fontSize: 8, color: edge.verified ? '#39d353' : '#808590', background: edge.verified ? '#39d35318' : '#80859018', border: `1px solid ${edge.verified ? '#39d35333' : '#80859033'}`, borderRadius: 3, padding: '1px 5px', fontFamily: FONTS.mono }}>{edge.verified ? 'verified' : 'inferred'}</span>
              {edge.confidence != null && <span style={{ fontSize: 8, color: '#c07af0', background: '#c07af018', border: '1px solid #c07af033', borderRadius: 3, padding: '1px 5px', fontFamily: FONTS.mono }}>{Math.round(Number(edge.confidence) * 100)}%</span>}
            </div>
            {edge.reason && <div style={{ fontSize: 9, color: PALETTE.textFaint, fontFamily: FONTS.mono }}>{edge.reason}</div>}
          </div>
        );
      })}
      {edges.length > 8 && (
        <div style={{ fontSize: 10, color: PALETTE.textGhost, fontFamily: FONTS.mono }}>+{edges.length - 8} more</div>
      )}
    </PanelSection>
  );
}
NodeAccessSection.propTypes = {
  edges: PropTypes.any,
  nodeId: PropTypes.any,
  nodes: PropTypes.any,
};

export function PathsPanel({ privilegePathDetails, pivotChains, nodes, selectedPathIdx, setSelectedPathIdx, setShowPathsPanel }) {
  return (
    <div style={{ width: 240, background: PALETTE.bg2, borderRight: '1px solid #1e2029', display: 'flex', flexDirection: 'column', overflow: 'hidden', flexShrink: 0 }}>
      <div style={{ padding: '10px 12px', borderBottom: `1px solid ${PALETTE.borderSoft}`, display: 'flex', alignItems: 'center', gap: 8 }}>
        <span style={{ fontSize: 10, fontWeight: 700, color: '#e8574a', fontFamily: FONTS.mono, textTransform: 'uppercase', letterSpacing: '0.1em', flex: 1 }}>
          DA Paths · {privilegePathDetails.length}
        </span>
        <button onClick={() => { setSelectedPathIdx(null); setShowPathsPanel(false); }}
          style={{ background: 'none', border: 'none', cursor: 'pointer', color: PALETTE.textGhost, fontSize: 13, padding: 0 }}>✕</button>
      </div>
      <div style={{ flex: 1, overflowY: 'auto', padding: '8px 0' }}>
        {privilegePathDetails.map((pathSteps, idx) => {
          const isSelected = selectedPathIdx === idx;
          return (
            <button type="button" key={`path-${pathSteps.map(s => s.label).join('-')}`} onClick={() => setSelectedPathIdx(isSelected ? null : idx)} onKeyDown={e => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                setSelectedPathIdx(isSelected ? null : idx);
              }
            }}
              style={{ margin: '3px 8px', padding: '8px 10px', borderRadius: 6, cursor: 'pointer', background: isSelected ? '#e8574a11' : 'transparent', border: `1px solid ${isSelected ? '#e8574a44' : PALETTE.borderSoft}`, width: 'calc(100% - 16px)', textAlign: 'left', outline: 'none', color: 'inherit', font: 'inherit' }}>
              <div style={{ fontSize: 9, color: '#e8574a', fontFamily: FONTS.mono, fontWeight: 700, marginBottom: 5, textTransform: 'uppercase' }}>
                Path {idx + 1} · {pathSteps.length} hops
              </div>
              {pathSteps.map((step, si) => (
                <div key={`pstep-${idx}-${si}`} style={{ display: 'flex', flexDirection: 'column', marginBottom: si < pathSteps.length - 1 ? 2 : 0 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                    {(() => {
                      const midDotBg = si === pathSteps.length - 1 ? '#e8574a' : '#5b8af5';
                      const dotBg = si === 0 ? '#cc2233' : midDotBg;
                      return <div style={{ width: 6, height: 6, borderRadius: '50%', flexShrink: 0, background: dotBg }} />;
                    })()}
                    <span style={{ fontSize: 10, color: PALETTE.textDim, fontFamily: FONTS.mono, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{step.label}</span>
                  </div>
                  {step.edge_to_next && (
                    <div style={{ marginLeft: 11, fontSize: 8, color: PALETTE.textGhost, fontFamily: FONTS.mono, display: 'flex', alignItems: 'center', gap: 3, marginBottom: 2 }}>
                      <span style={{ color: PALETTE.border }}>│</span>
                      <span style={{ color: '#e8574a', background: '#e8574a11', borderRadius: 2, padding: '0 3px' }}>{step.edge_to_next}</span>
                    </div>
                  )}
                </div>
              ))}
            </button>
          );
        })}
        {pivotChains.length > 0 && (
          <>
            <div style={{ margin: '8px 8px 4px', fontSize: 9, color: '#c07af0', fontFamily: FONTS.mono, textTransform: 'uppercase', fontWeight: 700, letterSpacing: '0.1em' }}>
              Pivot Chains · {pivotChains.length}
            </div>
            {pivotChains.map((chain, ci) => (
              <div key={`pchain-${chain.join('-')}`} style={{ margin: '2px 8px', padding: '7px 10px', borderRadius: 6, background: '#c07af011', border: '1px solid #c07af033' }}>
                {chain.map((hid, si) => {
                  const n = nodes.find(x => x.id === hid);
                  return (
                    <div key={`pchain-${ci}-node-${si}`} style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                      <div style={{ width: 5, height: 5, borderRadius: '50%', background: '#c07af0', flexShrink: 0 }} />
                      <span style={{ fontSize: 10, color: PALETTE.textDim, fontFamily: FONTS.mono }}>{n?.label || n?.ip || hid.slice(0, 10)}</span>
                      {si < chain.length - 1 && <span style={{ fontSize: 8, color: '#c07af0', marginLeft: 4 }}>→</span>}
                    </div>
                  );
                })}
              </div>
            ))}
          </>
        )}
      </div>
    </div>
  );
}
PathsPanel.propTypes = {
  privilegePathDetails: PropTypes.any,
  pivotChains: PropTypes.any,
  nodes: PropTypes.any,
  selectedPathIdx: PropTypes.any,
  setSelectedPathIdx: PropTypes.any,
  setShowPathsPanel: PropTypes.any,
};

export function NodeSidePanel({ selectedNode, setSelectedNode, accent, privilegePaths, nodes, selectedNodeAccessEdges, selectedNodePivotEdges, linkedCreds, linkedFindings, pivotChains }) {
  const involvedChains = pivotChains.filter(chain => chain.includes(selectedNode.id));
  return (
    <div style={{ width: 280, margin: 10, background: PALETTE.bg2, border: '1px solid #1e2029', borderRadius: 10, display: 'flex', flexDirection: 'column', overflow: 'hidden', flexShrink: 0 }}>
      <div style={{ padding: '12px 14px', borderBottom: `1px solid ${PALETTE.borderSoft}`, display: 'flex', alignItems: 'center', gap: 8 }}>
        <div style={{ flex: 1, overflow: 'hidden' }}>
          <div style={{ fontSize: 12, fontWeight: 700, color: PALETTE.text, fontFamily: FONTS.display, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {selectedNode.label || selectedNode.hostname || selectedNode.ip || 'Node'}
          </div>
          {selectedNode.ip && (selectedNode.label || selectedNode.hostname) && (
            <div style={{ fontSize: 10, color: PALETTE.textGhost, fontFamily: FONTS.mono, marginTop: 1 }}>{selectedNode.ip}</div>
          )}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          <div style={{ width: 6, height: 6, borderRadius: '50%', background: STATUS_COLOR[selectedNode.status] || STATUS_COLOR.unknown }} />
          <span style={{ fontSize: 9, color: STATUS_COLOR[selectedNode.status] || STATUS_COLOR.unknown, fontFamily: FONTS.mono, textTransform: 'uppercase' }}>{selectedNode.status || 'unknown'}</span>
        </div>
        <button onClick={() => setSelectedNode(null)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: PALETTE.textGhost, fontSize: 14, padding: 0, marginLeft: 4 }}>✕</button>
      </div>
      <div style={{ flex: 1, overflowY: 'auto', padding: '14px 14px 10px' }}>
        <NodeHostSection node={selectedNode} accent={accent} />
        <NodePrivilegeSection node={selectedNode} privilegePaths={privilegePaths} nodes={nodes} />
        <NodeAccessSection edges={selectedNodeAccessEdges} nodeId={selectedNode.id} nodes={nodes} />
        {involvedChains.length > 0 && (
          <PanelSection title="Pivot Chains" count={involvedChains.length}>
            {involvedChains.map((chain, ci) => (
              <div key={`ichain-${chain.join('-')}`} style={{ background: '#0a0c10', border: '1px solid #c07af033', borderRadius: 5, padding: '7px 9px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 4, flexWrap: 'wrap' }}>
                  {chain.map((hid, si) => {
                    const { text, isSelf, isLast } = renderChainNodeText(hid, si, chain, nodes, selectedNode.id);
                    return (
                      <React.Fragment key={si}>
                        <span style={{ fontSize: 9, color: isSelf ? '#c07af0' : '#808590', fontFamily: FONTS.mono, fontWeight: isSelf ? 700 : 400 }}>{text}</span>
                        {!isLast && <span style={{ fontSize: 9, color: '#c07af066' }}>→</span>}
                      </React.Fragment>
                    );
                  })}
                </div>
              </div>
            ))}
          </PanelSection>
        )}
        {selectedNodePivotEdges.length > 0 && (
          <PanelSection title="Pivot Routes" count={selectedNodePivotEdges.length}>
            {selectedNodePivotEdges.slice(0, 6).map(edge => {
              const isPR = edge.kind === 'pivot_route';
              const peerId = edge.from === selectedNode.id ? edge.to : edge.from;
              const peer = nodes.find(n => n.id === peerId);
              const color = ACCESS_COLOR.pivot_route;
              return (
                <div key={edge.id} style={{ background: '#0a0c10', border: `1px solid ${color}33`, borderRadius: 5, padding: '7px 9px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span style={{ fontSize: 8, color, background: color + '18', border: `1px solid ${color}33`, borderRadius: 3, padding: '1px 5px', fontFamily: FONTS.mono }}>
                      {isPR ? edge.route_cidr || 'route' : edge.pivot_tool || 'pivot'}
                    </span>
                    <span style={{ fontSize: 10, color: PALETTE.textDim }}>{peer?.label || peer?.ip || peerId}</span>
                  </div>
                </div>
              );
            })}
          </PanelSection>
        )}
        <PanelSection title="Credentials" count={linkedCreds.length}>
          {linkedCreds.length === 0 ? (
            <div style={{ fontSize: 10, color: '#353840', fontFamily: FONTS.mono }}>No credentials linked to this host</div>
          ) : linkedCreds.slice(0, 8).map(c => (
            <div key={c.id} style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 5, padding: '7px 9px' }}>
              <div style={{ fontSize: 11, color: PALETTE.textDim, fontFamily: FONTS.mono, fontWeight: 600 }}>{c.username}</div>
              <div style={{ fontSize: 9, color: PALETTE.textGhost, fontFamily: FONTS.mono, marginTop: 2 }}>{[c.service, c.type, c.domain].filter(Boolean).join(' · ')}</div>
            </div>
          ))}
          {linkedCreds.length > 8 && <div style={{ fontSize: 10, color: PALETTE.textGhost, fontFamily: FONTS.mono }}>+{linkedCreds.length - 8} more</div>}
        </PanelSection>
        <PanelSection title="Findings" count={linkedFindings.length}>
          {linkedFindings.length === 0 ? (
            <div style={{ fontSize: 10, color: '#353840', fontFamily: FONTS.mono }}>No findings mention this host</div>
          ) : linkedFindings.slice(0, 5).map(f => (
            <div key={f.id} style={{ background: '#0a0c10', border: `1px solid ${SEV_COLOR[f.severity] || '#2a2d35'}33`, borderRadius: 5, padding: '7px 9px' }}>
              <div style={{ fontSize: 10, color: PALETTE.textDim, fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{f.title}</div>
              <div style={{ fontSize: 8, color: SEV_COLOR[f.severity] || '#808590', fontFamily: FONTS.mono, textTransform: 'uppercase', marginTop: 2 }}>{f.severity}</div>
            </div>
          ))}
          {linkedFindings.length > 5 && <div style={{ fontSize: 10, color: PALETTE.textGhost, fontFamily: FONTS.mono }}>+{linkedFindings.length - 5} more</div>}
        </PanelSection>
      </div>
    </div>
  );
}
NodeSidePanel.propTypes = {
  selectedNode: PropTypes.any,
  setSelectedNode: PropTypes.any,
  accent: PropTypes.any,
  privilegePaths: PropTypes.any,
  nodes: PropTypes.any,
  selectedNodeAccessEdges: PropTypes.any,
  selectedNodePivotEdges: PropTypes.any,
  linkedCreds: PropTypes.any,
  linkedFindings: PropTypes.any,
  pivotChains: PropTypes.any,
};
