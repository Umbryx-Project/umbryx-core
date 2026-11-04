import PropTypes from 'prop-types';
import React from 'react';
import { STATUS_COLOR, ACCESS_COLOR, SEV_COLOR, renderChainNodeText, isPivotEdge, chainEdgeLabel, edgeFreshness } from '../../utils/attackGraph.js';
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

// AG Phase 3: the attack frontier as an actionable list — what to
// validate next, each item jumping to the surface where it's fixed.
export function FrontierPanel({ suggestions, onSuggestion, onClose }) {
  return (
    <div style={{ width: 250, background: PALETTE.bg2, borderRight: '1px solid #1e2029', display: 'flex', flexDirection: 'column', overflow: 'hidden', flexShrink: 0 }}>
      <div style={{ padding: '10px 12px', borderBottom: `1px solid ${PALETTE.borderSoft}`, display: 'flex', alignItems: 'center', gap: 8 }}>
        <span style={{ fontSize: 10, fontWeight: 700, color: '#f09a3a', fontFamily: FONTS.mono, textTransform: 'uppercase', letterSpacing: '0.1em', flex: 1 }}>
          Frontier · {suggestions.length}
        </span>
        <button onClick={onClose}
          style={{ background: 'none', border: 'none', cursor: 'pointer', color: PALETTE.textGhost, fontSize: 13, padding: 0 }}>✕</button>
      </div>
      <div style={{ padding: '6px 8px', fontSize: 9.5, color: PALETTE.textGhost, fontFamily: FONTS.mono, borderBottom: `1px solid ${PALETTE.borderSoft}` }}>
        believed but unconfirmed — validate to turn amber into fact
      </div>
      <div style={{ flex: 1, overflowY: 'auto', padding: '8px 8px' }}>
        {suggestions.length === 0 && (
          <div style={{ fontSize: 10, color: PALETTE.textGhost, fontFamily: FONTS.mono, padding: '8px 4px' }}>
            nothing to validate — every cred and access fact is confirmed
          </div>
        )}
        {suggestions.map((s, i) => (
          <button key={`${s.kind}-${i}`} onClick={() => onSuggestion(s)} style={{
            width: '100%', textAlign: 'left', marginBottom: 6, cursor: 'pointer',
            background: '#0d1016', border: '1px solid #1e2029', borderRadius: 6, padding: '7px 9px',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <span style={{ fontSize: 10, color: s.kind === 'validate_cred' ? '#f09a3a' : '#e8cc42', fontFamily: FONTS.mono }}>
                {s.kind === 'validate_cred' ? '🔑' : '→'}
              </span>
              <span style={{ fontSize: 10.5, color: PALETTE.text, fontFamily: FONTS.mono, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {s.title}
              </span>
            </div>
            <div style={{ fontSize: 9, color: PALETTE.textGhost, fontFamily: FONTS.mono, marginTop: 2 }}>
              {s.hint}
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}
FrontierPanel.propTypes = {
  suggestions: PropTypes.array,
  onSuggestion: PropTypes.func,
  onClose: PropTypes.func,
};

// AG: BloodHound-style edge tooltip — how the target node was reached.
export function EdgeTooltip({ hover, allCreds }) {
  if (!hover) return null;
  const { edge, src, tgt, pos } = hover;
  const fresh = edgeFreshness(edge);
  const cred = edge.cred_id ? (allCreds || []).find(c => c.id === edge.cred_id) : null;

  let title = '', lines = [];
  if (edge.kind === 'credential') {
    title = `🔑 held credential`;
    lines = [
      `attacker holds ${tgt.label || 'credential'}`,
      cred ? `type ${cred.type}${cred.cracked ? ' · cracked' : ' · hash not cracked'}` : edge.cred_type || '',
    ].filter(Boolean);
  } else if (edge.kind === 'credential_use') {
    title = `🔑 credential opens host`;
    lines = [
      `${src.label} → ${tgt.label}`,
      cred ? `${cred.domain ? cred.domain + '\\' : ''}${cred.username} · ${cred.type}${cred.cracked ? ' · cracked' : ''}` : 'validated access',
      'verified — host_ids come from validation',
    ];
  } else if (edge.kind === 'access') {
    title = `${edge.access_type || 'access'} access`;
    lines = [
      `${src.label} → ${tgt.label}`,
      edge.verified ? 'verified' : 'inferred — not confirmed yet',
      edge.label || '',
    ].filter(Boolean);
  } else if (edge.kind === 'pivot' || edge.kind === 'pivot_route') {
    title = `pivot · ${edge.pivot_tool || 'tunnel'}`;
    lines = [
      edge.kind === 'pivot_route' ? `route ${edge.route_cidr || ''}` : `${src.label} → ${tgt.label}`,
      edge.verified ? 'active' : 'status unknown',
      fresh ? `seen ${edge.observed_at?.slice(0, 10)}${fresh.stale ? ' · STALE' : ''}` : '',
    ].filter(Boolean);
  } else if (edge.kind === 'path') {
    title = 'attack path step';
    lines = [`${src.label} → ${tgt.label}`, edge.label || ''];
  } else {
    title = edge.kind || 'edge';
    lines = [`${src.label} → ${tgt.label}`];
  }

  return (
    <div style={{
      position: 'fixed', left: pos.x + 14, top: pos.y + 12, zIndex: 50,
      maxWidth: 280, padding: '7px 10px', background: '#0d0f14f2',
      border: '1px solid #1e2029', borderRadius: 6, pointerEvents: 'none',
      fontFamily: 'JetBrains Mono, monospace',
    }}>
      <div style={{ fontSize: 10, fontWeight: 700, color: '#e4e8f0', marginBottom: 3 }}>{title}</div>
      {lines.map((l, i) => (
        <div key={i} style={{ fontSize: 9, color: fresh?.stale && i === lines.length - 1 ? '#f09a3a' : '#808590' }}>{l}</div>
      ))}
      <div style={{ fontSize: 8.5, color: '#505560', marginTop: 4, borderTop: '1px solid #1a1c22', paddingTop: 3 }}>
        click a node for the full path — {tgt.label}
      </div>
    </div>
  );
}
EdgeTooltip.propTypes = {
  hover: PropTypes.any,
  allCreds: PropTypes.array,
};

export function PathsPanel({ privilegePathDetails, pivotChains, nodes, selectedPathIdx, setSelectedPathIdx, setShowPathsPanel, onNavigate }) {
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
              {isSelected && onNavigate && (
                <div style={{ display: 'flex', gap: 4, marginTop: 8 }} onClick={e => e.stopPropagation()}>
                  <button onClick={() => onNavigate('attackpath', { from_da_path: pathSteps.map(st => st.id) })} style={{ flex: 1, background: '#e8574a11', border: '1px solid #e8574a44', borderRadius: 4, padding: '4px 6px', cursor: 'pointer', color: '#e8574a', fontSize: 9, fontFamily: FONTS.mono }}>
                    → Attack Path
                  </button>
                  <button onClick={() => onNavigate('network', pathSteps[pathSteps.length - 1].id)} style={{ flex: 1, background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '4px 6px', cursor: 'pointer', color: PALETTE.textFaint, fontSize: 9, fontFamily: FONTS.mono }}>
                    → Map
                  </button>
                </div>
              )}
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

function CredSidePanel({ selectedNode, setSelectedNode, accent, edges, nodes, onDelete }) {
  const labelById = new Map((nodes || []).map(n => [n.id, n.label || n.ip || n.id]));
  const opens = edges
    .filter(e => e.kind === 'credential_use' && e.from === selectedNode.id)
    .map(e => ({ ...e, to_label: labelById.get(e.to) || e.to }));
  return (
    <div style={{ width: 290, borderLeft: `1px solid ${PALETTE.borderSoft}`, background: '#0a0c10', overflowY: 'auto', padding: '14px 16px', boxSizing: 'border-box' }}>
      <div style={{ fontSize: 11, color: PALETTE.textGhost, marginBottom: 4, fontFamily: FONTS.mono, textTransform: 'uppercase', letterSpacing: '0.08em' }}>Credential</div>
      <div style={{ fontSize: 15, fontWeight: 700, color: PALETTE.text, fontFamily: FONTS.display, marginBottom: 2 }}>
        {selectedNode.domain ? `${selectedNode.domain}\\` : ''}{selectedNode.username || selectedNode.label}
      </div>
      <div style={{ display: 'flex', gap: 6, margin: '8px 0 14px', flexWrap: 'wrap' }}>
        <span style={{ fontSize: 9, fontFamily: FONTS.mono, border: `1px solid ${selectedNode.cracked ? '#39d35366' : '#f09a3a66'}`, color: selectedNode.cracked ? '#39d353' : '#f09a3a', borderRadius: 3, padding: '1px 6px' }}>
          {selectedNode.cracked ? 'cracked / usable' : 'hash — not cracked'}
        </span>
        {selectedNode.cred_type && (
          <span style={{ fontSize: 9, fontFamily: FONTS.mono, border: `1px solid ${PALETTE.border}`, color: PALETTE.textDim, borderRadius: 3, padding: '1px 6px' }}>{selectedNode.cred_type}</span>
        )}
        {selectedNode.is_domain && (
          <span style={{ fontSize: 9, fontFamily: FONTS.mono, border: '1px solid #5b8af566', color: '#5b8af5', borderRadius: 3, padding: '1px 6px' }}>domain account</span>
        )}
      </div>
      <div style={{ fontSize: 10, color: PALETTE.textGhost, marginBottom: 6, fontFamily: FONTS.mono, textTransform: 'uppercase' }}>Opens ({opens.length})</div>
      {opens.map(e => (
        <div key={e.id} style={{ padding: '5px 8px', marginBottom: 4, background: '#0d0f14', border: `1px solid ${PALETTE.borderSoft}`, borderRadius: 4, fontSize: 11, color: PALETTE.textDim, fontFamily: FONTS.mono }}>
          → {e.to_label || e.to}
        </div>
      ))}
      {opens.length === 0 && (
        <div style={{ fontSize: 10, color: PALETTE.textGhost, fontFamily: FONTS.mono }}>No validated hosts — run a credential check (NetExec spray / validation job) to see where it works.</div>
      )}
      <div style={{ display: 'flex', gap: 6, marginTop: 14 }}>
        <button onClick={() => setSelectedNode(null)} style={{ flex: 1, background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '4px 12px', cursor: 'pointer', color: PALETTE.textFaint, fontSize: 10, fontFamily: FONTS.mono }}>Close</button>
        {onDelete && (
          <button onClick={() => { if (globalThis.confirm(`Delete credential ${selectedNode.label}? The graph rebuilds without it.`)) onDelete(selectedNode); }}
            style={{ flex: 1, background: '#cc223311', border: '1px solid #cc233344', borderRadius: 4, padding: '4px 12px', cursor: 'pointer', color: '#e8574a', fontSize: 10, fontFamily: FONTS.mono }}>Delete cred</button>
        )}
      </div>
    </div>
  );
}

export function HowWeGotHere({ chain }) {
  if (!chain || chain.length <= 1) return null;
  return (
    <div style={{ marginBottom: 12 }}>
      <div style={{ fontSize: 10, color: PALETTE.textGhost, marginBottom: 6, fontFamily: FONTS.mono, textTransform: 'uppercase' }}>How we got here</div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
        {chain.map((step, i) => (
          <div key={`${step.node.id}-${i}`}>
            {step.viaEdge && (
              <div style={{ fontSize: 9, color: PALETTE.textGhost, fontFamily: FONTS.mono, paddingLeft: 10 }}>
                ↓ {chainEdgeLabel(step.viaEdge)}
              </div>
            )}
            <div style={{
              display: 'inline-block', fontSize: 10, fontFamily: FONTS.mono,
              padding: '2px 8px', borderRadius: 3,
              background: step.node.type === 'cred' ? '#0d1016' : '#101218',
              border: `1px solid ${step.node.type === 'cred' ? (step.node.cracked ? '#39d35344' : '#f09a3a44') : PALETTE.borderSoft}`,
              color: step.node.type === 'cred' ? (step.node.cracked ? '#39d353' : '#f09a3a') : PALETTE.text,
            }}>
              {step.node.type === 'cred' ? '🔑 ' : ''}{step.node.label}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
HowWeGotHere.propTypes = { chain: PropTypes.any };

export function WhatItOpens({ opens }) {
  if (!opens || opens.length === 0) return null;
  return (
    <div style={{ marginBottom: 12 }}>
      <div style={{ fontSize: 10, color: PALETTE.textGhost, marginBottom: 6, fontFamily: FONTS.mono, textTransform: 'uppercase' }}>Opens / leads to ({opens.length})</div>
      {opens.slice(0, 8).map(({ node, edge }) => (
        <div key={edge.id} style={{ display: 'flex', gap: 6, alignItems: 'center', padding: '3px 0', fontSize: 10, fontFamily: FONTS.mono }}>
          <span style={{ color: edge.kind === 'credential_use' ? '#39d353' : edge.kind === 'pivot' ? '#c07af0' : '#f09a3a' }}>→</span>
          <span style={{ color: PALETTE.text }}>{node.label}</span>
          <span style={{ color: PALETTE.textGhost, fontSize: 9 }}>{chainEdgeLabel(edge)}</span>
        </div>
      ))}
    </div>
  );
}
WhatItOpens.propTypes = { opens: PropTypes.any };

export function NodeSidePanel({ selectedNode, setSelectedNode, accent, privilegePaths, nodes, selectedNodeEdges, selectedNodeAccessEdges, selectedNodePivotEdges, linkedCreds, linkedFindings, pivotChains, chain, opens, onNavigate, onDelete }) {
  if (selectedNode.type === 'cred') {
    return (
      <CredSidePanel
        selectedNode={selectedNode}
        setSelectedNode={setSelectedNode}
        accent={accent}
        edges={selectedNodeEdges || []}
        nodes={nodes || []}
        onDelete={onDelete}
      />
    );
  }
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
        <button onClick={() => setSelectedNode(null)}
          style={{ background: 'none', border: 'none', cursor: 'pointer', color: PALETTE.textGhost, fontSize: 13, padding: 0 }}>✕</button>
      </div>
      <div style={{ flex: 1, overflowY: 'auto', padding: '14px 14px 10px' }}>
        <HowWeGotHere chain={chain} />
        <WhatItOpens opens={opens} />
        <NodeHostSection node={selectedNode} accent={accent} />
        {onNavigate && selectedNode.type !== 'cred' && !selectedNode.is_attacker && (
          <button onClick={() => onNavigate('network', selectedNode.id)} style={{ width: '100%', marginBottom: 10, background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '5px 10px', cursor: 'pointer', color: PALETTE.textFaint, fontSize: 10, fontFamily: FONTS.mono }}>
            Show on Network Map →
          </button>
        )}
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
      <div style={{ display: 'flex', gap: 6, marginTop: 10, padding: '0 14px 12px' }}>
        <button onClick={() => setSelectedNode(null)} style={{ flex: 1, background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '4px 12px', cursor: 'pointer', color: PALETTE.textFaint, fontSize: 10, fontFamily: FONTS.mono }}>Close</button>
        {onDelete && (
          <button onClick={() => { if (globalThis.confirm(`Delete host ${selectedNode.label}? It disappears from the graph immediately.`)) onDelete(selectedNode); }}
            style={{ flex: 1, background: '#cc223311', border: '1px solid #cc233344', borderRadius: 4, padding: '4px 12px', cursor: 'pointer', color: '#e8574a', fontSize: 10, fontFamily: FONTS.mono }}>Delete host</button>
        )}
      </div>
    </div>
  );
}
NodeSidePanel.propTypes = {
  selectedNode: PropTypes.any,
  setSelectedNode: PropTypes.func,
  accent: PropTypes.any,
  privilegePaths: PropTypes.any,
  nodes: PropTypes.any,
  selectedNodeEdges: PropTypes.array,
  selectedNodeAccessEdges: PropTypes.array,
  selectedNodePivotEdges: PropTypes.array,
  linkedCreds: PropTypes.array,
  linkedFindings: PropTypes.array,
  pivotChains: PropTypes.array,
  chain: PropTypes.any,
  opens: PropTypes.array,
  onNavigate: PropTypes.func,
  onDelete: PropTypes.func,
};

