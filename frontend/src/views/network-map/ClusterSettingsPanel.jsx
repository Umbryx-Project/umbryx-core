import { useState, useMemo } from 'react';
import PropTypes from 'prop-types';
import { defaultSettings, cycleZoneLock, AUTO_COLLAPSE_THRESHOLD, DEFAULT_COLLAPSE_ZOOM, DEFAULT_EXPAND_ZOOM } from './clustering.js';
import { PALETTE, FONTS, Select } from '../../components/UI.jsx';

const ZONE_COLORS = ['#5b8af5', '#f09a3a', '#cc2233', '#c07af0', '#39d353', '#e8cc42', '#e8574a', '#6fc8f0'];
const LOCK_LABELS = { collapsed: '\u25FC lock-collapsed', expanded: '\u25B2 lock-expanded' };
const LOCK_COLORS = { collapsed: PALETTE.danger, expanded: PALETTE.ok };

export function ClusterSettingsPanel({ open, onClose, settings, onChange, clusters, nodes, netId }) {
  const [newZoneName, setNewZoneName] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedZones, setExpandedZones] = useState(new Set());

  const nodeById = useMemo(() => new Map(nodes.map(n => [n.id, n])), [nodes]);

  if (!open) return null;

  const s = settings || defaultSettings();

  const toggleZoneExpand = (key) => {
    setExpandedZones(prev => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const updateSetting = (key, value) => {
    onChange({ ...s, [key]: value });
  };

  const createCustomZone = () => {
    if (!newZoneName.trim()) return;
    const zoneKey = `custom:${Date.now().toString(36)}`;
    const colorIdx = Object.keys(s.customZones || {}).length % ZONE_COLORS.length;
    const newZones = {
      ...(s.customZones || {}),
      [zoneKey]: { label: newZoneName.trim(), color: ZONE_COLORS[colorIdx], zoneType: 'custom' },
    };
    onChange({ ...s, customZones: newZones });
    setNewZoneName('');
    setExpandedZones(prev => new Set([...prev, zoneKey]));
  };

  const toggleZoneLock = (clusterKey) => {
    onChange({ ...s, zoneLocks: cycleZoneLock(s.zoneLocks, clusterKey) });
  };

  const renderLockButton = (clusterKey) => {
    const lock = s.zoneLocks?.[clusterKey];
    if (lock) {
      return (
        <button onClick={(e) => { e.stopPropagation(); toggleZoneLock(clusterKey); }}
          style={{ background: `${LOCK_COLORS[lock]}22`, border: `1px solid ${LOCK_COLORS[lock]}66`, borderRadius: 3, padding: '1px 5px', color: LOCK_COLORS[lock], cursor: 'pointer', fontSize: 8, fontFamily: FONTS.mono, whiteSpace: 'nowrap' }}
          title={lock === 'collapsed' ? 'Manually collapsed (click to expand-lock)' : 'Manually expanded (click to reset to auto)'}>
          {lock === 'collapsed' ? '\u25FC' : '\u25B2'}
        </button>
      );
    }
    return (
      <button onClick={(e) => { e.stopPropagation(); toggleZoneLock(clusterKey); }}
        style={{ background: 'none', border: `1px solid ${PALETTE.border}`, borderRadius: 3, padding: '1px 5px', color: PALETTE.textGhost, cursor: 'pointer', fontSize: 8, fontFamily: FONTS.mono }}
        title="Auto (click to lock collapsed)">
        auto
      </button>
    );
  };

  const deleteCustomZone = (zoneKey) => {
    const newZones = { ...(s.customZones || {}) };
    delete newZones[zoneKey];
    const newOverrides = { ...(s.zoneOverrides || {}) };
    for (const [nodeId, zk] of Object.entries(newOverrides)) {
      if (zk === zoneKey) delete newOverrides[nodeId];
    }
    onChange({ ...s, customZones: newZones, zoneOverrides: newOverrides });
  };

  const assignNodeToZone = (nodeId, zoneKey) => {
    const newOverrides = { ...(s.zoneOverrides || {}) };
    if (zoneKey) {
      newOverrides[nodeId] = zoneKey;
    } else {
      delete newOverrides[nodeId];
    }
    onChange({ ...s, zoneOverrides: newOverrides });
  };

  const removeNodeFromZone = (nodeId) => {
    const newOverrides = { ...(s.zoneOverrides || {}) };
    delete newOverrides[nodeId];
    onChange({ ...s, zoneOverrides: newOverrides });
  };

  const customZoneList = Object.entries(s.customZones || {});
  const autoClusters = clusters.filter(c => !c.isCustom);
  const customClusters = clusters.filter(c => c.isCustom);

  const filteredNodes = searchQuery
    ? nodes.filter(n => {
        const q = searchQuery.toLowerCase();
        return (n.label || '').toLowerCase().includes(q) || (n.ip || '').toLowerCase().includes(q);
      })
    : nodes;

  const panelStyle = {
    position: 'absolute',
    top: 48,
    right: 0,
    width: 360,
    maxHeight: 'calc(100% - 48px)',
    background: '#0a0c10',
    borderLeft: `1px solid ${PALETTE.borderSoft}`,
    borderBottom: `1px solid ${PALETTE.borderSoft}`,
    display: 'flex',
    flexDirection: 'column',
    zIndex: 50,
    overflow: 'hidden',
  };

  const sectionTitle = {
    fontSize: 9,
    color: PALETTE.textGhost,
    textTransform: 'uppercase',
    letterSpacing: 1,
    padding: '8px 14px 4px',
    fontFamily: FONTS.mono,
  };

  const inputStyle = {
    background: PALETTE.bg3,
    border: `1px solid ${PALETTE.border}`,
    borderRadius: 4,
    padding: '5px 8px',
    color: PALETTE.textDim,
    fontSize: 10,
    fontFamily: FONTS.mono,
    width: '100%',
  };

  return (
    <div style={panelStyle}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 14px', borderBottom: `1px solid ${PALETTE.borderSoft}` }}>
        <span style={{ fontSize: 11, color: PALETTE.textDim, fontFamily: FONTS.display, fontWeight: 700 }}>Cluster Zones</span>
        <button onClick={onClose} style={{ background: 'none', border: 'none', color: PALETTE.textFaint, cursor: 'pointer', fontSize: 14, padding: 0, lineHeight: 1 }}>{'\u00D7'}</button>
      </div>

      <div style={{ flex: 1, overflowY: 'auto' }}>
        {/* Settings section */}
        <div style={sectionTitle}>Auto-Collapse Settings</div>
        <div style={{ padding: '0 14px 8px', display: 'flex', flexDirection: 'column', gap: 8 }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
              <span style={{ fontSize: 9, color: PALETTE.textFaint, fontFamily: FONTS.mono }}>Node threshold</span>
              <span style={{ fontSize: 9, color: PALETTE.textMute, fontFamily: FONTS.mono }}>{s.collapseThreshold}</span>
            </div>
            <input type="range" min="5" max="200" step="5" value={s.collapseThreshold}
              onChange={e => updateSetting('collapseThreshold', parseInt(e.target.value))}
              style={{ width: '100%', accentColor: '#5b8af5' }} />
            <div style={{ fontSize: 8, color: PALETTE.textGhost, fontFamily: FONTS.mono }}>Clusters auto-collapse when node count exceeds this</div>
          </div>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
              <span style={{ fontSize: 9, color: PALETTE.textFaint, fontFamily: FONTS.mono }}>Collapse zoom level</span>
              <span style={{ fontSize: 9, color: PALETTE.textMute, fontFamily: FONTS.mono }}>{Math.round(s.collapseZoomLevel * 100)}%</span>
            </div>
            <input type="range" min="0.3" max="1.0" step="0.05" value={s.collapseZoomLevel}
              onChange={e => updateSetting('collapseZoomLevel', parseFloat(e.target.value))}
              style={{ width: '100%', accentColor: PALETTE.warn }} />
            <div style={{ fontSize: 8, color: PALETTE.textGhost, fontFamily: FONTS.mono }}>Collapse all when zoomed below this level</div>
          </div>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
              <span style={{ fontSize: 9, color: PALETTE.textFaint, fontFamily: FONTS.mono }}>Expand zoom level</span>
              <span style={{ fontSize: 9, color: PALETTE.textMute, fontFamily: FONTS.mono }}>{Math.round(s.expandZoomLevel * 100)}%</span>
            </div>
            <input type="range" min="0.3" max="2.0" step="0.05" value={s.expandZoomLevel}
              onChange={e => updateSetting('expandZoomLevel', parseFloat(e.target.value))}
              style={{ width: '100%', accentColor: PALETTE.ok }} />
            <div style={{ fontSize: 8, color: PALETTE.textGhost, fontFamily: FONTS.mono }}>Auto-expand all when zoomed above this level</div>
          </div>
          <button onClick={() => onChange(defaultSettings())} style={{ ...inputStyle, cursor: 'pointer', textAlign: 'center', color: PALETTE.textFaint, width: 'auto' }}>Reset to defaults</button>
        </div>

        {/* Custom zones */}
        <div style={sectionTitle}>Custom Zones</div>
        <div style={{ padding: '0 14px 8px', display: 'flex', gap: 6 }}>
          <input value={newZoneName} onChange={e => setNewZoneName(e.target.value)} placeholder="Zone name..."
            onKeyDown={e => { if (e.key === 'Enter') createCustomZone(); }}
            style={inputStyle} />
          <button onClick={createCustomZone} style={{ background: '#5b8af5', border: 'none', borderRadius: 4, padding: '0 10px', color: '#fff', cursor: 'pointer', fontSize: 10, fontFamily: FONTS.mono, whiteSpace: 'nowrap' }}>+ Add</button>
        </div>

        {/* Custom zone list */}
        {customClusters.length > 0 && (
          <div style={{ padding: '0 14px 4px' }}>
            {customClusters.map(cluster => {
              const cz = s.customZones?.[cluster.key] || {};
              const isExpanded = expandedZones.has(cluster.key);
              const members = cluster.nodeIds.map(id => nodeById.get(id)).filter(Boolean);
              const zoneColor = cz.color || '#5b8af5';
              return (
                <div key={cluster.key} style={{ marginBottom: 4, border: `1px solid ${zoneColor}33`, borderRadius: 4, overflow: 'hidden' }}>
                  <div style={{ display: 'flex', alignItems: 'center', padding: '6px 8px', background: `${zoneColor}11`, cursor: 'pointer' }}
                    onClick={() => toggleZoneExpand(cluster.key)}>
                    <span style={{ width: 8, height: 8, borderRadius: 2, background: zoneColor, marginRight: 8, flexShrink: 0 }} />
                    <span style={{ flex: 1, fontSize: 10, color: PALETTE.textDim, fontFamily: FONTS.mono }}>{cluster.label}</span>
                    {renderLockButton(cluster.key)}
                    <span style={{ fontSize: 9, color: PALETTE.textFaint, fontFamily: FONTS.mono, marginLeft: 6, marginRight: 6 }}>{members.length}</span>
                    <button onClick={(e) => { e.stopPropagation(); deleteCustomZone(cluster.key); }} style={{ background: 'none', border: 'none', color: PALETTE.danger, cursor: 'pointer', fontSize: 10, padding: 0 }}>{'\u00D7'}</button>
                  </div>
                  {isExpanded && (
                    <div style={{ padding: '4px 8px 6px' }}>
                      {members.length === 0 && <div style={{ fontSize: 9, color: PALETTE.textGhost, fontFamily: FONTS.mono, padding: '4px 0' }}>No members — assign nodes below</div>}
                      {members.map(node => (
                        <div key={node.id} style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '2px 0' }}>
                          <span style={{ width: 6, height: 6, borderRadius: '50%', background: _statusColor(node.status), flexShrink: 0 }} />
                          <span style={{ flex: 1, fontSize: 9, color: '#808590', fontFamily: FONTS.mono }}>{node.label || node.ip}</span>
                          <button onClick={() => removeNodeFromZone(node.id)} style={{ background: 'none', border: 'none', color: PALETTE.textGhost, cursor: 'pointer', fontSize: 9, padding: 0 }}>remove</button>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}

        {/* Auto-detected zones */}
        <div style={sectionTitle}>Auto-Detected Zones ({autoClusters.length})</div>
        <div style={{ padding: '0 14px 8px', maxHeight: 320, overflowY: 'auto' }}>
          {autoClusters.map(cluster => {
            const isExpanded = expandedZones.has(cluster.key);
            const memberNodes = cluster.nodeIds.map(id => nodeById.get(id)).filter(Boolean);
            return (
              <div key={cluster.key} style={{ marginBottom: 3 }}>
                <div style={{ display: 'flex', alignItems: 'center', padding: '5px 8px', background: PALETTE.bg3, borderRadius: 4, cursor: 'pointer', border: `1px solid ${PALETTE.borderSoft}` }}
                  onClick={() => toggleZoneExpand(cluster.key)}>
                  <span style={{ fontSize: 10, color: '#808590', fontFamily: FONTS.mono, flex: 1 }}>{cluster.label}</span>
                  {renderLockButton(cluster.key)}
                  <span style={{ fontSize: 9, color: PALETTE.textGhost, fontFamily: FONTS.mono, marginLeft: 6 }}>{cluster.nodeCount}</span>
                  <span style={{ marginLeft: 4, fontSize: 8, color: PALETTE.textGhost }}>{isExpanded ? '\u25BC' : '\u25B8'}</span>
                </div>
                {isExpanded && (
                  <div style={{ padding: '4px 8px' }}>
                    {memberNodes.slice(0, 20).map(node => {
                      const isOverridden = !!s.zoneOverrides?.[node.id];
                      return (
                        <div key={node.id} style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '2px 0' }}>
                          <span style={{ width: 6, height: 6, borderRadius: '50%', background: _statusColor(node.status), flexShrink: 0 }} />
                          <span style={{ flex: 1, fontSize: 9, color: isOverridden ? '#404550' : '#808590', fontFamily: FONTS.mono, textDecoration: isOverridden ? 'line-through' : 'none' }}>{node.label || node.ip}</span>
                          <Select value={s.zoneOverrides?.[node.id] || ''} onChange={v => assignNodeToZone(node.id, v || null)}
                            placeholder="auto"
                            options={customZoneList.map(([zk, zd]) => ({ value: zk, label: zd.label }))} />
                        </div>
                      );
                    })}
                    {memberNodes.length > 20 && <div style={{ fontSize: 8, color: PALETTE.textGhost, fontFamily: FONTS.mono, paddingTop: 2 }}>+{memberNodes.length - 20} more...</div>}
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* Node search + assign */}
        <div style={sectionTitle}>Assign Node to Zone</div>
        <div style={{ padding: '0 14px 12px' }}>
          <input value={searchQuery} onChange={e => setSearchQuery(e.target.value)} placeholder="Search by name or IP..."
            style={inputStyle} />
          {searchQuery && (
            <div style={{ marginTop: 4, maxHeight: 200, overflowY: 'auto' }}>
              {filteredNodes.slice(0, 30).map(node => (
                <div key={node.id} style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '3px 0' }}>
                  <span style={{ flex: 1, fontSize: 9, color: '#808590', fontFamily: FONTS.mono }}>{node.label || node.ip}</span>
                  <Select value={s.zoneOverrides?.[node.id] || ''} onChange={v => assignNodeToZone(node.id, v || null)}
                    placeholder={s.zoneOverrides?.[node.id] ? '\u00D7 remove' : 'auto'}
                    options={customZoneList.map(([zk, zd]) => ({ value: zk, label: zd.label }))} />
                </div>
              ))}
              {filteredNodes.length === 0 && <div style={{ fontSize: 9, color: PALETTE.textGhost, fontFamily: FONTS.mono }}>No nodes found</div>}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

ClusterSettingsPanel.propTypes = {
  open: PropTypes.bool,
  onClose: PropTypes.func,
  settings: PropTypes.object,
  onChange: PropTypes.func,
  clusters: PropTypes.array,
  nodes: PropTypes.array,
  netId: PropTypes.string,
};

function _statusColor(status) {
  const map = { up: PALETTE.ok, owned: '#e8574a', pwned: PALETTE.danger, access: PALETTE.warn, scanned: '#5b8af5', alive: PALETTE.ok, unknown: PALETTE.textGhost, failed: PALETTE.danger, error: PALETTE.danger, down: PALETTE.danger };
  return map[status] || '#404550';
}

export { _statusColor };
