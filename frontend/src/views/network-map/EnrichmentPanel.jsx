import { useCallback, useEffect, useMemo, useState } from 'react';
import PropTypes from 'prop-types';
import Icon from '../../components/Icon.jsx';
import { PALETTE, FONTS } from '../../components/UI.jsx';
import { api } from '../../api.js';

/**
 * Network Map enrichment overlay (GRAPH_MODEL_REFACTOR Step 6).
 *
 * Reads the canonical graph's *suggestions* (`/topology/graph/suggestions`) —
 * what the canonical model knows but the operator hasn't placed on the map —
 * and offers a one-click "add to map". It never overwrites the operator's
 * layout or intent: it only proposes, and every proposal carries provenance
 * (source / confidence / reason) so the operator can judge it.
 *
 * Three kinds of suggestion:
 *  - unplaced **hosts** — a project host with no map node yet
 *  - undrawn **links**  — a canonical relationship (pivot / explicit link /
 *    inferred rule edge) between two placed hosts the map doesn't show
 *  - inferred **groups** — subnet / domain groupings (add as a labelled region)
 */

const CONF_COLOR = (c) => (c >= 0.85 ? '#4ade80' : c >= 0.6 ? '#facc15' : '#fb923c');

function SectionHeader({ title, count, open, onToggle, accent }) {
  return (
    <button
      type="button"
      onClick={onToggle}
      style={{
        display: 'flex', alignItems: 'center', gap: 8, width: '100%', textAlign: 'left',
        padding: '7px 14px', background: '#0e1016', border: 'none', borderBottom: '1px solid #1e2029',
        cursor: 'pointer', color: '#e0e4ec', font: 'inherit',
      }}
    >
      <Icon name="chevron" size={11} color="#606570" style={{ transform: open ? 'rotate(90deg)' : 'none' }} />
      <span style={{ fontSize: 10, fontWeight: 600, fontFamily: FONTS.display, flex: 1 }}>{title}</span>
      <span style={{ fontSize: 9, fontFamily: FONTS.mono, color: count ? accent : PALETTE.textGhost }}>{count}</span>
    </button>
  );
}
SectionHeader.propTypes = {
  title: PropTypes.string, count: PropTypes.number, open: PropTypes.bool,
  onToggle: PropTypes.func, accent: PropTypes.string,
};

function ProvBadge({ source, confidence, reason }) {
  const conf = typeof confidence === 'number' ? confidence : 1;
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontFamily: FONTS.mono, fontSize: 8.5 }}>
      <span style={{ color: PALETTE.textGhost }} title={reason || source}>{source || 'graph'}</span>
      <span style={{ width: 26, height: 4, background: '#1e2029', borderRadius: 2, overflow: 'hidden', display: 'inline-block' }}>
        <span style={{ display: 'block', height: '100%', width: `${Math.round(conf * 100)}%`, background: CONF_COLOR(conf) }} />
      </span>
      <span style={{ color: CONF_COLOR(conf) }}>{conf.toFixed(2)}</span>
    </span>
  );
}
ProvBadge.propTypes = { source: PropTypes.string, confidence: PropTypes.number, reason: PropTypes.string };

export default function EnrichmentPanel({ projectId, nodes, accent, onAddHosts, onAddEdge, onAddGroup, onClose }) {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [sug, setSug] = useState({ nodes: [], edges: [] });
  const [busy, setBusy] = useState(new Set());
  const [open, setOpen] = useState({ hosts: true, links: true, groups: false });

  const load = useCallback(() => {
    setLoading(true);
    setError('');
    api.getMapSuggestions(projectId, true)
      .then((s) => setSug({ nodes: s.nodes || [], edges: s.edges || [] }))
      .catch(() => setError('Could not load suggestions'))
      .finally(() => setLoading(false));
  }, [projectId]);

  useEffect(() => { load(); }, [load]);

  // host_id -> placed map node id (for resolving/showing edges)
  const placedByHostId = useMemo(() => {
    const m = new Map();
    (nodes || []).forEach((n) => { if (n.host_id) m.set(String(n.host_id), n); });
    return m;
  }, [nodes]);

  const hostNodes = useMemo(() => sug.nodes.filter((n) => n.type === 'host'), [sug.nodes]);
  const groupNodes = useMemo(() => sug.nodes.filter((n) => n.type === 'subnet' || n.type === 'domain'), [sug.nodes]);

  // Link suggestions = host<->host edges where both endpoints are already placed
  // (an edge touching an unplaced host or a grouping node is represented by that
  // node's own suggestion; adding the node then re-surfaces the edge).
  const linkEdges = useMemo(() => sug.edges.filter((e) => {
    if (!e.src_uid.startsWith('host:') || !e.dst_uid.startsWith('host:')) return false;
    const a = e.src_uid.slice(5); const b = e.dst_uid.slice(5);
    return placedByHostId.has(a) && placedByHostId.has(b);
  }), [sug.edges, placedByHostId]);

  const total = hostNodes.length + linkEdges.length + groupNodes.length;

  const mark = (key, on) => setBusy((prev) => {
    const next = new Set(prev);
    on ? next.add(key) : next.delete(key);
    return next;
  });

  const doAddHost = async (n) => {
    mark(n.uid, true);
    try { await onAddHosts?.([n.id]); load(); } finally { mark(n.uid, false); }
  };
  const doAddAllHosts = async () => {
    if (!hostNodes.length) return;
    mark('__hosts__', true);
    try { await onAddHosts?.(hostNodes.map((n) => n.id)); load(); } finally { mark('__hosts__', false); }
  };
  const doAddEdge = async (e) => {
    const key = `${e.src_uid}->${e.dst_uid}`;
    mark(key, true);
    try {
      await onAddEdge?.({
        from_host_id: e.src_uid.slice(5),
        to_host_id: e.dst_uid.slice(5),
        type: e.type, source: e.source, confidence: e.confidence,
        reason: e.reason || '', label: e.reason || e.type,
      });
      load();
    } finally { mark(key, false); }
  };
  const doAddGroup = async (n) => {
    mark(n.uid, true);
    try {
      const memberHostIds = sug.edges
        .filter((e) => e.dst_uid === n.uid && e.src_uid.startsWith('host:'))
        .map((e) => e.src_uid.slice(5));
      await onAddGroup?.({ type: n.type, label: n.label || n.id, memberHostIds });
      load();
    } finally { mark(n.uid, false); }
  };

  const labelForUid = (uid) => {
    const hid = uid.slice(5);
    const placed = placedByHostId.get(hid);
    return placed?.label || placed?.ip || hid;
  };

  return (
    <div style={{ background: '#0c0e13', borderBottom: `1px solid ${PALETTE.border}`, flexShrink: 0, maxHeight: 340, display: 'flex', flexDirection: 'column' }}>
      <div style={{ padding: '8px 14px', borderBottom: '1px solid #1e2029', display: 'flex', alignItems: 'center', gap: 8 }}>
        <Icon name="graph" size={12} color={accent} />
        <span style={{ fontSize: 10, fontWeight: 600, color: '#e0e4ec', fontFamily: FONTS.display, flex: 1 }}>
          Enrich from graph{!loading && total ? ` (${total})` : ''}
        </span>
        <button onClick={load} title="Refresh" style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 3, padding: '2px 6px', cursor: 'pointer', color: PALETTE.textFaint, display: 'flex' }}>
          <Icon name="reset" size={11} color="#808590" />
        </button>
        <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', display: 'flex' }}><Icon name="close" size={12} color="#606570" /></button>
      </div>

      {loading ? (
        <div style={{ padding: 20, textAlign: 'center', color: PALETTE.textGhost, fontSize: 10, fontFamily: FONTS.mono }}>Loading suggestions…</div>
      ) : error ? (
        <div style={{ padding: 20, textAlign: 'center', color: '#fb923c', fontSize: 10, fontFamily: FONTS.mono }}>{error}</div>
      ) : total === 0 ? (
        <div style={{ padding: 20, textAlign: 'center', color: PALETTE.textGhost, fontSize: 10, fontFamily: FONTS.mono }}>Map is in sync with the graph — nothing to add.</div>
      ) : (
        <div style={{ overflowY: 'auto', flex: 1 }}>
          {/* Unplaced hosts */}
          <SectionHeader title="Unplaced hosts" count={hostNodes.length} open={open.hosts} onToggle={() => setOpen((o) => ({ ...o, hosts: !o.hosts }))} accent={accent} />
          {open.hosts && hostNodes.length > 0 && (
            <div>
              <div style={{ padding: '4px 14px', borderBottom: '1px solid #14161c' }}>
                <button onClick={doAddAllHosts} disabled={busy.has('__hosts__')} style={{ background: accent, border: 'none', borderRadius: 3, padding: '3px 10px', cursor: 'pointer', color: '#fff', fontSize: 9, fontWeight: 600, fontFamily: FONTS.mono, opacity: busy.has('__hosts__') ? 0.5 : 1 }}>Add all ({hostNodes.length})</button>
              </div>
              {hostNodes.map((n) => (
                <div key={n.uid} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '5px 14px', borderBottom: '1px solid #14161c' }}>
                  <span style={{ fontFamily: FONTS.mono, fontSize: 11, color: PALETTE.textMute, width: 120 }}>{n.attrs?.ip || '-'}</span>
                  <span style={{ fontSize: 10, color: PALETTE.textDim, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{n.label}</span>
                  <button onClick={() => doAddHost(n)} disabled={busy.has(n.uid)} style={{ background: 'transparent', border: `1px solid ${accent}66`, borderRadius: 3, padding: '2px 8px', cursor: 'pointer', color: accent, fontSize: 9, fontFamily: FONTS.mono, opacity: busy.has(n.uid) ? 0.5 : 1 }}>Add</button>
                </div>
              ))}
            </div>
          )}

          {/* Undrawn links between placed hosts */}
          <SectionHeader title="Suggested links" count={linkEdges.length} open={open.links} onToggle={() => setOpen((o) => ({ ...o, links: !o.links }))} accent={accent} />
          {open.links && linkEdges.length > 0 && (
            <div>
              {linkEdges.map((e) => {
                const key = `${e.src_uid}->${e.dst_uid}`;
                return (
                  <div key={key} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '5px 14px', borderBottom: '1px solid #14161c' }}>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontSize: 10, color: PALETTE.textDim, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {labelForUid(e.src_uid)} <span style={{ color: accent, fontFamily: FONTS.mono }}>—{e.type}→</span> {labelForUid(e.dst_uid)}
                      </div>
                      <ProvBadge source={e.source} confidence={e.confidence} reason={e.reason} />
                    </div>
                    <button onClick={() => doAddEdge(e)} disabled={busy.has(key)} style={{ background: 'transparent', border: `1px solid ${accent}66`, borderRadius: 3, padding: '2px 8px', cursor: 'pointer', color: accent, fontSize: 9, fontFamily: FONTS.mono, opacity: busy.has(key) ? 0.5 : 1 }}>Add</button>
                  </div>
                );
              })}
            </div>
          )}

          {/* Inferred groupings */}
          <SectionHeader title="Inferred groups" count={groupNodes.length} open={open.groups} onToggle={() => setOpen((o) => ({ ...o, groups: !o.groups }))} accent={accent} />
          {open.groups && groupNodes.length > 0 && (
            <div>
              {groupNodes.map((n) => {
                const members = sug.edges.filter((e) => e.dst_uid === n.uid).length;
                return (
                  <div key={n.uid} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '5px 14px', borderBottom: '1px solid #14161c' }}>
                    <span style={{ fontSize: 8, fontFamily: FONTS.mono, textTransform: 'uppercase', color: PALETTE.textGhost, border: '1px solid #24262f', borderRadius: 2, padding: '1px 4px' }}>{n.type}</span>
                    <span style={{ fontSize: 10, color: PALETTE.textDim, flex: 1, fontFamily: FONTS.mono, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{n.label}</span>
                    <span style={{ fontSize: 9, color: PALETTE.textGhost, fontFamily: FONTS.mono }}>{members} hosts</span>
                    <button onClick={() => doAddGroup(n)} disabled={busy.has(n.uid)} style={{ background: 'transparent', border: `1px solid ${accent}66`, borderRadius: 3, padding: '2px 8px', cursor: 'pointer', color: accent, fontSize: 9, fontFamily: FONTS.mono, opacity: busy.has(n.uid) ? 0.5 : 1 }}>Add region</button>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

EnrichmentPanel.propTypes = {
  projectId: PropTypes.string,
  nodes: PropTypes.array,
  accent: PropTypes.string,
  onAddHosts: PropTypes.func,
  onAddEdge: PropTypes.func,
  onAddGroup: PropTypes.func,
  onClose: PropTypes.func,
};
