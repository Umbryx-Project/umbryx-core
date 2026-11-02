import { useState, useEffect, useCallback, useMemo } from 'react';
import PropTypes from 'prop-types';
import Icon from '../components/Icon.jsx';
import { api } from '../api.js';
import { toastError, toastSuccess } from '../components/Toast.jsx';
import { PALETTE, FONTS } from '../components/UI.jsx';
import { uiAlert } from '../components/Confirm.jsx';

// Cap initial DOM render. Long engagements have thousands of events;
// dumping all of them blows React reconciliation budgets and freezes
// the tab. User clicks "show older" to expand in chunks of the same
// size. The backend pagination shipped in feature/perf-pagination can
// take over later; this is the cheap DOM-side cap.
const VISIBLE_PAGE = 500;

const ENTITY_META = {
  note:    { icon: 'notes',   color: '#5b8af5', label: 'Note' },
  host:    { icon: 'hosts',   color: '#c07af0', label: 'Host' },
  cred:    { icon: 'person',  color: PALETTE.ok, label: 'Cred' },
  finding: { icon: 'bug',     color: '#e8574a', label: 'Finding' },
  // Audit events surface what privileged operators did with secrets;
  // visually distinct from data-mutation events so an analyst can find
  // them quickly when investigating insider-abuse scenarios.
  audit:   { icon: 'shield',  color: PALETTE.warn, label: 'Audit' },
};

const ACTION_META = {
  create: { icon: 'plus',    color: PALETTE.ok, label: 'Created' },
  update: { icon: 'edit',    color: '#5b8af5', label: 'Updated' },
  delete: { icon: 'trash',   color: PALETTE.danger, label: 'Deleted' },
  status: { icon: 'target',  color: PALETTE.warn, label: 'Status' },
  // Audit-specific actions — see backend log_event call sites.
  read_credential_secrets: { icon: 'eye',    color: PALETTE.warn, label: 'Secrets viewed' },
  secret_used_bulk_exec:   { icon: 'bolt',   color: PALETTE.warn, label: 'Secret → bulk exec' },
  secret_used_validate:    { icon: 'bolt',   color: PALETTE.warn, label: 'Secret → validate' },
  secret_used_c2_exec:     { icon: 'bolt',   color: PALETTE.warn, label: 'Secret → C2 exec' },
  export_with_secrets:     { icon: 'export', color: '#e8574a', label: 'Export with secrets' },
  webhook_token_regenerated: { icon: 'reset', color: '#5b8af5', label: 'Webhook token rotated' },
};

// Per-action highlight keys: which meta entries to show inline as chips.
// Falls back to a generic "key=value" rendering for anything not listed.
const AUDIT_HIGHLIGHTS = {
  read_credential_secrets: ['count', 'host_id'],
  secret_used_bulk_exec:   ['username', 'host_count'],
  secret_used_validate:    ['username', 'host_count'],
  secret_used_c2_exec:     ['c2_type', 'username', 'agent_id'],
  export_with_secrets:     ['cred_count'],
  webhook_token_regenerated: [],
};

function userColor(name) {
  if (!name) return '#404550';
  let h = 0;
  for (const ch of name) h = (h * 31 + ch.codePointAt(0)) & 0xffffff;
  return `hsl(${h % 360}, 55%, 52%)`;
}

function groupByDate(events) {
  const groups = {};
  for (const e of events) {
    const date = (e.ts || '').slice(0, 10) || 'Unknown';
    if (!groups[date]) groups[date] = [];
    groups[date].push(e);
  }
  return Object.entries(groups).sort((a, b) => b[0].localeCompare(a[0]));
}

const ALL_GROUPS = ['notes', 'findings', 'hosts', 'graph'];
const GROUP_COLORS = { notes: '#5b8af5', findings: '#e8574a', hosts: '#c07af0', graph: PALETTE.ok };

function SnapshotPanel({ pid, accent }) {
  const [snapshots, setSnapshots] = useState([]);
  const [open, setOpen] = useState(false);
  const [creating, setCreating] = useState(false);
  const [label, setLabel] = useState('');
  const [selGroups, setSelGroups] = useState(new Set(ALL_GROUPS));
  const [applyId, setApplyId] = useState(null);
  const [applyGroups, setApplyGroups] = useState(new Set());
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try { setSnapshots(await api.listSnapshots(pid)); } catch (e) { toastError(e.message); }
  }, [pid]);

  useEffect(() => { if (open) load(); }, [open, load]);

  const handleCreate = async () => {
    setBusy(true);
    try {
      await api.createSnapshot(pid, { label: label.trim() || undefined, groups: [...selGroups] });
      toastSuccess('Snapshot created');
      setLabel('');
      setCreating(false);
      load();
    } catch (e) { toastError(e.message); }
    setBusy(false);
  };

  const handleDelete = async (sid) => {
    try { await api.deleteSnapshot(pid, sid); load(); } catch (e) { toastError(e.message); }
  };

  const handleApply = async () => {
    setBusy(true);
    try {
      const res = await api.applySnapshot(pid, applyId, { groups: [...applyGroups] });
      toastSuccess(`Applied: ${Object.entries(res.counts || {}).map(([k, v]) => `${v} ${k}`).join(', ')}`);
      setApplyId(null);
    } catch (e) { toastError(e.message); }
    setBusy(false);
  };

  const inp = { background: '#0a0c10', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '5px 8px', color: PALETTE.textDim, fontSize: 11, fontFamily: FONTS.mono, outline: 'none' };

  return (
    <div style={{ position: 'relative' }}>
      <button onClick={() => setOpen(v => !v)} style={{ background: open ? accent + '22' : 'none', border: `1px solid ${open ? accent : PALETTE.border}`, borderRadius: 4, padding: '4px 10px', cursor: 'pointer', fontSize: 10, fontFamily: FONTS.mono, color: open ? accent : PALETTE.textFaint, display: 'flex', alignItems: 'center', gap: 4 }}>
        <Icon name="target" size={11} color="currentColor" /> Snapshots
      </button>
      {open && (
        <div style={{ position: 'absolute', right: 0, top: 32, zIndex: 300, background: '#0f1117', border: `1px solid ${PALETTE.border}`, borderRadius: 8, padding: 14, width: 340, boxShadow: '0 8px 32px #00000088' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
            <span style={{ fontSize: 11, color: PALETTE.textDim, fontFamily: FONTS.mono, fontWeight: 600 }}>Project Snapshots</span>
            {!creating && <button onClick={() => setCreating(true)} style={{ fontSize: 9, background: accent, border: 'none', borderRadius: 3, padding: '2px 8px', color: '#fff', cursor: 'pointer', fontFamily: FONTS.mono }}>+ New</button>}
          </div>

          {creating && (
            <div style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 6, padding: 10, marginBottom: 10 }}>
              <input value={label} onChange={e => setLabel(e.target.value)} placeholder="Label (optional)" style={{ ...inp, width: '100%', boxSizing: 'border-box', marginBottom: 8 }} />
              <div style={{ fontSize: 9, color: PALETTE.textGhost, marginBottom: 6, fontFamily: FONTS.mono }}>Groups to capture:</div>
              <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap', marginBottom: 8 }}>
                {ALL_GROUPS.map(g => {
                  const on = selGroups.has(g);
                  const c = GROUP_COLORS[g];
                  return <button key={g} onClick={() => setSelGroups(prev => { const n = new Set(prev); on ? n.delete(g) : n.add(g); return n; })} style={{ fontSize: 9, background: on ? c + '22' : 'transparent', border: `1px solid ${on ? c : PALETTE.border}`, borderRadius: 3, padding: '2px 8px', cursor: 'pointer', color: on ? c : '#505560', fontFamily: FONTS.mono }}>{g}</button>;
                })}
              </div>
              <div style={{ display: 'flex', gap: 6 }}>
                <button onClick={handleCreate} disabled={busy || selGroups.size === 0} style={{ flex: 1, background: accent, border: 'none', borderRadius: 3, padding: '4px 0', color: '#fff', fontSize: 10, fontFamily: FONTS.mono, cursor: 'pointer' }}>{busy ? '…' : 'Create'}</button>
                <button onClick={() => setCreating(false)} style={{ background: 'none', border: `1px solid ${PALETTE.border}`, borderRadius: 3, padding: '4px 10px', color: '#505560', fontSize: 10, fontFamily: FONTS.mono, cursor: 'pointer' }}>Cancel</button>
              </div>
            </div>
          )}

          {snapshots.length === 0 && !creating && <div style={{ fontSize: 10, color: PALETTE.textGhost, fontFamily: FONTS.mono, padding: '8px 0' }}>No snapshots yet.</div>}

          {snapshots.map(s => (
            <div key={s.id} style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 5, padding: '8px 10px', marginBottom: 6 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div>
                  <div style={{ fontSize: 11, color: PALETTE.textDim, fontFamily: FONTS.mono, fontWeight: 600 }}>{s.label}</div>
                  <div style={{ fontSize: 9, color: '#505560', fontFamily: FONTS.mono, marginTop: 2 }}>{s.created_at?.slice(0, 16)} · {s.created_by}</div>
                  <div style={{ display: 'flex', gap: 3, marginTop: 4 }}>
                    {(s.groups || []).map(g => <span key={g} style={{ fontSize: 8, color: GROUP_COLORS[g], background: GROUP_COLORS[g] + '18', border: `1px solid ${GROUP_COLORS[g]}33`, borderRadius: 3, padding: '1px 5px', fontFamily: FONTS.mono }}>{g}</span>)}
                  </div>
                </div>
                <div style={{ display: 'flex', gap: 4 }}>
                  <button onClick={() => { setApplyId(s.id); setApplyGroups(new Set(s.groups)); }} style={{ fontSize: 9, background: '#39d35318', border: '1px solid #39d35344', borderRadius: 3, padding: '2px 6px', color: PALETTE.ok, cursor: 'pointer', fontFamily: FONTS.mono }}>Apply</button>
                  <button onClick={() => handleDelete(s.id)} style={{ background: 'none', border: '1px solid #cc223344', borderRadius: 3, padding: '2px 5px', color: PALETTE.danger, cursor: 'pointer', fontSize: 9, fontFamily: FONTS.mono }}>✕</button>
                </div>
              </div>
              {applyId === s.id && (
                <div style={{ marginTop: 8, paddingTop: 8, borderTop: '1px solid #1e2029' }}>
                  <div style={{ fontSize: 9, color: PALETTE.textGhost, marginBottom: 5, fontFamily: FONTS.mono }}>Select groups to restore:</div>
                  <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginBottom: 6 }}>
                    {(s.groups || []).map(g => {
                      const on = applyGroups.has(g); const c = GROUP_COLORS[g];
                      return <button key={g} onClick={() => setApplyGroups(prev => { const n = new Set(prev); on ? n.delete(g) : n.add(g); return n; })} style={{ fontSize: 9, background: on ? c + '22' : 'transparent', border: `1px solid ${on ? c : PALETTE.border}`, borderRadius: 3, padding: '2px 8px', cursor: 'pointer', color: on ? c : '#505560', fontFamily: FONTS.mono }}>{g}</button>;
                    })}
                  </div>
                  <div style={{ display: 'flex', gap: 5 }}>
                    <button onClick={handleApply} disabled={busy || applyGroups.size === 0} style={{ flex: 1, background: '#39d35322', border: '1px solid #39d35366', borderRadius: 3, padding: '3px 0', color: PALETTE.ok, fontSize: 9, fontFamily: FONTS.mono, cursor: 'pointer' }}>{busy ? '…' : '↩ Restore'}</button>
                    <button onClick={() => setApplyId(null)} style={{ background: 'none', border: `1px solid ${PALETTE.border}`, borderRadius: 3, padding: '3px 8px', color: '#505560', fontSize: 9, fontFamily: FONTS.mono, cursor: 'pointer' }}>Cancel</button>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
SnapshotPanel.propTypes = { pid: PropTypes.string, accent: PropTypes.string };

export default function TimelineView({ selectedProject, accent }) {
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(false);
  const [filterEntity, setFilterEntity] = useState(null);
  const [expanded, setExpanded] = useState(new Set());
  const [undoingId, setUndoingId] = useState(null);
  const [visibleCount, setVisibleCount] = useState(VISIBLE_PAGE);

  const doUndo = useCallback(async (eventId) => {
    if (!eventId) return;
    setUndoingId(eventId);
    try {
      await api.undoTimelineEvent(eventId);
      setEvents(prev => prev.map(async e => e.id === eventId
        ? { ...e, meta: { ...e.meta, undone_at: new Date().toISOString().slice(0, 19).replace('T', ' ') } }
        : e));
    } catch (e) {
      await uiAlert(e.message || 'Undo failed');
    } finally {
      setUndoingId(null);
    }
  }, []);

  const toggleExpand = (id) => setExpanded(prev => {
    const next = new Set(prev);
    next.has(id) ? next.delete(id) : next.add(id);
    return next;
  });

  const load = useCallback(async () => {
    if (!selectedProject) return;
    setLoading(true);
    try {
      const data = await api.getTimeline(selectedProject, filterEntity);
      setEvents(data);
    } catch (e) { toastError(e.message); }
    setLoading(false);
  }, [selectedProject, filterEntity]);

  useEffect(() => { load(); }, [load]);

  // Memoise: filterEntity / events change → re-filter. Expanding a
  // single event, undo state, etc. don't need to refilter the whole
  // list. The cap is applied AFTER filtering so a narrow entity-filter
  // still loads up to VISIBLE_PAGE matching events.
  const filtered = useMemo(
    () => (filterEntity ? events.filter(e => e.entity === filterEntity) : events),
    [events, filterEntity],
  );
  const visible = useMemo(() => filtered.slice(0, visibleCount), [filtered, visibleCount]);
  const groups = useMemo(() => groupByDate(visible), [visible]);
  const hasMore = filtered.length > visible.length;

  // Reset the visible window when the active filter changes — otherwise
  // a previously-expanded "show more" carries over to the new filter
  // and you can't tell whether you're seeing the full filtered set.
  useEffect(() => { setVisibleCount(VISIBLE_PAGE); }, [filterEntity]);

  const entityCounts = useMemo(() => {
    const c = {};
    for (const e of events) c[e.entity] = (c[e.entity] || 0) + 1;
    return c;
  }, [events]);

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      {/* Toolbar */}
      <div style={{ padding: '12px 24px', borderBottom: `1px solid ${PALETTE.borderSoft}`, background: '#0a0c10', display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
        <span style={{ fontSize: 13, fontWeight: 600, color: '#e0e4ec', fontFamily: FONTS.display, marginRight: 4 }}>Event feed</span>
        <div style={{ display: 'flex', gap: 5, flex: 1 }}>
          {Object.entries(ENTITY_META).map(([key, meta]) => {
            const cnt = entityCounts[key] || 0;
            const act = filterEntity == key;
            return (
              <button key={key} onClick={() => setFilterEntity(act ? null : key)}
                style={{ background: act ? meta.color + '22' : 'transparent', border: `1px solid ${act ? meta.color : PALETTE.border}`, borderRadius: 4, padding: '4px 10px', cursor: 'pointer', fontSize: 10, fontFamily: FONTS.mono, color: act ? meta.color : PALETTE.textFaint, display: 'flex', alignItems: 'center', gap: 5 }}>
                <Icon name={meta.icon} size={10} color={act ? meta.color : PALETTE.textFaint} />
                {meta.label} {cnt > 0 && <span style={{ fontSize: 9, color: act ? meta.color : PALETTE.textGhost }}>{cnt}</span>}
              </button>
            );
          })}
        </div>
        <button onClick={load}
          style={{ background: 'none', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '4px 10px', cursor: 'pointer', fontSize: 10, fontFamily: FONTS.mono, color: PALETTE.textFaint, display: 'flex', alignItems: 'center', gap: 4 }}>
          <Icon name="reset" size={11} color="#606570" /> Refresh
        </button>
        <SnapshotPanel pid={selectedProject} accent={accent} />
        <span style={{ fontSize: 10, color: PALETTE.textGhost, fontFamily: FONTS.mono }}>
          {hasMore ? `${visible.length} of ${filtered.length} events` : `${filtered.length} events`}
        </span>
      </div>

      {/* Events */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '0 24px 24px' }}>
        {loading && <div style={{ padding: 30, textAlign: 'center', color: PALETTE.textGhost, fontSize: 11 }}>Loading...</div>}
        {!loading && filtered.length === 0 && (
          <div style={{ padding: '60px 0', textAlign: 'center', color: '#303540', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12 }}>
            <Icon name="clock" size={40} color="#2a2d35" />
            <div style={{ fontSize: 13 }}>No events</div>
            <div style={{ fontSize: 11, color: '#252830' }}>Events will appear as you work on the project</div>
          </div>
        )}
        {groups.map(([date, evts]) => (
          <div key={date}>
            <div style={{ padding: '16px 0 8px', position: 'sticky', top: 0, background: PALETTE.bg0, zIndex: 1 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <div style={{ height: 1, background: PALETTE.borderSoft, flex: 1 }} />
                <span style={{ fontSize: 10, color: PALETTE.textGhost, fontFamily: FONTS.mono, padding: '2px 10px', background: PALETTE.bg2, border: '1px solid #1e2029', borderRadius: 10 }}>
                  {date === new Date().toISOString().slice(0, 10) ? 'Today' : date}
                </span>
                <div style={{ height: 1, background: PALETTE.borderSoft, flex: 1 }} />
              </div>
            </div>
            {evts.map(evt => {
              const em = ENTITY_META[evt.entity] || { icon: 'notes', color: '#808590', label: evt.entity };
              const am = ACTION_META[evt.action] || { icon: 'bolt', color: '#808590' };
              const uc = userColor(evt.username);
              const time = (evt.ts || '').slice(11, 16);
              const isAudit = evt.entity === 'audit';
              const meta = evt.meta || {};
              const highlightKeys = AUDIT_HIGHLIGHTS[evt.action];
              const inlineChips = isAudit && highlightKeys
                ? highlightKeys
                    .filter(k => meta[k] !== undefined && meta[k] !== null && meta[k] !== '')
                    .map(k => ({ key: k, value: String(meta[k]) }))
                : [];
              const hasRawMeta = isAudit && Object.keys(meta).length > 0;
              const isExpanded = expanded.has(evt.id);
              const canUndo = !!meta.reversible && !meta.undone_at;
              const undoneByStr = meta.undone_by ? `by ${meta.undone_by}` : '';
              const undoneAtStr = (meta.undone_at || '').slice(11, 16);
              const undoLabel = meta.undone_at
                ? `Undone ${undoneByStr} ${undoneAtStr}`.trim()
                : null;
              const undoOpsCount = meta.undo?.type === 'batch' ? (meta.undo.operations?.length || 0) : 0;
              const undoButtonLabel = undoOpsCount > 0 ? `↶ Undo bulk (${undoOpsCount})` : '↶ Undo';
              return (
                <div key={evt.id} style={{ display: 'flex', gap: 12, padding: '8px 0', borderBottom: `1px solid ${PALETTE.bg3}`, background: isAudit ? '#10100808' : 'transparent' }}>
                  {/* Entity icon */}
                  <div style={{ width: 32, height: 32, borderRadius: 8, background: em.color + '18', border: `1px solid ${em.color}33`, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                    <Icon name={em.icon} size={14} color={em.color} />
                  </div>
                  {/* Content */}
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 2, flexWrap: 'wrap' }}>
                      <span style={{ fontSize: 9, color: am.color, fontWeight: 700, fontFamily: FONTS.mono, textTransform: 'uppercase', background: am.color + '18', padding: '1px 5px', borderRadius: 3 }}>{am.label || evt.action}</span>
                      <span style={{ fontSize: 9, color: PALETTE.textGhost, fontFamily: FONTS.mono }}>{em.label}</span>
                    </div>
                    <div style={{ fontSize: 12, color: '#b0b5c2', lineHeight: 1.4 }}>{evt.label}</div>
                    {/* Audit highlight chips */}
                    {inlineChips.length > 0 && (
                      <div style={{ display: 'flex', gap: 5, marginTop: 5, flexWrap: 'wrap' }}>
                        {inlineChips.map(({ key, value }) => (
                          <span key={key} style={{ fontSize: 9, fontFamily: FONTS.mono, color: '#909098', background: PALETTE.bg2, border: '1px solid #1e2029', borderRadius: 3, padding: '1px 6px' }}>
                            <span style={{ color: '#505560' }}>{key}=</span>{value}
                          </span>
                        ))}
                        {hasRawMeta && (
                          <button onClick={() => toggleExpand(evt.id)}
                            style={{ fontSize: 9, fontFamily: FONTS.mono, color: PALETTE.textFaint, background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 3, padding: '1px 6px', cursor: 'pointer' }}>
                            {isExpanded ? '− raw' : '+ raw'}
                          </button>
                        )}
                      </div>
                    )}
                    {/* Expanded raw meta JSON */}
                    {isAudit && isExpanded && (
                      <pre style={{ fontSize: 10, fontFamily: FONTS.mono, color: '#808590', background: '#07080b', border: `1px solid ${PALETTE.borderSoft}`, borderRadius: 4, padding: '6px 10px', marginTop: 6, overflowX: 'auto', whiteSpace: 'pre-wrap' }}>
                        {JSON.stringify(meta, null, 2)}
                      </pre>
                    )}
                  </div>
                  {/* Right side */}
                  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 4, flexShrink: 0 }}>
                    <span style={{ fontSize: 10, color: '#303540', fontFamily: FONTS.mono }}>{time}</span>
                    {canUndo && (
                      <button
                        onClick={() => doUndo(evt.id)}
                        disabled={undoingId === evt.id}
                        title="Revert this change"
                        style={{ fontSize: 9, fontFamily: FONTS.mono, color: PALETTE.warn, background: '#f09a3a18', border: '1px solid #f09a3a44', borderRadius: 3, padding: '1px 7px', cursor: undoingId === evt.id ? 'wait' : 'pointer', opacity: undoingId === evt.id ? 0.5 : 1 }}
                      >
                        {undoingId === evt.id ? '...' : undoButtonLabel}
                      </button>
                    )}
                    {undoLabel && (
                      <span title={undoLabel} style={{ fontSize: 9, color: PALETTE.textFaint, fontFamily: FONTS.mono }}>↶ undone</span>
                    )}
                    {evt.username && (
                      <span title={evt.username} style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                        <span style={{ fontSize: 10, fontWeight: 600, color: uc, fontFamily: FONTS.mono, whiteSpace: 'nowrap' }}>{evt.username}</span>
                        <span style={{ width: 20, height: 20, borderRadius: '50%', background: uc + '22', border: `1px solid ${uc}55`, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 8, fontWeight: 700, color: uc, fontFamily: FONTS.mono, flexShrink: 0 }}>
                          {evt.username.slice(0, 2).toUpperCase()}
                        </span>
                      </span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        ))}
        {hasMore && (
          <div style={{ padding: '16px 0 24px', display: 'flex', justifyContent: 'center' }}>
            <button onClick={() => setVisibleCount(c => c + VISIBLE_PAGE)}
              style={{ background: accent + '18', border: `1px solid ${accent}55`, borderRadius: 4, padding: '6px 14px', cursor: 'pointer', color: accent, fontSize: 11, fontFamily: FONTS.mono }}>
              Show {Math.min(VISIBLE_PAGE, filtered.length - visible.length)} older
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

TimelineView.propTypes = {
  selectedProject: PropTypes.string,
  accent: PropTypes.string,
};
