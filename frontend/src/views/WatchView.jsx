import { useState, useEffect, useCallback } from 'react';
import PropTypes from 'prop-types';
import Icon from '../components/Icon.jsx';
import { api } from '../api.js';
import { toastError, toastSuccess } from '../components/Toast.jsx';
import { PALETTE, FONTS, Select } from '../components/UI.jsx';
import { uiConfirm } from '../components/Confirm.jsx';

const INTERVAL_OPTS = [
  { value: 15, label: 'every 15 min' },
  { value: 30, label: 'every 30 min' },
  { value: 60, label: 'every hour' },
  { value: 360, label: 'every 6 hours' },
  { value: 1440, label: 'every day' },
];

const INTENSITY_OPTS = ['stealth', 'normal', 'aggressive'];

const INP = { background: PALETTE.bg2, border: `1px solid ${PALETTE.border}`, borderRadius: 5, padding: '7px 10px', color: PALETTE.textDim, fontSize: 11, fontFamily: FONTS.mono, outline: 'none', width: '100%' };

function fmtWhen(ts) {
  if (!ts) return 'never';
  return ts.replace('T', ' ').replace('Z', '');
}

function nextDue(w) {
  if (!w.enabled) return 'paused';
  if (!w.last_run_at) return 'next loop tick';
  const last = new Date(w.last_run_at.replace(' ', 'T').endsWith('Z') ? w.last_run_at.replace(' ', 'T') : w.last_run_at + 'Z');
  const due = new Date(last.getTime() + w.interval_minutes * 60000);
  if (Number.isNaN(due.getTime())) return '?';
  const mins = Math.round((due - Date.now()) / 60000);
  return mins <= 0 ? 'due now' : `in ~${mins} min`;
}

function DiffSummary({ diff }) {
  if (!diff || (!diff.new_hosts?.length && !diff.new_ports?.length && !diff.new_services?.length && !diff.status_changes?.length)) {
    return <span style={{ color: PALETTE.textGhost, fontSize: 10 }}>no changes</span>;
  }
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
      {diff.new_hosts?.map(h => (
        <div key={`h-${h.ip}`} style={{ fontFamily: FONTS.mono, fontSize: 10, color: PALETTE.ok }}>
          + host {h.ip}{h.hostname ? ` (${h.hostname})` : ''}
        </div>
      ))}
      {diff.new_ports?.map(p => (
        <div key={`p-${p.ip}`} style={{ fontFamily: FONTS.mono, fontSize: 10, color: PALETTE.ok }}>
          + {p.ip}: {p.ports.join(', ')}
        </div>
      ))}
      {diff.new_services?.map(s => (
        <div key={`s-${s.ip}`} style={{ fontFamily: FONTS.mono, fontSize: 10, color: PALETTE.ok }}>
          + {s.ip} service: {s.services.join(', ')}
        </div>
      ))}
      {diff.status_changes?.map(c => (
        <div key={`c-${c.ip}`} style={{ fontFamily: FONTS.mono, fontSize: 10, color: '#808590' }}>
          ~ {c.ip}: {c.from} → {c.to}
        </div>
      ))}
    </div>
  );
}
DiffSummary.propTypes = { diff: PropTypes.object };

function StateBadge({ state, enabled }) {
  const map = state === 'running'
    ? { label: 'running', color: '#5b8af5' }
    : enabled
      ? { label: 'active', color: PALETTE.ok }
      : { label: 'paused', color: PALETTE.textFaint };
  return (
    <span style={{ fontSize: 9, fontWeight: 700, color: map.color, background: `${map.color}22`, border: `1px solid ${map.color}44`, borderRadius: 3, padding: '1px 6px', fontFamily: FONTS.mono, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
      {map.label}
    </span>
  );
}
StateBadge.propTypes = { state: PropTypes.string, enabled: PropTypes.bool };

function GhostBtn({ icon, children, onClick, disabled, danger }) {
  const color = danger ? '#cc2233' : '#808590';
  const border = danger ? '#cc223344' : PALETTE.border;
  return (
    <button onClick={onClick} disabled={disabled}
      style={{ background: 'transparent', border: `1px solid ${border}`, borderRadius: 4, padding: '5px 10px', cursor: disabled ? 'default' : 'pointer', opacity: disabled ? 0.5 : 1, color, fontSize: 10, fontFamily: FONTS.mono, display: 'flex', alignItems: 'center', gap: 5 }}>
      {icon && <Icon name={icon} size={11} color="currentColor" />}
      {children}
    </button>
  );
}
GhostBtn.propTypes = { icon: PropTypes.string, children: PropTypes.node, onClick: PropTypes.func, disabled: PropTypes.bool, danger: PropTypes.bool };

function CreateWatchModal({ accent, onClose, onCreate }) {
  const [form, setForm] = useState({ name: 'Perimeter watch', interval_minutes: 60, targets: '', intensity_profile: 'normal' });
  const set = (k, v) => setForm(f => ({ ...f, [k]: v }));

  return (
    <div role="presentation" onClick={onClose} style={{ position: 'fixed', inset: 0, background: '#000000bb', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, backdropFilter: 'blur(4px)' }}>
      <div role="dialog" aria-modal="true" onClick={e => e.stopPropagation()} style={{ background: PALETTE.bg3, border: `1px solid ${PALETTE.border}`, borderRadius: 12, padding: '28px 32px', width: 460, boxShadow: '0 24px 64px #00000099' }}>
        <div style={{ fontSize: 14, fontWeight: 700, color: PALETTE.text, fontFamily: FONTS.display, marginBottom: 20 }}>New surface watch</div>

        <div style={{ marginBottom: 14 }}>
          <div style={{ fontSize: 9, color: '#505560', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 5 }}>Name</div>
          <input style={INP} value={form.name} onChange={e => set('name', e.target.value)} autoFocus />
        </div>

        <div style={{ marginBottom: 14 }}>
          <div style={{ fontSize: 9, color: '#505560', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 5 }}>Interval</div>
          <Select value={form.interval_minutes} onChange={v => set('interval_minutes', Number(v))} options={INTERVAL_OPTS} />
        </div>

        <div style={{ marginBottom: 14 }}>
          <div style={{ fontSize: 9, color: '#505560', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 5 }}>Targets (empty = project scope CIDRs)</div>
          <input style={{ ...INP, fontFamily: FONTS.mono }} value={form.targets} onChange={e => set('targets', e.target.value)} placeholder="10.0.0.0/24 192.168.1.0/24" />
        </div>

        <div style={{ marginBottom: 20 }}>
          <div style={{ fontSize: 9, color: '#505560', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 5 }}>Scan intensity</div>
          <div style={{ display: 'flex', gap: 5 }}>
            {INTENSITY_OPTS.map(p => (
              <button key={p} onClick={() => set('intensity_profile', p)}
                style={{ background: form.intensity_profile === p ? `${accent}22` : PALETTE.borderSoft, border: `1px solid ${form.intensity_profile === p ? accent : PALETTE.border}`, borderRadius: 4, padding: '4px 10px', cursor: 'pointer', color: form.intensity_profile === p ? accent : PALETTE.textFaint, fontSize: 10, fontFamily: FONTS.mono }}>
                {p}
              </button>
            ))}
          </div>
        </div>

        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
          <button onClick={onClose} style={{ background: 'none', border: `1px solid ${PALETTE.border}`, borderRadius: 5, padding: '7px 16px', cursor: 'pointer', color: PALETTE.textFaint, fontSize: 11, fontFamily: FONTS.mono }}>Cancel</button>
          <button onClick={() => onCreate(form)} disabled={!form.name.trim()}
            style={{ background: form.name.trim() ? accent : PALETTE.border, border: 'none', borderRadius: 5, padding: '7px 18px', cursor: form.name.trim() ? 'pointer' : 'default', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: FONTS.mono }}>
            Create watch
          </button>
        </div>
      </div>
    </div>
  );
}
CreateWatchModal.propTypes = { accent: PropTypes.string, onClose: PropTypes.func, onCreate: PropTypes.func };

function WatchCard({ w, busy, onRun, onToggle, onDelete }) {
  return (
    <div style={{ background: PALETTE.bg2, border: '1px solid #1e2029', borderRadius: 8, padding: 14, marginBottom: 10 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 8 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          <span style={{ color: '#e0e4ec', fontSize: 13, fontWeight: 600, fontFamily: FONTS.display }}>{w.name}</span>
          <StateBadge state={w.state} enabled={w.enabled} />
          <span style={{ color: PALETTE.textGhost, fontSize: 10, fontFamily: FONTS.mono }}>
            every {w.interval_minutes}m · {w.targets ? w.targets : 'project scope'} · next {nextDue(w)}
          </span>
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          <GhostBtn icon="target" onClick={onRun} disabled={!!busy || w.state === 'running'}>Run now</GhostBtn>
          <GhostBtn icon={w.enabled ? 'eyeOff' : 'eye'} onClick={onToggle} disabled={!!busy}>{w.enabled ? 'Pause' : 'Resume'}</GhostBtn>
          <GhostBtn icon="trash" onClick={onDelete} disabled={!!busy} danger>Delete</GhostBtn>
        </div>
      </div>

      <div style={{ display: 'flex', gap: 28, marginTop: 12 }}>
        <div>
          <div style={{ color: '#505560', fontSize: 9, textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 3 }}>Last run</div>
          <div style={{ fontFamily: FONTS.mono, fontSize: 11, color: PALETTE.textDim }}>{fmtWhen(w.last_run_at)}</div>
        </div>
        <div>
          <div style={{ color: '#505560', fontSize: 9, textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 3 }}>Baseline hosts</div>
          <div style={{ fontFamily: FONTS.mono, fontSize: 11, color: PALETTE.textDim }}>{Object.keys(w.baseline_json || {}).length}</div>
        </div>
        <div>
          <div style={{ color: '#505560', fontSize: 9, textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 3 }}>Last change</div>
          <div style={{ fontFamily: FONTS.mono, fontSize: 11, color: PALETTE.textDim }}>{fmtWhen(w.last_change_at)}</div>
        </div>
      </div>

      <div style={{ marginTop: 12, borderTop: `1px solid ${PALETTE.borderSoft}`, paddingTop: 10 }}>
        <div style={{ color: '#505560', fontSize: 9, textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 5 }}>Last diff</div>
        <DiffSummary diff={w.last_diff_json} />
      </div>
    </div>
  );
}
WatchCard.propTypes = { w: PropTypes.object, busy: PropTypes.string, onRun: PropTypes.func, onToggle: PropTypes.func, onDelete: PropTypes.func };

export default function WatchView({ selectedProject, accent }) {
  const [watches, setWatches] = useState([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(null);
  const [showCreate, setShowCreate] = useState(false);

  const load = useCallback(async () => {
    if (!selectedProject) { setLoading(false); return; }
    try {
      setWatches(await api.getProjectWatches(selectedProject));
    } catch (e) { console.error('watch load failed:', e); }
    setLoading(false);
  }, [selectedProject]);

  useEffect(() => { setLoading(true); load(); }, [load]);

  // refresh while any watch is running so the operator sees completion
  useEffect(() => {
    if (!watches.some(w => w.state === 'running')) return;
    const t = setInterval(load, 5000);
    return () => clearInterval(t);
  }, [watches, load]);

  const handleCreate = async (form) => {
    try {
      await api.createProjectWatch(selectedProject, form);
      toastSuccess('Watch created');
      setShowCreate(false);
      await load();
    } catch (e) { toastError(e.message); }
  };

  const handleRun = (id) => async () => {
    setBusy(`run:${id}`);
    try {
      await api.runProjectWatch(selectedProject, id);
      toastSuccess('Watch run started');
      await load();
    } catch (e) { toastError(e.message); }
    setBusy(null);
  };

  const handleToggle = (w) => async () => {
    setBusy(`tgl:${w.id}`);
    try {
      const updated = await api.updateProjectWatch(selectedProject, w.id, { enabled: !w.enabled });
      setWatches(prev => prev.map(x => x.id === w.id ? updated : x));
    } catch (e) { toastError(e.message); }
    setBusy(null);
  };

  const handleDelete = (w) => async () => {
    if (!await uiConfirm(`Delete watch '${w.name}'?`)) return;
    setBusy(`del:${w.id}`);
    try {
      await api.deleteProjectWatch(selectedProject, w.id);
      setWatches(prev => prev.filter(x => x.id !== w.id));
    } catch (e) { toastError(e.message); }
    setBusy(null);
  };

  if (!selectedProject) return (
    <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: PALETTE.textGhost, fontSize: 12, fontFamily: FONTS.mono }}>
      Select a project to manage its attack-surface watches
    </div>
  );

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      {/* Toolbar */}
      <div style={{ padding: '12px 24px', borderBottom: `1px solid ${PALETTE.borderSoft}`, background: '#0a0c10', display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
        <span style={{ fontSize: 13, fontWeight: 600, color: '#e0e4ec', fontFamily: FONTS.display }}>Surface Watches ({watches.length})</span>
        <div style={{ flex: 1 }} />
        <button onClick={() => setShowCreate(true)}
          style={{ background: accent, border: 'none', borderRadius: 5, padding: '6px 14px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: FONTS.mono, display: 'flex', alignItems: 'center', gap: 6 }}>
          <Icon name="plus" size={10} color="#fff" /> New Watch
        </button>
      </div>

      {/* Content */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '20px 24px' }}>
        {loading && <div style={{ padding: 30, textAlign: 'center', color: PALETTE.textGhost, fontSize: 11 }}>Loading...</div>}

        {!loading && watches.length === 0 && (
          <div style={{ padding: '60px 0', textAlign: 'center', color: '#303540', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12 }}>
            <Icon name="eye" size={40} color="#2a2d35" />
            <div style={{ fontSize: 13 }}>No watches</div>
            <div style={{ fontSize: 11, color: '#252830', maxWidth: 380, lineHeight: 1.5 }}>
              A watch runs a periodic light nmap over the project scope and alerts the team when the attack surface grows: new hosts, ports or services.
            </div>
          </div>
        )}

        {!loading && watches.map(w => (
          <WatchCard key={w.id} w={w} busy={busy}
            onRun={handleRun(w.id)} onToggle={handleToggle(w)} onDelete={handleDelete(w)} />
        ))}
      </div>

      {showCreate && <CreateWatchModal accent={accent} onClose={() => setShowCreate(false)} onCreate={handleCreate} />}
    </div>
  );
}

WatchView.propTypes = {
  selectedProject: PropTypes.string,
  accent: PropTypes.string,
};
