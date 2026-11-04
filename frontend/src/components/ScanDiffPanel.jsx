import { memo, useEffect, useState, useCallback } from 'react';
import { api } from '../api';
import { PALETTE, FONTS } from './UI.jsx';

export const ScanDiffPanel = memo(function ScanDiffPanel({ hostId }) {
  const [history, setHistory] = useState([]);
  const [diff, setDiff] = useState(null);
  const [selectedOld, setSelectedOld] = useState(null);
  const [selectedNew, setSelectedNew] = useState(null);
  const [showFull, setShowFull] = useState(false);
  const [loading, setLoading] = useState(true);

  const loadHistory = useCallback(() => {
    api.getScanHistory(hostId).then(r => {
      setHistory(r);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, [hostId]);

  const loadDiff = useCallback(() => {
    api.getScanDiff(hostId, selectedOld || undefined, selectedNew || undefined).then(setDiff).catch(() => setDiff(null));
  }, [hostId, selectedOld, selectedNew]);

  useEffect(() => { loadHistory(); }, [loadHistory]);
  useEffect(() => { loadDiff(); }, [loadDiff]);

  if (loading) return <div style={{ fontSize: 9, color: PALETTE.textGhost, fontFamily: FONTS.mono, padding: '8px 0' }}>Loading scan history...</div>;

  if (history.length === 0) {
    return <div style={{ fontSize: 9, color: PALETTE.textGhost, fontFamily: FONTS.mono, padding: '8px 0' }}>No scan history yet — snapshots are captured automatically after scans.</div>;
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      {/* Diff view */}
      {diff && diff.has_changes !== false && (
        <div style={{ background: PALETTE.bg3, border: `1px solid ${PALETTE.borderSoft}`, borderRadius: 6, padding: 10 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
            <span style={{ fontSize: 10, color: '#808590', fontFamily: FONTS.mono, textTransform: 'uppercase' }}>Scan Diff</span>
            <button onClick={() => setShowFull(v => !v)}
              style={{ background: 'none', border: `1px solid ${PALETTE.border}`, borderRadius: 3, padding: '2px 6px', color: PALETTE.textFaint, cursor: 'pointer', fontSize: 8, fontFamily: FONTS.mono }}>
              {showFull ? 'Changes only' : 'Show all'}
            </button>
          </div>
          <div style={{ fontSize: 8, color: PALETTE.textGhost, fontFamily: FONTS.mono, marginBottom: 8 }}>
            {diff.old_scan_type || '?'} → {diff.new_scan_type || '?'} · {diff.old_scan_at || ''} → {diff.new_scan_at || ''}
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            {diff.added_ports?.length > 0 && <DiffRow type="add" label="New ports" value={diff.added_ports.join(', ')} />}
            {diff.removed_ports?.length > 0 && <DiffRow type="remove" label="Gone ports" value={diff.removed_ports.join(', ')} />}
            {diff.added_services?.length > 0 && <DiffRow type="add" label="New services" value={diff.added_services.join(', ')} />}
            {diff.removed_services?.length > 0 && <DiffRow type="remove" label="Gone services" value={diff.removed_services.join(', ')} />}
            {diff.os_changed && <DiffRow type="change" label="OS" value={`${diff.os_old || '?'} → ${diff.os_new || '?'}`} />}
            {diff.hostname_changed && <DiffRow type="change" label="Hostname" value={`${diff.hostname_old || '?'} → ${diff.hostname_new || '?'}`} />}
            {diff.new_findings?.length > 0 && diff.new_findings.map((f, i) => (
              <DiffRow key={`nf${i}`} type="add" label={`Finding [${f.severity}]`} value={f.title + (f.cve ? ` (${f.cve})` : '')} />
            ))}
            {diff.resolved_findings?.length > 0 && diff.resolved_findings.map((f, i) => (
              <DiffRow key={`rf${i}`} type="remove" label={`Resolved [${f.severity}]`} value={f.title} />
            ))}
            {!diff.has_changes && <div style={{ fontSize: 9, color: PALETTE.textGhost, fontFamily: FONTS.mono, padding: '4px 0' }}>No changes between these scans.</div>}
          </div>
        </div>
      )}

      {/* History list */}
      <div>
        <div style={{ fontSize: 9, color: '#505560', fontFamily: FONTS.mono, textTransform: 'uppercase', marginBottom: 4 }}>Scan History ({history.length})</div>
        {history.map((s, i) => (
          <div key={s.id} style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '3px 0', borderBottom: '1px solid #131519' }}>
            <span style={{ width: 14, textAlign: 'center', fontSize: 8, color: PALETTE.textGhost, fontFamily: FONTS.mono }}>{i + 1}</span>
            <span style={{ fontSize: 9, color: '#5b8af5', fontFamily: FONTS.mono, minWidth: 50 }}>{s.connector_key || 'scan'}</span>
            <span style={{ fontSize: 8, color: PALETTE.textFaint, fontFamily: FONTS.mono, flex: 1 }}>
              {s.summary.ports}p · {s.summary.services}s · {s.summary.findings}f
            </span>
            <span style={{ fontSize: 8, color: PALETTE.textGhost, fontFamily: FONTS.mono }}>{(s.created_at || '').slice(0, 16).replace('T', ' ')}</span>
          </div>
        ))}
      </div>
    </div>
  );
});

const DIFF_STYLES = {
  add:    { color: PALETTE.ok, bg: '#39d35311', prefix: '+', label: 'ADD' },
  remove: { color: PALETTE.danger, bg: '#cc223311', prefix: '-', label: 'DEL' },
  change: { color: PALETTE.warn, bg: '#f09a3a11', prefix: '~', label: 'CHG' },
};

const DiffRow = memo(function DiffRow({ type, label, value }) {
  const s = DIFF_STYLES[type] || DIFF_STYLES.change;
  return (
    <div style={{ display: 'flex', alignItems: 'flex-start', gap: 6, padding: '2px 4px', background: s.bg, borderRadius: 3 }}>
      <span style={{ fontSize: 9, color: s.color, fontFamily: FONTS.mono, fontWeight: 700, flexShrink: 0 }}>{s.prefix}</span>
      <span style={{ fontSize: 8, color: PALETTE.textFaint, fontFamily: FONTS.mono, minWidth: 70, flexShrink: 0 }}>{label}</span>
      <span style={{ fontSize: 9, color: s.color, fontFamily: FONTS.mono, wordBreak: 'break-all' }}>{value}</span>
    </div>
  );
});
