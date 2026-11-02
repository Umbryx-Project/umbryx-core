import { memo, useState, useEffect, useCallback } from 'react';
import { api } from '../api';
import { PALETTE, FONTS } from './UI.jsx';

const CONNECTOR_ICONS = {
  nuclei: 'bug',
  httpx: 'globe',
  netexec: 'hosts',
  nmap: 'target',
};
const PRIORITY_COLORS = { high: PALETTE.danger, medium: PALETTE.warn, low: '#5b8af5' };

export const ChainSuggestions = memo(function ChainSuggestions({ pid, jobId, accent, onLaunch }) {
  const [suggestions, setSuggestions] = useState([]);
  const [loading, setLoading] = useState(false);
  const [dismissed, setDismissed] = useState(new Set());
  const [launching, setLaunching] = useState(null);

  const load = useCallback(() => {
    if (!pid) return;
    setLoading(true);
    api.getChainSuggestions(pid, jobId).then(r => {
      setSuggestions(Array.isArray(r) ? r : []);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, [pid, jobId]);

  useEffect(() => { load(); }, [load]);

  const visible = suggestions.filter(s => !dismissed.has(s.id));
  if (visible.length === 0 && !loading) return null;

  const launch = async (s) => {
    setLaunching(s.id);
    try {
      if (s.connector === 'nuclei') {
        await api.runNucleiScan(pid, { target: s.target });
      } else if (s.connector === 'netexec') {
        await api.runCmeScan(pid, { target: s.target, service: 'smb' });
      } else if (s.connector === 'httpx') {
        await api.req('POST', `/projects/${pid}/scans/httpx`, { target: s.target });
      }
      onLaunch?.(s);
      setDismissed(prev => new Set([...prev, s.id]));
    } catch (e) {
      console.error('Chain launch failed:', e);
    }
    setLaunching(null);
  };

  return (
    <div style={{ background: '#0c0e13', border: `1px solid ${PALETTE.borderSoft}`, borderRadius: 6, padding: 10, marginBottom: 12 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8 }}>
        <span style={{ fontSize: 9, color: accent || '#5b8af5', textTransform: 'uppercase', letterSpacing: '0.08em', fontFamily: FONTS.mono, fontWeight: 600 }}>Suggested next steps</span>
        {loading && <span style={{ fontSize: 8, color: PALETTE.textGhost, fontFamily: FONTS.mono }}>analysing...</span>}
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
        {visible.map(s => {
          const pc = PRIORITY_COLORS[s.priority] || PRIORITY_COLORS.low;
          return (
            <div key={s.id} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '6px 8px', background: '#0a0c10', borderRadius: 4, border: `1px solid ${pc}22` }}>
              <span style={{ width: 5, height: 5, borderRadius: '50%', background: pc, flexShrink: 0 }} />
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 10, color: PALETTE.textDim, fontFamily: FONTS.mono, fontWeight: 600 }}>{s.label}</div>
                <div style={{ fontSize: 9, color: '#505560', fontFamily: FONTS.mono }}>{s.description}</div>
              </div>
              <button onClick={() => launch(s)} disabled={launching === s.id}
                style={{ background: launching === s.id ? '#1a1c22' : `${accent || '#5b8af5'}22`, border: `1px solid ${accent || '#5b8af5'}44`, borderRadius: 3, padding: '4px 10px', color: accent || '#5b8af5', cursor: launching === s.id ? 'default' : 'pointer', fontSize: 9, fontFamily: FONTS.mono, fontWeight: 600, whiteSpace: 'nowrap', opacity: launching === s.id ? 0.6 : 1 }}>
                {launching === s.id ? 'Launching...' : 'Launch'}
              </button>
              <button onClick={() => setDismissed(prev => new Set([...prev, s.id]))}
                style={{ background: 'none', border: 'none', color: PALETTE.textGhost, cursor: 'pointer', fontSize: 12, padding: 0, lineHeight: 1 }}>
                {'\u00D7'}
              </button>
            </div>
          );
        })}
      </div>
    </div>
  );
});
