import { useState, useEffect } from 'react';
import { api } from '../api';
import { SEVERITY } from '../constants.js';
import { PALETTE, FONTS } from './UI.jsx';

const SEVERITY_COLORS = {
  critical: SEVERITY.critical.color,
  high: SEVERITY.high.color,
  medium: SEVERITY.medium.color,
  low: SEVERITY.low.color,
};

export default function BurnChecklist({ hostId, hostLabel, onClose, accent = '#5b8af5' }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [burning, setBurning] = useState(false);
  const [done, setDone] = useState(false);

  const load = async () => {
    try {
      const res = await api.getBurnChecklist(hostId);
      setData(res);
      setError('');
    } catch (e) {
      setError(e.message || 'Failed');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, [hostId]);

  const doBurn = async () => {
    setBurning(true);
    try {
      const res = await api.burnHost(hostId);
      setData(res);
      setDone(true);
    } catch (e) {
      setError(e.message || 'Burn failed');
    } finally {
      setBurning(false);
    }
  };

  const checklist = data?.checklist || [];

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 9999 }}>
      <div style={{ background: PALETTE.bg3, border: `1px solid ${PALETTE.danger}`, borderRadius: 8, padding: 0, maxWidth: 560, width: '90%', maxHeight: '85vh', display: 'flex', flexDirection: 'column' }}>
        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '12px 16px', borderBottom: '1px solid #1e2029' }}>
          <span style={{ fontSize: 18 }}>🔥</span>
          <div style={{ flex: 1 }}>
            <div style={{ fontSize: 13, fontWeight: 700, color: PALETTE.danger, fontFamily: FONTS.display }}>
              {done ? 'Host Burned — Teardown Checklist' : 'Burn Host — OPSEC Compromise Response'}
            </div>
            <div style={{ fontSize: 10, color: PALETTE.textFaint }}>{hostLabel || hostId}</div>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: PALETTE.textFaint, fontSize: 16 }}>✕</button>
        </div>

        {/* Body */}
        <div style={{ flex: 1, overflowY: 'auto', padding: 16 }}>
          {loading && <div style={{ fontSize: 11, color: PALETTE.textGhost }}>Analyzing host exposure...</div>}
          {error && <div style={{ fontSize: 11, color: PALETTE.danger, marginBottom: 8 }}>{error}</div>}

          {data && (
            <>
              {/* Stats */}
              <div style={{ display: 'flex', gap: 16, marginBottom: 16 }}>
                <div style={{ textAlign: 'center' }}>
                  <div style={{ fontSize: 22, fontWeight: 700, color: data.critical_count > 0 ? '#cc2233' : '#3a8a3a', fontFamily: FONTS.mono }}>{data.total_items}</div>
                  <div style={{ fontSize: 8, color: PALETTE.textGhost, textTransform: 'uppercase' }}>Items</div>
                </div>
                <div style={{ textAlign: 'center' }}>
                  <div style={{ fontSize: 22, fontWeight: 700, color: data.critical_count > 0 ? '#cc2233' : '#3a8a3a', fontFamily: FONTS.mono }}>{data.critical_count}</div>
                  <div style={{ fontSize: 8, color: PALETTE.textGhost, textTransform: 'uppercase' }}>Critical</div>
                </div>
                <div style={{ textAlign: 'center' }}>
                  <div style={{ fontSize: 22, fontWeight: 700, color: checklist.length > 0 ? '#b89530' : '#3a8a3a', fontFamily: FONTS.mono }}>{checklist.length}</div>
                  <div style={{ fontSize: 8, color: PALETTE.textGhost, textTransform: 'uppercase' }}>Categories</div>
                </div>
              </div>

              {checklist.length === 0 && (
                <div style={{ fontSize: 11, color: '#3a8a3a', textAlign: 'center', padding: 20 }}>
                  No exposure detected — no cleanup required.
                </div>
              )}

              {/* Checklist items */}
              {checklist.map(cat => {
                const color = SEVERITY_COLORS[cat.severity] || '#5b8af5';
                return (
                  <div key={cat.id} style={{ marginBottom: 12, border: `1px solid ${color}33`, borderRadius: 6, overflow: 'hidden' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '6px 10px', background: `${color}08` }}>
                      <span style={{ fontSize: 7, fontWeight: 700, color: '#fff', background: color, borderRadius: 2, padding: '1px 4px', textTransform: 'uppercase' }}>{cat.severity}</span>
                      <span style={{ fontSize: 11, color: '#c0c8d8', fontFamily: FONTS.display, fontWeight: 600 }}>{cat.label}</span>
                    </div>
                    <div style={{ padding: '6px 10px' }}>
                      {cat.items.map((item, i) => (
                        <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '3px 0', fontSize: 10, fontFamily: FONTS.mono, color: PALETTE.textMute }}>
                          <span style={{ color: color }}>▸</span>
                          <span>{item.agent_id || item.username || item.name || item.title || item.id}</span>
                          {item.integration_type && <span style={{ color: PALETTE.textGhost }}>({item.integration_type})</span>}
                          {item.status && <span style={{ color: item.status === 'alive' ? '#3a8a3a' : PALETTE.textFaint }}>[{item.status}]</span>}
                          {item.domain && <span style={{ color: PALETTE.textGhost }}>{item.domain}</span>}
                        </div>
                      ))}
                    </div>
                  </div>
                );
              })}

              {done && (
                <div style={{ fontSize: 10, color: '#b89530', background: 'rgba(184,149,48,0.08)', border: '1px solid rgba(184,149,48,0.3)', borderRadius: 4, padding: '8px 10px', marginTop: 4 }}>
                  Host marked as burned. Review each checklist item above and execute cleanup manually. C2 sessions and pivots should be killed immediately.
                </div>
              )}
            </>
          )}
        </div>

        {/* Footer */}
        {!done && (
          <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', padding: '10px 16px', borderTop: '1px solid #1e2029' }}>
            <button onClick={onClose} style={{ background: '#1e2029', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 14px', cursor: 'pointer', color: PALETTE.textMute, fontSize: 10 }}>Cancel</button>
            <button onClick={doBurn} disabled={burning} style={{ background: burning ? '#333' : PALETTE.danger, border: 'none', borderRadius: 4, padding: '6px 14px', cursor: burning ? 'wait' : 'pointer', color: '#fff', fontSize: 10, fontWeight: 700 }}>
              {burning ? 'Burning...' : '🔥 Confirm burn'}
            </button>
          </div>
        )}
        {done && (
          <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', padding: '10px 16px', borderTop: '1px solid #1e2029' }}>
            <button onClick={onClose} style={{ background: '#1e2029', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 14px', cursor: 'pointer', color: PALETTE.textMute, fontSize: 10 }}>Close</button>
          </div>
        )}
      </div>
    </div>
  );
}
