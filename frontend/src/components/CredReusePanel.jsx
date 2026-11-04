import { useState, useEffect, useMemo } from 'react';
import { api } from '../api';
import { SEVERITY } from '../constants.js';
import { PALETTE, FONTS } from './UI.jsx';

const SEVERITY_COLORS = {
  critical: SEVERITY.critical.color,
  high: SEVERITY.high.color,
  medium: SEVERITY.medium.color,
  low: SEVERITY.low.color,
};
const SEVERITY_BG = {
  critical: 'rgba(204,34,51,0.08)',
  high: 'rgba(232,87,74,0.08)',
  medium: 'rgba(240,154,58,0.08)',
  low: 'rgba(232,204,66,0.06)',
};

export default function CredReusePanel({ pid, accent = '#5b8af5' }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [expanded, setExpanded] = useState(null);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const res = await api.getCredReuse(pid);
        if (!cancelled) { setData(res); setError(''); }
      } catch (e) {
        if (!cancelled) setError(e.message || 'Failed to load');
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    load();
    return () => { cancelled = true; };
  }, [pid]);

  const stats = data?.stats;
  const groups = data?.groups || [];

  if (loading) return <div style={{ fontSize: 10, color: PALETTE.textGhost, padding: 12 }}>Analyzing credential reuse...</div>;
  if (error) return <div style={{ fontSize: 10, color: PALETTE.danger, padding: 12 }}>{error}</div>;
  if (!stats) return null;

  return (
    <div style={{ padding: 4 }}>
      {/* Stats bar */}
      <div style={{ display: 'flex', gap: 12, marginBottom: 12, flexWrap: 'wrap' }}>
        <StatBox label="Total Creds" value={stats.total_creds} color="#5b8af5" />
        <StatBox label="Reused" value={stats.reused_creds} color={stats.reused_creds > 0 ? '#f09a3a' : '#3a8a3a'} />
        <StatBox label="Affected Hosts" value={stats.affected_hosts} color={stats.affected_hosts > 0 ? '#f09a3a' : '#3a8a3a'} />
        <StatBox label="Reuse Clusters" value={stats.clusters} color={stats.clusters > 0 ? '#b89530' : '#3a8a3a'} />
      </div>

      {groups.length === 0 && (
        <div style={{ fontSize: 11, color: '#3a8a3a', padding: '12px 0', textAlign: 'center' }}>
          No credential reuse detected — all passwords are unique.
        </div>
      )}

      {/* Reuse groups */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
        {groups.map((g, i) => {
          const color = SEVERITY_COLORS[g.severity] || '#5b8af5';
          const bg = SEVERITY_BG[g.severity] || 'transparent';
          const isOpen = expanded === i;
          return (
            <div key={i} style={{ border: `1px solid ${color}44`, borderRadius: 5, overflow: 'hidden', background: bg }}>
              <div
                onClick={() => setExpanded(isOpen ? null : i)}
                style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '6px 10px', cursor: 'pointer' }}
              >
                <span style={{ fontSize: 8, fontWeight: 700, color: '#fff', background: color, borderRadius: 2, padding: '1px 5px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{g.severity}</span>
                <span style={{ fontSize: 10, color: '#c0c8d8', fontFamily: FONTS.mono }}>
                  {g.usernames.join(', ').slice(0, 60)}{g.usernames.join(', ').length > 60 ? '...' : ''}
                </span>
                <span style={{ flex: 1 }} />
                {g.is_domain && <span style={{ fontSize: 8, color: PALETTE.warn, background: 'rgba(240,154,58,0.1)', border: '1px solid rgba(240,154,58,0.3)', borderRadius: 2, padding: '1px 4px' }}>DOMAIN</span>}
                {g.has_admin_access && <span style={{ fontSize: 8, color: PALETTE.danger, background: 'rgba(204,34,51,0.1)', border: '1px solid rgba(204,34,51,0.3)', borderRadius: 2, padding: '1px 4px' }}>ADMIN</span>}
                <span style={{ fontSize: 9, color: PALETTE.textFaint, fontFamily: FONTS.mono }}>
                  {g.host_count} host(s) • {g.user_count} user(s)
                </span>
                <span style={{ fontSize: 9, color: PALETTE.textGhost }}>{isOpen ? '▾' : '▸'}</span>
              </div>

              {isOpen && (
                <div style={{ padding: '4px 10px 8px', borderTop: `1px solid ${color}22` }}>
                  <div style={{ fontSize: 9, color: '#707880', marginBottom: 4 }}>Secret: <span style={{ fontFamily: FONTS.mono, color: PALETTE.textMute }}>{g.secret_preview}</span></div>
                  {g.services.length > 0 && <div style={{ fontSize: 9, color: '#707880', marginBottom: 4 }}>Services: {g.services.join(', ')}</div>}
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 4 }}>
                    {g.hosts.map(h => (
                      <span key={h.id} style={{ fontSize: 9, color: PALETTE.textMute, background: PALETTE.bg3, border: '1px solid #1e2029', borderRadius: 3, padding: '2px 6px', fontFamily: FONTS.mono }}>
                        {h.ip || h.hostname}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function StatBox({ label, value, color }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', minWidth: 80 }}>
      <span style={{ fontSize: 18, fontWeight: 700, color, fontFamily: FONTS.mono }}>{value}</span>
      <span style={{ fontSize: 8, color: PALETTE.textGhost, textTransform: 'uppercase', letterSpacing: '0.08em' }}>{label}</span>
    </div>
  );
}
