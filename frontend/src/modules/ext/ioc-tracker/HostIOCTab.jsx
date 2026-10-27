import { useState, useEffect, useCallback } from 'react';
import PropTypes from 'prop-types';
import { Select } from '../../../components/UI.jsx';

const SEV_COLORS = {
  critical: '#cc2233',
  high: '#e8574a',
  medium: '#f09a3a',
  low: '#e8cc42',
  info: '#5b8af5',
};

export default function HostIOCTab({ extension, hostId, accent, pid }) {
  const [iocs, setIocs] = useState([]);
  const [loading, setLoading] = useState(Boolean(pid && hostId));

  const load = useCallback(async () => {
    if (!pid || !hostId) {
      setLoading(false);
      return;
    }
    try {
      const resp = await fetch(`/api/projects/${pid}/ext/ioc-tracker/iocs?q=${encodeURIComponent(hostId)}`, { credentials: 'include' });
      const data = await resp.json();
      const filtered = (data.items || []).filter(
        (ioc) => ioc.data?.host_id === hostId || ioc.data?.context?.includes(hostId)
      );
      setIocs(filtered);
    } catch {
      // best-effort
    } finally {
      setLoading(false);
    }
  }, [pid, hostId]);

  useEffect(() => {
    load();
  }, [load]);

  if (loading) return <div style={{ padding: 12, color: '#606570', fontSize: 11, fontFamily: 'JetBrains Mono' }}>Loading IOCs...</div>;

  if (iocs.length === 0) {
    return (
      <div style={{ padding: 20, textAlign: 'center', color: '#404550', fontSize: 11, fontFamily: 'JetBrains Mono' }}>
        No IOCs attributed to this host.
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 4, padding: 8 }}>
      {iocs.map((ioc) => {
        const sev = ioc.data?.severity || 'info';
        const sevColor = SEV_COLORS[sev] || '#606570';
        return (
          <div
            key={ioc.id}
            style={{
              display: 'flex',
              alignItems: 'flex-start',
              gap: 8,
              padding: '6px 10px',
              borderRadius: 4,
              background: '#0a0c10',
              border: `1px solid ${sevColor}22`,
            }}
          >
            <div style={{ flex: 1 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 2 }}>
                <span style={{ fontSize: 11, fontWeight: 600, color: '#c8cdd6', fontFamily: 'JetBrains Mono' }}>{ioc.name}</span>
                <span style={{ fontSize: 8, textTransform: 'uppercase', color: sevColor, fontWeight: 600, padding: '1px 4px', borderRadius: 2, background: sevColor + '15' }}>{sev}</span>
                <span style={{ fontSize: 8, color: '#404550', textTransform: 'uppercase' }}>{ioc.data?.ioc_type}</span>
              </div>
              {ioc.data?.context && (
                <div style={{ fontSize: 10, color: '#808590', lineHeight: 1.4 }}>{ioc.data.context}</div>
              )}
              {ioc.data?.source && (
                <div style={{ fontSize: 9, color: '#404550', marginTop: 2 }}>Source: {ioc.data.source}</div>
              )}
            </div>
            <div style={{ display: 'flex', gap: 2 }}>
              <Select
                value={ioc.data?.status || 'active'}
                onChange={async (v) => {
                  await fetch(`/api/projects/${pid}/ext/ioc-tracker/iocs/${ioc.id}`, {
                    method: 'PATCH',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'include',
                    body: JSON.stringify({ status: v }),
                  });
                  load();
                }}
                options={['active', 'contained', 'remediated', 'false_positive']}
              />
              <button
                onClick={async () => {
                  await fetch(`/api/projects/${pid}/ext/ioc-tracker/iocs/${ioc.id}`, { method: 'DELETE', credentials: 'include' });
                  load();
                }}
                style={{ background: 'transparent', border: 'none', color: '#404550', cursor: 'pointer', fontSize: 11, padding: '0 4px' }}
                title="Delete IOC"
              >
                {'\u2715'}
              </button>
            </div>
          </div>
        );
      })}
    </div>
  );
}

HostIOCTab.propTypes = {
  extension: PropTypes.object,
  hostId: PropTypes.string,
  accent: PropTypes.string,
};
