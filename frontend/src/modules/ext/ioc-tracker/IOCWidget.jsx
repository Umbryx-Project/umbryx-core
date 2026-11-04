import { useState, useEffect, useCallback } from 'react';
import PropTypes from 'prop-types';
import { api } from '../../../api.js';
import { Select } from '../../../components/UI.jsx';

const SEV_COLORS = {
  critical: '#cc2233',
  high: '#e8574a',
  medium: '#f09a3a',
  low: '#e8cc42',
  info: '#5b8af5',
};

const TYPE_ICONS = {
  ip: '🌐',
  domain: '🔗',
  url: '📍',
  hash_md5: '#',
  hash_sha256: '##',
  email: '✉',
  file_path: '📄',
  registry_key: '🗝',
  mutex: '🔒',
};

export default function IOCWidget({ extension, accent, pid }) {
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(Boolean(pid));
  const [showAdd, setShowAdd] = useState(false);
  const [newIoc, setNewIoc] = useState({ value: '', ioc_type: 'ip', severity: 'medium', context: '' });

  const load = useCallback(async () => {
    if (!pid) return;
    try {
      const data = await fetch(`/api/projects/${pid}/ext/ioc-tracker/summary`, { credentials: 'include' }).then((r) => r.json());
      setSummary(data);
    } catch {
      // best-effort
    } finally {
      setLoading(false);
    }
  }, [pid]);

  useEffect(() => {
    load();
  }, [load]);

  const addIoc = async () => {
    if (!newIoc.value.trim()) return;
    try {
      await fetch(`/api/projects/${pid}/ext/ioc-tracker/iocs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(newIoc),
      });
      setNewIoc({ value: '', ioc_type: 'ip', severity: 'medium', context: '' });
      setShowAdd(false);
      load();
    } catch {
      // best-effort
    }
  };

  if (loading) {
    return <div style={{ padding: 8, fontSize: 11, color: '#606570', fontFamily: 'JetBrains Mono' }}>Loading IOC data...</div>;
  }

  const total = summary?.total || 0;
  const bySev = summary?.by_severity || {};
  const recent = summary?.recent || [];

  return (
    <div
      style={{
        background: '#0d0f14',
        border: '1px solid #1e2029',
        borderRadius: 6,
        padding: 14,
        fontFamily: 'JetBrains Mono',
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
        <div style={{ fontSize: 12, fontWeight: 700, color: '#e0e4ec', display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{ color: accent }}>{total}</span>
          <span style={{ color: '#606570', fontWeight: 400 }}>IOCs tracked</span>
        </div>
        <button
          onClick={() => setShowAdd((v) => !v)}
          style={{
            background: accent ? accent + '22' : '#1a1c22',
            border: 'none',
            borderRadius: 3,
            padding: '3px 8px',
            cursor: 'pointer',
            color: accent || '#c8cdd6',
            fontSize: 10,
            fontWeight: 600,
          }}
        >
          {showAdd ? '\u2715' : '+ Add'}
        </button>
      </div>

      {showAdd && (
        <div style={{ marginBottom: 10, padding: 8, background: '#0a0c10', borderRadius: 4, border: '1px solid #1e2029' }}>
          <input
            value={newIoc.value}
            onChange={(e) => setNewIoc({ ...newIoc, value: e.target.value })}
            placeholder="IOC value (IP, domain, hash...)"
            style={{ width: '100%', background: '#0d0f14', border: '1px solid #2a2d35', borderRadius: 3, padding: '4px 6px', color: '#c8cdd6', fontSize: 11, fontFamily: 'JetBrains Mono', boxSizing: 'border-box', marginBottom: 4 }}
          />
          <div style={{ display: 'flex', gap: 4 }}>
            <Select value={newIoc.ioc_type} onChange={(v) => setNewIoc({ ...newIoc, ioc_type: v })} style={{ flex: 1 }}
              options={['ip', 'domain', 'url', 'hash_md5', 'hash_sha256', 'email', 'file_path', 'registry_key', 'mutex']} />
            <Select value={newIoc.severity} onChange={(v) => setNewIoc({ ...newIoc, severity: v })} style={{ flex: 1 }}
              options={['info', 'low', 'medium', 'high', 'critical']} />
            <button onClick={addIoc} style={{ background: accent || '#5b8af5', border: 'none', borderRadius: 3, padding: '4px 10px', cursor: 'pointer', color: '#fff', fontSize: 10, fontWeight: 600 }}>Add</button>
          </div>
          <input
            value={newIoc.context}
            onChange={(e) => setNewIoc({ ...newIoc, context: e.target.value })}
            placeholder="Context (optional)"
            style={{ width: '100%', background: '#0d0f14', border: '1px solid #2a2d35', borderRadius: 3, padding: '4px 6px', color: '#808590', fontSize: 10, fontFamily: 'JetBrains Mono', boxSizing: 'border-box', marginTop: 4 }}
          />
        </div>
      )}

      {/* Severity breakdown */}
      {Object.keys(bySev).length > 0 && (
        <div style={{ display: 'flex', gap: 3, marginBottom: 10 }}>
          {['critical', 'high', 'medium', 'low', 'info'].map((sev) => {
            const count = bySev[sev] || 0;
            if (count === 0) return null;
            return (
              <div key={sev} style={{ flex: 1, textAlign: 'center', padding: '3px 0', borderRadius: 3, background: (SEV_COLORS[sev] || '#404550') + '15', border: `1px solid ${SEV_COLORS[sev]}33` }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: SEV_COLORS[sev] }}>{count}</div>
                <div style={{ fontSize: 8, color: '#606570', textTransform: 'uppercase' }}>{sev.slice(0, 4)}</div>
              </div>
            );
          })}
        </div>
      )}

      {/* Recent IOCs */}
      {recent.length > 0 ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
          {recent.slice(0, 5).map((ioc) => {
            const sev = ioc.data?.severity || 'info';
            const iocType = ioc.data?.ioc_type || 'unknown';
            return (
              <div key={ioc.id} style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '4px 6px', borderRadius: 3, background: '#ffffff04' }}>
                <span style={{ fontSize: 10 }}>{TYPE_ICONS[iocType] || '\u2022'}</span>
                <span style={{ fontSize: 11, color: '#c8cdd6', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{ioc.name}</span>
                <span style={{ fontSize: 8, textTransform: 'uppercase', color: SEV_COLORS[sev] || '#606570', fontWeight: 600 }}>{sev}</span>
              </div>
            );
          })}
          {recent.length > 5 && (
            <div style={{ fontSize: 9, color: '#404550', textAlign: 'center', paddingTop: 2 }}>+{recent.length - 5} more</div>
          )}
        </div>
      ) : (
        <div style={{ fontSize: 10, color: '#404550', textAlign: 'center', padding: '8px 0' }}>
          No IOCs recorded yet.
        </div>
      )}
    </div>
  );
}

IOCWidget.propTypes = {
  extension: PropTypes.object,
  accent: PropTypes.string,
};
