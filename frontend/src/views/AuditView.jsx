import { useState, useEffect, useCallback } from 'react';
import PropTypes from 'prop-types';
import { api } from '../api.js';
import { toastError } from '../components/Toast.jsx';
import { Btn, FieldInput, EmptyState, PageTitle, PALETTE, TYPE, LOG_ROW_STYLE, LOG_HEADER_STYLE, logRowHover, logRowUnhover } from '../components/UI.jsx';

const AUDIT_GRID = '112px 150px 1fr 1fr 1fr 110px';

const ACTION_COLORS = {
  'auth.login': '#39d353', 'auth.logout': PALETTE.textGhost,
  'host.create': '#15bbb1', 'host.delete': '#cc2233', 'host.restore': '#4a9eff',
  'finding.create': '#15bbb1', 'finding.delete': '#cc2233',
  'note.create': '#15bbb1', 'note.delete': '#cc2233',
  'loot.create': '#15bbb1', 'loot.delete': '#cc2233',
  'project.create': '#39d353', 'project.delete': '#cc2233',
  'member.add': '#4a9eff', 'member.remove': '#cc2233', 'member.role_change': '#f09a3a',
};

function actionColor(action) {
  return ACTION_COLORS[action] || PALETTE.textDim;
}

export default function AuditView({ selectedProject, accent }) {
  const [entries, setEntries] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [filter, setFilter] = useState({ action: '', target_type: '' });
  const [offset, setOffset] = useState(0);
  const LIMIT = 50;

  const fetchAudit = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({ limit: LIMIT, offset });
      if (selectedProject) params.set('pid', selectedProject);
      if (filter.action) params.set('action', filter.action);
      if (filter.target_type) params.set('target_type', filter.target_type);
      const data = await api.getAuditLog(params.toString());
      setEntries(data.items || []);
      setTotal(data.total || 0);
    } catch (e) {
      toastError(e.message);
    } finally {
      setLoading(false);
    }
  }, [selectedProject, filter, offset]);

  useEffect(() => { fetchAudit(); }, [fetchAudit]);

  const formatTs = (iso) => {
    if (!iso) return '';
    const d = new Date(iso);
    return d.toLocaleString('ru-RU', { day: '2-digit', month: '2-digit', year: '2-digit', hour: '2-digit', minute: '2-digit' });
  };

  return (
    <div style={{ flex: 1, overflowY: 'auto', padding: '24px 28px' }}>
      <PageTitle accent={accent}>Audit Log</PageTitle>
      <div style={{ fontSize: TYPE.label, color: PALETTE.textGhost, marginBottom: 16 }}>
        {total} entries
      </div>

      <div style={{ display: 'flex', gap: 12, marginBottom: 16, flexWrap: 'wrap' }}>
        <FieldInput
          placeholder="Action filter (e.g. host.create)"
          value={filter.action}
          onChange={e => { setFilter(f => ({...f, action: e.target.value})); setOffset(0); }}
          style={{ width: 220 }}
        />
        <FieldInput
          placeholder="Target type (host, finding...)"
          value={filter.target_type}
          onChange={e => { setFilter(f => ({...f, target_type: e.target.value})); setOffset(0); }}
          style={{ width: 180 }}
        />
        <Btn accent={accent} onClick={fetchAudit}>Refresh</Btn>
      </div>

      {loading && <div style={{ color: PALETTE.textGhost }}>Loading...</div>}
      {!loading && entries.length === 0 && <EmptyState icon="list" title="No audit entries" />}
      {!loading && entries.length > 0 && (
        <div style={{ border: `1px solid ${PALETTE.border}`, borderRadius: 6, overflow: 'hidden' }}>
          <div style={{ display: 'grid', gridTemplateColumns: AUDIT_GRID, gap: 12, ...LOG_HEADER_STYLE }}>
            <span>Time</span><span>Action</span><span>Actor</span><span>Target</span><span>Detail</span><span>IP</span>
          </div>
          {entries.map(e => (
            <div key={e.id}
              style={{ display: 'grid', gridTemplateColumns: AUDIT_GRID, gap: 12, alignItems: 'center', ...LOG_ROW_STYLE }}
              onMouseEnter={logRowHover} onMouseLeave={logRowUnhover}>
              <span style={{ color: PALETTE.textFaint }}>{formatTs(e.ts)}</span>
              <span style={{
                background: actionColor(e.action) + '22',
                color: actionColor(e.action),
                padding: '3px 9px',
                borderRadius: 3,
                fontWeight: 600,
                fontSize: 12,
                textAlign: 'center',
                width: 'fit-content',
                maxWidth: '100%',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap',
              }} title={e.action}>{e.action}</span>
              <span style={{ color: PALETTE.textDim, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={e.actor_name || 'system'}>{e.actor_name || 'system'}</span>
              <span style={{ color: PALETTE.textFaint, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={e.target_type ? `${e.target_type}:${e.target_id || ''}` : ''}>{e.target_type ? `${e.target_type}:${(e.target_id || '').slice(0, 8)}` : '—'}</span>
              <span style={{ color: PALETTE.textFaint, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={e.detail || ''}>{e.detail || '—'}</span>
              <span style={{ color: PALETTE.textFaint }}>{e.ip_address || '—'}</span>
            </div>
          ))}
        </div>
      )}

      {total > LIMIT && (
        <div style={{ display: 'flex', gap: 12, marginTop: 16, alignItems: 'center' }}>
          <Btn accent={accent} disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - LIMIT))}>Prev</Btn>
          <span style={{ fontSize: TYPE.label, color: PALETTE.textGhost }}>
            {offset + 1}–{Math.min(offset + LIMIT, total)} of {total}
          </span>
          <Btn accent={accent} disabled={offset + LIMIT >= total} onClick={() => setOffset(offset + LIMIT)}>Next</Btn>
        </div>
      )}
    </div>
  );
}

AuditView.propTypes = {
  selectedProject: PropTypes.string,
  accent: PropTypes.string,
};
