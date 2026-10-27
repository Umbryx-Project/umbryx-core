import { useState, useEffect, useCallback } from 'react';
import PropTypes from 'prop-types';
import { EE_INFRA_TABS } from '@ee';
import { api } from '../../api.js';
import { toastError } from '../../components/Toast.jsx';
import { Btn, Select, EmptyState, SectionTitle, Badge, Overline, PALETTE, FONTS, TYPE, LOG_ROW_STYLE, LOG_HEADER_STYLE, logRowHover, logRowUnhover } from '../../components/UI.jsx';

const DEVOPS_GRID = '96px 64px 150px 1fr 100px';

const LEVEL_COLORS = {
  error: '#e5484d',
  warn: '#f5a623',
  info: '#5e9eff',
  debug: '#606570',
};

const CATEGORY_LABELS = {
  deploy: 'Deploy',
  destroy: 'Destroy',
  rollback: 'Rollback',
  error: 'Error',
  dns: 'DNS',
  vpn: 'VPN',
  firewall: 'Firewall',
  lifecycle: 'Lifecycle',
  config: 'Config',
  infra: 'Infra',
};

export default function DevOpsLogSection({ accent }) {
  const [entries, setEntries] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [filters, setFilters] = useState({ level: '', category: '' });
  const [stacks, setStacks] = useState([]);
  const [selectedStack, setSelectedStack] = useState('');
  const [autoRefresh, setAutoRefresh] = useState(true);

  const load = useCallback(async () => {
    try {
      const params = [];
      if (selectedStack) params.push(`stack_id=${selectedStack}`);
      if (filters.level) params.push(`level=${filters.level}`);
      if (filters.category) params.push(`category=${filters.category}`);
      const r = await api.getDevOpsLog(params.join('&'));
      setEntries(r.entries || []);
      setTotal(r.total || 0);
    } catch (e) {
      toastError(e.message);
    }
    setLoading(false);
  }, [selectedStack, filters]);

  useEffect(() => { load(); }, [load]);

  // Stacks are an Enterprise concept and GET /infra-v2/stacks is served only
  // there, so Community does not ask: the filter below is simply not shown.
  useEffect(() => {
    if (!EE_INFRA_TABS.length) return;
    (async () => {
      try { setStacks(await api.getInfraStacks()); } catch { /* keep the filter empty */ }
    })();
  }, []);

  useEffect(() => {
    globalThis.dispatchEvent(new CustomEvent('rt:set-view', { detail: { view: 'infra-devops' } }));
    return () => {
      globalThis.dispatchEvent(new CustomEvent('rt:set-view', { detail: { view: null } }));
    };
  }, []);

  const onStack = useCallback(() => { load(); }, [load]);
  useEffect(() => {
    globalThis.addEventListener('rt:infra-stack', onStack);
    globalThis.addEventListener('rt:infra-step', onStack);
    return () => {
      globalThis.removeEventListener('rt:infra-stack', onStack);
      globalThis.removeEventListener('rt:infra-step', onStack);
    };
  }, [onStack]);

  useEffect(() => {
    if (!autoRefresh) return;
    const timer = setInterval(load, 3000);
    return () => clearInterval(timer);
  }, [autoRefresh, load]);

  if (loading) return <div style={{ color: PALETTE.textMute, padding: 20, fontSize: TYPE.body }}>Loading...</div>;

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
        <SectionTitle>DevOps Log ({total})</SectionTitle>
        <div style={{ flex: 1 }} />
        <Btn
          variant={autoRefresh ? 'solid' : 'ghost'} accent={accent} icon="refresh"
          onClick={() => setAutoRefresh(!autoRefresh)}
        >
          {autoRefresh ? 'Auto' : 'Manual'}
        </Btn>
      </div>

      <div style={{ display: 'flex', gap: 8, marginBottom: 10 }}>
        {stacks.length > 0 && (
          <Select
            label="Stack"
            value={selectedStack}
            onChange={setSelectedStack}
            placeholder="All stacks"
            options={[{ value: '', label: 'All stacks' }, ...stacks.map(s => ({ value: s.id, label: s.name }))]}
          />
        )}
        <Select
          label="Level"
          value={filters.level}
          onChange={v => setFilters({ ...filters, level: v })}
          placeholder="All levels"
          options={[
            { value: '', label: 'All levels' },
            { value: 'error', label: 'Error' },
            { value: 'warn', label: 'Warning' },
            { value: 'info', label: 'Info' },
          ]}
        />
        <Select
          label="Category"
          value={filters.category}
          onChange={v => setFilters({ ...filters, category: v })}
          placeholder="All categories"
          options={[
            { value: '', label: 'All categories' },
            ...Object.entries(CATEGORY_LABELS).map(([k, v]) => ({ value: k, label: v })),
          ]}
        />
      </div>

      {entries.length === 0 ? (
        <EmptyState icon="list" title="No log entries"
          hint="Project and workstation operations write here, as does deploying a stack." />
      ) : (
        <div style={{ border: `1px solid ${PALETTE.border}`, borderRadius: 6, overflow: 'hidden', maxHeight: 'calc(100vh - 280px)', display: 'flex', flexDirection: 'column' }}>
          <div style={{ display: 'grid', gridTemplateColumns: DEVOPS_GRID, gap: 10, flexShrink: 0, ...LOG_HEADER_STYLE }}>
            <span>Time</span><span>Level</span><span>Category</span><span>Message</span><span>Actor</span>
          </div>
          <div style={{ overflow: 'auto' }}>
            {entries.map((e, i) => {
              const color = LEVEL_COLORS[e.level] || PALETTE.textFaint;
              return (
                <div key={e.id || i}
                  style={{ display: 'grid', gridTemplateColumns: DEVOPS_GRID, gap: 10, alignItems: 'start', ...LOG_ROW_STYLE }}
                  onMouseEnter={logRowHover} onMouseLeave={logRowUnhover}>
                  <span style={{ color: PALETTE.textFaint }}>
                    {e.created_at?.slice(11, 19)}
                  </span>
                  <span style={{ color, fontWeight: 700, textTransform: 'uppercase', fontSize: 11, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {e.level}
                  </span>
                  <span style={{ color: PALETTE.textFaint, fontSize: 12, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={e.category || ''}>
                    {CATEGORY_LABELS[e.category] || e.category}
                  </span>
                  <span style={{ color: e.level === 'error' ? PALETTE.danger : PALETTE.textDim, wordBreak: 'break-word' }}>
                    {e.message}
                  </span>
                  <span style={{ color: accent, fontSize: 12, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={e.actor || ''}>
                    {e.actor || '—'}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}

    </div>
  );
}

DevOpsLogSection.propTypes = { accent: PropTypes.string };
