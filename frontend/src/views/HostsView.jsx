import PropTypes from 'prop-types';
import { useMemo, useState, useEffect, useCallback, useDeferredValue, useRef } from 'react';
import Icon from '../components/Icon.jsx';
import { HostStatusBadge, SearchBar, FieldInput, Badge, TagEditor, PALETTE, FONTS, Checkbox, Select } from '../components/UI.jsx';
import { NODE_STATUS, OS_ICONS, PORT_SERVICES, serviceColor } from '../constants.js';
import C2HostActionsPanel from '../components/C2HostActionsPanel.jsx';
import BulkRunPanel from '../components/BulkRunPanel.jsx';
import CredPanel from '../components/CredPanel.jsx';
import HostNotesPanel, { useAddHostNote } from '../components/HostNotesPanel.jsx';
import { api } from '../api.js';
import { toastError } from '../components/Toast.jsx';
import { getCredBadges, getHostBadges, summarizeCreds, HOST_ROLES, normalizeDomain, domainsMatch } from '../utils/hostMeta.js';
import { toggleId, updateIpAtIndex, removeIpAtIndex, resolvedLinkType, hostRowBg, hostRowBorderLeft, ACTIVITY_TYPES, ACTIVITY_STATUS } from '../utils/hosts.js';
import { useColumnResize } from '../hooks/useColumnResize.js';
import CollectionSelector from '../components/CollectionSelector.jsx';
import EngagementBlock from '../components/EngagementBlock.jsx';
import { useProjectPermissions } from '../context/ProjectPermissions.jsx';
import { RiskScoreBadge, RiskScoreBreakdown } from '../components/RiskScoreBadge.jsx';
import { ScanDiffPanel } from '../components/ScanDiffPanel.jsx';
import BurnChecklist from '../components/BurnChecklist.jsx';
import { uiConfirm } from '../components/Confirm.jsx';

function ColHeader({ label, field, w = 100, sortBy, onSort, accent, onResize, fs }) {
  return (
    <div style={{ width: w || undefined, flex: w ? undefined : 1, flexShrink: 0, fontSize: Math.max(9, fs - 4), color: sortBy === field ? accent : PALETTE.textGhost, textTransform: 'uppercase', letterSpacing: '0.1em', userSelect: 'none', display: 'flex', alignItems: 'center', gap: 4, position: 'relative', minWidth: 0 }}>
      <button type="button" onClick={() => onSort(field)} style={{ cursor: 'pointer', display: 'inline-flex', alignItems: 'center', gap: 4, background: 'transparent', border: 'none', padding: 0, color: 'inherit', font: 'inherit', textTransform: 'inherit', letterSpacing: 'inherit' }}>{label}{sortBy === field && <span style={{ color: accent }}>↑</span>}</button>
      {w ? <button type="button" onMouseDown={(e) => onResize(field, e)} style={{ position: 'absolute', right: -6, top: -8, bottom: -8, width: 12, cursor: 'col-resize', background: 'none', border: 'none', padding: 0, outline: 'none' }} /> : null}
    </div>
  );
}

ColHeader.propTypes = {
  label: PropTypes.string,
  field: PropTypes.string,
  w: PropTypes.number,
  sortBy: PropTypes.string,
  onSort: PropTypes.func,
  accent: PropTypes.string,
  onResize: PropTypes.func,
  fs: PropTypes.number,
};

const TRANSPORT_META = {
  c2:     { label: 'C2 beacon',   color: PALETTE.ok, title: 'Active C2 session — will route via C2 exec' },
  socks:  { label: 'Pivot SOCKS', color: PALETTE.warn, title: 'Active pivot observation — exec will use proxychains' },
  direct: { label: 'Direct SSH',  color: '#4f8ef7', title: 'No live session or pivot; plain SSH from attacker' },
};

function TransportBadge({ hostId }) {
  const [advice, setAdvice] = useState(null);
  const [loading, setLoading] = useState(false);
  const loadedFor = useRef(null);

  useEffect(() => {
    if (!hostId || loadedFor.current === hostId) return;
    loadedFor.current = hostId;
    setLoading(true);
    api.getHostTransport(hostId)
      .then(r => setAdvice(r))
      .catch(() => setAdvice(null))
      .finally(() => setLoading(false));
  }, [hostId]);

  if (loading) return <div style={{ fontSize: 9, color: PALETTE.textGhost, fontFamily: FONTS.mono }}>Checking transport…</div>;
  if (!advice) return null;
  const meta = TRANSPORT_META[advice.method] || TRANSPORT_META.direct;
  return (
    <div style={{ background: '#0a0c10', border: `1px solid ${meta.color}33`, borderRadius: 4, padding: '7px 9px' }} title={meta.title}>
      <div style={{ fontSize: 9, color: PALETTE.textGhost, textTransform: 'uppercase', marginBottom: 4 }}>Transport path</div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
        <span style={{ fontSize: 9, color: meta.color, background: meta.color + '18', border: `1px solid ${meta.color}44`, borderRadius: 3, padding: '1px 6px', fontFamily: FONTS.mono }}>{meta.label}</span>
        <span style={{ fontSize: 9, color: '#505560', fontFamily: FONTS.mono }}>{advice.reason}</span>
      </div>
      {advice.method === 'socks' && advice.socks_host && (
        <div style={{ marginTop: 4, fontSize: 9, color: PALETTE.textFaint, fontFamily: FONTS.mono }}>
          via {advice.socks_host}:{advice.socks_port} ({advice.route_cidr})
        </div>
      )}
    </div>
  );
}
TransportBadge.propTypes = { hostId: PropTypes.string };

export default function HostsView({ hosts, creds, hostActivities = [], notes = [], onAdd, onUpdate, onDelete, onAddActivity, onUpdateActivity, onDeleteActivity, onAddNote, onUpdateNote, selectedProject, accent, onImport, onAddCred, fs = 14, focusId, consumeFocusId, onNavigate }) {
  const { can } = useProjectPermissions();
  const [search, setSearch] = useState('');
  const [filterStatus, setFilterStatus] = useState(null);
  const [sortBy, setSortBy] = useState('ip');
  const [selected, setSelected] = useState(null);
  const [showAdd, setShowAdd] = useState(false);
  const [newHost, setNewHost] = useState({ ip: '', hostname: '', os: 'Linux', status: 'unknown', ports: '', services: '', tags: '' });
  const [selectedIds, setSelectedIds] = useState([]);
  const [showBulkEdit, setShowBulkEdit] = useState(false);
  const [showBulkRun, setShowBulkRun] = useState(false);
  const [filterTag, setFilterTag] = useState(null);
  const [bulkOs, setBulkOs] = useState('');
  const [bulkStatus, setBulkStatus] = useState('');
  const [bulkTags, setBulkTags] = useState('');
  const [draftPorts, setDraftPorts] = useState([]);
  const [draftServices, setDraftServices] = useState([]);
  const [newActivity, setNewActivity] = useState({ title: '', activity_type: 'recon', command: '', summary: '', output: '', status: 'done' });
  const [editingActivityId, setEditingActivityId] = useState(null);
  const [showActivityComposer, setShowActivityComposer] = useState(false);
  const [activityTypeFilter, setActivityTypeFilter] = useState(null);
  const [activityStatusFilter, setActivityStatusFilter] = useState(null);
  const [editCell, setEditCell] = useState(null);
  const [editValue, setEditValue] = useState('');
  const [panelTab, setPanelTab] = useState('details');
  const [burnHostId, setBurnHostId] = useState(null);
  const [lateralPaths, setLateralPaths] = useState(null);
  const [lateralLoading, setLateralLoading] = useState(false);
  const [riskScores, setRiskScores] = useState({});
  const [engagement, setEngagement] = useState({ engagement: {} });

  const { widths, startResize } = useColumnResize({ ip: 120, hostname: 140, os: 110, status: 160, services: 0, creds: 70, tags: 140 });
  const colBorder = '1px solid #14161b';

  const projectHosts = useMemo(
    () => hosts.filter(h => h.pid === selectedProject),
    [hosts, selectedProject],
  );
  const deferredSearch = useDeferredValue(search);

  useEffect(() => {
    setLateralPaths(null);
  }, [selected]);

  useEffect(() => {
    if (!selectedProject) return;
    api.getRiskScores(selectedProject).then(setRiskScores).catch(() => {});
  }, [selectedProject, hosts]);

  // Deconfliction: who is working on which host (soft claims + running jobs)
  const loadEngagement = () => {
    if (!selectedProject) return;
    api.getDeconfliction(selectedProject).then(setEngagement).catch(() => {});
  };
  useEffect(() => {
    loadEngagement();
    const t = setInterval(loadEngagement, 30000);
    return () => clearInterval(t);
  }, [selectedProject]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!focusId || !projectHosts.length) return;
    const found = projectHosts.find(h => h.id === focusId);
    if (found) {
      setSelected(focusId);
      requestAnimationFrame(() => {
        document.getElementById(`host-${focusId}`)?.scrollIntoView({ behavior: 'smooth', block: 'center' });
      });
      consumeFocusId?.();
    }
  }, [focusId, projectHosts]);
  const getHostCredCount = (host) => {
    const hostDomain = normalizeDomain(host.domain || '');
    return (creds || []).filter(c => c.pid === selectedProject && (
      c.host === host.ip ||
      (host.hostname && c.host === host.hostname) ||
      (c.host_ids || []).includes(host.id) ||
      (c.is_domain && hostDomain && domainsMatch(c.domain || '', hostDomain))
    )).length;
  };
  const getSortValue = (host) => {
    if (sortBy === 'credCount') return getHostCredCount(host);
    if (sortBy === 'tagText') return (host.tags || []).join(' ');
    return host[sortBy] || '';
  };
  const hostTagCounts = useMemo(() => {
    const counts = new Map();
    projectHosts.forEach(h => (h.tags || []).forEach(tag => counts.set(tag, (counts.get(tag) || 0) + 1)));
    return [...counts.entries()].sort((a, b) => b[1] - a[1]);
  }, [projectHosts]);
  const filtered = useMemo(() => {
    const needle = deferredSearch ? deferredSearch.toLowerCase() : '';
    return projectHosts
      .filter(h => !filterStatus || h.status === filterStatus)
      .filter(h => !filterTag || (h.tags || []).includes(filterTag))
      .filter(h => !needle || [h.ip, h.hostname, (h.tags || []).join(' ')].join(' ').toLowerCase().includes(needle))
      .sort((a, b) => {
        const av = getSortValue(a);
        const bv = getSortValue(b);
        if (typeof av === 'number' || typeof bv === 'number') return Number(av) - Number(bv);
        return String(av).localeCompare(String(bv));
      });
  }, [projectHosts, filterStatus, filterTag, deferredSearch, sortBy, creds]);

  const selHost = projectHosts.find(h => h.id === selected);
  const hostCreds = useMemo(() => {
    if (!selHost) return [];
    const isDomainHost = !!selHost.domain?.trim();
    const hostDomain = normalizeDomain(selHost.domain || '');
    return (creds || []).filter(c => c.pid === selectedProject && (
      (c.host_ids || []).includes(selHost.id) ||
      c.host === selHost.ip ||
      (selHost.hostname && c.host === selHost.hostname) ||
      (c.is_domain && hostDomain && domainsMatch(c.domain || '', hostDomain))
    )).map(c => {
      const linkedByIds = (c.host_ids || []).includes(selHost.id);
      const linkedByIp = c.host === selHost.ip || (selHost.hostname && c.host === selHost.hostname);
      const linkTypeResult = resolvedLinkType(linkedByIds, linkedByIp, isDomainHost);
      return {
        ...c,
        _linkType: linkTypeResult,
      };
    });
  }, [creds, selHost, selectedProject]);
  const hostCredSummary = useMemo(() => summarizeCreds(hostCreds), [hostCreds]);
  const selHostActivities = useMemo(() => {
    if (!selHost) return [];
    return hostActivities
      .filter(a => a.host_id === selHost.id)
      .filter(a => !activityTypeFilter || a.activity_type === activityTypeFilter)
      .filter(a => !activityStatusFilter || a.status === activityStatusFilter)
      .sort((a, b) => String(b.ts || '').localeCompare(String(a.ts || '')));
  }, [hostActivities, selHost, activityTypeFilter, activityStatusFilter]);
  const selHostNotes = useMemo(() => {
    if (!selHost) return [];
    return notes
      .filter(n => n.host_id === selHost.id && n.pid === selectedProject)
      .sort((a, b) => String(b.ts || '').localeCompare(String(a.ts || '')));
  }, [notes, selHost, selectedProject]);

  const [addingNote, addHostNote] = useAddHostNote({
    selectedProject, hostId: selHost?.id, hostLabel: selHost?.hostname || selHost?.ip || '',
    onAddNote, onNavigate,
  });

  useEffect(() => {
    if (selHost) {
      setDraftPorts(selHost.ports || []);
      setDraftServices(selHost.services || []);
    }
  }, [selHost?.id]);

  const savePortsServices = (ports, services) => {
    const maxLen = Math.max(ports.length, services.length);
    const cleanPorts = [];
    const cleanServices = [];
    for (let i = 0; i < maxLen; i++) {
      const p = ports[i] || '';
      const s = services[i] || '';
      if (p || s) { cleanPorts.push(p); cleanServices.push(s); }
    }
    onUpdate(selHost.id, { ports: cleanPorts, services: cleanServices });
    setDraftPorts(cleanPorts);
    setDraftServices(cleanServices);
  };

  const addHost = () => {
    onAdd({
      pid: selectedProject,
      ...newHost,
      ports: newHost.ports.split(',').map(p => p.trim()).filter(Boolean),
      services: newHost.services.split(',').map(s => s.trim()).filter(Boolean),
      tags: newHost.tags.split(',').map(t => t.trim()).filter(Boolean),
    });
    setNewHost({ ip: '', hostname: '', os: 'Linux', status: 'unknown', ports: '', services: '', tags: '' });
    setShowAdd(false);
  };

  useEffect(() => {
    if (!editCell) return;
    const handler = (e) => {
      if (!e.target.closest('[data-inline-edit]')) setEditCell(null);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [editCell]);

  const startEdit = useCallback((e, host, field) => {
    e.stopPropagation();
    setEditCell({ hostId: host.id, field });
    setEditValue(host[field] || '');
  }, []);

  const commitEdit = useCallback((host, field, value) => {
    setEditCell(null);
    const trimmed = value.trim();
    if (trimmed !== (host[field] || '').trim()) {
      onUpdate(host.id, { [field]: trimmed });
    }
  }, [onUpdate]);

  const cancelEdit = useCallback(() => setEditCell(null), []);

  const colProps = { sortBy, onSort: setSortBy, accent, onResize: startResize, fs };

  return (
    <>
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <div style={{ padding: '14px 18px', borderBottom: `1px solid ${PALETTE.borderSoft}`, background: '#0a0c10', display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
        <div style={{ flex: 1 }}>
          <span style={{ fontSize: fs + 1, fontWeight: 600, color: '#e0e4ec', fontFamily: FONTS.display }}>hosts</span>
          <span style={{ fontSize: Math.max(10, fs - 2), color: PALETTE.textGhost, marginLeft: 10 }}>{filtered.length} of {projectHosts.length}</span>
          {selectedIds.length > 0 && <span style={{ fontSize: Math.max(10, fs - 2), color: accent, marginLeft: 10, fontWeight: 600 }}>({selectedIds.length} selected)</span>}
        </div>
        {selectedIds.length > 0 && <button onClick={() => { setShowBulkRun(v => !v); setShowBulkEdit(false); }} style={{ background: '#39d35322', border: '1px solid #39d35344', borderRadius: 4, padding: '5px 12px', cursor: 'pointer', color: PALETTE.ok, fontSize: Math.max(10, fs - 3), fontWeight: 600, fontFamily: FONTS.mono, display: 'flex', alignItems: 'center', gap: 5 }}><Icon name="terminal" size={10} color="currentColor" /> Bulk Run</button>}
        {selectedIds.length > 0 && can('hosts.update') && <button onClick={() => { setShowBulkEdit(v => !v); setShowBulkRun(false); }} style={{ background: accent, border: 'none', borderRadius: 4, padding: '5px 12px', cursor: 'pointer', color: '#fff', fontSize: Math.max(10, fs - 3), fontWeight: 600, fontFamily: FONTS.mono, display: 'flex', alignItems: 'center', gap: 5 }}><Icon name="terminal" size={10} color="#fff" /> Bulk edit</button>}
        {selectedIds.length > 0 && can('hosts.delete') && <button onClick={async () => {
          if (!await uiConfirm(`Delete ${selectedIds.length} selected host(s)?`)) return;
          for (const id of selectedIds) await onDelete(id);
          setSelectedIds([]);
          setSelected(null);
          setShowBulkEdit(false);
        }} style={{ background: 'transparent', border: '1px solid #cc223366', borderRadius: 4, padding: '5px 12px', cursor: 'pointer', color: PALETTE.danger, fontSize: Math.max(10, fs - 3), fontWeight: 600, fontFamily: FONTS.mono, display: 'flex', alignItems: 'center', gap: 5 }}><Icon name="trash" size={10} color="currentColor" /> Delete selected</button>}
        {selectedIds.length > 0 && <button onClick={() => setSelectedIds([])} style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '5px 10px', cursor: 'pointer', color: PALETTE.textFaint, fontSize: Math.max(10, fs - 3), fontFamily: FONTS.mono }}>Deselect all</button>}
        <div style={{ display: 'flex', gap: 4 }}>
          {Object.entries(NODE_STATUS).map(([k, v]) => {
            const cnt = projectHosts.filter(h => h.status === k).length;
            if (!cnt) return null;
            return <button key={k} onClick={() => setFilterStatus(filterStatus == k ? null : k)} style={{ background: filterStatus == k ? `${v.color}22` : 'transparent', border: `1px solid ${filterStatus == k ? v.color + '88' : PALETTE.border}`, borderRadius: 3, padding: '3px 8px', cursor: 'pointer', fontSize: Math.max(9, fs - 4), color: filterStatus == k ? v.color : '#505560', fontFamily: FONTS.mono }}>{v.label} <span style={{ opacity: .6 }}>{cnt}</span></button>;
          })}
        </div>
        <CollectionSelector
          pid={selectedProject}
          accent={accent}
          selectedIds={selectedIds}
          onSelect={(ids) => setSelectedIds(ids)}
          onClear={() => setSelectedIds([])}
        />
        <div style={{ width: 220 }}><SearchBar value={search} onChange={setSearch} placeholder="IP, hostname..." /></div>
        {onImport && <button onClick={onImport} style={{ background: 'transparent', border: `1px solid ${accent}66`, borderRadius: 4, padding: '5px 12px', cursor: 'pointer', color: accent, fontSize: Math.max(10, fs - 3), fontWeight: 600, fontFamily: FONTS.mono, display: 'flex', alignItems: 'center', gap: 5 }}><Icon name="export" size={10} color="currentColor" /> Import</button>}
        {can('hosts.create') && <button onClick={() => setShowAdd(v => !v)} style={{ background: accent, border: 'none', borderRadius: 4, padding: '5px 12px', cursor: 'pointer', color: '#fff', fontSize: Math.max(10, fs - 3), fontWeight: 600, fontFamily: FONTS.mono, display: 'flex', alignItems: 'center', gap: 5 }}><Icon name="plus" size={10} color="#fff" /> Add</button>}
      </div>

      {showAdd && (
        <div style={{ padding: '14px 18px', borderBottom: `1px solid ${PALETTE.borderSoft}`, background: '#0c0e13', display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'flex-end' }}>
          {[['IP', 'ip', '120px'], ['Hostname', 'hostname', '150px'], ['OS', 'os', '100px'], ['Ports', 'ports', '120px'], ['Tags', 'tags', '120px']].map(([l, k, w]) => (
            <div key={k} style={{ width: w, display: 'flex', flexDirection: 'column' }}>
              <div style={{ fontSize: Math.max(9, fs - 4), color: PALETTE.textGhost, marginBottom: 4, textTransform: 'uppercase' }}>{l}</div>
              <input value={newHost[k]} onChange={e => setNewHost(h => ({ ...h, [k]: e.target.value }))} style={{ width: '100%', background: PALETTE.bg3, border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '5px 7px', color: PALETTE.textDim, fontSize: Math.max(11, fs - 2), outline: 'none', fontFamily: FONTS.mono }} />
            </div>
          ))}
          <div style={{ display: 'flex', flexDirection: 'column' }}>
            <div style={{ fontSize: Math.max(9, fs - 4), color: PALETTE.textGhost, marginBottom: 4, textTransform: 'uppercase' }}>Status</div>
            <Select value={newHost.status} onChange={v => setNewHost(h => ({ ...h, status: v }))} style={{ fontSize: Math.max(11, fs - 2) }}
              options={Object.keys(NODE_STATUS).map(s => ({ value: s, label: NODE_STATUS[s].label }))} />
          </div>
          <button onClick={addHost} style={{ background: accent, border: 'none', borderRadius: 4, padding: '6px 14px', cursor: 'pointer', color: '#fff', fontSize: Math.max(11, fs - 2), fontWeight: 600, fontFamily: FONTS.mono, alignSelf: 'flex-end' }}>Save</button>
          <button onClick={() => setShowAdd(false)} style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 10px', cursor: 'pointer', color: PALETTE.textFaint, fontSize: Math.max(11, fs - 2), fontFamily: FONTS.mono, alignSelf: 'flex-end' }}>Cancel</button>
        </div>
      )}

      {showBulkRun && selectedIds.length > 0 && (
        <BulkRunPanel
          selectedIds={selectedIds}
          hosts={hosts}
          creds={creds}
          selectedProject={selectedProject}
          accent={accent}
          onClose={() => setShowBulkRun(false)}
        />
      )}

      {showBulkEdit && selectedIds.length > 0 && (
        <div style={{ padding: '14px 18px', borderBottom: `1px solid ${PALETTE.borderSoft}`, background: '#0c0e13', display: 'flex', gap: 10, alignItems: 'flex-end', flexWrap: 'wrap' }}>
          <div style={{ width: 120 }}>
            <div style={{ fontSize: Math.max(9, fs - 4), color: PALETTE.textGhost, marginBottom: 4, textTransform: 'uppercase' }}>OS</div>
            <Select value={bulkOs} onChange={setBulkOs} style={{ width: '100%', fontSize: Math.max(11, fs - 2) }}
              placeholder="No change"
              options={['Linux', 'Windows', 'macOS', 'Various', 'Unknown']} />
          </div>
          <div style={{ width: 140 }}>
            <div style={{ fontSize: Math.max(9, fs - 4), color: PALETTE.textGhost, marginBottom: 4, textTransform: 'uppercase' }}>Status</div>
            <Select value={bulkStatus} onChange={setBulkStatus} style={{ width: '100%', fontSize: Math.max(11, fs - 2) }}
              placeholder="No change"
              options={Object.entries(NODE_STATUS).map(([k, v]) => ({ value: k, label: v.label }))} />
          </div>
          <div style={{ width: 160 }}>
            <div style={{ fontSize: Math.max(9, fs - 4), color: PALETTE.textGhost, marginBottom: 4, textTransform: 'uppercase' }}>Add tags</div>
            <input value={bulkTags} onChange={e => setBulkTags(e.target.value)} placeholder="web, apache" style={{ width: '100%', background: PALETTE.bg3, border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '5px 7px', color: PALETTE.textDim, fontSize: Math.max(11, fs - 2), outline: 'none', fontFamily: FONTS.mono }} />
          </div>
          <button onClick={() => {
            const updates = {};
            if (bulkOs) updates.os = bulkOs;
            if (bulkStatus) updates.status = bulkStatus;
            selectedIds.forEach(id => {
              const host = hosts.find(h => h.id === id);
              const newTags = bulkTags ? [...new Set([...(host.tags || []), ...bulkTags.split(',').map(t => t.trim()).filter(Boolean)])] : host.tags;
              onUpdate(id, { ...updates, ...(bulkTags ? { tags: newTags } : {}) });
            });
            setBulkOs(''); setBulkStatus(''); setBulkTags('');
            setSelectedIds([]);
            setShowBulkEdit(false);
          }} style={{ background: accent, border: 'none', borderRadius: 4, padding: '6px 14px', cursor: 'pointer', color: '#fff', fontSize: Math.max(11, fs - 2), fontWeight: 600, fontFamily: FONTS.mono }}>Apply to {selectedIds.length} hosts</button>
          <button onClick={() => setShowBulkEdit(false)} style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 10px', cursor: 'pointer', color: PALETTE.textFaint, fontSize: Math.max(11, fs - 2), fontFamily: FONTS.mono }}>Cancel</button>
        </div>
      )}

      {hostTagCounts.length > 0 && (
        <div style={{ padding: '8px 18px', borderBottom: `1px solid ${PALETTE.borderSoft}`, background: '#0c0e13', display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
          <span style={{ fontSize: Math.max(9, fs - 4), color: PALETTE.textGhost, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Tags</span>
          {hostTagCounts.map(([tag, count]) => (
            <button key={tag} onClick={() => setFilterTag(filterTag === tag ? null : tag)}
              style={{ background: filterTag === tag ? `${accent}22` : PALETTE.bg3, border: `1px solid ${filterTag === tag ? accent + '88' : PALETTE.border}`, borderRadius: 4, padding: '3px 8px', cursor: 'pointer', color: filterTag === tag ? accent : '#808590', fontSize: Math.max(9, fs - 4), fontFamily: FONTS.mono, display: 'flex', alignItems: 'center', gap: 5 }}>
              <span>{tag}</span>
              <span style={{ opacity: 0.75 }}>{count}</span>
            </button>
          ))}
          {filterTag && <button onClick={() => setFilterTag(null)} style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '3px 8px', cursor: 'pointer', color: PALETTE.textFaint, fontSize: Math.max(9, fs - 4), fontFamily: FONTS.mono }}>Clear</button>}
        </div>
      )}

      <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
        <div style={{ flex: 1, overflowY: 'auto' }}>
          <div style={{ display: 'flex', alignItems: 'stretch', padding: '8px 16px', borderBottom: `1px solid ${PALETTE.borderSoft}`, background: '#090b0f', position: 'sticky', top: 0, zIndex: 2 }}>
            <div style={{ width: 32, flexShrink: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', borderRight: colBorder, paddingRight: 12, marginRight: 12 }}>
              <Checkbox checked={selectedIds.length === filtered.length && filtered.length > 0} accent={accent} onChange={v => setSelectedIds(v ? filtered.map(h => h.id) : [])} />
            </div>
            <div style={{ width: widths.ip, flexShrink: 0, borderRight: colBorder, paddingRight: 12, marginRight: 12 }}><ColHeader label="IP" field="ip" w={widths.ip} {...colProps} /></div>
            <div style={{ width: widths.hostname, flexShrink: 0, borderRight: colBorder, paddingRight: 12, marginRight: 12 }}><ColHeader label="Hostname" field="hostname" w={widths.hostname} {...colProps} /></div>
            <div style={{ width: widths.os, flexShrink: 0, borderRight: colBorder, paddingRight: 12, marginRight: 12 }}><ColHeader label="OS" field="os" w={widths.os} {...colProps} /></div>
            <div style={{ width: widths.status, flexShrink: 0, borderRight: colBorder, paddingRight: 12, marginRight: 12 }}><ColHeader label="Status" field="status" w={widths.status} {...colProps} /></div>
            <div style={{ flex: 1, minWidth: 0, fontSize: Math.max(9, fs - 4), color: PALETTE.textGhost, textTransform: 'uppercase', letterSpacing: '0.1em', position: 'relative', borderRight: colBorder, paddingRight: 12, marginRight: 12 }}>Services / Ports</div>
            <div style={{ width: widths.creds, flexShrink: 0, borderRight: colBorder, paddingRight: 12, marginRight: 12 }}><ColHeader label="Creds" field="credCount" w={widths.creds} {...colProps} /></div>
            <div style={{ width: widths.tags, flexShrink: 0, borderRight: colBorder, paddingRight: 12, marginRight: 12 }}><ColHeader label="Tags" field="tagText" w={widths.tags} {...colProps} /></div>
            <div style={{ width: 28 }} />
          </div>
          {filtered.length === 0 && <div style={{ padding: 32, textAlign: 'center', color: PALETTE.textGhost, fontSize: Math.max(12, fs - 1) }}>No hosts. Add the first one.</div>}
          {filtered.map(host => {
            const isSel = selected === host.id;
            const isChecked = selectedIds.includes(host.id);
            const intelBadges = getHostBadges(host);
            const credCount = getHostCredCount(host);
            const rowBg = hostRowBg(isSel, isChecked);
            const rowBorderLeft = hostRowBorderLeft(isSel, isChecked, accent);
            return (
              <button type="button" key={host.id} id={`host-${host.id}`} onClick={() => setSelected(isSel ? null : host.id)} style={{ display: 'flex', alignItems: 'stretch', minHeight: 48, padding: '9px 16px', borderBottom: '1px solid #14161b', cursor: 'pointer', background: rowBg, borderLeft: rowBorderLeft, width: '100%', textAlign: 'left', borderTop: 'none', borderRight: 'none', borderBottomStyle: 'solid', outline: 'none', color: 'inherit', font: 'inherit' }}>
                <div style={{ width: 32, flexShrink: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', borderRight: colBorder, paddingRight: 12, marginRight: 12 }}
                  onClick={e => e.stopPropagation()}>
                  <Checkbox checked={isChecked} accent={accent} onChange={v => setSelectedIds(prev => toggleId(prev, host.id, v))} />
                </div>
                <div style={{ width: widths.ip, flexShrink: 0, fontFamily: FONTS.mono, fontSize: Math.max(11, fs - 1), color: isSel ? accent : PALETTE.textMute, fontWeight: isSel ? 600 : 400, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', borderRight: colBorder, paddingRight: 12, marginRight: 12, display: 'flex', alignItems: 'center' }}>{host.ip}</div>
                {/* Hostname — inline edit on double-click */}
                <div style={{ width: widths.hostname, flexShrink: 0, minWidth: 0, borderRight: colBorder, paddingRight: 12, marginRight: 12, display: 'flex', alignItems: 'center' }}>
                  {editCell?.hostId === host.id && editCell?.field === 'hostname' ? (
                    <input
                      autoFocus
                      value={editValue}
                      onChange={e => setEditValue(e.target.value)}
                      onBlur={() => commitEdit(host, 'hostname', editValue)}
                      onKeyDown={e => { if (e.key === 'Enter') { commitEdit(host, 'hostname', editValue); } if (e.key === 'Escape') { cancelEdit(); } e.stopPropagation(); }}
                      onClick={e => e.stopPropagation()}
                      style={{ width: '100%', background: '#0a0c10', border: `1px solid ${accent}`, borderRadius: 3, padding: '2px 6px', color: '#e0e4ec', fontSize: Math.max(11, fs - 1), fontFamily: FONTS.mono, outline: 'none' }}
                    />
                  ) : (
                    <button type="button"
                      tabIndex={0}
                      onDoubleClick={e => startEdit(e, host, 'hostname')}
                      onClick={e => startEdit(e, host, 'hostname')}
                      onKeyDown={e => { if (e.key === 'Enter') { startEdit(e, host, 'hostname'); } }}
                      title="Double-click to edit"
                      style={{ fontSize: Math.max(11, fs - 1), color: PALETTE.textDim, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', cursor: 'text', width: '100%', background: 'none', border: 'none', padding: 0, font: 'inherit', textAlign: 'left', display: 'block' }}
                    >
                      {host.hostname || <span style={{ color: '#303540' }}>—</span>}
                    </button>
                  )}
                </div>

                {/* OS — inline edit on double-click */}
                <div style={{ width: widths.os, flexShrink: 0, minWidth: 0, overflow: 'hidden', borderRight: colBorder, paddingRight: 12, marginRight: 12, display: 'flex', alignItems: 'center' }}>
                  {editCell?.hostId === host.id && editCell?.field === 'os' ? (
                    <input
                      autoFocus
                      value={editValue}
                      onChange={e => setEditValue(e.target.value)}
                      onBlur={() => commitEdit(host, 'os', editValue)}
                      onKeyDown={e => { if (e.key === 'Enter') { commitEdit(host, 'os', editValue); } if (e.key === 'Escape') { cancelEdit(); } e.stopPropagation(); }}
                      onClick={e => e.stopPropagation()}
                      style={{ width: '100%', background: '#0a0c10', border: `1px solid ${accent}`, borderRadius: 3, padding: '2px 6px', color: '#e0e4ec', fontSize: Math.max(10, fs - 2), fontFamily: FONTS.mono, outline: 'none' }}
                    />
                  ) : (
                    <button type="button"
                      tabIndex={0}
                      onDoubleClick={e => startEdit(e, host, 'os')}
                      onClick={e => startEdit(e, host, 'os')}
                      onKeyDown={e => { if (e.key === 'Enter') { startEdit(e, host, 'os'); } }}
                      title="Double-click to edit"
                      style={{ fontSize: Math.max(10, fs - 2), color: PALETTE.textFaint, display: 'flex', alignItems: 'center', gap: 4, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', cursor: 'text', width: '100%', background: 'none', border: 'none', padding: 0, font: 'inherit', textAlign: 'left' }}
                    >
                      {OS_ICONS[host.os]} {host.os}
                    </button>
                  )}
                </div>

                {/* Status — click badge to get dropdown */}
                <div style={{ width: widths.status, flexShrink: 0, display: 'flex', alignItems: 'center', gap: 4, minWidth: 0, overflow: 'hidden', borderRight: colBorder, paddingRight: 12, marginRight: 12, position: 'relative' }}>
                  {editCell?.hostId === host.id && editCell?.field === 'status' ? (
                    <div data-inline-edit style={{ position: 'absolute', top: 0, left: 0, zIndex: 50, background: PALETTE.bg2, border: `1px solid ${accent}44`, borderRadius: 6, padding: 6, display: 'flex', flexDirection: 'column', gap: 2, boxShadow: '0 4px 20px #00000088', minWidth: 110 }}>
                      {Object.entries(NODE_STATUS).map(([k, v]) => (
                        <button key={k} onClick={e => { e.stopPropagation(); onUpdate(host.id, { status: k }); setEditCell(null); }}
                          style={{ background: host.status === k ? v.color + '22' : 'transparent', border: `1px solid ${host.status === k ? v.color + '66' : 'transparent'}`, borderRadius: 4, padding: '4px 8px', cursor: 'pointer', color: v.color, fontSize: 10, fontFamily: FONTS.mono, textAlign: 'left', display: 'flex', alignItems: 'center', gap: 6 }}>
                          <span style={{ width: 6, height: 6, borderRadius: '50%', background: v.color, flexShrink: 0 }} />
                          {v.label}
                        </button>
                      ))}
                      <button onClick={e => { e.stopPropagation(); setEditCell(null); }} style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: PALETTE.textGhost, fontSize: 10, padding: '2px 4px', marginTop: 2 }}>Cancel</button>
                    </div>
                  ) : null}
                  <button type="button" onClick={e => { e.stopPropagation(); setEditCell({ hostId: host.id, field: 'status' }); }} title="Click to change status" style={{ cursor: 'pointer', background: 'transparent', border: 'none', padding: 0, display: 'inline-flex' }}>
                    <HostStatusBadge status={host.status} />
                  </button>
                  {host.domain && <Badge label="AD" color="#c07af0" title={host.domain} />}
                  {riskScores[host.id] && riskScores[host.id].score >= 30 && <RiskScoreBadge hostId={host.id} score={riskScores[host.id].score} level={riskScores[host.id].level} compact />}
                  {(() => {
                    const busy = (engagement.engagement || {})[host.id];
                    if (!busy) return null;
                    const names = busy.operators.map(o => `${o.username}${o.is_me ? ' (you)' : ''} [${o.sources.join('+')}]`);
                    return (
                      <Badge color="#f09a3a" title={`Engaged: ${names.join(', ')}`}
                        label={`● ${busy.operators.map(o => o.username).join(',')}`}
                        style={{ textTransform: 'none', letterSpacing: 'normal', cursor: 'help', display: 'inline-block', maxWidth: 90, overflow: 'hidden', textOverflow: 'ellipsis' }} />
                    );
                  })()}
                </div>
                <div style={{ flex: 1, minWidth: 0, display: 'flex', alignItems: 'center', gap: 4, overflow: 'hidden', flexWrap: 'nowrap', borderRight: colBorder, paddingRight: 12, marginRight: 12 }}>
                  {(() => {
                    const svcs = host.services || [];
                    const ports = host.ports || [];
                    const maxLen = Math.max(svcs.length, ports.length);
                    if (maxLen === 0) return [<span key="empty" style={{ fontSize: Math.max(10, fs - 3), color: '#303540' }}>—</span>];
                    return Array.from({ length: Math.min(maxLen, 4) }).map((_, i) => {
                      const svc = svcs[i] || '';
                      const port = ports[i] || '';
                      const label = svc && port ? `${svc}:${port}` : svc || port;
                      const color = serviceColor(svc || PORT_SERVICES[Number.parseInt(port)] || port);
                      return <span key={`svc-${i}-${label}`} style={{ fontSize: Math.max(9, fs - 4), color, background: `${color}18`, border: `1px solid ${color}44`, borderRadius: 3, padding: '2px 6px', fontFamily: FONTS.mono, whiteSpace: 'nowrap' }}>{label}</span>;
                    }).concat(maxLen > 4 ? [<span key="more" style={{ fontSize: Math.max(9, fs - 4), color: PALETTE.textGhost, fontFamily: FONTS.mono }}>+{maxLen - 4}</span>] : []);
                  })()}
                </div>
                <div style={{ width: widths.creds, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, borderRight: colBorder, paddingRight: 12, marginRight: 12 }}>
                  {credCount > 0
                    ? <span style={{ fontSize: Math.max(9, fs - 4), color: PALETTE.ok, background: '#39d35322', border: '1px solid #39d35344', borderRadius: 3, padding: '1px 6px', fontFamily: FONTS.mono }}>{credCount}</span>
                    : <span style={{ fontSize: Math.max(9, fs - 4), color: '#303540', fontFamily: FONTS.mono }}>—</span>}
                </div>
                <div style={{ width: widths.tags, display: 'flex', gap: 3, overflow: 'hidden', alignItems: 'center', flexWrap: 'nowrap', minWidth: 0, borderRight: colBorder, paddingRight: 12, marginRight: 12 }}>
                  {intelBadges.slice(0, 2).map(b => <span key={b.label} style={{ fontSize: Math.max(9, fs - 4), color: b.color, background: `${b.color}18`, border: `1px solid ${b.color}44`, borderRadius: 3, padding: '1px 5px', whiteSpace: 'nowrap' }}>{b.label}</span>)}
                  {host.import_source && (() => {
                    const srcColors = { adaptix: '#00bcd4', mythic: '#ffa726', sliver: '#8bc34a', nmap: '#4caf50', bloodhound: '#c07af0', bh: '#c07af0' };
                    const c = srcColors[host.import_source] || '#f09a3a';
                    return <span title={`Imported from: ${host.import_source}`} style={{ fontSize: Math.max(9, fs - 4), color: c, background: `${c}18`, border: `1px solid ${c}44`, borderRadius: 3, padding: '1px 5px', whiteSpace: 'nowrap', fontFamily: FONTS.mono }}>{host.import_source}</span>;
                  })()}
                </div>
                {can('hosts.delete') && <button onClick={e => { e.stopPropagation(); onDelete(host.id); setSelected(null); }} style={{ width: 28, background: 'none', border: 'none', cursor: 'pointer', color: '#303540', display: 'flex', justifyContent: 'center' }}><Icon name="trash" size={12} color="currentColor" /></button>}
              </button>
            );
          })}
        </div>

        {selHost && (
          <div style={{ width: 300, background: '#0c0e13', borderLeft: '1px solid #1e2029', display: 'flex', flexDirection: 'column', flexShrink: 0 }}>
            {/* Panel header */}
            <div style={{ padding: '10px 14px', borderBottom: '1px solid #1e2029', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexShrink: 0 }}>
              <div>
                <span style={{ fontSize: Math.max(11, fs - 2), fontWeight: 600, color: '#e0e4ec', fontFamily: FONTS.display }}>{selHost.hostname || selHost.ip}</span>
                {selHost.hostname && <span style={{ fontSize: 9, color: PALETTE.textGhost, fontFamily: FONTS.mono, marginLeft: 6 }}>{selHost.ip}</span>}
              </div>
              <button onClick={() => setBurnHostId(selHost.id)} title="Burn host — mark compromised and get an OPSEC teardown checklist (kill C2, close pivots, rotate creds)" style={{ background: 'none', border: '1px solid #cc223344', borderRadius: 4, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4, padding: '2px 8px', color: PALETTE.danger, fontSize: 10, fontFamily: FONTS.mono, fontWeight: 600, letterSpacing: 0.3 }}>🔥 Burn</button>
              <button onClick={() => setSelected(null)} style={{ background: 'none', border: 'none', cursor: 'pointer', display: 'flex' }}><Icon name="close" size={12} color="#606570" /></button>
            </div>
            {/* Tabs */}
            <div style={{ display: 'flex', borderBottom: '1px solid #1e2029', flexShrink: 0 }}>
              {[['details', 'Details'], ['activity', 'Activity'], ['creds', 'Creds'], ['notes', 'Notes'], ['scan', 'Scan'], ['path', 'Path']].map(([key, label]) => (
                <button key={key} onClick={() => setPanelTab(key)}
                  style={{ flex: 1, background: panelTab === key ? '#ffffff0a' : 'transparent', border: 'none', borderBottom: `2px solid ${panelTab === key ? accent : 'transparent'}`, padding: '7px 4px', cursor: 'pointer', color: panelTab === key ? accent : '#505560', fontSize: 10, fontFamily: FONTS.mono, transition: 'color .15s' }}>
                  {label}
                </button>
              ))}
            </div>
            {/* Tab: Details */}
            {panelTab === 'details' && <div style={{ flex: 1, overflowY: 'auto', padding: 14, display: 'flex', flexDirection: 'column', gap: 10 }}>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
                {getHostBadges(selHost).map(b => <Badge key={b.label} label={b.label} color={b.color} />)}
              </div>
              <TransportBadge hostId={selHost.id} />
              <EngagementBlock pid={selectedProject} hostObj={selHost} />
              {hostCredSummary.total > 0 && (
                <div style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 4, padding: '7px 9px' }}>
                  <div style={{ fontSize: 9, color: PALETTE.textGhost, textTransform: 'uppercase', marginBottom: 5 }}>Known credentials</div>
                  <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                    <Badge label={`${hostCredSummary.total} linked`} color={accent} />
                    {hostCredSummary.withSecrets > 0 && <Badge label={`${hostCredSummary.withSecrets} secrets`} color="#39d353" />}
                    {hostCredSummary.passwords > 0 && <Badge label={`${hostCredSummary.passwords} passwords`} color="#5b8af5" />}
                    {hostCredSummary.hashes > 0 && <Badge label={`${hostCredSummary.hashes} hashes`} color="#c07af0" />}
                    {hostCredSummary.keys > 0 && <Badge label={`${hostCredSummary.keys} keys/tokens`} color="#f09a3a" />}
                  </div>
                </div>
              )}
              <div>
                <div style={{ fontSize: 9, color: PALETTE.textGhost, marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span>IP / CIDR addresses</span>
                  <button onClick={() => {
                    // Get current IPs, fallback to ip field if ips is empty
                    let currentIps = selHost.ips?.length > 0 ? [...selHost.ips] : [];
                    if (!currentIps.length && selHost.ip) currentIps = [selHost.ip];
                    onUpdate(selHost.id, { ips: [...currentIps, ''] });
                  }} style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 3, padding: '2px 6px', cursor: 'pointer', color: PALETTE.textFaint, fontSize: 9, fontFamily: FONTS.mono }}>+ Add</button>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {(() => {
                    // Get current IPs for display
                    let baseDisplayIps = selHost.ips?.length > 0 ? selHost.ips : [];
                    let displayIps;
                    if (baseDisplayIps.length > 0) { displayIps = baseDisplayIps; }
                    else if (selHost.ip) { displayIps = [selHost.ip]; }
                    else { displayIps = ['']; }
                    return displayIps.map((ip, i) => (
                      <div key={`ip-${i}`} style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
                        <input value={ip || ''} onChange={e => onUpdate(selHost.id, updateIpAtIndex(selHost, i, e.target.value))} placeholder="192.168.1.1 or 10.10.10.0/24" style={{ flex: 1, background: PALETTE.bg3, border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '5px 8px', color: PALETTE.textDim, fontSize: Math.max(10, fs - 3), outline: 'none', fontFamily: FONTS.mono }} />
                        {displayIps.length > 1 && (
                          <button onClick={() => onUpdate(selHost.id, removeIpAtIndex(selHost, i))} style={{ background: 'transparent', border: 'none', cursor: 'pointer', padding: 2, display: 'flex' }}>
                            <Icon name="trash" size={11} color="#404550" />
                          </button>
                        )}
                      </div>
                    ));
                  })()}
                </div>
              </div>
              <FieldInput label="Hostname" value={selHost.hostname} onChange={v => onUpdate(selHost.id, { hostname: v })} placeholder="server-01" />
              <div>
                <div style={{ fontSize: 9, color: PALETTE.textGhost, marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span>Domain</span>
                  {selHost.domain && <span style={{ fontSize: 8, color: '#c07af0', background: '#c07af018', border: '1px solid #c07af044', borderRadius: 3, padding: '1px 5px', fontFamily: FONTS.mono }}>joined</span>}
                </div>
                <input
                  value={selHost.domain || ''}
                  onChange={e => onUpdate(selHost.id, { domain: e.target.value })}
                  placeholder="acme.local (leave empty if not domain-joined)"
                  style={{ width: '100%', background: PALETTE.bg3, border: `1px solid ${selHost.domain ? '#c07af066' : PALETTE.border}`, borderRadius: 4, padding: '5px 8px', color: selHost.domain ? '#c07af0' : PALETTE.textDim, fontSize: Math.max(10, fs - 3), outline: 'none', fontFamily: FONTS.mono, boxSizing: 'border-box' }}
                />
              </div>
              <div>
                <div style={{ fontSize: 9, color: PALETTE.textGhost, marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>OS</div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>{['Linux', 'Windows', 'macOS', 'Various', 'Unknown'].map(os => <button key={os} onClick={() => onUpdate(selHost.id, { os })} style={{ background: selHost.os === os ? `${accent}22` : PALETTE.bg3, border: `1px solid ${selHost.os === os ? accent + '77' : PALETTE.border}`, borderRadius: 3, padding: '3px 9px', cursor: 'pointer', color: selHost.os === os ? accent : PALETTE.textFaint, fontSize: Math.max(10, fs - 3), fontFamily: FONTS.mono }}>{OS_ICONS[os] || '?'} {os}</button>)}</div>
              </div>
              <div>
                <div style={{ fontSize: 9, color: PALETTE.textGhost, marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Role</div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                  {Object.entries(HOST_ROLES).map(([role, meta]) => <button key={role} onClick={() => onUpdate(selHost.id, { role, is_attacker: role === 'attacker' })} style={{ background: selHost.role === role ? `${meta.color}22` : PALETTE.bg3, border: `1px solid ${selHost.role === role ? meta.color + '77' : PALETTE.border}`, borderRadius: 3, padding: '3px 9px', cursor: 'pointer', color: selHost.role === role ? meta.color : PALETTE.textFaint, fontSize: Math.max(10, fs - 3), fontFamily: FONTS.mono }}>{meta.label}</button>)}
                </div>
              </div>
              <div>
                <div style={{ fontSize: 9, color: PALETTE.textGhost, marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Status</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>{Object.entries(NODE_STATUS).map(([k, v]) => <button key={k} onClick={() => onUpdate(selHost.id, { status: k })} style={{ background: selHost.status === k ? `${v.color}18` : 'transparent', border: `1px solid ${selHost.status === k ? v.color + '66' : PALETTE.border}`, borderRadius: 4, padding: '4px 8px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 7, textAlign: 'left' }}><span style={{ width: 6, height: 6, borderRadius: '50%', background: v.color, flexShrink: 0 }} /><span style={{ fontSize: Math.max(10, fs - 3), color: selHost.status === k ? v.color : PALETTE.textFaint, fontFamily: FONTS.mono }}>{v.label}</span></button>)}</div>
              </div>
              <div>
                <div style={{ fontSize: 9, color: PALETTE.textGhost, marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span>Ports and Services</span>
                  <button onClick={() => {
                    setDraftPorts(p => [...p, '']);
                    setDraftServices(s => [...s, '']);
                  }} style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 3, padding: '2px 6px', cursor: 'pointer', color: PALETTE.textFaint, fontSize: 9, fontFamily: FONTS.mono }}>+ Add</button>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {draftPorts.length === 0 && draftServices.length === 0 && (
                    <div style={{ fontSize: Math.max(10, fs - 3), color: PALETTE.textGhost, fontStyle: 'italic' }}>No ports or services</div>
                  )}
                  {Array.from({ length: Math.max(draftPorts.length, draftServices.length) }).map((_, i) => (
                    <div key={`portsvc-${i}`} style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
                      <input
                        value={draftPorts[i] ?? ''}
                        onChange={e => {
                          const val = e.target.value;
                          setDraftPorts(prev => { const n = [...prev]; while (n.length <= i) { n.push(''); } n[i] = val; return n; });
                          // Auto-fill service name from port if service is empty
                          const suggested = PORT_SERVICES[Number.parseInt(val)];
                          if (suggested && !(draftServices[i] || '').trim()) {
                            setDraftServices(prev => { const n = [...prev]; while (n.length <= i) { n.push(''); } n[i] = suggested; return n; });
                          }
                        }}
                        onBlur={() => savePortsServices(draftPorts, draftServices)}
                        placeholder="Port"
                        style={{ width: 70, flexShrink: 0, background: PALETTE.bg3, border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '4px 6px', color: PALETTE.textDim, fontSize: Math.max(10, fs - 3), outline: 'none', fontFamily: FONTS.mono }}
                      />
                      <input
                        value={draftServices[i] ?? ''}
                        onChange={e => setDraftServices(prev => { const n = [...prev]; while (n.length <= i) { n.push(''); } n[i] = e.target.value; return n; })}
                        onBlur={() => savePortsServices(draftPorts, draftServices)}
                        placeholder="HTTP, SSH, SMB..."
                        style={{ flex: 1, minWidth: 0, background: PALETTE.bg3, border: `1px solid ${serviceColor(draftServices[i] || '') === '#606570' ? '#2a2d35' : serviceColor(draftServices[i] || '') + '55'}`, borderRadius: 4, padding: '4px 6px', color: draftServices[i] ? serviceColor(draftServices[i]) : PALETTE.textFaint, fontSize: Math.max(10, fs - 3), outline: 'none', fontFamily: FONTS.mono, transition: 'border-color .15s, color .15s' }}
                      />
                      <button onClick={() => {
                        const nextPorts = draftPorts.filter((_, idx) => idx !== i);
                        const nextServices = draftServices.filter((_, idx) => idx !== i);
                        setDraftPorts(nextPorts);
                        setDraftServices(nextServices);
                        savePortsServices(nextPorts, nextServices);
                      }} style={{ background: 'transparent', border: 'none', cursor: 'pointer', padding: 2, display: 'flex', flexShrink: 0 }}>
                        <Icon name="trash" size={11} color="#404550" />
                      </button>
                    </div>
                  ))}
                </div>
              </div>
              <TagEditor label="Tags" tags={selHost.tags || []} onChange={tags => onUpdate(selHost.id, { tags })} placeholder="nginx, rce" />
              <div>
                <div style={{ fontSize: 9, color: PALETTE.textGhost, marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.06em' }}>Notes</div>
                <HostNotesPanel
                  notes={selHostNotes}
                  canAdd={can('notes.create')}
                  adding={addingNote}
                  onAdd={addHostNote}
                  onSelect={id => onNavigate?.('notes', id)}
                  limit={2}
                  onShowAll={() => setPanelTab('notes')}
                  emptyLabel="No notes attached to this host yet"
                />
              </div>
              <C2HostActionsPanel pid={selectedProject} host={selHost} accent={accent} />
              {(selHostActivities.length > 0 || hostCreds.length > 0) && (
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                  {selHostActivities.length > 0 && (
                    <button onClick={() => onNavigate?.('findings')} style={{ background: 'transparent', border: `1px solid ${accent}55`, borderRadius: 4, padding: '4px 10px', cursor: 'pointer', color: accent, fontSize: 9, fontFamily: FONTS.mono }}>View findings for this host</button>
                  )}
                  {hostCreds.length > 0 && (
                    <button onClick={() => onNavigate?.('creds')} style={{ background: 'transparent', border: '1px solid #39d35355', borderRadius: 4, padding: '4px 10px', cursor: 'pointer', color: PALETTE.ok, fontSize: 9, fontFamily: FONTS.mono }}>View creds</button>
                  )}
                </div>
              )}
            </div>}

            {/* Tab: Activity */}
            {panelTab === 'activity' && <div style={{ flex: 1, overflowY: 'auto', padding: 14 }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
                  <div style={{ fontSize: 9, color: PALETTE.textGhost, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Host activity log</div>
                  <button onClick={() => {
                    setShowActivityComposer(v => !v);
                    if (!showActivityComposer && !editingActivityId) setNewActivity({ title: '', activity_type: 'recon', command: '', summary: '', output: '', status: 'done' });
                  }} style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '4px 8px', cursor: 'pointer', color: '#808590', fontSize: 9, fontFamily: FONTS.mono }}>{showActivityComposer || editingActivityId ? 'Hide form' : 'Add activity'}</button>
                </div>
                <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap', marginBottom: 8 }}>
                  {Object.entries(ACTIVITY_TYPES).map(([key, meta]) => (
                    <button key={key} onClick={() => setActivityTypeFilter(activityTypeFilter == key ? null : key)} style={{ background: activityTypeFilter == key ? `${meta.color}22` : 'transparent', border: `1px solid ${activityTypeFilter == key ? meta.color + '88' : PALETTE.border}`, borderRadius: 3, padding: '2px 7px', cursor: 'pointer', color: activityTypeFilter == key ? meta.color : PALETTE.textFaint, fontSize: 9, fontFamily: FONTS.mono }}>{meta.label}</button>
                  ))}
                </div>
                <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap', marginBottom: 10 }}>
                  {Object.entries(ACTIVITY_STATUS).map(([key, meta]) => (
                    <button key={key} onClick={() => setActivityStatusFilter(activityStatusFilter == key ? null : key)} style={{ background: activityStatusFilter == key ? `${meta.color}22` : 'transparent', border: `1px solid ${activityStatusFilter == key ? meta.color + '88' : PALETTE.border}`, borderRadius: 3, padding: '2px 7px', cursor: 'pointer', color: activityStatusFilter == key ? meta.color : PALETTE.textFaint, fontSize: 9, fontFamily: FONTS.mono }}>{meta.label}</button>
                  ))}
                  {(activityTypeFilter || activityStatusFilter) && <button onClick={() => { setActivityTypeFilter(null); setActivityStatusFilter(null); }} style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 3, padding: '2px 7px', cursor: 'pointer', color: PALETTE.textFaint, fontSize: 9, fontFamily: FONTS.mono }}>Clear</button>}
                </div>
                {(showActivityComposer || editingActivityId) && <div style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 6, padding: 10, marginBottom: 10 }}>
                  <input value={newActivity.title} onChange={e => setNewActivity(a => ({ ...a, title: e.target.value }))} placeholder="Title: SMB enum, nmap, exploit run..." style={{ width: '100%', background: PALETTE.bg3, border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 8px', color: PALETTE.textDim, fontSize: 10, outline: 'none', fontFamily: FONTS.mono, boxSizing: 'border-box', marginBottom: 6 }} />
                  <div style={{ display: 'flex', gap: 6, marginBottom: 6 }}>
                    <Select value={newActivity.activity_type} onChange={v => setNewActivity(a => ({ ...a, activity_type: v }))} style={{ flex: 1, minWidth: 0 }}
                      options={['recon','scan','exploit','privesc','lateral','postex','note']} />
                    <Select value={newActivity.status} onChange={v => setNewActivity(a => ({ ...a, status: v }))} style={{ flex: 1, minWidth: 0 }}
                      options={['planned','running','done','failed']} />
                  </div>
                  <textarea value={newActivity.command} onChange={e => setNewActivity(a => ({ ...a, command: e.target.value }))} placeholder="Command or technique used" rows={2} style={{ width: '100%', background: PALETTE.bg3, border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 8px', color: PALETTE.textDim, fontSize: 10, outline: 'none', fontFamily: FONTS.mono, resize: 'vertical', boxSizing: 'border-box', marginBottom: 6 }} />
                  <textarea value={newActivity.summary} onChange={e => setNewActivity(a => ({ ...a, summary: e.target.value }))} placeholder="Short summary of what was done / observed" rows={2} style={{ width: '100%', background: PALETTE.bg3, border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 8px', color: PALETTE.textDim, fontSize: 10, outline: 'none', fontFamily: FONTS.mono, resize: 'vertical', boxSizing: 'border-box', marginBottom: 6 }} />
                  <textarea value={newActivity.output} onChange={e => setNewActivity(a => ({ ...a, output: e.target.value }))} placeholder="Raw output / findings / IOC / next steps" rows={4} style={{ width: '100%', background: PALETTE.bg3, border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 8px', color: PALETTE.textDim, fontSize: 10, outline: 'none', fontFamily: FONTS.mono, resize: 'vertical', boxSizing: 'border-box', marginBottom: 6 }} />
                  <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 6, flexWrap: 'wrap', marginTop: 2 }}>
                    <button onClick={() => { setEditingActivityId(null); setShowActivityComposer(false); setNewActivity({ title: '', activity_type: 'recon', command: '', summary: '', output: '', status: 'done' }); }} style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 10px', cursor: 'pointer', color: PALETTE.textFaint, fontSize: 10, fontFamily: FONTS.mono }}>{editingActivityId ? 'Cancel edit' : 'Cancel'}</button>
                    <button onClick={async () => {
                      if (!newActivity.title.trim() && !newActivity.command.trim() && !newActivity.summary.trim() && !newActivity.output.trim()) return;
                      if (editingActivityId) {
                        await onUpdateActivity?.(editingActivityId, { ...newActivity, ts: new Date().toISOString().slice(0,16).replace('T',' ') });
                      } else {
                        await onAddActivity?.({ pid: selectedProject, host_id: selHost.id, ...newActivity, ts: new Date().toISOString().slice(0,16).replace('T',' ') });
                      }
                      setNewActivity({ title: '', activity_type: 'recon', command: '', summary: '', output: '', status: 'done' });
                      setEditingActivityId(null);
                      setShowActivityComposer(false);
                    }} style={{ background: accent, border: 'none', borderRadius: 4, padding: '6px 10px', cursor: 'pointer', color: '#fff', fontSize: 10, fontWeight: 600, fontFamily: FONTS.mono }}>{editingActivityId ? 'Update activity' : 'Save activity'}</button>
                  </div>
                </div>}
                {selHostActivities.length === 0 && <div style={{ fontSize: Math.max(10, fs - 3), color: PALETTE.textGhost }}>No recorded actions for this host</div>}
                {(() => {
                  // Group by date for timeline headers
                  const groups = {};
                  for (const act of selHostActivities) {
                    const date = (act.ts || '').slice(0, 10) || 'Unknown';
                    (groups[date] = groups[date] || []).push(act);
                  }
                  const today = new Date().toISOString().slice(0, 10);
                  const yesterday = new Date(Date.now() - 86400000).toISOString().slice(0, 10);
                  return Object.entries(groups).map(([date, acts]) => {
                    const label = date === today ? 'Today' : date === yesterday ? 'Yesterday' : date;
                    return (
                      <div key={date} style={{ marginBottom: 12 }}>
                        <div style={{ fontSize: 9, color: PALETTE.textGhost, textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 6, paddingBottom: 3, borderBottom: '1px solid #15171d' }}>{label} <span style={{ color: '#303540' }}>({acts.length})</span></div>
                        <div style={{ position: 'relative', paddingLeft: 18 }}>
                          {/* Vertical line */}
                          <div style={{ position: 'absolute', left: 5, top: 0, bottom: 0, width: 1, background: '#1e2029' }} />
                          {acts.map((act, i) => {
                            const typeColor = ACTIVITY_TYPES[act.activity_type]?.color || accent;
                            const statusColor = ACTIVITY_STATUS[act.status]?.color || '#606570';
                            return (
                              <div key={act.id} style={{ position: 'relative', marginBottom: i === acts.length - 1 ? 0 : 8 }}>
                                {/* Timeline dot */}
                                <div style={{ position: 'absolute', left: -18, top: 8, width: 11, height: 11, borderRadius: '50%', background: '#090b0f', border: `2px solid ${typeColor}`, boxShadow: act.status === 'running' ? `0 0 6px ${typeColor}` : 'none', zIndex: 1 }} />
                                {act.status === 'running' && <div style={{ position: 'absolute', left: -16, top: 10, width: 7, height: 7, borderRadius: '50%', background: typeColor, animation: 'pulse 1.5s infinite', zIndex: 2 }} />}
                                {/* Card */}
                                <div style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 6, padding: '8px 10px', borderLeft: `2px solid ${typeColor}` }}>
                                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                                    <span style={{ fontSize: 8, color: typeColor, background: typeColor + '18', border: `1px solid ${typeColor}44`, borderRadius: 3, padding: '1px 5px', fontFamily: FONTS.mono, textTransform: 'uppercase' }}>{ACTIVITY_TYPES[act.activity_type]?.label || act.activity_type}</span>
                                    <span style={{ fontSize: 8, color: statusColor, background: statusColor + '10', border: `1px solid ${statusColor}33`, borderRadius: 3, padding: '1px 5px', fontFamily: FONTS.mono, textTransform: 'uppercase' }}>{ACTIVITY_STATUS[act.status]?.label || act.status}</span>
                                    <span style={{ fontSize: 9, color: '#505560', fontFamily: FONTS.mono, marginLeft: 'auto' }}>{(act.ts || '').slice(11) || '--:--'}</span>
                                  </div>
                                  <div style={{ fontSize: 11, color: '#e0e4ec', fontFamily: FONTS.display, fontWeight: 600, marginBottom: 4 }}>{act.title || 'Untitled activity'}</div>
                                  {act.command && <div style={{ fontSize: 9, color: '#5b8af5', fontFamily: FONTS.mono, marginBottom: 4, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{act.command}</div>}
                                  {act.summary && <div style={{ fontSize: 10, color: PALETTE.textMute, lineHeight: 1.5, marginBottom: act.output ? 4 : 0 }}>{act.summary}</div>}
                                  {act.output && <pre style={{ margin: 0, fontSize: 9, color: PALETTE.textFaint, fontFamily: FONTS.mono, whiteSpace: 'pre-wrap', wordBreak: 'break-word', maxHeight: 120, overflowY: 'auto', background: PALETTE.bg3, border: '1px solid #1e2029', borderRadius: 4, padding: '8px 9px' }}>{act.output}</pre>}
                                  <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 6, marginTop: 6 }}>
                                    <button onClick={() => { setEditingActivityId(act.id); setShowActivityComposer(true); setNewActivity({ title: act.title || '', activity_type: act.activity_type || 'recon', command: act.command || '', summary: act.summary || '', output: act.output || '', status: act.status || 'done' }); }} style={{ background: 'none', border: 'none', cursor: 'pointer', color: accent, display: 'flex', padding: 2 }}><Icon name="edit" size={11} color="currentColor" /></button>
                                    <button onClick={() => onDeleteActivity?.(act.id)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#303540', display: 'flex', padding: 2 }}><Icon name="trash" size={11} color="currentColor" /></button>
                                  </div>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    );
                  });
                })()}
              </div>
            </div>}

            {/* Tab: Creds */}
            {panelTab === 'creds' && <div style={{ flex: 1, overflowY: 'auto', padding: 14 }}>
              {hostCredSummary.total > 0 && (
                <div style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 4, padding: '7px 9px', marginBottom: 10 }}>
                  <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                    <Badge label={`${hostCredSummary.total} linked`} color={accent} />
                    {hostCredSummary.withSecrets > 0 && <Badge label={`${hostCredSummary.withSecrets} secrets`} color="#39d353" />}
                    {hostCredSummary.passwords > 0 && <Badge label={`${hostCredSummary.passwords} passwords`} color="#5b8af5" />}
                    {hostCredSummary.hashes > 0 && <Badge label={`${hostCredSummary.hashes} hashes`} color="#c07af0" />}
                    {hostCredSummary.keys > 0 && <Badge label={`${hostCredSummary.keys} keys/tokens`} color="#f09a3a" />}
                  </div>
                </div>
              )}
              {hostCreds.length === 0 && <div style={{ fontSize: Math.max(10, fs - 3), color: PALETTE.textGhost }}>No linked credentials</div>}
              {hostCreds.map(c => (
                <div key={c.id} style={{ marginBottom: 6 }}>
                  <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginBottom: 4 }}>
                    {getCredBadges(c).slice(0, 5).map(b => <Badge key={`${c.id}-${b.label}`} label={b.label} color={b.color} />)}
                  </div>
                  <CredPanel cred={c} host={selHost} accent={accent} pid={selectedProject} linkType={c._linkType} />
                </div>
              ))}
            </div>}

            {/* Tab: Notes */}
            {panelTab === 'notes' && <div style={{ flex: 1, overflowY: 'auto', padding: 14 }}>
              <div style={{ fontSize: 9, color: PALETTE.textGhost, textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 10 }}>Notes for this host</div>
              <HostNotesPanel
                notes={selHostNotes}
                canAdd={can('notes.create')}
                adding={addingNote}
                onAdd={addHostNote}
                onSelect={id => onNavigate?.('notes', id)}
              />
            </div>}

            {/* Tab: Scan */}
            {panelTab === 'scan' && <div style={{ flex: 1, overflowY: 'auto', padding: 14, display: 'flex', flexDirection: 'column', gap: 10 }}>
              <RiskScoreBreakdown hostId={selHost.id} />
              <ScanDiffPanel hostId={selHost.id} />
            </div>}

            {/* Tab: Path */}
            {panelTab === 'path' && <div style={{ flex: 1, overflowY: 'auto', padding: 14 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
                <span style={{ fontSize: 9, color: PALETTE.textGhost, textTransform: 'uppercase', letterSpacing: '0.1em', flex: 1 }}>Lateral paths from this host</span>
                <button onClick={async () => {
                  setLateralLoading(true);
                  try {
                    const data = await api.topologyLateralPaths(selectedProject, selHost.id, 3);
                    setLateralPaths(data);
                  } catch { setLateralPaths({ paths: [], error: true }); }
                  finally { setLateralLoading(false); }
                }} disabled={lateralLoading} style={{ background: accent, border: 'none', borderRadius: 4, padding: '4px 10px', cursor: lateralLoading ? 'default' : 'pointer', color: '#fff', fontSize: 9, fontWeight: 600, fontFamily: FONTS.mono, opacity: lateralLoading ? 0.6 : 1 }}>
                  {lateralLoading ? 'Scanning…' : 'Find paths'}
                </button>
              </div>
              {!lateralPaths && !lateralLoading && <div style={{ fontSize: 10, color: PALETTE.textGhost }}>Click "Find paths" to compute lateral movement paths from this host.</div>}
              {lateralPaths?.error && <div style={{ fontSize: 10, color: PALETTE.danger }}>Failed to load paths.</div>}
              {lateralPaths && !lateralPaths.error && lateralPaths.paths?.length === 0 && <div style={{ fontSize: 10, color: PALETTE.textGhost }}>No lateral paths found from this host.</div>}
              {lateralPaths?.paths?.map((path, i) => (
                <div key={`lpath-${path.nodes?.map(n => n.id || n.ip).join('-') || i}`} style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 6, padding: '8px 10px', marginBottom: 8 }}>
                  <div style={{ fontSize: 9, color: accent, fontFamily: FONTS.mono, marginBottom: 6 }}>Path {i + 1} · {path.nodes?.length || 0} hops · conf {Math.round((path.confidence || 0) * 100)}%</div>
                  {(path.nodes || []).map((node, ni) => {
                    let dotColor = '#5b8af5';
                    if (ni === 0) dotColor = '#39d353';
                    else if (ni === path.nodes.length - 1) dotColor = '#e8574a';
                    return (
                    <div key={`lpath-${i}-node-${ni}`} style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: ni < path.nodes.length - 1 ? 4 : 0 }}>
                      <span style={{ width: 5, height: 5, borderRadius: '50%', background: dotColor, flexShrink: 0 }} />
                      <span style={{ fontSize: 9, color: PALETTE.textDim, fontFamily: FONTS.mono, flex: 1 }}>{node.label || node.id}</span>
                      {ni < path.nodes.length - 1 && <span style={{ fontSize: 8, color: PALETTE.textGhost }}>→</span>}
                    </div>
                    );
                  })}
                  {path.steps?.map((step, si) => (
                    <div key={`lpath-${i}-step-${si}`} style={{ fontSize: 8, color: PALETTE.textFaint, fontFamily: FONTS.mono, marginTop: 4, paddingLeft: 11 }}>{step.technique || step.type || step.label || ''}</div>
                  ))}
                </div>
              ))}
            </div>}
          </div>
        )}
      </div>
    </div>
    {burnHostId && (
      <BurnChecklist
        hostId={burnHostId}
        hostLabel={selHost?.hostname || selHost?.ip || burnHostId}
        onClose={() => setBurnHostId(null)}
        accent={accent}
      />
    )}
    </>
  );
}

HostsView.propTypes = {
  hosts: PropTypes.array,
  creds: PropTypes.array,
  hostActivities: PropTypes.array,
  notes: PropTypes.array,
  onAdd: PropTypes.func,
  onUpdate: PropTypes.func,
  onDelete: PropTypes.func,
  onAddActivity: PropTypes.func,
  onUpdateActivity: PropTypes.func,
  onDeleteActivity: PropTypes.func,
  onAddNote: PropTypes.func,
  onUpdateNote: PropTypes.func,
  selectedProject: PropTypes.string,
  accent: PropTypes.string,
  onImport: PropTypes.func,
  onAddCred: PropTypes.func,
  fs: PropTypes.number,
  focusId: PropTypes.string,
  consumeFocusId: PropTypes.func,
  onNavigate: PropTypes.func,
};
