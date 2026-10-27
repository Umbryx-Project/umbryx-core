import { useEffect, useRef, useState, useMemo } from 'react';
import PropTypes from 'prop-types';
import Icon from '../components/Icon.jsx';
import { SEVERITY, FINDING_STATUS } from '../constants.js';
import { api } from '../api.js';
import NessusParser from '../components/NessusParser.jsx';
import { useProjectPermissions } from '../context/ProjectPermissions.jsx';
import { PALETTE, FONTS, Select } from '../components/UI.jsx';

const SEV_COLORS = { critical:PALETTE.danger, high:'#e8574a', medium:PALETTE.warn, low:'#e8cc42', info:'#5b8af5' }

async function _importNessusItems(items, allHosts, selectedProject, onAdd) {
  const ts = new Date().toISOString().slice(0, 16).replace('T', ' ');
  let added = 0;
  for (const item of items) {
    const linkedHost = allHosts.find(h => h.pid === selectedProject && h.ip === item.host_ip);
    await onAdd({
      pid: selectedProject,
      title: item.title,
      severity: item.severity,
      cvss: item.cvss,
      cve: item.cve,
      description: item.description,
      proof: item.proof,
      recommendation: item.recommendation,
      host_id: linkedHost?.id || null,
      status: 'open',
      ts,
    });
    added++;
  }
  return { added };
};
TemplateLibrary.propTypes = { accent: PropTypes.any, templates: PropTypes.any, onUse: PropTypes.any, onDeleteCustom: PropTypes.any, onImport: PropTypes.any, onExport: PropTypes.any, onClose: PropTypes.any };
function TemplateLibrary({ accent, templates, onUse, onDeleteCustom, onImport, onExport, onClose }) {
  const [search, setSearch] = useState('');
  const [filterSev, setFilterSev] = useState(null);
  const fileRef = useRef();
  const filtered = useMemo(() => {
    const sevOf = t => (t.severity || '').toLowerCase();
    let list = templates;
    if (filterSev) list = list.filter(t => sevOf(t) === filterSev);
    if (search.trim()) {
      const q = search.toLowerCase();
      list = list.filter(t => t.title.toLowerCase().includes(q) || t.cve?.toLowerCase().includes(q));
    }
    // Sort by severity (critical → info), then title — the raw catalog order
    // mixes severities, which looked jumbled once you filtered/scanned it.
    const rank = s => { const i = SEV_ORDER.indexOf(s); return i === -1 ? SEV_ORDER.length : i; };
    return [...list].sort(
      (a, b) => rank(sevOf(a)) - rank(sevOf(b)) || (a.title || '').localeCompare(b.title || ''),
    );
  }, [templates, search, filterSev]);

  return (
    <div style={{ position:'fixed', inset:0, background:'#000000cc', display:'flex', alignItems:'center', justifyContent:'center', zIndex:1000, backdropFilter:'blur(4px)' }}>
      <div style={{ background:PALETTE.bg3, border:`1px solid ${PALETTE.border}`, borderRadius:12, width:700, maxHeight:'85vh', display:'flex', flexDirection:'column', boxShadow:'0 24px 64px #00000099' }}>
        <div style={{ padding:'18px 24px', borderBottom:'1px solid #1e2029', display:'flex', alignItems:'center', gap:10, flexShrink:0 }}>
          <Icon name="list" size={16} color={accent} />
          <span style={{ fontSize:14, fontWeight:700, color:PALETTE.text, fontFamily:FONTS.display, flex:1 }}>Template library</span>
          <span style={{ fontSize:10, color:PALETTE.textGhost, fontFamily:FONTS.mono }}>{templates.length} templates</span>
          <button onClick={() => fileRef.current?.click()} style={{ background:'none', border:`1px solid ${PALETTE.border}`, borderRadius:5, padding:'5px 10px', cursor:'pointer', color:'#808590', fontSize:10, fontFamily:FONTS.mono }}>Import</button>
          <button onClick={onExport} style={{ background:'none', border:`1px solid ${PALETTE.border}`, borderRadius:5, padding:'5px 10px', cursor:'pointer', color:'#808590', fontSize:10, fontFamily:FONTS.mono }}>Export</button>
          <input ref={fileRef} type="file" accept="application/json,.json" style={{ display:'none' }} onChange={e => e.target.files?.[0] && onImport(e.target.files[0])} />
          <button onClick={onClose} style={{ background:'none', border:'none', cursor:'pointer', display:'flex' }}>
            <Icon name="close" size={14} color="#606570" />
          </button>
        </div>
        <div style={{ padding:'12px 24px', borderBottom:`1px solid ${PALETTE.borderSoft}`, display:'flex', gap:8, alignItems:'center', flexShrink:0 }}>
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search template..."
            style={{ flex:1, background:PALETTE.bg2, border:`1px solid ${PALETTE.border}`, borderRadius:5, padding:'6px 10px', color:PALETTE.textDim, fontSize:11, fontFamily:FONTS.mono, outline:'none' }} />
          {['critical','high','medium','low'].map(s => (
            <button key={s} onClick={() => setFilterSev(filterSev == s ? null : s)}
              style={{ background: filterSev == s ? SEV_COLORS[s]+'33' : 'transparent', border:`1px solid ${filterSev == s ? SEV_COLORS[s] : PALETTE.border}`, borderRadius:4, padding:'3px 9px', cursor:'pointer', color: filterSev == s ? SEV_COLORS[s] : PALETTE.textFaint, fontSize:9, fontFamily:FONTS.mono, fontWeight:700, textTransform:'uppercase' }}>
              {s}
            </button>
          ))}
        </div>
        <div style={{ flex:1, overflowY:'auto', padding:'12px 24px' }}>
          {filtered.map(t => (
            <button type="button" key={t.id} style={{ padding:'12px 14px', marginBottom:8, background:PALETTE.bg2, border:'1px solid #1e2029', borderRadius:8, display:'flex', alignItems:'flex-start', gap:12, cursor:'pointer', color:'inherit', font:'inherit', textAlign:'left', width:'100%' }}
              onMouseEnter={e => e.currentTarget.style.borderColor='#2a2d35'}
              onMouseLeave={e => e.currentTarget.style.borderColor='#1e2029'}>
              <div style={{ flex:1 }}>
                <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:4 }}>
                  <span style={{ fontSize:9, fontWeight:700, color:SEV_COLORS[t.severity], background:SEV_COLORS[t.severity]+'22', border:`1px solid ${SEV_COLORS[t.severity]}44`, borderRadius:3, padding:'1px 5px', fontFamily:FONTS.mono, textTransform:'uppercase' }}>{t.severity}</span>
                  {t.is_custom && <span style={{ fontSize:9, fontWeight:700, color:'#15bbb1', background:'#15bbb122', border:'1px solid #15bbb144', borderRadius:3, padding:'1px 5px', fontFamily:FONTS.mono, textTransform:'uppercase' }}>custom</span>}
                  {t.cvss && <span style={{ fontSize:9, color:'#808590', fontFamily:FONTS.mono }}>CVSS: {t.cvss}</span>}
                  {t.cve && <span style={{ fontSize:9, color:'#5b8af5', fontFamily:FONTS.mono }}>{t.cve}</span>}
                </div>
                <div style={{ fontSize:12, fontWeight:600, color:'#e0e4ec', fontFamily:FONTS.display, marginBottom:4 }}>{t.title}</div>
                <div style={{ fontSize:10, color:PALETTE.textFaint, lineHeight:1.5, overflow:'hidden', textOverflow:'ellipsis', display:'-webkit-box', WebkitLineClamp:2, WebkitBoxOrient:'vertical' }}>{t.description}</div>
              </div>
              <div style={{ display:'flex', gap:6, flexShrink:0 }}>
                {t.is_custom && <button onClick={() => onDeleteCustom(t.id)}
                  style={{ background:'transparent', border:'1px solid #cc223344', borderRadius:5, padding:'6px 10px', cursor:'pointer', color:PALETTE.danger, fontSize:10, fontWeight:600, fontFamily:FONTS.mono }}>
                  Delete
                </button>}
                <button onClick={() => { onUse(t); onClose(); }}
                  style={{ background:accent, border:'none', borderRadius:5, padding:'6px 14px', cursor:'pointer', color:'#fff', fontSize:10, fontWeight:600, fontFamily:FONTS.mono }}>
                  Use
                </button>
              </div>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

function SevBadge({ severity, size = 10 }) {
  const s = SEVERITY[severity] || SEVERITY.info;
  return (
    <span style={{ fontSize: size, fontWeight: 700, color: s.color, background: s.color + '22', border: `1px solid ${s.color}55`, borderRadius: 3, padding: '1px 6px', fontFamily: FONTS.mono, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
      {s.label}
    </span>
  );
}
SevBadge.propTypes = { severity: PropTypes.any, size: PropTypes.any };

function StatusBadge({ status }) {
  const s = FINDING_STATUS[status] || FINDING_STATUS.open;
  return (
    <span style={{ fontSize: 9, color: s.color, background: s.color + '18', border: `1px solid ${s.color}44`, borderRadius: 3, padding: '1px 6px', fontFamily: FONTS.mono }}>
      {s.label}
    </span>
  );
}
StatusBadge.propTypes = { status: PropTypes.any };

function FindingForm({ finding, hosts, accent, onSave, onSaveTemplate, onCancel }) {
  const [form, setForm] = useState(finding || {
    title: '', severity: 'medium', cvss: '', cve: '', host_id: null,
    description: '', proof: '', recommendation: '', status: 'open',
  });
  const [templateState, setTemplateState] = useState({ saving: false, type: '', message: '' });
  const set = (k, v) => setForm(f => ({ ...f, [k]: v }));
  const inp = (style = {}) => ({ background: PALETTE.bg2, border: `1px solid ${PALETTE.border}`, borderRadius: 5, padding: '7px 10px', color: PALETTE.textDim, fontSize: 12, fontFamily: FONTS.mono, outline: 'none', width: '100%', ...style });
  const label = (text) => <div style={{ fontSize: 9, color: '#505560', textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 5 }}>{text}</div>;
  const field = (style = {}) => ({ marginBottom: 14, ...style });

  const handleSaveTemplateClick = async () => {
    setTemplateState({ saving: true, type: '', message: '' });
    try {
      const message = await onSaveTemplate(form);
      setTemplateState({ saving: false, type: 'success', message: message || 'Template saved' });
    } catch (e) {
      setTemplateState({ saving: false, type: 'error', message: e.message || 'Failed to save template' });
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 0, height: '100%', overflow: 'hidden' }}>
      <div style={{ padding: '14px 20px', borderBottom: `1px solid ${PALETTE.borderSoft}`, background: '#0a0c10', display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
        <span style={{ fontSize: 13, fontWeight: 600, color: PALETTE.text, fontFamily: FONTS.display, flex: 1 }}>
          {finding ? 'Edit finding' : 'New finding'}
        </span>
        {templateState.message && <span style={{ fontSize: 10, color: templateState.type === 'error' ? '#cc2233' : PALETTE.ok, fontFamily: FONTS.mono }}>{templateState.message}</span>}
        <button onClick={handleSaveTemplateClick} disabled={templateState.saving} style={{ background: '#1e2029', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '5px 12px', cursor: templateState.saving ? 'wait' : 'pointer', color: '#808590', fontSize: 11, fontFamily: FONTS.mono, opacity: templateState.saving ? 0.7 : 1 }}>{templateState.saving ? 'Saving...' : 'Save as template'}</button>
        <button onClick={onCancel} style={{ background: 'none', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '5px 12px', cursor: 'pointer', color: PALETTE.textFaint, fontSize: 11, fontFamily: FONTS.mono }}>Cancel</button>
        <button onClick={() => onSave(form)} style={{ background: accent, border: 'none', borderRadius: 4, padding: '5px 14px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: FONTS.mono }}>Save</button>
      </div>
      <div style={{ flex: 1, overflowY: 'auto', padding: '20px 24px' }}>
        <div style={field()}>
          {label('Title')}
          <input style={inp()} value={form.title} onChange={e => set('title', e.target.value)} placeholder="Vulnerability title" />
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12, ...field() }}>
          <div>
            {label('Severity')}
            <Select value={form.severity} onChange={v => set('severity', v)}
              options={SEV_ORDER.map(s => ({ value: s, label: SEVERITY[s].label }))} />
          </div>
          <div>
            {label('CVSS Score')}
            <input style={inp()} value={form.cvss} onChange={e => set('cvss', e.target.value)} placeholder="9.8" />
          </div>
          <div>
            {label('CVE')}
            <input style={inp()} value={form.cve} onChange={e => set('cve', e.target.value)} placeholder="CVE-2024-XXXX" />
          </div>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, ...field() }}>
          <div>
            {label('Host')}
            <Select value={form.host_id || ''} onChange={v => set('host_id', v || null)}
              placeholder="— not linked —"
              options={hosts.map(h => ({ value: h.id, label: `${h.ip}${h.hostname ? ` (${h.hostname})` : ''}` }))} />
          </div>
          <div>
            {label('Status')}
            <Select value={form.status} onChange={v => set('status', v)}
              options={Object.entries(FINDING_STATUS).map(([k, v]) => ({ value: k, label: v.label }))} />
          </div>
        </div>
        {[['description', 'Description', 'What was found, how to reproduce...', 120],
          ['proof', 'Proof / PoC', 'Command output, screenshots (markdown)...', 100],
          ['recommendation', 'Recommendation', 'How to fix...', 80]].map(([key, lbl, ph, h]) => (
          <div key={key} style={field()}>
            {label(lbl)}
            <textarea style={{ ...inp(), resize: 'vertical', minHeight: h, lineHeight: 1.7 }}
              value={form[key]} onChange={e => set(key, e.target.value)} placeholder={ph} />
          </div>
        ))}
      </div>
    </div>
  );
}
FindingForm.propTypes = { finding: PropTypes.any, hosts: PropTypes.any, accent: PropTypes.any, onSave: PropTypes.any, onSaveTemplate: PropTypes.any, onCancel: PropTypes.any };

function CandidatesList({ projCandidates, selected, setSelected, projHosts, scanResult }) {
  return (
    <>
      {scanResult && !scanResult.error && (
        <div style={{ padding: '6px 14px', background: '#0c1008', borderBottom: '1px solid #1e2910', fontSize: 9, color: PALETTE.ok, fontFamily: FONTS.mono }}>
          Scan complete: {scanResult.created} new candidate{scanResult.created === 1 ? '' : 's'}, {scanResult.skipped} already known
        </div>
      )}
      {scanResult?.error && (
        <div style={{ padding: '6px 14px', background: '#100808', borderBottom: '1px solid #2a1010', fontSize: 9, color: PALETTE.danger, fontFamily: FONTS.mono }}>{scanResult.error}</div>
      )}
      {projCandidates.length === 0 && (
        <div style={{ padding: 24, textAlign: 'center', color: PALETTE.textGhost, fontSize: 11 }}>
          No candidates yet. Click ⚑ Scan to analyse the project.
        </div>
      )}
      {[...projCandidates].sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity)).map(f => {
        const act = f.id === selected;
        const h = projHosts.find(h => h.id === f.host_id);
        return (
          <button type="button" key={f.id} onClick={() => setSelected(f.id)} onKeyDown={e => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault();
              setSelected(f.id);
            }
          }}
            style={{ padding: '10px 14px', cursor: 'pointer', background: act ? '#ffffff0a' : 'transparent', borderBottom: '1px solid #14161b', borderLeft: act ? '2px solid #f09a3a' : '2px solid transparent', transition: 'background .1s', width: '100%', textAlign: 'left', borderTop: 'none', borderRight: 'none', outline: 'none', color: 'inherit', font: 'inherit' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
              <SevBadge severity={f.severity} />
              <span style={{ fontSize: 8, color: PALETTE.warn, background: '#f09a3a18', border: '1px solid #f09a3a44', borderRadius: 3, padding: '1px 5px', fontFamily: FONTS.mono }}>CANDIDATE</span>
            </div>
            <div style={{ fontSize: 12, color: act ? '#f0f2f6' : '#b0b5c2', marginBottom: 3, fontWeight: act ? 600 : 400, lineHeight: 1.4 }}>{f.title}</div>
            {h && <div style={{ fontSize: 9, color: '#505560', fontFamily: FONTS.mono }}>{h.ip || h.hostname}</div>}
          </button>
        );
      })}
    </>
  );
}
CandidatesList.propTypes = { projCandidates: PropTypes.any, selected: PropTypes.any, setSelected: PropTypes.any, projHosts: PropTypes.any, scanResult: PropTypes.any };

function FindingsList({ sorted, selected, setSelected, projHosts, accent }) {
  return (
    <>
      {sorted.length === 0 && <div style={{ padding: 24, textAlign: 'center', color: PALETTE.textGhost, fontSize: 11 }}>No findings</div>}
      {sorted.map(f => {
        const act = f.id === selected;
        const h = projHosts.find(h => h.id === f.host_id);
        return (
          <button type="button" id={`finding-${f.id}`} key={f.id} onClick={() => setSelected(f.id)} onKeyDown={e => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault();
              setSelected(f.id);
            }
          }}
            style={{ padding: '10px 14px', cursor: 'pointer', background: act ? '#ffffff0a' : 'transparent', borderBottom: '1px solid #14161b', borderLeft: act ? `2px solid ${accent}` : '2px solid transparent', transition: 'background .1s', width: '100%', textAlign: 'left', borderTop: 'none', borderRight: 'none', outline: 'none', color: 'inherit', font: 'inherit' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 5 }}>
              <SevBadge severity={f.severity} />
              <StatusBadge status={f.status} />
            </div>
            <div style={{ fontSize: 12, color: act ? '#f0f2f6' : '#b0b5c2', marginBottom: 3, fontWeight: act ? 600 : 400, lineHeight: 1.4 }}>{f.title}</div>
            {h && <div style={{ fontSize: 9, color: '#505560', fontFamily: FONTS.mono }}>{h.ip}</div>}
            {f.cve && <div style={{ fontSize: 9, color: '#5b8af5', fontFamily: FONTS.mono }}>{f.cve}</div>}
          </button>
        );
      })}
    </>
  );
}
FindingsList.propTypes = { sorted: PropTypes.any, selected: PropTypes.any, setSelected: PropTypes.any, projHosts: PropTypes.any, accent: PropTypes.any };

export default function FindingsView({ findings, hosts, onAdd, onUpdate, onDelete, selectedProject, accent, focusId, consumeFocusId, onNavigate }) {
  const { can } = useProjectPermissions();
  const [selected, setSelected] = useState(null);
  const [templateData, setTemplateData] = useState(null);
  const [editing, setEditing] = useState(false);
  const [filterSev, setFilterSev] = useState(null);
  const [showNessus, setShowNessus] = useState(false);
  const [showTemplates, setShowTemplates] = useState(false);
  const [templates, setTemplates] = useState([]);
  const [view, setView] = useState('findings'); // 'findings' | 'candidates'
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);

  useEffect(() => {
    api.listFindingTemplates().then(setTemplates).catch(() => {});
  }, []);

  const projFindings = useMemo(
    () => findings.filter(f => f.pid === selectedProject && f.status !== 'candidate'),
    [findings, selectedProject],
  );
  const projCandidates = useMemo(
    () => findings.filter(f => f.pid === selectedProject && f.status === 'candidate'),
    [findings, selectedProject],
  );
  const filtered = useMemo(
    () => (filterSev ? projFindings.filter(f => f.severity === filterSev) : projFindings),
    [projFindings, filterSev],
  );
  const sorted = useMemo(
    () => [...filtered].sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity)),
    [filtered],
  );
  const projHosts = useMemo(
    () => hosts.filter(h => h.pid === selectedProject),
    [hosts, selectedProject],
  );
  const selFinding = useMemo(
    () => projFindings.find(f => f.id === selected),
    [projFindings, selected],
  );
  const stats = useMemo(
    () => SEV_ORDER.reduce((acc, s) => ({ ...acc, [s]: projFindings.filter(f => f.severity === s).length }), {}),
    [projFindings],
  );

  useEffect(() => {
    if (!focusId) return;
    const match = projFindings.find(f => f.id === focusId);
    if (match) {
      setSelected(focusId);
      document.getElementById(`finding-${focusId}`)?.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
    consumeFocusId?.();
  }, [focusId, projFindings, consumeFocusId]);

  const handleScan = async () => {
    setScanning(true);
    setScanResult(null);
    try {
      const r = await api.scanCandidates(selectedProject);
      setScanResult(r);
      setView('candidates');
    } catch (e) {
      setScanResult({ error: e?.message || 'Scan failed' });
    } finally {
      setScanning(false);
    }
  };

  const handleNessusImport = (items, allHosts) => _importNessusItems(items, allHosts, selectedProject, onAdd);

  const handleSave = async (form) => {
    const ts = new Date().toISOString().slice(0, 16).replace('T', ' ');
    if (selFinding && editing) {
      await onUpdate(selFinding.id, { ...form, ts });
    } else {
      const f = await onAdd({ ...form, pid: selectedProject, ts });
      if (f) setSelected(f.id);
    }
    setEditing(false);
  };

  const handleSaveTemplate = async (form) => {
    const title = (form.title || '').trim();
    if (!title) throw new Error('Template title is required');
    const created = await api.createCustomFindingTemplate({
      title,
      severity: form.severity || 'medium',
      cvss: form.cvss || '',
      cve: form.cve || '',
      description: form.description || '',
      proof: form.proof || '',
      recommendation: form.recommendation || '',
    });
    setTemplates(prev => [{ ...created, is_custom: true }, ...prev]);
    return 'Template saved';
  };

  const handleDeleteCustomTemplate = async (id) => {
    await api.deleteCustomFindingTemplate(id);
    setTemplates(prev => prev.filter(t => t.id !== id));
  };

  const handleExportTemplates = async () => {
    const blob = await api.exportFindingTemplates();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'finding_templates.json';
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleImportTemplates = async (file) => {
    await api.importFindingTemplates(file);
    const items = await api.listFindingTemplates();
    setTemplates(items);
  };

  if (editing) {
    return (
        <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
        <FindingForm finding={selFinding || templateData} hosts={projHosts} accent={accent}
          onSaveTemplate={handleSaveTemplate}
          onSave={handleSave} onCancel={() => { setEditing(false); setTemplateData(null); }} />
    </div>
  );
}
FindingsView.propTypes = { findings: PropTypes.any, hosts: PropTypes.any, onAdd: PropTypes.any, onUpdate: PropTypes.any, onDelete: PropTypes.any, selectedProject: PropTypes.any, accent: PropTypes.any, focusId: PropTypes.any, consumeFocusId: PropTypes.any, onNavigate: PropTypes.any };

  return (
    <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
      {showNessus && (
        <NessusParser pid={selectedProject} hosts={hosts} accent={accent}
          onImport={handleNessusImport}
          onClose={() => setShowNessus(false)} />
      )}
      {showTemplates && (
        <TemplateLibrary accent={accent} templates={templates} onClose={() => setShowTemplates(false)} onDeleteCustom={handleDeleteCustomTemplate} onImport={handleImportTemplates} onExport={handleExportTemplates}
          onUse={tpl => {
            setShowTemplates(false);
            setSelected(null);
            setTemplateData(tpl);
            setEditing(true);
          }} />
      )}
      {/* List */}
      <div style={{ width: 300, background: '#0a0c10', borderRight: '1px solid #1e2029', display: 'flex', flexDirection: 'column', flexShrink: 0 }}>
        <div style={{ padding: '12px 14px', borderBottom: `1px solid ${PALETTE.borderSoft}` }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 4, marginBottom: 6 }}>
            <button onClick={() => setView('findings')}
              style={{ background: view === 'findings' ? accent + '22' : 'none', border: `1px solid ${view === 'findings' ? accent + '66' : PALETTE.border}`, borderRadius: 4, padding: '3px 9px', cursor: 'pointer', color: view === 'findings' ? accent : PALETTE.textFaint, fontSize: 10, fontFamily: FONTS.mono }}>
              Findings {projFindings.length > 0 && `(${projFindings.length})`}
            </button>
            <button onClick={() => setView('candidates')}
              style={{ background: view === 'candidates' ? '#f09a3a22' : 'none', border: `1px solid ${view === 'candidates' ? '#f09a3a66' : PALETTE.border}`, borderRadius: 4, padding: '3px 9px', cursor: 'pointer', color: view === 'candidates' ? '#f09a3a' : PALETTE.textFaint, fontSize: 10, fontFamily: FONTS.mono }}>
              Candidates {projCandidates.length > 0 && `(${projCandidates.length})`}
            </button>
          </div>
          <div style={{ display: 'flex', gap: 5, marginBottom: 8, flexWrap: 'wrap' }}>
            {view === 'findings' && <>
              <button onClick={() => setShowTemplates(true)}
                style={{ background: '#1e2029', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '3px 8px', cursor: 'pointer', color: '#808590', fontSize: 10, fontFamily: FONTS.mono }}>
                Templates
              </button>
              <button onClick={() => setShowNessus(true)}
                style={{ background: '#1e2029', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '3px 8px', cursor: 'pointer', color: '#808590', fontSize: 10, fontFamily: FONTS.mono }}>
                Nessus
              </button>
              {can('findings.create') && <button onClick={() => { setSelected(null); setEditing(true); }}
                style={{ background: accent, border: 'none', borderRadius: 4, padding: '3px 9px', cursor: 'pointer', color: '#fff', fontSize: 10, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 4, fontFamily: FONTS.mono }}>
                <Icon name="plus" size={10} color="#fff" /> Add
              </button>}
            </>}
            {view === 'candidates' && (
              <button onClick={handleScan} disabled={scanning}
                style={{ background: PALETTE.warn, border: 'none', borderRadius: 4, padding: '3px 9px', cursor: scanning ? 'default' : 'pointer', color: '#fff', fontSize: 10, fontWeight: 600, fontFamily: FONTS.mono, opacity: scanning ? 0.7 : 1 }}>
                {scanning ? 'Scanning…' : '⚑ Scan'}
              </button>
            )}
          </div>
          {/* Stats */}
          <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap' }}>
            {SEV_ORDER.filter(s => stats[s] > 0).map(s => (
              <button key={s} onClick={() => setFilterSev(filterSev == s ? null : s)}
                style={{ background: filterSev == s ? SEVERITY[s].color + '33' : 'transparent', border: `1px solid ${filterSev == s ? SEVERITY[s].color : PALETTE.border}`, borderRadius: 3, padding: '2px 7px', cursor: 'pointer', fontSize: 9, fontFamily: FONTS.mono, fontWeight: 600, color: SEVERITY[s].color }}>
                {SEVERITY[s].label} {stats[s]}
              </button>
            ))}
          </div>
        </div>
        <div style={{ flex: 1, overflowY: 'auto' }}>
          {view === 'candidates' ? (
            <CandidatesList projCandidates={projCandidates} selected={selected} setSelected={setSelected} projHosts={projHosts} scanResult={scanResult} />
          ) : (
            <FindingsList sorted={sorted} selected={selected} setSelected={setSelected} projHosts={projHosts} accent={accent} />
          )}
        </div>
        <div style={{ padding: '10px 14px', borderTop: `1px solid ${PALETTE.borderSoft}`, display: 'flex', gap: 10 }}>
          {SEV_ORDER.map(s => (
            <div key={s} style={{ textAlign: 'center', flex: 1 }}>
              <div style={{ fontSize: 14, fontWeight: 700, color: SEVERITY[s].color, fontFamily: FONTS.mono }}>{stats[s]}</div>
              <div style={{ fontSize: 8, color: PALETTE.textGhost, textTransform: 'uppercase' }}>{s.slice(0, 4)}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Detail */}
      {selFinding ? (
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          <div style={{ padding: '10px 20px', borderBottom: `1px solid ${PALETTE.borderSoft}`, background: '#0a0c10', display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
            <SevBadge severity={selFinding.severity} size={11} />
            <span style={{ fontSize: 14, fontWeight: 600, color: PALETTE.text, fontFamily: FONTS.display, flex: 1 }}>{selFinding.title}</span>
            {selFinding.status === 'candidate' ? (
              <>
                <span style={{ fontSize: 8, color: PALETTE.warn, background: '#f09a3a18', border: '1px solid #f09a3a44', borderRadius: 3, padding: '2px 7px', fontFamily: FONTS.mono }}>CANDIDATE</span>
                <button onClick={() => { onUpdate(selFinding.id, { status: 'open', source: 'manual', ts: new Date().toISOString().slice(0,16).replace('T',' ') }); }}
                  style={{ background: accent, border: 'none', borderRadius: 4, padding: '4px 10px', cursor: 'pointer', color: '#fff', fontSize: 10, fontWeight: 600, fontFamily: FONTS.mono }}>
                  Promote → Finding
                </button>
                {can('findings.delete') && <button onClick={() => { onDelete(selFinding.id); setSelected(null); }}
                  style={{ background: 'none', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '4px 8px', cursor: 'pointer', color: PALETTE.textFaint, fontSize: 10, fontFamily: FONTS.mono }}>
                  Dismiss
                </button>}
              </>
            ) : (
              <>
                <StatusBadge status={selFinding.status} />
                <Select value={selFinding.status}
                  onChange={v => onUpdate(selFinding.id, { status: v, ts: new Date().toISOString().slice(0,16).replace('T',' ') })}
                  options={Object.entries(FINDING_STATUS).map(([k, v]) => ({ value: k, label: v.label }))} />
                {can('findings.update') && <button onClick={() => setEditing(true)}
                  style={{ background: 'none', border: `1px solid ${accent}55`, borderRadius: 4, padding: '4px 10px', cursor: 'pointer', color: accent, fontSize: 11, fontFamily: FONTS.mono, display: 'flex', alignItems: 'center', gap: 4 }}>
                  <Icon name="edit" size={11} color={accent} /> Edit
                </button>}
                {can('findings.delete') && <button onClick={() => { onDelete(selFinding.id); setSelected(null); }}
                  style={{ background: 'none', border: '1px solid #cc233344', borderRadius: 4, padding: '4px 8px', cursor: 'pointer', color: PALETTE.danger, display: 'flex' }}>
                  <Icon name="trash" size={13} color="currentColor" />
                </button>}
              </>
            )}
          </div>
          <div style={{ flex: 1, overflowY: 'auto', padding: '20px 28px' }}>
            {/* Meta row */}
            <div style={{ display: 'flex', gap: 20, marginBottom: 24, flexWrap: 'wrap' }}>
              {selFinding.cvss && <div><span style={{ fontSize: 9, color: '#505560', textTransform: 'uppercase' }}>CVSS</span><div style={{ fontSize: 18, fontWeight: 700, color: SEVERITY[selFinding.severity]?.color, fontFamily: FONTS.mono }}>{selFinding.cvss}</div></div>}
              {selFinding.cve && <div><span style={{ fontSize: 9, color: '#505560', textTransform: 'uppercase' }}>CVE</span><div style={{ fontSize: 12, color: '#5b8af5', fontFamily: FONTS.mono, marginTop: 2 }}>{selFinding.cve}</div></div>}
              {selFinding.host_id && <div><span style={{ fontSize: 9, color: '#505560', textTransform: 'uppercase' }}>Host</span><div style={{ fontSize: 12, color: PALETTE.textMute, fontFamily: FONTS.mono, marginTop: 2 }}>{projHosts.find(h => h.id === selFinding.host_id)?.ip || '—'}{' '}<a href="#" onClick={e => { e.preventDefault(); onNavigate?.('hosts', selFinding.host_id); }} style={{ color: accent, fontSize: 10, textDecoration: 'underline' }}>Go to host</a></div></div>}
              <div><span style={{ fontSize: 9, color: '#505560', textTransform: 'uppercase' }}>Date</span><div style={{ fontSize: 11, color: '#505560', fontFamily: FONTS.mono, marginTop: 2 }}>{selFinding.ts}</div></div>
            </div>
            {[['description', 'Description'], ['proof', 'Proof / PoC'], ['recommendation', 'Recommendation']].map(([key, lbl]) => selFinding[key] ? (
              <div key={key} style={{ marginBottom: 24 }}>
                <div style={{ fontSize: 10, color: accent, textTransform: 'uppercase', letterSpacing: '0.1em', fontWeight: 600, marginBottom: 8, display: 'flex', alignItems: 'center', gap: 8 }}>
                  {lbl}
                  <div style={{ flex: 1, height: 1, background: accent + '33' }} />
                </div>
                <div style={{ background: PALETTE.bg2, border: '1px solid #1e2029', borderRadius: 6, padding: '14px 16px' }}>
                  <pre style={{ fontFamily: FONTS.mono, fontSize: 12, color: '#b0b5c2', lineHeight: 1.7, whiteSpace: 'pre-wrap', wordBreak: 'break-word', margin: 0 }}>{selFinding[key]}</pre>
                </div>
              </div>
            ) : null)}
          </div>
        </div>
      ) : (
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 12, color: '#303540' }}>
          <Icon name="bug" size={40} color="#2a2d35" />
          <div style={{ fontSize: 13 }}>Select a finding or add a new one</div>
        </div>
      )}
    </div>
  );
}
