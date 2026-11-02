import PropTypes from 'prop-types';
import { useState, useRef, useEffect } from 'react';
import { toastError } from '../components/Toast.jsx';
import Icon from '../components/Icon.jsx';
import { OS_ICONS } from '../constants.js';
import ClosureWizard from './ClosureWizard.jsx';
import { api } from '../api.js';
import { isAttackerHost } from '../utils/hostMeta.js';
import { useProjectPermissions } from '../context/ProjectPermissions.jsx';
import MembersPanel from './MembersPanel.jsx';
import { PALETTE, FONTS, Select } from '../components/UI.jsx';
import { uiAlert } from '../components/Confirm.jsx';

const SCOPE_TYPE_COLORS = {
  cidr:     '#5b8af5',
  hostname: '#c07af0',
  domain:   PALETTE.warn,
  url:      '#6fc8f0',
};

function _nonAttackerHosts(hosts, pid) {
  return hosts.filter(h => h.pid === pid && !isAttackerHost(h));
}

function _projectStats(notes, hosts, creds, pid) {
  const nh = _nonAttackerHosts(hosts, pid);
  return {
    notes: notes.filter(n => n.pid === pid).length,
    hosts: nh.length,
    creds: creds.filter(c => c.pid === pid).length,
    pwned: nh.filter(h => h.status === 'pwned' || h.status === 'owned').length,
  };
}

function _inpField(editForm, setEditForm, label, key, placeholder, textarea = false) {
  return (
    <div style={{ marginBottom: 10 }}>
      <div style={{ fontSize: 9, color: '#505560', marginBottom: 4, textTransform: 'uppercase', letterSpacing: '.1em' }}>{label}</div>
      {textarea
        ? <textarea value={editForm[key] || ''} onChange={e => setEditForm(f => ({ ...f, [key]: e.target.value }))} rows={3} placeholder={placeholder}
            style={{ width: '100%', background: '#0a0c10', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 8px', color: PALETTE.textDim, fontSize: 11, outline: 'none', fontFamily: FONTS.mono, resize: 'vertical' }} />
        : <input value={editForm[key] || ''} onChange={e => setEditForm(f => ({ ...f, [key]: e.target.value }))} placeholder={placeholder}
            style={{ width: '100%', background: '#0a0c10', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 8px', color: PALETTE.textDim, fontSize: 11, outline: 'none', fontFamily: FONTS.mono }} />}
    </div>
  );
}

function detectScopeType(value) {
  const v = (value || '').trim();
  if (!v) {
    return 'cidr';
  }
  if (v.includes('/')) {
    return 'cidr';
  }
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) return 'cidr';
  if (/^https?:\/\//i.test(v)) {
    return 'url';
  }
  if (v.includes('.') && !v.includes(' ')) {
    return 'domain';
  }
  return 'hostname';
}

const sEl = (val, opts, onChange, style = {}) => (
  <Select value={val} onChange={onChange} style={{ width: '100%', ...style }}
    options={opts.map(([v, l]) => ({ value: v, label: l }))} />
);

function ProjectScopeBadges({ scopes, pid }) {
  const validScopes = (scopes || []).filter(s => s.pid === pid && s.in_scope);
  if (!validScopes.length) {
    return null;
  }
  return (
    <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginBottom: 8 }}>
      {validScopes.slice(0, 4).map(s => {
        const c = SCOPE_TYPE_COLORS[s.scope_type] || '#5b8af5';
        return (
          <span key={s.id} title={s.value} style={{ fontSize: 9, color: c, background: c + '18', border: `1px solid ${c}44`, borderRadius: 3, padding: '1px 6px', fontFamily: FONTS.mono, whiteSpace: 'nowrap', maxWidth: 130, overflow: 'hidden', textOverflow: 'ellipsis', display: 'inline-block' }}>
            {s.value}
          </span>
        );
      })}
      {validScopes.length > 4 && <span style={{ fontSize: 9, color: '#505560', fontFamily: FONTS.mono }}>+{validScopes.length - 4}</span>}
    </div>
  );
}

ProjectScopeBadges.propTypes = {
  scopes: PropTypes.array,
  pid: PropTypes.string,
};

function ProjectCardActions({ p, accent, canFor, exportingId, handleExport, setMembersPid, onImport, startEdit, setConfirmDelete, onCloseProject }) {
  const hasAny = canFor(p.id, 'project.import') || canFor(p.id, 'project.export') || canFor(p.id, 'project.update') || canFor(p.id, 'project.delete') || canFor(p.id, 'project.manage_members');
  if (!hasAny) {
    return null;
  }
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 6, borderTop: '1px solid #1e2029', paddingTop: 10 }}>
      <div style={{ display: 'flex', gap: 6, justifyContent: canFor(p.id, 'project.manage_members') ? 'flex-start' : 'flex-end', flex: 1, minWidth: 0 }}>
        {canFor(p.id, 'project.manage_members') && (
          <button onClick={e => { e.stopPropagation(); setMembersPid(p.id); }} title="Manage project members"
            style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '5px 10px', cursor: 'pointer', color: '#505560', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 4, fontSize: 10, fontFamily: FONTS.mono, transition: 'all .12s', whiteSpace: 'nowrap' }}
            onMouseEnter={e => { e.currentTarget.style.borderColor = '#6fc8f0'; e.currentTarget.style.color = '#6fc8f0'; }}
            onMouseLeave={e => { e.currentTarget.style.borderColor = '#2a2d35'; e.currentTarget.style.color = '#505560'; }}>
            <Icon name="person" size={10} color="currentColor" /> Members
          </button>
        )}
        {canFor(p.id, 'project.import') && (
          <button onClick={e => { e.stopPropagation(); onImport(p.id); }} title="Import scan"
            style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '5px 10px', cursor: 'pointer', color: '#505560', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 4, fontSize: 10, fontFamily: FONTS.mono, transition: 'all .12s', whiteSpace: 'nowrap' }}
            onMouseEnter={e => { e.currentTarget.style.borderColor = accent; e.currentTarget.style.color = accent; }}
            onMouseLeave={e => { e.currentTarget.style.borderColor = '#2a2d35'; e.currentTarget.style.color = '#505560'; }}>
            <Icon name="export" size={10} color="currentColor" /> Import
          </button>
        )}
        {canFor(p.id, 'project.export') && (
          <button onClick={e => handleExport(e, p.id, p.name)} title="Export project to ZIP"
            disabled={exportingId === p.id}
            style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '5px 10px', cursor: exportingId === p.id ? 'wait' : 'pointer', color: '#505560', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 4, fontSize: 10, fontFamily: FONTS.mono, transition: 'all .12s', opacity: exportingId === p.id ? 0.5 : 1, whiteSpace: 'nowrap' }}
            onMouseEnter={e => { if (exportingId !== p.id) { e.currentTarget.style.borderColor = '#39d353'; e.currentTarget.style.color = '#39d353'; } }}
            onMouseLeave={e => { e.currentTarget.style.borderColor = '#2a2d35'; e.currentTarget.style.color = '#505560'; }}>
            <Icon name="export" size={10} color="currentColor" /> {exportingId === p.id ? 'Exporting...' : 'Export ZIP'}
          </button>
        )}
      </div>
      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 6, flexShrink: 0 }}>
        {canFor(p.id, 'project.update') && p.status === 'active' && (
          <button onClick={e => { e.stopPropagation(); onCloseProject(p.id); }} title="Close project"
            style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '4px 8px', cursor: 'pointer', color: '#505560', display: 'flex', alignItems: 'center', transition: 'all .12s' }}
            onMouseEnter={e => { e.currentTarget.style.borderColor = '#f09a3a'; e.currentTarget.style.color = '#f09a3a'; }}
            onMouseLeave={e => { e.currentTarget.style.borderColor = '#2a2d35'; e.currentTarget.style.color = '#505560'; }}>
            <Icon name="lock" size={12} color="currentColor" />
          </button>
        )}
        {canFor(p.id, 'project.update') && (
          <button onClick={e => { e.stopPropagation(); startEdit(p); }} title="Edit project"
            style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '4px 8px', cursor: 'pointer', color: '#505560', display: 'flex', alignItems: 'center', transition: 'all .12s' }}
            onMouseEnter={e => { e.currentTarget.style.borderColor = '#5b8af5'; e.currentTarget.style.color = '#5b8af5'; }}
            onMouseLeave={e => { e.currentTarget.style.borderColor = '#2a2d35'; e.currentTarget.style.color = '#505560'; }}>
            <Icon name="edit" size={12} color="currentColor" />
          </button>
        )}
        {canFor(p.id, 'project.delete') && (
          <button onClick={e => { e.stopPropagation(); setConfirmDelete(p.id); }} title="Delete project"
            style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '4px 8px', cursor: 'pointer', color: '#505560', display: 'flex', alignItems: 'center', transition: 'all .12s' }}
            onMouseEnter={e => { e.currentTarget.style.borderColor = '#cc2233'; e.currentTarget.style.color = '#cc2233'; }}
            onMouseLeave={e => { e.currentTarget.style.borderColor = '#2a2d35'; e.currentTarget.style.color = '#505560'; }}>
            <Icon name="trash" size={12} color="currentColor" />
          </button>
        )}
      </div>
    </div>
  );
}

ProjectCardActions.propTypes = {
  p: PropTypes.object,
  accent: PropTypes.string,
  canFor: PropTypes.func,
  exportingId: PropTypes.string,
  handleExport: PropTypes.func,
  setMembersPid: PropTypes.func,
  onImport: PropTypes.func,
  startEdit: PropTypes.func,
  setConfirmDelete: PropTypes.func,
  onCloseProject: PropTypes.func,
};

export default function ProjectsView({ projects, notes, hosts, creds, scopes, selectedProject, onSelect, accent, onAdd, onAddScope, onUpdate, onDelete, onImport, onProjectImported }) {
  const [showAdd, setShowAdd] = useState(false);
  const [closeProjectId, setCloseProjectId] = useState(null);
  const [form, setForm] = useState({ name: '', ip: '', os: 'Linux', status: 'active', description: '' });
  const [confirmDelete, setConfirmDelete] = useState(null);
  const [editId, setEditId] = useState(null);
  const [editForm, setEditForm] = useState({});
  const [exportingId, setExportingId] = useState(null);
  const [importing, setImporting] = useState(false);
  const [membersPid, setMembersPid] = useState(null);
  const [orgs, setOrgs] = useState([]);
  const orgName = (oid) => orgs.find(o => o.id === oid)?.name || null;
  const importFileRef = useRef();
  const { can, projectId: permsPid, isSuperAdmin } = useProjectPermissions();
  const canFor = (pid, perm) => isSuperAdmin || (pid === permsPid ? can(perm) : true);

  const handleExport = async (e, pid, pname) => {
    e.stopPropagation();
    setExportingId(pid);
    try {
      const { blob, password } = await api.exportProject(pid);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${pname.replace(/[^a-zA-Z0-9_-]/g, '_')}_export.zip`;
      a.click();
      URL.revokeObjectURL(url);
      if (password) {
        setTimeout(async () => await uiAlert(`Archive is password-protected.\n\nPassword: ${password}\n\nSave it — it won't be shown again.`), 300);
      }
    } catch (err) {
      toastError('Export error: ' + err.message);
    } finally {
      setExportingId(null);
    }
  };

  const handleImportFile = async (e) => {
    const file = e.target.files?.[0];
    if (!file) {
      return;
    }
    e.target.value = '';
    setImporting(true);
    try {
      let result;
      try {
        result = await api.importProject(file);
      } catch (err) {
        // Exports are password-protected whenever the project has any
        // credential secrets — the export flow already shows that password
        // once via await uiAlert() above, so re-prompting for it here on import
        // matches the existing UX rather than adding a new modal.
        if (err.code === 'zip_password_required' || err.code === 'zip_password_invalid') {
          const password = window.prompt(
            err.code === 'zip_password_invalid'
              ? 'Неверный пароль. Введите пароль архива ещё раз:'
              : 'Архив защищён паролем. Введите пароль, полученный при экспорте:'
          );
          if (!password) {
            return;
          }
          result = await api.importProject(file, password);
        } else {
          throw err;
        }
      }
      onProjectImported?.(result);
    } catch (err) {
      toastError('Import error: ' + err.message);
    } finally {
      setImporting(false);
    }
  };

  const statusColor = { active: PALETTE.ok, paused: PALETTE.warn, done: '#555' };

  const handleAdd = async () => {
    if (!form.name.trim()) {
      return;
    }
    const p = await onAdd({ ...form, added: new Date().toISOString().slice(0, 10) });
    if (p?.id && form.org) {
      // Project creation itself doesn't take an org (backend contract) —
      // bind right after with the same PATCH the edit form uses.
      try { await onUpdate(p.id, { org_id: form.org }); }
      catch (e) { toastError(`Project created, but the organization binding failed: ${e.message}`); }
    }
    if (p?.id && form.ip.trim() && onAddScope) {
      onAddScope({ pid: p.id, value: form.ip.trim(), scope_type: detectScopeType(form.ip), in_scope: true, description: 'Project target' });
    }
    setForm({ name: '', ip: '', os: 'Linux', status: 'active', description: '' });
    setShowAdd(false);
  };

  useEffect(() => { api.listOrganizations().then(setOrgs).catch(() => {}); }, []);

  const startEdit = (p) => {
    setEditId(p.id);
    setEditForm({ name: p.name, ip: p.ip || '', os: p.os, status: p.status, description: p.description, env_vars: p.env_vars || {}, org_id: p.org_id || '' });
  };
  const saveEdit = () => {
    const originalIp = projects.find(p => p.id === editId)?.ip || '';
    const { org_id, ...rest } = editForm;
    // org binding: an id assigns (requires org-admin of that org),
    // empty string detaches — the backend distinguishes via detach_org.
    onUpdate(editId, org_id ? { ...rest, org_id } : { ...rest, detach_org: true });
    if (editForm.ip?.trim() && editForm.ip.trim() !== originalIp.trim() && onAddScope) {
      onAddScope({ pid: editId, value: editForm.ip.trim(), scope_type: detectScopeType(editForm.ip), in_scope: true, description: 'Project target' });
    }
    setEditId(null);
  };

  const deleteProj = confirmDelete ? projects.find(p => p.id === confirmDelete) : null;
  const deleteStats = confirmDelete ? _projectStats(notes, hosts, creds, confirmDelete) : null;

  return (
    <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
      {membersPid && <MembersPanel pid={membersPid} accent={accent} onClose={() => setMembersPid(null)} />}
      {/* Left: project grid */}
      <div style={{ flex: 1, overflowY: 'auto', padding: 24 }}>

        {/* Confirm delete */}
        {confirmDelete && deleteProj && (
          <div style={{ position: 'fixed', inset: 0, zIndex: 400, background: '#000000aa', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <button type="button" aria-label="Close delete dialog" onClick={() => setConfirmDelete(null)} style={{ position: 'absolute', inset: 0, background: 'transparent', border: 'none', cursor: 'default' }} />
            <div style={{ position: 'relative', background: PALETTE.bg3, border: '1px solid #cc233344', borderRadius: 10, padding: 28, width: 400, boxShadow: '0 20px 60px #00000099' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
                <div style={{ width: 36, height: 36, borderRadius: '50%', background: '#cc233318', border: '1px solid #cc233344', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                  <Icon name="trash" size={16} color="#cc2233" />
                </div>
                <div>
                  <div style={{ fontSize: 14, fontWeight: 700, color: PALETTE.text, fontFamily: FONTS.display }}>Delete project?</div>
                  <div style={{ fontSize: 11, color: PALETTE.textFaint, marginTop: 2 }}>«{deleteProj?.name}»</div>
                </div>
              </div>
              <div style={{ background: '#cc233311', border: '1px solid #cc233333', borderRadius: 6, padding: '10px 14px', marginBottom: 20, fontSize: 11, color: PALETTE.danger, lineHeight: 1.6 }}>
                Will delete: {deleteStats.notes} notes, {deleteStats.hosts} hosts, {deleteStats.creds} credentials. This action is irreversible.
              </div>
              <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
                <button onClick={() => setConfirmDelete(null)}
                  style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 6, padding: '7px 16px', cursor: 'pointer', color: PALETTE.textFaint, fontSize: 11, fontFamily: FONTS.mono }}>Cancel</button>
                <button onClick={() => { onDelete(confirmDelete); setConfirmDelete(null); if (editId === confirmDelete) setEditId(null); }}
                  style={{ background: PALETTE.danger, border: 'none', borderRadius: 6, padding: '7px 18px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: FONTS.mono, display: 'flex', alignItems: 'center', gap: 6 }}>
                  <Icon name="trash" size={11} color="#fff" /> Delete
                </button>
              </div>
            </div>
          </div>
        )}

        <div style={{ marginBottom: 20, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div>
            <h1 style={{ fontSize: 20, fontWeight: 700, color: PALETTE.text, fontFamily: FONTS.display, marginBottom: 4 }}>Projects</h1>
            <p style={{ fontSize: 11, color: '#505560' }}>{projects.length} engagements active</p>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <label title="Import project from ZIP"
              style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 5, padding: '7px 14px', cursor: importing ? 'wait' : 'pointer', color: importing ? '#606570' : '#808590', fontSize: 11, fontFamily: FONTS.mono, display: 'flex', alignItems: 'center', gap: 6, opacity: importing ? 0.6 : 1, transition: 'all .12s' }}
              onMouseEnter={e => { if (!importing) { e.currentTarget.style.borderColor = accent; e.currentTarget.style.color = accent; } }}
              onMouseLeave={e => { e.currentTarget.style.borderColor = '#2a2d35'; e.currentTarget.style.color = importing ? '#606570' : '#808590'; }}>
              <Icon name="export" size={11} color="currentColor" />
              {importing ? 'Importing...' : 'Import ZIP'}
              <input ref={importFileRef} type="file" accept=".zip" style={{ display: 'none' }} onChange={handleImportFile} disabled={importing} />
            </label>
            <button onClick={() => setShowAdd(v => !v)}
              style={{ background: accent, border: 'none', borderRadius: 5, padding: '7px 16px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: FONTS.mono, display: 'flex', alignItems: 'center', gap: 6 }}>
              <Icon name="plus" size={11} color="#fff" /> New project
            </button>
          </div>
        </div>

        {showAdd && (
          <div style={{ background: PALETTE.bg2, border: `1px solid ${accent}44`, borderRadius: 8, padding: 18, marginBottom: 18, display: 'flex', flexDirection: 'column', gap: 10 }}>
            <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
              {[['Name', 'name', '200px'], ['IP / CIDR', 'ip', '160px']].map(([l, k, w]) => (
                <div key={k} style={{ width: w }}>
                  <div style={{ fontSize: 9, color: PALETTE.textGhost, marginBottom: 4, textTransform: 'uppercase' }}>{l}</div>
                  <input value={form[k]} onChange={e => setForm(f => ({ ...f, [k]: e.target.value }))}
                    onKeyDown={e => e.key === 'Enter' && handleAdd()}
                    style={{ width: '100%', background: PALETTE.bg3, border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 8px', color: PALETTE.textDim, fontSize: 11, outline: 'none', fontFamily: FONTS.mono }} />
                </div>
              ))}
              <div>
                <div style={{ fontSize: 9, color: PALETTE.textGhost, marginBottom: 4, textTransform: 'uppercase' }}>OS</div>
                <Select value={form.os} onChange={v => setForm(f => ({ ...f, os: v }))}
                  options={['Linux', 'Windows', 'macOS', 'Various', 'Unknown']} />
              </div>
              <div>
                <div style={{ fontSize: 9, color: PALETTE.textGhost, marginBottom: 4, textTransform: 'uppercase' }}>Status</div>
                <Select value={form.status} onChange={v => setForm(f => ({ ...f, status: v }))}
                  options={[{ value: 'active', label: 'Active' }, { value: 'paused', label: 'Paused' }, { value: 'done', label: 'Done' }]} />
              </div>
              <div>
                <div style={{ fontSize: 9, color: PALETTE.textGhost, marginBottom: 4, textTransform: 'uppercase' }}>Organization</div>
                <Select value={form.org || ''} onChange={v => setForm(f => ({ ...f, org: v }))}
                  options={[{ value: '', label: '— none —' }, ...orgs.map(o => ({ value: o.id, label: o.name }))]} />
              </div>
            </div>
            <div>
              <div style={{ fontSize: 9, color: PALETTE.textGhost, marginBottom: 4, textTransform: 'uppercase' }}>Description</div>
              <textarea value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} rows={2}
                style={{ width: '100%', background: PALETTE.bg3, border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 8px', color: PALETTE.textDim, fontSize: 11, outline: 'none', fontFamily: FONTS.mono, resize: 'vertical' }} />
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              <button onClick={handleAdd} style={{ background: accent, border: 'none', borderRadius: 4, padding: '6px 14px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: FONTS.mono }}>Create</button>
              <button onClick={() => setShowAdd(false)} style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 10px', cursor: 'pointer', color: PALETTE.textFaint, fontSize: 11, fontFamily: FONTS.mono }}>Cancel</button>
            </div>
          </div>
        )}

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill,minmax(460px,1fr))', gap: 14 }}>
          {projects.map(p => {
            const s = _projectStats(notes, hosts, creds, p.id);
            const isActive = p.id === selectedProject;
            const isEdit = p.id === editId;
            const sc = statusColor[p.status] || '#555';
            return (
              <div key={p.id}
                style={{ background: isActive ? '#12141a' : PALETTE.bg2, border: `1px solid ${(() => { if (isEdit) { return accent + '88'; } if (isActive) { return accent + '44'; } return '#1e2029'; })()}`, borderRadius: 8, padding: 16, transition: 'all .15s', position: 'relative', overflow: 'hidden' }}>
                {isActive && !isEdit && <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 2, background: `linear-gradient(90deg,${accent},${accent}00)` }} />}

                {isEdit ? (
                  /* ── Edit mode ── */
                  <div>
                    <div style={{ fontSize: 11, fontWeight: 600, color: accent, fontFamily: FONTS.display, marginBottom: 12 }}>Editing</div>
                    {_inpField(editForm, setEditForm, 'Name', 'name', 'Corp VPN Breach')}
                    {_inpField(editForm, setEditForm, 'IP / CIDR', 'ip', 'x.x.x.x/24')}
                    {_inpField(editForm, setEditForm, 'Description', 'description', 'Target description...', true)}
                    <div style={{ display: 'flex', gap: 8, marginBottom: 10 }}>
                      <div style={{ flex: 1 }}>
                        <div style={{ fontSize: 9, color: '#505560', marginBottom: 4, textTransform: 'uppercase' }}>OS</div>
                        {sEl(editForm.os, [['Linux','Linux'],['Windows','Windows'],['macOS','macOS'],['Various','Various'],['Unknown','Unknown']], v => setEditForm(f => ({ ...f, os: v })))}
                      </div>
                      <div style={{ flex: 1 }}>
                        <div style={{ fontSize: 9, color: '#505560', marginBottom: 4, textTransform: 'uppercase' }}>Status</div>
                        {sEl(editForm.status, [['active','Active'],['paused','Paused'],['done','Done']], v => setEditForm(f => ({ ...f, status: v })))}
                      </div>
                    </div>
                    <div style={{ marginBottom: 10 }}>
                      <div style={{ fontSize: 9, color: '#505560', marginBottom: 4, textTransform: 'uppercase' }}>Organization</div>
                      {sEl(editForm.org_id || '', [
                        ['', '— none —'],
                        ...orgs.map(o => [o.id, o.name]),
                      ], v => setEditForm(f => ({ ...f, org_id: v })))}
                    </div>
                    <div style={{ marginBottom: 10 }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                        <div style={{ fontSize: 9, color: '#505560', textTransform: 'uppercase' }}>Deploy Env Vars</div>
                        <button onClick={() => setEditForm(f => ({ ...f, env_vars: { ...(f.env_vars || {}), NEW_KEY: '' } }))}
                          style={{ background: 'transparent', border: `1px solid ${accent}44`, borderRadius: 3, padding: '2px 8px', cursor: 'pointer', color: accent, fontSize: 9, fontFamily: FONTS.mono }}>
                          + var
                        </button>
                      </div>
                      {Object.entries(editForm.env_vars || {}).map(([k, v]) => (
                        <div key={k} style={{ display: 'flex', gap: 4, marginBottom: 3 }}>
                          <input value={k} readOnly
                            onChange={e => { const nk = e.target.value; setEditForm(f => { const cp = { ...(f.env_vars || {}) }; delete cp[k]; cp[nk] = v; return { ...f, env_vars: cp }; }); }}
                            style={{ flex: 1, background: '#0a0c10', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '4px 6px', color: PALETTE.textDim, fontSize: 10, fontFamily: FONTS.mono, outline: 'none' }} />
                          <input value={v}
                            onChange={e => setEditForm(f => ({ ...f, env_vars: { ...(f.env_vars || {}), [k]: e.target.value } }))}
                            style={{ flex: 2, background: '#0a0c10', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '4px 6px', color: PALETTE.textDim, fontSize: 10, fontFamily: FONTS.mono, outline: 'none' }} />
                          <button onClick={() => setEditForm(f => { const cp = { ...(f.env_vars || {}) }; delete cp[k]; return { ...f, env_vars: cp }; })}
                            style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '4px 8px', cursor: 'pointer', color: PALETTE.textFaint, fontSize: 10 }}>x</button>
                        </div>
                      ))}
                    </div>
                    <div style={{ display: 'flex', gap: 8 }}>
                      <button onClick={saveEdit} style={{ background: accent, border: 'none', borderRadius: 4, padding: '6px 14px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: FONTS.mono, flex: 1 }}>Save</button>
                      <button onClick={() => setEditId(null)} style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 10px', cursor: 'pointer', color: PALETTE.textFaint, fontSize: 11, fontFamily: FONTS.mono }}>Cancel</button>
                    </div>
                  </div>
                ) : (
                  /* ── View mode ── */
                  <button type="button" onClick={() => onSelect(p.id)} style={{ cursor: 'pointer', width: '100%', textAlign: 'left', background: 'transparent', border: 'none', padding: 0 }}
                    onMouseEnter={e => { if (!isActive) { e.currentTarget.parentElement.style.borderColor = '#2a2d35'; e.currentTarget.parentElement.style.background = '#0f1116'; } }}
                    onMouseLeave={e => { if (!isActive) { e.currentTarget.parentElement.style.borderColor = '#1e2029'; e.currentTarget.parentElement.style.background = '#0d0f14'; } }}>
                    <div style={{ marginBottom: 8 }}>
                      <div style={{ fontSize: 14, fontWeight: 600, color: PALETTE.text, fontFamily: FONTS.display, marginBottom: 4, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{p.name}</div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 9, color: sc, background: `${sc}18`, border: `1px solid ${sc}44`, borderRadius: 3, padding: '1px 7px', textTransform: 'uppercase', letterSpacing: '0.1em', fontWeight: 600 }}>
                          <span style={{ width: 5, height: 5, borderRadius: '50%', background: sc, boxShadow: `0 0 4px ${sc}` }} />
                          {{ active: 'Active', paused: 'Paused' }[p.status] || 'Done'}
                        </span>
                        <span style={{ fontSize: 9, color: '#505560', fontFamily: FONTS.mono }}>{OS_ICONS[p.os] || '?'} {p.os}</span>
                        {orgName(p.org_id) && (
                          <span title={`Organization: ${orgName(p.org_id)}`} style={{ fontSize: 9, color: '#5b8af5', background: '#5b8af518', border: '1px solid #5b8af544', borderRadius: 3, padding: '1px 6px', fontFamily: FONTS.mono }}>{orgName(p.org_id)}</span>
                        )}
                      </div>
                    </div>
                    <div title={p.description} style={{ fontSize: 10, color: PALETTE.textFaint, marginBottom: 10, lineHeight: 1.4, display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical', overflow: 'hidden' }}>{p.description}</div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6 }}>
                      <Icon name="target" size={10} color="#404550" />
                      {/* p.ip aggregates the project's scope values (comma-joined
                          by sync_project_ip_from_scopes) — with a large scope this
                          is a wall of text, so one line + ellipsis, full in tooltip */}
                      <span title={p.ip} style={{ fontSize: 10, color: '#505560', fontFamily: FONTS.mono, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{p.ip || '—'}</span>
                      <span style={{ fontSize: 9, color: '#303540', marginLeft: 'auto', fontFamily: FONTS.mono }}>{p.added}</span>
                    </div>
                    <ProjectScopeBadges scopes={scopes} pid={p.id} />
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 8, borderTop: '1px solid #1e2029', paddingTop: 10, marginBottom: 10 }}>
                      {[['notes', 'Notes', s.notes, '#6fc8f0'], ['hosts', 'Hosts', s.hosts, '#c07af0'], ['creds', 'Creds', s.creds, '#39d353'], ['target', 'Pwned', s.pwned, '#cc2233']].map(([icon, label, val, c]) => (
                        <div key={label} style={{ textAlign: 'center' }}>
                          <div style={{ fontSize: 18, fontWeight: 700, color: val > 0 ? c : '#303540', fontFamily: FONTS.display }}>{val}</div>
                          <div style={{ fontSize: 9, color: PALETTE.textGhost, marginTop: 2 }}>{label}</div>
                        </div>
                      ))}
                    </div>
                    <ProjectCardActions p={p} accent={accent} canFor={canFor} exportingId={exportingId} handleExport={handleExport} setMembersPid={setMembersPid} onImport={onImport} startEdit={startEdit} setConfirmDelete={setConfirmDelete} onCloseProject={setCloseProjectId} />
                  </button>
                )}
              </div>
            );
          })}
         </div>
       </div>
      {closeProjectId && <ClosureWizard projectId={closeProjectId} accent={accent} onClose={() => setCloseProjectId(null)} onDone={() => setCloseProjectId(null)} />}
     </div>
   );
}

ProjectsView.propTypes = {
  projects: PropTypes.array,
  notes: PropTypes.array,
  hosts: PropTypes.array,
  creds: PropTypes.array,
  scopes: PropTypes.array,
  selectedProject: PropTypes.string,
  onSelect: PropTypes.func,
  accent: PropTypes.string,
  onAdd: PropTypes.func,
  onAddScope: PropTypes.func,
  onUpdate: PropTypes.func,
  onDelete: PropTypes.func,
  onImport: PropTypes.func,
  onProjectImported: PropTypes.func,
};
