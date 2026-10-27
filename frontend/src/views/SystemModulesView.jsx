import { useEffect, useMemo, useState } from 'react';
import PropTypes from 'prop-types';
import Icon from '../components/Icon.jsx';
import { api } from '../api.js';
import { moduleRegistry } from '../features/plugins/registry.js';
import { PALETTE, FONTS } from '../components/UI.jsx';

const INP_STYLE = { width: '100%', background: '#0a0c10', border: `1px solid ${PALETTE.border}`, borderRadius: 5, padding: '8px 10px', color: PALETTE.textDim, fontSize: 12, outline: 'none', fontFamily: FONTS.mono, boxSizing: 'border-box' };

function FieldLabel({ children }) {
  return <div style={{ fontSize: 9, color: PALETTE.textGhost, marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>{children}</div>;
}
FieldLabel.propTypes = { children: PropTypes.any };


// ── Module-level helpers ───────────────────────────────────────────────
function _syncModuleRegistry(items) {
  for (const mod of items) {
    if (!moduleRegistry.get(mod.name)) {
      continue;
    }
    if (mod.enabled) {
      moduleRegistry.enable(mod.name);
    }
    else {
      moduleRegistry.disable(mod.name);
    }
  }
}

async function _loadModulesData(setModules, setConnectors, setError, setLoading) {
  setLoading(true);
  try {
    const [data, connectorData] = await Promise.all([
      api.adminListModules(),
      api.listConnectors().catch(() => ({ connectors: [] })),
    ]);
    const items = data.modules || [];
    setModules(items);
    setConnectors(connectorData.connectors || []);
    _syncModuleRegistry(items);
  } catch (e) {
    setError(e.message);
  } finally {
    setLoading(false);
  }
}

async function _toggleModuleEnabled(mod, setModules) {
  const updated = await api.adminUpdateModule(mod.name, { enabled: !mod.enabled });
  setModules(prev => prev.map(item => item.name === mod.name ? updated : item));
  if (moduleRegistry.get(mod.name)) {
    if (updated.enabled) {
      moduleRegistry.enable(mod.name);
    }
    else {
      moduleRegistry.disable(mod.name);
    }
  }
}

function EditModuleModal({ module, accent, onClose, onSave }) {
  const [form, setForm] = useState({ title: module.title || module.name, version: module.version || '1.0.0', description: module.description || '' });
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  const submit = async () => {
    setSaving(true);
    setError('');
    try {
      await onSave(form);
      onClose();
    } catch (e) {
      setError(e.message || 'Failed to save module');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div style={{ position: 'fixed', inset: 0, background: '#000000aa', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 500, backdropFilter: 'blur(3px)' }}>
      <div style={{ background: PALETTE.bg3, border: `1px solid ${accent}44`, borderRadius: 10, padding: '28px 32px', width: 440, boxShadow: '0 20px 60px #00000099' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 18 }}>
          <div style={{ fontSize: 14, fontWeight: 700, color: PALETTE.text, fontFamily: FONTS.display }}>Edit module</div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', display: 'flex' }}><Icon name="close" size={14} color="#606570" /></button>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {[['Title', 'title'], ['Version', 'version']].map(([label, key]) => (
            <div key={key}>
              <FieldLabel>{label}</FieldLabel>
              <input style={INP_STYLE} value={form[key]} onChange={e => setForm(prev => ({ ...prev, [key]: e.target.value }))} />
            </div>
          ))}
          <div>
            <FieldLabel>Description</FieldLabel>
            <textarea style={{ ...INP_STYLE, resize: 'vertical', minHeight: 100, lineHeight: 1.5 }} value={form.description} onChange={e => setForm(prev => ({ ...prev, description: e.target.value }))} />
          </div>
          {error && <div style={{ fontSize: 11, color: PALETTE.danger }}>{error}</div>}
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
            <button onClick={onClose} style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 5, padding: '7px 14px', cursor: 'pointer', color: PALETTE.textFaint, fontSize: 11, fontFamily: FONTS.mono }}>Cancel</button>
            <button onClick={submit} disabled={saving} style={{ background: accent, border: 'none', borderRadius: 5, padding: '7px 16px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 700, fontFamily: FONTS.mono }}>{saving ? 'Saving...' : 'Save'}</button>
          </div>
        </div>
      </div>
    </div>
  );
}
EditModuleModal.propTypes = { module: PropTypes.any, accent: PropTypes.any, onClose: PropTypes.any, onSave: PropTypes.any };

export default function SystemModulesView({ accent }) {
  const [modules, setModules] = useState([]);
  const [connectors, setConnectors] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [showCreate, setShowCreate] = useState(false);
  const [editing, setEditing] = useState(null);
  const [creating, setCreating] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [validation, setValidation] = useState(null);
  const [uploadError, setUploadError] = useState('');
  const [form, setForm] = useState({ name: '', title: '', version: '1.0.0', description: '' });

  const load = () => _loadModulesData(setModules, setConnectors, setError, setLoading);

  useEffect(() => { load(); }, []);

  const stats = useMemo(() => ({
    total: modules.length,
    enabled: modules.filter(m => m.enabled).length,
    custom: modules.filter(m => m.source === 'custom').length,
  }), [modules]);

  const connectorStats = useMemo(() => ({
    total: connectors.length,
    enabled: connectors.filter(c => c.enabled !== false).length,
    categories: new Set(connectors.map(c => c.category).filter(Boolean)).size,
  }), [connectors]);

  const toggleModule = (mod) => _toggleModuleEnabled(mod, setModules);

  const createModule = async () => {
    setCreating(true);
    setError('');
    try {
      const created = await api.adminCreateModule(form);
      setModules(prev => [...prev, created].sort((a, b) => a.title.localeCompare(b.title)));
      setForm({ name: '', title: '', version: '1.0.0', description: '' });
      setShowCreate(false);
    } catch (e) {
      setError(e.message);
    } finally {
      setCreating(false);
    }
  };

  const saveModule = async (mod, payload) => {
    const updated = await api.adminUpdateModule(mod.name, payload);
    setModules(prev => prev.map(item => item.name === mod.name ? updated : item));
  };

  const removeModule = async (mod) => {
    await api.adminDeleteModule(mod.name);
    setModules(prev => prev.filter(item => item.name !== mod.name));
  };

  const downloadTemplate = async () => {
    const blob = await api.adminDownloadModuleTemplate();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'module_template.py';
    a.click();
    URL.revokeObjectURL(url);
  };

  const downloadFrontendTemplate = async () => {
    const blob = await api.adminDownloadFrontendModuleTemplate();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'frontend_module_template.js';
    a.click();
    URL.revokeObjectURL(url);
  };

  const validateModule = async (file) => {
    const content = await file.text();
    return api.adminValidateModule({ filename: file.name, content });
  };

  const uploadModule = async (file) => {
    if (!file) {
      return;
    }
    setUploading(true);
    setError('');
    setUploadError('');
    setValidation(null);
    try {
      const validationResult = await validateModule(file);
      setValidation(validationResult);
      const created = await api.adminUploadModule(file);
      setModules(prev => [...prev, created].sort((a, b) => a.title.localeCompare(b.title)));
    } catch (e) {
      setUploadError(e.message || 'Failed to upload module');
    } finally {
      setUploading(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
      {editing && <EditModuleModal module={editing} accent={accent} onClose={() => setEditing(null)} onSave={(payload) => saveModule(editing, payload)} />}

      <div>
        <div style={{ fontSize: 9, color: PALETTE.textGhost, letterSpacing: '0.15em', textTransform: 'uppercase', marginBottom: 6 }}>System control</div>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
          <h1 style={{ fontSize: 22, fontWeight: 700, color: PALETTE.text, fontFamily: FONTS.display }}>Modules</h1>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
            <button onClick={downloadTemplate} style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 6, padding: '8px 14px', cursor: 'pointer', color: '#808590', fontSize: 11, fontWeight: 600, fontFamily: FONTS.mono, display: 'flex', alignItems: 'center', gap: 6 }}>
              <Icon name="export" size={11} color="currentColor" /> Get template
            </button>
            <button onClick={downloadFrontendTemplate} style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 6, padding: '8px 14px', cursor: 'pointer', color: '#808590', fontSize: 11, fontWeight: 600, fontFamily: FONTS.mono, display: 'flex', alignItems: 'center', gap: 6 }}>
              <Icon name="export" size={11} color="currentColor" /> Frontend template
            </button>
            <label style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 6, padding: '8px 14px', cursor: uploading ? 'wait' : 'pointer', color: '#808590', fontSize: 11, fontWeight: 600, fontFamily: FONTS.mono, display: 'flex', alignItems: 'center', gap: 6, opacity: uploading ? 0.7 : 1 }}>
              <Icon name="plus" size={11} color="currentColor" /> {uploading ? 'Uploading...' : 'Upload module'}
              <input type="file" accept=".py,text/x-python" style={{ display: 'none' }} onChange={e => e.target.files?.[0] && uploadModule(e.target.files[0])} disabled={uploading} />
            </label>
            <button onClick={() => setShowCreate(v => !v)} style={{ background: accent, border: 'none', borderRadius: 6, padding: '8px 18px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: FONTS.mono, display: 'flex', alignItems: 'center', gap: 6 }}>
              <Icon name="plus" size={11} color="#fff" /> Add module
            </button>
          </div>
        </div>
      </div>

      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        {[[stats.total, 'Total', '#808590'], [stats.enabled, 'Enabled', '#39d353'], [stats.custom, 'Custom', accent]].map(([value, label, color]) => (
          <div key={label} style={{ minWidth: 110, background: PALETTE.bg2, border: '1px solid #1e2029', borderRadius: 8, padding: '10px 12px' }}>
            <div style={{ fontSize: 20, fontWeight: 700, color, fontFamily: FONTS.display }}>{value}</div>
            <div style={{ fontSize: 9, color: '#505560', textTransform: 'uppercase', letterSpacing: '0.1em' }}>{label}</div>
          </div>
        ))}
      </div>

      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        {[[connectorStats.total, 'Connectors', '#6fc8f0'], [connectorStats.enabled, 'Active connectors', '#39d353'], [connectorStats.categories, 'Categories', '#c07af0']].map(([value, label, color]) => (
          <div key={label} style={{ minWidth: 140, background: PALETTE.bg2, border: '1px solid #1e2029', borderRadius: 8, padding: '10px 12px' }}>
            <div style={{ fontSize: 20, fontWeight: 700, color, fontFamily: FONTS.display }}>{value}</div>
            <div style={{ fontSize: 9, color: '#505560', textTransform: 'uppercase', letterSpacing: '0.1em' }}>{label}</div>
          </div>
        ))}
      </div>

      {showCreate && (
        <div style={{ background: PALETTE.bg2, border: `1px solid ${accent}44`, borderRadius: 10, padding: 18, display: 'grid', gridTemplateColumns: '1fr 1fr 120px', gap: 10 }}>
          <div>
            <FieldLabel>Module name</FieldLabel>
            <input style={INP_STYLE} value={form.name} onChange={e => setForm(prev => ({ ...prev, name: e.target.value }))} placeholder="my_module" />
          </div>
          <div>
            <FieldLabel>Title</FieldLabel>
            <input style={INP_STYLE} value={form.title} onChange={e => setForm(prev => ({ ...prev, title: e.target.value }))} placeholder="My Module" />
          </div>
          <div>
            <FieldLabel>Version</FieldLabel>
            <input style={INP_STYLE} value={form.version} onChange={e => setForm(prev => ({ ...prev, version: e.target.value }))} />
          </div>
          <div style={{ gridColumn: '1 / -1' }}>
            <FieldLabel>Description</FieldLabel>
            <textarea style={{ ...INP_STYLE, resize: 'vertical', minHeight: 70 }} value={form.description} onChange={e => setForm(prev => ({ ...prev, description: e.target.value }))} />
          </div>
          <div style={{ gridColumn: '1 / -1', display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
            <button onClick={() => setShowCreate(false)} style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 5, padding: '7px 14px', cursor: 'pointer', color: PALETTE.textFaint, fontSize: 11, fontFamily: FONTS.mono }}>Cancel</button>
            <button onClick={createModule} disabled={creating || !form.name.trim() || !form.title.trim()} style={{ background: accent, border: 'none', borderRadius: 5, padding: '7px 16px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 700, fontFamily: FONTS.mono, opacity: creating || !form.name.trim() || !form.title.trim() ? 0.7 : 1 }}>{creating ? 'Creating...' : 'Create module'}</button>
          </div>
        </div>
      )}

      {error && <div style={{ background: '#cc233318', border: '1px solid #cc233344', borderRadius: 6, padding: '10px 14px', fontSize: 12, color: PALETTE.danger }}>{error}</div>}
      {validation && (
        <div style={{ background: '#39d35318', border: '1px solid #39d35333', borderRadius: 6, padding: '10px 14px', fontSize: 12, color: PALETTE.ok }}>
          Validation passed for `{validation.module_name}`{validation.warnings?.length ? ` with ${validation.warnings.length} warning(s)` : ''}.
        </div>
      )}
      {validation?.warnings?.length > 0 && (
        <div style={{ background: '#f09a3a18', border: '1px solid #f09a3a33', borderRadius: 6, padding: '10px 14px', fontSize: 12, color: PALETTE.warn }}>
          {validation?.warnings?.join(' | ')}
        </div>
      )}
      {uploadError && (
        <div style={{ background: '#cc233318', border: '1px solid #cc233344', borderRadius: 6, padding: '10px 14px', fontSize: 12, color: PALETTE.danger, whiteSpace: 'pre-wrap', fontFamily: FONTS.mono }}>{uploadError}</div>
      )}

      <div style={{ background: PALETTE.bg2, border: '1px solid #1e2029', borderRadius: 10, overflow: 'auto' }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'minmax(220px, 1fr) 90px 90px 120px 180px', gap: 0, padding: '10px 18px', borderBottom: '1px solid #1e2029', background: '#090b0f' }}>
          {['Module', 'Version', 'Status', 'Source', 'Actions'].map(h => <div key={h} style={{ fontSize: 9, color: PALETTE.textGhost, textTransform: 'uppercase', letterSpacing: '0.1em' }}>{h}</div>)}
        </div>
        {loading && <div style={{ padding: 24, textAlign: 'center', color: PALETTE.textGhost, fontSize: 12 }}>Loading...</div>}
        {!loading && modules.map((mod, i) => (
          <div key={mod.name} style={{ display: 'grid', gridTemplateColumns: 'minmax(220px, 1fr) 90px 90px 120px 180px', gap: 0, padding: '13px 18px', borderBottom: i < modules.length - 1 ? '1px solid #14161b' : 'none', alignItems: 'center' }}>
            <div>
              <div style={{ fontSize: 13, color: PALETTE.text, fontWeight: 600, fontFamily: FONTS.display }}>{mod.title}</div>
              <div style={{ fontSize: 10, color: PALETTE.textFaint, fontFamily: FONTS.mono }}>{mod.name}</div>
              {mod.description && <div style={{ fontSize: 11, color: PALETTE.textFaint, fontFamily: FONTS.mono, marginTop: 4, lineHeight: 1.4 }}>{mod.description}</div>}
            </div>
            <div style={{ fontSize: 10, color: PALETTE.textMute, fontFamily: FONTS.mono }}>{mod.version}</div>
            <div>
              <span style={{ fontSize: 10, fontFamily: FONTS.mono, color: mod.enabled ? '#39d353' : PALETTE.textGhost, background: mod.enabled ? '#39d35318' : '#40455018', border: `1px solid ${mod.enabled ? '#39d35344' : '#40455044'}`, borderRadius: 4, padding: '2px 8px' }}>{mod.enabled ? 'Enabled' : 'Disabled'}</span>
            </div>
            <div>
              <span style={{ fontSize: 10, fontFamily: FONTS.mono, color: mod.source === 'custom' ? accent : '#5b8af5', background: mod.source === 'custom' ? `${accent}18` : '#5b8af518', border: `1px solid ${mod.source === 'custom' ? accent + '44' : '#5b8af544'}`, borderRadius: 4, padding: '2px 8px', textTransform: 'uppercase' }}>{mod.source}</span>
            </div>
            <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
              <button onClick={() => toggleModule(mod)} style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '4px 8px', cursor: 'pointer', color: mod.enabled ? '#f09a3a' : PALETTE.ok, fontSize: 10, fontFamily: FONTS.mono }}>{mod.enabled ? 'Disable' : 'Enable'}</button>
              {mod.editable && <button onClick={() => setEditing(mod)} style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '4px 8px', cursor: 'pointer', color: '#5b8af5', fontSize: 10, fontFamily: FONTS.mono }}>Edit</button>}
              {mod.source === 'custom' && <button onClick={() => removeModule(mod)} style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '4px 8px', cursor: 'pointer', color: PALETTE.danger, fontSize: 10, fontFamily: FONTS.mono }}>Delete</button>}
            </div>
          </div>
        ))}
      </div>

      <div style={{ background: PALETTE.bg2, border: '1px solid #1e2029', borderRadius: 10, overflow: 'hidden' }}>
        <div style={{ padding: '12px 18px', borderBottom: '1px solid #1e2029', background: '#090b0f', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div>
            <div style={{ fontSize: 12, color: PALETTE.text, fontWeight: 600, fontFamily: FONTS.display }}>Connector Inventory</div>
            <div style={{ fontSize: 11, color: PALETTE.textFaint, fontFamily: FONTS.mono, marginTop: 2 }}>Normalized orchestration contract aggregated from enabled backend modules</div>
          </div>
        </div>
        {connectors.length ? connectors.map((connector, i) => (
          <div key={`${connector.module}:${connector.key}`} style={{ padding: '14px 18px', borderBottom: i < connectors.length - 1 ? '1px solid #14161b' : 'none' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 6 }}>
              <span style={{ fontSize: 12, color: PALETTE.text, fontWeight: 600, fontFamily: FONTS.display }}>{connector.title}</span>
              <span style={{ fontSize: 10, fontFamily: FONTS.mono, color: '#6fc8f0', background: '#6fc8f018', border: '1px solid #6fc8f033', borderRadius: 4, padding: '1px 7px' }}>{connector.key}</span>
              <span style={{ fontSize: 10, fontFamily: FONTS.mono, color: '#c07af0', background: '#c07af018', border: '1px solid #c07af033', borderRadius: 4, padding: '1px 7px', textTransform: 'uppercase' }}>{connector.category}</span>
              <span style={{ fontSize: 10, fontFamily: FONTS.mono, color: PALETTE.textMute }}>module: {connector.module}</span>
            </div>
            {connector.description && <div style={{ fontSize: 11, color: PALETTE.textFaint, fontFamily: FONTS.mono, marginBottom: 8, lineHeight: 1.5 }}>{connector.description}</div>}
            <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', fontSize: 11, color: PALETTE.textFaint, fontFamily: FONTS.mono, lineHeight: 1.6 }}>
              <span><span style={{ color: PALETTE.textGhost }}>ops </span>{(connector.supported_operations || []).join(', ') || '—'}</span>
              <span><span style={{ color: PALETTE.textGhost }}>sources </span>{(connector.supported_sources || []).join(', ') || '—'}</span>
              <span><span style={{ color: PALETTE.textGhost }}>creates </span>{(connector.creates_entities || []).join(', ') || '—'}</span>
              <span><span style={{ color: PALETTE.textGhost }}>mode </span>{connector.execution_mode || 'sync'}</span>
            </div>
          </div>
        )) : (
          <div style={{ padding: 18, color: PALETTE.textFaint, fontSize: 11, fontFamily: FONTS.mono }}>No connectors discovered.</div>
        )}
      </div>

      {(() => {
        // SSH Executor target management moved to Infra → Connections
        // (2026-09-22); the module on/off switch stays here.
        return null;
      })()}
    </div>
  );
}
SystemModulesView.propTypes = { accent: PropTypes.any };
