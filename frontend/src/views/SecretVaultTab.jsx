import { useState, useEffect, useCallback } from 'react';
import PropTypes from 'prop-types';
import Icon from '../components/Icon.jsx';
import { api } from '../api.js';
import { toastError, toastSuccess } from '../components/Toast.jsx';
import { PALETTE, FONTS, Select } from '../components/UI.jsx';
import { uiConfirm } from '../components/Confirm.jsx';

export default function SecretVaultTab({ selectedProject, accent }) {
  const [secrets, setSecrets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);

  const load = useCallback(async () => {
    if (!selectedProject) return;
    setLoading(true);
    try { setSecrets(await api.listSecrets(selectedProject)); }
    catch (e) { toastError(e.message); }
    setLoading(false);
  }, [selectedProject]);

  useEffect(() => { load(); }, [load]);

  const handleRevoke = async (sid) => {
    try { await api.revokeSecret(selectedProject, sid); toastSuccess('Secret revoked'); load(); }
    catch (e) { toastError(e.message); }
  };

  const handleDelete = async (sid) => {
    if (!await uiConfirm('Delete this secret permanently?')) return;
    try { await api.deleteSecret(selectedProject, sid); toastSuccess('Secret deleted'); load(); }
    catch (e) { toastError(e.message); }
  };

  const handleGenerateSSH = async () => {
    try {
      await api.generateSSHKey(selectedProject, { name: `ssh-${Date.now()}` });
      toastSuccess('SSH key generated');
      load();
    } catch (e) { toastError(e.message); }
  };

  if (loading) return <div style={{ padding: 20, color: PALETTE.textGhost, fontFamily: FONTS.mono, fontSize: 11 }}>Loading secrets...</div>;

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 6, marginBottom: 12 }}>
        <button onClick={handleGenerateSSH} style={{ padding: '4px 10px', borderRadius: 4, border: '1px solid ' + accent + '66', background: 'transparent', color: accent, fontSize: 10, fontFamily: FONTS.mono, cursor: 'pointer' }}>+ Generate SSH Key</button>
        <button onClick={() => setShowCreate(true)} style={{ padding: '4px 10px', borderRadius: 4, border: 'none', background: accent, color: '#fff', fontSize: 10, fontFamily: FONTS.mono, cursor: 'pointer' }}>+ Add Secret</button>
      </div>

      {secrets.length === 0 && <div style={{ textAlign: 'center', padding: 30, color: PALETTE.textGhost, fontFamily: FONTS.mono, fontSize: 11 }}>No secrets in vault.</div>}

      {secrets.map(s => (
        <div key={s.id} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '8px 0', borderBottom: '1px solid #1e2029' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: 12 }}>🔑</span>
            <div>
              <div style={{ fontSize: 12, color: PALETTE.textDim, fontFamily: FONTS.mono }}>{s.name}</div>
              <div style={{ fontSize: 10, color: PALETTE.textFaint, fontFamily: FONTS.mono }}>{s.secret_type || s.type} {s.algorithm || ''}</div>
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{ fontSize: 9, color: s.status === 'active' ? '#22c55e' : PALETTE.danger, fontFamily: FONTS.mono }}>{s.status === 'active' ? '✅ Active' : '⚠ Revoked'}</span>
            {s.status === 'active' && <button onClick={() => handleRevoke(s.id)} style={{ padding: '2px 8px', borderRadius: 3, border: '1px solid #f09a3a66', background: 'transparent', color: PALETTE.warn, fontSize: 9, fontFamily: FONTS.mono, cursor: 'pointer' }}>Revoke</button>}
            <button onClick={() => handleDelete(s.id)} style={{ padding: '2px 8px', borderRadius: 3, border: '1px solid #cc223344', background: 'transparent', color: PALETTE.danger, fontSize: 9, fontFamily: FONTS.mono, cursor: 'pointer' }}>Delete</button>
          </div>
        </div>
      ))}

      {showCreate && <CreateSecretModal accent={accent} selectedProject={selectedProject} onClose={() => setShowCreate(false)} onDone={load} />}
    </div>
  );
}

function CreateSecretModal({ accent, selectedProject, onClose, onDone }) {
  const [name, setName] = useState('');
  const [secretType, setSecretType] = useState('password');
  const [value, setValue] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async () => {
    if (!name || !value) return;
    setLoading(true);
    try {
      await api.createSecret(selectedProject, { name, secret_type: secretType, value });
      toastSuccess('Secret created');
      onDone();
      onClose();
    } catch (e) { toastError(e.message); }
    setLoading(false);
  };

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }} onClick={onClose}>
      <div style={{ background: '#0f1117', border: `1px solid ${PALETTE.border}`, borderRadius: 8, padding: 20, width: 360 }} onClick={e => e.stopPropagation()}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <span style={{ fontSize: 13, fontWeight: 600, color: PALETTE.textDim, fontFamily: FONTS.mono }}>Add Secret</span>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: PALETTE.textFaint, cursor: 'pointer' }}><Icon name="close" size={14} /></button>
        </div>
        <div style={{ marginBottom: 10 }}>
          <label style={{ fontSize: 10, color: '#808590', display: 'block', marginBottom: 3, fontFamily: FONTS.mono }}>Name</label>
          <input value={name} onChange={e => setName(e.target.value)} placeholder="ssh-key-project"
            style={{ width: '100%', background: '#0a0c10', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 8px', color: PALETTE.textDim, fontSize: 11, fontFamily: FONTS.mono, outline: 'none' }} />
        </div>
        <div style={{ marginBottom: 10 }}>
          <label style={{ fontSize: 10, color: '#808590', display: 'block', marginBottom: 3, fontFamily: FONTS.mono }}>Type</label>
          <Select value={secretType} onChange={setSecretType} style={{ width: '100%' }}
            options={['password', 'ssh_key', 'api_token', 'certificate', 'vpn_config', 'other']} />
        </div>
        <div style={{ marginBottom: 16 }}>
          <label style={{ fontSize: 10, color: '#808590', display: 'block', marginBottom: 3, fontFamily: FONTS.mono }}>Value</label>
          <textarea value={value} onChange={e => setValue(e.target.value)} rows={4} placeholder="Secret value..."
            style={{ width: '100%', background: '#0a0c10', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 8px', color: PALETTE.textDim, fontSize: 11, fontFamily: FONTS.mono, outline: 'none', resize: 'vertical' }} />
        </div>
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
          <button onClick={onClose} style={{ padding: '6px 14px', borderRadius: 4, border: `1px solid ${PALETTE.border}`, background: 'transparent', color: '#808590', fontSize: 11, fontFamily: FONTS.mono, cursor: 'pointer' }}>Cancel</button>
          <button onClick={handleSubmit} disabled={!name || !value || loading} style={{ padding: '6px 14px', borderRadius: 4, border: 'none', background: accent, color: '#fff', fontSize: 11, fontFamily: FONTS.mono, cursor: name && value && !loading ? 'pointer' : 'not-allowed', opacity: name && value && !loading ? 1 : 0.5 }}>Create</button>
        </div>
      </div>
    </div>
  );
}

SecretVaultTab.propTypes = { selectedProject: PropTypes.string, accent: PropTypes.string };
CreateSecretModal.propTypes = { accent: PropTypes.string, selectedProject: PropTypes.string, onClose: PropTypes.func, onDone: PropTypes.func };
