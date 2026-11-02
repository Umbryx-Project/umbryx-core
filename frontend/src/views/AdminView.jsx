import { useEffect, useState, useCallback, useRef } from 'react';
import PropTypes from 'prop-types';
import { toastError, toastSuccess } from '../components/Toast.jsx';
import Icon from '../components/Icon.jsx';
import { api } from '../api.js';
import SystemModulesView from './SystemModulesView.jsx';
import ProjectAccessSection from '../components/admin/ProjectAccessSection.jsx';
import AISection from '../components/admin/AISection.jsx';
import PluginsPanel from './PluginsPanel.jsx';
import { GLOBAL_ROLE_COLOR, GLOBAL_ROLE_LABEL, EVENT_LABELS, DEFAULT_CONFIG, inp } from '../utils/admin.js';
import { Card, Overline, Checkbox, PALETTE, Select } from '../components/UI.jsx';
import { EE_WORKSTATION_PROVISIONING } from '@ee';
import DevOpsLogSection from './admin/DevOpsLogSection.jsx';
import { uiConfirm } from '../components/Confirm.jsx';

// Registries holds credentials for private images used when *deploying*
// workstations, and POST /workstations/image-registries is refused outright
// in Community (routers/workstations.py:61) — so there the section could only
// be opened and then fail. It is listed only where it can work.
const ADMIN_SECTIONS = [
  ['users', 'User Management'],
  ['system', 'System Modules'],
  ['plugins', 'Plugins'],
  ['encryption', 'Encryption'],
  ...(EE_WORKSTATION_PROVISIONING ? [['registries', 'Registries']] : []),
  ['devops', 'DevOps Log'],
  ['notifications', 'Notifications'],
  ['ai', 'AI'],
];

function ConfirmDialog({ text, onConfirm, onCancel }) {
  return (
    <div style={{ position: 'fixed', inset: 0, background: '#000000aa', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 400, backdropFilter: 'blur(3px)' }}>
      <div style={{ background: '#0e1016', border: '1px solid #cc233344', borderRadius: 10, padding: '28px 32px', width: 360, boxShadow: '0 20px 60px #00000099' }}>
        <div style={{ fontSize: 14, fontWeight: 700, color: '#f0f2f6', fontFamily: 'Space Grotesk', marginBottom: 12 }}>Confirm</div>
        <div style={{ fontSize: 12, color: '#808590', lineHeight: 1.6, marginBottom: 24 }}>{text}</div>
        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
          <button onClick={onCancel} style={{ background: 'none', border: '1px solid #2a2d35', borderRadius: 5, padding: '7px 16px', cursor: 'pointer', color: '#606570', fontSize: 11, fontFamily: 'JetBrains Mono' }}>Cancel</button>
          <button onClick={onConfirm} style={{ background: '#cc2233', border: 'none', borderRadius: 5, padding: '7px 16px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono' }}>Delete</button>
        </div>
      </div>
    </div>
  );
}
ConfirmDialog.propTypes = { text: PropTypes.string, onConfirm: PropTypes.func, onCancel: PropTypes.func };

function CreateUserModal({ accent, onClose, onCreated }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('user');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const submit = async () => {
    if (!username.trim() || !password) return;
    setError(''); setLoading(true);
    try {
      const user = await api.adminCreateUser({ username: username.trim(), password, role });
      onCreated(user);
      onClose();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const inp = { width: '100%', background: '#0a0c10', border: '1px solid #2a2d35', borderRadius: 5, padding: '7px 10px', color: '#c8cdd6', fontSize: 12, outline: 'none', fontFamily: 'JetBrains Mono', boxSizing: 'border-box' };

  return (
    <div style={{ position: 'fixed', inset: 0, background: '#000000aa', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 400, backdropFilter: 'blur(3px)' }}>
      <div style={{ background: '#0e1016', border: `1px solid ${accent}44`, borderRadius: 10, padding: '28px 32px', width: 380, boxShadow: '0 20px 60px #00000099' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
          <div style={{ fontSize: 14, fontWeight: 700, color: '#f0f2f6', fontFamily: 'Space Grotesk' }}>New user</div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', display: 'flex' }}><Icon name="close" size={14} color="#606570" /></button>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          {[['Login', username, setUsername, 'text', 'username'], ['Password', password, setPassword, 'password', 'new-password']].map(([label, val, set, type, ac]) => (
            <div key={label}>
              <div style={{ fontSize: 9, color: '#404550', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>{label}</div>
              <input style={inp} type={type} value={val} onChange={e => set(e.target.value)} autoComplete={ac} onKeyDown={e => e.key === 'Enter' && submit()} />
            </div>
          ))}
          <div>
            <div style={{ fontSize: 9, color: '#404550', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Role</div>
            <div style={{ display: 'flex', gap: 6 }}>
              {['viewer', 'user', 'platform_admin'].map(r => (
                <button key={r} onClick={() => setRole(r)}
                  style={{ flex: 1, background: role === r ? `${GLOBAL_ROLE_COLOR[r]}22` : 'transparent', border: `1px solid ${role === r ? GLOBAL_ROLE_COLOR[r] + '88' : '#2a2d35'}`, borderRadius: 5, padding: '6px 0', cursor: 'pointer', color: role === r ? GLOBAL_ROLE_COLOR[r] : '#606570', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono', transition: 'all .1s' }}>
                  {GLOBAL_ROLE_LABEL[r] || r}
                </button>
              ))}
            </div>
          </div>
          {error && <div style={{ background: '#cc233318', border: '1px solid #cc233344', borderRadius: 5, padding: '7px 10px', fontSize: 11, color: '#cc2233' }}>{error}</div>}
          <button onClick={submit} disabled={loading || !username.trim() || !password}
            style={{ background: username.trim() && password ? accent : '#1a1c22', border: 'none', borderRadius: 5, padding: '9px 0', cursor: 'pointer', color: '#fff', fontSize: 12, fontWeight: 700, fontFamily: 'JetBrains Mono', marginTop: 4, transition: 'background .15s' }}>
            {loading ? 'Creating...' : 'Create'}
          </button>
        </div>
      </div>
    </div>
  );
}
CreateUserModal.propTypes = { accent: PropTypes.string, onClose: PropTypes.func, onCreated: PropTypes.func };

function ResetPasswordModal({ user, accent, onClose }) {
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState('');
  const [done, setDone] = useState(false);
  const [loading, setLoading] = useState(false);

  const submit = async () => {
    if (password.length < 4) { setError('Minimum 4 characters'); return; }
    if (password !== confirm) { setError('Passwords do not match'); return; }
    setError(''); setLoading(true);
    try { await api.adminUpdateUser(user.id, { password }); setDone(true); }
    catch (err) { setError(err.message); }
    finally { setLoading(false); }
  };

  const inp = { width: '100%', background: '#0a0c10', border: '1px solid #2a2d35', borderRadius: 5, padding: '7px 10px', color: '#c8cdd6', fontSize: 12, outline: 'none', fontFamily: 'JetBrains Mono', boxSizing: 'border-box' };

  return (
    <div style={{ position: 'fixed', inset: 0, background: '#000000aa', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 400, backdropFilter: 'blur(3px)' }}>
      <div style={{ background: '#0e1016', border: `1px solid ${accent}44`, borderRadius: 10, padding: '28px 32px', width: 360, boxShadow: '0 20px 60px #00000099' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 18 }}>
          <div style={{ fontSize: 14, fontWeight: 700, color: '#f0f2f6', fontFamily: 'Space Grotesk' }}>Reset password</div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', display: 'flex' }}><Icon name="close" size={14} color="#606570" /></button>
        </div>
        <div style={{ fontSize: 11, color: '#606570', marginBottom: 18 }}>User: <span style={{ color: accent, fontFamily: 'JetBrains Mono' }}>{user.username}</span></div>
        {done ? (
          <div style={{ background: '#39d35322', border: '1px solid #39d35344', borderRadius: 5, padding: '12px', fontSize: 12, color: '#39d353', textAlign: 'center' }}>Password changed successfully</div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {[['New password', password, setPassword], ['Confirm', confirm, setConfirm]].map(([label, val, set]) => (
              <div key={label}>
                <div style={{ fontSize: 9, color: '#404550', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>{label}</div>
                <input style={inp} type="password" value={val} onChange={e => set(e.target.value)} />
              </div>
            ))}
            {error && <div style={{ fontSize: 11, color: '#cc2233' }}>{error}</div>}
            <button onClick={submit} disabled={loading}
              style={{ background: accent, border: 'none', borderRadius: 5, padding: '9px 0', cursor: 'pointer', color: '#fff', fontSize: 12, fontWeight: 700, fontFamily: 'JetBrains Mono' }}>
              {loading ? 'Saving...' : 'Set password'}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
ResetPasswordModal.propTypes = { user: PropTypes.object, accent: PropTypes.string, onClose: PropTypes.func };

// ── NotificationsSection ─────────────────────────────────────────────────
function NotificationsSection({ accent }) {
  const [cfg, setCfg] = useState(DEFAULT_CONFIG);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [msg, setMsg] = useState('');
  const [detecting, setDetecting] = useState(false);
  const [detectedChats, setDetectedChats] = useState([]);

  useEffect(() => {
    api.getNotificationConfig().then(data => {
      if (data && typeof data === 'object') {
        setCfg(prev => ({
          ...DEFAULT_CONFIG,
          ...data,
          telegram: { ...DEFAULT_CONFIG.telegram, ...data.telegram },
          slack:    { ...DEFAULT_CONFIG.slack,    ...data.slack },
          webhook:  { ...DEFAULT_CONFIG.webhook,  ...data.webhook },
          events:   { ...DEFAULT_CONFIG.events,   ...data.events },
        }));
      }
    }).catch(() => {});
  }, []);

  const save = async () => {
    setSaving(true); setMsg('');
    try { await api.saveNotificationConfig(cfg); setMsg('Saved.'); }
    catch (e) { setMsg(e.message || 'Save failed'); }
    finally { setSaving(false); }
  };

  const test = async () => {
    setTesting(true); setMsg('');
    try { await api.testNotification(); setMsg('Test message sent.'); }
    catch (e) { setMsg(e.message || 'Test failed'); }
    finally { setTesting(false); }
  };

  const detectChatId = async () => {
    setDetecting(true); setMsg(''); setDetectedChats([]);
    try {
      const data = await api.getTelegramChatIds();
      if (data.chats && data.chats.length > 0) {
        setDetectedChats(data.chats);
      } else {
        setMsg(data.hint || 'No chats found. Send a message to the bot first.');
      }
    } catch (e) { setMsg(e.message || 'Detection failed'); }
    finally { setDetecting(false); }
  };

  const set = (path, val) => setCfg(prev => {
    const parts = path.split('.');
    const next = JSON.parse(JSON.stringify(prev));
    let obj = next;
    for (let i = 0; i < parts.length - 1; i++) obj = obj[parts[i]];
    obj[parts[parts.length - 1]] = val;
    return next;
  });

  const row = { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginBottom: 10 };

  return (
    <div>
      <div style={{ fontSize: 16, color: PALETTE.text, fontWeight: 700, marginBottom: 4 }}>Notifications</div>
      <div style={{ fontSize: 11, color: PALETTE.textFaint, marginBottom: 20 }}>Send alerts to Telegram, Slack, or a custom webhook when key events happen.</div>

      {/* Telegram */}
      <Card style={{ marginBottom: 14 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
          <div style={{ fontSize: 13, color: PALETTE.text, fontWeight: 600, flex: 1 }}>Telegram</div>
          <Checkbox checked={cfg.telegram.enabled} onChange={v => set('telegram.enabled', v)} accent={accent} label={cfg.telegram.enabled ? 'Enabled' : 'Disabled'} />
        </div>
        <div style={row}>
          <div>
            <Overline style={{ marginBottom: 5 }}>Bot token</Overline>
            <input value={cfg.telegram.token} onChange={e => set('telegram.token', e.target.value)} placeholder="1234567890:AAF..." style={inp()} />
          </div>
          <div>
            <Overline style={{ marginBottom: 5 }}>Chat ID</Overline>
            <div style={{ display: 'flex', gap: 6 }}>
              <input value={cfg.telegram.chat_id} onChange={e => set('telegram.chat_id', e.target.value)} placeholder="-100123456789" style={inp({ flex: 1 })} />
              <button onClick={detectChatId} disabled={detecting || !cfg.telegram.token} title="Auto-detect from recent messages"
                style={{ background: 'transparent', border: `1px solid ${accent}44`, borderRadius: 5, padding: '0 10px', cursor: 'pointer', color: accent, fontSize: 11, fontFamily: 'JetBrains Mono', whiteSpace: 'nowrap' }}>
                {detecting ? '…' : 'Detect'}
              </button>
            </div>
            {detectedChats.length > 0 && (
              <div style={{ marginTop: 6, background: PALETTE.bg1, border: `1px solid ${PALETTE.border}`, borderRadius: 4, overflow: 'hidden' }}>
                {detectedChats.map(c => (
                  <button type="button" key={c.id} onClick={() => { set('telegram.chat_id', c.id); setDetectedChats([]); }}
                    style={{ padding: '6px 10px', cursor: 'pointer', borderBottom: `1px solid ${PALETTE.borderSoft}`, fontSize: 11, color: PALETTE.textDim, fontFamily: 'JetBrains Mono', width: '100%', textAlign: 'left', background: 'transparent', borderTop: 'none', borderLeft: 'none', borderRight: 'none' }}
                    onMouseEnter={e => e.currentTarget.style.background = PALETTE.borderSoft}
                    onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
                    <span style={{ color: accent }}>{c.id}</span> — {c.title} <span style={{ color: PALETTE.textGhost }}>({c.type})</span>
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>
        <div style={{ fontSize: 10, color: PALETTE.textFaint }}>Create a bot via @BotFather, add it to a channel/group, then click Detect.</div>
      </Card>

      {/* Slack */}
      <Card style={{ marginBottom: 14 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
          <div style={{ fontSize: 13, color: PALETTE.text, fontWeight: 600, flex: 1 }}>Slack</div>
          <Checkbox checked={cfg.slack.enabled} onChange={v => set('slack.enabled', v)} accent={accent} label={cfg.slack.enabled ? 'Enabled' : 'Disabled'} />
        </div>
        <div>
          <Overline style={{ marginBottom: 5 }}>Incoming webhook URL</Overline>
          <input value={cfg.slack.webhook_url} onChange={e => set('slack.webhook_url', e.target.value)} placeholder="https://hooks.slack.com/services/..." style={inp()} />
        </div>
      </Card>

      {/* Generic webhook */}
      <Card style={{ marginBottom: 14 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
          <div style={{ fontSize: 13, color: PALETTE.text, fontWeight: 600, flex: 1 }}>Custom webhook</div>
          <Checkbox checked={cfg.webhook.enabled} onChange={v => set('webhook.enabled', v)} accent={accent} label={cfg.webhook.enabled ? 'Enabled' : 'Disabled'} />
        </div>
        <div>
          <Overline style={{ marginBottom: 5 }}>URL (POST JSON: event, title, body)</Overline>
          <input value={cfg.webhook.url} onChange={e => set('webhook.url', e.target.value)} placeholder="https://your-server/hook" style={inp()} />
        </div>
      </Card>

      {/* Events */}
      <Card style={{ marginBottom: 14 }}>
        <div style={{ fontSize: 13, color: PALETTE.text, fontWeight: 600, marginBottom: 12 }}>Events</div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {Object.entries(EVENT_LABELS).map(([key, { label: lbl }]) => (
            <Checkbox key={key} checked={cfg.events[key]} onChange={v => set(`events.${key}`, v)} accent={accent} label={lbl} />
          ))}
        </div>
      </Card>

      <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
        <button onClick={save} disabled={saving} style={{ background: accent, border: 'none', borderRadius: 5, padding: '8px 18px', cursor: 'pointer', color: '#fff', fontSize: 12, fontFamily: 'JetBrains Mono', fontWeight: 600 }}>{saving ? 'Saving…' : 'Save'}</button>
        <button onClick={test} disabled={testing} style={{ background: 'transparent', border: `1px solid ${accent}44`, borderRadius: 5, padding: '8px 18px', cursor: 'pointer', color: accent, fontSize: 12, fontFamily: 'JetBrains Mono' }}>{testing ? 'Sending…' : 'Send test'}</button>
        {msg && <span style={{ fontSize: 11, color: msg.includes('failed') || msg.includes('Failed') ? '#f87171' : '#39d353', fontFamily: 'JetBrains Mono' }}>{msg}</span>}
      </div>
    </div>
  );
}
NotificationsSection.propTypes = { accent: PropTypes.string };

// ── EncryptionSection ──────────────────────────────────────────────────
function EncryptionSection({ accent }) {
  const [keys, setKeys] = useState([]);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try { setKeys(await api.listEncryptionKeys(null)); }
    catch (e) { toastError(e.message); }
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleRotate = async (projectId) => {
    if (!await uiConfirm('Rotate DEK for this project?')) return;
    try { await api.rotateDEK(projectId); toastSuccess('DEK rotated successfully'); load(); }
    catch (e) { toastError(e.message); }
  };

  if (loading) return <div style={{ padding: 20, color: '#404550', fontFamily: 'JetBrains Mono', fontSize: 11 }}>Loading...</div>;

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
        <span style={{ fontSize: 13, fontWeight: 600, color: '#c8cdd6', fontFamily: 'JetBrains Mono' }}>Encryption Keys</span>
      </div>
      {keys.length === 0 && <div style={{ color: '#404550', fontFamily: 'JetBrains Mono', fontSize: 11 }}>No DEK records found.</div>}
      {keys.map(k => (
        <Card key={k.id || k.project_id} style={{ marginBottom: 14 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div>
              <div style={{ fontSize: 11, color: PALETTE.textDim, fontFamily: 'JetBrains Mono' }}>Project: {k.project_id || 'N/A'}</div>
              <div style={{ fontSize: 9, color: PALETTE.textFaint, fontFamily: 'JetBrains Mono', marginTop: 2 }}>Algorithm: {k.algorithm || 'AES-256-GCM'} | Created: {k.created_at || 'N/A'}</div>
            </div>
            <button onClick={() => handleRotate(k.project_id)} style={{ padding: '4px 10px', borderRadius: 4, border: '1px solid ' + accent + '66', background: 'transparent', color: accent, fontSize: 10, fontFamily: 'JetBrains Mono', cursor: 'pointer' }}>Rotate DEK</button>
          </div>
        </Card>
      ))}
    </div>
  );
}
EncryptionSection.propTypes = { accent: PropTypes.string };

// ── RegistriesSection ─────────────────────────────────────────────────
function RegistriesSection({ accent }) {
  const [items, setItems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showAdd, setShowAdd] = useState(false);
  const prevShowAdd = useRef(false);

  const load = useCallback(async () => {
    setLoading(true);
    try { setItems(await api.listImageRegistries()); }
    catch (e) { toastError(e.message); }
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    if (prevShowAdd.current && !showAdd) load();
    prevShowAdd.current = showAdd;
  }, [showAdd, load]);

  const handleDelete = async (id) => {
    setItems(prev => prev.filter(r => r.id !== id));
    try { await api.deleteImageRegistry(id); toastSuccess('Registry deleted'); }
    catch (e) { toastError(e.message); load(); }
  };

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
        <span style={{ fontSize: 13, fontWeight: 600, color: '#c8cdd6', fontFamily: 'JetBrains Mono' }}>Image Registries</span>
        <button onClick={() => setShowAdd(true)} style={{ padding: '4px 10px', borderRadius: 4, border: 'none', background: accent, color: '#fff', fontSize: 10, fontFamily: 'JetBrains Mono', cursor: 'pointer' }}>+ Add Registry</button>
      </div>
      <div style={{ fontSize: 10, color: '#505560', fontFamily: 'JetBrains Mono', marginBottom: 14 }}>
        Configure private Docker registries. Credentials are used automatically when deploying workstations with private images.
      </div>

      {loading && <div style={{ color: '#404550', fontFamily: 'JetBrains Mono', fontSize: 11 }}>Loading...</div>}
      {!loading && items.length === 0 && <div style={{ textAlign: 'center', padding: 30, color: '#404550', fontFamily: 'JetBrains Mono', fontSize: 11 }}>No registries configured.</div>}
      {!loading && items.map(r => (
        <Card key={r.id} style={{ marginBottom: 14 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ fontSize: 12, color: PALETTE.textDim, fontFamily: 'JetBrains Mono', fontWeight: 600 }}>{r.name}</span>
                <span style={{ fontSize: 9, color: accent, background: accent + '18', borderRadius: 3, padding: '1px 6px', fontFamily: 'JetBrains Mono' }}>registry</span>
              </div>
              <div style={{ fontSize: 10, color: PALETTE.textFaint, fontFamily: 'JetBrains Mono', marginTop: 3 }}>
                {r.url} {r.username ? `· user: ${r.username}` : ''}
              </div>
            </div>
            <button onClick={() => handleDelete(r.id)} style={{ padding: '3px 8px', borderRadius: 3, border: '1px solid #cc223344', background: 'transparent', color: '#cc2233', fontSize: 9, fontFamily: 'JetBrains Mono', cursor: 'pointer' }}>Delete</button>
          </div>
        </Card>
      ))}

      {showAdd && <AddRegistryModal accent={accent} onClose={() => setShowAdd(false)} />}
    </div>
  );
}

function AddRegistryModal({ accent, onClose }) {
  const [name, setName] = useState('');
  const [url, setUrl] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async () => {
    if (!name || !url) return;
    setLoading(true);
    try {
      await api.addImageRegistry({ name, url, username, password });
      toastSuccess('Registry added');
      onClose();
    } catch (e) { toastError(e.message); }
    setLoading(false);
  };

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }} onClick={onClose}>
      <div style={{ background: '#0f1117', border: '1px solid #2a2d35', borderRadius: 8, padding: 20, width: 400 }} onClick={e => e.stopPropagation()}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <span style={{ fontSize: 13, fontWeight: 600, color: '#c8cdd6', fontFamily: 'JetBrains Mono' }}>Add Registry</span>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: '#606570', cursor: 'pointer', fontSize: 16 }}>×</button>
        </div>
        {[
          ['Name', name, setName, 'My Private Registry'],
          ['URL', url, setUrl, 'registry.example.com'],
          ['Username', username, setUsername, 'docker-user'],
        ].map(([label, val, set, ph]) => (
          <div key={label} style={{ marginBottom: 10 }}>
            <label style={{ fontSize: 10, color: '#808590', display: 'block', marginBottom: 3, fontFamily: 'JetBrains Mono' }}>{label}</label>
            <input value={val} onChange={e => set(e.target.value)} placeholder={ph}
              style={{ width: '100%', background: '#0a0c10', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 11, fontFamily: 'JetBrains Mono', outline: 'none', boxSizing: 'border-box' }} />
          </div>
        ))}
        <div style={{ marginBottom: 16 }}>
          <label style={{ fontSize: 10, color: '#808590', display: 'block', marginBottom: 3, fontFamily: 'JetBrains Mono' }}>Password / Token</label>
          <input type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="••••••••"
            style={{ width: '100%', background: '#0a0c10', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 11, fontFamily: 'JetBrains Mono', outline: 'none', boxSizing: 'border-box' }} />
        </div>
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
          <button onClick={onClose} style={{ padding: '6px 14px', borderRadius: 4, border: '1px solid #2a2d35', background: 'transparent', color: '#808590', fontSize: 11, fontFamily: 'JetBrains Mono', cursor: 'pointer' }}>Cancel</button>
          <button onClick={handleSubmit} disabled={!name || !url || loading} style={{ padding: '6px 14px', borderRadius: 4, border: 'none', background: accent, color: '#fff', fontSize: 11, fontFamily: 'JetBrains Mono', cursor: name && url && !loading ? 'pointer' : 'not-allowed', opacity: name && url && !loading ? 1 : 0.5 }}>Save</button>
        </div>
      </div>
    </div>
  );
}

RegistriesSection.propTypes = { accent: PropTypes.string };
AddRegistryModal.propTypes = { accent: PropTypes.string, onClose: PropTypes.func };

// ── Main AdminView ────────────────────────────────────────────────────
export default function AdminView({ currentUser, accent, onlineUsers = [] }) {
  const tableColumns = 'minmax(220px, 1fr) 120px 100px 110px 220px';
  const [section, setSection] = useState('users');
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [resetUser, setResetUser] = useState(null);
  const [confirmDelete, setConfirmDelete] = useState(null);
  const [error, setError] = useState('');

  const load = async () => {
    setLoading(true);
    try { setUsers(await api.adminListUsers()); } catch (e) { setError(e.message); } finally { setLoading(false); }
  };

  useEffect(() => { load(); }, []);

  const setRole = async (u, newRole) => {
    if (u.role === newRole) return;
    try {
      const updated = await api.adminUpdateUser(u.id, { role: newRole });
      setUsers(prev => prev.map(x => x.id === u.id ? updated : x));
    } catch (e) { toastError(e.message); }
  };

  const toggleActive = async (u) => {
    try {
      const updated = await api.adminUpdateUser(u.id, { active: !u.active });
      setUsers(prev => prev.map(x => x.id === u.id ? updated : x));
    } catch (e) { toastError(e.message); }
  };

  const doDelete = async (uid) => {
    try {
      await api.adminDeleteUser(uid);
      setUsers(prev => prev.filter(x => x.id !== uid));
      setConfirmDelete(null);
    } catch (e) { toastError(e.message); }
  };

  const isSelf = (u) => u.id === currentUser?.id;

  return (
    <div style={{ flex: 1, overflowY: 'auto', padding: '28px 32px' }}>
      <div style={{ display: 'flex', gap: 8, marginBottom: 22 }}>
        {ADMIN_SECTIONS.map(([id, label]) => {
          const active = section === id;
          return (
            <button key={id} onClick={() => setSection(id)}
              style={{ background: active ? `${accent}22` : 'transparent', border: `1px solid ${active ? accent + '88' : '#2a2d35'}`, borderRadius: 6, padding: '7px 14px', cursor: 'pointer', color: active ? accent : '#606570', fontSize: 11, fontWeight: 700, fontFamily: 'JetBrains Mono' }}>
              {label}
            </button>
          );
        })}
      </div>

      {section === 'system' && <SystemModulesView accent={accent} />}
      {section === 'plugins' && <PluginsPanel accent={accent} />}
      {section === 'encryption' && <EncryptionSection accent={accent} />}
      {section === 'registries' && EE_WORKSTATION_PROVISIONING && <RegistriesSection accent={accent} />}
      {section === 'devops' && <DevOpsLogSection accent={accent} />}
      {section === 'notifications' && <NotificationsSection accent={accent} />}
      {section === 'ai' && <AISection accent={accent} />}

      {section === 'users' && (
      <>
      {showCreate && <CreateUserModal accent={accent} onClose={() => setShowCreate(false)} onCreated={u => setUsers(prev => [...prev, u])} />}
      {resetUser && <ResetPasswordModal user={resetUser} accent={accent} onClose={() => setResetUser(null)} />}
      {confirmDelete && (
        <ConfirmDialog
          text={`Delete user «${users.find(u => u.id === confirmDelete)?.username}»? This action is irreversible.`}
          onConfirm={() => doDelete(confirmDelete)}
          onCancel={() => setConfirmDelete(null)}
        />
      )}

      {/* ── Users section ── */}
      <div style={{ marginBottom: 28 }}>
        <div style={{ fontSize: 9, color: '#404550', letterSpacing: '0.15em', textTransform: 'uppercase', marginBottom: 6 }}>Admin panel</div>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <h1 style={{ fontSize: 22, fontWeight: 700, color: '#f0f2f6', fontFamily: 'Space Grotesk' }}>User management</h1>
          <button onClick={() => setShowCreate(true)}
            style={{ background: accent, border: 'none', borderRadius: 6, padding: '8px 18px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 6 }}>
            <Icon name="plus" size={11} color="#fff" /> Add user
          </button>
        </div>
      </div>

      {error && <div style={{ background: '#cc233318', border: '1px solid #cc233344', borderRadius: 6, padding: '10px 14px', fontSize: 12, color: '#cc2233', marginBottom: 18 }}>{error}</div>}

      <div style={{ background: '#0d0f14', border: '1px solid #1e2029', borderRadius: 10, overflow: 'auto' }}>
        <div style={{ display: 'grid', gridTemplateColumns: tableColumns, gap: 0, padding: '10px 18px', borderBottom: '1px solid #1e2029', background: '#090b0f' }}>
          {['User', 'Role', 'Status', 'Created', 'Actions'].map(h => (
            <div key={h} style={{ fontSize: 9, color: '#404550', textTransform: 'uppercase', letterSpacing: '0.1em' }}>{h}</div>
          ))}
        </div>

        {onlineUsers.length > 0 && (
          <div style={{ padding: '8px 18px', background: '#09090d', borderBottom: '1px solid #14161b', display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ width: 7, height: 7, borderRadius: '50%', background: '#39d353', boxShadow: '0 0 6px #39d353', flexShrink: 0 }} />
            <span style={{ fontSize: 10, color: '#404550', fontFamily: 'JetBrains Mono' }}>Online now:</span>
            {onlineUsers.map(name => (
              <span key={name} style={{ fontSize: 10, color: '#39d353', fontFamily: 'JetBrains Mono', background: '#39d35318', border: '1px solid #39d35333', borderRadius: 4, padding: '1px 7px' }}>{name}</span>
            ))}
          </div>
        )}

        {loading && <div style={{ padding: 24, textAlign: 'center', color: '#404550', fontSize: 12 }}>Loading...</div>}

        {users.map((u, i) => (
          <div key={u.id} style={{ display: 'grid', gridTemplateColumns: tableColumns, gap: 0, padding: '13px 18px', borderBottom: i < users.length - 1 ? '1px solid #14161b' : 'none', alignItems: 'center', background: isSelf(u) ? `${accent}08` : 'transparent' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <div style={{ width: 32, height: 32, borderRadius: '50%', background: `${GLOBAL_ROLE_COLOR[u.role]}22`, border: `1px solid ${GLOBAL_ROLE_COLOR[u.role]}55`, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 11, fontWeight: 700, color: GLOBAL_ROLE_COLOR[u.role], fontFamily: 'JetBrains Mono', flexShrink: 0 }}>
                {u.username.slice(0, 2).toUpperCase()}
              </div>
              <div>
                <div style={{ fontSize: 13, color: '#e0e4ec', fontWeight: 600 }}>{u.username}</div>
                {isSelf(u) && <div style={{ fontSize: 9, color: accent, fontFamily: 'JetBrains Mono' }}>that's you</div>}
              </div>
            </div>

            <div>
              <span style={{ fontSize: 10, fontFamily: 'JetBrains Mono', fontWeight: 600, color: GLOBAL_ROLE_COLOR[u.role], background: `${GLOBAL_ROLE_COLOR[u.role]}18`, border: `1px solid ${GLOBAL_ROLE_COLOR[u.role]}44`, borderRadius: 4, padding: '2px 8px', textTransform: 'uppercase' }}>
                {GLOBAL_ROLE_LABEL[u.role] || u.role}
              </span>
            </div>

            <div>
              <span style={{ fontSize: 10, fontFamily: 'JetBrains Mono', color: u.active ? '#39d353' : '#404550', background: u.active ? '#39d35318' : '#40455018', border: `1px solid ${u.active ? '#39d35344' : '#40455044'}`, borderRadius: 4, padding: '2px 8px' }}>
                {u.active ? 'Active' : 'Disabled'}
              </span>
            </div>

            <div style={{ fontSize: 10, color: '#505560', fontFamily: 'JetBrains Mono' }}>{u.created_at}</div>

            <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', alignItems: 'center' }}>
              {!isSelf(u) && (
                <>
                  <Select value={u.role} onChange={v => setRole(u, v)}
                    style={{ color: GLOBAL_ROLE_COLOR[u.role] || '#808590', minWidth: 115 }}
                    options={[{ value: 'viewer', label: 'Viewer' }, { value: 'user', label: 'User' }, { value: 'platform_admin', label: 'Platform Admin' }]} />
                  <button onClick={() => toggleActive(u)} title={u.active ? 'Deactivate' : 'Activate'}
                    style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '3px 6px', cursor: 'pointer', color: '#404550', display: 'flex', transition: 'all .1s' }}
                    onMouseEnter={e => { e.currentTarget.style.borderColor = u.active ? '#f09a3a' : '#39d353'; e.currentTarget.style.color = u.active ? '#f09a3a' : '#39d353'; }}
                    onMouseLeave={e => { e.currentTarget.style.borderColor = '#2a2d35'; e.currentTarget.style.color = '#404550'; }}>
                    <Icon name={u.active ? 'close' : 'plus'} size={10} color="currentColor" />
                  </button>
                </>
              )}
              <button onClick={() => setResetUser(u)} title="Reset password"
                style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '3px 6px', cursor: 'pointer', color: '#404550', display: 'flex', transition: 'all .1s' }}
                onMouseEnter={e => { e.currentTarget.style.borderColor = '#5b8af5'; e.currentTarget.style.color = '#5b8af5'; }}
                onMouseLeave={e => { e.currentTarget.style.borderColor = '#2a2d35'; e.currentTarget.style.color = '#404550'; }}>
                <Icon name="key" size={10} color="currentColor" />
              </button>
              {!isSelf(u) && (
                <button onClick={() => setConfirmDelete(u.id)} title="Delete"
                  style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '3px 6px', cursor: 'pointer', color: '#404550', display: 'flex', transition: 'all .1s' }}
                  onMouseEnter={e => { e.currentTarget.style.borderColor = '#cc2233'; e.currentTarget.style.color = '#cc2233'; }}
                  onMouseLeave={e => { e.currentTarget.style.borderColor = '#2a2d35'; e.currentTarget.style.color = '#404550'; }}>
                  <Icon name="trash" size={10} color="currentColor" />
                </button>
              )}
            </div>
          </div>
        ))}
      </div>

      <div style={{ marginTop: 12, fontSize: 10, color: '#303540', fontFamily: 'JetBrains Mono' }}>
        Total: {users.length} · Active: {users.filter(u => u.active).length} · Platform Admins: {users.filter(u => u.role === 'platform_admin').length} · Users: {users.filter(u => u.role === 'user').length} · Viewers: {users.filter(u => u.role === 'viewer').length}
      </div>

      {/* ── Project Access section ── */}
      <ProjectAccessSection accent={accent} allUsers={users} />
      </>
      )}
    </div>
  );
}
AdminView.propTypes = { currentUser: PropTypes.object, accent: PropTypes.string, onlineUsers: PropTypes.array };
