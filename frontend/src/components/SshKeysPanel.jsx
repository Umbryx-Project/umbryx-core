import { useEffect, useState, useCallback } from 'react';
import PropTypes from 'prop-types';
import { api } from '../api.js';
import { PALETTE, FONTS } from './UI.jsx';

/** User-profile SSH public keys (workstation pool feature, 2026-09-02). */
const GREEN = '#39d353';
const RED = '#cc2233';

const btn = (bg, disabled) => ({ background: disabled ? '#1a1d26' : bg + '18', border: `1px solid ${disabled ? '#2a2d35' : bg + '66'}`, color: disabled ? '#606570' : bg, borderRadius: 4, padding: '4px 10px', cursor: disabled ? 'default' : 'pointer', fontSize: 10, fontFamily: FONTS.mono, fontWeight: 700 });

export default function SshKeysPanel({ accent }) {
  const [keys, setKeys] = useState(null);
  const [form, setForm] = useState({ name: '', public_key: '' });
  const [msg, setMsg] = useState(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      setKeys(await api.mySshKeys());
    } catch (e) {
      setMsg({ ok: false, text: e.message });
      setKeys([]);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const add = async () => {
    if (!form.public_key.trim()) return;
    setBusy(true);
    try {
      await api.addMySshKey(form);
      setForm({ name: '', public_key: '' });
      setMsg({ ok: true, text: 'Key added' });
      await load();
    } catch (e) { setMsg({ ok: false, text: e.message }); } finally { setBusy(false); }
  };

  const del = async (id) => {
    setBusy(true);
    try {
      await api.deleteMySshKey(id);
      await load();
    } catch (e) { setMsg({ ok: false, text: e.message }); } finally { setBusy(false); }
  };

  return (
    <div style={{ border: '1px solid #1e2230', borderRadius: 8, padding: 14, background: '#0a0c10' }}>
      <div style={{ fontSize: 13, fontWeight: 700, color: accent || '#c8cfe0', marginBottom: 4, fontFamily: FONTS.mono }}>SSH public keys</div>
      <div style={{ fontSize: 10, color: '#808590', marginBottom: 10, fontFamily: FONTS.mono }}>
        Granted onto pool workstations when an admin binds a machine to you. Only the public part is stored.
      </div>

      {msg && <div style={{ fontSize: 10, fontFamily: FONTS.mono, marginBottom: 8, color: msg.ok ? GREEN : RED }}>{msg.ok ? '✓ ' : '✗ '}{msg.text}</div>}

      {keys === null ? (
        <div style={{ color: PALETTE.textFaint, fontSize: 11 }}>Loading…</div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginBottom: 10 }}>
          {keys.length === 0 && <div style={{ color: PALETTE.textFaint, fontSize: 11, fontFamily: FONTS.mono }}>No keys yet.</div>}
          {keys.map(k => (
            <div key={k.id} style={{ display: 'flex', gap: 8, alignItems: 'center', border: '1px solid #1e2230', borderRadius: 6, padding: '6px 8px' }}>
              <span style={{ fontSize: 11, color: '#c8cfe0', fontFamily: FONTS.mono, minWidth: 80 }}>{k.name || '(unnamed)'}</span>
              <span style={{ fontSize: 9, color: PALETTE.textFaint, fontFamily: FONTS.mono, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{k.fingerprint || k.public_key.slice(0, 40)}</span>
              {k.in_use && <span style={{ fontSize: 9, color: GREEN, fontFamily: FONTS.mono }}>in use</span>}
              <button disabled={busy || k.in_use} onClick={() => del(k.id)} style={btn(RED, busy || k.in_use)} title={k.in_use ? 'Revoke machine access first' : 'Delete'}>Delete</button>
            </div>
          ))}
        </div>
      )}

      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
        <input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} placeholder="name (laptop, desktop…)" style={{ flex: '1 1 140px', background: PALETTE.bg3, border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 8px', color: '#c8cfe0', fontSize: 10, fontFamily: FONTS.mono }} />
        <input value={form.public_key} onChange={e => setForm(f => ({ ...f, public_key: e.target.value }))} placeholder="ssh-ed25519 AAAA… comment" style={{ flex: '3 1 260px', background: PALETTE.bg3, border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 8px', color: '#c8cfe0', fontSize: 10, fontFamily: FONTS.mono }} />
        <button disabled={busy || !form.public_key.trim()} onClick={add} style={btn(GREEN, busy || !form.public_key.trim())}>Add key</button>
      </div>
    </div>
  );
}

SshKeysPanel.propTypes = { accent: PropTypes.string };
