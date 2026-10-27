import PropTypes from 'prop-types';
import { useState, useEffect, useRef } from 'react';
import Icon from './Icon.jsx';
import { api } from '../api.js';
import { ACCESS_ROLES } from '../utils/hosts.js';
import { copyToClipboard } from '../utils/clipboard.js';
import { PALETTE, FONTS } from './UI.jsx';
import { toastError } from './Toast.jsx';

const linkColors = { ip: '#5b8af5', domain: '#c07af0', 'domain?': PALETTE.warn, linked: PALETTE.ok };
const linkLabels = { ip: 'IP', domain: 'domain', 'domain?': 'domain?', linked: 'linked' };
const linkTitles = { ip: 'Linked by IP', domain: 'Domain credential (host is domain-joined)', 'domain?': 'Domain credential — set host domain to confirm', linked: 'Linked via host_ids' };

export default function CredPanel({ cred, host, accent, pid, linkType }) {
  const [open, setOpen] = useState(false);
  const [chn, setChn] = useState(null);
  const [notes, setNotes] = useState('');
  const [revealedSecret, setRevealedSecret] = useState(null);
  const [revealing, setRevealing] = useState(false);
  const [secretHidden, setSecretHidden] = useState(true);
  const [copied, setCopied] = useState(null);
  const copyTimer = useRef(null);

  useEffect(() => {
    if (!open) return;
    api.getCredHostNotes({ cred_id: cred.id, host_id: host.id }).then(list => {
      const found = list[0] || null;
      setChn(found);
      setNotes(found?.notes || '');
    }).catch(() => {});
  }, [open, cred.id, host.id]);

  useEffect(() => () => { if (copyTimer.current) clearTimeout(copyTimer.current); }, []);

  const revealSecret = async () => {
    if (revealedSecret !== null) { setSecretHidden(false); return; }
    setRevealing(true);
    try {
      const res = await api.revealCredSecret(cred.id);
      setRevealedSecret(res.secret || '');
      setSecretHidden(false);
    } catch { setRevealedSecret(''); }
    finally { setRevealing(false); }
  };

  const copy = (text, label) => {
    if (!text) return;
    copyToClipboard(text).catch(() => {});
    setCopied(label);
    if (copyTimer.current) clearTimeout(copyTimer.current);
    copyTimer.current = setTimeout(() => setCopied(null), 1500);
  };

  const toggleAccess = async (roleId) => {
    const current = chn?.access || [];
    const next = current.includes(roleId) ? current.filter(r => r !== roleId) : [...current, roleId];
    await saveNote(notes, next);
  };

  const saveNote = async (newNotes, newAccess) => {
    try {
      const body = { cred_id: cred.id, host_id: host.id, pid, notes: newNotes, access: newAccess ?? chn?.access ?? [] };
      const result = chn
        ? await api.updateCredHostNote(chn.id, { notes: newNotes, access: newAccess ?? chn.access })
        : await api.upsertCredHostNote(body);
      setChn(result);
      setNotes(result.notes);
    } catch (e) { toastError(e.message); }
  };

  const secretDisplay = secretHidden ? null : (revealedSecret ?? '');

  return (
    <div style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 4, marginBottom: 6 }}>
      <button type="button" onClick={() => setOpen(v => !v)}
        style={{ padding: '7px 9px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 8, width: '100%', textAlign: 'left', border: 'none', outline: 'none', background: 'transparent', color: 'inherit', font: 'inherit' }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <span style={{ fontSize: 11, color: '#e0e4ec', fontFamily: FONTS.mono, flex: 1, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{cred.username}</span>
            <div style={{ display: 'flex', gap: 3, flexShrink: 0, alignItems: 'center' }}>
              <span title={linkTitles[linkType]} style={{ fontSize: 8, color: linkColors[linkType], background: linkColors[linkType] + '22', border: `1px solid ${linkColors[linkType]}44`, borderRadius: 3, padding: '1px 4px', fontFamily: FONTS.mono, whiteSpace: 'nowrap' }}>{linkLabels[linkType]}</span>
              {cred.is_domain && <span style={{ fontSize: 8, color: PALETTE.warn, background: '#f09a3a18', border: '1px solid #f09a3a44', borderRadius: 3, padding: '1px 4px', fontFamily: FONTS.mono, whiteSpace: 'nowrap' }}>AD</span>}
              {(chn?.access || []).slice(0, 2).map(r => {
                const role = ACCESS_ROLES.find(a => a.id === r);
                return role ? <span key={r} style={{ fontSize: 8, color: accent, background: accent + '22', border: `1px solid ${accent}44`, borderRadius: 3, padding: '1px 4px', fontFamily: FONTS.mono, whiteSpace: 'nowrap' }}>{role.label}</span> : null;
              })}
            </div>
          </div>
          <div style={{ fontSize: 9, color: PALETTE.textFaint, marginTop: 2, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{cred.service || '—'} · {cred.type}{cred.cracked ? ' · cracked' : ''}</div>
        </div>
        <Icon name="chevron" size={10} color="#606570" style={{ transform: open ? 'rotate(180deg)' : 'rotate(0deg)', transition: 'transform .12s', flexShrink: 0 }} />
      </button>

      {open && (
        <div style={{ padding: '8px 9px', borderTop: '1px solid #1e2029' }}>
          {/* Secret row */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8 }}>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontSize: 9, color: PALETTE.textGhost, textTransform: 'uppercase', letterSpacing: '.08em', marginBottom: 3 }}>Secret</div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                <code style={{ flex: 1, minWidth: 0, fontSize: 10, color: secretDisplay != null ? '#c8cdd6' : PALETTE.textGhost, fontFamily: FONTS.mono, background: PALETTE.bg3, border: `1px solid ${PALETTE.border}`, borderRadius: 3, padding: '4px 7px', wordBreak: 'break-all', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {secretDisplay != null ? (secretDisplay || '(empty)') : '••••••••'}
                </code>
                {secretDisplay != null && (
                  <button onClick={() => copy(secretDisplay, 'secret')} title="Copy"
                    style={{ background: PALETTE.bg3, border: `1px solid ${PALETTE.border}`, borderRadius: 3, padding: '4px 6px', cursor: 'pointer', display: 'flex', alignItems: 'center', flexShrink: 0 }}>
                    <Icon name={copied === 'secret' ? 'check' : 'copy'} size={11} color={copied === 'secret' ? '#39d353' : PALETTE.textFaint} />
                  </button>
                )}
                <button onClick={() => secretHidden ? revealSecret() : setSecretHidden(true)} title={secretHidden ? 'Reveal' : 'Hide'} disabled={revealing}
                  style={{ background: PALETTE.bg3, border: `1px solid ${PALETTE.border}`, borderRadius: 3, padding: '4px 6px', cursor: revealing ? 'default' : 'pointer', display: 'flex', alignItems: 'center', flexShrink: 0, opacity: revealing ? 0.5 : 1 }}>
                  <Icon name={secretHidden ? 'eye' : 'eyeOff'} size={11} color={secretHidden ? '#606570' : '#5b8af5'} />
                </button>
              </div>
            </div>
          </div>

          {/* Access roles */}
          <div style={{ marginBottom: 8 }}>
            <div style={{ fontSize: 9, color: PALETTE.textGhost, textTransform: 'uppercase', letterSpacing: '.08em', marginBottom: 4 }}>Access on this host</div>
            <div style={{ display: 'flex', gap: 3, flexWrap: 'wrap' }}>
              {ACCESS_ROLES.map(role => {
                const active = (chn?.access || []).includes(role.id);
                return (
                  <button key={role.id} onClick={() => toggleAccess(role.id)} title={role.title}
                    style={{ background: active ? accent + '22' : PALETTE.bg3, border: `1px solid ${active ? accent + '66' : PALETTE.border}`, borderRadius: 3, padding: '3px 7px', cursor: 'pointer', color: active ? accent : PALETTE.textFaint, fontSize: 9, fontFamily: FONTS.mono, transition: 'all .1s' }}>
                    {role.label}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Notes */}
          <div style={{ fontSize: 9, color: PALETTE.textGhost, textTransform: 'uppercase', letterSpacing: '.08em', marginBottom: 4 }}>Notes on this host</div>
          <textarea value={notes} onChange={e => setNotes(e.target.value)} onBlur={() => saveNote(notes)}
            placeholder="e.g. can't RDP, needs relay, password expired..."
            style={{ width: '100%', background: PALETTE.bg3, border: `1px solid ${PALETTE.border}`, borderRadius: 3, padding: '5px 7px', color: PALETTE.textMute, fontSize: 10, fontFamily: FONTS.mono, lineHeight: 1.5, resize: 'vertical', outline: 'none', minHeight: 48, boxSizing: 'border-box' }} />

          {cred.notes && <div style={{ fontSize: 9, color: PALETTE.textFaint, marginTop: 6, lineHeight: 1.5 }}>Cred notes: {cred.notes}</div>}
        </div>
      )}
    </div>
  );
}

CredPanel.propTypes = {
  cred: PropTypes.object,
  host: PropTypes.object,
  accent: PropTypes.string,
  pid: PropTypes.string,
  linkType: PropTypes.string,
};
