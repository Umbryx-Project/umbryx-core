import { useEffect, useState } from 'react';
import PropTypes from 'prop-types';
import { api } from '../api.js';
import { PALETTE, FONTS } from './UI.jsx';

/**
 * Global actionable alert for ROE/scope gate outcomes.
 *
 * Listens to `roe:alert` events dispatched by the API client:
 *  - kind === 'blocked'  — the job was rejected by the engagement guard
 *    (out-of-scope target / forbidden activity / outside work hours).
 *    Actions: request a scope extension (notifies project admins — the
 *    operator never widens the boundary unilaterally), close.
 *  - kind === 'awaiting' — the job is held in `awaiting_approval`.
 *    Actions: approve / reject (project admins; the backend enforces
 *    rights), close.
 */
const AMBER = '#e0a820';
const RED = '#cc2233';
const GREEN = '#39d353';

export default function RoeAlertHost() {
  const [alert, setAlert] = useState(null);
  const [extensionForm, setExtensionForm] = useState(null);
  const [status, setStatus] = useState(null); // {ok:bool, text}
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const onAlert = (e) => {
      setAlert(e.detail);
      setExtensionForm(null);
      setStatus(null);
    };
    globalThis.addEventListener('roe:alert', onAlert);
    return () => globalThis.removeEventListener('roe:alert', onAlert);
  }, []);

  if (!alert) return null;

  // App.jsx keeps the active project in localStorage-backed state; read the
  // same source so the alert works from any view that fired the job.
  const pid = localStorage.getItem('rt_project') || '';
  const isAwaiting = alert.kind === 'awaiting';
  const color = isAwaiting ? AMBER : RED;

  const close = () => { setAlert(null); setExtensionForm(null); setStatus(null); };

  const requestExtension = async () => {
    if (!pid || !extensionForm?.value?.trim()) return;
    setBusy(true);
    try {
      const r = await api.requestScopeExtension({
        pid,
        value: extensionForm.value.trim(),
        reason: extensionForm.reason || '',
      });
      setStatus({ ok: true, text: `Extension request sent to project admins (${r.notified || '?'} notified).` });
      setExtensionForm(null);
    } catch (e) {
      setStatus({ ok: false, text: e.message || 'Request failed' });
    } finally {
      setBusy(false);
    }
  };

  const btn = (bg) => ({ background: bg + '18', border: `1px solid ${bg}66`, color: bg, borderRadius: 4, padding: '6px 14px', cursor: 'pointer', fontSize: 11, fontFamily: FONTS.mono, fontWeight: 700 });

  return (
    <div onClick={close} style={{ position: 'fixed', inset: 0, background: '#000000aa', zIndex: 1000, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <div onClick={e => e.stopPropagation()} style={{ width: 560, maxHeight: '80vh', overflowY: 'auto', background: '#0a0c10', border: `1px solid ${color}55`, borderRadius: 8, boxShadow: '0 12px 60px #000000cc', padding: 18 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
          <span style={{ fontSize: 20 }}>{isAwaiting ? '⏳' : '⛔'}</span>
          <div style={{ fontSize: 14, fontWeight: 700, color, fontFamily: FONTS.mono }}>
            {isAwaiting ? 'Job held for ROE approval' : 'Job blocked by ROE / scope guard'}
          </div>
        </div>
        <div style={{ fontSize: 12, color: '#c8cfe0', fontFamily: FONTS.mono, whiteSpace: 'pre-wrap', marginBottom: 10 }}>{alert.message}</div>

        {Array.isArray(alert.outOfScope) && alert.outOfScope.length > 0 && (
          <div style={{ marginBottom: 10 }}>
            <div style={{ fontSize: 10, color: '#808590', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 4 }}>Out of scope</div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
              {alert.outOfScope.map(r => (
                <span key={r} style={{ fontSize: 11, color: RED, background: RED + '12', border: `1px solid ${RED}44`, borderRadius: 3, padding: '2px 6px', fontFamily: FONTS.mono }}>{r}</span>
              ))}
            </div>
          </div>
        )}

        {Array.isArray(alert.activities) && alert.activities.length > 0 && (
          <div style={{ marginBottom: 10 }}>
            <div style={{ fontSize: 10, color: '#808590', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 4 }}>Requires approval</div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
              {alert.activities.map(a => (
                <span key={a} style={{ fontSize: 11, color: AMBER, background: AMBER + '12', border: `1px solid ${AMBER}44`, borderRadius: 3, padding: '2px 6px', fontFamily: FONTS.mono }}>{a}</span>
              ))}
            </div>
          </div>
        )}

        {status && (
          <div style={{ fontSize: 11, fontFamily: FONTS.mono, marginBottom: 10, color: status.ok ? GREEN : RED, background: (status.ok ? GREEN : RED) + '10', border: `1px solid ${(status.ok ? GREEN : RED)}44`, borderRadius: 4, padding: '6px 8px' }}>{status.ok ? '✓ ' : '✗ '}{status.text}</div>
        )}

        {extensionForm && (
          <div style={{ marginBottom: 12, border: '1px solid #1e2230', borderRadius: 6, padding: 10, background: PALETTE.bg3 }}>
            <div style={{ fontSize: 10, color: '#808590', marginBottom: 6 }}>REQUEST SCOPE EXTENSION — goes to project admins for approval, the scope is not changed here</div>
            <input value={extensionForm.value} onChange={e => setExtensionForm(f => ({ ...f, value: e.target.value }))} placeholder="CIDR or host, e.g. 10.20.0.0/24" style={{ width: '100%', boxSizing: 'border-box', background: '#0a0c10', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 8px', color: '#c8cfe0', fontSize: 11, fontFamily: FONTS.mono, marginBottom: 6, outline: 'none' }} />
            <input value={extensionForm.reason} onChange={e => setExtensionForm(f => ({ ...f, reason: e.target.value }))} placeholder="Reason for the client engagement record" style={{ width: '100%', boxSizing: 'border-box', background: '#0a0c10', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 8px', color: '#c8cfe0', fontSize: 11, fontFamily: FONTS.mono, marginBottom: 8, outline: 'none' }} />
            <div style={{ display: 'flex', gap: 6 }}>
              <button disabled={busy || !pid} onClick={requestExtension} style={btn(GREEN)}>Send request</button>
              <button onClick={() => setExtensionForm(null)} style={btn('#6a7080')}>Cancel</button>
            </div>
          </div>
        )}

        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', flexWrap: 'wrap' }}>
          {!isAwaiting && !extensionForm && (
            <button onClick={() => setExtensionForm({ value: (alert.outOfScope && alert.outOfScope[0]) || '', reason: '' })} style={btn(AMBER)}>Request scope extension</button>
          )}
          <button onClick={close} style={btn('#6a7080')}>Close</button>
        </div>

        {isAwaiting && (
          <div style={{ marginTop: 8, paddingTop: 8, borderTop: '1px solid #1e2230', fontSize: 10, color: PALETTE.textFaint, fontFamily: FONTS.mono }}>
            Approve / reject from the Jobs view (project admins) — the job stays in <span style={{ color: AMBER }}>awaiting_approval</span> until then.
          </div>
        )}
      </div>
    </div>
  );
}

RoeAlertHost.propTypes = {};
