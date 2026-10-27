import { useState, useEffect, useCallback } from 'react';
import PropTypes from 'prop-types';
import { api } from '../api.js';
import { Btn, Card, Badge, EmptyState, SectionTitle, Overline, PALETTE, FONTS, TYPE } from '../components/UI.jsx';
import Icon from '../components/Icon.jsx';
import { toastError, toastSuccess } from '../components/Toast.jsx';
import { copyToClipboard } from '../utils/clipboard.js';

/**
 * Output → Access: everything the operator needs to connect to the
 * project's C2 and infrastructure — teamserver addresses and operator
 * logins/passwords, infra service credentials, pool machine ssh
 * addresses. Single aggregated endpoint (GET /api/projects/{pid}/access-info).
 */

const value = { fontFamily: FONTS.mono, fontSize: TYPE.body, color: PALETTE.text };
const entry = { border: `1px solid ${PALETTE.borderSoft}`, borderRadius: 6, padding: '10px 12px', marginBottom: 8 };

function IconBtn({ name, color, title, onClick }) {
  return (
    <button onClick={onClick} title={title}
      style={{ background: 'transparent', border: 'none', cursor: 'pointer', color, padding: 2, display: 'inline-flex', alignItems: 'center' }}>
      <Icon name={name} size={12} color={color} />
    </button>
  );
}
IconBtn.propTypes = { name: PropTypes.string, color: PropTypes.string, title: PropTypes.string, onClick: PropTypes.func };

function Copyable({ val, accent, secret = false }) {
  const [shown, setShown] = useState(!secret);
  if (!val) return <span style={{ ...value, color: PALETTE.textGhost }}>—</span>;
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
      <span style={value}>{shown || !secret ? val : '••••••••'}</span>
      {secret && (
        <IconBtn name={shown ? 'eyeOff' : 'eye'} color={PALETTE.textFaint} title={shown ? 'hide' : 'show'}
          onClick={() => setShown(s => !s)} />
      )}
      <IconBtn name="copy" color={accent} title="copy"
        onClick={() => copyToClipboard(val).then(() => toastSuccess('Copied')).catch(() => toastError('Copy failed'))} />
    </span>
  );
}
Copyable.propTypes = { val: PropTypes.string, accent: PropTypes.string, secret: PropTypes.bool };

function Row({ label, children }) {
  return (
    <div style={{ display: 'flex', gap: 10, alignItems: 'center', padding: '3px 0', flexWrap: 'wrap' }}>
      <span style={{ fontFamily: FONTS.mono, fontSize: TYPE.label, color: PALETTE.textGhost, minWidth: 78, textTransform: 'uppercase', letterSpacing: '0.08em' }}>{label}</span>
      {children}
    </div>
  );
}
Row.propTypes = { label: PropTypes.string, children: PropTypes.node };

const statusColor = s => (s === 'ready' || s === 'healthy') ? PALETTE.ok : PALETTE.warn;

export default function AccessView({ pid, accent }) {
  const [info, setInfo] = useState(null);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    if (!pid) { setInfo(null); return; }
    try {
      setInfo(await api.projectAccessInfo(pid));
      setError('');
    } catch (e) { setError(e.message); }
  }, [pid]);

  useEffect(() => { load(); }, [load]);

  if (!pid) {
    return (
      <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <EmptyState icon="lock" title="No project selected" hint="Pick a project to see its access info." />
      </div>
    );
  }
  if (error) {
    return (
      <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <EmptyState icon="lock" title="Access info unavailable" hint={error} />
      </div>
    );
  }
  if (!info) {
    return (
      <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: PALETTE.textMute, fontSize: TYPE.body, fontFamily: FONTS.mono }}>
        Loading…
      </div>
    );
  }

  // dropped_restricted payloads are invisible here (empty list) but still
  // count as entries — without this check a project whose ONLY access
  // entries are gated payloads showed "No access entries" instead of
  // the locked count card.
  const nothing = !info.c2?.length && !info.infra?.length && !info.machines?.length && !info.dropped?.length && !(info.dropped_restricted && info.dropped_total > 0);
  if (nothing) {
    return (
      <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <EmptyState icon="lock" title="No access entries for this project"
          hint="Register a C2 integration scoped to this project, deploy infrastructure or bind a pool machine." />
      </div>
    );
  }

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <div style={{ padding: '16px 20px 0' }}>
        <SectionTitle right={<Btn variant="ghost" icon="reset" onClick={load}>Refresh</Btn>}>
          Project access ({info.c2?.length || 0} C2 · {info.infra?.length || 0} infra · {info.machines?.length || 0} machines)
        </SectionTitle>
      </div>

      <div style={{ flex: 1, overflow: 'auto', padding: '0 20px 20px', display: 'flex', flexDirection: 'column', gap: 10 }}>
        {info.c2?.length > 0 && (
          <Card style={{ width: '100%', boxSizing: 'border-box' }}>
            <Overline style={{ marginBottom: 10 }}>C2 — operator connections</Overline>
            {info.c2.map(c => (
              <div key={c.id} style={entry}>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 6, flexWrap: 'wrap' }}>
                  <Badge label={c.type} color={accent} />
                  <span style={{ fontFamily: FONTS.display, fontSize: TYPE.body, color: PALETTE.text, fontWeight: 600 }}>{c.name}</span>
                </div>
                <Row label="connect"><Copyable val={c.how_to} accent={accent} /></Row>
                <Row label="url"><Copyable val={c.url} accent={accent} /></Row>
                {c.username && <Row label="login"><Copyable val={c.username} accent={accent} /></Row>}
                {c.password && <Row label="password"><Copyable val={c.password} accent={accent} secret /></Row>}
                {c.token && <Row label="token"><Copyable val={c.token} accent={accent} secret /></Row>}
              </div>
            ))}
          </Card>
        )}

        {info.infra?.length > 0 && (
          <Card style={{ width: '100%', boxSizing: 'border-box' }}>
            <Overline style={{ marginBottom: 10 }}>Infrastructure — services &amp; credentials</Overline>
            {info.infra.map(c => (
              <div key={c.id} style={entry}>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 6, flexWrap: 'wrap' }}>
                  <span style={{ fontFamily: FONTS.display, fontSize: TYPE.body, color: PALETTE.text, fontWeight: 600 }}>{c.service || c.label}</span>
                  {c.role && <span style={{ ...value, fontSize: TYPE.label, color: PALETTE.textFaint }}>({c.role})</span>}
                  <Badge label={`${c.stack} · ${c.stack_status}`} color={statusColor(c.stack_status)} />
                </div>
                {c.url && <Row label="address"><Copyable val={c.url} accent={accent} /></Row>}
                {c.username && <Row label="login"><Copyable val={c.username} accent={accent} /></Row>}
                {c.secret && <Row label="password"><Copyable val={c.secret} accent={accent} secret /></Row>}
              </div>
            ))}
          </Card>
        )}

        {info.dropped_restricted && info.dropped_total > 0 && (
          <Card style={{ width: '100%', boxSizing: 'border-box', opacity: 0.75 }}>
            <Overline style={{ marginBottom: 8 }}>Dropped payloads — public links (pwndrop)</Overline>
            <div style={{ display: 'flex', gap: 10, alignItems: 'center', padding: '5px 0' }}>
              <span style={{ ...value, color: PALETTE.textGhost }}>🔒</span>
              <span style={{ ...value, color: PALETTE.textGhost }}>
                {info.dropped_total} payload link{info.dropped_total === 1 ? '' : 's'} — visible to operator roles and above
              </span>
            </div>
          </Card>
        )}

        {info.dropped?.length > 0 && (
          <Card style={{ width: '100%', boxSizing: 'border-box' }}>
            <Overline style={{ marginBottom: 8 }}>Dropped payloads — public links (pwndrop)</Overline>
            {info.dropped.map(d => (
              <div key={d.loot_id} style={{ display: 'flex', gap: 10, alignItems: 'center', padding: '5px 0', borderBottom: `1px solid ${PALETTE.borderSoft}`, flexWrap: 'wrap' }}>
                <span style={{ ...value, color: PALETTE.warn }}>📦</span>
                <span style={{ ...value, color: PALETTE.text }}>{d.filename}</span>
                <span style={{ ...value, color: PALETTE.textGhost }}>{String(d.sha256 || '').slice(0, 12)}…</span>
                <span style={{ ...value, color: accent, flex: 1 }}>
                  <Copyable val={d.url} accent={accent} />
                </span>
              </div>
            ))}
          </Card>
        )}

      {info.machines?.length > 0 && (
          <Card style={{ width: '100%', boxSizing: 'border-box' }}>
            <Overline style={{ marginBottom: 10 }}>Workstations — pool machines of this project</Overline>
            {info.machines.map(m => (
              <div key={m.id} style={{ display: 'flex', gap: 10, alignItems: 'center', padding: '7px 0', borderBottom: `1px solid ${PALETTE.borderSoft}`, flexWrap: 'wrap' }}>
                <span style={{ width: 7, height: 7, borderRadius: '50%', background: m.status === 'ready' ? PALETTE.ok : PALETTE.warn, flexShrink: 0 }} />
                <span style={{ ...value, fontWeight: 600 }}>{m.name}</span>
                <span style={{ ...value, color: PALETTE.textMute }}>{m.address}</span>
                {m.ssh_cmd && (
                  <span style={{ background: `${accent}10`, border: `1px solid ${accent}33`, borderRadius: 4, padding: '2px 8px' }}>
                    <Copyable val={m.ssh_cmd} accent={accent} />
                  </span>
                )}
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, marginLeft: 'auto' }}>
                  {m.my_access && <Icon name="key" size={11} color={PALETTE.ok} />}
                  <span style={{ ...value, fontSize: TYPE.label, color: m.my_access ? PALETTE.ok : PALETTE.textGhost }}>
                    {m.my_access ? 'your key installed' : 'no access granted to you'}
                  </span>
                </span>
              </div>
            ))}
          </Card>
        )}
      </div>
    </div>
  );
}

AccessView.propTypes = { pid: PropTypes.string, accent: PropTypes.string };
