import { useState, useEffect, useRef } from 'react';
import PropTypes from 'prop-types';
import Icon from '../components/Icon.jsx';
import { api } from '../api.js';
import { PALETTE, FONTS } from '../components/UI.jsx';

// Reads the fragment the OIDC callback (routers/oidc_auth.py) redirects
// back to — never a query string, so none of these short-lived tokens
// ever end up in a server access log (ours or a downstream proxy's).
function readOidcHash() {
  const raw = globalThis.location.hash.replace(/^#/, '');
  if (!raw) return {};
  const params = new URLSearchParams(raw);
  const out = {};
  for (const key of ['oidc_mfa', 'oidc_link', 'oidc_error']) {
    if (params.has(key)) out[key] = params.get(key);
  }
  return out;
}

function LinkConfirmForm({ accent, inp, loading, username, setUsername, password, setPassword, error, onSubmit, onBack }) {
  return (
    <form onSubmit={onSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ background: `${accent}11`, border: `1px solid ${accent}33`, borderRadius: 6, padding: '10px 14px', fontSize: 11, color: accent, lineHeight: 1.6 }}>
        An account with this email already exists. Confirm it&apos;s yours by signing in with its password to link SSO.
      </div>
      <div>
        <div style={{ fontSize: 9, color: PALETTE.textGhost, marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Login</div>
        <input style={inp} value={username} onChange={e => setUsername(e.target.value)} placeholder="username" autoFocus autoComplete="username" />
      </div>
      <div>
        <div style={{ fontSize: 9, color: PALETTE.textGhost, marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Password</div>
        <input style={inp} type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="••••••••" autoComplete="current-password" />
      </div>
      {error && (
        <div style={{ background: '#cc233318', border: '1px solid #cc233344', borderRadius: 5, padding: '8px 12px', fontSize: 11, color: PALETTE.danger }}>{error}</div>
      )}
      <button type="submit" disabled={loading || !username.trim() || !password}
        style={{ background: loading || !username.trim() || !password ? '#1a1c22' : accent, border: 'none', borderRadius: 6, padding: '11px 0', cursor: loading ? 'wait' : 'pointer', color: '#fff', fontSize: 12, fontWeight: 700, fontFamily: FONTS.mono, marginTop: 4 }}>
        {loading ? 'Linking...' : 'Confirm & link account'}
      </button>
      <button type="button" onClick={onBack} style={{ background: 'none', border: 'none', color: '#505560', fontSize: 11, cursor: 'pointer', fontFamily: FONTS.mono }}>
        ← Cancel
      </button>
    </form>
  );
}
LinkConfirmForm.propTypes = { accent: PropTypes.string, inp: PropTypes.object, loading: PropTypes.bool, username: PropTypes.string, setUsername: PropTypes.func, password: PropTypes.string, setPassword: PropTypes.func, error: PropTypes.string, onSubmit: PropTypes.func, onBack: PropTypes.func };

function SsoProviderList({ accent, providers }) {
  if (!providers.length) return null;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 18 }}>
      {providers.map(p => (
        <a key={p.id} href={api.oidcLoginUrl(p.id)} title={p.org_name ? `${p.name} — ${p.org_name}` : p.name}
          style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8, background: '#12141a', border: `1px solid ${accent}44`, borderRadius: 6, padding: '10px 14px', color: PALETTE.textDim, fontSize: 12, fontWeight: 600, fontFamily: FONTS.mono, textDecoration: 'none', minWidth: 0 }}>
          <Icon name="shield" size={13} color={accent} style={{ flexShrink: 0 }} />
          <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', minWidth: 0 }}>
            Sign in with {p.name}
          </span>
        </a>
      ))}
    </div>
  );
}
SsoProviderList.propTypes = { accent: PropTypes.string, providers: PropTypes.array };

function MfaForm({ accent, inp, loading, totpCode, setTotpCode, error, onSubmit, onBack }) {
  return (
    <form onSubmit={onSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ background: `${accent}11`, border: `1px solid ${accent}33`, borderRadius: 6, padding: '10px 14px', fontSize: 11, color: accent, lineHeight: 1.6 }}>
        Open your authenticator app and enter the 6-digit code.
      </div>
      <div>
        <div style={{ fontSize: 9, color: PALETTE.textGhost, marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Authenticator code</div>
        <input
          style={{ ...inp, letterSpacing: '0.2em', fontSize: 18, textAlign: 'center' }}
          value={totpCode}
          onChange={e => setTotpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
          placeholder="000000"
          autoFocus
          autoComplete="one-time-code"
          inputMode="numeric"
          maxLength={6}
        />
      </div>
      {error && (
        <div style={{ background: '#cc233318', border: '1px solid #cc233344', borderRadius: 5, padding: '8px 12px', fontSize: 11, color: PALETTE.danger }}>{error}</div>
      )}
      <button type="submit" disabled={loading || totpCode.length !== 6}
        style={{ background: loading || totpCode.length !== 6 ? '#1a1c22' : accent, border: 'none', borderRadius: 6, padding: '11px 0', cursor: loading ? 'wait' : 'pointer', color: '#fff', fontSize: 12, fontWeight: 700, fontFamily: FONTS.mono, marginTop: 4, transition: 'background .15s' }}>
        {loading ? 'Verifying...' : 'Verify'}
      </button>
      <button type="button" onClick={onBack}
        style={{ background: 'none', border: 'none', color: '#505560', fontSize: 11, cursor: 'pointer', fontFamily: FONTS.mono }}>
        ← Back to login
      </button>
    </form>
  );
}
MfaForm.propTypes = { accent: PropTypes.string, inp: PropTypes.object, loading: PropTypes.bool, totpCode: PropTypes.string, setTotpCode: PropTypes.func, error: PropTypes.string, onSubmit: PropTypes.func, onBack: PropTypes.func };

function CredForm({ accent, inp, isFirstRun, loading, username, setUsername, password, setPassword, error, onSubmit }) {
  return (
    <>
      {isFirstRun && (
        <div style={{ background: `${accent}11`, border: `1px solid ${accent}33`, borderRadius: 6, padding: '10px 14px', marginBottom: 22, fontSize: 11, color: accent, lineHeight: 1.6 }}>
          First launch — create an administrator account.
        </div>
      )}
      <form onSubmit={onSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        <div>
          <div style={{ fontSize: 9, color: PALETTE.textGhost, marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Login</div>
          <input style={inp} value={username} onChange={e => setUsername(e.target.value)} placeholder="username" autoFocus autoComplete="username" />
        </div>
        <div>
          <div style={{ fontSize: 9, color: PALETTE.textGhost, marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Password</div>
          <input style={inp} type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="••••••••" autoComplete={isFirstRun ? 'new-password' : 'current-password'} />
        </div>
        {error && (
          <div style={{ background: '#cc233318', border: '1px solid #cc233344', borderRadius: 5, padding: '8px 12px', fontSize: 11, color: PALETTE.danger }}>{error}</div>
        )}
        <button type="submit" disabled={loading || !username.trim() || !password}
          style={{ background: loading || !username.trim() || !password ? '#1a1c22' : accent, border: 'none', borderRadius: 6, padding: '11px 0', cursor: loading ? 'wait' : 'pointer', color: '#fff', fontSize: 12, fontWeight: 700, fontFamily: FONTS.mono, marginTop: 4, transition: 'background .15s' }}>
          {(() => { if (loading) { return 'Please wait...'; } if (isFirstRun) { return 'Create administrator account'; } return 'Sign in'; })()}
        </button>
      </form>
    </>
  );
}
CredForm.propTypes = { accent: PropTypes.string, inp: PropTypes.object, isFirstRun: PropTypes.bool, loading: PropTypes.bool, username: PropTypes.string, setUsername: PropTypes.func, password: PropTypes.string, setPassword: PropTypes.func, error: PropTypes.string, onSubmit: PropTypes.func };

export default function LoginView({ accent, isFirstRun, onAuth, sessionExpired }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  // MFA step state
  const [mfaToken, setMfaToken] = useState(null);
  const [totpCode, setTotpCode] = useState('');

  // OIDC/SSO state
  const [ssoBase, setSsoBase] = useState([]);
  const [ssoMatch, setSsoMatch] = useState([]);
  const [linkToken, setLinkToken] = useState(null);
  const [linkUsername, setLinkUsername] = useState('');
  const [linkPassword, setLinkPassword] = useState('');
  const domainDebounceRef = useRef(null);

  // Pick up the fragment the OIDC callback redirects back to — the SPA
  // never sees the callback request itself (that's a full browser
  // navigation to the backend), only lands here afterward.
  useEffect(() => {
    const { oidc_mfa: oidcMfa, oidc_link: oidcLink, oidc_error: oidcError } = readOidcHash();
    if (oidcMfa) { setMfaToken(oidcMfa); }
    else if (oidcLink) { setLinkToken(oidcLink); }
    else if (oidcError) { setError(oidcError); }
    if (oidcMfa || oidcLink || oidcError) {
      globalThis.history.replaceState(null, '', globalThis.location.pathname + globalThis.location.search);
    }
  }, []);

  // Platform-wide catch-all providers are shown up front — no typing needed.
  useEffect(() => {
    api.publicOidcProviders({}).then(setSsoBase).catch(() => setSsoBase([]));
  }, []);

  useEffect(() => {
    clearTimeout(domainDebounceRef.current);
    const v = username.trim();
    if (!v) { setSsoMatch([]); return; }
    // Either an email or a bare login works: without "@" the backend maps
    // the username to the user's stored email and matches by its domain.
    domainDebounceRef.current = setTimeout(() => {
      api.publicOidcProviders({ email: v }).then(setSsoMatch).catch(() => setSsoMatch([]));
    }, 400);
    return () => clearTimeout(domainDebounceRef.current);
  }, [username]);

  const submitLinkConfirm = async (e) => {
    e.preventDefault();
    if (!linkUsername.trim() || !linkPassword) return;
    setError(''); setLoading(true);
    try {
      const res = await api.oidcConfirmLink({ link_token: linkToken, username: linkUsername.trim(), password: linkPassword });
      if (res.mfa_required) {
        setLinkToken(null);
        setMfaToken(res.mfa_token);
      } else {
        onAuth(res.user);
      }
    } catch (err) {
      setError(err.status === 429
        ? 'Too many attempts. Wait a minute and try again.'
        : err.message);
    } finally {
      setLoading(false);
    }
  };

  const submitCredentials = async (e) => {
    e.preventDefault();
    if (!username.trim() || !password) {
      return;
    }
    setError(''); setLoading(true);
    try {
      const res = isFirstRun
        ? await api.authSetup({ username: username.trim(), password })
        : await api.authLogin({ username: username.trim(), password });
      if (res.mfa_required) {
        setMfaToken(res.mfa_token);
      } else {
        onAuth(res.user);
      }
    } catch (err) {
      setError(err.status === 429
        ? 'Too many attempts. Wait a minute and try again.'
        : err.message);
    } finally {
      setLoading(false);
    }
  };

  const submitMfa = async (e) => {
    e.preventDefault();
    if (!totpCode.trim()) {
      return;
    }
    setError(''); setLoading(true);
    try {
      const res = await api.authMfaVerify({ mfa_token: mfaToken, code: totpCode.trim() });
      onAuth(res.user);
    } catch (err) {
      setError(err.status === 429
        ? 'Too many attempts. Wait a minute and try again.'
        : err.message);
      setTotpCode('');
    } finally {
      setLoading(false);
    }
  };

  const inp = { width: '100%', background: '#0a0c10', border: `1px solid ${PALETTE.border}`, borderRadius: 6, padding: '10px 12px', color: PALETTE.textDim, fontSize: 13, outline: 'none', fontFamily: FONTS.mono, boxSizing: 'border-box' };

  return (
    <div style={{ width: '100%', height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', background: PALETTE.bg0, position: 'relative', overflow: 'hidden' }}>
      {/* Subtle grid bg */}
      <div style={{ position: 'absolute', inset: 0, backgroundImage: `linear-gradient(${accent}08 1px, transparent 1px), linear-gradient(90deg, ${accent}08 1px, transparent 1px)`, backgroundSize: '40px 40px', pointerEvents: 'none' }} />

      <div style={{ width: 400, position: 'relative', zIndex: 1 }}>
        {/* Logo */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginBottom: 36, justifyContent: 'center' }}>
          <div style={{ width: 48, height: 48, borderRadius: 12, background: `${accent}18`, border: `1px solid ${accent}44`, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Icon name="shield" size={24} color={accent} />
          </div>
          <div>
            <div style={{ fontSize: 22, fontWeight: 700, color: PALETTE.text, fontFamily: FONTS.display }}>Umbryx</div>
            <div style={{ fontSize: 11, color: PALETTE.textGhost, fontFamily: FONTS.mono }}>
              {(() => { if (mfaToken) { return 'two-factor authentication'; } if (linkToken) { return 'confirm account link'; } if (isFirstRun) { return 'initial setup'; } return 'sign in'; })()}
            </div>
          </div>
        </div>

        <div style={{ background: PALETTE.bg2, border: '1px solid #1e2029', borderRadius: 12, padding: '32px 36px', boxShadow: '0 24px 64px #00000088' }}>
          {sessionExpired && !mfaToken && (
            <div style={{ background: '#c8820011', border: '1px solid #c8820044', borderRadius: 6, padding: '8px 12px', marginBottom: 18, fontSize: 11, color: '#c88200', fontFamily: FONTS.mono }}>
              Session expired — please sign in again
            </div>
          )}
          {(() => {
            if (mfaToken) {
              return (
                <MfaForm accent={accent} inp={inp} loading={loading} totpCode={totpCode} setTotpCode={setTotpCode}
                  error={error} onSubmit={submitMfa}
                  onBack={() => { setMfaToken(null); setError(''); setTotpCode(''); }} />
              );
            }
            if (linkToken) {
              return (
                <LinkConfirmForm accent={accent} inp={inp} loading={loading}
                  username={linkUsername} setUsername={setLinkUsername}
                  password={linkPassword} setPassword={setLinkPassword}
                  error={error} onSubmit={submitLinkConfirm}
                  onBack={() => { setLinkToken(null); setError(''); setLinkUsername(''); setLinkPassword(''); }} />
              );
            }
            return (
              <>
                <SsoProviderList accent={accent} providers={[...ssoBase, ...ssoMatch.filter(m => !ssoBase.some(b => b.id === m.id))]} />
                <CredForm accent={accent} inp={inp} isFirstRun={isFirstRun} loading={loading}
                  username={username} setUsername={setUsername} password={password} setPassword={setPassword}
                  error={error} onSubmit={submitCredentials} />
              </>
            );
          })()}
        </div>

        <div style={{ textAlign: 'center', marginTop: 18, fontSize: 10, color: '#303540', fontFamily: FONTS.mono }}>
          Umbryx · secured access
        </div>
      </div>
    </div>
  );
}
LoginView.propTypes = { accent: PropTypes.string, isFirstRun: PropTypes.bool, onAuth: PropTypes.func, sessionExpired: PropTypes.bool };
