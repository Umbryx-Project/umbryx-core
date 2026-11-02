import { useState, useEffect, useCallback } from 'react';
import PropTypes from 'prop-types';
import { api } from '../api.js';
import { toastError, toastSuccess } from './Toast.jsx';
import { Btn, Select, FieldInput, Checkbox, PALETTE, FONTS } from './UI.jsx';
import { uiConfirm } from '../components/Confirm.jsx';

/*
 * Egress proxy pool management (2026-09-22).
 *
 * The pool routes the platform's outbound traffic per category (ai,
 * notifications, provisioner, c2, dns, webhooks, pivots, ssh, updates):
 *   route (category [+ target]) → endpoints matching tags → policy
 *   (round_robin / failover) → failure_mode (fail_open → direct fallback,
 *   fail_closed → hard error).
 * Resolution order overall: pool route → outbound env-floor → direct.
 */

const GREEN = '#39d353';
const RED = '#cc2233';
const AMBER = '#e0a820';
const BLUE = '#5b8af5';

const btn = (bg, disabled) => ({
  background: disabled ? '#1a1d26' : bg + '18',
  border: `1px solid ${disabled ? '#2a2d35' : bg + '66'}`,
  color: disabled ? '#606570' : bg,
  borderRadius: 4, padding: '3px 9px',
  cursor: disabled ? 'default' : 'pointer',
  fontSize: 10, fontFamily: FONTS.mono, fontWeight: 700,
});

const inp = {
  background: '#0a0c10', border: `1px solid ${PALETTE.border}`, borderRadius: 4,
  padding: '5px 8px', color: '#c8cfe0', fontSize: 11, fontFamily: FONTS.mono,
  outline: 'none', boxSizing: 'border-box',
};

const label = { fontSize: 9, color: PALETTE.textGhost, textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 4 };

const CATEGORY_HINTS = {
  all: 'everything below (fallback)',
  ai: 'AI providers (LLM calls)',
  notifications: 'messengers (Telegram/Slack/…)',
  provisioner: 'cloud / provider APIs',
  c2: 'C2 integrations (adaptix/mythic/…)',
  dns: 'DNS plugins',
  webhooks: 'outgoing webhooks',
  pivots: 'chisel/ligolo downloads',
  ssh: 'SSH egress (ProxyCommand)',
  updates: 'platform update checks',
};

function HealthBadge({ e }) {
  if (e.last_ok === null || e.last_ok === undefined) {
    return <span style={{ fontSize: 9, color: '#606570', fontFamily: FONTS.mono }}>not checked</span>;
  }
  return (
    <span style={{ fontSize: 9, color: e.last_ok ? GREEN : RED, fontFamily: FONTS.mono }}>
      {e.last_ok ? '● ok' : '● fail'}{e.latency_ms != null ? ` ${e.latency_ms}ms` : ''}
      {e.last_check_at ? ` · ${String(e.last_check_at).slice(5, 16)}` : ''}
    </span>
  );
}
HealthBadge.propTypes = { e: PropTypes.object };

function EndpointRow({ e, busy, onCheck, onToggle, onDelete }) {
  return (
    <div style={{ border: '1px solid #1e2230', borderLeft: `2px solid ${e.enabled ? BLUE : '#404550'}`, borderRadius: 6, padding: '7px 10px', background: '#0a0c10', display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
      <span style={{ fontSize: 11, color: '#c8cfe0', fontFamily: FONTS.mono, fontWeight: 700 }}>{e.name}</span>
      <span style={{ fontSize: 10, color: BLUE, fontFamily: FONTS.mono }}>{e.scheme}://{e.host}:{e.port}</span>
      {e.username && <span style={{ fontSize: 9, color: '#808590', fontFamily: FONTS.mono }}>· {e.username}{e.has_password ? ':•••' : ''}</span>}
      {(e.tags || []).map(t => (
        <span key={t} style={{ fontSize: 9, color: AMBER, fontFamily: FONTS.mono, background: AMBER + '10', border: `1px solid ${AMBER}33`, borderRadius: 4, padding: '1px 6px' }}>#{t}</span>
      ))}
      <HealthBadge e={e} />
      <span style={{ flex: 1 }} />
      <button disabled={busy} onClick={() => onCheck(e.id)} style={btn(BLUE, busy)}>Check</button>
      <button disabled={busy} onClick={() => onToggle(e)} style={btn(e.enabled ? AMBER : GREEN, busy)}>{e.enabled ? 'Disable' : 'Enable'}</button>
      <button disabled={busy} onClick={() => onDelete(e.id)} style={btn(RED, busy)}>Delete</button>
    </div>
  );
}
EndpointRow.propTypes = { e: PropTypes.object, busy: PropTypes.bool, onCheck: PropTypes.func, onToggle: PropTypes.func, onDelete: PropTypes.func };

function RouteRow({ r, busy, onToggle, onDelete }) {
  return (
    <div style={{ border: '1px solid #1e2230', borderLeft: `2px solid ${r.enabled ? GREEN : '#404550'}`, borderRadius: 6, padding: '7px 10px', background: '#0a0c10', display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
      <span style={{ fontSize: 11, color: '#c8cfe0', fontFamily: FONTS.mono, fontWeight: 700 }}>{r.name}</span>
      <span style={{ fontSize: 9, color: BLUE, fontFamily: FONTS.mono, background: BLUE + '10', border: `1px solid ${BLUE}33`, borderRadius: 4, padding: '1px 6px' }}>{r.category}</span>
      {r.target_ref && <span style={{ fontSize: 9, color: '#808590', fontFamily: FONTS.mono }}>→ {r.target_ref}</span>}
      <span style={{ fontSize: 9, color: '#808590', fontFamily: FONTS.mono }}>
        via {(r.proxy_tags || []).map(t => `#${t}`).join(' ') || 'any'}
      </span>
      <span style={{ fontSize: 9, color: '#808590', fontFamily: FONTS.mono }}>{r.policy} · {r.failure_mode} · prio {r.priority}</span>
      <span style={{ flex: 1 }} />
      <button disabled={busy} onClick={() => onToggle(r)} style={btn(r.enabled ? AMBER : GREEN, busy)}>{r.enabled ? 'Disable' : 'Enable'}</button>
      <button disabled={busy} onClick={() => onDelete(r.id)} style={btn(RED, busy)}>Delete</button>
    </div>
  );
}
RouteRow.propTypes = { r: PropTypes.object, busy: PropTypes.bool, onToggle: PropTypes.func, onDelete: PropTypes.func };

export function EgressProxyPanel({ accent }) {
  const [endpoints, setEndpoints] = useState([]);
  const [routes, setRoutes] = useState([]);
  const [meta, setMeta] = useState({ categories: [], policies: [], failure_modes: [] });
  const [outbound, setOutbound] = useState(null);
  const [outboundForm, setOutboundForm] = useState({ http: '', https: '', no_proxy: '' });
  const [busy, setBusy] = useState(false);
  const [showAddEp, setShowAddEp] = useState(false);
  const [showAddRoute, setShowAddRoute] = useState(false);
  const [epForm, setEpForm] = useState({ name: '', scheme: 'http', host: '', port: 8080, username: '', password: '', tags: '' });
  const [routeForm, setRouteForm] = useState({ name: '', category: 'ai', target_ref: '', proxy_tags: '', policy: 'round_robin', failure_mode: 'fail_open', priority: 100 });
  const [preview, setPreview] = useState(null);
  const [previewForm, setPreviewForm] = useState({ category: 'ai', target_ref: '' });

  const load = useCallback(async () => {
    try {
      const [eps, rts, cats, ob] = await Promise.all([
        api.listProxyEndpoints().catch(() => []),
        api.listProxyRoutes().catch(() => []),
        api.proxyCategories().catch(() => ({ categories: [], policies: [], failure_modes: [] })),
        api.getOutboundProxy().catch(() => ({})),
      ]);
      setEndpoints(Array.isArray(eps) ? eps : []);
      setRoutes(Array.isArray(rts) ? rts : []);
      setMeta(cats || {});
      setOutbound(ob || {});
      setOutboundForm({ http: (ob || {}).http || '', https: (ob || {}).https || '', no_proxy: (ob || {}).no_proxy || '' });
    } catch (e) {
      toastError(e.message || 'Failed to load proxy pool');
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const run = async (fn) => {
    if (busy) return;
    setBusy(true);
    try { await fn(); } finally { setBusy(false); }
  };

  const addEndpoint = () => run(async () => {
    try {
      await api.createProxyEndpoint({
        ...epForm,
        port: Number(epForm.port),
        tags: epForm.tags.split(',').map(t => t.trim()).filter(Boolean),
        enabled: true,
      });
      toastSuccess('Proxy endpoint added');
      setEpForm({ name: '', scheme: 'http', host: '', port: 8080, username: '', password: '', tags: '' });
      setShowAddEp(false);
      await load();
    } catch (e) { toastError(e.message || 'Failed to add endpoint'); }
  });

  const addRoute = () => run(async () => {
    try {
      await api.createProxyRoute({
        ...routeForm,
        priority: Number(routeForm.priority),
        proxy_tags: routeForm.proxy_tags.split(',').map(t => t.trim()).filter(Boolean),
        enabled: true,
      });
      toastSuccess('Route added');
      setRouteForm({ name: '', category: 'ai', target_ref: '', proxy_tags: '', policy: 'round_robin', failure_mode: 'fail_open', priority: 100 });
      setShowAddRoute(false);
      await load();
    } catch (e) { toastError(e.message || 'Failed to add route'); }
  });

  const checkEp = (id) => run(async () => {
    try {
      const r = await api.checkProxyEndpoint(id, { test_url: 'https://api.ipify.org' });
      if (r.ok) toastSuccess(`Proxy OK — ${r.detail}`);
      else toastError(`Proxy check failed — ${r.detail}`);
      await load();
    } catch (e) { toastError(e.message || 'Check failed'); }
  });

  const toggleEp = (e) => run(async () => {
    try {
      await api.patchProxyEndpoint(e.id, { enabled: !e.enabled });
      await load();
    } catch (err) { toastError(err.message); }
  });

  const deleteEp = (id) => run(async () => {
    if (!await uiConfirm('Delete this proxy endpoint?')) return;
    try {
      await api.deleteProxyEndpoint(id);
      toastSuccess('Endpoint deleted');
      await load();
    } catch (e) { toastError(e.message); }
  });

  const toggleRoute = (r) => run(async () => {
    try {
      await api.patchProxyRoute(r.id, { enabled: !r.enabled });
      await load();
    } catch (e) { toastError(e.message); }
  });

  const deleteRoute = (id) => run(async () => {
    if (!await uiConfirm('Delete this route?')) return;
    try {
      await api.deleteProxyRoute(id);
      toastSuccess('Route deleted');
      await load();
    } catch (e) { toastError(e.message); }
  });

  const runPreview = () => run(async () => {
    try {
      const r = await api.proxyResolve(previewForm.category, previewForm.target_ref || undefined);
      setPreview(r);
    } catch (e) { toastError(e.message); }
  });

  const saveOutbound = () => run(async () => {
    try {
      const body = {};
      if (outboundForm.http.trim()) body.http = outboundForm.http.trim();
      if (outboundForm.https.trim()) body.https = outboundForm.https.trim();
      if (outboundForm.no_proxy.trim()) body.no_proxy = outboundForm.no_proxy.trim();
      await api.setOutboundProxy(body);
      toastSuccess('Outbound floor saved');
      await load();
    } catch (e) { toastError(e.message); }
  });

  const clearOutbound = () => run(async () => {
    try {
      await api.setOutboundProxy({});
      toastSuccess('Outbound floor cleared (direct egress)');
      await load();
    } catch (e) { toastError(e.message); }
  });

  const floorActive = !!(outbound && (outbound.http || outbound.https));

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* ── Endpoints ── */}
      <div style={{ background: PALETTE.bg2, border: '1px solid #1e2029', borderRadius: 10, padding: 16 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
          <div>
            <div style={{ fontSize: 14, fontWeight: 700, color: PALETTE.text, fontFamily: FONTS.display }}>Egress proxies</div>
            <div style={{ fontSize: 10, color: PALETTE.textFaint }}>Pool of proxy endpoints the platform routes outbound traffic through — per category (AI, notifications, provisioner, C2, DNS, pivots, SSH…).</div>
          </div>
          <Btn variant="solid" accent={accent} onClick={() => setShowAddEp(v => !v)} disabled={busy}>
            {showAddEp ? 'Cancel' : '+ Endpoint'}
          </Btn>
        </div>

        {showAddEp && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 12, background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 6, padding: 10 }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'minmax(130px, 1fr) 110px minmax(150px, 1.4fr) 80px', gap: 8 }}>
              <div><div style={label}>Name</div><input style={{ ...inp, width: '100%' }} value={epForm.name} onChange={e => setEpForm(f => ({ ...f, name: e.target.value }))} placeholder="dc1-egress" /></div>
              <div><div style={label}>Scheme</div><Select value={epForm.scheme} onChange={v => setEpForm(f => ({ ...f, scheme: v }))} style={{ width: '100%' }} options={['http', 'https', 'socks5', 'socks4']} /></div>
              <div><div style={label}>Host</div><input style={{ ...inp, width: '100%' }} value={epForm.host} onChange={e => setEpForm(f => ({ ...f, host: e.target.value }))} placeholder="10.0.0.5" /></div>
              <div><div style={label}>Port</div><input style={{ ...inp, width: '100%' }} type="number" value={epForm.port} onChange={e => setEpForm(f => ({ ...f, port: e.target.value }))} /></div>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'minmax(150px, 1fr) minmax(220px, 1.6fr) minmax(120px, 1fr) auto', gap: 8, alignItems: 'end' }}>
              <div><div style={label}>Username</div><input style={{ ...inp, width: '100%' }} value={epForm.username} onChange={e => setEpForm(f => ({ ...f, username: e.target.value }))} placeholder="user (optional)" /></div>
              <div><div style={label}>Password</div><input style={{ ...inp, width: '100%' }} type="password" value={epForm.password} onChange={e => setEpForm(f => ({ ...f, password: e.target.value }))} placeholder="encrypted at rest" /></div>
              <div><div style={label}>Tags</div><input style={{ ...inp, width: '100%' }} value={epForm.tags} onChange={e => setEpForm(f => ({ ...f, tags: e.target.value }))} placeholder="dc1, ai" /></div>
              <Btn variant="solid" accent={accent} onClick={addEndpoint} disabled={busy || !epForm.name || !epForm.host}>Add endpoint</Btn>
            </div>
          </div>
        )}

        {endpoints.length === 0 && <div style={{ color: PALETTE.textFaint, fontSize: 11, fontFamily: FONTS.mono }}>No proxy endpoints — all platform egress goes direct (or via the outbound floor below).</div>}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          {endpoints.map(e => <EndpointRow key={e.id} e={e} busy={busy} onCheck={checkEp} onToggle={toggleEp} onDelete={deleteEp} />)}
        </div>
      </div>

      {/* ── Routes ── */}
      <div style={{ background: PALETTE.bg2, border: '1px solid #1e2029', borderRadius: 10, padding: 16 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
          <div>
            <div style={{ fontSize: 13, fontWeight: 700, color: PALETTE.text, fontFamily: FONTS.display }}>Routing rules</div>
            <div style={{ fontSize: 10, color: PALETTE.textFaint }}>Which categories (and optional targets) go through which endpoint tags — round_robin or failover, fail_open (fallback to direct) or fail_closed.</div>
          </div>
          <Btn variant="solid" accent={accent} onClick={() => setShowAddRoute(v => !v)} disabled={busy}>
            {showAddRoute ? 'Cancel' : '+ Route'}
          </Btn>
        </div>

        {showAddRoute && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 12, background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 6, padding: 10 }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'minmax(140px, 1fr) minmax(190px, 1.3fr) minmax(160px, 1.1fr) minmax(140px, 1fr)', gap: 8 }}>
              <div><div style={label}>Name</div><input style={{ ...inp, width: '100%' }} value={routeForm.name} onChange={e => setRouteForm(f => ({ ...f, name: e.target.value }))} placeholder="ai via dc1" /></div>
              <div>
                <div style={label}>Category</div>
                <Select value={routeForm.category} onChange={v => setRouteForm(f => ({ ...f, category: v }))} style={{ width: '100%' }}
                  options={(meta.categories || []).map(c => ({ value: c, label: c }))} />
              </div>
              <div><div style={label}>Target ref (opt)</div><input style={{ ...inp, width: '100%' }} value={routeForm.target_ref} onChange={e => setRouteForm(f => ({ ...f, target_ref: e.target.value }))} placeholder="ai_provider:openai" /></div>
              <div><div style={label}>Endpoint tags</div><input style={{ ...inp, width: '100%' }} value={routeForm.proxy_tags} onChange={e => setRouteForm(f => ({ ...f, proxy_tags: e.target.value }))} placeholder="dc1 (empty = any)" /></div>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'minmax(150px, 1fr) minmax(170px, 1fr) 80px auto', gap: 8, alignItems: 'end' }}>
              <div><div style={label}>Policy</div><Select value={routeForm.policy} onChange={v => setRouteForm(f => ({ ...f, policy: v }))} style={{ width: '100%' }} options={(meta.policies || ['round_robin', 'failover'])} /></div>
              <div><div style={label}>On failure</div><Select value={routeForm.failure_mode} onChange={v => setRouteForm(f => ({ ...f, failure_mode: v }))} style={{ width: '100%' }} options={meta.failure_modes || ['fail_open', 'fail_closed']} /></div>
              <div><div style={label}>Prio</div><input style={{ ...inp, width: '100%' }} type="number" value={routeForm.priority} onChange={e => setRouteForm(f => ({ ...f, priority: e.target.value }))} /></div>
              <Btn variant="solid" accent={accent} onClick={addRoute} disabled={busy || !routeForm.name}>Add route</Btn>
            </div>
            <div style={{ fontSize: 9, color: PALETTE.textGhost, fontFamily: FONTS.mono }}>{CATEGORY_HINTS[routeForm.category] || ''}</div>
          </div>
        )}

        {routes.length === 0 && <div style={{ color: PALETTE.textFaint, fontSize: 11, fontFamily: FONTS.mono }}>No routes — endpoints stay unused until a category is routed to their tags.</div>}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          {routes.map(r => <RouteRow key={r.id} r={r} busy={busy} onToggle={toggleRoute} onDelete={deleteRoute} />)}
        </div>

        {/* resolve preview */}
        <div style={{ marginTop: 12, display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap', borderTop: `1px solid ${PALETTE.borderSoft}`, paddingTop: 10 }}>
          <span style={{ fontSize: 9, color: PALETTE.textGhost, textTransform: 'uppercase', letterSpacing: '0.08em' }}>Preview:</span>
          <Select value={previewForm.category} onChange={v => setPreviewForm(f => ({ ...f, category: v }))} style={{ maxWidth: 190 }}
            options={(meta.categories || []).map(c => ({ value: c, label: c }))} />
          <input style={{ ...inp, width: 180 }} value={previewForm.target_ref} onChange={e => setPreviewForm(f => ({ ...f, target_ref: e.target.value }))} placeholder="target ref (optional)" />
          <Btn variant="ghost" onClick={runPreview} disabled={busy}>Resolve</Btn>
          {preview && (
            <span style={{ fontSize: 10, fontFamily: FONTS.mono, color: preview.direct ? PALETTE.textFaint : GREEN }}>
              {preview.direct ? '→ direct (no route matched)' : `→ ${preview.resolved}`}
              {preview.route ? ` · route '${preview.route}'` : ''}
            </span>
          )}
        </div>
      </div>

      {/* ── Outbound floor ── */}
      <div style={{ background: PALETTE.bg2, border: '1px solid #1e2029', borderRadius: 10, padding: 16 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
          <div style={{ fontSize: 13, fontWeight: 700, color: PALETTE.text, fontFamily: FONTS.display }}>Outbound floor (fallback)</div>
          <span style={{ fontSize: 9, color: floorActive ? GREEN : '#606570', fontFamily: FONTS.mono, background: (floorActive ? GREEN : '#606570') + '10', border: `1px solid ${(floorActive ? GREEN : '#606570')}33`, borderRadius: 4, padding: '1px 6px' }}>
            {floorActive ? 'active' : 'off'}
          </span>
        </div>
        <div style={{ fontSize: 10, color: PALETTE.textFaint, fontFamily: FONTS.mono, marginBottom: 10 }}>
          Applies when no pool route matched: sets HTTP_PROXY/HTTPS_PROXY for every outbound client (AI, DNS, C2, kubectl…). Resolution order: <span style={{ color: PALETTE.textDim }}>pool route → floor → direct</span>.
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1.4fr 1.6fr auto auto', gap: 8, alignItems: 'end' }}>
          <div><div style={label}>HTTP</div><input style={{ ...inp, width: '100%' }} value={outboundForm.http} onChange={e => setOutboundForm(f => ({ ...f, http: e.target.value }))} placeholder="http://proxy:3128" /></div>
          <div><div style={label}>HTTPS</div><input style={{ ...inp, width: '100%' }} value={outboundForm.https} onChange={e => setOutboundForm(f => ({ ...f, https: e.target.value }))} placeholder="http://proxy:3128" /></div>
          <div><div style={label}>No proxy</div><input style={{ ...inp, width: '100%' }} value={outboundForm.no_proxy} onChange={e => setOutboundForm(f => ({ ...f, no_proxy: e.target.value }))} placeholder="localhost,127.0.0.1,10.0.0.0/8" /></div>
          <Btn variant="solid" accent={accent} onClick={saveOutbound} disabled={busy}>Save</Btn>
          <Btn variant="ghost" onClick={clearOutbound} disabled={busy || !floorActive}>Clear</Btn>
        </div>
      </div>
    </div>
  );
}
EgressProxyPanel.propTypes = { accent: PropTypes.string };
