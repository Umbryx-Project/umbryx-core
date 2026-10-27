import { useState, useEffect, useCallback } from 'react';
import PropTypes from 'prop-types';
import { api } from '../api.js';
import Icon from '../components/Icon.jsx';
import ModulesView from './ModulesView.jsx';
import { PALETTE, TYPE, FONTS, Checkbox, LOG_ROW_STYLE, LOG_HEADER_STYLE, logRowHover, logRowUnhover } from '../components/UI.jsx';
import { copyToClipboard } from '../utils/clipboard.js';
import { useEntitlement, FEATURE } from '../hooks/useEntitlement.js';

const cardStyle = { background: PALETTE.bg2, border: `1px solid ${PALETTE.borderSoft}`, borderRadius: 6, padding: 14 };
const inputStyle = { background: PALETTE.bg1, border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 8px', color: PALETTE.textDim, fontSize: TYPE.body, fontFamily: FONTS.mono, outline: 'none' };
const tabBtn = (active, accent) => ({ padding: '5px 10px', borderRadius: 4, border: active ? `1px solid ${accent}` : `1px solid ${PALETTE.border}`, background: active ? `${accent}15` : 'transparent', color: active ? accent : PALETTE.textMute, fontSize: TYPE.button, fontFamily: FONTS.mono, cursor: 'pointer', transition: 'all .12s' });
const thStyle = { textAlign: 'left', padding: '5px 8px', color: PALETTE.textGhost, fontSize: TYPE.overline, textTransform: 'uppercase' };
const tdStyle = { padding: '5px 8px' };
const rowBorder = { borderBottom: `1px solid ${PALETTE.bg1}` };
const SYSTEM_LOG_GRID = '90px 100px 70px 1fr 2fr';

function StatCard({ label, value, color }) {
  return (
    <div style={{ ...cardStyle, flex: 1, minWidth: 120 }}>
      <div style={{ fontSize: TYPE.overline, color: PALETTE.textFaint, fontFamily: FONTS.mono, textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 4 }}>{label}</div>
      <div style={{ fontSize: 16, color: color || PALETTE.text, fontFamily: FONTS.mono, fontWeight: 700 }}>{value}</div>
    </div>
  );
}
StatCard.propTypes = { label: PropTypes.string, value: PropTypes.any, color: PropTypes.string };

function StatusDot({ ok }) {
  const c = ok ? PALETTE.ok : PALETTE.danger;
  return <div style={{ width: 7, height: 7, borderRadius: '50%', background: c, boxShadow: `0 0 6px ${c}`, display: 'inline-block' }} />;
}
StatusDot.propTypes = { ok: PropTypes.bool };

export default function SystemDashboard({ accent }) {
  const { hasFeature, requiredTier } = useEntitlement();
  // Global SSO is an Enterprise feature — on lower tiers the System → SSO
  // tab stays visible as an upsell but the config UI itself is replaced
  // with a locked card (the org-scoped panel gates itself the same way).
  const ssoEntitled = hasFeature(FEATURE.SSO);
  const [health, setHealth] = useState(null);
  const [logs, setLogs] = useState([]);
  const [metrics, setMetrics] = useState(null);
  const [ha, setHa] = useState(null);
  const [section, setSection] = useState('health');
  const [logFilter, setLogFilter] = useState('');
  const [err, setErr] = useState(null);

  const loadHealth = useCallback(async () => {
    try { setHealth(await api.getSystemHealth()); setErr(null); } catch (e) { setErr(e.message); }
  }, []);

  const loadLogs = useCallback(async () => {
    try { const data = await api.getSystemLogs(logFilter || undefined); setLogs(Array.isArray(data) ? data : data.items || []); setErr(null); } catch (e) { setErr(e.message); }
  }, [logFilter]);

  const loadMetrics = useCallback(async () => {
    try { setMetrics(await api.getSystemMetrics()); setErr(null); } catch (e) { setErr(e.message); }
  }, []);

  const loadHa = useCallback(async () => {
    try { setHa(await api.getHAStatus()); setErr(null); } catch (e) { setErr(e.message); }
  }, []);

  useEffect(() => {
    if (section === 'health') loadHealth();
    if (section === 'logs') loadLogs();
    if (section === 'metrics') loadMetrics();
    if (section === 'ha') loadHa();
  }, [section, loadHealth, loadLogs, loadMetrics, loadHa]);

  // HA Cluster tab auto-refreshes while visible — this is the one place
  // an operator actually wants to watch a failover happen live, not just
  // read a one-shot snapshot.
  useEffect(() => {
    if (section !== 'ha') return;
    const t = setInterval(loadHa, 5000);
    return () => clearInterval(t);
  }, [section, loadHa]);

  const sections = [
    { id: 'health', label: 'Health', icon: 'bolt' },
    { id: 'modules', label: 'Modules', icon: 'package' },
    { id: 'logs', label: 'Logs', icon: 'notes' },
    { id: 'metrics', label: 'Metrics', icon: 'target' },
    { id: 'ha', label: 'HA Cluster', icon: 'network' },
    { id: 'sso', label: 'SSO', icon: 'shield' },
    { id: 'license', label: 'License', icon: 'shield' },
  ];

  return (
    <div style={{ padding: 16 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
        <Icon name="dashboard" size={20} color={accent} />
        <h2 style={{ fontSize: TYPE.sectionTitle, color: PALETTE.text, fontFamily: FONTS.display, fontWeight: 700, margin: 0 }}>System</h2>
      </div>

      <div style={{ display: 'flex', gap: 6, marginBottom: 14 }}>
        {sections.map(s => (
          <button key={s.id} onClick={() => setSection(s.id)} style={tabBtn(section === s.id, accent)}>
            {s.label}
          </button>
        ))}
      </div>

      <div style={{ display: 'flex', gap: 10, alignItems: 'baseline', fontSize: TYPE.button, color: PALETTE.textGhost, fontFamily: FONTS.mono, marginBottom: 12, flexWrap: 'wrap' }}>
        <span style={{ color: PALETTE.textFaint }}>Setup:</span>
        <span>1. Add provider — issuer + client id/secret from your IdP app</span>
        <span>·</span>
        <span>2. Copy the redirect URI from its row into the IdP app</span>
        <span>·</span>
        <span>3. Test sign-in — the row shows the last verified sign-in</span>
      </div>
      {err && <div style={{ background: `${PALETTE.danger}18`, border: `1px solid ${PALETTE.danger}44`, borderRadius: 4, padding: '7px 10px', fontSize: TYPE.body, color: PALETTE.danger, marginBottom: 12, fontFamily: FONTS.mono }}>{err}</div>}

      {section === 'health' && (
        <div>
          {health ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              <div style={{ ...cardStyle, display: 'flex', alignItems: 'center', gap: 10 }}>
                <StatusDot ok={health.status === 'ok'} />
                <div style={{ fontSize: TYPE.body, color: PALETTE.textDim, fontFamily: FONTS.mono }}>Platform status: <span style={{ color: health.status === 'ok' ? PALETTE.ok : PALETTE.danger, fontWeight: 600 }}>{health.status}</span></div>
              </div>
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                <StatCard label="Worker" value={health.worker?.running ? 'Running' : 'Stopped'} color={health.worker?.running ? PALETTE.ok : PALETTE.danger} />
                <StatCard label="Active Jobs" value={health.worker?.active_jobs ?? 0} />
                <StatCard label="Max Workers" value={health.worker?.max_workers ?? '-'} />
                <StatCard label="Users" value={health.db?.users ?? '-'} />
                <StatCard label="Projects" value={health.db?.projects ?? '-'} />
              </div>
              <button onClick={loadHealth} style={{ padding: '4px 10px', borderRadius: 4, border: `1px solid ${PALETTE.border}`, background: 'transparent', color: PALETTE.textMute, fontSize: TYPE.button, fontFamily: FONTS.mono, cursor: 'pointer', width: 'fit-content' }}>Refresh</button>
            </div>
          ) : (
            <div style={{ color: PALETTE.textFaint, fontSize: TYPE.body, fontFamily: FONTS.mono }}>Loading...</div>
          )}
        </div>
      )}

      {section === 'modules' && (
        <div style={{ marginTop: -4 }}>
          <ModulesView accent={accent} />
        </div>
      )}

      {section === 'logs' && (
        <div>
          <div style={{ display: 'flex', gap: 8, marginBottom: 10 }}>
            <input value={logFilter} onChange={e => setLogFilter(e.target.value)} placeholder="category=system&limit=50" style={{ ...inputStyle, flex: 1 }} />
            <button onClick={loadLogs} style={{ padding: '4px 10px', borderRadius: 4, border: `1px solid ${PALETTE.border}`, background: 'transparent', color: accent, fontSize: TYPE.button, fontFamily: FONTS.mono, cursor: 'pointer' }}>Load</button>
          </div>
          {logs.length > 0 ? (
            <div style={{ border: `1px solid ${PALETTE.border}`, borderRadius: 6, overflow: 'hidden', maxHeight: 420, display: 'flex', flexDirection: 'column' }}>
              <div style={{ display: 'grid', gridTemplateColumns: SYSTEM_LOG_GRID, gap: 12, flexShrink: 0, ...LOG_HEADER_STYLE }}>
                <span>Time</span><span>Category</span><span>Level</span><span>Event</span><span>Message</span>
              </div>
              <div style={{ overflow: 'auto' }}>
                {logs.slice(0, 100).map((l, i) => (
                  <div key={i}
                    style={{ display: 'grid', gridTemplateColumns: SYSTEM_LOG_GRID, gap: 12, alignItems: 'start', ...LOG_ROW_STYLE }}
                    onMouseEnter={logRowHover} onMouseLeave={logRowUnhover}>
                    <span style={{ color: PALETTE.textFaint, whiteSpace: 'nowrap' }}>{(l.ts || '').slice(11, 19)}</span>
                    <span style={{ color: '#5b8af5', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={l.category || ''}>{l.category}</span>
                    <span style={{ color: l.level === 'error' ? PALETTE.danger : l.level === 'warning' ? PALETTE.warn : PALETTE.textMute, textTransform: 'uppercase', fontSize: 11, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{l.level}</span>
                    <span style={{ color: PALETTE.textDim, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={l.event || ''}>{l.event}</span>
                    <span style={{ color: PALETTE.textFaint, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={l.message || ''}>{l.message}</span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div style={{ ...cardStyle, color: PALETTE.textFaint, fontSize: TYPE.body, textAlign: 'center' }}>No logs loaded</div>
          )}
        </div>
      )}

      {section === 'metrics' && (
        <div>
          {metrics ? (
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              <StatCard label="Projects" value={metrics.total_projects ?? '-'} />
              <StatCard label="Users" value={metrics.total_users ?? '-'} />
              <StatCard label="Hosts" value={metrics.total_hosts ?? '-'} />
              <StatCard label="Findings" value={metrics.total_findings ?? '-'} />
              {(metrics.job_status_counts && Object.keys(metrics.job_status_counts).length > 0) && (
                <div style={{ ...cardStyle, width: '100%', marginTop: 4 }}>
                  <div style={{ fontSize: TYPE.overline, color: PALETTE.textFaint, fontFamily: FONTS.mono, textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 8 }}>Jobs (all time)</div>
                  <div style={{ display: 'flex', gap: 12 }}>
                    {Object.entries(metrics.job_status_counts).map(([k, v]) => (
                      <div key={k} style={{ fontSize: TYPE.body, fontFamily: FONTS.mono, color: k === 'failed' ? PALETTE.danger : k === 'done' ? PALETTE.ok : PALETTE.textMute }}>
                        <span style={{ fontWeight: 700 }}>{v}</span> <span style={{ fontSize: TYPE.overline, textTransform: 'uppercase' }}>{k}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
              <button onClick={loadMetrics} style={{ padding: '4px 10px', borderRadius: 4, border: `1px solid ${PALETTE.border}`, background: 'transparent', color: PALETTE.textMute, fontSize: TYPE.button, fontFamily: FONTS.mono, cursor: 'pointer', width: 'fit-content' }}>Refresh</button>
            </div>
          ) : (
            <div style={{ color: PALETTE.textFaint, fontSize: TYPE.body, fontFamily: FONTS.mono }}>Loading...</div>
          )}
        </div>
      )}

      {section === 'ha' && (
        <div>
          {!ha ? (
            <div style={{ color: PALETTE.textFaint, fontSize: TYPE.body, fontFamily: FONTS.mono }}>Loading...</div>
          ) : !ha.enabled ? (
            <div style={{ ...cardStyle, color: PALETTE.textFaint, fontSize: TYPE.body, textAlign: 'center' }}>
              Not running in HA mode — HA_MONITOR_HOST / REDIS_SENTINEL_HOSTS aren&apos;t set.
              <div style={{ marginTop: 4, fontSize: TYPE.button, color: PALETTE.textGhost }}>See docs/modules/HA_DEPLOYMENT.md to deploy the multi-node cluster.</div>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              <div style={{ ...cardStyle, padding: 0 }}>
                <div style={{ fontSize: TYPE.overline, color: PALETTE.textFaint, fontFamily: FONTS.mono, textTransform: 'uppercase', letterSpacing: '0.06em', padding: '12px 14px 4px' }}>Postgres (pg_auto_failover)</div>
                {!ha.postgres ? (
                  <div style={{ fontSize: TYPE.body, color: PALETTE.textGhost, fontFamily: FONTS.mono, padding: '4px 14px 12px' }}>Not configured (HA_MONITOR_HOST unset)</div>
                ) : !ha.postgres.reachable ? (
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '4px 14px 12px' }}>
                    <StatusDot ok={false} />
                    <span style={{ fontSize: TYPE.body, color: PALETTE.danger, fontFamily: FONTS.mono }}>Monitor unreachable{ha.postgres.error ? `: ${ha.postgres.error}` : ''}</span>
                  </div>
                ) : (
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: TYPE.body, fontFamily: FONTS.mono }}>
                    <thead>
                      <tr style={{ borderBottom: `1px solid ${PALETTE.borderSoft}` }}>
                        {['', 'Node', 'Host:Port', 'State', 'Goal', 'TLI:LSN'].map(h => <th key={h} style={thStyle}>{h}</th>)}
                      </tr>
                    </thead>
                    <tbody>
                      {ha.postgres.nodes.map(n => {
                        const isPrimary = n.reportedstate === 'primary';
                        const isHealthy = ['primary', 'secondary'].includes(n.reportedstate);
                        return (
                          <tr key={n.nodeid} style={rowBorder}>
                            <td style={tdStyle}><StatusDot ok={isHealthy} /></td>
                            <td style={{ ...tdStyle, color: PALETTE.textDim }}>{n.nodename}</td>
                            <td style={{ ...tdStyle, color: PALETTE.textMute }}>{n.nodehost}:{n.nodeport}</td>
                            <td style={tdStyle}><span style={{ color: isPrimary ? PALETTE.ok : isHealthy ? '#5b8af5' : PALETTE.warn, fontWeight: 600 }}>{n.reportedstate}</span></td>
                            <td style={{ ...tdStyle, color: PALETTE.textFaint }}>{n.goalstate}</td>
                            <td style={{ ...tdStyle, color: PALETTE.textGhost }}>{n.reportedtli}:{n.reportedlsn}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                )}
              </div>

              <div style={{ ...cardStyle, padding: 0 }}>
                <div style={{ fontSize: TYPE.overline, color: PALETTE.textFaint, fontFamily: FONTS.mono, textTransform: 'uppercase', letterSpacing: '0.06em', padding: '12px 14px 4px' }}>Redis (Sentinel)</div>
                {!ha.redis ? (
                  <div style={{ fontSize: TYPE.body, color: PALETTE.textGhost, fontFamily: FONTS.mono, padding: '4px 14px 12px' }}>Not configured (REDIS_SENTINEL_HOSTS unset)</div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 8, padding: '4px 14px 12px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <StatusDot ok={ha.redis.reachable} />
                      <span style={{ fontSize: TYPE.body, fontFamily: FONTS.mono, color: PALETTE.textDim }}>
                        Master: {ha.redis.master ? <span style={{ color: PALETTE.ok, fontWeight: 600 }}>{ha.redis.master.host}:{ha.redis.master.port}</span> : <span style={{ color: PALETTE.danger }}>unknown{ha.redis.error ? `: ${ha.redis.error}` : ''}</span>}
                      </span>
                    </div>
                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: TYPE.body, fontFamily: FONTS.mono }}>
                      <thead>
                        <tr style={{ borderBottom: `1px solid ${PALETTE.borderSoft}` }}>
                          {['', 'Sentinel', 'Quorum', 'Known slaves', 'Known sentinels'].map(h => <th key={h} style={thStyle}>{h}</th>)}
                        </tr>
                      </thead>
                      <tbody>
                        {ha.redis.sentinels.map(s => (
                          <tr key={`${s.host}:${s.port}`} style={rowBorder}>
                            <td style={tdStyle}><StatusDot ok={s.reachable} /></td>
                            <td style={{ ...tdStyle, color: PALETTE.textMute }}>{s.host}:{s.port}</td>
                            <td style={{ ...tdStyle, color: PALETTE.textFaint }}>{s.quorum ?? '-'}</td>
                            <td style={{ ...tdStyle, color: PALETTE.textFaint }}>{s.num_slaves ?? '-'}</td>
                            <td style={{ ...tdStyle, color: PALETTE.textFaint }}>{s.num_other_sentinels != null ? Number(s.num_other_sentinels) + 1 : '-'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    {ha.redis.replicas.length > 0 && (
                      <div style={{ fontSize: TYPE.button, color: PALETTE.textFaint, fontFamily: FONTS.mono }}>
                        Replicas: {ha.redis.replicas.map(r => `${r.host}:${r.port}`).join(', ')}
                      </div>
                    )}
                  </div>
                )}
              </div>

              <button onClick={loadHa} style={{ padding: '4px 10px', borderRadius: 4, border: `1px solid ${PALETTE.border}`, background: 'transparent', color: PALETTE.textMute, fontSize: TYPE.button, fontFamily: FONTS.mono, cursor: 'pointer', width: 'fit-content' }}>Refresh</button>
            </div>
          )}
        </div>
      )}

      {section === 'sso' && (
        <div style={{ marginTop: -4 }}>
          {ssoEntitled ? (
            <PlatformSsoPanel accent={accent} />
          ) : (
            <div style={{ ...cardStyle, display: 'flex', alignItems: 'center', gap: 12 }}>
              <div style={{ width: 34, height: 34, borderRadius: 8, background: `${PALETTE.warn}18`, border: `1px solid ${PALETTE.warn}55`, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                <Icon name="lock" size={14} color={PALETTE.warn} />
              </div>
              <div>
                <div style={{ fontSize: TYPE.body, color: PALETTE.text, fontFamily: FONTS.display, fontWeight: 700, marginBottom: 3 }}>
                  SSO / OIDC <span style={{ color: PALETTE.warn, fontSize: TYPE.micro, fontFamily: FONTS.mono, fontWeight: 700, letterSpacing: '0.05em', marginLeft: 6 }}>REQUIRES {requiredTier(FEATURE.SSO).toUpperCase()}</span>
                </div>
                <div style={{ fontSize: TYPE.label, color: PALETTE.textFaint }}>
                  Platform-wide SSO is an Enterprise feature. Contact sales@umbryx.pro to upgrade — the license you install then unlocks this tab.
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {section === 'license' && (
        <div style={{ marginTop: -4 }}>
          <PlatformLicensePanel accent={accent} />
        </div>
      )}
    </div>
  );
}

SystemDashboard.propTypes = { accent: PropTypes.string };

// ── Platform-wide SSO (org_id NULL) ─────────────────────────────────────
// JIT-provisioned users from these providers join no organization — a
// manager assigns one afterward. Distinct from the org-scoped SSO panel
// in OrganizationsView.jsx (that one still exists, for the MSSP case
// where a client org runs its own IdP).

function PlatformSsoPanel({ accent }) {
  const [providers, setProviders] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [err, setErr] = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    try { setProviders(await api.listPlatformOidcProviders()); setErr(null); }
    catch (e) { setErr(e.message); }
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleCreate = async (data) => {
    try {
      const created = await api.createPlatformOidcProvider(data);
      // NOTE: don't setShowCreate(false) here — the modal switches to its
      // "provider created" state (redirect URI + copy) and closes on Done.
      await load();
      return created;
    } catch (e) { setErr(e.message); return null; }
  };

  const handleToggle = async (p, field) => {
    try { await api.updatePlatformOidcProvider(p.id, { [field]: !p[field] }); await load(); }
    catch (e) { setErr(e.message); }
  };

  const handleDelete = async (id) => {
    if (!confirm('Delete this platform SSO provider? Users linked through it will no longer be able to sign in via SSO.')) return;
    try { await api.deletePlatformOidcProvider(id); await load(); }
    catch (e) { setErr(e.message); }
  };

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 12, gap: 12 }}>
        <div style={{ fontSize: TYPE.body, color: PALETTE.textFaint, fontFamily: FONTS.mono, lineHeight: 1.5 }}>
          Platform-wide SSO — applies to the whole instance, not one organization. New users are
          matched by email and created with no organization membership; assign them to
          orgs/teams from Organizations afterward.
        </div>
        <button onClick={() => setShowCreate(true)} style={{ padding: '5px 10px', borderRadius: 4, border: `1px solid ${accent}`, background: `${accent}15`, color: accent, fontSize: TYPE.button, fontFamily: FONTS.mono, cursor: 'pointer', flexShrink: 0 }}>+ Add Provider</button>
      </div>

      {err && <div style={{ background: `${PALETTE.danger}18`, border: `1px solid ${PALETTE.danger}44`, borderRadius: 4, padding: '7px 10px', fontSize: TYPE.body, color: PALETTE.danger, marginBottom: 12, fontFamily: FONTS.mono }}>{err}</div>}
      {loading && <div style={{ color: PALETTE.textFaint, fontSize: TYPE.body, fontFamily: FONTS.mono }}>Loading...</div>}
      {!loading && providers.length === 0 && (
        <div style={{ ...cardStyle, color: PALETTE.textFaint, fontSize: TYPE.body, textAlign: 'center' }}>No platform-wide SSO providers configured</div>
      )}

      {providers.map(p => (
        <div key={p.id} style={{ ...cardStyle, marginBottom: 10 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontSize: 12, fontWeight: 600, color: PALETTE.textDim, fontFamily: FONTS.mono }}>{p.name}</span>
              <span style={{ fontSize: TYPE.overline, padding: '1px 6px', borderRadius: 3, background: p.enabled ? `${PALETTE.ok}22` : `${PALETTE.textFaint}22`, color: p.enabled ? PALETTE.ok : PALETTE.textFaint, fontFamily: FONTS.mono }}>{p.enabled ? 'enabled' : 'disabled'}</span>
              {p.jit_provisioning_enabled && <span style={{ fontSize: TYPE.overline, padding: '1px 6px', borderRadius: 3, background: '#5b8af522', color: '#5b8af5', fontFamily: FONTS.mono }}>JIT</span>}
              {p.allow_private_issuer && <span style={{ fontSize: TYPE.overline, padding: '1px 6px', borderRadius: 3, background: `${PALETTE.warn}22`, color: PALETTE.warn, fontFamily: FONTS.mono }}>private issuer allowed</span>}
            </div>
            <button onClick={() => handleDelete(p.id)} style={{ padding: '2px 6px', borderRadius: 4, border: `1px solid ${PALETTE.danger}44`, background: 'transparent', color: PALETTE.danger, fontSize: TYPE.button, fontFamily: FONTS.mono, cursor: 'pointer' }}>Delete</button>
          </div>
          <div style={{ fontSize: TYPE.button, color: PALETTE.textFaint, fontFamily: FONTS.mono, marginTop: 4 }}>{p.issuer_url}</div>
          {/* Ready-to-paste IdP redirect URI: the provider id in the path is
              generated on create, so admins previously had to construct the
              URI by hand (and hunt for ids via API/psql) to register it in
              the IdP. */}
          <div style={{ fontSize: TYPE.button, color: PALETTE.textGhost, fontFamily: FONTS.mono, marginTop: 2, display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
            <span>redirect URI:</span>
            <span style={{ color: PALETTE.textDim }}>{`${location.origin}/api/auth/oidc/${p.id}/callback`}</span>
            <button
              onClick={() => copyToClipboard(`${location.origin}/api/auth/oidc/${p.id}/callback`).catch(() => {})}
              title="Copy redirect URI"
              style={{ padding: '1px 7px', borderRadius: 3, border: `1px solid ${PALETTE.border}`, background: 'transparent', color: PALETTE.textMute, fontSize: TYPE.overline, fontFamily: FONTS.mono, cursor: 'pointer' }}
            >copy</button>
          </div>
          <div style={{ fontSize: TYPE.button, color: PALETTE.textGhost, fontFamily: FONTS.mono, marginTop: 2 }}>
            {p.email_domain ? `domain: ${p.email_domain}` : 'no domain set — matches any email (catch-all)'}
            {p.require_platform_mfa && ' · platform MFA required'}
            {p.last_test_login_at ? ` · last verified sign-in: ${new Date(p.last_test_login_at).toLocaleString()}` : ' · not yet verified with a successful sign-in'}
          </div>
          <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
            <a href={`/api/auth/oidc/${p.id}/login`} target="_blank" rel="noopener" title="Open the provider's sign-in flow in a new tab"
              style={{ padding: '3px 8px', borderRadius: 4, border: `1px solid ${accent}44`, background: `${accent}15`, color: accent, fontSize: TYPE.button, fontFamily: FONTS.mono, cursor: 'pointer', textDecoration: 'none' }}>Test sign-in</a>
            <button onClick={() => handleToggle(p, 'enabled')} style={{ padding: '3px 8px', borderRadius: 4, border: `1px solid ${PALETTE.border}`, background: 'transparent', color: PALETTE.textMute, fontSize: TYPE.button, fontFamily: FONTS.mono, cursor: 'pointer' }}>{p.enabled ? 'Disable' : 'Enable'}</button>
          </div>
        </div>
      ))}

      {showCreate && <CreatePlatformSsoModal accent={accent} onClose={() => setShowCreate(false)} onCreate={handleCreate} />}
    </div>
  );
}
PlatformSsoPanel.propTypes = { accent: PropTypes.string };

export function CreatePlatformSsoModal({ accent, onClose, onCreate }) {
  const [created, setCreated] = useState(null);
  // Pre-generated provider id — the exact callback URL is copyable while
  // filling the form (register it in the IdP first, then Create).
  const [presetId] = useState(() => 'oidcp' + Array.from(globalThis.crypto.getRandomValues(new Uint8Array(4))).map(b => b.toString(16).padStart(2, '0')).join(''));
  const presetUri = `${location.origin}/api/auth/oidc/${presetId}/callback`;
  const [name, setName] = useState('');
  const [issuerUrl, setIssuerUrl] = useState('');
  const [clientId, setClientId] = useState('');
  const [clientSecret, setClientSecret] = useState('');
  const [emailDomain, setEmailDomain] = useState('');
  const [jit, setJit] = useState(true);
  const [requireMfa, setRequireMfa] = useState(false);
  const [allowPrivate, setAllowPrivate] = useState(false);

  const canSubmit = name.trim() && issuerUrl.trim() && clientId.trim() && clientSecret.trim();

  if (created) {
    // Provider id is generated server-side on create — the redirect URI
    // only exists now. Show it in the same dialog with a copy button so
    // the IdP registration doesn't need a second trip to the provider row.
    const uri = `${location.origin}/api/auth/oidc/${created.id}/callback`;
    return (
      <div style={{ position: 'fixed', inset: 0, background: '#00000088', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }} onClick={onClose}>
        <div style={{ background: PALETTE.bg2, border: `1px solid ${PALETTE.borderSoft}`, borderRadius: 10, padding: 20, width: 480 }} onClick={e => e.stopPropagation()}>
          <div style={{ fontSize: TYPE.sectionTitle, fontWeight: 700, color: PALETTE.text, fontFamily: FONTS.display, marginBottom: 12 }}>Provider created</div>
          <div style={{ fontSize: TYPE.body, color: PALETTE.textFaint, fontFamily: FONTS.mono, marginBottom: 10, lineHeight: 1.6 }}>
            Register this redirect URI in your IdP application settings, then use <b>Test sign-in</b> on the provider row.
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, background: PALETTE.bg1, border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '8px 10px' }}>
            <span style={{ fontSize: TYPE.button, color: PALETTE.textDim, fontFamily: FONTS.mono, wordBreak: 'break-all', flex: 1 }}>{uri}</span>
            <button onClick={() => copyToClipboard(uri).catch(() => {})}
              style={{ padding: '4px 10px', borderRadius: 4, border: `1px solid ${accent}44`, background: `${accent}15`, color: accent, fontSize: TYPE.button, fontFamily: FONTS.mono, cursor: 'pointer', flexShrink: 0 }}>copy</button>
          </div>
          <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 14 }}>
            <button onClick={onClose} style={{ padding: '8px 18px', borderRadius: 4, border: `1px solid ${PALETTE.border}`, background: 'transparent', color: PALETTE.textMute, fontSize: TYPE.body, fontFamily: FONTS.mono, cursor: 'pointer' }}>Done</button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div style={{ position: 'fixed', inset: 0, background: '#00000088', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }} onClick={onClose}>
      <div style={{ background: PALETTE.bg2, border: `1px solid ${PALETTE.borderSoft}`, borderRadius: 10, padding: 20, width: 420, maxHeight: '85vh', overflow: 'auto' }} onClick={e => e.stopPropagation()}>
        <div style={{ fontSize: TYPE.sectionTitle, fontWeight: 700, color: PALETTE.text, fontFamily: FONTS.display, marginBottom: 14 }}>Add Platform SSO Provider</div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          <FieldRow label="Display name"><input value={name} onChange={e => setName(e.target.value)} placeholder="Corp GitLab" style={{ ...inputStyle, width: '100%' }} /></FieldRow>
          <FieldRow label="Issuer URL"><input value={issuerUrl} onChange={e => setIssuerUrl(e.target.value)} placeholder="https://gitlab.example.com" style={{ ...inputStyle, width: '100%' }} /></FieldRow>
          <div style={{ fontSize: TYPE.overline, color: PALETTE.textGhost, fontFamily: FONTS.mono, marginTop: -6 }}>
            Endpoints are discovered automatically from {'{issuer}'}/.well-known/openid-configuration.
          </div>

          <div style={{ background: PALETTE.bg1, border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '8px 10px', display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: TYPE.overline, color: PALETTE.textGhost, fontFamily: FONTS.mono, textTransform: 'uppercase', flexShrink: 0 }}>Callback URL</span>
            <span style={{ fontSize: TYPE.button, color: PALETTE.textDim, fontFamily: FONTS.mono, wordBreak: 'break-all', flex: 1 }}>{presetUri}</span>
            <button onClick={() => copyToClipboard(presetUri).catch(() => {})}
              style={{ padding: '4px 10px', borderRadius: 4, border: `1px solid ${accent}44`, background: `${accent}15`, color: accent, fontSize: TYPE.button, fontFamily: FONTS.mono, cursor: 'pointer', flexShrink: 0 }}>copy</button>
          </div>
          <FieldRow label="Client ID"><input value={clientId} onChange={e => setClientId(e.target.value)} style={{ ...inputStyle, width: '100%' }} /></FieldRow>
          <FieldRow label="Client secret"><input type="password" value={clientSecret} onChange={e => setClientSecret(e.target.value)} style={{ ...inputStyle, width: '100%' }} /></FieldRow>
          <FieldRow label="Email domain (blank = matches any email)"><input value={emailDomain} onChange={e => setEmailDomain(e.target.value)} placeholder="corp.example.com" style={{ ...inputStyle, width: '100%' }} /></FieldRow>
          <Checkbox checked={jit} onChange={setJit} label="Auto-create accounts for new users on first sign-in (JIT provisioning)" />
          <Checkbox checked={requireMfa} onChange={setRequireMfa} label="Still require platform TOTP-MFA after a successful SSO sign-in" />
          <Checkbox checked={allowPrivate} onChange={setAllowPrivate} accent={PALETTE.warn} label="Allow issuer on a private/internal address (self-hosted IdP behind your firewall)" />
          <div style={{ display: 'flex', gap: 8, marginTop: 4 }}>
            <button onClick={onClose} style={{ flex: 1, padding: '8px 0', borderRadius: 4, border: `1px solid ${PALETTE.border}`, background: 'transparent', color: PALETTE.textMute, fontSize: TYPE.body, fontFamily: FONTS.mono, cursor: 'pointer' }}>Cancel</button>
            <button
              disabled={!canSubmit}
              onClick={async () => {
                const created = await onCreate({
                  name: name.trim(), issuer_url: issuerUrl.trim(), client_id: clientId.trim(), client_secret: clientSecret,
                  email_domain: emailDomain.trim(), jit_provisioning_enabled: jit, require_platform_mfa: requireMfa,
                  allow_private_issuer: allowPrivate, id: presetId,
                });
                if (created) setCreated(created);
              }}
              style={{ flex: 1, padding: '8px 0', borderRadius: 4, border: `1px solid ${accent}`, background: canSubmit ? `${accent}22` : 'transparent', color: accent, fontSize: TYPE.body, fontFamily: FONTS.mono, cursor: canSubmit ? 'pointer' : 'not-allowed', opacity: canSubmit ? 1 : 0.5 }}
            >
              Create
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
CreatePlatformSsoModal.propTypes = { accent: PropTypes.string, onClose: PropTypes.func, onCreate: PropTypes.func };

function FieldRow({ label, children }) {
  return (
    <div>
      <div style={{ fontSize: TYPE.overline, color: PALETTE.textGhost, marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.08em', fontFamily: FONTS.mono }}>{label}</div>
      {children}
    </div>
  );
}
FieldRow.propTypes = { label: PropTypes.node, children: PropTypes.node };

// ── License (ФТ-9, docs/modules/LICENSING_TZ.md) ────────────────────────
// Instance-wide, not per-org — a self-hosted install is licensed as a
// whole (backend/app/core/license.py's module docstring). Every internal
// Organization shares this same entitlement.

const TIER_LABELS = { free: 'Free', team: 'Team', pro: 'Pro', enterprise: 'Enterprise' };

function daysUntil(expiresAtEpochSeconds) {
  if (!expiresAtEpochSeconds) return null;
  const ms = Number(expiresAtEpochSeconds) * 1000 - Date.now();
  return Math.ceil(ms / (24 * 3600 * 1000));
}

function PlatformLicensePanel({ accent }) {
  const [status, setStatus] = useState(null);
  const [fingerprint, setFingerprint] = useState('');
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState(null);
  const [showUpload, setShowUpload] = useState(false);
  const [keyInput, setKeyInput] = useState('');
  const [activating, setActivating] = useState(false);

  const handleActivateKey = async () => {
    setActivating(true);
    try {
      await api.activateLicenseKey(keyInput.trim());
      setKeyInput('');
      setErr(null);
      await load();
    } catch (e) { setErr(e.message); }
    setActivating(false);
  };

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [s, f] = await Promise.all([api.getLicenseStatus(), api.getLicenseFingerprint()]);
      setStatus(s);
      setFingerprint(f.fingerprint);
      setErr(null);
    } catch (e) { setErr(e.message); }
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleDownloadActivationRequest = async () => {
    // Offline (air-gap) activation: export the C2V request; carry it to the
    // License Server, get back a signed .lic, and upload it below. No network.
    try {
      const data = await api.getActivationRequest();
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = 'umbryx-activation-request.c2v.json'; a.click();
      URL.revokeObjectURL(url);
    } catch (e) { setErr(e.message || 'Could not build activation request'); }
  };

  const handleDownloadFingerprint = () => {
    const blob = new Blob([fingerprint], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'umbryx.fingerprint'; a.click();
    URL.revokeObjectURL(url);
  };

  const handleCopyFingerprint = async () => {
    // navigator.clipboard is undefined over plain HTTP (no secure context) —
    // copyToClipboard falls back to execCommand so Copy works there too.
    try { await copyToClipboard(fingerprint); }
    catch { setErr('Clipboard access denied — use Download instead'); }
  };

  const handleUpload = async (token) => {
    try { await api.uploadLicense(token); setShowUpload(false); setErr(null); await load(); }
    catch (e) { setErr(e.message); }
  };

  const handleToggleChannel = async () => {
    try { await api.setLicenseChannel(status.channel !== 'offline'); setErr(null); await load(); }
    catch (e) { setErr(e.message); }
  };

  if (loading) {
    return <div style={{ color: PALETTE.textFaint, fontSize: TYPE.body, fontFamily: FONTS.mono }}>Loading...</div>;
  }

  const lifecycle = status?.state;
  const reason = status?.expiry_reason;
  const effLeft = status?.days_left != null ? status.days_left : null;
  // The real "renew" horizon is the token's own expiry — NOT the effective
  // days_left, which in online mode is capped by the rolling 7-day heartbeat
  // window and so would perpetually read ~6 days on a healthy instance.
  const renewLeft = status?.token_days_left != null
    ? status.token_days_left
    : (status?.expires_at ? daysUntil(status.expires_at) : null);
  // Lost contact with the license server is only a concern once the heartbeat
  // window is genuinely running down (heartbeats failing for days), not while
  // they are succeeding.
  const heartbeatCritical = reason === 'heartbeat' && effLeft !== null && effLeft <= 3;
  const showExpiryWarning =
    lifecycle === 'grace' || lifecycle === 'wind_down' ||
    heartbeatCritical || (renewLeft !== null && renewLeft <= 14);
  const bannerColor =
    lifecycle === 'wind_down' || (renewLeft !== null && renewLeft < 0) ? PALETTE.danger : PALETTE.warn;
  let bannerText;
  if (lifecycle === 'wind_down') {
    bannerText = 'License lapsed — creating and operating resources is paused. Reads, exports and teardown still work. Upload a renewed license to restore full access; no data was lost.';
  } else if (lifecycle === 'grace') {
    bannerText = `License expired — in grace period (${status?.grace_days ?? 14}-day window). Renew now to avoid functionality being limited.`;
  } else if (heartbeatCritical) {
    const age = status?.heartbeat_age_days;
    const ageStr = age != null ? ` (last contact ${age} day${age !== 1 ? 's' : ''} ago)` : '';
    bannerText = `Can’t reach the license server${ageStr} — reconnect within ${effLeft} day${effLeft !== 1 ? 's' : ''} to avoid interruption.`;
  } else if (renewLeft !== null && renewLeft < 0) {
    bannerText = `License expired ${Math.abs(renewLeft)} day${Math.abs(renewLeft) !== 1 ? 's' : ''} ago — upload a renewed license.`;
  } else if (renewLeft !== null && renewLeft <= 14) {
    bannerText = `License expires in ${renewLeft} day${renewLeft !== 1 ? 's' : ''} — renew soon to avoid an interruption.`;
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      {err && <div style={{ background: `${PALETTE.danger}18`, border: `1px solid ${PALETTE.danger}44`, borderRadius: 4, padding: '7px 10px', fontSize: TYPE.body, color: PALETTE.danger, fontFamily: FONTS.mono }}>{err}</div>}

      <div style={{ ...cardStyle, display: 'flex', alignItems: 'center', gap: 10 }}>
        <span style={{ fontSize: 16, fontWeight: 700, color: PALETTE.text, fontFamily: FONTS.mono }}>
          {TIER_LABELS[status?.tier] || status?.tier}
        </span>
        <span style={{ fontSize: TYPE.button, fontFamily: FONTS.mono, padding: '2px 8px', borderRadius: 10, background: status?.source === 'license_token' ? `${PALETTE.ok}22` : `${PALETTE.textMute}22`, color: status?.source === 'license_token' ? PALETTE.ok : PALETTE.textMute }}>
          {status?.source === 'license_token' ? 'licensed' : 'manual'}
        </span>
        {status?.source === 'license_token' && (
          <span style={{ fontSize: TYPE.button, fontFamily: FONTS.mono, padding: '2px 8px', borderRadius: 10, background: status.channel === 'offline' ? '#eab30822' : '#5b8af522', color: status.channel === 'offline' ? '#eab308' : '#5b8af5' }}>
            {status.channel === 'offline' ? 'offline channel' : 'online channel'}
          </span>
        )}
      </div>

      {showExpiryWarning && bannerText && (
        <div style={{ border: `1px solid ${bannerColor}`, borderRadius: 6, padding: '8px 12px', color: bannerColor, fontSize: TYPE.body, fontFamily: FONTS.mono }}>
          {bannerText}
        </div>
      )}

      {status?.source === 'license_token' && (
        <div style={{ fontSize: TYPE.body, color: PALETTE.textFaint, fontFamily: FONTS.mono }}>
          Last verified: {status.verified_at ? new Date(status.verified_at).toLocaleString() : '—'}
          {status.channel !== 'offline' && (
            <> · Last heartbeat: {status.last_heartbeat_ok_at ? new Date(status.last_heartbeat_ok_at).toLocaleString() : 'never'}</>
          )}
        </div>
      )}

      <div style={cardStyle}>
        <div style={{ fontSize: TYPE.sectionTitle, fontWeight: 600, color: PALETTE.textDim, fontFamily: FONTS.mono, marginBottom: 6 }}>Installation fingerprint</div>
        <div style={{ fontSize: TYPE.button, color: PALETTE.textGhost, fontFamily: FONTS.mono, marginBottom: 8 }}>
          Send this to Umbryx to activate or renew a license for this installation. It never leaves this page automatically.
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <code style={{ flex: 1, fontSize: TYPE.button, color: PALETTE.textFaint, fontFamily: FONTS.mono, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{fingerprint}</code>
          <button onClick={handleCopyFingerprint} style={{ padding: '4px 10px', borderRadius: 4, border: `1px solid ${PALETTE.border}`, background: 'transparent', color: PALETTE.textMute, fontSize: TYPE.button, fontFamily: FONTS.mono, cursor: 'pointer', flexShrink: 0 }}>Copy</button>
          <button onClick={handleDownloadFingerprint} style={{ padding: '4px 10px', borderRadius: 4, border: `1px solid ${PALETTE.border}`, background: 'transparent', color: PALETTE.textMute, fontSize: TYPE.button, fontFamily: FONTS.mono, cursor: 'pointer', flexShrink: 0 }}>Download</button>
        </div>
        <div style={{ marginTop: 10, paddingTop: 10, borderTop: `1px solid ${PALETTE.borderSoft}` }}>
          <div style={{ fontSize: TYPE.button, color: PALETTE.textGhost, fontFamily: FONTS.mono, marginBottom: 8 }}>
            Air-gapped? Download an activation request and hand it to Umbryx — you'll get back a <code>.lic</code> bound to this machine to upload below. No internet needed.
          </div>
          <button onClick={handleDownloadActivationRequest} style={{ padding: '5px 12px', borderRadius: 4, border: `1px solid ${accent}66`, background: 'transparent', color: accent, fontSize: TYPE.button, fontFamily: FONTS.mono, cursor: 'pointer' }}>Download activation request</button>
        </div>
      </div>

      <div style={cardStyle}>
        <div style={{ fontSize: TYPE.sectionTitle, fontWeight: 600, color: PALETTE.textDim, fontFamily: FONTS.mono, marginBottom: 6 }}>Delivery channel</div>
        <div style={{ fontSize: TYPE.button, color: PALETTE.textGhost, fontFamily: FONTS.mono, marginBottom: 8 }}>
          Online checks in automatically every 24h and renews on its own. Offline requires manually uploading a new license file when it's due — pick this if this installation is deliberately isolated from the internet.
        </div>
        <button onClick={handleToggleChannel} style={{ padding: '5px 12px', borderRadius: 4, border: `1px solid ${PALETTE.border}`, background: 'transparent', color: PALETTE.textMute, fontSize: TYPE.button, fontFamily: FONTS.mono, cursor: 'pointer' }}>
          {status?.channel === 'offline' ? 'Switch to online (automatic)' : 'Switch to offline (manual)'}
        </button>
      </div>

      {/* Online key activation — the whole flow is server-to-server: paste
          the UMBR- key, the backend exchanges it + this instance's identity
          for a signed token. Files are only for the offline channel below. */}
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
        <input value={keyInput} onChange={e => setKeyInput(e.target.value.toUpperCase())}
          placeholder="UMBR-XXXX-XXXX-XXXX"
          disabled={activating}
          style={{ width: 230, background: PALETTE.bg2, border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 10px', color: PALETTE.textDim, fontSize: TYPE.body, fontFamily: FONTS.mono, outline: 'none', letterSpacing: '0.05em' }} />
        <button onClick={handleActivateKey} disabled={activating || !keyInput.trim()}
          style={{ padding: '6px 14px', borderRadius: 4, border: `1px solid ${accent}`, background: keyInput.trim() ? `${accent}18` : 'transparent', color: accent, fontSize: TYPE.body, fontFamily: FONTS.mono, cursor: keyInput.trim() ? 'pointer' : 'default', opacity: keyInput.trim() ? 1 : 0.5 }}>
          {activating ? 'Activating…' : 'Activate online'}
        </button>
        <span style={{ fontSize: TYPE.overline, color: PALETTE.textGhost, fontFamily: FONTS.mono }}>— or use the file flow for offline installs:</span>
        <button onClick={() => setShowUpload(true)} style={{ padding: '6px 14px', borderRadius: 4, border: `1px solid ${PALETTE.border}`, background: 'transparent', color: PALETTE.textMute, fontSize: TYPE.body, fontFamily: FONTS.mono, cursor: 'pointer', width: 'fit-content' }}>
          Upload license file
        </button>
      </div>

      {showUpload && <UploadLicenseModal accent={accent} onClose={() => setShowUpload(false)} onUpload={handleUpload} />}
    </div>
  );
}
PlatformLicensePanel.propTypes = { accent: PropTypes.string };

function UploadLicenseModal({ accent, onClose, onUpload }) {
  const [token, setToken] = useState('');

  const handleFile = (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => setToken(String(reader.result || '').trim());
    reader.readAsText(file);
  };

  return (
    <div style={{ position: 'fixed', inset: 0, background: '#00000088', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }} onClick={onClose}>
      <div style={{ background: PALETTE.bg2, border: `1px solid ${PALETTE.borderSoft}`, borderRadius: 10, padding: 20, width: 420, maxHeight: '85vh', overflow: 'auto' }} onClick={e => e.stopPropagation()}>
        <div style={{ fontSize: TYPE.sectionTitle, fontWeight: 700, color: PALETTE.text, fontFamily: FONTS.display, marginBottom: 14 }}>Activate / renew license</div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          <div style={{ fontSize: TYPE.button, color: PALETTE.textGhost, fontFamily: FONTS.mono }}>
            Upload the .lic file you received, or paste its contents directly.
          </div>
          <input type="file" accept=".lic,.txt" onChange={handleFile} style={{ fontSize: TYPE.button, color: PALETTE.textFaint, fontFamily: FONTS.mono }} />
          <FieldRow label="License token">
            <textarea value={token} onChange={e => setToken(e.target.value)} placeholder="<payload>.<signature>" rows={4}
              style={{ ...inputStyle, width: '100%', resize: 'vertical', fontFamily: FONTS.mono }} />
          </FieldRow>
          <div style={{ display: 'flex', gap: 8, marginTop: 4 }}>
            <button onClick={onClose} style={{ flex: 1, padding: '8px 0', borderRadius: 4, border: `1px solid ${PALETTE.border}`, background: 'transparent', color: PALETTE.textMute, fontSize: TYPE.body, fontFamily: FONTS.mono, cursor: 'pointer' }}>Cancel</button>
            <button
              disabled={!token.trim()}
              onClick={() => onUpload(token.trim())}
              style={{ flex: 1, padding: '8px 0', borderRadius: 4, border: `1px solid ${accent}`, background: token.trim() ? `${accent}22` : 'transparent', color: accent, fontSize: TYPE.body, fontFamily: FONTS.mono, cursor: token.trim() ? 'pointer' : 'not-allowed', opacity: token.trim() ? 1 : 0.5 }}
            >
              Activate
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
UploadLicenseModal.propTypes = { accent: PropTypes.string, onClose: PropTypes.func, onUpload: PropTypes.func };
