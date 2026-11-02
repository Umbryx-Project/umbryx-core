import { useState, useEffect, useCallback } from 'react';
import PropTypes from 'prop-types';
import { api } from '../api.js';
import { AttackerSSHPanel } from '../components/AttackerSSHPanel.jsx';
import { EgressProxyPanel } from '../components/EgressProxyPanel.jsx';
import { toastError, toastSuccess } from '../components/Toast.jsx';
import {
  Badge, PageTitle, SectionTitle, Overline, Card,
  PALETTE, FONTS,
} from '../components/UI.jsx';

/*
 * Infra → Connections (2026-09-22).
 *
 * One place for "how the platform connects to machines it runs things on":
 *   1. SSH Executor targets — attacker machines for scans / exec / pivots
 *      (moved here from Admin → System Modules).
 *   2. Executor workstations — pool/imported machines flagged as executors
 *      (they appear to projects as ready-to-use executor targets).
 *   3. Pointers to provider credentials (Platform Ops → Providers) —
 *      provisioning connection settings live there.
 */

const AMBER = '#e0a820';
const GREEN = '#39d353';
const RED = '#cc2233';

const btn = (bg, disabled) => ({
  background: disabled ? '#1a1d26' : bg + '18',
  border: `1px solid ${disabled ? '#2a2d35' : bg + '66'}`,
  color: disabled ? '#606570' : bg,
  borderRadius: 4, padding: '4px 10px',
  cursor: disabled ? 'default' : 'pointer',
  fontSize: 10, fontFamily: FONTS.mono, fontWeight: 700,
});

const statusColor = (s) => (s === 'ready' ? GREEN : s === 'error' || s === 'failed' ? RED : AMBER);

function ExecutorMachineRow({ m, busy, onTest, onToggle, accent }) {
  const isExec = !!(m.executor && m.executor.enabled);
  return (
    <div style={{ border: '1px solid #1e2230', borderLeft: `2px solid ${isExec ? AMBER : statusColor(m.status)}`, borderRadius: 6, padding: '8px 10px', background: '#0a0c10', display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
      <span style={{ fontSize: 12, color: '#c8cfe0', fontFamily: FONTS.mono, fontWeight: 700 }}>{m.name}</span>
      <span style={{ fontSize: 9, color: statusColor(m.status), fontFamily: FONTS.mono, textTransform: 'uppercase' }}>{m.status}</span>
      <span style={{ fontSize: 10, color: '#808590', fontFamily: FONTS.mono }}>{m.access_address || '…'}</span>
      <Badge color={m.ssh_auth_type && m.ssh_auth_type !== 'platform_key' ? '#5b8af5' : '#606570'}>
        {m.ssh_auth_type === 'password' ? 'password' : m.ssh_auth_type === 'private_key' ? 'own key' : 'platform key'}
      </Badge>
      {m.project_name && <span style={{ fontSize: 9, color: '#5b8af5', fontFamily: FONTS.mono, background: '#5b8af510', border: '1px solid #5b8af533', borderRadius: 4, padding: '1px 6px' }}>⛨ {m.project_name}</span>}
      {isExec && (
        <span title={`SSH executor · ${m.executor.scope === 'all' ? 'all projects' : 'bound project'}`} style={{ fontSize: 9, color: AMBER, fontFamily: FONTS.mono, background: AMBER + '10', border: `1px solid ${AMBER}44`, borderRadius: 4, padding: '1px 6px' }}>
          ⟴ executor{m.executor.scope === 'all' ? ' ·all' : ''}
        </span>
      )}
      <span style={{ flex: 1 }} />
      <button disabled={busy} onClick={() => onTest(m.id)} style={btn('#5b8af5', busy)}>Test</button>
      <button disabled={busy || m.status !== 'ready'} onClick={() => onToggle(m)} style={btn(isExec ? RED : AMBER, busy || m.status !== 'ready')}>
        {isExec ? 'Executor ✕' : 'Executor'}
      </button>
    </div>
  );
}
ExecutorMachineRow.propTypes = {
  m: PropTypes.object, busy: PropTypes.bool, onTest: PropTypes.func, onToggle: PropTypes.func, accent: PropTypes.string,
};

export default function ConnectionsView({ accent = '#15bbb1', currentUser }) {
  const [moduleEnabled, setModuleEnabled] = useState(true);
  const [machines, setMachines] = useState([]);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState(null);

  const load = useCallback(async () => {
    try {
      const [mods, pool] = await Promise.all([
        api.adminListModules().catch(() => []),
        api.listPoolMachines().catch(() => []),
      ]);
      const atk = (Array.isArray(mods) ? mods : []).find((x) => x && x.name === 'attacker_ssh');
      setModuleEnabled(atk ? !!atk.enabled : true);
      setMachines(Array.isArray(pool) ? pool : []);
    } catch (e) {
      setMsg({ ok: false, text: e.message || 'Failed to load connections data' });
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  // Executor machines transition outside this view (provisioning in the
  // Workstations tab, probes elsewhere) — poll so toggles/statuses settle
  // without a manual refresh. Faster while something is in flight.
  const hasTransitional = machines.some(m => ['planned', 'provisioning', 'restarting', 'queued', 'deploying', 'starting', 'tearing_down'].includes(m.status));
  useEffect(() => {
    const timer = setInterval(() => { load(); }, hasTransitional ? 3000 : 12000);
    return () => clearInterval(timer);
  }, [hasTransitional, load]);

  const testMachine = async (wsId) => {
    setBusy(true);
    try {
      await api.testPoolMachine(wsId);
      toastSuccess('Probe OK — machine reachable, credentials valid');
      await load();
    } catch (e) { toastError(e.message || 'Probe failed'); } finally { setBusy(false); }
  };

  const toggleExecutor = async (m) => {
    const enabled = !(m.executor && m.executor.enabled);
    const nextScope = enabled
      ? ((m.executor && m.executor.scope) || (m.project_id ? 'project' : 'all'))
      : 'project';
    setBusy(true);
    try {
      await api.setWsExecutor(m.id, { enabled, scope: nextScope });
      toastSuccess(enabled
        ? `SSH executor ON (${nextScope === 'all' ? 'all projects' : 'bound project'}) — machine is now a scan/exec target`
        : 'SSH executor OFF');
      await load();
    } catch (e) { toastError(e.message || 'Failed to toggle executor'); } finally { setBusy(false); }
  };

  return (
    <div style={{ flex: 1, overflowY: 'auto', padding: 18, maxWidth: 1280, width: '100%', margin: '0 auto' }}>
      <PageTitle accent={accent}>Connections</PageTitle>
      <div style={{ fontSize: 11, color: PALETTE.textFaint, fontFamily: FONTS.mono, marginBottom: 16 }}>
        How the platform connects outward — SSH executor targets, egress proxies, executor workstations and provider credentials.
      </div>

      {msg && (
        <div style={{ fontSize: 11, fontFamily: FONTS.mono, color: msg.ok ? GREEN : RED, background: (msg.ok ? GREEN : RED) + '10', border: `1px solid ${(msg.ok ? GREEN : RED)}44`, borderRadius: 4, padding: '6px 8px', marginBottom: 12 }}>
          {msg.ok ? '✓ ' : '✗ '}{msg.text}
        </div>
      )}

      <AttackerSSHPanel accent={accent} enabled={moduleEnabled} />

      <div style={{ marginTop: 18 }}>
        <SectionTitle accent={accent}>Egress proxies</SectionTitle>
        <div style={{ fontSize: 10, color: PALETTE.textFaint, fontFamily: FONTS.mono, margin: '4px 0 10px' }}>
          Where the platform's own outbound traffic goes — proxy pool + routing rules + outbound floor.
        </div>
        <EgressProxyPanel accent={accent} />
      </div>

      <div style={{ marginTop: 18 }}>
        <SectionTitle accent={accent}>Executor machines (workstations)</SectionTitle>
        <div style={{ fontSize: 10, color: PALETTE.textFaint, fontFamily: FONTS.mono, margin: '4px 0 10px' }}>
          Pool / imported machines flagged as executors — they appear to projects as ready SSH-executor targets (id <span style={{ color: PALETTE.textDim }}>ws:…</span>).
          Import &amp; provision machines in <span style={{ color: PALETTE.textDim }}>Infra → Workstations</span>.
        </div>
        <Card>
          {machines.length === 0 && (
            <div style={{ color: PALETTE.textFaint, fontSize: 11, fontFamily: FONTS.mono }}>
              No pool machines yet — provision or import one in Workstations, then flip Executor here.
            </div>
          )}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {machines.map((m) => (
              <ExecutorMachineRow key={m.id} m={m} busy={busy} onTest={testMachine} onToggle={toggleExecutor} accent={accent} />
            ))}
          </div>
        </Card>
      </div>

      <div style={{ marginTop: 18 }}>
        <SectionTitle accent={accent}>Provider credentials</SectionTitle>
        <div style={{ fontSize: 10, color: PALETTE.textFaint, fontFamily: FONTS.mono, margin: '4px 0 10px' }}>
          Ways the platform connects to provisioners (cloud APIs, hypervisors, Docker/k8s, SSH hosts) are managed in
          <span style={{ color: PALETTE.textDim }}> Platform Ops → Providers</span>.
        </div>
        <Card>
          <Overline>Platform Ops → Providers</Overline>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 6 }}>
            <span style={{ fontSize: 11, color: PALETTE.textDim, fontFamily: FONTS.mono }}>Cloud / hypervisor / container / SSH-host credentials, connectivity checks</span>
          </div>
        </Card>
      </div>
    </div>
  );
}
ConnectionsView.propTypes = { accent: PropTypes.string, currentUser: PropTypes.object };
