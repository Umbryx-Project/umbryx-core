import { useEffect, useState, useCallback } from 'react';
import { api } from '../api.js';
import { PALETTE, FONTS, Select, Checkbox } from './UI.jsx';
// null in Community Edition: nothing can be provisioned there, and the
// backend refuses the call (routers/workstations.py:30), so the form would
// exist only to be rejected. Registering a machine you already own stays.
import { EE_WORKSTATION_PROVISIONING } from '@ee';

/**
 * Workstation pool admin panel (2026-09-02 feature).
 * Pool machines provisioned via PlatformOps providers; binding a user's
 * profile SSH key to a machine = authorized_keys push (server-side);
 * revoke removes the key line. Per-user "my machines" view below.
 */
const AMBER = '#e0a820';
const GREEN = '#39d353';
const RED = '#cc2233';

const btn = (bg, disabled) => ({ background: disabled ? '#1a1d26' : bg + '18', border: `1px solid ${disabled ? '#2a2d35' : bg + '66'}`, color: disabled ? '#606570' : bg, borderRadius: 4, padding: '4px 10px', cursor: disabled ? 'default' : 'pointer', fontSize: 10, fontFamily: FONTS.mono, fontWeight: 700 });

export function PoolPanel() {
  const [machines, setMachines] = useState([]);
  const [providers, setProviders] = useState([]);
  const [users, setUsers] = useState([]);
  const [msg, setMsg] = useState(null);
  const [busy, setBusy] = useState(false);
  const [manualForm, setManualForm] = useState({ name: '', access_address: '', ssh_user: 'root', ssh_port: 22, auth_type: 'platform_key', auth_secret: '', make_executor: false });
  const [provForm, setProvForm] = useState({ name: '', infra_provider_id: '', size: '', image: '', location: '', node: '', project_id: '', make_executor: false });
  const [assignForm, setAssignForm] = useState(null); // { wsId, userId, keyId }
  const [deployUsers, setDeployUsers] = useState([]); // [{user_id, username, key_id, keys}]
  const [projects, setProjects] = useState([]);

  const load = useCallback(async () => {
    try {
      const [m, p, u, pr] = await Promise.all([
        api.listPoolMachines(),
        // GET /workstations/pool/providers answers 404 in a Community build —
        // provisioning is Enterprise (docs/modules/EDITIONS.md), and the
        // provider list only feeds the provisioning form this panel hides
        // there anyway. Without this catch the whole load() rejected and the
        // pool itself — a Community feature — never rendered.
        api.listPoolProviders().catch(() => []),
        api.adminListUsers(),
        api.getProjects().catch(() => []),
      ]);
      setMachines(m || []);
      setProviders(p || []);
      setUsers((u && (u.users || u)) || []);
      setProjects(pr || []);
    } catch (e) {
      setMsg({ ok: false, text: e.message || 'load failed' });
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  // Live statuses: pool machines transition (provisioning → ready, error
  // after a failed refresh…) outside this tab's actions — poll so button
  // effects show up without a manual page refresh. Faster while something
  // is actually in flight.
  const hasTransitional = machines.some(m => ['planned', 'provisioning', 'restarting', 'queued', 'deploying', 'starting', 'tearing_down'].includes(m.status));
  useEffect(() => {
    const timer = setInterval(() => { load(); }, hasTransitional ? 3000 : 10000);
    return () => clearInterval(timer);
  }, [hasTransitional, load]);

  const registerManual = async () => {
    if (!manualForm.name || !manualForm.access_address) return;
    if (manualForm.auth_type !== 'platform_key' && !manualForm.auth_secret) {
      setMsg({ ok: false, text: 'Paste the password / private key for this auth type' }); return;
    }
    setBusy(true);
    try {
      const r = await api.registerManualMachine({
        name: manualForm.name,
        access_address: manualForm.access_address,
        ssh_user: manualForm.ssh_user,
        ssh_port: manualForm.ssh_port,
        auth: { type: manualForm.auth_type, secret: manualForm.auth_secret },
        make_executor: manualForm.make_executor || undefined,
      });
      const st = r?.status;
      setManualForm({ name: '', access_address: '', ssh_user: 'root', ssh_port: 22, auth_type: 'platform_key', auth_secret: '', make_executor: false });
      setMsg(st === 'ready'
        ? { ok: true, text: 'Machine registered — SSH probe OK' + (r?.executor?.enabled ? ' · executor ON' : '') }
        : { ok: false, text: `Registered but probe failed: ${r?.error || st}` });
      await load();
    } catch (e) { setMsg({ ok: false, text: e.message }); } finally { setBusy(false); }
  };

  const testMachine = async (wsId) => {
    setBusy(true);
    try {
      await api.testPoolMachine(wsId);
      setMsg({ ok: true, text: 'Probe OK — machine reachable, credentials valid' });
      await load();
    } catch (e) { setMsg({ ok: false, text: e.message }); } finally { setBusy(false); }
  };

  const toggleExecutor = async (m) => {
    const enabled = !(m.executor && m.executor.enabled);
    const nextScope = enabled
      ? ((m.executor && m.executor.scope) || (m.project_id ? 'project' : 'all'))
      : 'project';
    setBusy(true);
    try {
      await api.setWsExecutor(m.id, { enabled, scope: nextScope });
      setMsg({ ok: true, text: enabled ? `SSH executor ON (${nextScope === 'all' ? 'all projects' : 'this project'}) — machine is now a scan/exec target` : 'SSH executor OFF' });
      await load();
    } catch (e) { setMsg({ ok: false, text: e.message }); } finally { setBusy(false); }
  };

  const provisionNew = async () => {
    if (!provForm.name || !provForm.infra_provider_id) return;
    const noKey = deployUsers.find(d => !d.key_id);
    if (noKey) { setMsg({ ok: false, text: `User ${noKey.username} has no SSH key on profile` }); return; }
    setBusy(true);
    try {
      const r = await api.createPoolMachine({
        ...provForm,
        project_id: provForm.project_id || undefined,
        assign_users: deployUsers.map(d => ({ user_id: d.user_id, key_id: d.key_id })),
      });
      const grants = r?.grants;
      const gtxt = Array.isArray(grants)
        ? ' · ' + grants.map(g => `${(users.find(u => u.id === g.user_id)?.username) || g.user_id}: ${g.ok ? 'granted' : 'FAILED (' + (g.error || '?') + ')'}`).join(', ')
        : '';
      setProvForm({ name: '', infra_provider_id: '', size: '', image: '', location: '', node: '', project_id: '', make_executor: false });
      setDeployUsers([]);
      setMsg({ ok: true, text: 'Provisioning done' + gtxt });
      await load();
    } catch (e) { setMsg({ ok: false, text: e.message }); } finally { setBusy(false); }
  };

  const addDeployUser = async (userId) => {
    if (!userId || deployUsers.some(d => d.user_id === userId)) return;
    const u = users.find(x => x.id === userId);
    let keys = [];
    try { keys = (await api.userSshKeys(userId)) || []; } catch { keys = []; }
    setDeployUsers(lst => [...lst, { user_id: userId, username: u?.username || userId, key_id: (keys[0] || {}).id || '', keys }]);
  };

  const setDeployUserKey = (userId, keyId) => {
    setDeployUsers(lst => lst.map(d => (d.user_id === userId ? { ...d, key_id: keyId } : d)));
  };

  const removeDeployUser = (userId) => {
    setDeployUsers(lst => lst.filter(d => d.user_id !== userId));
  };

  const startAssign = async (wsId, userId) => {
    if (!userId) return;
    try {
      const keys = await api.userSshKeys(userId);
      setAssignForm({ wsId, userId, keyId: (keys[0] || {}).id || '', keys });
    } catch (e) { setMsg({ ok: false, text: e.message }); }
  };

  const doAssign = async () => {
    if (!assignForm?.keyId) return;
    setBusy(true);
    try {
      await api.assignPoolMachine(assignForm.wsId, { user_id: assignForm.userId, key_id: assignForm.keyId });
      setAssignForm(null);
      setMsg({ ok: true, text: 'Access granted (key installed)' });
      await load();
    } catch (e) { setMsg({ ok: false, text: e.message }); } finally { setBusy(false); }
  };

  const doBind = async (wsId, projectId) => {
    setBusy(true);
    try {
      await api.bindPoolMachine(wsId, { project_id: projectId || null });
      setMsg({ ok: true, text: projectId ? 'Machine bound to project' : 'Machine unbound from project' });
      await load();
    } catch (e) { setMsg({ ok: false, text: e.message }); } finally { setBusy(false); }
  };

  const doRevoke = async (wsId, userId) => {
    setBusy(true);
    try {
      await api.revokePoolMachine(wsId, { user_id: userId });
      setMsg({ ok: true, text: 'Access revoked (key removed)' });
      await load();
    } catch (e) { setMsg({ ok: false, text: e.message }); } finally { setBusy(false); }
  };

  const statusColor = (s) => (s === 'ready' ? GREEN : s === 'failed' ? RED : AMBER);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      {msg && (
        <div style={{ fontSize: 11, fontFamily: FONTS.mono, color: msg.ok ? GREEN : RED, background: (msg.ok ? GREEN : RED) + '10', border: `1px solid ${(msg.ok ? GREEN : RED)}44`, borderRadius: 4, padding: '6px 8px' }}>{msg.ok ? '✓ ' : '✗ '}{msg.text}</div>
      )}

      {EE_WORKSTATION_PROVISIONING && (
        <div style={{ border: '1px solid #1e2230', borderRadius: 6, padding: 10, background: PALETTE.bg3 }}>
          <div style={{ fontSize: 10, color: '#808590', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 6 }}>Provision new machine (PlatformOps provider)</div>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 6 }}>
            <input value={provForm.name} onChange={e => setProvForm(f => ({ ...f, name: e.target.value }))} placeholder="name" style={{ flex: '1 1 110px', background: '#0a0c10', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 8px', color: '#c8cfe0', fontSize: 11, fontFamily: FONTS.mono }} />
            <Select value={provForm.infra_provider_id} onChange={v => setProvForm(f => ({ ...f, infra_provider_id: v }))} style={{ flex: '1 1 150px' }}
              placeholder="provider…"
              options={providers.map(p => ({ value: p.id, label: `${p.name} (${p.type})` }))} />
            <input value={provForm.size} onChange={e => setProvForm(f => ({ ...f, size: e.target.value }))} placeholder="size/plan" style={{ width: 100, background: '#0a0c10', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 8px', color: '#c8cfe0', fontSize: 11, fontFamily: FONTS.mono }} />
            <input value={provForm.image} onChange={e => setProvForm(f => ({ ...f, image: e.target.value }))} placeholder="image / template" style={{ width: 140, background: '#0a0c10', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 8px', color: '#c8cfe0', fontSize: 11, fontFamily: FONTS.mono }} />
            <input value={provForm.location} onChange={e => setProvForm(f => ({ ...f, location: e.target.value }))} placeholder="location" style={{ width: 90, background: '#0a0c10', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 8px', color: '#c8cfe0', fontSize: 11, fontFamily: FONTS.mono }} />
            <input value={provForm.node} onChange={e => setProvForm(f => ({ ...f, node: e.target.value }))} placeholder="node (pve)" style={{ width: 90, background: '#0a0c10', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 8px', color: '#c8cfe0', fontSize: 11, fontFamily: FONTS.mono }} />
            <Select value={provForm.project_id} onChange={v => setProvForm(f => ({ ...f, project_id: v }))} style={{ flex: '1 1 130px' }}
              placeholder="project (optional)…"
              options={projects.map(pr => ({ value: pr.id, label: pr.name }))} />
            <button disabled={busy || !provForm.name || !provForm.infra_provider_id} onClick={provisionNew} style={btn(GREEN, busy || !provForm.name || !provForm.infra_provider_id)}>Provision</button>
          </div>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center', marginBottom: 4 }}>
            <Select value="" onChange={addDeployUser}
              placeholder="+ grant access at deploy…"
              options={users.filter(u => !deployUsers.some(d => d.user_id === u.id)).map(u => ({ value: u.id, label: u.username }))} />
            {deployUsers.map(d => (
              <span key={d.user_id} style={{ display: 'inline-flex', alignItems: 'center', gap: 4, border: '1px solid #39d35344', borderRadius: 4, padding: '2px 6px', background: '#0a0c10', fontSize: 10, fontFamily: FONTS.mono }}>
                <span style={{ color: PALETTE.ok }}>🔑 {d.username}</span>
                {d.keys.length > 1 ? (
                  <Select value={d.key_id} onChange={v => setDeployUserKey(d.user_id, v)}
                    options={d.keys.map(k => ({ value: k.id, label: k.name || k.id }))} />
                ) : (
                  <span style={{ color: d.key_id ? '#606570' : PALETTE.danger, fontSize: 9 }}>{d.key_id ? (d.keys[0]?.name || 'key') : 'no key on profile'}</span>
                )}
                <button onClick={() => removeDeployUser(d.user_id)} style={{ background: 'none', border: 'none', color: '#808590', cursor: 'pointer', padding: 0, fontSize: 10 }}>✕</button>
              </span>
            ))}
          </div>
          <div style={{ display: 'flex', gap: 10, alignItems: 'center', marginBottom: 4, flexWrap: 'wrap' }}>
            <Checkbox checked={!!provForm.make_executor} onChange={v => setProvForm(f => ({ ...f, make_executor: v }))} accent={GREEN}
              label="make SSH executor (image needs tools — e.g. umbryx/pool-ssh-tools)" />
          </div>
          <div style={{ fontSize: 9, color: PALETTE.textFaint, fontFamily: FONTS.mono }}>hetzner: cloud VM · proxmox: terraform clone (image = template id) · docker/k8s: pool-ssh container/pod · keys are installed once the machine is ready</div>
        </div>
      )}

      <div style={{ border: '1px solid #1e2230', borderRadius: 6, padding: 10, background: PALETTE.bg3 }}>
        <div style={{ fontSize: 10, color: '#808590', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 6 }}>Register existing machine (pool)</div>
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          <input value={manualForm.name} onChange={e => setManualForm(f => ({ ...f, name: e.target.value }))} placeholder="name" style={{ flex: '1 1 120px', background: '#0a0c10', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 8px', color: '#c8cfe0', fontSize: 11, fontFamily: FONTS.mono }} />
          <input value={manualForm.access_address} onChange={e => setManualForm(f => ({ ...f, access_address: e.target.value }))} placeholder="host / ip" style={{ flex: '1 1 140px', background: '#0a0c10', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 8px', color: '#c8cfe0', fontSize: 11, fontFamily: FONTS.mono }} />
          <input value={manualForm.ssh_user} onChange={e => setManualForm(f => ({ ...f, ssh_user: e.target.value }))} placeholder="ssh user" style={{ width: 90, background: '#0a0c10', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 8px', color: '#c8cfe0', fontSize: 11, fontFamily: FONTS.mono }} />
          <input value={manualForm.ssh_port} onChange={e => setManualForm(f => ({ ...f, ssh_port: e.target.value }))} placeholder="port" type="number" style={{ width: 60, background: '#0a0c10', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 8px', color: '#c8cfe0', fontSize: 11, fontFamily: FONTS.mono }} />
          <Select value={manualForm.auth_type} onChange={v => setManualForm(f => ({ ...f, auth_type: v }))} style={{ width: 150 }}
            placeholder="auth…"
            options={[
              { value: 'platform_key', label: 'platform key' },
              { value: 'password', label: 'password' },
              { value: 'private_key', label: 'private key' },
            ]} />
        </div>
        {manualForm.auth_type !== 'platform_key' && (
          <textarea value={manualForm.auth_secret} onChange={e => setManualForm(f => ({ ...f, auth_secret: e.target.value }))} placeholder={manualForm.auth_type === 'password' ? 'ssh password' : '-----BEGIN OPENSSH PRIVATE KEY----- …'}
            style={{ width: '100%', marginTop: 6, minHeight: 54, resize: 'vertical', background: '#0a0c10', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 8px', color: '#c8cfe0', fontSize: 10, fontFamily: FONTS.mono }} />
        )}
        <div style={{ display: 'flex', gap: 10, alignItems: 'center', marginTop: 6, flexWrap: 'wrap' }}>
          <Checkbox checked={!!manualForm.make_executor} onChange={v => setManualForm(f => ({ ...f, make_executor: v }))} accent={GREEN}
            label="make SSH executor (scans/exec run from this machine)" />
          <button disabled={busy || !manualForm.name || !manualForm.access_address} onClick={registerManual} style={btn(GREEN, busy || !manualForm.name || !manualForm.access_address)}>Register</button>
        </div>
        <div style={{ fontSize: 9, color: PALETTE.textFaint, marginTop: 4, fontFamily: FONTS.mono }}>
          platform key = machine already has the platform pubkey · password/private key stored encrypted, used for grants + executor · probe runs at registration
        </div>
      </div>

      {assignForm && (
        <div style={{ border: `1px solid ${AMBER}44`, borderRadius: 6, padding: 10, background: PALETTE.bg3 }}>
          <div style={{ fontSize: 10, color: AMBER, marginBottom: 6, fontFamily: FONTS.mono }}>GRANT ACCESS — pick the user key to install</div>
          <Select value={assignForm.keyId} onChange={v => setAssignForm(f => ({ ...f, keyId: v }))} style={{ width: '100%' }}
            options={(assignForm.keys || []).length > 0
              ? assignForm.keys.map(k => ({ value: k.id, label: `${k.name || k.id} — ${k.fingerprint?.slice(0, 24) || k.public_key.slice(0, 32)}` }))
              : [{ value: '', label: 'no keys on this user profile' }]} />
          <div style={{ display: 'flex', gap: 6, marginTop: 8 }}>
            <button disabled={busy || !assignForm.keyId} onClick={doAssign} style={btn(GREEN, busy || !assignForm.keyId)}>Grant</button>
            <button onClick={() => setAssignForm(null)} style={btn('#6a7080', false)}>Cancel</button>
          </div>
        </div>
      )}

      {machines.length === 0 && <div style={{ color: PALETTE.textFaint, fontSize: 11, fontFamily: FONTS.mono }}>No pool machines yet.</div>}
      {machines.map(m => (
        <div key={m.id} style={{ border: '1px solid #1e2230', borderLeft: `2px solid ${statusColor(m.status)}`, borderRadius: 6, padding: '8px 10px', background: '#0a0c10' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <span style={{ fontSize: 12, color: '#c8cfe0', fontFamily: FONTS.mono, fontWeight: 700 }}>{m.name}</span>
            <span style={{ fontSize: 9, color: statusColor(m.status), fontFamily: FONTS.mono, textTransform: 'uppercase' }}>{m.status}</span>
            {m.infra_provider_name && <span style={{ fontSize: 9, color: '#5b8af5', fontFamily: FONTS.mono }}>{m.infra_provider_name}</span>}
            <span style={{ fontSize: 10, color: '#808590', fontFamily: FONTS.mono, flex: 1 }}>{m.access_address || '…'}</span>
            {m.project_name && (
              <span style={{ fontSize: 9, color: '#5b8af5', fontFamily: FONTS.mono, background: '#5b8af510', border: '1px solid #5b8af533', borderRadius: 4, padding: '1px 6px' }}>
                ⛨ {m.project_name}
              </span>
            )}
            {m.executor && m.executor.enabled && (
              <span title={`SSH executor · ${m.executor.scope === 'all' ? 'all projects' : 'bound project'}`} style={{ fontSize: 9, color: AMBER, fontFamily: FONTS.mono, background: AMBER + '10', border: `1px solid ${AMBER}44`, borderRadius: 4, padding: '1px 6px' }}>
                ⟴ executor{m.executor.scope === 'all' ? ' ·all' : ''}
              </span>
            )}
            <button disabled={busy} onClick={() => testMachine(m.id)} style={btn('#5b8af5', busy)}>Test</button>
            <button disabled={busy || m.status !== 'ready'} onClick={() => toggleExecutor(m)} style={btn(m.executor && m.executor.enabled ? RED : AMBER, busy || m.status !== 'ready')}>
              {m.executor && m.executor.enabled ? 'Executor ✕' : 'Executor'}
            </button>
          </div>
          <div style={{ marginTop: 4 }}>
            <Select value={m.project_id || ''} onChange={v => doBind(m.id, v)} disabled={busy}
              style={{ color: m.project_id ? '#5b8af5' : '#808590' }}
              placeholder="project: not bound…"
              options={projects.map(pr => ({ value: pr.id, label: pr.name }))} />
          </div>
          {m.error && <div style={{ fontSize: 10, color: RED, fontFamily: FONTS.mono, marginTop: 4 }}>{m.error}</div>}
          <div style={{ marginTop: 6, display: 'flex', flexDirection: 'column', gap: 4 }}>
            {(m.accesses || []).map(a => {
              const u = users.find?.(x => x.id === a.user_id);
              return (
                <div key={a.id} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <span style={{ fontSize: 10, color: GREEN, fontFamily: FONTS.mono }}>🔑 {u?.username || a.user_id}</span>
                  <span style={{ fontSize: 9, color: PALETTE.textFaint, fontFamily: FONTS.mono }}>since {String(a.granted_at || '').slice(0, 16)}</span>
                  <button disabled={busy} onClick={() => doRevoke(m.id, a.user_id)} style={btn(AMBER, busy)}>Revoke</button>
                </div>
              );
            })}
          </div>
          <div style={{ marginTop: 6 }}>
            <Select value="" onChange={v => startAssign(m.id, v)}
              placeholder="+ grant access to…"
              options={users.filter(u => !(m.accesses || []).some(a => a.user_id === u.id)).map(u => ({ value: u.id, label: u.username }))} />
          </div>
        </div>
      ))}
    </div>
  );
}

PoolPanel.propTypes = {};

export function MyMachinesPanel() {
  const [machines, setMachines] = useState(null);
  useEffect(() => { api.myPoolMachines().then(setMachines).catch(() => setMachines([])); }, []);
  if (machines === null) return <div style={{ color: PALETTE.textFaint, fontSize: 11, fontFamily: FONTS.mono }}>Loading…</div>;
  if (!machines.length) return <div style={{ color: PALETTE.textFaint, fontSize: 11, fontFamily: FONTS.mono }}>No infrastructure access granted. Add an SSH key to your profile and ask an admin to grant access.</div>;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
      {machines.map(m => (
        <div key={m.access_id} style={{ border: '1px solid #1e2230', borderRadius: 6, padding: '8px 10px', background: '#0a0c10', display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          <span style={{ fontSize: 12, color: '#c8cfe0', fontFamily: FONTS.mono, fontWeight: 700 }}>{m.machine.name}</span>
          <span style={{ fontSize: 10, color: '#5b8af5', fontFamily: FONTS.mono }}>ssh {m.machine.access_address}</span>
          <span style={{ fontSize: 9, color: m.machine.status === 'ready' ? GREEN : AMBER, fontFamily: FONTS.mono, textTransform: 'uppercase' }}>{m.machine.status}</span>
          <span style={{ fontSize: 9, color: PALETTE.textFaint, fontFamily: FONTS.mono, flex: 1 }}>granted {String(m.granted_at || '').slice(0, 10)}</span>
        </div>
      ))}
    </div>
  );
}
