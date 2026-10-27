import { useState, useEffect, useCallback, useRef } from 'react';
import PropTypes from 'prop-types';
import { api } from '../api.js';
import { toastError, toastSuccess } from '../components/Toast.jsx';
import { PoolPanel } from '../components/PoolPanel.jsx';
import WorkstationActionsLog from './WorkstationActionsLog.jsx';
import { useProjectPermissions } from '../context/ProjectPermissions.jsx';
import { copyToClipboard } from '../utils/clipboard.js';
import {
  Btn, Modal, FieldInput, EmptyState, Badge, PageTitle, Overline,
  PALETTE, TYPE, FONTS, FeatureLock,
} from '../components/UI.jsx';
import { useEntitlement, FEATURE } from '../hooks/useEntitlement.js';
// null in Community Edition, where nothing can be provisioned: the request
// and template dialogs are not in the build, so the buttons that open them
// are not rendered either (docs/modules/EDITIONS.md). Community registers
// machines the operator already owns, through the pool tab.
import { EE_WORKSTATION_PROVISIONING } from '@ee';
import { PROVIDER_META } from '../constants.js';

const STATUS_COLORS = {
  ready: '#22c55e', provisioning: '#f09a3a', planned: '#808590',
  failed: '#cc2233', destroyed: '#404550', destroying: '#f0c040',
};

const WS_CATEGORIES = {
  kali:   { label: 'Kali Linux',    icon: '🐉', color: '#3b82f6' },
  linux:  { label: 'Linux',         icon: '🐧', color: '#22c55e' },
  windows:{ label: 'Windows',       icon: '🪟', color: '#f09a3a' },
  custom: { label: 'Custom',        icon: '📦', color: '#808590' },
};


const IMAGE_SOURCE_LABELS = {
  dockerhub: 'Docker Hub',
  mcr: 'MCR',
  ghcr: 'GHCR',
  custom: 'Custom',
};

const inpStyle = {
  background: PALETTE.bg3, border: `1px solid ${PALETTE.border}`, borderRadius: 4,
  padding: '6px 8px', color: PALETTE.textDim, fontSize: TYPE.body,
  fontFamily: FONTS.mono, outline: 'none', boxSizing: 'border-box',
};

export default function WorkstationsView({ selectedProject, accent, currentUser }) {
  const [workstations, setWorkstations] = useState([]);
  const [templates, setTemplates] = useState([]);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState('workstations');
  const provisioning = EE_WORKSTATION_PROVISIONING;
  const [showRequest, setShowRequest] = useState(false);
  const [showCreateTpl, setShowCreateTpl] = useState(false);
  const [expandedId, setExpandedId] = useState(null);
  const [events, setEvents] = useState({});
  const [confirmDestroyId, setConfirmDestroyId] = useState(null);
  const [confirmDeleteTplId, setConfirmDeleteTplId] = useState(null);
  const [editingWs, setEditingWs] = useState(null);
  const [confirmDeleteWsId, setConfirmDeleteWsId] = useState(null);
  const [confirmForceDeleteId, setConfirmForceDeleteId] = useState(null);
  const [confirmRestartId, setConfirmRestartId] = useState(null);

  const prevShowRequest = useRef(false);
  const prevShowCreateTpl = useRef(false);
  // Infra management is org-level, not project-level: platform admins and
  // org owner/admin/manager/team_lead get the pool regardless of the
  // selected project's membership role (2026-09-22).
  const { hasAnyOrgAdminRole } = useProjectPermissions();
  const isAdmin = currentUser?.role === 'platform_admin' || hasAnyOrgAdminRole;
  const { hasFeature, requiredTier } = useEntitlement();
  const wsLocked = !hasFeature(FEATURE.WORKSTATIONS);

  const load = useCallback(async () => {
    if (!selectedProject) return;
    setLoading(true);
    try {
      const [ws, tmpl] = await Promise.all([
        api.listWorkstations(selectedProject),
        api.listWsTemplates(selectedProject),
      ]);
      setWorkstations(Array.isArray(ws) ? ws : []);
      setTemplates(Array.isArray(tmpl) ? tmpl : []);
    } catch (e) { toastError(e.message); }
    setLoading(false);
  }, [selectedProject]);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    if (prevShowRequest.current && !showRequest) load();
    prevShowRequest.current = showRequest;
  }, [showRequest, load]);

  useEffect(() => {
    if (prevShowCreateTpl.current && !showCreateTpl) load();
    prevShowCreateTpl.current = showCreateTpl;
  }, [showCreateTpl, load]);

  const loadEvents = async (wsId) => {
    try {
      const evts = await api.listWsEvents(wsId);
      setEvents(prev => ({ ...prev, [wsId]: Array.isArray(evts) ? evts : [] }));
    } catch (e) { /* ignore */ }
  };

  useEffect(() => {
    const active = workstations.some(ws => ['planned', 'provisioning', 'restarting', 'queued', 'deploying', 'starting', 'tearing_down', 'destroying'].includes(ws.status));
    if (!active) return;
    const timer = setInterval(() => { load(); }, 3000);
    return () => clearInterval(timer);
  }, [workstations, load]);

  useEffect(() => {
    const activeIds = workstations.filter(ws => ['provisioning', 'destroying'].includes(ws.status)).map(ws => ws.id);
    if (activeIds.length === 0) return;
    const timer = setInterval(() => {
      activeIds.forEach(id => loadEvents(id));
    }, 4000);
    return () => clearInterval(timer);
  }, [workstations]);

  const handleProvision = async (id) => {
    try { await api.provisionWs(id); toastSuccess('Provisioning started'); load(); }
    catch (e) { toastError(e.message); }
  };

  const confirmDestroy = async () => {
    const id = confirmDestroyId;
    setConfirmDestroyId(null);
    try { await api.destroyWs(id); toastSuccess('Destroy initiated'); load(); }
    catch (e) { toastError(e.message); }
  };

  const handleDeleteTemplate = async (id) => {
    setConfirmDeleteTplId(null);
    try { await api.deleteWsTemplate(id); toastSuccess('Template deleted'); load(); }
    catch (e) { toastError(e.message); }
  };

  const handleDeleteWs = async () => {
    const id = confirmDeleteWsId;
    setConfirmDeleteWsId(null);
    try { await api.deleteWorkstation(id); toastSuccess('Workstation deleted'); load(); }
    catch (e) { toastError(e.message); }
  };

  const handleForceDeleteWs = async () => {
    const id = confirmForceDeleteId;
    setConfirmForceDeleteId(null);
    try { await api.forceDeleteWorkstation(id); toastSuccess('Workstation force-deleted'); load(); }
    catch (e) { toastError(e.message); }
  };

  const handleRestartWs = async () => {
    const id = confirmRestartId;
    setConfirmRestartId(null);
    try { await api.restartWorkstation(id); toastSuccess('Restart initiated'); load(); }
    catch (e) { toastError(e.message); }
  };

  const copySsh = (cmd) => { copyToClipboard(cmd).then(() => toastSuccess('Copied')).catch(() => toastError('Copy failed')); };

  if (!selectedProject) {
    // No project selected — infra admins still get the org-level pool;
    // everyone else is asked to pick a project first.
    return isAdmin ? (
      <div style={{ flex: 1, overflowY: 'auto', padding: 16 }}>
        <PageTitle icon="monitor" accent={accent} sub="organization infrastructure — not tied to a project">
          Workstation pool
        </PageTitle>
        <PoolPanel />
      </div>
    ) : (
      <EmptyState icon="monitor" title="Select a project" />
    );
  }

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px 16px', borderBottom: `1px solid ${PALETTE.borderSoft}`, flexShrink: 0 }}>
        <PageTitle icon="monitor" accent={accent} sub={`${workstations.length} workstations · ${templates.length} templates`}
          style={{ marginBottom: 0 }}>
          Workstations
        </PageTitle>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <div style={{ display: 'flex', gap: 2, background: PALETTE.bg2, border: `1px solid ${PALETTE.borderSoft}`, borderRadius: 5, padding: 2 }}>
            {[
              ['workstations', `${workstations.length} workstations`],
              ...(provisioning ? [['templates', `${templates.length} templates`]] : []),
              ...(isAdmin ? [['pool', 'pool & access']] : []),
            ].map(([id, label]) => (
              <button key={id} onClick={() => setTab(id)} style={{
                padding: '3px 10px', borderRadius: 3, border: 'none', cursor: 'pointer',
                background: tab === id ? '#1e2229' : 'transparent',
                color: tab === id ? PALETTE.textDim : PALETTE.textFaint,
                fontSize: TYPE.label, fontFamily: FONTS.mono,
              }}>{label}</button>
            ))}
          </div>
          {tab === 'workstations' && provisioning && (
            <FeatureLock locked={wsLocked} tier={requiredTier(FEATURE.WORKSTATIONS)}
              note="Operator workstations require the Team plan or higher.">
              <Btn variant="solid" accent={accent} disabled={wsLocked} onClick={() => setShowRequest(true)}>+ Request</Btn>
            </FeatureLock>
          )}
          {tab === 'templates' && isAdmin && provisioning && (
            <Btn variant="solid" accent={accent} onClick={() => setShowCreateTpl(true)}>+ Template</Btn>
          )}
        </div>
      </div>

      <div style={{ flex: 1, overflow: 'auto', padding: '8px 16px' }}>
        {loading && <div style={{ color: PALETTE.textGhost, fontFamily: FONTS.mono, fontSize: TYPE.body, padding: 20 }}>Loading...</div>}

        {!loading && tab === 'workstations' && (
          <>
            {workstations.length === 0 && (
              <EmptyState icon="monitor" title="No workstations" hint="Click Request to create one." />
            )}
            {workstations.map(ws => (
              <div key={ws.id} style={{ background: PALETTE.bg1, border: `1px solid ${PALETTE.borderSoft}`, borderRadius: 6, padding: '12px 14px', marginBottom: 8 }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{ width: 8, height: 8, borderRadius: '50%', background: STATUS_COLORS[ws.status] || '#808590', display: 'inline-block' }} />
                    <span style={{ fontSize: TYPE.body + 1, color: PALETTE.textDim, fontFamily: FONTS.mono, fontWeight: 600 }}>{ws.name}</span>
                    <Badge label={templates.find(t => t.id === ws.template_id)?.name || ws.template_id} color={PALETTE.textFaint} />
                    {ws.provider && ws.provider !== 'docker' && (
                      <Badge label={PROVIDER_META[ws.provider]?.label || ws.provider} color={PROVIDER_META[ws.provider]?.color || PALETTE.textMute} />
                    )}
                    {ws.meta?.custom_image && (
                      <Badge label={ws.meta.custom_image} color={PALETTE.textMute} />
                    )}
                    {ws.meta?.ssh_pub_key && (
                      <Badge label="SSH ✓" color={PALETTE.ok} />
                    )}
                  </div>
                  <div style={{ display: 'flex', gap: 6 }}>
                    {ws.status === 'planned' && provisioning && <Btn variant="accentGhost" accent={accent} onClick={() => handleProvision(ws.id)} style={{ fontSize: TYPE.label, padding: '2px 8px' }}>Provision</Btn>}
                    {ws.status === 'ready' && provisioning && <Btn variant="accentGhost" accent={accent} onClick={() => setConfirmRestartId(ws.id)} style={{ fontSize: TYPE.label, padding: '2px 8px' }}>Restart</Btn>}
                    {['ready', 'failed'].includes(ws.status) && <Btn variant="danger" onClick={() => setConfirmDestroyId(ws.id)} style={{ fontSize: TYPE.label, padding: '2px 8px' }}>Destroy</Btn>}
                    {['destroyed', 'planned', 'failed'].includes(ws.status) && isAdmin && <Btn variant="danger" onClick={() => setConfirmDeleteWsId(ws.id)} style={{ fontSize: TYPE.label, padding: '2px 8px' }}>Delete</Btn>}
                    {!['destroyed', 'planned', 'failed'].includes(ws.status) && isAdmin && <Btn variant="danger" onClick={() => setConfirmForceDeleteId(ws.id)} style={{ fontSize: TYPE.label, padding: '2px 8px' }}>Force Delete</Btn>}
                    <Btn variant="ghost" onClick={() => setEditingWs(ws)} style={{ fontSize: TYPE.label, padding: '2px 8px' }}>Edit</Btn>
                    <Btn variant="ghost" onClick={() => { setExpandedId(expandedId === ws.id ? null : ws.id); if (expandedId !== ws.id) loadEvents(ws.id); }} style={{ fontSize: TYPE.label, padding: '2px 8px' }}>
                      {expandedId === ws.id ? '▲' : '▼'}
                    </Btn>
                  </div>
                </div>
                {['provisioning', 'destroying'].includes(ws.status) && ws.step && (
                  <div style={{ marginTop: 6, display: 'flex', alignItems: 'center', gap: 6, background: PALETTE.bg2, borderRadius: 4, padding: '5px 10px' }}>
                    <span style={{ width: 6, height: 6, borderRadius: '50%', background: PALETTE.warn, display: 'inline-block', animation: 'pulse 1.5s infinite' }} />
                    <span style={{ fontSize: TYPE.label, color: PALETTE.warn, fontFamily: FONTS.mono }}>{ws.step.replace(/_/g, ' ')}</span>
                  </div>
                )}
                {ws.ssh_command && (
                  <div style={{ marginTop: 8, display: 'flex', alignItems: 'center', gap: 6, background: PALETTE.bg2, borderRadius: 4, padding: '6px 10px' }}>
                    <span style={{ fontSize: TYPE.label, color: PALETTE.textMute, fontFamily: FONTS.mono, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{ws.ssh_command}</span>
                    <Btn variant="accentGhost" accent={accent} onClick={() => copySsh(ws.ssh_command)} style={{ fontSize: TYPE.label, padding: '2px 6px' }}>Copy</Btn>
                  </div>
                )}
                {expandedId === ws.id && (
                  <div style={{ marginTop: 8, padding: '8px 10px', background: PALETTE.bg2, borderRadius: 4, fontSize: TYPE.label, color: PALETTE.textMute, fontFamily: FONTS.mono }}>
                    <div style={{ marginBottom: 3 }}>Status: <span style={{ color: STATUS_COLORS[ws.status] || PALETTE.textDim }}>{ws.status}</span></div>
                    {ws.provider && ws.provider !== 'docker' && <div style={{ marginBottom: 3 }}>Provider: <span style={{ color: PROVIDER_META[ws.provider]?.color || PALETTE.textDim }}>{PROVIDER_META[ws.provider]?.label || ws.provider}</span></div>}
                    {ws.meta?.cloud_ip && <div style={{ marginBottom: 3 }}>IP: <span style={{ color: PALETTE.textDim }}>{ws.meta.cloud_ip}</span></div>}
                    {ws.created_at && <div style={{ marginBottom: 3 }}>Created: {ws.created_at}</div>}
                    {ws.ready_at && <div style={{ marginBottom: 3 }}>Ready: {ws.ready_at}</div>}
                    {ws.meta?.error && <div style={{ color: PALETTE.danger, marginBottom: 3 }}>Error: {ws.meta.error}</div>}
                    {ws.meta?.image && <div style={{ marginBottom: 3 }}>Image: <span style={{ color: PALETTE.textDim }}>{ws.meta.image}</span></div>}
                    <div style={{ marginTop: 6, maxHeight: 140, overflow: 'auto' }}>
                      {(events[ws.id] || []).length === 0 && <div style={{ color: PALETTE.textGhost }}>No events</div>}
                      {(events[ws.id] || []).map((ev, i) => (
                        <div key={i} style={{ padding: '2px 0', borderBottom: `1px solid ${PALETTE.borderSoft}` }}>
                          <span style={{ color: PALETTE.textFaint }}>{ev.created_at || ''}</span> {ev.event_type}: {ev.message || ''}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </>
        )}

        {tab === 'pool' && isAdmin && (
          <>
            <PoolPanel />
            <div style={{ height: 18 }} />
            {/* Who ran what on which machine. It used to be reachable only
                from the Enterprise-only Infrastructure page, so a Community
                install could not see it at all — see WorkstationActionsLog. */}
            <WorkstationActionsLog />
          </>
        )}

        {!loading && tab === 'templates' && provisioning && (
          <>
            {templates.length === 0 && (
              <EmptyState icon="list" title="No templates" />
            )}
            {(() => {
              const groups = {};
              templates.forEach(t => {
                const cat = t.category || 'custom';
                if (!groups[cat]) groups[cat] = [];
                groups[cat].push(t);
              });
              const catOrder = ['kali', 'linux', 'windows', 'custom'];
              return catOrder.filter(c => groups[c]).map(cat => (
                <div key={cat} style={{ marginBottom: 16 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8, paddingBottom: 4, borderBottom: `1px solid ${(WS_CATEGORIES[cat]?.color || PALETTE.textGhost)}33` }}>
                    <span style={{ fontSize: TYPE.body }}>{WS_CATEGORIES[cat]?.icon || '📦'}</span>
                    <span style={{ fontSize: TYPE.body, fontWeight: 700, color: WS_CATEGORIES[cat]?.color || PALETTE.textMute, fontFamily: FONTS.mono }}>{WS_CATEGORIES[cat]?.label || cat}</span>
                    <span style={{ fontSize: TYPE.label, color: PALETTE.textGhost, fontFamily: FONTS.mono }}>({groups[cat].length})</span>
                  </div>
                  {groups[cat].map(t => (
                    <div key={t.id} style={{ background: PALETTE.bg1, border: `1px solid ${PALETTE.borderSoft}`, borderRadius: 6, padding: '12px 14px', marginBottom: 6 }}>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <span style={{ fontSize: TYPE.body + 1, color: PALETTE.textDim, fontFamily: FONTS.mono, fontWeight: 600 }}>{t.name}</span>
                          {t.spec?.image_source && t.spec.image_source !== 'dockerhub' && (
                            <Badge label={IMAGE_SOURCE_LABELS[t.spec.image_source] || t.spec.image_source} color={PALETTE.textFaint} />
                          )}
                          {t.is_builtin && (
                            <Badge label="builtin" color={PALETTE.textFaint} />
                          )}
                        </div>
                        {isAdmin && !t.is_builtin && (
                          <Btn variant="danger" onClick={() => setConfirmDeleteTplId(t.id)} style={{ fontSize: TYPE.label, padding: '2px 8px' }}>Delete</Btn>
                        )}
                      </div>
                      {t.spec?.image && <div style={{ marginTop: 4, fontSize: TYPE.label, color: PALETTE.textFaint, fontFamily: FONTS.mono }}>Image: {t.spec.image}</div>}
                      <div style={{ marginTop: 4, display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                        {(t.spec?.ports || []).map((p, i) => (
                          <Badge key={`p${i}`} label={p} color={accent} />
                        ))}
                        {(t.spec?.tools || []).map((tool, i) => (
                          <Badge key={`t${i}`} label={tool} color={PALETTE.textMute} />
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              ));
            })()}
          </>
        )}
      </div>

      {showRequest && provisioning && (
        <provisioning.RequestModal accent={accent} templates={templates} selectedProject={selectedProject} onClose={() => setShowRequest(false)} />
      )}
      {showCreateTpl && provisioning && (
        <provisioning.CreateTemplateModal accent={accent} onClose={() => setShowCreateTpl(false)} />
      )}
      {confirmDestroyId && (
        <Modal title="Confirm Destroy" accent={PALETTE.danger} onClose={() => setConfirmDestroyId(null)}
          footer={<>
            <Btn variant="ghost" onClick={() => setConfirmDestroyId(null)}>Cancel</Btn>
            <Btn variant="primary" onClick={confirmDestroy}>Destroy</Btn>
          </>}>
          <div style={{ fontSize: TYPE.body, color: PALETTE.textMute, fontFamily: FONTS.mono, lineHeight: 1.5 }}>
            Destroy this workstation? All container data will be lost.
          </div>
        </Modal>
      )}
      {confirmDeleteTplId && (
        <Modal title="Confirm Delete" accent={PALETTE.danger} onClose={() => setConfirmDeleteTplId(null)}
          footer={<>
            <Btn variant="ghost" onClick={() => setConfirmDeleteTplId(null)}>Cancel</Btn>
            <Btn variant="primary" onClick={() => handleDeleteTemplate(confirmDeleteTplId)}>Delete</Btn>
          </>}>
          <div style={{ fontSize: TYPE.body, color: PALETTE.textMute, fontFamily: FONTS.mono, lineHeight: 1.5 }}>
            Delete template "{templates.find(t => t.id === confirmDeleteTplId)?.name}"?
          </div>
        </Modal>
      )}
      {confirmDeleteWsId && (
        <Modal title="Delete Workstation" accent={PALETTE.danger} onClose={() => setConfirmDeleteWsId(null)}
          footer={<>
            <Btn variant="ghost" onClick={() => setConfirmDeleteWsId(null)}>Cancel</Btn>
            <Btn variant="primary" onClick={handleDeleteWs}>Delete</Btn>
          </>}>
          <div style={{ fontSize: TYPE.body, color: PALETTE.textMute, fontFamily: FONTS.mono, lineHeight: 1.5 }}>
            Permanently delete this workstation from the system? This cannot be undone.
          </div>
        </Modal>
      )}
      {confirmForceDeleteId && (
        <Modal title="Force Delete Workstation" accent={PALETTE.danger} onClose={() => setConfirmForceDeleteId(null)}
          footer={<>
            <Btn variant="ghost" onClick={() => setConfirmForceDeleteId(null)}>Cancel</Btn>
            <Btn variant="primary" onClick={handleForceDeleteWs}>Force Delete</Btn>
          </>}>
          <div style={{ fontSize: TYPE.body, color: PALETTE.textMute, fontFamily: FONTS.mono, lineHeight: 1.5 }}>
            Force delete this workstation? This will attempt cleanup and then remove all records. Cannot be undone.
          </div>
        </Modal>
      )}
      {confirmRestartId && (
        <Modal title="Restart Workstation" accent={PALETTE.warn} onClose={() => setConfirmRestartId(null)}
          footer={<>
            <Btn variant="ghost" onClick={() => setConfirmRestartId(null)}>Cancel</Btn>
            <Btn variant="primary" onClick={handleRestartWs}>Restart</Btn>
          </>}>
          <div style={{ fontSize: TYPE.body, color: PALETTE.textMute, fontFamily: FONTS.mono, lineHeight: 1.5 }}>
            Restart this workstation? It will be destroyed and re-provisioned. All container data will be lost.
          </div>
        </Modal>
      )}
      {editingWs && (
        <EditWorkstationModal ws={editingWs} accent={accent} isAdmin={isAdmin} onClose={() => { setEditingWs(null); load(); }} />
      )}
    </div>
  );
}


function EditWorkstationModal({ ws, accent, isAdmin, onClose }) {
  const isDocker = (ws.provider || 'docker') === 'docker';
  const [name, setName] = useState(ws.name || '');
  const [ports, setPorts] = useState(() => {
    const raw = ws.meta?.ports_override || ws.meta?.ports || [];
    return raw.map(p => ({ value: String(p) }));
  });
  const [customImage, setCustomImage] = useState(ws.meta?.custom_image || '');
  const [sshPubKey, setSshPubKey] = useState(ws.meta?.ssh_pub_key || '');
  const [namespace, setNamespace] = useState(ws.meta?.namespace || 'default');
  const [replicas, setReplicas] = useState(String(ws.meta?.replicas || '1'));
  const [loading, setLoading] = useState(false);

  const handleSave = async () => {
    setLoading(true);
    try {
      const patch = {};
      if (name.trim() && name !== ws.name) patch.name = name.trim();
      if (isDocker) {
        const newPorts = ports.filter(p => p.value.trim()).map(p => p.value.trim());
        const oldPorts = (ws.meta?.ports_override || ws.meta?.ports || []);
        if (JSON.stringify(newPorts) !== JSON.stringify(oldPorts)) patch.ports = newPorts;
      }
      if (customImage.trim() !== (ws.meta?.custom_image || '')) patch.custom_image = customImage.trim();
      if (sshPubKey.trim() !== (ws.meta?.ssh_pub_key || '')) patch.ssh_pub_key = sshPubKey.trim();
      if (!isDocker && namespace.trim() !== (ws.meta?.namespace || 'default')) patch.namespace = namespace.trim();
      if (isDocker && replicas !== String(ws.meta?.replicas || '1')) patch.replicas = parseInt(replicas) || 1;
      if (Object.keys(patch).length > 0) {
        await api.updateWorkstation(ws.id, patch);
        toastSuccess('Workstation updated');
      }
      onClose();
    } catch (e) { toastError(e.message); }
    setLoading(false);
  };

  const canSave = name.trim() && !loading;

  return (
    <Modal title={`Edit: ${ws.name}`} icon="edit" accent={accent} onClose={onClose}
      footer={<>
        <Btn variant="ghost" onClick={onClose}>Cancel</Btn>
        <Btn variant="solid" accent={accent} onClick={handleSave} disabled={!canSave}>
          {loading ? 'Saving...' : 'Save'}
        </Btn>
      </>}>

      <FieldInput label="Name" value={name} onChange={setName} placeholder="workstation-name" />

      {isDocker && (
        <div>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 5 }}>
            <Overline>Ports (host:container)</Overline>
            <Btn variant="accentGhost" accent={accent} onClick={() => setPorts(p => [...p, { value: '' }])} style={{ fontSize: TYPE.label, padding: '2px 8px' }}>+ Add</Btn>
          </div>
          {ports.length === 0 && <div style={{ fontSize: TYPE.label, color: PALETTE.textGhost, fontFamily: FONTS.mono }}>No ports configured</div>}
          {ports.map((p, i) => (
            <div key={i} style={{ display: 'flex', gap: 5, marginBottom: 4 }}>
              <input value={p.value} onChange={e => setPorts(ps => ps.map((x, idx) => idx === i ? { value: e.target.value } : x))} placeholder="2222:22" style={{ ...inpStyle, flex: 1 }} />
              <button onClick={() => setPorts(ps => ps.filter((_, idx) => idx !== i))} style={{ background: 'transparent', border: `1px solid ${PALETTE.danger}44`, borderRadius: 3, color: PALETTE.danger, cursor: 'pointer', padding: '0 8px', fontFamily: FONTS.mono, fontSize: 12 }}>×</button>
            </div>
          ))}
          <div style={{ marginTop: 4, fontSize: TYPE.label, color: PALETTE.textGhost, fontFamily: FONTS.mono }}>
            Changing ports requires Restart to take effect
          </div>
        </div>
      )}

      {!isDocker && (
        <div style={{ background: PALETTE.bg2, borderRadius: 4, padding: '8px 10px', fontSize: TYPE.label, color: PALETTE.textFaint, fontFamily: FONTS.mono }}>
          Ports are managed by {PROVIDER_META[ws.provider]?.label || ws.provider} provider and cannot be edited directly
        </div>
      )}

      <FieldInput label={isDocker ? 'Custom Image (optional)' : 'Custom Image'} value={customImage} onChange={setCustomImage} placeholder="registry.io/img:tag" />
      {customImage && <div style={{ marginTop: -4, fontSize: TYPE.label, color: PALETTE.textGhost, fontFamily: FONTS.mono }}>Image change requires Restart to take effect</div>}

      <FieldInput label="SSH Public Key" value={sshPubKey} onChange={setSshPubKey} placeholder="ssh-ed25519 AAAA... user@host" textarea />
      {sshPubKey && <div style={{ marginTop: -4, fontSize: TYPE.label, color: PALETTE.textGhost, fontFamily: FONTS.mono }}>SSH key change requires Restart to inject into container</div>}

      {isDocker && (
        <FieldInput label="Replicas" value={replicas} onChange={setReplicas} placeholder="1" />
      )}

      {!isDocker && ws.provider === 'kubernetes' && (
        <FieldInput label="Namespace" value={namespace} onChange={setNamespace} placeholder="default" />
      )}

      <div style={{ marginTop: 8, padding: '8px 10px', background: PALETTE.bg2, borderRadius: 4 }}>
        <div style={{ fontSize: TYPE.label, color: PALETTE.textFaint, fontFamily: FONTS.mono, marginBottom: 4 }}>Current status: <span style={{ color: STATUS_COLORS[ws.status] || PALETTE.textDim }}>{ws.status}</span></div>
        <div style={{ fontSize: TYPE.label, color: PALETTE.textFaint, fontFamily: FONTS.mono }}>Provider: {PROVIDER_META[ws.provider]?.label || ws.provider}</div>
        {ws.meta?.error && <div style={{ fontSize: TYPE.label, color: PALETTE.danger, fontFamily: FONTS.mono, marginTop: 4 }}>Error: {ws.meta.error}</div>}
      </div>
    </Modal>
  );
}

WorkstationsView.propTypes = { selectedProject: PropTypes.string, accent: PropTypes.string, currentUser: PropTypes.object };
EditWorkstationModal.propTypes = { ws: PropTypes.object.isRequired, accent: PropTypes.string, isAdmin: PropTypes.bool, onClose: PropTypes.func };
