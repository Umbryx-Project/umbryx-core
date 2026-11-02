import { useState, useEffect, useCallback } from 'react';
import PropTypes from 'prop-types';
import Icon from '../components/Icon.jsx';
import { api } from '../api.js';
import { useSync } from '../hooks/useSync.js';
import { useProjectPermissions } from '../context/ProjectPermissions.jsx';
import { toastError, toastSuccess } from '../components/Toast.jsx';
import { copyToClipboard } from '../utils/clipboard.js';

// Idempotent list merges — safe to apply the same add/remove twice (once
// from the actor's own refreshOrg() re-fetch after their action, once
// from the org-room WS echo of that same action, in whichever order they
// land) without ever producing a duplicate row.
function upsertMember(list, member) {
  const idx = list.findIndex(m => m.user_id === member.user_id);
  if (idx === -1) return [...list, member];
  const next = list.slice();
  next[idx] = { ...next[idx], ...member };
  return next;
}
function dropMember(list, userId) {
  return list.filter(m => m.user_id !== userId);
}
import {
  Btn, Modal, FieldInput, Select, EmptyState, Overline, Badge,
  PALETTE, TYPE, FONTS, Checkbox, FeatureLock } from '../components/UI.jsx';
import { useEntitlement, FEATURE } from '../hooks/useEntitlement.js';
import { uiConfirm } from '../components/Confirm.jsx';

const RC = {
  owner: '#f09a3a', admin: '#cc2233', manager: '#a855f7', team_lead: '#22d3ee',
  editor: '#5b8af5', operator: '#22c55e', analyst: '#eab308', reviewer: '#f97316',
  viewer: '#808590', observer: '#64748b', auditor: '#94a3b8',
};
const RL = {
  owner: 'Owner', admin: 'Admin', manager: 'Manager', team_lead: 'Team Lead',
  editor: 'Editor', operator: 'Operator', analyst: 'Analyst', reviewer: 'Reviewer',
  viewer: 'Viewer', observer: 'Observer', auditor: 'Auditor',
};
const RO = Object.keys(RL);

export default function OrganizationsView({ accent, currentUser }) {
  const { isOrgOwnerOrAdmin, isOrgAdminCapable } = useProjectPermissions();
  const { hasFeature, requiredTier } = useEntitlement();
  const [orgs, setOrgs] = useState([]);
  const [allUsers, setAllUsers] = useState([]);
  const [expandedOrg, setExpandedOrg] = useState(null);
  const [orgMembers, setOrgMembers] = useState({});
  const [orgTeams, setOrgTeams] = useState({});
  const [selectedTeam, setSelectedTeam] = useState(null);
  const [teamMembers, setTeamMembers] = useState({});
  const [loading, setLoading] = useState(true);
  const [showCreateOrg, setShowCreateOrg] = useState(false);
  const [showCreateTeam, setShowCreateTeam] = useState(null);
  const [showBulkAdd, setShowBulkAdd] = useState(null);
  const [bulkRole, setBulkRole] = useState('viewer');
  const [bulkDefaultRole, setBulkDefaultRole] = useState('viewer');
  const [bulkSelected, setBulkSelected] = useState(new Set());
  const [showCreateUser, setShowCreateUser] = useState(false);
  const [rightView, setRightView] = useState('members'); // 'members' | 'sso'

  const loadOrgs = useCallback(async () => {
    setLoading(true);
    try {
      // adminListUsers() is platform_admin-only — org-scoped
      // owner/admin/manager/team_lead can still see and manage their own
      // org here, they just don't get the "pick from every platform
      // user" bulk-add list (they can create new accounts directly via
      // "+ Create User" instead, which is scoped to their org).
      const o = await api.listOrganizations();
      setOrgs(o);
      if (currentUser?.role === 'platform_admin') {
        setAllUsers(await api.adminListUsers());
      } else {
        setAllUsers([]);
      }
    } catch (e) { toastError(e.message); }
    setLoading(false);
  }, [currentUser]);

  useEffect(() => { loadOrgs(); }, [loadOrgs]);

  const refreshOrg = useCallback(async (orgId) => {
    try {
      const [m, t] = await Promise.all([api.listOrgMembers(orgId), api.listOrgTeams(orgId)]);
      setOrgMembers(p => ({ ...p, [orgId]: m }));
      setOrgTeams(p => ({ ...p, [orgId]: t }));
    } catch (e) { toastError(e.message); }
  }, []);

  const refreshTeam = useCallback(async (orgId, teamId) => {
    try {
      const tm = await api.listTeamMembers(orgId, teamId);
      setTeamMembers(p => ({ ...p, [teamId]: tm }));
    } catch (e) { toastError(e.message); }
  }, []);

  // Live org-room subscription — only open while an org is actually
  // expanded (nothing to sync otherwise). Reuses the exact same
  // ConnectionManager/broadcast the project rooms use — see `org:` prefix
  // handling in main.py's /ws/{pid} — not a separate realtime mechanism.
  const handleOrgWsEvent = useCallback((msg) => {
    if (msg.entity !== 'org_member') return;
    const orgId = (msg.pid || '').slice('org:'.length);
    const data = msg.data || {};
    switch (msg.action) {
      case 'add':
      case 'role_change':
        setOrgMembers(p => ({ ...p, [orgId]: upsertMember(p[orgId] || [], data) }));
        break;
      case 'remove':
        setOrgMembers(p => ({ ...p, [orgId]: dropMember(p[orgId] || [], data.user_id) }));
        break;
      case 'team_add':
      case 'team_role_change':
        setTeamMembers(p => ({ ...p, [data.team_id]: upsertMember(p[data.team_id] || [], data) }));
        break;
      case 'team_remove':
        setTeamMembers(p => ({ ...p, [data.team_id]: dropMember(p[data.team_id] || [], data.user_id) }));
        break;
      default:
        break;
    }
  }, []);
  useSync(expandedOrg ? `org:${expandedOrg}` : null, currentUser?.username, handleOrgWsEvent, null);

  const toggleOrg = async (org) => {
    if (expandedOrg === org.id) { setExpandedOrg(null); setSelectedTeam(null); return; }
    setExpandedOrg(org.id);
    setSelectedTeam(null);
    setRightView('members');
    await refreshOrg(org.id);
  };

  const selectTeam = async (orgId, team) => {
    if (selectedTeam?.id === team.id) { setSelectedTeam(null); return; }
    setSelectedTeam({ ...team, orgId });
    setRightView('members');
    await refreshTeam(orgId, team.id);
  };

  const handleCreateOrg = async (data) => {
    try { await api.createOrganization(data); toastSuccess('Organization created'); setShowCreateOrg(false); await loadOrgs(); }
    catch (e) { toastError(e.message); }
  };

  const handleDeleteOrg = async (id) => {
    if (!await uiConfirm('Delete this organization?')) return;
    try { await api.deleteOrganization(id); toastSuccess('Deleted'); setExpandedOrg(null); setSelectedTeam(null); await loadOrgs(); }
    catch (e) { toastError(e.message); }
  };

  const handleCreateTeam = async (orgId, name) => {
    try { await api.createOrgTeam(orgId, { name }); toastSuccess('Team created'); setShowCreateTeam(null); await refreshOrg(orgId); }
    catch (e) { toastError(e.message); }
  };

  const handleDeleteTeam = async (orgId, teamId) => {
    try {
      await api.deleteOrgTeam(orgId, teamId); toastSuccess('Team deleted');
      if (selectedTeam?.id === teamId) setSelectedTeam(null);
      await refreshOrg(orgId);
    } catch (e) { toastError(e.message); }
  };

  const handleCreateOrgUser = async (orgId, data) => {
    try {
      await api.createOrgUser(orgId, data);
      toastSuccess('User created and added to organization');
      setShowCreateUser(false);
      await refreshOrg(orgId);
    } catch (e) { toastError(e.message); }
  };

  const handleRemoveOrgMember = async (orgId, uid) => {
    try { await api.removeOrgMember(orgId, uid); toastSuccess('Removed'); await refreshOrg(orgId); }
    catch (e) { toastError(e.message); }
  };

  const handleChangeOrgMemberRole = async (orgId, uid, role) => {
    try { await api.updateOrgMemberRole(orgId, uid, role); toastSuccess('Role updated'); await refreshOrg(orgId); }
    catch (e) { toastError(e.message); }
  };

  const handleRemoveTeamMember = async (orgId, teamId, uid) => {
    try { await api.removeTeamMember(orgId, teamId, uid); toastSuccess('Removed'); await refreshTeam(orgId, teamId); }
    catch (e) { toastError(e.message); }
  };

  const handleBulkAdd = async () => {
    if (bulkSelected.size === 0) return;
    const orgId = expandedOrg;
    const teamId = showBulkAdd;
    let ok = 0;
    for (const uid of bulkSelected) {
      try {
        const u = allUsers.find(x => x.id === uid);
        if (!u) continue;
        if (teamId) {
          await api.addTeamMember(orgId, teamId, { username: u.username, role: bulkRole, default_project_role: bulkDefaultRole });
        } else {
          await api.addOrgMember(orgId, { username: u.username, role: bulkRole });
        }
        ok++;
      } catch { /* counted by omission: ok++ runs only on success */ }
    }
    toastSuccess(`${ok} member${ok !== 1 ? 's' : ''} added`);
    setShowBulkAdd(null);
    setBulkSelected(new Set());
    if (teamId) { await refreshTeam(orgId, teamId); await refreshOrg(orgId); }
    else { await refreshOrg(orgId); }
  };

  const rightMembers = selectedTeam ? (teamMembers[selectedTeam.id] || []) : (orgMembers[expandedOrg] || []);
  const rightTitle = selectedTeam ? selectedTeam.name : (orgs.find(o => o.id === expandedOrg)?.name || '');

  const getAvailableUsers = () => {
    if (!expandedOrg) return [];
    const orgMs = orgMembers[expandedOrg] || [];
    const existingIds = new Set(orgMs.map(m => m.user_id));
    if (showBulkAdd) {
      const tms = teamMembers[showBulkAdd] || [];
      for (const m of tms) existingIds.add(m.user_id);
    }
    return allUsers.filter(u => !existingIds.has(u.id) && u.active);
  };

  return (
    <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>

      <div style={{ width: 320, flexShrink: 0, borderRight: `1px solid ${PALETTE.borderSoft}`, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px 16px', borderBottom: `1px solid ${PALETTE.borderSoft}`, flexShrink: 0 }}>
          <Overline color={PALETTE.textMute} style={{ fontSize: TYPE.sectionTitle, fontWeight: 700 }}>Organizations</Overline>
          {currentUser?.role === 'platform_admin' && (() => {
            const orgLocked = !hasFeature(FEATURE.MULTIPLE_ORGS) && orgs.length >= 1;
            return (
              <FeatureLock locked={orgLocked} tier={requiredTier(FEATURE.MULTIPLE_ORGS)}
                note="Running more than one organization requires the Pro plan or higher.">
                <Btn variant="accentGhost" accent={accent} disabled={orgLocked} onClick={() => setShowCreateOrg(true)}>+ New</Btn>
              </FeatureLock>
            );
          })()}
        </div>

        <div style={{ flex: 1, overflow: 'auto', padding: '4px 0' }}>
          {loading && <div style={{ color: PALETTE.textGhost, fontSize: TYPE.body + 1, fontFamily: FONTS.mono, padding: 16 }}>Loading...</div>}
          {!loading && orgs.length === 0 && <EmptyState icon="shield" title="No organizations yet" />}

          {orgs.map(org => {
            const isExp = expandedOrg === org.id;
            const teams = orgTeams[org.id] || [];
            const members = orgMembers[org.id] || [];
            return (
              <div key={org.id}>
                <div onClick={() => toggleOrg(org)}
                  style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 16px', cursor: 'pointer', background: isExp ? '#ffffff08' : 'transparent', borderLeft: isExp ? `2px solid ${accent}` : '2px solid transparent' }}
                  onMouseEnter={e => { if (!isExp) e.currentTarget.style.background = '#ffffff04'; }}
                  onMouseLeave={e => { if (!isExp) e.currentTarget.style.background = 'transparent'; }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, flex: 1, minWidth: 0 }}>
                    <Icon name={isExp ? 'chevron-down' : 'chevron-right'} size={10} color={PALETTE.textFaint} />
                    <Icon name="shield" size={14} color={isExp ? accent : PALETTE.textFaint} />
                    <span style={{ fontSize: TYPE.sectionTitle, fontWeight: 600, color: isExp ? PALETTE.textDim : '#a0a5b0', fontFamily: FONTS.mono, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{org.name}</span>
                    {isExp && <span style={{ fontSize: TYPE.button, color: PALETTE.textFaint, fontFamily: FONTS.mono }}>{members.length}</span>}
                    {isExp && (
                      <span
                        title={`${org.id} — click to copy`}
                        onClick={e => { e.stopPropagation(); copyToClipboard(org.id).catch(() => {}); }}
                        style={{ fontSize: TYPE.button, color: PALETTE.textGhost, fontFamily: FONTS.mono, cursor: 'pointer' }}
                      >{org.id}</span>
                    )}
                  </div>
                  {isOrgOwnerOrAdmin(org.id) && (
                    <Btn variant="danger" onClick={e => { e.stopPropagation(); handleDeleteOrg(org.id); }} style={{ fontSize: TYPE.label, padding: '2px 5px' }}>×</Btn>
                  )}
                </div>

                {isExp && (
                  <div style={{ paddingLeft: 34 }}>
                    {teams.map(t => {
                      const isSel = selectedTeam?.id === t.id;
                      const tms = teamMembers[t.id] || [];
                      return (
                        <div key={t.id} onClick={() => selectTeam(org.id, t)}
                          style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '6px 16px', cursor: 'pointer', background: isSel ? `${accent}14` : 'transparent', borderLeft: isSel ? `2px solid ${accent}` : '2px solid transparent' }}
                          onMouseEnter={e => { if (!isSel) e.currentTarget.style.background = '#ffffff04'; }}
                          onMouseLeave={e => { if (!isSel) e.currentTarget.style.background = 'transparent'; }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                            <Icon name="users" size={11} color={isSel ? accent : PALETTE.textFaint} />
                            <span style={{ fontSize: TYPE.body + 1, color: isSel ? PALETTE.textDim : PALETTE.textMute, fontFamily: FONTS.mono, fontWeight: isSel ? 600 : 400 }}>{t.name}</span>
                            <span style={{ fontSize: TYPE.label, color: PALETTE.textGhost, fontFamily: FONTS.mono }}>{tms.length}</span>
                          </div>
                          {isOrgOwnerOrAdmin(org.id) && (
                            <Btn variant="danger" onClick={e => { e.stopPropagation(); handleDeleteTeam(org.id, t.id); }} style={{ fontSize: TYPE.micro, padding: '1px 4px' }}>×</Btn>
                          )}
                        </div>
                      );
                    })}

                    <div onClick={() => setSelectedTeam(null)}
                      style={{ padding: '6px 16px', cursor: 'pointer', background: !selectedTeam ? `${accent}14` : 'transparent', borderLeft: !selectedTeam ? `2px solid ${accent}` : '2px solid transparent' }}
                      onMouseEnter={e => { if (selectedTeam) e.currentTarget.style.background = '#ffffff04'; }}
                      onMouseLeave={e => { if (selectedTeam) e.currentTarget.style.background = 'transparent'; }}>
                      <span style={{ fontSize: TYPE.body, color: !selectedTeam ? accent : PALETTE.textFaint, fontFamily: FONTS.mono, fontWeight: 600 }}>All members</span>
                    </div>

                    {/* create_team / add_org_member both require org owner/admin
                        on the backend (_require_org_admin) — manager/team_lead
                        can see this section (they can onboard *new* users via
                        "+ Create User" below) but not these two. */}
                    {isOrgOwnerOrAdmin(org.id) && (
                      <div style={{ display: 'flex', gap: 6, padding: '6px 16px 8px' }}>
                        <Btn variant="accentGhost" accent={accent} onClick={() => setShowCreateTeam(org.id)}>+ Team</Btn>
                        <Btn variant="accentGhost" accent={accent} onClick={() => { setShowBulkAdd(null); setBulkSelected(new Set()); }}>+ Add Members</Btn>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        {!expandedOrg ? (
          <EmptyState icon="shield" title="Select an organization" style={{ color: '#303540' }} />
        ) : (
          <>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px 16px', borderBottom: `1px solid ${PALETTE.borderSoft}`, flexShrink: 0 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                {selectedTeam ? (
                  <>
                    <Btn variant="ghost" onClick={() => setSelectedTeam(null)} style={{ fontSize: TYPE.body + 1, padding: 0 }}>←</Btn>
                    <Icon name="users" size={14} color={accent} />
                    <span style={{ fontSize: TYPE.sectionTitle + 1, fontWeight: 600, color: PALETTE.textDim, fontFamily: FONTS.mono }}>{selectedTeam.name}</span>
                  </>
                ) : (
                  <>
                    <Icon name="shield" size={14} color={accent} />
                    <span style={{ fontSize: TYPE.sectionTitle + 1, fontWeight: 600, color: PALETTE.textDim, fontFamily: FONTS.mono }}>{rightTitle}</span>
                  </>
                )}
                <span style={{ fontSize: TYPE.body, color: PALETTE.textFaint, fontFamily: FONTS.mono }}>{rightMembers.length} member{rightMembers.length !== 1 ? 's' : ''}</span>
              </div>
              <div style={{ display: 'flex', gap: 6 }}>
                {!selectedTeam && rightView === 'members' && isOrgAdminCapable(expandedOrg) && (
                  <Btn variant="accentGhost" accent={accent} onClick={() => setShowCreateUser(true)}>+ Create User</Btn>
                )}
                {rightView === 'members' && isOrgOwnerOrAdmin(expandedOrg) && (
                  <Btn variant="accentGhost" accent={accent} onClick={() => { setShowBulkAdd(selectedTeam?.id || false); setBulkSelected(new Set()); setBulkRole('viewer'); setBulkDefaultRole('viewer'); }}>+ Add Members</Btn>
                )}
              </div>
            </div>

            {!selectedTeam && (
              <div style={{ display: 'flex', gap: 2, padding: '8px 16px 0', borderBottom: `1px solid ${PALETTE.borderSoft}`, flexShrink: 0 }}>
                {[['members', 'Members'], ['sso', 'SSO / OIDC']].map(([id, label]) => (
                  <button key={id} onClick={() => setRightView(id)}
                    style={{ background: 'none', border: 'none', borderBottom: rightView === id ? `2px solid ${accent}` : '2px solid transparent', color: rightView === id ? accent : PALETTE.textFaint, fontSize: TYPE.body, fontFamily: FONTS.mono, fontWeight: 600, padding: '6px 10px', cursor: 'pointer' }}>
                    {label}
                  </button>
                ))}
              </div>
            )}

            {rightView === 'sso' && !selectedTeam && (
              <OidcProvidersPanel accent={accent} orgId={expandedOrg} canManage={isOrgOwnerOrAdmin(expandedOrg)} isPlatformAdmin={currentUser?.role === 'platform_admin'} />
            )}

            {rightView === 'members' && showBulkAdd !== null && (
              <div style={{ padding: '12px 16px', borderBottom: `1px solid ${PALETTE.borderSoft}`, background: PALETTE.bg1, flexShrink: 0 }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
                  <span style={{ fontSize: TYPE.body + 1, fontWeight: 600, color: PALETTE.textDim, fontFamily: FONTS.mono }}>
                    Add members {showBulkAdd ? `to team` : `to organization`}
                  </span>
                  <div style={{ display: 'flex', gap: 6 }}>
                    <Btn variant="ghost" onClick={() => { const avail = getAvailableUsers(); setBulkSelected(new Set(avail.map(u => u.id))); }} style={{ fontSize: TYPE.label, padding: '3px 8px' }}>Select all</Btn>
                    <Btn variant="ghost" onClick={() => setBulkSelected(new Set())} style={{ fontSize: TYPE.label, padding: '3px 8px' }}>Deselect</Btn>
                  </div>
                </div>

                <div style={{ maxHeight: 180, overflow: 'auto', marginBottom: 10, background: PALETTE.bg2, border: `1px solid ${PALETTE.borderSoft}`, borderRadius: 4, padding: 6 }}>
                  {getAvailableUsers().length === 0 && <div style={{ color: PALETTE.textGhost, fontSize: TYPE.body, fontFamily: FONTS.mono, padding: 8 }}>No available users.</div>}
                  {getAvailableUsers().map(u => (
                    <div key={u.id} style={{ display: 'flex', alignItems: 'center', padding: '4px 4px', borderRadius: 3 }}
                      onMouseEnter={e => e.currentTarget.style.background = '#ffffff08'}
                      onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
                      <Checkbox checked={bulkSelected.has(u.id)} accent={accent} onChange={v => {
                        setBulkSelected(prev => {
                          const next = new Set(prev);
                          if (v) next.add(u.id); else next.delete(u.id);
                          return next;
                        });
                      }} label={<>
                        <span style={{ fontSize: TYPE.body + 1, color: PALETTE.textDim, fontFamily: FONTS.mono }}>{u.username}</span>{' '}
                        <span style={{ fontSize: TYPE.label, color: PALETTE.textFaint, fontFamily: FONTS.mono }}>{u.role}</span>
                      </>} />
                    </div>
                  ))}
                </div>

                <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                  <span style={{ fontSize: TYPE.button, color: PALETTE.textFaint, fontFamily: FONTS.mono }}>Role:</span>
                  <Select value={bulkRole} onChange={setBulkRole}
                    options={RO.map(r => ({ value: r, label: RL[r] }))} />
                  {showBulkAdd && (
                    <>
                      <span style={{ fontSize: TYPE.button, color: PALETTE.textFaint, fontFamily: FONTS.mono }}>Project role:</span>
                      <Select value={bulkDefaultRole} onChange={setBulkDefaultRole}
                        options={RO.map(r => ({ value: r, label: RL[r] }))} />
                    </>
                  )}
                  <Btn variant="solid" accent={accent} onClick={handleBulkAdd} disabled={bulkSelected.size === 0}>
                    Add {bulkSelected.size > 0 ? `(${bulkSelected.size})` : ''}
                  </Btn>
                  <Btn variant="ghost" onClick={() => { setShowBulkAdd(null); setBulkSelected(new Set()); }}>Cancel</Btn>
                </div>
              </div>
            )}

            {rightView === 'members' && (
            <div style={{ flex: 1, overflow: 'auto', padding: '8px 16px' }}>
              {rightMembers.map(m => {
                const c = RC[m.role] || PALETTE.textMute;
                return (
                  <div key={m.user_id} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '9px 0', borderBottom: `1px solid ${PALETTE.borderSoft}` }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                      <div style={{ width: 30, height: 30, borderRadius: '50%', background: c + '22', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: TYPE.button, color: c, fontWeight: 700, fontFamily: FONTS.mono, flexShrink: 0 }}>
                        {(m.username || '?').slice(0, 2).toUpperCase()}
                      </div>
                      <span style={{ fontSize: TYPE.sectionTitle, color: PALETTE.textDim, fontFamily: FONTS.mono }}>{m.username}</span>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      {selectedTeam || !isOrgOwnerOrAdmin(expandedOrg) ? (
                        <Badge label={RL[m.role] || m.role} color={c} />
                      ) : (
                        <Select value={m.role} onChange={v => handleChangeOrgMemberRole(expandedOrg, m.user_id, v)}
                          style={{ color: c, fontWeight: 600 }}
                          options={RO.map(r => ({ value: r, label: RL[r] }))} />
                      )}
                      {m.default_project_role && (
                        <span style={{ fontSize: TYPE.label, color: '#c07af0', fontFamily: FONTS.mono }}>→ {RL[m.default_project_role] || m.default_project_role}</span>
                      )}
                      {/* add/remove_team_member and add/remove_org_member all
                          require org owner/admin on the backend
                          (_require_org_admin) — manager/team_lead can view
                          this list but not mutate it. */}
                      {selectedTeam ? (
                        isOrgOwnerOrAdmin(expandedOrg) && (
                          <Btn variant="ghost" onClick={() => handleRemoveTeamMember(selectedTeam.orgId, selectedTeam.id, m.user_id)} style={{ fontSize: TYPE.button, padding: '3px 6px' }}>Remove</Btn>
                        )
                      ) : m.role !== 'owner' && isOrgOwnerOrAdmin(expandedOrg) ? (
                        <Btn variant="ghost" onClick={() => handleRemoveOrgMember(expandedOrg, m.user_id)} style={{ fontSize: TYPE.button, padding: '3px 6px' }}>Remove</Btn>
                      ) : null}
                    </div>
                  </div>
                );
              })}
              {rightMembers.length === 0 && <EmptyState icon="users" title="No members" />}
            </div>
            )}
          </>
        )}
      </div>

      {showCreateOrg && <CreateOrgModal accent={accent} onClose={() => setShowCreateOrg(false)} onCreate={handleCreateOrg} />}
      {showCreateTeam && <CreateTeamModal accent={accent} onClose={() => setShowCreateTeam(null)} onCreate={name => handleCreateTeam(showCreateTeam, name)} />}
      {showCreateUser && <CreateOrgUserModal accent={accent} onClose={() => setShowCreateUser(false)} onCreate={data => handleCreateOrgUser(expandedOrg, data)} />}
    </div>
  );
}

// ── OIDC / SSO admin panel ──────────────────────────────────────────────

const ROLE_OPTIONS = Object.keys(RL);

function OidcProvidersPanel({ accent, orgId, canManage, isPlatformAdmin }) {
  const { hasFeature, requiredTier } = useEntitlement();
  const ssoLocked = !hasFeature(FEATURE.SSO);
  const [providers, setProviders] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try { setProviders(await api.listOidcProviders(orgId)); }
    catch (e) { toastError(e.message); }
    setLoading(false);
  }, [orgId]);

  useEffect(() => { load(); }, [load]);

  const handleCreate = async (data) => {
    try {
      const created = await api.createOidcProvider(orgId, data);
      toastSuccess('OIDC provider created');
      await load();
      return created;
    } catch (e) { toastError(e.message); return null; }
  };

  const handleToggle = async (p, field) => {
    try { await api.updateOidcProvider(orgId, p.id, { [field]: !p[field] }); await load(); }
    catch (e) { toastError(e.message); }
  };

  const handleDelete = async (id) => {
    if (!await uiConfirm('Delete this OIDC provider? Users linked through it will no longer be able to sign in via SSO.')) return;
    try { await api.deleteOidcProvider(orgId, id); toastSuccess('Deleted'); await load(); }
    catch (e) { toastError(e.message); }
  };

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: '12px 16px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
        <span style={{ fontSize: TYPE.body, color: PALETTE.textFaint, fontFamily: FONTS.mono, lineHeight: 1.6 }}>
          Corporate SSO providers for this organization. New users are matched by email; group/role claims can auto-assign an org role.<br />
          <span style={{ color: PALETTE.textGhost }}>
            Setup: 1. Add provider (issuer + client id/secret from your IdP app) · 2. Copy the redirect URI from its row into the IdP app · 3. Test sign-in.
          </span>
        </span>
        {canManage && (
          <FeatureLock locked={ssoLocked} tier={requiredTier(FEATURE.SSO)} style={{ flexShrink: 0, marginLeft: 12 }}
            note="SSO / OIDC requires the Enterprise plan.">
            <Btn variant="accentGhost" accent={accent} disabled={ssoLocked} onClick={() => setShowCreate(true)}>+ Add Provider</Btn>
          </FeatureLock>
        )}
      </div>

      {loading && <div style={{ color: PALETTE.textGhost, fontSize: TYPE.body + 1, fontFamily: FONTS.mono }}>Loading...</div>}
      {!loading && providers.length === 0 && <EmptyState icon="shield" title="No OIDC providers configured" />}

      {providers.map(p => (
        <div key={p.id} style={{ border: `1px solid ${PALETTE.borderSoft}`, borderRadius: 6, padding: '10px 14px', marginBottom: 10 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontSize: TYPE.sectionTitle, fontWeight: 600, color: PALETTE.textDim, fontFamily: FONTS.mono }}>{p.name}</span>
              <Badge label={p.enabled ? 'enabled' : 'disabled'} color={p.enabled ? '#22c55e' : '#606570'} />
              {p.enforced && <Badge label="obligatory" color="#cc2233" />}
              {p.jit_provisioning_enabled && <Badge label="JIT" color="#5b8af5" />}
            </div>
            {canManage && <Btn variant="danger" onClick={() => handleDelete(p.id)} style={{ fontSize: TYPE.label, padding: '2px 6px' }}>Delete</Btn>}
          </div>
          <div style={{ fontSize: TYPE.label, color: PALETTE.textFaint, fontFamily: FONTS.mono, marginTop: 4 }}>{p.issuer_url}</div>
          {/* Same ready-to-paste redirect URI as the platform SSO panel —
              org-scoped providers use the identical /api/auth/oidc path. */}
          <div style={{ fontSize: TYPE.label, color: PALETTE.textGhost, fontFamily: FONTS.mono, marginTop: 2, display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
            <span>redirect URI:</span>
            <span style={{ color: PALETTE.textDim }}>{`${location.origin}/api/auth/oidc/${p.id}/callback`}</span>
            <button
              onClick={() => copyToClipboard(`${location.origin}/api/auth/oidc/${p.id}/callback`).catch(() => {})}
              title="Copy redirect URI"
              style={{ padding: '1px 7px', borderRadius: 3, border: `1px solid ${PALETTE.border}`, background: 'transparent', color: PALETTE.textMute, fontSize: TYPE.overline, fontFamily: FONTS.mono, cursor: 'pointer' }}
            >copy</button>
          </div>
          <div style={{ fontSize: TYPE.label, color: PALETTE.textGhost, fontFamily: FONTS.mono, marginTop: 2 }}>
            default role: {RL[p.default_role] || p.default_role}
            {p.email_domain && ` · domain: ${p.email_domain}`}
            {p.require_platform_mfa && ' · platform MFA required'}
            {p.last_test_login_at ? ` · last verified sign-in: ${new Date(p.last_test_login_at).toLocaleString()}` : ' · not yet verified with a successful sign-in'}
          </div>
          {canManage && (
            <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
              <a href={`/api/auth/oidc/${p.id}/login`} target="_blank" rel="noopener" title="Open the provider's sign-in flow in a new tab"
                style={{ padding: '3px 10px', borderRadius: 4, border: `1px solid ${accent}44`, background: `${accent}15`, color: accent, fontSize: TYPE.button, fontFamily: FONTS.mono, cursor: 'pointer', textDecoration: 'none' }}>Test sign-in</a>
              <Btn variant="ghost" onClick={() => handleToggle(p, 'enabled')} style={{ fontSize: TYPE.button, padding: '3px 8px' }}>{p.enabled ? 'Disable' : 'Enable'}</Btn>
              <Btn variant="ghost" onClick={() => handleToggle(p, 'enforced')} style={{ fontSize: TYPE.button, padding: '3px 8px' }}>
                {p.enforced ? 'Stop requiring SSO' : 'Require SSO (disable passwords)'}
              </Btn>
            </div>
          )}
        </div>
      ))}

      {showCreate && <CreateOidcProviderModal accent={accent} onClose={() => setShowCreate(false)} onCreate={handleCreate} isPlatformAdmin={isPlatformAdmin} />}
    </div>
  );
}
OidcProvidersPanel.propTypes = { accent: PropTypes.string, orgId: PropTypes.string, canManage: PropTypes.bool };

export function CreateOidcProviderModal({ accent, onClose, onCreate, isPlatformAdmin }) {
  // Pre-generated provider id: the exact callback URL is known and copyable
  // WHILE filling the form — register it in the IdP first, then Create here.
  // The backend accepts this id (format-validated; 409 on collision).
  const [presetId] = useState(() => 'oidcp' + Array.from(globalThis.crypto.getRandomValues(new Uint8Array(4))).map(b => b.toString(16).padStart(2, '0')).join(''));
  const presetUri = `${location.origin}/api/auth/oidc/${presetId}/callback`;
  const [created, setCreated] = useState(null);
  const [allowPrivate, setAllowPrivate] = useState(false);
  const [name, setName] = useState('');
  const [issuerUrl, setIssuerUrl] = useState('');
  const [clientId, setClientId] = useState('');
  const [clientSecret, setClientSecret] = useState('');
  const [emailDomain, setEmailDomain] = useState('');
  const [defaultRole, setDefaultRole] = useState('viewer');
  const [jit, setJit] = useState(false);
  const [requireMfa, setRequireMfa] = useState(false);

  const canSubmit = name.trim() && issuerUrl.trim() && clientId.trim() && clientSecret.trim();

  if (created) {
    // The provider id is generated server-side on create — this is the
    // first moment the redirect URI exists. Show it right here with a
    // copy button, so the IdP registration is part of the same dialog.
    const uri = `${location.origin}/api/auth/oidc/${created.id}/callback`;
    return (
      <Modal title="Provider created" onClose={onClose} width={520}>
        <div style={{ fontSize: TYPE.body, color: PALETTE.textFaint, fontFamily: FONTS.mono, marginBottom: 10 }}>
          Register this redirect URI in your IdP application settings, then use <b>Test sign-in</b> on the provider row.
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, background: PALETTE.bg2, border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '8px 10px' }}>
          <span style={{ fontSize: TYPE.button, color: PALETTE.textDim, fontFamily: FONTS.mono, wordBreak: 'break-all', flex: 1 }}>{uri}</span>
          <Btn variant="accentGhost" accent={accent} onClick={() => copyToClipboard(uri).catch(() => {})}>copy</Btn>
        </div>
        <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 14 }}>
          <Btn variant="ghost" onClick={onClose}>Done</Btn>
        </div>
      </Modal>
    );
  }

  return (
    <Modal accent={accent} title="Add OIDC Provider" onClose={onClose}>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        <FieldInput label="Display name" value={name} onChange={setName} placeholder="Corp Okta" />
        <FieldInput label="Issuer URL" value={issuerUrl} onChange={setIssuerUrl} placeholder="https://your-org.okta.com" />

        <div style={{ background: PALETTE.bg2, border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '8px 10px', display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ fontSize: TYPE.overline, color: PALETTE.textGhost, fontFamily: FONTS.mono, textTransform: 'uppercase', flexShrink: 0 }}>Callback URL</span>
          <span style={{ fontSize: TYPE.button, color: PALETTE.textDim, fontFamily: FONTS.mono, wordBreak: 'break-all', flex: 1 }}>{presetUri}</span>
          <Btn variant="accentGhost" accent={accent} onClick={() => copyToClipboard(presetUri).catch(() => {})}>copy</Btn>
        </div>
        <div style={{ fontSize: 10, color: PALETTE.textGhost, fontFamily: FONTS.mono, marginTop: -6 }}>
          Authorization/token/JWKS endpoints are discovered automatically from {'{issuer}'}/.well-known/openid-configuration.
        </div>
        <FieldInput label="Client ID" value={clientId} onChange={setClientId} />
        <div>
          <div style={{ fontSize: 9, color: PALETTE.textGhost, marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Client secret</div>
          <input type="password" value={clientSecret} onChange={e => setClientSecret(e.target.value)}
            style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 11, outline: 'none', fontFamily: 'JetBrains Mono', boxSizing: 'border-box' }} />
        </div>
        <FieldInput label="Email domain (for login-screen SSO suggestion)" value={emailDomain} onChange={setEmailDomain} placeholder="corp.example.com" />
        <div>
          <div style={{ fontSize: 9, color: PALETTE.textGhost, marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.08em' }}>Default role for new/unmapped users</div>
          <Select value={defaultRole} onChange={setDefaultRole} style={{ width: '100%' }}
            options={ROLE_OPTIONS.map(r => ({ value: r, label: RL[r] }))} />
        </div>
        <Checkbox checked={jit} onChange={setJit} label="Auto-create accounts for new users on first SSO sign-in (JIT provisioning)" />
        <Checkbox checked={requireMfa} onChange={setRequireMfa} label="Still require platform TOTP-MFA after a successful SSO sign-in" />
        {isPlatformAdmin && (
          <Checkbox checked={allowPrivate} onChange={setAllowPrivate} accent={PALETTE.warn}
            label="Allow issuer on a private/internal address (self-hosted IdP behind your firewall) — platform admin only" />
        )}
        <Btn variant="solid" accent={accent} disabled={!canSubmit}
          onClick={async () => {
            const created = await onCreate({
              name: name.trim(), issuer_url: issuerUrl.trim(), client_id: clientId.trim(), client_secret: clientSecret,
              email_domain: emailDomain.trim(), default_role: defaultRole,
              jit_provisioning_enabled: jit, require_platform_mfa: requireMfa,
              allow_private_issuer: allowPrivate, id: presetId,
            });
            if (created) setCreated(created);
          }}>
          Create
        </Btn>
      </div>
    </Modal>
  );
}
CreateOidcProviderModal.propTypes = { accent: PropTypes.string, onClose: PropTypes.func, onCreate: PropTypes.func };

function CreateOrgModal({ accent, onClose, onCreate }) {
  const [name, setName] = useState('');
  const [slug, setSlug] = useState('');
  const handleSubmit = () => { if (name) onCreate({ name, slug: slug || name.toLowerCase().replace(/[^a-z0-9-]/g, '-').replace(/-+/g, '-') }); };
  return (
    <Modal title="Create Organization" icon="shield" accent={accent} onClose={onClose}
      footer={<>
        <Btn variant="ghost" onClick={onClose}>Cancel</Btn>
        <Btn variant="solid" accent={accent} onClick={handleSubmit} disabled={!name}>Create</Btn>
      </>}>
      <FieldInput label="Name" value={name} onChange={setName} placeholder="Acme Corp" mono={false} />
      <FieldInput label="Slug" value={slug} onChange={setSlug} placeholder="acme-corp" />
    </Modal>
  );
}

function CreateTeamModal({ accent, onClose, onCreate }) {
  const [name, setName] = useState('');
  return (
    <Modal title="Create Team" icon="users" accent={accent} onClose={onClose}
      footer={<>
        <Btn variant="ghost" onClick={onClose}>Cancel</Btn>
        <Btn variant="solid" accent={accent} onClick={() => { if (name) { onCreate(name); onClose(); } }} disabled={!name}>Create</Btn>
      </>}>
      <FieldInput label="Name" value={name} onChange={setName} placeholder="Red Team Alpha" mono={false} />
    </Modal>
  );
}

function CreateOrgUserModal({ accent, onClose, onCreate }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [role, setRole] = useState('viewer');
  const canSubmit = username.trim().length > 0 && password.length >= 12;
  return (
    <Modal title="Create User" icon="users" accent={accent} onClose={onClose}
      footer={<>
        <Btn variant="ghost" onClick={onClose}>Cancel</Btn>
        <Btn variant="solid" accent={accent} disabled={!canSubmit}
          onClick={() => onCreate({ username, password, display_name: displayName, role })}>Create</Btn>
      </>}>
      <FieldInput label="Username" value={username} onChange={setUsername} placeholder="jdoe" />
      <FieldInput label="Display name" value={displayName} onChange={setDisplayName} placeholder="Jane Doe" mono={false} />
      <div>
        <div style={{ fontSize: 9, color: '#404550', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Password</div>
        <input type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="min. 12 characters"
          style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 11, outline: 'none', fontFamily: 'JetBrains Mono', boxSizing: 'border-box' }} />
      </div>
      <div style={{ marginTop: 8 }}>
        <span style={{ fontSize: TYPE.button, color: PALETTE.textFaint, fontFamily: FONTS.mono, display: 'block', marginBottom: 4 }}>Org role</span>
        <Select value={role} onChange={setRole} style={{ width: '100%' }}
          options={RO.map(r => ({ value: r, label: RL[r] }))} />
      </div>
    </Modal>
  );
}

OrganizationsView.propTypes = { accent: PropTypes.string, currentUser: PropTypes.object };
CreateOrgModal.propTypes = { accent: PropTypes.string, onClose: PropTypes.func, onCreate: PropTypes.func };
CreateTeamModal.propTypes = { accent: PropTypes.string, onClose: PropTypes.func, onCreate: PropTypes.func };
CreateOrgUserModal.propTypes = { accent: PropTypes.string, onClose: PropTypes.func, onCreate: PropTypes.func };
