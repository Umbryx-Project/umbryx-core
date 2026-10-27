import { useState, useEffect } from 'react';
import PropTypes from 'prop-types';
import { api } from '../api.js';
import Icon from '../components/Icon.jsx';
import { toastError, toastSuccess } from '../components/Toast.jsx';
import {
  Btn, Select, EmptyState, Overline, Badge,
  PALETTE, TYPE, FONTS } from '../components/UI.jsx';
import { assignableProjectRoles } from '../utils/admin.js';
import { useEntitlement } from '../hooks/useEntitlement.js';

const ROLE_COLOR = {
  owner: '#f09a3a', admin: '#cc2233', editor: '#5b8af5', manager: '#39d353',
  team_lead: '#c07af0', operator: '#c07af0', analyst: '#6fc8f0', reviewer: '#e8cc42',
  viewer: '#39d353', observer: '#5b8af5', auditor: '#6fc8f0',
};

function SourceBadge({ source }) {
  if (!source || source === 'direct') return null;
  if (source.startsWith('team:')) {
    return <Badge label="TEAM" color="#c07af0" />;
  }
  return null;
}
SourceBadge.propTypes = { source: PropTypes.string };

function Avatar({ name, role }) {
  const color = ROLE_COLOR[role] || PALETTE.textMute;
  return (
    <div style={{ width: 28, height: 28, borderRadius: '50%', background: `${color}18`, border: `1px solid ${color}44`, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: TYPE.button, fontWeight: 700, color, fontFamily: FONTS.mono, flexShrink: 0 }}>
      {(name || '?').slice(0, 2).toUpperCase()}
    </div>
  );
}
Avatar.propTypes = { name: PropTypes.string, role: PropTypes.string };

export default function MembersPanel({ pid, accent }) {
  // Tier, not edition: the review roles exist in every build and are gated
  // by the license, so this is an upsell case rather than a missing
  // capability — the picker just does not offer what the backend refuses.
  const { tier } = useEntitlement();
  const [members, setMembers] = useState([]);
  const [users, setUsers] = useState([]);
  const [teams, setTeams] = useState([]);
  const [loading, setLoading] = useState(true);
  const [addUserId, setAddUserId] = useState('');
  const [addRole, setAddRole] = useState('viewer');
  const [adding, setAdding] = useState(false);
  const [canManage, setCanManage] = useState(false);
  const [showAdd, setShowAdd] = useState(false);
  const [showAttach, setShowAttach] = useState(false);
  const [availableTeams, setAvailableTeams] = useState([]);
  const [attachTeamId, setAttachTeamId] = useState('');

  const load = async () => {
    if (!pid) return;
    setLoading(true);
    try {
      const [m, u, p] = await Promise.all([
        api.listProjectMembers(pid),
        api.listAvailableUsers(pid),
        api.getMyProjectPermissions(pid),
      ]);
      setMembers(m);
      setUsers(u);
      setCanManage(p.permissions?.includes('project.manage_members') || p.is_super_admin || false);
      try {
        const t = await api.listProjectTeams(pid);
        setTeams(t || []);
      } catch { setTeams([]); }
    } catch (e) { toastError(e.message); }
    setLoading(false);
  };

  useEffect(() => { load(); }, [pid]);

  const loadAvailableTeams = async () => {
    try {
      const orgs = await api.listOrganizations();
      const attachedIds = new Set(teams.map(t => t.team_id));
      const allTeams = [];
      for (const org of orgs) {
        try {
          const orgTeams = await api.listOrgTeams(org.id);
          for (const t of orgTeams) {
            if (!attachedIds.has(t.id)) {
              allTeams.push({ id: t.id, name: t.name, org_name: org.name });
            }
          }
        } catch { /* skip an organization whose teams cannot be listed */ }
      }
      setAvailableTeams(allTeams);
      setShowAttach(true);
    } catch (e) { toastError(e.message); }
  };

  const handleRoleChange = async (uid, role) => {
    try { await api.updateMemberRole(pid, uid, { role }); load(); }
    catch (e) { toastError(e.message); }
  };

  const handleRemove = async (uid) => {
    try { await api.removeProjectMember(pid, uid); toastSuccess('Member removed'); load(); }
    catch (e) { toastError(e.message); }
  };

  const handleAdd = async () => {
    if (!addUserId) return;
    setAdding(true);
    try {
      await api.addProjectMember(pid, { user_id: addUserId, role: addRole });
      toastSuccess('Member added');
      setAddUserId('');
      setShowAdd(false);
      load();
    } catch (e) { toastError(e.message); }
    setAdding(false);
  };

  const handleAttachTeam = async () => {
    if (!attachTeamId) return;
    setAdding(true);
    try {
      await api.attachTeamToProject(pid, attachTeamId);
      toastSuccess('Team attached');
      setAttachTeamId('');
      setShowAttach(false);
      load();
    } catch (e) { toastError(e.message); }
    setAdding(false);
  };

  const handleDetachTeam = async (teamId, teamName) => {
    try {
      await api.detachTeamFromProject(pid, teamId);
      toastSuccess(`Team "${teamName}" detached`);
      load();
    } catch (e) { toastError(e.message); }
  };

  const nonMembers = users.filter(u => !new Set(members.map(m => m.user_id)).has(u.id));

  if (!pid) return <EmptyState icon="users" title="Select a project" />;

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>

      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px 16px', borderBottom: `1px solid ${PALETTE.borderSoft}`, flexShrink: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Icon name="users" size={16} color={accent} />
          <span style={{ fontSize: TYPE.sectionTitle, fontWeight: 600, color: PALETTE.textDim, fontFamily: FONTS.mono }}>Members</span>
          {!loading && (
            <span style={{ fontSize: TYPE.button, color: PALETTE.textFaint, fontFamily: FONTS.mono }}>
              {members.length} member{members.length !== 1 ? 's' : ''}
              {teams.length > 0 && ` · ${teams.length} team${teams.length !== 1 ? 's' : ''}`}
            </span>
          )}
        </div>
        {canManage && (
          <div style={{ display: 'flex', gap: 6 }}>
            <Btn variant="solid" accent="#c07af0" onClick={loadAvailableTeams}
              style={{ background: showAttach ? PALETTE.border : undefined, color: showAttach ? PALETTE.textMute : undefined }}>
              + Attach Team
            </Btn>
            {nonMembers.length > 0 && (
              <Btn variant="solid" accent={accent} onClick={() => setShowAdd(v => !v)}
                style={{ background: showAdd ? PALETTE.border : undefined, color: showAdd ? PALETTE.textMute : undefined }}>
                {showAdd ? 'Cancel' : '+ Add Member'}
              </Btn>
            )}
          </div>
        )}
      </div>

      {teams.length > 0 && (
        <div style={{ padding: '8px 16px', borderBottom: `1px solid ${PALETTE.borderSoft}`, background: `${PALETTE.bg1}08`, flexShrink: 0 }}>
          <Overline style={{ marginBottom: 6 }}>Attached Teams</Overline>
          {teams.map(t => (
            <div key={t.team_id} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4, padding: '4px 8px', background: PALETTE.bg1, border: `1px solid ${PALETTE.borderSoft}`, borderRadius: 4 }}>
              <Icon name="users" size={11} color="#c07af0" />
              <span style={{ fontSize: TYPE.body, color: PALETTE.textDim, fontFamily: FONTS.mono, flex: 1 }}>{t.team_name}</span>
              <span style={{ fontSize: TYPE.label, color: PALETTE.textFaint, fontFamily: FONTS.mono }}>{t.member_count} member{t.member_count !== 1 ? 's' : ''}</span>
              {canManage && (
                <button onClick={() => handleDetachTeam(t.team_id, t.team_name)} title="Detach team"
                  style={{ background: 'transparent', border: '1px solid transparent', borderRadius: 3, cursor: 'pointer', color: PALETTE.textGhost, padding: '2px 4px', display: 'flex' }}
                  onMouseEnter={e => { e.currentTarget.style.borderColor = `${PALETTE.danger}66`; e.currentTarget.style.color = PALETTE.danger; }}
                  onMouseLeave={e => { e.currentTarget.style.borderColor = 'transparent'; e.currentTarget.style.color = PALETTE.textGhost; }}>
                  <Icon name="close" size={9} color="currentColor" />
                </button>
              )}
            </div>
          ))}
        </div>
      )}

      {showAttach && canManage && (
        <div style={{ padding: '10px 16px', borderBottom: `1px solid ${PALETTE.borderSoft}`, background: PALETTE.bg1, flexShrink: 0 }}>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <Select value={attachTeamId} onChange={setAttachTeamId}
              options={availableTeams.map(t => ({ value: t.id, label: `${t.name} (${t.org_name})` }))}
              placeholder="Select team..." style={{ flex: 1 }} />
            <Btn variant="solid" accent="#c07af0" onClick={handleAttachTeam} disabled={!attachTeamId || adding}>
              {adding ? '...' : 'Attach'}
            </Btn>
            <Btn variant="ghost" onClick={() => { setShowAttach(false); setAttachTeamId(''); }}>Cancel</Btn>
          </div>
        </div>
      )}

      {showAdd && canManage && (
        <div style={{ padding: '10px 16px', borderBottom: `1px solid ${PALETTE.borderSoft}`, background: PALETTE.bg1, flexShrink: 0 }}>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <Select value={addUserId} onChange={setAddUserId}
              options={nonMembers.map(u => ({ value: u.id, label: u.username }))}
              placeholder="Select user..." style={{ flex: 1 }} />
            <Select value={addRole} onChange={setAddRole}
              style={{ width: 120, color: ROLE_COLOR[addRole] || PALETTE.textDim }}
              options={assignableProjectRoles(tier, addRole).map(r => ({ value: r, label: r.replace('_', ' ') }))} />
            <Btn variant="solid" accent={accent} onClick={handleAdd} disabled={!addUserId || adding}>
              {adding ? '...' : 'Add'}
            </Btn>
          </div>
        </div>
      )}

      <div style={{ flex: 1, overflow: 'auto', padding: '8px 16px' }}>
        {loading && <div style={{ color: PALETTE.textGhost, fontFamily: FONTS.mono, fontSize: TYPE.body }}>Loading...</div>}

        {!loading && members.length === 0 && (
          <EmptyState icon="users" title="No members yet" />
        )}

        {!loading && members.map(m => (
          <div key={m.user_id} style={{ background: PALETTE.bg1, border: `1px solid ${PALETTE.borderSoft}`, borderRadius: 6, padding: '10px 14px', marginBottom: 6, display: 'flex', alignItems: 'center', gap: 10 }}>
            <Avatar name={m.username || m.user_id} role={m.role} />
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{ fontSize: TYPE.body + 1, color: PALETTE.textDim, fontFamily: FONTS.mono, fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {m.username || m.user_id}
                </span>
                <SourceBadge source={m.source} />
              </div>
              {m.email && <div style={{ fontSize: TYPE.label, color: PALETTE.textFaint, fontFamily: FONTS.mono, marginTop: 1 }}>{m.email}</div>}
            </div>

            {canManage ? (
              <Select value={m.role} onChange={v => handleRoleChange(m.user_id, v)}
                style={{ color: ROLE_COLOR[m.role] || PALETTE.textDim, fontWeight: 700, textTransform: 'uppercase' }}
                options={assignableProjectRoles(tier, m.role).map(r => ({ value: r, label: r.replace('_', ' ') }))} />
            ) : (
              <Badge label={m.role.replace('_', ' ')} color={ROLE_COLOR[m.role] || PALETTE.textMute} />
            )}

            {canManage && (!m.source || m.source === 'direct') && (
              <button onClick={() => handleRemove(m.user_id)} title="Remove"
                style={{ background: 'transparent', border: '1px solid transparent', borderRadius: 3, cursor: 'pointer', color: PALETTE.textGhost, padding: '3px 5px', display: 'flex', alignItems: 'center' }}
                onMouseEnter={e => { e.currentTarget.style.borderColor = `${PALETTE.danger}66`; e.currentTarget.style.color = PALETTE.danger; }}
                onMouseLeave={e => { e.currentTarget.style.borderColor = 'transparent'; e.currentTarget.style.color = PALETTE.textGhost; }}>
                <Icon name="close" size={10} color="currentColor" />
              </button>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

MembersPanel.propTypes = { pid: PropTypes.string, accent: PropTypes.string };
