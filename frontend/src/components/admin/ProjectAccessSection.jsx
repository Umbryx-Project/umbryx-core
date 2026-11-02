import { useEffect, useState } from 'react';
import PropTypes from 'prop-types';
import Icon from '../Icon.jsx';
import { api } from '../../api.js';
import { PROJECT_ROLE_ORDER, PROJECT_ROLE_COLOR, PROJECT_ROLE_LABEL } from '../../utils/admin.js';
import { PALETTE, FONTS, Select } from '../UI.jsx';

export default function ProjectAccessSection({ accent, allUsers }) {
  const [projects, setProjects] = useState([]);
  const [selectedPid, setSelectedPid] = useState('');
  const [members, setMembers] = useState([]);
  const [loadingMembers, setLoadingMembers] = useState(false);
  const [addUserId, setAddUserId] = useState('');
  const [addRole, setAddRole] = useState('viewer');
  const [adding, setAdding] = useState(false);
  const [error, setError] = useState('');
  const [transferTo, setTransferTo] = useState('');
  const [showTransfer, setShowTransfer] = useState(false);

  useEffect(() => {
    api.getProjects().then(setProjects).catch(() => {});
  }, []);

  useEffect(() => {
    if (!selectedPid) { setMembers([]); return; }
    setLoadingMembers(true);
    setError('');
    api.getProjectMembers(selectedPid)
      .then(setMembers)
      .catch(e => setError(e.message))
      .finally(() => setLoadingMembers(false));
  }, [selectedPid]);

  const memberUserIds = new Set(members.map(m => m.user_id));
  const nonMembers = allUsers.filter(u => !memberUserIds.has(u.id));

  const handleAdd = async () => {
    if (!addUserId || !selectedPid) return;
    setAdding(true); setError('');
    try {
      const m = await api.addProjectMember(selectedPid, { user_id: addUserId, role: addRole });
      setMembers(prev => [...prev, m]);
      setAddUserId('');
    } catch (e) { setError(e.message); }
    finally { setAdding(false); }
  };

  const handleRoleChange = async (uid, newRole) => {
    try {
      const updated = await api.updateProjectMember(selectedPid, uid, { role: newRole });
      setMembers(prev => prev.map(m => m.user_id === uid ? { ...m, role: updated.role } : m));
    } catch (e) { setError(e.message); }
  };

  const handleRemove = async (uid) => {
    try {
      await api.removeProjectMember(selectedPid, uid);
      setMembers(prev => prev.filter(m => m.user_id !== uid));
    } catch (e) { setError(e.message); }
  };

  const handleTransfer = async () => {
    if (!transferTo) return;
    try {
      await api.transferOwnership(selectedPid, { user_id: transferTo });
      const refreshed = await api.getProjectMembers(selectedPid);
      setMembers(refreshed);
      setShowTransfer(false);
      setTransferTo('');
    } catch (e) { setError(e.message); }
  };

  return (
    <div style={{ marginTop: 36 }}>
      <div style={{ marginBottom: 18 }}>
        <div style={{ fontSize: 9, color: PALETTE.textGhost, letterSpacing: '0.15em', textTransform: 'uppercase', marginBottom: 6 }}>Access control</div>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <h2 style={{ fontSize: 18, fontWeight: 700, color: PALETTE.text, fontFamily: FONTS.display }}>Project members</h2>
          {projects.length > 0 && (
            <Select value={selectedPid} onChange={v => { setSelectedPid(v); setShowTransfer(false); setError(''); }}
              style={{ minWidth: 200 }} placeholder="— select project —"
              options={projects.map(p => ({ value: p.id, label: p.name }))} />
          )}
        </div>
      </div>

      {!selectedPid && (
        <div style={{ background: PALETTE.bg2, border: '1px solid #1e2029', borderRadius: 8, padding: '24px', textAlign: 'center', color: PALETTE.textGhost, fontSize: 12 }}>
          Select a project to manage its members
        </div>
      )}

      {selectedPid && (
        <div style={{ background: PALETTE.bg2, border: '1px solid #1e2029', borderRadius: 10, overflow: 'hidden' }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 160px 100px', gap: 0, padding: '9px 18px', borderBottom: '1px solid #1e2029', background: '#090b0f' }}>
            {['User', 'Project role', 'Actions'].map(h => (
              <div key={h} style={{ fontSize: 9, color: PALETTE.textGhost, textTransform: 'uppercase', letterSpacing: '0.1em' }}>{h}</div>
            ))}
          </div>

          {loadingMembers && (
            <div style={{ padding: '18px', color: '#505560', fontSize: 12 }}>Loading...</div>
          )}

          {error && (
            <div style={{ margin: '10px 18px', background: '#cc233318', border: '1px solid #cc233344', borderRadius: 5, padding: '7px 10px', fontSize: 11, color: PALETTE.danger }}>{error}</div>
          )}

          {!loadingMembers && members.map((m, i) => (
            <div key={m.user_id} style={{ display: 'grid', gridTemplateColumns: '1fr 160px 100px', gap: 0, padding: '11px 18px', borderBottom: i < members.length - 1 ? '1px solid #14161b' : 'none', alignItems: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <div style={{ width: 28, height: 28, borderRadius: '50%', background: `${PROJECT_ROLE_COLOR[m.role] || accent}22`, border: `1px solid ${PROJECT_ROLE_COLOR[m.role] || accent}44`, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 10, fontWeight: 700, color: PROJECT_ROLE_COLOR[m.role] || accent, fontFamily: FONTS.mono, flexShrink: 0 }}>
                  {m.username.slice(0, 2).toUpperCase()}
                </div>
                <span style={{ fontSize: 13, color: '#e0e4ec', fontWeight: 500 }}>{m.username}</span>
              </div>

              {m.role === 'owner' ? (
                <span style={{ fontSize: 10, color: PROJECT_ROLE_COLOR.owner, background: PROJECT_ROLE_COLOR.owner + '18', border: `1px solid ${PROJECT_ROLE_COLOR.owner}44`, borderRadius: 4, padding: '2px 8px', fontFamily: FONTS.mono, fontWeight: 600, display: 'inline-block' }}>
                  Owner
                </span>
              ) : (
                <Select value={m.role} onChange={v => handleRoleChange(m.user_id, v)}
                  options={PROJECT_ROLE_ORDER.filter(r => r !== 'owner').map(r => ({ value: r, label: PROJECT_ROLE_LABEL[r] }))} />
              )}

              <div>
                {m.role !== 'owner' && (
                  <button onClick={() => handleRemove(m.user_id)} title="Remove from project"
                    style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '3px 6px', cursor: 'pointer', color: PALETTE.textGhost, display: 'flex', transition: 'all .1s' }}
                    onMouseEnter={e => { e.currentTarget.style.borderColor = '#cc2233'; e.currentTarget.style.color = '#cc2233'; }}
                    onMouseLeave={e => { e.currentTarget.style.borderColor = '#2a2d35'; e.currentTarget.style.color = '#404550'; }}>
                    <Icon name="trash" size={10} color="currentColor" />
                  </button>
                )}
              </div>
            </div>
          ))}

          {!loadingMembers && nonMembers.length > 0 && (
            <div style={{ display: 'flex', gap: 8, alignItems: 'center', padding: '12px 18px', borderTop: members.length ? '1px solid #1e2029' : 'none', background: '#090b0f' }}>
              <Icon name="plus" size={11} color="#404550" />
              <Select value={addUserId} onChange={setAddUserId} style={{ flex: 1 }}
                placeholder="Add user to project..."
                options={nonMembers.map(u => ({ value: u.id, label: u.username }))} />
              <Select value={addRole} onChange={setAddRole}
                options={PROJECT_ROLE_ORDER.filter(r => r !== 'owner').map(r => ({ value: r, label: PROJECT_ROLE_LABEL[r] }))} />
              <button onClick={handleAdd} disabled={!addUserId || adding}
                style={{ background: addUserId ? accent : PALETTE.borderSoft, border: 'none', borderRadius: 4, padding: '5px 14px', cursor: addUserId ? 'pointer' : 'default', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: FONTS.mono, whiteSpace: 'nowrap', transition: 'background .15s' }}>
                {adding ? '...' : 'Add'}
              </button>
            </div>
          )}

          {!loadingMembers && members.length > 0 && (
            <div style={{ padding: '12px 18px', borderTop: '1px solid #1e2029', background: '#07080b' }}>
              {showTransfer ? (
                <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                  <span style={{ fontSize: 10, color: PALETTE.textFaint, fontFamily: FONTS.mono, whiteSpace: 'nowrap' }}>New owner:</span>
                  <Select value={transferTo} onChange={setTransferTo} style={{ flex: 1 }}
                    placeholder="Select user..."
                    options={members.filter(m => m.role !== 'owner').map(m => ({ value: m.user_id, label: m.username }))} />
                  <button onClick={handleTransfer} disabled={!transferTo}
                    style={{ background: transferTo ? '#f09a3a' : PALETTE.borderSoft, border: 'none', borderRadius: 4, padding: '5px 12px', cursor: transferTo ? 'pointer' : 'default', color: '#fff', fontSize: 10, fontWeight: 600, fontFamily: FONTS.mono }}>
                    Transfer
                  </button>
                  <button onClick={() => { setShowTransfer(false); setTransferTo(''); }}
                    style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '5px 10px', cursor: 'pointer', color: PALETTE.textFaint, fontSize: 10, fontFamily: FONTS.mono }}>
                    Cancel
                  </button>
                </div>
              ) : (
                <button onClick={() => setShowTransfer(true)}
                  style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '5px 12px', cursor: 'pointer', color: '#505560', fontSize: 10, fontFamily: FONTS.mono, transition: 'all .12s' }}
                  onMouseEnter={e => { e.currentTarget.style.borderColor = '#f09a3a'; e.currentTarget.style.color = '#f09a3a'; }}
                  onMouseLeave={e => { e.currentTarget.style.borderColor = '#2a2d35'; e.currentTarget.style.color = '#505560'; }}>
                  Transfer ownership…
                </button>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
ProjectAccessSection.propTypes = { accent: PropTypes.string, allUsers: PropTypes.array };
