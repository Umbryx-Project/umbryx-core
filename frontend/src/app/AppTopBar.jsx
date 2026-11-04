import PropTypes from 'prop-types';
import { useMemo, useState, useEffect, useCallback, useRef } from 'react';
import Icon from '../components/Icon.jsx';
import { EE_INFRA_TABS } from '@ee';
import { TABS, TAB_GROUPS, groupForTab } from '../constants.js';
import { getVisibleTabs } from '../features/visibility/zones.js';
import { useProjectPermissions } from '../context/ProjectPermissions.jsx';
import { useEntitlement } from '../hooks/useEntitlement.js';

function NotificationBell({ accent }) {
  const [count, setCount] = useState(0);
  const [items, setItems] = useState([]);
  const [open, setOpen] = useState(false);
  const dropRef = useRef(null);

  const fetchCount = useCallback(() => {
    import('../api.js').then(({ api }) => api.getUnreadCount().then(r => setCount(r.count ?? 0)).catch(() => {}));
  }, []);

  const fetchItems = useCallback(() => {
    import('../api.js').then(({ api }) => api.getNotifications('limit=20').then(r => setItems(r.items ?? [])).catch(() => {}));
  }, []);

  useEffect(() => {
    fetchCount();
    const id = setInterval(fetchCount, 30000);
    return () => clearInterval(id);
  }, [fetchCount]);

  useEffect(() => { if (open) fetchItems(); }, [open, fetchItems]);

  useEffect(() => {
    if (!open) return;
    const handler = (e) => { if (dropRef.current && !dropRef.current.contains(e.target)) setOpen(false); };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [open]);

  const markAllRead = () => {
    import('../api.js').then(({ api }) => api.markAllNotificationsRead().then(() => { setCount(0); fetchItems(); }).catch(() => {}));
  };

  const fmtTs = (iso) => {
    if (!iso) return '';
    const d = new Date(iso);
    const diff = Math.floor((new Date() - d) / 60000);
    if (diff < 1) return 'just now';
    if (diff < 60) return `${diff}m ago`;
    if (diff < 1440) return `${Math.floor(diff / 60)}h ago`;
    return d.toLocaleDateString();
  };

  return (
    <div ref={dropRef} style={{ position: 'relative' }}>
      <button onClick={() => setOpen(v => !v)} title="Notifications"
        style={{ background: open ? `${accent}18` : 'none', border: 'none', cursor: 'pointer', padding: '6px 8px', borderRadius: 4, display: 'flex', alignItems: 'center', gap: 4, position: 'relative' }}>
        <Icon name="bell" size={16} color={open ? accent : '#606570'} />
        {count > 0 && <span style={{ position: 'absolute', top: 2, right: 2, background: '#cc2233', color: '#fff', fontSize: 8, fontWeight: 700, borderRadius: '50%', width: 14, height: 14, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>{count > 9 ? '9+' : count}</span>}
      </button>
      {open && (
        <div style={{ position: 'absolute', top: 36, right: 0, width: 320, maxHeight: 400, background: '#12131a', border: '1px solid #1a1c22', borderRadius: 8, boxShadow: '0 8px 32px rgba(0,0,0,.5)', zIndex: 100, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          <div style={{ padding: '8px 12px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid #1a1c22' }}>
            <span style={{ fontSize: 10, color: '#c8cdd6', fontWeight: 600, fontFamily: 'JetBrains Mono', textTransform: 'uppercase', letterSpacing: '0.08em' }}>Notifications</span>
            {count > 0 && <button onClick={markAllRead} style={{ background: 'none', border: 'none', color: accent, fontSize: 9, cursor: 'pointer', fontFamily: 'JetBrains Mono' }}>Mark all read</button>}
          </div>
          <div style={{ flex: 1, overflowY: 'auto', maxHeight: 330 }}>
            {items.length === 0 && <div style={{ padding: 20, textAlign: 'center', fontSize: 10, color: '#404550' }}>No notifications</div>}
            {items.map(n => (
              <div key={n.id} style={{ padding: '8px 12px', borderBottom: '1px solid #151720', opacity: n.read ? 0.5 : 1 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 2 }}>
                  {!n.read && <span style={{ width: 5, height: 5, borderRadius: '50%', background: n.type === 'warning' ? '#f09a3a' : accent, flexShrink: 0 }} />}
                  <span style={{ fontSize: 10, color: n.read ? '#606570' : '#c8cdd6', fontWeight: 600 }}>{n.title}</span>
                </div>
                {n.body && <div style={{ fontSize: 9, color: '#606570', marginBottom: 2 }}>{n.body}</div>}
                <div style={{ fontSize: 8, color: '#353840' }}>{fmtTs(n.ts)}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
NotificationBell.propTypes = { accent: PropTypes.string };

export default function AppTopBar({
  tab, setTab,
  accent,
  badges,
  showSearch, setShowSearch,
  showTweaks, setShowTweaks,
  currentUser,
  onLogout,
}) {
  const acc = accent;
  const { role, globalRole, hasAnyOrgAdminRole } = useProjectPermissions();
  const { edition, version } = useEntitlement();
  const [adminMenuOpen, setAdminMenuOpen] = useState(false);
  const adminRef = useRef(null);

  const visibleTabs = useMemo(() => {
    const allowed = getVisibleTabs(role, globalRole);
    const isAll = allowed.includes('*');
    return TABS.filter(t => {
      if (t.id === '_sep') return false;
      if (t.id === 'projects') return true;
      if (t.id === 'system') return globalRole === 'platform_admin';
      // Every tab on that page comes from the Enterprise registry, so in a
      // Community build the page would be empty — don't offer it at all.
      if (t.id === 'platform-ops') {
        if (EE_INFRA_TABS.length === 0) return false;
        return currentUser?.role === 'platform_admin' || currentUser?.role === 'devops';
      }
      // Workstations (pool machines) and Connections (executor targets /
      // egress proxies) are ORG-level infrastructure, not project assets —
      // visibility must not depend on the role in the selected project.
      // Org owner/admin/manager/team_lead see them everywhere; project
      // managers/team-leads keep the previous project-scoped access.
      if (t.id === 'connections') return globalRole === 'platform_admin' || hasAnyOrgAdminRole;
      if (t.id === 'workstations') {
        if (globalRole === 'platform_admin' || hasAnyOrgAdminRole) return true;
        if (isAll) return true;
        return allowed.includes(t.id);
      }
      // Context is organization membership, not the currently-selected
      // project's role — those are unrelated axes. Previously checked
      // `role === 'owner' || role === 'admin'` here, which is the
      // *project* role from useProjectPermissions() — so a project owner
      // with zero organizations saw this menu, while an org
      // manager/team_lead with no elevated role on whatever project
      // happened to be selected (or no project selected at all) didn't
      // (2026-08-18).
      if (t.id === 'organizations') return globalRole === 'platform_admin' || hasAnyOrgAdminRole;
      if (t.id === 'admin') return currentUser?.role === 'platform_admin';
      if (t.id === 'audit') return currentUser?.role === 'platform_admin';
      if (isAll) return true;
      return allowed.includes(t.id);
    });
  }, [role, globalRole, currentUser?.role, hasAnyOrgAdminRole]);

  const visibleTabIds = useMemo(() => new Set(visibleTabs.map(t => t.id)), [visibleTabs]);

  const activeGroup = groupForTab(tab);
  const isAdminTab = ['audit', 'system', 'organizations', 'admin'].includes(tab);
  const showAdminMenu = visibleTabs.some(t => ['audit', 'system', 'organizations', 'admin'].includes(t.id));

  useEffect(() => {
    if (!adminMenuOpen) return;
    const handler = (e) => { if (adminRef.current && !adminRef.current.contains(e.target)) setAdminMenuOpen(false); };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [adminMenuOpen]);

  const initials = (currentUser?.display_name || currentUser?.username || '').slice(0, 2).toUpperCase();

  return (
    <div style={{ position: 'sticky', top: 0, zIndex: 50, background: '#0a0b0f', borderBottom: '1px solid #1a1c22', flexShrink: 0 }}>
      {/* Main top bar row */}
      <div style={{ display: 'flex', alignItems: 'center', height: 44, padding: '0 12px', gap: 4 }}>
        {/* Logo */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, paddingRight: 12, marginRight: 4, borderRight: '1px solid #151720', flexShrink: 0, cursor: 'pointer' }}
          onClick={() => setTab('projects')}>
          <div style={{ width: 26, height: 26, background: `${acc}20`, border: `1px solid ${acc}55`, borderRadius: 6, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Icon name="shield" size={14} color={acc} />
          </div>
          <span style={{ fontSize: 12, color: '#e0e4ec', fontFamily: 'Space Grotesk', fontWeight: 700 }}>Umbryx</span>
          {version && (
            <span
              title={`Umbryx ${version} (${edition === 'ce' ? 'Community' : 'Enterprise'} build)`}
              style={{ fontSize: 9, color: '#505560', fontFamily: 'JetBrains Mono, monospace', border: '1px solid #1e2029', borderRadius: 3, padding: '1px 5px', userSelect: 'none' }}
            >
              v{version}
            </span>
          )}
        </div>

        {/* Group tabs — scrollable */}
        <div style={{ flex: 1, minWidth: 0, display: 'flex', alignItems: 'center', gap: 2, overflowX: 'auto', scrollbarWidth: 'none' }}>
          {TAB_GROUPS.filter(g => g.label).map(group => {
            const groupTabs = group.tabs.filter(id => visibleTabIds.has(id));
            if (groupTabs.length === 0) return null;
            const isActive = activeGroup === group.label && !isAdminTab;
            return (
              <button key={group.label} onClick={() => setTab(groupTabs[0])} title={group.label}
                style={{
                  background: isActive ? `${acc}14` : 'transparent',
                  border: 'none',
                  borderBottom: isActive ? `2px solid ${acc}` : '2px solid transparent',
                  color: isActive ? acc : '#606570',
                  fontSize: 12,
                  fontWeight: isActive ? 700 : 600,
                  fontFamily: 'Space Grotesk',
                  padding: '6px 14px',
                  cursor: 'pointer',
                  borderRadius: 0,
                  whiteSpace: 'nowrap',
                  transition: 'all .15s',
                  flexShrink: 0,
                }}
                onMouseEnter={e => { if (!isActive) { e.currentTarget.style.color = '#9098a8'; e.currentTarget.style.background = '#ffffff06'; } }}
                onMouseLeave={e => { if (!isActive) { e.currentTarget.style.color = '#606570'; e.currentTarget.style.background = 'transparent'; } }}>
                {group.label}
              </button>
            );
          })}
        </div>

        {/* Right controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 4, flexShrink: 0, paddingLeft: 8, borderLeft: '1px solid #151720' }}>
          <button onClick={() => setShowSearch(v => !v)} title="Search (Ctrl+K)"
            style={{ background: showSearch ? `${acc}18` : 'none', border: 'none', cursor: 'pointer', padding: '6px 8px', borderRadius: 4, display: 'flex', alignItems: 'center', gap: 4, color: showSearch ? acc : '#606570' }}>
            <Icon name="search" size={16} color="currentColor" />
          </button>

          <NotificationBell accent={acc} />

          {showAdminMenu && (
            <div ref={adminRef} style={{ position: 'relative' }}>
              <button onClick={() => setAdminMenuOpen(v => !v)} title="Admin"
                style={{ background: isAdminTab || adminMenuOpen ? '#cc223318' : 'none', border: 'none', cursor: 'pointer', padding: '6px 8px', borderRadius: 4, display: 'flex', alignItems: 'center', color: isAdminTab || adminMenuOpen ? '#cc2233' : '#606570' }}>
                <Icon name="shield" size={16} color="currentColor" />
              </button>
              {adminMenuOpen && (
                <div style={{ position: 'absolute', top: 36, right: 0, background: '#12131a', border: '1px solid #1a1c22', borderRadius: 6, boxShadow: '0 8px 24px rgba(0,0,0,.5)', zIndex: 100, minWidth: 160, overflow: 'hidden' }}>
                  {visibleTabs.filter(t => ['audit', 'system', 'organizations', 'admin'].includes(t.id)).map(t => (
                    <button key={t.id} onClick={() => { setTab(t.id); setAdminMenuOpen(false); }}
                      style={{ display: 'flex', alignItems: 'center', gap: 8, width: '100%', padding: '8px 12px', background: tab === t.id ? '#ffffff08' : 'transparent', border: 'none', cursor: 'pointer', color: tab === t.id ? acc : '#9098a8', fontSize: 11, fontFamily: 'JetBrains Mono', textAlign: 'left' }}
                      onMouseEnter={e => { if (tab !== t.id) e.currentTarget.style.background = '#ffffff06'; }}
                      onMouseLeave={e => { if (tab !== t.id) e.currentTarget.style.background = 'transparent'; }}>
                      <Icon name={t.icon} size={14} color="currentColor" />
                      {t.label}
                    </button>
                  ))}
                </div>
              )}
            </div>
          )}

          <button onClick={() => setShowTweaks(v => !v)} title="Tweaks"
            style={{ background: showTweaks ? `${acc}18` : 'none', border: 'none', cursor: 'pointer', padding: '6px 8px', borderRadius: 4, display: 'flex', alignItems: 'center', color: showTweaks ? acc : '#606570' }}>
            <Icon name="settings" size={16} color="currentColor" />
          </button>

          <div style={{ width: 1, height: 20, background: '#151720', margin: '0 2px' }} />

          <button onClick={() => { setTab('user-settings'); }} title="User settings"
            style={{ background: 'none', border: 'none', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 6, padding: '4px 6px', borderRadius: 4 }}>
            <div style={{ width: 24, height: 24, borderRadius: '50%', background: `${acc}22`, border: `1px solid ${acc}55`, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 9, fontWeight: 700, color: acc, fontFamily: 'JetBrains Mono' }}>
              {initials}
            </div>
          </button>

          <button onClick={onLogout} title="Sign out"
            style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#303540', padding: '4px 6px', borderRadius: 4, display: 'flex', alignItems: 'center' }}
            onMouseEnter={e => { e.currentTarget.style.color = '#cc2233'; }}
            onMouseLeave={e => { e.currentTarget.style.color = '#303540'; }}>
            <Icon name="close" size={12} color="currentColor" />
          </button>
        </div>
      </div>

      {/* Sub-navigation row (level 2) */}
      {(() => {
        if (isAdminTab) return null;
        const group = TAB_GROUPS.find(g => g.label === activeGroup);
        if (!group) return null;
        const subTabs = group.tabs.filter(id => visibleTabIds.has(id));
        if (subTabs.length <= 1) return null;

        return (
          <div style={{ display: 'flex', alignItems: 'center', height: 34, padding: '0 12px', gap: 1, borderBottom: '1px solid #151720', background: '#0c0d12', overflowX: 'auto', scrollbarWidth: 'none' }}>
            {subTabs.map(tabId => {
              const t = TABS.find(x => x.id === tabId);
              if (!t) return null;
              const isActive = tab === tabId;
              const badge = badges?.[tabId] || 0;
              return (
                <button key={tabId} onClick={() => setTab(tabId)} title={t.label}
                  style={{
                    background: isActive ? `${acc}0a` : 'transparent',
                    border: 'none',
                    borderLeft: isActive ? `2px solid ${acc}` : '2px solid transparent',
                    color: isActive ? acc : '#606570',
                    fontSize: 11,
                    fontWeight: isActive ? 600 : 500,
                    fontFamily: 'JetBrains Mono',
                    padding: '4px 12px',
                    cursor: 'pointer',
                    whiteSpace: 'nowrap',
                    display: 'flex',
                    alignItems: 'center',
                    gap: 6,
                    transition: 'all .12s',
                    flexShrink: 0,
                  }}
                  onMouseEnter={e => { if (!isActive) { e.currentTarget.style.color = '#9098a8'; e.currentTarget.style.background = '#ffffff04'; } }}
                  onMouseLeave={e => { if (!isActive) { e.currentTarget.style.color = '#606570'; e.currentTarget.style.background = 'transparent'; } }}>
                  <Icon name={t.icon} size={13} color="currentColor" />
                  {t.label}
                  {badge > 0 && <span style={{ background: acc, color: '#fff', fontSize: 8, fontWeight: 700, borderRadius: '50%', width: 14, height: 14, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>{badge > 9 ? '9+' : badge}</span>}
                </button>
              );
            })}
          </div>
        );
      })()}
    </div>
  );
}

AppTopBar.propTypes = {
  tab: PropTypes.string,
  setTab: PropTypes.func,
  accent: PropTypes.string,
  badges: PropTypes.object,
  showSearch: PropTypes.func,
  setShowSearch: PropTypes.func,
  showTweaks: PropTypes.bool,
  setShowTweaks: PropTypes.func,
  currentUser: PropTypes.object,
  onLogout: PropTypes.func,
};
