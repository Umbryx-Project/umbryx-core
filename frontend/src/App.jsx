import { useState, useEffect, useCallback, useRef, Suspense } from 'react';

function _syncNodeWithHosts(node, hosts, net) {
  const host = hosts.find(h => h.pid === net.pid && (node.host_id ? h.id === node.host_id : h.ip === node.ip));
  if (!host) return { node, changed: false };
  const next = { ...node };
  let changed = false;
  if (next.status !== host.status) { next.status = host.status; changed = true; }
  if (next.notes !== (host.notes || '')) { next.notes = host.notes || ''; changed = true; }
  const fallbackIps = host.ip ? [host.ip] : [];
  const hostIps = host.ips && host.ips.length > 0 ? host.ips : fallbackIps;
  if (JSON.stringify(next.ips || []) !== JSON.stringify(hostIps)) { next.ips = hostIps; changed = true; }
  if (JSON.stringify(next.ports || []) !== JSON.stringify(host.ports || [])) { next.ports = host.ports || []; changed = true; }
  if (next.host_id !== host.id) { next.host_id = host.id; changed = true; }
  if ((next.label === node.ip || next.label === host.ip || next.label === host.hostname || !next.label) && host.hostname) {
    if (next.label !== host.hostname) { next.label = host.hostname; changed = true; }
  }
  return { node: next, changed };
}
import ToastContainer from './components/Toast.jsx';
import { ConfirmHost } from './components/Confirm.jsx';
import RoeAlertHost from './components/RoeAlertHost.jsx';
import Icon from './components/Icon.jsx';
import { api } from './api.js';
import { useProjectStore } from './store/useProjectStore.js';
import { useSync } from './hooks/useSync.js';
import { useEntityCRUD } from './hooks/useEntityCRUD.js';
import lazyWithReload from './utils/lazyWithReload.js';
import { useProjectPermissions } from './context/ProjectPermissions.jsx';
import { TweaksPanel } from './app/AppChrome.jsx';
import { TWEAK_DEFAULTS, TWEAKS_KEY } from './app/uiConstants.js';
import { applySyncEvent, createBatchedSyncHandler } from './app/applySyncEvent.js';
import AppTopBar from './app/AppTopBar.jsx';
import LicenseBanner from './app/LicenseBanner.jsx';
import AppContextSidebar from './app/AppContextSidebar.jsx';
import AppTabRouter from './app/AppTabRouter.jsx';
import { isAttackerHost } from './utils/hostMeta.js';
import { moduleRegistry } from './features/plugins/registry.js';
import { loadExtensions } from './modules/extensionStore.js';

// Eagerly loaded — needed on first render
import LoginView from './views/LoginView.jsx';

// Lazily loaded modals
const SearchModal = lazyWithReload(() => import('./components/SearchModal.jsx'));
import ImportModal from './components/ImportModal.jsx';
import AIChatPanel from './components/AIChatPanelV2.jsx';

// ── Main App ──────────────────────────────────────────────────────────
export default function App() {
  // ── Auth state ──────────────────────────────────────────────────────
  const [authReady, setAuthReady] = useState(false);
  const [isFirstRun, setIsFirstRun] = useState(false);
  const [currentUser, setCurrentUser] = useState(null);
  const [sessionExpired, setSessionExpired] = useState(false);
  const { loadPermissions, setGlobalRole, loadOrgRoles, clearOrgRoles } = useProjectPermissions();

  useEffect(() => {
    const doCheck = async () => {
      const status = await api.authStatus();
      if (!status.initialized) { setIsFirstRun(true); setAuthReady(true); return; }
      try {
        const u = await api.authMe();
        setCurrentUser(u);
        setGlobalRole(u.role, u.role === 'platform_admin');
        loadOrgRoles();
        moduleRegistry.syncFromBackend(api.listModules);
        loadExtensions();
      } catch { /* the session is already established; this is extra profile data */ }
      setAuthReady(true);
    };
    doCheck();
    const onLogout = () => { setCurrentUser(null); setIsFirstRun(false); setSessionExpired(false); loadPermissions(null); setGlobalRole('user', false); clearOrgRoles(); };
    const onAuthExpired = () => { setCurrentUser(null); setIsFirstRun(false); setSessionExpired(true); loadPermissions(null); setGlobalRole('user', false); clearOrgRoles(); };
    globalThis.addEventListener('rt:logout', onLogout);
    globalThis.addEventListener('rt:auth-expired', onAuthExpired);
    return () => {
      globalThis.removeEventListener('rt:logout', onLogout);
      globalThis.removeEventListener('rt:auth-expired', onAuthExpired);
    };
  }, [loadPermissions]);

  const handleAuth = (user) => {
    setError(null);
    setLoading(true);
    setCurrentUser(user);
    setIsFirstRun(false);
    setGlobalRole(user.role, user.role === 'platform_admin');
    loadOrgRoles();
  };
  const handleLogout = async () => {
    try { await api.authLogout(); } catch { /* logging out locally regardless of what the server says */ }
    setCurrentUser(null);
    setError(null);
    setLoading(true);
    clearOrgRoles();
  };

  // ── UI state ─────────────────────────────────────────────────────────
  const [tweaks, setTweaks] = useState(() => {
    try { return { ...TWEAK_DEFAULTS, ...JSON.parse(localStorage.getItem(TWEAKS_KEY) || '{}') }; } catch { return TWEAK_DEFAULTS; }
  });
  const [showTweaks, setShowTweaks] = useState(false);
  const [tab, setTabState] = useState(() => {
    const hash = window.location.hash.slice(1);
    return hash || localStorage.getItem('rt_tab') || 'projects';
  });
  const setTab = useCallback((newTab) => {
    setTabState(newTab);
    localStorage.setItem('rt_tab', newTab);
    if (window.location.hash.slice(1) !== newTab) {
      window.location.hash = newTab;
    }
  }, []);
  const [focusId, setFocusId] = useState(null);
  const [selectedProject, setSelectedProject] = useState(() => localStorage.getItem('rt_project') || '');
  const [jobsFilter, setJobsFilter] = useState(null);
  const [showSearch, setShowSearch] = useState(false);
  const [onlineUsers, setOnlineUsers] = useState([]);
  const [importProjectId, setImportProjectId] = useState(null);
  const [presence, setPresence] = useState([]);
  const [aiEnabled, setAiEnabled] = useState(true);
  const [networkMapExpanded, setNetworkMapExpanded] = useState(false);

  // Expanded-map mode only makes sense on the Network Map tab — drop it
  // automatically if the user navigates away, so returning to the tab
  // later doesn't unexpectedly restore full-tab mode.
  useEffect(() => {
    if (tab !== 'network' && networkMapExpanded) setNetworkMapExpanded(false);
  }, [tab]); // eslint-disable-line react-hooks/exhaustive-deps

  const navigateTo = useCallback((view, focus) => {
    setTab(view);
    setFocusId(focus || null);
  }, []);

  // ── Project data (Zustand) ───────────────────────────────────────────
  const {
    projects, setProjects,
    notes, setNotes,
    hosts, setHosts,
    creds, setCreds,
    setNetworks,
    findings, setFindings,
    objectives, setObjectives,
    attackPaths, setAttackPaths,
    setAttackSteps,
    loots, setLoots,
    scopes, setScopes,
    setHostActivities,
  } = useProjectStore();

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [jobs, setJobs] = useState([]);

  // ── CRUD actions ─────────────────────────────────────────────────────
  const crud = useEntityCRUD({ selectedProject, setSelectedProject });

  // ── Effects ───────────────────────────────────────────────────────────
  useEffect(() => {
    if (!currentUser) return;
    let cancelled = false;
    setError(null);
    setLoading(true);
    Promise.all([
      api.getProjects(), api.getNotes(), api.getHosts(), api.getCreds(),
      api.getNetworks(), api.getFindings(), api.getObjectives(),
      api.getAttackPaths(), api.getAttackSteps(), api.getLoots(),
      api.getScopes(), api.getHostActivities(),
    ])
      .then(([p, n, h, c, nets, f, obj, aps, ass, lts, scs, acts]) => {
        if (cancelled) return;
        setProjects(p); setNotes(n); setHosts(h); setCreds(c); setNetworks(nets);
        setFindings(f); setObjectives(obj); setAttackPaths(aps); setAttackSteps(ass);
        setLoots(lts); setScopes(scs); setHostActivities(acts);
        setSelectedProject(prev => prev || p[0]?.id || '');
        setLoading(false);
      })
      .catch(e => { if (!cancelled) { setError(e.message); setLoading(false); } });
    return () => { cancelled = true; };
  }, [currentUser]);

  useEffect(() => {
    if (!currentUser) return;
    let cancelled = false;
    const load = () => {
      api.getAIStatus()
        // Show AI chat only when AI is enabled AND at least one provider is
        // configured — otherwise the chat button opens a panel that can't do
        // anything (no provider to call).
        .then(s => { if (!cancelled) setAiEnabled(s?.enabled !== false && s?.has_providers === true); })
        .catch(() => { if (!cancelled) setAiEnabled(false); });
    };
    load();
    const handler = () => load();
    globalThis.addEventListener('rt:ai_status_changed', handler);
    return () => { cancelled = true; globalThis.removeEventListener('rt:ai_status_changed', handler); };
  }, [currentUser]);

  // ── Hash-based routing (browser back/forward, deep links) ───────────
  useEffect(() => {
    const handler = () => {
      const hash = window.location.hash.slice(1);
      if (hash && hash !== tab) {
        setTabState(hash);
        localStorage.setItem('rt_tab', hash);
      }
    };
    window.addEventListener('hashchange', handler);
    return () => window.removeEventListener('hashchange', handler);
  }, [tab]);

  useEffect(() => {
    localStorage.setItem(TWEAKS_KEY, JSON.stringify(tweaks));
    const color = encodeURIComponent(tweaks.accent);
    const svg = `<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><rect width='32' height='32' rx='7' fill='%2308090b'/><path d='M16 4 L27 8 L27 17 C27 23 22 28 16 30 C10 28 5 23 5 17 L5 8 Z' fill='${color}' opacity='0.22'/><path d='M16 4 L27 8 L27 17 C27 23 22 28 16 30 C10 28 5 23 5 17 L5 8 Z' fill='none' stroke='${color}' stroke-width='1.5'/><path d='M11 16 L14.5 19.5 L21 13' stroke='${color}' stroke-width='2' stroke-linecap='round' stroke-linejoin='round' fill='none'/></svg>`;
    const link = document.getElementById('favicon-link');
    if (link) { link.href = `data:image/svg+xml,${svg}`; }
  }, [tweaks]);

  useEffect(() => { localStorage.setItem('rt_tab', tab); }, [tab]);

  useEffect(() => {
    if (!currentUser) return;
    const fetchPresence = () => api.getPresence().then(r => setOnlineUsers(r.online || [])).catch(() => {});
    fetchPresence();
    const iv = setInterval(fetchPresence, 20000);
    return () => clearInterval(iv);
  }, [currentUser]);

  useEffect(() => {
    const onKey = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') { e.preventDefault(); setShowSearch(v => !v); }
      if (e.key === 'Escape') {
        setShowSearch(false);
        setNetworkMapExpanded(false);
      }
    };
    globalThis.addEventListener('keydown', onKey);
    return () => globalThis.removeEventListener('keydown', onKey);
  }, []);

  useEffect(() => { if (selectedProject) localStorage.setItem('rt_project', selectedProject); }, [selectedProject]);
  useEffect(() => {
    if (!currentUser) return;
    loadPermissions(selectedProject || null);
  }, [selectedProject, loadPermissions, currentUser]);

  useEffect(() => {
    const onRefresh = () => {
      Promise.all([api.getHosts(), api.getCreds()]).then(([h, c]) => { setHosts(h); setCreds(c); }).catch(() => {});
    };
    globalThis.addEventListener('rt:refresh', onRefresh);
    return () => globalThis.removeEventListener('rt:refresh', onRefresh);
  }, []);

  useEffect(() => {
    return () => {
      Object.values(crud.netSaveTimers.current).forEach(clearTimeout);
      crud.netSaveTimers.current = {};
    };
  }, []);

  // ── WebSocket sync ────────────────────────────────────────────────────
  const localOps = useRef(new Set());
  const markLocalOp = useCallback((id) => { if (id) localOps.current.add(id); }, []);

  const updateOneNetwork = useCallback((networkId, updater) => {
    setNetworks(prev => prev.map(net => net.id === networkId ? updater(net) : net));
  }, [setNetworks]);

  const syncCtx = {
    localOps, setNotes, setHosts, setCreds, setNetworks, setFindings,
    setObjectives, setAttackPaths, setAttackSteps, setLoots, setScopes,
    setHostActivities, setJobs, setProjects, updateOneNetwork,
  };

  const handleSyncEvent = useCallback(createBatchedSyncHandler(syncCtx), [
    setAttackPaths, setAttackSteps, setCreds, setFindings, setHostActivities, setHosts, setJobs, setLoots, setNetworks, setNotes, setObjectives, setProjects, setScopes, updateOneNetwork,
  ]);

  useEffect(() => () => handleSyncEvent.cancel?.(), [handleSyncEvent]);

  const { send: sendWs } = useSync(selectedProject, currentUser?.username, handleSyncEvent, setPresence);
  const sendFocus = useCallback((noteId) => sendWs(noteId ? { type: 'focus', note_id: noteId } : { type: 'blur' }), [sendWs]);

  useEffect(() => {
    const onSetView = (e) => {
      const view = e.detail?.view;
      sendWs(view ? { type: 'view', view } : { type: 'unview' });
    };
    globalThis.addEventListener('rt:set-view', onSetView);
    return () => globalThis.removeEventListener('rt:set-view', onSetView);
  }, [sendWs]);

  // ── Sync hosts → network nodes ────────────────────────────────────────
  useEffect(() => {
    setNetworks(prev => prev.map(net => {
      let changed = false;
      const nodes = [];
      for (const node of (net.nodes || [])) {
        const { node: next, changed: c } = _syncNodeWithHosts(node, hosts, net);
        changed = changed || c;
        nodes.push(next);
      }
      return changed ? { ...net, nodes } : net;
    }));
  }, [hosts]);

  // ── Import modal refresh ──────────────────────────────────────────────
  const handleImported = async () => {
    const [n, h, c, nets, f, obj, aps, ass, lts, scs, acts] = await Promise.all([
      api.getNotes(), api.getHosts(), api.getCreds(), api.getNetworks(),
      api.getFindings(), api.getObjectives(), api.getAttackPaths(),
      api.getAttackSteps(), api.getLoots(), api.getScopes(), api.getHostActivities(),
    ]);
    setNotes(n); setHosts(h); setCreds(c); setNetworks(nets); setFindings(f);
    setObjectives(obj); setAttackPaths(aps); setAttackSteps(ass);
    setLoots(lts); setScopes(scs); setHostActivities(acts);
  };

  // ── Derived ───────────────────────────────────────────────────────────
  const acc = tweaks.accent;
  const green = tweaks.accentGreen;
  const fs = tweaks.fontSize;
  // Interface scale via CSS zoom — the old root fontSize was dead (every
  // component sets explicit px inline). 14px = 100%. See EE for details.
  const uiZoom = fs / TWEAK_DEFAULTS.fontSize;

  const badges = {
    notes:      notes.filter(n => n.pid === selectedProject && n.starred).length,
    hosts:      hosts.filter(h => h.pid === selectedProject && !isAttackerHost(h) && (h.status === 'pwned' || h.status === 'owned')).length,
    creds:      creds.filter(c => c.pid === selectedProject && c.cracked).length,
    findings:   findings.filter(f => f.pid === selectedProject && (f.severity === 'critical' || f.severity === 'high') && f.status === 'open').length,
    objectives: objectives.filter(o => o.pid === selectedProject && (o.status === 'captured' || o.status === 'in_progress')).length,
    attackpath: attackPaths.filter(p => p.pid === selectedProject).length,
    loot:       loots.filter(l => l.pid === selectedProject).length,
    scope:      scopes.filter(s => s.pid === selectedProject).length,
    jobs:       jobs.filter(j => j.pid === selectedProject && (j.status === 'running' || j.status === 'queued')).length,
    network: 0, attackgraph: 0, projects: 0, report: 0, checklist: 0, timeline: 0, cheatsheet: 0, scans: 0,
  };

  const refreshHosts = useCallback(() => api.getHosts().then(h => setHosts(h)), []);
  const refreshNetworks = useCallback(() => api.getNetworks().then(nets => setNetworks(nets)), []);

  // network/edges_updated carries no payload (see applySyncEvent), so the
  // only way to pick up a rewritten edge set is to refetch.
  useEffect(() => {
    const onEdges = () => { refreshNetworks().catch(() => {}); };
    globalThis.addEventListener('rt:network-edges-updated', onEdges);
    return () => globalThis.removeEventListener('rt:network-edges-updated', onEdges);
  }, [refreshNetworks]);
  const updateTweak = (key, val) => setTweaks(t => ({ ...t, [key]: val }));

  // ── Auth guards ───────────────────────────────────────────────────────
  if (!authReady) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', width: '100%', height: '100%', color: '#404550', flexDirection: 'column', gap: 12 }}>
      <Icon name="shield" size={32} color={acc} />
      <div style={{ fontSize: 12, fontFamily: 'JetBrains Mono' }}>Connecting...</div>
    </div>
  );

  if (!currentUser) return <LoginView accent={acc} isFirstRun={isFirstRun} onAuth={handleAuth} sessionExpired={sessionExpired} />;

  if (loading) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', width: '100%', height: '100%', color: '#404550', flexDirection: 'column', gap: 12 }}>
      <Icon name="shield" size={32} color={acc} />
      <div style={{ fontSize: 12, fontFamily: 'JetBrains Mono' }}>Loading...</div>
    </div>
  );

  if (error) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', width: '100%', height: '100%', color: '#cc2233', flexDirection: 'column', gap: 12 }}>
      <Icon name="warning" size={32} color="#cc2233" />
      <div style={{ fontSize: 12, fontFamily: 'JetBrains Mono' }}>Error: {error}</div>
    </div>
  );

  const mapExpanded = networkMapExpanded && tab === 'network';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', width: '100%', height: '100%', zoom: uiZoom, background: '#08090b' }}>
      {!mapExpanded && (
        <AppTopBar
          tab={tab} setTab={setTab}
          accent={acc} badges={badges}
          showSearch={showSearch} setShowSearch={setShowSearch}
          showTweaks={showTweaks} setShowTweaks={setShowTweaks}
          currentUser={currentUser}
          onLogout={handleLogout}
        />
      )}

      {!mapExpanded && <LicenseBanner />}

      <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
        {!mapExpanded && (
          <AppContextSidebar
            tab={tab}
            projects={projects} notes={notes} hosts={hosts} creds={creds}
            selectedProject={selectedProject} onSelectProject={setSelectedProject}
            accent={acc}
            presence={presence}
          />
        )}

        <AppTabRouter
          tab={tab} setTab={setTab}
          focusId={focusId} consumeFocusId={() => setFocusId(null)}
          accent={acc} accentGreen={green} fontSize={fs}
          animateLinks={!!tweaks.networkMapAnimations}
          selectedProject={selectedProject} setSelectedProject={setSelectedProject}
          currentUser={currentUser} setCurrentUser={setCurrentUser}
          onlineUsers={onlineUsers}
          jobs={jobs} setJobs={setJobs}
          jobsFilter={jobsFilter} setJobsFilter={setJobsFilter}
          presence={presence}
          markLocalOp={markLocalOp}
          refreshHosts={refreshHosts}
          refreshNetworks={refreshNetworks}
          sendFocus={sendFocus}
          setImportProjectId={setImportProjectId}
          crud={crud}
          networkMapExpanded={mapExpanded}
          setNetworkMapExpanded={setNetworkMapExpanded}
          onNavigate={navigateTo}
        />
      </div>

      {showTweaks && <TweaksPanel tweaks={tweaks} updateTweak={updateTweak} onClose={() => setShowTweaks(false)} left={'auto'} right={12} top={78} />}

      {showSearch && (
        <Suspense fallback={null}>
          <SearchModal accent={acc} selectedProject={selectedProject} projects={projects}
            onNavigate={(view, focus) => navigateTo(view, focus)}
            onClose={() => setShowSearch(false)} />
        </Suspense>
      )}

      {importProjectId && (
        <ImportModal projectId={importProjectId} accent={acc}
          onClose={() => setImportProjectId(null)}
          onImported={handleImported} />
      )}

      {!mapExpanded && selectedProject && aiEnabled && <AIChatPanel selectedProject={selectedProject} accent={acc} />}

      <ToastContainer />
      <ConfirmHost />
      <RoeAlertHost />
    </div>
  );
}
