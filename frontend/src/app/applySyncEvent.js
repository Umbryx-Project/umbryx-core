function handleNote(action, data, setNotes) {
  if (action === 'create') setNotes(prev => prev.some(x => x.id === data.id) ? prev : [data, ...prev]);
  if (action === 'update') setNotes(prev => prev.map(x => x.id === data.id ? data : x));
  if (action === 'delete') setNotes(prev => prev.filter(x => x.id !== data.id));
}

function handleHost(action, data, setHosts) {
  // Deconfliction events carry no host row — they change who is engaged,
  // which the map and the engagement widget fetch separately. 'claim' and
  // 'release' are the explicit button actions; 'engagement' is workstation
  // shell activity engaging a host automatically. Without this they arrived
  // over the socket and were dropped, so the map chip only showed up on the
  // next 30s poll or a page reload.
  if (action === 'claim' || action === 'release' || action === 'engagement') {
    globalThis.dispatchEvent(new CustomEvent('rt:host-engagement', { detail: { action, data } }));
    return;
  }
  if (action === 'create') setHosts(prev => prev.some(x => x.id === data.id) ? prev : [...prev, data]);
  if (action === 'update') setHosts(prev => prev.map(x => x.id === data.id ? data : x));
  if (action === 'upsert') setHosts(prev => prev.some(x => x.id === data.id) ? prev.map(x => x.id === data.id ? data : x) : [...prev, data]);
  if (action === 'delete') setHosts(prev => prev.filter(x => x.id !== data.id));
}

function handleCred(action, data, setCreds) {
  if (action === 'create') setCreds(prev => prev.some(x => x.id === data.id) ? prev : [...prev, data]);
  if (action === 'update') setCreds(prev => prev.map(x => x.id === data.id ? data : x));
  if (action === 'delete') setCreds(prev => prev.filter(x => x.id !== data.id));
}

function applyNodeUpdated(net, data) {
  return {
    ...net,
    nodes: (net.nodes || []).map(node => {
      if (node.id !== data.node.id) return node;
      if ((node.version || 0) > (data.node.version || 0)) return node;
      return { ...node, ...data.node };
    }),
  };
}

function applyNodePositionUpdated(net, data) {
  return {
    ...net,
    nodes: (net.nodes || []).map(node => {
      if (node.id !== data.node_id) return node;
      if ((node.version || 0) > (data.version || 0)) return node;
      return {
        ...node,
        x: data.position.x,
        y: data.position.y,
        manually_positioned: data.manually_positioned,
        auto_positioned: !data.manually_positioned,
        updated_at: data.updated_at,
        version: data.version,
      };
    }),
  };
}

function applyRegionUpdated(net, data) {
  return {
    ...net,
    regions: (net.regions || []).map(region => {
      if (region.id !== data.region.id) return region;
      if ((region.version || 0) > (data.region.version || 0)) return region;
      return { ...region, ...data.region };
    }),
  };
}

function applyLinkUpdated(net, data) {
  return {
    ...net,
    edges: (net.edges || []).map(edge => {
      if (edge.id !== data.link.id) return edge;
      if ((edge.version || 0) > (data.link.version || 0)) return edge;
      return { ...edge, ...data.link };
    }),
  };
}

function applyLayoutApplied(net, data) {
  if (net.id !== data.network.id) return net;
  const _RANK = { unknown: 0, alive: 1, up: 2, scanned: 3, access: 4, owned: 5, pwned: 5, attacker: 6 };
  const statusById = new Map((net.nodes || []).map(n => [n.id, n.status]));
  const statusByHostId = new Map((net.nodes || []).map(n => n.host_id ? [n.host_id, n.status] : null).filter(Boolean));
  const nodes = (data.network.nodes || []).map(n => {
    const cur = statusById.get(n.id) ?? statusByHostId.get(n.host_id);
    const inc = n.status;
    const status = cur && (_RANK[cur] ?? 0) >= (_RANK[inc] ?? 0) ? cur : inc;
    return { ...n, status };
  });
  return { ...data.network, nodes };
}

function handleNetworkNodeActions(action, data, updateOneNetwork) {
  if (action === 'node_created') {
    updateOneNetwork(data.network_id, net => ({
      ...net,
      nodes: net.nodes?.some(node => node.id === data.node.id) ? net.nodes : [...(net.nodes || []), data.node],
    }));
  }
  if (action === 'node_updated') updateOneNetwork(data.network_id, net => applyNodeUpdated(net, data));
  if (action === 'node_position_updated') updateOneNetwork(data.network_id, net => applyNodePositionUpdated(net, data));
  if (action === 'node_deleted') {
    updateOneNetwork(data.network_id, net => ({
      ...net,
      nodes: (net.nodes || []).filter(node => node.id !== data.node_id),
      edges: (net.edges || []).filter(edge => edge.from !== data.node_id && edge.to !== data.node_id && !(data.deleted_edge_ids || []).includes(edge.id)),
    }));
  }
}

function handleNetworkLinkActions(action, data, updateOneNetwork) {
  if (action === 'link_created') {
    updateOneNetwork(data.network_id, net => ({
      ...net,
      edges: net.edges?.some(edge => edge.id === data.link.id) ? net.edges : [...(net.edges || []), data.link],
    }));
  }
  if (action === 'link_updated') updateOneNetwork(data.network_id, net => applyLinkUpdated(net, data));
  if (action === 'link_deleted') {
    updateOneNetwork(data.network_id, net => ({
      ...net,
      edges: (net.edges || []).filter(edge => edge.id !== data.link_id),
    }));
  }
}

function handleNetworkRegionActions(action, data, updateOneNetwork) {
  if (action === 'region_created') {
    updateOneNetwork(data.network_id, net => ({
      ...net,
      regions: net.regions?.some(region => region.id === data.region.id) ? net.regions : [...(net.regions || []), data.region],
    }));
  }
  if (action === 'region_updated') updateOneNetwork(data.network_id, net => applyRegionUpdated(net, data));
  if (action === 'region_deleted') {
    updateOneNetwork(data.network_id, net => ({
      ...net,
      regions: (net.regions || []).filter(region => region.id !== data.region_id),
    }));
  }
}

function handleNetworkLayoutActions(action, data, setNetworks) {
  // C2 session sync and snapshot apply rewrite the edge set wholesale and
  // announce it without a payload, so there is nothing to patch in — the
  // networks have to be refetched. This was previously unhandled, which left
  // C2-derived links and applied snapshots invisible until a page reload.
  if (action === 'edges_updated') {
    globalThis.dispatchEvent(new CustomEvent('rt:network-edges-updated', { detail: data }));
  }
  if (action === 'layout_applied' || action === 'topology_rebuilt') {
    if (data.network) setNetworks(prev => prev.map(net => applyLayoutApplied(net, data)));
  }
  if (action === 'layout_reset') {
    if (data.network) setNetworks(prev => prev.map(net => net.id === data.network.id ? data.network : net));
  }
}

function handleNetwork(action, data, setNetworks, updateOneNetwork) {
  if (action === 'create') setNetworks(prev => prev.some(x => x.id === data.id) ? prev : [...prev, data]);
  if (action === 'update') setNetworks(prev => prev.map(x => x.id === data.id ? data : x));
  if (action === 'delete') setNetworks(prev => prev.filter(x => x.id !== data.id));
  handleNetworkNodeActions(action, data, updateOneNetwork);
  handleNetworkLinkActions(action, data, updateOneNetwork);
  handleNetworkRegionActions(action, data, updateOneNetwork);
  handleNetworkLayoutActions(action, data, setNetworks);
}

function handleFinding(action, data, setFindings) {
  if (action === 'create') setFindings(prev => prev.some(x => x.id === data.id) ? prev : [...prev, data]);
  if (action === 'update') setFindings(prev => prev.map(x => x.id === data.id ? data : x));
  if (action === 'delete') setFindings(prev => prev.filter(x => x.id !== data.id));
}

function handleObjective(action, data, setObjectives) {
  if (action === 'create') setObjectives(prev => prev.some(x => x.id === data.id) ? prev : [...prev, data]);
  if (action === 'update') setObjectives(prev => prev.map(x => x.id === data.id ? data : x));
  if (action === 'delete') setObjectives(prev => prev.filter(x => x.id !== data.id));
}

function handleAttackPath(action, data, setAttackPaths) {
  if (action === 'create') setAttackPaths(prev => prev.some(x => x.id === data.id) ? prev : [...prev, data]);
  if (action === 'update') setAttackPaths(prev => prev.map(x => x.id === data.id ? data : x));
  if (action === 'delete') setAttackPaths(prev => prev.filter(x => x.id !== data.id));
}

function handleAttackStep(action, data, setAttackSteps) {
  if (action === 'create') setAttackSteps(prev => prev.some(x => x.id === data.id) ? prev : [...prev, data]);
  if (action === 'update') setAttackSteps(prev => prev.map(x => x.id === data.id ? data : x));
  if (action === 'delete') setAttackSteps(prev => prev.filter(x => x.id !== data.id));
}

function handleLoot(action, data, setLoots) {
  if (action === 'create') setLoots(prev => prev.some(x => x.id === data.id) ? prev : [data, ...prev]);
  if (action === 'update') setLoots(prev => prev.map(x => x.id === data.id ? data : x));
  if (action === 'delete') setLoots(prev => prev.filter(x => x.id !== data.id));
}

function handleScope(action, data, setScopes) {
  if (action === 'create') setScopes(prev => prev.some(x => x.id === data.id) ? prev : [...prev, data]);
  if (action === 'update') setScopes(prev => prev.map(x => x.id === data.id ? data : x));
  if (action === 'delete') setScopes(prev => prev.filter(x => x.id !== data.id));
}

function handleHostActivity(action, data, setHostActivities) {
  if (action === 'create') setHostActivities(prev => prev.some(x => x.id === data.id) ? prev : [data, ...prev]);
  if (action === 'update') setHostActivities(prev => prev.map(x => x.id === data.id ? data : x));
  if (action === 'delete') setHostActivities(prev => prev.filter(x => x.id !== data.id));
}

function handleJob(action, data, setJobs) {
  if (action === 'create') setJobs(prev => prev.some(x => x.id === data.id) ? prev : [data, ...prev]);
  if (action === 'update') setJobs(prev => prev.map(x => x.id === data.id ? data : x));
  if (action === 'delete') setJobs(prev => prev.filter(x => x.id !== data.id));
}

function handleProject(action, data, { setProjects, setNotes, setHosts, setCreds, setNetworks, setHostActivities }) {
  if (action === 'update') setProjects(prev => prev.map(x => x.id === data.id ? data : x));
  if (action === 'delete') {
    setProjects(prev => prev.filter(x => x.id !== data.id));
    setNotes(prev => prev.filter(x => x.pid !== data.id));
    setHosts(prev => prev.filter(x => x.pid !== data.id));
    setCreds(prev => prev.filter(x => x.pid !== data.id));
    setNetworks(prev => prev.filter(x => x.pid !== data.id));
    setHostActivities(prev => prev.filter(x => x.pid !== data.id));
  }
}

function dispatchCoreEntities(entity, action, data, ctx) {
  const { setNotes, setHosts, setCreds, setNetworks, updateOneNetwork, setFindings, setObjectives } = ctx;
  if (entity === 'note') handleNote(action, data, setNotes);
  if (entity === 'host') handleHost(action, data, setHosts);
  if (entity === 'cred') handleCred(action, data, setCreds);
  if (entity === 'network') handleNetwork(action, data, setNetworks, updateOneNetwork);
  if (entity === 'finding') handleFinding(action, data, setFindings);
  if (entity === 'objective') handleObjective(action, data, setObjectives);
}

function dispatchExtendedEntities(entity, action, data, ctx) {
  const { setAttackPaths, setAttackSteps, setLoots, setScopes, setHostActivities, setJobs, setProjects, setNotes, setHosts, setCreds, setNetworks } = ctx;
  if (entity === 'attack_path') handleAttackPath(action, data, setAttackPaths);
  if (entity === 'attack_step') handleAttackStep(action, data, setAttackSteps);
  if (entity === 'loot') handleLoot(action, data, setLoots);
  if (entity === 'scope') handleScope(action, data, setScopes);
  if (entity === 'host_activity') handleHostActivity(action, data, setHostActivities);
  if (entity === 'job') handleJob(action, data, setJobs);
  if (entity === 'project') handleProject(action, data, { setProjects, setNotes, setHosts, setCreds, setNetworks, setHostActivities });
  if (entity === 'playbook_run') {
    globalThis.dispatchEvent(new CustomEvent('rt:playbook_run', { detail: { action, data } }));
  }
  if (entity === 'infra.step') {
    globalThis.dispatchEvent(new CustomEvent('rt:infra-step', { detail: data }));
  }
  if (entity === 'infra.stack') {
    globalThis.dispatchEvent(new CustomEvent('rt:infra-stack', { detail: data }));
  }
  // Pivot observations drive the PIVOT/SOCKS chips on the map and the pivot
  // panel, but they live in NetworkView's own state rather than this context,
  // so announce the change and let that view refetch.
  if (entity === 'pivot') {
    globalThis.dispatchEvent(new CustomEvent('rt:pivots-changed', { detail: { action, data } }));
  }
}

export function applySyncEvent(msg, ctx) {
  if (msg?.type === 'batch' && Array.isArray(msg?.events)) {
    for (const ev of msg.events) {
      applySyncEvent({ ...ev, pid: msg.pid }, ctx);
    }
    return;
  }

  const { localOps } = ctx;
  const { entity, action, data } = msg;

  if (data?._lid && localOps.current.has(data._lid)) {
    localOps.current.delete(data._lid);
    // Own-echo skip — but never for network creates, and not for
    // region_updated. Found live: a region created on the canvas lives
    // only in the canvas draft (emit persist:false); skipping its
    // region_created echo meant the parent networks store never learned
    // it existed, so the NEXT incoming net snapshot (any event — the
    // deferred one after a drag, a teammate edit) replaced the draft and
    // the region vanished until page reload. The create handlers dedup
    // by id, so re-applying an echo is a no-op for stores that already
    // have the entity and a heal for stores that don't. region_updated
    // echoes converge the store's position/label (version-guarded);
    // node/link updates keep the skip — the canvas reconciles those via
    // lastSentPos + version bookkeeping.
    const exempt =
      (entity === 'network' && action.endsWith('_created')) ||
      (entity === 'network' && action === 'region_updated');
    if (!exempt) return;
  }

  dispatchCoreEntities(entity, action, data, ctx);
  dispatchExtendedEntities(entity, action, data, ctx);
}

export function createBatchedSyncHandler(ctx) {
  const buffer = [];
  let rafId = null;

  const flush = () => {
    rafId = null;
    const events = buffer.splice(0);
    if (!events.length) return;
    for (const msg of events) {
      if (msg?.type === 'batch' && Array.isArray(msg?.events)) {
        for (const ev of msg.events) {
          buffer.push({ ...ev, pid: msg.pid });
        }
      } else {
        applySyncEvent(msg, ctx);
      }
    }
    if (buffer.length) {
      rafId = requestAnimationFrame(flush);
    }
  };

  const batched = (msg) => {
    buffer.push(msg);
    if (rafId === null) {
      rafId = requestAnimationFrame(flush);
    }
  };

  batched.flush = () => {
    if (rafId !== null) {
      cancelAnimationFrame(rafId);
      rafId = null;
    }
    const events = buffer.splice(0);
    for (const msg of events) {
      applySyncEvent(msg, ctx);
    }
  };

  batched.cancel = () => {
    if (rafId !== null) {
      cancelAnimationFrame(rafId);
      rafId = null;
    }
    buffer.length = 0;
  };

  return batched;
}
