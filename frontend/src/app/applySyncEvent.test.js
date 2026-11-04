import { describe, it, expect, vi } from 'vitest';
import { applySyncEvent } from './applySyncEvent.js';

function ctx(overrides = {}) {
  return {
    localOps: { current: new Map() },
    setHosts: vi.fn(),
    setNotes: vi.fn(),
    setCreds: vi.fn(),
    setNetworks: vi.fn(),
    updateOneNetwork: vi.fn(),
    setFindings: vi.fn(),
    setObjectives: vi.fn(),
    ...overrides,
  };
}

describe('applySyncEvent — host deconfliction', () => {
  it('re-broadcasts a claim as rt:host-engagement instead of dropping it', () => {
    const seen = [];
    const h = (e) => seen.push(e.detail);
    globalThis.addEventListener('rt:host-engagement', h);
    const c = ctx();
    applySyncEvent({ entity: 'host', action: 'claim', data: { host_id: 'h1', username: 'alice' } }, c);
    globalThis.removeEventListener('rt:host-engagement', h);

    expect(seen).toHaveLength(1);
    expect(seen[0].action).toBe('claim');
    expect(seen[0].data.host_id).toBe('h1');
    // a claim carries no host row, so the host list must be left alone
    expect(c.setHosts).not.toHaveBeenCalled();
  });

  it('re-broadcasts workstation-driven engagement so the chip appears live', () => {
    const seen = [];
    const h = (e) => seen.push(e.detail);
    globalThis.addEventListener('rt:host-engagement', h);
    const c = ctx();
    applySyncEvent({ entity: 'host', action: 'engagement', data: { host_ids: ['h1', 'h2'] } }, c);
    globalThis.removeEventListener('rt:host-engagement', h);
    expect(seen).toHaveLength(1);
    expect(seen[0].data.host_ids).toEqual(['h1', 'h2']);
    expect(c.setHosts).not.toHaveBeenCalled();
  });

  it('re-broadcasts a release the same way', () => {
    const seen = [];
    const h = (e) => seen.push(e.detail);
    globalThis.addEventListener('rt:host-engagement', h);
    applySyncEvent({ entity: 'host', action: 'release', data: { host_id: 'h2' } }, ctx());
    globalThis.removeEventListener('rt:host-engagement', h);
    expect(seen[0].action).toBe('release');
  });

  it('still applies ordinary host updates to the host list', () => {
    const c = ctx();
    applySyncEvent({ entity: 'host', action: 'upsert', data: { id: 'h3', ip: '10.0.0.3' } }, c);
    expect(c.setHosts).toHaveBeenCalled();
  });
});

describe('applySyncEvent — network edge rewrites', () => {
  it('announces edges_updated for a refetch instead of dropping it', () => {
    const seen = [];
    const h = (e) => seen.push(e.detail);
    globalThis.addEventListener('rt:network-edges-updated', h);
    applySyncEvent({ entity: 'network', action: 'edges_updated', data: { source: 'c2_sync', ts: 'now' } }, ctx());
    globalThis.removeEventListener('rt:network-edges-updated', h);
    expect(seen).toHaveLength(1);
    expect(seen[0].source).toBe('c2_sync');
  });

  it('announces it for an applied snapshot too', () => {
    const seen = [];
    const h = (e) => seen.push(e.detail);
    globalThis.addEventListener('rt:network-edges-updated', h);
    applySyncEvent({ entity: 'network', action: 'edges_updated', data: { source: 'snapshot_apply' } }, ctx());
    globalThis.removeEventListener('rt:network-edges-updated', h);
    expect(seen[0].source).toBe('snapshot_apply');
  });
});

describe('applySyncEvent — pivots', () => {
  const capture = (fn) => {
    const seen = [];
    const h = (e) => seen.push(e.detail);
    globalThis.addEventListener('rt:pivots-changed', h);
    fn();
    globalThis.removeEventListener('rt:pivots-changed', h);
    return seen;
  };

  it.each(['create', 'update', 'delete', 'collected'])('announces a pivot %s', (action) => {
    const seen = capture(() =>
      applySyncEvent({ entity: 'pivot', action, data: { id: 'pvt1' } }, ctx()));
    expect(seen).toHaveLength(1);
    expect(seen[0].action).toBe(action);
    expect(seen[0].data.id).toBe('pvt1');
  });

  it('does not touch the host list for a pivot event', () => {
    const c = ctx();
    applySyncEvent({ entity: 'pivot', action: 'create', data: { id: 'pvt2' } }, c);
    expect(c.setHosts).not.toHaveBeenCalled();
  });
});


describe('applySyncEvent — own-echo skip exemptions (region vanish regression)', () => {
  // Found live: a region created on the canvas lives only in the canvas
  // draft; skipping its own region_created echo starved the parent
  // networks store, so the next incoming net snapshot replaced the draft
  // and the region disappeared until page reload.
  const localOpsCtx = () => ctx({ localOps: { current: new Set(['lid-own']) } });

  it('applies own region_created echo to the networks store', () => {
    const c = localOpsCtx();
    applySyncEvent({
      entity: 'network',
      action: 'region_created',
      data: { network_id: 'net1', region: { id: 'reg1', x: 1, version: 1 }, _lid: 'lid-own' },
    }, c);
    expect(c.updateOneNetwork).toHaveBeenCalledWith('net1', expect.any(Function));
    // and the reducer actually adds the region
    const reducer = c.updateOneNetwork.mock.calls[0][1];
    const next = reducer({ id: 'net1', regions: [] });
    expect(next.regions).toHaveLength(1);
    expect(next.regions[0].id).toBe('reg1');
  });

  it('applies own node_created and link_created echoes (idempotent by id)', () => {
    const c = localOpsCtx();
    applySyncEvent({ entity: 'network', action: 'node_created', data: { network_id: 'net1', node: { id: 'n1' }, _lid: 'lid-own' } }, c);
    applySyncEvent({ entity: 'network', action: 'link_created', data: { network_id: 'net1', link: { id: 'e1' }, _lid: 'lid-own' } }, c);
    expect(c.updateOneNetwork).toHaveBeenCalledTimes(2);
  });

  it('applies own region_updated echo (position/label convergence)', () => {
    const c = localOpsCtx();
    applySyncEvent({
      entity: 'network',
      action: 'region_updated',
      data: { network_id: 'net1', region: { id: 'reg1', x: 99, y: 99, version: 2 }, _lid: 'lid-own' },
    }, c);
    expect(c.updateOneNetwork).toHaveBeenCalledWith('net1', expect.any(Function));
    const reducer = c.updateOneNetwork.mock.calls[0][1];
    const next = reducer({ id: 'net1', regions: [{ id: 'reg1', x: 1, y: 1, version: 1 }] });
    expect(next.regions[0].x).toBe(99);
    expect(next.regions[0].version).toBe(2);
  });

  it('still skips own node position/update echoes (canvas reconciles those)', () => {
    // each mutation carries its own unique lid — the skip consumes it
    const c = ctx({ localOps: { current: new Set(['lid-pos', 'lid-upd']) } });
    applySyncEvent({ entity: 'network', action: 'node_position_updated', data: { network_id: 'net1', node_id: 'n1', position: { x: 5, y: 5 }, _lid: 'lid-pos' } }, c);
    applySyncEvent({ entity: 'network', action: 'node_updated', data: { network_id: 'net1', node: { id: 'n1' }, _lid: 'lid-upd' } }, c);
    expect(c.updateOneNetwork).not.toHaveBeenCalled();
  });

  it('still skips own echoes for non-network entities', () => {
    const c = localOpsCtx();
    applySyncEvent({ entity: 'host', action: 'upsert', data: { id: 'h1', ip: '1.2.3.4', _lid: 'lid-own' } }, c);
    expect(c.setHosts).not.toHaveBeenCalled();
  });

  it('echo exemption does not resurrect foreign echoes: unknown lid applies normally', () => {
    const c = ctx(); // empty localOps
    applySyncEvent({ entity: 'network', action: 'region_created', data: { network_id: 'net1', region: { id: 'reg2' } } }, c);
    expect(c.updateOneNetwork).toHaveBeenCalled();
  });
});
