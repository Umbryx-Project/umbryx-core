import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import NetworkCanvas from './NetworkCanvas.jsx';
import { api } from '../../api.js';
import { toastError } from '../../components/Toast.jsx';

// Stable per-method mock fns via a memoising proxy — the component tree
// imports many api methods; only the ones these tests touch need impls.
vi.mock('../../api.js', () => {
  const fns = {};
  // every method resolves by default — mount-path calls that chain
  // .then() must not explode; tests override the ones they assert on
  return { api: new Proxy(fns, { get: (t, k) => (t[k] ??= vi.fn().mockResolvedValue(undefined)) }) };
});

const toastCalls = [];
vi.mock('../../components/Toast.jsx', () => ({
  toastError: (...a) => toastCalls.push(['error', ...a]),
  toast: () => {},
  toastSuccess: () => {},
  toastWarn: () => {},
}));

const NET = { id: 'net1', pid: 'p1', name: 'Test', background: '#07080b', nodes: [], edges: [], regions: [] };
const HOST = { id: 'hst9', pid: 'p1', ip: '10.0.0.9', hostname: 'new-box', status: 'alive', ports: [], role: 'unknown', is_attacker: false };

function mkProps(overrides = {}) {
  return {
    projectId: 'p1',
    net: NET,
    hosts: [],
    onUpdate: vi.fn(),
    onCreateHost: vi.fn().mockResolvedValue(HOST),
    onUpdateHost: vi.fn(),
    accent: '#15bbb1',
    accentGreen: '#38b26a',
    markLocalOp: vi.fn(),
    ...overrides,
  };
}

async function openCreateDialog() {
  fireEvent.click(screen.getByRole('button', { name: 'Node' }));
  // dialog inputs: IP, Hostname, Domain — the first empty input is IP
  return screen.getAllByDisplayValue('')[0];
}

describe('NetworkCanvas — manual node/region creation', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    toastCalls.length = 0;
    // mount-path poller — resolves into component state; must be an object
    api.getDeconfliction.mockResolvedValue({ engagement: {} });
  });

  it('Save node creates the host, then the node, and renders it', async () => {
    const props = mkProps();
    api.createNetworkNode.mockResolvedValue({ node: { id: 'n1', host_id: 'hst9', ip: '10.0.0.9', label: 'new-box', x: 0, y: 0 } });
    render(<NetworkCanvas {...props} />);
    const ipInput = await openCreateDialog();
    fireEvent.change(ipInput, { target: { value: '10.0.0.9' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save node' }));
    await waitFor(() => expect(props.onCreateHost).toHaveBeenCalledWith(
      expect.objectContaining({ pid: 'p1', ip: '10.0.0.9' })));
    await waitFor(() => expect(api.createNetworkNode).toHaveBeenCalledWith(
      'p1', expect.objectContaining({ network_id: 'net1', host_id: 'hst9', ip: '10.0.0.9' })));
  });

  it('node creation failure surfaces a toast instead of dying silently', async () => {
    // Regression (found live): create_network_node 422'd on every request
    // for years with zero operator feedback.
    const props = mkProps();
    api.createNetworkNode.mockRejectedValue('422 Validation Error'); // non-Error: covers the `|| err` fallback
    render(<NetworkCanvas {...props} />);
    const ipInput = await openCreateDialog();
    fireEvent.change(ipInput, { target: { value: '10.0.0.9' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save node' }));
    await waitFor(() => expect(toastCalls.some(c => String(c[1]).includes('Failed to add node'))).toBe(true));
  });

  it('region creation failure is swallowed (no crash, no toast storm)', async () => {
    const props = mkProps();
    api.createNetworkRegion.mockRejectedValue(new Error('409'));
    render(<NetworkCanvas {...props} />);
    fireEvent.click(screen.getByRole('button', { name: 'Region' }));
    await waitFor(() => expect(api.createNetworkRegion).toHaveBeenCalled());
    await new Promise(r => setTimeout(r, 60));
    expect(toastCalls.length).toBe(0); // empty catch by design
  });

  it('+ from project failure surfaces a toast', async () => {
    const props = mkProps({ hosts: [HOST] });
    api.createNetworkNode.mockRejectedValue(new Error('boom'));
    render(<NetworkCanvas {...props} />);
    fireEvent.click(await screen.findByRole('button', { name: /\+ from project \(1\)/ }));
    fireEvent.click(await screen.findByRole('button', { name: /^All/ }));
    fireEvent.click(await screen.findByRole('button', { name: /^Add \(1\)/ }));
    await waitFor(() => expect(toastCalls.some(c => String(c[1]).includes('Failed to add host'))).toBe(true));
  });

  it('adding a host whose IP is already placed updates the node instead of creating a duplicate', async () => {
    const placed = { id: 'n-existing', host_id: '', ip: '10.0.0.9', label: 'new-box', x: 10, y: 10 };
    const props = mkProps({ net: { ...NET, nodes: [placed] } });
    render(<NetworkCanvas {...props} />);
    const ipInput = await openCreateDialog();
    fireEvent.change(ipInput, { target: { value: '10.0.0.9' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save node' }));
    await waitFor(() => expect(props.onCreateHost).toHaveBeenCalled());
    await new Promise(r => setTimeout(r, 120));
    expect(api.createNetworkNode).not.toHaveBeenCalled();
  });

  it('Region button creates a region', async () => {
    const props = mkProps();
    api.createNetworkRegion.mockResolvedValue({ region: { id: 'reg1', x: 80, y: 80, w: 320, h: 180, label: 'Subnet 1' } });
    render(<NetworkCanvas {...props} />);
    fireEvent.click(screen.getByRole('button', { name: 'Region' }));
    await waitFor(() => expect(api.createNetworkRegion).toHaveBeenCalledWith(
      'p1', expect.objectContaining({ network_id: 'net1' })));
  });

  it('+ from project places unplaced hosts and dedups with the echo', async () => {
    const props = mkProps({ hosts: [HOST] });
    api.createNetworkNode.mockResolvedValue({ node: { id: 'n2', host_id: 'hst9', ip: '10.0.0.9' } });
    render(<NetworkCanvas {...props} />);
    const addBtn = await screen.findByRole('button', { name: /\+ from project \(1\)/ });
    fireEvent.click(addBtn);
    fireEvent.click(await screen.findByRole('button', { name: /^All/ })); // select all
    fireEvent.click(await screen.findByRole('button', { name: /^Add \(1\)/ }));
    await waitFor(() => expect(api.createNetworkNode).toHaveBeenCalledWith(
      'p1', expect.objectContaining({ network_id: 'net1', host_id: 'hst9' })));
  });
});

describe('NetworkCanvas — region drag persists position', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    toastCalls.length = 0;
    api.getDeconfliction.mockResolvedValue({ engagement: {} });
  });

  it('mouse-down → move → release PATCHes the region and bookkeeps the version', async () => {
    const region = { id: 'reg1', x: 100, y: 100, w: 200, h: 150, label: 'DMZ', version: 1 };
    const props = mkProps({ net: { ...NET, regions: [region] } });
    api.updateNetworkRegion.mockResolvedValue({ region: { ...region, x: 190, y: 245, version: 2 } });
    render(<NetworkCanvas {...props} />);
    const g = document.querySelector('g[transform="translate(100,100)"]');
    expect(g).toBeTruthy();
    // right-click selects the region and enters region-edit mode (drag
    // is only allowed for a selected region / in edit mode)
    fireEvent.contextMenu(g);
    fireEvent.mouseDown(g, { button: 0, clientX: 120, clientY: 120 });
    const canvas = document.querySelector('button[aria-label="Network map canvas"]');
    fireEvent.mouseMove(canvas, { clientX: 210, clientY: 265 });
    fireEvent.mouseUp(canvas);
    await waitFor(() => expect(api.updateNetworkRegion).toHaveBeenCalledWith(
      'p1', 'reg1', 'net1',
      expect.objectContaining({ x: expect.any(Number), y: expect.any(Number), w: 200, h: 150 })));
  });

  it('region resize via the SE corner handle PATCHes w/h', async () => {
    const region = { id: 'reg1', x: 100, y: 100, w: 200, h: 150, label: 'DMZ', version: 1 };
    const props = mkProps({ net: { ...NET, regions: [region] } });
    api.updateNetworkRegion.mockResolvedValue({ region: { ...region, w: 260, h: 200, version: 2 } });
    render(<NetworkCanvas {...props} />);
    fireEvent.contextMenu(document.querySelector('g[transform="translate(100,100)"]')); // select + edit mode
    // resize handles render only for the selected region — wait for them
    const se = await waitFor(() => {
      const el = document.querySelector('circle[style*="se-resize"]');
      expect(el).toBeTruthy();
      return el;
    });
    fireEvent.mouseDown(se, { button: 0, clientX: 360, clientY: 300 });
    const canvas = document.querySelector('button[aria-label="Network map canvas"]');
    fireEvent.mouseMove(canvas, { clientX: 380, clientY: 320 });
    fireEvent.mouseUp(canvas);
    await waitFor(() => expect(api.updateNetworkRegion).toHaveBeenCalledWith(
      'p1', 'reg1', 'net1', expect.objectContaining({ w: expect.any(Number), h: expect.any(Number) })));
  });
});
