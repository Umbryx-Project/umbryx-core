import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import AttackGraphView from './AttackGraphView.jsx';

// View shell: loads the derived graph, renders stats/chips, opens the
// node panel with the compromise chain, toggles frontier mode.

vi.mock('../api.js', () => ({
  api: {
    getAttackGraph: vi.fn(async () => ({
      nodes: [
        { id: 'atk', type: 'attacker', is_attacker: true, label: 'attack-box', ip: '', status: 'attacker', tags: [], os: 'Kali', ports: [], reachability: {}, privilege_info: {} },
        { id: 'cnode_c1', type: 'cred', label: 'CORP\\svc', username: 'svc', domain: 'CORP', cred_type: 'ntlm', cracked: false, is_domain: true, host_ids: ['h1'], status: 'cred', ip: '', frontier: true },
        { id: 'h1', type: 'host', label: 'WS01', ip: '10.0.0.5', status: 'access', tags: [], os: 'Windows 10', ports: [], reachability: { reachable: true, distance: 2 }, privilege_info: {} },
      ],
      edges: [
        { id: 'e1', from: 'atk', to: 'cnode_c1', kind: 'credential', cred_id: 'c1', cred_type: 'ntlm' },
        { id: 'e2', from: 'cnode_c1', to: 'h1', kind: 'credential_use', verified: true },
      ],
      privilege_paths: [],
      privilege_path_details: [],
      pivot_chains: [],
      stats: {
        hosts: 2, edges: 2, compromised: 1, cred_nodes: 1, credential_edges: 2,
        access_edges: 0, verified_access_edges: 0, pivot_route_edges: 0,
        unvalidated_creds: 1, inferred_access_edges: 0, reachable_hosts: 1,
        privilege_paths: 0, da_capable_hosts: 0, pivot_chains: 0,
      },
    })),
    getCreds: vi.fn(async () => []),
    getFindings: vi.fn(async () => ({ findings: [] })),
  },
}));

const creds = [
  { id: 'c1', username: 'svc', domain: 'CORP', type: 'ntlm', cracked: false },
];

describe('AttackGraphView', () => {
  beforeEach(() => {
    window.localStorage.clear();
  });

  it('loads the graph and renders the live-map header with stats', async () => {
    render(<AttackGraphView selectedProject="p1" accent="#39d353" />);
    await waitFor(() => expect(screen.getByText(/live map of compromise/i)).toBeTruthy());
    expect(screen.getByText('Attack Graph')).toBeTruthy();
    // stats chips render
    expect(screen.getByText('hosts')).toBeTruthy();
  });

  it('shows the frontier toggle when unvalidated creds exist', async () => {
    render(<AttackGraphView selectedProject="p1" accent="#39d353" allCreds={creds} />);
    await waitFor(() => expect(screen.getByText(/Frontier · 1/i)).toBeTruthy());
  });

  it('opens the node panel with the how-we-got-here chain on node click', async () => {
    render(<AttackGraphView selectedProject="p1" accent="#39d353" allCreds={creds} onNavigate={vi.fn()} />);
    await waitFor(() => expect(screen.getByText(/live map of compromise/i)).toBeTruthy());
    const ws01 = [...document.querySelectorAll('svg text')].find(t => t.textContent === 'WS01');
    expect(ws01).toBeTruthy();
    ws01.dispatchEvent(new MouseEvent('mousedown', { bubbles: true }));
    ws01.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    await waitFor(() => expect(screen.getByText('How we got here')).toBeTruthy());
    expect(screen.getAllByText(/attack-box/).length).toBeGreaterThan(1); // node + chain
    expect(screen.getByText(/CORP\\svc/)).toBeTruthy();
    expect(screen.getByText('Show on Network Map →')).toBeTruthy();
  });

  it('frontier mode dims confirmed nodes and opens the next-steps panel', async () => {
    render(<AttackGraphView selectedProject="p1" accent="#39d353" allCreds={creds} />);
    await waitFor(() => expect(screen.getByText(/Frontier · 1/i)).toBeTruthy());
    fireEvent.click(screen.getByText(/Frontier · 1/i));
    await waitFor(() => expect(screen.getByText(/believed but unconfirmed/i)).toBeTruthy());
    expect(screen.getByText(/hash not cracked|never validated/i)).toBeTruthy();
  });

  it('exports a PNG snapshot on the header button', async () => {
    render(<AttackGraphView selectedProject="p1" accent="#39d353" allCreds={creds} />);
    await waitFor(() => expect(screen.getByText(/live map of compromise/i)).toBeTruthy());
    const btn = screen.getByText('PNG');
    expect(btn).toBeTruthy();
    // click runs exportGraphPng against the live svg (no crash in jsdom:
    // canvas rasterization is skipped when the image never loads)
    fireEvent.click(btn);
  });
});
