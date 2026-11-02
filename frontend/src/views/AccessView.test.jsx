import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import AccessView from './AccessView.jsx';

vi.mock('../api.js', () => ({
  api: { projectAccessInfo: vi.fn() },
}));

import { api } from '../api.js';

describe('AccessView', () => {
  beforeEach(() => vi.clearAllMocks());

  it('renders C2, infra and machine sections with no emoji glyphs', async () => {
    api.projectAccessInfo.mockResolvedValue({
      c2: [{ id: 'c2-1', type: 'adaptix', name: 'ops-adaptix', how_to: 'connect via client', url: 'edge:443', username: 'operator', password: 'hunter2' }],
      infra: [{ id: 'i-1', service: 'redirector', role: 'edge', stack: 'test55', stack_status: 'ready', url: 'https://edge.example', username: 'admin', secret: 's3cr3t' }],
      machines: [{ id: 'm-1', name: 'ws-01', address: '10.0.0.5', status: 'ready', ssh_cmd: 'ssh root@10.0.0.5', my_access: true }],
    });
    render(<AccessView pid="p1" accent="#15bbb1" />);

    expect(await screen.findByText('ops-adaptix')).toBeTruthy();
    expect(screen.getByText('adaptix')).toBeTruthy();
    expect(screen.getByText('operator')).toBeTruthy();
    // password is masked by default (secret) — the raw value isn't in the DOM yet
    expect(screen.queryByText('hunter2')).toBeFalsy();

    expect(screen.getByText('redirector')).toBeTruthy();
    expect(screen.getByText('test55 · ready')).toBeTruthy();

    expect(screen.getByText('ws-01')).toBeTruthy();
    expect(screen.getByText('10.0.0.5')).toBeTruthy();
    expect(screen.getByText('your key installed')).toBeTruthy();

    // regression guard: no emoji glyphs anywhere in the rendered tree
    expect(document.body.innerHTML).not.toMatch(/[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}]/u);
  });

  it('reveals a secret value on eye toggle click', async () => {
    api.projectAccessInfo.mockResolvedValue({
      c2: [{ id: 'c2-1', type: 'adaptix', name: 'ops', password: 'hunter2' }],
      infra: [], machines: [],
    });
    render(<AccessView pid="p1" accent="#15bbb1" />);

    await screen.findByText('ops');
    expect(screen.queryByText('hunter2')).toBeFalsy();
    fireEvent.click(screen.getByTitle('show'));
    await waitFor(() => expect(screen.getByText('hunter2')).toBeTruthy());
  });

  it('shows empty state with no project selected', () => {
    render(<AccessView pid={null} accent="#15bbb1" />);
    expect(screen.getByText('No project selected')).toBeTruthy();
  });

  it('shows empty state when project has no access entries', async () => {
    api.projectAccessInfo.mockResolvedValue({ c2: [], infra: [], machines: [] });
    render(<AccessView pid="p1" accent="#15bbb1" />);
    expect(await screen.findByText('No access entries for this project')).toBeTruthy();
  });
});

describe('AccessView — dropped payload gate', () => {
  it('shows the locked count card when restricted', async () => {
    api.projectAccessInfo.mockResolvedValue({
      c2: [], infra: [], machines: [],
      dropped: [], dropped_total: 3, dropped_restricted: true,
    });
    render(<AccessView pid="p1" accent="#15bbb1" />);
    // flush the fetch → setState cycle
    await new Promise(r => setTimeout(r, 50));
    const bodyText = document.body.textContent || '';
    if (!/3 payload links/.test(bodyText)) {
      throw new Error('locked card missing; body=' + bodyText.replace(/\s+/g, ' ').slice(0, 160));
    }
    expect(/visible to operator roles and above/.test(bodyText)).toBeTruthy();
  });

  it('shows full links when not restricted', async () => {
    api.projectAccessInfo.mockResolvedValue({
      c2: [], infra: [], machines: [],
      dropped: [{ loot_id: 'l1', filename: 'implant.exe', url: 'https://drop.example/p1', sha256: 'aa' }],
      dropped_total: 1, dropped_restricted: false,
    });
    render(<AccessView pid="p1" accent="#15bbb1" />);
    expect(await screen.findByText('implant.exe')).toBeTruthy();
  });
});
