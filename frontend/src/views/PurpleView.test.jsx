import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import PurpleView from './PurpleView.jsx';

vi.mock('../api.js', () => ({
  api: { getPurpleView: vi.fn() },
}));

import { api } from '../api.js';

const DATA = {
  techniques: [
    { id: 'T1550.002', tactic: 'Lateral Movement', steps: 1, edges: 1, labels: ['Pass-the-hash to DC'] },
    { id: 'T1021', tactic: 'Lateral Movement', steps: 0, edges: 2, labels: ['cred validation'] },
    { id: 'T1059', tactic: '', steps: 0, edges: 1, labels: [] },
  ],
  tactic_order: ['Lateral Movement'],
  by_tactic: { 'Lateral Movement': 2, Unmapped: 1 },
  stats: {
    techniques_total: 3, mapped_to_tactic: 2, steps_total: 1, steps_with_mitre: 1,
    tagged_edges: 2, findings_total: 2, findings_by_severity: { high: 1, low: 1 },
    timeline_events: 2,
  },
  timeline: [
    { ts: '2026-09-15T10:01:00Z', entity: 'host', action: 'create', label: 'Host up', username: 'alice' },
    { ts: '2026-09-15T09:00:00Z', entity: 'cred', action: 'validate', label: 'SMB valid', username: 'bob' },
  ],
};

describe('PurpleView', () => {
  beforeEach(() => vi.clearAllMocks());

  it('renders techniques with source badges and tactic chips', async () => {
    api.getPurpleView.mockResolvedValue(DATA);
    render(<PurpleView selectedProject="p1" projects={[{ id: 'p1', name: 'Eng' }]} accent="#15bbb1" />);

    expect(await screen.findByText('T1550.002')).toBeTruthy();
    expect(screen.getByText(/Purple Team \(3 techniques\)/)).toBeTruthy();
    expect(screen.getByText('Lateral Movement · 2')).toBeTruthy();
    expect(screen.getByText('1 step')).toBeTruthy();
    expect(screen.getByText('2 edge')).toBeTruthy();
    expect(screen.getByText(/Defender timeline/)).toBeTruthy();
    expect(screen.getByText('[host/create]')).toBeTruthy();
  });

  it('shows severity badges', async () => {
    api.getPurpleView.mockResolvedValue(DATA);
    render(<PurpleView selectedProject="p1" accent="#15bbb1" />);
    await screen.findByText('T1550.002');
    expect(screen.getByText('high: 1')).toBeTruthy();
  });

  it('empty state without techniques', async () => {
    api.getPurpleView.mockResolvedValue({
      techniques: [], tactic_order: [], by_tactic: {},
      stats: { techniques_total: 0, findings_by_severity: {} }, timeline: [],
    });
    render(<PurpleView selectedProject="p1" accent="#15bbb1" />);
    await waitFor(() => screen.getByText(/No MITRE coverage yet/));
  });

  it('copies the markdown report', async () => {
    api.getPurpleView.mockResolvedValue(DATA);
    const writeText = vi.fn().mockResolvedValue();
    Object.assign(navigator, { clipboard: { writeText } });
    Object.defineProperty(window, 'isSecureContext', { value: true, configurable: true });
    render(<PurpleView selectedProject="p1" projects={[{ id: 'p1', name: 'Engagement X' }]} accent="#15bbb1" />);

    fireEvent.click(await screen.findByText(/Copy report/));
    await waitFor(() => expect(writeText).toHaveBeenCalled());
    const md = writeText.mock.calls[0][0];
    expect(md).toContain('# Purple Team Report — Engagement X');
    expect(md).toContain('**T1550.002** (Lateral Movement)');
    expect(md).toContain('## Defender timeline');
  });
});
