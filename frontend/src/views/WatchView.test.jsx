import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import WatchView from './WatchView.jsx';

vi.mock('../api.js', () => ({
  api: {
    getProjectWatches: vi.fn(),
    createProjectWatch: vi.fn(),
    updateProjectWatch: vi.fn(),
    deleteProjectWatch: vi.fn(),
    runProjectWatch: vi.fn(),
  },
}));

import { api } from '../api.js';

const WATCH = {
  id: 'sw1',
  name: 'Perimeter watch',
  enabled: true,
  state: 'idle',
  interval_minutes: 60,
  targets: '',
  last_run_at: '2026-09-15T10:00:00Z',
  last_change_at: '2026-09-15T10:00:00Z',
  baseline_json: { '10.0.0.1': {}, '10.0.0.2': {} },
  last_diff_json: {
    new_hosts: [{ ip: '10.0.0.9', hostname: 'newbox', ports: ['443/tcp'] }],
    new_ports: [{ ip: '10.0.0.1', ports: ['8080/tcp'] }],
    new_services: [],
    status_changes: [],
  },
};

describe('WatchView', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders watches with diff summary and run/pause controls', async () => {
    api.getProjectWatches.mockResolvedValue([WATCH]);
    render(<WatchView selectedProject="p1" accent="#15bbb1" />);

    expect(await screen.findByText('Perimeter watch')).toBeTruthy();
    expect(screen.getByText(/Surface Watches \(1\)/)).toBeTruthy();
    expect(screen.getByText('+ host 10.0.0.9 (newbox)')).toBeTruthy();
    expect(screen.getByText('+ 10.0.0.1: 8080/tcp')).toBeTruthy();
    expect(screen.getByText(/Baseline hosts/)).toBeTruthy();
    expect(screen.getByText('Run now')).toBeTruthy();
    expect(screen.getByText('Pause')).toBeTruthy();
  });

  it('shows empty state without watches', async () => {
    api.getProjectWatches.mockResolvedValue([]);
    render(<WatchView selectedProject="p1" accent="#15bbb1" />);
    await waitFor(() => screen.getByText(/No watches/));
    expect(screen.getByText(/New Watch/)).toBeTruthy();
  });

  it('creates a watch through the modal', async () => {
    api.getProjectWatches.mockResolvedValue([]);
    api.createProjectWatch.mockResolvedValue({ id: 'sw2' });
    render(<WatchView selectedProject="p1" accent="#15bbb1" />);

    await waitFor(() => screen.getByText(/No watches/));
    fireEvent.click(screen.getByText(/New Watch/));
    fireEvent.click(screen.getByText('Create watch'));

    await waitFor(() =>
      expect(api.createProjectWatch).toHaveBeenCalledWith('p1', expect.objectContaining({ interval_minutes: 60 })),
    );
  });

  it('runs a watch on demand', async () => {
    api.getProjectWatches.mockResolvedValue([WATCH]);
    render(<WatchView selectedProject="p1" accent="#15bbb1" />);
    fireEvent.click(await screen.findByText('Run now'));
    await waitFor(() => expect(api.runProjectWatch).toHaveBeenCalledWith('p1', 'sw1'));
  });

  it('shows "no changes" for a clean diff', async () => {
    api.getProjectWatches.mockResolvedValue([
      { ...WATCH, last_diff_json: { new_hosts: [], new_ports: [], new_services: [], status_changes: [] } },
    ]);
    render(<WatchView selectedProject="p1" accent="#15bbb1" />);
    expect(await screen.findByText('no changes')).toBeTruthy();
  });
});
