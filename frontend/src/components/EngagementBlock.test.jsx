import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import EngagementBlock from './EngagementBlock.jsx';

vi.mock('../api.js', () => ({
  api: {
    getDeconfliction: vi.fn(),
    claimHost: vi.fn(),
    releaseHost: vi.fn(),
  },
}));
vi.mock('./Toast.jsx', () => ({ toastError: vi.fn() }));

import { api } from '../api.js';
import { toastError } from './Toast.jsx';

const HOST = { id: 'h1' };

describe('EngagementBlock', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders nothing without a host', () => {
    const { container } = render(<EngagementBlock pid="p1" hostObj={null} />);
    expect(container).toBeEmptyDOMElement();
  });

  it('shows "free" state and an Engage button when nobody is on the host', async () => {
    api.getDeconfliction.mockResolvedValue({ engagement: {} });
    render(<EngagementBlock pid="p1" hostObj={HOST} />);

    expect(await screen.findByText(/nobody/)).toBeTruthy();
    expect(screen.getByText('Engage')).toBeTruthy();
  });

  it('shows who is engaged and a Release button when the current user holds it', async () => {
    api.getDeconfliction.mockResolvedValue({
      engagement: { h1: { operators: [{ username: 'alice', is_me: true, sources: ['claim'] }] } },
    });
    render(<EngagementBlock pid="p1" hostObj={HOST} />);

    expect(await screen.findByText(/alice \(claim\)/)).toBeTruthy();
    expect(screen.getByText('Release')).toBeTruthy();
  });

  it('shows Engage (not Release) when someone else holds it', async () => {
    api.getDeconfliction.mockResolvedValue({
      engagement: { h1: { operators: [{ username: 'bob', is_me: false, sources: ['job'] }] } },
    });
    render(<EngagementBlock pid="p1" hostObj={HOST} />);

    expect(await screen.findByText(/bob \(job\)/)).toBeTruthy();
    expect(screen.getByText('Engage')).toBeTruthy();
  });

  it('claims the host on Engage click', async () => {
    api.getDeconfliction.mockResolvedValue({ engagement: {} });
    api.claimHost.mockResolvedValue({});
    render(<EngagementBlock pid="p1" hostObj={HOST} />);

    fireEvent.click(await screen.findByText('Engage'));
    await waitFor(() => expect(api.claimHost).toHaveBeenCalledWith('p1', 'h1', { note: '' }));
  });

  it('releases the host on Release click', async () => {
    api.getDeconfliction.mockResolvedValue({
      engagement: { h1: { operators: [{ username: 'alice', is_me: true, sources: ['claim'] }] } },
    });
    api.releaseHost.mockResolvedValue({});
    render(<EngagementBlock pid="p1" hostObj={HOST} />);

    fireEvent.click(await screen.findByText('Release'));
    await waitFor(() => expect(api.releaseHost).toHaveBeenCalledWith('p1', 'h1'));
  });

  it('surfaces the error via toastError without crashing when the toggle fails', async () => {
    api.getDeconfliction.mockResolvedValue({ engagement: {} });
    api.claimHost.mockRejectedValue(new Error('host already claimed'));
    render(<EngagementBlock pid="p1" hostObj={HOST} />);

    fireEvent.click(await screen.findByText('Engage'));
    await waitFor(() => expect(toastError).toHaveBeenCalledWith('host already claimed'));
  });

  describe('polling', () => {
    beforeEach(() => vi.useFakeTimers({ shouldAdvanceTime: true }));
    afterEach(() => vi.useRealTimers());

    it('refreshes engagement state every 30s without user interaction', async () => {
      api.getDeconfliction.mockResolvedValue({ engagement: {} });
      render(<EngagementBlock pid="p1" hostObj={HOST} />);

      await waitFor(() => expect(api.getDeconfliction).toHaveBeenCalledTimes(1));

      await act(async () => { await vi.advanceTimersByTimeAsync(30000); });
      expect(api.getDeconfliction).toHaveBeenCalledTimes(2);

      await act(async () => { await vi.advanceTimersByTimeAsync(30000); });
      expect(api.getDeconfliction).toHaveBeenCalledTimes(3);
    });
  });

  describe('notifying other surfaces', () => {
    it('announces rt:host-engagement after a claim so the map chip updates', async () => {
      api.getDeconfliction.mockResolvedValue({ engagement: {} });
      api.claimHost.mockResolvedValue({});
      const seen = [];
      const h = (e) => seen.push(e.detail);
      globalThis.addEventListener('rt:host-engagement', h);
      try {
        render(<EngagementBlock pid="p1" hostObj={HOST} />);
        await waitFor(() => expect(screen.getByText('Engage')).toBeTruthy());
        fireEvent.click(screen.getByText('Engage'));
        await waitFor(() => expect(api.claimHost).toHaveBeenCalled());
        await waitFor(() => expect(seen.length).toBeGreaterThan(0));
      } finally {
        globalThis.removeEventListener('rt:host-engagement', h);
      }
      expect(seen[0].action).toBe('claim');
      expect(seen[0].data.host_id).toBe('h1');
    });

    it('refetches when another operator claims a host', async () => {
      api.getDeconfliction.mockResolvedValue({ engagement: {} });
      render(<EngagementBlock pid="p1" hostObj={HOST} />);
      await waitFor(() => expect(api.getDeconfliction).toHaveBeenCalledTimes(1));
      await act(async () => {
        globalThis.dispatchEvent(new CustomEvent('rt:host-engagement', { detail: { action: 'claim', data: { host_id: 'h9' } } }));
      });
      await waitFor(() => expect(api.getDeconfliction).toHaveBeenCalledTimes(2));
    });
  });
});

describe('release with other engagement sources', () => {
  const engagedVia = (sources) => ({
    engagement: { h1: { operators: [{ username: 'me', is_me: true, sources }] } },
  });

  it('offers Release while an actual claim is held', async () => {
    api.getDeconfliction.mockResolvedValue(engagedVia(['claim', 'job']));
    render(<EngagementBlock pid="p1" hostObj={HOST} />);
    await waitFor(() => expect(screen.getByText('Release')).toBeTruthy());
  });

  it.each([['job'], ['ws']])('offers Release when only %s engages the host', async (src) => {
    // Release outranks every signal on the server, so it must be offered for
    // inferred engagement too — otherwise the chip could not be cleared at all.
    api.getDeconfliction.mockResolvedValue(engagedVia([src]));
    render(<EngagementBlock pid="p1" hostObj={HOST} />);
    await waitFor(() => expect(screen.getByText('Release')).toBeTruthy());
  });

  it('releases a job-only engagement without an error', async () => {
    api.getDeconfliction.mockResolvedValue(engagedVia(['job']));
    api.releaseHost.mockResolvedValue({});
    render(<EngagementBlock pid="p1" hostObj={HOST} />);
    await waitFor(() => expect(screen.getByText('Release')).toBeTruthy());
    fireEvent.click(screen.getByText('Release'));
    await waitFor(() => expect(api.releaseHost).toHaveBeenCalledWith('p1', 'h1'));
    expect(api.claimHost).not.toHaveBeenCalled();
    expect(toastError).not.toHaveBeenCalled();
  });

  it("offers Engage when the host is free", async () => {
    api.getDeconfliction.mockResolvedValue({ engagement: {} });
    render(<EngagementBlock pid="p1" hostObj={HOST} />);
    await waitFor(() => expect(screen.getByText('Engage')).toBeTruthy());
  });

  it("offers Engage when only someone else holds the host", async () => {
    api.getDeconfliction.mockResolvedValue({
      engagement: { h1: { operators: [{ username: 'other', is_me: false, sources: ['claim'] }] } },
    });
    render(<EngagementBlock pid="p1" hostObj={HOST} />);
    await waitFor(() => expect(screen.getByText('Engage')).toBeTruthy());
  });
});
