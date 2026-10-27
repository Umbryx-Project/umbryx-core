import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, screen } from '@testing-library/react';

// The pool itself is a Community feature (docs/modules/EDITIONS.md): a
// machine the operator already owns, registered over SSH. Provisioning is
// not, so GET /workstations/pool/providers answers 404 in a Community build.
// These tests pin that the panel survives that 404 — it used to load the
// providers inside the same Promise.all as the machines, so the rejection
// took the whole panel down and the pool rendered empty.
const apiMock = {
  listPoolMachines: vi.fn(),
  listPoolProviders: vi.fn(),
  adminListUsers: vi.fn(),
  getProjects: vi.fn(),
};

async function renderPanel({ EE_WORKSTATION_PROVISIONING = null } = {}) {
  vi.resetModules();
  vi.doMock('../api.js', () => ({ api: apiMock, downloadUrl: () => '' }));
  vi.doMock('@ee', () => ({ EE_WORKSTATION_PROVISIONING }));
  const { PoolPanel } = await import('./PoolPanel.jsx');
  return render(<PoolPanel />);
}

beforeEach(() => {
  vi.clearAllMocks();
  apiMock.listPoolMachines.mockResolvedValue([
    { id: 'ws1', name: 'registered-box', provider: 'manual', status: 'ready', meta: {} },
  ]);
  apiMock.adminListUsers.mockResolvedValue({ users: [] });
  apiMock.getProjects.mockResolvedValue([]);
});

afterEach(() => vi.useRealTimers());

describe('PoolPanel — Community Edition', () => {
  it('lists pool machines when the provider endpoint answers 404', async () => {
    apiMock.listPoolProviders.mockRejectedValue(new Error('Workstation provisioning is not part of Umbryx Community Edition.'));
    await renderPanel();
    expect(await screen.findByText('registered-box')).toBeTruthy();
    expect(screen.queryByText(/not part of Umbryx Community Edition/)).toBeNull();
  });

  it('still lists pool machines when providers resolve (Enterprise)', async () => {
    apiMock.listPoolProviders.mockResolvedValue([{ id: 'p1', name: 'hetzner-1', type: 'hetzner' }]);
    await renderPanel({ EE_WORKSTATION_PROVISIONING: {} });
    expect(await screen.findByText('registered-box')).toBeTruthy();
  });
});
