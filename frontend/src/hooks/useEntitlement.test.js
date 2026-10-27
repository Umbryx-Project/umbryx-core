import { describe, it, expect, beforeEach, vi } from 'vitest';
import { renderHook, waitFor } from '@testing-library/react';

vi.mock('../api/index.ts', () => ({
  api: {
    getLicenseState: vi.fn(),
    getEdition: vi.fn(),
  },
}));

import { api } from '../api/index.ts';

// The hook caches at module level so every mounted gate shares one fetch.
// Each test needs a clean module instance, otherwise the first test's
// entitlement answers all the others.
async function freshHook() {
  vi.resetModules();
  const { useEntitlement } = await import('./useEntitlement.js');
  return renderHook(() => useEntitlement());
}

beforeEach(() => {
  vi.clearAllMocks();
  api.getLicenseState.mockResolvedValue({ tier: 'free', features: [], limits: {} });
  api.getEdition.mockResolvedValue({ edition: 'ce', tier: 'free', features: [] });
});

describe('useEntitlement — edition', () => {
  it('reports the build edition alongside the license', async () => {
    const { result } = await freshHook();
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.edition).toBe('ce');
    expect(result.current.isCommunity).toBe(true);
    expect(result.current.tier).toBe('free');
  });

  it('reports Enterprise builds as not community', async () => {
    api.getEdition.mockResolvedValue({ edition: 'ee' });
    const { result } = await freshHook();
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.edition).toBe('ee');
    expect(result.current.isCommunity).toBe(false);
  });

  it('assumes Enterprise while still loading', async () => {
    // Fail open, same as hasFeature: a slow call must not blank out the
    // navigation of a paying installation for a frame.
    const { result } = await freshHook();
    expect(result.current.loading).toBe(true);
    expect(result.current.isCommunity).toBe(false);
    // Let the in-flight load settle so React isn't updating state after
    // the test has finished.
    await waitFor(() => expect(result.current.loading).toBe(false));
  });

  it('assumes Enterprise when the edition call fails', async () => {
    api.getEdition.mockRejectedValue(new Error('boom'));
    const { result } = await freshHook();
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.edition).toBe('ee');
    // The license half still came through — one failing call must not
    // discard the other.
    expect(result.current.tier).toBe('free');
  });

  it('still fails open on hasFeature when both calls fail', async () => {
    api.getLicenseState.mockRejectedValue(new Error('down'));
    api.getEdition.mockRejectedValue(new Error('down'));
    const { result } = await freshHook();
    expect(result.current.hasFeature('infra_lifecycle')).toBe(true);
  });

  it('gates accurately once the license is loaded', async () => {
    api.getLicenseState.mockResolvedValue({
      tier: 'enterprise',
      features: ['infra_lifecycle', 'workstations'],
      limits: { max_workstations: -1 },
    });
    api.getEdition.mockResolvedValue({ edition: 'ee' });
    const { result } = await freshHook();
    await waitFor(() => expect(result.current.loading).toBe(false));
    expect(result.current.hasFeature('infra_lifecycle')).toBe(true);
    expect(result.current.hasFeature('sso')).toBe(false);
    expect(result.current.limits.max_workstations).toBe(-1);
  });
});
