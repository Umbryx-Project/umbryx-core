import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import AppTopBar from './AppTopBar.jsx';
import { ProjectPermissionsProvider } from '../context/ProjectPermissions.jsx';

// The badge is presentation: the entitlement hook has its own test file —
// here we control its output directly (the module-level _cache makes
// driving it through api mocks order-dependent in a shared render).
const entMock = vi.fn(() => ({ edition: 'ee', version: '', tier: 'enterprise', features: [] }));
vi.mock('../hooks/useEntitlement.js', () => ({ useEntitlement: (...a) => entMock(...a) }));

vi.mock('../api/index.ts', () => ({
  api: {
    listNotifications: vi.fn().mockResolvedValue({ notifications: [] }),
    getUnreadCount: vi.fn().mockResolvedValue({ count: 0 }),
    markNotificationRead: vi.fn(),
  },
}));

function renderBar() {
  return render(
    <ProjectPermissionsProvider>
      <AppTopBar
        tab="hosts" setTab={() => {}} accent="#15bbb1"
        showSearch={false} setShowSearch={() => {}}
        showTweaks={false} setShowTweaks={() => {}}
        currentUser={null} onLogout={() => {}}
      />
    </ProjectPermissionsProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('AppTopBar — version badge', () => {
  it('shows v0.10.0 next to the logo when the version is known', () => {
    entMock.mockReturnValue({ edition: 'ee', version: '0.10.0', tier: 'enterprise', features: [] });
    renderBar();
    const badge = screen.getByText('v0.10.0');
    expect(badge.title).toContain('0.10.0');
    expect(badge.title).toContain('Enterprise');
  });

  it('labels the Community build in the tooltip', () => {
    entMock.mockReturnValue({ edition: 'ce', version: '0.10.0', tier: 'free', features: [] });
    renderBar();
    expect(screen.getByText('v0.10.0').title).toContain('Community');
  });

  it('renders no badge when the version is unknown', () => {
    entMock.mockReturnValue({ edition: 'ee', version: '', tier: 'enterprise', features: [] });
    renderBar();
    expect(screen.queryByText(/^v\d/)).toBeNull();
  });
});
