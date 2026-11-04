import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen, act } from '@testing-library/react';

// The `@ee` alias is resolved once, at config time (edition.config.js), so
// an edition cannot be switched inside a run. Mocking the registry instead
// tests what this view actually depends on: the shape of what `@ee`
// exports, not which directory it came from.
vi.mock('../components/UI.jsx', async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, PageTitle: ({ children }) => <h1>{children}</h1> };
});

async function renderWithRegistry(EE_INFRA_TABS) {
  vi.resetModules();
  vi.doMock('@ee', () => ({ EE_INFRA_TABS }));
  const { default: PlatformOpsView } = await import('./PlatformOpsView.jsx');
  return render(<PlatformOpsView selectedProject="p1" />);
}

const EE_TABS_FIXTURE = [
  { id: 'catalog', label: 'Catalog', padded: true, render: () => <div>catalog-body</div> },
  { id: 'builder', label: 'Builder', padded: false, render: () => <div>builder-body</div> },
];

beforeEach(() => vi.clearAllMocks());

describe('PlatformOpsView — edition composition', () => {
  it('offers no tabs at all when the Enterprise registry is empty', async () => {
    await renderWithRegistry([]);
    // Every tab on this page is Enterprise-backed. DevOps and C2 Ops used to
    // be listed here as "Community tabs", but both call /api/infra-v2, which
    // a Community build does not serve — so the page showed an empty log
    // under an error toast. A tab whose backend answers 404 must not be
    // offered; with no Enterprise registry the page offers nothing, and
    // AppTopBar hides the nav entry entirely.
    expect(screen.queryByRole('button', { name: 'DevOps' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'C2 Ops' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Catalog' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Builder' })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Stacks' })).toBeNull();
  });

  it('shows the registry tabs in the order the registry gives', async () => {
    await renderWithRegistry(EE_TABS_FIXTURE);
    const labels = screen.getAllByRole('button').map(b => b.textContent);
    expect(labels).toEqual(['Catalog', 'Builder']);
  });

  it('opens on the first registry tab when the Enterprise package is present', async () => {
    await renderWithRegistry(EE_TABS_FIXTURE);
    expect(screen.getByText('catalog-body')).toBeTruthy();
  });

  it('renders a registry tab through its own descriptor', async () => {
    const { container } = await renderWithRegistry(EE_TABS_FIXTURE);
    await act(async () => {
      screen.getByRole('button', { name: 'Builder' }).click();
    });
    expect(screen.getByText('builder-body')).toBeTruthy();
    // padded: false means the tab owns its layout — core must not wrap it
    // in the scrolling 16px container.
    expect(container.querySelector('div[style*="padding: 16px"]')).toBeNull();
  });

  it('wraps a padded registry tab in the scrolling container', async () => {
    const { container } = await renderWithRegistry(EE_TABS_FIXTURE);
    expect(container.querySelector('div[style*="padding: 16px"]')).toBeTruthy();
  });

  it('still renders the page itself with an empty registry', async () => {
    await renderWithRegistry([]);
    expect(screen.getByText('Infrastructure')).toBeTruthy();
  });
});
