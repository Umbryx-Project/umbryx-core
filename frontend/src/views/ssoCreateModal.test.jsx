import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { CreatePlatformSsoModal } from './SystemDashboard.jsx';
import { CreateOidcProviderModal } from './OrganizationsView.jsx';

// Regression: the "provider created → show redirect URI" state used to sit
// ABOVE the remaining useState hooks (an early return) — flipping to it
// re-rendered with fewer hooks and crashed with React error #300
// ("Rendered fewer hooks than expected"). These tests walk the real
// create path; the hooks violation would throw right here.

const fill = (inputs, vals) => inputs.forEach((inp, i) => fireEvent.change(inp, { target: { value: vals[i] } }));

describe('SSO create modals — success state', () => {
  it('platform modal shows the redirect URI after create (hooks stay stable)', async () => {
    const onCreate = vi.fn(async () => ({ id: 'oidcp123' }));
    const { container } = render(<CreatePlatformSsoModal accent="#5b8af5" onClose={() => {}} onCreate={onCreate} />);
    const inputs = [...container.querySelectorAll("input")];
    fill(inputs, ['GitLab', 'https://gitlab.example.com', 'cid', 'secret']);
    fireEvent.click(screen.getByText('Create'));
    await waitFor(() => expect(screen.getByText(/Register this redirect URI/)).toBeTruthy());
    expect(screen.getByText(/\/api\/auth\/oidc\/oidcp123\/callback/)).toBeTruthy();
  });

  it('org modal shows the redirect URI after create (hooks stay stable)', async () => {
    const onCreate = vi.fn(async () => ({ id: 'oidcp456' }));
    const { container } = render(<CreateOidcProviderModal accent="#5b8af5" onClose={() => {}} onCreate={onCreate} />);
    const inputs = [...container.querySelectorAll("input")];
    fill(inputs.slice(0, 4), ['GitLab', 'https://gitlab.example.com', 'cid', 'secret']);
    fireEvent.click(screen.getByText('Create'));
    await waitFor(() => expect(screen.getByText(/Register this redirect URI/)).toBeTruthy());
    expect(screen.getByText(/\/api\/auth\/oidc\/oidcp456\/callback/)).toBeTruthy();
  });
});
