import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import LoginView from './LoginView.jsx';
import { api } from '../api.js';

vi.mock('../api.js', () => ({
  api: {
    authLogin: vi.fn(),
    authSetup: vi.fn(),
    oidcConfirmLink: vi.fn(),
    authMfaVerify: vi.fn(),
    publicOidcProviders: vi.fn().mockResolvedValue([]),
  },
}));

// All three auth forms map 429 to a human message instead of the raw
// slowapi payload (regression for the JSON-blob-in-banner bug).
describe('LoginView — rate-limit errors', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('shows a human message on 429 instead of the raw payload', async () => {
    api.authLogin.mockRejectedValue(
      Object.assign(new Error('Rate limit exceeded: 5 per 1 minute'), { status: 429 })
    );
    render(<LoginView isFirstRun={false} onAuth={() => {}} />);
    fireEvent.change(screen.getByPlaceholderText('username'), { target: { value: 'admin' } });
    fireEvent.change(screen.getByPlaceholderText('••••••••'), { target: { value: 'wrong' } });
    fireEvent.submit(screen.getByPlaceholderText('username').closest('form'));
    await waitFor(() =>
      expect(screen.getByText('Too many attempts. Wait a minute and try again.')).toBeTruthy());
  });

  it('still shows the plain message for other errors', async () => {
    api.authLogin.mockRejectedValue(new Error('Invalid username or password'));
    render(<LoginView isFirstRun={false} onAuth={() => {}} />);
    fireEvent.change(screen.getByPlaceholderText('username'), { target: { value: 'admin' } });
    fireEvent.change(screen.getByPlaceholderText('••••••••'), { target: { value: 'wrong' } });
    fireEvent.submit(screen.getByPlaceholderText('username').closest('form'));
    await waitFor(() =>
      expect(screen.getByText('Invalid username or password')).toBeTruthy());
  });
});

describe('LoginView — MFA form rate limit', () => {
  beforeEach(() => { vi.clearAllMocks(); });

  it('MFA verify 429 shows the human message too', async () => {
    api.publicOidcProviders.mockResolvedValue([]);
    api.authLogin.mockResolvedValue({ mfa_required: true, mfa_token: 'mtok' });
    api.authMfaVerify.mockRejectedValue(
      Object.assign(new Error('Rate limit exceeded: 10 per 1 minute'), { status: 429 })
    );
    render(<LoginView isFirstRun={false} onAuth={() => {}} />);
    fireEvent.change(screen.getByPlaceholderText('username'), { target: { value: 'admin' } });
    fireEvent.change(screen.getByPlaceholderText('••••••••'), { target: { value: 'x' } });
    fireEvent.submit(screen.getByPlaceholderText('username').closest('form'));
    const code = await screen.findByPlaceholderText('000000', {}, { timeout: 3000 });
    fireEvent.change(code, { target: { value: '123456' } });
    fireEvent.submit(code.closest('form'));
    await waitFor(() =>
      expect(screen.getByText('Too many attempts. Wait a minute and try again.')).toBeTruthy());
  });
});
