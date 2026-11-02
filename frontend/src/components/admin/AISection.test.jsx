import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import AISection from './AISection.jsx';

vi.mock('../../api.js', () => ({
  api: {
    getAISettings: vi.fn(),
    getAIProviders: vi.fn(),
    getAIProviderTypes: vi.fn(),
    getAIProviderModels: vi.fn(),
    fetchAIProviderModels: vi.fn(),
    updateAIProvider: vi.fn(),
  },
}));

import { api } from '../../api.js';

const PROVIDER = { id: 'p1', name: 'my-litellm', provider: 'litellm', model: 'gpt-4', base_url: 'http://litellm:4000', api_key: '****abcd', priority: 1, enabled: true };

describe('AISection — edit provider model fetch', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    api.getAISettings.mockResolvedValue({});
    api.getAIProviders.mockResolvedValue({ providers: [PROVIDER] });
    api.getAIProviderTypes.mockResolvedValue([]);
  });

  it('uses the provider-scoped endpoint (server-side stored key) when no new key was typed', async () => {
    api.getAIProviderModels.mockResolvedValue({ models: [{ id: 'gpt-4', name: 'gpt-4' }, { id: 'gpt-4-turbo', name: 'gpt-4-turbo' }] });
    render(<AISection accent="#15bbb1" />);

    fireEvent.click(await screen.findByText('Edit'));
    fireEvent.click(screen.getByText('↻ Fetch models'));

    await waitFor(() => expect(api.getAIProviderModels).toHaveBeenCalledWith('p1'));
    // the masked key must never be sent as a real credential to the generic endpoint
    expect(api.fetchAIProviderModels).not.toHaveBeenCalled();
    // Select is a custom popup (not a native <select>) so its options only
    // render once opened, not always-in-DOM like native <option> elements.
    fireEvent.click(await screen.findByText('gpt-4'));
    expect(await screen.findByText('gpt-4-turbo')).toBeTruthy();
  });

  it('sends the explicit unsaved key when the operator typed a new one', async () => {
    api.fetchAIProviderModels.mockResolvedValue({ models: [{ id: 'claude-x', name: 'claude-x' }] });
    render(<AISection accent="#15bbb1" />);

    fireEvent.click(await screen.findByText('Edit'));
    const keyInput = screen.getByPlaceholderText('(unchanged)');
    fireEvent.change(keyInput, { target: { value: 'sk-new-real-key' } });
    fireEvent.click(screen.getByText('↻ Fetch models'));

    await waitFor(() => expect(api.fetchAIProviderModels).toHaveBeenCalledWith(
      expect.objectContaining({ api_key: 'sk-new-real-key' }),
    ));
    expect(api.getAIProviderModels).not.toHaveBeenCalled();
  });

  it('surfaces the backend error instead of silently showing nothing', async () => {
    api.getAIProviderModels.mockResolvedValue({ models: [], error: 'Connection refused' });
    render(<AISection accent="#15bbb1" />);

    fireEvent.click(await screen.findByText('Edit'));
    fireEvent.click(screen.getByText('↻ Fetch models'));

    expect(await screen.findByText('Connection refused')).toBeTruthy();
  });
});
