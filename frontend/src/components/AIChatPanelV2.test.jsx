import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import AIChatPanelV2 from './AIChatPanelV2.jsx';

vi.mock('../api.js', () => ({
  api: {
    getAIChats: vi.fn(),
    getAIChat: vi.fn(),
    getAISettings: vi.fn(),
    listAIAgents: vi.fn(),
    createAIChat: vi.fn(),
    deleteAIChat: vi.fn(),
    listPlaybooks: vi.fn(),
  },
}));

import { api } from '../api.js';

// jsdom doesn't implement scrollIntoView — the component calls it whenever
// the message list changes, unrelated to what these tests exercise.
Element.prototype.scrollIntoView = vi.fn();

function openPanel() {
  render(<AIChatPanelV2 selectedProject="p1" accent="#15bbb1" />);
  fireEvent.click(screen.getByTitle('Open AI Agent'));
}

describe('AIChatPanelV2 — resizable panel', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    api.getAIChats.mockResolvedValue({ chats: [] });
    api.getAISettings.mockResolvedValue({ agent_mode: true });
    api.listAIAgents.mockResolvedValue({ agents: [] });
  });

  it('opens compact by default, sized 480px', async () => {
    openPanel();
    await waitFor(() => expect(api.getAIChats).toHaveBeenCalled());

    const toggle = await screen.findByTitle('Expand to half screen');
    const panel = toggle.closest('div[style*="position: fixed"]');
    expect(panel.style.width).toContain('480px');
  });

  it('cycles compact -> half -> full -> compact on repeated clicks', async () => {
    openPanel();
    const toggle = await screen.findByTitle('Expand to half screen');
    const panel = toggle.closest('div[style*="position: fixed"]');

    fireEvent.click(toggle);
    expect(panel.style.width).toContain('50vw');
    expect(await screen.findByTitle('Expand to full screen')).toBeTruthy();

    fireEvent.click(screen.getByTitle('Expand to full screen'));
    expect(panel.style.width).toContain('100vw - 200px');
    expect(await screen.findByTitle('Back to compact')).toBeTruthy();

    fireEvent.click(screen.getByTitle('Back to compact'));
    expect(panel.style.width).toContain('480px');
  });

  it('never overlaps the app top bar, at any size', async () => {
    // top: 0 previously let this fixed, zIndex:1000 panel sit on top of the
    // app's own sticky top bar (zIndex 50) — most visibly broken in 'full',
    // where the panel's left edge lands mid-screen and clips a tab label
    // (e.g. "Exploit") right through the middle of the text. 78 is the
    // established below-top-bar offset used elsewhere (TweaksPanel in
    // AppChrome.jsx).
    openPanel();
    const toggle = await screen.findByTitle('Expand to half screen');
    const panel = toggle.closest('div[style*="position: fixed"]');
    expect(panel.style.top).toBe('78px');

    fireEvent.click(toggle);
    fireEvent.click(screen.getByTitle('Expand to full screen'));
    expect(panel.style.top).toBe('78px');
  });

  it('closes via the header close button', async () => {
    openPanel();
    await screen.findByText('AI Agent');
    fireEvent.click(screen.getByTitle('Close'));
    expect(screen.queryByText('AI Agent')).toBeNull();
  });
});

function sseResponse(events) {
  const enc = new TextEncoder();
  const body = new ReadableStream({
    start(ctrl) {
      for (const e of events) ctrl.enqueue(enc.encode('data: ' + JSON.stringify(e) + '\n\n'));
      ctrl.close();
    },
  });
  return { ok: true, body, headers: { get: () => 'text/event-stream' } };
}

describe('AIChatPanelV2 — run status line', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    api.getAIChats.mockResolvedValue({ chats: [] });
    api.getAISettings.mockResolvedValue({ agent_mode: true });
    api.listAIAgents.mockResolvedValue({ agents: [] });
    api.getAIChat.mockResolvedValue({ messages: [] });
    api.listPlaybooks.mockResolvedValue({ playbooks: [] });
    api.getAIChats.mockResolvedValue({ chats: [] });
    api.getAISettings.mockResolvedValue({ agent_mode: true });
  });

  it('shows no status while idle', async () => {
    openPanel();
    await waitFor(() => expect(api.getAIChats).toHaveBeenCalled());
    expect(screen.queryByText('Finished')).toBeNull();
    expect(screen.queryByText('Working…')).toBeNull();
  });

  it('Working… appears while the run streams and ✓ Finished after done', async () => {
    const fetchMock = vi.fn(() => Promise.resolve(sseResponse([
      { type: 'step', step_num: 1, provider_id: 'p' },
      { type: 'reasoning', text: 'thinking…' },
      { type: 'content', text: 'hi' },
      { type: 'done', content: 'hi', provider_id: 'p', tool_calls_made: 0 },
    ])));
    vi.stubGlobal('fetch', fetchMock);

    api.createAIChat.mockResolvedValue({ id: 'c1' });
    api.getAIChats.mockResolvedValue({ chats: [{ id: 'c1', title: 't' }] });

    openPanel();
    const ta = await screen.findByRole('textbox');
    fireEvent.change(ta, { target: { value: 'hello' } });
    fireEvent.keyDown(ta, { key: 'Enter', shiftKey: false });
    await waitFor(() => expect(fetchMock).toHaveBeenCalled());
    // стрим предзаполнен и пролетает мгновенно: рабочие фазы (Thinking…/
    // Writing…) успевают отрендериться по пути, а устойчивое конечное
    // состояние — зелёное ✓ Finished; Working… после завершения нет.
    await waitFor(() => expect(screen.getByText('Finished')).toBeTruthy());
    expect(screen.queryByText(/Working…/)).toBeNull();
    expect(screen.queryByText(/Thinking…/)).toBeNull();
    vi.unstubAllGlobals();
  });

  it('Waiting for confirmation appears when a write action is gated', async () => {
    const fetchMock = vi.fn(() => Promise.resolve(sseResponse([
      { type: 'confirmation_needed', tool_name: 'run_command', arguments: { command: 'id' }, risk: 'write' },
    ])));
    vi.stubGlobal('fetch', fetchMock);
    api.createAIChat.mockResolvedValue({ id: 'c2' });
    api.getAIChats.mockResolvedValue({ chats: [{ id: 'c2', title: 't' }] });

    openPanel();
    const ta = await screen.findByRole('textbox');
    fireEvent.change(ta, { target: { value: 'run id' } });
    fireEvent.keyDown(ta, { key: 'Enter', shiftKey: false });
    await waitFor(() =>
      expect(screen.getByText(/Waiting for your confirmation: run_command/)).toBeTruthy());
    vi.unstubAllGlobals();
  });
});
