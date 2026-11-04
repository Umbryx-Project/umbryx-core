import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { FrontierPanel, EdgeTooltip, PathsPanel } from './GraphPanels.jsx';

// The remaining panel surface: frontier next-steps, the BloodHound-style
// edge tooltip, and the DA paths panel.

describe('FrontierPanel', () => {
  const suggestions = [
    { kind: 'validate_cred', title: 'CORP\\svc', hint: 'hash not cracked — no usable secret yet', focus: 'c1', tab: 'creds' },
    { kind: 'confirm_access', title: 'WS01 → DC01', hint: 'inferred access — confirm it works', focus: 'h2', tab: 'network' },
  ];

  it('lists what to validate next with per-item navigation', () => {
    const onSuggestion = vi.fn();
    render(<FrontierPanel suggestions={suggestions} onSuggestion={onSuggestion} onClose={vi.fn()} />);
    expect(screen.getByText(/Frontier · 2/)).toBeTruthy();
    expect(screen.getByText(/hash not cracked/)).toBeTruthy();
    expect(screen.getByText(/inferred access/)).toBeTruthy();
    fireEvent.click(screen.getByText('CORP\\svc'));
    expect(onSuggestion).toHaveBeenCalledWith(expect.objectContaining({ tab: 'creds', focus: 'c1' }));
  });

  it('shows the all-clear state when nothing needs validation', () => {
    render(<FrontierPanel suggestions={[]} onSuggestion={vi.fn()} onClose={vi.fn()} />);
    expect(screen.getByText(/nothing to validate/)).toBeTruthy();
  });

  it('closes via the ✕ button', () => {
    const onClose = vi.fn();
    render(<FrontierPanel suggestions={suggestions} onSuggestion={vi.fn()} onClose={onClose} />);
    fireEvent.click(screen.getByText('✕'));
    expect(onClose).toHaveBeenCalled();
  });
});

describe('EdgeTooltip', () => {
  const pos = { x: 100, y: 100 };

  it('explains a held credential with its type and crack state', () => {
    render(
      <EdgeTooltip
        allCreds={[{ id: 'c1', username: 'svc', domain: 'CORP', type: 'ntlm', cracked: false }]}
        hover={{ edge: { kind: 'credential', cred_id: 'c1' }, src: { label: 'attack-box' }, tgt: { label: 'CORP\\svc' }, pos }}
      />,
    );
    expect(screen.getByText(/🔑 held credential/)).toBeTruthy();
    expect(screen.getByText(/attacker holds CORP\\svc/)).toBeTruthy();
    expect(screen.getByText(/hash not cracked/)).toBeTruthy();
  });

  it('marks verified credential_use edges as validated', () => {
    render(
      <EdgeTooltip
        allCreds={[]}
        hover={{ edge: { kind: 'credential_use', verified: true }, src: { label: 'CORP\\krbtgt' }, tgt: { label: 'DC01' }, pos }}
      />,
    );
    expect(screen.getByText(/credential opens host/)).toBeTruthy();
    expect(screen.getByText(/validated access/)).toBeTruthy();
  });

  it('flags stale pivots with the seen date', () => {
    render(
      <EdgeTooltip
        allCreds={[]}
        hover={{ edge: { kind: 'pivot', pivot_tool: 'chisel', verified: false, observed_at: '2026-09-01T00:00:00Z' }, src: { label: 'WS01' }, tgt: { label: 'JUMP01' }, pos }}
      />,
    );
    expect(screen.getByText(/pivot · chisel/)).toBeTruthy();
    expect(screen.getByText(/STALE/)).toBeTruthy();
    expect(screen.getByText(/seen 2026-09-01/)).toBeTruthy();
  });

  it('distinguishes inferred access from verified', () => {
    render(
      <EdgeTooltip
        allCreds={[]}
        hover={{ edge: { kind: 'access', access_type: 'lateral', verified: false }, src: { label: 'WS01' }, tgt: { label: 'SQL01' }, pos }}
      />,
    );
    expect(screen.getByText(/lateral access/)).toBeTruthy();
    expect(screen.getByText(/inferred — not confirmed/)).toBeTruthy();
  });

  it('renders nothing without a hovered edge', () => {
    const { container } = render(<EdgeTooltip hover={null} allCreds={[]} />);
    expect(container.textContent).toBe('');
  });
});

describe('PathsPanel', () => {
  const details = [
    [
      { id: 'h1', label: 'WS01', edge_to_next: 'lateral' },
      { id: 'h2', label: 'DC01' },
    ],
  ];

  it('renders DA path steps and cross-links for the selected path', () => {
    render(
      <PathsPanel
        privilegePathDetails={details}
        pivotChains={[]}
        nodes={[{ id: 'h1', label: 'WS01' }, { id: 'h2', label: 'DC01' }]}
        selectedPathIdx={0}
        setSelectedPathIdx={vi.fn()}
        setShowPathsPanel={vi.fn()}
        onNavigate={vi.fn()}
      />,
    );
    expect(screen.getByText(/DA Paths · 1/)).toBeTruthy();
    expect(screen.getByText('WS01')).toBeTruthy();
    expect(screen.getByText('→ Attack Path')).toBeTruthy();
  });

  it('navigates with the path node ids when handed to Attack Path', () => {
    const onNavigate = vi.fn();
    render(
      <PathsPanel
        privilegePathDetails={details}
        pivotChains={[]}
        nodes={[{ id: 'h1' }, { id: 'h2' }]}
        selectedPathIdx={0}
        setSelectedPathIdx={vi.fn()}
        setShowPathsPanel={vi.fn()}
        onNavigate={onNavigate}
      />,
    );
    fireEvent.click(screen.getByText('→ Attack Path'));
    expect(onNavigate).toHaveBeenCalledWith('attackpath', { from_da_path: ['h1', 'h2'] });
  });
});
