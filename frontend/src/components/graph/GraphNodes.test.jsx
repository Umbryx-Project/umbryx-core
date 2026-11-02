import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import HostNode, { CredNode } from './GraphNodes.jsx';

// Node cards: status colors, DA badges, frontier ring/dimming — the
// visual contract of the canvas.

const base = { x: 300, y: 200 };

describe('CredNode', () => {
  it('renders dashed border for an uncracked hash, solid when cracked', () => {
    const { container, rerender } = render(
      <CredNode node={{ ...base, id: 'c1', type: 'cred', label: 'CORP\\svc', username: 'svc', domain: 'CORP', cracked: false }} selected={false} privMode={false} onMouseDown={() => {}} onClick={() => {}} />,
    );
    let rect = container.querySelectorAll('rect')[0];
    expect(rect.getAttribute('stroke-dasharray')).toBeTruthy();

    rerender(
      <CredNode node={{ ...base, id: 'c1', type: 'cred', label: 'CORP\\svc', username: 'svc', domain: 'CORP', cracked: true }} selected={false} privMode={false} onMouseDown={() => {}} onClick={() => {}} />,
    );
    rect = container.querySelectorAll('rect')[0];
    expect(rect.getAttribute('stroke-dasharray')).toBeFalsy();
  });

  it('shows the domain and hash hint in the sublabel', () => {
    render(
      <CredNode node={{ ...base, id: 'c1', type: 'cred', label: 'svc', username: 'svc', domain: 'corp.local', cracked: false }} selected={false} privMode={false} onMouseDown={() => {}} onClick={() => {}} />,
    );
    expect(screen.getByText(/corp\.local · hash/)).toBeTruthy();
  });

  it('dims in frontier mode when it is NOT the frontier', () => {
    const { container } = render(
      <CredNode node={{ ...base, id: 'c1', type: 'cred', label: 'svc', username: 'svc', cracked: true, host_ids: ['h1'], frontierDim: true }} selected={false} privMode={false} frontierMode onMouseDown={() => {}} onClick={() => {}} />,
    );
    expect(container.firstChild.style.opacity).toBe('0.25');
  });

  it('rings the frontier pill in frontier mode', () => {
    const { container } = render(
      <CredNode node={{ ...base, id: 'c1', type: 'cred', label: 'svc', username: 'svc', cracked: false, frontier: true, frontierHost: true }} selected={false} privMode={false} frontierMode onMouseDown={() => {}} onClick={() => {}} />,
    );
    const ring = container.querySelector('rect[stroke="#f09a3a"]');
    expect(ring).toBeTruthy();
  });

  it('clicks report the node', () => {
    const onClick = vi.fn();
    const { container } = render(
      <CredNode node={{ ...base, id: 'c1', type: 'cred', label: 'svc', username: 'svc' }} selected={false} privMode={false} onMouseDown={() => {}} onClick={onClick} />,
    );
    fireEvent.click(container.firstChild);
    expect(onClick).toHaveBeenCalledWith(expect.objectContaining({ id: 'c1' }));
  });
});

describe('HostNode', () => {
  it('renders the hostname, IP and status', () => {
    render(
      <HostNode node={{ ...base, id: 'h1', type: 'host', label: 'DC01', ip: '10.0.0.10', status: 'pwned', os: 'Windows Server 2022' }} selected={false} privMode={false} onMouseDown={() => {}} onClick={() => {}} />,
    );
    expect(screen.getByText('DC01')).toBeTruthy();
    expect(screen.getByText('10.0.0.10')).toBeTruthy();
    expect(screen.getByText('PWNED')).toBeTruthy();
    expect(screen.getByText('WIN')).toBeTruthy();
  });

  it('shows the DA badge for DA-capable hosts', () => {
    render(
      <HostNode node={{ ...base, id: 'h1', type: 'host', label: 'DC01', status: 'pwned', privilege_info: { is_da_capable: true, is_dc: true } }} selected={false} privMode={false} onMouseDown={() => {}} onClick={() => {}} />,
    );
    expect(screen.getByText('DC')).toBeTruthy();
  });

  it('shows reachability and ports badges', () => {
    render(
      <HostNode node={{ ...base, id: 'h1', type: 'host', label: 'WS01', status: 'alive', reachability: { distance: 2, reachable: true }, ports: ['445', '22', '80'] }} selected={false} privMode={false} onMouseDown={() => {}} onClick={() => {}} />,
    );
    expect(screen.getByText('r2')).toBeTruthy();
    expect(screen.getByText('3p')).toBeTruthy();
  });

  it('renders the attacker sublabel for the attacker node', () => {
    render(
      <HostNode node={{ ...base, id: 'atk', type: 'attacker', is_attacker: true, label: 'attack-box', status: 'attacker' }} selected={false} privMode={false} onMouseDown={() => {}} onClick={() => {}} />,
    );
    expect(screen.getByText('◆ ATTACKER')).toBeTruthy();
  });

  it('dims non-frontier hosts in frontier mode', () => {
    const { container } = render(
      <HostNode node={{ ...base, id: 'h1', type: 'host', label: 'WS01', status: 'alive', frontierDim: true }} selected={false} privMode={false} frontierMode onMouseDown={() => {}} onClick={() => {}} />,
    );
    expect(container.firstChild.style.opacity).toBe('0.25');
  });
});
