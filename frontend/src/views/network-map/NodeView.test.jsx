import { describe, it, expect, vi } from 'vitest';
import { render } from '@testing-library/react';
import { NetworkNodeView } from './NodeView.jsx';

const NODE = { id: 'n1', x: 100, y: 100, type: 'host', status: 'up', label: 'srv-01', ip: '10.0.0.5' };

function renderNode(props = {}) {
  return render(
    <svg>
      <NetworkNodeView node={NODE} statusColor="#39d353" accent="#15bbb1" onMouseDown={vi.fn()} {...props} />
    </svg>,
  );
}

describe('NetworkNodeView', () => {
  it('renders the node label and its IP', () => {
    const { container } = renderNode();
    expect(container.textContent).toContain('srv-01');
    expect(container.textContent).toContain('10.0.0.5');
  });

  it('hides label/IP/badges in simplified mode unless selected', () => {
    const { container } = renderNode({ simplified: true });
    expect(container.textContent).not.toContain('srv-01');
    expect(container.textContent).not.toContain('10.0.0.5');
  });

  it('shows the label again in simplified mode when selected', () => {
    const { container } = renderNode({ simplified: true, isSelected: true });
    expect(container.textContent).toContain('srv-01');
  });

  it('renders no engagement marker when engagedBy is absent', () => {
    const { container } = renderNode();
    expect(container.querySelector('title')).toBeNull();
  });

  it('renders an engagement marker with a tooltip listing operators when engagedBy is set', () => {
    const engagedBy = {
      operators: [
        { username: 'alice', is_me: true, sources: ['claim'] },
        { username: 'bob', is_me: false, sources: ['job'] },
      ],
    };
    const { container } = renderNode({ engagedBy });
    const title = container.querySelector('title');
    expect(title).not.toBeNull();
    expect(title.textContent).toBe('Engaged: alice (you) [claim], bob [job]');
    // the current operator's username is visible on the map itself, not only on hover
    expect(container.textContent).toContain('alice+1');
  });

  it('truncates a long username in the visible engagement chip', () => {
    const engagedBy = { operators: [{ username: 'redteam-operator-nine', is_me: true, sources: ['claim'] }] };
    const { container } = renderNode({ engagedBy });
    expect(container.textContent).toContain('redteam-ope…');
  });

  it('renders a pivot chip labelled SOCKS for a socks5 pivot', () => {
    const { container } = renderNode({ pivotInfo: { type: 'socks5' } });
    expect(container.textContent).toContain('SOCKS');
  });

  it('renders a pivot chip labelled ROUTE for a route pivot', () => {
    const { container } = renderNode({ pivotInfo: { type: 'route' } });
    expect(container.textContent).toContain('ROUTE');
  });

  it('omits the pivot chip in simplified mode', () => {
    const { container } = renderNode({ pivotInfo: { type: 'socks5' }, simplified: true, isSelected: true });
    expect(container.textContent).not.toContain('SOCKS');
  });

  it('renders a zone chip for a non-scope zone_type, truncated to 4 chars', () => {
    const { container } = renderNode({ node: { ...NODE, zone_type: 'management' } });
    expect(container.textContent).toContain('MANA');
  });

  it('does not render a zone chip for zone_type "scope"', () => {
    const { container } = renderNode({ node: { ...NODE, zone_type: 'scope' } });
    expect(container.textContent).not.toContain('SCOP');
  });

  it('renders a tier badge for tier 0 or 1', () => {
    // Design (2026-10): the badge is a thin accent bar carrying an SVG
    // <title> tooltip ("Tier 0"/"Tier 1") instead of the old T0/T1 text.
    const t0 = renderNode({ node: { ...NODE, tier: 0 } });
    expect(t0.container.textContent).toContain('Tier 0');
    t0.unmount();

    const t1 = renderNode({ node: { ...NODE, tier: 1 } });
    expect(t1.container.textContent).toContain('Tier 1');
    t1.unmount();

    // tier also works via extra_json (backend spreads extra_json into node dicts)
    const tj = renderNode({ node: { ...NODE, extra_json: { tier: 1 } } });
    expect(tj.container.textContent).toContain('Tier 1');
    tj.unmount();

    const none = renderNode({ node: { ...NODE } });
    expect(none.container.textContent).not.toContain('Tier ');
    none.unmount();
  });

  it('renders role badges when provided', () => {
    const { container } = renderNode({ roleBadges: [{ id: 'r1', color: '#5b8af5', short: 'DC' }] });
    expect(container.textContent).toContain('DC');
  });
});
