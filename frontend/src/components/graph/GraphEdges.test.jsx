import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { createRef } from 'react';
import GraphEdge from './GraphEdges.jsx';
import { GraphSvg } from './GraphControls.jsx';
import { NODE_W, CRED_W } from '../../utils/attackGraph.js';

// Routing v5 + Phase 3 rendering: port-anchored paths, stale fading,
// hover tooltips, twin bends. The geometry math itself is unit-tested
// in attackGraph.test.js — these cover the component wiring.

const HOST = (id, x, y, extra = {}) => ({ id, type: 'host', label: id, x, y, status: 'alive', ...extra });
const CRED = (id, x, y, extra = {}) => ({ id, type: 'cred', label: id, x, y, ...extra });

const nodes = (extra = []) => [
  HOST('atk', 100, 200, { type: 'attacker', is_attacker: true }),
  CRED('cnode_c1', 400, 100),
  HOST('h1', 700, 300),
  ...extra,
];
const fwdEdge = { id: 'e1', from: 'cnode_c1', to: 'h1', kind: 'credential_use', verified: true };
const holdEdge = { id: 'e2', from: 'atk', to: 'cnode_c1', kind: 'credential' };

function pathOf(container) {
  const p = container.querySelector('path[d]');
  return p.getAttribute('d');
}

describe('GraphEdge', () => {
  it('renders a forward S-curve from the right port to the left port', () => {
    const { container } = render(
      <GraphEdge edge={fwdEdge} nodes={nodes()} privMode={false} dimmed={false} selectedNode={null} />,
    );
    const d = pathOf(container);
    const m = d.match(/^M ([\d.]+) ([\d.]+)/);
    // leaves the cred pill's right port exactly
    expect(+m[1]).toBe(400 + CRED_W / 2);
    const end = d.match(/ ([\d.]+) ([\d.]+)$/);
    // enters the host's left port exactly
    expect(+end[1]).toBe(700 - NODE_W / 2);
  });

  it('reports hover with edge, both nodes and pointer position', () => {
    const onHover = vi.fn();
    const { container } = render(
      <GraphEdge edge={fwdEdge} nodes={nodes()} privMode={false} dimmed={false} selectedNode={null} onHover={onHover} />,
    );
    fireEvent.mouseEnter(container.querySelector('g'), { clientX: 10, clientY: 20 });
    expect(onHover).toHaveBeenCalledTimes(1);
    const [edge, src, tgt, pos] = onHover.mock.calls[0];
    expect(edge.id).toBe('e1');
    expect(src.id).toBe('cnode_c1');
    expect(tgt.id).toBe('h1');
    expect(pos).toEqual({ x: 10, y: 20 });
  });

  it('clears hover on mouse leave', () => {
    const onHover = vi.fn();
    const { container } = render(
      <GraphEdge edge={fwdEdge} nodes={nodes()} privMode={false} dimmed={false} selectedNode={null} onHover={onHover} />,
    );
    const g = container.querySelector('g');
    fireEvent.mouseEnter(g, { clientX: 1, clientY: 2 });
    fireEvent.mouseLeave(g);
    expect(onHover).toHaveBeenLastCalledWith(null);
  });

  it('fades stale pivot facts to 0.28 opacity', () => {
    const old = '2020-01-01T00:00:00Z';
    const { container } = render(
      <GraphEdge edge={{ ...holdEdge, kind: 'pivot', observed_at: old }} nodes={nodes()} privMode={false} dimmed={false} selectedNode={null} />,
    );
    const paths = [...container.querySelectorAll('path')].filter(p => p.getAttribute('stroke') !== 'transparent');
    expect(paths[0].getAttribute('stroke-opacity')).toBe('0.28');
  });

  it('keeps an invisible wide hit path for hover precision', () => {
    const { container } = render(
      <GraphEdge edge={fwdEdge} nodes={nodes()} privMode={false} dimmed={false} selectedNode={null} />,
    );
    const hit = [...container.querySelectorAll('path')].find(p => p.getAttribute('stroke') === 'transparent');
    expect(hit).toBeTruthy();
    expect(+hit.getAttribute('stroke-width')).toBeGreaterThanOrEqual(10);
  });

  it('renders nothing for dangling endpoints', () => {
    const { container } = render(
      <GraphEdge edge={{ id: 'x', from: 'ghost', to: 'h1', kind: 'access' }} nodes={nodes()} privMode={false} dimmed={false} selectedNode={null} />,
    );
    expect(container.querySelector('path[d]')).toBeNull();
  });
});

describe('GraphSvg', () => {
  it('renders host cards, cred pills and edges; forwards ref to the svg', () => {
    const ref = createRef();
    const ns = nodes();
    const { container } = render(
      <GraphSvg
        ref={ref}
        nodes={ns}
        edges={[fwdEdge, holdEdge]}
        arrowColors={['#39d353', '#5b8af5']}
        pan={{ x: 0, y: 0 }}
        zoom={1}
        privMode={false}
        selectedNode={null}
        selectedPathEdgePairs={new Set()}
        handleNodeMouseDown={() => {}}
        handleNodeClick={() => {}}
      />,
    );
    expect(ref.current.tagName).toBe('svg');
    // one visible + one hit path per edge (marker arrowheads excluded)
    const ds = [...container.querySelectorAll('path[d]')].filter(p => p.getAttribute('d').startsWith('M '));
    expect(ds.length).toBe(4);
    // marker defs for both colors
    expect(container.querySelectorAll('marker').length).toBe(2);
  });

  it('gives a bidirectional pair opposite bends', () => {
    // pair detection is internal; assert indirectly — both edges render
    // with different d (they must not overlap exactly)
    const ns = nodes();
    const a = { id: 'ab', from: 'h1', to: 'cnode_c1', kind: 'access' };
    const b = { id: 'ba', from: 'cnode_c1', to: 'h1', kind: 'access' };
    const { container } = render(
      <GraphSvg
        nodes={ns}
        edges={[a, b]}
        arrowColors={['#f09a3a']}
        pan={{ x: 0, y: 0 }}
        zoom={1}
        privMode={false}
        selectedNode={null}
        selectedPathEdgePairs={new Set()}
        handleNodeMouseDown={() => {}}
        handleNodeClick={() => {}}
      />,
    );
    const ds = [...container.querySelectorAll('path[d]')]
      .map(p => p.getAttribute('d'))
      .filter(d => d.startsWith('M '));
    expect(new Set(ds).size).toBe(2);
  });
});
