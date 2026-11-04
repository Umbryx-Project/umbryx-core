import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { HowWeGotHere, WhatItOpens } from './GraphPanels.jsx';
import { pathFromAttacker, opensFrom, chainEdgeLabel, fitNodesToViewport } from '../../utils/attackGraph.js';

// AG Phase 2 comprehension helpers: the "how we got here" chain and
// "what it opens" replace the raw edge list in the side panel.

const NODES = [
  { id: 'atk', label: 'attack-box', type: 'attacker', is_attacker: true },
  { id: 'c_ivanov', label: 'corp\\ivanov', type: 'cred', username: 'ivanov', cracked: true },
  { id: 'ws01', label: 'WS01', type: 'host', x: 300, y: 100 },
  { id: 'dc01', label: 'DC01', type: 'host', x: 520, y: 100 },
];
const EDGES = [
  { id: 'e1', from: 'atk', to: 'c_ivanov', kind: 'credential' },
  { id: 'e2', from: 'c_ivanov', to: 'ws01', kind: 'credential_use' },
  { id: 'e3', from: 'ws01', to: 'dc01', kind: 'access', access_type: 'lateral', verified: true },
  { id: 'e4', from: 'ws01', to: 'nowhere', kind: 'access' }, // dangling target
];

describe('pathFromAttacker', () => {
  it('builds the chain attacker → cred → host with the via edges', () => {
    const chain = pathFromAttacker(NODES, EDGES, 'ws01');
    expect(chain).toBeTruthy();
    expect(chain.map(s => s.node.id)).toEqual(['atk', 'c_ivanov', 'ws01']);
    expect(chain[1].viaEdge.kind).toBe('credential');
    expect(chain[2].viaEdge.kind).toBe('credential_use');
  });

  it('returns null for unreachable nodes', () => {
    expect(pathFromAttacker(NODES, EDGES, 'ghost')).toBeNull();
  });
});

describe('opensFrom', () => {
  it('lists successors with nodes, skipping dangling targets', () => {
    const opens = opensFrom(NODES, EDGES, 'ws01');
    expect(opens).toHaveLength(1);
    expect(opens[0].node.id).toBe('dc01');
    expect(opens[0].edge.access_type).toBe('lateral');
  });
});

describe('chainEdgeLabel', () => {
  it('humanizes the edge kinds', () => {
    expect(chainEdgeLabel({ kind: 'credential' })).toBe('holds');
    expect(chainEdgeLabel({ kind: 'credential_use' })).toBe('opens');
    expect(chainEdgeLabel({ kind: 'access', access_type: 'domain_admin' })).toBe('domain admin');
    expect(chainEdgeLabel(null)).toBe('');
  });
});

describe('fitNodesToViewport', () => {
  it('centers and scales a path into the viewport', () => {
    const fit = fitNodesToViewport(
      [NODES[2], NODES[3]],
      { width: 1000, height: 600 },
      { x: 0, y: 0 },
      1,
    );
    expect(fit.zoom).toBeGreaterThan(0);
    // path center (410, 100) lands at viewport center
    expect(Math.round(fit.pan.x + 410 * fit.zoom)).toBeCloseTo(500, -1);
    expect(Math.round(fit.pan.y + 100 * fit.zoom)).toBeCloseTo(300, -1);
  });

  it('returns null for an empty path', () => {
    expect(fitNodesToViewport([], { width: 800, height: 600 }, {}, 1)).toBeNull();
  });
});

describe('HowWeGotHere panel section', () => {
  it('renders the readable chain with cred node and edge labels', () => {
    const chain = pathFromAttacker(NODES, EDGES, 'ws01');
    render(<HowWeGotHere chain={chain} />);
    expect(screen.getByText('How we got here')).toBeTruthy();
    expect(screen.getByText(/ivanov/)).toBeTruthy();
    expect(screen.getByText('↓ holds')).toBeTruthy();
    expect(screen.getByText('↓ opens')).toBeTruthy();
  });

  it('hides for roots and unreachable nodes', () => {
    const { container } = render(<HowWeGotHere chain={null} />);
    expect(container.textContent).toBe('');
  });
});

describe('WhatItOpens panel section', () => {
  it('lists successors with the edge label', () => {
    render(<WhatItOpens opens={opensFrom(NODES, EDGES, 'ws01')} />);
    expect(screen.getByText(/Opens \/ leads to \(1\)/)).toBeTruthy();
    expect(screen.getByText('DC01')).toBeTruthy();
    expect(screen.getByText('lateral')).toBeTruthy();
  });

  it('hides when nothing opens', () => {
    const { container } = render(<WhatItOpens opens={[]} />);
    expect(container.textContent).toBe('');
  });
});
