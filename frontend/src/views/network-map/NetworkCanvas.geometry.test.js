import { describe, it, expect } from 'vitest';
import { _mergeServerGeometry, _segmentIntersectsRect, _computeVisible } from './NetworkCanvas.jsx';

const refOf = (...ids) => ({ current: new Set(ids) });

function node(id, x, y, version = 1) {
  return { id, x, y, version, manually_positioned: true };
}

describe('_mergeServerGeometry — nodes', () => {
  it("accepts a teammate's move instead of overwriting it with the local draft", () => {
    // The teammate moved n1 to (500,500) and the server bumped its version.
    const server = { nodes: [node('n1', 500, 500, 2)] };
    const draft = { nodes: [node('n1', 10, 10, 1)] };
    _mergeServerGeometry(server, draft, refOf(), refOf());
    expect(server.nodes[0]).toMatchObject({ x: 500, y: 500 });
  });

  it('keeps our own position while the move is still in flight', () => {
    const server = { nodes: [node('n1', 10, 10, 1)] };
    const draft = { nodes: [node('n1', 400, 400, 1)] };
    _mergeServerGeometry(server, draft, refOf('n1'), refOf());
    expect(server.nodes[0]).toMatchObject({ x: 400, y: 400 });
  });

  it('keeps the draft when it carries a newer version than the server', () => {
    const server = { nodes: [node('n1', 10, 10, 1)] };
    const draft = { nodes: [node('n1', 400, 400, 5)] };
    _mergeServerGeometry(server, draft, refOf(), refOf());
    expect(server.nodes[0]).toMatchObject({ x: 400, y: 400 });
  });

  it('leaves nodes the draft does not know about untouched', () => {
    const server = { nodes: [node('new', 77, 88, 1)] };
    _mergeServerGeometry(server, { nodes: [node('other', 1, 1)] }, refOf(), refOf());
    expect(server.nodes[0]).toMatchObject({ x: 77, y: 88 });
  });

  it('applies per node, not all-or-nothing', () => {
    const server = { nodes: [node('mine', 0, 0, 1), node('theirs', 300, 300, 2)] };
    const draft = { nodes: [node('mine', 50, 50, 1), node('theirs', 9, 9, 1)] };
    _mergeServerGeometry(server, draft, refOf('mine'), refOf());
    expect(server.nodes[0]).toMatchObject({ x: 50, y: 50 });   // in flight → ours
    expect(server.nodes[1]).toMatchObject({ x: 300, y: 300 });  // theirs wins
  });
});

describe('_mergeServerGeometry — regions', () => {
  const region = (id, x, y, w, h, version = 1) => ({ id, x, y, w, h, version });

  it("accepts a teammate's region move and resize", () => {
    const server = { regions: [region('r1', 200, 200, 400, 400, 2)] };
    const draft = { regions: [region('r1', 0, 0, 10, 10, 1)] };
    _mergeServerGeometry(server, draft, refOf(), refOf());
    expect(server.regions[0]).toMatchObject({ x: 200, y: 200, w: 400, h: 400 });
  });

  it('keeps our own region geometry while in flight', () => {
    const server = { regions: [region('r1', 0, 0, 10, 10, 1)] };
    const draft = { regions: [region('r1', 60, 60, 90, 90, 1)] };
    _mergeServerGeometry(server, draft, refOf(), refOf('r1'));
    expect(server.regions[0]).toMatchObject({ x: 60, y: 60, w: 90, h: 90 });
  });

  // Regression (region-vanish): after a drag the draft region carries the
  // bookkept server version; when the draft geometry wins the merge must
  // ALSO carry the draft version onto the clone — otherwise the clone's
  // stale version replaces it and the SECOND incoming merge (draft no
  // longer "newer") yanks the region back to the store's stale geometry.
  it('carries the draft version when draft region geometry wins', () => {
    const server = { regions: [region('r1', 0, 0, 10, 10, 1)] };  // stale store copy
    const draft = { regions: [region('r1', 60, 60, 90, 90, 2)] }; // dragged + bookkept
    _mergeServerGeometry(server, draft, refOf(), refOf());
    expect(server.regions[0]).toMatchObject({ x: 60, y: 60, w: 90, h: 90, version: 2 });
  });

  it('does not regress the server version when the draft is stale', () => {
    const server = { regions: [region('r1', 200, 200, 400, 400, 5)] };
    const draft = { regions: [region('r1', 0, 0, 10, 10, 2)] };
    _mergeServerGeometry(server, draft, refOf('r1'), refOf());  // in flight, draft wins
    expect(server.regions[0].version).toBe(5);
  });
});

describe('_mergeServerGeometry — robustness', () => {
  it('tolerates empty collections and missing refs', () => {
    expect(() => _mergeServerGeometry({}, {}, undefined, undefined)).not.toThrow();
    expect(() => _mergeServerGeometry({ nodes: [] }, { nodes: [] }, refOf(), refOf())).not.toThrow();
  });
});


describe('_segmentIntersectsRect — edge viewport culling', () => {
  const rect = (l, t, r, b) => [l, t, r, b];

  it('keeps an edge whose far endpoint is off-screen but whose line crosses the viewport', () => {
    // user's exact case: one endpoint visible, the other far outside
    expect(_segmentIntersectsRect(500, 500, -5000, -5000, ...rect(0, 0, 1000, 1000))).toBe(true);
  });

  it('keeps an edge crossing the viewport with BOTH endpoints off-screen', () => {
    // a long link passing diagonally through the visible area
    expect(_segmentIntersectsRect(-2000, 0, 2000, 1000, ...rect(0, 0, 1000, 1000))).toBe(true);
  });

  it('culls an edge entirely outside the viewport', () => {
    expect(_segmentIntersectsRect(-2000, -2000, -1000, -1000, ...rect(0, 0, 1000, 1000))).toBe(false);
  });

  it('culls an edge fully to one side', () => {
    expect(_segmentIntersectsRect(2000, 100, 3000, 200, ...rect(0, 0, 1000, 1000))).toBe(false);
  });

  it('accepts an endpoint inside the rect', () => {
    expect(_segmentIntersectsRect(100, 100, 9000, 9000, ...rect(0, 0, 1000, 1000))).toBe(true);
  });
});

describe('_computeVisible — edges survive one endpoint off-screen', () => {
  const all = new Set(['a', 'b', 'c']);
  const nodes = [
    { id: 'a', x: 500, y: 500 },
    { id: 'b', x: 5000, y: 5000 },   // far outside
    { id: 'c', x: 3000, y: 3000 },
  ];
  const edges = [
    { from: 'a', to: 'b' },          // crosses viewport diagonally
    { from: 'b', to: 'c' },          // fully outside
    { from: 'a', to: 'a' },          // self
  ];
  const viewport = { width: 1000, height: 1000 };

  it('renders the crossing edge, culls the outside one', () => {
    const { visibleEdges } = _computeVisible(nodes, edges, all, viewport, { x: 0, y: 0 }, 1, 0);
    const ids = visibleEdges.map(e => `${e.from}->${e.to}`);
    expect(ids).toContain('a->b');
    expect(ids).not.toContain('b->c');
  });

  it('still culls edges of collapsed clusters', () => {
    const withoutB = new Set(['a', 'c']);
    const { visibleEdges } = _computeVisible(nodes, edges, withoutB, viewport, { x: 0, y: 0 }, 1, 0);
    // every edge touching the collapsed node b is gone; the self-loop on
    // the visible node a stays (same as the pre-fix behavior)
    const flat = visibleEdges.map(e => [e.from, e.to]).flat();
    expect(flat).not.toContain('b');
    expect(visibleEdges.map(e => `${e.from}->${e.to}`)).toEqual(['a->a']);
  });

  it('zero viewport falls back to expanded-only (old behavior)', () => {
    const { visibleEdges } = _computeVisible(nodes, edges, all, { width: 0, height: 0 }, { x: 0, y: 0 }, 1);
    expect(visibleEdges).toHaveLength(3);
  });
});
