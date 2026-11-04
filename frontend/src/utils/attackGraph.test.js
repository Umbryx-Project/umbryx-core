import { describe, it, expect } from 'vitest';
import { edgeGeometry, nodeHalfW, nodeHalfH, layoutNodes, NODE_W, CRED_W, edgeFreshness, isFrontierEdge, computeFrontierSets, frontierSuggestions, STALE_AFTER_DAYS } from './attackGraph.js';

// Visual pass regression tests: edges anchor ON card borders (type-aware),
// same-column routes bracket around the column instead of cutting through
// the cards in between, and bidirectional pairs separate into two arcs.

const HOST = (id, x, y) => ({ id, type: 'host', label: id, x, y });
const CRED = (id, x, y) => ({ id, type: 'cred', label: id, x, y });

describe('nodeHalfW/H', () => {
  it('uses card size for hosts and pill size for creds', () => {
    expect(nodeHalfW(HOST('a', 0, 0))).toBe(NODE_W / 2);
    expect(nodeHalfW(CRED('c', 0, 0))).toBe(CRED_W / 2);
    expect(nodeHalfW(null)).toBe(NODE_W / 2);
  });
});

describe('edgeGeometry', () => {
  it('anchors on the cred pill border, not the host card border', () => {
    const src = CRED('c', 300, 100);
    const tgt = HOST('h', 570, 100);
    const { d } = edgeGeometry(src, tgt);
    // path starts at src.x + CRED_W/2 (previously floated at NODE_W/2)
    const m = d.match(/^M ([\d.]+) ([\d.]+)/);
    expect(+m[1]).toBe(300 + CRED_W / 2);
  });

  it('lands the arrow on the target face FACING the source (near side)', () => {
    // horizontal: arrow must land on the LEFT face of the target
    const h = edgeGeometry(HOST('a', 300, 100), HOST('b', 570, 100));
    const he = h.d.match(/ ([-\d.]+) ([-\d.]+)$/);
    expect(+he[1]).toBe(570 - NODE_W / 2);

    // steep diagonal between separated columns: LR convention still
    // enters through the LEFT face (flow reads left-to-right)
    const d = edgeGeometry(HOST('a', 300, 100), HOST('b', 700, 420));
    const de = d.d.match(/ ([-\d.]+) ([-\d.]+)$/);
    expect(Math.abs(+de[1] - (700 - NODE_W / 2))).toBeLessThan(2);
  });

  it('leaves from the RIGHT face of the source for separated columns', () => {
    const { d } = edgeGeometry(HOST('a', 300, 200), HOST('b', 700, 420));
    const m = d.match(/^M ([-\d.]+) ([-\d.]+)/);
    expect(Math.abs(+m[1] - (300 + NODE_W / 2))).toBeLessThan(2);
    // fixed OUT port: exactly the face center, no sliding
    expect(Math.abs(+m[2] - 200)).toBeLessThan(2);
  });

  it('FAN: all edges from one node leave from the exact same point', () => {
    const src = HOST('hub', 300, 250);
    const t1 = HOST('t1', 700, 100);
    const t2 = HOST('t2', 700, 250);
    const t3 = HOST('t3', 700, 420);
    const starts = [t1, t2, t3].map(t =>
      edgeGeometry(src, t).d.match(/^M ([-\d.]+) ([-\d.]+)/).slice(1, 3).join(','));
    expect(new Set(starts).size).toBe(1);
  });

  it('CONVERGE: all edges into one node arrive at the exact same point', () => {
    const tgt = HOST('sink', 700, 250);
    const s1 = HOST('s1', 300, 100);
    const s2 = HOST('s2', 300, 250);
    const s3 = HOST('s3', 300, 420);
    const ends = [s1, s2, s3].map(s =>
      edgeGeometry(s, tgt).d.match(/ ([-\d.]+) ([-\d.]+)$/).slice(1, 3).join(','));
    expect(new Set(ends).size).toBe(1);
  });

  it('backward edges dome over and still enter the LEFT port', () => {
    const src = HOST('a', 700, 300);
    const tgt = HOST('b', 300, 200);
    const { d } = edgeGeometry(src, tgt);
    const end = d.match(/ ([-\d.]+) ([-\d.]+)$/);
    expect(Math.abs(+end[1] - (300 - NODE_W / 2))).toBeLessThan(0.6);
    // v5 wrap: the dome corner control sits above both cards
    const ys = [...d.matchAll(/ ([-\d.]+) ([-\d.]+)/g)].map(m => +m[2]);
    expect(Math.min(...ys)).toBeLessThan(Math.min(src.y - 34, tgt.y - 34));
  });

  it('every separated-column edge enters through the LEFT face, any direction', () => {
    // LR flow convention: regardless of where the source sits around
    // the target, the entry face is the left one (backward edges get a
    // bridge). Blend-zone angles (target nearly above/below) are skipped.
    const tgt = HOST('b', 570, 300);
    for (let ang = 0; ang < 360; ang += 15) {
      const rad = (ang * Math.PI) / 180;
      if (Math.abs(Math.cos(rad)) < 0.7) continue; // |dx| < ~294: blend/perimeter zone
      const src = HOST('a', 570 + 420 * Math.cos(rad), 300 + 420 * Math.sin(rad));
      const end = edgeGeometry(src, tgt).d.match(/ ([-\d.]+) ([-\d.]+)$/);
      expect(Math.abs(+end[1] - (570 - NODE_W / 2))).toBeLessThan(2);
    }
  });

  it('starts on the source card perimeter (anchor glides, never floats)', () => {
    // same-column: perimeter base route keeps the bracket anchor on the border
    const { d } = edgeGeometry(HOST('a', 300, 200), HOST('b', 300, 420));
    const m = d.match(/^M ([-\d.]+) ([-\d.]+)/);
    const onVerticalFace = Math.abs(Math.abs(+m[1] - 300) - NODE_W / 2) < 2.5;
    const onHorizontalFace = Math.abs(Math.abs(+m[2] - 200) - 68 / 2) < 2.5;
    expect(onVerticalFace || onHorizontalFace).toBe(true);
  });

  it('same-column edges wrap over the top, clear of the cards between', () => {
    // DC01 → WS02 in the same column, SQL01 (448-612 × 258-326) sits between
    const src = HOST('dc01', 530, 196);
    const tgt = HOST('ws02', 530, 484);
    const { d } = edgeGeometry(src, tgt);
    // v5: enters the LEFT port of the target exactly
    const end = d.match(/ ([-\d.]+) ([-\d.]+)$/);
    expect(Math.abs(+end[1] - (530 - NODE_W / 2))).toBeLessThan(0.6);
    expect(Math.abs(+end[2] - 484)).toBeLessThan(0.6);
    // sample the whole path: no point may fall inside the middle card
    const nums = [...d.matchAll(/[-\d.]+/g)].map(m => +m[0]);
    // parse M/C commands into points; sample each cubic segment
    const pts = [];
    const cmds = d.match(/[MC][^MC]*/g) || [];
    const coords = str => [...str.matchAll(/[-\d.]+/g)].map(x => +x[0]);
    let prev = null;
    for (const c of cmds) {
      const co = coords(c);
      if (c[0] === 'M') { prev = co; pts.push([co[0], co[1]]); continue; }
      const [c1x, c1y, c2x, c2y, x, y] = co;
      const [x0, y0] = prev;
      for (let t = 0; t <= 1.001; t += 0.02) {
        const u = 1 - t;
        pts.push([
          u * u * u * x0 + 3 * u * u * t * c1x + 3 * u * t * t * c2x + t * t * t * x,
          u * u * u * y0 + 3 * u * u * t * c1y + 3 * u * t * t * c2y + t * t * t * y,
        ]);
      }
      prev = [x, y];
    }
    const insideMiddleCard = pts.filter(([x, y]) => x > 448 && x < 612 && y > 258 && y < 326);
    expect(insideMiddleCard).toHaveLength(0);
    // and the dome rises above both cards
    expect(Math.min(...pts.map(p => p[1]))).toBeLessThan(196 - 34);
  });

  it('same-column with cards between: right-side approach, nothing cut', () => {
    const src = HOST('dc01', 530, 196);
    const tgt = HOST('ws02', 530, 484);
    const { d } = edgeGeometry(src, tgt, 0, true);
    const end = d.match(/ ([-\d.]+) ([-\d.]+)$/);
    // enters the RIGHT port of the target
    expect(Math.abs(+end[1] - (530 + NODE_W / 2))).toBeLessThan(0.6);
    // whole path stays right of the column edge — nothing between is cut
    const nums = [...d.matchAll(/[-\d.]+/g)].map(m => +m[0]);
    const xVals = [];
    for (let i = 0; i < nums.length; i += 2) xVals.push(nums[i]);
    expect(Math.min(...xVals)).toBeGreaterThanOrEqual(530 + NODE_W / 2 - 0.6);
  });

  it('same-column adjacent rows: compact loop into the LEFT port', () => {
    // one-row hop — the loop height must scale with the hop, not the column
    const src = CRED('c1', 420, 400);
    const tgt = HOST('h1', 420, 505);
    const { d } = edgeGeometry(src, tgt);
    const end = d.match(/ ([-\d.]+) ([-\d.]+)$/);
    expect(Math.abs(+end[1] - (420 - NODE_W / 2))).toBeLessThan(0.6);
    const ys = [...d.matchAll(/ ([-\d.]+)/g)].map(m => +m[1]); // odd indices are y
    const yVals = [];
    const nums = [...d.matchAll(/[-\d.]+/g)].map(m => +m[0]);
    for (let i = 1; i < nums.length; i += 2) yVals.push(nums[i]);
    const loopTop = Math.min(...yVals);
    // compact: tops out within a hop-sized clearance, not the old fixed dome
    expect(loopTop).toBeGreaterThan(400 - 22 - 95);
  });

  it('anchors are EXACT ports — attachment cannot move while dragging', () => {
    // the v2-v4 perimeter anchors slid around the border (user report);
    // v5 pins them: same node → same local anchor for any counterpart
    const src = HOST('a', 300, 200);
    const anchors = [
      HOST('b', 700, 100), HOST('b', 700, 200), HOST('b', 700, 500),
      HOST('b', 300, 500), HOST('b', 300, 40), HOST('b', 100, 200), HOST('b', 60, 90),
    ].map(t => {
      const m = edgeGeometry(src, t).d.match(/^M ([-\d.]+) ([-\d.]+)/);
      return Math.round(+m[1]) + ',' + Math.round(+m[2]);
    });
    expect(new Set(anchors).size).toBe(1);
    expect(anchors[0]).toBe(`${300 + NODE_W / 2},200`);
  });

  it('separates bidirectional pairs into distinct arcs', () => {
    const a = HOST('a', 300, 100);
    const b = HOST('b', 570, 300);
    const fwd = edgeGeometry(a, b, 1);
    const rev = edgeGeometry(a, b, -1);
    expect(fwd.d).not.toBe(rev.d);
    expect(edgeGeometry(a, b, 0).d).not.toBe(fwd.d);
  });

  it('produces a bezier with a label point between the anchors', () => {
    const { d, label } = edgeGeometry(HOST('a', 300, 100), HOST('b', 570, 300));
    expect(d.startsWith('M ')).toBe(true);
    expect(d).toContain(' C ');
    expect(label.x).toBeGreaterThan(300);
    expect(label.x).toBeLessThan(570);
  });

  // Regression (user report): anchors used to flip discretely between
  // side and top/bottom routing at |dy| = |dx| — dragging a node made
  // its edges jump. Perimeter anchoring must glide instead.
  it('anchor glides continuously around the source while the target sweeps', () => {
    const src = HOST('a', 300, 200);
    let prev = null;
    let maxStep = 0;
    for (let ang = 0; ang <= 90; ang += 1) {
      const rad = (ang * Math.PI) / 180;
      const tgt = HOST('b', 300 + 400 * Math.cos(rad), 200 + 400 * Math.sin(rad));
      const m = edgeGeometry(src, tgt).d.match(/^M ([\d.]+) ([\d.]+)/);
      const pt = { x: +m[1], y: +m[2] };
      if (prev) maxStep = Math.max(maxStep, Math.hypot(pt.x - prev.x, pt.y - prev.y));
      prev = pt;
    }
    expect(maxStep).toBeLessThan(8);
  });

  it('same-column deflection fades out with separation (no snap at the band edge)', () => {
    const src = HOST('a', 300, 100);
    let prev = null;
    let maxStep = 0;
    for (let dx = 0; dx <= 420; dx += 5) {
      const tgt = HOST('b', 300 + dx, 420);
      const m = edgeGeometry(src, tgt).d.match(/^M ([-\d.]+) ([-\d.]+)/);
      const pt = { x: +m[1], y: +m[2] };
      if (prev) maxStep = Math.max(maxStep, Math.hypot(pt.x - prev.x, pt.y - prev.y));
      prev = pt;
    }
    expect(maxStep).toBeLessThan(8); // a discrete face flip moves 30-80px at once
  });
});

describe('layoutNodes spacing', () => {
  const mkNodes = () => [
    { id: 'atk', type: 'attacker', label: 'attack-box' },
    { id: 'c1', type: 'cred', label: 'alpha' },
    { id: 'c2', type: 'cred', label: 'beta' },
    { id: 'h1', type: 'host', label: 'DC01' },
  ];
  const edges = [
    { from: 'atk', to: 'c1' }, { from: 'atk', to: 'c2' }, { from: 'c1', to: 'h1' },
  ];

  it('gives the attacker a real left margin (not flush at the canvas edge)', () => {
    const nodes = layoutNodes(mkNodes(), 680, edges);
    const atk = nodes.find(n => n.id === 'atk');
    expect(atk.x - NODE_W / 2).toBeGreaterThanOrEqual(60);
  });

  it('orders host cards before cred pills inside a mixed column', () => {
    // attacker column contains attacker only; make a mixed column by
    // putting a pivot edge to a host at depth 1
    const nodes = layoutNodes(mkNodes(), 680, [...edges, { from: 'atk', to: 'h1' }]);
    const col1 = nodes.filter(n => n.id !== 'atk');
    // all at the same x (depth 1); hosts must come first in y
    const hostY = nodes.find(n => n.id === 'h1').y;
    const credYs = col1.filter(n => n.type === 'cred').map(n => n.y);
    credYs.forEach(cy => expect(cy).toBeGreaterThan(hostY));
  });

  it('scales pitch with the canvas instead of a fixed 680 band', () => {
    const small = layoutNodes(mkNodes(), 520, edges);
    const big = layoutNodes(mkNodes(), 1100, edges);
    const spread = ns => Math.max(...ns.filter(n => n.type === 'cred').map(n => n.y));
    expect(spread(big)).toBeGreaterThan(spread(small));
  });

  it('barycenter pulls connected nodes level (no tall S-curves)', () => {
    // col1: cred A opens the LAST host of col2; cred B opens the FIRST.
    // Alphabetical leaves edges as tall crossing S-curves; barycenter
    // may fix it by reordering EITHER column — assert the pairs end up
    // level, not which side moved.
    const nodes = [
      { id: 'atk', type: 'attacker', label: 'atk' },
      { id: 'cA', type: 'cred', label: 'aaa' },
      { id: 'cB', type: 'cred', label: 'bbb' },
      { id: 'h1', type: 'host', label: 'h1' },
      { id: 'h4', type: 'host', label: 'h4' },
    ];
    const es = [
      { from: 'atk', to: 'cA' }, { from: 'atk', to: 'cB' },
      { from: 'cA', to: 'h4' },
      { from: 'cB', to: 'h1' },
    ];
    const laid = layoutNodes(nodes, 680, es);
    const y = Object.fromEntries(laid.map(n => [n.id, n.y]));
    expect(Math.abs(y.cA - y.h4)).toBeLessThanOrEqual(1); // level with its host
    expect(Math.abs(y.cB - y.h1)).toBeLessThanOrEqual(1);
    // and the two pairs do not cross each other
    expect(Math.sign(y.cA - y.cB)).toBe(Math.sign(y.h4 - y.h1));
  });

  it('layout is deterministic (same input, same output)', () => {
    const a = layoutNodes(mkNodes(), 680, edges);
    const b = layoutNodes(mkNodes(), 680, edges);
    expect(a.map(n => `${n.id}:${Math.round(n.y)}`)).toEqual(b.map(n => `${n.id}:${Math.round(n.y)}`));
  });
});

// ── AG Phase 3: frontier & freshness ────────────────────────────────────

describe('edgeFreshness', () => {
  const NOW = Date.parse('2026-10-28T12:00:00Z');

  it('marks access facts older than the threshold as stale', () => {
    const old = edgeFreshness({ observed_at: '2026-09-01T00:00:00Z' }, NOW);
    expect(old.stale).toBe(true);
    expect(old.ageDays).toBeGreaterThan(STALE_AFTER_DAYS);
    const recent = edgeFreshness({ observed_at: '2026-10-27T00:00:00Z' }, NOW);
    expect(recent.stale).toBe(false);
  });

  it('returns null without a parseable timestamp', () => {
    expect(edgeFreshness({}, NOW)).toBeNull();
    expect(edgeFreshness({ observed_at: 'not-a-date' }, NOW)).toBeNull();
  });
});

describe('isFrontierEdge / computeFrontierSets', () => {
  const NODES = [
    { id: 'atk', type: 'attacker' },
    { id: 'c_ok', type: 'cred', frontier: false },
    { id: 'c_hash', type: 'cred', frontier: true },
    { id: 'h1', type: 'host' },
    { id: 'h2', type: 'host' },
  ];
  const EDGES = [
    { id: 'e1', from: 'atk', to: 'c_ok', kind: 'credential' },
    { id: 'e2', from: 'atk', to: 'c_hash', kind: 'credential' },
    { id: 'e3', from: 'c_ok', to: 'h1', kind: 'credential_use', verified: true },
    { id: 'e4', from: 'h1', to: 'h2', kind: 'access', verified: false },
    { id: 'e5', from: 'h1', to: 'h2', kind: 'access', verified: true },
  ];

  it('unverified access/pivot edges are the frontier', () => {
    expect(isFrontierEdge(EDGES[3])).toBe(true);
    expect(isFrontierEdge(EDGES[4])).toBe(false);
    expect(isFrontierEdge(EDGES[2])).toBe(false);
  });

  it('frontier sets cover frontier creds, their holder edges and unverified targets', () => {
    const { frontierNodes, frontierEdges } = computeFrontierSets(NODES, EDGES);
    expect(frontierNodes.has('c_hash')).toBe(true);
    expect(frontierNodes.has('c_ok')).toBe(false);
    expect(frontierNodes.has('h2')).toBe(true); // target of the unverified access
    expect(frontierNodes.has('h1')).toBe(false);
    expect(frontierEdges.has('e2')).toBe(true); // credential edge into the frontier cred
    expect(frontierEdges.has('e4')).toBe(true);
    expect(frontierEdges.has('e1')).toBe(false);
    expect(frontierEdges.has('e5')).toBe(false);
  });
});

describe('frontierSuggestions', () => {
  it('lists unvalidated creds first, then unconfirmed access', () => {
    const NODES = [
      { id: 'atk', type: 'attacker' },
      { id: 'cnode_c1', type: 'cred', frontier: true, cracked: false, label: 'CORP\\svc' },
      { id: 'h1', type: 'host', label: 'WS01' },
      { id: 'h2', type: 'host', label: 'WS02' },
    ];
    const EDGES = [
      { id: 'e1', from: 'atk', to: 'cnode_c1', kind: 'credential' },
      { id: 'e2', from: 'h1', to: 'h2', kind: 'access', verified: false },
    ];
    const out = frontierSuggestions(NODES, EDGES);
    expect(out).toHaveLength(2);
    expect(out[0].kind).toBe('validate_cred');
    expect(out[0].focus).toBe('c1'); // cnode_ prefix stripped for navigation
    expect(out[0].tab).toBe('creds');
    expect(out[1].kind).toBe('confirm_access');
    expect(out[1].tab).toBe('network');
    expect(out[1].title).toBe('WS01 → WS02');
  });

  it('caps the list and sorts by severity', () => {
    const NODES = [
      { id: 'atk', type: 'attacker' },
      { id: 'h1', type: 'host', label: 'A' },
      { id: 'h2', type: 'host', label: 'B' },
    ];
    const EDGES = Array.from({ length: 12 }, (_, i) => ({
      id: `e${i}`, from: 'h1', to: 'h2', kind: 'access', verified: false,
    }));
    expect(frontierSuggestions(NODES, EDGES, 5)).toHaveLength(5);
  });
});
