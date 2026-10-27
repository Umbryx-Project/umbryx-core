import { describe, it, expect, vi } from 'vitest';
import { _handleRegionDragMove, _handleRegionResizeMove } from './NetworkCanvas.jsx';

// Direct unit coverage of the region drag/resize handlers — module-level
// pure-enough functions taking a synthetic pointer event and getSVGPt.
const R1 = { id: 'r1', x: 100, y: 100, w: 200, h: 150 };
const mk = (regions) => ({ current: { regions } });
const pt = (x, y) => () => ({ x, y });
const emi = () => vi.fn();

describe('_handleRegionDragMove', () => {
  it('moves the region to pointer minus drag offset', () => {
    const emit = emi();
    const ref = mk([R1]);
    _handleRegionDragMove({}, 'r1', { current: { x: 10, y: 5 } }, pt(300, 250), ref, emit);
    expect(emit).toHaveBeenCalled();
    const moved = emit.mock.calls[0][0].regions.find(r => r.id === 'r1');
    expect(moved.x).toBe(290);
    expect(moved.y).toBe(245);
    expect(moved.w).toBe(200); // size untouched
  });

  it('a vanished dragging id re-emits the list unchanged (no crash)', () => {
    const emit = emi();
    _handleRegionDragMove({}, 'ghost', { current: { x: 0, y: 0 } }, pt(1, 1), mk([R1]), emit);
    expect(emit).toHaveBeenCalledTimes(1);
    const regions = emit.mock.calls[0][0].regions;
    expect(regions.find(r => r.id === 'r1').x).toBe(100); // untouched
  });
});

describe('_handleRegionResizeMove', () => {
  const cases = [
    ['se', { w: 150, h: 100 }],
    ['sw', { x: 150, h: 100 }],
    ['ne', { y: 150, w: 150 }],
    ['nw', { x: 150, y: 150 }],
  ];
  it.each(cases)('corner %s resizes with a 40px floor', (corner, expectKeys) => {
    const emit = emi();
    _handleRegionResizeMove({}, { id: 'r1', corner }, pt(250, 250), mk([R1]), emit);
    const patched = emit.mock.calls[0][0].regions.find(r => r.id === 'r1');
    for (const k of Object.keys(expectKeys)) expect(patched[k]).toBeDefined();
    expect(patched.w).toBeGreaterThanOrEqual(40);
    expect(patched.h).toBeGreaterThanOrEqual(40);
  });

  it('floors a violent drag-out at 40px', () => {
    const emit = emi();
    _handleRegionResizeMove({}, { id: 'r1', corner: 'se' }, pt(-9999, -9999), mk([R1]), emit);
    const patched = emit.mock.calls[0][0].regions.find(r => r.id === 'r1');
    expect(patched.w).toBe(40);
    expect(patched.h).toBe(40);
  });

  it('unknown corner emits an unchanged patch shell', () => {
    const emit = emi();
    _handleRegionResizeMove({}, { id: 'r1', corner: '??' }, pt(1, 1), mk([R1]), emit);
    const patched = emit.mock.calls[0][0].regions.find(r => r.id === 'r1');
    expect(patched.x).toBe(100); // no geometry keys applied
  });

  it('no-ops when the region is gone', () => {
    const emit = emi();
    _handleRegionResizeMove({}, { id: 'ghost', corner: 'se' }, pt(1, 1), mk([R1]), emit);
    expect(emit).not.toHaveBeenCalled();
  });
});
