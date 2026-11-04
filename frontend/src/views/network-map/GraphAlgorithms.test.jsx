import { describe, it, expect } from 'vitest';
import { render } from '@testing-library/react';
import { renderChip, renderRoleBadges } from './GraphAlgorithms.jsx';

// These return raw SVG <g> elements — wrap in an <svg> so the DOM accepts them.
function renderSvg(children) {
  return render(<svg>{children}</svg>);
}

describe('renderChip', () => {
  it('sizes the chip to the label length', () => {
    const short = renderSvg(renderChip(20, 10, 'DMZ', '#f09a3a'));
    const rectShort = short.container.querySelector('rect');
    short.unmount();

    const long = renderSvg(renderChip(20, 10, 'MANAGEMENT', '#f09a3a'));
    const rectLong = long.container.querySelector('rect');

    expect(Number(rectLong.getAttribute('width'))).toBeGreaterThan(Number(rectShort.getAttribute('width')));
  });

  it('centers the chip horizontally on x', () => {
    const { container } = renderSvg(renderChip(20, 10, 'SOCKS', '#e8cc42'));
    const g = container.querySelector('g');
    const rect = container.querySelector('rect');
    const w = Number(rect.getAttribute('width'));

    const transform = g.getAttribute('transform');
    const match = /translate\(([-\d.]+),([-\d.]+)\)/.exec(transform);
    expect(Number(match[1])).toBeCloseTo(20 - w / 2, 1);
    expect(Number(match[2])).toBe(10);
  });

  it('uses the requested height and default font size', () => {
    const { container } = renderSvg(renderChip(0, 0, 'PIVOT', '#f09a3a', { height: 9, fontSize: 5.5 }));
    const rect = container.querySelector('rect');
    const text = container.querySelector('text');
    expect(rect.getAttribute('height')).toBe('9');
    expect(text.getAttribute('font-size')).toBe('5.5');
    expect(text.textContent).toBe('PIVOT');
  });

  it('derives fill/stroke from the given color', () => {
    const { container } = renderSvg(renderChip(0, 0, 'EXTERNAL', '#cc2233'));
    const rect = container.querySelector('rect');
    expect(rect.getAttribute('fill')).toBe('#cc223322');
    expect(rect.getAttribute('stroke')).toBe('#cc223366');
  });
});

describe('renderRoleBadges', () => {
  it('renders one badge per entry with its own color/label', () => {
    const badges = [
      { id: 'r1', color: '#5b8af5', short: 'DC' },
      { id: 'r2', color: '#c07af0', short: 'WEB' },
    ];
    const { container } = renderSvg(renderRoleBadges(badges, 40));
    const groups = container.querySelectorAll('g');
    expect(groups).toHaveLength(2);
    expect(container.textContent).toContain('DC');
    expect(container.textContent).toContain('WEB');
  });

  it('centers the whole badge row around x=20', () => {
    const badges = [
      { id: 'r1', color: '#5b8af5', short: 'DC' },
      { id: 'r2', color: '#c07af0', short: 'WEB' },
    ];
    const { container } = renderSvg(renderRoleBadges(badges, 40));
    const groups = [...container.querySelectorAll('g')];
    const xs = groups.map(g => {
      const m = /translate\(([-\d.]+),/.exec(g.getAttribute('transform'));
      return Number(m[1]);
    });
    // Two 20px-wide badges with a 2px gap centered on 20 should straddle it symmetrically.
    const mid = (xs[0] + xs[1] + 20) / 2; // left edge of first + left edge of second + badge width
    expect(mid).toBeCloseTo(20, 0);
  });

  it('returns an empty list for no badges', () => {
    const { container } = renderSvg(<>{renderRoleBadges([], 40)}</>);
    expect(container.querySelectorAll('g')).toHaveLength(0);
  });
});
