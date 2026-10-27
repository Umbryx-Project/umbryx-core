import { describe, it, expect } from 'vitest';
import { mergeCreated, mergeCreatedMany, applyRegionVersionBookkeep } from './NetworkCanvas.jsx';

// Create-emit merge helpers — the region/node/link *_created echo can
// land in the draft before the POST response (own echoes apply to the
// store), so create-emits append only genuinely-new entities instead of
// blindly rebuilding from a stale closure (duplicate ids / lost echoes).
describe('mergeCreated', () => {
  it('appends a genuinely new entity', () => {
    const next = mergeCreated([{ id: 'a' }], { id: 'b' });
    expect(next).toEqual([{ id: 'a' }, { id: 'b' }]);
  });

  it('returns null when the echo already delivered the entity', () => {
    expect(mergeCreated([{ id: 'a' }, { id: 'b' }], { id: 'b' })).toBeNull();
  });

  it('tolerates a missing list', () => {
    expect(mergeCreated(undefined, { id: 'x' })).toEqual([{ id: 'x' }]);
  });
});

describe('mergeCreatedMany', () => {
  it('appends only entities not already present, preserving order', () => {
    const next = mergeCreatedMany([{ id: 'a' }], [{ id: 'b' }, { id: 'a' }, { id: 'c' }, null]);
    expect(next).toEqual([{ id: 'a' }, { id: 'b' }, { id: 'c' }]);
  });

  it('returns null when everything already landed (no emit needed)', () => {
    expect(mergeCreatedMany([{ id: 'a' }], [{ id: 'a' }])).toBeNull();
  });
});

describe('applyRegionVersionBookkeep', () => {
  it('bumps the draft region version from the PATCH response', () => {
    const regions = [{ id: 'r1', version: 1 }];
    applyRegionVersionBookkeep(regions, 'r1', { region: { version: 2 } });
    expect(regions[0].version).toBe(2);
  });

  it('never regresses the version on a stale response', () => {
    const regions = [{ id: 'r1', version: 5 }];
    applyRegionVersionBookkeep(regions, 'r1', { region: { version: 2 } });
    expect(regions[0].version).toBe(5);
  });

  it('ignores unknown regions and malformed responses', () => {
    const regions = [{ id: 'r1', version: 1 }];
    expect(() => applyRegionVersionBookkeep(regions, 'nope', { region: { version: 9 } })).not.toThrow();
    expect(() => applyRegionVersionBookkeep(regions, 'r1', null)).not.toThrow();
    expect(() => applyRegionVersionBookkeep(regions, 'r1', { region: {} })).not.toThrow();
    expect(regions[0].version).toBe(1);
  });
});
