import { describe, it, expect } from 'vitest';
import { mdRow, mdSep, activityStatusCell, buildActivityLogLines } from './reportMarkdown.js';

describe('activityStatusCell', () => {
  it('renders an explicit UNCONFIRMED marker for unconfirmed status', () => {
    // Audit 2026-08-31, finding 4.1.3: the exported client-facing report must
    // not show a silently-green status for a command the agent never confirmed.
    expect(activityStatusCell('unconfirmed')).toBe('⚠ UNCONFIRMED');
  });

  it('passes through known statuses unchanged', () => {
    expect(activityStatusCell('done')).toBe('done');
    expect(activityStatusCell('failed')).toBe('failed');
  });

  it('falls back to empty for missing status', () => {
    expect(activityStatusCell(undefined)).toBe('');
    expect(activityStatusCell('')).toBe('');
  });
});

describe('buildActivityLogLines', () => {
  const hosts = [{ id: 'h1', ip: '10.0.0.5', hostname: 'dc01' }];

  it('includes the ⚠ UNCONFIRMED marker in the markdown table row', () => {
    const lines = buildActivityLogLines(
      [{ ts: '2026-08-31T10:00:00Z', host_id: 'h1', activity_type: 'postex', title: 'shell whoami', status: 'unconfirmed' }],
      hosts,
    );
    const joined = lines.join('\n');
    expect(joined).toContain('## Activity Log');
    expect(joined).toContain('⚠ UNCONFIRMED');
    expect(joined).toContain('dc01');
  });

  it('renders a plain status for confirmed activities', () => {
    const lines = buildActivityLogLines(
      [{ ts: '2026-08-31T10:00:00Z', host_id: 'h1', activity_type: 'postex', title: 'shell whoami', status: 'done' }],
      hosts,
    );
    expect(lines.join('\n')).toContain('| done |');
    expect(lines.join('\n')).not.toContain('UNCONFIRMED');
  });

  it('caps the log at 50 rows', () => {
    const many = Array.from({ length: 80 }, (_, i) => ({ ts: `t${i}`, host_id: 'h1', activity_type: 'recon', title: `a${i}`, status: 'done' }));
    const lines = buildActivityLogLines(many, hosts);
    // header (2 lines) + separator + 80 capped to 50 rows + trailing empty
    expect(lines.length).toBe(4 + 50 + 1);
  });
});

describe('mdRow/mdSep', () => {
  it('escapes pipes in cells', () => {
    expect(mdRow('a', 'b|c')).toBe('| a | b\\|c |');
  });
  it('builds a separator with n columns', () => {
    expect(mdSep(3)).toBe('| --- | --- | --- |');
  });
});
