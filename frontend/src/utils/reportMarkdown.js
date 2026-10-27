// Markdown report helpers shared by ReportView and tests.
// Extracted from ReportView.jsx so the exported-report behavior —
// especially the UNCONFIRMED marker for C2 commands the agent never
// confirmed (audit 2026-08-31, finding 4.1.3) — is unit-testable.

export function mdEscape(s) { return (s || '').replace(/\|/g, String.raw`\|`); }
export function mdRow(...cells) { return '| ' + cells.map(c => mdEscape(String(c ?? ''))).join(' | ') + ' |'; }
export function mdSep(n) { return '|' + ' --- |'.repeat(n); }

export function activityStatusCell(status) {
  // An unconfirmed activity must be a first-class ⚠ UNCONFIRMED marker in
  // the exported report — not a bare lowercase word and not something the
  // reader has to dig out of the summary text.
  if (status === 'unconfirmed') return '⚠ UNCONFIRMED';
  return status || '';
}

export function buildActivityLogLines(activities, hosts) {
  const lines = ['## Activity Log', '', mdRow('Date', 'Host', 'Type', 'Title', 'Status'), mdSep(5)];
  activities.slice(0, 50).forEach(a => {
    const h = hosts.find(x => x.id === a.host_id);
    const hostStr = h ? (() => {
      const suffix = h.hostname ? ` (${h.hostname})` : '';
      return `${h.ip}${suffix}`;
    })() : '';
    lines.push(mdRow(a.ts || '', hostStr, a.activity_type || '', a.title || '', activityStatusCell(a.status)));
  });
  lines.push('');
  return lines;
}
