import PropTypes from 'prop-types';
import Icon from '../components/Icon.jsx';
import { isAttackerHost } from '../utils/hostMeta.js';
import { SEVERITY, NODE_STATUS } from '../constants.js';
import ExtensionPoint from '../modules/ExtensionPoint.jsx';
import { PALETTE, FONTS } from '../components/UI.jsx';

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_COLORS = Object.fromEntries(SEV_ORDER.map(k => [k, SEVERITY[k]?.color || '#606570']));
const HOST_STATUS_COLORS = Object.fromEntries(
  Object.entries(NODE_STATUS).map(([k, v]) => [k, v.color])
);
HOST_STATUS_COLORS.up = '#5b8af5';
HOST_STATUS_COLORS.down = '#505560';
const HOST_STATUS_LABELS = {
  unknown: 'Unknown',
  up:      'Up',
  down:    'Down',
  alive:   'Discovered',
  scanned: 'Scanned',
  access:  'Access',
  pwned:   'Compromised',
  owned:   'Full Control',
};

function timeAgo(tsStr) {
  if (!tsStr) return '?';
  const ts = new Date(tsStr);
  if (Number.isNaN(ts.getTime())) return tsStr;
  const diff = Math.floor((Date.now() - ts.getTime()) / 1000);
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

const ENTITY_ICONS = {
  host: 'hosts', note: 'notes', cred: 'person', finding: 'bug',
  objective: 'flag', loot: 'loot', network: 'network',
};

const CHECKLIST_PHASES = ['recon', 'scan', 'exploit', 'post', 'report'];
const PHASE_LABELS = { recon: 'Recon', scan: 'Scan', exploit: 'Exploit', post: 'Post-Exploit', report: 'Report' };
const PHASE_COLORS = { recon: '#5b8af5', scan: '#c07af0', exploit: '#e8574a', post: PALETTE.warn, report: '#6fc8f0' };

export default function OverviewView({
  selectedProject, projects, hosts, creds, findings,
  notes, objectives, timelineEvents = [], checklistItems = [],
  accent, onTabChange,
}) {
  const proj = projects.find(p => p.id === selectedProject);
  const pHosts = (hosts || []).filter(h => h.pid === selectedProject && !isAttackerHost(h));
  const pCreds = (creds || []).filter(c => c.pid === selectedProject);
  const pFindings = (findings || []).filter(f => f.pid === selectedProject);
  const pNotes = (notes || []).filter(n => n.pid === selectedProject);
  const pObjectives = (objectives || []).filter(o => o.pid === selectedProject);
  const pChecklist = (checklistItems || []).filter(i => i.pid === selectedProject);
  const pTimeline = (timelineEvents || []).filter(e => e.pid === selectedProject);

  const pwnedCount = pHosts.filter(h => h.status === 'pwned' || h.status === 'owned').length;
  const criticalCount = pFindings.filter(f => f.severity === 'critical').length;
  const highCount = pFindings.filter(f => f.severity === 'high').length;
  const crackedCount = pCreds.filter(c => c.cracked).length;
  const capturedCount = pObjectives.filter(o => o.status === 'captured' || o.status === 'submitted').length;

  // Findings breakdown
  const totalFindings = pFindings.length;

  // Hosts by status
  const allStatuses = [...new Set(pHosts.map(h => h.status || 'unknown'))];
  const hostStatusStats = allStatuses.map(s => ({
    status: s,
    count: pHosts.filter(h => (h.status || 'unknown') === s).length,
  })).sort((a, b) => b.count - a.count);

  // Timeline — последние 8
  const recentEvents = [...pTimeline]
    .sort((a, b) => String(b.ts || b.created_at || '').localeCompare(String(a.ts || a.created_at || '')))
    .slice(0, 8);

  // Checklist phases
  const checklistPhaseStats = CHECKLIST_PHASES.map(phase => {
    const items = pChecklist.filter(i => i.phase === phase || i.category === phase);
    const done = items.filter(i => i.done || i.checked || i.status === 'done').length;
    return { phase, done, total: items.length };
  });

  const cardStyle = {
    background: PALETTE.bg2,
    border: '1px solid #1e2029',
    borderRadius: 8,
    padding: '16px 18px',
    cursor: 'pointer',
    transition: 'border-color .15s',
  };

  const blockStyle = {
    background: PALETTE.bg2,
    border: '1px solid #1e2029',
    borderRadius: 8,
    padding: 18,
  };

  if (!proj) {
    return (
      <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: PALETTE.textGhost, fontSize: 13 }}>
        No project selected
      </div>
    );
  }

  const isEmpty = pHosts.length === 0 && pFindings.length === 0 && pNotes.length === 0 && pCreds.length === 0;

  const ONBOARDING_STEPS = [
    { key: 'scope', label: 'Define scope', desc: 'Add IPs, domains, and ranges', tab: 'scope', done: pHosts.length > 0 },
    { key: 'hosts', label: 'Add hosts', desc: 'Import or manually create target hosts', tab: 'hosts', done: pHosts.length > 0 },
    { key: 'notes', label: 'Take notes', desc: 'Document your reconnaissance findings', tab: 'notes', done: pNotes.length > 0 },
    { key: 'findings', label: 'Log findings', desc: 'Record vulnerabilities and issues', tab: 'findings', done: pFindings.length > 0 },
    { key: 'creds', label: 'Store credentials', desc: 'Capture and manage discovered creds', tab: 'creds', done: pCreds.length > 0 },
  ];
  const completedSteps = ONBOARDING_STEPS.filter(s => s.done).length;

  return (
    <div style={{ flex: 1, overflowY: 'auto', padding: '24px 28px' }}>
      {/* Header */}
      <div style={{ marginBottom: 24 }}>
        <div style={{ fontSize: 9, color: PALETTE.textGhost, letterSpacing: '0.15em', textTransform: 'uppercase', marginBottom: 6 }}>
          Overview · {new Date().toLocaleDateString('en')}
        </div>
        <h1 style={{ fontSize: 22, fontWeight: 700, color: PALETTE.text, fontFamily: FONTS.display, margin: 0 }}>
          {proj.name}
        </h1>
      </div>

      {isEmpty && (
        <div style={{ background: PALETTE.bg2, border: '1px solid #1e2029', borderRadius: 8, padding: '20px 22px', marginBottom: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
            <div>
              <div style={{ fontSize: 13, fontWeight: 700, color: '#e0e4ec', fontFamily: FONTS.display, marginBottom: 4 }}>Get started</div>
              <div style={{ fontSize: 10, color: PALETTE.textFaint }}>Complete these steps to set up your engagement</div>
            </div>
            <span style={{ fontSize: 11, color: accent, fontFamily: FONTS.mono }}>{completedSteps}/{ONBOARDING_STEPS.length}</span>
          </div>
          <div style={{ height: 4, background: PALETTE.borderSoft, borderRadius: 2, marginBottom: 16, overflow: 'hidden' }}>
            <div style={{ height: '100%', width: `${(completedSteps / ONBOARDING_STEPS.length) * 100}%`, background: accent, borderRadius: 2, transition: 'width 0.4s' }} />
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {ONBOARDING_STEPS.filter(s => !s.done).map(step => (
              <button key={step.key} type="button" onClick={() => onTabChange?.(step.tab)}
                style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '10px 14px', background: '#14161b', border: '1px solid #1e2029', borderRadius: 6, cursor: 'pointer', textAlign: 'left', color: 'inherit', font: 'inherit', transition: 'border-color .15s' }}
                onMouseEnter={e => e.currentTarget.style.borderColor = accent + '55'}
                onMouseLeave={e => e.currentTarget.style.borderColor = '#1e2029'}>
                <div style={{ width: 22, height: 22, borderRadius: '50%', border: `2px solid ${accent}44`, flexShrink: 0, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  <span style={{ fontSize: 10, color: accent, fontFamily: FONTS.mono }}>{ONBOARDING_STEPS.indexOf(step) + 1}</span>
                </div>
                <div>
                  <div style={{ fontSize: 12, fontWeight: 600, color: PALETTE.textDim, fontFamily: FONTS.display }}>{step.label}</div>
                  <div style={{ fontSize: 10, color: PALETTE.textFaint }}>{step.desc}</div>
                </div>
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Stat cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))', gap: 12, marginBottom: 20 }}>
        {/* Hosts */}
        <button type="button" style={{ ...cardStyle, borderColor: pwnedCount > 0 ? '#cc223333' : '#1e2029', textAlign: 'left', width: '100%', background: cardStyle.background, borderWidth: cardStyle.borderWidth, borderStyle: cardStyle.borderStyle, padding: cardStyle.padding, borderRadius: cardStyle.borderRadius, boxShadow: cardStyle.boxShadow, outline: 'none', color: 'inherit', font: 'inherit' }}
          onClick={() => onTabChange?.('hosts')}
          onMouseEnter={e => e.currentTarget.style.borderColor = accent + '55'}
          onMouseLeave={e => e.currentTarget.style.borderColor = pwnedCount > 0 ? '#cc223333' : '#1e2029'}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
            <Icon name="hosts" size={13} color="#404550" />
            <span style={{ fontSize: 10, color: PALETTE.textFaint, textTransform: 'uppercase', letterSpacing: '0.08em' }}>Hosts</span>
          </div>
          <div style={{ fontSize: 28, fontWeight: 700, color: '#c07af0', fontFamily: FONTS.display, marginBottom: 4 }}>{pHosts.length}</div>
          {pwnedCount > 0 && (
            <button onClick={() => onTabChange?.('hosts', null)} style={{ fontSize: 10, color: PALETTE.danger, fontFamily: FONTS.mono, background: 'none', border: 'none', cursor: 'pointer', padding: 0, textAddress: 'left' }}>{pwnedCount} pwned</button>
          )}
        </button>

        {/* Findings */}
        <button type="button" style={{ ...cardStyle, borderColor: totalFindings > 0 ? '#e8574a33' : '#1e2029', textAlign: 'left', width: '100%', background: cardStyle.background, borderWidth: cardStyle.borderWidth, borderStyle: cardStyle.borderStyle, padding: cardStyle.padding, borderRadius: cardStyle.borderRadius, boxShadow: cardStyle.boxShadow, outline: 'none', color: 'inherit', font: 'inherit' }}
          onClick={() => onTabChange?.('findings')}
          onMouseEnter={e => e.currentTarget.style.borderColor = accent + '55'}
          onMouseLeave={e => e.currentTarget.style.borderColor = totalFindings > 0 ? '#e8574a33' : '#1e2029'}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
            <Icon name="bug" size={13} color="#404550" />
            <span style={{ fontSize: 10, color: PALETTE.textFaint, textTransform: 'uppercase', letterSpacing: '0.08em' }}>Findings</span>
          </div>
          <div style={{ fontSize: 28, fontWeight: 700, color: '#e8574a', fontFamily: FONTS.display, marginBottom: 4 }}>{totalFindings}</div>
          <div style={{ fontSize: 10, fontFamily: FONTS.mono, display: 'flex', gap: 8 }}>
            {criticalCount > 0 && <button onClick={() => onTabChange?.('findings')} style={{ fontSize: 10, color: PALETTE.danger, background: 'none', border: 'none', cursor: 'pointer', padding: 0, fontFamily: FONTS.mono }}>{criticalCount} crit</button>}
            {highCount > 0 && <button onClick={() => onTabChange?.('findings')} style={{ fontSize: 10, color: '#e8574a', background: 'none', border: 'none', cursor: 'pointer', padding: 0, fontFamily: FONTS.mono }}>{highCount} high</button>}
          </div>
        </button>

        {/* Creds */}
        <button type="button" style={{ ...cardStyle, textAlign: 'left', width: '100%', background: cardStyle.background, borderWidth: cardStyle.borderWidth, borderStyle: cardStyle.borderStyle, padding: cardStyle.padding, borderRadius: cardStyle.borderRadius, boxShadow: cardStyle.boxShadow, outline: 'none', color: 'inherit', font: 'inherit' }}
          onClick={() => onTabChange?.('creds')}
          onMouseEnter={e => e.currentTarget.style.borderColor = accent + '55'}
          onMouseLeave={e => e.currentTarget.style.borderColor = '#1e2029'}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
            <Icon name="person" size={13} color="#404550" />
            <span style={{ fontSize: 10, color: PALETTE.textFaint, textTransform: 'uppercase', letterSpacing: '0.08em' }}>Creds</span>
          </div>
          <div style={{ fontSize: 28, fontWeight: 700, color: PALETTE.ok, fontFamily: FONTS.display, marginBottom: 4 }}>{pCreds.length}</div>
          {crackedCount > 0 && (
            <button onClick={() => onTabChange?.('creds')} style={{ fontSize: 10, color: PALETTE.ok, fontFamily: FONTS.mono, background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}>{crackedCount} cracked</button>
          )}
        </button>

        {/* Objectives */}
        <button type="button" style={{ ...cardStyle, textAlign: 'left', width: '100%', background: cardStyle.background, borderWidth: cardStyle.borderWidth, borderStyle: cardStyle.borderStyle, padding: cardStyle.padding, borderRadius: cardStyle.borderRadius, boxShadow: cardStyle.boxShadow, outline: 'none', color: 'inherit', font: 'inherit' }}
          onClick={() => onTabChange?.('objectives')}
          onMouseEnter={e => e.currentTarget.style.borderColor = accent + '55'}
          onMouseLeave={e => e.currentTarget.style.borderColor = '#1e2029'}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
            <Icon name="flag" size={13} color="#404550" />
            <span style={{ fontSize: 10, color: PALETTE.textFaint, textTransform: 'uppercase', letterSpacing: '0.08em' }}>Objectives</span>
          </div>
          <div style={{ fontSize: 28, fontWeight: 700, color: PALETTE.warn, fontFamily: FONTS.display, marginBottom: 4 }}>
            {capturedCount}/{pObjectives.length}
          </div>
          <div style={{ fontSize: 10, color: PALETTE.textFaint, fontFamily: FONTS.mono }}>captured</div>
        </button>

        {/* Notes */}
        <button type="button" style={{ ...cardStyle, textAlign: 'left', width: '100%', background: cardStyle.background, borderWidth: cardStyle.borderWidth, borderStyle: cardStyle.borderStyle, padding: cardStyle.padding, borderRadius: cardStyle.borderRadius, boxShadow: cardStyle.boxShadow, outline: 'none', color: 'inherit', font: 'inherit' }}
          onClick={() => onTabChange?.('notes')}
          onMouseEnter={e => e.currentTarget.style.borderColor = accent + '55'}
          onMouseLeave={e => e.currentTarget.style.borderColor = '#1e2029'}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
            <Icon name="notes" size={13} color="#404550" />
            <span style={{ fontSize: 10, color: PALETTE.textFaint, textTransform: 'uppercase', letterSpacing: '0.08em' }}>Notes</span>
          </div>
          <div style={{ fontSize: 28, fontWeight: 700, color: '#6fc8f0', fontFamily: FONTS.display, marginBottom: 4 }}>{pNotes.length}</div>
        </button>
      </div>

      {/* Middle row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))', gap: 16, marginBottom: 16 }}>
        {/* Findings by severity */}
        <div style={blockStyle}>
          <div style={{ fontSize: 11, fontWeight: 600, color: '#e0e4ec', fontFamily: FONTS.display, marginBottom: 14 }}>Findings by severity</div>
          {totalFindings === 0 ? (
            <div style={{ fontSize: 11, color: PALETTE.textGhost }}>No findings</div>
          ) : SEV_ORDER.map(s => {
            const count = pFindings.filter(f => f.severity === s).length;
            const pct = totalFindings > 0 ? Math.round((count / totalFindings) * 100) : 0;
            return (
              <div key={s} style={{ marginBottom: 10 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 5 }}>
                  <span style={{ fontSize: 10, color: SEV_COLORS[s], textTransform: 'uppercase', letterSpacing: '0.08em', fontFamily: FONTS.mono, width: 70 }}>{s}</span>
                  <span style={{ fontSize: 11, color: count > 0 ? SEV_COLORS[s] : '#303540', fontFamily: FONTS.mono, width: 30, textAlign: 'right' }}>{count}</span>
                  <span style={{ fontSize: 9, color: PALETTE.textGhost, fontFamily: FONTS.mono, width: 35, textAlign: 'right' }}>{pct}%</span>
                </div>
                <div style={{ height: 5, background: PALETTE.borderSoft, borderRadius: 3, overflow: 'hidden' }}>
                  <div style={{ height: '100%', width: `${pct}%`, background: SEV_COLORS[s], borderRadius: 3, transition: 'width 0.5s' }} />
                </div>
              </div>
            );
          })}
        </div>

        {/* Hosts by status */}
        <div style={blockStyle}>
          <div style={{ fontSize: 11, fontWeight: 600, color: '#e0e4ec', fontFamily: FONTS.display, marginBottom: 14 }}>Hosts by status</div>
          {pHosts.length === 0 ? (
            <div style={{ fontSize: 11, color: PALETTE.textGhost }}>No hosts</div>
          ) : hostStatusStats.map(({ status, count }) => {
            const pct = pHosts.length > 0 ? Math.round((count / pHosts.length) * 100) : 0;
            const color = HOST_STATUS_COLORS[status] || '#404550';
            const label = HOST_STATUS_LABELS[status] || status;
            return (
              <div key={status} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '7px 0', borderBottom: '1px solid #14161b' }}>
                <span style={{ width: 7, height: 7, borderRadius: '50%', background: color, flexShrink: 0 }} />
                <span style={{ fontSize: 11, color: '#808590', flex: 1 }}>{label}</span>
                <span style={{ fontSize: 12, fontWeight: 600, color, fontFamily: FONTS.mono, width: 30, textAlign: 'right' }}>{count}</span>
                <span style={{ fontSize: 10, color: PALETTE.textGhost, fontFamily: FONTS.mono, width: 36, textAlign: 'right' }}>{pct}%</span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Bottom row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))', gap: 16 }}>
        {/* Recent activity */}
        <div style={blockStyle}>
          <div style={{ fontSize: 11, fontWeight: 600, color: '#e0e4ec', fontFamily: FONTS.display, marginBottom: 14, display: 'flex', alignItems: 'center', gap: 8 }}>
            <Icon name="clock" size={13} color="#404550" />Recent activity
          </div>
          {recentEvents.length === 0 ? (
            <div style={{ fontSize: 11, color: PALETTE.textGhost }}>No recent events</div>
          ) : recentEvents.map((ev, i) => {
            const iconName = ENTITY_ICONS[ev.entity] || ENTITY_ICONS[ev.type] || 'notes';
            const ts = ev.ts || ev.created_at || ev.timestamp;
            return (
              <div key={ev.id || i} style={{ display: 'flex', alignItems: 'flex-start', gap: 10, padding: '8px 0', borderBottom: '1px solid #14161b' }}>
                <div style={{ width: 24, height: 24, borderRadius: 6, background: PALETTE.borderSoft, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, marginTop: 1 }}>
                  <Icon name={iconName} size={11} color="#606570" />
                </div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 11, color: PALETTE.textDim, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {ev.label || ev.title || ev.name || 'Event'}
                  </div>
                  {ev.description && (
                    <div style={{ fontSize: 10, color: PALETTE.textFaint, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', marginTop: 2 }}>{ev.description}</div>
                  )}
                </div>
                <span style={{ fontSize: 9, color: PALETTE.textGhost, fontFamily: FONTS.mono, flexShrink: 0, marginTop: 3 }}>{timeAgo(ts)}</span>
              </div>
            );
          })}
        </div>

        {/* Quick status + project lifecycle */}
        <div style={blockStyle}>
          <div style={{ fontSize: 11, fontWeight: 600, color: '#e0e4ec', fontFamily: FONTS.display, marginBottom: 14, display: 'flex', alignItems: 'center', gap: 8 }}>
            <Icon name="flag" size={13} color="#404550" />Engagement status
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: 11, color: '#808590' }}>Project status</span>
              <span style={{ fontSize: 11, fontWeight: 600, color: proj.status === 'active' ? '#39d353' : proj.status === 'completed' ? '#5b8af5' : PALETTE.textFaint, fontFamily: FONTS.mono }}>{proj.status || 'active'}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: 11, color: '#808590' }}>Compromise ratio</span>
              <span style={{ fontSize: 11, fontWeight: 600, color: pHosts.length > 0 ? (pwnedCount / pHosts.length > 0.5 ? '#cc2233' : PALETTE.warn) : PALETTE.textGhost, fontFamily: FONTS.mono }}>{pHosts.length > 0 ? `${Math.round(pwnedCount / pHosts.length * 100)}%` : '—'}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: 11, color: '#808590' }}>Finding severity</span>
              <span style={{ fontSize: 11, fontWeight: 600, color: criticalCount > 0 ? '#cc2233' : highCount > 0 ? '#e8574a' : PALETTE.ok, fontFamily: FONTS.mono }}>{criticalCount > 0 ? `${criticalCount} critical` : highCount > 0 ? `${highCount} high` : 'No critical/high'}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: 11, color: '#808590' }}>Objectives</span>
              <span style={{ fontSize: 11, fontWeight: 600, color: capturedCount === pObjectives.length && pObjectives.length > 0 ? '#39d353' : PALETTE.warn, fontFamily: FONTS.mono }}>{pObjectives.length > 0 ? `${capturedCount}/${pObjectives.length}` : '—'}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: 11, color: '#808590' }}>Credential coverage</span>
              <span style={{ fontSize: 11, fontWeight: 600, color: crackedCount > 0 ? '#39d353' : PALETTE.textFaint, fontFamily: FONTS.mono }}>{pCreds.length > 0 ? `${crackedCount}/${pCreds.length} cracked` : '—'}</span>
            </div>
            {proj.added && (
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: 11, color: '#808590' }}>Started</span>
                <span style={{ fontSize: 11, color: PALETTE.textFaint, fontFamily: FONTS.mono }}>{new Date(proj.added).toLocaleDateString('en')}</span>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Extension module widgets */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 12, marginBottom: 20 }}>
        <ExtensionPoint point="dashboard.widget" accent={accent} pid={selectedProject} />
      </div>
    </div>
  );
}

OverviewView.propTypes = {
  selectedProject: PropTypes.string,
  projects: PropTypes.array,
  hosts: PropTypes.array,
  creds: PropTypes.array,
  findings: PropTypes.array,
  notes: PropTypes.array,
  objectives: PropTypes.array,
  timelineEvents: PropTypes.array,
  checklistItems: PropTypes.array,
  accent: PropTypes.string,
  onTabChange: PropTypes.func,
};