import { useState, useEffect, useCallback } from 'react';
import PropTypes from 'prop-types';
import Icon from '../components/Icon.jsx';
import { api } from '../api.js';
import { toastError, toastSuccess } from '../components/Toast.jsx';
import { copyToClipboard } from '../utils/clipboard.js';
import { PALETTE, FONTS } from '../components/UI.jsx';

const SEV_COLORS = { critical: PALETTE.danger, high: '#e8574a', medium: PALETTE.warn, low: '#e8cc42', unknown: PALETTE.textFaint };

const PURPLE_TACTICS = [
  'Reconnaissance', 'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
  'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement', 'Collection',
  'Command and Control', 'Exfiltration', 'Impact', 'Unmapped',
];

function tacticColor(tactic) {
  const idx = PURPLE_TACTICS.indexOf(tactic);
  if (idx < 0) return '#606570';
  const hue = 200 + idx * 12;
  return `hsl(${hue}, 60%, 55%)`;
}

function buildReport(data, projectName) {
  const lines = [];
  lines.push(`# Purple Team Report — ${projectName || 'Project'}`);
  lines.push('');
  lines.push(`Techniques exercised: **${data.stats.techniques_total}**` +
    ` (mapped to tactics: ${data.stats.mapped_to_tactic}); attack-path steps: ${data.stats.steps_with_mitre}/${data.stats.steps_total};` +
    ` tagged graph edges: ${data.stats.tagged_edges}; findings: ${data.stats.findings_total}.`);
  lines.push('');
  lines.push('## Technique coverage');
  for (const t of data.techniques) {
    const src = [];
    if (t.steps) src.push(`${t.steps} step(s)`);
    if (t.edges) src.push(`${t.edges} edge(s)`);
    lines.push(`- **${t.id}**${t.tactic ? ` (${t.tactic})` : ''} — ${src.join(', ')}` +
      (t.labels?.length ? `; e.g. ${t.labels.slice(0, 3).join(' / ')}` : ''));
  }
  lines.push('');
  lines.push('## Findings by severity');
  for (const [sev, n] of Object.entries(data.stats.findings_by_severity || {})) {
    lines.push(`- ${sev}: ${n}`);
  }
  lines.push('');
  lines.push('## Defender timeline (newest first)');
  for (const e of data.timeline.slice(0, 40)) {
    lines.push(`- ${e.ts} [${e.entity}/${e.action}] ${e.label}${e.username ? ` — ${e.username}` : ''}`);
  }
  return lines.join('\n');
}

function TacticChip({ tactic, count }) {
  const c = tacticColor(tactic);
  return (
    <span title={`${tactic}: ${count} technique(s)`} style={{
      padding: '4px 10px', borderRadius: 4, border: `1px solid ${c}44`,
      background: `${c}18`, color: c, fontFamily: FONTS.mono, fontSize: 10, fontWeight: 700,
    }}>
      {tactic} · {count}
    </span>
  );
}
TacticChip.propTypes = { tactic: PropTypes.string, count: PropTypes.number };

function TechniqueRow({ t, accent }) {
  const tacticC = t.tactic ? tacticColor(t.tactic) : PALETTE.textFaint;
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 0', borderBottom: '1px solid #14161b' }}>
      <span style={{ fontFamily: FONTS.mono, fontSize: 11, color: accent, fontWeight: 700, minWidth: 86 }}>{t.id}</span>
      <span style={{ fontSize: 9, fontWeight: 700, color: t.tactic ? tacticC : PALETTE.textGhost, background: t.tactic ? `${tacticC}22` : 'transparent', border: `1px solid ${t.tactic ? `${tacticC}44` : PALETTE.border}`, borderRadius: 3, padding: '1px 6px', fontFamily: FONTS.mono, textTransform: 'uppercase' }}>
        {t.tactic || 'unmapped'}
      </span>
      {!!t.steps && <span style={{ fontSize: 9, color: '#5b8af5', background: '#5b8af522', border: '1px solid #5b8af544', borderRadius: 3, padding: '1px 6px', fontFamily: FONTS.mono }}>{t.steps} step</span>}
      {!!t.edges && <span style={{ fontSize: 9, color: '#15bbb1', background: '#15bbb122', border: '1px solid #15bbb144', borderRadius: 3, padding: '1px 6px', fontFamily: FONTS.mono }}>{t.edges} edge</span>}
      <span style={{ color: PALETTE.textFaint, fontSize: 10, fontFamily: FONTS.mono, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>
        {t.labels?.slice(0, 2).join(' / ')}
      </span>
    </div>
  );
}
TechniqueRow.propTypes = { t: PropTypes.object, accent: PropTypes.string };

export default function PurpleView({ selectedProject, projects, accent }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    if (!selectedProject) { setLoading(false); return; }
    try {
      setData(await api.getPurpleView(selectedProject));
    } catch (e) { toastError(e.message); }
    setLoading(false);
  }, [selectedProject]);

  useEffect(() => { setLoading(true); load(); }, [load]);

  const copyReport = async () => {
    const name = (projects || []).find(p => p.id === selectedProject)?.name || '';
    const md = buildReport(data, name);
    try {
      await copyToClipboard(md);
      toastSuccess('Purple report copied as Markdown');
    } catch {
      toastError('Clipboard unavailable');
    }
  };

  if (!selectedProject) return (
    <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: PALETTE.textGhost, fontSize: 12, fontFamily: FONTS.mono }}>
      Select a project to see its purple-team coverage
    </div>
  );

  const stats = data?.stats || { techniques_total: 0 };
  const byTactic = data?.by_tactic || {};
  const techniques = data?.techniques || [];
  const timeline = data?.timeline || [];

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      {/* Toolbar */}
      <div style={{ padding: '12px 24px', borderBottom: `1px solid ${PALETTE.borderSoft}`, background: '#0a0c10', display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
        <span style={{ fontSize: 13, fontWeight: 600, color: '#e0e4ec', fontFamily: FONTS.display }}>Purple Team ({stats.techniques_total} techniques)</span>
        <div style={{ flex: 1 }} />
        <button onClick={copyReport} disabled={!data}
          style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '5px 10px', cursor: data ? 'pointer' : 'default', opacity: data ? 1 : 0.5, color: '#808590', fontSize: 10, fontFamily: FONTS.mono, display: 'flex', alignItems: 'center', gap: 5 }}>
          <Icon name="copy" size={11} color="currentColor" /> Copy report (MD)
        </button>
      </div>

      {/* Content */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '20px 24px' }}>
        {loading && <div style={{ padding: 30, textAlign: 'center', color: PALETTE.textGhost, fontSize: 11 }}>Loading...</div>}

        {!loading && stats.techniques_total === 0 && (
          <div style={{ padding: '60px 0', textAlign: 'center', color: '#303540', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12 }}>
            <Icon name="shield" size={40} color="#2a2d35" />
            <div style={{ fontSize: 13 }}>No MITRE coverage yet</div>
            <div style={{ fontSize: 11, color: '#252830', maxWidth: 420, lineHeight: 1.5 }}>
              Techniques appear here from attack-path steps (MITRE ID field) and graph edges tagged by Smart Build (cred validation, bulk exec, pivots, C2).
            </div>
          </div>
        )}

        {!loading && stats.techniques_total > 0 && (
          <>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: 16 }}>
              {PURPLE_TACTICS.filter(t => byTactic[t]).map(t => (
                <TacticChip key={t} tactic={t} count={byTactic[t]} />
              ))}
            </div>

            <div style={{ background: PALETTE.bg2, border: '1px solid #1e2029', borderRadius: 8, padding: '4px 14px', marginBottom: 16 }}>
              <div style={{ fontSize: 9, color: '#505560', textTransform: 'uppercase', letterSpacing: '0.1em', padding: '10px 0 4px' }}>Techniques exercised</div>
              {techniques.map(t => <TechniqueRow key={t.id} t={t} accent={accent} />)}
            </div>

            {!!Object.keys(stats.findings_by_severity || {}).length && (
              <div style={{ display: 'flex', gap: 6, marginBottom: 16 }}>
                {Object.entries(stats.findings_by_severity).map(([sev, n]) => {
                  const c = SEV_COLORS[sev] || SEV_COLORS.unknown;
                  return (
                    <span key={sev} style={{ fontSize: 9, fontWeight: 700, color: c, background: `${c}22`, border: `1px solid ${c}44`, borderRadius: 3, padding: '2px 8px', fontFamily: FONTS.mono, textTransform: 'uppercase' }}>
                      {sev}: {n}
                    </span>
                  );
                })}
              </div>
            )}

            <div style={{ background: PALETTE.bg2, border: '1px solid #1e2029', borderRadius: 8, padding: '4px 14px' }}>
              <div style={{ fontSize: 9, color: '#505560', textTransform: 'uppercase', letterSpacing: '0.1em', padding: '10px 0 4px' }}>Defender timeline (newest first)</div>
              {timeline.slice(0, 40).map((e, i) => (
                <div key={i} style={{ display: 'flex', gap: 10, padding: '5px 0', fontFamily: FONTS.mono, fontSize: 10, borderBottom: i < Math.min(timeline.length, 40) - 1 ? '1px solid #14161b' : 'none' }}>
                  <span style={{ color: PALETTE.textGhost, whiteSpace: 'nowrap' }}>{(e.ts || '').replace('T', ' ').slice(5, 16)}</span>
                  <span style={{ color: accent }}>[{e.entity}/{e.action}]</span>
                  <span style={{ color: '#808590', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{e.label}</span>
                </div>
              ))}
              {!timeline.length && (
                <div style={{ color: PALETTE.textGhost, fontSize: 10, padding: '4px 0 10px' }}>no events</div>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  );
}

PurpleView.propTypes = {
  selectedProject: PropTypes.string,
  projects: PropTypes.array,
  accent: PropTypes.string,
};
