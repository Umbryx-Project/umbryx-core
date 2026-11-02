import { memo, useEffect, useState, useCallback } from 'react';
import { api } from '../api';
import { PALETTE, FONTS } from './UI.jsx';

const LEVEL_COLORS = {
  critical: { bg: PALETTE.danger, text: '#ff4455', label: 'CRIT' },
  high:     { bg: '#e8574a', text: '#ff7a6e', label: 'HIGH' },
  medium:   { bg: PALETTE.warn, text: '#f0aa5a', label: 'MED'  },
  low:      { bg: '#5b8af5', text: '#7ba8f7', label: 'LOW'  },
  info:     { bg: PALETTE.textGhost, text: PALETTE.textFaint, label: '—'    },
};

export const RiskScoreBadge = memo(function RiskScoreBadge({ hostId, score, level, compact }) {
  const c = LEVEL_COLORS[level] || LEVEL_COLORS.info;
  if (compact) {
    return (
      <span title={`Risk: ${score}/100 (${level})`}
        style={{ display: 'inline-flex', alignItems: 'center', gap: 2, fontSize: 8, fontFamily: FONTS.mono, color: c.text, fontWeight: 700 }}>
        {score}
      </span>
    );
  }
  return (
    <span title={`Risk score: ${score}/100`}
      style={{ display: 'inline-flex', alignItems: 'center', gap: 3, fontSize: 8, fontFamily: FONTS.mono, background: `${c.bg}22`, border: `1px solid ${c.bg}44`, borderRadius: 3, padding: '1px 4px', color: c.text, fontWeight: 600 }}>
      <span style={{ width: 5, height: 5, borderRadius: '50%', background: c.bg }} />
      {score}
    </span>
  );
});

export function RiskScoreBreakdown({ hostId }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(() => {
    api.getHostRisk(hostId).then(r => { setData(r); setLoading(false); }).catch(() => setLoading(false));
  }, [hostId]);

  useEffect(() => { load(); }, [load]);

  if (loading) return <div style={{ fontSize: 9, color: PALETTE.textGhost, fontFamily: FONTS.mono }}>Loading risk score...</div>;
  if (!data) return null;

  const c = LEVEL_COLORS[data.level] || LEVEL_COLORS.info;
  const b = data.breakdown || {};

  return (
    <div style={{ background: PALETTE.bg3, border: `1px solid ${PALETTE.borderSoft}`, borderRadius: 6, padding: 10 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
        <span style={{ fontSize: 10, color: '#808590', fontFamily: FONTS.mono, textTransform: 'uppercase' }}>Risk Score</span>
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 14, fontFamily: FONTS.mono, fontWeight: 700, color: c.text }}>
          <span style={{ width: 8, height: 8, borderRadius: '50%', background: c.bg }} />
          {data.score}<span style={{ fontSize: 9, color: PALETTE.textGhost }}>/100</span>
        </span>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
        <RiskBar label="Status" value={b.status} max={30} color="#5b8af5" />
        <RiskBar label={`Findings (${b.open_findings || 0})`} value={b.findings} max={25} color="#cc2233" />
        <RiskBar label="Role" value={b.role} max={15} color="#f09a3a" />
        <RiskBar label={`Cred reuse (${b.reused_creds || 0})`} value={b.cred_reuse} max={15} color="#c07af0" />
        <RiskBar label={`Paths (${b.path_count || 0})`} value={b.attack_paths} max={15} color="#39d353" />
      </div>
    </div>
  );
}

const RiskBar = memo(function RiskBar({ label, value, max, color }) {
  const pct = Math.min((value / max) * 100, 100);
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
      <span style={{ width: 90, fontSize: 8, color: PALETTE.textFaint, fontFamily: FONTS.mono, textAlign: 'right' }}>{label}</span>
      <div style={{ flex: 1, height: 5, background: PALETTE.borderSoft, borderRadius: 3, overflow: 'hidden' }}>
        <div style={{ width: `${pct}%`, height: '100%', background: color, borderRadius: 3, transition: 'width 0.3s' }} />
      </div>
      <span style={{ width: 28, fontSize: 8, color: '#808590', fontFamily: FONTS.mono, textAlign: 'right' }}>{value}/{max}</span>
    </div>
  );
});
