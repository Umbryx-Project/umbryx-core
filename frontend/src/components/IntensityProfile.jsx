import { memo, useState, useEffect } from 'react';
import PropTypes from 'prop-types';
import { api } from '../api';
import { PALETTE, TYPE, FONTS, Select } from './UI.jsx';

const PROFILES = {
  stealth:    { label: 'Stealth',    color: PALETTE.ok, desc: 'Slow, quiet, minimal noise' },
  normal:     { label: 'Normal',     color: '#5b8af5', desc: 'Balanced speed and stealth' },
  aggressive: { label: 'Aggressive', color: PALETTE.danger, desc: 'Fast, noisy, all scripts' },
};

export const IntensityIndicator = memo(function IntensityIndicator({ profile }) {
  const p = PROFILES[profile] || PROFILES.normal;
  return (
    <span title={`Intensity: ${p.label} — ${p.desc}`}
      style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 9, fontFamily: FONTS.mono, color: p.color, background: `${p.color}11`, border: `1px solid ${p.color}33`, borderRadius: 3, padding: '2px 6px', whiteSpace: 'nowrap' }}>
      <span style={{ width: 5, height: 5, borderRadius: '50%', background: p.color }} />
      {p.label}
    </span>
  );
});
IntensityIndicator.propTypes = { profile: PropTypes.string };

export const IntensityProfileSelector = memo(function IntensityProfileSelector({ pid, profile, onChange, compact }) {
  const [profiles, setProfiles] = useState(PROFILES);

  useEffect(() => {
    api.getIntensityProfiles().then(data => {
      if (data && typeof data === 'object') setProfiles(data);
    }).catch(() => {});
  }, []);

  const keys = Object.keys(profiles);

  if (compact) {
    return (
      <Select value={profile || 'normal'} onChange={v => onChange?.(v)} title="Scan intensity profile"
        options={keys.map(k => ({ value: k, label: profiles[k].label || k }))} />
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
      <span style={{ fontSize: 9, color: PALETTE.textGhost, textTransform: 'uppercase', letterSpacing: '0.08em', fontFamily: FONTS.mono }}>Intensity Profile</span>
      <div style={{ display: 'flex', gap: 6 }}>
        {keys.map(k => {
          const p = profiles[k];
          const active = (profile || 'normal') === k;
          return (
            <button key={k} onClick={() => onChange?.(k)}
              style={{
                flex: 1, padding: '8px 10px', borderRadius: 6, cursor: 'pointer',
                background: active ? `${p.color}18` : '#0a0c10',
                border: `1px solid ${active ? p.color + '66' : PALETTE.borderSoft}`,
                display: 'flex', flexDirection: 'column', gap: 2, alignItems: 'flex-start',
              }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 11, fontFamily: FONTS.mono, color: active ? p.color : '#808590', fontWeight: active ? 600 : 400 }}>
                <span style={{ width: 6, height: 6, borderRadius: '50%', background: p.color }} />
                {p.label}
              </span>
              <span style={{ fontSize: 8, color: PALETTE.textGhost, fontFamily: FONTS.mono }}>{p.description}</span>
            </button>
          );
        })}
      </div>
    </div>
  );
});
IntensityProfileSelector.propTypes = { pid: PropTypes.string, profile: PropTypes.string, onChange: PropTypes.func, compact: PropTypes.bool };
