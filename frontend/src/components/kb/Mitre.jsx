import PropTypes from 'prop-types';
import { useState } from 'react';
import { toastError } from '../Toast.jsx';
import { api } from '../../api.js';
import { TACTIC_ORDER, TACTIC_COLOR, parseMitreArticle } from '../../utils/kb.js';
import { PALETTE, FONTS } from '../UI.jsx';

export function MitreMatrix({ techniques, usedIds, usedNames, accent, onSelectArticle, collapsed, setCollapsed }) {
  const byTactic = {};
  for (const t of techniques) {
    const key = t.tactic || 'Other';
    if (!byTactic[key]) byTactic[key] = [];
    byTactic[key].push(t);
  }

  const order = [...TACTIC_ORDER, 'Other'].filter(k => byTactic[k]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
      {order.map(tactic => {
        const techs = byTactic[tactic] || [];
        const color = TACTIC_COLOR[tactic] || '#606570';
        const usedCount = techs.filter(t =>
          usedIds.has(t.id.toUpperCase()) ||
          [...usedNames].some(n => n.includes(t.name.toLowerCase()) || t.name.toLowerCase().includes(n))
        ).length;
        const isCollapsed = collapsed[tactic];

        return (
          <div key={tactic} style={{ border: '1px solid #1e2029', borderRadius: 6, overflow: 'hidden' }}>
            <button
              type="button"
              onClick={() => setCollapsed(p => ({ ...p, [tactic]: !p[tactic] }))}
              onKeyDown={e => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault();
                  setCollapsed(p => ({ ...p, [tactic]: !p[tactic] }));
                }
              }}
              style={{
                display: 'flex', alignItems: 'center', gap: 8, padding: '7px 12px',
                cursor: 'pointer', background: PALETTE.bg2, userSelect: 'none',
                borderBottom: isCollapsed ? 'none' : '1px solid #1e2029', width: '100%', textAlign: 'left',
                borderTop: 'none', borderLeft: 'none', borderRight: 'none', outline: 'none', color: 'inherit', font: 'inherit'
              }}
            >
              <span style={{ fontSize: 9, color: PALETTE.textGhost, fontFamily: FONTS.mono, width: 10 }}>
                {isCollapsed ? '▶' : '▼'}
              </span>
              <span style={{ fontSize: 10, fontWeight: 700, color, textTransform: 'uppercase', letterSpacing: '0.08em', flex: 1 }}>
                {tactic}
              </span>
              <span style={{ fontSize: 9, fontFamily: FONTS.mono, color: usedCount > 0 ? color : PALETTE.textGhost }}>
                {usedCount}/{techs.length}
              </span>
              {usedCount > 0 && (
                <div style={{ width: 40, height: 4, background: '#1e2029', borderRadius: 2, overflow: 'hidden' }}>
                  <div style={{ height: '100%', width: `${(usedCount / techs.length) * 100}%`, background: color, borderRadius: 2 }} />
                </div>
              )}
            </button>

            {!isCollapsed && (
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, padding: '8px 10px' }}>
                {techs.map(t => {
                  const used = usedIds.has(t.id.toUpperCase()) ||
                    [...usedNames].some(n => n.includes(t.name.toLowerCase()) || t.name.toLowerCase().includes(n));
                  return (
                    <button
                      type="button"
                      key={t.id}
                      onClick={() => t.article && onSelectArticle(t.article)}
                      style={{
                        padding: '3px 7px', borderRadius: 4, cursor: t.article ? 'pointer' : 'default',
                        border: used ? `1px solid ${color}66` : '1px solid #1e2029',
                        background: used ? `${color}14` : 'transparent',
                        display: 'flex', alignItems: 'center', gap: 5, color: 'inherit', font: 'inherit', outline: 'none'
                      }}
                    >
                      <span style={{ fontSize: 8, fontFamily: FONTS.mono, color: used ? color : PALETTE.textGhost, flexShrink: 0 }}>
                        {t.id}
                      </span>
                      <span style={{ fontSize: 9, color: used ? '#c8cdd6' : '#505560', maxWidth: 120, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {t.name}
                      </span>
                      {used && <span style={{ width: 5, height: 5, borderRadius: '50%', background: color, flexShrink: 0 }} />}
                    </button>
                  );
                })}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
MitreMatrix.propTypes = {
  techniques: PropTypes.array,
  usedIds: PropTypes.object,
  usedNames: PropTypes.object,
  accent: PropTypes.string,
  onSelectArticle: PropTypes.func,
  collapsed: PropTypes.object,
  setCollapsed: PropTypes.func,
};

export function StepsFlow({ attackSteps, techniques, accent }) {
  const usedSteps = attackSteps.filter(s => s.technique || s.mitre_id);

  if (usedSteps.length === 0) {
    return (
      <div style={{ padding: '24px 16px', textAlign: 'center', color: PALETTE.textGhost, fontSize: 11, lineHeight: 1.6 }}>
        No attack path steps with techniques yet.<br />
        Add techniques in Attack Path → step editor.
      </div>
    );
  }

  const techMap = {};
  for (const t of techniques) {
    techMap[t.id.toUpperCase()] = t;
    if (t.name) techMap[t.name.toLowerCase()] = t;
  }

  const enriched = usedSteps.map(s => {
    const mid = (s.mitre_id || '').toUpperCase();
    const name = (s.technique || '').toLowerCase();
    const tech = techMap[mid] || techMap[name] || null;
    return { ...s, _tech: tech };
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
      {enriched.map((s, i) => {
        const tech = s._tech;
        const color = tech ? (TACTIC_COLOR[tech.tactic] || accent) : accent;
        const isLast = i === enriched.length - 1;
        return (
          <div key={s.id} style={{ display: 'flex', gap: 0 }}>
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', width: 24, flexShrink: 0 }}>
              <div style={{ width: 10, height: 10, borderRadius: '50%', border: `2px solid ${color}`, background: PALETTE.bg2, flexShrink: 0, marginTop: 10, zIndex: 1 }} />
              {!isLast && <div style={{ width: 2, flex: 1, background: '#1e2029', minHeight: 16 }} />}
            </div>

            <div style={{
              flex: 1, margin: '4px 0 4px 8px',
              padding: '8px 12px', borderRadius: 6,
              border: `1px solid ${color}33`,
              background: `${color}08`,
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 2 }}>
                <span style={{ fontSize: 8, fontFamily: FONTS.mono, color: PALETTE.textGhost, width: 18 }}>
                  {String(i + 1).padStart(2, '0')}
                </span>
                <span style={{ fontSize: 11, fontWeight: 600, color: '#e0e4ec', flex: 1 }}>
                  {s.label || s.sublabel || '(unnamed step)'}
                </span>
                {s.mitre_id && (
                  <span style={{ fontSize: 8, fontFamily: FONTS.mono, color, background: `${color}18`, border: `1px solid ${color}44`, borderRadius: 3, padding: '1px 5px' }}>
                    {s.mitre_id}
                  </span>
                )}
              </div>
              {s.technique && (
                <div style={{ fontSize: 10, color: color, fontFamily: FONTS.mono, paddingLeft: 24 }}>
                  {s.technique}
                  {tech?.tactic && <span style={{ color: '#505560' }}> · {tech.tactic}</span>}
                </div>
              )}
              {s.notes && (
                <div style={{ fontSize: 10, color: '#505560', paddingLeft: 24, marginTop: 2, fontStyle: 'italic' }}>
                  {s.notes.slice(0, 80)}{s.notes.length > 80 ? '…' : ''}
                </div>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}
StepsFlow.propTypes = {
  attackSteps: PropTypes.array,
  techniques: PropTypes.array,
  accent: PropTypes.string,
};

export function MitrePanel({ articles, attackSteps, accent, onSelectArticle, selectedProject }) {
  const [mode, setMode] = useState('matrix');
  const [seeding, setSeeding] = useState(false);
  const [collapsedTactics, setCollapsedTactics] = useState({});

  const techniques = articles.map(parseMitreArticle);
  const kbSeeded = techniques.length > 0;

  const usedIds = new Set(
    attackSteps.map(s => (s.mitre_id || '').toUpperCase()).filter(Boolean)
  );
  const usedNames = new Set(
    attackSteps.map(s => (s.technique || '').toLowerCase()).filter(Boolean)
  );

  const usedCount = techniques.filter(t =>
    usedIds.has(t.id.toUpperCase()) ||
    [...usedNames].some(n => n.includes(t.name.toLowerCase()) || t.name.toLowerCase().includes(n))
  ).length;

  const pct = techniques.length ? Math.round((usedCount / techniques.length) * 100) : 0;

  const seedToKB = async () => {
    setSeeding(true);
    try {
      await api.seedMitreKB();
      globalThis.location.reload();
    } catch (e) {
      toastError('Seed failed: ' + e.message);
    } finally {
      setSeeding(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div style={{ padding: '8px 12px', borderBottom: '1px solid #1e2029', flexShrink: 0 }}>
        {kbSeeded ? (
          <>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
              <div style={{ flex: 1, height: 4, background: '#1e2029', borderRadius: 2, overflow: 'hidden' }}>
                <div style={{ height: '100%', width: `${pct}%`, background: '#c07af0', borderRadius: 2, transition: 'width .3s' }} />
              </div>
              <span style={{ fontSize: 9, color: '#505560', fontFamily: FONTS.mono, flexShrink: 0 }}>
                {usedCount}/{techniques.length} · {pct}%
              </span>
            </div>
            <div style={{ display: 'flex', gap: 4 }}>
              {['matrix', 'steps'].map(m => (
                <button key={m} onClick={() => setMode(m)} style={{
                  flex: 1, background: mode === m ? '#c07af022' : 'transparent',
                  border: `1px solid ${mode === m ? '#c07af066' : PALETTE.border}`,
                  borderRadius: 4, padding: '4px 0', cursor: 'pointer',
                  color: mode === m ? '#c07af0' : '#505560',
                  fontSize: 9, fontFamily: FONTS.mono, textTransform: 'uppercase',
                }}>{m === 'matrix' ? 'Matrix' : 'Attack Path'}</button>
              ))}
            </div>
          </>
        ) : (
          <div style={{ fontSize: 10, color: '#505560', lineHeight: 1.5, marginBottom: 6 }}>
            MITRE ATT&CK library not seeded to KB.
          </div>
        )}
        <button
          onClick={seedToKB}
          disabled={seeding}
          style={{
            width: '100%', marginTop: 4,
            background: kbSeeded ? 'transparent' : '#c07af022',
            border: `1px solid ${kbSeeded ? '#2a2d35' : '#c07af066'}`,
            borderRadius: 4, padding: '4px 0', cursor: 'pointer',
            color: kbSeeded ? '#404550' : '#c07af0',
            fontSize: 9, fontFamily: FONTS.mono,
            opacity: seeding ? 0.5 : 1,
          }}
        >
          {(() => {
            if (seeding) return 'Seeding…';
            if (kbSeeded) return 'Re-seed MITRE';
            return '⬡ Seed MITRE ATT&CK to KB';
          })()}
        </button>
      </div>

      {kbSeeded && (
        <div style={{ flex: 1, overflowY: 'auto', padding: '8px' }}>
          {mode === 'matrix' ? (
            <MitreMatrix
              techniques={techniques}
              usedIds={usedIds}
              usedNames={usedNames}
              accent={accent}
              onSelectArticle={onSelectArticle}
              collapsed={collapsedTactics}
              setCollapsed={setCollapsedTactics}
            />
          ) : (
            <StepsFlow
              attackSteps={attackSteps}
              techniques={techniques}
              accent={accent}
            />
          )}
        </div>
      )}
    </div>
  );
}
MitrePanel.propTypes = {
  articles: PropTypes.array,
  attackSteps: PropTypes.array,
  accent: PropTypes.string,
  onSelectArticle: PropTypes.func,
  selectedProject: PropTypes.string,
};
