import { useState, useEffect, useCallback } from 'react';
import PropTypes from 'prop-types';
import { api } from '../api.js';
import { Btn, Badge, PALETTE, FONTS, TYPE } from '../components/UI.jsx';

export default function ModulesView({ accent = '#15bbb1' }) {
  const [modules, setModules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState(null);
  const [healthMap, setHealthMap] = useState({});

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await api.listExtModules();
      setModules(data.modules || []);
    } catch {
      // best-effort
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const toggle = async (mod) => {
    try {
      if (mod.enabled) {
        await api.disableExtModule(mod.id);
      } else {
        await api.enableExtModule(mod.id);
      }
      load();
    } catch (e) {
      console.error(e);
    }
  };

  const checkHealth = async (id) => {
    try {
      const result = await api.extModuleHealth(id);
      setHealthMap((prev) => ({ ...prev, [id]: result }));
    } catch (e) {
      setHealthMap((prev) => ({ ...prev, [id]: { status: 'error', error: String(e) } }));
    }
  };

  const sel = modules.find((m) => m.id === selected);

  const baseCardStyle = {
    background: PALETTE.bg2,
    borderRadius: 6,
    padding: 12,
    cursor: 'pointer',
    transition: 'border-color .12s',
  };

  return (
    <div style={{ display: 'flex', minHeight: 500, gap: 0, border: `1px solid ${PALETTE.borderSoft}`, borderRadius: 6, overflow: 'hidden' }}>
      {/* Module list */}
      <div style={{ width: 320, borderRight: `1px solid ${PALETTE.border}`, overflowY: 'auto', padding: 8 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12, padding: '0 4px' }}>
          <span style={{ fontFamily: FONTS.display, fontSize: TYPE.sectionTitle, color: PALETTE.text, letterSpacing: '0.04em' }}>
            Extension Modules
          </span>
          <Btn variant="ghost" onClick={load} style={{ fontSize: TYPE.micro }}>
            {'\u21bb'}
          </Btn>
        </div>

        {loading ? (
          <div style={{ color: PALETTE.textMute, fontFamily: FONTS.mono, fontSize: TYPE.body, padding: 8 }}>
            Loading...
          </div>
        ) : modules.length === 0 ? (
          <div style={{ color: PALETTE.textMute, fontFamily: FONTS.mono, fontSize: TYPE.body, padding: 8 }}>
            No extension modules found. Place modules in <code>/modules/</code>.
          </div>
        ) : (
          modules.map((mod) => (
            <div
              key={mod.id}
              style={{
                ...baseCardStyle,
                marginBottom: 6,
                border: `1px solid ${selected === mod.id ? accent : PALETTE.borderSoft}`,
                opacity: mod.has_error ? 0.6 : 1,
              }}
              onClick={() => setSelected(mod.id)}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div>
                  <div style={{ fontFamily: FONTS.mono, fontSize: TYPE.body, fontWeight: 600, color: PALETTE.text }}>
                    {mod.name}
                  </div>
                  <div style={{ fontFamily: FONTS.mono, fontSize: TYPE.micro, color: PALETTE.textFaint }}>
                    v{mod.version} - {mod.id}
                  </div>
                </div>
                {mod.has_error ? (
                  <Badge label="ERROR" color={PALETTE.danger} />
                ) : mod.enabled ? (
                  <Badge label="ON" color={PALETTE.ok} />
                ) : (
                  <Badge label="OFF" color={PALETTE.textFaint} />
                )}
              </div>
              {mod.description && (
                <div style={{ fontFamily: FONTS.mono, fontSize: TYPE.micro, color: PALETTE.textMute, marginTop: 4 }}>
                  {mod.description.slice(0, 80)}
                </div>
              )}
            </div>
          ))
        )}
      </div>

      {/* Detail panel */}
      <div style={{ flex: 1, overflowY: 'auto', padding: 16 }}>
        {!sel ? (
          <div style={{ color: PALETTE.textMute, fontFamily: FONTS.mono, fontSize: TYPE.body }}>
            Select a module to view details.
          </div>
        ) : (
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16 }}>
              <div>
                <h2 style={{ fontFamily: FONTS.display, fontSize: TYPE.pageTitle, color: PALETTE.text, margin: 0 }}>
                  {sel.name}
                </h2>
                <div style={{ fontFamily: FONTS.mono, fontSize: TYPE.label, color: PALETTE.textFaint, marginTop: 2 }}>
                  {sel.id} - v{sel.version} - {sel.author || 'unknown'} - {sel.license || 'N/A'}
                </div>
              </div>
              <div style={{ display: 'flex', gap: 8 }}>
                <Btn variant="ghost" accent={accent} onClick={() => checkHealth(sel.id)}>
                  Health Check
                </Btn>
                {!sel.has_error && (
                  <Btn
                    variant={sel.enabled ? 'primary' : 'solid'}
                    accent={accent}
                    onClick={() => toggle(sel)}
                  >
                    {sel.enabled ? 'Disable' : 'Enable'}
                  </Btn>
                )}
              </div>
            </div>

            {sel.description && (
              <p style={{ fontFamily: FONTS.mono, fontSize: TYPE.body, color: PALETTE.textDim, lineHeight: 1.6 }}>
                {sel.description}
              </p>
            )}

            {sel.has_error && (
              <div
                style={{
                  marginTop: 12,
                  padding: 10,
                  borderRadius: 4,
                  border: `1px solid ${PALETTE.danger}44`,
                  background: `${PALETTE.danger}11`,
                  fontFamily: FONTS.mono,
                  fontSize: TYPE.body,
                  color: PALETTE.danger,
                }}
              >
                {sel.error}
              </div>
            )}

            {healthMap[sel.id] && (
              <div
                style={{
                  marginTop: 12,
                  padding: 10,
                  borderRadius: 4,
                  border: `1px solid ${PALETTE.border}`,
                  background: PALETTE.bg1,
                  fontFamily: FONTS.mono,
                  fontSize: TYPE.body,
                  color: PALETTE.textDim,
                }}
              >
                <strong>Health:</strong> {JSON.stringify(healthMap[sel.id], null, 2)}
              </div>
            )}

            {/* Permissions */}
            {sel.permissions?.length > 0 && (
              <Section title="Permissions">
                <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                  {sel.permissions.map((p) => (
                    <Badge key={p} label={p} color={PALETTE.warn} />
                  ))}
                </div>
              </Section>
            )}

            {/* Dependencies */}
            {sel.depends_on?.length > 0 && (
              <Section title="Dependencies">
                <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                  {sel.depends_on.map((d) => (
                    <Badge key={d} label={d} color={PALETTE.textDim} />
                  ))}
                </div>
              </Section>
            )}

            {/* Objects */}
            {sel.objects?.length > 0 && (
              <Section title={`Object Types (${sel.objects.length})`}>
                <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                  {sel.objects.map((o) => (
                    <Badge key={o.type} label={o.name} color={accent} />
                  ))}
                </div>
              </Section>
            )}

            {/* Extensions */}
            {sel.extensions?.length > 0 && (
              <Section title={`Extension Points (${sel.extensions.length})`}>
                <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                  {sel.extensions.map((e, i) => (
                    <Badge key={`${e.point}:${e.id}:${i}`} label={`${e.point} / ${e.id}`} color={PALETTE.textDim} />
                  ))}
                </div>
              </Section>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function Section({ title, children }) {
  return (
    <div style={{ marginTop: 16 }}>
      <div
        style={{
          fontFamily: FONTS.mono,
          fontSize: TYPE.label,
          fontWeight: 600,
          letterSpacing: '0.06em',
          textTransform: 'uppercase',
          color: PALETTE.textMute,
          marginBottom: 6,
        }}
      >
        {title}
      </div>
      {children}
    </div>
  );
}

ModulesView.propTypes = {
  accent: PropTypes.string,
};

Section.propTypes = {
  title: PropTypes.string,
  children: PropTypes.node,
};
