import { useState, useEffect, useCallback } from 'react';
import PropTypes from 'prop-types';
import Icon from '../components/Icon.jsx';
import { api } from '../api.js';
import { toastError, toastSuccess } from '../components/Toast.jsx';
import { PALETTE, FONTS } from '../components/UI.jsx';
import { uiConfirm } from '../components/Confirm.jsx';

export default function PluginsPanel({ accent }) {
  const [plugins, setPlugins] = useState([]);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try { setPlugins(await api.listPlugins()); }
    catch (e) { toastError(e.message); }
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleToggle = async (id, enabled) => {
    try { await api.togglePlugin(id, { enabled: !enabled }); toastSuccess(enabled ? 'Plugin disabled' : 'Plugin enabled'); load(); }
    catch (e) { toastError(e.message); }
  };

  const handleUninstall = async (id) => {
    if (!await uiConfirm('Uninstall this plugin?')) return;
    try { await api.uninstallPlugin(id); toastSuccess('Plugin uninstalled'); load(); }
    catch (e) { toastError(e.message); }
  };

  if (loading) return <div style={{ padding: 20, color: PALETTE.textGhost, fontFamily: FONTS.mono, fontSize: 11 }}>Loading...</div>;

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
        <span style={{ fontSize: 13, fontWeight: 600, color: PALETTE.textDim, fontFamily: FONTS.mono }}>Plugins</span>
      </div>
      {plugins.length === 0 && <div style={{ color: PALETTE.textGhost, fontFamily: FONTS.mono, fontSize: 11 }}>No plugins installed.</div>}
      {plugins.map(p => (
        <div key={p.id} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 0', borderBottom: '1px solid #1e2029' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <span style={{ fontSize: 12, color: PALETTE.textDim, fontFamily: FONTS.mono, fontWeight: 600 }}>{p.name}</span>
              <span style={{ fontSize: 9, color: PALETTE.textFaint, fontFamily: FONTS.mono }}>v{p.version || '?'}</span>
              {p.source === 'builtin' && <span style={{ fontSize: 8, color: '#5b8af5', background: '#5b8af518', borderRadius: 3, padding: '1px 5px', fontFamily: FONTS.mono }}>builtin</span>}
            </div>
            {p.description && <div style={{ fontSize: 10, color: PALETTE.textFaint, fontFamily: FONTS.mono, marginTop: 2 }}>{p.description}</div>}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{ fontSize: 9, color: p.enabled ? '#22c55e' : PALETTE.textFaint, fontFamily: FONTS.mono }}>{p.enabled ? '✅ Enabled' : '⬜ Disabled'}</span>
            <button onClick={() => handleToggle(p.id, p.enabled)} style={{ padding: '2px 8px', borderRadius: 3, border: `1px solid ${PALETTE.border}`, background: 'transparent', color: '#808590', fontSize: 9, fontFamily: FONTS.mono, cursor: 'pointer' }}>
              {p.enabled ? 'Disable' : 'Enable'}
            </button>
            {p.source !== 'builtin' && (
              <button onClick={() => handleUninstall(p.id)} style={{ padding: '2px 8px', borderRadius: 3, border: '1px solid #cc223344', background: 'transparent', color: PALETTE.danger, fontSize: 9, fontFamily: FONTS.mono, cursor: 'pointer' }}>Uninstall</button>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}

PluginsPanel.propTypes = { accent: PropTypes.string };
