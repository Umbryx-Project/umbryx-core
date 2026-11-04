/**
 * Shared form primitives for scan panels (Nmap, Nuclei, CME, DonPAPI).
 */

import PropTypes from 'prop-types';
import { PALETTE, FONTS, Select } from '../../components/UI.jsx';

export const FieldRow = ({ label, children }) => (
  <div style={{ display: 'flex', flexDirection: 'column', gap: 4, marginBottom: 12 }}>
    <label style={{ fontSize: 10, color: PALETTE.textFaint, fontFamily: FONTS.mono, textTransform: 'uppercase', letterSpacing: '0.08em' }}>{label}</label>
    {children}
  </div>
);
FieldRow.propTypes = { label: PropTypes.any, children: PropTypes.any };

export const Input = ({ value, onChange, placeholder, monospace, multiline, rows = 3 }) => {
  const base = {
    background: PALETTE.bg2, border: `1px solid ${PALETTE.border}`, borderRadius: 5,
    padding: '7px 10px', color: PALETTE.textDim, fontSize: 12,
    fontFamily: monospace ? 'JetBrains Mono' : 'inherit',
    outline: 'none', width: '100%', boxSizing: 'border-box',
  };
  return multiline
    ? <textarea value={value} onChange={e => onChange(e.target.value)} placeholder={placeholder} rows={rows} style={{ ...base, resize: 'vertical' }} />
    : <input value={value} onChange={e => onChange(e.target.value)} placeholder={placeholder} style={base} />;
};
Input.propTypes = { value: PropTypes.any, onChange: PropTypes.any, placeholder: PropTypes.any, monospace: PropTypes.any, multiline: PropTypes.any, rows: PropTypes.any };

export const ResultBox = ({ result, error }) => {
  if (!result && !error) return null;
  if (error) return (
    <div style={{ background: '#1a0508', border: '1px solid #cc223344', borderRadius: 6, padding: 12, marginTop: 12, fontSize: 12, color: PALETTE.danger, fontFamily: FONTS.mono }}>
      {error}
    </div>
  );
  return (
    <div style={{ background: '#0a1208', border: '1px solid #39d35344', borderRadius: 6, padding: 12, marginTop: 12, fontSize: 11, fontFamily: FONTS.mono, color: PALETTE.textDim, whiteSpace: 'pre-wrap', overflowX: 'auto', maxHeight: 300, overflowY: 'auto' }}>
      {typeof result === 'string' ? result : JSON.stringify(result, null, 2)}
    </div>
  );
};
ResultBox.propTypes = { result: PropTypes.any, error: PropTypes.any };

export function ExecutionSourceRow({ executionSource, setExecutionSource, pivotObservationId, setPivotObservationId, pivotOptions = [], loading = false }) {
  return (
    <>
      <FieldRow label="Execution source">
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          {[
            { id: 'attacker', label: 'Attacker host', color: '#5b8af5' },
            { id: 'pivot_listener', label: 'Pivot listener', color: '#e8cc42' },
          ].map(opt => (
            <button key={opt.id} onClick={() => setExecutionSource(opt.id)}
              style={{ background: executionSource === opt.id ? `${opt.color}22` : PALETTE.borderSoft, border: `1px solid ${executionSource === opt.id ? opt.color : PALETTE.border}`, borderRadius: 4, padding: '4px 10px', cursor: 'pointer', color: executionSource === opt.id ? opt.color : PALETTE.textFaint, fontSize: 10, fontFamily: FONTS.mono }}>
              {opt.label}
            </button>
          ))}
        </div>
      </FieldRow>
      {executionSource === 'pivot_listener' && (
        <FieldRow label="Pivot listener">
          <Select value={pivotObservationId} onChange={setPivotObservationId} style={{ width: '100%', boxSizing: 'border-box' }}
            placeholder={loading ? 'Loading listeners...' : 'Select pivot listener...'}
            options={pivotOptions.map(item => ({ value: item.id, label: item.label }))} />
        </FieldRow>
      )}
    </>
  );
}
ExecutionSourceRow.propTypes = {
  executionSource: PropTypes.any,
  setExecutionSource: PropTypes.any,
  pivotObservationId: PropTypes.any,
  setPivotObservationId: PropTypes.any,
  pivotOptions: PropTypes.any,
  loading: PropTypes.any,
};

export function isSocksPivot(item) {
  if (!item.bind_address) return false;
  const pt = String(item.pivot_type || '').toLowerCase();
  return pt.includes('socks4') || pt.includes('socks5');
}
