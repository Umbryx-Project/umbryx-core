import { useState, useEffect } from 'react';
import PropTypes from 'prop-types';
import Icon from '../components/Icon.jsx';
import { api } from '../api.js';
import { toastError, toastSuccess } from '../components/Toast.jsx';
import {
  Btn, Modal, EmptyState,
  PALETTE, TYPE, FONTS,
} from '../components/UI.jsx';

const STEPS = ['preflight', 'confirm', 'progress', 'result'];

export default function ClosureWizard({ projectId, accent, onClose, onDone }) {
  const [step, setStep] = useState(0);
  const [preview, setPreview] = useState(null);
  const [loading, setLoading] = useState(true);
  const [progress, setProgress] = useState('');
  const [result, setResult] = useState(null);

  useEffect(() => {
    (async () => {
      try {
        const p = await api.closurePreview(projectId);
        setPreview(p);
      } catch (e) { toastError(e.message); }
      setLoading(false);
    })();
  }, [projectId]);

  const handleClose = async () => {
    setStep(2);
    setProgress('Closing project...');
    try {
      const r = await api.closeProject(projectId, {});
      setResult(r);
      setStep(3);
      toastSuccess('Project closed');
      if (onDone) onDone();
    } catch (e) {
      toastError(e.message);
      setStep(0);
    }
  };

  return (
    <Modal title="Close Project" icon="shield" accent={accent} onClose={onClose}
      footer={
        step === 0 && !loading ? <>
          <Btn variant="ghost" onClick={onClose}>Cancel</Btn>
          <Btn variant="solid" accent={accent} onClick={() => setStep(1)}>Next →</Btn>
        </> :
        step === 1 ? <>
          <Btn variant="ghost" onClick={() => setStep(0)}>← Back</Btn>
          <Btn variant="primary" onClick={handleClose}>Close Project</Btn>
        </> :
        step === 3 ? <>
          <Btn variant="solid" accent={accent} onClick={onClose}>Go to Projects</Btn>
        </> : null
      }>

      <div style={{ display: 'flex', justifyContent: 'center', gap: 4, marginBottom: 8 }}>
        {STEPS.map((_, i) => (
          <div key={i} style={{ width: 24, height: 3, borderRadius: 2, background: i <= step ? accent : PALETTE.border, transition: 'all .2s' }} />
        ))}
      </div>

      {loading && <div style={{ color: PALETTE.textGhost, fontFamily: FONTS.mono, fontSize: TYPE.body, textAlign: 'center', padding: 20 }}>Loading preview...</div>}

      {!loading && step === 0 && preview && (
        <div>
          <div style={{ fontSize: TYPE.body, color: PALETTE.textMute, fontFamily: FONTS.mono, marginBottom: 12 }}>Pre-flight check:</div>
          {preview.running_jobs > 0 && <div style={{ fontSize: TYPE.body, color: PALETTE.warn, fontFamily: FONTS.mono, marginBottom: 6 }}>⚠ {preview.running_jobs} running jobs detected</div>}
          {preview.open_findings > 0 && <div style={{ fontSize: TYPE.body, color: PALETTE.warn, fontFamily: FONTS.mono, marginBottom: 6 }}>⚠ {preview.open_findings} open findings</div>}
          {preview.infra_instances > 0 && <div style={{ fontSize: TYPE.body, color: '#5b8af5', fontFamily: FONTS.mono, marginBottom: 6 }}>ℹ {preview.infra_instances} infrastructure instances to destroy</div>}
          {preview.active_members > 0 && <div style={{ fontSize: TYPE.body, color: '#5b8af5', fontFamily: FONTS.mono, marginBottom: 6 }}>ℹ {preview.active_members} active members to deactivate</div>}
          {preview.active_secrets > 0 && <div style={{ fontSize: TYPE.body, color: '#5b8af5', fontFamily: FONTS.mono, marginBottom: 6 }}>ℹ {preview.active_secrets} active secrets to revoke</div>}
          <div style={{ fontSize: TYPE.button, color: PALETTE.textFaint, fontFamily: FONTS.mono, marginTop: 10 }}>Review and acknowledge to proceed.</div>
        </div>
      )}

      {!loading && step === 1 && (
        <div>
          <div style={{ fontSize: TYPE.body, color: PALETTE.danger, fontFamily: FONTS.mono, marginBottom: 12 }}>
            All resources will be cleaned up and the project will be marked as closed. This action is irreversible.
          </div>
        </div>
      )}

      {step === 2 && (
        <div style={{ textAlign: 'center', padding: 20 }}>
          <div style={{ fontSize: TYPE.body, color: PALETTE.textMute, fontFamily: FONTS.mono }}>{progress}</div>
        </div>
      )}

      {step === 3 && result && (
        <div>
          <div style={{ fontSize: TYPE.body + 1, color: PALETTE.ok, fontFamily: FONTS.mono, marginBottom: 12 }}>✅ Project closed successfully</div>
          {result.status && <div style={{ fontSize: TYPE.button, color: PALETTE.textMute, fontFamily: FONTS.mono, marginBottom: 4 }}>Status: {result.status}</div>}
          {result.warnings > 0 && <div style={{ fontSize: TYPE.button, color: PALETTE.warn, fontFamily: FONTS.mono, marginBottom: 4 }}>Warnings: {result.warnings}</div>}
        </div>
      )}
    </Modal>
  );
}

ClosureWizard.propTypes = { projectId: PropTypes.string, accent: PropTypes.string, onClose: PropTypes.func, onDone: PropTypes.func };
