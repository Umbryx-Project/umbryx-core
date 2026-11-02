import { useState, useEffect, useRef, useCallback } from 'react';
import Icon from './Icon.jsx';
import { PALETTE, TYPE, FONTS } from './UI.jsx';

/**
 * App-styled replacements for the native confirm()/alert()/prompt() —
 * those render as raw OS dialogs that ignore the product's theme, sizes
 * and copy tone. Toast-pattern service: module-level queue + a single
 * <ConfirmHost/> mounted next to the Toaster; every call returns a
 * Promise that resolves when the dialog closes.
 *
 *   const ok = await uiConfirm('Delete this organization?');
 *   await uiAlert('Download failed: ...');
 *   const pw = await uiPrompt({ message: 'Archive password', defaultValue: '' });
 */

let _open = null; // (dialog | null) => void

const _DIALOG_SHAPE = {
  kind: 'confirm', // confirm | alert | prompt
  title: '',
  message: '',
  confirmLabel: 'Confirm',
  cancelLabel: 'Cancel',
  danger: true,
  placeholder: '',
  defaultValue: '',
};

function _show(opts) {
  return new Promise((resolve) => {
    if (!_open) {
      // Host not mounted (tests) — degrade to the native dialog so the
      // calling code keeps working instead of hanging forever.
      const o = { ..._DIALOG_SHAPE, ...opts };
      if (o.kind === 'confirm') resolve(window.confirm(o.message));
      else if (o.kind === 'prompt') resolve(window.prompt(o.message, o.defaultValue));
      else { window.alert(o.message); resolve(undefined); }
      return;
    }
    _open({ ..._DIALOG_SHAPE, ...opts, resolve });
  });
}

export function uiConfirm(message, opts = {}) {
  return _show({ kind: 'confirm', message: typeof message === 'string' ? message : message.message, ...(typeof message === 'string' ? opts : message) });
}

export function uiAlert(message, opts = {}) {
  return _show({ kind: 'alert', message, confirmLabel: 'OK', danger: false, ...opts });
}

export function uiPrompt(opts) {
  if (typeof opts === 'string') opts = { message: opts };
  return _show({ kind: 'prompt', danger: false, confirmLabel: 'OK', ...opts });
}

export function ConfirmHost() {
  const [dialog, setDialog] = useState(null);
  const [input, setInput] = useState('');
  const confirmRef = useRef(null);
  const inputRef = useRef(null);

  const close = useCallback((value) => {
    dialog?.resolve(value);
    setDialog(null);
  }, [dialog]);

  useEffect(() => {
    _open = (d) => {
      setInput(d.defaultValue || '');
      setDialog(d);
    };
    return () => { _open = null; };
  }, []);

  useEffect(() => {
    if (!dialog) return;
    const onKey = (e) => {
      if (e.key === 'Escape') close(dialog.kind === 'confirm' ? false : dialog.kind === 'prompt' ? null : undefined);
      if (e.key === 'Enter') {
        if (dialog.kind === 'prompt') close(input);
        else close(true);
      }
    };
    document.addEventListener('keydown', onKey);
    const t = setTimeout(() => {
      if (dialog.kind === 'prompt') inputRef.current?.focus();
      else confirmRef.current?.focus();
    }, 30);
    return () => { document.removeEventListener('keydown', onKey); clearTimeout(t); };
  }, [dialog, close, input]);

  if (!dialog) return null;

  const accentColor = dialog.danger ? PALETTE.danger : '#5b8af5';
  return (
    <div role="presentation" onClick={() => close(dialog.kind === 'confirm' ? false : dialog.kind === 'prompt' ? null : undefined)}
      style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.55)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 3000 }}>
      <div role="dialog" aria-modal="true" onClick={e => e.stopPropagation()}
        style={{ width: 430, maxWidth: '92vw', background: PALETTE.bg1, border: `1px solid ${PALETTE.border}`, borderRadius: 8, boxShadow: '0 12px 48px rgba(0,0,0,0.5)', padding: 18 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 9, marginBottom: 10 }}>
          <Icon name={dialog.danger ? 'trash' : 'bolt'} size={13} color={accentColor} />
          <span style={{ fontSize: TYPE.sectionTitle, fontWeight: 600, color: PALETTE.text, fontFamily: FONTS.display }}>
            {dialog.title || (dialog.kind === 'confirm' ? 'Confirm' : dialog.kind === 'prompt' ? 'Input' : 'Notice')}
          </span>
        </div>
        <div style={{ fontSize: TYPE.body, color: PALETTE.textDim, fontFamily: FONTS.mono, lineHeight: 1.6, whiteSpace: 'pre-wrap', marginBottom: dialog.kind === 'prompt' ? 10 : 16 }}>
          {dialog.message}
        </div>
        {dialog.kind === 'prompt' && (
          <input ref={inputRef} value={input} onChange={e => setInput(e.target.value)} placeholder={dialog.placeholder}
            style={{ width: '100%', boxSizing: 'border-box', background: PALETTE.bg2, border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '7px 10px', color: PALETTE.textDim, fontSize: TYPE.body, fontFamily: FONTS.mono, outline: 'none', marginBottom: 16 }} />
        )}
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
          {dialog.kind === 'confirm' && (
            <button onClick={() => close(false)}
              style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '7px 16px', cursor: 'pointer', color: PALETTE.textFaint, fontSize: TYPE.body, fontFamily: FONTS.mono }}>
              {dialog.cancelLabel}
            </button>
          )}
          <button ref={confirmRef} onClick={() => close(dialog.kind === 'prompt' ? input : true)}
            style={{ background: dialog.danger ? `${PALETTE.danger}22` : '#5b8af522', border: `1px solid ${accentColor}88`, borderRadius: 4, padding: '7px 18px', cursor: 'pointer', color: accentColor, fontSize: TYPE.body, fontWeight: 600, fontFamily: FONTS.mono }}>
            {dialog.confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
