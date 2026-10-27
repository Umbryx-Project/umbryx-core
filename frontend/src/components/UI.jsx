import { useState, useRef, useEffect } from 'react';
import { createPortal } from 'react-dom';
import PropTypes from 'prop-types';
import Icon from './Icon.jsx';
import { NODE_STATUS, CRED_TYPES, PHASE_COLORS } from '../constants.js';

// ── Design tokens — single source of truth for the visual system ──────
export const FONTS = {
  display: 'Space Grotesk', // headings / titles
  mono: 'JetBrains Mono',   // body / labels / data
};

export const TYPE = {
  pageTitle: 22,
  sectionTitle: 13,
  overline: 9,
  body: 11,
  label: 9,
  button: 10,
  micro: 8,
};

export const PALETTE = {
  bg0: '#08090b',
  bg1: '#0a0b0f',
  bg2: '#0d0f14',
  bg3: '#0e1016',
  border: '#2a2d35',
  borderSoft: '#1a1c22',
  borderFocus: '#3a3d48',
  text: '#f0f2f6',
  textDim: '#c8cdd6',
  textMute: '#9098a8',
  textFaint: '#606570',
  textGhost: '#404550',
  danger: '#cc2233',
  warn: '#f09a3a',
  ok: '#39d353',
};

export const StatusDot = ({ status }) => {
  const c = { active: PALETTE.ok, paused: PALETTE.warn, done: PALETTE.textFaint }[status] || PALETTE.textFaint;
  return <span style={{ display: 'inline-block', width: 6, height: 6, borderRadius: '50%', background: c, boxShadow: `0 0 6px ${c}`, flexShrink: 0 }} />;
};
StatusDot.propTypes = { status: PropTypes.string };

export const PhaseTag = ({ phase, small }) => {
  const c = PHASE_COLORS[phase] || PALETTE.textGhost;
  return (
    <span style={{ fontSize: small ? TYPE.overline : TYPE.button, fontFamily: FONTS.mono, fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', padding: small ? '1px 5px' : '2px 7px', borderRadius: 3, border: `1px solid ${c}55`, color: c, background: `${c}11`, whiteSpace: 'nowrap' }}>
      {phase}
    </span>
  );
};
PhaseTag.propTypes = { phase: PropTypes.string, small: PropTypes.bool };

export const Badge = ({ label, color = PALETTE.textGhost, bg, title, style = {} }) => (
  <span title={title} style={{ fontSize: TYPE.overline, fontFamily: FONTS.mono, fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase', padding: '1px 6px', borderRadius: 3, border: `1px solid ${color}55`, color, background: bg || `${color}11`, whiteSpace: 'nowrap', ...style }}>
    {label}
  </span>
);
Badge.propTypes = { label: PropTypes.string, color: PropTypes.string, bg: PropTypes.string, title: PropTypes.string, style: PropTypes.object };

export const HostStatusBadge = ({ status }) => {
  const { color, label } = NODE_STATUS[status] || { color: PALETTE.textGhost, label: '?' };
  return <Badge label={label} color={color} />;
};
HostStatusBadge.propTypes = { status: PropTypes.string };

export const CredTypeBadge = ({ type }) => {
  const { color, label } = CRED_TYPES[type] || { color: PALETTE.textGhost, label: type };
  return <Badge label={label} color={color} />;
};
CredTypeBadge.propTypes = { type: PropTypes.string };

export const Btn = ({ children, onClick, variant = 'ghost', icon, style = {}, accent = '#15bbb1', disabled = false, title, type = 'button' }) => {
  const [hov, setHov] = useState(false);
  const h = hov && !disabled;
  const base = { border: 'none', borderRadius: 4, padding: '5px 12px', cursor: disabled ? 'not-allowed' : 'pointer', fontSize: TYPE.button, fontFamily: FONTS.mono, display: 'flex', alignItems: 'center', gap: 6, transition: 'all .12s', fontWeight: 600, opacity: disabled ? 0.4 : 1, ...style };
  const variants = {
    primary:     { background: PALETTE.danger, color: '#fff', opacity: disabled ? 0.4 : (h ? .85 : 1) },
    solid:       { background: accent, color: '#06110f', opacity: disabled ? 0.4 : (h ? .85 : 1) },
    accentGhost: { background: h ? `${accent}1a` : 'transparent', border: '1px solid ' + (h ? accent : PALETTE.border), color: h ? accent : PALETTE.textMute },
    ghost:       { background: h ? '#ffffff0e' : 'transparent', border: '1px solid ' + (h ? PALETTE.textGhost : PALETTE.border), color: h ? PALETTE.textDim : PALETTE.textMute },
    danger:      { background: h ? `${PALETTE.danger}22` : 'transparent', border: '1px solid ' + (h ? PALETTE.danger : PALETTE.border), color: h ? PALETTE.danger : PALETTE.textFaint },
  };
  return (
    <button type={type} title={title} disabled={disabled} onClick={disabled ? undefined : onClick} style={{ ...base, ...variants[variant] }} onMouseEnter={() => setHov(true)} onMouseLeave={() => setHov(false)}>
      {icon && <Icon name={icon} size={11} color="currentColor" />}
      {children}
    </button>
  );
};
Btn.propTypes = { children: PropTypes.node, onClick: PropTypes.func, variant: PropTypes.string, icon: PropTypes.string, style: PropTypes.object, accent: PropTypes.string, disabled: PropTypes.bool, title: PropTypes.string, type: PropTypes.string };

export const SearchBar = ({ value, onChange, placeholder = 'Search...' }) => (
  <div style={{ position: 'relative' }}>
    <Icon name="search" size={12} color={PALETTE.textGhost} style={{ position: 'absolute', left: 9, top: '50%', transform: 'translateY(-50%)' }} />
    <input
      value={value} onChange={e => onChange(e.target.value)} placeholder={placeholder}
      style={{ width: '100%', background: PALETTE.bg2, border: `1px solid ${PALETTE.border}`, borderRadius: 5, padding: '6px 8px 6px 28px', color: PALETTE.textDim, fontSize: TYPE.body, outline: 'none', fontFamily: FONTS.mono }}
      onFocus={e => e.target.style.borderColor = PALETTE.borderFocus}
      onBlur={e => e.target.style.borderColor = PALETTE.border}
    />
  </div>
);
SearchBar.propTypes = { value: PropTypes.string, onChange: PropTypes.func, placeholder: PropTypes.string };

export const FieldInput = ({ label, value, onChange, placeholder, mono = true, textarea = false }) => (
  <div>
    <div style={{ fontSize: TYPE.label, color: PALETTE.textGhost, marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>{label}</div>
    {textarea
      ? <textarea value={value} onChange={e => onChange(e.target.value)} placeholder={placeholder} rows={3}
          style={{ width: '100%', background: PALETTE.bg3, border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 8px', color: PALETTE.textDim, fontSize: TYPE.body, outline: 'none', fontFamily: mono ? FONTS.mono : FONTS.display, resize: 'vertical' }} />
      : <input value={value} onChange={e => onChange(e.target.value)} placeholder={placeholder}
          style={{ width: '100%', background: PALETTE.bg3, border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 8px', color: PALETTE.textDim, fontSize: TYPE.body, outline: 'none', fontFamily: mono ? FONTS.mono : FONTS.display }} />
    }
  </div>
);
FieldInput.propTypes = { label: PropTypes.string, value: PropTypes.string, onChange: PropTypes.func, placeholder: PropTypes.string, mono: PropTypes.bool, textarea: PropTypes.bool };

export const TagEditor = ({ label, tags = [], onChange, placeholder = 'add tag' }) => {
  const [draft, setDraft] = useState('');
  const addTag = () => {
    const next = draft.trim();
    if (!next) return;
    onChange([...new Set([...(tags || []), next])]);
    setDraft('');
  };
  const removeTag = (tag) => onChange((tags || []).filter(t => t !== tag));

  return (
    <div>
      <div style={{ fontSize: TYPE.label, color: PALETTE.textGhost, marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>{label}</div>
      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 6 }}>
        {(tags || []).map(tag => (
          <span key={tag} style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: TYPE.overline, fontFamily: FONTS.mono, padding: '2px 6px', borderRadius: 4, border: `1px solid ${PALETTE.border}`, color: PALETTE.textMute, background: PALETTE.bg1 }}>
            {tag}
            <button onClick={() => removeTag(tag)} style={{ background: 'none', border: 'none', color: PALETTE.textFaint, cursor: 'pointer', padding: 0, display: 'flex', alignItems: 'center' }}>
              <Icon name="close" size={9} color="currentColor" />
            </button>
          </span>
        ))}
        {(tags || []).length === 0 && <span style={{ fontSize: TYPE.button, color: PALETTE.textGhost, fontStyle: 'italic' }}>No tags</span>}
      </div>
      <div style={{ display: 'flex', gap: 6 }}>
        <input value={draft} onChange={e => setDraft(e.target.value)} onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); addTag(); } }} placeholder={placeholder}
          style={{ flex: 1, background: PALETTE.bg3, border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 8px', color: PALETTE.textDim, fontSize: TYPE.body, outline: 'none', fontFamily: FONTS.mono }} />
        <button onClick={addTag} style={{ background: PALETTE.borderSoft, border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 10px', cursor: 'pointer', color: PALETTE.textMute, fontSize: TYPE.button, fontFamily: FONTS.mono }}>Add</button>
      </div>
    </div>
  );
};
TagEditor.propTypes = { label: PropTypes.string, tags: PropTypes.array, onChange: PropTypes.func, placeholder: PropTypes.string };

// ── Typography ────────────────────────────────────────────────────────
export const PageTitle = ({ children, sub, icon, accent = '#15bbb1', right, style = {} }) => (
  <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 18, ...style }}>
    {icon && (
      <div style={{ width: 32, height: 32, borderRadius: 8, background: `${accent}18`, border: `1px solid ${accent}44`, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
        <Icon name={icon} size={16} color={accent} />
      </div>
    )}
    <div style={{ flex: 1, minWidth: 0 }}>
      <h1 style={{ margin: 0, fontSize: TYPE.pageTitle, fontWeight: 700, color: PALETTE.text, fontFamily: FONTS.display, lineHeight: 1.2 }}>{children}</h1>
      {sub && <div style={{ fontSize: TYPE.overline, color: PALETTE.textFaint, fontFamily: FONTS.mono, marginTop: 3 }}>{sub}</div>}
    </div>
    {right}
  </div>
);
PageTitle.propTypes = { children: PropTypes.node, sub: PropTypes.node, icon: PropTypes.string, accent: PropTypes.string, right: PropTypes.node, style: PropTypes.object };

export const SectionTitle = ({ children, right, style = {} }) => (
  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, marginBottom: 12, ...style }}>
    <h2 style={{ margin: 0, fontSize: TYPE.sectionTitle, fontWeight: 600, color: PALETTE.text, fontFamily: FONTS.display }}>{children}</h2>
    {right}
  </div>
);
SectionTitle.propTypes = { children: PropTypes.node, right: PropTypes.node, style: PropTypes.object };

export const Overline = ({ children, color = PALETTE.textFaint, style = {} }) => (
  <div style={{ fontSize: TYPE.overline, color, fontFamily: FONTS.mono, textTransform: 'uppercase', letterSpacing: '0.08em', fontWeight: 600, ...style }}>{children}</div>
);
Overline.propTypes = { children: PropTypes.node, color: PropTypes.string, style: PropTypes.object };

// ── Log rows ──────────────────────────────────────────────────────────
// Shared style for readable log lists — Audit Log, System > Logs, and
// Infra > DevOps Log each rolled their own compressed row at 8-9px font
// (TYPE.label/TYPE.micro) with a barely-visible borderSoft separator and
// ~3px vertical padding, which reads as an undifferentiated wall of tiny
// text. One row/header style, spread into each list's own layout, so all
// three are actually readable and stay in sync going forward.
export const LOG_ROW_STYLE = {
  fontSize: 13,
  fontFamily: FONTS.mono,
  lineHeight: 1.6,
  padding: '10px 14px',
  borderBottom: `1px solid ${PALETTE.border}`,
};
export const LOG_HEADER_STYLE = {
  fontSize: 10,
  fontFamily: FONTS.mono,
  color: PALETTE.textGhost,
  textTransform: 'uppercase',
  letterSpacing: '0.08em',
  fontWeight: 700,
  padding: '9px 14px',
  borderBottom: `1px solid ${PALETTE.border}`,
  background: PALETTE.bg1,
};
// Secondary/meta text within a log row (timestamp, level tag, category) —
// smaller than the row's own message text but still legible, not the old
// 8-9px used for everything.
export const LOG_META_STYLE = {
  fontSize: 11,
  fontFamily: FONTS.mono,
  color: PALETTE.textFaint,
};
export const logRowHover = (e) => { e.currentTarget.style.background = '#ffffff07'; };
export const logRowUnhover = (e) => { e.currentTarget.style.background = 'transparent'; };

// ── Select ────────────────────────────────────────────────────────────
// Canonical dropdown look, lifted from the playbooks module (the one part
// of the app whose selects always looked and read consistently) and
// applied everywhere — every other <select> in the app should spread this
// into its own style rather than inventing its own padding/colors.
export const SELECT_STYLE = { background: PALETTE.bg1, border: `1px solid ${PALETTE.border}`, borderRadius: 5, padding: '8px 10px', color: PALETTE.textDim, fontSize: 12, outline: 'none', fontFamily: FONTS.mono, cursor: 'pointer' };

// A native <select>'s open dropdown is drawn by the OS/browser, not by
// our CSS — it can't be made to match the dark theme reliably (light
// popup on macOS/Windows regardless of SELECT_STYLE on the closed box).
// Select is a self-contained popup instead — closed box looks identical
// to a plain select, but the open option list is our own themed panel.
// This is the one base dropdown component: fix or restyle it here and
// every screen using <Select> inherits the change, instead of each tab
// hand-rolling its own version of this widget.
export const Select = ({ label, value, onChange, options = [], placeholder, style = {}, title, disabled = false, autoOpen = false, onClose }) => {
  const [open, setOpen] = useState(autoOpen);
  const [rect, setRect] = useState(null);
  const ref = useRef(null);
  const anchorRef = useRef(null);
  // The listbox is portaled to <body>, so the outside-click check must
  // cover BOTH the anchor and the portaled listbox — without this, the
  // mousedown on an option read as "outside", closed the dropdown before
  // the click landed, and selection silently never happened.
  const listboxRef = useRef(null);
  useEffect(() => {
    if (!open) return;
    const handler = (e) => {
      const inside = (ref.current && ref.current.contains(e.target))
        || (listboxRef.current && listboxRef.current.contains(e.target));
      if (!inside) close();
    };
    // The listbox is portaled to <body> (see below) — ancestors with
    // overflow:auto/hidden used to clip it (e.g. the admin users list),
    // leaving invisible options. Track the anchor's viewport rect and
    // follow it on any scroll/resize.
    const place = () => {
      const r = anchorRef.current?.getBoundingClientRect();
      if (r) setRect({ top: r.bottom + 2, left: r.left, width: r.width });
    };
    place();
    document.addEventListener('mousedown', handler);
    window.addEventListener('resize', place);
    window.addEventListener('scroll', place, true);
    return () => {
      document.removeEventListener('mousedown', handler);
      window.removeEventListener('resize', place);
      window.removeEventListener('scroll', place, true);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);
  const close = () => { setOpen(false); onClose?.(); };

  const norm = (o) => ({ value: typeof o === 'string' ? o : o.value, label: typeof o === 'string' ? o : (o.label ?? o.value) });
  const current = options.map(norm).find(o => o.value === value);

  return (
    <div>
      {label && <div style={{ fontSize: TYPE.label, color: PALETTE.textGhost, marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>{label}</div>}
      <div ref={ref} style={{ position: 'relative' }}>
        <div ref={anchorRef} role="combobox" tabIndex={disabled ? -1 : 0} aria-haspopup="listbox" aria-expanded={open} aria-disabled={disabled} title={title}
          onClick={() => { if (disabled) return; open ? close() : setOpen(true); }}
          onKeyDown={e => { if (disabled) return; if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open ? close() : setOpen(true); } else if (e.key === 'Escape') close(); }}
          style={{ width: '100%', boxSizing: 'border-box', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, ...SELECT_STYLE, borderColor: open ? PALETTE.borderFocus : PALETTE.border, cursor: disabled ? 'not-allowed' : SELECT_STYLE.cursor, opacity: disabled ? 0.5 : 1, ...style }}>
          <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: current ? SELECT_STYLE.color : PALETTE.textGhost }}>
            {current ? current.label : (placeholder || '')}
          </span>
          <span style={{ fontSize: 10, color: PALETTE.textFaint, flexShrink: 0, transform: open ? 'rotate(180deg)' : 'none', transition: 'transform .12s' }}>▾</span>
        </div>
        {open && !disabled && rect && createPortal((
          <div ref={listboxRef} role="listbox" style={{ position: 'fixed', top: rect.top, left: rect.left, minWidth: rect.width, width: 'max-content', maxWidth: 380, zIndex: 10000, background: PALETTE.bg3, border: `1px solid ${PALETTE.border}`, borderRadius: 6, maxHeight: 240, overflowY: 'auto', boxShadow: '0 8px 24px #00000099' }}>
            {placeholder && (
              <button type="button" role="option" aria-selected={!value} onClick={() => { onChange(''); close(); }}
                style={{ padding: '7px 12px', cursor: 'pointer', borderBottom: options.length ? `1px solid ${PALETTE.borderSoft}` : 'none', width: '100%', textAlign: 'left', background: 'transparent', border: 'none', outline: 'none', font: 'inherit', fontFamily: FONTS.mono, fontSize: 11, color: PALETTE.textGhost }}
                onMouseEnter={e => { e.currentTarget.style.background = '#ffffff08'; }}
                onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; }}>
                {placeholder}
              </button>
            )}
            {options.map(norm).map((o, i) => (
              <button type="button" role="option" aria-selected={o.value === value} key={o.value} onClick={() => { onChange(o.value); close(); }}
                style={{ padding: '7px 12px', cursor: 'pointer', borderBottom: i < options.length - 1 ? `1px solid ${PALETTE.borderSoft}` : 'none', width: '100%', textAlign: 'left', background: o.value === value ? '#ffffff08' : 'transparent', border: 'none', outline: 'none', font: 'inherit', fontFamily: FONTS.mono, fontSize: 11, color: o.value === value ? PALETTE.text : PALETTE.textDim }}
                onMouseEnter={e => { e.currentTarget.style.background = '#ffffff08'; }}
                onMouseLeave={e => { e.currentTarget.style.background = o.value === value ? '#ffffff08' : 'transparent'; }}>
                {o.label}
              </button>
            ))}
          </div>
        ), document.body)}
      </div>
    </div>
  );
};
Select.propTypes = { label: PropTypes.string, value: PropTypes.string, onChange: PropTypes.func, options: PropTypes.array, placeholder: PropTypes.string, style: PropTypes.object, title: PropTypes.string, disabled: PropTypes.bool, autoOpen: PropTypes.bool, onClose: PropTypes.func };

// ── Checkbox ──────────────────────────────────────────────────────────
// Every on/off setting across the app used a bare <input type="checkbox">
// with inconsistent (or missing) accentColor and size — a browser-default
// blue checkbox stands out against the dark theme wherever a caller forgot
// to style it. One checkbox component, used everywhere, fixes both at once.
export const Checkbox = ({ checked, onChange, accent = '#15bbb1', disabled = false, label, style = {} }) => {
  const box = {
    width: 16, height: 16, borderRadius: 4, flexShrink: 0,
    border: `1.5px solid ${checked ? accent : PALETTE.border}`,
    background: checked ? accent : 'transparent',
    display: 'flex', alignItems: 'center', justifyContent: 'center',
    transition: 'background .12s, border-color .12s',
    opacity: disabled ? 0.4 : 1,
  };
  const toggle = () => { if (!disabled) onChange(!checked); };
  return (
    <label style={{ display: 'inline-flex', alignItems: 'center', gap: 8, cursor: disabled ? 'not-allowed' : 'pointer', ...style }}>
      <span role="checkbox" aria-checked={checked} tabIndex={disabled ? -1 : 0}
        onClick={toggle}
        onKeyDown={e => { if (e.key === ' ' || e.key === 'Enter') { e.preventDefault(); toggle(); } }}
        style={box}>
        {checked && <Icon name="check" size={10} color="#06110f" />}
      </span>
      {label && <span style={{ fontSize: TYPE.body, fontFamily: FONTS.mono, color: checked ? PALETTE.text : PALETTE.textFaint }}>{label}</span>}
    </label>
  );
};
Checkbox.propTypes = { checked: PropTypes.bool, onChange: PropTypes.func, accent: PropTypes.string, disabled: PropTypes.bool, label: PropTypes.node, style: PropTypes.object };

// ── Slider (range) ────────────────────────────────────────────────────
// Native <input type="range"> can't be themed with inline styles (the
// track/thumb need pseudo-elements), and the app has no global CSS file —
// so inject the rule set once. Filled portion is an inline gradient driven
// by the current value; thumb/track come from the injected class. Replaces
// the bare browser-default sliders (accentColor only) across the app.
let _sliderStyleInjected = false;
function _ensureSliderStyle() {
  if (_sliderStyleInjected || typeof document === 'undefined') return;
  _sliderStyleInjected = true;
  const el = document.createElement('style');
  el.textContent = `
  .ui-range{-webkit-appearance:none;appearance:none;height:4px;border-radius:3px;outline:none;cursor:pointer;background:${PALETTE.border}}
  .ui-range::-webkit-slider-thumb{-webkit-appearance:none;appearance:none;width:14px;height:14px;border-radius:50%;background:var(--slider-accent,#15bbb1);border:2px solid ${PALETTE.bg2};box-shadow:0 0 0 1px var(--slider-accent,#15bbb1);cursor:pointer;transition:transform .1s}
  .ui-range::-webkit-slider-thumb:hover{transform:scale(1.12)}
  .ui-range::-moz-range-thumb{width:14px;height:14px;border-radius:50%;background:var(--slider-accent,#15bbb1);border:2px solid ${PALETTE.bg2};cursor:pointer}
  .ui-range::-moz-range-track{height:4px;border-radius:3px;background:transparent}
  .ui-range:focus-visible{box-shadow:0 0 0 2px var(--slider-accent,#15bbb1)55}
  `;
  document.head.appendChild(el);
}

export const Slider = ({ min = 0, max = 100, step = 1, value, onChange, onCommit, accent = '#15bbb1', width = 120, style = {} }) => {
  _ensureSliderStyle();
  const v = Number(value) || 0;
  const pct = max > min ? ((v - min) / (max - min)) * 100 : 0;
  return (
    <input
      type="range" className="ui-range" min={min} max={max} step={step} value={v}
      onChange={e => onChange?.(parseFloat(e.target.value))}
      onPointerUp={() => onCommit?.()}
      onKeyUp={() => onCommit?.()}
      style={{
        width,
        '--slider-accent': accent,
        background: `linear-gradient(90deg, ${accent} ${pct}%, ${PALETTE.border} ${pct}%)`,
        ...style,
      }}
    />
  );
};
Slider.propTypes = { min: PropTypes.number, max: PropTypes.number, step: PropTypes.number, value: PropTypes.number, onChange: PropTypes.func, onCommit: PropTypes.func, accent: PropTypes.string, width: PropTypes.number, style: PropTypes.object };

// ── FeatureLock (tier upsell) ─────────────────────────────────────────
// Wraps a feature's UI. When `locked`, the children are shown but visually
// dimmed and non-interactive, with a small "requires <tier>" badge — an
// upsell rather than hiding the feature entirely. Pair with
// hooks/useEntitlement's hasFeature to decide `locked`.
export const FeatureLock = ({ locked, tier = 'Pro', children, note, style = {} }) => {
  if (!locked) return children;
  const label = `Requires ${tier}`;
  const tip = note || `${label} plan — contact sales@umbryx.pro to upgrade.`;
  return (
    <div style={{ position: 'relative', display: 'inline-block', ...style }} title={tip}>
      <div style={{ opacity: 0.45, filter: 'grayscale(0.6)', pointerEvents: 'none', userSelect: 'none' }} aria-disabled="true">
        {children}
      </div>
      {/* Badge overlays the button itself (centered). The previous spot —
          floating above via bottom:100% — spilled over the toolbar row above
          and covered neighboring controls. */}
      <span
        style={{
          position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)',
          zIndex: 2, pointerEvents: 'none',
          display: 'inline-flex', alignItems: 'center', gap: 4,
          background: '#0b0d12ee', border: `1px solid ${PALETTE.warn}66`,
          color: PALETTE.warn, borderRadius: 10, padding: '1px 7px',
          fontSize: TYPE.micro, fontFamily: FONTS.mono, fontWeight: 700, whiteSpace: 'nowrap',
        }}>
        <Icon name="lock" size={8} color={PALETTE.warn} />{tier}
      </span>
    </div>
  );
};
FeatureLock.propTypes = { locked: PropTypes.bool, tier: PropTypes.string, children: PropTypes.node, note: PropTypes.string, style: PropTypes.object };

// ── Card ──────────────────────────────────────────────────────────────
export const Card = ({ children, pad = 14, style = {} }) => (
  <div style={{ background: PALETTE.bg2, border: `1px solid ${PALETTE.borderSoft}`, borderRadius: 8, padding: pad, ...style }}>{children}</div>
);
Card.propTypes = { children: PropTypes.node, pad: PropTypes.number, style: PropTypes.object };

// ── Modal ─────────────────────────────────────────────────────────────
export const Modal = ({ title, onClose, children, footer, icon, accent = '#15bbb1', width = 460 }) => (
  <div role="presentation" onClick={onClose}
    style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}>
    <div role="dialog" aria-modal="true" onClick={e => e.stopPropagation()}
      style={{ width, maxWidth: '92vw', maxHeight: '88vh', overflowY: 'auto', background: PALETTE.bg1, border: `1px solid ${PALETTE.border}`, borderRadius: 8, boxShadow: '0 12px 48px rgba(0,0,0,0.5)' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 9, padding: '14px 16px', borderBottom: `1px solid ${PALETTE.borderSoft}` }}>
        {icon && <Icon name={icon} size={14} color={accent} />}
        <span style={{ flex: 1, fontSize: TYPE.sectionTitle, fontWeight: 600, color: PALETTE.text, fontFamily: FONTS.display }}>{title}</span>
        <button onClick={onClose} aria-label="Close"
          style={{ background: 'none', border: 'none', cursor: 'pointer', color: PALETTE.textFaint, display: 'flex', padding: 2 }}
          onMouseEnter={e => { e.currentTarget.style.color = PALETTE.danger; }}
          onMouseLeave={e => { e.currentTarget.style.color = PALETTE.textFaint; }}>
          <Icon name="close" size={13} color="currentColor" />
        </button>
      </div>
      <div style={{ padding: 16, display: 'flex', flexDirection: 'column', gap: 12 }}>{children}</div>
      {footer && <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, padding: '12px 16px', borderTop: `1px solid ${PALETTE.borderSoft}` }}>{footer}</div>}
    </div>
  </div>
);
Modal.propTypes = { title: PropTypes.node, onClose: PropTypes.func, children: PropTypes.node, footer: PropTypes.node, icon: PropTypes.string, accent: PropTypes.string, width: PropTypes.number };

// ── Empty state ───────────────────────────────────────────────────────
export const EmptyState = ({ icon = 'list', title, hint, action, style = {} }) => (
  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 8, padding: '40px 20px', textAlign: 'center', ...style }}>
    <Icon name={icon} size={26} color={PALETTE.textGhost} />
    {title && <div style={{ fontSize: TYPE.body, color: PALETTE.textMute, fontFamily: FONTS.display, fontWeight: 600 }}>{title}</div>}
    {hint && <div style={{ fontSize: TYPE.label, color: PALETTE.textFaint, fontFamily: FONTS.mono, maxWidth: 320, lineHeight: 1.5 }}>{hint}</div>}
    {action && <div style={{ marginTop: 6 }}>{action}</div>}
  </div>
);
EmptyState.propTypes = { icon: PropTypes.string, title: PropTypes.node, hint: PropTypes.node, action: PropTypes.node, style: PropTypes.object };
