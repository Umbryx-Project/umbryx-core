import PropTypes from 'prop-types';
import { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import Icon from '../components/Icon.jsx';
import { PALETTE, TYPE, FONTS, Badge, Btn, Modal, FieldInput, Select, EmptyState, Slider } from '../components/UI.jsx';
import { toastError } from '../components/Toast.jsx';
import { api } from '../api.js';
import AttackPathNodeEditor from './attack-path/NodeEditor.jsx';
import { uiConfirm } from '../components/Confirm.jsx';

const STEP_TYPES = {
  action:    { label: 'Action',    color: '#5b8af5' },
  condition: { label: 'Condition', color: '#e8cc42' },
  milestone: { label: 'Milestone', color: '#39d353' },
  pivot:     { label: 'Pivot',     color: '#f09a3a' },
};

const STATUS_CFG = {
  hypothetical: { color: '#808590' },
  planned:      { color: '#5b8af5' },
  executing:    { color: '#f09a3a' },
  verified:     { color: '#39d353' },
  failed:       { color: '#cc2233' },
};

const CONFIDENCE_CFG = {
  low:    { color: '#39d353', label: 'Low', dots: 1 },
  medium: { color: '#f09a3a', label: 'Medium', dots: 2 },
  high:   { color: '#cc2233', label: 'High', dots: 3 },
};

const NODE_W = 180;
const NODE_H = 64;
const H_GAP = 60;
const V_GAP = 24;

const EMPTY_STEP = {
  label: '',
  node_type: 'action',
  technique: '',
  mitre_id: '',
  notes: '',
  node_status: 'hypothetical',
  confidence: 'medium',
  branch_name: '',
};

let _kbCache = null;

async function loadKBTechniques() {
  if (_kbCache) return _kbCache;
  try {
    const articles = await api.getKBArticles({ category: 'MITRE ATT&CK' });
    _kbCache = articles.map(a => {
      const mid = (a.tags || []).find(t => /^T\d{4}/.test(t)) || '';
      const name = a.title.includes(' \u2014 ') ? a.title.split(' \u2014 ')[1] : a.title;
      const tacticTag = (a.tags || []).find(t => t !== 'mitre' && !/^T\d/.test(t));
      const tactic = tacticTag
        ? tacticTag.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
        : 'Other';
      return { id: mid, name, tactic, kb_id: a.id };
    }).filter(t => t.id);
    return _kbCache;
  } catch {
    return [];
  }
}

const TACTIC_ORDER = [
  'Reconnaissance', 'Initial Access', 'Execution', 'Persistence',
  'Privilege Escalation', 'Defense Evasion', 'Credential Access',
  'Discovery', 'Lateral Movement', 'Collection',
  'Command and Control', 'Exfiltration', 'Impact', 'Other',
];

function TechniqueInput({ value, mitreId, onChange, accent }) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState(value || '');
  const [hints, setHints] = useState([]);
  const ref = useRef(null);

  useEffect(() => { setQuery(value || ''); }, [value]);
  useEffect(() => { loadKBTechniques().then(setHints); }, []);
  useEffect(() => {
    const handler = e => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  const q = query.trim().toLowerCase();
  const matches = q.length > 0
    ? hints.filter(t => t.name.toLowerCase().includes(q) || t.id.toLowerCase().includes(q) || t.tactic.toLowerCase().includes(q))
    : hints;

  const grouped = {};
  for (const t of matches) {
    if (!grouped[t.tactic]) grouped[t.tactic] = [];
    grouped[t.tactic].push(t);
  }
  const tacticOrder = TACTIC_ORDER.filter(tc => grouped[tc]);
  const pick = t => { setQuery(t.name); onChange(t.name, t.id); setOpen(false); };
  const kbEmpty = hints.length === 0;

  return (
    <div ref={ref} style={{ position: 'relative' }}>
      <div style={{ position: 'relative' }}>
        <input
          value={query}
          onChange={e => { setQuery(e.target.value); onChange(e.target.value, mitreId); setOpen(true); }}
          onFocus={() => setOpen(true)}
          placeholder={kbEmpty ? 'Type technique name\u2026' : 'Search technique\u2026'}
          style={{ width: '100%', background: PALETTE.bg0, border: `1px solid ${PALETTE.border}`, borderRadius: 5, padding: '7px 32px 7px 10px', color: PALETTE.textDim, fontSize: 12, outline: 'none', boxSizing: 'border-box' }}
        />
        {query && (
          <button onMouseDown={e => { e.preventDefault(); setQuery(''); onChange('', ''); }}
            style={{ position: 'absolute', right: 8, top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', cursor: 'pointer', color: PALETTE.textFaint, fontSize: 13, lineHeight: 1 }}>\u00d7</button>
        )}
      </div>
      {open && (hints.length > 0 || q) && (
        <div style={{ position: 'absolute', top: '100%', left: 0, right: 0, zIndex: 200, background: '#0e1016', border: `1px solid ${PALETTE.border}`, borderRadius: 6, boxShadow: '0 12px 32px #00000099', maxHeight: 320, overflow: 'auto', marginTop: 2 }}>
          {tacticOrder.map(tactic => (
            <div key={tactic}>
              <div style={{ padding: '5px 10px 3px', fontSize: 8, fontWeight: 700, color: '#404550', textTransform: 'uppercase', letterSpacing: '0.1em', background: PALETTE.bg0, position: 'sticky', top: 0 }}>{tactic}</div>
              {grouped[tactic].map(t => (
                <button type="button" key={t.id} onMouseDown={e => { e.preventDefault(); pick(t); }}
                  style={{ padding: '5px 10px 5px 14px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 8, background: 'transparent', border: 'none', color: 'inherit', font: 'inherit', textAlign: 'left', width: '100%' }}
                  onMouseEnter={e => e.currentTarget.style.background = '#ffffff0a'}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
                  <span style={{ fontSize: 8, fontFamily: FONTS.mono, color: accent, width: 60, flexShrink: 0 }}>{t.id}</span>
                  <span style={{ fontSize: 11, color: '#c8cdd6' }}>{t.name}</span>
                </button>
              ))}
            </div>
          ))}
          {q && matches.length === 0 && <div style={{ padding: '10px 12px', fontSize: 10, color: PALETTE.textFaint }}>No matches for &ldquo;{query}&rdquo;</div>}
        </div>
      )}
    </div>
  );
}

function computeLiveness(steps) {
  const childrenOf = {};
  steps.forEach(s => {
    if (s.parent_step_id && s.parent_step_id !== s.id) {
      childrenOf[s.parent_step_id] = childrenOf[s.parent_step_id] || [];
      childrenOf[s.parent_step_id].push(s);
    }
  });

  const cache = {};

  function isLive(step, visiting = new Set()) {
    if (cache[step.id] !== undefined) return cache[step.id];
    // Cycle guard — a corrupt parent chain would recurse forever here.
    if (visiting.has(step.id)) return true;
    visiting.add(step.id);
    const kids = childrenOf[step.id] || [];
    if (kids.length === 0) {
      const live = (step.node_status || '') !== 'failed';
      cache[step.id] = live;
      return live;
    }
    const anyLive = kids.some(k => isLive(k, visiting));
    cache[step.id] = anyLive;
    return anyLive;
  }

  const result = {};
  steps.forEach(s => { result[s.id] = isLive(s); });
  return result;
}

function layoutTree(steps) {
  const byId = {};
  steps.forEach(s => { byId[s.id] = s; });

  const childrenOf = {};
  const roots = [];
  steps.forEach(s => {
    // Only attach to a parent that exists in this step set. A stale
    // parent_step_id (parent deleted mid-race, cross-path ref, self-ref)
    // otherwise leaves the step out of both roots and layoutNode — it
    // renders without a position and ghosts/overlaps existing cards.
    if (s.parent_step_id && byId[s.parent_step_id] && s.parent_step_id !== s.id) {
      childrenOf[s.parent_step_id] = childrenOf[s.parent_step_id] || [];
      childrenOf[s.parent_step_id].push(s);
    } else {
      roots.push(s);
    }
  });

  Object.values(childrenOf).forEach(arr => arr.sort((a, b) => (a.step_order || 0) - (b.step_order || 0)));
  roots.sort((a, b) => (a.step_order || 0) - (b.step_order || 0));

  function subtreeHeight(id, seen = new Set()) {
    // Cycle guard: corrupt parent chains would otherwise recurse forever
    // and take the whole tab down with a RangeError.
    if (seen.has(id)) return NODE_H;
    seen.add(id);
    const kids = childrenOf[id] || [];
    if (kids.length === 0) return NODE_H;
    return kids.reduce((sum, k) => sum + subtreeHeight(k.id, seen), 0) + (kids.length - 1) * V_GAP;
  }

  const positions = {};

  function layoutNode(id, x, yCenter) {
    positions[id] = { x, y: yCenter - NODE_H / 2 };
    const kids = childrenOf[id] || [];
    if (kids.length === 0) return;

    const totalH = kids.reduce((sum, k) => sum + subtreeHeight(k.id), 0) + (kids.length - 1) * V_GAP;
    let yCursor = yCenter - totalH / 2;

    kids.forEach(k => {
      const h = subtreeHeight(k.id);
      layoutNode(k.id, x + NODE_W + H_GAP, yCursor + h / 2);
      yCursor += h + V_GAP;
    });
  }

  if (roots.length === 0) return positions;

  const totalRootH = roots.reduce((sum, r) => sum + subtreeHeight(r.id), 0) + Math.max(roots.length - 1, 0) * V_GAP;
  let yCursor = -totalRootH / 2;
  roots.forEach(r => {
    const h = subtreeHeight(r.id);
    layoutNode(r.id, 0, yCursor + h / 2);
    yCursor += h + V_GAP;
  });

  return positions;
}

function StepModal({ step, isNew, parentId, parentLabel, onSave, onClose, accent, hosts }) {
  const [form, setForm] = useState(() => step ? { ...EMPTY_STEP, ...step } : { ...EMPTY_STEP });
  const set = (k, v) => setForm(f => ({ ...f, [k]: v }));

  return (
    <Modal
      title={isNew ? (parentId ? `Add child \u2192 ${parentLabel || ''}` : 'Add root step') : 'Edit step'}
      onClose={onClose}
      icon="attackpath"
      accent={accent}
      width={520}
      footer={
        <>
          <Btn onClick={onClose} variant="ghost">Cancel</Btn>
          <Btn onClick={() => onSave(form)} variant="solid" accent={accent}>{isNew ? 'Add' : 'Save'}</Btn>
        </>
      }
    >
      {parentId && (
        <div style={{ fontSize: 9, color: PALETTE.textFaint, fontFamily: FONTS.mono, background: PALETTE.bg0, padding: '6px 10px', borderRadius: 4 }}>
          Parent: {parentLabel || parentId}
        </div>
      )}

      {hosts && hosts.length > 0 && (
        <Select
          label="Link to host (optional)"
          value={form.host_id || ''}
          onChange={v => {
            if (!v) { set('host_id', null); return; }
            const host = hosts.find(h => h.id === v);
            if (host) {
              set('host_id', v);
              if (!form.label) set('label', host.hostname || host.ip || '');
            }
          }}
          options={[{ value: '', label: '\u2014 none \u2014' }, ...hosts.map(h => ({ value: h.id, label: `${h.hostname || h.ip}${h.ip && h.hostname ? ` (${h.ip})` : ''}` }))]}
        />
      )}

      <FieldInput label="Label" value={form.label || ''} onChange={v => set('label', v)} placeholder="e.g. Initial Access" mono={false} />

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        <Select label="Node type" value={form.node_type || 'action'} onChange={v => set('node_type', v)}
          options={Object.entries(STEP_TYPES).map(([k, t]) => ({ value: k, label: t.label }))} />
        <Select label="Status" value={form.node_status || 'hypothetical'} onChange={v => set('node_status', v)}
          options={Object.keys(STATUS_CFG)} />
      </div>

      <div>
        <div style={{ fontSize: 9, color: PALETTE.textGhost, marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Technique</div>
        <TechniqueInput value={form.technique || ''} mitreId={form.mitre_id || ''} accent={accent}
          onChange={(name, id) => setForm(f => ({ ...f, technique: name, mitre_id: id ?? f.mitre_id }))} />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        <Select label="Confidence" value={form.confidence || 'medium'} onChange={v => set('confidence', v)}
          options={Object.entries(CONFIDENCE_CFG).map(([k, c]) => ({ value: k, label: c.label }))} />
        <FieldInput label="Branch name (optional)" value={form.branch_name || ''} onChange={v => set('branch_name', v)} placeholder="e.g. alt-phishing" />
      </div>

      <FieldInput label="Notes" value={form.notes || ''} onChange={v => set('notes', v)} placeholder="Additional context\u2026" textarea />
    </Modal>
  );
}

function PathNameEditor({ path, onSave }) {
  const [editing, setEditing] = useState(false);
  const [val, setVal] = useState(path.name);
  useEffect(() => { setVal(path.name); }, [path.name]);

  const commit = () => {
    setEditing(false);
    if (val.trim() && val !== path.name) onSave(val.trim());
  };

  if (editing) return (
    <input value={val} onChange={e => setVal(e.target.value)} onBlur={commit}
      onKeyDown={e => { if (e.key === 'Enter') commit(); if (e.key === 'Escape') setEditing(false); }}
      autoFocus style={{ background: PALETTE.bg0, border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '3px 8px', color: PALETTE.text, fontSize: 14, fontWeight: 700, fontFamily: FONTS.display, outline: 'none', width: 220 }} />
  );

  return (
    <button type="button" onClick={() => setEditing(true)} title="Click to rename"
      style={{ fontSize: 14, fontWeight: 700, color: PALETTE.text, fontFamily: FONTS.display, cursor: 'text', background: 'transparent', border: 'none', padding: 0, display: 'flex', alignItems: 'center', gap: 6 }}>
      {path.name}
      <Icon name="edit" size={11} color="#404550" />
    </button>
  );
}

function ConfidenceDots({ level, color }) {
  const filled = CONFIDENCE_CFG[level]?.dots || 2;
  return (
    <span style={{ display: 'inline-flex', gap: 2, alignItems: 'center' }}>
      {[1, 2, 3].map(i => (
        <span key={i} style={{
          display: 'inline-block', width: 5, height: 5, borderRadius: '50%',
          background: i <= filled ? color : PALETTE.border,
        }} />
      ))}
    </span>
  );
}

function StepCard({ step, pos, stepMap, accent, onEdit, onDelete, onAddChild, childrenCount, live }) {
  const [hov, setHov] = useState(false);
  const t = STEP_TYPES[step.node_type] || STEP_TYPES.action;
  const sc = STATUS_CFG[step.node_status] || STATUS_CFG.hypothetical;
  const cc = CONFIDENCE_CFG[step.confidence] || CONFIDENCE_CFG.medium;
  const isDead = live === false;

  return (
    <div
      style={{
        position: 'absolute',
        left: pos.x,
        top: pos.y,
        width: NODE_W,
        height: NODE_H,
        boxSizing: 'border-box',
        background: isDead ? '#0a0b0f' : '#0e1016',
        border: `1px solid ${isDead ? '#14161b' : live ? accent + '44' : PALETTE.border}`,
        borderLeft: `3px solid ${isDead ? '#14161b' : live ? accent : t.color + '55'}`,
        borderRadius: 6,
        padding: '6px 10px',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'center',
        gap: 2,
        cursor: 'default',
        transition: 'border-color .15s, box-shadow .15s, opacity .25s',
        boxShadow: isDead ? 'none' : live ? `0 0 0 1px ${accent}22, 0 0 8px ${accent}15` : hov ? `0 0 0 1px ${t.color}33, 0 2px 12px #00000055` : 'none',
        opacity: isDead ? 0.35 : 1,
      }}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
        <span style={{ display: 'inline-block', width: 6, height: 6, borderRadius: '50%', background: t.color, flexShrink: 0 }} />
        <span style={{ fontSize: 8, color: t.color, fontFamily: FONTS.mono, textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.04em' }}>
          {t.label}
        </span>
        <div style={{ flex: 1 }} />
        {childrenCount > 0 && (
          <span style={{ fontSize: 7, color: PALETTE.textFaint, fontFamily: FONTS.mono, marginRight: 2 }}>→{childrenCount}</span>
        )}
        <Badge label={step.node_status || 'hypothetical'} color={sc.color} />
      </div>

      <div style={{
        fontSize: 11, fontWeight: 600, color: PALETTE.text, fontFamily: FONTS.display,
        overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
      }}>
        {step.label || 'Unnamed step'}
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
        {(step.mitre_id || step.technique) && (
          <span style={{
            fontSize: 8, color: PALETTE.textMute, fontFamily: FONTS.mono,
            overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1,
          }}>
            {step.mitre_id ? `${step.mitre_id}` : ''}{step.mitre_id && step.technique ? ' \u00b7 ' : ''}{step.technique || ''}
          </span>
        )}
        {(!step.mitre_id && !step.technique) && <div style={{ flex: 1 }} />}
        <span style={{ fontSize: 7, color: PALETTE.textFaint, fontFamily: FONTS.mono }}>conf:</span>
        <ConfidenceDots level={step.confidence} color={cc.color} />
      </div>

      {hov && (
        <div style={{
          position: 'absolute', top: '100%', left: 0, right: 0,
          display: 'flex', gap: 3, padding: '3px 4px', zIndex: 10,
        }}>
          <button onClick={() => onEdit(step)}
            style={{
              flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 3,
              background: PALETTE.bg3, border: `1px solid ${accent}55`, borderRadius: 3,
              cursor: 'pointer', padding: '3px 0',
              fontSize: 9, fontWeight: 600, color: accent, fontFamily: FONTS.mono,
            }}>
            <Icon name="edit" size={9} color={accent} /> Edit
          </button>
          <button onClick={() => onDelete(step.id)}
            style={{
              flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 3,
              background: PALETTE.bg3, border: `1px solid ${PALETTE.danger}55`, borderRadius: 3,
              cursor: 'pointer', padding: '3px 0',
              fontSize: 9, fontWeight: 600, color: PALETTE.danger, fontFamily: FONTS.mono,
            }}>
            <Icon name="x" size={9} color={PALETTE.danger} /> Del
          </button>
        </div>
      )}

      {/* Branch/add-child: hidden when the step already has children
          (the chain continues visually), appears on hover to let the
          operator fork from any point. Same position as before. */}
      {!isDead && (childrenCount === 0 || hov) && (
        <button
          onClick={(e) => { e.stopPropagation(); onAddChild(step); }}
          title="Add child step"
          style={{
            position: 'absolute', right: -11, top: '50%', transform: 'translateY(-50%)',
            width: 20, height: 20, borderRadius: '50%',
            background: '#0e1016', border: `2px solid ${accent}`,
            cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center',
            padding: 0, zIndex: 10,
            transition: 'background .15s, transform .15s, box-shadow .15s, opacity .15s',
            boxShadow: `0 0 0 2px #0e1016`,
            opacity: hov ? 1 : childrenCount === 0 ? 0.7 : 0,
          }}
          onMouseEnter={e => { e.currentTarget.style.background = accent; e.currentTarget.style.transform = 'translateY(-50%) scale(1.15)'; e.currentTarget.style.boxShadow = `0 0 8px ${accent}66`; }}
          onMouseLeave={e => { e.currentTarget.style.background = '#0e1016'; e.currentTarget.style.transform = 'translateY(-50%) scale(1)'; e.currentTarget.style.boxShadow = `0 0 0 2px #0e1016`; }}
        >
          <Icon name="plus" size={10} color={accent} />
        </button>
      )}
    </div>
  );
}

export default function AttackPathView({
  attackPaths, attackSteps, selectedProject, accent, hosts,
  onCreatePath, onCreateStep, onUpdateStep, onDeleteStep,
  onUpdatePath, onDeletePath,
}) {
  const [activePath, setActivePath] = useState(null);
  const [modal, setModal] = useState(null);
  const [impactLocal, setImpactLocal] = useState(null);
  const [editorMode, setEditorMode] = useState('tree');

  useEffect(() => { _kbCache = null; }, []);
  useEffect(() => { setImpactLocal(null); }, [activePath?.id]);

  const paths = useMemo(() => attackPaths.filter(p => p.pid === selectedProject), [attackPaths, selectedProject]);
  const steps = useMemo(() => {
    // Last-line dedup by id: if any writer ever appends a duplicate (WS sync
    // racing a POST response), duplicate React keys here corrupt the tree DOM.
    const seen = new Set();
    return attackSteps
      .filter(s => activePath && s.path_id === activePath.id && !seen.has(s.id) && seen.add(s.id))
      .sort((a, b) => (a.step_order || 0) - (b.step_order || 0));
  }, [attackSteps, activePath]);

  useEffect(() => {
    if (!paths.length) { setActivePath(null); return; }
    if (!activePath || !paths.some(p => p.id === activePath.id)) setActivePath(paths[0]);
  }, [selectedProject, paths]);

  const stepMap = useMemo(() => {
    const m = {};
    steps.forEach(s => { m[s.id] = s; });
    return m;
  }, [steps]);

  const positions = useMemo(() => layoutTree(steps), [steps]);

  const childrenMap = useMemo(() => {
    const m = {};
    steps.forEach(s => {
      if (s.parent_step_id) {
        m[s.parent_step_id] = m[s.parent_step_id] || [];
        m[s.parent_step_id].push(s);
      }
    });
    return m;
  }, [steps]);

  const liveness = useMemo(() => computeLiveness(steps), [steps]);

  const bounds = useMemo(() => {
    const vals = Object.values(positions);
    if (vals.length === 0) return { w: 600, h: 400, ox: 40, oy: 200 };
    const minX = Math.min(...vals.map(p => p.x));
    const maxX = Math.max(...vals.map(p => p.x + NODE_W));
    const minY = Math.min(...vals.map(p => p.y));
    const maxY = Math.max(...vals.map(p => p.y + NODE_H));
    return { w: maxX - minX + 120, h: maxY - minY + 120, ox: -minX + 50, oy: -minY + 50 };
  }, [positions]);

  const edges = useMemo(() => {
    const result = [];
    steps.forEach(s => {
      if (s.parent_step_id && positions[s.id] && positions[s.parent_step_id]) {
        result.push({
          child: s,
          parent: stepMap[s.parent_step_id],
          childPos: positions[s.id],
          parentPos: positions[s.parent_step_id],
        });
      }
    });
    return result;
  }, [steps, positions, stepMap]);

  const handleCreatePath = async () => {
    try {
      const ap = await onCreatePath({ pid: selectedProject, name: 'Attack Path ' + (paths.length + 1) });
      setActivePath(ap);
    } catch (e) { toastError(e.message || 'Failed to create path'); }
  };

  const handleDeletePath = async (id) => {
    if (!await uiConfirm('Delete attack path and all steps?')) return;
    try {
      await onDeletePath(id);
      setActivePath(paths.find(p => p.id !== id) || null);
    } catch (e) { toastError(e.message || 'Failed to delete path'); }
  };

  const scrollRef = useRef(null);

  const handleSaveStep = async (form) => {
    if (!activePath) return;
    try {
      if (modal.mode === 'new') {
        const maxOrder = steps.length ? Math.max(...steps.map(s => s.step_order || 0)) : -1;
        const created = await onCreateStep({
          ...form,
          path_id: activePath.id,
          pid: selectedProject,
          step_order: maxOrder + 1,
          parent_step_id: modal.parentId || null,
        });
        if (scrollRef.current && created) {
          setTimeout(() => {
            requestAnimationFrame(() => {
              const newPositions = layoutTree([...attackSteps, created].filter(s => s.path_id === activePath.id));
              const p = newPositions[created.id];
              if (p) {
                const container = scrollRef.current;
                const cx = p.x + bounds.ox + NODE_W / 2;
                const cy = p.y + bounds.oy + NODE_H / 2;
                container.scrollTo({ left: cx - container.clientWidth / 2, top: cy - container.clientHeight / 2, behavior: 'smooth' });
              }
            });
          }, 100);
        }
      } else {
        await onUpdateStep(modal.step.id, form);
      }
      setModal(null);
    } catch (e) { toastError(e.message || 'Failed to save step'); }
  };

  const handleDeleteStep = async (id) => {
    if (!await uiConfirm('Delete step?')) return;
    try { await onDeleteStep(id); } catch (e) { toastError(e.message || 'Failed to delete step'); }
  };

  const handleEdit = useCallback((step) => {
    setModal({ mode: 'edit', step, parentId: step.parent_step_id, parentLabel: stepMap[step.parent_step_id]?.label });
  }, [stepMap]);

  const handleAddChild = useCallback((step) => {
    setModal({ mode: 'new', step: null, parentId: step.id, parentLabel: step.label });
  }, []);

  const riskColor = (score) => {
    if (score >= 70) return '#cc2233';
    if (score >= 40) return '#f09a3a';
    return '#39d353';
  };

  const projectHosts = useMemo(() => (hosts || []).filter(h => h.pid === selectedProject), [hosts, selectedProject]);

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', background: PALETTE.bg0 }}>

      <div style={{ padding: '14px 20px', borderBottom: `1px solid ${PALETTE.borderSoft}`, display: 'flex', alignItems: 'center', gap: 12, flexShrink: 0 }}>
        <Icon name="attackpath" size={16} color={accent} />
        <div style={{ fontSize: 11, color: PALETTE.textGhost, fontFamily: FONTS.display, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Attack Path</div>
        <div style={{ flex: 1 }} />
        {activePath && (
          <div style={{ display: 'flex', gap: 0, background: PALETTE.bg2, borderRadius: 4, overflow: 'hidden' }}>
            {['tree', 'editor'].map(mode => (
              <button key={mode} onClick={() => setEditorMode(mode)}
                style={{
                  padding: '4px 10px', border: 'none', cursor: 'pointer',
                  fontSize: TYPE.label, fontFamily: FONTS.mono, fontWeight: 600,
                  background: editorMode === mode ? (accent || '#5b8af5') + '22' : 'transparent',
                  color: editorMode === mode ? (accent || '#5b8af5') : PALETTE.textFaint,
                  textTransform: 'capitalize',
                }}>
                {mode === 'tree' ? 'Step Tree' : 'Node Editor'}
              </button>
            ))}
          </div>
        )}
        <Btn onClick={handleCreatePath} variant="accentGhost" accent={accent} icon="plus">New path</Btn>
      </div>

      {paths.length > 0 && (
        <div style={{ padding: '0 20px', borderBottom: `1px solid ${PALETTE.borderSoft}`, display: 'flex', alignItems: 'center', gap: 0, flexShrink: 0, overflowX: 'auto' }}>
          {paths.map(p => {
            const active = activePath?.id === p.id;
            return (
              <div key={p.id} style={{ display: 'flex', alignItems: 'center' }}>
                <button onClick={() => setActivePath(p)}
                  style={{ padding: '10px 14px', border: 'none', borderBottom: active ? `2px solid ${accent}` : '2px solid transparent', background: 'transparent', cursor: 'pointer', color: active ? accent : PALETTE.textFaint, fontSize: 12, fontFamily: FONTS.display, fontWeight: active ? 600 : 400, whiteSpace: 'nowrap', transition: 'all .15s' }}>
                  {p.name}
                </button>
                {active && (
                  <button onClick={() => handleDeletePath(p.id)}
                    style={{ background: 'none', border: 'none', cursor: 'pointer', padding: '4px', display: 'flex', opacity: 0.4 }}
                    onMouseEnter={e => e.currentTarget.style.opacity = 1}
                    onMouseLeave={e => e.currentTarget.style.opacity = 0.4}>
                    <Icon name="close" size={10} color="#cc2233" />
                  </button>
                )}
              </div>
            );
          })}
        </div>
      )}

      <div style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
        {activePath ? (
          editorMode === 'editor' ? (
            <AttackPathNodeEditor pathId={activePath.id} accent={accent} />
          ) : (
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>

            <div style={{ padding: '10px 24px', display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0, flexWrap: 'wrap' }}>
              <PathNameEditor path={activePath} onSave={name => onUpdatePath(activePath.id, { name })} />

              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{ fontSize: 9, color: PALETTE.textFaint, fontFamily: FONTS.mono }}>Impact:</span>
                <Slider min={0} max={100} accent={accent} width={80}
                  value={impactLocal != null ? impactLocal : (activePath.impact_score || 0)}
                  onChange={v => setImpactLocal(Math.round(v))}
                  onCommit={() => {
                    if (impactLocal != null) {
                      onUpdatePath(activePath.id, { impact_score: impactLocal });
                    }
                  }} />
                <span style={{ fontSize: 10, color: PALETTE.textMute, fontFamily: FONTS.mono, width: 24 }}>{impactLocal != null ? impactLocal : (activePath.impact_score || 0)}</span>
              </div>

              {activePath.risk_score != null && (
                <span style={{
                  fontSize: 10, fontFamily: FONTS.mono, fontWeight: 700,
                  padding: '2px 8px', borderRadius: 4,
                  background: riskColor(activePath.risk_score) + '22',
                  color: riskColor(activePath.risk_score),
                  border: `1px solid ${riskColor(activePath.risk_score)}44`,
                }}>
                  Risk: {activePath.risk_score}
                </span>
              )}

              <span style={{ fontSize: 10, color: PALETTE.textFaint, fontFamily: FONTS.mono }}>
                {steps.length} step{steps.length === 1 ? '' : 's'}
              </span>

              <div style={{ flex: 1 }} />
              <Btn onClick={() => setModal({ mode: 'new', step: null, parentId: null, parentLabel: null })} variant="accentGhost" accent={accent} icon="plus">Root step</Btn>
            </div>

            <div ref={scrollRef} style={{ flex: 1, overflow: 'auto', position: 'relative' }}>
              {steps.length === 0 ? (
                <EmptyState
                  icon="attackpath"
                  title="No steps yet"
                  hint="Add the first step to start building your attack tree"
                  action={<Btn onClick={() => setModal({ mode: 'new', step: null, parentId: null, parentLabel: null })} variant="solid" accent={accent}>Add root step</Btn>}
                />
              ) : (
                <div style={{ position: 'relative', width: bounds.w, height: bounds.h, minWidth: '100%', minHeight: '100%' }}>

                  <svg width={bounds.w} height={bounds.h} style={{ position: 'absolute', top: 0, left: 0, pointerEvents: 'none' }}>
                    <g transform={`translate(${bounds.ox},${bounds.oy})`}>
                      {edges.map(({ child, parent, childPos, parentPos }) => {
                        const x1 = parentPos.x + NODE_W;
                        const y1 = parentPos.y + NODE_H / 2;
                        const x2 = childPos.x;
                        const y2 = childPos.y + NODE_H / 2;
                        const midX = (x1 + x2) / 2;
                        const childLive = liveness[child.id];

                        return (
                          <g key={`${parent?.id}-${child.id}`}>
                            <path
                              d={`M${x1},${y1} C${midX},${y1} ${midX},${y2} ${x2},${y2}`}
                              stroke={childLive === false ? '#1a1c22' : accent + '55'}
                              strokeWidth={childLive === false ? '1' : '1.5'}
                              strokeDasharray={childLive === false ? '4 3' : 'none'}
                              fill="none"
                              style={{ transition: 'stroke .25s, opacity .25s' }}
                              opacity={childLive === false ? 0.3 : 1}
                            />
                            {child.branch_name && (
                              <text
                                x={midX}
                                y={(y1 + y2) / 2 - 5}
                                textAnchor="middle"
                                fill={accent}
                                fontSize={8}
                                fontFamily={FONTS.mono}
                              >
                                {child.branch_name}
                              </text>
                            )}
                          </g>
                        );
                      })}
                    </g>
                  </svg>

                  <div style={{ position: 'absolute', top: bounds.oy, left: bounds.ox }}>
                    {steps.filter(s => positions[s.id]).map(step => {
                      const pos = positions[step.id];
                      return (
                        <div key={step.id} style={{ position: 'absolute', left: pos.x, top: pos.y }}>
                          <StepCard
                            step={step}
                            pos={{ x: 0, y: 0 }}
                            stepMap={stepMap}
                            accent={accent}
                            onEdit={handleEdit}
                            onDelete={handleDeleteStep}
                            onAddChild={handleAddChild}
                            childrenCount={(childrenMap[step.id] || []).length}
                            live={liveness[step.id]}
                          />
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>

            <div style={{ padding: '8px 24px', borderTop: `1px solid ${PALETTE.borderSoft}`, display: 'flex', alignItems: 'center', gap: 16, flexShrink: 0, flexWrap: 'wrap' }}>
              {Object.entries(STEP_TYPES).map(([k, t]) => (
                <div key={k} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                  <div style={{ width: 7, height: 7, borderRadius: 2, background: t.color }} />
                  <span style={{ fontSize: 9, color: PALETTE.textGhost, fontFamily: FONTS.mono, textTransform: 'uppercase' }}>{t.label}</span>
                </div>
              ))}
              <div style={{ flex: 1 }} />
              {Object.entries(STATUS_CFG).map(([k, sc]) => (
                <div key={k} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                  <div style={{ width: 7, height: 7, borderRadius: 2, background: sc.color }} />
                  <span style={{ fontSize: 8, color: PALETTE.textGhost, fontFamily: FONTS.mono }}>{k}</span>
                </div>
              ))}
            </div>
          </div>
          )
        ) : (
          <EmptyState
            icon="attackpath"
            title="No attack paths"
            hint="Create a new path and add steps \u2014 from initial access to DA"
            action={<Btn onClick={handleCreatePath} variant="solid" accent={accent} icon="plus">Create attack path</Btn>}
          />
        )}
      </div>

      {modal && (
        <StepModal
          step={modal.step}
          isNew={modal.mode === 'new'}
          parentId={modal.parentId}
          parentLabel={modal.parentLabel}
          onSave={handleSaveStep}
          onClose={() => setModal(null)}
          accent={accent}
          hosts={projectHosts}
        />
      )}
    </div>
  );
}

AttackPathView.propTypes = {
  attackPaths: PropTypes.array,
  attackSteps: PropTypes.array,
  selectedProject: PropTypes.string,
  accent: PropTypes.string,
  hosts: PropTypes.array,
  onCreatePath: PropTypes.func,
  onCreateStep: PropTypes.func,
  onUpdateStep: PropTypes.func,
  onDeleteStep: PropTypes.func,
  onUpdatePath: PropTypes.func,
  onDeletePath: PropTypes.func,
};

TechniqueInput.propTypes = {
  value: PropTypes.string,
  mitreId: PropTypes.string,
  onChange: PropTypes.func,
  accent: PropTypes.string,
};

StepModal.propTypes = {
  step: PropTypes.object,
  isNew: PropTypes.bool,
  parentId: PropTypes.string,
  parentLabel: PropTypes.string,
  onSave: PropTypes.func,
  onClose: PropTypes.func,
  accent: PropTypes.string,
  hosts: PropTypes.array,
};

PathNameEditor.propTypes = {
  path: PropTypes.object,
  onSave: PropTypes.func,
};

StepCard.propTypes = {
  step: PropTypes.object,
  pos: PropTypes.object,
  stepMap: PropTypes.object,
  accent: PropTypes.string,
  onEdit: PropTypes.func,
  onDelete: PropTypes.func,
  onAddChild: PropTypes.func,
  childrenCount: PropTypes.number,
};

ConfidenceDots.propTypes = {
  level: PropTypes.string,
  color: PropTypes.string,
};
