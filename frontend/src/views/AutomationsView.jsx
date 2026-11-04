import { useState, useEffect, useCallback, useRef } from 'react';
import PropTypes from 'prop-types';
import { api } from '../api.js';
import Icon from '../components/Icon.jsx';
import { PALETTE, FONTS, Select } from '../components/UI.jsx';
import { uiConfirm, uiAlert } from '../components/Confirm.jsx';

const EMPTY_DEF = {
  triggers: [{ type: 'manual' }],
  conditions: [],
  steps: [{ id: 'step1', type: 'action', action: 'list_hosts', params: {}, on_error: 'stop' }],
  settings: { timeout: 300, max_concurrent: 1, on_step_error: 'stop' },
};

const STATUS_COLORS = {
  success: PALETTE.ok, failed: PALETTE.danger, running: '#5b8af5',
  pending: PALETTE.warn, cancelled: PALETTE.textFaint, skipped: '#808590',
  dry_run: '#c07af0',
};

const STEP_TYPE_ICON = { action: '\u26A1', delay: '\u23F1', if: '\u2194', loop: '\u21BB', call: '\u29C9' };
const STEP_TYPES = ['action', 'delay', 'if', 'loop', 'call'];
const ON_ERROR_OPTS = ['stop', 'continue'];
const TRIGGER_TYPES = ['manual', 'event', 'schedule', 'cascade'];
const OPERATORS = ['eq', 'ne', 'gt', 'lt', 'gte', 'lte', 'contains', 'not_contains', 'in', 'not_in', 'starts_with', 'ends_with', 'matches', 'is_empty', 'is_not_empty', 'is_null', 'is_not_null'];
const GROUP_OPS = ['AND', 'OR', 'NOT'];

function genId() { return 's' + Math.random().toString(36).slice(2, 8); }

// ── AutoCard ──────────────────────────────────────────────────────────

function AutoCard({ auto, accent, selected, onSelect, onToggle, onRun, onDelete }) {
  const status = auto.last_run_status || 'none';
  const statusColor = STATUS_COLORS[status] || '#404550';
  return (
    <div
      onClick={() => onSelect(auto.id)}
      style={{
        padding: '12px 14px', cursor: 'pointer', borderRadius: 6,
        background: selected ? '#ffffff08' : 'transparent',
        borderLeft: selected ? `2px solid ${accent}` : '2px solid transparent',
        display: 'flex', alignItems: 'center', gap: 10,
      }}
    >
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 12, color: '#e0e4ec', fontFamily: FONTS.mono, fontWeight: 600 }}>{auto.name}</div>
        <div style={{ fontSize: 10, color: '#505560', fontFamily: FONTS.mono, marginTop: 2 }}>
          {(auto.definition?.triggers || []).map(t => t.type).join(', ') || 'manual'}
          {' \u00B7 '}runs: {auto.run_count || 0}
        </div>
      </div>
      <div style={{ width: 8, height: 8, borderRadius: '50%', background: statusColor, flexShrink: 0 }} title={status} />
      <button
        onClick={(e) => { e.stopPropagation(); onToggle(auto.id, auto.enabled); }}
        style={{
          background: auto.enabled ? accent + '22' : 'transparent',
          border: `1px solid ${auto.enabled ? accent + '66' : PALETTE.border}`,
          borderRadius: 4, padding: '3px 10px', cursor: 'pointer',
          color: auto.enabled ? accent : PALETTE.textFaint, fontSize: 10, fontFamily: FONTS.mono, fontWeight: 700,
        }}
      >
        {auto.enabled ? 'ON' : 'OFF'}
      </button>
      <button onClick={(e) => { e.stopPropagation(); onRun(auto.id); }}
        style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '3px 8px', cursor: 'pointer', color: PALETTE.ok, fontSize: 10, fontFamily: FONTS.mono }}>
        Run
      </button>
      <button onClick={(e) => { e.stopPropagation(); onDelete(auto.id); }}
        title="Delete automation"
        style={{ background: 'transparent', border: `1px solid ${PALETTE.danger}44`, borderRadius: 4, padding: '3px 8px', cursor: 'pointer', color: PALETTE.danger, fontSize: 10, fontFamily: FONTS.mono, display: 'flex', alignItems: 'center', gap: 3 }}>
        <Icon name="trash" size={9} color={PALETTE.danger} /> Del
      </button>
    </div>
  );
}
AutoCard.propTypes = { auto: PropTypes.object, accent: PropTypes.string, selected: PropTypes.bool, onSelect: PropTypes.func, onToggle: PropTypes.func, onRun: PropTypes.func, onDelete: PropTypes.func };

// ── StepLogEntry ──────────────────────────────────────────────────────

function StepLogEntry({ step }) {
  const [expanded, setExpanded] = useState(false);
  const statusColor = step.status === 'success' ? '#39d353' : step.status === 'failed' ? '#cc2233' : PALETTE.warn;
  const hasDetail = step.error || step.result != null;
  return (
    <div style={{ background: '#0a0c10', border: `1px solid ${statusColor}33`, borderRadius: 5, marginBottom: 4, fontSize: 11, fontFamily: FONTS.mono }}>
      <button
        onClick={() => hasDetail && setExpanded(v => !v)}
        style={{ padding: '5px 10px', cursor: hasDetail ? 'pointer' : 'default', display: 'flex', alignItems: 'center', gap: 8, width: '100%', textAlign: 'left', background: 'transparent', border: 'none', color: '#808590' }}
      >
        <span style={{ color: statusColor }}>{step.status === 'success' ? '\u2713' : step.status === 'failed' ? '\u2715' : '\u25CB'}</span>
        <span style={{ color: '#c07af0', fontWeight: 600 }}>{step.step_id}</span>
        <span style={{ color: '#505560' }}>{step.type}</span>
        {step.result?.dry_run && <span style={{ color: '#c07af0', fontSize: 9 }}>DRY RUN</span>}
        <span style={{ marginLeft: 'auto', fontSize: 10, color: PALETTE.textGhost }}>{step.duration}s</span>
      </button>
      {expanded && step.error && (
        <div style={{ borderTop: '1px solid #1e2029', padding: '8px 10px', color: PALETTE.danger }}>{step.error}</div>
      )}
      {expanded && step.result != null && (
        <div style={{ borderTop: '1px solid #1e2029', padding: '8px 10px' }}>
          <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all', color: '#808590', fontSize: 10, lineHeight: 1.5 }}>
            {typeof step.result === 'string' ? step.result : JSON.stringify(step.result, null, 2)}
          </pre>
        </div>
      )}
      {expanded && step.result?.steps && (
        <div style={{ borderTop: '1px solid #1e2029', padding: '6px 10px 8px 20px' }}>
          {(step.result.steps || []).map((sub, i) => <StepLogEntry key={i} step={sub} />)}
        </div>
      )}
    </div>
  );
}
StepLogEntry.propTypes = { step: PropTypes.object };

// ── Visual Editor: Trigger Editor ─────────────────────────────────────

function TriggerCard({ trig, idx, onChange, onRemove, tools, accent }) {
  const inp = { background: '#0a0c10', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '5px 8px', color: PALETTE.textDim, fontSize: 11, outline: 'none', fontFamily: FONTS.mono, width: '100%', boxSizing: 'border-box' };
  const lbl = { fontSize: 9, color: '#505560', marginBottom: 2, display: 'block' };
  return (
    <div style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 6, padding: '10px 12px', marginBottom: 6 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
        <span style={{ fontSize: 16 }}>{trig.type === 'event' ? '\u26A1' : trig.type === 'schedule' ? '\u23F0' : trig.type === 'cascade' ? '\u29C9' : '\u270E'}</span>
        <Select value={trig.type} onChange={v => onChange(idx, { ...trig, type: v })} style={{ width: 'auto', flex: 0 }}
          options={TRIGGER_TYPES} />
        <button onClick={() => onRemove(idx)} style={{ marginLeft: 'auto', background: 'transparent', border: 'none', cursor: 'pointer', color: PALETTE.textGhost, fontSize: 12 }}>{'\u2715'}</button>
      </div>
      {trig.type === 'event' && (
        <>
          <label style={lbl}>Event name</label>
          <input value={trig.event || ''} onChange={e => onChange(idx, { ...trig, event: e.target.value })} placeholder="finding.create" style={inp} />
          <div style={{ display: 'flex', gap: 8, marginTop: 6 }}>
            <div style={{ flex: 1 }}>
              <label style={lbl}>Debounce (ms)</label>
              <input type="number" value={trig.debounce_ms || 0} onChange={e => onChange(idx, { ...trig, debounce_ms: +e.target.value })} style={inp} />
            </div>
            <div style={{ flex: 1 }}>
              <label style={lbl}>Rate limit / hour</label>
              <input type="number" value={trig.rate_limit_per_hour || 0} onChange={e => onChange(idx, { ...trig, rate_limit_per_hour: +e.target.value })} style={inp} />
            </div>
          </div>
        </>
      )}
      {trig.type === 'schedule' && (
        <>
          <label style={lbl}>Cron expression</label>
          <input value={trig.cron || ''} onChange={e => onChange(idx, { ...trig, cron: e.target.value })} placeholder="0 9 * * *" style={inp} />
          <div style={{ fontSize: 9, color: PALETTE.textGhost, marginTop: 3 }}>Format: minute hour day month weekday</div>
        </>
      )}
      {trig.type === 'cascade' && (
        <>
          <label style={lbl}>Triggered by playbook</label>
          <input value={trig.playbook_id || ''} onChange={e => onChange(idx, { ...trig, playbook_id: e.target.value })} placeholder="pba..." style={inp} />
        </>
      )}
    </div>
  );
}
TriggerCard.propTypes = { trig: PropTypes.object, idx: PropTypes.number, onChange: PropTypes.func, onRemove: PropTypes.func, tools: PropTypes.array, accent: PropTypes.string };

// ── Visual Editor: Step Card ──────────────────────────────────────────

function StepCard({ step, idx, onChange, onRemove, onDragStart, onDragOver, onDrop, isDragging, tools, automations, accent }) {
  const [expanded, setExpanded] = useState(false);
  const inp = { background: '#0a0c10', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '5px 8px', color: PALETTE.textDim, fontSize: 11, outline: 'none', fontFamily: FONTS.mono, width: '100%', boxSizing: 'border-box' };
  const lbl = { fontSize: 9, color: '#505560', marginBottom: 2, display: 'block' };

  const update = (patch) => onChange(idx, { ...step, ...patch });
  const toolDef = tools.find(t => t.name === step.action);

  return (
    <div
      draggable
      onDragStart={(e) => onDragStart(e, idx)}
      onDragOver={(e) => onDragOver(e, idx)}
      onDrop={(e) => onDrop(e, idx)}
      style={{
        background: '#0a0c10', border: `1px solid ${isDragging ? accent + '66' : '#1e2029'}`, borderRadius: 6,
        marginBottom: 6, opacity: isDragging ? 0.5 : 1, transition: 'border-color 0.15s',
      }}
    >
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 12px', cursor: 'grab' }} onClick={() => setExpanded(v => !v)}>
        <span style={{ color: PALETTE.textGhost, fontSize: 10 }}>{'\u2261'}</span>
        <span style={{ fontSize: 14 }}>{STEP_TYPE_ICON[step.type] || '\u25CB'}</span>
        <span style={{ fontSize: 11, color: '#c07af0', fontWeight: 600, fontFamily: FONTS.mono, minWidth: 60 }}>{step.id}</span>
        <span style={{ fontSize: 10, padding: '1px 6px', borderRadius: 3, background: accent + '15', color: accent }}>{step.type}</span>
        {step.type === 'action' && <span style={{ fontSize: 10, color: '#808590' }}>{step.action}</span>}
        {step.type === 'delay' && <span style={{ fontSize: 10, color: '#808590' }}>{step.duration}s</span>}
        {step.type === 'call' && <span style={{ fontSize: 10, color: '#808590' }}>{'\u2192'} {step.playbook_id}</span>}
        <span style={{ marginLeft: 'auto', fontSize: 10, color: PALETTE.textGhost }}>{expanded ? '\u25B2' : '\u25BC'}</span>
        <button onClick={(e) => { e.stopPropagation(); onRemove(idx); }} style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: PALETTE.textGhost, fontSize: 11 }}>{'\u2715'}</button>
      </div>

      {/* Expanded editor */}
      {expanded && (
        <div style={{ borderTop: '1px solid #1e2029', padding: '10px 12px' }}>
          <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
            <div style={{ flex: 1 }}>
              <label style={lbl}>Step ID</label>
              <input value={step.id} onChange={e => update({ id: e.target.value })} style={inp} />
            </div>
            <div style={{ width: 100 }}>
              <label style={lbl}>Type</label>
              <Select value={step.type} onChange={v => update({ type: v })} options={STEP_TYPES} />
            </div>
          </div>

          {step.type === 'action' && (
            <>
              <div style={{ display: 'flex', gap: 8, marginBottom: 8 }}>
                <div style={{ flex: 1 }}>
                  <label style={lbl}>Action (tool)</label>
                  <Select value={step.action} onChange={v => update({ action: v, params: {} })}
                    placeholder="-- select --"
                    options={tools.map(t => ({ value: t.name, label: `${t.name} (${t.risk})` }))} />
                </div>
                <div style={{ width: 100 }}>
                  <label style={lbl}>On error</label>
                  <Select value={step.on_error || 'stop'} onChange={v => update({ on_error: v })} options={ON_ERROR_OPTS} />
                </div>
              </div>
              {toolDef && <div style={{ fontSize: 9, color: '#505560', marginBottom: 6 }}>{toolDef.description}</div>}
              {toolDef && Object.keys(toolDef.params || {}).length > 0 && (
                <div>
                  <label style={lbl}>Parameters</label>
                  {Object.entries(toolDef.params).map(([pk, pv]) => (
                    <div key={pk} style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                      <span style={{ fontSize: 10, color: PALETTE.textFaint, minWidth: 100, fontFamily: FONTS.mono }}>{pk}{(toolDef.required || []).includes(pk) ? ' *' : ''}</span>
                      <span style={{ fontSize: 9, color: PALETTE.textGhost }}>{pv.type || 'any'}</span>
                      <input
                        value={step.params?.[pk] != null ? String(step.params[pk]) : ''}
                        onChange={e => update({ params: { ...step.params, [pk]: e.target.value } })}
                        placeholder={pv.description || ''}
                        style={inp}
                      />
                    </div>
                  ))}
                </div>
              )}
              <div style={{ display: 'flex', gap: 8, marginTop: 6 }}>
                <div>
                  <label style={lbl}>Retry count</label>
                  <input type="number" value={step.retry_count || 0} onChange={e => update({ retry_count: +e.target.value })} style={{ ...inp, width: 80 }} />
                </div>
                <div>
                  <label style={lbl}>Retry delay (s)</label>
                  <input type="number" step="0.5" value={step.retry_delay || 1} onChange={e => update({ retry_delay: +e.target.value })} style={{ ...inp, width: 80 }} />
                </div>
              </div>
            </>
          )}

          {step.type === 'delay' && (
            <div>
              <label style={lbl}>Duration (seconds)</label>
              <input type="number" step="0.5" value={step.duration || 0} onChange={e => update({ duration: +e.target.value })} style={inp} />
            </div>
          )}

          {step.type === 'if' && (
            <div>
              <label style={lbl}>Condition (JSON)</label>
              <textarea
                value={step.condition ? JSON.stringify(step.condition, null, 2) : ''}
                onChange={e => { try { update({ condition: JSON.parse(e.target.value) }); } catch { /* incomplete JSON while typing — keep the last valid condition */ } }}
                placeholder='{"op": "AND", "rules": [...]}'
                style={{ ...inp, minHeight: 80, resize: 'vertical', lineHeight: 1.4 }}
                spellCheck={false}
              />
              <div style={{ fontSize: 9, color: PALETTE.textGhost, marginTop: 4 }}>Then/else steps are nested — edit in JSON mode for complex branches</div>
            </div>
          )}

          {step.type === 'loop' && (
            <>
              <div style={{ display: 'flex', gap: 8, marginBottom: 6 }}>
                <div style={{ flex: 1 }}>
                  <label style={lbl}>Loop over (template)</label>
                  <input value={step.loop_over || ''} onChange={e => update({ loop_over: e.target.value })} placeholder="{{step1.result.items}}" style={inp} />
                </div>
                <div style={{ width: 80 }}>
                  <label style={lbl}>Var name</label>
                  <input value={step.loop_var || 'item'} onChange={e => update({ loop_var: e.target.value })} style={inp} />
                </div>
              </div>
            </>
          )}

          {step.type === 'call' && (
            <div>
              <label style={lbl}>Target playbook</label>
              <Select value={step.playbook_id} onChange={v => update({ playbook_id: v })}
                placeholder="-- select --"
                options={automations.map(a => ({ value: a.id, label: a.name }))} />
            </div>
          )}
        </div>
      )}
    </div>
  );
}
StepCard.propTypes = { step: PropTypes.object, idx: PropTypes.number, onChange: PropTypes.func, onRemove: PropTypes.func, onDragStart: PropTypes.func, onDragOver: PropTypes.func, onDrop: PropTypes.func, isDragging: PropTypes.bool, tools: PropTypes.array, automations: PropTypes.array, accent: PropTypes.string };

// ── Visual Editor: Condition Editor ───────────────────────────────────

function ConditionRuleRow({ rule, onChange, onRemove, accent }) {
  const inp = { background: '#080a0e', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '5px 8px', color: PALETTE.textDim, fontSize: 11, outline: 'none', fontFamily: FONTS.mono, boxSizing: 'border-box' };
  const isEmptyOp = rule.operator === 'is_empty' || rule.operator === 'is_not_empty' || rule.operator === 'is_null' || rule.operator === 'is_not_null';
  return (
    <div style={{ display: 'flex', gap: 6, alignItems: 'center', marginBottom: 4, paddingLeft: 16, borderLeft: `2px solid ${accent}33` }}>
      <input value={rule.field || ''} onChange={e => onChange({ ...rule, field: e.target.value })} placeholder="{{event.data.x}}" style={{ ...inp, flex: 1 }} />
      <Select value={rule.operator} onChange={v => onChange({ ...rule, operator: v })} style={{ width: 120 }} options={OPERATORS} />
      {!isEmptyOp && (
        <input value={typeof rule.value === 'object' ? JSON.stringify(rule.value) : (rule.value ?? '')} onChange={e => {
          let v = e.target.value;
          if (v.startsWith('[') || v.startsWith('{')) { try { v = JSON.parse(v); } catch { /* not JSON after all — keep the raw string */ } }
          onChange({ ...rule, value: v });
        }} placeholder="value" style={{ ...inp, flex: 1 }} />
      )}
      <button onClick={onRemove} style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: PALETTE.textGhost, fontSize: 11, padding: '2px 4px' }}>{'\u2715'}</button>
    </div>
  );
}
ConditionRuleRow.propTypes = { rule: PropTypes.object, onChange: PropTypes.func, onRemove: PropTypes.func, accent: PropTypes.string };

function ConditionGroupEditor({ group, onChange, onRemove, depth, accent }) {
  const rules = group.rules || [];
  const updateRule = (i, val) => onChange({ ...group, rules: rules.map((r, j) => j === i ? val : r) });
  const removeRule = (i) => onChange({ ...group, rules: rules.filter((_, j) => j !== i) });
  const addRule = () => onChange({ ...group, rules: [...rules, { field: '', operator: 'eq', value: '' }] });
  const updateGroupOp = (i, val) => {
    const updated = rules.map((r, j) => j === i ? val : r);
    onChange({ ...group, rules: updated });
  };
  const removeGroup = (i) => onChange({ ...group, rules: rules.filter((_, j) => j !== i) });
  const addGroup = () => onChange({ ...group, rules: [...rules, { op: 'AND', rules: [] }] });

  const bg = depth === 0 ? '#0a0c10' : '#080a0e';
  const borderColor = depth === 0 ? '#1e2029' : accent + '22';

  return (
    <div style={{ background: bg, border: `1px solid ${borderColor}`, borderRadius: 6, padding: '10px 12px', marginBottom: 6 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
        <Select value={group.op} onChange={v => onChange({ ...group, op: v })} style={{ color: accent, fontWeight: 700, width: 70 }} options={GROUP_OPS} />
        <span style={{ fontSize: 10, color: '#505560' }}>{rules.length} {rules.length === 1 ? 'rule' : 'rules'}</span>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 4 }}>
          <button onClick={addRule} style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 3, padding: '3px 8px', cursor: 'pointer', color: accent, fontSize: 9 }}>+ Rule</button>
          <button onClick={addGroup} style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 3, padding: '3px 8px', cursor: 'pointer', color: '#808590', fontSize: 9 }}>+ Group</button>
          {onRemove && <button onClick={onRemove} style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: PALETTE.textGhost, fontSize: 11 }}>{'\u2715'}</button>}
        </div>
      </div>
      {rules.length === 0 && (
        <div style={{ fontSize: 10, color: PALETTE.textGhost, paddingLeft: 16, padding: '6px 0 6px 16px' }}>No rules — group always evaluates to true</div>
      )}
      {rules.map((r, i) => {
        if (r.rules) {
          return <ConditionGroupEditor key={i} group={r} depth={depth + 1} accent={accent}
            onChange={(val) => updateGroupOp(i, val)}
            onRemove={() => removeGroup(i)}
          />;
        }
        return <ConditionRuleRow key={i} rule={r} accent={accent}
          onChange={(val) => updateRule(i, val)}
          onRemove={() => removeRule(i)}
        />;
      })}
    </div>
  );
}
ConditionGroupEditor.propTypes = { group: PropTypes.object, onChange: PropTypes.func, onRemove: PropTypes.func, depth: PropTypes.number, accent: PropTypes.string };

// ── Visual Editor ─────────────────────────────────────────────────────

function VisualEditor({ definition, onChange, tools, automations, accent }) {
  const [dragIdx, setDragIdx] = useState(null);
  const [overIdx, setOverIdx] = useState(null);
  const def = definition || EMPTY_DEF;

  const updateTriggers = (triggers) => onChange({ ...def, triggers });
  const updateConditions = (conditions) => onChange({ ...def, conditions });
  const updateSteps = (steps) => onChange({ ...def, steps });
  const updateSettings = (settings) => onChange({ ...def, settings });

  const handleDragStart = (e, idx) => { setDragIdx(idx); e.dataTransfer.effectAllowed = 'move'; };
  const handleDragOver = (e, idx) => { e.preventDefault(); setOverIdx(idx); };
  const handleDrop = (e, idx) => {
    e.preventDefault();
    if (dragIdx === null || dragIdx === idx) return;
    const steps = [...def.steps];
    const [moved] = steps.splice(dragIdx, 1);
    steps.splice(idx, 0, moved);
    updateSteps(steps);
    setDragIdx(null);
    setOverIdx(null);
  };

  const addStep = (type) => {
    const base = { id: genId(), type };
    if (type === 'action') { base.action = ''; base.params = {}; base.on_error = 'stop'; }
    if (type === 'delay') { base.duration = 5; }
    if (type === 'if') { base.condition = null; base.then = []; base.else = []; }
    if (type === 'loop') { base.loop_over = ''; base.loop_var = 'item'; base.loop_body = []; }
    if (type === 'call') { base.playbook_id = ''; }
    updateSteps([...def.steps, base]);
  };

  const addTrigger = () => updateTriggers([...def.triggers, { type: 'event', event: '' }]);

  const sectionHdr = { fontSize: 9, color: PALETTE.textGhost, textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 6, marginTop: 16, display: 'flex', alignItems: 'center', gap: 8 };

  return (
    <div>
      {/* Triggers */}
      <div style={sectionHdr}>
        <span>Triggers</span>
        <button onClick={addTrigger} style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 3, padding: '2px 8px', cursor: 'pointer', color: accent, fontSize: 9 }}>+ Add</button>
      </div>
      {(def.triggers || []).map((t, i) => (
        <TriggerCard key={i} trig={t} idx={i} tools={tools} accent={accent}
          onChange={(idx, val) => updateTriggers(def.triggers.map((tt, j) => j === idx ? val : tt))}
          onRemove={(idx) => updateTriggers(def.triggers.filter((_, j) => j !== idx))}
        />
      ))}

      {/* Conditions */}
      <div style={sectionHdr}>
        <span>Pre-conditions ({(def.conditions || []).length})</span>
        <button onClick={() => updateConditions([...(def.conditions || []), { op: 'AND', rules: [] }])} style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 3, padding: '2px 8px', cursor: 'pointer', color: accent, fontSize: 9 }}>+ Add Group</button>
      </div>
      {(def.conditions || []).length === 0 && (
        <div style={{ padding: '10px 14px', fontSize: 10, color: PALETTE.textGhost, background: '#0a0c10', borderRadius: 6, border: `1px dashed ${PALETTE.border}`, marginBottom: 6 }}>
          No conditions — playbook runs unconditionally when triggered
        </div>
      )}
      {(def.conditions || []).map((grp, i) => (
        <ConditionGroupEditor
          key={i} group={grp} depth={0} accent={accent}
          onChange={(val) => updateConditions((def.conditions || []).map((g, j) => j === i ? val : g))}
          onRemove={() => updateConditions((def.conditions || []).filter((_, j) => j !== i))}
        />
      ))}

      {/* Steps */}
      <div style={sectionHdr}>
        <span>Steps ({def.steps?.length || 0})</span>
        <div style={{ display: 'flex', gap: 4 }}>
          {STEP_TYPES.map(t => (
            <button key={t} onClick={() => addStep(t)} style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 3, padding: '2px 8px', cursor: 'pointer', color: PALETTE.textFaint, fontSize: 9 }}>
              {STEP_TYPE_ICON[t]} {t}
            </button>
          ))}
        </div>
      </div>
      <div>
        {(def.steps || []).map((s, i) => (
          <StepCard
            key={i} step={s} idx={i} tools={tools} automations={automations} accent={accent}
            isDragging={dragIdx === i}
            onChange={(idx, val) => updateSteps(def.steps.map((ss, j) => j === idx ? val : ss))}
            onRemove={(idx) => updateSteps(def.steps.filter((_, j) => j !== idx))}
            onDragStart={handleDragStart}
            onDragOver={handleDragOver}
            onDrop={handleDrop}
          />
        ))}
        {(def.steps || []).length === 0 && (
          <div style={{ padding: '16px', textAlign: 'center', color: PALETTE.textGhost, fontSize: 11, background: '#0a0c10', borderRadius: 6, border: `1px dashed ${PALETTE.border}` }}>
            No steps yet. Add one above.
          </div>
        )}
      </div>

      {/* Settings */}
      <div style={sectionHdr}><span>Settings</span></div>
      <div style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 6, padding: '10px 12px', display: 'flex', gap: 12 }}>
        {[
          { key: 'timeout', label: 'Timeout (s)', type: 'number', def: 300 },
          { key: 'max_concurrent', label: 'Max concurrent', type: 'number', def: 1 },
          { key: 'on_step_error', label: 'On error', type: 'select', opts: ON_ERROR_OPTS, def: 'stop' },
        ].map(({ key, label, type, opts, def: d }) => (
          <div key={key} style={{ flex: 1 }}>
            <label style={{ fontSize: 9, color: '#505560', marginBottom: 2, display: 'block' }}>{label}</label>
            {type === 'select' ? (
              <Select value={def.settings?.[key] ?? d} onChange={v => updateSettings({ ...def.settings, [key]: v })}
                style={{ width: '100%', boxSizing: 'border-box' }} options={opts} />
            ) : (
              <input type={type} value={def.settings?.[key] ?? d} onChange={e => updateSettings({ ...def.settings, [key]: type === 'number' ? +e.target.value : e.target.value })}
                style={{ background: '#080a0e', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '5px 8px', color: PALETTE.textDim, fontSize: 11, fontFamily: FONTS.mono, width: '100%', boxSizing: 'border-box' }} />
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
VisualEditor.propTypes = { definition: PropTypes.object, onChange: PropTypes.func, tools: PropTypes.array, automations: PropTypes.array, accent: PropTypes.string };

// ── Main View ─────────────────────────────────────────────────────────

export default function AutomationsView({ selectedProject, accent }) {
  const [automations, setAutomations] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [loading, setLoading] = useState(true);
  const [mode, setMode] = useState('list');
  const [editorMode, setEditorMode] = useState('visual');
  const [definition, setDefinition] = useState(EMPTY_DEF);
  const [jsonText, setJsonText] = useState('');
  const [editorName, setEditorName] = useState('');
  const [editorDesc, setEditorDesc] = useState('');
  const [validation, setValidation] = useState(null);
  const [runs, setRuns] = useState([]);
  const [tools, setTools] = useState([]);
  const [templates, setTemplates] = useState([]);
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);
  const [isNew, setIsNew] = useState(false);
  const [dryRunResult, setDryRunResult] = useState(null);
  const dragCounter = useRef(0);

  const load = useCallback(async () => {
    if (!selectedProject) return;
    try {
      const [autoData, toolsData, tplData] = await Promise.all([
        api.listAutomations(selectedProject),
        api.getAutomationTools(selectedProject).catch(() => ({ tools: [] })),
        api.getAutomationTemplates(selectedProject).catch(() => ({ templates: [] })),
      ]);
      setAutomations(autoData.items || []);
      setTools(toolsData.tools || []);
      setTemplates(tplData.templates || []);
    } catch (e) {
      setError(e.message || 'Load failed');
    } finally {
      setLoading(false);
    }
  }, [selectedProject]);

  useEffect(() => { load(); }, [load]);

  const selected = automations.find(a => a.id === selectedId);

  const syncToJson = (def) => { setJsonText(JSON.stringify(def, null, 2)); };
  const syncFromJson = () => {
    try { const d = JSON.parse(jsonText); setDefinition(d); return d; }
    catch { setError('Invalid JSON'); return null; }
  };

  const startNew = () => {
    setIsNew(true);
    setEditorName('');
    setEditorDesc('');
    setDefinition(EMPTY_DEF);
    syncToJson(EMPTY_DEF);
    setValidation(null);
    setDryRunResult(null);
    setMode('editor');
  };

  const startEdit = (auto) => {
    setIsNew(false);
    setSelectedId(auto.id);
    setEditorName(auto.name);
    setEditorDesc(auto.description || '');
    const def = auto.definition || EMPTY_DEF;
    setDefinition(def);
    syncToJson(def);
    setValidation(null);
    setDryRunResult(null);
    setMode('editor');
  };

  const onEditorModeSwitch = (newMode) => {
    if (newMode === 'json' && editorMode === 'visual') {
      syncToJson(definition);
    } else if (newMode === 'visual' && editorMode === 'json') {
      syncFromJson();
    }
    setEditorMode(newMode);
  };

  const doValidate = async () => {
    setError('');
    const def = editorMode === 'visual' ? definition : syncFromJson();
    if (!def) return;
    try {
      const result = await api.validateAutomationDef(selectedProject, { definition: def });
      setValidation(result);
    } catch (e) {
      setError(e.message || 'Validation failed');
    }
  };

  const doDryRun = async () => {
    setError('');
    setDryRunResult(null);
    const def = editorMode === 'visual' ? definition : syncFromJson();
    if (!def) return;
    let aid = selectedId;
    if (!isNew && !aid) return;

    try {
      if (isNew) {
        const created = await api.createAutomation(selectedProject, {
          name: (editorName || 'Untitled') + ' [DRAFT]', description: editorDesc, definition: def,
        });
        aid = created.id;
        setAutomations(prev => [...prev, created]);
        setSelectedId(aid);
        setIsNew(false);
      } else {
        await api.updateAutomation(selectedProject, aid, { definition: def });
      }
      const result = await api.dryRunAutomation(selectedProject, aid, { event_data: { severity: 'critical', title: 'Dry run test' } });
      setDryRunResult(result);
    } catch (e) {
      setError(e.message || 'Dry run failed');
    }
  };

  const doSave = async () => {
    setError('');
    setSaving(true);
    const def = editorMode === 'visual' ? definition : syncFromJson();
    if (!def) { setSaving(false); return; }

    try {
      if (isNew) {
        const result = await api.createAutomation(selectedProject, {
          name: editorName || 'Untitled', description: editorDesc, definition: def,
        });
        setAutomations(prev => [...prev, result]);
        setSelectedId(result.id);
        setIsNew(false);
        setMode('list');
      } else {
        const result = await api.updateAutomation(selectedProject, selectedId, {
          name: editorName, description: editorDesc, definition: def,
        });
        setAutomations(prev => prev.map(a => a.id === selectedId ? result : a));
        setMode('list');
      }
    } catch (e) {
      setError(e.message || 'Save failed');
    } finally {
      setSaving(false);
    }
  };

  const doToggle = async (aid, currentlyEnabled) => {
    try {
      if (currentlyEnabled) {
        await api.disableAutomation(selectedProject, aid);
        setAutomations(prev => prev.map(a => a.id === aid ? { ...a, enabled: false } : a));
      } else {
        await api.enableAutomation(selectedProject, aid);
        setAutomations(prev => prev.map(async a => a.id === aid ? { ...a, enabled: true } : a));
      }
    } catch (e) {
      const detail = e.message || '';
      if (detail.includes('422') || detail.includes('validation')) {
        await uiAlert('Cannot enable: validation errors. Check the playbook definition.');
      } else if (detail.includes('403') || detail.includes('consent')) {
        await uiAlert('Cannot enable: contains critical-risk actions. Set consent_critical=true first.');
      } else {
        await uiAlert(detail);
      }
    }
  };

  const doRun = async (aid) => {
    try {
      const run = await api.runAutomation(selectedProject, aid, {});
      setAutomations(prev => prev.map(async a => a.id === aid ? { ...a, last_run_status: run.status, run_count: (a.run_count || 0) + 1 } : a));
    } catch (e) { await uiAlert(e.message || 'Run failed'); }
  };

  const doDelete = async (aid) => {
    if (!await uiConfirm('Delete this automation?')) return;
    try {
      await api.deleteAutomation(selectedProject, aid);
      setAutomations(prev => prev.filter(async a => a.id !== aid));
      if (selectedId === aid) { setSelectedId(null); setMode('list'); }
    } catch (e) { await uiAlert(e.message); }
  };

  const doKillAll = async () => {
    if (!await uiConfirm('Disable ALL automations and cancel ALL running executions?')) return;
    try {
      const result = await api.killAllAutomations(selectedProject);
      await uiAlert(`Disabled ${result.disabled_automations} automations, cancelled ${result.cancelled_runs} runs.`);
      load();
    } catch (e) { await uiAlert(e.message); }
  };

  const loadRuns = async (aid) => {
    setSelectedId(aid);
    setMode('runs');
    try {
      const data = await api.listAutomationRuns(selectedProject, aid);
      setRuns(data.items || []);
    } catch (e) { setError(e.message); }
  };

  const applyTemplate = (tpl) => {
    setIsNew(true);
    setEditorName(tpl.name);
    setEditorDesc(tpl.description);
    setDefinition(tpl.definition);
    syncToJson(tpl.definition);
    setValidation(null);
    setDryRunResult(null);
    setMode('editor');
  };

  const exportAuto = async (aid) => {
    try {
      const data = await api.exportAutomation(selectedProject, aid);
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = `${data.name || 'automation'}.json`; a.click();
      URL.revokeObjectURL(url);
    } catch (e) { await uiAlert(e.message); }
  };

  if (!selectedProject) return <div style={{ padding: 40, color: '#6a7080', textAlign: 'center' }}>Select a project to manage automations.</div>;
  if (loading) return <div style={{ padding: 40, color: '#6a7080', textAlign: 'center' }}>Loading...</div>;

  const inp = { background: '#0a0c10', border: `1px solid ${PALETTE.border}`, borderRadius: 5, padding: '8px 10px', color: PALETTE.textDim, fontSize: 12, outline: 'none', fontFamily: FONTS.mono, boxSizing: 'border-box', width: '100%' };

  return (
    <div style={{ display: 'flex', height: '100%', fontFamily: FONTS.mono }}>
      {/* Sidebar */}
      <div style={{ width: 300, borderRight: '1px solid #1e2029', display: 'flex', flexDirection: 'column', flexShrink: 0 }}>
        <div style={{ padding: '12px 14px', borderBottom: '1px solid #1e2029', display: 'flex', gap: 8 }}>
          <button onClick={startNew} style={{ flex: 1, background: accent + '22', border: `1px solid ${accent}44`, borderRadius: 4, padding: '6px', cursor: 'pointer', color: accent, fontSize: 10, fontWeight: 600 }}>+ New</button>
          <button onClick={doKillAll} style={{ background: 'transparent', border: '1px solid #cc223344', borderRadius: 4, padding: '6px 10px', cursor: 'pointer', color: PALETTE.danger, fontSize: 10 }} title="Kill switch">{'\u26D4'}</button>
        </div>
        <div style={{ flex: 1, overflowY: 'auto' }}>
          {automations.length === 0 && <div style={{ padding: '20px 14px', fontSize: 10, color: PALETTE.textGhost }}>No automations yet</div>}
          {automations.map(a => (
            <AutoCard key={a.id} auto={a} accent={accent}
              selected={selectedId === a.id && mode !== 'editor'}
              onSelect={(id) => { setSelectedId(id); setMode('list'); }}
              onToggle={doToggle} onRun={doRun} onDelete={doDelete}
            />
          ))}
        </div>
        {templates.length > 0 && (
          <div style={{ borderTop: '1px solid #1e2029', padding: '8px 14px' }}>
            <div style={{ fontSize: 9, color: PALETTE.textGhost, textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 6 }}>Templates</div>
            {templates.map(t => (
              <button key={t.name} onClick={() => applyTemplate(t)} style={{ display: 'block', width: '100%', textAlign: 'left', background: 'transparent', border: 'none', color: PALETTE.textFaint, fontSize: 10, cursor: 'pointer', padding: '4px 0' }}>{t.name}</button>
            ))}
          </div>
        )}
      </div>

      {/* Main panel */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '20px 24px' }}>
        {error && <div style={{ background: '#cc223318', border: '1px solid #cc223344', borderRadius: 5, padding: '8px 12px', fontSize: 11, color: PALETTE.danger, marginBottom: 12 }}>{error}</div>}

        {/* List mode */}
        {mode === 'list' && selected && (
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
              <div style={{ fontSize: 16, color: '#e0e4ec', fontWeight: 700, fontFamily: FONTS.display }}>{selected.name}</div>
              <span style={{ fontSize: 10, padding: '2px 8px', borderRadius: 3, background: selected.enabled ? accent + '22' : '#40455022', border: `1px solid ${selected.enabled ? accent + '44' : '#40455044'}`, color: selected.enabled ? accent : PALETTE.textFaint }}>
                {selected.enabled ? 'ENABLED' : 'DISABLED'}
              </span>
            </div>
            {selected.description && <div style={{ fontSize: 11, color: PALETTE.textFaint, marginBottom: 16 }}>{selected.description}</div>}
            <div style={{ display: 'flex', gap: 8, marginBottom: 20 }}>
              <button onClick={() => startEdit(selected)} style={{ background: accent, border: 'none', borderRadius: 4, padding: '6px 14px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 600 }}>Edit</button>
              <button onClick={() => loadRuns(selected.id)} style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 14px', cursor: 'pointer', color: '#808590', fontSize: 11 }}>History</button>
              <button onClick={() => doRun(selected.id)} style={{ background: 'transparent', border: '1px solid #39d35344', borderRadius: 4, padding: '6px 14px', cursor: 'pointer', color: PALETTE.ok, fontSize: 11 }}>Run Now</button>
              <button onClick={() => exportAuto(selected.id)} style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 14px', cursor: 'pointer', color: '#808590', fontSize: 11 }}>Export</button>
            </div>
            <div style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 6, padding: '14px' }}>
              <div style={{ fontSize: 9, color: PALETTE.textGhost, textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 8 }}>Definition</div>
              <pre style={{ margin: 0, whiteSpace: 'pre-wrap', fontSize: 11, color: '#808590', lineHeight: 1.6 }}>{JSON.stringify(selected.definition, null, 2)}</pre>
            </div>
            <div style={{ marginTop: 16 }}>
              <div style={{ fontSize: 9, color: PALETTE.textGhost, textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 8 }}>Available Tools ({tools.length})</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {tools.map(t => (
                  <span key={t.name} style={{ fontSize: 10, padding: '3px 8px', borderRadius: 3, background: '#0a0c10', border: `1px solid ${t.risk === 'critical' ? '#cc223344' : t.risk === 'write' ? '#f09a3a44' : '#39d35344'}`, color: t.risk === 'critical' ? '#cc2233' : t.risk === 'write' ? '#f09a3a' : PALETTE.ok }} title={t.description}>{t.name}</span>
                ))}
              </div>
            </div>
          </div>
        )}

        {mode === 'list' && !selected && (
          <div style={{ color: PALETTE.textGhost, fontSize: 13, textAlign: 'center', marginTop: 60 }}>Select an automation or create a new one.</div>
        )}

        {/* Editor mode */}
        {mode === 'editor' && (
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
              <div style={{ fontSize: 16, color: '#e0e4ec', fontWeight: 700, fontFamily: FONTS.display }}>{isNew ? 'New Automation' : `Edit: ${selected?.name || ''}`}</div>
              {/* Editor mode toggle */}
              <div style={{ marginLeft: 'auto', display: 'flex', gap: 2, background: '#0a0c10', borderRadius: 5, padding: 2, border: '1px solid #1e2029' }}>
                {['visual', 'json'].map(m => (
                  <button key={m} onClick={() => onEditorModeSwitch(m)} style={{
                    background: editorMode === m ? accent + '22' : 'transparent', border: 'none', borderRadius: 3,
                    padding: '4px 12px', cursor: 'pointer', color: editorMode === m ? accent : '#505560',
                    fontSize: 10, fontWeight: 600, textTransform: 'uppercase',
                  }}>{m}</button>
                ))}
              </div>
            </div>

            <div style={{ display: 'flex', gap: 16 }}>
              <div style={{ flex: 1, maxWidth: 600 }}>
                <div style={{ marginBottom: 12 }}>
                  <div style={{ fontSize: 9, color: PALETTE.textGhost, textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 4 }}>Name</div>
                  <input value={editorName} onChange={e => setEditorName(e.target.value)} placeholder="Automation name" style={inp} />
                </div>
                <div style={{ marginBottom: 12 }}>
                  <div style={{ fontSize: 9, color: PALETTE.textGhost, textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 4 }}>Description</div>
                  <input value={editorDesc} onChange={e => setEditorDesc(e.target.value)} placeholder="What does this automation do?" style={inp} />
                </div>

                {editorMode === 'visual' ? (
                  <VisualEditor definition={definition} onChange={(d) => { setDefinition(d); syncToJson(d); }} tools={tools} automations={automations} accent={accent} />
                ) : (
                  <div>
                    <textarea
                      value={jsonText}
                      onChange={e => { setJsonText(e.target.value); setValidation(null); }}
                      style={{ ...inp, minHeight: 400, resize: 'vertical', lineHeight: 1.5 }}
                      spellCheck={false}
                    />
                  </div>
                )}

                {validation && (
                  <div style={{ marginTop: 8, padding: '10px 12px', borderRadius: 5, background: validation.ok ? '#39d35311' : '#cc223311', border: `1px solid ${validation.ok ? '#39d35344' : '#cc223344'}` }}>
                    <div style={{ fontSize: 11, color: validation.ok ? '#39d353' : PALETTE.danger, fontWeight: 600, marginBottom: 6 }}>
                      {validation.ok ? '\u2713 Valid' : '\u2715 Validation errors'}
                      {validation.has_critical && <span style={{ color: PALETTE.warn, marginLeft: 8 }}>Contains critical-risk actions</span>}
                    </div>
                    {validation.errors?.map((e, i) => <div key={i} style={{ fontSize: 10, color: PALETTE.danger, marginBottom: 3 }}>{e.step_id ? `[${e.step_id}] ` : ''}{e.message}</div>)}
                    {validation.warnings?.map((w, i) => <div key={i} style={{ fontSize: 10, color: PALETTE.warn, marginBottom: 3 }}>{w.step_id ? `[${w.step_id}] ` : ''}{w.message}</div>)}
                  </div>
                )}

                {dryRunResult && (
                  <div style={{ marginTop: 8, padding: '10px 12px', borderRadius: 5, background: '#c07af011', border: '1px solid #c07af044' }}>
                    <div style={{ fontSize: 11, color: '#c07af0', fontWeight: 600, marginBottom: 6 }}>{'\u25B8'} Dry Run Result: {dryRunResult.status}</div>
                    {(dryRunResult.steps_log || []).map((s, i) => <StepLogEntry key={i} step={s} />)}
                  </div>
                )}

                <div style={{ display: 'flex', gap: 8, marginTop: 16 }}>
                  <button onClick={doSave} disabled={saving} style={{ background: accent, border: 'none', borderRadius: 4, padding: '8px 18px', cursor: 'pointer', color: '#fff', fontSize: 12, fontWeight: 600 }}>{saving ? 'Saving...' : 'Save'}</button>
                  <button onClick={doValidate} style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '8px 14px', cursor: 'pointer', color: '#5b8af5', fontSize: 11 }}>Validate</button>
                  <button onClick={doDryRun} style={{ background: 'transparent', border: '1px solid #c07af044', borderRadius: 4, padding: '8px 14px', cursor: 'pointer', color: '#c07af0', fontSize: 11 }}>Dry Run</button>
                  <button onClick={() => setMode('list')} style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '8px 18px', cursor: 'pointer', color: PALETTE.textFaint, fontSize: 12 }}>Cancel</button>
                </div>
              </div>

              {/* Right sidebar: tools reference */}
              <div style={{ width: 240, flexShrink: 0 }}>
                <div style={{ fontSize: 9, color: PALETTE.textGhost, textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 8, position: 'sticky', top: 0 }}>Tools ({tools.length})</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {tools.map(t => (
                    <div key={t.name} style={{ padding: '6px 8px', borderRadius: 4, background: '#0a0c10', border: `1px solid ${t.risk === 'critical' ? '#cc223322' : t.risk === 'write' ? '#f09a3a22' : '#39d35322'}` }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <span style={{ fontSize: 10, color: t.risk === 'critical' ? '#cc2233' : t.risk === 'write' ? '#f09a3a' : PALETTE.ok, fontFamily: FONTS.mono, fontWeight: 600 }}>{t.name}</span>
                        <span style={{ fontSize: 8, padding: '1px 4px', borderRadius: 2, background: t.risk === 'critical' ? '#cc223322' : t.risk === 'write' ? '#f09a3a22' : '#39d35322', color: t.risk === 'critical' ? '#cc2233' : t.risk === 'write' ? '#f09a3a' : PALETTE.ok }}>{t.risk}</span>
                      </div>
                      <div style={{ fontSize: 9, color: '#505560', marginTop: 2, lineHeight: 1.3 }}>{t.description}</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Runs mode */}
        {mode === 'runs' && (
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
              <div style={{ fontSize: 16, color: '#e0e4ec', fontWeight: 700, fontFamily: FONTS.display }}>Run History</div>
              <button onClick={() => setMode('list')} style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '4px 10px', cursor: 'pointer', color: PALETTE.textFaint, fontSize: 10 }}>Back</button>
            </div>
            {runs.length === 0 && <div style={{ color: PALETTE.textGhost, fontSize: 12, padding: '20px 0', textAlign: 'center' }}>No runs yet.</div>}
            {runs.map(run => (
              <div key={run.id} style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 6, padding: '12px 14px', marginBottom: 8 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                  <span style={{ width: 8, height: 8, borderRadius: '50%', background: STATUS_COLORS[run.status] || '#404550' }} />
                  <span style={{ fontSize: 11, color: '#e0e4ec', fontWeight: 600 }}>{run.status}</span>
                  <span style={{ fontSize: 10, color: '#505560' }}>{run.trigger_type}</span>
                  <span style={{ fontSize: 10, color: '#505560', marginLeft: 'auto' }}>{run.started_at?.replace('T', ' ').slice(0, 19)}</span>
                </div>
                {run.error && <div style={{ fontSize: 10, color: PALETTE.danger, marginBottom: 6 }}>{run.error}</div>}
                <div>{(run.steps_log || []).map((step, i) => <StepLogEntry key={i} step={step} />)}</div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
AutomationsView.propTypes = { selectedProject: PropTypes.any, accent: PropTypes.string };
