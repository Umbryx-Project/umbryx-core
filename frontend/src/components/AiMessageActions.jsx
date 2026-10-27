import { useState, useEffect, useMemo } from 'react';
import PropTypes from 'prop-types';
import { api } from '../api.js';
import { toastError, toastSuccess } from './Toast.jsx';
import { Btn, Select, PALETTE, FONTS, TYPE } from './UI.jsx';
import { uiConfirm } from '../components/Confirm.jsx';

/**
 * One-click actions on AI messages (2026-09-18):
 * - runnable command blocks detected in the assistant answer → "Run" opens
 *   a dialog: pick attacker target, fill {{PLACEHOLDER}} vars, execute via
 *   the existing attacker-exec pipeline (job + host activity + output)
 * - playbook name mentions → run the playbook right from the chat
 * - "Create task" turns the answer into a project task
 */

const CMD_BLOCK_RE = /```(bash|sh|shell|console|zsh|powershell)?\s*\n([\s\S]*?)```/g;
const PLACEHOLDER_RE = /\{\{([A-Z_][A-Z0-9_]*)\}\}/g;

const RUNNABLE_HINTS = /^(?:\$\s|#|sudo\s|nmap\s|nuclei\s|crackmapexec|nxc|impacket-|smbclient|ssh\s|curl\s|wget\s|python\d?\s|sliver|mythic|bloodhound|sharp|proxychains|ligolo|responder|enum4linux|gobuster|ffuf|nikto|hydra|mimikatz|rpcclient|wmiexec|psexec|secretsdump|GetUserSPNs|certutil|whoami|id\s|ls\s|cat\s)/i;

function extractCommandBlocks(content) {
  const blocks = [];
  let m;
  CMD_BLOCK_RE.lastIndex = 0;
  while ((m = CMD_BLOCK_RE.exec(content)) !== null) {
    const code = m[2].trim();
    if (!code || code.length > 8000) continue;
    const firstLine = code.split('\n')[0].trim();
    const looksRunnable =
      (m[1] && ['bash', 'sh', 'shell', 'console', 'zsh'].includes(m[1])) ||
      RUNNABLE_HINTS.test(firstLine) ||
      PLACEHOLDER_RE.test(code);
    PLACEHOLDER_RE.lastIndex = 0;
    if (looksRunnable) blocks.push(code);
  }
  // нет fenced-блоков, но одиночная строка выглядит командой
  if (!blocks.length) {
    const lines = String(content || '').split('\n').map(l => l.trim()).filter(Boolean);
    if (lines.length === 1 && lines[0].length < 300 && RUNNABLE_HINTS.test(lines[0])) {
      blocks.push(lines[0].replace(/^\$\s+/, ''));
    }
  }
  return blocks;
}

function RunDialog({ pid, accent, command, onClose }) {
  const [targets, setTargets] = useState(null);
  const [targetId, setTargetId] = useState('');
  const [vars, setVars] = useState({});
  const [running, setRunning] = useState(false);

  const placeholders = useMemo(() => {
    const found = [];
    let m;
    PLACEHOLDER_RE.lastIndex = 0;
    while ((m = PLACEHOLDER_RE.exec(command)) !== null) {
      if (!found.includes(m[1])) found.push(m[1]);
    }
    return found;
  }, [command]);

  useEffect(() => {
    api.listAttackerExecutionTargets(pid)
      .then(r => {
        const list = [
          ...(r.project_hosts || []).map(t => ({ value: t.id, label: `${t.name} (project · ${t.cred_count ?? 0} creds)` })),
          ...(r.global_targets || []).map(t => ({ value: t.id, label: `${t.name || t.host} (global)` })),
        ];
        setTargets(list);
        if (list.length) setTargetId(list[0].value);
      })
      .catch(e => { toastError(e.message); setTargets([]); });
  }, [pid]);

  const finalCommand = useMemo(() => {
    let c = command;
    for (const [k, v] of Object.entries(vars)) c = c.split(`{{${k}}}`).join(v);
    return c;
  }, [command, vars]);

  const run = async () => {
    const missing = placeholders.filter(p => !vars[p]);
    if (missing.length) { toastError(`Fill ${missing.join(', ')}`); return; }
    if (!targetId) { toastError('No execution target available — add an attacker host or global target'); return; }
    setRunning(true);
    try {
      const r = await api.executeAttackerCommand(pid, {
        command: finalCommand,
        target_id: targetId,
        execution_mode: 'auto',
        snippet_title: 'From AI chat',
        timeout_seconds: 120,
      });
      const okExit = r.exit_code === 0;
      (okExit ? toastSuccess : toastError)(`Exit ${r.exit_code}${r.job_id ? ` · job ${r.job_id}` : ''}`);
      onClose(true);
    } catch (e) { toastError(e.message); }
    setRunning(false);
  };

  return (
    <div style={{ position: 'fixed', inset: 0, background: '#000a', zIndex: 1000, display: 'flex', alignItems: 'center', justifyContent: 'center' }} onClick={onClose}>
      <div style={{ background: PALETTE.bg1, border: `1px solid ${accent}55`, borderRadius: 8, padding: 16, width: 'min(680px, 92vw)', maxHeight: '86vh', overflowY: 'auto' }} onClick={e => e.stopPropagation()}>
        <div style={{ fontFamily: FONTS.mono, fontSize: 13, fontWeight: 700, color: PALETTE.text, marginBottom: 10 }}>▶ Run from AI chat</div>

        <pre style={{ background: PALETTE.bg3, border: `1px solid ${PALETTE.border}`, borderRadius: 6, padding: 10, fontFamily: FONTS.mono, fontSize: 11, color: '#c8cdd6', whiteSpace: 'pre-wrap', margin: '0 0 12px' }}>{finalCommand}</pre>

        <div style={{ marginBottom: 10 }}>
          <div style={{ fontSize: 9, color: PALETTE.textGhost, textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 5, fontFamily: FONTS.mono }}>Target (attacker host)</div>
          {targets === null
            ? <div style={{ fontSize: 11, color: PALETTE.textGhost }}>Loading targets…</div>
            : <Select value={targetId} onChange={setTargetId}
                options={targets.length ? targets : [{ value: '', label: 'no targets — configure attacker SSH' }]} />}
        </div>

        {placeholders.length > 0 && (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: 8, marginBottom: 12 }}>
            {placeholders.map(p => (
              <div key={p}>
                <div style={{ fontSize: 9, color: accent, fontFamily: FONTS.mono, marginBottom: 4 }}>{`{{${p}}}`}</div>
                <input value={vars[p] || ''} onChange={e => setVars(v => ({ ...v, [p]: e.target.value }))}
                  placeholder={p} style={{ width: '100%', background: PALETTE.bg3, border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '5px 8px', color: PALETTE.textDim, fontSize: 11, fontFamily: FONTS.mono, outline: 'none' }} />
              </div>
            ))}
          </div>
        )}

        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
          <Btn variant="ghost" onClick={onClose}>Cancel</Btn>
          <Btn variant="solid" accent={accent} onClick={run} disabled={running || targets === null}>{running ? 'Running…' : 'Run'}</Btn>
        </div>
      </div>
    </div>
  );
}

function TaskDialog({ pid, accent, suggested, onClose }) {
  const [title, setTitle] = useState(suggested.slice(0, 120));
  const [description, setDescription] = useState(suggested.slice(0, 2000));
  const [saving, setSaving] = useState(false);

  const save = async () => {
    if (!title.trim()) { toastError('Title required'); return; }
    setSaving(true);
    try {
      await api.createTask({ pid, title: title.trim(), description: description.trim(), priority: 'medium', status: 'open' });
      toastSuccess('Task created');
      onClose();
    } catch (e) { toastError(e.message); }
    setSaving(false);
  };

  return (
    <div style={{ position: 'fixed', inset: 0, background: '#000a', zIndex: 1000, display: 'flex', alignItems: 'center', justifyContent: 'center' }} onClick={onClose}>
      <div style={{ background: PALETTE.bg1, border: `1px solid ${accent}55`, borderRadius: 8, padding: 16, width: 'min(560px, 92vw)', maxHeight: '86vh', overflowY: 'auto' }} onClick={e => e.stopPropagation()}>
        <div style={{ fontFamily: FONTS.mono, fontSize: 13, fontWeight: 700, color: PALETTE.text, marginBottom: 10 }}>＋ Task from AI</div>
        <input value={title} onChange={e => setTitle(e.target.value)} placeholder="title"
          style={{ width: '100%', marginBottom: 8, background: PALETTE.bg3, border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 8px', color: PALETTE.textDim, fontSize: 12, fontFamily: FONTS.mono, outline: 'none' }} />
        <textarea value={description} onChange={e => setDescription(e.target.value)} rows={5} placeholder="description"
          style={{ width: '100%', marginBottom: 10, background: PALETTE.bg3, border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 8px', color: PALETTE.textDim, fontSize: 11, fontFamily: FONTS.mono, outline: 'none', resize: 'vertical' }} />
        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
          <Btn variant="ghost" onClick={onClose}>Cancel</Btn>
          <Btn variant="solid" accent={accent} onClick={save} disabled={saving}>{saving ? 'Saving…' : 'Create task'}</Btn>
        </div>
      </div>
    </div>
  );
}

export default function AiMessageActions({ pid, accent, content }) {
  const [runCmd, setRunCmd] = useState(null);
  const [taskOpen, setTaskOpen] = useState(false);
  const [playbooks, setPlaybooks] = useState([]);

  const blocks = useMemo(() => extractCommandBlocks(content), [content]);

  const mentionedPlaybooks = useMemo(() => {
    if (!playbooks.length) return [];
    const lower = String(content || '').toLowerCase();
    return playbooks.filter(p => p.name && lower.includes(p.name.toLowerCase())).slice(0, 3);
  }, [content, playbooks]);

  useEffect(() => {
    if (!pid) return;
    api.listPlaybooks().then(r => setPlaybooks(Array.isArray(r) ? r : []))
      .catch(() => setPlaybooks([]));
  }, [pid]);

  const runPlaybookNow = async (pb) => {
    if (!await uiConfirm(`Run playbook '${pb.name}'?`)) return;
    try {
      await api.runPlaybook(pid, pb.id, {});
      toastSuccess(`Playbook '${pb.name}' started`);
    } catch (e) { toastError(e.message); }
  };

  if (!blocks.length && !mentionedPlaybooks.length && !content) return null;

  const chip = {
    display: 'inline-flex', alignItems: 'center', gap: 4,
    background: `${accent}10`, border: `1px solid ${accent}44`, borderRadius: 4,
    padding: '2px 8px', cursor: 'pointer', fontSize: 10,
    fontFamily: FONTS.mono, color: accent, fontWeight: 600,
  };

  return (
    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginTop: 5 }}>
      {blocks.map((cmd, i) => (
        <button key={`cmd-${i}`} style={chip} onClick={() => setRunCmd(cmd)} title={cmd.split('\n')[0].slice(0, 100)}>
          ▶ Run {blocks.length > 1 ? `#${i + 1}` : ''}
        </button>
      ))}
      {mentionedPlaybooks.map(pb => (
        <button key={`pb-${pb.id}`} style={chip} onClick={() => runPlaybookNow(pb)}>
          ▶ Playbook “{pb.name}”
        </button>
      ))}
      <button style={{ ...chip, color: PALETTE.textDim, borderColor: PALETTE.border, background: 'transparent' }} onClick={() => setTaskOpen(true)}>
        ＋ Task
      </button>

      {runCmd && <RunDialog pid={pid} accent={accent} command={runCmd} onClose={() => setRunCmd(null)} />}
      {taskOpen && <TaskDialog pid={pid} accent={accent} suggested={String(content || '').slice(0, 2000)} onClose={() => setTaskOpen(false)} />}
    </div>
  );
}

AiMessageActions.propTypes = { pid: PropTypes.string, accent: PropTypes.string, content: PropTypes.string };
