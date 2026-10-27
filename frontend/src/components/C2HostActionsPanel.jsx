import PropTypes from 'prop-types';
import { useEffect, useMemo, useState } from 'react';
import { api } from '../api.js';
import Icon from './Icon.jsx';
import { PALETTE, FONTS, Select } from './UI.jsx';

const RESERVED_AUTOFILL_KEYS = new Set(['user', 'username', 'pass', 'password', 'secret', 'domain', 'realm', 'target', 'host']);

// C2 integration types that support live execution from this panel.
// Matches backend SUPPORTED_EXEC_C2_TYPES — keep in sync.
const SUPPORTED_EXEC_C2 = new Set(['adaptix', 'mythic', 'sliver']);

function getOperationTemplates(host) {
  const os = String(host?.os || '').toLowerCase();
  const isWindows = os.includes('win');
  const isLinux = os.includes('linux') || os.includes('ubuntu') || os.includes('debian') || os.includes('centos') || os.includes('redhat');
  const hasDomain = Boolean((host?.domain || '').trim());
  const common = [
    { id: 'whoami', label: 'Whoami', commandline: isWindows ? 'shell whoami /all' : 'shell whoami && id' },
    { id: 'hostname', label: 'Host identity', commandline: isWindows ? 'shell hostname && ver' : 'shell hostname && uname -a' },
    { id: 'net', label: 'Network info', commandline: isWindows ? 'shell ipconfig /all && route print' : 'shell ip a && ip route' },
    { id: 'users', label: 'Logged-on users', commandline: isWindows ? 'shell query user' : 'shell w && who' },
    { id: 'processes', label: 'Processes', commandline: isWindows ? 'shell tasklist' : 'shell ps aux' },
  ];
  const windows = [
    { id: 'admins', label: 'Local admins', commandline: 'shell net localgroup administrators' },
    { id: 'shares', label: 'Shares', commandline: 'shell net share' },
    { id: 'services', label: 'Services', commandline: 'shell sc query type= service state= all' },
    { id: 'sessions', label: 'Net sessions', commandline: 'shell net session' },
  ];
  const domain = [
    { id: 'domain-whoami', label: 'Domain identity', commandline: 'shell whoami /all && echo {{DOMAIN}}' },
    { id: 'dc-discovery', label: 'DC discovery', commandline: 'shell nltest /dsgetdc:{{DOMAIN}}' },
    { id: 'kerb-tickets', label: 'Kerberos tickets', commandline: 'shell klist' },
  ];
  const linux = [
    { id: 'sudoers', label: 'Sudo rights', commandline: 'shell sudo -l' },
    { id: 'mounts', label: 'Mounts', commandline: 'shell mount && cat /etc/fstab' },
    { id: 'services-linux', label: 'Services', commandline: 'shell systemctl list-units --type=service --state=running' },
  ];
  return [
    ...common,
    ...(isWindows ? windows : []),
    ...(isLinux ? linux : []),
    ...(isWindows && hasDomain ? domain : []),
  ];
}

function getCredentialOperationPacks(host, cred) {
  if (!cred) return [];
  const os = String(host?.os || '').toLowerCase();
  const isWindows = os.includes('win');
  const isLinux = os.includes('linux') || os.includes('ubuntu') || os.includes('debian') || os.includes('centos') || os.includes('redhat');
  const hasDomain = Boolean((host?.domain || '').trim() || (cred?.domain || '').trim());
  const type = String(cred.type || '').toLowerCase();
  const isHash = type.includes('hash') || type.includes('ntlm');

  const packs = [];
  if (isWindows) {
    if (isHash) {
      packs.push({ id: 'smb-hash', label: 'SMB hash check', commandline: 'netexec smb {{TARGET}} -u {{USER}} -H {{HASH}}' }, { id: 'wmiexec-hash', label: 'WMI exec (hash)', commandline: 'impacket-wmiexec {{DOMAIN}}/{{USER}}@{{TARGET}} -hashes :{{HASH}}' }, { id: 'psexec-hash', label: 'PsExec (hash)', commandline: 'impacket-psexec {{DOMAIN}}/{{USER}}@{{TARGET}} -hashes :{{HASH}}' });
    } else {
      packs.push({ id: 'smb-pass', label: 'SMB auth check', commandline: 'netexec smb {{TARGET}} -u {{USER}} -p {{PASS}}' }, { id: 'winrm-pass', label: 'WinRM check', commandline: 'netexec winrm {{TARGET}} -u {{USER}} -p {{PASS}}' }, { id: 'wmiexec-pass', label: 'WMI exec', commandline: 'impacket-wmiexec {{DOMAIN}}/{{USER}}:{{PASS}}@{{TARGET}}' }, { id: 'psexec-pass', label: 'PsExec', commandline: 'impacket-psexec {{DOMAIN}}/{{USER}}:{{PASS}}@{{TARGET}}' }, { id: 'evil-winrm', label: 'Evil-WinRM', commandline: 'evil-winrm -i {{TARGET}} -u {{USER}} -p {{PASS}}' });
    }
    if (hasDomain) {
      packs.push({ id: 'ldap-bind', label: 'LDAP bind', commandline: 'ldapsearch -x -H ldap://{{TARGET}} -D "{{USER}}@{{DOMAIN}}" -w "{{PASS}}" -b "" "(objectClass=*)"' }, { id: 'kerb-check', label: 'Kerberos check', commandline: 'kerbrute userenum -d {{DOMAIN}} --dc {{TARGET}} users.txt' });
    }
  }
  if (isLinux && !isHash) {
    packs.push({ id: 'ssh-check', label: 'SSH check', commandline: 'ssh -o StrictHostKeyChecking=no {{USER}}@{{TARGET}}' }, { id: 'ssh-batch', label: 'SSH whoami', commandline: 'ssh -o StrictHostKeyChecking=no {{USER}}@{{TARGET}} "whoami && id && hostname"' });
  }
  if (!isWindows && !isLinux) {
    if (isHash) { packs.push({ id: 'hash-check', label: 'Hash auth check', commandline: 'netexec smb {{TARGET}} -u {{USER}} -H {{HASH}}' }); }
    else { packs.push({ id: 'auth-check', label: 'Auth check', commandline: 'netexec smb {{TARGET}} -u {{USER}} -p {{PASS}}' }); }
  }
  return packs;
}

function OperationTemplatesSection({ form, operationTemplates, applyTemplate, accent }) {
  if (form.mode !== 'command' || operationTemplates.length === 0) return null;
  return (
    <div style={{ marginBottom: 8 }}>
      <div style={{ fontSize: 8, color: PALETTE.textGhost, marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Quick operations</div>
      <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap' }}>
        {operationTemplates.map(template => (
          <button key={template.id} onClick={() => applyTemplate(template)} style={{ background: form.commandline === template.commandline ? `${accent}22` : PALETTE.bg3, border: `1px solid ${form.commandline === template.commandline ? accent + '66' : PALETTE.border}`, borderRadius: 999, padding: '3px 8px', cursor: 'pointer', color: form.commandline === template.commandline ? accent : '#808590', fontSize: 9, fontFamily: FONTS.mono }}>
            {template.label}
          </button>
        ))}
      </div>
    </div>
  );
}
OperationTemplatesSection.propTypes = {
  form: PropTypes.any,
  operationTemplates: PropTypes.any,
  applyTemplate: PropTypes.any,
  accent: PropTypes.any,
};

function BofSection({ form, setForm, commandCatalog, selectedCommand, visibleParams, renderedBofCommand, onParamChange, accent }) {
  if (form.mode !== 'bof' || commandCatalog.length === 0) return null;
  return (
    <>
      <Select value={form.commandId} onChange={v => setForm(prev => ({ ...prev, commandId: v, params: {} }))} style={{ width: '100%', marginBottom: 8 }}
        options={commandCatalog.map(item => ({ value: item.id, label: `${item.group ? `${item.group} :: ` : ''}${item.title || item.name}` }))} />
      {selectedCommand?.description && <div style={{ fontSize: 9, color: PALETTE.textFaint, marginBottom: 8, lineHeight: 1.5 }}>{selectedCommand.description}</div>}
      {visibleParams.map(param => (
        <div key={param.key} style={{ marginBottom: 8 }}>
          <div style={{ fontSize: 8, color: PALETTE.textGhost, marginBottom: 4, textTransform: 'uppercase', letterSpacing: '0.1em' }}>{param.label}</div>
          {renderParam(param, form, onParamChange, accent)}
          {param.description && <div style={{ fontSize: 9, color: PALETTE.textGhost, marginTop: 4 }}>{param.description}</div>}
        </div>
      ))}
      <div style={{ fontSize: 9, color: PALETTE.textGhost, marginBottom: 4, fontFamily: FONTS.mono }}>Rendered BOF command</div>
      <pre style={{ margin: '0 0 8px', fontSize: 9, color: PALETTE.textMute, fontFamily: FONTS.mono, whiteSpace: 'pre-wrap', wordBreak: 'break-word', background: PALETTE.bg3, border: '1px solid #1e2029', borderRadius: 4, padding: '8px 9px' }}>{renderedBofCommand || selectedCommand?.template || ''}</pre>
    </>
  );
}
BofSection.propTypes = {
  form: PropTypes.any,
  setForm: PropTypes.any,
  commandCatalog: PropTypes.any,
  selectedCommand: PropTypes.any,
  visibleParams: PropTypes.any,
  renderedBofCommand: PropTypes.any,
  onParamChange: PropTypes.any,
  accent: PropTypes.any,
};

function CredentialPacksSection({ form, selectedCredential, credentialPacks, applyTemplate }) {
  if (form.mode !== 'command' || !selectedCredential || credentialPacks.length === 0) return null;
  return (
    <div style={{ marginBottom: 8 }}>
      <div style={{ fontSize: 8, color: PALETTE.textGhost, marginBottom: 5, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Credential packs</div>
      <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap' }}>
        {credentialPacks.map(template => (
          <button key={template.id} onClick={() => applyTemplate(template)} style={{ background: form.commandline === template.commandline ? '#cc223322' : PALETTE.bg3, border: `1px solid ${form.commandline === template.commandline ? '#cc223366' : PALETTE.border}`, borderRadius: 999, padding: '3px 8px', cursor: 'pointer', color: form.commandline === template.commandline ? '#cc2233' : '#808590', fontSize: 9, fontFamily: FONTS.mono }}>
            {template.label}
          </button>
        ))}
      </div>
    </div>
  );
}
CredentialPacksSection.propTypes = {
  form: PropTypes.any,
  selectedCredential: PropTypes.any,
  credentialPacks: PropTypes.any,
  applyTemplate: PropTypes.any,
};

function CliSection({ cliInput, setCliInput, tasksLoading, tasks, refreshTasks, run, running }) {
  return (
    <div style={{ borderTop: '1px solid #1e2029', paddingTop: 10 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
        <span style={{ fontSize: 9, color: PALETTE.textGhost, textTransform: 'uppercase', letterSpacing: '0.1em', flex: 1 }}>Interactive CLI</span>
        <button onClick={() => refreshTasks()} style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 3, padding: '2px 6px', cursor: 'pointer', color: PALETTE.textFaint, fontSize: 9, fontFamily: FONTS.mono }}>{tasksLoading ? '...' : 'Refresh'}</button>
      </div>
      <div style={{ display: 'flex', gap: 6, marginBottom: 8 }}>
        <input value={cliInput} onChange={e => setCliInput(e.target.value)} placeholder='shell whoami /all' style={{ flex: 1, background: PALETTE.bg3, border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 8px', color: PALETTE.textDim, fontSize: 10, fontFamily: FONTS.mono, minWidth: 0 }} />
        <button onClick={() => run({ interactive: true })} disabled={running || !cliInput.trim()} style={{ background: PALETTE.danger, border: 'none', borderRadius: 4, padding: '6px 10px', cursor: 'pointer', color: '#fff', fontSize: 10, fontWeight: 600, fontFamily: FONTS.mono }}>{running ? '...' : 'Send'}</button>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6, maxHeight: 220, overflowY: 'auto' }}>
        {tasks.length === 0 && <div style={{ fontSize: 10, color: PALETTE.textGhost }}>No task history for this agent yet</div>}
        {tasks.map(task => (
          <TaskItem key={task.task_id || `${task.start_time}:${task.cmdline}`} task={task} />
        ))}
      </div>
    </div>
  );
}
CliSection.propTypes = {
  cliInput: PropTypes.any,
  setCliInput: PropTypes.any,
  tasksLoading: PropTypes.any,
  tasks: PropTypes.any,
  refreshTasks: PropTypes.any,
  run: PropTypes.any,
  running: PropTypes.any,
};

function TaskItem({ task }) {
  const statusColor = task.completed ? '#39d353' : PALETTE.warn;
  return (
    <div style={{ background: PALETTE.bg3, border: '1px solid #1e2029', borderRadius: 4, padding: '7px 8px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
        <span style={{ fontSize: 8, color: statusColor, background: `${statusColor}18`, border: `1px solid ${statusColor}44`, borderRadius: 3, padding: '1px 5px', fontFamily: FONTS.mono }}>{task.completed ? 'done' : 'running'}</span>
        <span style={{ fontSize: 8, color: '#505560', fontFamily: FONTS.mono, marginLeft: 'auto' }}>{task.finish_time || task.start_time || ''}</span>
      </div>
      <div style={{ fontSize: 10, color: '#5b8af5', fontFamily: FONTS.mono, marginBottom: (task.text || task.message) ? 4 : 0, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{task.cmdline || '(empty command)'}</div>
      {(task.text || task.message) && <pre style={{ margin: 0, fontSize: 9, color: PALETTE.textMute, fontFamily: FONTS.mono, whiteSpace: 'pre-wrap', wordBreak: 'break-word', maxHeight: 120, overflowY: 'auto' }}>{task.text || task.message}</pre>}
    </div>
  );
}
TaskItem.propTypes = {
  task: PropTypes.any,
};

function _sessionValue(form) {
  return form.integrationId && form.agentId ? `${form.integrationId}::${form.agentId}` : '';
}

function _onCredentialChange(value, setForm) {
  const [credentialSource, credentialId] = value ? value.split(':') : ['', ''];
  setForm(prev => ({ ...prev, credentialSource, credentialId }));
}

function _runLabel(running, mode) {
  if (running) return 'Executing...';
  return mode === 'bof' ? 'Run BOF' : 'Run command';
}

function C2SessionPanel({ form, setForm, accent, c2Meta, sessionOptions, creds, operationTemplates, commandCatalog, selectedCommand, visibleParams, renderedBofCommand, selectedCredential, credentialPacks, applyTemplate, onPickSession, onParamChange, run, cliInput, setCliInput, tasksLoading, tasks, refreshTasks, running }) {
  const runDisabled = running || !(form.mode === 'bof' ? renderedBofCommand.trim() : form.commandline.trim());
  const bofTitle = c2Meta.supportsBof ? '' : `BOF execution is Adaptix-only — current agent is ${c2Meta.label}`;
  return (
    <>
      <Select value={_sessionValue(form)} onChange={onPickSession} style={{ width: '100%', marginBottom: 8 }}
        options={sessionOptions.map(s => ({
          value: `${s.integration_id}::${s.agent_id || s.beacon_id}`,
          label: `[${(s.integration_type || '?').toUpperCase()}] ${s.integration_name} :: ${s.username || '?'} @ ${s.ip || '?'}`,
        }))} />

      <div style={{ display: 'flex', gap: 6, marginBottom: 8 }}>
        <button onClick={() => setForm(prev => ({ ...prev, mode: 'command' }))} style={{ flex: 1, background: form.mode === 'command' ? `${accent}22` : PALETTE.bg3, border: `1px solid ${form.mode === 'command' ? accent + '77' : PALETTE.border}`, borderRadius: 4, padding: '5px 8px', cursor: 'pointer', color: form.mode === 'command' ? accent : PALETTE.textFaint, fontSize: 9, fontFamily: FONTS.mono }}>Command</button>
        <button
          onClick={() => c2Meta.supportsBof && setForm(prev => ({ ...prev, mode: 'bof' }))}
          disabled={!c2Meta.supportsBof}
          title={bofTitle}
          style={{ flex: 1, background: form.mode === 'bof' ? '#cc223322' : PALETTE.bg3, border: `1px solid ${form.mode === 'bof' ? '#cc223377' : PALETTE.border}`, borderRadius: 4, padding: '5px 8px', cursor: c2Meta.supportsBof ? 'pointer' : 'not-allowed', color: form.mode === 'bof' ? '#cc2233' : PALETTE.textFaint, fontSize: 9, fontFamily: FONTS.mono, opacity: c2Meta.supportsBof ? 1 : 0.35 }}
        >BOF{c2Meta.supportsBof ? '' : ' (Adaptix only)'}</button>
      </div>

      <OperationTemplatesSection form={form} operationTemplates={operationTemplates} applyTemplate={applyTemplate} accent={accent} />

      <BofSection form={form} setForm={setForm} commandCatalog={commandCatalog} selectedCommand={selectedCommand} visibleParams={visibleParams} renderedBofCommand={renderedBofCommand} onParamChange={onParamChange} accent={accent} />

      <Select value={form.credentialId ? `${form.credentialSource}:${form.credentialId}` : ''} onChange={v => _onCredentialChange(v, setForm)} style={{ width: '100%', marginBottom: 8 }}
        placeholder="No credential substitution"
        options={creds.map(c => ({ value: `${c.source}:${c.id}`, label: `${c.source} :: ${c.username}${c.domain ? `@${c.domain}` : ''}` }))} />

      <CredentialPacksSection form={form} selectedCredential={selectedCredential} credentialPacks={credentialPacks} applyTemplate={applyTemplate} />

      {form.mode === 'command' && <textarea value={form.commandline} onChange={e => setForm(prev => ({ ...prev, commandline: e.target.value }))} placeholder="Command, e.g. shell whoami /all" rows={3} style={{ width: '100%', background: PALETTE.bg3, border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 8px', color: PALETTE.textDim, fontSize: 10, outline: 'none', fontFamily: FONTS.mono, resize: 'vertical', boxSizing: 'border-box', marginBottom: 8 }} />}

      <div style={{ fontSize: 9, color: PALETTE.textGhost, marginBottom: 8, fontFamily: FONTS.mono }}>
        Supported autofill placeholders: <code>{'{{USER}}'}</code>, <code>{'{{PASS}}'}</code>, <code>{'{{DOMAIN}}'}</code>, <code>{'{{TARGET}}'}</code>, <code>{'{{HASH}}'}</code>
      </div>

      <button onClick={() => run()} disabled={runDisabled} style={{ background: running ? '#1a1c22' : accent, border: 'none', borderRadius: 4, padding: '6px 10px', cursor: 'pointer', color: '#fff', fontSize: 10, fontWeight: 600, fontFamily: FONTS.mono, display: 'flex', alignItems: 'center', gap: 6, marginBottom: 10 }}>
        <Icon name='terminal' size={11} color='#fff' />{_runLabel(running, form.mode)}
      </button>

      <CliSection cliInput={cliInput} setCliInput={setCliInput} tasksLoading={tasksLoading} tasks={tasks} refreshTasks={refreshTasks} run={run} running={running} />
    </>
  );
}
C2SessionPanel.propTypes = {
  form: PropTypes.any,
  setForm: PropTypes.any,
  accent: PropTypes.any,
  c2Meta: PropTypes.any,
  sessionOptions: PropTypes.any,
  creds: PropTypes.any,
  operationTemplates: PropTypes.any,
  commandCatalog: PropTypes.any,
  selectedCommand: PropTypes.any,
  visibleParams: PropTypes.any,
  renderedBofCommand: PropTypes.any,
  selectedCredential: PropTypes.any,
  credentialPacks: PropTypes.any,
  applyTemplate: PropTypes.any,
  onPickSession: PropTypes.any,
  onParamChange: PropTypes.any,
  run: PropTypes.any,
  cliInput: PropTypes.any,
  setCliInput: PropTypes.any,
  tasksLoading: PropTypes.any,
  tasks: PropTypes.any,
  refreshTasks: PropTypes.any,
  running: PropTypes.any,
};

function resolveCommandline(form, cliInput, renderedBofCommand, interactive) {
  if (interactive) return cliInput.trim();
  if (form.mode === 'bof') return renderedBofCommand.trim();
  return form.commandline.trim();
}

function buildRunTitle(form, c2Meta, selectedCommand, interactive) {
  if (interactive) return `${c2Meta.label} CLI command`;
  if (form.mode === 'bof') return selectedCommand?.title || `${c2Meta.label} BOF`;
  return `${c2Meta.label} command`;
}

function buildRunPayload(form, host, c2Meta, selectedCommand, cliInput, renderedBofCommand, interactive) {
  const commandline = resolveCommandline(form, cliInput, renderedBofCommand, interactive);
  return {
    commandline,
    payload: {
      integration_id: form.integrationId,
      agent_id: form.agentId,
      host_id: host.id,
      mode: interactive ? 'command' : form.mode,
      commandline,
      credential_id: form.credentialId || '',
      credential_source: form.credentialSource || '',
      wait_for_output: !interactive,
      title: buildRunTitle(form, c2Meta, selectedCommand, interactive),
    },
  };
}

function renderParam(param, form, onParamChange, accent) {
  const val = String(form.params?.[param.key] || '');
  if (param.type === 'choice') {
    return (
      <Select value={val} onChange={v => onParamChange(param.key, v)} style={{ width: '100%' }}
        placeholder="Select..." options={param.choices || []} />
    );
  }
  if (param.type === 'boolean') {
    const isTrue = val === 'true';
    return (
      <button onClick={() => onParamChange(param.key, String(!isTrue))} style={{ width: '100%', background: isTrue ? `${accent}22` : PALETTE.bg3, border: `1px solid ${isTrue ? accent + '77' : PALETTE.border}`, borderRadius: 4, padding: '6px 8px', color: isTrue ? accent : PALETTE.textFaint, fontSize: 10, fontFamily: FONTS.mono, cursor: 'pointer', textAlign: 'left' }}>{isTrue ? 'true' : 'false'}</button>
    );
  }
  if (param.type === 'textarea') {
    return <textarea value={val} onChange={e => onParamChange(param.key, e.target.value)} rows={3} placeholder={param.placeholder || ''} style={{ width: '100%', background: PALETTE.bg3, border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 8px', color: PALETTE.textDim, fontSize: 10, fontFamily: FONTS.mono, resize: 'vertical', boxSizing: 'border-box' }} />;
  }
  return <input value={val} onChange={e => onParamChange(param.key, e.target.value)} placeholder={param.placeholder || ''} style={{ width: '100%', background: PALETTE.bg3, border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 8px', color: PALETTE.textDim, fontSize: 10, fontFamily: FONTS.mono, boxSizing: 'border-box' }} />;
}

function renderCommandTemplate(template, values) {
  let next = template || '';
  for (const [key, value] of Object.entries(values || {})) {
    if (value == null || value === '') continue;
    const upper = key.toUpperCase();
    next = next.replaceAll(`{{${upper}}}`, String(value));
    next = next.replaceAll(`{{${key}}}`, String(value));
  }
  return next;
}

export default function C2HostActionsPanel({ pid, host, accent = '#5b8af5', onExecuted }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [running, setRunning] = useState(false);
  const [opsecWarning, setOpsecWarning] = useState(null);
  const [result, setResult] = useState(null);
  const [tasks, setTasks] = useState([]);
  const [tasksLoading, setTasksLoading] = useState(false);
  const [cliInput, setCliInput] = useState('shell whoami /all');
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [form, setForm] = useState({ integrationId: '', agentId: '', mode: 'command', commandline: '', credentialId: '', credentialSource: '', commandId: '', params: {} });

  useEffect(() => {
    if (!pid || !host?.id) return;
    let cancelled = false;
    setLoading(true);
    setError('');
    api.getC2HostActions(pid, host.id)
      .then((next) => {
        if (cancelled) return;
        setData(next);
        const firstSession = next.sessions?.find(s => SUPPORTED_EXEC_C2.has(s.integration_type) && s.alive) || next.sessions?.[0];
        setForm(prev => ({
          ...prev,
          integrationId: firstSession?.integration_id || '',
          agentId: firstSession?.agent_id || firstSession?.beacon_id || '',
        }));
      })
      .catch((e) => { if (!cancelled) setError(e.message || 'Failed to load C2 actions'); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [host?.id, pid]);

  const sessions = data?.sessions || [];
  const creds = data?.creds || [];
  const sessionOptions = sessions.filter(s => SUPPORTED_EXEC_C2.has(s.integration_type) && s.alive !== false);
  const deadSessionCount = sessions.filter(s => SUPPORTED_EXEC_C2.has(s.integration_type) && s.alive === false).length;
  const selectedSession = useMemo(
    () => sessionOptions.find(s => s.integration_id === form.integrationId && (s.agent_id === form.agentId || s.beacon_id === form.agentId)) || null,
    [sessionOptions, form.integrationId, form.agentId],
  );
  const activeC2Type = (selectedSession?.integration_type || '').toLowerCase();
  const C2_META = {
    adaptix: { label: 'Adaptix', color: PALETTE.danger, supportsBof: true },
    mythic:  { label: 'Mythic',  color: '#ffa726', supportsBof: false },
    sliver:  { label: 'Sliver',  color: '#8bc34a', supportsBof: false },
  };
  const c2Meta = C2_META[activeC2Type] || { label: 'C2', color: '#5b8af5', supportsBof: false };

  // If user has BOF selected but switched to a framework that doesn't support
  // it, snap back to command mode automatically.
  useEffect(() => {
    if (form.mode === 'bof' && !c2Meta.supportsBof) {
      setForm(prev => ({ ...prev, mode: 'command' }));
    }
  }, [c2Meta.supportsBof, form.mode]);
  const operationTemplates = useMemo(() => getOperationTemplates(host), [host]);
  const selectedCredential = useMemo(() => creds.find(c => c.id === form.credentialId && c.source === form.credentialSource) || null, [creds, form.credentialId, form.credentialSource]);
  const credentialPacks = useMemo(() => getCredentialOperationPacks(host, selectedCredential), [host, selectedCredential]);
  const commandCatalog = useMemo(() => data?.bofs?.[form.integrationId] ?? [], [data?.bofs, form.integrationId]);
  const selectedCommand = useMemo(() => commandCatalog.find(item => item.id === form.commandId) || null, [commandCatalog, form.commandId]);
  const visibleParams = useMemo(() => (selectedCommand?.parameters || []).filter(param => !RESERVED_AUTOFILL_KEYS.has(String(param.key || '').toLowerCase())), [selectedCommand]);
  const renderedBofCommand = useMemo(() => selectedCommand ? renderCommandTemplate(selectedCommand.template, form.params) : '', [form.params, selectedCommand]);

  useEffect(() => {
    if (!commandCatalog.length) {
      setForm(prev => ({ ...prev, commandId: '', params: {} }));
      return;
    }
    setForm(prev => {
      const nextId = commandCatalog.some(item => item.id === prev.commandId) ? prev.commandId : commandCatalog[0].id;
      return nextId === prev.commandId ? prev : { ...prev, commandId: nextId, params: {} };
    });
  }, [commandCatalog]);

  useEffect(() => {
    if (!selectedCommand) return;
    const defaults = {};
    for (const param of (selectedCommand.parameters || [])) {
      if (param.default != null && param.default !== '') defaults[param.key] = String(param.default);
    }
    setForm(prev => ({ ...prev, params: Object.keys(prev.params || {}).length ? prev.params : defaults }));
  }, [selectedCommand]);

  const refreshTasks = async ({ silent = false } = {}) => {
    if (!pid || !form.integrationId || !form.agentId) return;
    if (!silent) setTasksLoading(true);
    try {
      const next = await api.getC2AgentTasks(pid, form.integrationId, form.agentId, 25);
      setTasks(next || []);
    } catch (e) {
      if (!silent) setError(e.message || 'Failed to load agent tasks');
    }
    if (!silent) setTasksLoading(false);
  };

  useEffect(() => {
    if (!form.integrationId || !form.agentId) return;
    refreshTasks();
  }, [form.integrationId, form.agentId]);

  useEffect(() => {
    if (!autoRefresh || !form.integrationId || !form.agentId) return undefined;
    const id = setInterval(() => { refreshTasks({ silent: true }); }, 3000);
    return () => clearInterval(id);
  }, [autoRefresh, form.agentId, form.integrationId, pid]);

  const onPickSession = (value) => {
    const [integrationId, agentId] = value.split('::');
    setForm(prev => ({ ...prev, integrationId, agentId }));
  };

  const onParamChange = (key, value) => {
    setForm(prev => ({ ...prev, params: { ...prev.params, [key]: value } }));
  };

  const applyTemplate = (template) => {
    setForm(prev => ({ ...prev, mode: 'command', commandline: template.commandline }));
    setCliInput(template.commandline);
  };

  const _doRun = async (payload, { interactive } = {}) => {
    setRunning(true);
    setResult(null);
    setError('');
    try {
      const res = await api.executeC2HostAction(pid, payload);
      setResult(res);
      await refreshTasks({ silent: true });
      onExecuted?.(res);
    } catch (e) {
      setError(e.message || 'Execution failed');
    }
    setRunning(false);
  };

  const run = async ({ interactive = false } = {}) => {
    const { commandline, payload } = buildRunPayload(form, host, c2Meta, selectedCommand, cliInput, renderedBofCommand, interactive);
    if (!form.integrationId || !form.agentId || !commandline) return;

    // OPSEC pre-assessment
    if (form.mode === 'command' || form.mode === 'bof') {
      try {
        const assessment = await api.assessOpsec(pid, { commandline, host_id: host.id });
        if (assessment.level !== 'ok') {
          setOpsecWarning({ assessment, pendingPayload: payload, pendingInteractive: interactive });
          return;
        }
      } catch (_) { /* assessment failure should not block execution */ }
    }

    await _doRun(payload, { interactive });
  };

  const confirmOpsecRun = () => {
    if (!opsecWarning) return;
    const { pendingPayload, pendingInteractive } = opsecWarning;
    setOpsecWarning(null);
    _doRun(pendingPayload, { interactive: pendingInteractive });
  };

  return (
    <div style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 6, padding: 10 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
        <span style={{ fontSize: 9, color: PALETTE.textGhost, textTransform: 'uppercase', letterSpacing: '0.1em', flex: 1 }}>
          C2 live actions
          {deadSessionCount > 0 && <span title={`${deadSessionCount} dead agents hidden`} style={{ marginLeft: 6, color: PALETTE.textFaint, textTransform: 'none', letterSpacing: 0 }}>({deadSessionCount} dead hidden)</span>}
        </span>
        <button onClick={() => setAutoRefresh(v => !v)} style={{ background: autoRefresh ? `${accent}22` : PALETTE.bg3, border: `1px solid ${autoRefresh ? accent + '66' : PALETTE.border}`, borderRadius: 3, padding: '1px 6px', cursor: 'pointer', color: autoRefresh ? accent : PALETTE.textFaint, fontSize: 9, fontFamily: FONTS.mono }}>{autoRefresh ? 'Auto' : 'Manual'}</button>
        <span title={selectedSession ? `${c2Meta.label} agent` : 'Select an agent to choose a framework'} style={{ fontSize: 9, color: c2Meta.color, background: `${c2Meta.color}18`, border: `1px solid ${c2Meta.color}44`, borderRadius: 3, padding: '1px 6px', fontFamily: FONTS.mono }}>{c2Meta.label}</span>
      </div>

      {loading && <div style={{ fontSize: 10, color: PALETTE.textGhost }}>Loading live sessions...</div>}
      {!loading && sessionOptions.length === 0 && <div style={{ fontSize: 10, color: PALETTE.textGhost }}>{deadSessionCount > 0 ? `No live agents matched to this host (${deadSessionCount} dead hidden)` : 'No live C2 agent matched to this host'}</div>}

      {!loading && sessionOptions.length > 0 && (
        <C2SessionPanel
          form={form} setForm={setForm} accent={accent} c2Meta={c2Meta}
          sessionOptions={sessionOptions} creds={creds}
          operationTemplates={operationTemplates} commandCatalog={commandCatalog}
          selectedCommand={selectedCommand} visibleParams={visibleParams}
          renderedBofCommand={renderedBofCommand} selectedCredential={selectedCredential}
          credentialPacks={credentialPacks} applyTemplate={applyTemplate}
          onPickSession={onPickSession} onParamChange={onParamChange}
          run={run} cliInput={cliInput} setCliInput={setCliInput}
          tasksLoading={tasksLoading} tasks={tasks} refreshTasks={refreshTasks}
          running={running}
        />
      )}

      {error && <div style={{ fontSize: 10, color: PALETTE.danger, marginTop: 8, whiteSpace: 'pre-wrap', fontFamily: FONTS.mono }}>{error}</div>}
      {result?.status === 'unconfirmed' && (
        <div style={{ fontSize: 10, color: '#e0a820', marginTop: 8, whiteSpace: 'pre-wrap', fontFamily: FONTS.mono, background: '#e0a82012', border: '1px solid #e0a82044', borderRadius: 4, padding: '6px 8px' }}>
          ⚠ Unconfirmed — teamserver accepted the command, but the agent did not report completion within the timeout. Output may be partial or stale.
        </div>
      )}
      {result?.result && <pre style={{ margin: '8px 0 0', fontSize: 9, color: PALETTE.textMute, fontFamily: FONTS.mono, whiteSpace: 'pre-wrap', wordBreak: 'break-word', background: PALETTE.bg3, border: '1px solid #1e2029', borderRadius: 4, padding: '8px 9px', maxHeight: 160, overflowY: 'auto' }}>{result.result.output || result.result.message || JSON.stringify(result.result.task || result.result, null, 2)}</pre>}

      {opsecWarning && (() => {
        const a = opsecWarning.assessment;
        const isWarn = a.level === 'warning';
        const color = isWarn ? '#f09a3a' : '#b89530';
        return (
          <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 9999 }}>
            <div style={{ background: PALETTE.bg3, border: `1px solid ${color}`, borderRadius: 6, padding: 16, maxWidth: 480, width: '90%' }}>
              <div style={{ fontSize: 12, fontWeight: 700, color, marginBottom: 8, display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{ fontSize: 16 }}>{isWarn ? '⚠' : '⚡'}</span>
                OPSEC {isWarn ? 'Warning' : 'Caution'} (risk score: {a.score}/10)
              </div>
              <div style={{ fontSize: 10, color: PALETTE.textMute, marginBottom: 8 }}>The following concerns were detected:</div>
              {a.concerns.map((c, i) => (
                <div key={i} style={{ fontSize: 10, color: c.level >= 3 ? '#f09a3a' : c.level >= 2 ? '#b89530' : '#7090a0', marginBottom: 4, paddingLeft: 12, fontFamily: FONTS.mono }}>
                  • {c.message}
                </div>
              ))}
              <div style={{ fontSize: 9, color: PALETTE.textGhost, marginTop: 8, marginBottom: 12, fontStyle: 'italic' }}>
                This is an advisory heuristic. Proceed only if you accept the OPSEC risk.
              </div>
              <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
                <button onClick={() => setOpsecWarning(null)} style={{ background: '#1e2029', border: `1px solid ${PALETTE.border}`, borderRadius: 3, padding: '4px 12px', cursor: 'pointer', color: PALETTE.textMute, fontSize: 10 }}>Cancel</button>
                <button onClick={confirmOpsecRun} style={{ background: `${color}22`, border: `1px solid ${color}`, borderRadius: 3, padding: '4px 12px', cursor: 'pointer', color, fontSize: 10, fontWeight: 700 }}>Force execute</button>
              </div>
            </div>
          </div>
        );
      })()}
    </div>
  );
}
C2HostActionsPanel.propTypes = {
  pid: PropTypes.any,
  host: PropTypes.any,
  accent: PropTypes.any,
  onExecuted: PropTypes.any,
};
