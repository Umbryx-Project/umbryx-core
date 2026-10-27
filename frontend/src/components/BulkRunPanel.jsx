import PropTypes from 'prop-types';
import { useState, useEffect, useMemo } from 'react';
import Icon from './Icon.jsx';
import { api } from '../api.js';
import { normalizeDomain, domainsMatch } from '../utils/hostMeta.js';
import { BULK_TEMPLATES, getBulkCredentialPacks, resultBg, resultBorder } from '../utils/hosts.js';
import { PALETTE, FONTS, Select } from './UI.jsx';

export default function BulkRunPanel({ selectedIds, hosts, creds, selectedProject, accent, onClose }) {
  const [moduleOk, setModuleOk] = useState(null);
  const [attackerTargets, setAttackerTargets] = useState(null);
  const [selectedAttacker, setSelectedAttacker] = useState('');
  const [templateKey, setTemplateKey] = useState('nmap');
  const [command, setCommand] = useState(BULK_TEMPLATES.nmap.cmd);
  const [running, setRunning] = useState(false);
  const [results, setResults] = useState(null);
  const [summary, setSummary] = useState(null);
  const [timeoutSec, setTimeoutSec] = useState(60);
  const [selectedCredentialId, setSelectedCredentialId] = useState('');

  useEffect(() => {
    api.listModules().then(({ modules }) => {
      const m = (modules || []).find(m => m.name === 'attacker_ssh');
      setModuleOk(m ? m.enabled !== false : false);
    }).catch(() => setModuleOk(false));

    api.listAttackerExecutionTargets(selectedProject).then(data => {
      setAttackerTargets(data);
      // Auto-select first available
      if (data.project_hosts?.length > 0) {
        setSelectedAttacker(`project:${data.project_hosts[0].id}`);
      } else if (data.global_targets?.length > 0) {
        setSelectedAttacker(`global:${data.global_targets[0].id}`);
      }
    }).catch(() => {});
  }, [selectedProject]);

  const pickTemplate = (key) => {
    setTemplateKey(key);
    if (BULK_TEMPLATES[key].cmd) setCommand(BULK_TEMPLATES[key].cmd);
  };

  const run = async () => {
    if (!command.trim()) return;
    setRunning(true);
    setResults(null);
    setSummary(null);
    try {
      const tpl = BULK_TEMPLATES[templateKey] || BULK_TEMPLATES.exec;
      const [kind, id] = selectedAttacker.split(':');
      const res = await api.bulkExec(selectedProject, {
        host_ids: selectedIds,
        command_template: command,
        scan_type: tpl.type,
        activity_type: tpl.activity,
        timeout_seconds: timeoutSec,
        attacker_host_id: kind === 'project' ? id : null,
        attacker_target_id: kind === 'global' ? id : null,
        credential_id: selectedCredentialId || null,
      });
      setResults(res.results || []);
      setSummary(res.summary || null);
    } catch (e) {
      setResults([{ error: e.message || 'Request failed', ok: false }]);
      setSummary(null);
    }
    setRunning(false);
  };

  const selectedHosts = hosts.filter(h => selectedIds.includes(h.id));
  const acc = accent || '#5b8af5';
  const allTargets = [
    ...(attackerTargets?.project_hosts || []).map(h => ({ value: `project:${h.id}`, label: `${h.name || h.host} (project)` })),
    ...(attackerTargets?.global_targets || []).map(t => ({ value: `global:${t.id}`, label: `${t.name || t.host} (global)` })),
  ];
  const noTargets = attackerTargets !== null && allTargets.length === 0;
  const bulkCreds = useMemo(() => {
    return (creds || []).filter((cred) => {
      if (cred.pid !== selectedProject) return false;
      return selectedHosts.some((host) => {
        const hostDomain = normalizeDomain(host.domain || '');
        return (cred.host_ids || []).includes(host.id)
          || cred.host === host.ip
          || (host.hostname && cred.host === host.hostname)
          || (cred.is_domain && hostDomain && domainsMatch(cred.domain || '', hostDomain));
      });
    });
  }, [creds, selectedHosts, selectedProject]);
  const selectedCredential = bulkCreds.find(cred => cred.id === selectedCredentialId) || null;
  const bulkCredentialPacks = useMemo(() => getBulkCredentialPacks(selectedHosts, selectedCredential), [selectedCredential, selectedHosts]);

  return (
    <div style={{ padding: '14px 18px', borderBottom: `1px solid ${PALETTE.borderSoft}`, background: '#0a0c10', display: 'flex', flexDirection: 'column', gap: 10 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <span style={{ fontSize: 12, fontWeight: 600, color: '#e0e4ec', fontFamily: FONTS.display }}>Bulk Run</span>
        <span style={{ fontSize: 11, color: PALETTE.textFaint }}>→ {selectedIds.length} hosts</span>
        {!moduleOk && (
          <span style={{ fontSize: 10, color: PALETTE.warn, background: '#f09a3a18', border: '1px solid #f09a3a44', borderRadius: 4, padding: '2px 8px', fontFamily: FONTS.mono }}>
            ⚠ Attacker SSH module is disabled
          </span>
        )}
        {noTargets && moduleOk && (
          <span style={{ fontSize: 10, color: PALETTE.danger, background: '#cc223318', border: '1px solid #cc223344', borderRadius: 4, padding: '2px 8px', fontFamily: FONTS.mono }}>
            No attacker hosts configured
          </span>
        )}
        <button onClick={onClose} style={{ marginLeft: 'auto', background: 'transparent', border: 'none', cursor: 'pointer', color: PALETTE.textFaint, display: 'flex' }}>
          <Icon name="close" size={12} color="currentColor" />
        </button>
      </div>

      {/* Attacker host selector */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <span style={{ fontSize: 10, color: PALETTE.textFaint, fontFamily: FONTS.mono, whiteSpace: 'nowrap' }}>Run from:</span>
        <Select
          value={selectedAttacker}
          onChange={setSelectedAttacker}
          style={{ flex: 1 }}
          placeholder={allTargets.length === 0 ? '— no attacker hosts available —' : undefined}
          options={allTargets}
        />
      </div>

      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
        {Object.entries(BULK_TEMPLATES).map(([key, tpl]) => (
          <button key={key} onClick={() => pickTemplate(key)}
            style={{ background: templateKey === key ? `${acc}22` : '#13161f', border: `1px solid ${templateKey === key ? acc + '66' : '#1e2230'}`, borderRadius: 4, padding: '3px 10px', cursor: 'pointer', color: templateKey === key ? acc : PALETTE.textFaint, fontSize: 11, fontFamily: FONTS.mono, fontWeight: 600 }}>
            {tpl.label}
          </button>
        ))}
        <input
          type="number" min={5} max={300} value={timeoutSec}
          onChange={e => setTimeoutSec(Number(e.target.value))}
          style={{ width: 60, background: '#13161f', border: '1px solid #1e2230', borderRadius: 4, padding: '3px 8px', color: PALETTE.textMute, fontSize: 11, fontFamily: FONTS.mono, outline: 'none' }}
          title="Timeout (seconds)"
        />
        <span style={{ fontSize: 10, color: PALETTE.textGhost }}>sec</span>
      </div>

      <Select value={selectedCredentialId} onChange={setSelectedCredentialId} style={{ width: '100%' }}
        placeholder="— no credential selected —"
        options={bulkCreds.map(cred => ({ value: cred.id, label: `${cred.username}${cred.domain ? `@${cred.domain}` : ''} · ${cred.type}` }))} />

      {selectedCredential && bulkCredentialPacks.length > 0 && (
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
          {bulkCredentialPacks.map((pack) => (
            <button key={pack.id} onClick={() => { setTemplateKey(pack.id); setCommand(pack.cmd); }} style={{ background: command === pack.cmd ? '#cc223322' : '#13161f', border: `1px solid ${command === pack.cmd ? '#cc223366' : '#1e2230'}`, borderRadius: 4, padding: '3px 10px', cursor: 'pointer', color: command === pack.cmd ? '#cc2233' : '#808590', fontSize: 11, fontFamily: FONTS.mono, fontWeight: 600 }}>
              {pack.label}
            </button>
          ))}
        </div>
      )}

      <div style={{ display: 'flex', gap: 8 }}>
        <input
          value={command} onChange={e => setCommand(e.target.value)}
          placeholder="nmap -sV {target} — supports {target}, {{USER}}, {{PASS}}, {{DOMAIN}}, {{HASH}}"
          style={{ flex: 1, background: PALETTE.bg3, border: `1px solid ${acc}44`, borderRadius: 4, padding: '6px 10px', color: '#c8cfe0', fontSize: 12, outline: 'none', fontFamily: FONTS.mono }}
        />
        <button onClick={run} disabled={running || !moduleOk || !command.trim() || !selectedAttacker || noTargets}
          style={{ background: (moduleOk && command.trim() && selectedAttacker && !noTargets) ? acc : '#1e2230', border: 'none', borderRadius: 4, padding: '6px 16px', cursor: 'pointer', color: '#fff', fontSize: 12, fontWeight: 600, fontFamily: FONTS.mono, opacity: running ? 0.7 : 1 }}>
          {running ? 'Running…' : `Run on ${selectedIds.length} hosts`}
        </button>
      </div>

      <div style={{ fontSize: 10, color: PALETTE.textGhost, fontFamily: FONTS.mono }}>
        Targets: {selectedHosts.slice(0, 6).map(h => h.ip || h.hostname).join(', ')}{selectedHosts.length > 6 ? ` +${selectedHosts.length - 6} more` : ''}
      </div>

      {summary && (
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          <span style={{ fontSize: 10, color: PALETTE.textMute, background: PALETTE.bg3, border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '3px 8px', fontFamily: FONTS.mono }}>{summary.total} total</span>
          <span style={{ fontSize: 10, color: PALETTE.ok, background: '#39d35318', border: '1px solid #39d35333', borderRadius: 4, padding: '3px 8px', fontFamily: FONTS.mono }}>{summary.ok} ran</span>
          <span style={{ fontSize: 10, color: '#5b8af5', background: '#5b8af518', border: '1px solid #5b8af533', borderRadius: 4, padding: '3px 8px', fontFamily: FONTS.mono }}>{summary.successful_auth} success</span>
          <span style={{ fontSize: 10, color: PALETTE.warn, background: '#f09a3a18', border: '1px solid #f09a3a33', borderRadius: 4, padding: '3px 8px', fontFamily: FONTS.mono }}>{summary.state_updates} state updates</span>
          <span style={{ fontSize: 10, color: PALETTE.ok, background: '#39d35318', border: '1px solid #39d35333', borderRadius: 4, padding: '3px 8px', fontFamily: FONTS.mono }}>{summary.graph_updates || 0} graph updates</span>
          {summary.access_role && <span style={{ fontSize: 10, color: '#c07af0', background: '#c07af018', border: '1px solid #c07af033', borderRadius: 4, padding: '3px 8px', fontFamily: FONTS.mono }}>role: {summary.access_role}</span>}
        </div>
      )}

      {results && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4, maxHeight: 200, overflowY: 'auto' }}>
          {results.map((r, i) => {
            const rBg = resultBg(r);
            const rBorder = resultBorder(r);
            return (
            <div key={`result-${i}-${r.ip || r.error || ''}`} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '4px 8px', background: rBg, border: `1px solid ${rBorder}`, borderRadius: 4 }}>
              <span style={{ fontSize: 10, color: r.ok ? '#39d353' : PALETTE.danger, fontFamily: FONTS.mono, minWidth: 16 }}>{r.ok ? '✓' : '✗'}</span>
              <span style={{ fontSize: 10, color: PALETTE.textMute, fontFamily: FONTS.mono, flex: 1 }}>{r.ip || r.error || '?'}</span>
              {r.exit_code !== undefined && <span style={{ fontSize: 9, color: PALETTE.textGhost, fontFamily: FONTS.mono }}>exit {r.exit_code}</span>}
            </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

BulkRunPanel.propTypes = {
  selectedIds: PropTypes.array,
  hosts: PropTypes.array,
  creds: PropTypes.array,
  selectedProject: PropTypes.object,
  accent: PropTypes.string,
  onClose: PropTypes.func,
};
