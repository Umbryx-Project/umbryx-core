import { useState, useMemo, useEffect } from 'react';
import PropTypes from 'prop-types';
import Icon from '../../components/Icon.jsx';
import { api } from '../../api.js';
import { domainsMatch } from '../../utils/hostMeta.js';
import { PALETTE, FONTS, Checkbox, Select } from '../../components/UI.jsx';

const isWindows = h => h.os === 'Windows' || (h.os || '').toLowerCase().includes('windows');

export default function ValidateCredPanel({ cred, projectHosts, selectedProject, accent, onClose }) {
  const [moduleOk, setModuleOk] = useState(null);
  const [attackerTargets, setAttackerTargets] = useState(null);
  const [selectedAttacker, setSelectedAttacker] = useState('');
  const [service, setService] = useState('auto');
  const [selectedHostIds, setSelectedHostIds] = useState([]);
  const [running, setRunning] = useState(false);
  const [results, setResults] = useState(null);
  const acc = accent || '#5b8af5';

  const { confirmed, predicted } = useMemo(() => {
    const conf = projectHosts.filter(h => (cred.host_ids || []).includes(h.id));
    const credDomain = (cred.domain || '').toLowerCase().replace(/^\./, '');
    const pred = cred.is_domain
      ? projectHosts.filter(h => !conf.some(c => c.id === h.id) && isWindows(h) &&
          h.domain && domainsMatch(h.domain, credDomain))
      : [];
    return { confirmed: conf, predicted: pred };
  }, [cred, projectHosts]);

  const availableHosts = [...confirmed, ...predicted, ...projectHosts.filter(h =>
    !confirmed.some(c => c.id === h.id) && !predicted.some(p => p.id === h.id)
  )];

  useEffect(() => {
    setSelectedHostIds([...confirmed.map(h => h.id), ...predicted.map(h => h.id)]);
    setResults(null);
    api.listModules().then(({ modules }) => {
      const m = (modules || []).find(m => m.name === 'attacker_ssh');
      setModuleOk(m ? m.enabled !== false : false);
    }).catch(() => setModuleOk(false));
    api.listAttackerExecutionTargets(selectedProject).then(data => {
      setAttackerTargets(data);
      if (data.project_hosts?.length > 0) setSelectedAttacker(`project:${data.project_hosts[0].id}`);
      else if (data.global_targets?.length > 0) setSelectedAttacker(`global:${data.global_targets[0].id}`);
    }).catch(() => {});
  }, [cred.id, selectedProject]);

  const toggle = (id) => setSelectedHostIds(prev =>
    prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]
  );

  const run = async () => {
    if (!selectedHostIds.length) return;
    setRunning(true);
    setResults(null);
    try {
      const [atkType, atkId] = (selectedAttacker || '').split(':');
      const res = await api.validateCred(selectedProject, cred.id, {
        host_ids: selectedHostIds,
        service,
        timeout_seconds: 15,
        attacker_host_id: atkType === 'project' ? atkId : undefined,
        attacker_target_id: atkType === 'global' ? atkId : undefined,
      });
      setResults(res.results || []);
    } catch (e) {
      setResults([{ error: e.message || 'Request failed', ok: false }]);
    }
    setRunning(false);
  };

  const hostById = useMemo(() => new Map(projectHosts.map(h => [h.id, h])), [projectHosts]);

  return (
    <div style={{ background: '#0a0c12', border: `1px solid ${acc}33`, borderRadius: 6, padding: 12, marginTop: 10 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
        <span style={{ fontSize: 11, fontWeight: 600, color: acc, fontFamily: FONTS.display }}>Validate credential</span>
        {!moduleOk && (
          <span style={{ fontSize: 9, color: PALETTE.warn, background: '#f09a3a18', border: '1px solid #f09a3a44', borderRadius: 3, padding: '1px 6px', fontFamily: FONTS.mono }}>
            Attacker SSH disabled
          </span>
        )}
        <button onClick={onClose} style={{ marginLeft: 'auto', background: 'none', border: 'none', cursor: 'pointer', display: 'flex' }}>
          <Icon name="close" size={11} color="#606570" />
        </button>
      </div>

      <div style={{ marginBottom: 8 }}>
        <div style={{ fontSize: 9, color: '#505560', textTransform: 'uppercase', marginBottom: 5 }}>Service</div>
        <div style={{ display: 'flex', gap: 4 }}>
          {[['auto', 'Auto'], ['ssh', 'SSH'], ['smb', 'SMB'], ['winrm', 'WinRM'], ['mssql', 'MSSQL'], ['ldap', 'LDAP'], ['rdp', 'RDP']].map(([v, l]) => (
            <button key={v} onClick={() => setService(v)}
              style={{ background: service === v ? `${acc}22` : PALETTE.bg3, border: `1px solid ${service === v ? acc + '66' : PALETTE.border}`, borderRadius: 3, padding: '3px 10px', cursor: 'pointer', color: service === v ? acc : PALETTE.textFaint, fontSize: 10, fontFamily: FONTS.mono }}>
              {l}
            </button>
          ))}
        </div>
      </div>

      {attackerTargets && (() => {
        const allTargets = [
          ...(attackerTargets.project_hosts || []).map(h => ({ value: `project:${h.id}`, label: `${h.ip || h.hostname || 'attacker'} (project)` })),
          ...(attackerTargets.global_targets || []).map(t => ({ value: `global:${t.id}`, label: `${t.host || t.label || 'global'} (global)` })),
        ];
        if (!allTargets.length) return null;
        return (
          <div style={{ marginBottom: 8 }}>
            <div style={{ fontSize: 9, color: '#505560', textTransform: 'uppercase', marginBottom: 5 }}>Run from</div>
            <Select value={selectedAttacker} onChange={setSelectedAttacker}
              style={{ width: '100%' }} options={allTargets} />
          </div>
        );
      })()}

      <div style={{ marginBottom: 10 }}>
        <div style={{ fontSize: 9, color: '#505560', textTransform: 'uppercase', marginBottom: 5 }}>
          Target hosts ({selectedHostIds.length} selected)
        </div>
        <div style={{ maxHeight: 160, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 3 }}>
          {availableHosts.map(h => {
            const isConf = confirmed.some(c => c.id === h.id);
            const isPred = predicted.some(p => p.id === h.id);
            const isSelected = selectedHostIds.includes(h.id);
            const resultForHost = results?.find(r => r.host_id === h.id);
            return (
              <div key={h.id} style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '4px 6px', borderRadius: 4, background: isSelected ? `${acc}10` : 'transparent', border: `1px solid ${isSelected ? acc + '33' : PALETTE.borderSoft}` }}>
                <Checkbox checked={isSelected} onChange={() => toggle(h.id)} accent={acc} />
                <span style={{ fontSize: 10, color: PALETTE.textMute, fontFamily: FONTS.mono, flex: 1 }}>
                  {h.ip}{h.hostname ? ` (${h.hostname})` : ''}
                </span>
                {isConf && <span style={{ fontSize: 8, color: PALETTE.ok, background: '#39d35318', borderRadius: 2, padding: '1px 4px' }}>linked</span>}
                {isPred && <span style={{ fontSize: 8, color: '#c07af0', background: '#c07af018', borderRadius: 2, padding: '1px 4px' }}>domain</span>}
                {resultForHost && (
                  <span style={{ fontSize: 9, fontWeight: 600, color: resultForHost.ok ? '#39d353' : PALETTE.danger }}>
                    {resultForHost.ok ? '✓' : '✗'}
                  </span>
                )}
              </div>
            );
          })}
          {availableHosts.length === 0 && (
            <div style={{ fontSize: 10, color: PALETTE.textGhost, fontStyle: 'italic' }}>No hosts in project</div>
          )}
        </div>
      </div>

      <button onClick={run} disabled={running || !moduleOk || !selectedHostIds.length}
        style={{ width: '100%', background: moduleOk && selectedHostIds.length ? acc : PALETTE.borderSoft, border: 'none', borderRadius: 4, padding: '7px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: FONTS.mono, opacity: running ? 0.7 : 1 }}>
        {(() => {
          if (running) return 'Validating…';
          const plural = selectedHostIds.length === 1 ? '' : 's';
          return `Test on ${selectedHostIds.length} host${plural}`;
        })()}
      </button>

      {results && (
        <div style={{ marginTop: 8, display: 'flex', flexDirection: 'column', gap: 4 }}>
          {results.map((r, i) => {
            const h = hostById.get(r.host_id);
            return (
              <div key={r.host_id || i} style={{ padding: '5px 8px', background: r.ok ? '#39d35312' : '#cc223312', border: `1px solid ${r.ok ? '#39d35333' : '#cc223333'}`, borderRadius: 4, fontSize: 10, fontFamily: FONTS.mono }}>
                <span style={{ color: r.ok ? '#39d353' : PALETTE.danger, fontWeight: 600 }}>{r.ok ? '✓ valid' : '✗ failed'}</span>
                <span style={{ color: '#808590', marginLeft: 8 }}>{r.ip || (h && (h.ip || h.hostname)) || '?'}</span>
                {r.service && <span style={{ color: '#505560', marginLeft: 6 }}>({r.service})</span>}
                {r.error && <span style={{ color: PALETTE.warn, marginLeft: 6 }}>{r.error}</span>}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

ValidateCredPanel.propTypes = {
  cred: PropTypes.object,
  projectHosts: PropTypes.array,
  selectedProject: PropTypes.string,
  accent: PropTypes.string,
  onClose: PropTypes.func,
};
