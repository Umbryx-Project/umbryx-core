import PropTypes from 'prop-types';
import { useState, useRef, useEffect, useMemo } from 'react';
import Icon from './Icon.jsx';
import { parseNmapXml, parseApsHtml, parseNetexecText } from '../utils/parsers.js';
import { parseScan } from './NmapParser.jsx';
import BloodHoundParser from './BloodHoundParser.jsx';
import { api } from '../api.js';
import { PALETTE, FONTS, Checkbox } from './UI.jsx';

const MODES = [
  {
    id: 'nmap',
    label: 'Nmap',
    icon: 'terminal',
    desc: 'paste scan output (-oN / -oG / XML) or upload .xml — format detected automatically',
    color: PALETTE.ok,
    inputType: 'both',
    accept: '.xml',
  },
  {
    id: 'bloodhound',
    label: 'BloodHound',
    icon: 'blood',
    desc: 'SharpHound / BloodHound JSON or ZIP collection',
    color: PALETTE.danger,
    inputType: 'custom',
  },
  {
    id: 'aps',
    label: 'Advanced Port Scanner',
    icon: 'hosts',
    desc: 'HTML report from APS',
    color: '#5b8af5',
    inputType: 'file',
    accept: '.html,.htm',
  },
  {
    id: 'netexec',
    label: 'NetExec / CME',
    icon: 'bolt',
    desc: 'Paste netexec or crackmapexec output',
    color: PALETTE.warn,
    inputType: 'text',
  },
];

const TABS_NAV = [
  { id: 'parsers', label: 'Parsers' },
  { id: 'scanners', label: 'Scanners' },
];

async function _doNessusImport(projectId, nessusFile, setNessusLoading, setNessusError, setNessusResult, onImported) {
  if (!nessusFile) return;
  setNessusLoading(true);
  setNessusError('');
  setNessusResult(null);
  try {
    const res = await api.importNessus(projectId, nessusFile);
    setNessusResult(res);
    onImported();
  } catch (e) {
    setNessusError(e.message || 'Import failed');
  } finally {
    setNessusLoading(false);
  }
}

async function _doBurpImport(projectId, burpFile, setBurpLoading, setBurpError, setBurpResult, onImported) {
  if (!burpFile) return;
  setBurpLoading(true);
  setBurpError('');
  setBurpResult(null);
  try {
    const res = await api.importBurp(projectId, burpFile);
    setBurpResult(res);
    onImported();
  } catch (e) {
    setBurpError(e.message || 'Import failed');
  } finally {
    setBurpLoading(false);
  }
}

async function _doParse(mode, fileRef, text, setError, setPreview, setResult) {
  setError('');
  setPreview(null);
  setResult(null);
  try {
    const parsed = await parseFileInput(mode, fileRef, text);
    validateParsed(parsed);
    setPreview(parsed);
  } catch (e) {
    setError('Parse error: ' + e.message);
  }
}

async function _doImport(projectId, preview, setLoading, setError, setResult, onImported, scopeOnly) {
  if (!preview) return;
  setLoading(true);
  setError('');
  try {
    const body = {
      hosts: preview.hosts.map(h => ({ ...h, pid: projectId })),
      creds: preview.creds.map(c => ({ ...c, pid: projectId })),
      scope_only: scopeOnly || false,
    };
    const res = await api.batchImport(projectId, body);
    setResult(res);
    onImported();
  } catch (e) {
    setError('Import error: ' + e.message);
  } finally {
    setLoading(false);
  }
}

function _ipInScope(ip, cidrs) {
  if (!ip || !cidrs.length) return false;
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(n => isNaN(n))) return false;
  const ipNum = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
  for (const cidr of cidrs) {
    const [base, bits] = cidr.split('/');
    const bParts = base.split('.').map(Number);
    if (bParts.length !== 4) continue;
    const baseNum = (bParts[0] << 24) | (bParts[1] << 16) | (bParts[2] << 8) | bParts[3];
    const mask = bits && Number(bits) > 0 ? (-1 << (32 - Number(bits))) >>> 0 : 0xFFFFFFFF;
    if ((ipNum & mask) === (baseNum & mask)) return true;
  }
  return false;
}

async function parseFileInput(mode, fileRef, text) {
  const currentMode = MODES.find(m => m.id === mode);
  if (currentMode.inputType === 'file') {
    const file = fileRef.current?.files?.[0];
    if (!file) throw new Error('Select a file');
    const content = await file.text();
    return parseApsHtml(content);
  }
  if (mode === 'nmap') {
    // file wins if both are filled; text paste is the quick path.
    // parseScan auto-detects XML / -oG grepable / -oN text.
    const file = fileRef.current?.files?.[0];
    const content = file ? await file.text() : (text || '');
    if (!content.trim()) throw new Error('Paste scan output or select an .xml file');
    const parsed = parseScan(content);
    // same shape as every other mode ({hosts, creds}) — returning the
    // bare array broke the preview (preview.hosts undefined; found by
    // the ImportModal paste test)
    return { hosts: parsed.hosts, creds: [] };
  }
  if (!text.trim()) throw new Error('Enter text');
  return parseNetexecText(text);
}

function validateParsed(parsed) {
  if (parsed.hosts.length === 0 && parsed.creds.length === 0) {
    throw new Error('Nothing found in data. Check the format.');
  }
}

const NODE_STATUS_COLOR = {
  unknown: PALETTE.textGhost, alive: '#5b8af5', scanned: '#c07af0',
  access: PALETTE.warn, pwned: PALETTE.danger, owned: PALETTE.ok,
};

const SPINNER_STYLE = { width: 10, height: 10, border: '2px solid #ffffff44', borderTopColor: '#fff', borderRadius: '50%', animation: 'spin 0.7s linear infinite', display: 'inline-block' };

function ScannerCard({ title, iconName, iconColor, desc, file, onFileChange, loading, result, error, fileRef, accept, onImport, importLabel, accent }) {
  const canImport = file && !loading;
  return (
    <div style={{ background: PALETTE.bg2, border: '1px solid #1e2029', borderRadius: 8, padding: 16, display: 'flex', flexDirection: 'column', gap: 10 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <Icon name={iconName} size={14} color={iconColor} />
        <span style={{ fontSize: 13, fontWeight: 600, color: '#e0e4ec', fontFamily: FONTS.display }}>{title}</span>
      </div>
      <div style={{ fontSize: 10, color: PALETTE.textFaint }}>{desc}</div>
      <label style={{ display: 'flex', alignItems: 'center', gap: 8, background: '#0a0c10', border: `1px dashed ${PALETTE.border}`, borderRadius: 6, padding: '10px 12px', cursor: 'pointer' }}
        onMouseEnter={e => e.currentTarget.style.borderColor = '#404550'}
        onMouseLeave={e => e.currentTarget.style.borderColor = '#2a2d35'}>
        <Icon name="export" size={13} color="#404550" />
        <div style={{ minWidth: 0 }}>
          <div style={{ fontSize: 10, color: file ? '#c8cdd6' : '#808590', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {file ? file.name : `Select ${accept} file`}
          </div>
        </div>
        <input ref={fileRef} type="file" accept={accept} style={{ display: 'none' }}
          onChange={onFileChange} />
      </label>
      {error && <div style={{ fontSize: 10, color: PALETTE.danger, background: '#cc223318', border: '1px solid #cc223344', borderRadius: 5, padding: '6px 10px' }}>{error}</div>}
      {result && (
        <div style={{ fontSize: 10, color: PALETTE.ok, background: '#39d35318', border: '1px solid #39d35344', borderRadius: 5, padding: '6px 10px' }}>
          Imported: {result.hosts_created ?? result.hosts_added ?? '?'} hosts, {result.findings_created ?? result.findings_added ?? '?'} findings
        </div>
      )}
      <button onClick={onImport} disabled={!canImport}
        style={{ background: canImport ? accent : '#1e2029', border: 'none', borderRadius: 6, padding: '7px 14px', cursor: canImport ? 'pointer' : 'not-allowed', color: canImport ? '#fff' : PALETTE.textGhost, fontSize: 11, fontWeight: 600, fontFamily: FONTS.mono, display: 'flex', alignItems: 'center', gap: 6, transition: 'all .15s' }}>
        {loading ? <><span style={SPINNER_STYLE} /> Importing...</> : importLabel}
      </button>
    </div>
  );
}
ScannerCard.propTypes = {
  title: PropTypes.any,
  iconName: PropTypes.any,
  iconColor: PropTypes.any,
  desc: PropTypes.any,
  file: PropTypes.any,
  onFileChange: PropTypes.any,
  loading: PropTypes.any,
  result: PropTypes.any,
  error: PropTypes.any,
  fileRef: PropTypes.any,
  accept: PropTypes.any,
  onImport: PropTypes.any,
  importLabel: PropTypes.any,
  accent: PropTypes.any,
};

const FW_ERR_STYLE = { fontSize: 10, color: PALETTE.danger, background: '#cc223318', border: '1px solid #cc223344', borderRadius: 5, padding: '6px 10px' };

function _fwBtnStyle(accent, enabled) {
  return { background: enabled ? accent : '#1e2029', border: 'none', borderRadius: 6, padding: '7px 14px', cursor: enabled ? 'pointer' : 'not-allowed', color: enabled ? '#fff' : PALETTE.textGhost, fontSize: 11, fontWeight: 600, fontFamily: FONTS.mono, display: 'flex', alignItems: 'center', gap: 6, alignSelf: 'flex-start' };
}

function FirewallConfigStat({ value, label, color }) {
  return (
    <div style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 6, padding: '8px 10px', minWidth: 64 }}>
      <div style={{ fontSize: 16, fontWeight: 700, color, fontFamily: FONTS.display }}>{value}</div>
      <div style={{ fontSize: 9, color: PALETTE.textFaint }}>{label}</div>
    </div>
  );
}
FirewallConfigStat.propTypes = { value: PropTypes.any, label: PropTypes.any, color: PropTypes.any };

function FirewallConfigDiffPanel({ diff }) {
  if (!diff || Object.keys(diff).length === 0) return null;
  if (!diff.has_changes) {
    return <div style={{ fontSize: 10, color: PALETTE.textFaint }}>No changes since the previous upload for this device.</div>;
  }
  const rows = [
    ['ACL rules added', diff.added_acl_rules?.length || 0],
    ['ACL rules removed', diff.removed_acl_rules?.length || 0],
    ['NAT rules added', diff.added_nat_rules?.length || 0],
    ['NAT rules removed', diff.removed_nat_rules?.length || 0],
    ['Interfaces added', diff.added_interfaces?.length || 0],
    ['Interfaces removed', diff.removed_interfaces?.length || 0],
  ].filter(([, n]) => n > 0);
  return (
    <div style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 6, padding: '8px 12px', fontSize: 10, color: PALETTE.textMute }}>
      <div style={{ color: PALETTE.textGhost, textTransform: 'uppercase', letterSpacing: '0.1em', fontSize: 9, marginBottom: 6 }}>Diff vs. previous upload</div>
      {rows.map(([label, n]) => (
        <div key={label} style={{ display: 'flex', justifyContent: 'space-between', padding: '2px 0' }}>
          <span>{label}</span><span style={{ color: PALETTE.textDim, fontFamily: FONTS.mono }}>{n}</span>
        </div>
      ))}
    </div>
  );
}
FirewallConfigDiffPanel.propTypes = { diff: PropTypes.any };

function FirewallConfigPublicIpBanner({ publicIps }) {
  if (!publicIps || publicIps.length === 0) return null;
  return (
    <div style={{ background: '#f09a3a18', border: '1px solid #f09a3a44', borderRadius: 6, padding: '8px 12px', fontSize: 10, color: PALETTE.warn, display: 'flex', flexDirection: 'column', gap: 3 }}>
      <div style={{ fontWeight: 600 }}>{publicIps.length} public IP{publicIps.length > 1 ? 's' : ''} detected — external attack surface</div>
      <div style={{ color: '#d9a15f', fontFamily: FONTS.mono }}>{publicIps.join(', ')}</div>
      <div style={{ color: PALETTE.textMute }}>These subnets will be marked in-scope automatically on apply.</div>
    </div>
  );
}
FirewallConfigPublicIpBanner.propTypes = { publicIps: PropTypes.array };

function FirewallConfigPreviewPanel({ preview, onApply, onBack, applying, accent }) {
  const { counts, planned, diff, vendor, display_name, hostname, public_ips } = preview;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      <div style={{ fontSize: 11, color: PALETTE.textDim }}>
        Detected vendor: <strong style={{ color: accent }}>{display_name || vendor}</strong>
        {hostname ? <> · device hostname: <strong style={{ color: PALETTE.textDim }}>{hostname}</strong></> : null}
      </div>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        <FirewallConfigStat value={counts.interfaces} label="interfaces" color="#5b8af5" />
        <FirewallConfigStat value={counts.acl_rules} label="ACL rules" color="#c07af0" />
        <FirewallConfigStat value={counts.nat_rules} label="NAT rules" color="#f09a3a" />
        <FirewallConfigStat value={counts.routes} label="routes" color="#39d353" />
        <FirewallConfigStat value={counts.vlans} label="VLANs" color="#5b8af5" />
        <FirewallConfigStat value={counts.local_users} label="local users" color="#9098a8" />
        {counts.arp_entries > 0 && <FirewallConfigStat value={counts.arp_entries} label="ARP entries" color="#22d3ee" />}
        {counts.dhcp_leases > 0 && <FirewallConfigStat value={counts.dhcp_leases} label="DHCP leases" color="#22d3ee" />}
      </div>
      <FirewallConfigPublicIpBanner publicIps={public_ips} />
      <div style={{ background: PALETTE.bg2, border: '1px solid #1e2029', borderRadius: 6, padding: '8px 12px', fontSize: 10, color: PALETTE.textMute, display: 'flex', flexDirection: 'column', gap: 3 }}>
        <div>{planned.host_created ? 'New device host will be created' : 'Existing device host will be updated'}</div>
        <div>{planned.networks_created} new / {planned.networks_existing} existing subnet(s) in scope</div>
        <div>{planned.findings_created} new finding(s) ({planned.findings_skipped} already tracked)</div>
        <div>{planned.creds_created} new credential(s) will be stored encrypted ({planned.creds_skipped} already tracked)</div>
        {(planned.hosts_discovered > 0 || planned.hosts_enriched > 0) && (
          <div>{planned.hosts_discovered} host(s) discovered via ARP/DHCP, {planned.hosts_enriched} existing host(s) enriched (MAC/hostname)</div>
        )}
      </div>
      <FirewallConfigDiffPanel diff={diff} />
      <div style={{ display: 'flex', gap: 8 }}>
        <button onClick={onApply} disabled={applying} style={_fwBtnStyle(accent, !applying)}>
          <Icon name="export" size={12} color="#fff" /> {applying ? 'Applying...' : 'Apply'}
        </button>
        <button onClick={onBack} disabled={applying}
          style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 6, padding: '7px 14px', cursor: applying ? 'not-allowed' : 'pointer', color: PALETTE.textFaint, fontSize: 11, fontFamily: FONTS.mono }}>
          Back
        </button>
      </div>
    </div>
  );
}
FirewallConfigPreviewPanel.propTypes = { preview: PropTypes.any, onApply: PropTypes.any, onBack: PropTypes.any, applying: PropTypes.bool, accent: PropTypes.any };

function FirewallConfigDoneStatus({ job, onClose, accent }) {
  const failed = job.status === 'failed' || job.status === 'cancelled';
  const r = job.result_json || {};
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      {failed ? (
        <div style={FW_ERR_STYLE}>{job.error_output || `Job ${job.status}`}</div>
      ) : (
        <div style={{ fontSize: 10, color: PALETTE.ok, background: '#39d35318', border: '1px solid #39d35344', borderRadius: 5, padding: '8px 10px' }}>
          Applied — {r.networks_created ?? 0} networks, {r.findings_created ?? 0} findings, {r.creds_created ?? 0} creds
          {r.has_changes === false ? ' · no changes vs. previous upload' : ''}
        </div>
      )}
      <button onClick={onClose} style={_fwBtnStyle(accent, true)}>Upload another</button>
    </div>
  );
}
FirewallConfigDoneStatus.propTypes = { job: PropTypes.any, onClose: PropTypes.any, accent: PropTypes.any };

function FirewallConfigCard({ projectId, onImported, accent }) {
  const [file, setFile] = useState(null);
  const [stage, setStage] = useState('idle'); // idle | previewing | preview | applying | polling | done
  const [preview, setPreview] = useState(null);
  const [error, setError] = useState('');
  const [job, setJob] = useState(null);
  const fileRef = useRef();
  const pollRef = useRef(null);

  useEffect(() => () => { if (pollRef.current) clearTimeout(pollRef.current); }, []);

  const onFileChange = e => {
    setFile(e.target.files?.[0] || null);
    setPreview(null);
    setError('');
    setJob(null);
    setStage('idle');
  };

  const doPreview = async () => {
    if (!file) return;
    setError('');
    setStage('previewing');
    try {
      const res = await api.firewallConfigPreview(projectId, file);
      setPreview(res);
      setStage('preview');
    } catch (e) {
      setError(e.message || 'Preview failed');
      setStage('idle');
    }
  };

  const pollJob = jobId => {
    const tick = async () => {
      try {
        const j = await api.getJob(projectId, jobId);
        setJob(j);
        if (['done', 'failed', 'cancelled'].includes(j.status)) {
          setStage('done');
          if (j.status === 'done') onImported();
          return;
        }
      } catch {
        // transient — keep polling
      }
      pollRef.current = setTimeout(() => tick(), 2000);
    };
    tick();
  };

  const doApply = async () => {
    if (!file) return;
    setError('');
    setStage('applying');
    try {
      const res = await api.firewallConfigApply(projectId, file);
      setJob({ id: res.job_id, status: 'queued' });
      setStage('polling');
      pollJob(res.job_id);
    } catch (e) {
      setError(e.message || 'Apply failed');
      setStage('preview');
    }
  };

  const reset = () => {
    if (pollRef.current) clearTimeout(pollRef.current);
    setFile(null); setPreview(null); setError(''); setJob(null); setStage('idle');
    if (fileRef.current) fileRef.current.value = '';
  };

  return (
    <div style={{ gridColumn: '1 / -1', background: PALETTE.bg2, border: '1px solid #1e2029', borderRadius: 8, padding: 16, display: 'flex', flexDirection: 'column', gap: 10 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <Icon name="shield" size={14} color="#f09a3a" />
        <span style={{ fontSize: 13, fontWeight: 600, color: '#e0e4ec', fontFamily: FONTS.display }}>Firewall / Router Config</span>
      </div>
      <div style={{ fontSize: 10, color: PALETTE.textFaint }}>
        Cisco IOS/IOS-XE, Cisco ASA, MikroTik RouterOS, Huawei VRP, Fortinet FortiOS, PaloAlto PAN-OS, UniFi (EdgeOS/USG) or pfSense — auto-detects vendor, parses interfaces/routes/ACL/NAT, flags public IPs as external attack surface, enriches hosts, networks, findings and credentials. Paste `show arp`/DHCP-lease command output into the same file to auto-discover hosts by MAC/hostname too — see docs/modules/FIREWALL_EXPORT_GUIDE.md for the exact command per vendor.
      </div>

      {(stage === 'idle' || stage === 'previewing') && (
        <>
          <label style={{ display: 'flex', alignItems: 'center', gap: 8, background: '#0a0c10', border: `1px dashed ${PALETTE.border}`, borderRadius: 6, padding: '10px 12px', cursor: 'pointer' }}>
            <Icon name="export" size={13} color="#404550" />
            <div style={{ fontSize: 10, color: file ? '#c8cdd6' : '#808590' }}>{file ? file.name : 'Select config file (.txt, .cfg, .conf, .rsc, .xml, .json)'}</div>
            <input ref={fileRef} type="file" accept=".txt,.cfg,.conf,.rsc,.xml,.json" style={{ display: 'none' }} onChange={onFileChange} />
          </label>
          {error && <div style={FW_ERR_STYLE}>{error}</div>}
          <button onClick={doPreview} disabled={!file || stage === 'previewing'} style={_fwBtnStyle(accent, !!file && stage !== 'previewing')}>
            {stage === 'previewing' ? <><span style={SPINNER_STYLE} /> Detecting & parsing...</> : 'Preview'}
          </button>
        </>
      )}

      {stage === 'preview' && preview && (
        <FirewallConfigPreviewPanel preview={preview} onApply={doApply} onBack={reset} applying={false} accent={accent} />
      )}

      {(stage === 'applying' || stage === 'polling') && (
        <div style={{ fontSize: 11, color: PALETTE.textFaint, display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={SPINNER_STYLE} />
          {stage === 'applying' ? 'Uploading...' : `Parsing & enriching project (${job?.status || 'queued'})...`}
        </div>
      )}

      {stage === 'done' && job && (
        <FirewallConfigDoneStatus job={job} onClose={reset} accent={accent} />
      )}
    </div>
  );
}
FirewallConfigCard.propTypes = { projectId: PropTypes.any, onImported: PropTypes.any, accent: PropTypes.any };

function _onNessusFileChange(e, setNessusFile, setNessusResult, setNessusError) {
  setNessusFile(e.target.files?.[0] || null);
  setNessusResult(null);
  setNessusError('');
}

function _onBurpFileChange(e, setBurpFile, setBurpResult, setBurpError) {
  setBurpFile(e.target.files?.[0] || null);
  setBurpResult(null);
  setBurpError('');
}

function ScannersTab({ nessusFile, setNessusFile, nessusLoading, nessusResult, setNessusResult, nessusError, setNessusError, nessusRef, doNessusImport, burpFile, setBurpFile, burpLoading, burpResult, setBurpResult, burpError, setBurpError, burpRef, doBurpImport, accent, projectId, onImported }) {
  const onNessusChange = e => _onNessusFileChange(e, setNessusFile, setNessusResult, setNessusError);
  const onBurpChange = e => _onBurpFileChange(e, setBurpFile, setBurpResult, setBurpError);
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
      <ScannerCard title="Nessus" iconName="target" iconColor="#e8574a" desc="Import .nessus XML scan report"
        file={nessusFile} onFileChange={onNessusChange} loading={nessusLoading} result={nessusResult} error={nessusError}
        fileRef={nessusRef} accept=".xml,.nessus" onImport={doNessusImport} importLabel="Import Nessus" accent={accent} />
      <ScannerCard title="Burp Suite" iconName="bug" iconColor="#f09a3a" desc="Import Burp Suite XML scan report"
        file={burpFile} onFileChange={onBurpChange} loading={burpLoading} result={burpResult} error={burpError}
        fileRef={burpRef} accept=".xml" onImport={doBurpImport} importLabel="Import Burp" accent={accent} />
      <FirewallConfigCard projectId={projectId} onImported={onImported} accent={accent} />
    </div>
  );
}
ScannersTab.propTypes = {
  nessusFile: PropTypes.any,
  setNessusFile: PropTypes.any,
  nessusLoading: PropTypes.any,
  nessusResult: PropTypes.any,
  setNessusResult: PropTypes.any,
  nessusError: PropTypes.any,
  setNessusError: PropTypes.any,
  nessusRef: PropTypes.any,
  doNessusImport: PropTypes.any,
  burpFile: PropTypes.any,
  setBurpFile: PropTypes.any,
  burpLoading: PropTypes.any,
  burpResult: PropTypes.any,
  setBurpResult: PropTypes.any,
  burpError: PropTypes.any,
  setBurpError: PropTypes.any,
  burpRef: PropTypes.any,
  doBurpImport: PropTypes.any,
  accent: PropTypes.any,
  projectId: PropTypes.any,
  onImported: PropTypes.any,
};

function ParsersInputArea({ currentMode, mode, fileRef, text, setText, setPreview, setError, setResult, error, parse, accent, projectId }) {
  if (currentMode.inputType === 'custom' && mode === 'bloodhound') {
    return (
      <BloodHoundParser
        embedded
        pid={projectId}
        accent={accent}
        onDone={() => globalThis.dispatchEvent(new Event('rt:refresh'))}
      />
    );
  }
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      {currentMode.inputType === 'file' ? (
        <div>
          <div style={{ fontSize: 9, color: PALETTE.textGhost, marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.1em' }}>File ({currentMode.accept})</div>
          <label style={{ display: 'flex', alignItems: 'center', gap: 10, background: '#0a0c10', border: `1px dashed ${PALETTE.border}`, borderRadius: 6, padding: '14px 16px', cursor: 'pointer', transition: 'border-color .15s' }}
            onMouseEnter={e => e.currentTarget.style.borderColor = '#404550'}
            onMouseLeave={e => e.currentTarget.style.borderColor = '#2a2d35'}>
            <Icon name="export" size={16} color="#404550" />
            <div>
              <div style={{ fontSize: 11, color: PALETTE.textMute }}>Click to select or drag and drop a file</div>
              <div style={{ fontSize: 9, color: PALETTE.textGhost, marginTop: 2 }}>{currentMode.accept}</div>
            </div>
            <input ref={fileRef} type="file" accept={currentMode.accept} style={{ display: 'none' }}
              onChange={() => { setPreview(null); setError(''); setResult(null); }} />
          </label>
          {fileRef.current?.files?.[0] && (
            <div style={{ fontSize: 10, color: PALETTE.textFaint, marginTop: 6, fontFamily: FONTS.mono }}>
              {fileRef.current.files[0].name} · {(fileRef.current.files[0].size / 1024).toFixed(1)} KB
            </div>
          )}
        </div>
      ) : currentMode.inputType === 'both' ? (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          <div>
            <div style={{ fontSize: 9, color: PALETTE.textGhost, marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Paste scan output (auto-detect: -oN / -oG / XML)</div>
            <textarea value={text}
              onChange={e => { setText(e.target.value); setPreview(null); setError(''); setResult(null); if (fileRef.current) fileRef.current.value = ''; }}
              placeholder={'# Nmap scan report for 10.10.10.5\nHost is up (0.001s latency).\nNot shown: 998 filtered tcp ports (no-response)\nPORT     STATE SERVICE\n22/tcp   open  ssh\n80/tcp   open  http\n\n— or -oG grepable —\nHost: 10.10.10.5 (srv)  Ports: 22/open/tcp//ssh///, 80/open/tcp//http///'}
              rows={9}
              style={{ width: '100%', background: '#080a0e', border: `1px solid ${PALETTE.border}`, borderRadius: 6, padding: '10px 12px', color: PALETTE.textDim, fontSize: 11, outline: 'none', fontFamily: FONTS.mono, lineHeight: 1.6, resize: 'vertical' }} />
          </div>
          <div>
            <div style={{ fontSize: 9, color: PALETTE.textGhost, marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.1em' }}>…or upload an .xml file</div>
            <label style={{ display: 'flex', alignItems: 'center', gap: 10, background: '#0a0c10', border: `1px dashed ${PALETTE.border}`, borderRadius: 6, padding: '10px 14px', cursor: 'pointer', transition: 'border-color .15s' }}
              onMouseEnter={e => e.currentTarget.style.borderColor = '#404550'}
              onMouseLeave={e => e.currentTarget.style.borderColor = '#2a2d35'}>
              <Icon name="export" size={14} color="#404550" />
              <div style={{ fontSize: 10, color: PALETTE.textMute }}>nmap -oX file (overrides the paste)</div>
              <input ref={fileRef} type="file" accept=".xml" style={{ display: 'none' }}
                onChange={() => { setPreview(null); setError(''); setResult(null); }} />
            </label>
          </div>
        </div>
      ) : (
        <div>
          <div style={{ fontSize: 9, color: PALETTE.textGhost, marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.1em' }}>
            Output {mode === 'netexec' ? 'netexec / crackmapexec' : mode}
          </div>
          <textarea value={text}
            onChange={e => { setText(e.target.value); setPreview(null); setError(''); }}
            placeholder={`SMB  10.10.14.5  445  WEB-01   [*] Windows 10.0 Build 19041 (name:WEB-01) (domain:CORP)\nSMB  10.10.14.5  445  WEB-01   [+] CORP\\administrator:Password123! (Pwn3d!)\nSMB  10.10.14.6  445  APP-01   [-] CORP\\administrator:Password123! STATUS_LOGON_FAILURE\nSSH  10.10.14.10 22   BACKEND  [+] deploy:secretkey`}
            rows={9}
            style={{ width: '100%', background: '#080a0e', border: `1px solid ${PALETTE.border}`, borderRadius: 6, padding: '10px 12px', color: PALETTE.textDim, fontSize: 11, outline: 'none', fontFamily: FONTS.mono, lineHeight: 1.6, resize: 'vertical' }} />
        </div>
      )}
      {error && (
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8, background: '#cc223318', border: '1px solid #cc223344', borderRadius: 6, padding: '10px 12px' }}>
          <Icon name="warning" size={13} color="#cc2233" style={{ flexShrink: 0, marginTop: 1 }} />
          <span style={{ fontSize: 11, color: PALETTE.danger, fontFamily: FONTS.mono }}>{error}</span>
        </div>
      )}
      <button onClick={parse}
        style={{ background: accent, border: 'none', borderRadius: 6, padding: '8px 18px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: FONTS.mono, display: 'flex', alignItems: 'center', gap: 7, alignSelf: 'flex-start', transition: 'opacity .1s' }}
        onMouseEnter={e => e.currentTarget.style.opacity = '.85'}
        onMouseLeave={e => e.currentTarget.style.opacity = '1'}>
        <Icon name="search" size={12} color="#fff" /> Parse
      </button>
    </div>
  );
}
ParsersInputArea.propTypes = {
  currentMode: PropTypes.any,
  mode: PropTypes.any,
  fileRef: PropTypes.any,
  text: PropTypes.any,
  setText: PropTypes.any,
  setPreview: PropTypes.any,
  setError: PropTypes.any,
  setResult: PropTypes.any,
  error: PropTypes.any,
  parse: PropTypes.any,
  accent: PropTypes.any,

  projectId: PropTypes.any,
};

function ParsersPreview({ preview, error, loading, doImport, setPreview, setError, accent }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ display: 'flex', gap: 10 }}>
        <div style={{ flex: 1, background: PALETTE.bg2, border: '1px solid #1e2029', borderRadius: 7, padding: '12px 14px' }}>
          <div style={{ fontSize: 22, fontWeight: 700, color: '#c07af0', fontFamily: FONTS.display }}>{preview.hosts.length}</div>
          <div style={{ fontSize: 10, color: PALETTE.textFaint, marginTop: 2 }}>hosts to import</div>
        </div>
        <div style={{ flex: 1, background: PALETTE.bg2, border: '1px solid #1e2029', borderRadius: 7, padding: '12px 14px' }}>
          <div style={{ fontSize: 22, fontWeight: 700, color: PALETTE.ok, fontFamily: FONTS.display }}>{preview.creds.length}</div>
          <div style={{ fontSize: 10, color: PALETTE.textFaint, marginTop: 2 }}>credentials</div>
        </div>
      </div>
      {preview.hosts.length > 0 && <HostsPreviewTable hosts={preview.hosts} />}
      {preview.creds.length > 0 && <CredsPreviewTable creds={preview.creds} />}
      {error && (
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 8, background: '#cc223318', border: '1px solid #cc223344', borderRadius: 6, padding: '10px 12px' }}>
          <Icon name="warning" size={13} color="#cc2233" />
          <span style={{ fontSize: 11, color: PALETTE.danger }}>{error}</span>
        </div>
      )}
      <div style={{ display: 'flex', gap: 8 }}>
        <button onClick={doImport} disabled={loading}
          style={{ background: accent, border: 'none', borderRadius: 6, padding: '8px 20px', cursor: loading ? 'wait' : 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: FONTS.mono, display: 'flex', alignItems: 'center', gap: 7, opacity: loading ? .7 : 1, transition: 'opacity .1s' }}
          onMouseEnter={e => !loading && (e.currentTarget.style.opacity = '.85')}
          onMouseLeave={e => { e.currentTarget.style.opacity = loading ? '.7' : '1'; }}>
          <Icon name="export" size={12} color="#fff" />
          {loading ? 'Importing...' : 'Import'}
        </button>
        <button onClick={() => { setPreview(null); setError(''); }}
          style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 6, padding: '8px 14px', cursor: 'pointer', color: PALETTE.textFaint, fontSize: 11, fontFamily: FONTS.mono }}>
          Back
        </button>
      </div>
    </div>
  );
}
ParsersPreview.propTypes = {
  preview: PropTypes.any,
  error: PropTypes.any,
  loading: PropTypes.any,
  doImport: PropTypes.any,
  setPreview: PropTypes.any,
  setError: PropTypes.any,
  accent: PropTypes.any,
};

function HostsPreviewTable({ hosts }) {
  return (
    <div style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 7, overflow: 'hidden' }}>
      <div style={{ padding: '8px 12px', borderBottom: '1px solid #1e2029', fontSize: 9, color: PALETTE.textGhost, textTransform: 'uppercase', letterSpacing: '0.1em' }}>
        Hosts ({Math.min(hosts.length, 8)} of {hosts.length})
      </div>
      <div style={{ maxHeight: 200, overflowY: 'auto' }}>
        {hosts.slice(0, 8).map((h) => {
          const statusColor = NODE_STATUS_COLOR[h.status] || '#404550';
          return (
            <div key={h.ip} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '6px 12px', borderBottom: '1px solid #14161b' }}>
              <span style={{ width: 7, height: 7, borderRadius: '50%', background: statusColor, flexShrink: 0 }} />
              <span style={{ fontFamily: FONTS.mono, fontSize: 11, color: PALETTE.textMute, width: 120, flexShrink: 0 }}>{h.ip}</span>
              <span style={{ fontSize: 10, color: PALETTE.textDim, width: 120, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{h.hostname || '—'}</span>
              <span style={{ fontSize: 9, color: '#505560' }}>{h.os}</span>
              <div style={{ display: 'flex', gap: 3, flex: 1, overflow: 'hidden' }}>
                {h.ports.slice(0, 5).map(p => (
                  <span key={p} style={{ fontSize: 9, color: statusColor, background: `${statusColor}11`, border: `1px solid ${statusColor}33`, borderRadius: 3, padding: '0 4px', fontFamily: FONTS.mono }}>{p}</span>
                ))}
                {h.ports.length > 5 && <span style={{ fontSize: 9, color: PALETTE.textGhost }}>+{h.ports.length - 5}</span>}
              </div>
            </div>
          );
        })}
        {hosts.length > 8 && <div style={{ padding: '6px 12px', fontSize: 9, color: PALETTE.textGhost, textAlign: 'center' }}>... {hosts.length - 8} more hosts</div>}
      </div>
    </div>
  );
}
HostsPreviewTable.propTypes = {
  hosts: PropTypes.any,
};

function CredsPreviewTable({ creds }) {
  return (
    <div style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 7, overflow: 'hidden' }}>
      <div style={{ padding: '8px 12px', borderBottom: '1px solid #1e2029', fontSize: 9, color: PALETTE.textGhost, textTransform: 'uppercase', letterSpacing: '0.1em' }}>
        Credentials
      </div>
      {creds.slice(0, 6).map((c) => (
        <div key={`${c.username}-${c.host}`} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '6px 12px', borderBottom: '1px solid #14161b' }}>
          <span style={{ fontSize: 11, color: '#e0e4ec', fontFamily: FONTS.mono, width: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{c.username}</span>
          <span style={{ fontSize: 10, color: '#5b8af5', fontFamily: FONTS.mono, width: 110 }}>{c.host}</span>
          <span style={{ fontSize: 9, color: PALETTE.textFaint }}>{c.service}</span>
          <span style={{ fontSize: 9, color: PALETTE.ok, marginLeft: 'auto' }}>✓ cracked</span>
        </div>
      ))}
      {creds.length > 6 && <div style={{ padding: '6px 12px', fontSize: 9, color: PALETTE.textGhost, textAlign: 'center' }}>... {creds.length - 6} more</div>}
    </div>
  );
}
CredsPreviewTable.propTypes = {
  creds: PropTypes.any,
};

function ParsersSuccess({ result, onClose, accent }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 16, padding: '20px 0' }}>
      <div style={{ width: 48, height: 48, borderRadius: '50%', background: '#39d35322', border: '1px solid #39d35366', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <Icon name="check" size={24} color="#39d353" />
      </div>
      <div style={{ textAlign: 'center' }}>
        <div style={{ fontSize: 15, fontWeight: 600, color: PALETTE.text, fontFamily: FONTS.display, marginBottom: 6 }}>Import complete</div>
        <div style={{ fontSize: 11, color: PALETTE.textFaint }}>
          Hosts added: <strong style={{ color: '#c07af0' }}>{result.hosts_added}</strong>
          {' · '}
          Credentials: <strong style={{ color: PALETTE.ok }}>{result.creds_added}</strong>
          {' · '}
          Duplicates — merged
        </div>
      </div>
      <button onClick={onClose}
        style={{ background: accent, border: 'none', borderRadius: 6, padding: '8px 24px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: FONTS.mono }}>
        Done
      </button>
    </div>
  );
}
ParsersSuccess.propTypes = {
  result: PropTypes.any,
  onClose: PropTypes.any,
  accent: PropTypes.any,
};

function ParsersTab({ mode, setMode, currentMode, fileRef, text, setText, preview, setPreview, error, setError, loading, result, setResult, doImport, parse, onClose, accent, scopeOnly, setScopeOnly, scopeCount, rawPreview, projectId }) {
  const resetMode = id => { setMode(id); setPreview(null); setError(''); setResult(null); setText(''); if (fileRef.current) fileRef.current.value = ''; };
  const showScopeToggle = scopeCount > 0 && rawPreview;
  return (
    <>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 8 }}>
        {MODES.map(m => (
          <button key={m.id} onClick={() => resetMode(m.id)}
            style={{ background: mode === m.id ? `${m.color}15` : '#12141a', border: `1px solid ${mode === m.id ? m.color + '66' : PALETTE.border}`, borderRadius: 7, padding: '10px 12px', cursor: 'pointer', textAlign: 'left', transition: 'all .15s' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 5 }}>
              <Icon name={m.icon} size={13} color={mode === m.id ? m.color : '#505560'} />
              <span style={{ fontSize: 11, fontWeight: 600, color: mode === m.id ? m.color : PALETTE.textMute, fontFamily: FONTS.mono }}>{m.label}</span>
            </div>
            <div style={{ fontSize: 9, color: PALETTE.textGhost, lineHeight: 1.4 }}>{m.desc}</div>
          </button>
        ))}
      </div>
      {showScopeToggle && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, background: PALETTE.bg2, border: `1px solid ${scopeOnly ? accent + '44' : '#1e2029'}`, borderRadius: 6, padding: '8px 12px', transition: 'border-color .15s' }}>
          <Checkbox checked={scopeOnly} onChange={setScopeOnly} accent={accent} label={<>
            <Icon name="target" size={12} color={scopeOnly ? accent : '#505560'} />
            <span style={{ fontSize: 11, color: scopeOnly ? '#c8cdd6' : '#505560', fontFamily: FONTS.mono, marginLeft: 6 }}>
              Only import in-scope hosts ({scopeCount} CIDR scope{scopeCount === 1 ? '' : 's'} defined)
            </span>
          </>} />
          {scopeOnly && preview?.skipped > 0 && (
            <span style={{ fontSize: 10, color: PALETTE.warn, fontFamily: FONTS.mono, marginLeft: 'auto' }}>
              {preview.skipped} out of scope
            </span>
          )}
        </div>
      )}
      {result && <ParsersSuccess result={result} onClose={onClose} accent={accent} />}
      {preview && !result && <ParsersPreview preview={preview} error={error} loading={loading} doImport={doImport} setPreview={setPreview} setError={setError} accent={accent} />}
      {!result && !preview && <ParsersInputArea currentMode={currentMode} mode={mode} fileRef={fileRef} text={text} setText={setText} setPreview={setPreview} setError={setError} setResult={setResult} error={error} parse={parse} accent={accent} projectId={projectId} />}
    </>
  );
}
ParsersTab.propTypes = {
  mode: PropTypes.any,
  setMode: PropTypes.any,
  currentMode: PropTypes.any,
  fileRef: PropTypes.any,
  text: PropTypes.any,
  setText: PropTypes.any,
  preview: PropTypes.any,
  setPreview: PropTypes.any,
  error: PropTypes.any,
  setError: PropTypes.any,
  loading: PropTypes.any,
  result: PropTypes.any,
  setResult: PropTypes.any,
  doImport: PropTypes.any,
  parse: PropTypes.any,
  onClose: PropTypes.any,
  accent: PropTypes.any,
  scopeOnly: PropTypes.bool,
  setScopeOnly: PropTypes.func,
  scopeCount: PropTypes.number,
  rawPreview: PropTypes.any,

  projectId: PropTypes.any,
};

export default function ImportModal({ projectId, onClose, onImported, accent }) {
  const [activeTab, setActiveTab] = useState('parsers');
  const [mode, setMode] = useState('nmap');
  const [text, setText] = useState('');
  const [preview, setPreview] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [scopeOnly, setScopeOnly] = useState(false);
  const [scopeCidrs, setScopeCidrs] = useState([]);
  const fileRef = useRef();

  const [nessusFile, setNessusFile] = useState(null);
  const [nessusLoading, setNessusLoading] = useState(false);
  const [nessusResult, setNessusResult] = useState(null);
  const [nessusError, setNessusError] = useState('');
  const [burpFile, setBurpFile] = useState(null);
  const [burpLoading, setBurpLoading] = useState(false);
  const [burpResult, setBurpResult] = useState(null);
  const [burpError, setBurpError] = useState('');
  const nessusRef = useRef();
  const burpRef = useRef();

  useEffect(() => {
    api.getScopes(projectId).then(rows => {
      const cidrs = (rows || [])
        .filter(r => r.in_scope && r.scope_type === 'cidr' && r.value)
        .map(r => r.value);
      setScopeCidrs(cidrs);
      if (cidrs.length > 0) setScopeOnly(true);
    }).catch(() => {});
  }, [projectId]);

  const filteredPreview = useMemo(() => {
    if (!preview) return null;
    if (!scopeOnly || scopeCidrs.length === 0) return preview;
    const inScopeHosts = preview.hosts.filter(h => _ipInScope(h.ip, scopeCidrs));
    const inScopeIps = new Set(inScopeHosts.map(h => h.ip));
    const inScopeCreds = preview.creds.filter(c => !c.host_id || inScopeIps.has(c.host_id));
    return { ...preview, hosts: inScopeHosts, creds: inScopeCreds, skipped: preview.hosts.length - inScopeHosts.length };
  }, [preview, scopeOnly, scopeCidrs]);

  const doNessusImport = () => _doNessusImport(projectId, nessusFile, setNessusLoading, setNessusError, setNessusResult, onImported);
  const doBurpImport = () => _doBurpImport(projectId, burpFile, setBurpLoading, setBurpError, setBurpResult, onImported);
  const parse = () => _doParse(mode, fileRef, text, setError, setPreview, setResult);
  const doImport = () => _doImport(projectId, filteredPreview, setLoading, setError, setResult, onImported, scopeOnly);

  const currentMode = MODES.find(m => m.id === mode);

  return (
    <div style={{ position: 'fixed', inset: 0, zIndex: 500, background: '#000000bb', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <button type="button" aria-label="Close import modal" onClick={onClose} style={{ position: 'absolute', inset: 0, background: 'transparent', border: 'none', cursor: 'default' }} />
      <div style={{ position: 'relative', background: PALETTE.bg3, border: `1px solid ${PALETTE.border}`, borderRadius: 10, width: 680, maxHeight: '86vh', display: 'flex', flexDirection: 'column', boxShadow: '0 24px 80px #00000099' }}>
        <div style={{ padding: '16px 20px', borderBottom: '1px solid #1e2029', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexShrink: 0 }}>
          <div>
            <div style={{ fontSize: 14, fontWeight: 700, color: PALETTE.text, fontFamily: FONTS.display }}>Import scan data</div>
            <div style={{ fontSize: 10, color: '#505560', marginTop: 2 }}>Hosts and credentials will be added to the current project</div>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', display: 'flex', padding: 4 }}>
            <Icon name="close" size={14} color="#606570" />
          </button>
        </div>

        <div style={{ display: 'flex', gap: 2, padding: '10px 20px 0', borderBottom: '1px solid #1e2029', flexShrink: 0 }}>
          {TABS_NAV.map(t => (
            <button key={t.id} onClick={() => setActiveTab(t.id)}
              style={{ background: 'none', border: 'none', borderBottom: activeTab === t.id ? `2px solid ${accent}` : '2px solid transparent', padding: '6px 14px 8px', cursor: 'pointer', fontSize: 11, fontWeight: 600, color: activeTab === t.id ? accent : PALETTE.textFaint, fontFamily: FONTS.mono, transition: 'color .15s', marginBottom: -1 }}>
              {t.label}
            </button>
          ))}
        </div>

        <div style={{ flex: 1, overflowY: 'auto', padding: 20, display: 'flex', flexDirection: 'column', gap: 16 }}>
          {activeTab === 'scanners' && (
            <ScannersTab nessusFile={nessusFile} setNessusFile={setNessusFile} nessusLoading={nessusLoading} nessusResult={nessusResult} setNessusResult={setNessusResult} nessusError={nessusError} setNessusError={setNessusError} nessusRef={nessusRef} doNessusImport={doNessusImport}
              burpFile={burpFile} setBurpFile={setBurpFile} burpLoading={burpLoading} burpResult={burpResult} setBurpResult={setBurpResult} burpError={burpError} setBurpError={setBurpError} burpRef={burpRef} doBurpImport={doBurpImport} accent={accent}
              projectId={projectId} onImported={onImported} />
          )}
          {activeTab === 'parsers' && (
            <ParsersTab mode={mode} setMode={setMode} currentMode={currentMode} fileRef={fileRef} text={text} setText={setText}
              preview={filteredPreview} setPreview={setPreview} error={error} setError={setError} loading={loading} result={result} setResult={setResult}
              doImport={doImport} parse={parse} onClose={onClose} accent={accent}
              scopeOnly={scopeOnly} setScopeOnly={setScopeOnly} scopeCount={scopeCidrs.length} rawPreview={preview}  projectId={projectId} />
          )}
        </div>
      </div>
    </div>
  );
}
ImportModal.propTypes = {
  projectId: PropTypes.any,
  onClose: PropTypes.any,
  onImported: PropTypes.any,
  accent: PropTypes.any,
};
