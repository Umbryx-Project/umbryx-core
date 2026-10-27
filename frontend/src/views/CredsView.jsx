import { useState, useMemo, useDeferredValue, useRef, useCallback, useEffect } from 'react';
import PropTypes from 'prop-types';
import SecretVaultTab from './SecretVaultTab.jsx';

function _toggleId(prev, id, checked) {
  return checked ? [...prev, id] : prev.filter(x => x !== id);
}
import { toastError } from '../components/Toast.jsx';
import Icon from '../components/Icon.jsx';
import { api } from '../api.js';
import CredMatrix from '../components/CredMatrix.jsx';
import CredReusePanel from '../components/CredReusePanel.jsx';
import { Badge, CredTypeBadge, SearchBar, FieldInput, TagEditor, PALETTE, FONTS, Checkbox, Select } from '../components/UI.jsx';
import { CRED_TYPES } from '../constants.js';
import { getCredBadges, getCredTagMeta, normalizeDomain, domainsMatch } from '../utils/hostMeta.js';
import { useColumnResize } from '../hooks/useColumnResize.js';
import { useProjectPermissions } from '../context/ProjectPermissions.jsx';
import ValidateCredPanel from './creds/ValidateCredPanel.jsx';
import { copyToClipboard } from '../utils/clipboard.js';
import { uiConfirm } from '../components/Confirm.jsx';

const COMMON_SERVICES = ['SSH','SMB','RDP','HTTP','HTTPS','FTP','MySQL','PostgreSQL','MSSQL','Oracle','WinRM','LDAP','Kerberos','VNC','Telnet','WebApp'];

const isWindows = h => h.os === 'Windows' || (h.os || '').toLowerCase().includes('windows');
const sanitizeDomainDraft = (value) => /^\.+$/.test(String(value || '').trim()) ? '' : value;

// Returns { confirmed: Host[], predicted: Host[] } for a cred
function getApplicableHosts(cred, projectHosts) {
  const confirmed = projectHosts.filter(h => (cred.host_ids || []).includes(h.id));
  const credDomain = normalizeDomain(cred.domain || '');
  const predicted = cred.is_domain
    ? projectHosts.filter(h => !confirmed.some(c => c.id === h.id) && isWindows(h) && normalizeDomain(h.domain || '') && domainsMatch(h.domain || '', credDomain))
    : [];
  return { confirmed, predicted };
}

// ── Domain toggle button ──────────────────────────────────────────────
function DomainToggle({ value, onChange, size = 'normal' }) {
  const small = size === 'small';
  return (
    <button onClick={() => onChange(!value)}
      title={value ? 'Domain cred — remove flag' : 'Mark as domain (works on all Windows machines in domain)'}
      style={{ display: 'flex', alignItems: 'center', gap: small ? 4 : 5, padding: small ? '2px 7px' : '4px 10px', borderRadius: 4, border: `1px solid ${value ? '#c07af077' : PALETTE.border}`, background: value ? '#c07af018' : 'transparent', cursor: 'pointer', color: value ? '#c07af0' : '#505560', fontSize: small ? 9 : 10, fontFamily: FONTS.mono, transition: 'all .15s', whiteSpace: 'nowrap' }}>
      <Icon name="globe" size={small ? 10 : 11} color={value ? '#c07af0' : '#505560'} />
      {value ? 'Domain' : 'Domain?'}
    </button>
  );
}

// ── Host chips display ────────────────────────────────────────────────
function HostChips({ cred, projectHosts, maxVisible = 2 }) {
  const { confirmed, predicted } = getApplicableHosts(cred, projectHosts);
  const total = confirmed.length + predicted.length;

  if (cred.is_domain && total === 0 && confirmed.length === 0) {
    return <span style={{ fontSize: 9, color: '#c07af0', background: '#c07af018', border: '1px solid #c07af033', borderRadius: 3, padding: '1px 6px', fontFamily: FONTS.mono }}>Domain</span>;
  }

  if (cred.is_domain) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', gap: 4, flexWrap: 'nowrap' }}>
        <span style={{ fontSize: 9, color: '#c07af0', background: '#c07af018', border: '1px solid #c07af033', borderRadius: 3, padding: '1px 6px', fontFamily: FONTS.mono, whiteSpace: 'nowrap' }}>
          Domain
        </span>
        {total > 0 && (
          <span style={{ fontSize: 9, color: '#808590', fontFamily: FONTS.mono, whiteSpace: 'nowrap' }}>
            ≈{total} host{total === 1 ? '' : 's'}
          </span>
        )}
      </div>
    );
  }

  if (confirmed.length === 0) {
    return <span style={{ fontSize: 10, color: '#353840', fontFamily: FONTS.mono }}>{cred.host || '—'}</span>;
  }

  const visible = confirmed.slice(0, maxVisible);
  const rest = confirmed.length - maxVisible;
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 3, flexWrap: 'nowrap', overflow: 'hidden' }}>
      {visible.map(h => (
        <span key={h.id} title={h.hostname || h.ip}
          style={{ fontSize: 9, color: '#5b8af5', background: '#5b8af518', border: '1px solid #5b8af533', borderRadius: 3, padding: '1px 5px', fontFamily: FONTS.mono, whiteSpace: 'nowrap', maxWidth: 80, overflow: 'hidden', textOverflow: 'ellipsis' }}>
          {h.hostname || h.ip}
        </span>
      ))}
      {rest > 0 && (
        <span style={{ fontSize: 9, color: PALETTE.textFaint, fontFamily: FONTS.mono }}>+{rest}</span>
      )}
    </div>
  );
}

// ── Multi-host selector in edit panel ────────────────────────────────
function HostSelector({ selectedIds, onChange, projectHosts, domainFilter = '' }) {
  if (!projectHosts.length) return <div style={{ fontSize: 10, color: PALETTE.textGhost, fontFamily: FONTS.mono }}>No hosts in project</div>;
  return (
    <div style={{ maxHeight: 160, overflowY: 'auto', border: `1px solid ${PALETTE.border}`, borderRadius: 5, background: '#07080b' }}>
      {projectHosts.map(h => {
        const checked = selectedIds.includes(h.id);
        const domainLocked = !!domainFilter;
        const matchesDomain = !domainLocked || domainsMatch(h.domain || '', domainFilter);
        return (
          <div key={h.id} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '6px 10px', borderBottom: '1px solid #13151c' }}
            onMouseEnter={e => e.currentTarget.style.background = matchesDomain ? '#ffffff04' : '#301214'}
            onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
            <Checkbox checked={checked} disabled={!matchesDomain} accent="#5b8af5"
              onChange={() => matchesDomain && onChange(checked ? selectedIds.filter(id => id !== h.id) : [...selectedIds, h.id])} />
            <span style={{ fontSize: 10, color: matchesDomain ? '#9098a8' : '#90545a', fontFamily: FONTS.mono, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {h.ip}{h.hostname ? ` — ${h.hostname}` : ''}
            </span>
            <span style={{ fontSize: 9, color: PALETTE.textGhost }}>{h.os}</span>
            {domainLocked && h.domain && <span style={{ fontSize: 8, color: matchesDomain ? '#39d353' : PALETTE.danger }}>{matchesDomain ? 'match' : 'other'}</span>}
            {checked && isWindows(h) && (
              <span style={{ fontSize: 8, color: PALETTE.ok }}>✓</span>
            )}
          </div>
        );
      })}
    </div>
  );
}

function CredTagsCell({ tags, fs }) {
  if (!tags || tags.length === 0) {
    return <span style={{ fontSize: Math.max(9, fs - 4), color: '#303540', fontFamily: FONTS.mono }}>—</span>;
  }
  return (
    <>
      {tags.slice(0, 3).map(tag => {
        const meta = getCredTagMeta(tag);
        return <span key={tag} style={{ fontSize: Math.max(9, fs - 4), color: meta.color, background: `${meta.color}18`, border: `1px solid ${meta.color}44`, borderRadius: 3, padding: '1px 5px', fontFamily: FONTS.mono, whiteSpace: 'nowrap' }}>{meta.label}</span>;
      })}
      {tags.length > 3 && <span style={{ fontSize: Math.max(9, fs - 4), color: '#505560', fontFamily: FONTS.mono }}>+{tags.length - 3}</span>}
    </>
  );
}

function CredSecretCell({ canReadSecret, cred, revealedSecret, revealTtl, fs, colBorder, onReveal, onHide }) {
  const isRevealed = !!revealedSecret;
  return (
    <div style={{ flex: 1, display: 'flex', alignItems: 'center', gap: 6, minWidth: 0, borderRight: colBorder, paddingRight: 12, marginRight: 12, overflow: 'hidden' }}>
      {isRevealed ? (
        <>
          <span style={{ fontSize: Math.max(10, fs - 3), color: PALETTE.textDim, fontFamily: FONTS.mono, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1, userSelect: 'text' }}>
            {revealedSecret || '(empty)'}
          </span>
          {revealTtl != null && (
            <span style={{ fontSize: 9, color: PALETTE.textGhost, fontFamily: FONTS.mono, flexShrink: 0 }}>{revealTtl}s</span>
          )}
        </>
      ) : (
        <span style={{ fontSize: Math.max(10, fs - 3), color: canReadSecret ? '#404550' : '#303540', fontFamily: FONTS.mono, flex: 1 }}>••••••••</span>
      )}
    </div>
  );
}

function CredActionsCell({ canReadSecret, isRevealed, revealedSecret, isCopied, isSel, cred, onReveal, onHide, copy, onDelete, setSelectedId }) {
  const { can } = useProjectPermissions();
  return (
    <div style={{ width: 56, display: 'flex', alignItems: 'center', gap: 4 }}>
      {canReadSecret && (
        <button onClick={e => { e.stopPropagation(); isRevealed ? onHide(cred.id) : onReveal(cred.id); }} title={isRevealed ? 'Hide' : 'Reveal'}
          style={{ background: 'none', border: 'none', cursor: 'pointer', color: PALETTE.textGhost, display: 'flex', padding: 2 }}
          onMouseEnter={e => e.currentTarget.style.color = '#9098a8'}
          onMouseLeave={e => e.currentTarget.style.color = '#404550'}>
          <Icon name={isRevealed ? 'eyeOff' : 'eye'} size={13} color="currentColor" />
        </button>
      )}
      {canReadSecret && isRevealed && (
        <button onClick={e => { e.stopPropagation(); copy(revealedSecret, cred.id); }} title="Copy"
          style={{ background: 'none', border: 'none', cursor: 'pointer', color: isCopied ? '#39d353' : PALETTE.textGhost, display: 'flex', padding: 2 }}
          onMouseEnter={e => !isCopied && (e.currentTarget.style.color = '#9098a8')}
          onMouseLeave={e => !isCopied && (e.currentTarget.style.color = '#404550')}>
          <Icon name={isCopied ? 'check' : 'copy'} size={13} color="currentColor" />
        </button>
      )}
      {can('credentials.delete') && <button onClick={e => { e.stopPropagation(); onDelete(cred.id); if (isSel) setSelectedId(null); }}
        style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#303540', display: 'flex', padding: 2 }}
        onMouseEnter={e => e.currentTarget.style.color = '#cc2233'}
        onMouseLeave={e => e.currentTarget.style.color = '#303540'}>
        <Icon name="trash" size={12} color="currentColor" />
      </button>}
    </div>
  );
}

function CredCrackedCell({ cred, colBorder, widths, onUpdate }) {
  return (
    <div style={{ width: widths.cracked, flexShrink: 0, borderRight: colBorder, paddingRight: 12, marginRight: 12, display: 'flex', alignItems: 'center', justifyContent: 'center', overflow: 'hidden' }}>
      {cred.cracked
        ? <span style={{ maxWidth: '100%', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: 9, color: PALETTE.ok, background: '#39d35322', border: '1px solid #39d35344', borderRadius: 3, padding: '1px 6px', fontFamily: FONTS.mono }}>✓ cracked</span>
        : <button onClick={e => { e.stopPropagation(); onUpdate(cred.id, { cracked: true }); }}
            style={{ maxWidth: '100%', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: 9, color: PALETTE.textGhost, background: PALETTE.borderSoft, border: `1px solid ${PALETTE.border}`, borderRadius: 3, padding: '1px 6px', fontFamily: FONTS.mono, cursor: 'pointer' }}>hash</button>}
    </div>
  );
}

function _credRowBg(isSel, checkedId) {
  if (isSel) {
    return '#ffffff06';
  }
  if (checkedId) {
    return '#ffffff04';
  }
  return 'transparent';
}

function _credRowBorderLeft(isSel, accent, isDomain) {
  if (isSel) return `2px solid ${accent}`;
  if (isDomain) {
    return '2px solid #c07af033';
  }
  return '2px solid transparent';
}

function CredRow({ id, cred, isSel, isCopied, revealedSecret, revealTtl, canReadSecret, checkedIds, widths, colBorder, accent, fs, projectHosts, setSelectedId, setCheckedIds, onReveal, onHide, copy, onUpdate, onDelete }) {
  const { predicted } = getApplicableHosts(cred, projectHosts);
  const isChecked = checkedIds.includes(cred.id);
  return (
    <button type="button" id={id} onClick={() => setSelectedId(isSel ? null : cred.id)}
      style={{ display: 'flex', alignItems: 'stretch', minHeight: 44, padding: '8px 18px', borderBottom: '1px solid #14161b', transition: 'background .1s', cursor: 'pointer', background: _credRowBg(isSel, isChecked), borderLeft: _credRowBorderLeft(isSel, accent, cred.is_domain), width: '100%', textAlign: 'left', borderTop: 'none', borderRight: 'none', borderBottomStyle: 'solid', outline: 'none', color: 'inherit', font: 'inherit' }}
      onMouseEnter={e => !isSel && (e.currentTarget.style.background = '#ffffff04')}
      onMouseLeave={e => !isSel && !isChecked && (e.currentTarget.style.background = 'transparent')}>

      <div style={{ width: 28, flexShrink: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', borderRight: colBorder, paddingRight: 12, marginRight: 12 }}
        onClick={e => e.stopPropagation()}>
        <Checkbox checked={isChecked} accent={accent}
          onChange={v => setCheckedIds(prev => _toggleId(prev, cred.id, v))} />
      </div>

      <div style={{ width: widths.username, flexShrink: 0, minWidth: 0, borderRight: colBorder, paddingRight: 12, marginRight: 12, overflow: 'hidden', display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
        <div style={{ fontSize: Math.max(11, fs - 1), color: '#e0e4ec', fontFamily: FONTS.mono, fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{cred.username}</div>
        {cred.notes && <div style={{ fontSize: Math.max(9, fs - 4), color: PALETTE.textGhost, marginTop: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{cred.notes}</div>}
      </div>

      <div style={{ width: widths.type, flexShrink: 0, borderRight: colBorder, paddingRight: 12, marginRight: 12, display: 'flex', alignItems: 'center', overflow: 'hidden' }}><CredTypeBadge type={cred.type} /></div>

      <div style={{ width: widths.service, flexShrink: 0, fontSize: Math.max(10, fs - 3), color: PALETTE.textFaint, fontFamily: FONTS.mono, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', minWidth: 0, borderRight: colBorder, paddingRight: 12, marginRight: 12, display: 'flex', alignItems: 'center' }}>{cred.service || '—'}</div>

      <div style={{ width: widths.hosts, flexShrink: 0, minWidth: 0, borderRight: colBorder, paddingRight: 12, marginRight: 12, overflow: 'hidden', display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
        <HostChips cred={cred} projectHosts={projectHosts} maxVisible={2} />
        {cred.is_domain && predicted.length > 0 && (
          <div style={{ fontSize: 8, color: '#505560', fontFamily: FONTS.mono, marginTop: 1 }}>
            +{predicted.length} Windows (predicted)
          </div>
        )}
      </div>

      <div style={{ width: widths.tags, flexShrink: 0, minWidth: 0, display: 'flex', gap: 3, flexWrap: 'nowrap', alignItems: 'center', overflow: 'hidden', borderRight: colBorder, paddingRight: 12, marginRight: 12 }}>
        <CredTagsCell tags={cred.tags} fs={fs} />
      </div>

      <CredSecretCell canReadSecret={canReadSecret} cred={cred} revealedSecret={revealedSecret} revealTtl={revealTtl} fs={fs} colBorder={colBorder} onReveal={onReveal} onHide={onHide} />

      <CredCrackedCell cred={cred} colBorder={colBorder} widths={widths} onUpdate={onUpdate} />

      <CredActionsCell canReadSecret={canReadSecret} isRevealed={!!revealedSecret} revealedSecret={revealedSecret} isCopied={isCopied} isSel={isSel} cred={cred} onReveal={onReveal} onHide={onHide} copy={copy} onDelete={onDelete} setSelectedId={setSelectedId} />
    </button>
  );
}

async function _importBulkCredsLines(lines, delimiter, selectedProject, onAdd) {
  for (const line of lines) {
    const parts = line.split(delimiter).map(x => x.trim());
    if (parts.length < 2) {
      continue;
    }
    const [username, secret, type = 'plain', service = '', host = '', cracked = 'false', notes = '', tags = ''] = parts;
    await onAdd({ pid: selectedProject, username, secret, type: type || 'plain', service, host, domain: '', cracked: ['1','true','yes','y','+'].includes(String(cracked).toLowerCase()), notes, tags: tags.split(',').map(t => t.trim()).filter(Boolean), host_ids: [], is_domain: false });
  }
}

async function _exportCredsCsv(selectedProject) {
  try {
    const blob = await api.exportCredsCsv(selectedProject);
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `creds_${selectedProject?.slice(0, 8) || 'project'}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  } catch (e) {
    toastError(e.message || 'Failed to export credentials CSV');
  }
}

async function _applyBulkEditPatch(checkedIds, creds, bulkEditFields, onUpdate) {
  const f = bulkEditFields;
  const basePatch = {};
  if (f.type) {
    basePatch.type = f.type;
  }
  if (f.service !== '') {
    basePatch.service = f.service;
  }
  if (f.domain !== '') {
    basePatch.domain = f.domain;
  }
  if (f.is_domain !== '') {
    basePatch.is_domain = f.is_domain === 'true';
  }
  if (f.cracked !== '') {
    basePatch.cracked = f.cracked === 'true';
  }
  const addTags = f.addTags.split(',').map(t => t.trim()).filter(Boolean);
  const removeTags = f.removeTags.split(',').map(t => t.trim()).filter(Boolean);
  for (const id of checkedIds) {
    const cred = creds.find(c => c.id === id);
    if (!cred) {
      continue;
    }
    const patch = { ...basePatch };
    if (addTags.length || removeTags.length) {
      const current = cred.tags || [];
      patch.tags = [...new Set([...current.filter(t => !removeTags.includes(t)), ...addTags])];
    }
    if (Object.keys(patch).length) {
      await onUpdate(id, patch);
    }
  }
}

function _computeProjectHosts(hosts, pid) { return (hosts || []).filter(h => h.pid === pid); }
function _computeWindowsHosts(ph) { return ph.filter(isWindows); }
function _computeProjectCreds(creds, pid) { return creds.filter(c => c.pid === pid); }
function _computeFilteredCreds(pc, filterType, filterDomain, filterTag, search) {
  const needle = search ? search.toLowerCase() : '';
  return pc
    .filter(c => !filterType || c.type === filterType)
    .filter(c => !filterDomain || c.is_domain)
    .filter(c => !filterTag || (c.tags || []).includes(filterTag))
    .filter(c => !needle || [c.username, c.service, c.host, c.notes, (c.tags || []).join(' ')].join(' ').toLowerCase().includes(needle));
}
function _findSelCred(creds, id) { return creds.find(c => c.id === id); }
function _countCracked(list) { return list.filter(c => c.cracked).length; }
function _countDomain(list) { return list.filter(c => c.is_domain).length; }
function _computeTagCounts(list) {
  const m = new Map();
  list.forEach(c => (c.tags || []).forEach(t => m.set(t, (m.get(t) || 0) + 1)));
  return [...m.entries()].sort((a, b) => b[1] - a[1]);
}
function _copyCred(text, id, setCopied) {
  copyToClipboard(text).catch(() => {});
  setCopied(id);
  setTimeout(() => setCopied(null), 1500);
}
function _toggleSecretVis(id, setShowSecrets) { setShowSecrets(p => ({ ...p, [id]: !p[id] })); }

function useSecretReveal() {
  // { [credId]: { secret, ttl } }
  const [revealed, setRevealed] = useState({});
  const timers = useRef({});
  const tickTimers = useRef({});

  const _clearAll = (credId) => {
    if (timers.current[credId]) { clearTimeout(timers.current[credId]); delete timers.current[credId]; }
    if (tickTimers.current[credId]) { clearInterval(tickTimers.current[credId]); delete tickTimers.current[credId]; }
  };

  const reveal = async (credId) => {
    if (revealed[credId]) return;
    try {
      const { api } = await import('../api.js');
      const res = await api.revealCredSecret(credId);
      const ttl = res.ttl ?? 30;
      setRevealed(p => ({ ...p, [credId]: { secret: res.secret, ttl } }));
      _clearAll(credId);
      timers.current[credId] = setTimeout(() => {
        setRevealed(p => { const next = { ...p }; delete next[credId]; return next; });
        _clearAll(credId);
      }, ttl * 1000);
      tickTimers.current[credId] = setInterval(() => {
        setRevealed(p => {
          if (!p[credId]) return p;
          const newTtl = p[credId].ttl - 1;
          if (newTtl <= 0) return p;
          return { ...p, [credId]: { ...p[credId], ttl: newTtl } };
        });
      }, 1000);
    } catch { /* the countdown is cosmetic; a failed tick just stops it */ }
  };

  const hide = (credId) => {
    setRevealed(p => { const next = { ...p }; delete next[credId]; return next; });
    _clearAll(credId);
  };

  useEffect(() => () => {
    Object.values(timers.current).forEach(clearTimeout);
    Object.values(tickTimers.current).forEach(clearInterval);
  }, []);

  return { revealed, reveal, hide };
}
function _addNewCred(nc, pid, onAdd, setNewCred, setShowAdd) {
  if (!nc.username.trim()) {
    return;
  }
  onAdd({ pid, ...nc });
  setNewCred({ username: '', secret: '', type: 'plain', service: '', host: '', domain: '', cracked: false, notes: '', tags: [], is_domain: false, host_ids: [] });
  setShowAdd(false);
}
async function _importBulkCredsAction(delim, text, pid, onAdd, setText, setShow) {
  const d = delim === '\t' ? '\t' : delim;
  const lines = text.split('\n').map(l => l.trim()).filter(Boolean);
  await _importBulkCredsLines(lines, d, pid, onAdd);
  setText('');
  setShow(false);
}

const credPropType = PropTypes.shape({
  id: PropTypes.any,
  pid: PropTypes.any,
  username: PropTypes.string,
  secret: PropTypes.string,
  type: PropTypes.string,
  service: PropTypes.string,
  host: PropTypes.string,
  domain: PropTypes.string,
  cracked: PropTypes.bool,
  notes: PropTypes.string,
  tags: PropTypes.arrayOf(PropTypes.string),
  host_ids: PropTypes.arrayOf(PropTypes.any),
  is_domain: PropTypes.bool,
});

const hostPropType = PropTypes.shape({
  id: PropTypes.any,
  pid: PropTypes.any,
  ip: PropTypes.string,
  hostname: PropTypes.string,
  os: PropTypes.string,
  domain: PropTypes.string,
});

const widthsPropType = PropTypes.shape({
  username: PropTypes.number,
  type: PropTypes.number,
  service: PropTypes.number,
  hosts: PropTypes.number,
  tags: PropTypes.number,
  cracked: PropTypes.number,
});

DomainToggle.propTypes = {
  value: PropTypes.bool,
  onChange: PropTypes.func.isRequired,
  size: PropTypes.string,
};

HostChips.propTypes = {
  cred: credPropType.isRequired,
  projectHosts: PropTypes.arrayOf(hostPropType).isRequired,
  maxVisible: PropTypes.number,
};

HostSelector.propTypes = {
  selectedIds: PropTypes.arrayOf(PropTypes.any).isRequired,
  onChange: PropTypes.func.isRequired,
  projectHosts: PropTypes.arrayOf(hostPropType).isRequired,
  domainFilter: PropTypes.string,
};

CredTagsCell.propTypes = {
  tags: PropTypes.arrayOf(PropTypes.string),
  fs: PropTypes.number.isRequired,
};

CredSecretCell.propTypes = {
  canReadSecret: PropTypes.bool.isRequired,
  revealedSecret: PropTypes.string,
  revealTtl: PropTypes.number,
  cred: credPropType.isRequired,
  fs: PropTypes.number.isRequired,
  colBorder: PropTypes.string.isRequired,
  onReveal: PropTypes.func,
  onHide: PropTypes.func,
};

CredActionsCell.propTypes = {
  canReadSecret: PropTypes.bool.isRequired,
  isRevealed: PropTypes.bool,
  revealedSecret: PropTypes.string,
  isCopied: PropTypes.bool,
  isSel: PropTypes.bool,
  cred: credPropType.isRequired,
  onReveal: PropTypes.func.isRequired,
  onHide: PropTypes.func.isRequired,
  copy: PropTypes.func.isRequired,
  onDelete: PropTypes.func.isRequired,
  setSelectedId: PropTypes.func.isRequired,
};

CredCrackedCell.propTypes = {
  cred: credPropType.isRequired,
  colBorder: PropTypes.string.isRequired,
  widths: widthsPropType.isRequired,
  onUpdate: PropTypes.func.isRequired,
};

CredRow.propTypes = {
  id: PropTypes.string,
  cred: credPropType.isRequired,
  isSel: PropTypes.bool,
  isCopied: PropTypes.bool,
  revealedSecret: PropTypes.string,
  revealTtl: PropTypes.number,
  canReadSecret: PropTypes.bool.isRequired,
  checkedIds: PropTypes.arrayOf(PropTypes.any).isRequired,
  widths: widthsPropType.isRequired,
  colBorder: PropTypes.string.isRequired,
  accent: PropTypes.string.isRequired,
  fs: PropTypes.number.isRequired,
  projectHosts: PropTypes.arrayOf(hostPropType).isRequired,
  setSelectedId: PropTypes.func.isRequired,
  setCheckedIds: PropTypes.func.isRequired,
  onReveal: PropTypes.func.isRequired,
  onHide: PropTypes.func.isRequired,
  copy: PropTypes.func.isRequired,
  onUpdate: PropTypes.func.isRequired,
  onDelete: PropTypes.func.isRequired,
};

CredsSelectedActions.propTypes = {
  accent: PropTypes.string.isRequired,
  fs: PropTypes.number.isRequired,
  checkedIds: PropTypes.arrayOf(PropTypes.any).isRequired,
  setCheckedIds: PropTypes.func.isRequired,
  filtered: PropTypes.arrayOf(credPropType).isRequired,
  showBulkEdit: PropTypes.bool,
  setShowBulkEdit: PropTypes.func.isRequired,
  setShowAdd: PropTypes.func.isRequired,
  setShowBulk: PropTypes.func.isRequired,
  onDelete: PropTypes.func.isRequired,
};

CredsHeader.propTypes = {
  accent: PropTypes.string.isRequired,
  fs: PropTypes.number.isRequired,
  creds: PropTypes.arrayOf(credPropType).isRequired,
  selectedProject: PropTypes.any,
  crackedCount: PropTypes.number.isRequired,
  domainCount: PropTypes.number.isRequired,
  search: PropTypes.string.isRequired,
  setSearch: PropTypes.func.isRequired,
  filterType: PropTypes.string,
  setFilterType: PropTypes.func.isRequired,
  filterDomain: PropTypes.bool,
  setFilterDomain: PropTypes.func.isRequired,
  checkedIds: PropTypes.arrayOf(PropTypes.any).isRequired,
  setCheckedIds: PropTypes.func.isRequired,
  filtered: PropTypes.arrayOf(credPropType).isRequired,
  showBulkEdit: PropTypes.bool,
  setShowBulkEdit: PropTypes.func.isRequired,
  setShowAdd: PropTypes.func.isRequired,
  showBulk: PropTypes.bool,
  setShowBulk: PropTypes.func.isRequired,
  handleExportCsv: PropTypes.func.isRequired,
  viewMode: PropTypes.string.isRequired,
  setViewMode: PropTypes.func.isRequired,
  onDelete: PropTypes.func.isRequired,
};

CredsViewBody.propTypes = {
  accent: PropTypes.string.isRequired,
  fs: PropTypes.number.isRequired,
  creds: PropTypes.arrayOf(credPropType).isRequired,
  selectedProject: PropTypes.any,
  onAdd: PropTypes.func.isRequired,
  onUpdate: PropTypes.func.isRequired,
  onDelete: PropTypes.func.isRequired,
  projectHosts: PropTypes.arrayOf(hostPropType).isRequired,
  windowsHosts: PropTypes.arrayOf(hostPropType).isRequired,
  projectCreds: PropTypes.arrayOf(credPropType).isRequired,
  filtered: PropTypes.arrayOf(credPropType).isRequired,
  selCred: credPropType,
  crackedCount: PropTypes.number.isRequired,
  domainCount: PropTypes.number.isRequired,
  tagCounts: PropTypes.arrayOf(PropTypes.array).isRequired,
  search: PropTypes.string.isRequired,
  setSearch: PropTypes.func.isRequired,
  filterType: PropTypes.string,
  setFilterType: PropTypes.func.isRequired,
  filterDomain: PropTypes.bool,
  setFilterDomain: PropTypes.func.isRequired,
  filterTag: PropTypes.string,
  setFilterTag: PropTypes.func.isRequired,
  revealed: PropTypes.object.isRequired,
  reveal: PropTypes.func.isRequired,
  hide: PropTypes.func.isRequired,
  showAdd: PropTypes.bool,
  setShowAdd: PropTypes.func.isRequired,
  showBulk: PropTypes.bool,
  setShowBulk: PropTypes.func.isRequired,
  showBulkEdit: PropTypes.bool,
  setShowBulkEdit: PropTypes.func.isRequired,
  newCred: PropTypes.object.isRequired,
  setNewCred: PropTypes.func.isRequired,
  bulkDelimiter: PropTypes.string.isRequired,
  setBulkDelimiter: PropTypes.func.isRequired,
  bulkText: PropTypes.string.isRequired,
  setBulkText: PropTypes.func.isRequired,
  bulkEditFields: PropTypes.object.isRequired,
  setBulkEditFields: PropTypes.func.isRequired,
  copied: PropTypes.any,
  selectedId: PropTypes.any,
  setSelectedId: PropTypes.func.isRequired,
  checkedIds: PropTypes.arrayOf(PropTypes.any).isRequired,
  setCheckedIds: PropTypes.func.isRequired,
  showValidate: PropTypes.bool,
  setShowValidate: PropTypes.func.isRequired,
  viewMode: PropTypes.string.isRequired,
  setViewMode: PropTypes.func.isRequired,
  widths: widthsPropType.isRequired,
  startResize: PropTypes.func.isRequired,
  colBorder: PropTypes.string.isRequired,
  canReadSecret: PropTypes.bool.isRequired,
  copy: PropTypes.func.isRequired,
  addCred: PropTypes.func.isRequired,
  handleExportCsv: PropTypes.func.isRequired,
  importBulkCreds: PropTypes.func.isRequired,
  applyBulkEdit: PropTypes.func.isRequired,
  onNavigate: PropTypes.func,
};

function CredsSelectedActions({ accent, fs, checkedIds, setCheckedIds, filtered, showBulkEdit, setShowBulkEdit, setShowAdd, setShowBulk, onDelete }) {
  const { can } = useProjectPermissions();
  return (
    <>
      <button onClick={() => { setShowBulkEdit(v => !v); setShowAdd(false); setShowBulk(false); }}
        style={{ background: showBulkEdit ? `${accent}22` : 'transparent', border: `1px solid ${showBulkEdit ? accent + '88' : PALETTE.border}`, borderRadius: 4, padding: '5px 10px', cursor: 'pointer', color: showBulkEdit ? accent : '#808590', fontSize: Math.max(10, fs - 3), fontFamily: FONTS.mono, display: 'flex', alignItems: 'center', gap: 4 }}>
        <Icon name="edit" size={10} color="currentColor" /> Edit {checkedIds.length}
      </button>
      <button onClick={() => {
        const text = filtered.filter(c => checkedIds.includes(c.id)).map(c => `${c.username};${c.secret};${c.type};${c.service};${c.host}`).join('\n');
        copyToClipboard(text).catch(() => {});
      }} style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '5px 10px', cursor: 'pointer', color: '#808590', fontSize: Math.max(10, fs - 3), fontFamily: FONTS.mono, display: 'flex', alignItems: 'center', gap: 4 }}>
        <Icon name="copy" size={10} color="currentColor" /> Copy
      </button>
      {can('credentials.delete') && <button onClick={async () => {
        if (!await uiConfirm(`Delete ${checkedIds.length} credential(s)?`)) return;
        for (const id of checkedIds) {
          await onDelete(id);
        }
        setCheckedIds([]);
        setShowBulkEdit(false);
      }} style={{ background: '#cc233322', border: '1px solid #cc233344', borderRadius: 4, padding: '5px 10px', cursor: 'pointer', color: PALETTE.danger, fontSize: Math.max(10, fs - 3), fontFamily: FONTS.mono, display: 'flex', alignItems: 'center', gap: 4 }}>
        <Icon name="trash" size={10} color="currentColor" /> Delete {checkedIds.length}
      </button>}
      <button onClick={() => { setCheckedIds([]); setShowBulkEdit(false); }} style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '5px 8px', cursor: 'pointer', color: '#505560', fontSize: Math.max(9, fs - 4), fontFamily: FONTS.mono }}>✗</button>
    </>
  );
}

function CredsHeader({ accent, fs, creds, selectedProject, crackedCount, domainCount, search, setSearch, filterType, setFilterType, filterDomain, setFilterDomain, checkedIds, setCheckedIds, filtered, showBulkEdit, setShowBulkEdit, setShowAdd, showBulk, setShowBulk, handleExportCsv, viewMode, setViewMode, onDelete }) {
  const { can } = useProjectPermissions();
  return (
    <div style={{ padding: '14px 18px', borderBottom: `1px solid ${PALETTE.borderSoft}`, background: '#0a0c10', display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
      <div style={{ flex: 1 }}>
        <span style={{ fontSize: fs + 1, fontWeight: 600, color: '#e0e4ec', fontFamily: FONTS.display }}>creds</span>
        <span style={{ fontSize: Math.max(10, fs - 2), color: PALETTE.textGhost, marginLeft: 10 }}>{filtered.length} entries · {crackedCount} cracked</span>
        {domainCount > 0 && (
          <span style={{ fontSize: Math.max(9, fs - 4), color: '#c07af0', marginLeft: 8, fontFamily: FONTS.mono }}>· {domainCount} domain</span>
        )}
        {checkedIds.length > 0 && (
          <span style={{ fontSize: Math.max(9, fs - 4), color: accent, marginLeft: 8, fontFamily: FONTS.mono, fontWeight: 600 }}>· {checkedIds.length} selected</span>
        )}
      </div>
      <div style={{ display: 'flex', gap: 4 }}>
        {Object.entries(CRED_TYPES).map(([k, v]) => {
          const cnt = creds.filter(c => c.pid === selectedProject && c.type === k).length;
          if (!cnt) {
            return null;
          }
          return <button key={k} onClick={() => setFilterType(filterType === k ? null : k)}
            style={{ background: filterType === k ? `${v.color}22` : 'transparent', border: `1px solid ${filterType === k ? v.color + '88' : PALETTE.border}`, borderRadius: 3, padding: '3px 8px', cursor: 'pointer', fontSize: Math.max(9, fs - 4), color: filterType === k ? v.color : '#505560', fontFamily: FONTS.mono, transition: 'all .12s' }}>
            {v.label} {cnt}
          </button>;
        })}
        {domainCount > 0 && (
          <button onClick={() => setFilterDomain(v => !v)}
            style={{ background: filterDomain ? '#c07af022' : 'transparent', border: `1px solid ${filterDomain ? '#c07af088' : PALETTE.border}`, borderRadius: 3, padding: '3px 8px', cursor: 'pointer', fontSize: Math.max(9, fs - 4), color: filterDomain ? '#c07af0' : '#505560', fontFamily: FONTS.mono, display: 'flex', alignItems: 'center', gap: 4, transition: 'all .12s' }}>
            <Icon name="globe" size={10} color={filterDomain ? '#c07af0' : '#505560'} /> Domain
          </button>
        )}
      </div>
      <div style={{ width: 180 }}><SearchBar value={search} onChange={setSearch} placeholder="Username, host..." /></div>
      {can('credentials.create') && <button onClick={() => setShowAdd(v => !v)}
        style={{ background: accent, border: 'none', borderRadius: 4, padding: '5px 12px', cursor: 'pointer', color: '#fff', fontSize: Math.max(10, fs - 3), fontWeight: 600, fontFamily: FONTS.mono, display: 'flex', alignItems: 'center', gap: 5 }}>
        <Icon name="plus" size={10} color="#fff" /> Add
      </button>}
      {checkedIds.length > 0 && (
        <CredsSelectedActions accent={accent} fs={fs} checkedIds={checkedIds} setCheckedIds={setCheckedIds} filtered={filtered} showBulkEdit={showBulkEdit} setShowBulkEdit={setShowBulkEdit} setShowAdd={setShowAdd} setShowBulk={setShowBulk} onDelete={onDelete} />
      )}
      <button onClick={() => setShowBulk(v => !v)}
        style={{ background: 'transparent', border: `1px solid ${accent}66`, borderRadius: 4, padding: '5px 12px', cursor: 'pointer', color: accent, fontSize: Math.max(10, fs - 3), fontWeight: 600, fontFamily: FONTS.mono, display: 'flex', alignItems: 'center', gap: 5 }}>
        <Icon name="export" size={10} color="currentColor" /> Bulk
      </button>
      <button onClick={handleExportCsv}
        style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '5px 12px', cursor: 'pointer', color: '#808590', fontSize: Math.max(10, fs - 3), fontWeight: 600, fontFamily: FONTS.mono, display: 'flex', alignItems: 'center', gap: 5 }}>
        <Icon name="export" size={10} color="currentColor" /> CSV
      </button>
      <button onClick={() => setViewMode(v => v === 'matrix' ? 'list' : 'matrix')}
        title="Matrix: credentials × hosts"
        style={{ background: viewMode === 'matrix' ? `${accent}22` : 'transparent', border: `1px solid ${viewMode === 'matrix' ? accent + '88' : PALETTE.border}`, borderRadius: 4, padding: '5px 12px', cursor: 'pointer', color: viewMode === 'matrix' ? accent : '#808590', fontSize: Math.max(10, fs - 3), fontWeight: 600, fontFamily: FONTS.mono, display: 'flex', alignItems: 'center', gap: 5 }}>
        ⊞ Matrix
      </button>
      <button onClick={() => setViewMode(v => v === 'reuse' ? 'list' : 'reuse')}
        title="Credential reuse analysis"
        style={{ background: viewMode === 'reuse' ? `${accent}22` : 'transparent', border: `1px solid ${viewMode === 'reuse' ? accent + '88' : PALETTE.border}`, borderRadius: 4, padding: '5px 12px', cursor: 'pointer', color: viewMode === 'reuse' ? accent : '#808590', fontSize: Math.max(10, fs - 3), fontWeight: 600, fontFamily: FONTS.mono, display: 'flex', alignItems: 'center', gap: 5 }}>
        ⚠ Reuse
      </button>
    </div>
  );
}

function CredsViewBody({ accent, fs, creds, selectedProject, onAdd, onUpdate, onDelete, projectHosts, windowsHosts, projectCreds, filtered, selCred, crackedCount, domainCount, tagCounts, search, setSearch, filterType, setFilterType, filterDomain, setFilterDomain, filterTag, setFilterTag, revealed, reveal, hide, showAdd, setShowAdd, showBulk, setShowBulk, showBulkEdit, setShowBulkEdit, newCred, setNewCred, bulkDelimiter, setBulkDelimiter, bulkText, setBulkText, bulkEditFields, setBulkEditFields, copied, selectedId, setSelectedId, checkedIds, setCheckedIds, showValidate, setShowValidate, viewMode, setViewMode, widths, startResize, colBorder, canReadSecret, copy, addCred, handleExportCsv, importBulkCreds, applyBulkEdit, onNavigate }) {
  const [secretDraft, setSecretDraft] = useState(null);
  useEffect(() => {
    setSecretDraft(null);
    if (selCred?.id && canReadSecret) reveal(selCred.id);
  }, [selCred?.id]);
  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <CredsHeader accent={accent} fs={fs} creds={creds} selectedProject={selectedProject} crackedCount={crackedCount} domainCount={domainCount} search={search} setSearch={setSearch} filterType={filterType} setFilterType={setFilterType} filterDomain={filterDomain} setFilterDomain={setFilterDomain} checkedIds={checkedIds} setCheckedIds={setCheckedIds} filtered={filtered} showBulkEdit={showBulkEdit} setShowBulkEdit={setShowBulkEdit} setShowAdd={setShowAdd} showBulk={showBulk} setShowBulk={setShowBulk} handleExportCsv={handleExportCsv} viewMode={viewMode} setViewMode={setViewMode} onDelete={onDelete} />

      {tagCounts.length > 0 && (
        <div style={{ padding: '8px 18px', borderBottom: `1px solid ${PALETTE.borderSoft}`, background: '#0c0e13', display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
          <span style={{ fontSize: 9, color: PALETTE.textGhost, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Tags</span>
          {tagCounts.map(([tag, count]) => {
            const meta = getCredTagMeta(tag);
            const active = filterTag === tag;
            return (
              <button key={tag} onClick={() => setFilterTag(active ? null : tag)}
                style={{ background: active ? `${meta.color}22` : PALETTE.bg3, border: `1px solid ${active ? meta.color + '88' : PALETTE.border}`, borderRadius: 4, padding: '3px 8px', cursor: 'pointer', color: active ? meta.color : '#808590', fontSize: 9, fontFamily: FONTS.mono, display: 'flex', alignItems: 'center', gap: 5 }}>
                <span>{meta.label}</span>
                <span style={{ opacity: 0.75 }}>{count}</span>
              </button>
            );
          })}
          {filterTag && <button onClick={() => setFilterTag(null)} style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '3px 8px', cursor: 'pointer', color: PALETTE.textFaint, fontSize: 9, fontFamily: FONTS.mono }}>Clear</button>}
        </div>
      )}

      {/* Bulk import */}
      {showBulk && (
        <div style={{ padding: '14px 18px', borderBottom: `1px solid ${PALETTE.borderSoft}`, background: '#0c0e13' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
            <div style={{ fontSize: 10, color: '#808590' }}>Format: username secret type service host cracked notes tags</div>
            <Select value={bulkDelimiter} onChange={setBulkDelimiter}
              options={[';', ',', '|', '\t'].map(d => ({ value: d, label: d === '\t' ? 'TAB' : d }))} />
          </div>
          <textarea value={bulkText} onChange={e => setBulkText(e.target.value)} rows={5}
            placeholder={'admin;Password123!;plain;SMB;10.0.0.5;true;local admin;shared,prod\nDOMAIN\\user1;aad3b435:ntlmhash;ntlm;SMB;;false;BH import;domain-admin,kerberoastable'}
            style={{ width: '100%', background: PALETTE.bg3, border: `1px solid ${PALETTE.border}`, borderRadius: 6, padding: '8px 10px', color: PALETTE.textDim, fontSize: 11, outline: 'none', fontFamily: FONTS.mono, resize: 'vertical', boxSizing: 'border-box' }} />
          <div style={{ display: 'flex', gap: 8, marginTop: 10 }}>
            <button onClick={importBulkCreds} style={{ background: accent, border: 'none', borderRadius: 4, padding: '6px 14px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: FONTS.mono }}>Import</button>
            <button onClick={() => setShowBulk(false)} style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 10px', cursor: 'pointer', color: PALETTE.textFaint, fontSize: 11, fontFamily: FONTS.mono }}>Cancel</button>
          </div>
        </div>
      )}

      {/* Bulk edit panel */}
      {showBulkEdit && checkedIds.length > 0 && (
        <div style={{ padding: '12px 18px', borderBottom: `1px solid ${PALETTE.borderSoft}`, background: '#0c0e13', display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'flex-end' }}>
          <div style={{ fontSize: 9, color: accent, fontFamily: FONTS.mono, fontWeight: 600, alignSelf: 'center', whiteSpace: 'nowrap' }}>{checkedIds.length} selected</div>

          {/* Type */}
          <div style={{ width: 110 }}>
            <div style={{ fontSize: 9, color: PALETTE.textGhost, marginBottom: 4, textTransform: 'uppercase' }}>Type</div>
            <Select value={bulkEditFields.type} onChange={v => setBulkEditFields(f => ({ ...f, type: v }))}
              style={{ width: '100%' }} placeholder="No change"
              options={Object.entries(CRED_TYPES).map(([k, v]) => ({ value: k, label: v.label }))} />
          </div>

          {/* Service */}
          <div style={{ width: 120 }}>
            <div style={{ fontSize: 9, color: PALETTE.textGhost, marginBottom: 4, textTransform: 'uppercase' }}>Service</div>
            <Select value={bulkEditFields.service} onChange={v => setBulkEditFields(f => ({ ...f, service: v }))}
              style={{ width: '100%' }} placeholder="No change" options={COMMON_SERVICES} />
          </div>

          {/* Domain */}
          <div style={{ width: 140 }}>
            <div style={{ fontSize: 9, color: PALETTE.textGhost, marginBottom: 4, textTransform: 'uppercase' }}>Domain</div>
            <input value={bulkEditFields.domain} onChange={e => setBulkEditFields(f => ({ ...f, domain: e.target.value }))}
              placeholder="No change"
              style={{ width: '100%', background: PALETTE.bg3, border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '5px 7px', color: PALETTE.textDim, fontSize: 11, outline: 'none', fontFamily: FONTS.mono, boxSizing: 'border-box' }} />
          </div>

          {/* Domain flag */}
          <div style={{ width: 130 }}>
            <div style={{ fontSize: 9, color: PALETTE.textGhost, marginBottom: 4, textTransform: 'uppercase' }}>Domain flag</div>
            <Select value={bulkEditFields.is_domain} onChange={v => setBulkEditFields(f => ({ ...f, is_domain: v }))}
              style={{ width: '100%' }} placeholder="No change"
              options={[{ value: 'true', label: 'Mark as Domain' }, { value: 'false', label: 'Remove Domain flag' }]} />
          </div>

          {/* Cracked */}
          <div style={{ width: 130 }}>
            <div style={{ fontSize: 9, color: PALETTE.textGhost, marginBottom: 4, textTransform: 'uppercase' }}>Cracked</div>
            <Select value={bulkEditFields.cracked} onChange={v => setBulkEditFields(f => ({ ...f, cracked: v }))}
              style={{ width: '100%' }} placeholder="No change"
              options={[{ value: 'true', label: '✓ Mark cracked' }, { value: 'false', label: 'Unmark cracked' }]} />
          </div>

          {/* Add tags */}
          <div style={{ width: 150 }}>
            <div style={{ fontSize: 9, color: PALETTE.textGhost, marginBottom: 4, textTransform: 'uppercase' }}>Add tags</div>
            <input value={bulkEditFields.addTags} onChange={e => setBulkEditFields(f => ({ ...f, addTags: e.target.value }))}
              placeholder="domain-admin, kerberoastable"
              style={{ width: '100%', background: PALETTE.bg3, border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '5px 7px', color: PALETTE.textDim, fontSize: 11, outline: 'none', fontFamily: FONTS.mono, boxSizing: 'border-box' }} />
          </div>

          {/* Remove tags */}
          <div style={{ width: 130 }}>
            <div style={{ fontSize: 9, color: PALETTE.textGhost, marginBottom: 4, textTransform: 'uppercase' }}>Remove tags</div>
            <input value={bulkEditFields.removeTags} onChange={e => setBulkEditFields(f => ({ ...f, removeTags: e.target.value }))}
              placeholder="old-tag, stale"
              style={{ width: '100%', background: PALETTE.bg3, border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '5px 7px', color: PALETTE.textDim, fontSize: 11, outline: 'none', fontFamily: FONTS.mono, boxSizing: 'border-box' }} />
          </div>

          <button onClick={applyBulkEdit}
            style={{ background: accent, border: 'none', borderRadius: 4, padding: '6px 16px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: FONTS.mono }}>
            Apply to {checkedIds.length}
          </button>
          <button onClick={() => { setShowBulkEdit(false); setBulkEditFields({ type: '', service: '', domain: '', is_domain: '', cracked: '', addTags: '', removeTags: '' }); }}
            style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 10px', cursor: 'pointer', color: PALETTE.textFaint, fontSize: 11, fontFamily: FONTS.mono }}>
            Cancel
          </button>
        </div>
      )}

      {/* Quick add form */}
      {showAdd && (
        <div style={{ padding: '14px 18px', borderBottom: `1px solid ${PALETTE.borderSoft}`, background: '#0c0e13', display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'flex-end' }}>
          <div style={{ width: 150 }}>
            <div style={{ fontSize: 9, color: PALETTE.textGhost, marginBottom: 4, textTransform: 'uppercase' }}>Username</div>
            <input value={newCred.username} onChange={e => setNewCred(c => ({ ...c, username: e.target.value }))} autoFocus
              style={{ width: '100%', background: PALETTE.bg3, border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '5px 7px', color: PALETTE.textDim, fontSize: 11, outline: 'none', fontFamily: FONTS.mono, boxSizing: 'border-box' }} />
          </div>
          <div style={{ flex: 1, minWidth: 160 }}>
            <div style={{ fontSize: 9, color: PALETTE.textGhost, marginBottom: 4, textTransform: 'uppercase' }}>Secret / Hash</div>
            <input value={newCred.secret} onChange={e => setNewCred(c => ({ ...c, secret: e.target.value }))}
              style={{ width: '100%', background: PALETTE.bg3, border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '5px 7px', color: PALETTE.textDim, fontSize: 11, outline: 'none', fontFamily: FONTS.mono, boxSizing: 'border-box' }} />
          </div>
          <div>
            <div style={{ fontSize: 9, color: PALETTE.textGhost, marginBottom: 4, textTransform: 'uppercase' }}>Type</div>
            <Select value={newCred.type} onChange={v => setNewCred(c => ({ ...c, type: v }))}
              options={Object.entries(CRED_TYPES).map(([k, v]) => ({ value: k, label: v.label }))} />
          </div>
          <div style={{ width: 120 }}>
            <div style={{ fontSize: 9, color: PALETTE.textGhost, marginBottom: 4, textTransform: 'uppercase' }}>Host (quick)</div>
            <Select value={newCred.host} onChange={v => setNewCred(c => ({ ...c, host: v }))}
              style={{ width: '100%' }} placeholder="—"
              options={projectHosts.map(h => ({ value: h.ip, label: `${h.ip}${h.hostname ? ` (${h.hostname})` : ''}` }))} />
          </div>
          <div style={{ width: 150 }}>
            <div style={{ fontSize: 9, color: PALETTE.textGhost, marginBottom: 4, textTransform: 'uppercase' }}>Domain</div>
            <input value={newCred.domain} onChange={e => setNewCred(c => ({ ...c, domain: sanitizeDomainDraft(e.target.value) }))}
              style={{ width: '100%', background: PALETTE.bg3, border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '5px 7px', color: PALETTE.textDim, fontSize: 11, outline: 'none', fontFamily: FONTS.mono, boxSizing: 'border-box' }} />
          </div>
          {/* Domain toggle */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            <div style={{ fontSize: 9, color: PALETTE.textGhost, textTransform: 'uppercase' }}>Flags</div>
            <DomainToggle value={newCred.is_domain} onChange={v => setNewCred(c => ({ ...c, is_domain: v }))} />
          </div>
          <button onClick={addCred}
            style={{ background: accent, border: 'none', borderRadius: 4, padding: '6px 14px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: FONTS.mono }}>
            Save
          </button>
          <button onClick={() => setShowAdd(false)}
            style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 10px', cursor: 'pointer', color: PALETTE.textFaint, fontSize: 11, fontFamily: FONTS.mono }}>
            Cancel
          </button>
        </div>
      )}

      {/* Matrix view */}
      {viewMode === 'matrix' && (
        <div style={{ flex: 1, overflow: 'hidden', padding: '8px 18px', display: 'flex', flexDirection: 'column' }}>
          <CredMatrix pid={selectedProject} accent={accent} />
        </div>
      )}

      {/* Reuse analysis view */}
      {viewMode === 'reuse' && (
        <div style={{ flex: 1, overflow: 'auto', padding: '8px 18px' }}>
          <CredReusePanel pid={selectedProject} accent={accent} />
        </div>
      )}

      {/* Table header */}
      {viewMode === 'list' && <div style={{ display: 'flex', alignItems: 'stretch', padding: '8px 18px', borderBottom: `1px solid ${PALETTE.borderSoft}`, background: '#090b0f', flexShrink: 0 }}>
        <div style={{ width: 28, flexShrink: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', borderRight: colBorder, paddingRight: 12, marginRight: 12 }}>
          <Checkbox checked={checkedIds.length === filtered.length && filtered.length > 0} accent={accent}
            onChange={v => setCheckedIds(v ? filtered.map(c => c.id) : [])} />
        </div>
        {[
          ['Username', 'username', widths.username],
          ['Type', 'type', widths.type],
          ['Service', 'service', widths.service],
          ['Hosts', 'hosts', widths.hosts],
          ['Tags', 'tags', widths.tags],
        ].map(([label, key, width]) => (
          <div key={key} style={{ width, flexShrink: 0, fontSize: Math.max(9, fs - 4), color: PALETTE.textGhost, textTransform: 'uppercase', letterSpacing: '0.1em', position: 'relative', minWidth: 0, borderRight: colBorder, paddingRight: 12, marginRight: 12 }}>
            {label}
            <button type="button" onMouseDown={(e) => startResize(key, e)} style={{ position: 'absolute', right: -6, top: -8, bottom: -8, width: 12, cursor: 'col-resize', background: 'none', border: 'none', padding: 0, outline: 'none' }} />
          </div>
        ))}
        <div style={{ flex: 1, minWidth: 0, fontSize: Math.max(9, fs - 4), color: PALETTE.textGhost, textTransform: 'uppercase', letterSpacing: '0.1em', borderRight: colBorder, paddingRight: 12, marginRight: 12 }}>Secret / Hash</div>
        <div style={{ width: widths.cracked, flexShrink: 0, fontSize: Math.max(9, fs - 4), color: PALETTE.textGhost, textTransform: 'uppercase', letterSpacing: '0.1em', position: 'relative', borderRight: colBorder, paddingRight: 12, marginRight: 12, display: 'flex', alignItems: 'center', justifyContent: 'center', textAlign: 'center', overflow: 'hidden', whiteSpace: 'nowrap' }}>
          <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>Cracked</span>
          <button type="button" onMouseDown={(e) => startResize('cracked', e)} style={{ position: 'absolute', right: -6, top: -8, bottom: -8, width: 12, cursor: 'col-resize', background: 'none', border: 'none', padding: 0, outline: 'none' }} />
        </div>
        <div style={{ width: 56 }} />
      </div>}

      {viewMode === 'list' && <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
        {/* Rows */}
        <div style={{ flex: 1, overflowY: 'auto' }}>
          {filtered.length === 0 && <div style={{ padding: 32, textAlign: 'center', color: PALETTE.textGhost, fontSize: 12 }}>No credentials</div>}
          {filtered.map(cred => (
            <CredRow key={cred.id} id={`cred-${cred.id}`} cred={cred}
              isSel={selectedId === cred.id}
              isCopied={copied === cred.id}
              revealedSecret={revealed[cred.id]?.secret}
              revealTtl={revealed[cred.id]?.ttl}
              canReadSecret={canReadSecret}
              checkedIds={checkedIds}
              widths={widths} colBorder={colBorder}
              accent={accent} fs={fs}
              projectHosts={projectHosts}
              setSelectedId={setSelectedId}
              setCheckedIds={setCheckedIds}
              onReveal={reveal}
              onHide={hide}
              copy={copy}
              onUpdate={onUpdate}
              onDelete={onDelete}
            />
          ))}
        </div>

        {/* ── Edit panel ─────────────────────────────────────────────── */}
        {selCred && (
          <div style={{ width: 300, background: '#0c0e13', borderLeft: '1px solid #1e2029', overflowY: 'auto', flexShrink: 0 }}>
            <div style={{ padding: '12px 14px', borderBottom: '1px solid #1e2029', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <span style={{ fontSize: 11, fontWeight: 600, color: '#e0e4ec', fontFamily: FONTS.display }}>Edit</span>
              <button onClick={() => setSelectedId(null)} style={{ background: 'none', border: 'none', cursor: 'pointer', display: 'flex' }}>
                <Icon name="close" size={12} color="#606570" />
              </button>
            </div>

            <div style={{ padding: 14, display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                {getCredBadges(selCred).map(b => <Badge key={b.label} label={b.label} color={b.color} />)}
              </div>
              <FieldInput label="Username" value={selCred.username} onChange={v => onUpdate(selCred.id, { username: v })} placeholder="DOMAIN\admin" />
              {canReadSecret
                ? (() => {
                    const sid = selCred.id;
                    const isRevealed = !!revealed[sid];
                    const secretValue = secretDraft !== null ? secretDraft : (revealed[sid]?.secret ?? '');
                    return (
                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
                          <span style={{ fontSize: 9, color: '#505560', textTransform: 'uppercase', letterSpacing: '.1em' }}>Secret / Password / Hash</span>
                          <button onClick={() => isRevealed ? hide(sid) : reveal(sid)}
                            title={isRevealed ? 'Hide' : 'Reveal'}
                            style={{ background: 'none', border: 'none', cursor: 'pointer', display: 'flex', alignItems: 'center', padding: 0 }}>
                            <Icon name={isRevealed ? 'eyeOff' : 'eye'} size={12} color={isRevealed ? '#5b8af5' : PALETTE.textGhost} />
                          </button>
                        </div>
                        <FieldInput value={secretValue} onChange={v => { setSecretDraft(v); onUpdate(sid, { secret: v }); }} placeholder={isRevealed ? 'P@ssw0rd or NTLM' : '••••••••'} />
                      </div>
                    );
                  })()
                : <div style={{ fontSize: 10, color: PALETTE.textGhost, fontFamily: FONTS.mono, padding: '6px 0' }}>Secret / Hash — <span style={{ color: '#303540' }}>access restricted</span></div>
              }

              {/* Type */}
              <div>
                <div style={{ fontSize: 9, color: '#505560', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '.1em' }}>Type</div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                  {Object.entries(CRED_TYPES).map(([k, v]) => (
                    <button key={k} onClick={() => onUpdate(selCred.id, { type: k })}
                      style={{ background: selCred.type === k ? `${v.color}22` : PALETTE.bg3, border: `1px solid ${selCred.type === k ? v.color + '77' : PALETTE.border}`, borderRadius: 3, padding: '3px 9px', cursor: 'pointer', color: selCred.type === k ? v.color : PALETTE.textFaint, fontSize: 9, fontFamily: FONTS.mono, transition: 'all .1s' }}>
                      {v.label}
                    </button>
                  ))}
                </div>
              </div>

              {/* Domain toggle */}
              <div>
                <div style={{ fontSize: 9, color: '#505560', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '.1em' }}>Scope</div>
                <DomainToggle value={selCred.is_domain} onChange={v => onUpdate(selCred.id, { is_domain: v })} />
                {selCred.is_domain && (
                  <div style={{ marginTop: 6, fontSize: 10, color: '#808590', lineHeight: 1.5 }}>
                    Applies to all Windows machines in domain.
                    {windowsHosts.length > 0 && (
                      <span style={{ color: '#c07af0' }}> ≈{windowsHosts.length} host{windowsHosts.length === 1 ? '' : 's'} in project.</span>
                    )}
                  </div>
                )}
              </div>

              {/* Multi-host selector */}
              <div>
                <div style={{ fontSize: 9, color: '#505560', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '.1em' }}>
                  Confirmed hosts
                  {(selCred.host_ids || []).length > 0 && (
                    <span style={{ color: '#5b8af5', marginLeft: 6 }}>{(selCred.host_ids || []).length}</span>
                  )}
                </div>
                <HostSelector
                  selectedIds={selCred.host_ids || []}
                  onChange={ids => onUpdate(selCred.id, { host_ids: ids })}
                  projectHosts={projectHosts}
                  domainFilter={selCred.is_domain ? normalizeDomain(selCred.domain || '') : ''}
                />
                {(selCred.host_ids || []).length > 0 && selCred.is_domain && (
                  <div style={{ marginTop: 4, fontSize: 9, color: PALETTE.ok, fontFamily: FONTS.mono }}>
                    ✓ {(selCred.host_ids || []).length} confirmed + ≈{windowsHosts.filter(h => !(selCred.host_ids || []).includes(h.id)).length} predicted
                  </div>
                )}
              </div>

              {/* Legacy single host (free text) */}
              <div>
                <div style={{ fontSize: 9, color: '#505560', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '.1em' }}>Additional host (text)</div>
                <input value={selCred.host || ''} onChange={e => onUpdate(selCred.id, { host: e.target.value })} placeholder="10.0.0.1 or any text"
                  style={{ width: '100%', background: '#0a0c10', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '5px 7px', color: PALETTE.textDim, fontSize: 11, outline: 'none', fontFamily: FONTS.mono, boxSizing: 'border-box' }} />
              </div>

              <FieldInput label="Domain" value={selCred.domain || ''} onChange={v => onUpdate(selCred.id, { domain: sanitizeDomainDraft(v) })} placeholder="edu or edu.local" />

              {/* Service */}
              <div>
                <div style={{ fontSize: 9, color: '#505560', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '.1em' }}>Service</div>
                <Select value={COMMON_SERVICES.includes(selCred.service) ? selCred.service : '__custom'}
                  onChange={v => { if (v !== '__custom') onUpdate(selCred.id, { service: v }); }}
                  style={{ width: '100%', marginBottom: 5 }}
                  options={[{ value: '__custom', label: '— enter manually —' }, ...COMMON_SERVICES.map(s => ({ value: s, label: s }))]} />
                <input value={selCred.service || ''} onChange={e => onUpdate(selCred.id, { service: e.target.value })} placeholder="SSH"
                  style={{ width: '100%', background: '#0a0c10', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '5px 7px', color: PALETTE.textDim, fontSize: 11, outline: 'none', fontFamily: FONTS.mono, boxSizing: 'border-box' }} />
              </div>

              <TagEditor label="Tags" tags={selCred.tags || []} onChange={tags => onUpdate(selCred.id, { tags })} placeholder="domain-admin, kerberoastable" />

              {/* Cracked */}
              <div>
                <div style={{ fontSize: 9, color: '#505560', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '.1em' }}>Status</div>
                <div style={{ display: 'flex', gap: 6 }}>
                  {[[false, 'Hash/token', '#404550'], [true, '✓ Cracked', '#39d353']].map(([v, l, c]) => (
                    <button key={String(v)} onClick={() => onUpdate(selCred.id, { cracked: v })}
                      style={{ flex: 1, background: selCred.cracked === v ? `${c}18` : 'transparent', border: `1px solid ${selCred.cracked === v ? c + '66' : PALETTE.border}`, borderRadius: 4, padding: '5px 8px', cursor: 'pointer', color: selCred.cracked === v ? c : PALETTE.textFaint, fontSize: 10, fontFamily: FONTS.mono, transition: 'all .1s' }}>
                      {l}
                    </button>
                  ))}
                </div>
              </div>

              <FieldInput label="Notes" value={selCred.notes || ''} onChange={v => onUpdate(selCred.id, { notes: v })} placeholder="Where found, context..." textarea />

              {/* Validate button — only when username + secret are filled */}
              {selCred.username?.trim() && selCred.secret?.trim() && (
              <div>
                <button onClick={() => setShowValidate(v => !v)}
                  style={{ width: '100%', background: showValidate ? `${accent || '#5b8af5'}22` : PALETTE.bg3, border: `1px solid ${showValidate ? (accent || '#5b8af5') + '66' : PALETTE.border}`, borderRadius: 4, padding: '6px 10px', cursor: 'pointer', color: showValidate ? (accent || '#5b8af5') : PALETTE.textFaint, fontSize: 10, fontFamily: FONTS.mono, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 6, justifyContent: 'center' }}>
                  <Icon name="terminal" size={11} color="currentColor" />
                  {showValidate ? 'Hide validator' : 'Validate credential'}
                </button>
                {showValidate && (
                  <ValidateCredPanel
                    cred={selCred}
                    projectHosts={projectHosts}
                    selectedProject={selectedProject}
                    accent={accent}
                    onClose={() => setShowValidate(false)}
                  />
                )}
              </div>
              )}

              {/* Summary */}
              {(() => {
                const { confirmed, predicted } = getApplicableHosts(selCred, projectHosts);
                if (!confirmed.length && !predicted.length) {
                  return null;
                }
                return (
                  <div style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 6, padding: '10px 12px' }}>
                    <div style={{ fontSize: 9, color: '#505560', textTransform: 'uppercase', letterSpacing: '.1em', marginBottom: 8 }}>Potential access</div>
                    {confirmed.map(h => (
                      <div key={h.id} style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                        <span style={{ width: 6, height: 6, borderRadius: '50%', background: PALETTE.ok, flexShrink: 0 }} />
                        <span style={{ fontSize: 10, color: PALETTE.textMute, fontFamily: FONTS.mono }}>{h.ip}{h.hostname ? ` (${h.hostname})` : ''}</span>
                        <span style={{ fontSize: 8, color: PALETTE.ok }}>✓ confirmed</span>
                        <button onClick={() => onNavigate?.('hosts', h.id)} style={{ background: 'none', border: 'none', cursor: 'pointer', fontSize: 8, color: '#5b8af5', fontFamily: FONTS.mono, padding: 0, textDecoration: 'underline' }}>Go to host</button>
                      </div>
                    ))}
                    {predicted.map(h => (
                      <div key={h.id} style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                        <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#c07af066', flexShrink: 0 }} />
                        <span style={{ fontSize: 10, color: PALETTE.textFaint, fontFamily: FONTS.mono }}>{h.ip}{h.hostname ? ` (${h.hostname})` : ''}</span>
                        <span style={{ fontSize: 8, color: '#c07af0' }}>~ domain</span>
                      </div>
                    ))}
                  </div>
                );
              })()}
            </div>
          </div>
        )}
      </div>}
    </div>
  );
}

export default function CredsView({ creds, onAdd, onUpdate, onDelete, selectedProject, accent, hosts, fs = 14, focusId, consumeFocusId, onNavigate }) {
  const { can, isSuperAdmin } = useProjectPermissions();
  const canReadSecret = isSuperAdmin || can('credentials.read_secret');
  const [credsTab, setCredsTab] = useState('credentials');
  const [search, setSearch] = useState('');
  const [filterType, setFilterType] = useState(null);
  const [filterDomain, setFilterDomain] = useState(false);
  const [filterTag, setFilterTag] = useState(null);
  const { revealed, reveal, hide } = useSecretReveal();
  const [showAdd, setShowAdd] = useState(false);
  const [showBulk, setShowBulk] = useState(false);
  const [showBulkEdit, setShowBulkEdit] = useState(false);
  const [newCred, setNewCred] = useState({ username: '', secret: '', type: 'plain', service: '', host: '', domain: '', cracked: false, notes: '', tags: [], is_domain: false, host_ids: [] });
  const [bulkDelimiter, setBulkDelimiter] = useState(';');
  const [bulkText, setBulkText] = useState('');
  const [bulkEditFields, setBulkEditFields] = useState({ type: '', service: '', domain: '', is_domain: '', cracked: '', addTags: '', removeTags: '' });
  const [copied, setCopied] = useState(null);
  const [selectedId, setSelectedId] = useState(null);
  const [checkedIds, setCheckedIds] = useState([]);
  const [showValidate, setShowValidate] = useState(false);
  const [viewMode, setViewMode] = useState('list'); // 'list' | 'matrix' | 'reuse'
  const { widths, startResize } = useColumnResize({ username: 150, type: 90, service: 90, hosts: 160, tags: 160, cracked: 70 });
  const colBorder = '1px solid #14161b';

  const deferredSearch = useDeferredValue(search);
  const projectHosts = useMemo(() => _computeProjectHosts(hosts, selectedProject), [hosts, selectedProject]);
  const windowsHosts = useMemo(() => _computeWindowsHosts(projectHosts), [projectHosts]);
  const projectCreds = useMemo(() => _computeProjectCreds(creds, selectedProject), [creds, selectedProject]);
  const filtered = useMemo(() => _computeFilteredCreds(projectCreds, filterType, filterDomain, filterTag, deferredSearch), [projectCreds, filterType, filterDomain, filterTag, deferredSearch]);
  const selCred = useMemo(() => _findSelCred(creds, selectedId), [creds, selectedId]);
  const crackedCount = useMemo(() => _countCracked(filtered), [filtered]);
  const domainCount = useMemo(() => _countDomain(projectCreds), [projectCreds]);
  const tagCounts = useMemo(() => _computeTagCounts(projectCreds), [projectCreds]);

  const copy = (text, id) => _copyCred(text, id, setCopied);
  const addCred = () => _addNewCred(newCred, selectedProject, onAdd, setNewCred, setShowAdd);
  const handleExportCsv = () => _exportCredsCsv(selectedProject);
  const importBulkCreds = () => _importBulkCredsAction(bulkDelimiter, bulkText, selectedProject, onAdd, setBulkText, setShowBulk);
  const applyBulkEdit = async () => { await _applyBulkEditPatch(checkedIds, creds, bulkEditFields, onUpdate); setBulkEditFields({ type: '', service: '', domain: '', is_domain: '', cracked: '', addTags: '', removeTags: '' }); setShowBulkEdit(false); setCheckedIds([]); };

  useEffect(() => {
    if (!focusId) return;
    const cred = creds.find(c => c.id === focusId);
    if (cred) {
      setSelectedId(cred.id);
      requestAnimationFrame(() => {
        document.getElementById(`cred-${focusId}`)?.scrollIntoView({ behavior: 'smooth', block: 'center' });
      });
    }
    consumeFocusId?.();
  }, [focusId]);

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <div style={{ display: 'flex', gap: 0, padding: '0 16px', borderBottom: '1px solid #1e2029' }}>
        {['credentials', 'vault'].map(t => (
          <button key={t} onClick={() => setCredsTab(t)}
            style={{ padding: '8px 16px', fontSize: 10, fontFamily: FONTS.mono, cursor: 'pointer', border: 'none', borderBottom: credsTab === t ? `2px solid ${accent}` : '2px solid transparent', background: 'transparent', color: credsTab === t ? accent : PALETTE.textFaint }}>
            {t === 'credentials' ? 'Credentials' : 'Secret Vault'}
          </button>
        ))}
      </div>
      {credsTab === 'credentials' ? (
        <CredsViewBody accent={accent} fs={fs} creds={creds} selectedProject={selectedProject} onAdd={onAdd} onUpdate={onUpdate} onDelete={onDelete} projectHosts={projectHosts} windowsHosts={windowsHosts} projectCreds={projectCreds} filtered={filtered} selCred={selCred} crackedCount={crackedCount} domainCount={domainCount} tagCounts={tagCounts} search={search} setSearch={setSearch} filterType={filterType} setFilterType={setFilterType} filterDomain={filterDomain} setFilterDomain={setFilterDomain} filterTag={filterTag} setFilterTag={setFilterTag} revealed={revealed} reveal={reveal} hide={hide} showAdd={showAdd} setShowAdd={setShowAdd} showBulk={showBulk} setShowBulk={setShowBulk} showBulkEdit={showBulkEdit} setShowBulkEdit={setShowBulkEdit} newCred={newCred} setNewCred={setNewCred} bulkDelimiter={bulkDelimiter} setBulkDelimiter={setBulkDelimiter} bulkText={bulkText} setBulkText={setBulkText} bulkEditFields={bulkEditFields} setBulkEditFields={setBulkEditFields} copied={copied} selectedId={selectedId} setSelectedId={setSelectedId} checkedIds={checkedIds} setCheckedIds={setCheckedIds} showValidate={showValidate} setShowValidate={setShowValidate} viewMode={viewMode} setViewMode={setViewMode} widths={widths} startResize={startResize} colBorder={colBorder} canReadSecret={canReadSecret} copy={copy} addCred={addCred} handleExportCsv={handleExportCsv} importBulkCreds={importBulkCreds} applyBulkEdit={applyBulkEdit} onNavigate={onNavigate} />
      ) : (
        <div style={{ flex: 1, overflow: 'auto', padding: '8px 16px' }}>
          <SecretVaultTab selectedProject={selectedProject} accent={accent} />
        </div>
      )}
    </div>
  );
}

CredsView.propTypes = {
  creds: PropTypes.arrayOf(credPropType).isRequired,
  onAdd: PropTypes.func.isRequired,
  onUpdate: PropTypes.func.isRequired,
  onDelete: PropTypes.func.isRequired,
  selectedProject: PropTypes.any,
  accent: PropTypes.string.isRequired,
  hosts: PropTypes.arrayOf(hostPropType).isRequired,
  fs: PropTypes.number,
  focusId: PropTypes.any,
  consumeFocusId: PropTypes.func,
  onNavigate: PropTypes.func,
};
