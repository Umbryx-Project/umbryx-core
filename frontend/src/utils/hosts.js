export function toggleId(prev, id, checked) {
  return checked ? [...prev, id] : prev.filter(x => x !== id);
}

export function updateIpAtIndex(selHost, idx, value) {
  const baseIps = selHost.ips?.length > 0 ? [...selHost.ips] : [];
  let current;
  if (baseIps.length > 0) {
    current = baseIps;
  } else if (selHost.ip) {
    current = [selHost.ip];
  } else {
    current = [''];
  }
  const next = [...current];
  next[idx] = value;
  const filtered = next.filter(x => x?.trim());
  return { ips: filtered, ip: filtered[0] || '' };
}

export function removeIpAtIndex(selHost, idx) {
  const baseIps = selHost.ips?.length > 0 ? [...selHost.ips] : [];
  let current;
  if (baseIps.length > 0) {
    current = baseIps;
  } else if (selHost.ip) {
    current = [selHost.ip];
  } else {
    current = [];
  }
  const next = current.filter((_, i) => i !== idx);
  return { ips: next, ip: next[0] || '' };
}

export function resolvedLinkType(linkedByIds, linkedByIp, isDomainHost) {
  if (linkedByIds) return 'linked';
  if (linkedByIp) return 'ip';
  if (isDomainHost) return 'domain';
  return 'domain?';
}

export function hostRowBg(isSel, isChecked) {
  if (isSel) return '#ffffff0a';
  if (isChecked) return '#ffffff05';
  return 'transparent';
}

export function hostRowBorderLeft(isSel, isChecked, accent) {
  if (isSel) return `2px solid ${accent}`;
  if (isChecked) return `2px solid ${accent}88`;
  return '2px solid transparent';
}

export function resultBg(r) {
  if (r.ok) return '#39d35310';
  if (r.error) return '#f09a3a10';
  return '#cc223310';
}

export function resultBorder(r) {
  if (r.ok) return '#39d35333';
  if (r.error) return '#f09a3a33';
  return '#cc223333';
}

export function getBulkCredentialPacks(hosts, cred) {
  if (!cred) return [];
  const allWindows = hosts.length > 0 && hosts.every(h => String(h.os || '').toLowerCase().includes('win'));
  const allLinux = hosts.length > 0 && hosts.every(h => {
    const os = String(h.os || '').toLowerCase();
    return os.includes('linux') || os.includes('ubuntu') || os.includes('debian') || os.includes('centos') || os.includes('redhat');
  });
  const hasDomain = hosts.some(h => (h.domain || '').trim()) || Boolean((cred.domain || '').trim());
  const type = String(cred.type || '').toLowerCase();
  const isHash = type.includes('hash') || type.includes('ntlm');
  const packs = [];
  if (allWindows) {
    if (isHash) {
      packs.push({ id: 'bulk-smb-hash', label: 'SMB hash sweep', cmd: 'netexec smb {target} -u {{USER}} -H {{HASH}}', type: 'exec', activity: 'recon' }, { id: 'bulk-wmi-hash', label: 'WMI hash exec', cmd: 'impacket-wmiexec {{DOMAIN}}/{{USER}}@{target} -hashes :{{HASH}}', type: 'exec', activity: 'postex' });
    } else {
      packs.push({ id: 'bulk-smb-pass', label: 'SMB auth sweep', cmd: 'netexec smb {target} -u {{USER}} -p {{PASS}}', type: 'exec', activity: 'recon' }, { id: 'bulk-winrm-pass', label: 'WinRM sweep', cmd: 'netexec winrm {target} -u {{USER}} -p {{PASS}}', type: 'exec', activity: 'recon' }, { id: 'bulk-wmi-pass', label: 'WMI exec sweep', cmd: 'impacket-wmiexec {{DOMAIN}}/{{USER}}:{{PASS}}@{target}', type: 'exec', activity: 'postex' }, { id: 'bulk-psexec-pass', label: 'PsExec sweep', cmd: 'impacket-psexec {{DOMAIN}}/{{USER}}:{{PASS}}@{target}', type: 'exec', activity: 'postex' });
    }
    if (hasDomain && !isHash) packs.push({ id: 'bulk-ldap-bind', label: 'LDAP bind sweep', cmd: 'ldapsearch -x -H ldap://{target} -D "{{USER}}@{{DOMAIN}}" -w "{{PASS}}" -b "" "(objectClass=*)"', type: 'exec', activity: 'recon' });
  }
  if (allLinux && !isHash) {
    packs.push({ id: 'bulk-ssh-pass', label: 'SSH sweep', cmd: 'sshpass -p "{{PASS}}" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 {{USER}}@{target} "whoami && hostname"', type: 'exec', activity: 'postex' });
  }
  return packs;
}

export const BULK_TEMPLATES = {
  nmap:    { label: 'Nmap quick',  cmd: 'nmap -sV -sC -T4 {target}',       type: 'nmap',  activity: 'recon' },
  nmap_f:  { label: 'Nmap full',   cmd: 'nmap -p- -T4 --open {target}',    type: 'nmap',  activity: 'recon' },
  cme:     { label: 'NetExec SMB', cmd: 'netexec smb {target}',            type: 'cme',   activity: 'recon' },
  cme_all: { label: 'NetExec ALL', cmd: 'netexec all {target}',            type: 'cme',   activity: 'recon' },
  exec:    { label: 'Custom',      cmd: '',                                 type: 'exec',  activity: 'postex' },
};

export const ACCESS_ROLES = [
  { id: 'local_admin', label: 'LA', title: 'Local Admin' },
  { id: 'domain_admin', label: 'DA', title: 'Domain Admin' },
  { id: 'rdp', label: 'RDP', title: 'RDP access' },
  { id: 'ssh', label: 'SSH', title: 'SSH access' },
  { id: 'winrm', label: 'WRM', title: 'WinRM access' },
  { id: 'no_rights', label: 'None', title: 'No rights' },
];

export const ACTIVITY_TYPES = {
  recon:   { label: 'Recon', color: '#5b8af5' },
  scan:    { label: 'Scan', color: '#6fc8f0' },
  exploit: { label: 'Exploit', color: '#e8574a' },
  privesc: { label: 'PrivEsc', color: '#f09a3a' },
  lateral: { label: 'Lateral', color: '#e8cc42' },
  postex:  { label: 'PostEx', color: '#39d353' },
  note:    { label: 'Note', color: '#808590' },
};

export const ACTIVITY_STATUS = {
  planned: { label: 'Planned', color: '#5b8af5' },
  running: { label: 'Running', color: '#f09a3a' },
  done:    { label: 'Done', color: '#39d353' },
  unconfirmed: { label: 'Unconfirmed', color: '#e0a820' },
  failed:  { label: 'Failed', color: '#cc2233' },
};
