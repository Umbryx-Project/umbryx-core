import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import ImportModal from './ImportModal.jsx';
import { parseScan } from './NmapParser.jsx';

vi.mock('../api.js', () => ({
  api: {
    getScopes: vi.fn(),
    batchImport: vi.fn(),
    importNessus: vi.fn(),
    importBurp: vi.fn(),
    importBloodHound: vi.fn(),
    firewallConfigPreview: vi.fn(),
    getJob: vi.fn(),
  },
}));

import { api } from '../api.js';

const NMAP_ON = `Starting Nmap 7.95 ( https://nmap.org ) at 2026-10-22 00:00 MSK
Nmap scan report for 10.124.2.34
Host is up (0.0062s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
53/tcp open  domain  ISC BIND 9.18.30
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap done: 1 IP address (1 host up) scanned in 3.02 seconds`;

function openModal() {
  const onClose = vi.fn();
  render(<ImportModal projectId="p1" accent="#15bbb1" onClose={onClose} />);
  return onClose;
}

beforeEach(() => {
  vi.clearAllMocks();
  api.getScopes.mockResolvedValue([]);
});

describe('ImportModal — unified parsers tab', () => {
  it('lists nmap and bloodhound modes (the consolidated entry points)', async () => {
    openModal();
    expect(await screen.findByText('Nmap')).toBeTruthy();
    expect(screen.getByText('BloodHound')).toBeTruthy();
    expect(screen.getByText('NetExec / CME')).toBeTruthy();
  });

  it('nmap mode accepts pasted -oN text and parses it into a preview', async () => {
    openModal();
    await screen.findByText('Nmap');
    const ta = screen.getByPlaceholderText(/Nmap scan report for/);
    fireEvent.change(ta, { target: { value: NMAP_ON } });
    fireEvent.click(screen.getByText('Parse'));
    // preview table shows the discovered host
    await waitFor(() => expect(screen.getByText('10.124.2.34')).toBeTruthy());
    // and the import button carries the parsed payload through batchImport
    api.batchImport.mockResolvedValue({ hosts_added: 1, creds_added: 0, hosts_skipped: 0 });
    fireEvent.click(screen.getByRole('button', { name: 'Import' }));
    await waitFor(() => expect(api.batchImport).toHaveBeenCalled());
    const body = api.batchImport.mock.calls[0][1];
    const host = body.hosts.find(h => h.ip === '10.124.2.34');
    // frontend parsers emit bare port numbers; the canonical '22/tcp'
    // normalization happens at the batch-import boundary (backend,
    // covered by test_scan_helpers) — one normalization point.
    expect(host.ports).toEqual(['22', '53']);
    expect(host.services.some(s => /ssh/i.test(s))).toBe(true);
  });

  it('shows a parse error for garbage input without crashing', async () => {
    openModal();
    await screen.findByText('Nmap');
    fireEvent.change(screen.getByPlaceholderText(/Nmap scan report for/), {
      target: { value: 'hello world not a scan' },
    });
    fireEvent.click(screen.getByText('Parse'));
    await waitFor(() => expect(screen.getByText(/Parse error/i)).toBeTruthy());
  });
});

describe('parseScan — -oG hostname/ip fields', () => {
  it('no-PTR grepable host must not copy the IP into hostname (old swap bug)', () => {
    const out = parseScan('Host: 10.124.2.34 (10.124.2.34)\tPorts: 22/open/tcp//ssh (OpenSSH 8.2p1)///\tIgnored State: closed (998)');
    expect(out.fmt).toBe('nmap-grep');
    expect(out.hosts).toHaveLength(1);
    expect(out.hosts[0].ip).toBe('10.124.2.34');
    expect(out.hosts[0].hostname).toBe('');
  });

  it('grepable host WITH a name keeps name and ip in their fields', () => {
    const out = parseScan('Host: exchange.icg.stf (10.124.2.3)\tPorts: 443/open/tcp//ssl/http (IIS)///');
    expect(out.hosts[0].ip).toBe('10.124.2.3');
    expect(out.hosts[0].hostname).toBe('exchange.icg.stf');
  });
});

describe('ImportModal — embedded BloodHound', () => {
  it('bloodhound mode renders the embedded parser (drop zone) inside the modal', async () => {
    openModal();
    await screen.findByText('Nmap');
    fireEvent.click(screen.getByText('BloodHound'));
    // BloodHoundParser's own chrome appears INSIDE the modal (embedded),
    // and its fixed-position overlay wrapper must NOT exist.
    await waitFor(() => expect(screen.getByText(/Drop SharpHound/i)).toBeTruthy());
    // exactly ONE fixed overlay exists — the Import modal itself. The
    // embedded parser must not add its own (the old standalone wrapper).
    const overlays = document.querySelectorAll('div[style*="position: fixed"]');
    expect(overlays).toHaveLength(1);
  });
});
