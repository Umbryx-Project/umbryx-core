import { useState, useEffect, useCallback } from 'react';
import PropTypes from 'prop-types';
import { api } from '../api.js';
import { toastError } from './Toast.jsx';
import { PALETTE, FONTS } from './UI.jsx';

/**
 * Deconfliction claim/release widget — shared by HostsView's host details
 * panel and the network map's node inspector so both surfaces show and
 * control engagement the same way instead of each hand-rolling it.
 */
export default function EngagementBlock({ pid, hostObj }) {
  const [busy, setBusy] = useState(null);
  const [toggling, setToggling] = useState(false);

  const load = useCallback(() => {
    if (!pid || !hostObj) { setBusy(null); return; }
    api.getDeconfliction(pid).then(r => setBusy((r.engagement || {})[hostObj.id] || null)).catch(() => {});
  }, [pid, hostObj]);

  useEffect(() => {
    load();
    const t = setInterval(load, 30000);
    globalThis.addEventListener('rt:host-engagement', load);
    return () => {
      clearInterval(t);
      globalThis.removeEventListener('rt:host-engagement', load);
    };
  }, [load]);

  if (!hostObj) return null;

  // Engagement merges an explicit claim, a fresh job against the host and
  // recent workstation shell activity. Release outranks all three on the
  // server, so offer it whenever the host reads as engaged by me — including
  // when only a job or shell session put it there.
  const meEntry = busy?.operators?.find(o => o.is_me);
  const mine = !!meEntry;
  const sources = (meEntry?.sources || []).join('+');
  const toggle = async () => {
    setToggling(true);
    try {
      if (mine) await api.releaseHost(pid, hostObj.id);
      else await api.claimHost(pid, hostObj.id, { note: '' });
      // Announce locally rather than only refreshing this widget: the map
      // chip has to update too, and the socket round-trip may be down.
      globalThis.dispatchEvent(new CustomEvent('rt:host-engagement', { detail: { action: mine ? 'release' : 'claim', data: { host_id: hostObj.id } } }));
    } catch (e) { toastError(e.message); }
    setToggling(false);
  };

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8, background: busy ? '#f09a3a0d' : 'transparent', border: busy ? '1px solid #f09a3a33' : '1px solid #1e2029', borderRadius: 4, padding: '6px 9px' }}>
      <span style={{ fontSize: 9, color: PALETTE.textGhost, textTransform: 'uppercase' }}>Engagement</span>
      {busy
        ? <span style={{ fontSize: 10, fontFamily: FONTS.mono, color: PALETTE.warn }}>
            {busy.operators.map(o => `${o.username} (${o.sources.join('+')})`).join(', ')}
          </span>
        : <span style={{ fontSize: 10, color: '#505560' }}>nobody — host is free</span>}
      <button onClick={toggle} disabled={toggling} title={mine
        ? `Clear your engagement on this host (currently from: ${sources}). Working on it again re-engages it.`
        : 'Claim this host so teammates see it is taken'} style={{
        marginLeft: 'auto', background: mine ? '#f09a3a18' : 'transparent',
        border: `1px solid ${mine ? '#f09a3a55' : PALETTE.border}`, borderRadius: 4,
        padding: '3px 10px', cursor: toggling ? 'default' : 'pointer', opacity: toggling ? 0.6 : 1,
        color: mine ? '#f09a3a' : '#808590', fontSize: 10, fontFamily: FONTS.mono,
      }}>
        {mine ? 'Release' : 'Engage'}
      </button>
    </div>
  );
}
EngagementBlock.propTypes = { pid: PropTypes.any, hostObj: PropTypes.object };
