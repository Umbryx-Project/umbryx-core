import { useState, useEffect, useCallback } from 'react';
import PropTypes from 'prop-types';
import { api } from '../api.js';
import {
  Overline, PALETTE, FONTS, LOG_ROW_STYLE, LOG_HEADER_STYLE, logRowHover, logRowUnhover,
} from '../components/UI.jsx';

const WS_ACTION_GRID = '96px 110px 90px 1fr 130px';

/**
 * Every operator command typed on a workstation, newest first.
 *
 * This used to sit at the bottom of the Infrastructure page's DevOps tab,
 * which is Enterprise-only — so in Community it was unreachable, even though
 * /workstations/actions-feed is a core endpoint and docs/modules/EDITIONS.md
 * is explicit that this log belongs in every edition: revoking access and
 * seeing what was run are safety features, not paid ones. It lives with
 * Workstations now, which is where its data comes from and which both
 * editions have.
 */
export default function WorkstationActionsLog({ limit = 100 }) {
  const [actions, setActions] = useState(null);

  const load = useCallback(async () => {
    try {
      const r = await api.wsActionsFeed(limit);
      setActions(r.actions || []);
    } catch {
      setActions([]);
    }
  }, [limit]);

  useEffect(() => { load(); }, [load]);

  // The feed must refresh while the page is open — the backend harvests
  // pull-mode machines in the background, so a mount-time snapshot goes
  // stale. 10s matches the feed's per-machine pull throttle.
  useEffect(() => {
    const timer = setInterval(load, 10000);
    return () => clearInterval(timer);
  }, [load]);

  return (
    <div>
      <Overline style={{ marginBottom: 8 }}>
        Workstation shell actions ({(actions || []).length})
      </Overline>
      {actions === null ? (
        <div style={{ color: PALETTE.textFaint, fontSize: 12, fontFamily: FONTS.mono }}>Loading…</div>
      ) : actions.length === 0 ? (
        <div style={{ color: PALETTE.textFaint, fontSize: 12, fontFamily: FONTS.mono }}>
          No operator commands recorded — enable the shell hook on a workstation (action log) and type in its shell.
        </div>
      ) : (
        <div style={{ border: `1px solid ${PALETTE.border}`, borderRadius: 6, overflow: 'hidden', maxHeight: 320, display: 'flex', flexDirection: 'column' }}>
          <div style={{ display: 'grid', gridTemplateColumns: WS_ACTION_GRID, gap: 10, flexShrink: 0, ...LOG_HEADER_STYLE }}>
            <span>Time</span><span>Workstation</span><span>User</span><span>Command</span><span>Client</span>
          </div>
          <div style={{ overflow: 'auto' }}>
            {actions.map((a, i) => (
              <div key={a.id || i}
                style={{ display: 'grid', gridTemplateColumns: WS_ACTION_GRID, gap: 10, alignItems: 'start', ...LOG_ROW_STYLE }}
                onMouseEnter={logRowHover} onMouseLeave={logRowUnhover}>
                <span style={{ color: PALETTE.textFaint }}>
                  {a.ts?.slice(11, 19)}
                </span>
                <span style={{ color: '#39d353', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={a.workstation || ''}>
                  {a.workstation}
                </span>
                <span style={{ color: PALETTE.textFaint, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={a.username || ''}>
                  {a.username}
                </span>
                <span style={{ color: PALETTE.textDim, wordBreak: 'break-word' }}>
                  {a.command}
                </span>
                <span style={{ color: PALETTE.textFaint, fontSize: 12, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {a.ssh_client ? `← ${a.ssh_client.split(' ')[0]}` : '—'}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

WorkstationActionsLog.propTypes = {
  limit: PropTypes.number,
};
