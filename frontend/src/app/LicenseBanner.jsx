import { useCallback, useEffect, useState } from 'react';
import { api } from '../api/index.ts';

// Global, non-dismissable license banner shown to every authenticated user
// in the `grace` and `wind_down` lifecycle states (ФТ-18). Uses the
// lightweight /system/license/state endpoint (any user), not the
// admin-only /status. Silent in active/unlicensed states.
export default function LicenseBanner() {
  const [state, setState] = useState(null);

  const load = useCallback(async () => {
    try {
      setState(await api.getLicenseState());
    } catch {
      setState(null); // e.g. transient error — just don't show the banner
    }
  }, []);

  useEffect(() => {
    load();
    const iv = setInterval(load, 5 * 60 * 1000);
    return () => clearInterval(iv);
  }, [load]);

  if (!state || (state.state !== 'grace' && state.state !== 'wind_down')) return null;

  const windDown = state.state === 'wind_down';
  const color = windDown ? '#cc2233' : '#f09a3a';
  const left = state.days_left;

  const message = windDown
    ? 'This installation’s license has lapsed. Creating and operating resources is paused — you can still view, export, and wind down infrastructure. Contact an administrator to renew; no data was lost.'
    : `This installation’s license has expired and is in its grace period${
        left != null && left < 0 ? `, about ${state.grace_days + left} day(s) before functionality is limited` : ''
      }. Ask an administrator to renew to avoid interruption.`;

  return (
    <div
      role="status"
      style={{
        background: `${color}18`,
        borderBottom: `1px solid ${color}`,
        color,
        fontFamily: 'JetBrains Mono',
        fontSize: 12,
        padding: '7px 16px',
        display: 'flex',
        alignItems: 'center',
        gap: 8,
      }}
    >
      <span style={{ fontWeight: 700 }}>{windDown ? 'License lapsed' : 'License expired'}</span>
      <span style={{ opacity: 0.9 }}>{message}</span>
    </div>
  );
}
