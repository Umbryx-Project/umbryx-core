import { useCallback, useEffect, useState } from 'react';
import { api } from '../api/index.ts';

// PlanFeature string values — mirror backend/app/core/plan.py::PlanFeature.
export const FEATURE = {
  INFRA_LIFECYCLE: 'infra_lifecycle',
  WORKSTATIONS: 'workstations',
  DNS_MANAGEMENT: 'dns_management',
  CLOUD_PROVIDER_TIER1: 'cloud_provider_tier1',
  CLOUD_PROVIDER_TIER2: 'cloud_provider_tier2',
  VPN_GENERATION: 'vpn_generation',
  PLUGIN_UPLOAD: 'plugin_upload',
  CUSTOM_TEMPLATES: 'custom_templates',
  ADVANCED_AUDIT: 'advanced_audit',
  API_ACCESS: 'api_access',
  MULTIPLE_ORGS: 'multiple_orgs',
  SSO: 'sso',
};

// The lowest tier that includes each feature — used for the upsell badge
// ("Requires Team / Pro / Enterprise"). Keep in sync with TIER_LIMITS.
export const FEATURE_TIER = {
  [FEATURE.INFRA_LIFECYCLE]: 'Team',
  [FEATURE.WORKSTATIONS]: 'Team',
  [FEATURE.DNS_MANAGEMENT]: 'Team',
  [FEATURE.VPN_GENERATION]: 'Team',
  [FEATURE.CUSTOM_TEMPLATES]: 'Team',
  [FEATURE.API_ACCESS]: 'Team',
  [FEATURE.CLOUD_PROVIDER_TIER1]: 'Pro',
  [FEATURE.PLUGIN_UPLOAD]: 'Pro',
  [FEATURE.ADVANCED_AUDIT]: 'Pro',
  [FEATURE.MULTIPLE_ORGS]: 'Pro',
  [FEATURE.CLOUD_PROVIDER_TIER2]: 'Enterprise',
  [FEATURE.SSO]: 'Enterprise',
};

// Module-level cache so every mounted gate shares one fetch, not N.
let _cache = null;

/**
 * Current instance entitlement (tier / features / limits). Licensing is
 * instance-wide, so a single /system/license/state call covers every org.
 * `hasFeature` fails OPEN while the entitlement is still loading (returns
 * true) so the UI isn't briefly locked on a slow network; once loaded it
 * gates accurately.
 */
export function useEntitlement() {
  const [ent, setEnt] = useState(_cache);

  const load = useCallback(async () => {
    try {
      const [state, ed] = await Promise.all([
        api.getLicenseState(),
        // Edition is a property of the build, not of the license, and the
        // two gate differently: a capability missing from the build is
        // hidden, one missing from the license gets an upsell.
        api.getEdition().catch(() => null),
      ]);
      const e = { ...state, edition: ed?.edition || 'ee', version: ed?.version || '' };
      _cache = e;
      setEnt(e);
    } catch {
      /* leave previous/empty — hasFeature fails open */
    }
  }, []);

  useEffect(() => {
    if (!_cache) load();
    const h = () => load();
    globalThis.addEventListener('rt:license_changed', h);
    return () => globalThis.removeEventListener('rt:license_changed', h);
  }, [load]);

  const hasFeature = useCallback(
    (f) => {
      if (!ent || !Array.isArray(ent.features)) return true; // fail open while loading
      return ent.features.includes(f);
    },
    [ent],
  );

  return {
    ent,
    tier: ent?.tier,
    limits: ent?.limits,
    loading: !ent,
    hasFeature,
    requiredTier: (f) => FEATURE_TIER[f] || 'a higher',
    // Defaults to Enterprise while loading and on error, matching
    // hasFeature's fail-open: a slow or failed call must not briefly blank
    // out the navigation of a paying installation.
    edition: ent?.edition || 'ee',
    isCommunity: (ent?.edition || 'ee') === 'ce',
  };
}
