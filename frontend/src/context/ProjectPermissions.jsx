import { createContext, useContext, useState, useCallback, useMemo } from 'react';
import PropTypes from 'prop-types';
import { api } from '../api.js';

// Org roles that carry some administrative capability — mirrors
// backend core/org_access.py's ORG_ADMIN_ROLES ∪ ORG_USER_MANAGER_ROLES.
// Kept in one place so "does this org role get the admin UI" is answered
// identically everywhere on the frontend, matching what the backend
// actually enforces (2026-08-18: the org-admin menu was previously gated
// on the *project* role of whatever project happened to be selected —
// an unrelated axis, so it was wrong in both directions: a project owner
// with no org role at all could see it, and an org manager/team_lead
// with no elevated *project* role couldn't).
const ORG_ADMIN_CAPABLE_ROLES = new Set(['owner', 'admin', 'manager', 'team_lead']);
// Narrower bar for destructive/owner-only org actions (delete org, edit
// org profile/registries) — mirrors backend core/org_access.py's
// ORG_ADMIN_ROLES exactly (owner/admin only, unlike the broader set
// above which also covers manager/team_lead's user-management/read
// access to the org admin section).
const ORG_OWNER_ADMIN_ROLES = new Set(['owner', 'admin']);

const Ctx = createContext({
  permissions: [], role: null, globalRole: 'user', isLoading: false, can: () => false, isSuperAdmin: false,
  loadPermissions: async () => {}, orgRoles: {}, loadOrgRoles: async () => {}, clearOrgRoles: () => {}, isOrgAdminCapable: () => false, isOrgOwnerOrAdmin: () => false, hasAnyOrgAdminRole: false,
});

export function ProjectPermissionsProvider({ children }) {
  const [state, setState] = useState({ permissions: [], role: null, globalRole: 'user', isLoading: false, isSuperAdmin: false, projectId: null, orgRoles: {} });

  const loadPermissions = useCallback(async (pid) => {
    if (!pid) {
      setState(s => ({ ...s, permissions: [], role: null, isLoading: false, projectId: null }));
      return;
    }
    setState(s => ({ ...s, isLoading: true }));
    try {
      const data = await api.getMyProjectPermissions(pid);
      setState(s => ({ ...s, permissions: data.permissions || [], role: data.role, isSuperAdmin: data.is_super_admin || false, source: data.source || 'direct', isLoading: false, projectId: pid }));
    } catch {
      setState(s => ({ ...s, permissions: [], role: null, isLoading: false, projectId: pid }));
    }
  }, []);

  // Single source of truth for "what is this user's role in each org they
  // belong to" — GET /api/orgs now returns the caller's own `role` per
  // org (previously omitted). Fetched once at login/mount, not tied to
  // whichever project happens to be selected.
  const loadOrgRoles = useCallback(async () => {
    try {
      const orgs = await api.listOrganizations();
      const map = {};
      for (const o of orgs) if (o.role) map[o.id] = o.role;
      setState(s => ({ ...s, orgRoles: map }));
    } catch {
      setState(s => ({ ...s, orgRoles: {} }));
    }
  }, []);

  const setGlobalRole = useCallback((globalRole, isSuperAdmin) => {
    setState(s => ({ ...s, globalRole, isSuperAdmin }));
  }, []);

  const clearOrgRoles = useCallback(() => {
    setState(s => ({ ...s, orgRoles: {} }));
  }, []);

  const can = useCallback((permission) => {
    if (state.isSuperAdmin) return true;
    return state.permissions.includes(permission);
  }, [state.permissions, state.isSuperAdmin]);

  // Context-aware role check for a *specific* org — this is what a
  // component showing one expanded/selected org should use, not the
  // blanket "any org" flag below.
  const isOrgAdminCapable = useCallback((orgId) => {
    if (state.isSuperAdmin) return true;
    return ORG_ADMIN_CAPABLE_ROLES.has(state.orgRoles[orgId]);
  }, [state.isSuperAdmin, state.orgRoles]);

  const isOrgOwnerOrAdmin = useCallback((orgId) => {
    if (state.isSuperAdmin) return true;
    return ORG_OWNER_ADMIN_ROLES.has(state.orgRoles[orgId]);
  }, [state.isSuperAdmin, state.orgRoles]);

  // Blanket "is this user an admin-capable member of *any* org" — this is
  // the correct check for top-level nav visibility (the "Organizations"
  // menu item), where no single org is in context yet; the page itself
  // then scopes further by org once one is expanded.
  const hasAnyOrgAdminRole = useMemo(() => {
    if (state.isSuperAdmin) return true;
    return Object.values(state.orgRoles).some(r => ORG_ADMIN_CAPABLE_ROLES.has(r));
  }, [state.isSuperAdmin, state.orgRoles]);

  const ctxValue = useMemo(
    () => ({ ...state, can, loadPermissions, setGlobalRole, loadOrgRoles, clearOrgRoles, isOrgAdminCapable, isOrgOwnerOrAdmin, hasAnyOrgAdminRole }),
    [state, can, loadPermissions, setGlobalRole, loadOrgRoles, clearOrgRoles, isOrgAdminCapable, isOrgOwnerOrAdmin, hasAnyOrgAdminRole]
  );

  return (
    <Ctx.Provider value={ctxValue}>
      {children}
    </Ctx.Provider>
  );
}

ProjectPermissionsProvider.propTypes = {
  children: PropTypes.node,
};

export const useProjectPermissions = () => useContext(Ctx);
