import { describe, it, expect } from 'vitest';
import { assignableProjectRoles, EXTENDED_PROJECT_ROLES, PROJECT_ROLE_ORDER } from './admin.js';

describe('assignableProjectRoles', () => {
  it('offers every role from Team upwards', () => {
    for (const tier of ['team', 'pro', 'enterprise']) {
      expect(assignableProjectRoles(tier)).toEqual(PROJECT_ROLE_ORDER);
    }
  });

  it('withholds the review roles on Free', () => {
    const roles = assignableProjectRoles('free');
    for (const r of EXTENDED_PROJECT_ROLES) expect(roles).not.toContain(r);
  });

  it('never withholds a base role', () => {
    // RBAC is how an unlicensed install keeps a read-only auditor out of
    // credentials — gating it would be gating a security feature.
    const roles = assignableProjectRoles('free');
    for (const r of ['owner', 'admin', 'editor', 'manager', 'team_lead', 'operator', 'viewer', 'auditor']) {
      expect(roles).toContain(r);
    }
  });

  it('treats an unknown or missing tier as Free', () => {
    expect(assignableProjectRoles(undefined)).not.toContain('analyst');
    expect(assignableProjectRoles('nonsense')).not.toContain('analyst');
  });

  it('keeps the role a member already holds, even when it is paid', () => {
    // After a downgrade a member can still be an analyst. Dropping it from
    // the options would blank the Select and rewrite their role on the next
    // change.
    const roles = assignableProjectRoles('free', 'analyst');
    expect(roles).toContain('analyst');
    expect(roles).not.toContain('reviewer');
  });

  it('preserves the canonical ordering', () => {
    const roles = assignableProjectRoles('free');
    expect(roles).toEqual(PROJECT_ROLE_ORDER.filter(r => !EXTENDED_PROJECT_ROLES.includes(r)));
  });
});
