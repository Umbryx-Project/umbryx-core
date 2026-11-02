export const ROLE_TABS = {
  platform_admin: ['*'],
  owner: ['*'],
  admin: ['*'],
  manager: ['overview', 'platform-ops', 'workstations', 'roe', 'findings', 'timeline', 'report', 'hosts', 'creds'],
  team_lead: ['overview', 'platform-ops', 'workstations', 'roe', 'findings', 'timeline', 'report'],
  operator: ['hosts', 'creds', 'scans', 'watch', 'jobs', 'playbooks', 'attackpath', 'attackgraph', 'findings', 'notes', 'loot', 'kb', 'timeline', 'cheatsheet', 'scope', 'checklist', 'objectives', 'network', 'purple'],
  analyst: ['hosts', 'findings', 'notes', 'kb', 'timeline', 'report', 'scope', 'checklist', 'objectives', 'attackpath', 'purple'],
  reviewer: ['findings', 'report', 'timeline', 'purple'],
  viewer: ['hosts', 'creds', 'findings', 'notes', 'loot', 'attackpath', 'attackgraph', 'report', 'timeline', 'kb', 'playbooks', 'jobs', 'scans', 'watch', 'network', 'scope', 'checklist', 'objectives', 'purple'],
  observer: ['findings', 'report'],
  auditor: ['hosts', 'findings', 'notes', 'loot', 'report', 'timeline', 'kb', 'playbooks', 'jobs', 'scans', 'watch', 'purple'],
};

export const GLOBAL_TABS = ['projects', 'system', 'organizations', 'admin'];

export function getVisibleTabs(role, globalRole) {
  if (globalRole === 'platform_admin') return ['*'];
  const tabs = ROLE_TABS[role];
  if (!tabs) return [];
  if (tabs.includes('*')) return ['*'];
  return tabs;
}
