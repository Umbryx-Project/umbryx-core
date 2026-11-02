export const GLOBAL_ROLE_COLOR = { platform_admin: '#cc2233', user: '#5b8af5', viewer: '#808590' };
export const GLOBAL_ROLE_LABEL = { platform_admin: 'Platform Admin', user: 'User', viewer: 'Viewer' };

export const PROJECT_ROLE_ORDER = ['owner', 'admin', 'editor', 'manager', 'team_lead', 'operator', 'analyst', 'reviewer', 'viewer', 'observer', 'auditor'];

// The client-facing review roles are Team+ (docs/modules/MONETIZATION.md).
// Mirrors backend/app/core/plan.py::EXTENDED_MEMBER_ROLES — the backend
// answers 402 for these below Team, so offering them would be a dead
// option. The base roles are never gated: RBAC is how an unlicensed
// install keeps a read-only auditor out of credentials.
export const EXTENDED_PROJECT_ROLES = ['reviewer', 'analyst', 'observer'];

const TIER_ORDER = ['free', 'team', 'pro', 'enterprise'];

/**
 * Roles offerable in a picker on this tier.
 *
 * `current` is always kept, even when it is a paid role: after a downgrade
 * a member can still hold one, and dropping it from the options would make
 * the Select render blank and silently rewrite the member's role on the
 * next change.
 */
export function assignableProjectRoles(tier, current) {
  const licensed = TIER_ORDER.indexOf(tier || 'free') >= TIER_ORDER.indexOf('team');
  if (licensed) return PROJECT_ROLE_ORDER;
  return PROJECT_ROLE_ORDER.filter(
    r => !EXTENDED_PROJECT_ROLES.includes(r) || r === current,
  );
}
export const PROJECT_ROLE_COLOR = {
  owner: '#f09a3a', admin: '#cc2233', editor: '#5b8af5', manager: '#39d353',
  team_lead: '#c07af0', operator: '#c07af0', analyst: '#6fc8f0', reviewer: '#e8cc42',
  viewer: '#39d353', observer: '#5b8af5', auditor: '#6fc8f0',
};
export const PROJECT_ROLE_LABEL = {
  owner: 'Owner', admin: 'Admin', editor: 'Editor', manager: 'Manager',
  team_lead: 'Team Lead', operator: 'Operator', analyst: 'Analyst', reviewer: 'Reviewer',
  viewer: 'Viewer', observer: 'Observer', auditor: 'Auditor',
};

export const DEFAULT_PROVIDERS = [
  { name: 'anthropic', model: 'claude-haiku-4-5-20251001' },
  { name: 'openai', model: 'gpt-4o-mini' },
  { name: 'ollama', model: 'llama3.2' },
  { name: 'groq', model: 'llama-3.1-8b-instant' },
  { name: 'mistral', model: 'mistral-small' },
  { name: 'openrouter', model: 'openai/gpt-4o-mini' },
  { name: 'litellm', model: '' },
];

export const PROVIDER_DEFAULT_MODELS = {
  anthropic: 'claude-haiku-4-5-20251001',
  openai: 'gpt-4o-mini',
  ollama: 'llama3.2',
  groq: 'llama-3.1-8b-instant',
  mistral: 'mistral-small',
  openrouter: 'openai/gpt-4o-mini',
  litellm: '',
};

export const PROVIDER_BASE_URLS = {
  anthropic: 'https://api.anthropic.com',
  openai: 'https://api.openai.com',
  ollama: 'http://localhost:11434',
  groq: 'https://api.groq.com/openai',
  mistral: 'https://api.mistral.ai',
  openrouter: 'https://openrouter.ai/api',
  litellm: 'http://localhost:4000',
};

export const EVENT_LABELS = {
  host_compromised: { label: 'Host compromised (Pwn3d!)', icon: '🔴' },
  finding_critical: { label: 'Critical / High finding created', icon: '🟠' },
  playbook_done:    { label: 'Playbook run finished', icon: '✅' },
  batch_done:       { label: 'Batch run finished', icon: '📦' },
  job_done:         { label: 'Job completed successfully', icon: '✔' },
  job_failed:       { label: 'Job failed', icon: '✖' },
  test:             { label: 'Test messages', icon: '🔔' },
};

export const DEFAULT_CONFIG = {
  telegram: { enabled: false, token: '', chat_id: '' },
  slack:    { enabled: false, webhook_url: '' },
  webhook:  { enabled: false, url: '' },
  events:   Object.fromEntries(Object.keys(EVENT_LABELS).map(k => [k, true])),
};

import { PALETTE, TYPE, FONTS } from '../components/UI.jsx';

export function inp(extra = {}) {
  return { width: '100%', background: PALETTE.bg1, border: `1px solid ${PALETTE.border}`, borderRadius: 5, padding: '7px 10px', color: PALETTE.textDim, fontSize: TYPE.body, outline: 'none', fontFamily: FONTS.mono, boxSizing: 'border-box', ...extra };
}
