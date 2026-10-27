import { api } from '../api.js';

export const MITRE_CATEGORY = 'MITRE ATT&CK';

export const CATEGORIES = [
  'General', 'Reconnaissance', 'Initial Access', 'Execution', 'Persistence',
  'Privilege Escalation', 'Lateral Movement', 'Collection', 'Exfiltration',
  'Command & Control', 'Defense Evasion', MITRE_CATEGORY,
];

export const TACTIC_ORDER = [
  'Reconnaissance', 'Initial Access', 'Execution', 'Persistence',
  'Privilege Escalation', 'Defense Evasion', 'Credential Access',
  'Discovery', 'Lateral Movement', 'Collection',
  'Command and Control', 'Exfiltration', 'Impact',
];

export const TACTIC_COLOR = {
  'Reconnaissance':       '#808590',
  'Initial Access':       '#cc2233',
  'Execution':            '#e8574a',
  'Persistence':          '#f09a3a',
  'Privilege Escalation': '#e8cc42',
  'Defense Evasion':      '#6fc8f0',
  'Credential Access':    '#c07af0',
  'Discovery':            '#5b8af5',
  'Lateral Movement':     '#39d353',
  'Collection':           '#3bc9c9',
  'Command and Control':  '#f07080',
  'Exfiltration':         '#a8d8a8',
  'Impact':               '#cc2233',
};

export const CATEGORY_COLORS = {
  'General': '#6fc8f0',
  'Reconnaissance': '#5b8af5',
  'Initial Access': '#f09a3a',
  'Execution': '#cc2233',
  'Persistence': '#c07af0',
  'Privilege Escalation': '#e8574a',
  'Lateral Movement': '#e8cc42',
  'Collection': '#39d353',
  'Exfiltration': '#f09a3a',
  'Command & Control': '#cc2233',
  'Defense Evasion': '#808590',
  [MITRE_CATEGORY]: '#c07af0',
};

export function categoryColor(cat) {
  return CATEGORY_COLORS[cat] || '#606570';
}

export const KB_INP_STYLE = {
  width: '100%', background: '#0a0c10', border: '1px solid #2a2d35', borderRadius: 5,
  padding: '8px 10px', color: '#c8cdd6', fontSize: 12, outline: 'none',
  fontFamily: 'JetBrains Mono', boxSizing: 'border-box',
};

export function parseMitreArticle(a) {
  const mid = (a.tags || []).find(t => /^T\d{4}/.test(t)) || '';
  const name = a.title.includes(' — ') ? a.title.split(' — ')[1] : a.title;
  const tacticTag = (a.tags || []).find(t => t !== 'mitre' && !/^T\d/.test(t));
  const tactic = tacticTag
    ? tacticTag.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
    : '';
  return { id: mid, name, tactic, kb_id: a.id, article: a };
}

export function buildCatCounts(articles) {
  const catCounts = {};
  for (const a of articles) {
    catCounts[a.category] = (catCounts[a.category] || 0) + 1;
  }
  return catCounts;
}

export function filterArticles(articles, category, search) {
  return articles
    .filter(a => !category || a.category === category)
    .filter(a => !search || [a.title, a.content, (a.tags || []).join(' ')].join(' ').toLowerCase().includes(search.toLowerCase()));
}

export async function deleteArticle(id, articles, setArticles, setSelectedArticle) {
  await api.deleteKBArticle(id);
  setArticles(prev => prev.filter(a => a.id !== id));
  setSelectedArticle(null);
}

export function exportKB(articles) {
  const blob = new Blob([JSON.stringify(articles, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'knowledge-base.json';
  a.click();
  URL.revokeObjectURL(url);
}

export function startKBEdit(article, setEditId, setForm) {
  setEditId(article.id);
  setForm({ title: article.title, category: article.category, tags: (article.tags || []).join(', '), content: article.content || '', scope: article.scope || 'project' });
}
