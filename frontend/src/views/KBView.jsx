import React, { useState, useEffect } from 'react';
import PropTypes from 'prop-types';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { api } from '../api.js';
import { toastError } from '../components/Toast.jsx';
import { MITRE_CATEGORY, CATEGORIES, CATEGORY_COLORS, categoryColor, KB_INP_STYLE, parseMitreArticle } from '../utils/kb.js';
import { MitrePanel } from '../components/kb/Mitre.jsx';
import { PALETTE, FONTS, Select } from '../components/UI.jsx';


// ── Module-level helpers ───────────────────────────────────────────────
function _buildCatCounts(articles) {
  const catCounts = {};
  for (const a of articles) {
    catCounts[a.category] = (catCounts[a.category] || 0) + 1;
  }
  return catCounts;
}

function _filterArticles(articles, selectedCat, search) {
  return articles.filter(a => {
    if (selectedCat && a.category !== selectedCat) return false;
    if (!search) return true;
    const q = search.toLowerCase();
    return (
      a.title?.toLowerCase().includes(q) ||
      a.content?.toLowerCase().includes(q) ||
      (a.tags || []).some(t => t.toLowerCase().includes(q))
    );
  });
}

async function _deleteArticle(articleId, setArticles, setSelectedArticle, setConfirmDelete) {
  try {
    await api.deleteKBArticle(articleId);
    setArticles(prev => prev.filter(a => a.id !== articleId));
    setSelectedArticle(null);
    setConfirmDelete(false);
  } catch (e) { toastError(e.message); }
}

async function _exportKB(selectedProject) {
  try {
    const blob = await api.exportKB(selectedProject);
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `kb-export-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  } catch (e) { toastError(e.message); }
}

function _startKBEdit(art, setEditTitle, setEditCategory, setEditTags, setEditContent, setEditing) {
  setEditTitle(art.title || '');
  setEditCategory(art.category || 'General');
  setEditTags((art.tags || []).join(', '));
  setEditContent(art.content || '');
  setEditing(true);
}

function KBCreateForm({ accent, saving, newTitle, setNewTitle, newCategory, setNewCategory, newTags, setNewTags, newContent, setNewContent, newScope, setNewScope, selectedProject, createArticle, setShowCreate }) {
  return (
    <div style={{ flex: 1, overflowY: 'auto', padding: '20px 24px' }}>
      <div style={{ fontSize: 14, fontWeight: 700, color: PALETTE.text, fontFamily: FONTS.display, marginBottom: 16 }}>New Article</div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        <div>
          <div style={{ fontSize: 9, color: PALETTE.textGhost, textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 4 }}>Title</div>
          <input value={newTitle} onChange={e => setNewTitle(e.target.value)} placeholder="Article title" autoFocus style={KB_INP_STYLE} />
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
          <div>
            <div style={{ fontSize: 9, color: PALETTE.textGhost, textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 4 }}>Category</div>
            <Select value={newCategory} onChange={setNewCategory} options={CATEGORIES} />
          </div>
          <div>
            <div style={{ fontSize: 9, color: PALETTE.textGhost, textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 4 }}>Tags</div>
            <input value={newTags} onChange={e => setNewTags(e.target.value)} placeholder="tag1, tag2" style={KB_INP_STYLE} />
          </div>
        </div>
        <div>
          <div style={{ fontSize: 9, color: PALETTE.textGhost, textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 4 }}>Scope</div>
          <div style={{ display: 'flex', gap: 8 }}>
            {['project', 'global'].map(s => (
              <label key={s} style={{ display: 'flex', alignItems: 'center', gap: 5, cursor: 'pointer', fontSize: 11, color: newScope === s ? accent : PALETTE.textFaint }}>
                <input type="radio" name="scope" value={s} checked={newScope === s} onChange={() => setNewScope(s)} style={{ accentColor: accent }} />
                {s === 'project' ? 'Project' : 'Global'}
              </label>
            ))}
          </div>
        </div>
        <div>
          <div style={{ fontSize: 9, color: PALETTE.textGhost, textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 4 }}>Content (Markdown)</div>
          <textarea value={newContent} onChange={e => setNewContent(e.target.value)} placeholder="# Title&#10;&#10;Content..." rows={16} style={{ ...KB_INP_STYLE, resize: 'vertical', lineHeight: 1.6 }} />
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button onClick={createArticle} disabled={saving || !newTitle.trim()} style={{ background: newTitle.trim() ? accent : PALETTE.borderSoft, border: 'none', borderRadius: 5, padding: '7px 16px', cursor: 'pointer', color: '#fff', fontSize: 11, fontFamily: FONTS.mono, fontWeight: 600 }}>
            {saving ? 'Creating…' : 'Create'}
          </button>
          <button onClick={() => setShowCreate(false)} style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 5, padding: '7px 16px', cursor: 'pointer', color: PALETTE.textFaint, fontSize: 11, fontFamily: FONTS.mono }}>Cancel</button>
        </div>
      </div>
    </div>
  );
}

KBCreateForm.propTypes = {
  accent: PropTypes.string,
  saving: PropTypes.bool,
  newTitle: PropTypes.string,
  setNewTitle: PropTypes.func,
  newCategory: PropTypes.string,
  setNewCategory: PropTypes.func,
  newTags: PropTypes.string,
  setNewTags: PropTypes.func,
  newContent: PropTypes.string,
  setNewContent: PropTypes.func,
  newScope: PropTypes.string,
  setNewScope: PropTypes.func,
  selectedProject: PropTypes.string,
  createArticle: PropTypes.func,
  setShowCreate: PropTypes.func,
};

function KBArticleEditor({ accent, saving, editTitle, setEditTitle, editCategory, setEditCategory, editTags, setEditTags, editContent, setEditContent, saveEdit, setEditing }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ fontSize: 13, fontWeight: 700, color: PALETTE.text, fontFamily: FONTS.display, marginBottom: 4 }}>Edit Article</div>
      <div>
        <div style={{ fontSize: 9, color: PALETTE.textGhost, textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 4 }}>Title</div>
        <input value={editTitle} onChange={e => setEditTitle(e.target.value)} style={KB_INP_STYLE} />
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
        <div>
          <div style={{ fontSize: 9, color: PALETTE.textGhost, textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 4 }}>Category</div>
          <Select value={editCategory} onChange={setEditCategory} options={CATEGORIES} />
        </div>
        <div>
          <div style={{ fontSize: 9, color: PALETTE.textGhost, textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 4 }}>Tags</div>
          <input value={editTags} onChange={e => setEditTags(e.target.value)} placeholder="tag1, tag2" style={KB_INP_STYLE} />
        </div>
      </div>
      <div>
        <div style={{ fontSize: 9, color: PALETTE.textGhost, textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 4 }}>Content (Markdown)</div>
        <textarea value={editContent} onChange={e => setEditContent(e.target.value)} rows={20} style={{ ...KB_INP_STYLE, resize: 'vertical', lineHeight: 1.6 }} />
      </div>
      <div style={{ display: 'flex', gap: 8 }}>
        <button onClick={saveEdit} disabled={saving} style={{ background: accent, border: 'none', borderRadius: 5, padding: '7px 16px', cursor: 'pointer', color: '#fff', fontSize: 11, fontFamily: FONTS.mono, fontWeight: 600 }}>{saving ? 'Saving…' : 'Save'}</button>
        <button onClick={() => setEditing(false)} style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 5, padding: '7px 16px', cursor: 'pointer', color: PALETTE.textFaint, fontSize: 11, fontFamily: FONTS.mono }}>Cancel</button>
      </div>
    </div>
  );
}

KBArticleEditor.propTypes = {
  accent: PropTypes.string,
  saving: PropTypes.bool,
  editTitle: PropTypes.string,
  setEditTitle: PropTypes.func,
  editCategory: PropTypes.string,
  setEditCategory: PropTypes.func,
  editTags: PropTypes.string,
  setEditTags: PropTypes.func,
  editContent: PropTypes.string,
  setEditContent: PropTypes.func,
  saveEdit: PropTypes.func,
  setEditing: PropTypes.func,
};

async function _saveKBEdit(articleId, { editTitle, editCategory, editTags, editContent }, { setArticles, setSelectedArticle, setEditing, setSaving }) {
  setSaving(true);
  try {
    const updated = await api.updateKBArticle(articleId, {
      title: editTitle, category: editCategory,
      tags: editTags.split(',').map(t => t.trim()).filter(Boolean),
      content: editContent,
    });
    setArticles(prev => prev.map(a => a.id === updated.id ? updated : a));
    setSelectedArticle(updated);
    setEditing(false);
  } catch (e) { toastError(e.message); }
  finally { setSaving(false); }
}

async function _importKB(file, selectedProject, setLoading, setError, setArticles, setImporting) {
  setImporting(true);
  try {
    await api.importKB(file, selectedProject);
    await _loadKBArticles(selectedProject, setLoading, setError, setArticles);
  } catch (e) { toastError(e.message); }
  finally { setImporting(false); }
}

async function _createKBArticle({ newTitle, newCategory, newTags, newContent, newScope, selectedProject }, { setArticles, setShowCreate, setSelectedArticle, setSaving, resetNew }) {
  setSaving(true);
  try {
    const data = {
      title: newTitle, category: newCategory,
      tags: newTags.split(',').map(t => t.trim()).filter(Boolean),
      content: newContent,
    };
    if (newScope === 'project' && selectedProject) data.pid = selectedProject;
    const created = await api.createKBArticle(data);
    setArticles(prev => [created, ...prev]);
    setShowCreate(false);
    resetNew();
    setSelectedArticle(created);
  } catch (e) { toastError(e.message); }
  finally { setSaving(false); }
}

async function _loadKBArticles(selectedProject, setLoading, setError, setArticles) {
  setLoading(true);
  setError('');
  try {
    const params = {};
    if (selectedProject) params.pid = selectedProject;
    const data = await api.listKBArticles(params);
    setArticles(Array.isArray(data) ? data : (data.articles || []));
  } catch (e) {
    setError(e.message || 'Failed to load');
  } finally {
    setLoading(false);
  }
}

function KBCategoryItem({ cat, active, col, count, setSelectedCat, setSelectedArticle, setEditing }) {
  return (
    <button
      type="button"
      onClick={() => { setSelectedCat(active ? '' : cat); setSelectedArticle(null); setEditing(false); }}
      onKeyDown={e => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          setSelectedCat(active ? '' : cat);
          setSelectedArticle(null);
          setEditing(false);
        }
      }}
      style={{ padding: '6px 14px', cursor: 'pointer', display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: active ? col + '18' : 'transparent', borderLeft: active ? `2px solid ${col}` : '2px solid transparent', width: '100%', textAlign: 'left', borderTop: 'none', borderRight: 'none', borderBottom: 'none', outline: 'none', color: 'inherit', font: 'inherit' }}
      onMouseEnter={e => { if (!active) e.currentTarget.style.background = '#ffffff06'; }}
      onMouseLeave={e => { if (!active) e.currentTarget.style.background = 'transparent'; }}
    >
      <span style={{ fontSize: 11, color: active ? col : '#808590' }}>{cat}</span>
      {count > 0 && <span style={{ fontSize: 9, color: '#505560', fontFamily: FONTS.mono }}>{count}</span>}
    </button>
  );
}

KBCategoryItem.propTypes = {
  cat: PropTypes.string,
  active: PropTypes.bool,
  col: PropTypes.string,
  count: PropTypes.number,
  setSelectedCat: PropTypes.func,
  setSelectedArticle: PropTypes.func,
  setEditing: PropTypes.func,
};

function KBArticleListItem({ art, isSel, accent, setSelectedArticle, setEditing, setConfirmDelete, setShowCreate }) {
  const col = categoryColor(art.category);
  return (
    <button
      type="button"
      onClick={() => { setSelectedArticle(art); setEditing(false); setConfirmDelete(false); setShowCreate(false); }}
      onKeyDown={e => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          setSelectedArticle(art);
          setEditing(false);
          setConfirmDelete(false);
          setShowCreate(false);
        }
      }}
      style={{ padding: '9px 12px', cursor: 'pointer', borderBottom: '1px solid #14161b', borderLeft: isSel ? `2px solid ${accent}` : '2px solid transparent', background: isSel ? accent + '10' : 'transparent', width: '100%', textAlign: 'left', borderTop: 'none', borderRight: 'none', outline: 'none', color: 'inherit', font: 'inherit' }}
      onMouseEnter={e => { if (!isSel) e.currentTarget.style.background = '#ffffff06'; }}
      onMouseLeave={e => { if (!isSel) e.currentTarget.style.background = 'transparent'; }}
    >
      <div style={{ fontSize: 12, fontWeight: 600, color: isSel ? '#f0f2f6' : PALETTE.textDim, fontFamily: FONTS.display, marginBottom: 4, lineHeight: 1.3 }}>{art.title}</div>
      <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
        <span style={{ fontSize: 8, background: col + '18', border: `1px solid ${col}33`, borderRadius: 2, padding: '1px 5px', color: col, fontFamily: FONTS.mono }}>{art.category}</span>
        <span style={{ fontSize: 8, background: art.pid ? accent + '18' : '#c07af018', border: `1px solid ${art.pid ? accent + '33' : '#c07af033'}`, borderRadius: 2, padding: '1px 5px', color: art.pid ? accent : '#c07af0', fontFamily: FONTS.mono }}>{art.pid ? 'PROJECT' : 'GLOBAL'}</span>
      </div>
    </button>
  );
}

KBArticleListItem.propTypes = {
  art: PropTypes.object,
  isSel: PropTypes.bool,
  accent: PropTypes.string,
  setSelectedArticle: PropTypes.func,
  setEditing: PropTypes.func,
  setConfirmDelete: PropTypes.func,
  setShowCreate: PropTypes.func,
};

function KBArticleView({ selectedArticle, accent, confirmDelete, setConfirmDelete, startEdit, doDelete }) {
  return (
    <>
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10, marginBottom: 16, paddingBottom: 16, borderBottom: '1px solid #1e2029' }}>
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: 20, fontWeight: 700, color: PALETTE.text, fontFamily: FONTS.display, marginBottom: 10, lineHeight: 1.2 }}>{selectedArticle.title}</div>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
            <span style={{ fontSize: 10, background: categoryColor(selectedArticle.category) + '22', border: `1px solid ${categoryColor(selectedArticle.category)}44`, borderRadius: 3, padding: '2px 8px', color: categoryColor(selectedArticle.category), fontFamily: FONTS.mono }}>
              {selectedArticle.category}
            </span>
            <span style={{ fontSize: 10, background: selectedArticle.pid ? accent + '22' : '#c07af022', border: `1px solid ${selectedArticle.pid ? accent + '44' : '#c07af044'}`, borderRadius: 3, padding: '2px 8px', color: selectedArticle.pid ? accent : '#c07af0', fontFamily: FONTS.mono }}>
              {selectedArticle.pid ? 'PROJECT' : 'GLOBAL'}
            </span>
            {(selectedArticle.tags || []).map(t => (
              <span key={t} style={{ fontSize: 10, background: PALETTE.borderSoft, border: `1px solid ${PALETTE.border}`, borderRadius: 3, padding: '2px 6px', color: '#808590', fontFamily: FONTS.mono }}>{t}</span>
            ))}
          </div>
        </div>
        <div style={{ display: 'flex', gap: 6, flexShrink: 0 }}>
          <button onClick={() => startEdit(selectedArticle)} style={{ background: 'transparent', border: `1px solid ${accent}44`, borderRadius: 5, padding: '5px 12px', cursor: 'pointer', color: accent, fontSize: 11, fontFamily: FONTS.mono }}>Edit</button>
          <button onClick={() => setConfirmDelete(true)} style={{ background: 'transparent', border: '1px solid #cc233344', borderRadius: 5, padding: '5px 12px', cursor: 'pointer', color: PALETTE.danger, fontSize: 11, fontFamily: FONTS.mono }}>Delete</button>
        </div>
      </div>
      <div className="kb-markdown" style={{ color: PALETTE.textDim, lineHeight: 1.8, fontSize: 13 }}>
        <ReactMarkdown remarkPlugins={[remarkGfm]}>
          {selectedArticle.content || '*(empty)*'}
        </ReactMarkdown>
      </div>
      {confirmDelete && (
        <div style={{ marginTop: 20, background: '#cc233318', border: '1px solid #cc233344', borderRadius: 6, padding: '12px 14px' }}>
          <div style={{ fontSize: 12, color: PALETTE.text, marginBottom: 10 }}>Delete "{selectedArticle.title}"?</div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button onClick={doDelete} style={{ background: PALETTE.danger, border: 'none', borderRadius: 4, padding: '6px 14px', cursor: 'pointer', color: '#fff', fontSize: 11, fontFamily: FONTS.mono, fontWeight: 600 }}>Delete</button>
            <button onClick={() => setConfirmDelete(false)} style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 14px', cursor: 'pointer', color: PALETTE.textFaint, fontSize: 11, fontFamily: FONTS.mono }}>Cancel</button>
          </div>
        </div>
      )}
    </>
  );
}

KBArticleView.propTypes = {
  selectedArticle: PropTypes.object,
  accent: PropTypes.string,
  confirmDelete: PropTypes.bool,
  setConfirmDelete: PropTypes.func,
  startEdit: PropTypes.func,
  doDelete: PropTypes.func,
};

function KBSidebar({ search, setSearch, selectedCat, setSelectedCat, setSelectedArticle, setEditing, catCounts, totalCount, accent, importing, importKB, exportKB }) {
  return (
    <div style={{ width: 220, borderRight: '1px solid #1e2029', display: 'flex', flexDirection: 'column', flexShrink: 0 }}>
      <div style={{ padding: '14px 14px 10px', borderBottom: '1px solid #1e2029' }}>
        <div style={{ fontSize: 13, fontWeight: 700, color: PALETTE.text, fontFamily: FONTS.display, marginBottom: 10 }}>Knowledge Base</div>
        <input
          value={search}
          onChange={e => { setSearch(e.target.value); setSelectedArticle(null); setEditing(false); }}
          placeholder="Search…"
          style={{ ...KB_INP_STYLE, fontSize: 11 }}
        />
      </div>
      <div style={{ flex: 1, overflowY: 'auto', padding: '6px 0' }}>
        <button
          type="button"
          onClick={() => { setSelectedCat(''); setSelectedArticle(null); setEditing(false); }}
          onKeyDown={e => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault();
              setSelectedCat('');
              setSelectedArticle(null);
              setEditing(false);
            }
          }}
          style={{ padding: '6px 14px', cursor: 'pointer', display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: selectedCat ? 'transparent' : accent + '18', borderLeft: selectedCat ? '2px solid transparent' : `2px solid ${accent}`, width: '100%', textAlign: 'left', borderTop: 'none', borderRight: 'none', borderBottom: 'none', outline: 'none', color: 'inherit', font: 'inherit' }}
          onMouseEnter={e => { if (selectedCat) e.currentTarget.style.background = '#ffffff06'; }}
          onMouseLeave={e => { if (selectedCat) e.currentTarget.style.background = 'transparent'; }}
        >
          <span style={{ fontSize: 11, color: selectedCat ? '#c8cdd6' : accent }}>All articles</span>
          <span style={{ fontSize: 9, color: PALETTE.textFaint, fontFamily: FONTS.mono }}>{totalCount}</span>
        </button>
        {CATEGORIES.map(cat => {
          const count = catCounts[cat] || 0;
          const active = selectedCat === cat;
          const col = categoryColor(cat);
          return <KBCategoryItem key={cat} cat={cat} active={active} col={col} count={count} setSelectedCat={setSelectedCat} setSelectedArticle={setSelectedArticle} setEditing={setEditing} />;
        })}
      </div>
      <div style={{ padding: '8px 10px', borderTop: '1px solid #1e2029', display: 'flex', gap: 6, flexShrink: 0 }}>
        <label style={{ flex: 1, background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '5px 0', cursor: importing ? 'wait' : 'pointer', color: '#808590', fontSize: 10, fontFamily: FONTS.mono, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 4, opacity: importing ? 0.7 : 1 }}>
          {importing ? 'Importing…' : 'Import'}
          <input type="file" accept="application/json,.json" style={{ display: 'none' }} onChange={e => e.target.files?.[0] && importKB(e.target.files[0])} disabled={importing} />
        </label>
        <button onClick={exportKB} style={{ flex: 1, background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '5px 0', cursor: 'pointer', color: '#808590', fontSize: 10, fontFamily: FONTS.mono }}>
          Export
        </button>
      </div>
    </div>
  );
}

KBSidebar.propTypes = {
  search: PropTypes.string,
  setSearch: PropTypes.func,
  selectedCat: PropTypes.string,
  setSelectedCat: PropTypes.func,
  setSelectedArticle: PropTypes.func,
  setEditing: PropTypes.func,
  catCounts: PropTypes.object,
  totalCount: PropTypes.number,
  accent: PropTypes.string,
  importing: PropTypes.bool,
  importKB: PropTypes.func,
  exportKB: PropTypes.func,
};

function KBMiddlePanel({ isMitre, mitreArticles, attackSteps, accent, selectedArticle, setSelectedArticle, setEditing, setConfirmDelete, setShowCreate, filtered, loading, error, showCreate, selectedProject }) {
  return (
    <div style={{ width: isMitre ? 380 : 270, borderRight: '1px solid #1e2029', display: 'flex', flexDirection: 'column', flexShrink: 0, transition: 'width .15s' }}>
      {isMitre ? (
        <MitrePanel
          articles={mitreArticles}
          attackSteps={attackSteps}
          accent={accent}
          onSelectArticle={a => { setSelectedArticle(a); setEditing(false); setShowCreate(false); }}
          selectedProject={selectedProject}
        />
      ) : (
        <>
          <div style={{ padding: '8px 12px', borderBottom: '1px solid #1e2029', display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
            <div style={{ flex: 1, fontSize: 10, color: '#505560', fontFamily: FONTS.mono }}>
              {filtered.length} article{filtered.length === 1 ? '' : 's'}
            </div>
            <button
              onClick={() => { setShowCreate(v => !v); setSelectedArticle(null); setEditing(false); }}
              style={{ background: showCreate ? accent + '33' : accent, border: 'none', borderRadius: 4, padding: '4px 9px', cursor: 'pointer', color: '#fff', fontSize: 10, fontWeight: 600, fontFamily: FONTS.mono }}
            >+ New</button>
          </div>
          {error && <div style={{ margin: '6px 10px', background: '#cc233318', border: '1px solid #cc233344', borderRadius: 4, padding: '5px 8px', fontSize: 10, color: PALETTE.danger, fontFamily: FONTS.mono }}>{error}</div>}
          <div style={{ flex: 1, overflowY: 'auto' }}>
            {loading && <div style={{ color: PALETTE.textGhost, fontSize: 11, textAlign: 'center', padding: 32 }}>Loading…</div>}
            {!loading && filtered.length === 0 && (
              <div style={{ color: PALETTE.textGhost, fontSize: 11, textAlign: 'center', padding: 32, lineHeight: 1.6 }}>No articles.<br />Click "+ New" to create.</div>
            )}
            {filtered.map(art => (
              <KBArticleListItem key={art.id} art={art} isSel={selectedArticle?.id === art.id} accent={accent} setSelectedArticle={setSelectedArticle} setEditing={setEditing} setConfirmDelete={setConfirmDelete} setShowCreate={setShowCreate} />
            ))}
          </div>
        </>
      )}
    </div>
  );
}

KBMiddlePanel.propTypes = {
  isMitre: PropTypes.bool,
  mitreArticles: PropTypes.array,
  attackSteps: PropTypes.array,
  accent: PropTypes.string,
  selectedArticle: PropTypes.object,
  setSelectedArticle: PropTypes.func,
  setEditing: PropTypes.func,
  setConfirmDelete: PropTypes.func,
  setShowCreate: PropTypes.func,
  filtered: PropTypes.array,
  loading: PropTypes.bool,
  error: PropTypes.string,
  showCreate: PropTypes.bool,
  selectedProject: PropTypes.string,
};

function KBRightPanel({ isMitre, selectedArticle, setSelectedArticle, showCreate, setShowCreate, editing, setEditing, confirmDelete, setConfirmDelete, accent, saving, newTitle, setNewTitle, newCategory, setNewCategory, newTags, setNewTags, newContent, setNewContent, newScope, setNewScope, selectedProject, createArticle, editTitle, setEditTitle, editCategory, setEditCategory, editTags, setEditTags, editContent, setEditContent, saveEdit, startEdit, doDelete }) {
  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      {isMitre && !selectedArticle && !showCreate && (
        <div style={{ padding: '8px 12px', borderBottom: '1px solid #1e2029', display: 'flex', gap: 8, flexShrink: 0 }}>
          <button
            onClick={() => { setShowCreate(true); setSelectedArticle(null); }}
            style={{ background: accent, border: 'none', borderRadius: 4, padding: '4px 10px', cursor: 'pointer', color: '#fff', fontSize: 10, fontWeight: 600, fontFamily: FONTS.mono }}
          >+ New Article</button>
        </div>
      )}
      {showCreate && (
        <KBCreateForm
          accent={accent} saving={saving}
          newTitle={newTitle} setNewTitle={setNewTitle}
          newCategory={newCategory} setNewCategory={setNewCategory}
          newTags={newTags} setNewTags={setNewTags}
          newContent={newContent} setNewContent={setNewContent}
          newScope={newScope} setNewScope={setNewScope}
          selectedProject={selectedProject}
          createArticle={createArticle} setShowCreate={setShowCreate}
        />
      )}
      {selectedArticle && !showCreate && (
        <div style={{ flex: 1, overflowY: 'auto', padding: '20px 28px' }}>
          {editing ? (
            <KBArticleEditor
              accent={accent} saving={saving}
              editTitle={editTitle} setEditTitle={setEditTitle}
              editCategory={editCategory} setEditCategory={setEditCategory}
              editTags={editTags} setEditTags={setEditTags}
              editContent={editContent} setEditContent={setEditContent}
              saveEdit={saveEdit} setEditing={setEditing}
            />
          ) : (
            <KBArticleView selectedArticle={selectedArticle} accent={accent} confirmDelete={confirmDelete} setConfirmDelete={setConfirmDelete} startEdit={startEdit} doDelete={doDelete} />
          )}
        </div>
      )}
      {!selectedArticle && !showCreate && !isMitre && (
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 10, color: '#303540' }}>
          <div style={{ fontSize: 32 }}>📖</div>
          <div style={{ fontSize: 12, fontFamily: FONTS.mono, color: PALETTE.textGhost }}>Select an article to read</div>
        </div>
      )}
      {!selectedArticle && !showCreate && isMitre && (
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 8, color: '#303540' }}>
          <div style={{ fontSize: 11, fontFamily: FONTS.mono, color: PALETTE.textGhost }}>Click a technique to read its article</div>
        </div>
      )}
    </div>
  );
}

KBRightPanel.propTypes = {
  isMitre: PropTypes.bool,
  selectedArticle: PropTypes.object,
  setSelectedArticle: PropTypes.func,
  showCreate: PropTypes.bool,
  setShowCreate: PropTypes.func,
  editing: PropTypes.bool,
  setEditing: PropTypes.func,
  confirmDelete: PropTypes.bool,
  setConfirmDelete: PropTypes.func,
  accent: PropTypes.string,
  saving: PropTypes.bool,
  newTitle: PropTypes.string,
  setNewTitle: PropTypes.func,
  newCategory: PropTypes.string,
  setNewCategory: PropTypes.func,
  newTags: PropTypes.string,
  setNewTags: PropTypes.func,
  newContent: PropTypes.string,
  setNewContent: PropTypes.func,
  newScope: PropTypes.string,
  setNewScope: PropTypes.func,
  selectedProject: PropTypes.string,
  createArticle: PropTypes.func,
  editTitle: PropTypes.string,
  setEditTitle: PropTypes.func,
  editCategory: PropTypes.string,
  setEditCategory: PropTypes.func,
  editTags: PropTypes.string,
  setEditTags: PropTypes.func,
  editContent: PropTypes.string,
  setEditContent: PropTypes.func,
  saveEdit: PropTypes.func,
  startEdit: PropTypes.func,
  doDelete: PropTypes.func,
};

function KBViewBody({ accent, attackSteps, selectedProject, articles, loading, error, search, setSearch, selectedCat, setSelectedCat, selectedArticle, setSelectedArticle, editing, setEditing, showCreate, setShowCreate, confirmDelete, setConfirmDelete, importing, setImporting, editTitle, setEditTitle, editCategory, setEditCategory, editTags, setEditTags, editContent, setEditContent, newTitle, setNewTitle, newCategory, setNewCategory, newTags, setNewTags, newContent, setNewContent, newScope, setNewScope, saving, isMitre, catCounts, totalCount, mitreArticles, filtered, startEdit, saveEdit, doDelete, exportKB, importKB, createArticle }) {
  return (
    <div style={{ flex: 1, display: 'flex', overflow: 'hidden', background: '#090b0f' }}>
      <KBSidebar search={search} setSearch={setSearch} selectedCat={selectedCat} setSelectedCat={setSelectedCat} setSelectedArticle={setSelectedArticle} setEditing={setEditing} catCounts={catCounts} totalCount={totalCount} accent={accent} importing={importing} importKB={importKB} exportKB={exportKB} />
      <KBMiddlePanel isMitre={isMitre} mitreArticles={mitreArticles} attackSteps={attackSteps} accent={accent} selectedArticle={selectedArticle} setSelectedArticle={setSelectedArticle} setEditing={setEditing} setConfirmDelete={setConfirmDelete} setShowCreate={setShowCreate} filtered={filtered} loading={loading} error={error} showCreate={showCreate} selectedProject={selectedProject} />
      <KBRightPanel isMitre={isMitre} selectedArticle={selectedArticle} setSelectedArticle={setSelectedArticle} showCreate={showCreate} setShowCreate={setShowCreate} editing={editing} setEditing={setEditing} confirmDelete={confirmDelete} setConfirmDelete={setConfirmDelete} accent={accent} saving={saving} newTitle={newTitle} setNewTitle={setNewTitle} newCategory={newCategory} setNewCategory={setNewCategory} newTags={newTags} setNewTags={setNewTags} newContent={newContent} setNewContent={setNewContent} newScope={newScope} setNewScope={setNewScope} selectedProject={selectedProject} createArticle={createArticle} editTitle={editTitle} setEditTitle={setEditTitle} editCategory={editCategory} setEditCategory={setEditCategory} editTags={editTags} setEditTags={setEditTags} editContent={editContent} setEditContent={setEditContent} saveEdit={saveEdit} startEdit={startEdit} doDelete={doDelete} />
    </div>
  );
}

KBViewBody.propTypes = {
  accent: PropTypes.string,
  attackSteps: PropTypes.array,
  selectedProject: PropTypes.string,
  articles: PropTypes.array,
  loading: PropTypes.bool,
  error: PropTypes.string,
  search: PropTypes.string,
  setSearch: PropTypes.func,
  selectedCat: PropTypes.string,
  setSelectedCat: PropTypes.func,
  selectedArticle: PropTypes.object,
  setSelectedArticle: PropTypes.func,
  editing: PropTypes.bool,
  setEditing: PropTypes.func,
  showCreate: PropTypes.bool,
  setShowCreate: PropTypes.func,
  confirmDelete: PropTypes.bool,
  setConfirmDelete: PropTypes.func,
  importing: PropTypes.bool,
  setImporting: PropTypes.func,
  editTitle: PropTypes.string,
  setEditTitle: PropTypes.func,
  editCategory: PropTypes.string,
  setEditCategory: PropTypes.func,
  editTags: PropTypes.string,
  setEditTags: PropTypes.func,
  editContent: PropTypes.string,
  setEditContent: PropTypes.func,
  newTitle: PropTypes.string,
  setNewTitle: PropTypes.func,
  newCategory: PropTypes.string,
  setNewCategory: PropTypes.func,
  newTags: PropTypes.string,
  setNewTags: PropTypes.func,
  newContent: PropTypes.string,
  setNewContent: PropTypes.func,
  newScope: PropTypes.string,
  setNewScope: PropTypes.func,
  saving: PropTypes.bool,
  isMitre: PropTypes.bool,
  catCounts: PropTypes.object,
  totalCount: PropTypes.number,
  mitreArticles: PropTypes.array,
  filtered: PropTypes.array,
  startEdit: PropTypes.func,
  saveEdit: PropTypes.func,
  doDelete: PropTypes.func,
  exportKB: PropTypes.func,
  importKB: PropTypes.func,
  createArticle: PropTypes.func,
};

// ── Main KBView ────────────────────────────────────────────────────────
export default function KBView({ selectedProject, accent, currentUser, attackSteps = [] }) {
  const [articles, setArticles] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [search, setSearch] = useState('');
  const [selectedCat, setSelectedCat] = useState('');
  const [selectedArticle, setSelectedArticle] = useState(null);
  const [editing, setEditing] = useState(false);
  const [showCreate, setShowCreate] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [importing, setImporting] = useState(false);

  const [editTitle, setEditTitle] = useState('');
  const [editCategory, setEditCategory] = useState('General');
  const [editTags, setEditTags] = useState('');
  const [editContent, setEditContent] = useState('');

  const [newTitle, setNewTitle] = useState('');
  const [newCategory, setNewCategory] = useState('General');
  const [newTags, setNewTags] = useState('');
  const [newContent, setNewContent] = useState('');
  const [newScope, setNewScope] = useState('project');
  const [saving, setSaving] = useState(false);

  const isMitre = selectedCat === MITRE_CATEGORY;

  useEffect(() => {
    _loadKBArticles(selectedProject, setLoading, setError, setArticles);
  }, [selectedProject]);

  const catCounts = _buildCatCounts(articles);
  const totalCount = articles.length;
  const mitreArticles = articles.filter(a => a.category === MITRE_CATEGORY);
  const filtered = _filterArticles(articles, selectedCat, search);

  const startEdit = (art) => _startKBEdit(art, setEditTitle, setEditCategory, setEditTags, setEditContent, setEditing);
  const saveEdit = () => {
    if (!selectedArticle) return;
    return _saveKBEdit(selectedArticle.id, { editTitle, editCategory, editTags, editContent }, { setArticles, setSelectedArticle, setEditing, setSaving });
  };
  const doDelete = () => {
    if (!selectedArticle) return;
    return _deleteArticle(selectedArticle.id, setArticles, setSelectedArticle, setConfirmDelete);
  };
  const exportKB = () => _exportKB(selectedProject);
  const importKB = (file) => _importKB(file, selectedProject, setLoading, setError, setArticles, setImporting);
  const resetNew = () => { setNewTitle(''); setNewCategory('General'); setNewTags(''); setNewContent(''); setNewScope('project'); };
  const createArticle = () => _createKBArticle({ newTitle, newCategory, newTags, newContent, newScope, selectedProject }, { setArticles, setShowCreate, setSelectedArticle, setSaving, resetNew });

  return <KBViewBody accent={accent} attackSteps={attackSteps} selectedProject={selectedProject} articles={articles} loading={loading} error={error} search={search} setSearch={setSearch} selectedCat={selectedCat} setSelectedCat={setSelectedCat} selectedArticle={selectedArticle} setSelectedArticle={setSelectedArticle} editing={editing} setEditing={setEditing} showCreate={showCreate} setShowCreate={setShowCreate} confirmDelete={confirmDelete} setConfirmDelete={setConfirmDelete} importing={importing} setImporting={setImporting} editTitle={editTitle} setEditTitle={setEditTitle} editCategory={editCategory} setEditCategory={setEditCategory} editTags={editTags} setEditTags={setEditTags} editContent={editContent} setEditContent={setEditContent} newTitle={newTitle} setNewTitle={setNewTitle} newCategory={newCategory} setNewCategory={setNewCategory} newTags={newTags} setNewTags={setNewTags} newContent={newContent} setNewContent={setNewContent} newScope={newScope} setNewScope={setNewScope} saving={saving} isMitre={isMitre} catCounts={catCounts} totalCount={totalCount} mitreArticles={mitreArticles} filtered={filtered} startEdit={startEdit} saveEdit={saveEdit} doDelete={doDelete} exportKB={exportKB} importKB={importKB} createArticle={createArticle} />;
}

KBView.propTypes = {
  selectedProject: PropTypes.string,
  accent: PropTypes.string,
  currentUser: PropTypes.object,
  attackSteps: PropTypes.array,
};
