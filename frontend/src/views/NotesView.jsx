import PropTypes from 'prop-types';
import { useEffect, useRef, useState } from 'react';
import { toastError } from '../components/Toast.jsx';
import Icon from '../components/Icon.jsx';
import MdEditor from '../components/MdEditor.jsx';
import { PhaseTag, Btn, SearchBar, PALETTE, FONTS, Select } from '../components/UI.jsx';
import { PHASES, PHASE_COLORS } from '../constants.js';
import { api } from '../api.js';
import { useProjectPermissions } from '../context/ProjectPermissions.jsx';

function _buildPresenceMap(presence, username) {
  const map = {};
  for (const u of presence) {
    if (u.note_id && u.name !== username) {
      if (!map[u.note_id]) map[u.note_id] = [];
      map[u.note_id].push(u.name);
    }
  }
  return map;
}

// Deterministic color from username
function userColor(name) {
  let h = 0;
  for (const ch of name) h = (h * 31 + ch.codePointAt(0)) & 0xffffff;
  return `hsl(${h % 360}, 60%, 55%)`;
}

function UserDot({ name, size = 18 }) {
  const color = userColor(name);
  const initials = name.slice(0, 2).toUpperCase();
  return (
    <span title={name} style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', width: size, height: size, borderRadius: '50%', background: color + '33', border: `1px solid ${color}88`, color, fontSize: size * 0.44, fontWeight: 700, fontFamily: FONTS.mono, flexShrink: 0, letterSpacing: 0 }}>
      {initials}
    </span>
  );
}

function PhaseDropdown({ value, onChange }) {
  const [open, setOpen] = useState(false);
  useEffect(() => {
    if (!open) return;
    const close = () => setOpen(false);
    globalThis.addEventListener('click', close);
    return () => globalThis.removeEventListener('click', close);
  }, [open]);
  return (
    <div style={{ position: 'relative' }}>
      <button type="button" onClick={e => { e.stopPropagation(); setOpen(v => !v); }} style={{ cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 5, background: 'transparent', border: 'none', padding: 0, outline: 'none', color: 'inherit', font: 'inherit' }}>
        <PhaseTag phase={value} small />
        <Icon name="chevron" size={10} color="#404550" />
      </button>
      {open && (
        <div style={{ position: 'absolute', top: '100%', left: 0, marginTop: 4, background: PALETTE.bg3, border: `1px solid ${PALETTE.border}`, borderRadius: 6, padding: 6, zIndex: 200, display: 'flex', flexDirection: 'column', gap: 3, minWidth: 120, boxShadow: '0 8px 24px #00000066' }}>
          {PHASES.map(ph => (
            <button key={ph} onClick={() => { onChange(ph); setOpen(false); }} style={{ background: value === ph ? `${PHASE_COLORS[ph]}22` : 'transparent', border: `1px solid ${value === ph ? PHASE_COLORS[ph] + '66' : 'transparent'}`, borderRadius: 4, padding: '4px 10px', cursor: 'pointer', textAlign: 'left', outline: 'none', color: 'inherit', font: 'inherit' }}>
              <span style={{ fontSize: 10, fontFamily: FONTS.mono, fontWeight: 600, color: PHASE_COLORS[ph], textTransform: 'uppercase' }}>{ph}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

function HostLinkControl({ hostId, hosts, canEdit, onChange, onGoToHost }) {
  const [picking, setPicking] = useState(false);
  const host = hostId ? hosts.find(h => h.id === hostId) : null;

  if (host) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
        <button
          onClick={() => onGoToHost(hostId)}
          title="Go to host"
          style={{ display: 'flex', alignItems: 'center', gap: 5, background: 'transparent', border: '1px solid #2a2d3577', borderRadius: 4, padding: '2px 7px', cursor: 'pointer', color: '#5b8af5', font: 'inherit' }}
        >
          <Icon name="server" size={10} color="currentColor" />
          <span style={{ fontSize: 10, fontFamily: FONTS.mono }}>{host.hostname || host.ip}</span>
        </button>
        {canEdit && (
          <button onClick={() => onChange(null)} title="Unlink host" style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 2, display: 'flex', color: PALETTE.textGhost }}>
            <Icon name="close" size={9} color="currentColor" />
          </button>
        )}
      </div>
    );
  }

  if (!canEdit) return null;

  if (picking) {
    return (
      <Select
        autoOpen
        value=""
        onChange={v => { if (v) onChange(v); }}
        onClose={() => setPicking(false)}
        placeholder="Attach to host…"
        options={hosts.map(h => ({ value: h.id, label: h.hostname || h.ip }))}
      />
    );
  }

  return (
    <button onClick={() => setPicking(true)} style={{ background: 'transparent', border: `1px dashed ${PALETTE.border}`, borderRadius: 4, padding: '2px 7px', cursor: 'pointer', color: '#505560', fontSize: 10, fontFamily: FONTS.mono }}>
      + Attach host
    </button>
  );
}

HostLinkControl.propTypes = {
  hostId: PropTypes.string,
  hosts: PropTypes.array,
  canEdit: PropTypes.bool,
  onChange: PropTypes.func,
  onGoToHost: PropTypes.func,
};

function AttachmentBar({ attachments, uploading, accent, onRemove }) {
  if (!attachments.length && !uploading) return null;
  const typeIcon = (ct = '', fn = '') => {
    const ext = fn.split('.').pop().toLowerCase();
    if (ct.startsWith('image/')) return '🖼';
    if (ct.startsWith('video/')) return '🎬';
    if (ct.startsWith('audio/')) return '🎵';
    if (ext === 'pdf') return '📄';
    const codeExts = ['py','js','ts','sh','bash','ps1','go','rb','java','c','cpp','cs','php','sql','json','xml','yaml','yml'];
    if (codeExts.includes(ext)) return '📋';
    return '📎';
  };
  return (
    <div style={{ padding: '5px 20px', borderBottom: '1px solid #14161b', background: '#070809', display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap', flexShrink: 0 }}>
      <span style={{ fontSize: 9, color: '#303540', fontFamily: FONTS.mono, textTransform: 'uppercase', marginRight: 4 }}>Attachments</span>
      {attachments.map(att => (
        <div key={att.id} style={{ display: 'flex', alignItems: 'center', gap: 5, background: PALETTE.bg2, border: '1px solid #1e2029', borderRadius: 5, padding: '3px 8px' }}>
          <span style={{ fontSize: 12 }}>{typeIcon(att.content_type, att.filename)}</span>
          <a href={att.public_url} target="_blank" rel="noreferrer" style={{ color: '#6fc8f0', fontSize: 10, fontFamily: FONTS.mono, textDecoration: 'none', maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {att.filename}
          </a>
          <button onClick={() => onRemove(att)} style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0, display: 'flex', color: PALETTE.textGhost }}>
            <Icon name="close" size={9} color="currentColor" />
          </button>
        </div>
      ))}
      {uploading && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 5, color: accent, fontSize: 10, fontFamily: FONTS.mono }}>
          <div style={{ width: 10, height: 10, border: `2px solid ${accent}33`, borderTopColor: accent, borderRadius: '50%', animation: 'spin 0.6s linear infinite' }} />
          Uploading...
        </div>
      )}
    </div>
  );
}

function UnsavedDialog({ accent, onSave, onDiscard, onCancel }) {
  return (
    <div style={{ position: 'fixed', inset: 0, background: '#000000aa', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, backdropFilter: 'blur(3px)' }}>
      <div style={{ background: PALETTE.bg3, border: `1px solid ${PALETTE.border}`, borderRadius: 10, padding: '28px 32px', width: 360, boxShadow: '0 20px 60px #00000088' }}>
        <div style={{ fontSize: 15, fontWeight: 700, color: PALETTE.text, fontFamily: FONTS.display, marginBottom: 8 }}>Unsaved changes</div>
        <div style={{ fontSize: 12, color: '#808590', lineHeight: 1.6, marginBottom: 24 }}>
          The note has been modified. Save changes before leaving?
        </div>
        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
          <button onClick={onCancel} style={{ background: 'none', border: `1px solid ${PALETTE.border}`, borderRadius: 5, padding: '7px 16px', cursor: 'pointer', color: PALETTE.textFaint, fontSize: 11, fontFamily: FONTS.mono }}>Cancel</button>
          <button onClick={onDiscard} style={{ background: 'none', border: '1px solid #cc223366', borderRadius: 5, padding: '7px 16px', cursor: 'pointer', color: PALETTE.danger, fontSize: 11, fontFamily: FONTS.mono }}>Discard</button>
          <button onClick={onSave} style={{ background: accent, border: 'none', borderRadius: 5, padding: '7px 16px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: FONTS.mono }}>Save</button>
        </div>
      </div>
    </div>
  );
}

function ConflictDialog({ accent, myContent, serverNote, onOverwrite, onLoadServer, onCancel }) {
  return (
    <div style={{ position: 'fixed', inset: 0, background: '#000000bb', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1100, backdropFilter: 'blur(4px)' }}>
      <div style={{ background: PALETTE.bg3, border: '1px solid #cc233344', borderRadius: 12, padding: '28px 32px', width: 560, boxShadow: '0 24px 64px #00000099' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
          <Icon name="warning" size={18} color="#cc2233" />
          <div style={{ fontSize: 15, fontWeight: 700, color: PALETTE.text, fontFamily: FONTS.display }}>Version conflict</div>
        </div>
        <div style={{ fontSize: 12, color: '#808590', lineHeight: 1.7, marginBottom: 18 }}>
          While you were editing, another user saved this note. Choose how to proceed:
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 22 }}>
          <div style={{ background: '#0a0c10', border: `1px solid ${PALETTE.border}`, borderRadius: 6, padding: '10px 12px' }}>
            <div style={{ fontSize: 9, color: PALETTE.textFaint, textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 6 }}>Your version</div>
            <div style={{ fontSize: 10, color: PALETTE.textMute, fontFamily: FONTS.mono, lineHeight: 1.5, maxHeight: 100, overflow: 'hidden', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
              {myContent.slice(0, 300)}{myContent.length > 300 ? '...' : ''}
            </div>
          </div>
          <div style={{ background: '#0a0c10', border: '1px solid #cc233333', borderRadius: 6, padding: '10px 12px' }}>
            <div style={{ fontSize: 9, color: PALETTE.danger, textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 6 }}>Server version · v{serverNote.version}</div>
            <div style={{ fontSize: 10, color: PALETTE.textMute, fontFamily: FONTS.mono, lineHeight: 1.5, maxHeight: 100, overflow: 'hidden', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
              {(serverNote.content || '').slice(0, 300)}{(serverNote.content || '').length > 300 ? '...' : ''}
            </div>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
          <button onClick={onCancel} style={{ background: 'none', border: `1px solid ${PALETTE.border}`, borderRadius: 5, padding: '7px 16px', cursor: 'pointer', color: PALETTE.textFaint, fontSize: 11, fontFamily: FONTS.mono }}>Continue editing</button>
          <button onClick={onLoadServer} style={{ background: 'none', border: '1px solid #5b8af566', borderRadius: 5, padding: '7px 16px', cursor: 'pointer', color: '#5b8af5', fontSize: 11, fontFamily: FONTS.mono }}>Load their version</button>
          <button onClick={onOverwrite} style={{ background: PALETTE.danger, border: 'none', borderRadius: 5, padding: '7px 16px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: FONTS.mono }}>Overwrite with mine</button>
        </div>
      </div>
    </div>
  );
}

export default function NotesView({ notes, onAdd, onUpdate, onDelete, projects, selectedProject, accent, fs, presence = [], onFocus, username, focusId, consumeFocusId, hosts = [], onNavigate }) {
  const { can } = useProjectPermissions();
  const [search, setSearch] = useState('');
  const [filterPhase, setFilterPhase] = useState(null);
  const [selectedNote, setSelectedNote] = useState(null);
  const [editing, setEditing] = useState(false);
  const [editContent, setEditContent] = useState('');
  const [editTitle, setEditTitle] = useState('');
  const [editPhase, setEditPhase] = useState('recon');
  const [editTags, setEditTags] = useState('');
  const [attachments, setAttachments] = useState([]);
  const [uploading, setUploading] = useState(false);
  const [isDragging, setIsDragging] = useState(false);
  const [pendingNoteId, setPendingNoteId] = useState(null);
  const [baseVersion, setBaseVersion] = useState(null);
  const [remoteUpdated, setRemoteUpdated] = useState(false);
  const [conflictNote, setConflictNote] = useState(null);
  const prevVersionRef = useRef(null);

  const selNote = notes.find(n => n.id === selectedNote);

  useEffect(() => {
    if (!focusId) return;
    const match = notes.find(n => n.id === focusId && n.pid === selectedProject);
    if (match) {
      selectNote(focusId);
      requestAnimationFrame(() => {
        document.getElementById(`note-${focusId}`)?.scrollIntoView({ behavior: 'smooth', block: 'center' });
      });
    }
    consumeFocusId?.();
  }, [focusId]);

  const isDirty = editing && selNote && (
    editContent !== (selNote.content || '') ||
    editTitle   !== (selNote.title   || '') ||
    editPhase   !== (selNote.phase   || 'recon') ||
    editTags    !== (selNote.tags || []).join(', ')
  );

  // Detect external update while editing
  useEffect(() => {
    if (!editing || !selNote || baseVersion === null) {
      prevVersionRef.current = selNote?.version ?? null;
      return;
    }
    const prev = prevVersionRef.current;
    prevVersionRef.current = selNote.version;
    if (prev !== null && selNote.version > prev) {
      setRemoteUpdated(true);
    }
  }, [selNote?.version, editing, baseVersion]);

  const trySelectNote = (id) => {
    if (isDirty && id !== selectedNote) {
      setPendingNoteId(id);
      return;
    }
    selectNote(id);
  };

  const selectNote = (id) => {
    setSelectedNote(id);
    setEditing(false);
    setBaseVersion(null);
    setRemoteUpdated(false);
    setConflictNote(null);
    onFocus?.(id);
  };

  const proj = projects.find(p => p.id === selectedProject);
  const filtered = notes
    .filter(n => n.pid === selectedProject)
    .filter(n => !filterPhase || n.phase === filterPhase)
    .filter(n => !search || [n.title, (n.tags || []).join(' '), n.content].join(' ').toLowerCase().includes(search.toLowerCase()));

  useEffect(() => {
    if (!selNote) return;
    setEditContent(selNote.content || '');
    setEditTitle(selNote.title || '');
    setEditPhase(selNote.phase || 'recon');
    setEditTags((selNote.tags || []).join(', '));
    api.getNoteAttachments(selNote.id).then(setAttachments).catch(() => setAttachments([]));
  }, [selectedNote, selNote?.id]);

  const startEditing = () => {
    setBaseVersion(selNote?.version ?? 0);
    setRemoteUpdated(false);
    setConflictNote(null);
    setEditing(true);
    setEditContent(selNote.content || '');
    setEditTitle(selNote.title || '');
    setEditPhase(selNote.phase || 'recon');
    setEditTags((selNote.tags || []).join(', '));
  };

  const saveNote = async (thenGoTo = null, forceVersion = null) => {
    const ts = new Date().toISOString().slice(0, 16).replace('T', ' ');
    try {
      await onUpdate(selectedNote, {
        content: editContent, title: editTitle,
        phase: editPhase,
        tags: editTags.split(',').map(t => t.trim()).filter(Boolean),
        ts,
        client_version: forceVersion === null ? baseVersion : forceVersion,
      });
      setEditing(false);
      setBaseVersion(null);
      setRemoteUpdated(false);
      setConflictNote(null);
      if (thenGoTo) { setSelectedNote(thenGoTo); setPendingNoteId(null); onFocus?.(thenGoTo); }
    } catch (err) {
      if (err.status === 409) {
        setConflictNote(err.serverNote);
      } else {
        toastError(`Save error: ${err.message}`);
      }
    }
  };

  const addNote = () => {
    const ts = new Date().toISOString().slice(0, 16).replace('T', ' ');
    onAdd({ pid: selectedProject, title: 'New note', phase: 'recon', tags: [], content: '# New note\n\n', ts, starred: false });
  };

  const uploadAttachment = async (file) => {
    if (!selNote || !file) return;
    setUploading(true);
    try {
      const att = await api.uploadNoteAttachment(selNote.id, file);
      setAttachments(prev => [...prev, att]);
      const ct = att.content_type || '';
      const snippet = ct.startsWith('image/') ? `\n![${att.filename}](${att.public_url})\n` : `\n[${att.filename}](${att.public_url})\n`;
      const ts = new Date().toISOString().slice(0, 16).replace('T', ' ');
      if (editing) {
        const newContent = editContent + snippet;
        setEditContent(newContent);
        onUpdate(selNote.id, { content: newContent, ts });
      } else {
        const newContent = (selNote.content || '') + snippet;
        onUpdate(selNote.id, { content: newContent, ts });
        setEditContent(newContent);
        setEditing(true);
      }
    } catch (err) {
      toastError(`Upload error: ${err.message}`);
    } finally {
      setUploading(false);
    }
  };

  const removeAttachment = async (att) => {
    await api.deleteAttachment(att.id);
    setAttachments(prev => prev.filter(x => x.id !== att.id));
  };

  const handleDrop = async (e) => {
    e.preventDefault();
    setIsDragging(false);
    if (!selNote) return;
    for (const file of Array.from(e.dataTransfer.files)) await uploadAttachment(file);
  };

  const presenceMap = _buildPresenceMap(presence, username);

  // Other users editing the currently selected note
  const editingHere = selNote ? (presenceMap[selNote.id] || []) : [];

  return (
    <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
      {pendingNoteId && (
        <UnsavedDialog
          accent={accent}
          onSave={() => saveNote(pendingNoteId)}
          onDiscard={() => { setEditing(false); selectNote(pendingNoteId); setPendingNoteId(null); }}
          onCancel={() => setPendingNoteId(null)}
        />
      )}

      {conflictNote && (
        <ConflictDialog
          accent={accent}
          myContent={editContent}
          serverNote={conflictNote}
          onOverwrite={() => saveNote(null, conflictNote.version)}
          onLoadServer={() => {
            setEditContent(conflictNote.content || '');
            setEditTitle(conflictNote.title || selNote?.title || '');
            setBaseVersion(conflictNote.version);
            setConflictNote(null);
            setRemoteUpdated(false);
          }}
          onCancel={() => setConflictNote(null)}
        />
      )}

      {/* ── Note list ── */}
      <div style={{ width: 272, background: '#0a0c10', borderRight: '1px solid #1e2029', display: 'flex', flexDirection: 'column', flexShrink: 0 }}>
        <div style={{ padding: '12px 14px', borderBottom: `1px solid ${PALETTE.borderSoft}` }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
            <span style={{ fontSize: fs, fontWeight: 600, color: '#e0e4ec', fontFamily: FONTS.display, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>
              {proj?.name}
            </span>
            {can('notes.create') && <button onClick={addNote} style={{ background: accent, border: 'none', borderRadius: 4, padding: '3px 9px', cursor: 'pointer', color: '#fff', fontSize: 10, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 4, fontFamily: FONTS.mono, flexShrink: 0, marginLeft: 8 }}>
              <Icon name="plus" size={10} color="#fff" />
            </button>}
          </div>
          <SearchBar value={search} onChange={setSearch} />
        </div>
        <div style={{ padding: '6px 12px', borderBottom: `1px solid ${PALETTE.borderSoft}`, display: 'flex', gap: 4, flexWrap: 'wrap' }}>
          {PHASES.map(ph => {
            const cnt = notes.filter(n => n.pid === selectedProject && n.phase === ph).length;
            if (!cnt) return null;
            const active = filterPhase == ph;
            const c = PHASE_COLORS[ph];
            return (
              <button key={ph} onClick={() => setFilterPhase(active ? null : ph)} style={{ background: active ? `${c}22` : 'transparent', border: `1px solid ${active ? c + '88' : PALETTE.border}`, borderRadius: 3, padding: '2px 6px', cursor: 'pointer', fontSize: 9, color: active ? c : '#505560', fontFamily: FONTS.mono, fontWeight: 600, textTransform: 'uppercase' }}>
                {ph}
              </button>
            );
          })}
        </div>
        <div style={{ overflowY: 'auto', flex: 1 }}>
          {filtered.length === 0 && <div style={{ padding: 20, textAlign: 'center', color: PALETTE.textGhost, fontSize: 11 }}>No notes</div>}
          {filtered.map(note => {
            const active = note.id === selectedNote;
            const viewers = presenceMap[note.id] || [];
            return (
              <button
                type="button"
                key={note.id}
                id={`note-${note.id}`}
                onClick={() => !note._pending && trySelectNote(note.id)}
                style={{ padding: '11px 14px', cursor: note._pending ? 'default' : 'pointer', opacity: note._pending ? 0.55 : 1, background: active ? '#ffffff0a' : 'transparent', borderBottom: '1px solid #14161b', borderLeft: active ? `2px solid ${accent}` : '2px solid transparent', transition: 'background .1s, opacity .15s', width: '100%', textAlign: 'left', borderTop: 'none', borderRight: 'none', outline: 'none', color: 'inherit', font: 'inherit' }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                  <PhaseTag phase={note.phase} small />
                  {note.starred && <Icon name="star" size={10} color="#f09a3a" />}
                  {viewers.length > 0 && (
                    <div style={{ marginLeft: 'auto', display: 'flex', gap: 2 }}>
                      {viewers.slice(0, 3).map(n => <UserDot key={n} name={n} size={16} />)}
                    </div>
                  )}
                </div>
                <div style={{ fontSize: fs - 1, color: active ? '#f0f2f6' : '#b0b5c2', marginBottom: 4, lineHeight: 1.4, display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical', overflow: 'hidden' }}>
                  {note.title}
                </div>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <span style={{ fontSize: 9, color: PALETTE.textGhost }}>{note.ts}</span>
                  <div style={{ display: 'flex', gap: 4 }}>
                    {(note.tags || []).slice(0, 2).map(t => (
                      <span key={t} style={{ fontSize: 9, color: '#505560', background: PALETTE.borderSoft, padding: '1px 5px', borderRadius: 3 }}>{t}</span>
                    ))}
                  </div>
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* ── Note content ── */}
      {selNote ? (
          <div
            role="application"
            aria-label="Note editor"
            tabIndex={-1}
            style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0, position: 'relative' }}
          onDrop={handleDrop}
          onDragOver={e => { e.preventDefault(); setIsDragging(true); }}
          onDragLeave={e => { if (!e.currentTarget.contains(e.relatedTarget)) setIsDragging(false); }}
        >
          {isDragging && (
            <div style={{ position: 'absolute', inset: 0, background: `${accent}18`, border: `2px dashed ${accent}`, borderRadius: 8, display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 100, pointerEvents: 'none', backdropFilter: 'blur(2px)' }}>
              <div style={{ fontSize: 15, fontWeight: 600, color: accent, fontFamily: FONTS.display }}>Drop to upload</div>
            </div>
          )}

          {/* Header */}
          <div style={{ padding: '10px 20px', borderBottom: `1px solid ${PALETTE.borderSoft}`, display: 'flex', alignItems: 'center', gap: 10, background: '#0a0c10', flexShrink: 0 }}>
            {editing
              ? <input value={editTitle} onChange={e => setEditTitle(e.target.value)} style={{ flex: 1, background: 'transparent', border: 'none', outline: 'none', fontSize: 15, fontWeight: 600, color: PALETTE.text, fontFamily: FONTS.display }} />
              : <div style={{ flex: 1, fontSize: 15, fontWeight: 600, color: PALETTE.text, fontFamily: FONTS.display, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{selNote.title}</div>
            }
            {/* Who's here */}
            {editingHere.length > 0 && (
              <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                {editingHere.slice(0, 4).map(n => <UserDot key={n} name={n} size={20} />)}
              </div>
            )}
            {isDirty && <span title="Unsaved changes" style={{ width: 7, height: 7, borderRadius: '50%', background: accent, display: 'inline-block', flexShrink: 0, boxShadow: `0 0 6px ${accent}` }} />}
            {!editing && (
              <>
                {can('notes.update') && <Btn icon="terminal" onClick={startEditing}>Edit</Btn>}
                <button onClick={() => onUpdate(selNote.id, { starred: !selNote.starred })} style={{ background: 'transparent', border: 'none', cursor: 'pointer', padding: 4, display: 'flex' }}>
                  <Icon name={selNote.starred ? 'star' : 'starO'} size={15} color={selNote.starred ? '#f09a3a' : PALETTE.textGhost} />
                </button>
                {can('notes.delete') && <button onClick={() => { onDelete(selNote.id); setSelectedNote(null); onFocus?.(null); }} style={{ background: 'transparent', border: 'none', cursor: 'pointer', padding: 4, display: 'flex', color: PALETTE.textGhost }}>
                  <Icon name="trash" size={14} color="currentColor" />
                </button>}
              </>
            )}
          </div>

          {/* Remote update banner */}
          {remoteUpdated && editing && !conflictNote && (
            <div style={{ padding: '7px 20px', background: '#f09a3a18', borderBottom: '1px solid #f09a3a44', display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
              <Icon name="warning" size={12} color="#f09a3a" />
              <span style={{ fontSize: 11, color: PALETTE.warn, flex: 1 }}>Another user modified this note. Saving may cause a conflict.</span>
              <button onClick={() => setRemoteUpdated(false)} style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0, display: 'flex' }}>
                <Icon name="close" size={10} color="#f09a3a" />
              </button>
            </div>
          )}

          {/* Meta bar */}
          <div style={{ padding: '6px 20px', borderBottom: '1px solid #14161b', background: '#080a0e', display: 'flex', alignItems: 'center', gap: 16, flexShrink: 0, flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <Icon name="target" size={11} color="#404550" />
              <span style={{ fontSize: 10, color: '#505560', fontFamily: FONTS.mono }}>{proj?.ip || '—'}</span>
            </div>
            {editing
              ? <Select value={editPhase} onChange={setEditPhase} options={PHASES} />
              : <PhaseDropdown value={selNote.phase} onChange={v => onUpdate(selNote.id, { phase: v, ts: new Date().toISOString().slice(0, 16).replace('T', ' ') })} />
            }
            {editing
              ? <input value={editTags} onChange={e => setEditTags(e.target.value)} placeholder="tag1, tag2" style={{ background: 'transparent', border: 'none', borderBottom: `1px solid ${accent}44`, outline: 'none', color: PALETTE.textMute, fontSize: 11, fontFamily: FONTS.mono, width: 220 }} />
              : <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>{(selNote.tags || []).map(t => <span key={t} style={{ fontSize: 9, color: '#505560', background: PALETTE.borderSoft, padding: '1px 6px', borderRadius: 3 }}>{t}</span>)}</div>
            }
            <HostLinkControl
              hostId={selNote.host_id}
              hosts={hosts}
              canEdit={can('notes.update')}
              onChange={hid => onUpdate(selNote.id, { host_id: hid })}
              onGoToHost={hid => onNavigate?.('hosts', hid)}
            />
            <div style={{ marginLeft: 'auto', fontSize: 9, color: '#303540' }}>{selNote.ts}</div>
          </div>

          {/* Attachments bar */}
          <AttachmentBar attachments={attachments} uploading={uploading} accent={accent} onRemove={removeAttachment} />

          {/* Content area */}
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0, overflow: 'hidden' }}>
            {editing ? (
              <MdEditor
                value={editContent}
                onChange={setEditContent}
                accent={accent}
                onUpload={uploadAttachment}
                uploading={uploading}
                onSave={() => saveNote()}
                onCancel={() => { setEditing(false); setBaseVersion(null); setRemoteUpdated(false); }}
              />
            ) : (
              <MdEditor value={selNote.content || ''} accent={accent} readOnly />
            )}
          </div>
        </div>
      ) : (
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 12, color: '#303540' }}>
          <Icon name="notes" size={36} color="#2a2d35" />
          <div style={{ fontSize: 13 }}>Select a note or create a new one</div>
        </div>
      )}
    </div>
  );
}

UserDot.propTypes = {
  name: PropTypes.string,
  size: PropTypes.number,
};

PhaseDropdown.propTypes = {
  value: PropTypes.string,
  onChange: PropTypes.func,
};

AttachmentBar.propTypes = {
  attachments: PropTypes.array,
  uploading: PropTypes.bool,
  accent: PropTypes.string,
  onRemove: PropTypes.func,
};

UnsavedDialog.propTypes = {
  accent: PropTypes.string,
  onSave: PropTypes.func,
  onDiscard: PropTypes.func,
  onCancel: PropTypes.func,
};

ConflictDialog.propTypes = {
  accent: PropTypes.string,
  myContent: PropTypes.object,
  serverNote: PropTypes.object,
  onOverwrite: PropTypes.func,
  onLoadServer: PropTypes.func,
  onCancel: PropTypes.func,
};

NotesView.propTypes = {
  notes: PropTypes.array,
  onAdd: PropTypes.func,
  onUpdate: PropTypes.func,
  onDelete: PropTypes.func,
  projects: PropTypes.array,
  selectedProject: PropTypes.string,
  accent: PropTypes.string,
  fs: PropTypes.number,
  presence: PropTypes.array,
  onFocus: PropTypes.func,
  username: PropTypes.string,
  focusId: PropTypes.string,
  consumeFocusId: PropTypes.func,
  hosts: PropTypes.array,
  onNavigate: PropTypes.func,
};
