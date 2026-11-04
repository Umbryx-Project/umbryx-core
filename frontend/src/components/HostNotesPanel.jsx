import PropTypes from 'prop-types';
import { useState } from 'react';
import Icon from './Icon.jsx';
import { PALETTE, FONTS } from './UI.jsx';

/**
 * Shared "notes attached to this host" list — used both as a compact
 * preview (Details tab, `limit` set) and as the full Notes tab (no
 * limit), in HostsView and in the Network Map node inspector, so both
 * host-card surfaces show the same real content instead of a bare
 * "go look in Notes" link.
 */
export default function HostNotesPanel({ notes, canAdd, adding, onAdd, onSelect, limit, onShowAll, emptyLabel = 'No notes attached to this host' }) {
  const shown = limit ? notes.slice(0, limit) : notes;
  const hiddenCount = limit ? Math.max(0, notes.length - limit) : 0;

  return (
    <div>
      {canAdd && (
        <button onClick={onAdd} disabled={adding} style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '4px 8px', cursor: adding ? 'default' : 'pointer', color: '#808590', fontSize: 9, fontFamily: FONTS.mono, opacity: adding ? 0.6 : 1, display: 'flex', alignItems: 'center', gap: 4, marginBottom: 8 }}>
          <Icon name="plus" size={9} color="currentColor" />
          {adding ? 'Adding…' : 'Add note'}
        </button>
      )}
      {shown.length === 0 && <div style={{ fontSize: 10, color: PALETTE.textGhost }}>{emptyLabel}</div>}
      {shown.map(n => (
        <button
          key={n.id}
          onClick={() => onSelect(n.id)}
          disabled={n._pending}
          style={{ display: 'block', width: '100%', textAlign: 'left', background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 6, padding: '8px 10px', marginBottom: 6, cursor: n._pending ? 'default' : 'pointer', font: 'inherit', color: 'inherit', opacity: n._pending ? 0.55 : 1 }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
            <span style={{ fontSize: 11, color: '#e0e4ec', fontFamily: FONTS.display, fontWeight: 600, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{n.title || 'Untitled'}</span>
            {n.starred && <Icon name="star" size={10} color="#f09a3a" />}
            <span style={{ fontSize: 9, color: PALETTE.textGhost, fontFamily: FONTS.mono, flexShrink: 0 }}>{n.ts}</span>
          </div>
          {n.content && (
            <div style={{ fontSize: 10, color: PALETTE.textMute, lineHeight: 1.4, display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical', overflow: 'hidden' }}>
              {n.content}
            </div>
          )}
        </button>
      ))}
      {hiddenCount > 0 && (
        <button onClick={onShowAll} style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: PALETTE.textFaint, fontSize: 9, fontFamily: FONTS.mono, padding: '2px 0' }}>
          +{hiddenCount} more →
        </button>
      )}
    </div>
  );
}

HostNotesPanel.propTypes = {
  notes: PropTypes.array.isRequired,
  canAdd: PropTypes.bool,
  adding: PropTypes.bool,
  onAdd: PropTypes.func,
  onSelect: PropTypes.func.isRequired,
  limit: PropTypes.number,
  onShowAll: PropTypes.func,
  emptyLabel: PropTypes.string,
};

// Small hook-like helper: builds the "create note pre-attached to this
// host, then jump to it" handler shared by every host-card surface.
export function useAddHostNote({ selectedProject, hostId, hostLabel, onAddNote, onNavigate }) {
  const [adding, setAdding] = useState(false);
  const run = async () => {
    if (!hostId || adding) return;
    setAdding(true);
    try {
      const ts = new Date().toISOString().slice(0, 16).replace('T', ' ');
      const note = await onAddNote?.({
        pid: selectedProject,
        title: `${hostLabel} — note`,
        phase: 'recon', tags: [], content: '', ts, starred: false,
        host_id: hostId,
      });
      if (note?.id) onNavigate?.('notes', note.id);
    } finally {
      setAdding(false);
    }
  };
  return [adding, run];
}
