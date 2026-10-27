import { useEffect, useRef, useState } from 'react';
import PropTypes from 'prop-types';
import DOMPurify from 'dompurify';
import { api, downloadUrl } from '../api.js';
import Icon from '../components/Icon.jsx';
import { SearchBar, PALETTE, FONTS, Select } from '../components/UI.jsx';
import { useProjectPermissions } from '../context/ProjectPermissions.jsx';
import { copyToClipboard } from '../utils/clipboard.js';
import { uiAlert } from '../components/Confirm.jsx';

// Filename helpers
const _hasExt = (name) => typeof name === 'string' && /\.[a-z0-9]{1,8}$/i.test(name);
const _extOf = (name) => {
  if (typeof name !== 'string') {
    return '';
  }
  const m = /\.([a-z0-9]{1,8})$/i.exec(name);
  return m ? m[1].toLowerCase() : '';
};

/** Build the final download filename without clobbering an existing extension. */
function _downloadFilename(loot, isFileBlob) {
  const fname = (loot.filename || '').trim();
  if (fname) {
    // Always honour the user-stored filename — it's the truth even when
    // there's no public_url (e.g. a text-loot the operator named report.yaml).
    return fname;
  }
  const sourceTail = (loot.source_path || '').split('/').pop() || '';
  if (sourceTail && _hasExt(sourceTail)) {
    return sourceTail;
  }
  // No filename and no extension hint — value-based loot is text, file is bin.
  return isFileBlob ? 'loot.bin' : 'loot.txt';
}

async function downloadLoot(loot) {
  if (loot.public_url) {
    // Real file on disk — fetch with auth and trigger blob download.
    // Backend sets Content-Disposition with the right filename already, but
    // we override here so the operator sees a predictable name.
    const url = downloadUrl(loot.public_url);
    try {
      const resp = await fetch(url);
      if (!resp.ok) throw new Error(`${resp.status}`);
      const blob = await resp.blob();
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = _downloadFilename(loot, true);
      a.click();
      setTimeout(async () => URL.revokeObjectURL(a.href), 5000);
    } catch (e) {
      await uiAlert(`Download failed: ${e.message}`);
    }
  } else {
    // No file — serialize the value as bytes and download.
    const content = loot.value || loot.description || '';
    const blob = new Blob([content], { type: 'text/plain' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = _downloadFilename(loot, false);
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 5000);
  }
}

// ── Preview classification ────────────────────────────────────────────
const PREVIEW_EXT = {
  image: new Set(['png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp', 'svg', 'ico']),
  pdf:   new Set(['pdf']),
  text:  new Set([
    'txt', 'log', 'md', 'json', 'xml', 'yaml', 'yml',
    'conf', 'cnf', 'cfg', 'ini', 'env', 'toml',
    'sh', 'bash', 'zsh', 'ps1', 'py', 'js', 'ts', 'jsx', 'tsx',
    'go', 'rs', 'java', 'c', 'cpp', 'h', 'hpp', 'rb', 'php', 'sql',
    'html', 'htm', 'css',
  ]),
  // Rendered as a table via SheetJS (also reads csv/tsv/ods).
  sheet: new Set(['xlsx', 'xls', 'ods', 'csv', 'tsv']),
  // Rendered as HTML via mammoth (modern Word only).
  docx:  new Set(['docx']),
  audio: new Set(['mp3', 'wav', 'ogg', 'flac', 'm4a']),
  video: new Set(['mp4', 'webm', 'mov', 'mkv', 'avi']),
  // Known office/db formats with no in-browser preview — download only.
  office: new Set(['doc', 'ppt', 'pptx', 'odt', 'odp', 'accdb', 'mdb', 'rtf']),
};

function _contentTypeKind(ct) {
  if (ct.startsWith('image/')) {
    return 'image';
  }
  if (ct === 'application/pdf') {
    return 'pdf';
  }
  if (ct === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document') {
    return 'docx';
  }
  if (
    ct === 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' ||
    ct === 'application/vnd.ms-excel' ||
    ct === 'application/vnd.oasis.opendocument.spreadsheet' ||
    ct === 'text/csv' || ct === 'text/tab-separated-values'
  ) {
    return 'sheet';
  }
  if (ct.startsWith('text/')) {
    return 'text';
  }
  if (ct.startsWith('audio/')) {
    return 'audio';
  }
  if (ct.startsWith('video/')) {
    return 'video';
  }
  if (ct === 'application/json' || ct === 'application/xml') {
    return 'text';
  }
  return null;
}

function _extKind(ext) {
  if (PREVIEW_EXT.image.has(ext)) {
    return 'image';
  }
  if (PREVIEW_EXT.pdf.has(ext)) {
    return 'pdf';
  }
  if (PREVIEW_EXT.docx.has(ext)) {
    return 'docx';
  }
  if (PREVIEW_EXT.sheet.has(ext)) {
    return 'sheet';
  }
  if (PREVIEW_EXT.text.has(ext)) {
    return 'text';
  }
  if (PREVIEW_EXT.audio.has(ext)) {
    return 'audio';
  }
  if (PREVIEW_EXT.video.has(ext)) {
    return 'video';
  }
  if (PREVIEW_EXT.office.has(ext)) {
    return 'office';
  }
  return 'binary';
}

function _previewKind(loot) {
  if (loot.public_url) {
    const ct = (loot.content_type || '').toLowerCase();
    return _contentTypeKind(ct) || _extKind(_extOf(loot.filename));
  }
  if (loot.value) {
    return 'text';
  }
  return 'none';
}

function _hostLabel(hosts, host_id) {
  const h = hosts.find(h => h.id === host_id);
  return h ? (h.hostname || h.ip) : null;
}

function _previewable(loot) {
  const k = _previewKind(loot);
  return k !== 'binary' && k !== 'none' && k !== 'office';
}

const LOOT_TYPES = {
  file:   { label: 'File',    color: '#5b8af5' },
  hash:   { label: 'Hash',    color: '#c07af0' },
  secret: { label: 'Secret',  color: '#e8574a' },
  env:    { label: 'ENV',     color: PALETTE.warn },
  token:  { label: 'Token',   color: PALETTE.ok },
  key:    { label: 'Key',     color: '#6fc8f0' },
  config: { label: 'Config',  color: '#e8cc42' },
  other:  { label: 'Other',   color: PALETTE.textFaint },
};

// ── Office previews (lazy-loaded — heavy libs stay out of the main bundle) ──
function DocxPreview({ url }) {
  const [html, setHtml] = useState(null);
  const [err, setErr] = useState('');
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [{ default: mammoth }, resp] = await Promise.all([import('mammoth'), fetch(url)]);
        if (!resp.ok) throw new Error(`${resp.status}`);
        const buf = await resp.arrayBuffer();
        const { value } = await mammoth.convertToHtml({ arrayBuffer: buf });
        if (!cancelled) setHtml(DOMPurify.sanitize(value));
      } catch (e) { if (!cancelled) setErr(e.message || 'Failed to render'); }
    })();
    return () => { cancelled = true; };
  }, [url]);
  if (err) return <div style={{ padding: 40, color: PALETTE.danger, fontSize: 12, fontFamily: FONTS.mono }}>Failed to render: {err}</div>;
  if (html == null) return <div style={{ padding: 40, color: '#505560', fontSize: 12, fontFamily: FONTS.mono }}>Rendering document…</div>;
  return (
    <div style={{ width: '100%', overflow: 'auto', background: '#f6f7f9', color: '#14161b', padding: '32px 48px' }}>
      <div className="docx-body" style={{ maxWidth: 820, margin: '0 auto', fontFamily: 'Georgia, serif', lineHeight: 1.6 }}
        dangerouslySetInnerHTML={{ __html: html }} />
    </div>
  );
}
DocxPreview.propTypes = { url: PropTypes.string.isRequired };

function SheetPreview({ url }) {
  const [sheets, setSheets] = useState(null); // [{name, html}]
  const [active, setActive] = useState(0);
  const [err, setErr] = useState('');
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [XLSX, resp] = await Promise.all([import('xlsx'), fetch(url)]);
        if (!resp.ok) throw new Error(`${resp.status}`);
        const buf = await resp.arrayBuffer();
        const wb = XLSX.read(buf, { type: 'array' });
        const out = wb.SheetNames.map(name => ({
          name,
          html: DOMPurify.sanitize(XLSX.utils.sheet_to_html(wb.Sheets[name], { editable: false })),
        }));
        if (!cancelled) setSheets(out);
      } catch (e) { if (!cancelled) setErr(e.message || 'Failed to render'); }
    })();
    return () => { cancelled = true; };
  }, [url]);
  if (err) return <div style={{ padding: 40, color: PALETTE.danger, fontSize: 12, fontFamily: FONTS.mono }}>Failed to render: {err}</div>;
  if (sheets == null) return <div style={{ padding: 40, color: '#505560', fontSize: 12, fontFamily: FONTS.mono }}>Rendering spreadsheet…</div>;
  if (!sheets.length) return <div style={{ padding: 40, color: PALETTE.textFaint, fontSize: 12, fontFamily: FONTS.mono }}>Empty workbook.</div>;
  return (
    <div style={{ width: '100%', display: 'flex', flexDirection: 'column', minHeight: 0 }}>
      {sheets.length > 1 && (
        <div style={{ display: 'flex', gap: 4, padding: '8px 12px', borderBottom: `1px solid ${PALETTE.borderSoft}`, flexWrap: 'wrap', flexShrink: 0 }}>
          {sheets.map((s, i) => (
            <button key={s.name} onClick={() => setActive(i)}
              style={{ background: i === active ? `${PALETTE.accent || '#15bbb1'}22` : 'transparent', border: `1px solid ${i === active ? '#15bbb1' : PALETTE.border}`, borderRadius: 4, padding: '3px 9px', cursor: 'pointer', color: i === active ? '#15bbb1' : PALETTE.textFaint, fontSize: 10, fontFamily: FONTS.mono }}>
              {s.name}
            </button>
          ))}
        </div>
      )}
      <div className="sheet-body" style={{ flex: 1, overflow: 'auto', background: '#f6f7f9', color: '#14161b', padding: 12 }}
        dangerouslySetInnerHTML={{ __html: sheets[active].html }} />
    </div>
  );
}
SheetPreview.propTypes = { url: PropTypes.string.isRequired };

// ── Preview modal ─────────────────────────────────────────────────────
function LootPreviewModal({ loot, onClose }) {
  const kind = _previewKind(loot);
  const [textContent, setTextContent] = useState(loot.public_url ? null : (loot.value || ''));
  const [textError, setTextError] = useState('');

  // Lock body scroll while open
  useEffect(() => {
    const prev = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => { document.body.style.overflow = prev; };
  }, []);

  // Close on Esc
  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose(); };
    globalThis.addEventListener('keydown', onKey);
    return () => globalThis.removeEventListener('keydown', onKey);
  }, [onClose]);

  // For file-text previews, fetch the file body lazily.
  useEffect(() => {
    if (kind !== 'text' || !loot.public_url) {
      return;
    }
    let cancelled = false;
    (async () => {
      try {
        const resp = await fetch(downloadUrl(loot.public_url));
        if (!resp.ok) throw new Error(`${resp.status}`);
        const text = await resp.text();
        if (!cancelled) {
          setTextContent(text);
        }
      } catch (e) {
        if (!cancelled) {
          setTextError(e.message || 'Failed to load');
        }
      }
    })();
    return () => { cancelled = true; };
  }, [kind, loot.public_url]);

  const fileUrl = loot.public_url ? downloadUrl(loot.public_url) : '';
  const titleFile = loot.filename || loot.source_path || 'loot';

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.78)', zIndex: 5000, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 40 }}>
      <button type="button" aria-label="Close preview" onClick={onClose} style={{ position: 'absolute', inset: 0, background: 'transparent', border: 'none', cursor: 'default' }} />
      <div
        style={{ position: 'relative', background: '#0c0e13', border: `1px solid ${PALETTE.border}`, borderRadius: 10, width: '100%', maxWidth: 1100, maxHeight: '92vh', display: 'flex', flexDirection: 'column', overflow: 'hidden', boxShadow: '0 10px 40px rgba(0,0,0,0.6)' }}>
        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '12px 16px', borderBottom: '1px solid #1e2029', flexShrink: 0 }}>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontSize: 12, color: '#e0e4ec', fontFamily: FONTS.mono, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={titleFile}>
              {titleFile}
            </div>
            <div style={{ fontSize: 10, color: PALETTE.textFaint, fontFamily: FONTS.mono, marginTop: 2 }}>
              {kind} · {loot.content_type || (loot.public_url ? 'binary' : 'text/plain')}
              {loot.file_size ? ` · ${_formatBytes(loot.file_size)}` : ''}
            </div>
          </div>
          <button onClick={() => downloadLoot(loot)} title="Download"
            style={{ background: PALETTE.borderSoft, border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 10px', cursor: 'pointer', color: PALETTE.textMute, fontSize: 10, fontFamily: FONTS.mono, display: 'flex', alignItems: 'center', gap: 5 }}>
            <Icon name="export" size={11} color="#9098a8" /> Download
          </button>
          <button onClick={onClose} title="Close (Esc)"
            style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 8px', cursor: 'pointer', display: 'flex' }}>
            <Icon name="close" size={11} color="#9098a8" />
          </button>
        </div>
        {/* Body */}
        <div style={{ flex: 1, overflow: 'auto', background: '#07080b', display: 'flex', alignItems: 'stretch', justifyContent: 'center' }}>
          {kind === 'image' && (
            <img src={fileUrl} alt={titleFile} style={{ maxWidth: '100%', maxHeight: '86vh', objectFit: 'contain', alignSelf: 'center', margin: 'auto', display: 'block' }} />
          )}
          {kind === 'pdf' && (
            // disposition=inline so the server serves it renderable in the
            // iframe instead of triggering a download.
            <iframe title={titleFile} src={`${fileUrl}${fileUrl.includes('?') ? '&' : '?'}disposition=inline`} style={{ width: '100%', height: '86vh', border: 'none', background: '#0a0c10' }} />
          )}
          {kind === 'docx' && <DocxPreview url={fileUrl} />}
          {kind === 'sheet' && <SheetPreview url={fileUrl} />}
          {kind === 'office' && (
            <div style={{ padding: 60, color: PALETTE.textFaint, fontSize: 12, fontFamily: FONTS.mono, textAlign: 'center', alignSelf: 'center', margin: 'auto' }}>
              <div style={{ marginBottom: 6, color: PALETTE.textMute }}>This format has no in-browser preview.</div>
              <div>Use the Download button to open it in a desktop application.</div>
            </div>
          )}
          {kind === 'text' && textContent != null && (
            <pre style={{ width: '100%', margin: 0, padding: 16, color: PALETTE.textDim, fontSize: 12, fontFamily: FONTS.mono, whiteSpace: 'pre-wrap', wordBreak: 'break-word', overflow: 'auto' }}>
              {textContent}
            </pre>
          )}
          {kind === 'text' && textContent == null && !textError && (
            <div style={{ padding: 40, color: '#505560', fontSize: 12, fontFamily: FONTS.mono }}>Loading…</div>
          )}
          {kind === 'text' && textError && (
            <div style={{ padding: 40, color: PALETTE.danger, fontSize: 12, fontFamily: FONTS.mono }}>Failed to load: {textError}</div>
          )}
          {kind === 'audio' && (
            <audio controls src={fileUrl} style={{ alignSelf: 'center', margin: 'auto', width: '60%' }}>
              <track kind="captions" label="No captions available" />
            </audio>
          )}
          {kind === 'video' && (
            <video controls src={fileUrl} style={{ maxWidth: '100%', maxHeight: '86vh', alignSelf: 'center', margin: 'auto' }}>
              <track kind="captions" label="No captions available" />
            </video>
          )}
          {(kind === 'binary' || kind === 'none') && (
            <div style={{ padding: 60, color: PALETTE.textFaint, fontSize: 12, fontFamily: FONTS.mono, textAlign: 'center', alignSelf: 'center', margin: 'auto' }}>
              <div style={{ fontSize: 36, marginBottom: 14 }}>📦</div>
              <div style={{ marginBottom: 6, color: PALETTE.textMute }}>No inline preview available for this file type.</div>
              <div>Use the Download button to retrieve the original.</div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function _formatBytes(n) {
  if (!n) {
    return '0 B';
  }
  const u = ['B', 'KB', 'MB', 'GB'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i === 0 ? 0 : 1)} ${u[i]}`;
}

function TypeBadge({ type }) {
  const t = LOOT_TYPES[type] || LOOT_TYPES.other;
  return (
    <span style={{ fontSize: 9, fontWeight: 700, color: t.color, background: t.color + '22', border: `1px solid ${t.color}44`, borderRadius: 3, padding: '1px 6px', fontFamily: FONTS.mono, textTransform: 'uppercase', letterSpacing: '0.05em', whiteSpace: 'nowrap' }}>
      {t.label}
    </span>
  );
}

const EMPTY = { loot_type: 'file', value: '', description: '', source_path: '', host_id: null };

const lootPropType = PropTypes.shape({
  id: PropTypes.any,
  pid: PropTypes.any,
  loot_type: PropTypes.string,
  value: PropTypes.string,
  description: PropTypes.string,
  source_path: PropTypes.string,
  host_id: PropTypes.any,
  artifact_type: PropTypes.string,
  public_url: PropTypes.string,
  filename: PropTypes.string,
  content_type: PropTypes.string,
  file_size: PropTypes.number,
  sha256: PropTypes.string,
  job_id: PropTypes.any,
  ts: PropTypes.any,
});

const hostPropType = PropTypes.shape({
  id: PropTypes.any,
  pid: PropTypes.any,
  ip: PropTypes.string,
  hostname: PropTypes.string,
});

const refPropType = PropTypes.shape({
  current: PropTypes.any,
});

LootPreviewModal.propTypes = {
  loot: lootPropType.isRequired,
  onClose: PropTypes.func.isRequired,
};

TypeBadge.propTypes = {
  type: PropTypes.string,
};

LootRow.propTypes = {
  loot: lootPropType.isRequired,
  isSel: PropTypes.bool,
  isCopied: PropTypes.bool,
  shown: PropTypes.bool,
  canReadSecret: PropTypes.bool.isRequired,
  hl: PropTypes.string,
  accent: PropTypes.string.isRequired,
  fs: PropTypes.number.isRequired,
  setSelectedId: PropTypes.func.isRequired,
  setShowValues: PropTypes.func.isRequired,
  copy: PropTypes.func.isRequired,
  setPreviewLootId: PropTypes.func.isRequired,
  onDelete: PropTypes.func.isRequired,
};

LootHeader.propTypes = {
  accent: PropTypes.string.isRequired,
  fs: PropTypes.number.isRequired,
  filtered: PropTypes.arrayOf(lootPropType).isRequired,
  projectLoots: PropTypes.arrayOf(lootPropType).isRequired,
  filterType: PropTypes.string,
  setFilterType: PropTypes.func.isRequired,
  typeCounts: PropTypes.object.isRequired,
  search: PropTypes.string.isRequired,
  setSearch: PropTypes.func.isRequired,
  showAdd: PropTypes.bool,
  setShowAdd: PropTypes.func.isRequired,
};

LootQuickAdd.propTypes = {
  newLoot: lootPropType.isRequired,
  setNewLoot: PropTypes.func.isRequired,
  addFileRef: refPropType.isRequired,
  projectHosts: PropTypes.arrayOf(hostPropType).isRequired,
  uploading: PropTypes.bool,
  addLoot: PropTypes.func.isRequired,
  createLootWithFile: PropTypes.func.isRequired,
  setShowAdd: PropTypes.func.isRequired,
  accent: PropTypes.string.isRequired,
};

LootEditPanel.propTypes = {
  selLoot: lootPropType.isRequired,
  projectHosts: PropTypes.arrayOf(hostPropType).isRequired,
  uploading: PropTypes.bool,
  editFileRef: refPropType.isRequired,
  copied: PropTypes.any,
  setCopied: PropTypes.func.isRequired,
  setPreviewLootId: PropTypes.func.isRequired,
  setSelectedId: PropTypes.func.isRequired,
  uploadFileForLoot: PropTypes.func.isRequired,
  onUpdate: PropTypes.func.isRequired,
};

function LootRow({ loot, isSel, isCopied, shown, canReadSecret, hl, accent, fs, setSelectedId, setShowValues, copy, setPreviewLootId, onDelete }) {
  const { can } = useProjectPermissions();
  return (
    <button type="button" key={loot.id} id={`loot-${loot.id}`} onClick={() => setSelectedId(isSel ? null : loot.id)}
      style={{ display: 'flex', alignItems: 'center', minHeight: 44, padding: '8px 18px', borderTop: 'none', borderRight: 'none', borderBottom: '1px solid #14161b', gap: 12, cursor: 'pointer', background: isSel ? '#ffffff06' : 'transparent', borderLeft: isSel ? `2px solid ${accent}` : '2px solid transparent', outline: 'none', color: 'inherit', font: 'inherit', transition: 'background .1s', width: '100%', textAlign: 'left' }}
      onMouseEnter={e => !isSel && (e.currentTarget.style.background = '#ffffff04')}
      onMouseLeave={e => !isSel && (e.currentTarget.style.background = 'transparent')}>
      <div style={{ width: 80, flexShrink: 0, display: 'flex', flexDirection: 'column', gap: 2 }}>
        <TypeBadge type={loot.loot_type} />
        {loot.artifact_type && loot.artifact_type !== 'file' && (
          <span style={{ fontSize: 8, color: '#808590', background: '#80859018', border: '1px solid #80859033', borderRadius: 3, padding: '1px 4px', fontFamily: FONTS.mono }}>{loot.artifact_type.replace('_', ' ')}</span>
        )}
      </div>
      <div style={{ flex: 1, minWidth: 0, fontFamily: FONTS.mono, fontSize: Math.max(10, fs - 3), color: shown ? '#c8cdd6' : PALETTE.textFaint, filter: (canReadSecret && shown) ? 'none' : 'blur(5px)', transition: 'filter .2s', userSelect: (canReadSecret && shown) ? 'text' : 'none', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {canReadSecret ? (loot.value || '(empty)') : '••••••••'}
      </div>
      <div style={{ width: 200, flexShrink: 0, fontSize: Math.max(10, fs - 3), color: '#808590', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {loot.description || '—'}
      </div>
      <div style={{ width: 160, flexShrink: 0, fontSize: Math.max(9, fs - 4), color: '#505560', fontFamily: FONTS.mono, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {loot.filename || loot.source_path || '—'}
      </div>
      <div style={{ width: 120, flexShrink: 0, fontSize: Math.max(9, fs - 4), color: '#5b8af5', fontFamily: FONTS.mono, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {hl || '—'}
      </div>
      <div style={{ width: 60, display: 'flex', gap: 4, alignItems: 'center' }}>
        {canReadSecret && (
          <button onClick={e => { e.stopPropagation(); setShowValues(p => ({ ...p, [loot.id]: !p[loot.id] })); }} title={shown ? 'Hide' : 'Show'}
            style={{ background: 'none', border: 'none', cursor: 'pointer', color: PALETTE.textGhost, display: 'flex', padding: 2 }}
            onMouseEnter={e => e.currentTarget.style.color = '#9098a8'}
            onMouseLeave={e => e.currentTarget.style.color = '#404550'}>
            <Icon name={shown ? 'eyeOff' : 'eye'} size={12} color="currentColor" />
          </button>
        )}
        {canReadSecret && (
          <button onClick={e => { e.stopPropagation(); copy(loot.value, loot.id); }} title="Copy"
            style={{ background: 'none', border: 'none', cursor: 'pointer', color: isCopied ? '#39d353' : PALETTE.textGhost, display: 'flex', padding: 2 }}>
            <Icon name={isCopied ? 'check' : 'copy'} size={12} color="currentColor" />
          </button>
        )}
        {_previewable(loot) && (
          <button onClick={e => { e.stopPropagation(); setPreviewLootId(loot.id); }} title="Preview"
            style={{ background: 'none', border: 'none', cursor: 'pointer', color: PALETTE.textGhost, display: 'flex', padding: 2 }}
            onMouseEnter={e => e.currentTarget.style.color = '#c07af0'}
            onMouseLeave={e => e.currentTarget.style.color = '#404550'}>
            <Icon name="eye" size={12} color="currentColor" />
          </button>
        )}
        <button onClick={() => downloadLoot(loot)} title="Download"
          style={{ background: 'none', border: 'none', cursor: 'pointer', color: loot.public_url ? '#5b8af5' : PALETTE.textGhost, display: 'flex', padding: 2 }}
          onMouseEnter={e => e.currentTarget.style.color = '#5b8af5'}
          onMouseLeave={e => e.currentTarget.style.color = loot.public_url ? '#5b8af5' : PALETTE.textGhost}>
          <Icon name="export" size={12} color="currentColor" />
        </button>
        {can('loot.delete') && <button onClick={() => { onDelete(loot.id); setSelectedId(prev => prev === loot.id ? null : prev); }}
          style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#303540', display: 'flex', padding: 2 }}
          onMouseEnter={e => e.currentTarget.style.color = '#cc2233'}
          onMouseLeave={e => e.currentTarget.style.color = '#303540'}>
          <Icon name="trash" size={12} color="currentColor" />
        </button>}
      </div>
    </button>
  );
}

async function _uploadFileForLoot(lootId, file, onUpdate, setUploading) {
  if (!file) {
    return;
  }
  setUploading(true);
  try {
    const updated = await api.uploadLootFile(lootId, file);
    await onUpdate(lootId, updated);
  } finally {
    setUploading(false);
  }
}

async function _createLootWithFile(file, selectedProject, newLoot, { onAdd, onUpdate, setNewLoot, setShowAdd, setUploading }) {
  if (!file) {
    return;
  }
  setUploading(true);
  try {
    const loot = await onAdd({ pid: selectedProject, ...newLoot, loot_type: 'file', value: file.name || newLoot.value || 'uploaded file' });
    await _uploadFileForLoot(loot.id, file, onUpdate, setUploading);
    setNewLoot(EMPTY);
    setShowAdd(false);
  } finally {
    setUploading(false);
  }
}

function _addLoot(newLoot, pid, onAdd, setNewLoot, setShowAdd) {
  if (!newLoot.value.trim() && !newLoot.description.trim()) {
    return;
  }
  onAdd({ pid, ...newLoot });
  setNewLoot(EMPTY);
  setShowAdd(false);
}

function _findPreviewLoot(loots, id) {
  return id ? loots.find(l => l.id === id) : null;
}

function LootHeader({ accent, fs, filtered, projectLoots, filterType, setFilterType, typeCounts, search, setSearch, showAdd, setShowAdd }) {
  const { can } = useProjectPermissions();
  return (
    <div style={{ padding: '14px 18px', borderBottom: `1px solid ${PALETTE.borderSoft}`, background: '#0a0c10', display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0 }}>
      <div style={{ flex: 1 }}>
        <span style={{ fontSize: fs + 1, fontWeight: 600, color: '#e0e4ec', fontFamily: FONTS.display }}>loot</span>
        <span style={{ fontSize: Math.max(10, fs - 2), color: PALETTE.textGhost, marginLeft: 10 }}>{filtered.length} of {projectLoots.length}</span>
      </div>
      <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
        {Object.entries(LOOT_TYPES).map(([k, v]) => {
          if (!typeCounts[k]) {
            return null;
          }
          return (
            <button key={k} onClick={() => setFilterType(filterType === k ? null : k)}
              style={{ background: filterType === k ? v.color + '22' : 'transparent', border: `1px solid ${filterType === k ? v.color + '88' : PALETTE.border}`, borderRadius: 3, padding: '3px 8px', cursor: 'pointer', fontSize: Math.max(9, fs - 4), color: filterType === k ? v.color : '#505560', fontFamily: FONTS.mono, transition: 'all .12s' }}>
              {v.label} {typeCounts[k]}
            </button>
          );
        })}
      </div>
      <div style={{ width: 200 }}><SearchBar value={search} onChange={setSearch} placeholder="Value, description..." /></div>
      {can('loot.create') && <button onClick={() => setShowAdd(v => !v)}
        style={{ background: accent, border: 'none', borderRadius: 4, padding: '5px 12px', cursor: 'pointer', color: '#fff', fontSize: Math.max(10, fs - 3), fontWeight: 600, fontFamily: FONTS.mono, display: 'flex', alignItems: 'center', gap: 5 }}>
        <Icon name="plus" size={10} color="#fff" /> Add
      </button>}
    </div>
  );
}

function _computeFilteredLoots(loots, filterType, search) {
  return loots
    .filter(l => !filterType || l.loot_type === filterType)
    .filter(l => !search || [l.value, l.description, l.source_path].join(' ').toLowerCase().includes(search.toLowerCase()));
}

function _computeTypeCounts(loots) {
  return Object.keys(LOOT_TYPES).reduce((acc, k) => {
    acc[k] = loots.filter(l => l.loot_type === k).length;
    return acc;
  }, {});
}

function _copyLoot(text, id, setCopied) {
  copyToClipboard(text).catch(() => {});
  setCopied(id);
  setTimeout(() => setCopied(null), 1500);
}

function LootQuickAdd({ newLoot, setNewLoot, addFileRef, projectHosts, uploading, addLoot, createLootWithFile, setShowAdd, accent }) {
  return (
    <div style={{ padding: '14px 18px', borderBottom: `1px solid ${PALETTE.borderSoft}`, background: '#0c0e13', display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'flex-end' }}>
      <div>
        <div style={{ fontSize: 9, color: PALETTE.textGhost, marginBottom: 4, textTransform: 'uppercase' }}>Type</div>
        <Select value={newLoot.loot_type} onChange={v => setNewLoot(l => ({ ...l, loot_type: v }))}
          options={Object.entries(LOOT_TYPES).map(([k, v]) => ({ value: k, label: v.label }))} />
      </div>
      <div style={{ flex: 1, minWidth: 200 }}>
        <div style={{ fontSize: 9, color: PALETTE.textGhost, marginBottom: 4, textTransform: 'uppercase' }}>Value</div>
        <input value={newLoot.value} onChange={e => setNewLoot(l => ({ ...l, value: e.target.value }))} autoFocus
          placeholder="Password, hash, file path..."
          style={{ width: '100%', background: PALETTE.bg3, border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '5px 7px', color: PALETTE.textDim, fontSize: 11, outline: 'none', fontFamily: FONTS.mono, boxSizing: 'border-box' }} />
      </div>
      <div style={{ width: 160 }}>
        <div style={{ fontSize: 9, color: PALETTE.textGhost, marginBottom: 4, textTransform: 'uppercase' }}>Description</div>
        <input value={newLoot.description} onChange={e => setNewLoot(l => ({ ...l, description: e.target.value }))}
          placeholder="Where from, what is it..."
          style={{ width: '100%', background: PALETTE.bg3, border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '5px 7px', color: PALETTE.textDim, fontSize: 11, outline: 'none', fontFamily: FONTS.mono, boxSizing: 'border-box' }} />
      </div>
      <div style={{ width: 140 }}>
        <div style={{ fontSize: 9, color: PALETTE.textGhost, marginBottom: 4, textTransform: 'uppercase' }}>Path / source</div>
        <input value={newLoot.source_path} onChange={e => setNewLoot(l => ({ ...l, source_path: e.target.value }))}
          placeholder="/etc/shadow"
          style={{ width: '100%', background: PALETTE.bg3, border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '5px 7px', color: PALETTE.textDim, fontSize: 11, outline: 'none', fontFamily: FONTS.mono, boxSizing: 'border-box' }} />
      </div>
      <div style={{ width: 140 }}>
        <div style={{ fontSize: 9, color: PALETTE.textGhost, marginBottom: 4, textTransform: 'uppercase' }}>Host</div>
        <Select value={newLoot.host_id || ''} onChange={v => setNewLoot(l => ({ ...l, host_id: v || null }))}
          style={{ width: '100%' }} placeholder="—"
          options={projectHosts.map(h => ({ value: h.id, label: h.hostname || h.ip }))} />
      </div>
      <input ref={addFileRef} type="file" style={{ display: 'none' }} onChange={e => e.target.files?.[0] && createLootWithFile(e.target.files[0])} />
      <button onClick={addLoot} style={{ background: accent, border: 'none', borderRadius: 4, padding: '6px 14px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: FONTS.mono }}>Save</button>
      <button onClick={() => addFileRef.current?.click()} style={{ background: PALETTE.borderSoft, border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 12px', cursor: 'pointer', color: PALETTE.textMute, fontSize: 11, fontFamily: FONTS.mono }}>
        {uploading ? 'Uploading…' : 'Upload file'}
      </button>
      <button onClick={() => setShowAdd(false)} style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 10px', cursor: 'pointer', color: PALETTE.textFaint, fontSize: 11, fontFamily: FONTS.mono }}>Cancel</button>
    </div>
  );
}

function LootEditPanel({ selLoot, projectHosts, uploading, editFileRef, copied, setCopied, setPreviewLootId, setSelectedId, uploadFileForLoot, onUpdate }) {
  return (
    <div style={{ width: 280, background: '#0c0e13', borderLeft: '1px solid #1e2029', overflowY: 'auto', flexShrink: 0 }}>
      <div style={{ padding: '12px 14px', borderBottom: '1px solid #1e2029', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <span style={{ fontSize: 11, fontWeight: 600, color: '#e0e4ec', fontFamily: FONTS.display }}>Edit</span>
        <button onClick={() => setSelectedId(null)} style={{ background: 'none', border: 'none', cursor: 'pointer', display: 'flex' }}>
          <Icon name="close" size={12} color="#606570" />
        </button>
      </div>
      <div style={{ padding: 14, display: 'flex', flexDirection: 'column', gap: 12 }}>
        <div>
          <div style={{ fontSize: 9, color: '#505560', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '.1em' }}>Type</div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
            {Object.entries(LOOT_TYPES).map(([k, v]) => (
              <button key={k} onClick={() => onUpdate(selLoot.id, { loot_type: k })}
                style={{ background: selLoot.loot_type === k ? v.color + '22' : PALETTE.bg3, border: `1px solid ${selLoot.loot_type === k ? v.color + '77' : PALETTE.border}`, borderRadius: 3, padding: '3px 8px', cursor: 'pointer', color: selLoot.loot_type === k ? v.color : PALETTE.textFaint, fontSize: 9, fontFamily: FONTS.mono }}>
                {v.label}
              </button>
            ))}
          </div>
        </div>
        <div>
          <div style={{ fontSize: 9, color: '#505560', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '.1em' }}>Value</div>
          <textarea value={selLoot.value} onChange={e => onUpdate(selLoot.id, { value: e.target.value })} rows={4}
            style={{ width: '100%', background: '#07080b', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 8px', color: PALETTE.textDim, fontSize: 11, outline: 'none', fontFamily: FONTS.mono, resize: 'vertical', boxSizing: 'border-box' }} />
        </div>
        <div>
          <div style={{ fontSize: 9, color: '#505560', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '.1em' }}>Description</div>
          <input value={selLoot.description} onChange={e => onUpdate(selLoot.id, { description: e.target.value })}
            style={{ width: '100%', background: '#07080b', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '5px 7px', color: PALETTE.textDim, fontSize: 11, outline: 'none', fontFamily: FONTS.mono, boxSizing: 'border-box' }} />
        </div>
        <div>
          <div style={{ fontSize: 9, color: '#505560', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '.1em' }}>Source / path</div>
          <input value={selLoot.source_path} onChange={e => onUpdate(selLoot.id, { source_path: e.target.value })}
            placeholder="/etc/shadow, proc memory..."
            style={{ width: '100%', background: '#07080b', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '5px 7px', color: PALETTE.textDim, fontSize: 11, outline: 'none', fontFamily: FONTS.mono, boxSizing: 'border-box' }} />
        </div>
        <div>
          <div style={{ fontSize: 9, color: '#505560', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '.1em' }}>Host</div>
          <Select value={selLoot.host_id || ''} onChange={v => onUpdate(selLoot.id, { host_id: v || null })}
            style={{ width: '100%' }} placeholder="— not linked —"
            options={projectHosts.map(h => ({ value: h.id, label: h.hostname || h.ip }))} />
        </div>
        <div>
          <div style={{ fontSize: 9, color: '#505560', marginBottom: 5, textTransform: 'uppercase', letterSpacing: '.1em' }}>Attached file</div>
          <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
            <input ref={editFileRef} type="file" style={{ display: 'none' }} onChange={e => e.target.files?.[0] && uploadFileForLoot(selLoot.id, e.target.files[0])} />
            <button onClick={() => editFileRef.current?.click()} style={{ background: PALETTE.borderSoft, border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 10px', cursor: 'pointer', color: PALETTE.textMute, fontSize: 10, fontFamily: FONTS.mono }}>{uploading ? 'Uploading…' : 'Upload / replace'}</button>
            {_previewable(selLoot) && (
              <button onClick={() => setPreviewLootId(selLoot.id)} style={{ background: PALETTE.borderSoft, border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 10px', cursor: 'pointer', color: '#c07af0', fontSize: 10, fontFamily: FONTS.mono, display: 'flex', alignItems: 'center', gap: 5 }}>
                <Icon name="eye" size={11} color="#c07af0" /> Preview
              </button>
            )}
            <button onClick={() => downloadLoot(selLoot)} style={{ background: PALETTE.borderSoft, border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '6px 10px', cursor: 'pointer', color: selLoot.public_url ? '#5b8af5' : '#808590', fontSize: 10, fontFamily: FONTS.mono }}>
              Download{(() => { if (selLoot.filename) { return ` (${(_extOf(selLoot.filename) || (selLoot.public_url ? 'bin' : 'txt')).toUpperCase()})`; } if (selLoot.public_url) { return ''; } return ' (TXT)'; })()}
            </button>
          </div>
          <div style={{ fontSize: 10, color: PALETTE.textFaint, marginTop: 6, fontFamily: FONTS.mono }}>{(() => { if (selLoot.filename) { const sizeInfo = selLoot.file_size ? ` · ${selLoot.file_size} bytes` : ''; return `${selLoot.filename}${sizeInfo}`; } return 'No file attached'; })()}</div>
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          <button onClick={() => { copyToClipboard(selLoot.value).catch(() => {}); setCopied('panel'); setTimeout(() => setCopied(null), 1500); }}
            style={{ flex: 1, background: copied === 'panel' ? '#39d35322' : PALETTE.borderSoft, border: `1px solid ${copied === 'panel' ? '#39d35366' : PALETTE.border}`, borderRadius: 4, padding: '6px', cursor: 'pointer', color: copied === 'panel' ? '#39d353' : PALETTE.textFaint, fontSize: 10, fontFamily: FONTS.mono, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 5 }}>
            <Icon name={copied === 'panel' ? 'check' : 'copy'} size={11} color="currentColor" />
            {copied === 'panel' ? 'Copied' : 'Copy'}
          </button>
        </div>
        {selLoot.sha256 && <div style={{ fontSize: 8, color: '#303540', fontFamily: FONTS.mono, wordBreak: 'break-all' }}>sha256: {selLoot.sha256}</div>}
        {selLoot.job_id && <div style={{ fontSize: 9, color: PALETTE.textGhost, fontFamily: FONTS.mono }}>Source job: <span style={{ color: '#5b8af5' }}>{selLoot.job_id}</span></div>}
        <div style={{ fontSize: 9, color: '#303540', fontFamily: FONTS.mono }}>{selLoot.ts}</div>
      </div>
    </div>
  );
}

export default function LootView({ loots, hosts, onAdd, onUpdate, onDelete, selectedProject, accent, fs = 14, focusId, consumeFocusId }) {
  const { can, isSuperAdmin } = useProjectPermissions();
  const canReadSecret = isSuperAdmin || can('credentials.read_secret');
  const [search, setSearch] = useState('');
  const [filterType, setFilterType] = useState(null);
  const [showAdd, setShowAdd] = useState(false);
  const [newLoot, setNewLoot] = useState(EMPTY);
  const [selectedId, setSelectedId] = useState(null);
  const [previewLootId, setPreviewLootId] = useState(null);
  const [showValues, setShowValues] = useState({});
  const [copied, setCopied] = useState(null);
  const [uploading, setUploading] = useState(false);
  const addFileRef = useRef(null);
  const editFileRef = useRef(null);

  const projectLoots = loots.filter(l => l.pid === selectedProject);
  const projectHosts = (hosts || []).filter(h => h.pid === selectedProject);
  const filtered = _computeFilteredLoots(projectLoots, filterType, search);
  const selLoot = projectLoots.find(l => l.id === selectedId);
  const typeCounts = _computeTypeCounts(projectLoots);
  const copy = (text, id) => _copyLoot(text, id, setCopied);
  const addLoot = () => _addLoot(newLoot, selectedProject, onAdd, setNewLoot, setShowAdd);
  const uploadFileForLoot = (lootId, file) => _uploadFileForLoot(lootId, file, onUpdate, setUploading);
  const createLootWithFile = (file) => _createLootWithFile(file, selectedProject, newLoot, { onAdd, onUpdate, setNewLoot, setShowAdd, setUploading });
  const previewLoot = _findPreviewLoot(loots, previewLootId);

  useEffect(() => {
    if (!focusId) return;
    const match = projectLoots.find(l => l.id === focusId);
    if (match) {
      setSelectedId(focusId);
      requestAnimationFrame(() => {
        document.getElementById(`loot-${focusId}`)?.scrollIntoView({ behavior: 'smooth', block: 'center' });
      });
    }
    consumeFocusId?.();
  }, [focusId]);

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <LootHeader accent={accent} fs={fs} filtered={filtered} projectLoots={projectLoots} filterType={filterType} setFilterType={setFilterType} typeCounts={typeCounts} search={search} setSearch={setSearch} showAdd={showAdd} setShowAdd={setShowAdd} />

      {showAdd && <LootQuickAdd newLoot={newLoot} setNewLoot={setNewLoot} addFileRef={addFileRef} projectHosts={projectHosts} uploading={uploading} addLoot={addLoot} createLootWithFile={createLootWithFile} setShowAdd={setShowAdd} accent={accent} />}

      {/* Table header */}
      <div style={{ display: 'flex', alignItems: 'center', padding: '8px 18px', borderBottom: `1px solid ${PALETTE.borderSoft}`, background: '#090b0f', flexShrink: 0, gap: 12 }}>
        {[['Type', 80], ['Value', 0], ['Description', 200], ['Source', 160], ['Host', 120]].map(([l, w]) => (
          <div key={l} style={{ width: w || undefined, flex: w ? undefined : 1, fontSize: Math.max(9, fs - 4), color: PALETTE.textGhost, textTransform: 'uppercase', letterSpacing: '0.1em' }}>{l}</div>
        ))}
        <div style={{ width: 60 }} />
      </div>

      <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
        <div style={{ flex: 1, overflowY: 'auto' }}>
          {filtered.length === 0 && (
            <div style={{ padding: 48, textAlign: 'center', color: '#303540' }}>
              <Icon name="loot" size={36} color="#2a2d35" />
              <div style={{ marginTop: 12, fontSize: 13, color: PALETTE.textGhost }}>No loot. Add the first trophy.</div>
            </div>
          )}
          {filtered.map(loot => (
            <LootRow key={loot.id} loot={loot}
              isSel={selectedId === loot.id}
              isCopied={copied === loot.id}
              shown={showValues[loot.id]}
              canReadSecret={canReadSecret}
              hl={_hostLabel(projectHosts, loot.host_id)}
              accent={accent} fs={fs}
              setSelectedId={setSelectedId}
              setShowValues={setShowValues}
              copy={copy}
              setPreviewLootId={setPreviewLootId}
              onDelete={onDelete}
            />
          ))}
        </div>
        {selLoot && <LootEditPanel selLoot={selLoot} projectHosts={projectHosts} uploading={uploading} editFileRef={editFileRef} copied={copied} setCopied={setCopied} setPreviewLootId={setPreviewLootId} setSelectedId={setSelectedId} uploadFileForLoot={uploadFileForLoot} onUpdate={onUpdate} />}
      </div>
      {previewLoot && <LootPreviewModal loot={previewLoot} onClose={() => setPreviewLootId(null)} />}
    </div>
  );
}

LootView.propTypes = {
  loots: PropTypes.arrayOf(lootPropType).isRequired,
  hosts: PropTypes.arrayOf(hostPropType).isRequired,
  onAdd: PropTypes.func.isRequired,
  onUpdate: PropTypes.func.isRequired,
  onDelete: PropTypes.func.isRequired,
  selectedProject: PropTypes.any,
  accent: PropTypes.string.isRequired,
  fs: PropTypes.number,
};
