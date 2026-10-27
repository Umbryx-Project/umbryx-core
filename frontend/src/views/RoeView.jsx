import { useState, useEffect, useCallback } from 'react';
import PropTypes from 'prop-types';
import { api } from '../api.js';
import Icon from '../components/Icon.jsx';
import { toastError, toastSuccess } from '../components/Toast.jsx';
import { useProjectPermissions } from '../context/ProjectPermissions.jsx';
import {
  Btn, FieldInput, Select, EmptyState, PageTitle, Overline, Badge,
  PALETTE, TYPE, FONTS } from '../components/UI.jsx';

const ACTIVITY_OPTIONS = [
  'web_scanning', 'port_scanning', 'ad_recon', 'exploitation',
  'phishing', 'social_engineering', 'wireless_attack', 'physical_access',
  'dos_testing', 'credential_stuffing', 'lateral_movement', 'privilege_escalation',
];

const APPROVAL_OPTIONS = ['destructive', 'dos_risk', 'data_access', 'lateral_movement'];

const TIMEZONES = ['UTC', 'Europe/Moscow', 'Europe/Berlin', 'US/Eastern', 'US/Pacific', 'Asia/Tokyo'];

const inpStyle = {
  background: PALETTE.bg1, border: `1px solid ${PALETTE.border}`, borderRadius: 4,
  padding: '6px 8px', color: PALETTE.textDim, fontSize: TYPE.body,
  fontFamily: FONTS.mono, outline: 'none',
};

function Chip({ label, active, onClick, color }) {
  return (
    <button onClick={onClick} style={{
      padding: '3px 8px', borderRadius: 3, cursor: 'pointer',
      border: active ? `1px solid ${color}88` : `1px solid ${PALETTE.border}`,
      background: active ? `${color}18` : 'transparent',
      color: active ? color : PALETTE.textFaint,
      fontSize: TYPE.label, fontFamily: FONTS.mono, fontWeight: 700,
      textTransform: 'uppercase', letterSpacing: '0.04em',
    }}>
      {label.replace(/_/g, ' ')}
    </button>
  );
}
Chip.propTypes = { label: PropTypes.string, active: PropTypes.bool, onClick: PropTypes.func, color: PropTypes.string };

function ReadBlock({ label, children }) {
  return (
    <div style={{ background: PALETTE.bg1, border: `1px solid ${PALETTE.borderSoft}`, borderRadius: 6, padding: '10px 14px', marginBottom: 8 }}>
      <Overline style={{ marginBottom: 6 }}>{label}</Overline>
      <div style={{ fontSize: TYPE.body, color: PALETTE.textDim, fontFamily: FONTS.mono }}>{children}</div>
    </div>
  );
}
ReadBlock.propTypes = { label: PropTypes.string, children: PropTypes.node };

function EditSection({ label, children }) {
  return (
    <div style={{ marginBottom: 16 }}>
      <Overline style={{ marginBottom: 6 }}>{label}</Overline>
      {children}
    </div>
  );
}
EditSection.propTypes = { label: PropTypes.string, children: PropTypes.node };

export default function RoeView({ selectedProject, accent, currentUser }) {
  const [roe, setRoe] = useState(null);
  const [editing, setEditing] = useState(false);
  const [form, setForm] = useState({});
  const [saving, setSaving] = useState(false);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    if (!selectedProject) return;
    setLoading(true);
    try {
      const data = await api.getROE(selectedProject);
      setRoe(data);
      setForm({
        allowed_activities: data.allowed_activities || [],
        forbidden_activities: data.forbidden_activities || [],
        work_hours_start: data.work_hours_start || '',
        work_hours_end: data.work_hours_end || '',
        timezone: data.timezone || 'UTC',
        max_scan_rate: data.max_scan_rate || '',
        requires_approval: data.requires_approval || [],
        notes: data.notes || '',
      });
    } catch (e) { toastError(e.message); }
    setLoading(false);
  }, [selectedProject]);

  useEffect(() => { load(); }, [load]);

  // Backend gates PUT/DELETE on the project-scoped `project.manage_members`
  // permission (project owner/admin), not the platform_admin global role —
  // matching that here instead of the global-only check that previously
  // hid editing from every project owner/admin who wasn't also a platform
  // admin (2026-08-18 UI/backend role-source audit).
  const { can, isSuperAdmin } = useProjectPermissions();
  const canEdit = isSuperAdmin || can('project.manage_members');

  const toggle = (field, value) =>
    setForm(f => ({ ...f, [field]: f[field].includes(value) ? f[field].filter(v => v !== value) : [...f[field], value] }));

  const save = async () => {
    setSaving(true);
    try {
      const data = await api.upsertROE(selectedProject, form);
      setRoe(data);
      setEditing(false);
      toastSuccess('ROE saved');
    } catch (e) { toastError(e.message); }
    setSaving(false);
  };

  if (!selectedProject) return <EmptyState icon="scroll" title="Select a project" />;

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>

      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px 16px', borderBottom: `1px solid ${PALETTE.borderSoft}`, flexShrink: 0 }}>
        <PageTitle icon="scroll" accent={accent}
          sub={roe?.updated_at ? `updated ${roe.updated_at}${roe.updated_by ? ` by ${roe.updated_by}` : ''}` : undefined}
          style={{ marginBottom: 0 }}>
          Rules of Engagement
        </PageTitle>
        {canEdit && !editing && roe && (
          <Btn variant="accentGhost" accent={accent} onClick={() => setEditing(true)}>Edit</Btn>
        )}
        {editing && (
          <div style={{ display: 'flex', gap: 6 }}>
            <Btn variant="ghost" onClick={() => setEditing(false)}>Cancel</Btn>
            <Btn variant="solid" accent={accent} onClick={save} disabled={saving}>{saving ? 'Saving...' : 'Save'}</Btn>
          </div>
        )}
      </div>

      <div style={{ flex: 1, overflow: 'auto', padding: '12px 16px' }}>
        {loading && <div style={{ color: PALETTE.textGhost, fontFamily: FONTS.mono, fontSize: TYPE.body }}>Loading...</div>}

        {!loading && !roe && (
          <EmptyState icon="scroll" title="No ROE configured yet" />
        )}

        {!loading && roe && !editing && (
          <>
            <ReadBlock label="Allowed Activities">
              {roe.allowed_activities?.length
                ? <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 2 }}>
                    {roe.allowed_activities.map(a => (
                      <Badge key={a} label={a.replace(/_/g, ' ')} color={PALETTE.ok} />
                    ))}
                  </div>
                : <span style={{ color: PALETTE.textGhost }}>—</span>}
            </ReadBlock>

            <ReadBlock label="Forbidden Activities">
              {roe.forbidden_activities?.length
                ? <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 2 }}>
                    {roe.forbidden_activities.map(a => (
                      <Badge key={a} label={a.replace(/_/g, ' ')} color={PALETTE.danger} />
                    ))}
                  </div>
                : <span style={{ color: PALETTE.textGhost }}>—</span>}
            </ReadBlock>

            <ReadBlock label="Requires Approval">
              {roe.requires_approval?.length
                ? <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 2 }}>
                    {roe.requires_approval.map(a => (
                      <Badge key={a} label={a.replace(/_/g, ' ')} color={PALETTE.warn} />
                    ))}
                  </div>
                : <span style={{ color: PALETTE.textGhost }}>—</span>}
            </ReadBlock>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 8 }}>
              <ReadBlock label="Work Hours">
                <span style={{ color: roe.work_hours_start ? PALETTE.textDim : PALETTE.textGhost }}>
                  {roe.work_hours_start && roe.work_hours_end ? `${roe.work_hours_start} — ${roe.work_hours_end}` : '—'}
                </span>
                {roe.timezone && roe.work_hours_start && <span style={{ color: PALETTE.textFaint, marginLeft: 6 }}>({roe.timezone})</span>}
              </ReadBlock>
              <ReadBlock label="Max Scan Rate">
                <span style={{ color: roe.max_scan_rate ? PALETTE.textDim : PALETTE.textGhost }}>{roe.max_scan_rate || '—'}</span>
              </ReadBlock>
            </div>

            {roe.notes && (
              <ReadBlock label="Notes">
                <span style={{ whiteSpace: 'pre-wrap', color: '#a0a8b8' }}>{roe.notes}</span>
              </ReadBlock>
            )}
          </>
        )}

        {!loading && editing && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
            <div style={{ background: PALETTE.bg1, border: `1px solid ${PALETTE.borderSoft}`, borderRadius: 6, padding: '14px 16px', marginBottom: 8 }}>
              <EditSection label="Allowed Activities">
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
                  {ACTIVITY_OPTIONS.map(a => <Chip key={a} label={a} active={form.allowed_activities.includes(a)} onClick={() => toggle('allowed_activities', a)} color={PALETTE.ok} />)}
                </div>
              </EditSection>
              <EditSection label="Forbidden Activities">
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
                  {ACTIVITY_OPTIONS.map(a => <Chip key={a} label={a} active={form.forbidden_activities.includes(a)} onClick={() => toggle('forbidden_activities', a)} color={PALETTE.danger} />)}
                </div>
              </EditSection>
              <EditSection label="Requires Approval">
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
                  {APPROVAL_OPTIONS.map(a => <Chip key={a} label={a} active={form.requires_approval.includes(a)} onClick={() => toggle('requires_approval', a)} color={PALETTE.warn} />)}
                </div>
              </EditSection>
            </div>

            <div style={{ background: PALETTE.bg1, border: `1px solid ${PALETTE.borderSoft}`, borderRadius: 6, padding: '14px 16px', marginBottom: 8 }}>
              <EditSection label="Work Hours">
                <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                  <input type="time" value={form.work_hours_start} onChange={e => setForm(f => ({ ...f, work_hours_start: e.target.value }))} style={inpStyle} />
                  <span style={{ color: PALETTE.textGhost, fontSize: TYPE.body, fontFamily: FONTS.mono }}>—</span>
                  <input type="time" value={form.work_hours_end} onChange={e => setForm(f => ({ ...f, work_hours_end: e.target.value }))} style={inpStyle} />
                  <Select value={form.timezone} onChange={v => setForm(f => ({ ...f, timezone: v }))} options={TIMEZONES} />
                </div>
              </EditSection>
              <EditSection label="Max Scan Rate">
                <input value={form.max_scan_rate} onChange={e => setForm(f => ({ ...f, max_scan_rate: e.target.value }))} placeholder="e.g. 100 req/s" style={{ ...inpStyle, width: 200 }} />
              </EditSection>
            </div>

            <div style={{ background: PALETTE.bg1, border: `1px solid ${PALETTE.borderSoft}`, borderRadius: 6, padding: '14px 16px' }}>
              <EditSection label="Notes">
                <textarea value={form.notes} onChange={e => setForm(f => ({ ...f, notes: e.target.value }))} rows={4} placeholder="Emergency contacts, out-of-scope systems, additional constraints..." style={{ ...inpStyle, resize: 'vertical', width: '100%', boxSizing: 'border-box' }} />
              </EditSection>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

RoeView.propTypes = { selectedProject: PropTypes.string, accent: PropTypes.string, currentUser: PropTypes.object };
