import { useState, useMemo } from 'react';
import PropTypes from 'prop-types';
import { EE_INFRA_TABS } from '@ee';
import { PageTitle, PALETTE, FONTS, TYPE } from '../components/UI.jsx';

// Every tab on this page comes from the Enterprise registry, so in Community
// the page has none and is not reachable at all — AppTopBar hides the nav
// entry when EE_INFRA_TABS is empty.
//
// DevOps and C2 Ops used to live here as "Community tabs", on the reasoning
// that operating a C2 does not require having deployed one. That was wrong in
// practice: both of them talk to /api/infra-v2, which is served entirely by
// backend/app/ee, so in a Community build the DevOps log and the stack list
// answered 404 and the tab rendered an empty log under an error toast. The
// one part of it that did work — the workstation shell-action feed, on the
// core /workstations/actions-feed — moved to the Workstations page, where its
// data comes from and where both editions can see it.

export default function PlatformOpsView({ selectedProject, accent = '#15bbb1', currentUser }) {
  const tabs = useMemo(() => [...EE_INFRA_TABS], []);
  const [tab, setTab] = useState(tabs[0]?.id);
  const [template, setTemplate] = useState(null);

  const handleUseTemplate = (tpl) => {
    setTemplate(tpl);
    setTab('builder');
  };

  const active = tabs.find(t => t.id === tab) || tabs[0];
  const ctx = {
    accent,
    selectedProject,
    currentUser,
    template,
    setTab,
    onUseTemplate: handleUseTemplate,
  };

  return (
    <div style={{ flex: 1, height: '100%', display: 'flex', flexDirection: 'column', minWidth: 0 }}>
      <style>{`@keyframes infra-pulse { 0%,100%{opacity:1} 50%{opacity:.4} }`}</style>
      <div style={{ padding: '12px 16px 0', flexShrink: 0 }}>
        <PageTitle icon="server" accent={accent} sub="Design, deploy, and manage attack infrastructure">
          Infrastructure
        </PageTitle>
        <div style={{ display: 'flex', gap: 2, borderBottom: `1px solid ${PALETTE.borderSoft}` }}>
          {tabs.map(t => (
            <button key={t.id} onClick={() => setTab(t.id)} style={{
              background: tab === t.id ? `${accent}14` : 'transparent',
              border: 'none',
              borderBottom: tab === t.id ? `2px solid ${accent}` : '2px solid transparent',
              color: tab === t.id ? PALETTE.text : PALETTE.textMute,
              padding: '8px 16px', cursor: 'pointer', fontSize: TYPE.body,
              fontFamily: FONTS.mono, fontWeight: 600,
              borderRadius: '4px 4px 0 0', transition: 'all .12s',
            }}>
              {t.label}
            </button>
          ))}
        </div>
      </div>

      <div style={{ flex: 1, overflow: 'hidden' }}>
        {active?.padded
          ? <div style={{ height: '100%', overflow: 'auto', padding: 16 }}>{active.render(ctx)}</div>
          : active?.render(ctx)}
      </div>
    </div>
  );
}

PlatformOpsView.propTypes = {
  selectedProject: PropTypes.string,
  accent: PropTypes.string,
  currentUser: PropTypes.object,
};
