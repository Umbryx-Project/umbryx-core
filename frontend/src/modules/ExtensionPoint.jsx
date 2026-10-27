import { Suspense } from 'react';
import PropTypes from 'prop-types';
import { useExtensions } from './extensionStore.js';
import { getComponent } from './moduleComponents.js';
import ModuleErrorBoundary from './ModuleErrorBoundary.jsx';

/**
 * Renders all extension components registered for a given extension point.
 *
 * Usage:
 *   <ExtensionPoint point="dashboard.widget" accent={accent} />
 *
 * Each extension is wrapped in ModuleErrorBoundary so a crash in one
 * module's UI doesn't break the host page.
 */
export default function ExtensionPoint({ point, ...props }) {
  const extensions = useExtensions(point);

  if (!extensions || extensions.length === 0) return null;

  const sorted = [...extensions].sort((a, b) => (a.order ?? 999) - (b.order ?? 999));

  return sorted.map((ext) => {
    const componentName = ext.component || ext.id;
    const Component = getComponent(componentName);

    if (!Component) {
      return (
        <div
          key={`${ext.module_id}:${ext.id}`}
          style={{
            padding: 8,
            borderRadius: 4,
            border: '1px solid #404550',
            background: '#ffffff06',
            fontFamily: 'JetBrains Mono',
            fontSize: 10,
            color: '#606570',
          }}
        >
          Module <strong>{ext.module_id}</strong> declares component{' '}
          <code>{componentName}</code> for <code>{point}</code>, but no
          frontend component is registered for it.
        </div>
      );
    }

    return (
      <ModuleErrorBoundary
        key={`${ext.module_id}:${ext.id}`}
        moduleName={ext.module_id}
      >
        <Suspense fallback={<div style={{ padding: 8, fontSize: 10, color: '#606570', fontFamily: 'JetBrains Mono' }}>Loading {ext.label || ext.id}...</div>}>
          <Component extension={ext} {...props} />
        </Suspense>
      </ModuleErrorBoundary>
    );
  });
}

ExtensionPoint.propTypes = {
  point: PropTypes.string.isRequired,
};
