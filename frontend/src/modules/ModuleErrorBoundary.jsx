import { Component } from 'react';
import PropTypes from 'prop-types';

/**
 * Error boundary that isolates module UI failures from the main app.
 * If a module component throws, the rest of the UI keeps working.
 */
export default class ModuleErrorBoundary extends Component {
  static propTypes = {
    children: PropTypes.node.isRequired,
    moduleName: PropTypes.string,
    fallback: PropTypes.node,
  };

  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, info) {
    const name = this.props.moduleName || 'unknown';
    console.error(`[module:${name}] UI error:`, error, info);
  }

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) return this.props.fallback;
      const name = this.props.moduleName || 'module';
      return (
        <div
          style={{
            padding: 12,
            borderRadius: 6,
            border: '1px solid #cc223344',
            background: '#cc223311',
            fontFamily: 'JetBrains Mono',
            fontSize: 10,
            color: '#cc2233',
          }}
        >
          {name} UI error: {this.state.error?.message || 'unknown'}
        </div>
      );
    }
    return this.props.children;
  }
}
