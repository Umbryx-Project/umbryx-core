import React, { memo, useMemo } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import hljs from 'highlight.js/lib/common';
import { PALETTE, FONTS } from './UI.jsx';

const CODE_STYLES = {
  background: '#0a0c10',
  border: '1px solid #1e2029',
  borderRadius: 5,
  margin: '6px 0',
  overflow: 'hidden',
  fontSize: 11,
  fontFamily: 'JetBrains Mono, monospace',
};

const LANG_LABEL = {
  display: 'inline-block',
  padding: '2px 8px',
  fontSize: 9,
  color: '#505560',
  background: PALETTE.bg2,
  borderBottom: '1px solid #1e2029',
  textTransform: 'uppercase',
  letterSpacing: '0.05em',
};

function CodeBlock({ language, children }) {
  const highlighted = useMemo(() => {
    const lang = language && hljs.getLanguage(language) ? language : null;
    try {
      return lang
        ? hljs.highlight(String(children), { language: lang }).value
        : hljs.highlightAuto(String(children)).value;
    } catch {
      return String(children);
    }
  }, [language, children]);

  return (
    <div style={CODE_STYLES}>
      {language && <span style={LANG_LABEL}>{language}</span>}
      <pre style={{ margin: 0, padding: '8px 10px', overflowX: 'auto' }}>
        <code dangerouslySetInnerHTML={{ __html: highlighted }} />
      </pre>
    </div>
  );
}

function InlineCode({ children }) {
  return (
    <code style={{
      background: '#ffffff10',
      padding: '1px 4px',
      borderRadius: 3,
      fontSize: '0.9em',
      fontFamily: 'JetBrains Mono, monospace',
      color: '#c07af0',
    }}>{children}</code>
  );
}

const MarkdownRenderer = memo(function MarkdownRenderer({ content }) {
  const components = useMemo(() => ({
    code({ node, inline, className, children, ...props }) {
      const match = /language-(\w+)/.exec(className || '');
      const lang = match ? match[1] : '';
      const text = String(children).replace(/\n$/, '');
      if (inline || (!lang && !text.includes('\n'))) {
        return <InlineCode>{children}</InlineCode>;
      }
      return <CodeBlock language={lang}>{text}</CodeBlock>;
    },
    p({ children }) {
      return <p style={{ margin: '0 0 8px 0' }}>{children}</p>;
    },
    ul({ children }) {
      return <ul style={{ margin: '0 0 8px 0', paddingLeft: 18 }}>{children}</ul>;
    },
    ol({ children }) {
      return <ol style={{ margin: '0 0 8px 0', paddingLeft: 18 }}>{children}</ol>;
    },
    li({ children }) {
      return <li style={{ marginBottom: 2 }}>{children}</li>;
    },
    h1({ children }) {
      return <h1 style={{ fontSize: 15, fontWeight: 700, margin: '8px 0 6px', color: PALETTE.text }}>{children}</h1>;
    },
    h2({ children }) {
      return <h2 style={{ fontSize: 14, fontWeight: 700, margin: '8px 0 6px', color: PALETTE.text }}>{children}</h2>;
    },
    h3({ children }) {
      return <h3 style={{ fontSize: 13, fontWeight: 600, margin: '6px 0 4px', color: '#e0e2e6' }}>{children}</h3>;
    },
    a({ href, children }) {
      return <a href={href} target="_blank" rel="noopener noreferrer" style={{ color: '#5b8af5', textDecoration: 'none' }}>{children}</a>;
    },
    blockquote({ children }) {
      return <blockquote style={{ borderLeft: `2px solid #404550`, margin: '6px 0', padding: '2px 10px', color: '#808590' }}>{children}</blockquote>;
    },
    table({ children }) {
      return <div style={{ overflowX: 'auto', margin: '6px 0' }}><table style={{ borderCollapse: 'collapse', fontSize: 11, width: '100%' }}>{children}</table></div>;
    },
    th({ children }) {
      return <th style={{ border: `1px solid ${PALETTE.border}`, padding: '4px 8px', textAlign: 'left', color: '#e0e2e6', fontWeight: 600 }}>{children}</th>;
    },
    td({ children }) {
      return <td style={{ border: `1px solid ${PALETTE.border}`, padding: '4px 8px', color: PALETTE.textDim }}>{children}</td>;
    },
    hr() {
      return <hr style={{ border: 'none', borderTop: '1px solid #1e2029', margin: '8px 0' }} />;
    },
    strong({ children }) {
      return <strong style={{ color: PALETTE.text, fontWeight: 700 }}>{children}</strong>;
    },
  }), []);

  return (
    <div style={{ wordBreak: 'break-word' }}>
      <ReactMarkdown remarkPlugins={[remarkGfm]} components={components}>
        {content}
      </ReactMarkdown>
    </div>
  );
});

export default MarkdownRenderer;
