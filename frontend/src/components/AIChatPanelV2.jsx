import React, { useState, useEffect, useCallback, useRef } from 'react';
import PropTypes from 'prop-types';
import { api } from '../api.js';
import Icon from './Icon.jsx';
import MarkdownRenderer from './MarkdownRenderer.jsx';
import AiMessageActions from './AiMessageActions.jsx';
import { PALETTE, FONTS, Checkbox, Select } from './UI.jsx';

// Compact fits the common "quick question" case; half/full trade fixed width
// for room to actually read long tool output and reasoning once a
// conversation's context grows. Full leaves the 200px project sidebar alone
// (AppContextSidebar.jsx) rather than covering it.
const PANEL_SIZES = {
  compact: { width: '480px', label: 'Expand to half screen' },
  half:    { width: '50vw',  label: 'Expand to full screen' },
  full:    { width: 'calc(100vw - 200px)', label: 'Back to compact' },
};
const NEXT_SIZE = { compact: 'half', half: 'full', full: 'compact' };

function ToolCallBlock({ toolCall }) {
  const [expanded, setExpanded] = useState(false);
  const name = toolCall.name || toolCall.tool_name || 'tool';
  const args = toolCall.args || toolCall.arguments || {};
  const result = toolCall.result || toolCall.result_summary || '';

  const argsStr = typeof args === 'string' ? args : JSON.stringify(args, null, 2);
  const argsPreview = argsStr.length > 60 ? argsStr.slice(0, 60) + '...' : argsStr;

  const riskColor = toolCall.risk === 'critical' ? '#cc2233' : toolCall.risk === 'write' ? '#f09a3a' : PALETTE.ok;

  return (
    <div style={{ background: '#0a0c10', border: `1px solid ${riskColor}33`, borderRadius: 5, marginBottom: 4, fontSize: 11, fontFamily: FONTS.mono, overflow: 'hidden' }}>
      <button
        type="button"
        onClick={() => setExpanded(v => !v)}
        style={{ padding: '5px 10px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 6, color: '#808590', userSelect: 'none', width: '100%', textAlign: 'left', background: 'transparent', border: 'none' }}
      >
        <span style={{ fontSize: 12 }}>{toolCall.risk === 'write' ? '\u26A0' : toolCall.risk === 'critical' ? '\u26D4' : '\u2699'}</span>
        <span style={{ color: '#c07af0', fontWeight: 600 }}>{name}</span>
        <span style={{ color: '#505560' }}>({argsPreview})</span>
        {toolCall.risk && <span style={{ fontSize: 9, color: riskColor, textTransform: 'uppercase', marginLeft: 4 }}>{toolCall.risk}</span>}
        <span style={{ marginLeft: 'auto', fontSize: 10, color: PALETTE.textGhost }}>{expanded ? '\u25B2' : '\u25BC'}</span>
      </button>
      {expanded && (
        <div style={{ borderTop: '1px solid #1e2029', padding: '8px 10px' }}>
          <div style={{ fontSize: 9, color: PALETTE.textGhost, textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 4 }}>Args</div>
          <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all', color: PALETTE.textDim, fontSize: 11, lineHeight: 1.5 }}>{argsStr}</pre>
          {result && (
            <>
              <div style={{ fontSize: 9, color: PALETTE.textGhost, textTransform: 'uppercase', letterSpacing: '0.1em', marginTop: 8, marginBottom: 4 }}>Result</div>
              <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all', color: typeof result === 'string' && result.includes('error') ? '#cc2233' : PALETTE.ok, fontSize: 11, lineHeight: 1.5 }}>{typeof result === 'string' ? result : JSON.stringify(result, null, 2)}</pre>
            </>
          )}
        </div>
      )}
    </div>
  );
}

function ThinkingDots() {
  const [dots, setDots] = useState('');
  useEffect(() => {
    const iv = setInterval(() => setDots(d => d.length >= 3 ? '' : d + '.'), 400);
    return () => clearInterval(iv);
  }, []);
  return <span style={{ color: PALETTE.textFaint, fontStyle: 'italic', fontSize: 12 }}>thinking{dots}</span>;
}

function ConfirmationDialog({ toolName, args, onConfirm, onDeny }) {
  return (
    <div style={{ background: '#f09a3a15', border: '1px solid #f09a3a44', borderRadius: 5, padding: '10px 12px', marginBottom: 8, fontSize: 11, fontFamily: FONTS.mono }}>
      <div style={{ color: PALETTE.warn, fontWeight: 600, marginBottom: 6 }}>
        {'\u26A0'} Confirmation required: {toolName}
      </div>
      <pre style={{ margin: '0 0 8px 0', whiteSpace: 'pre-wrap', wordBreak: 'break-all', color: '#808590', fontSize: 10 }}>{JSON.stringify(args, null, 2)}</pre>
      <div style={{ display: 'flex', gap: 8 }}>
        <button onClick={onConfirm} style={{ background: PALETTE.warn, border: 'none', borderRadius: 4, padding: '5px 12px', cursor: 'pointer', color: '#000', fontSize: 10, fontWeight: 600 }}>Allow</button>
        <button onClick={onDeny} style={{ background: 'transparent', border: `1px solid ${PALETTE.textGhost}`, borderRadius: 4, padding: '5px 12px', cursor: 'pointer', color: '#808590', fontSize: 10 }}>Deny</button>
      </div>
    </div>
  );
}

export default function AIChatPanelV2({ selectedProject, accent }) {
  const [open, setOpen] = useState(false);
  const [size, setSize] = useState('compact');
  const [btnHover, setBtnHover] = useState(false);
  const [chats, setChats] = useState([]);
  const [activeChat, setActiveChat] = useState(null);
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [finished, setFinished] = useState(false);
  const [streamingContent, setStreamingContent] = useState('');
  const [streamingReasoning, setStreamingReasoning] = useState('');
  const [activeSteps, setActiveSteps] = useState([]);
  const [pendingConfirmation, setPendingConfirmation] = useState(null);
  const [agentMode, setAgentMode] = useState(true);
  const [agents, setAgents] = useState([]);
  const [agentId, setAgentId] = useState('field-op');
  const [error, setError] = useState('');
  const messagesEndRef = useRef(null);
  const abortRef = useRef(null);
  const pendingMsgRef = useRef('');

  useEffect(() => {
    if (!selectedProject) return;
    api.getAIChats(selectedProject).then(data => {
      setChats(data.chats || []);
    }).catch(() => {});
  }, [selectedProject]);

  useEffect(() => {
    if (activeChat && selectedProject) {
      api.getAIChat(selectedProject, activeChat).then(data => {
        setMessages(data.messages || []);
      }).catch(() => {});
    } else {
      setMessages([]);
    }
    setStreamingContent('');
    setStreamingReasoning('');
    setActiveSteps([]);
    setPendingConfirmation(null);
  }, [activeChat, selectedProject]);

  const syncSettings = useCallback(() => {
    api.getAISettings().then(data => {
      setAgentMode(data.agent_mode !== false);
    }).catch(() => {});
  }, []);

  useEffect(() => {
    syncSettings();
    const handler = () => syncSettings();
    globalThis.addEventListener('rt:ai_status_changed', handler);
    return () => globalThis.removeEventListener('rt:ai_status_changed', handler);
  }, [syncSettings]);

  useEffect(() => {
    if (open && messagesEndRef.current) {
      messagesEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages, streamingContent, streamingReasoning, activeSteps, open]);

  useEffect(() => {
    if (!open || agents.length) return;
    api.listAIAgents().then(r => setAgents(r.agents || [])).catch(() => {});
  }, [open, agents.length]);

  const createChat = useCallback(async () => {
    try {
      const persona = agents.find(a => a.id === agentId);
      const res = await api.createAIChat(selectedProject, { agent_id: persona ? persona.id : undefined, agent_mode: persona ? persona.agent_mode !== false : agentMode });
      setChats(prev => [res, ...prev]);
      setActiveChat(res.id);
      return res.id;
    } catch (e) {
      setError(e.message || 'Failed to create chat');
      return null;
    }
  }, [selectedProject, agentMode, agentId, agents]);

  const sendMessage = useCallback(async (confirmedTools = []) => {
    const msg = (pendingMsgRef.current || input).trim();
    if (!msg || loading) return;

    let chatId = activeChat;
    if (!chatId) {
      chatId = await createChat();
      if (!chatId) return;
    }

    setInput('');
    pendingMsgRef.current = msg;
    setError('');
    setFinished(false);
    setLoading(true);
    setStreamingContent('');
    setStreamingReasoning('');
    setActiveSteps([]);
    setPendingConfirmation(null);

    const userMsg = { role: 'user', content: msg, seq: (messages.at(-1)?.seq || 0) + 1 };
    setMessages(prev => [...prev, userMsg]);

    const controller = new AbortController();
    abortRef.current = controller;

    try {
      const token = document.cookie.match(/rt_auth=([^;]+)/)?.[1] || '';
      const resp = await fetch(`/api/projects/${selectedProject}/ai/chats/${chatId}/stream`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Cookie': `rt_auth=${token}`,
        },
        body: JSON.stringify({ message: msg, agent_mode: agentMode, confirmed_tools: confirmedTools }),
        signal: controller.signal,
      });

      if (!resp.ok) {
        const errText = await resp.text();
        throw new Error(errText || `HTTP ${resp.status}`);
      }

      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
        let buf = '';
        let contentAccum = '';
        let reasoningAccum = '';
        let stepsAccum = [];

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const lines = buf.split('\n');
        buf = lines.pop() || '';
        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          try {
            const event = JSON.parse(line.slice(6));
            if (event.type === 'reasoning') {
              reasoningAccum += event.text;
              setStreamingReasoning(reasoningAccum);
            } else if (event.type === 'content') {
              contentAccum += event.text;
              setStreamingContent(contentAccum);
            } else if (event.type === 'tool_call') {
              stepsAccum = [...stepsAccum, { type: 'tool_call', name: event.tool_name, args: event.arguments, risk: event.risk }];
              setActiveSteps([...stepsAccum]);
            } else if (event.type === 'tool_result') {
              stepsAccum = [...stepsAccum, { type: 'tool_result', name: event.tool_name, args: event.arguments, result: event.result, risk: event.risk }];
              setActiveSteps([...stepsAccum]);
            } else if (event.type === 'confirmation_needed') {
              setPendingConfirmation({ tool_name: event.tool_name, arguments: event.arguments, risk: event.risk });
              setLoading(false);
              return;
            } else if (event.type === 'done') {
              const assistantMsg = {
                role: 'assistant',
                content: event.content || contentAccum,
                seq: userMsg.seq + 1,
                provider_id: event.provider_id,
                tool_calls_made: event.tool_calls_made,
              };
              setMessages(prev => [...prev, assistantMsg]);
              setStreamingContent('');
              setStreamingReasoning('');
              setActiveSteps([]);
              setFinished(true);
              if (chats.find(c => c.id === chatId)?.title === 'New Chat' && msg) {
                setChats(prev => prev.map(c => c.id === chatId ? { ...c, title: msg.slice(0, 60) } : c));
              }
            } else if (event.type === 'error') {
              setError(event.message || 'Unknown error');
            }
          } catch { /* malformed stream frame — skip it, the stream continues */ }
        }
      }
    } catch (e) {
      if (e.name !== 'AbortError') {
        setError(e.message || 'Request failed');
      }
    } finally {
      setLoading(false);
      abortRef.current = null;
      pendingMsgRef.current = '';
    }
  }, [input, loading, activeChat, messages, selectedProject, agentMode, chats, createChat]);

  const handleConfirm = useCallback(() => {
    if (!pendingConfirmation) return;
    const tc = pendingConfirmation;
    setPendingConfirmation(null);
    sendMessage([{ name: tc.tool_name, arguments: tc.arguments }]);
  }, [pendingConfirmation, sendMessage]);

  const handleDeny = useCallback(() => {
    setPendingConfirmation(null);
    setLoading(false);
    setMessages(prev => [...prev, { role: 'assistant', content: 'Tool call denied by user.', seq: (prev.at(-1)?.seq || 0) + 1 }]);
  }, []);

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  const deleteChat = async (cid) => {
    try {
      await api.deleteAIChat(selectedProject, cid);
      setChats(prev => prev.filter(c => c.id !== cid));
      if (activeChat === cid) {
        setActiveChat(null);
        setMessages([]);
      }
    } catch (e) {
      setError(e.message);
    }
  };

  const stopGeneration = () => {
    if (abortRef.current) {
      abortRef.current.abort();
      setLoading(false);
    }
  };

  const inp = { width: '100%', background: '#0a0c10', border: `1px solid ${PALETTE.border}`, borderRadius: 5, padding: '8px 10px', color: PALETTE.textDim, fontSize: 12, outline: 'none', fontFamily: FONTS.mono, boxSizing: 'border-box', resize: 'none' };

  return (
    <>
      <button
        onClick={() => setOpen(v => !v)}
        onMouseEnter={() => setBtnHover(true)}
        onMouseLeave={() => setBtnHover(false)}
        style={{
          position: 'fixed', bottom: 20, right: 20, zIndex: 999,
          width: 40, height: 40, borderRadius: '50%',
          background: open ? '#1a1c22' : accent, border: open ? `2px solid ${accent}` : 'none',
          cursor: 'pointer', color: open ? accent : '#fff',
          fontSize: 11, fontWeight: 700, fontFamily: FONTS.display,
          boxShadow: '0 3px 12px rgba(0,0,0,0.5)',
          transition: 'opacity .2s, transform .2s',
          opacity: open || btnHover ? 1 : 0.35,
          transform: btnHover && !open ? 'scale(1.1)' : 'scale(1)',
        }}
        title={open ? 'Close AI' : 'Open AI Agent'}
      >
        AI
      </button>

      {open && (
        <div style={{
          // top: 78 clears the app's own sticky top bar (main row + group-tabs
          // row, same offset TweaksPanel uses below it in App.jsx) — at top: 0
          // this fixed-position panel (zIndex 1000) sat on top of that sticky
          // bar (zIndex 50) regardless of size, most visibly in 'full' where
          // the panel's left edge lands mid-screen and clips tab labels
          // (e.g. "Exploit") right through the middle of the text instead of
          // covering or avoiding them cleanly.
          position: 'fixed', top: 78, right: 0, bottom: 0,
          width: `min(${PANEL_SIZES[size].width}, 100vw)`, minWidth: 'min(480px, 100vw)', zIndex: 1000,
          background: PALETTE.bg2, borderLeft: '1px solid #1e2029',
          display: 'flex', flexDirection: 'row',
          boxShadow: '-8px 0 40px rgba(0,0,0,0.6)',
          fontFamily: FONTS.mono,
          transition: 'width .15s ease',
        }}>
          {/* Chat list sidebar */}
          <div style={{ width: 140, borderRight: '1px solid #1e2029', display: 'flex', flexDirection: 'column', flexShrink: 0 }}>
            <div style={{ padding: '10px 8px', borderBottom: '1px solid #1e2029' }}>
              <button
                onClick={createChat}
                style={{ width: '100%', background: accent + '22', border: `1px solid ${accent}44`, borderRadius: 4, padding: '6px', cursor: 'pointer', color: accent, fontSize: 10, fontWeight: 600 }}
              >
                + New Chat
              </button>
            </div>
            <div style={{ flex: 1, overflowY: 'auto' }}>
              {chats.length === 0 && (
                <div style={{ padding: '10px 8px', fontSize: 9, color: PALETTE.textGhost }}>No chats yet</div>
              )}
              {chats.map(c => (
                <div
                  key={c.id}
                  onClick={() => setActiveChat(c.id)}
                  style={{
                    padding: '8px 10px', cursor: 'pointer', fontSize: 10, lineHeight: 1.3,
                    color: activeChat === c.id ? '#c8cdd6' : '#505560',
                    background: activeChat === c.id ? '#ffffff08' : 'transparent',
                    borderLeft: activeChat === c.id ? `2px solid ${accent}` : '2px solid transparent',
                    display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 4,
                  }}
                  title={c.title}
                >
                  <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>{c.title || 'Untitled'}</span>
                  <button
                    onClick={(e) => { e.stopPropagation(); deleteChat(c.id); }}
                    style={{ background: 'transparent', border: 'none', color: PALETTE.textGhost, cursor: 'pointer', fontSize: 10, padding: 0, flexShrink: 0 }}
                    title="Delete chat"
                  >
                    {'\u2715'}
                  </button>
                </div>
              ))}
            </div>
          </div>

          {/* Main chat area */}
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0 }}>
            {/* Header */}
            <div style={{ padding: '14px 16px', borderBottom: '1px solid #1e2029', display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 14, fontWeight: 700, color: PALETTE.text, fontFamily: FONTS.display }}>AI Agent</div>
                {(agents.find(a => a.id === agentId) || {}).description && (
                  <div title={agents.find(a => a.id === agentId).description}
                    style={{ fontSize: 9, color: PALETTE.textGhost, marginTop: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {agents.find(a => a.id === agentId).description}
                  </div>
                )}
                <div title={activeChat ? (chats.find(c => c.id === activeChat)?.title || 'Chat') : undefined}
                  style={{ fontSize: 10, color: '#505560', marginTop: 2, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {activeChat ? (chats.find(c => c.id === activeChat)?.title || 'Chat') : 'Select or create a chat'}
                </div>
              </div>
              <Select
                value={agentId}
                onChange={setAgentId}
                title={(agents.find(a => a.id === agentId) || {}).description || 'AI agent persona'}
                style={{ width: 96, flexShrink: 0 }}
                options={(agents.length ? agents : [{ id: 'field-op', name: 'Field Operator' }]).map(a => ({ value: a.id, label: a.name }))}
              />
              <Checkbox checked={agentMode} onChange={setAgentMode} accent={accent} label="Agent" style={{ flexShrink: 0 }} />
              <button onClick={() => setSize(s => NEXT_SIZE[s])} style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: PALETTE.textFaint, display: 'flex', padding: '2px 4px', flexShrink: 0 }} title={PANEL_SIZES[size].label}>
                <Icon name={size === 'full' ? 'collapse' : 'expand'} size={13} color="currentColor" />
              </button>
              <button onClick={() => setOpen(false)} style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: PALETTE.textFaint, fontSize: 16, lineHeight: 1, padding: '2px 4px', flexShrink: 0 }} title="Close">{'\u2715'}</button>
            </div>

            {/* Messages */}
            <div style={{ flex: 1, overflowY: 'auto', padding: '12px 16px', display: 'flex', flexDirection: 'column', gap: 10 }}>
              {messages.length === 0 && !streamingContent && !loading && (
                <div style={{ color: PALETTE.textGhost, fontSize: 12, textAlign: 'center', marginTop: 40 }}>
                  {activeChat ? 'Continue the conversation...' : 'Create a new chat to start.'}<br />
                  <span style={{ fontSize: 10, color: '#303540' }}>I can read hosts, creds, findings, notes and run tools.</span>
                </div>
              )}
              {messages.map((msg) => (
                <div key={`${msg.role}-${msg.seq}`} style={{ display: 'flex', flexDirection: 'column', alignItems: msg.role === 'user' ? 'flex-end' : 'flex-start' }}>
                  {msg.content && (
                    <div style={{
                      maxWidth: 'min(85%, 780px)',
                      background: msg.role === 'user' ? accent + '22' : '#0a0c10',
                      border: `1px solid ${msg.role === 'user' ? accent + '55' : '#1e2029'}`,
                      borderRadius: msg.role === 'user' ? '12px 12px 2px 12px' : '12px 12px 12px 2px',
                      padding: '9px 12px',
                      color: PALETTE.textDim,
                      fontSize: 12,
                      lineHeight: 1.6,
                      wordBreak: 'break-word',
                    }}>
                      {msg.role === 'assistant'
                        ? <MarkdownRenderer content={msg.content} />
                        : msg.content}
                    </div>
                  )}
                  {msg.role === 'assistant' && !loading && msg.content && selectedProject && (
                    <AiMessageActions pid={selectedProject} accent={accent} content={msg.content} />
                  )}
                  {msg.role === 'assistant' && msg.provider_id && (
                    <div style={{ fontSize: 9, color: PALETTE.textGhost, marginTop: 3 }}>Provider: {msg.provider_id}</div>
                  )}
                </div>
              ))}

              {/* Streaming reasoning (thinking model) */}
              {streamingReasoning && (
                <div style={{ width: '100%', marginBottom: 4 }}>
                  <details open style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: 5, padding: '6px 10px' }}>
                    <summary style={{ cursor: 'pointer', fontSize: 10, color: '#808590', fontWeight: 600, userSelect: 'none' }}>
                      {'\u{1F4AD}'} Reasoning<span style={{ color: PALETTE.textGhost, fontWeight: 400 }}> ({streamingReasoning.length} chars)</span>
                    </summary>
                    <div style={{ margin: '6px 0 0 0', color: PALETTE.textFaint, fontSize: 10, lineHeight: 1.5, maxHeight: 300, overflowY: 'auto' }}>
                      <MarkdownRenderer content={streamingReasoning} />
                    </div>
                  </details>
                </div>
              )}

              {/* Active steps (tool calls in progress) */}
              {activeSteps.map((step, i) => (
                <div key={`step-${i}`} style={{ width: '100%' }}>
                  <ToolCallBlock toolCall={{
                    name: step.name,
                    arguments: step.args,
                    result: step.result,
                    risk: step.risk,
                  }} />
                </div>
              ))}

              {/* Pending confirmation */}
              {pendingConfirmation && (
                <ConfirmationDialog
                  toolName={pendingConfirmation.tool_name}
                  args={pendingConfirmation.arguments}
                  onConfirm={handleConfirm}
                  onDeny={handleDeny}
                />
              )}

              {/* Streaming content */}
              {streamingContent && (
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start' }}>
                  <div style={{
                    maxWidth: 'min(85%, 780px)', background: '#0a0c10', border: '1px solid #1e2029',
                    borderRadius: '12px 12px 12px 2px', padding: '9px 12px',
                    color: PALETTE.textDim, fontSize: 12, lineHeight: 1.6,
                    wordBreak: 'break-word',
                  }}>
                    <MarkdownRenderer content={streamingContent} />
                    <span style={{ opacity: 0.5 }}>|</span>
                  </div>
                </div>
              )}

              {loading && !streamingContent && !streamingReasoning && !pendingConfirmation && (
                <div style={{ display: 'flex', alignItems: 'flex-start' }}>
                  <div style={{ background: '#0a0c10', border: '1px solid #1e2029', borderRadius: '12px 12px 12px 2px', padding: '9px 12px' }}>
                    <ThinkingDots />
                  </div>
                </div>
              )}
              {error && (
                <div style={{ background: '#cc233318', border: '1px solid #cc233344', borderRadius: 5, padding: '8px 12px', fontSize: 11, color: PALETTE.danger }}>
                  {error}
                </div>
              )}
              <div ref={messagesEndRef} />
            </div>

            {/* Input area */}
            <div style={{ padding: '12px 16px', borderTop: '1px solid #1e2029', flexShrink: 0 }}>
              {(loading || finished || pendingConfirmation) && (() => {
                let text, color;
                if (pendingConfirmation) {
                  text = `Waiting for your confirmation: ${pendingConfirmation.tool_name}`;
                  color = PALETTE.warn;
                } else if (loading) {
                  const lastStep = activeSteps[activeSteps.length - 1];
                  if (streamingReasoning && !streamingContent) text = 'Thinking…';
                  else if (streamingContent) text = 'Writing the answer…';
                  else if (lastStep && lastStep.type === 'tool_call') text = `Running tool: ${lastStep.name}…`;
                  else text = 'Working…';
                  color = PALETTE.textMute;
                } else {
                  text = 'Finished';
                  color = PALETTE.ok;
                }
                return (
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 10, fontFamily: FONTS.mono, color, padding: '0 2px 6px' }}>
                    <span>{pendingConfirmation ? '⏸' : loading ? '⏳' : '✓'}</span>
                    <span>{text}</span>
                  </div>
                );
              })()}
              <div style={{ display: 'flex', gap: 8, alignItems: 'flex-end' }}>
                <textarea
                  value={input}
                  onChange={e => setInput(e.target.value)}
                  onKeyDown={handleKeyDown}
                  placeholder={activeChat ? 'Ask AI...' : 'Create a chat first...'}
                  rows={3}
                  style={{ ...inp, lineHeight: 1.5 }}
                  disabled={loading}
                />
                {loading ? (
                  <button onClick={stopGeneration} style={{ background: PALETTE.danger, border: 'none', borderRadius: 5, padding: '8px 14px', cursor: 'pointer', color: '#fff', fontSize: 11, fontWeight: 600, flexShrink: 0, height: 36, alignSelf: 'flex-end' }}>
                    Stop
                  </button>
                ) : (
                  <button
                    onClick={() => sendMessage()}
                    disabled={!input.trim()}
                    style={{
                      background: input.trim() ? accent : PALETTE.borderSoft, border: 'none', borderRadius: 5,
                      padding: '8px 14px', cursor: input.trim() ? 'pointer' : 'not-allowed',
                      color: '#fff', fontSize: 11, fontWeight: 600, fontFamily: FONTS.mono,
                      flexShrink: 0, alignSelf: 'flex-end', height: 36,
                    }}
                  >
                    Send
                  </button>
                )}
              </div>
              <div style={{ fontSize: 9, color: '#303540', marginTop: 6 }}>Enter to send | Shift+Enter for newline {agentMode ? '| Agent mode: tools enabled' : '| Chat only'}</div>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

ToolCallBlock.propTypes = { toolCall: PropTypes.object };
ConfirmationDialog.propTypes = { toolName: PropTypes.string, args: PropTypes.object, onConfirm: PropTypes.func, onDeny: PropTypes.func };
AIChatPanelV2.propTypes = { selectedProject: PropTypes.any, accent: PropTypes.string };
