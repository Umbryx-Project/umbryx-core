import { useEffect, useState, useCallback } from 'react';
import PropTypes from 'prop-types';
import Icon from '../Icon.jsx';
import { api } from '../../api.js';
import { Card, Overline, Checkbox, PALETTE, TYPE, FONTS, Select } from '../UI.jsx';
import { PROVIDER_DEFAULT_MODELS, PROVIDER_BASE_URLS, inp } from '../../utils/admin.js';
import { uiAlert } from '../Confirm.jsx';

const PROVIDER_TYPES = ['anthropic', 'openai', 'ollama', 'groq', 'mistral', 'openrouter', 'litellm'];

export default function AISection({ accent }) {
  const [settings, setSettings] = useState({ ai_enabled: true, agent_mode: true, max_tool_calls: 10, require_confirmation_writes: true, block_critical_tools: true });
  const [providers, setProviders] = useState([]);
  const [loading, setLoading] = useState(true);
  const [savingSettings, setSavingSettings] = useState(false);
  const [settingsMsg, setSettingsMsg] = useState('');
  const [providerTypes, setProviderTypes] = useState([]);

  const [showAdd, setShowAdd] = useState(false);
  const [newName, setNewName] = useState('');
  const [newProvider, setNewProvider] = useState('anthropic');
  const [newApiKey, setNewApiKey] = useState('');
  const [newModel, setNewModel] = useState(PROVIDER_DEFAULT_MODELS.anthropic);
  const [newBaseUrl, setNewBaseUrl] = useState('');
  const [newPriority, setNewPriority] = useState(1);
  const [newSystemPrompt, setNewSystemPrompt] = useState('');
  const [newModels, setNewModels] = useState([]);
  const [fetchingModels, setFetchingModels] = useState(false);
  const [addError, setAddError] = useState('');

  const [editIdx, setEditIdx] = useState(-1);
  const [editName, setEditName] = useState('');
  const [editProvider, setEditProvider] = useState('');
  const [editApiKey, setEditApiKey] = useState('');
  const [editModel, setEditModel] = useState('');
  const [editBaseUrl, setEditBaseUrl] = useState('');
  const [editPriority, setEditPriority] = useState(1);
  const [editSkipTools, setEditSkipTools] = useState(false);
  const [editAnonymize, setEditAnonymize] = useState(true);
  const [editSkipSysPrompt, setEditSkipSysPrompt] = useState(false);
  const [editSystemPrompt, setEditSystemPrompt] = useState('');
  const [editModels, setEditModels] = useState([]);
  const [editFetching, setEditFetching] = useState(false);
  const [editFetchError, setEditFetchError] = useState('');
  const [addFetchError, setAddFetchError] = useState('');

  const loadAll = useCallback(async () => {
    try {
      const [settingsData, providersData, typesData] = await Promise.all([
        api.getAISettings().catch(() => ({})),
        api.getAIProviders().catch(() => ({ providers: [] })),
        api.getAIProviderTypes().catch(() => []),
      ]);
      setSettings(prev => ({
        ai_enabled: settingsData.ai_enabled !== false,
        agent_mode: settingsData.agent_mode !== false,
        max_tool_calls: settingsData.max_tool_calls || 10,
        require_confirmation_writes: settingsData.require_confirmation_writes !== false,
        block_critical_tools: settingsData.block_critical_tools !== false,
      }));
      setProviders(providersData.providers || []);
      setProviderTypes(typesData || []);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadAll(); }, [loadAll]);

  const saveSettings = async () => {
    setSavingSettings(true); setSettingsMsg('');
    try {
      await api.saveAISettings(settings);
      globalThis.dispatchEvent(new Event('rt:ai_status_changed'));
      setSettingsMsg('Saved.');
    } catch (e) { setSettingsMsg(e.message || 'Save failed'); }
    finally { setSavingSettings(false); }
  };

  const handleProviderChange = (val) => {
    setNewProvider(val);
    setNewModel(PROVIDER_DEFAULT_MODELS[val] || '');
    setNewBaseUrl(PROVIDER_BASE_URLS[val] || '');
    setNewModels([]);
    setAddFetchError('');
  };

  const fetchModels = async (providerType, baseUrl, apiKey, setModels, setFetching, setFetchError) => {
    setFetching(true);
    setFetchError('');
    try {
      const data = await api.fetchAIProviderModels({ provider: providerType, base_url: baseUrl, api_key: apiKey });
      setModels(data.models || []);
      if (!data.models?.length && data.error) setFetchError(data.error);
    } catch (e) {
      setModels([]);
      setFetchError(e.message || 'Failed to fetch models');
    } finally {
      setFetching(false);
    }
  };

  // Editing an already-saved provider: GET /ai/providers/{id}/api_key comes
  // back masked ("****abcd") — never the real value — so the generic
  // fetch-models call (which needs a real key in the request body) always
  // silently returned zero models here unless the operator retyped the key
  // from scratch. Use the provider's own /models endpoint instead, which
  // resolves the real (server-side decrypted) stored key — unless the
  // operator is actively testing a new key or base URL they haven't saved
  // yet, in which case those unsaved values have to be sent explicitly.
  const fetchEditModels = async (p) => {
    setEditFetching(true);
    setEditFetchError('');
    try {
      const testingUnsaved = !!editApiKey || editBaseUrl !== (p.base_url || '') || editProvider !== p.provider;
      const data = testingUnsaved
        ? await api.fetchAIProviderModels({ provider: editProvider, base_url: editBaseUrl, api_key: editApiKey })
        : await api.getAIProviderModels(p.id);
      setEditModels(data.models || []);
      if (!data.models?.length && data.error) setEditFetchError(data.error);
    } catch (e) {
      setEditModels([]);
      setEditFetchError(e.message || 'Failed to fetch models');
    } finally {
      setEditFetching(false);
    }
  };

  const addProvider = async () => {
    if (!newName.trim()) return;
    setAddError('');
    try {
      const result = await api.addAIProvider({
        id: newName.trim().toLowerCase().replace(/\s+/g, '-'),
        name: newName.trim(),
        provider: newProvider,
        api_key: newApiKey,
        model: newModel,
        base_url: newBaseUrl,
        priority: Number.parseInt(newPriority) || 1,
        enabled: true,
        system_prompt: newSystemPrompt,
      });
      setProviders(prev => [...prev, result]);
      setNewName(''); setNewApiKey(''); setNewBaseUrl(''); setNewPriority(1); setNewSystemPrompt(''); setNewModels([]);
      setShowAdd(false);
    } catch (e) {
      setAddError(e.message || 'Failed to add provider');
    }
  };

  const removeProvider = async (pid) => {
    try {
      await api.removeAIProvider(pid);
      setProviders(prev => prev.filter(p => p.id !== pid));
    } catch (e) { /* ignore */ }
  };

  const toggleProvider = async (pid) => {
    const p = providers.find(x => x.id === pid);
    if (!p) return;
    try {
      await api.updateAIProvider(pid, { enabled: !p.enabled });
      setProviders(prev => prev.map(x => x.id === pid ? { ...x, enabled: !x.enabled } : x));
    } catch (e) { /* ignore */ }
  };

  const startEdit = (idx) => {
    const p = providers[idx];
    setEditIdx(idx);
    setEditName(p.name || '');
    setEditProvider(p.provider || 'openai');
    setEditApiKey('');
    setEditModel(p.model || '');
    setEditBaseUrl(p.base_url || '');
    setEditPriority(p.priority || 1);
    setEditSkipTools(!!p.skip_tools);
    setEditAnonymize(p.anonymize !== false);
    setEditSkipSysPrompt(!!p.skip_system_prompt);
    setEditSystemPrompt(p.system_prompt || '');
    setEditModels([]);
    setEditFetchError('');
  };

  const commitEdit = async () => {
    const p = providers[editIdx];
    if (!p) return;
    const updates = {
      name: editName.trim() || p.name,
      provider: editProvider,
      model: editModel,
      base_url: editBaseUrl,
      priority: Number.parseInt(editPriority) || 1,
      skip_tools: editSkipTools,
      anonymize: editAnonymize,
      skip_system_prompt: editSkipSysPrompt,
      system_prompt: editSystemPrompt,
    };
    if (editApiKey) updates.api_key = editApiKey;
    try {
      const result = await api.updateAIProvider(p.id, updates);
      setProviders(prev => prev.map((x, i) => i === editIdx ? result : x));
      setEditIdx(-1);
    } catch (e) { /* ignore */ }
  };

  const testConnection = async (pid) => {
    try {
      const result = await api.testAIProvider(pid);
      await uiAlert(result.ok ? `Connected: ${result.message}` : `Failed: ${result.message}`, { title: 'AI Provider', danger: !result.ok });
    } catch (e) { await uiAlert(`Error: ${e.message}`, { title: 'AI Provider', danger: true }); }
  };

  const modelDropdown = (value, onChange, models, fetching) => {
    if (models && models.length > 0) {
      return (
        <Select value={value} onChange={onChange} placeholder="— Select model —"
          options={models.map(m => ({ value: m.id, label: m.name || m.id }))} />
      );
    }
    return (
      <div style={{ display: 'flex', gap: 4 }}>
        <input value={value} onChange={e => onChange(e.target.value)} placeholder="model name" style={{ ...inp(), flex: 1 }} />
        <span style={{ fontSize: TYPE.overline, color: fetching ? accent : PALETTE.textGhost, alignSelf: 'center' }}>{fetching ? '...' : ''}</span>
      </div>
    );
  };

  const outlineBtn = { background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '3px 8px', cursor: 'pointer', color: PALETTE.textFaint, fontSize: TYPE.button, fontFamily: FONTS.mono };

  return (
    <div>
      <div style={{ fontSize: 16, color: PALETTE.text, fontWeight: 700, marginBottom: 4, fontFamily: FONTS.display }}>AI Configuration</div>
      <div style={{ fontSize: TYPE.body, color: PALETTE.textFaint, marginBottom: 20, fontFamily: FONTS.mono }}>Configure LLM providers, system prompts, and agent settings.</div>

      {!loading && (
        <Card style={{ marginBottom: 14, borderColor: settings.ai_enabled ? PALETTE.borderSoft : '#3a1010', background: settings.ai_enabled ? PALETTE.bg2 : '#130808' }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: 12, cursor: 'pointer' }}>
            <Checkbox checked={!!settings.ai_enabled} onChange={v => setSettings(prev => ({ ...prev, ai_enabled: v }))} accent={settings.ai_enabled ? PALETTE.ok : PALETTE.danger} />
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: TYPE.sectionTitle, color: PALETTE.text, fontWeight: 600 }}>Enable AI features</div>
              <div style={{ fontSize: TYPE.button, color: PALETTE.textFaint, marginTop: 3, fontFamily: FONTS.mono, lineHeight: 1.55 }}>When disabled, the AI chat panel is hidden and all AI endpoints return 503.</div>
            </div>
            <Overline color={settings.ai_enabled ? PALETTE.ok : PALETTE.danger}
              style={{ background: settings.ai_enabled ? `${PALETTE.ok}18` : `${PALETTE.danger}18`, border: `1px solid ${settings.ai_enabled ? PALETTE.ok : PALETTE.danger}44`, borderRadius: 3, padding: '3px 8px' }}>
              {settings.ai_enabled ? 'Enabled' : 'Disabled'}
            </Overline>
          </label>
        </Card>
      )}

      {loading && <div style={{ color: PALETTE.textGhost, fontSize: TYPE.body, fontFamily: FONTS.mono }}>Loading...</div>}

      {!loading && (
        <Card style={{ marginBottom: 14 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
            <div style={{ fontSize: TYPE.sectionTitle, color: PALETTE.text, fontWeight: 600, flex: 1, fontFamily: FONTS.display }}>Providers</div>
            <button onClick={() => setShowAdd(v => !v)} style={{ background: 'transparent', border: `1px solid ${accent}44`, borderRadius: 4, padding: '4px 10px', cursor: 'pointer', color: accent, fontSize: TYPE.body, fontFamily: FONTS.mono }}>{showAdd ? 'Cancel' : '+ Add provider'}</button>
          </div>

          {showAdd && (
            <div style={{ background: PALETTE.bg1, border: `1px solid ${PALETTE.border}`, borderRadius: 6, padding: 14, marginBottom: 12 }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginBottom: 10 }}>
                <div>
                  <Overline style={{ marginBottom: 5 }}>Name</Overline>
                  <input value={newName} onChange={e => setNewName(e.target.value)} placeholder="e.g. my-claude" style={inp()} />
                </div>
                <div>
                  <Overline style={{ marginBottom: 5 }}>Provider type</Overline>
                  <Select value={newProvider} onChange={handleProviderChange}
                    options={(providerTypes.length > 0 ? providerTypes : PROVIDER_TYPES.map(t => ({ type: t, display_name: t }))).map(t => ({ value: t.type, label: t.display_name || t.type }))} />
                </div>
                <div>
                  <Overline style={{ marginBottom: 5 }}>API Key</Overline>
                  <input type="password" value={newApiKey} onChange={e => setNewApiKey(e.target.value)} placeholder="sk-..." style={inp()} />
                </div>
                <div>
                  <Overline style={{ marginBottom: 5 }}>Base URL</Overline>
                  <input value={newBaseUrl} onChange={e => { setNewBaseUrl(e.target.value); setNewModels([]); }} placeholder={PROVIDER_BASE_URLS[newProvider] || 'http://...'} style={inp()} />
                </div>
                <div style={{ gridColumn: '1 / 2' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 5 }}>
                    <Overline>Model</Overline>
                    <button onClick={() => fetchModels(newProvider, newBaseUrl, newApiKey, setNewModels, setFetchingModels, setAddFetchError)} disabled={fetchingModels} style={{ background: 'transparent', border: 'none', color: fetchingModels ? PALETTE.textFaint : accent, cursor: fetchingModels ? 'wait' : 'pointer', fontSize: TYPE.overline, padding: 0 }}>
                      {fetchingModels ? 'Fetching...' : '↻ Fetch models'}
                    </button>
                  </div>
                  {modelDropdown(newModel, setNewModel, newModels, fetchingModels)}
                  {addFetchError && <div style={{ fontSize: TYPE.overline, color: PALETTE.danger, marginTop: 4, fontFamily: FONTS.mono }}>{addFetchError}</div>}
                </div>
                <div>
                  <Overline style={{ marginBottom: 5 }}>Priority</Overline>
                  <input type="number" value={newPriority} onChange={e => setNewPriority(e.target.value)} min={1} style={inp()} />
                </div>
              </div>
              <div style={{ marginBottom: 10 }}>
                <Overline style={{ marginBottom: 5 }}>System Prompt (optional — overrides default)</Overline>
                <textarea value={newSystemPrompt} onChange={e => setNewSystemPrompt(e.target.value)} placeholder="Leave empty to use the built-in security assistant prompt. Project stats (hosts, findings) are appended automatically." style={{ ...inp(), minHeight: 60, resize: 'vertical' }} />
              </div>
              {addError && <div style={{ fontSize: TYPE.body, color: PALETTE.danger, marginBottom: 8, fontFamily: FONTS.mono }}>{addError}</div>}
              <button onClick={addProvider} disabled={!newName.trim()} style={{ background: newName.trim() ? accent : PALETTE.borderSoft, border: 'none', borderRadius: 4, padding: '6px 16px', cursor: 'pointer', color: '#fff', fontSize: TYPE.body, fontWeight: 600, fontFamily: FONTS.mono }}>Add</button>
            </div>
          )}

          {providers.length === 0 && !showAdd && (
            <div style={{ color: PALETTE.textGhost, fontSize: TYPE.body, fontFamily: FONTS.mono, textAlign: 'center', padding: '20px 0' }}>No providers configured</div>
          )}

          {providers.map((p, i) => (
            <div key={p.id || i} style={{ padding: '9px 0', borderBottom: i < providers.length - 1 ? `1px solid ${PALETTE.borderSoft}` : 'none' }}>
              {editIdx === i ? (
                <div style={{ background: PALETTE.bg1, border: `1px solid ${PALETTE.border}`, borderRadius: 6, padding: 14 }}>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginBottom: 10 }}>
                    <div>
                      <Overline style={{ marginBottom: 5 }}>Name</Overline>
                      <input value={editName} onChange={e => setEditName(e.target.value)} style={inp()} />
                    </div>
                    <div>
                      <Overline style={{ marginBottom: 5 }}>Provider type</Overline>
                      <Select value={editProvider} onChange={v => { setEditProvider(v); setEditModel(PROVIDER_DEFAULT_MODELS[v] || editModel); setEditModels([]); setEditFetchError(''); }}
                        options={(providerTypes.length > 0 ? providerTypes : PROVIDER_TYPES.map(t => ({ type: t, display_name: t }))).map(t => ({ value: t.type, label: t.display_name || t.type }))} />
                    </div>
                    <div>
                      <Overline style={{ marginBottom: 5 }}>API Key {p.api_key && p.api_key.startsWith('****') && <span style={{ textTransform: 'none', letterSpacing: 0 }}>({p.api_key})</span>}</Overline>
                      <input type="password" value={editApiKey} onChange={e => setEditApiKey(e.target.value)} placeholder="(unchanged)" style={inp()} />
                    </div>
                    <div>
                      <Overline style={{ marginBottom: 5 }}>Base URL</Overline>
                      <input value={editBaseUrl} onChange={e => { setEditBaseUrl(e.target.value); setEditModels([]); setEditFetchError(''); }} style={inp()} />
                    </div>
                    <div style={{ gridColumn: '1 / 2' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 5 }}>
                        <Overline>Model</Overline>
                        <button onClick={() => fetchEditModels(p)} disabled={editFetching} style={{ background: 'transparent', border: 'none', color: editFetching ? PALETTE.textFaint : accent, cursor: editFetching ? 'wait' : 'pointer', fontSize: TYPE.overline, padding: 0 }}>
                          {editFetching ? 'Fetching...' : '↻ Fetch models'}
                        </button>
                      </div>
                      {modelDropdown(editModel, setEditModel, editModels, editFetching)}
                      {editFetchError && <div style={{ fontSize: TYPE.overline, color: PALETTE.danger, marginTop: 4, fontFamily: FONTS.mono }}>{editFetchError}</div>}
                    </div>
                    <div>
                      <Overline style={{ marginBottom: 5 }}>Priority</Overline>
                      <input type="number" value={editPriority} onChange={e => setEditPriority(e.target.value)} min={1} style={inp()} />
                    </div>
                  </div>
                  <div style={{ marginBottom: 10 }}>
                    <Overline style={{ marginBottom: 5 }}>System Prompt</Overline>
                    <textarea value={editSystemPrompt} onChange={e => setEditSystemPrompt(e.target.value)} placeholder="Leave empty for default security assistant prompt. Project stats are appended automatically." style={{ ...inp(), minHeight: 60, resize: 'vertical' }} />
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginBottom: 12 }}>
                    <Checkbox checked={editSkipTools} onChange={setEditSkipTools} accent={accent} label="Skip tools (thinking / reasoning models)" />
                    <Checkbox checked={editAnonymize} onChange={setEditAnonymize} accent={accent} label="Anonymize outgoing data (IPs, hostnames, emails → tokens; on by default)" />
                    <Checkbox checked={editSkipSysPrompt} onChange={setEditSkipSysPrompt} accent={accent} label="Disable system prompt (raw chat — no pre-prompting)" />
                  </div>
                  <div style={{ display: 'flex', gap: 8 }}>
                    <button onClick={commitEdit} style={{ background: accent, border: 'none', borderRadius: 4, padding: '5px 14px', cursor: 'pointer', color: '#fff', fontSize: TYPE.body, fontFamily: FONTS.mono, fontWeight: 600 }}>Save</button>
                    <button onClick={() => setEditIdx(-1)} style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '5px 14px', cursor: 'pointer', color: PALETTE.textFaint, fontSize: TYPE.body, fontFamily: FONTS.mono }}>Cancel</button>
                  </div>
                </div>
              ) : (
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: 12, color: PALETTE.text, fontFamily: FONTS.mono, fontWeight: 600 }}>{p.name}</div>
                    <div style={{ fontSize: TYPE.button, color: PALETTE.textFaint, fontFamily: FONTS.mono }}>
                      {p.provider} {'·'} {p.model || '(no model)'} {'·'} priority {p.priority}
                      {p.base_url && ` · ${p.base_url}`}
                      {p.skip_tools && <span style={{ marginLeft: 6, color: PALETTE.warn }}>{'·'} no-tools</span>}
                      {p.skip_system_prompt && <span style={{ marginLeft: 6, color: PALETTE.warn }}>{'·'} no-sys-prompt</span>}
                      {p.system_prompt && <span style={{ marginLeft: 6, color: '#5090c0' }}>{'·'} custom prompt</span>}
                    </div>
                  </div>
                  <button onClick={() => testConnection(p.id)} style={outlineBtn}
                    onMouseEnter={e => { e.currentTarget.style.borderColor = PALETTE.ok; e.currentTarget.style.color = PALETTE.ok; }}
                    onMouseLeave={e => { e.currentTarget.style.borderColor = PALETTE.border; e.currentTarget.style.color = PALETTE.textFaint; }}>Test</button>
                  <button onClick={() => startEdit(i)} style={outlineBtn}
                    onMouseEnter={e => { e.currentTarget.style.borderColor = accent; e.currentTarget.style.color = accent; }}
                    onMouseLeave={e => { e.currentTarget.style.borderColor = PALETTE.border; e.currentTarget.style.color = PALETTE.textFaint; }}>Edit</button>
                  <button onClick={() => toggleProvider(p.id)} style={{ background: p.enabled ? accent + '22' : 'transparent', border: `1px solid ${p.enabled ? accent + '66' : PALETTE.border}`, borderRadius: 4, padding: '3px 10px', cursor: 'pointer', color: p.enabled ? accent : PALETTE.textFaint, fontSize: TYPE.button, fontFamily: FONTS.mono, fontWeight: 700 }}>{p.enabled ? 'Enabled' : 'Disabled'}</button>
                  <button onClick={() => removeProvider(p.id)} style={{ background: 'transparent', border: `1px solid ${PALETTE.border}`, borderRadius: 4, padding: '3px 6px', cursor: 'pointer', color: PALETTE.textGhost, display: 'flex', transition: 'all .1s' }}
                    onMouseEnter={e => { e.currentTarget.style.borderColor = PALETTE.danger; e.currentTarget.style.color = PALETTE.danger; }}
                    onMouseLeave={e => { e.currentTarget.style.borderColor = PALETTE.border; e.currentTarget.style.color = PALETTE.textGhost; }}>
                    <Icon name="trash" size={10} color="currentColor" />
                  </button>
                </div>
              )}
            </div>
          ))}
        </Card>
      )}

      {!loading && (
        <Card style={{ marginBottom: 14 }}>
          <div style={{ fontSize: TYPE.sectionTitle, color: PALETTE.text, fontWeight: 600, marginBottom: 12, fontFamily: FONTS.display }}>Agent settings</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <Checkbox checked={settings.agent_mode} onChange={v => setSettings(prev => ({ ...prev, agent_mode: v }))} accent={accent} label="Agent mode (enable tool calling)" />
            <Checkbox checked={settings.require_confirmation_writes} onChange={v => setSettings(prev => ({ ...prev, require_confirmation_writes: v }))} accent={accent} label="Require confirmation for write actions (create finding, add tag, etc.)" />
            <Checkbox checked={settings.block_critical_tools} onChange={v => setSettings(prev => ({ ...prev, block_critical_tools: v }))} accent={accent} label="Block critical-risk tools (run playbook, etc.)" />
            <div>
              <Overline style={{ marginBottom: 5 }}>Max tool calls per agent run</Overline>
              <input type="number" value={settings.max_tool_calls} min={1} max={100} onChange={e => setSettings(prev => ({ ...prev, max_tool_calls: Number.parseInt(e.target.value) || 10 }))} style={{ ...inp(), width: 120 }} />
            </div>
          </div>
        </Card>
      )}

      <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
        <button onClick={saveSettings} disabled={savingSettings} style={{ background: accent, border: 'none', borderRadius: 5, padding: '8px 18px', cursor: 'pointer', color: '#fff', fontSize: TYPE.body, fontFamily: FONTS.mono, fontWeight: 600 }}>
          {savingSettings ? 'Saving...' : 'Save settings'}
        </button>
        {settingsMsg && <span style={{ fontSize: TYPE.body, color: settingsMsg.toLowerCase().includes('fail') || settingsMsg.toLowerCase().includes('error') ? PALETTE.danger : PALETTE.ok, fontFamily: FONTS.mono }}>{settingsMsg}</span>}
      </div>
    </div>
  );
}
AISection.propTypes = { accent: PropTypes.string };
