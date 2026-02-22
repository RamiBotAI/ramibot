import { useEffect, useState } from 'react'
import useStore from '../store'
import {
  Plus, X, Settings, PanelLeftClose, PanelLeftOpen,
  Cpu, Brain, Wrench, ChevronDown, ChevronRight, Pencil, List, Swords, ShieldCheck,
} from 'lucide-react'

/* ── shared micro-styles ─────────────────────────── */
const sectionLabel = {
  fontFamily: 'var(--font-display)',
  fontSize: '0.58rem',
  letterSpacing: '0.16em',
  textTransform: 'uppercase',
  color: 'var(--t2)',
  display: 'flex',
  alignItems: 'center',
  gap: '0.35rem',
  marginBottom: '0.45rem',
}

const sharpSelect = {
  width: '100%',
  background: 'var(--surface-2)',
  border: '1px solid var(--bd)',
  borderRadius: 0,
  padding: '0.32rem 1.75rem 0.32rem 0.5rem',
  fontSize: '0.72rem',
  color: 'var(--t1)',
  fontFamily: 'var(--font-mono)',
  outline: 'none',
  cursor: 'pointer',
  transition: 'border-color 0.15s',
}

const sharpInput = {
  width: '100%',
  background: 'var(--surface-2)',
  border: '1px solid var(--bd)',
  borderRadius: 0,
  padding: '0.32rem 0.5rem',
  fontSize: '0.72rem',
  color: 'var(--t1)',
  fontFamily: 'var(--font-mono)',
  outline: 'none',
  transition: 'border-color 0.15s',
}

function focusAccent(e) {
  e.target.style.borderColor = `rgb(var(--accent) / 0.6)`
  e.target.style.boxShadow = `0 0 0 1px rgb(var(--accent) / 0.1)`
}
function blurAccent(e) {
  e.target.style.borderColor = 'var(--bd)'
  e.target.style.boxShadow = 'none'
}

/* ── Toggle Switch ───────────────────────────────── */
function Toggle({ on, onClick }) {
  return (
    <button
      onClick={onClick}
      style={{
        width: '2.1rem', height: '1.1rem',
        background: on ? `rgb(var(--toggle-on))` : 'var(--bd-2)',
        border: 'none', borderRadius: 0,
        position: 'relative', cursor: 'pointer',
        transition: 'background 0.2s', flexShrink: 0,
      }}
    >
      <span style={{
        position: 'absolute', top: '2px',
        left: on ? 'calc(100% - 17px)' : '2px',
        width: '14px', height: '14px',
        background: on ? 'var(--t1)' : 'var(--t2)',
        transition: 'left 0.15s',
      }} />
    </button>
  )
}

/* ── Sidebar ─────────────────────────────────────── */
function Sidebar({ onOpenSettings }) {
  const {
    conversations, currentConversation, fetchConversation, createConversation, deleteConversation,
    providers, models, selectedProvider, selectedModel, mcpEnabled, reasoningEnabled,
    setProvider, setModel, toggleMcp, toggleReasoning, sidebarOpen, toggleSidebar,
    fetchModels, mcpTools, fetchMcpTools, disabledMcpTools, toggleMcpTool, teamMode, setTeamMode,
  } = useStore()

  const [mcpToolsExpanded, setMcpToolsExpanded] = useState(false)
  const [customModelMode, setCustomModelMode] = useState(false)

  useEffect(() => {
    if (selectedProvider) fetchModels(selectedProvider)
  }, [selectedProvider])

  useEffect(() => {
    if (mcpEnabled) fetchMcpTools()
  }, [mcpEnabled])

  const formatDate = (dateStr) => {
    if (!dateStr) return ''
    const d = new Date(dateStr)
    const now = new Date()
    const diff = now - d
    if (diff < 86400000) return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    if (diff < 604800000) return d.toLocaleDateString([], { weekday: 'short' })
    return d.toLocaleDateString([], { month: 'short', day: 'numeric' })
  }

  const enabledCount = mcpTools.length - disabledMcpTools.filter(t => mcpTools.some(mt => mt.function?.name === t)).length

  return (
    <>
      {/* Collapsed toggle */}
      {!sidebarOpen && (
        <div style={{ position: 'fixed', top: '0.75rem', left: '0.75rem', zIndex: 50, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.4rem' }}>
          <img src="/ramibot.png" alt="RamiBot" style={{ height: '1.6rem', objectFit: 'contain', opacity: 0.85 }} />
          <button
            onClick={toggleSidebar}
            style={{
              padding: '0.35rem',
              background: 'var(--surface)',
              border: '1px solid var(--bd)',
              borderRadius: 0,
              color: 'var(--t2)',
              cursor: 'pointer',
              transition: 'border-color 0.15s',
            }}
            onMouseEnter={e => { e.currentTarget.style.borderColor = `rgb(var(--accent) / 0.5)`; e.currentTarget.style.color = `rgb(var(--accent))` }}
            onMouseLeave={e => { e.currentTarget.style.borderColor = 'var(--bd)'; e.currentTarget.style.color = 'var(--t2)' }}
          >
            <PanelLeftOpen size={16} />
          </button>
        </div>
      )}

      <div
        style={{
          width: sidebarOpen ? '17rem' : '0',
          flexShrink: 0,
          display: 'flex',
          flexDirection: 'column',
          background: `rgb(var(--sidebar-bg))`,
          borderRight: '1px solid var(--bd)',
          transition: 'width 0.3s ease',
          overflow: 'hidden',
        }}
      >
        {/* ── Header ───────────────────────────────── */}
        <div style={{ padding: '0.875rem 1rem', borderBottom: '1px solid var(--bd)', flexShrink: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
              <img src="/ramibot.png" alt="RamiBot" style={{ height: '1.6rem', objectFit: 'contain' }} />
            </div>
            <button
              onClick={toggleSidebar}
              style={{ background: 'none', border: 'none', color: 'var(--t2)', cursor: 'pointer', padding: '0.25rem', lineHeight: 0 }}
            >
              <PanelLeftClose size={16} />
            </button>
          </div>

          {/* New session */}
          <button
            onClick={async () => { await createConversation() }}
            style={{
              width: '100%',
              display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.45rem',
              padding: '0.45rem',
              background: `rgb(var(--accent) / 0.08)`,
              border: `1px solid rgb(var(--accent) / 0.35)`,
              borderRadius: 0,
              color: `rgb(var(--accent))`,
              fontFamily: 'var(--font-display)',
              fontSize: '0.65rem', fontWeight: 700,
              letterSpacing: '0.18em',
              cursor: 'pointer',
              transition: 'background 0.15s, border-color 0.15s',
            }}
            onMouseEnter={e => { e.currentTarget.style.background = `rgb(var(--accent) / 0.15)`; e.currentTarget.style.borderColor = `rgb(var(--accent) / 0.6)` }}
            onMouseLeave={e => { e.currentTarget.style.background = `rgb(var(--accent) / 0.08)`; e.currentTarget.style.borderColor = `rgb(var(--accent) / 0.35)` }}
          >
            <Plus size={13} />
            NEW SESSION
          </button>
        </div>

        {/* ── Conversation list ─────────────────────── */}
        <div style={{ flex: 1, overflowY: 'auto', minHeight: 0, position: 'relative' }}>
          {/* Watermark */}
          <div style={{
            pointerEvents: 'none', position: 'absolute', bottom: 0, left: 0, right: 0,
            display: 'flex', justifyContent: 'center', opacity: 0.44, zIndex: 0,
          }}>
            <img
              src={teamMode === 'blue' ? '/avatar_blue.png' : '/avatar_red.png'}
              alt=""
              style={{ width: '15rem', height: '15rem', objectFit: 'contain' }}
            />
          </div>

          {conversations.map((conv) => {
            const isActive = currentConversation?.id === conv.id
            return (
              <div
                key={conv.id}
                onClick={() => fetchConversation(conv.id)}
                className="group"
                style={{
                  display: 'flex', alignItems: 'center', gap: '0.5rem',
                  padding: '0.5rem 0.75rem',
                  cursor: 'pointer',
                  borderBottom: '1px solid var(--bd)',
                  borderLeft: isActive ? `2px solid rgb(var(--accent))` : '2px solid transparent',
                  background: isActive ? `rgb(var(--accent) / 0.06)` : 'transparent',
                  transition: 'background 0.12s',
                  position: 'relative', zIndex: 1,
                }}
                onMouseEnter={e => { if (!isActive) e.currentTarget.style.background = 'var(--surface-2)' }}
                onMouseLeave={e => { if (!isActive) e.currentTarget.style.background = 'transparent' }}
              >
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{
                    fontSize: '0.7rem',
                    fontFamily: 'var(--font-mono)',
                    color: isActive ? 'var(--t1)' : 'var(--t2)',
                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                    lineHeight: 1.35,
                  }}>
                    {conv.title === 'New conversation' || !conv.title
                      ? <span style={{ color: 'var(--t3)', fontStyle: 'italic' }}>new session</span>
                      : conv.title}
                  </div>
                  <div style={{
                    display: 'flex', alignItems: 'center', gap: '0.35rem', marginTop: '0.2rem', flexWrap: 'nowrap',
                  }}>
                    {/* Team badge */}
                    <span style={{
                      fontFamily: 'var(--font-display)', fontSize: '0.5rem',
                      letterSpacing: '0.1em', textTransform: 'uppercase',
                      color: conv.team_mode === 'blue' ? '#00b8ff' : '#ff3250',
                      border: `1px solid ${conv.team_mode === 'blue' ? '#00b8ff30' : '#ff325030'}`,
                      padding: '0.02rem 0.28rem',
                      flexShrink: 0,
                    }}>
                      {conv.team_mode === 'blue' ? 'BLUE' : 'RED'}
                    </span>
                    <span style={{
                      fontSize: '0.55rem', color: 'var(--t3)',
                      fontFamily: 'var(--font-display)', letterSpacing: '0.06em',
                      overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                    }}>
                      {formatDate(conv.updated_at || conv.created_at)}
                    </span>
                  </div>
                </div>
                <button
                  onClick={(e) => { e.stopPropagation(); deleteConversation(conv.id) }}
                  className="opacity-0 group-hover:opacity-100"
                  style={{
                    padding: '0.2rem', background: 'none', border: 'none',
                    color: 'var(--t2)', cursor: 'pointer', transition: 'color 0.15s, opacity 0.15s', lineHeight: 0,
                  }}
                  onMouseEnter={e => e.currentTarget.style.color = '#ff3250'}
                  onMouseLeave={e => e.currentTarget.style.color = 'var(--t2)'}
                >
                  <X size={11} />
                </button>
              </div>
            )
          })}

          {conversations.length === 0 && (
            <div style={{
              padding: '2rem 1rem', textAlign: 'center',
              fontFamily: 'var(--font-display)', fontSize: '0.6rem',
              letterSpacing: '0.14em', color: 'var(--t3)', textTransform: 'uppercase',
            }}>
              NO ACTIVE SESSIONS
            </div>
          )}
        </div>

        {/* ── Controls ─────────────────────────────── */}
        <div style={{
          flexShrink: 0, borderTop: '1px solid var(--bd)',
          padding: '0.75rem', display: 'flex', flexDirection: 'column', gap: '0.7rem',
        }}>
          {/* Operative mode */}
          <div>
            <div style={sectionLabel}>OPERATIVE MODE</div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.35rem' }}>
              {[
                { key: 'red', label: 'RED', Icon: Swords, color: '#ff3250', rgb: '255 50 80' },
                { key: 'blue', label: 'BLUE', Icon: ShieldCheck, color: '#00b8ff', rgb: '0 184 255' },
              ].map(({ key, label, Icon, color, rgb }) => (
                <button
                  key={key}
                  onClick={() => setTeamMode(key)}
                  style={{
                    display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.35rem',
                    padding: '0.4rem 0',
                    background: teamMode === key ? `rgba(${rgb.replace(/ /g, ',')}, 0.1)` : 'transparent',
                    border: teamMode === key ? `1px solid rgba(${rgb.replace(/ /g, ',')}, 0.5)` : '1px solid var(--bd)',
                    borderRadius: 0,
                    color: teamMode === key ? color : 'var(--t2)',
                    fontFamily: 'var(--font-display)', fontSize: '0.6rem',
                    fontWeight: 700, letterSpacing: '0.12em',
                    cursor: 'pointer', transition: 'all 0.15s',
                  }}
                >
                  <Icon size={11} /> {label}
                </button>
              ))}
            </div>
          </div>

          {/* Provider */}
          <div>
            <div style={sectionLabel}><Cpu size={9} /> Provider</div>
            <select
              value={selectedProvider}
              onChange={(e) => setProvider(e.target.value)}
              style={sharpSelect}
              onFocus={focusAccent}
              onBlur={blurAccent}
            >
              {providers.length > 0 ? (
                providers.map((p) => (
                  <option key={p.name || p} value={p.name || p}>{p.name || p}</option>
                ))
              ) : (
                <>
                  <option value="openai">openai</option>
                  <option value="anthropic">anthropic</option>
                  <option value="openrouter">openrouter</option>
                  <option value="lmstudio">lmstudio</option>
                  <option value="ollama">ollama</option>
                </>
              )}
            </select>
          </div>

          {/* Model */}
          <div>
            <div style={{ ...sectionLabel, justifyContent: 'space-between' }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                <Brain size={9} /> Model
              </span>
              <button
                onClick={() => setCustomModelMode(!customModelMode)}
                style={{ background: 'none', border: 'none', color: 'var(--t2)', cursor: 'pointer', padding: '0.1rem', lineHeight: 0 }}
                title={customModelMode ? 'Select from list' : 'Type model name'}
              >
                {customModelMode ? <List size={12} /> : <Pencil size={12} />}
              </button>
            </div>
            {customModelMode ? (
              <input
                type="text"
                value={selectedModel}
                onChange={(e) => setModel(e.target.value)}
                placeholder="e.g. claude-3-haiku-20240307"
                style={sharpInput}
                onFocus={focusAccent}
                onBlur={blurAccent}
              />
            ) : (
              <select
                value={selectedModel}
                onChange={(e) => setModel(e.target.value)}
                style={sharpSelect}
                onFocus={focusAccent}
                onBlur={blurAccent}
              >
                {models.length > 0 ? (
                  models.map((m) => (
                    <option key={m.id || m} value={m.id || m}>{m.name || m.id || m}</option>
                  ))
                ) : (
                  <option value="">-- select model --</option>
                )}
              </select>
            )}
          </div>

          {/* MCP Tools */}
          <div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div style={{ ...sectionLabel, marginBottom: 0 }}>
                <Wrench size={9} /> MCP Tools
                {mcpEnabled && mcpTools.length > 0 && (
                  <span style={{
                    fontSize: '0.52rem', padding: '0.1rem 0.35rem',
                    background: `rgb(var(--accent) / 0.15)`,
                    color: `rgb(var(--accent))`,
                    fontFamily: 'var(--font-display)', letterSpacing: '0.08em',
                  }}>
                    {enabledCount}/{mcpTools.length}
                  </span>
                )}
              </div>
              <Toggle on={mcpEnabled} onClick={toggleMcp} />
            </div>
            {mcpEnabled && mcpTools.length > 0 && (
              <div style={{ marginTop: '0.45rem' }}>
                <button
                  onClick={() => setMcpToolsExpanded(!mcpToolsExpanded)}
                  style={{
                    display: 'flex', alignItems: 'center', gap: '0.25rem',
                    background: 'none', border: 'none',
                    fontFamily: 'var(--font-display)', fontSize: '0.55rem',
                    letterSpacing: '0.12em', textTransform: 'uppercase',
                    color: 'var(--t3)', cursor: 'pointer',
                  }}
                >
                  {mcpToolsExpanded ? <ChevronDown size={9} /> : <ChevronRight size={9} />}
                  {mcpToolsExpanded ? 'HIDE' : 'SHOW'} TOOLS
                </button>
                {mcpToolsExpanded && (
                  <div style={{
                    marginTop: '0.35rem', marginLeft: '0.5rem',
                    maxHeight: '7.5rem', overflowY: 'auto',
                    display: 'flex', flexDirection: 'column', gap: '0.25rem',
                  }}>
                    {mcpTools.map((tool, i) => {
                      const name = tool.function?.name
                      const disabled = disabledMcpTools.includes(name)
                      return (
                        <label
                          key={i}
                          style={{
                            display: 'flex', alignItems: 'center', gap: '0.45rem',
                            fontSize: '0.65rem', cursor: 'pointer',
                            fontFamily: 'var(--font-mono)',
                          }}
                          title={tool.function?.description}
                        >
                          <input
                            type="checkbox"
                            checked={!disabled}
                            onChange={() => toggleMcpTool(name)}
                            style={{ width: '10px', height: '10px', accentColor: `rgb(var(--accent))`, cursor: 'pointer', borderRadius: 0 }}
                          />
                          <span style={{
                            color: disabled ? 'var(--t3)' : 'var(--t2)',
                            textDecoration: disabled ? 'line-through' : 'none',
                            overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                          }}>
                            {name}
                          </span>
                        </label>
                      )
                    })}
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Reasoning */}
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ ...sectionLabel, marginBottom: 0 }}>
              <Brain size={9} /> Reasoning
            </div>
            <button
              onClick={toggleReasoning}
              style={{
                width: '2.1rem', height: '1.1rem',
                background: reasoningEnabled ? '#8b5cf6' : 'var(--bd-2)',
                border: 'none', borderRadius: 0,
                position: 'relative', cursor: 'pointer',
                transition: 'background 0.2s', flexShrink: 0,
              }}
            >
              <span style={{
                position: 'absolute', top: '2px',
                left: reasoningEnabled ? 'calc(100% - 17px)' : '2px',
                width: '14px', height: '14px',
                background: reasoningEnabled ? 'var(--t1)' : 'var(--t2)',
                transition: 'left 0.15s',
              }} />
            </button>
          </div>

          {/* Settings */}
          <button
            onClick={onOpenSettings}
            style={{
              display: 'flex', alignItems: 'center', gap: '0.5rem',
              width: '100%', padding: '0.45rem 0.5rem',
              background: 'transparent', border: '1px solid var(--bd)',
              borderRadius: 0, cursor: 'pointer',
              fontFamily: 'var(--font-display)', fontSize: '0.62rem',
              letterSpacing: '0.14em', textTransform: 'uppercase',
              color: 'var(--t2)', transition: 'all 0.15s',
            }}
            onMouseEnter={e => {
              e.currentTarget.style.background = 'var(--surface-2)'
              e.currentTarget.style.color = 'var(--t1)'
              e.currentTarget.style.borderColor = 'var(--bd-2)'
            }}
            onMouseLeave={e => {
              e.currentTarget.style.background = 'transparent'
              e.currentTarget.style.color = 'var(--t2)'
              e.currentTarget.style.borderColor = 'var(--bd)'
            }}
          >
            <Settings size={13} /> CONFIGURATION
          </button>
        </div>
      </div>
    </>
  )
}

export default Sidebar
