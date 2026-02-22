import { useState, useEffect } from 'react'
import useStore from '../store'
import { X, Key, Globe, Save, Wrench, Plus, Trash2, Terminal, Link, Shield, Tv2, Container, Activity, RefreshCw, Trash } from 'lucide-react'

/* ── Shared input styles ─────────────────────────────── */
const fieldInput = {
  width: '100%',
  background: 'var(--surface-2)',
  border: '1px solid var(--bd)',
  borderRadius: 0,
  padding: '0.4rem 0.6rem',
  fontSize: '0.78rem',
  fontFamily: 'var(--font-mono)',
  color: 'var(--t1)',
  outline: 'none',
  transition: 'border-color 0.15s',
  boxSizing: 'border-box',
}

function focusAccent(e) {
  e.target.style.borderColor = `rgb(var(--accent) / 0.6)`
  e.target.style.boxShadow = `0 0 0 1px rgb(var(--accent) / 0.08)`
}
function blurAccent(e) {
  e.target.style.borderColor = 'var(--bd)'
  e.target.style.boxShadow = 'none'
}

function Toggle({ on, onClick }) {
  return (
    <button onClick={onClick} style={{
      width: '2.1rem', height: '1.1rem',
      background: on ? `rgb(var(--accent))` : 'var(--bd-2)',
      border: 'none', borderRadius: 0,
      position: 'relative', cursor: 'pointer',
      transition: 'background 0.2s', flexShrink: 0,
    }}>
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

function Field({ label, type, placeholder, icon: Icon, value, onChange }) {
  return (
    <div style={{ marginBottom: '0.75rem' }}>
      <label style={{
        display: 'flex', alignItems: 'center', gap: '0.4rem',
        fontFamily: 'var(--font-display)', fontSize: '0.55rem',
        letterSpacing: '0.14em', textTransform: 'uppercase',
        color: 'var(--t2)', marginBottom: '0.35rem',
      }}>
        {Icon && <Icon size={10} />}{label}
      </label>
      <input
        type={type} value={value || ''} onChange={onChange}
        placeholder={placeholder} style={fieldInput}
        onFocus={focusAccent} onBlur={blurAccent}
      />
    </div>
  )
}

/* ── Tab content panels ──────────────────────────────── */
function PanelInterface({ matrixEnabled, toggleMatrix, matrixSpeed, setMatrixSpeed }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
      <div style={{ background: 'var(--surface-2)', border: '1px solid var(--bd)', padding: '0.75rem', display: 'flex', flexDirection: 'column', gap: '0.7rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Tv2 size={13} style={{ color: matrixEnabled ? `rgb(var(--accent))` : 'var(--t2)' }} />
            <span style={{ fontFamily: 'var(--font-display)', fontSize: '0.65rem', letterSpacing: '0.12em', textTransform: 'uppercase', color: 'var(--t1)' }}>Matrix Rain</span>
          </div>
          <Toggle on={matrixEnabled} onClick={toggleMatrix} />
        </div>

        {matrixEnabled && (
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.35rem' }}>
              <span style={{ fontFamily: 'var(--font-display)', fontSize: '0.52rem', letterSpacing: '0.14em', textTransform: 'uppercase', color: 'var(--t2)' }}>Speed</span>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.62rem', color: `rgb(var(--accent))` }}>{matrixSpeed}</span>
            </div>
            <input
              type="range" min={1} max={10} step={1} value={matrixSpeed}
              onChange={(e) => setMatrixSpeed(Number(e.target.value))}
              style={{ width: '100%', cursor: 'pointer', accentColor: `rgb(var(--accent))`, height: '3px' }}
            />
            <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '0.2rem' }}>
              <span style={{ fontFamily: 'var(--font-display)', fontSize: '0.48rem', color: 'var(--t3)', letterSpacing: '0.1em' }}>SLOW</span>
              <span style={{ fontFamily: 'var(--font-display)', fontSize: '0.48rem', color: 'var(--t3)', letterSpacing: '0.1em' }}>FAST</span>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

function PanelApiKeys({ form, handleChange }) {
  const providers = [
    { key: 'openai_api_key', label: 'OpenAI API Key', type: 'password', icon: Key, placeholder: 'sk-...' },
    { key: 'anthropic_api_key', label: 'Anthropic API Key', type: 'password', icon: Key, placeholder: 'sk-ant-...' },
    { key: 'openrouter_api_key', label: 'OpenRouter API Key', type: 'password', icon: Key, placeholder: 'sk-or-...' },
    { key: 'lmstudio_base_url', label: 'LM Studio Base URL', type: 'text', icon: Globe, placeholder: 'http://localhost:1234' },
    { key: 'ollama_base_url', label: 'Ollama Base URL', type: 'text', icon: Globe, placeholder: 'http://localhost:11434' },
  ]
  return (
    <div>
      {providers.map((f) => (
        <Field key={f.key} label={f.label} type={f.type} icon={f.icon}
          placeholder={f.placeholder} value={form[f.key]}
          onChange={(e) => handleChange(f.key, e.target.value)}
        />
      ))}
    </div>
  )
}

function PanelDocker({ form, handleChange }) {
  return (
    <div>
      <Field
        label="Container Name" type="text" icon={Container}
        placeholder="e.g. kali-container, ubuntu-dev"
        value={form.docker_container}
        onChange={(e) => handleChange('docker_container', e.target.value)}
      />
      <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.65rem', color: 'var(--t3)' }}>
        # container will be auto-started if stopped
      </div>
    </div>
  )
}

function PanelTor() {
  const setGlobalTorActive = useStore((s) => s.setTorActive)
  const [torStatus, setTorStatus] = useState({ running: false, transparent_proxy: false })
  const [torLoading, setTorLoading] = useState(false)
  const [torError, setTorError] = useState('')

  const fetchTorStatus = async () => {
    try {
      const res = await fetch('/api/docker/tor')
      if (res.ok) {
        const data = await res.json()
        setTorStatus(data)
        setGlobalTorActive(data.running && data.transparent_proxy)
        setTorError('')
      }
    } catch {}
  }

  const toggleTor = async () => {
    setTorLoading(true); setTorError('')
    const action = torStatus.running ? 'stop' : 'start'
    try {
      const res = await fetch('/api/docker/tor', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action }),
      })
      const data = await res.json()
      if (!res.ok) setTorError(data.detail || 'Tor toggle failed')
      else {
        setTorStatus(data)
        setGlobalTorActive(data.running && data.transparent_proxy)
      }
    } catch (e) { setTorError(e.message) }
    finally { setTorLoading(false) }
  }

  useEffect(() => { fetchTorStatus() }, [])

  return (
    <div style={{ background: 'var(--surface-2)', border: '1px solid var(--bd)', padding: '0.875rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Shield size={14} style={{ color: torStatus.running && torStatus.transparent_proxy ? '#22c55e' : 'var(--t2)' }} />
          <span style={{ fontFamily: 'var(--font-display)', fontSize: '0.65rem', letterSpacing: '0.12em', textTransform: 'uppercase', color: 'var(--t1)' }}>
            Tor Transparent Proxy
          </span>
        </div>
        <button
          onClick={toggleTor} disabled={torLoading}
          style={{
            padding: '0.3rem 0.75rem',
            background: torStatus.running ? 'rgba(255,50,80,0.1)' : 'rgba(34,197,94,0.1)',
            border: torStatus.running ? '1px solid rgba(255,50,80,0.4)' : '1px solid rgba(34,197,94,0.4)',
            borderRadius: 0,
            color: torStatus.running ? '#ff3250' : '#22c55e',
            fontFamily: 'var(--font-display)', fontSize: '0.58rem',
            letterSpacing: '0.12em', textTransform: 'uppercase',
            cursor: torLoading ? 'not-allowed' : 'pointer',
            opacity: torLoading ? 0.5 : 1, transition: 'all 0.15s',
          }}
        >
          {torLoading ? 'WORKING...' : torStatus.running ? 'STOP TOR' : 'START TOR'}
        </button>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
        {[
          { label: 'TOR', active: torStatus.running },
          { label: 'PROXY', active: torStatus.transparent_proxy },
          { label: 'KILL-SW', active: torStatus.kill_switch },
        ].map(({ label, active }) => (
          <div key={label} style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
            <span style={{ width: '5px', height: '5px', borderRadius: '50%', background: active ? '#22c55e' : 'var(--bd-2)' }} />
            <span style={{ fontFamily: 'var(--font-display)', fontSize: '0.52rem', letterSpacing: '0.1em', color: active ? 'var(--t2)' : 'var(--t3)' }}>
              {label}: {active ? 'ON' : 'OFF'}
            </span>
          </div>
        ))}
      </div>

      {torError && <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.65rem', color: '#ff3250' }}>{torError}</span>}
      <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.62rem', color: 'var(--t3)' }}>
        # routes container traffic through Tor via iptables. requires NET_ADMIN capability.
      </div>
    </div>
  )
}

function PanelMcp() {
  const [mcpServers, setMcpServers] = useState([])
  const [mcpLoading, setMcpLoading] = useState(false)
  const [mcpForm, setMcpForm] = useState({ name: '', type: 'stdio', command: '', args: '', url: '' })
  const [mcpError, setMcpError] = useState('')

  const fetchMcpServers = async () => {
    try {
      const res = await fetch('/api/mcp/servers')
      if (res.ok) setMcpServers(await res.json())
    } catch {}
  }

  useEffect(() => { fetchMcpServers() }, [])

  const addMcpServer = async () => {
    if (!mcpForm.name) { setMcpError('Name is required'); return }
    if (mcpForm.type === 'stdio' && !mcpForm.command) { setMcpError('Command is required'); return }
    if (mcpForm.type === 'url' && !mcpForm.url) { setMcpError('URL is required'); return }
    setMcpLoading(true); setMcpError('')
    try {
      const body = {
        name: mcpForm.name,
        ...(mcpForm.type === 'stdio'
          ? { command: mcpForm.command, args: mcpForm.args ? mcpForm.args.split(' ') : [] }
          : { url: mcpForm.url }),
      }
      const res = await fetch('/api/mcp/servers', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
      })
      if (!res.ok) setMcpError((await res.text()) || 'Failed to add server')
      else { setMcpForm({ name: '', type: 'stdio', command: '', args: '', url: '' }); await fetchMcpServers() }
    } catch (e) { setMcpError(e.message) }
    finally { setMcpLoading(false) }
  }

  const deleteMcpServer = async (name) => {
    try {
      await fetch(`/api/mcp/servers/${encodeURIComponent(name)}`, { method: 'DELETE' })
      await fetchMcpServers()
    } catch {}
  }

  const typeBtn = (type) => ({
    display: 'flex', alignItems: 'center', gap: '0.4rem',
    padding: '0.3rem 0.65rem',
    background: mcpForm.type === type ? `rgb(var(--accent) / 0.1)` : 'transparent',
    border: mcpForm.type === type ? `1px solid rgb(var(--accent) / 0.45)` : '1px solid var(--bd)',
    borderRadius: 0,
    color: mcpForm.type === type ? `rgb(var(--accent))` : 'var(--t2)',
    fontFamily: 'var(--font-display)', fontSize: '0.58rem',
    letterSpacing: '0.12em', textTransform: 'uppercase',
    cursor: 'pointer', transition: 'all 0.15s',
  })

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
      {mcpServers.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
          {mcpServers.map((server) => (
            <div key={server.name} style={{
              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              background: 'var(--surface-2)', border: '1px solid var(--bd)', padding: '0.5rem 0.6rem',
            }}>
              <div style={{ minWidth: 0, flex: 1 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <span style={{ width: '5px', height: '5px', borderRadius: '50%', flexShrink: 0, background: server.connected ? '#22c55e' : '#ff3250' }} />
                  {server.url ? <Link size={10} style={{ color: `rgb(var(--accent) / 0.7)`, flexShrink: 0 }} /> : <Terminal size={10} style={{ color: '#22c55e', flexShrink: 0 }} />}
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem', color: 'var(--t1)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {server.name}
                  </span>
                </div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.62rem', color: 'var(--t3)', marginTop: '0.2rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {server.url || `${server.command} ${(server.args || []).join(' ')}`}
                </div>
              </div>
              <button onClick={() => deleteMcpServer(server.name)}
                style={{ padding: '0.3rem', background: 'none', border: 'none', cursor: 'pointer', color: 'var(--t3)', flexShrink: 0, transition: 'color 0.15s', lineHeight: 0 }}
                onMouseEnter={e => e.currentTarget.style.color = '#ff3250'}
                onMouseLeave={e => e.currentTarget.style.color = 'var(--t3)'}
              >
                <Trash2 size={13} />
              </button>
            </div>
          ))}
        </div>
      )}

      <div style={{ background: 'var(--surface-2)', border: '1px solid var(--bd)', padding: '0.75rem', display: 'flex', flexDirection: 'column', gap: '0.55rem' }}>
        <div style={{ fontFamily: 'var(--font-display)', fontSize: '0.55rem', letterSpacing: '0.16em', textTransform: 'uppercase', color: 'var(--t2)' }}>
          <Wrench size={9} style={{ display: 'inline', marginRight: '0.35rem', verticalAlign: 'middle' }} />
          Add Server
        </div>
        <div style={{ display: 'flex', gap: '0.4rem' }}>
          <button onClick={() => setMcpForm(f => ({ ...f, type: 'stdio' }))} style={typeBtn('stdio')}><Terminal size={11} /> STDIO</button>
          <button onClick={() => setMcpForm(f => ({ ...f, type: 'url' }))} style={typeBtn('url')}><Link size={11} /> REMOTE</button>
        </div>
        <input type="text" value={mcpForm.name} onChange={(e) => setMcpForm(f => ({ ...f, name: e.target.value }))}
          placeholder="server name" style={fieldInput} onFocus={focusAccent} onBlur={blurAccent} />
        {mcpForm.type === 'stdio' ? (
          <>
            <input type="text" value={mcpForm.command} onChange={(e) => setMcpForm(f => ({ ...f, command: e.target.value }))}
              placeholder="command (e.g. npx, python)" style={fieldInput} onFocus={focusAccent} onBlur={blurAccent} />
            <input type="text" value={mcpForm.args} onChange={(e) => setMcpForm(f => ({ ...f, args: e.target.value }))}
              placeholder="arguments" style={fieldInput} onFocus={focusAccent} onBlur={blurAccent} />
          </>
        ) : (
          <input type="text" value={mcpForm.url} onChange={(e) => setMcpForm(f => ({ ...f, url: e.target.value }))}
            placeholder="http://localhost:3001/mcp" style={fieldInput} onFocus={focusAccent} onBlur={blurAccent} />
        )}
        {mcpError && <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.65rem', color: '#ff3250' }}>{mcpError}</span>}
        <button onClick={addMcpServer} disabled={mcpLoading} style={{
          display: 'flex', alignItems: 'center', gap: '0.4rem',
          padding: '0.38rem 0.75rem', alignSelf: 'flex-start',
          background: `rgb(var(--accent) / 0.1)`, border: `1px solid rgb(var(--accent) / 0.4)`,
          borderRadius: 0, color: `rgb(var(--accent))`,
          fontFamily: 'var(--font-display)', fontSize: '0.6rem',
          letterSpacing: '0.14em', textTransform: 'uppercase',
          cursor: mcpLoading ? 'not-allowed' : 'pointer', opacity: mcpLoading ? 0.5 : 1,
        }}
          onMouseEnter={e => { if (!mcpLoading) e.currentTarget.style.background = `rgb(var(--accent) / 0.18)` }}
          onMouseLeave={e => e.currentTarget.style.background = `rgb(var(--accent) / 0.1)`}
        >
          <Plus size={12} />{mcpLoading ? 'ADDING...' : 'ADD SERVER'}
        </button>
      </div>
    </div>
  )
}

/* ── Skill Log panel ─────────────────────────────────── */
function PanelSkillLog() {
  const [entries, setEntries] = useState([])
  const [loading, setLoading] = useState(false)

  const fetchLog = async () => {
    setLoading(true)
    try {
      const r = await fetch('http://localhost:8000/api/skills/log?limit=50')
      const data = await r.json()
      setEntries(data)
    } catch {}
    setLoading(false)
  }

  const clearLog = async () => {
    await fetch('http://localhost:8000/api/skills/log', { method: 'DELETE' })
    setEntries([])
  }

  useEffect(() => { fetchLog() }, [])

  const riskColor = (r) => r === 'critical' ? '#ff3250' : r === 'high' ? '#f97316' : r === 'medium' ? '#fbbf24' : '#22c55e'
  const teamColor = (t) => t === 'red' ? '#ff3250' : '#00b8ff'

  const formatTime = (iso) => {
    try {
      const d = new Date(iso)
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) +
        ' · ' + d.toLocaleDateString([], { month: 'short', day: 'numeric' })
    } catch { return iso }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
      {/* Toolbar */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.25rem' }}>
        <span style={{ fontFamily: 'var(--font-display)', fontSize: '0.55rem', letterSpacing: '0.14em', textTransform: 'uppercase', color: 'var(--t2)' }}>
          {entries.length} DECISIONS
        </span>
        <div style={{ display: 'flex', gap: '0.4rem' }}>
          <button onClick={fetchLog} disabled={loading} style={{
            display: 'flex', alignItems: 'center', gap: '0.3rem',
            padding: '0.25rem 0.6rem', background: 'transparent',
            border: '1px solid var(--bd)', cursor: 'pointer',
            fontFamily: 'var(--font-display)', fontSize: '0.55rem',
            letterSpacing: '0.12em', textTransform: 'uppercase',
            color: 'var(--t2)', transition: 'color 0.12s',
          }}>
            <RefreshCw size={10} style={{ animation: loading ? 'spin 1s linear infinite' : 'none' }} />
            REFRESH
          </button>
          <button onClick={clearLog} style={{
            display: 'flex', alignItems: 'center', gap: '0.3rem',
            padding: '0.25rem 0.6rem', background: 'transparent',
            border: '1px solid var(--bd)', cursor: 'pointer',
            fontFamily: 'var(--font-display)', fontSize: '0.55rem',
            letterSpacing: '0.12em', textTransform: 'uppercase',
            color: '#ff3250', transition: 'opacity 0.12s',
          }}>
            <Trash size={10} /> CLEAR
          </button>
        </div>
      </div>

      {entries.length === 0 && !loading && (
        <div style={{
          padding: '2rem', textAlign: 'center',
          fontFamily: 'var(--font-mono)', fontSize: '0.72rem',
          color: 'var(--t3)', border: '1px dashed var(--bd)',
        }}>
          No skill decisions logged yet.<br />
          <span style={{ fontSize: '0.65rem' }}>Send a message with MCP enabled to see activations.</span>
        </div>
      )}

      {entries.map((e, i) => (
        <div key={i} style={{
          border: '1px solid var(--bd)',
          borderLeft: `2px solid ${teamColor(e.team_mode)}`,
          background: 'var(--surface)',
          padding: '0.55rem 0.7rem',
          fontFamily: 'var(--font-mono)', fontSize: '0.7rem',
        }}>
          {/* Row 1: time + team + risk */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.35rem', flexWrap: 'wrap' }}>
            <span style={{ color: 'var(--t3)', fontSize: '0.62rem' }}>{formatTime(e.timestamp)}</span>
            <span style={{
              padding: '0.05rem 0.35rem', fontSize: '0.55rem',
              fontFamily: 'var(--font-display)', letterSpacing: '0.12em',
              textTransform: 'uppercase', color: teamColor(e.team_mode),
              border: `1px solid ${teamColor(e.team_mode)}40`,
            }}>{e.team_mode}</span>
            <span style={{
              padding: '0.05rem 0.35rem', fontSize: '0.55rem',
              fontFamily: 'var(--font-display)', letterSpacing: '0.12em',
              textTransform: 'uppercase', color: riskColor(e.risk_level),
              border: `1px solid ${riskColor(e.risk_level)}40`,
            }}>{e.risk_level}</span>
            <span style={{ color: 'var(--t3)', fontSize: '0.6rem', marginLeft: 'auto' }}>{e.prompt_length} chars</span>
          </div>

          {/* Row 2: input snippet */}
          <div style={{ color: 'var(--t1)', marginBottom: '0.3rem', fontSize: '0.68rem', lineHeight: 1.4, wordBreak: 'break-word' }}>
            &ldquo;{e.input_snippet}{e.input_snippet?.length >= 100 ? '…' : ''}&rdquo;
          </div>

          {/* Row 3: tags + skills */}
          <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', fontSize: '0.62rem' }}>
            {e.matched_tags?.length > 0 && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.3rem', flexWrap: 'wrap' }}>
                <span style={{ color: 'var(--t3)', fontFamily: 'var(--font-display)', fontSize: '0.5rem', letterSpacing: '0.1em', textTransform: 'uppercase' }}>TAGS</span>
                {e.matched_tags.map((t, j) => (
                  <span key={j} style={{ color: 'var(--t2)', background: 'var(--bg)', padding: '0.05rem 0.3rem', border: '1px solid var(--bd)' }}>{t}</span>
                ))}
              </div>
            )}
            {e.activated_skills?.length > 0 && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.3rem', flexWrap: 'wrap' }}>
                <span style={{ color: 'var(--t3)', fontFamily: 'var(--font-display)', fontSize: '0.5rem', letterSpacing: '0.1em', textTransform: 'uppercase' }}>SKILLS</span>
                {e.activated_skills.map((s, j) => (
                  <span key={j} style={{ color: `rgb(var(--accent))`, background: `rgb(var(--accent)/0.08)`, padding: '0.05rem 0.3rem', border: `1px solid rgb(var(--accent)/0.25)` }}>{s}</span>
                ))}
              </div>
            )}
          </div>
        </div>
      ))}
    </div>
  )
}

/* ── Main modal ──────────────────────────────────────── */
function SettingsModal({ onClose }) {
  const { settings, saveSettings, setDockerContainer, matrixEnabled, toggleMatrix, matrixSpeed, setMatrixSpeed } = useStore()
  const [activeTab, setActiveTab] = useState('interface')
  const [form, setForm] = useState({
    openai_api_key: '', anthropic_api_key: '',
    openrouter_api_key: '',
    lmstudio_base_url: 'http://localhost:1234', ollama_base_url: 'http://localhost:11434',
    ...settings,
  })

  const handleChange = (key, value) => setForm((prev) => ({ ...prev, [key]: value }))

  const handleSave = () => {
    saveSettings(form)
    if (form.docker_container !== undefined) setDockerContainer(form.docker_container)
    onClose()
  }

  const handleBackdropClick = (e) => { if (e.target === e.currentTarget) onClose() }

  const tabs = [
    { id: 'interface', label: 'Interface',  icon: Tv2 },
    { id: 'apikeys',   label: 'API Keys',   icon: Key },
    { id: 'docker',    label: 'Docker',     icon: Container },
    { id: 'tor',       label: 'Tor',        icon: Shield },
    { id: 'mcp',       label: 'MCP',        icon: Wrench },
    { id: 'skilllog',  label: 'Skill Log',  icon: Activity },
  ]

  return (
    <div onClick={handleBackdropClick} style={{
      position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.75)',
      display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 50,
    }}>
      <div style={{
        background: 'var(--surface)', border: '1px solid var(--bd)', borderRadius: 0,
        width: '100%', maxWidth: '42rem', margin: '1rem', height: '78vh',
        display: 'flex', flexDirection: 'column',
        boxShadow: '0 0 80px rgba(0,0,0,0.9)', position: 'relative',
      }}>
        {/* Corner marks */}
        {[['top','-2px','left','-2px','borderTop','borderLeft'],['top','-2px','right','-2px','borderTop','borderRight'],
          ['bottom','-2px','left','-2px','borderBottom','borderLeft'],['bottom','-2px','right','-2px','borderBottom','borderRight']
        ].map(([v,vo,h,ho,bv,bh],i) => (
          <div key={i} style={{ position:'absolute', [v]:vo, [h]:ho, width:'12px', height:'12px',
            [bv]:`2px solid rgb(var(--accent)/0.6)`, [bh]:`2px solid rgb(var(--accent)/0.6)`, pointerEvents:'none' }} />
        ))}

        {/* Header */}
        <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', padding:'1rem 1.25rem', borderBottom:'1px solid var(--bd)', flexShrink:0 }}>
          <div style={{ display:'flex', alignItems:'center', gap:'0.75rem' }}>
            <div style={{ width:'2px', height:'1.1rem', background:`rgb(var(--accent))` }} />
            <span style={{ fontFamily:'var(--font-display)', fontSize:'0.72rem', fontWeight:700, letterSpacing:'0.22em', textTransform:'uppercase', color:'var(--t1)' }}>
              SYSTEM CONFIGURATION
            </span>
          </div>
          <button onClick={onClose} style={{ background:'none', border:'none', color:'var(--t2)', cursor:'pointer', padding:'0.25rem', lineHeight:0, transition:'color 0.15s' }}
            onMouseEnter={e => e.currentTarget.style.color='var(--t1)'}
            onMouseLeave={e => e.currentTarget.style.color='var(--t2)'}
          >
            <X size={18} />
          </button>
        </div>

        {/* Body: left nav + right content */}
        <div style={{ flex:1, display:'flex', minHeight:0 }}>
          {/* Left tab list */}
          <div style={{ width:'9rem', flexShrink:0, borderRight:'1px solid var(--bd)', display:'flex', flexDirection:'column', padding:'0.5rem 0' }}>
            {tabs.map(({ id, label, icon: Icon }) => {
              const active = activeTab === id
              return (
                <button key={id} onClick={() => setActiveTab(id)} style={{
                  display:'flex', alignItems:'center', gap:'0.55rem',
                  padding:'0.6rem 0.875rem',
                  background: active ? `rgb(var(--accent)/0.08)` : 'transparent',
                  border:'none',
                  borderLeft: active ? `2px solid rgb(var(--accent))` : '2px solid transparent',
                  cursor:'pointer', transition:'all 0.12s', textAlign:'left',
                  color: active ? `rgb(var(--accent))` : 'var(--t2)',
                  fontFamily:'var(--font-display)', fontSize:'0.62rem',
                  letterSpacing:'0.14em', textTransform:'uppercase',
                }}>
                  <Icon size={12} />
                  {label}
                </button>
              )
            })}
          </div>

          {/* Right content */}
          <div style={{ flex:1, overflowY:'auto', padding:'1.1rem 1.25rem' }}>
            {activeTab === 'interface' && (
              <PanelInterface matrixEnabled={matrixEnabled} toggleMatrix={toggleMatrix} matrixSpeed={matrixSpeed} setMatrixSpeed={setMatrixSpeed} />
            )}
            {activeTab === 'apikeys' && <PanelApiKeys form={form} handleChange={handleChange} />}
            {activeTab === 'docker'  && <PanelDocker  form={form} handleChange={handleChange} />}
            {activeTab === 'tor'     && <PanelTor />}
            {activeTab === 'mcp'     && <PanelMcp />}
            {activeTab === 'skilllog' && <PanelSkillLog />}
          </div>
        </div>

        {/* Footer */}
        <div style={{ flexShrink:0, padding:'0.875rem 1.25rem', borderTop:'1px solid var(--bd)', display:'flex', justifyContent:'flex-end', gap:'0.6rem', background:'var(--surface)' }}>
          <button onClick={onClose} style={{
            padding:'0.4rem 1rem', background:'transparent', border:'1px solid var(--bd)',
            borderRadius:0, cursor:'pointer', fontFamily:'var(--font-display)', fontSize:'0.62rem',
            letterSpacing:'0.14em', textTransform:'uppercase', color:'var(--t2)', transition:'all 0.15s',
          }}
            onMouseEnter={e => { e.currentTarget.style.color='var(--t1)'; e.currentTarget.style.borderColor='var(--bd-2)' }}
            onMouseLeave={e => { e.currentTarget.style.color='var(--t2)'; e.currentTarget.style.borderColor='var(--bd)' }}
          >
            CANCEL
          </button>
          <button onClick={handleSave} style={{
            display:'flex', alignItems:'center', gap:'0.4rem',
            padding:'0.4rem 1rem', background:`rgb(var(--accent)/0.12)`,
            border:`1px solid rgb(var(--accent)/0.45)`, borderRadius:0, cursor:'pointer',
            fontFamily:'var(--font-display)', fontSize:'0.62rem',
            letterSpacing:'0.14em', textTransform:'uppercase', color:`rgb(var(--accent))`, transition:'background 0.15s',
          }}
            onMouseEnter={e => e.currentTarget.style.background=`rgb(var(--accent)/0.22)`}
            onMouseLeave={e => e.currentTarget.style.background=`rgb(var(--accent)/0.12)`}
          >
            <Save size={13} /> SAVE CONFIG
          </button>
        </div>
      </div>
    </div>
  )
}

export default SettingsModal
