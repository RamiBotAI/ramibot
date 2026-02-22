import { useEffect, useRef, useState, useCallback } from 'react'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import { WebLinksAddon } from '@xterm/addon-web-links'
import '@xterm/xterm/css/xterm.css'
import useStore from '../store'
import { X, RotateCw, Terminal as TermIcon, Wifi, WifiOff, Shield } from 'lucide-react'

const API = '/api/terminal'
const INPUT_BATCH_MS = 30

// Returns the export PS1 command for the given tor/team state
const buildPS1Cmd = (tor, team) => {
  const color = tor ? '35' : team === 'red' ? '31' : '34'
  return `export PS1='\\[\\e[${color}m\\]\\u@\\h:\\w\\$\\[\\e[0m\\] '\r`
}

function DockerTerminal({ terminalId, onClose }) {
  const termRef = useRef(null)
  const termInstance = useRef(null)
  const fitAddon = useRef(null)
  const sessionRef = useRef(null)
  const sseRef = useRef(null)
  const disposed = useRef(false)
  const inputBuffer = useRef('')
  const inputTimer = useRef(null)
  const [connected, setConnected] = useState(false)
  const [connecting, setConnecting] = useState(false)
  const [torActive, setTorActive] = useState(false)
  const [torLoading, setTorLoading] = useState(false)
  const { dockerContainer, teamMode, setTorActive: setGlobalTorActive, torActive: globalTorActive } = useStore()
  const globalTorRef = useRef(globalTorActive)
  const teamModeRef = useRef(teamMode)
  const connectedRef = useRef(false)

  // Match CSS variable accent colors exactly
  const teamColor = teamMode === 'red' ? '#ff3250' : teamMode === 'blue' ? '#00b8ff' : '#22c55e'

  const flushInput = useCallback(async () => {
    const sid = sessionRef.current
    const buf = inputBuffer.current
    if (!sid || !buf) return
    inputBuffer.current = ''
    const b64 = btoa(buf)
    try {
      await fetch(`${API}/input`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: sid, data: b64 }),
      })
    } catch {}
  }, [])

  const sendRawInput = useCallback(async (text) => {
    const sid = sessionRef.current
    if (!sid) return
    try {
      const b64 = btoa(text)
      await fetch(`${API}/input`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: sid, data: b64 }),
      })
    } catch {}
  }, [])

  const sendInput = useCallback((data) => {
    inputBuffer.current += data
    if (inputTimer.current) clearTimeout(inputTimer.current)
    inputTimer.current = setTimeout(flushInput, INPUT_BATCH_MS)
  }, [flushInput])

  const sendResize = useCallback(async (cols, rows) => {
    const sid = sessionRef.current
    if (!sid) return
    try {
      await fetch(`${API}/resize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: sid, cols, rows }),
      })
    } catch {}
  }, [])

  const closeSSE = useCallback(() => {
    if (sseRef.current) {
      sseRef.current.close()
      sseRef.current = null
    }
  }, [])

  const fetchTorStatus = useCallback(async () => {
    try {
      const res = await fetch('/api/docker/tor')
      if (res.ok) {
        const data = await res.json()
        const active = data.running && data.transparent_proxy
        setTorActive(active)
        setGlobalTorActive(active)
      }
    } catch {}
  }, [setGlobalTorActive])

  const startSession = useCallback(async () => {
    if (disposed.current) return
    setConnecting(true)

    // Stop any previous session
    closeSSE()
    if (sessionRef.current) {
      try {
        await fetch(`${API}/stop`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ session_id: sessionRef.current }),
        })
      } catch {}
      sessionRef.current = null
    }

    try {
      const res = await fetch(`${API}/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ container: dockerContainer || undefined }),
      })
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: 'Connection failed' }))
        if (termInstance.current) {
          termInstance.current.write(`\r\n\x1b[31m${err.detail}\x1b[0m\r\n`)
        }
        setConnecting(false)
        return
      }
      const { session_id, info } = await res.json()
      sessionRef.current = session_id

      // Print info messages (e.g. container was started)
      if (termInstance.current && info) {
        for (const msg of info) {
          termInstance.current.write(`\x1b[33m${msg}\x1b[0m\r\n`)
        }
      }

      // Send initial resize
      if (termInstance.current) {
        const { cols, rows } = termInstance.current
        sendResize(cols, rows)
      }

      // Start SSE stream using native EventSource
      const es = new EventSource(`${API}/stream?session_id=${session_id}`)
      sseRef.current = es

      es.addEventListener('output', (e) => {
        try {
          const { b64 } = JSON.parse(e.data)
          if (b64 && termInstance.current) {
            const bytes = Uint8Array.from(atob(b64), c => c.charCodeAt(0))
            termInstance.current.write(bytes)
          }
        } catch {}
      })

      es.addEventListener('exit', () => {
        closeSSE()
        setConnected(false)
        connectedRef.current = false
      })

      es.onopen = () => {
        if (disposed.current) { es.close(); return }
        setConnected(true)
        setConnecting(false)
        connectedRef.current = true
        fetchTorStatus()
        // Always apply team/tor colored PS1 when terminal connects
        setTimeout(() => {
          sendRawInput(buildPS1Cmd(globalTorRef.current, teamModeRef.current))
        }, 800)
      }

      es.onerror = () => {
        setConnected(false)
        setConnecting(false)
      }
    } catch (e) {
      if (termInstance.current) {
        termInstance.current.write(`\r\n\x1b[31mConnection error: ${e.message}\x1b[0m\r\n`)
      }
      setConnected(false)
      setConnecting(false)
    }
  }, [dockerContainer, sendResize, closeSSE, fetchTorStatus])

  const reconnect = useCallback(() => {
    if (termInstance.current) {
      termInstance.current.clear()
    }
    startSession()
  }, [startSession])

  const toggleTor = useCallback(async () => {
    if (torLoading) return
    setTorLoading(true)
    const action = torActive ? 'stop' : 'start'
    try {
      const res = await fetch('/api/docker/tor', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action }),
      })
      const data = await res.json()
      if (!res.ok) {
        const msg = data.detail || 'Tor toggle failed'
        if (termInstance.current) {
          termInstance.current.write(`\r\n\x1b[31m[Tor] ${msg}\x1b[0m\r\n`)
        }
      } else {
        const active = data.running && data.transparent_proxy
        setTorActive(active)
        setGlobalTorActive(active)
        if (termInstance.current) {
          const status = data.running ? 'ON — transparent proxy active' : 'OFF'
          termInstance.current.write(`\r\n\x1b[36m[Tor] ${status}\x1b[0m\r\n`)
        }
      }
    } catch (e) {
      if (termInstance.current) {
        termInstance.current.write(`\r\n\x1b[31m[Tor] ${e.message}\x1b[0m\r\n`)
      }
    } finally {
      setTorLoading(false)
    }
  }, [torActive, torLoading, sendRawInput])

  // Keep refs in sync
  useEffect(() => { globalTorRef.current = globalTorActive }, [globalTorActive])
  useEffect(() => { teamModeRef.current = teamMode }, [teamMode])
  useEffect(() => { connectedRef.current = connected }, [connected])

  // Re-apply PS1 whenever Tor or team mode changes
  useEffect(() => {
    if (!sessionRef.current) return
    sendRawInput('\x03\r' + buildPS1Cmd(globalTorActive, teamMode))
  }, [globalTorActive, teamMode, sendRawInput])

  useEffect(() => {
    if (!termRef.current) return
    disposed.current = false

    const term = new Terminal({
      cursorBlink: true,
      cursorStyle: 'block',
      fontFamily: "'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace",
      fontSize: 13,
      theme: {
        background: '#07070b',
        foreground: '#dcdcf0',
        cursor: teamColor,
        cursorAccent: '#07070b',
        selectionBackground: teamColor + '33',
        black: '#0d0d16',
        red: '#ff3250',
        green: '#22c55e',
        yellow: '#eab308',
        blue: '#00b8ff',
        magenta: '#a855f7',
        cyan: '#00e6c8',
        white: '#dcdcf0',
        brightBlack: '#585890',
        brightRed: '#ff6075',
        brightGreen: '#4ade80',
        brightYellow: '#facc15',
        brightBlue: '#33ccff',
        brightMagenta: '#c084fc',
        brightCyan: '#33edda',
        brightWhite: '#f0f0ff',
      },
      allowProposedApi: true,
    })

    const fit = new FitAddon()
    fitAddon.current = fit
    term.loadAddon(fit)
    term.loadAddon(new WebLinksAddon())

    term.open(termRef.current)
    fit.fit()
    termInstance.current = term

    // Send keyboard input via POST
    term.onData((data) => {
      sendInput(data)
    })

    // Send resize events via POST
    term.onResize(({ cols, rows }) => {
      sendResize(cols, rows)
    })

    // ResizeObserver to auto-fit
    const observer = new ResizeObserver(() => {
      try {
        fit.fit()
      } catch {}
    })
    observer.observe(termRef.current)

    // Start session
    startSession()

    return () => {
      disposed.current = true
      observer.disconnect()
      if (inputTimer.current) {
        clearTimeout(inputTimer.current)
        inputTimer.current = null
      }
      if (sseRef.current) {
        sseRef.current.close()
        sseRef.current = null
      }
      // Fire-and-forget stop
      const sid = sessionRef.current
      if (sid) {
        fetch(`${API}/stop`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ session_id: sid }),
        }).catch(() => {})
        sessionRef.current = null
      }
      term.dispose()
      termInstance.current = null
    }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps


  const btnStyle = {
    padding: '0.2rem 0.4rem',
    background: 'none',
    border: 'none',
    cursor: 'pointer',
    color: 'var(--t2)',
    display: 'flex',
    alignItems: 'center',
    transition: 'color 0.15s',
  }

  return (
    <div className="terminal-float" style={{
      display: 'flex', flexDirection: 'column', height: '100%',
      background: 'rgb(var(--accent) / 0.07)',
      border: '2px solid rgb(var(--accent) / 0.6)',
      borderLeft: '3px solid rgb(var(--accent))',
      borderRight: '3px solid rgb(var(--accent))',
    }}>
      {/* Header */}
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '0.35rem 0.75rem',
        borderBottom: '2px solid rgb(var(--accent) / 0.35)',
        background: 'rgb(var(--accent) / 0.05)',
        flexShrink: 0,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', minWidth: 0 }}>
          <TermIcon size={13} style={{ color: `rgb(var(--accent))`, flexShrink: 0 }} />
          <span style={{
            fontFamily: 'var(--font-display)', fontSize: '0.6rem',
            letterSpacing: '0.14em', color: `rgb(var(--accent))`, fontWeight: 700,
            textTransform: 'uppercase', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
          }}>
            {dockerContainer || 'NO CONTAINER'}
          </span>
          <span style={{ color: 'var(--t3)', fontSize: '0.5rem' }}>──</span>
          {connected ? (
            <Wifi size={11} style={{ color: '#22c55e', flexShrink: 0 }} />
          ) : (
            <WifiOff size={11} style={{ color: '#ff3250', flexShrink: 0 }} />
          )}
          {connecting && (
            <span style={{ fontFamily: 'var(--font-display)', fontSize: '0.52rem', letterSpacing: '0.1em', color: '#eab308' }}>
              CONNECTING
            </span>
          )}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.15rem', flexShrink: 0 }}>
          <button
            onClick={toggleTor}
            disabled={torLoading || !connected}
            style={{
              ...btnStyle,
              color: torActive ? '#22c55e' : 'var(--t2)',
              opacity: (torLoading || !connected) ? 0.35 : 1,
            }}
            title={torActive ? 'Disable Tor transparent proxy' : 'Enable Tor transparent proxy'}
          >
            <Shield size={13} style={torLoading ? { animation: 'pulse-dot 1s infinite' } : {}} />
          </button>
          <button onClick={reconnect} style={btnStyle} title="Reconnect">
            <RotateCw size={12} />
          </button>
          <button onClick={onClose} style={btnStyle} title="Close terminal">
            <X size={12} />
          </button>
        </div>
      </div>
      {/* Terminal */}
      <div ref={termRef} style={{ flex: 1, minHeight: 0 }} />
    </div>
  )
}

export default DockerTerminal
