import { useState } from 'react'
import { Wrench, ChevronDown, ChevronRight, Loader } from 'lucide-react'

function ToolTrace({ traces }) {
  const [expanded, setExpanded] = useState(false)
  if (!traces || traces.length === 0) return null

  return (
    <div style={{ marginTop: '0.875rem' }}>
      <button
        onClick={() => setExpanded(!expanded)}
        style={{
          display: 'flex', alignItems: 'center', gap: '0.45rem',
          background: 'none', border: 'none', cursor: 'pointer',
          fontFamily: 'var(--font-display)', fontSize: '0.58rem',
          letterSpacing: '0.16em', textTransform: 'uppercase',
          color: 'var(--t2)', padding: '0.2rem 0',
          transition: 'color 0.15s',
        }}
        onMouseEnter={e => e.currentTarget.style.color = 'var(--t1)'}
        onMouseLeave={e => e.currentTarget.style.color = 'var(--t2)'}
      >
        <Wrench size={10} />
        {traces.length} EXEC{traces.length > 1 ? 'S' : ''}
        {expanded ? <ChevronDown size={10} /> : <ChevronRight size={10} />}
      </button>

      {expanded && (
        <div style={{ marginTop: '0.5rem', display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
          {traces.map((trace, idx) => (
            <TraceItem key={trace.id || idx} trace={trace} />
          ))}
        </div>
      )}
    </div>
  )
}

function TraceItem({ trace }) {
  const [showDetails, setShowDetails] = useState(false)

  const statusColor = trace.status === 'done'
    ? '#22c55e'
    : trace.status === 'error'
    ? '#ff3250'
    : '#fbbf24'

  const statusSymbol = trace.status === 'done' ? '✓' : trace.status === 'error' ? '✗' : null

  const formatJSON = (data) => {
    if (!data) return 'null'
    if (typeof data === 'string') {
      try { return JSON.stringify(JSON.parse(data), null, 2) }
      catch { return data }
    }
    return JSON.stringify(data, null, 2)
  }

  return (
    <div style={{
      border: '1px solid var(--bd)',
      borderLeft: `2px solid ${statusColor}`,
      fontFamily: 'var(--font-mono)', fontSize: '0.72rem',
      background: 'var(--surface)',
    }}>
      <button
        onClick={() => setShowDetails(!showDetails)}
        style={{
          display: 'flex', alignItems: 'center', gap: '0.55rem',
          width: '100%', textAlign: 'left',
          background: 'none', border: 'none', cursor: 'pointer',
          padding: '0.4rem 0.6rem',
          transition: 'background 0.12s',
        }}
        onMouseEnter={e => e.currentTarget.style.background = 'var(--surface-2)'}
        onMouseLeave={e => e.currentTarget.style.background = 'none'}
      >
        <span style={{ color: statusColor, flexShrink: 0, lineHeight: 0, display: 'flex', alignItems: 'center' }}>
          {trace.status === 'calling'
            ? <Loader size={11} className="animate-spin" />
            : <span style={{ fontSize: '0.75rem' }}>{statusSymbol}</span>
          }
        </span>
        <span style={{ color: 'var(--t1)', flex: 1 }}>{trace.name}</span>
        {showDetails ? <ChevronDown size={10} style={{ color: 'var(--t2)', flexShrink: 0 }} /> : <ChevronRight size={10} style={{ color: 'var(--t2)', flexShrink: 0 }} />}
      </button>

      {showDetails && (
        <div style={{ borderTop: '1px solid var(--bd)', padding: '0.5rem 0.6rem', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          {trace.arguments && (
            <div>
              <div style={{
                fontFamily: 'var(--font-display)', fontSize: '0.52rem',
                letterSpacing: '0.14em', textTransform: 'uppercase',
                color: 'var(--t3)', marginBottom: '0.3rem',
              }}>
                ARGS
              </div>
              <pre style={{
                background: 'var(--bg)', padding: '0.5rem',
                overflowX: 'auto', whiteSpace: 'pre-wrap',
                color: 'var(--t2)', fontSize: '0.7rem', margin: 0,
                border: '1px solid var(--bd)', borderRadius: 0,
                fontFamily: 'var(--font-mono)',
              }}>
                {formatJSON(trace.arguments)}
              </pre>
            </div>
          )}
          {trace.result !== undefined && (
            <div>
              <div style={{
                fontFamily: 'var(--font-display)', fontSize: '0.52rem',
                letterSpacing: '0.14em', textTransform: 'uppercase',
                color: 'var(--t3)', marginBottom: '0.3rem',
              }}>
                RESULT
              </div>
              <pre style={{
                background: 'var(--bg)', padding: '0.5rem',
                overflowX: 'auto', whiteSpace: 'pre-wrap',
                color: 'var(--t2)', fontSize: '0.7rem', margin: 0,
                maxHeight: '12rem', overflowY: 'auto',
                border: '1px solid var(--bd)', borderRadius: 0,
                fontFamily: 'var(--font-mono)',
              }}>
                {formatJSON(trace.result)}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default ToolTrace
