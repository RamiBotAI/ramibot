import { useEffect, useRef, useState } from 'react'
import { ShieldAlert } from 'lucide-react'
import useStore from '../store'

const TIMEOUT_S = 120

const RISK_COLORS = {
  low:      '#22c55e',
  medium:   '#fbbf24',
  high:     '#f97316',
  critical: '#ff3250',
}

const KEY_ARGS = ['target', 'host', 'url', 'port', 'ports', 'username', 'user', 'command', 'path']

function getRiskColor(level) {
  return RISK_COLORS[level] || RISK_COLORS.medium
}

function pickKeyArgs(args) {
  if (!args || typeof args !== 'object') return []
  const entries = Object.entries(args)
  const priority = entries.filter(([k]) => KEY_ARGS.includes(k.toLowerCase()))
  const rest = entries.filter(([k]) => !KEY_ARGS.includes(k.toLowerCase()))
  return [...priority, ...rest].slice(0, 4)
}

function ToolApprovalBanner() {
  const { pendingApproval, respondToApproval } = useStore()
  const [secondsLeft, setSecondsLeft] = useState(TIMEOUT_S)
  const [timedOut, setTimedOut] = useState(false)
  const intervalRef = useRef(null)

  useEffect(() => {
    if (!pendingApproval) return
    const start = pendingApproval.startedAt
    setTimedOut(false)

    intervalRef.current = setInterval(() => {
      const elapsed = Math.floor((Date.now() - start) / 1000)
      const remaining = Math.max(0, TIMEOUT_S - elapsed)
      setSecondsLeft(remaining)
      if (remaining === 0) {
        clearInterval(intervalRef.current)
        setTimedOut(true)
      }
    }, 250)

    return () => clearInterval(intervalRef.current)
  }, [pendingApproval])

  if (!pendingApproval) return null

  const { toolName, arguments: args, riskLevel } = pendingApproval
  const shortName = toolName.includes('__') ? toolName.split('__')[1] : toolName
  const color = getRiskColor(riskLevel)
  const keyArgs = pickKeyArgs(args)
  const pct = (secondsLeft / TIMEOUT_S) * 100
  const timerRed = secondsLeft <= 15

  return (
    <div style={{
      margin: '0 1.5rem 0.75rem',
      maxWidth: '52rem',
      marginLeft: 'auto',
      marginRight: 'auto',
      border: `1px solid ${color}55`,
      background: `${color}08`,
      position: 'relative',
      overflow: 'hidden',
    }}>
      {/* Progress bar on bottom edge */}
      <div style={{
        position: 'absolute', bottom: 0, left: 0,
        height: '2px',
        width: `${pct}%`,
        background: timerRed ? '#ff3250' : color,
        transition: 'width 0.25s linear, background 0.3s',
      }} />

      {/* Header */}
      <div style={{
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '0.55rem 0.75rem 0.4rem',
        borderBottom: `1px solid ${color}30`,
      }}>
        <div style={{
          display: 'flex', alignItems: 'center', gap: '0.45rem',
          fontFamily: 'var(--font-display)', fontSize: '0.6rem',
          letterSpacing: '0.16em', textTransform: 'uppercase',
          color,
        }}>
          <ShieldAlert size={12} />
          TOOL APPROVAL REQUIRED
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
          {/* Risk badge */}
          <span style={{
            fontFamily: 'var(--font-display)', fontSize: '0.52rem',
            letterSpacing: '0.12em', textTransform: 'uppercase',
            color,
            border: `1px solid ${color}55`,
            padding: '0.1rem 0.4rem',
          }}>
            {(riskLevel || 'medium').toUpperCase()}
          </span>

          {/* Countdown */}
          {timedOut ? (
            <span style={{
              fontFamily: 'var(--font-display)', fontSize: '0.55rem',
              letterSpacing: '0.1em', color: '#ff3250',
            }}>
              TIMED OUT — AUTO-DENIED
            </span>
          ) : (
            <span style={{
              fontFamily: 'var(--font-mono)', fontSize: '0.65rem',
              color: timerRed ? '#ff3250' : 'var(--t2)',
              minWidth: '2.2rem', textAlign: 'right',
              transition: 'color 0.3s',
            }}>
              {secondsLeft}s
            </span>
          )}
        </div>
      </div>

      {/* Body: tool name + args */}
      <div style={{ padding: '0.5rem 0.75rem' }}>
        <div style={{
          fontFamily: 'var(--font-mono)', fontSize: '0.72rem',
          color: 'var(--t1)', marginBottom: keyArgs.length > 0 ? '0.4rem' : 0,
        }}>
          {shortName}
        </div>

        {keyArgs.length > 0 && (
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem' }}>
            {keyArgs.map(([k, v]) => (
              <span key={k} style={{
                fontFamily: 'var(--font-mono)', fontSize: '0.6rem',
                color: 'var(--t2)',
                background: 'var(--surface-2)',
                border: '1px solid var(--bd)',
                padding: '0.1rem 0.4rem',
              }}>
                <span style={{ color: 'var(--t3)' }}>{k}=</span>
                {String(v).length > 40 ? String(v).slice(0, 40) + '…' : String(v)}
              </span>
            ))}
          </div>
        )}
      </div>

      {/* Footer: buttons */}
      <div style={{
        display: 'flex', gap: '0.5rem',
        padding: '0.4rem 0.75rem 0.55rem',
        justifyContent: 'flex-end',
      }}>
        <button
          disabled={timedOut}
          onClick={() => respondToApproval(false)}
          style={{
            fontFamily: 'var(--font-display)', fontSize: '0.6rem',
            letterSpacing: '0.14em', textTransform: 'uppercase',
            padding: '0.3rem 0.8rem',
            background: timedOut ? 'transparent' : 'rgba(255,50,80,0.08)',
            border: '1px solid rgba(255,50,80,0.4)',
            color: timedOut ? 'var(--t3)' : '#ff3250',
            cursor: timedOut ? 'not-allowed' : 'pointer',
            borderRadius: 0,
            transition: 'background 0.15s',
          }}
          onMouseEnter={e => { if (!timedOut) e.currentTarget.style.background = 'rgba(255,50,80,0.16)' }}
          onMouseLeave={e => { if (!timedOut) e.currentTarget.style.background = 'rgba(255,50,80,0.08)' }}
        >
          DENY
        </button>

        <button
          disabled={timedOut}
          onClick={() => respondToApproval(true)}
          style={{
            fontFamily: 'var(--font-display)', fontSize: '0.6rem',
            letterSpacing: '0.14em', textTransform: 'uppercase',
            padding: '0.3rem 0.8rem',
            background: timedOut ? 'transparent' : `${color}18`,
            border: `1px solid ${color}55`,
            color: timedOut ? 'var(--t3)' : color,
            cursor: timedOut ? 'not-allowed' : 'pointer',
            borderRadius: 0,
            transition: 'background 0.15s',
          }}
          onMouseEnter={e => { if (!timedOut) e.currentTarget.style.background = `${color}30` }}
          onMouseLeave={e => { if (!timedOut) e.currentTarget.style.background = `${color}18` }}
        >
          APPROVE
        </button>
      </div>
    </div>
  )
}

export default ToolApprovalBanner
