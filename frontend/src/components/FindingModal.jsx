import { useState } from 'react'
import { X, Flag, Save } from 'lucide-react'
import useStore from '../store'

const SEVERITIES = [
  { id: 'info',     label: 'INFO',     color: '#60a5fa' },
  { id: 'low',      label: 'LOW',      color: '#22c55e' },
  { id: 'medium',   label: 'MEDIUM',   color: '#fbbf24' },
  { id: 'high',     label: 'HIGH',     color: '#f97316' },
  { id: 'critical', label: 'CRITICAL', color: '#ff3250' },
]

function extractTarget(args) {
  if (!args) return ''
  try {
    const a = typeof args === 'string' ? JSON.parse(args) : args
    return a.target || a.host || a.ip || a.url || a.domain || a.address || ''
  } catch { return '' }
}

function extractText(result) {
  if (!result) return ''
  // MCP tool results: { content: [{ type: "text", text: "..." }] }
  if (result.content && Array.isArray(result.content)) {
    const parts = result.content
      .filter((c) => c.type === 'text' && c.text)
      .map((c) => c.text)
    if (parts.length) return parts.join('\n')
  }
  if (typeof result === 'string') return result
  return JSON.stringify(result, null, 2)
}

function cleanMcpText(text) {
  // If there's an EVIDENCE GATE, extract only its content — it's the clean summary.
  // Everything else (raw JSON output, TACTICAL CONTEXT docs) is noise for a finding.
  const gateMatch = text.match(/\[EVIDENCE GATE[^\]]*\]([\s\S]*?)\[END EVIDENCE GATE\]/i)
  if (gateMatch) {
    return gateMatch[1]
      .replace(/^LANGUAGE RULE:.*$/gm, '')
      .replace(/^IMPORTANT: Only the facts.*$/gm, '')
      .trim()
  }
  // No evidence gate: strip TACTICAL CONTEXT block and return the raw tool output
  return text
    .replace(/\[TACTICAL CONTEXT[^\]]*\][\s\S]*?(\[END TACTICAL CONTEXT\]|$)/g, '')
    .replace(/^LANGUAGE RULE:.*$/gm, '')
    .trim()
}

function truncateResult(result) {
  const raw = extractText(result)
  const str = cleanMcpText(raw)
  return str.length > 800 ? str.slice(0, 800) + '\n...' : str
}

function buildTitle(traceName, args) {
  const tool = traceName.includes('__') ? traceName.split('__')[1] : traceName
  const target = extractTarget(args)
  return target ? `${tool} → ${target}` : tool
}

const fieldStyle = {
  width: '100%',
  background: 'var(--surface-2)',
  border: '1px solid var(--bd)',
  borderRadius: 0,
  padding: '0.4rem 0.6rem',
  fontSize: '0.78rem',
  fontFamily: 'var(--font-mono)',
  color: 'var(--t1)',
  outline: 'none',
  boxSizing: 'border-box',
}

function FindingModal({ trace, onClose }) {
  const createFinding = useStore((s) => s.createFinding)
  const currentConversation = useStore((s) => s.currentConversation)

  const [title, setTitle] = useState(buildTitle(trace.name, trace.arguments))
  const [severity, setSeverity] = useState('medium')
  const [description, setDescription] = useState(truncateResult(trace.result))
  const [target, setTarget] = useState(extractTarget(trace.arguments))
  const [saving, setSaving] = useState(false)
  const [saved, setSaved] = useState(false)

  const handleSave = async () => {
    if (!title.trim()) return
    setSaving(true)
    await createFinding({
      conversation_id: currentConversation?.id || null,
      tool: trace.name,
      severity,
      title: title.trim(),
      description: description.trim(),
      target: target.trim(),
    })
    setSaving(false)
    setSaved(true)
    setTimeout(onClose, 600)
  }

  const handleBackdrop = (e) => { if (e.target === e.currentTarget) onClose() }

  return (
    <div
      onClick={handleBackdrop}
      style={{
        position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)',
        display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 100,
      }}
    >
      <div style={{
        background: 'var(--surface)', border: '1px solid var(--bd)',
        width: '100%', maxWidth: '30rem', margin: '1rem',
        display: 'flex', flexDirection: 'column',
        boxShadow: '0 0 60px rgba(0,0,0,0.85)',
      }}>
        {/* Header */}
        <div style={{
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          padding: '0.75rem 1rem', borderBottom: '1px solid var(--bd)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Flag size={13} style={{ color: `rgb(var(--accent))` }} />
            <span style={{
              fontFamily: 'var(--font-display)', fontSize: '0.65rem',
              fontWeight: 700, letterSpacing: '0.2em', textTransform: 'uppercase',
              color: 'var(--t1)',
            }}>
              Save Finding
            </span>
          </div>
          <button
            onClick={onClose}
            style={{ background: 'none', border: 'none', color: 'var(--t2)', cursor: 'pointer', padding: '0.2rem', lineHeight: 0 }}
            onMouseEnter={e => e.currentTarget.style.color = 'var(--t1)'}
            onMouseLeave={e => e.currentTarget.style.color = 'var(--t2)'}
          >
            <X size={15} />
          </button>
        </div>

        {/* Body */}
        <div style={{ padding: '1rem', display: 'flex', flexDirection: 'column', gap: '0.75rem', overflowY: 'auto', maxHeight: '70vh' }}>
          {/* Title */}
          <div>
            <label style={{
              display: 'block', fontFamily: 'var(--font-display)', fontSize: '0.52rem',
              letterSpacing: '0.14em', textTransform: 'uppercase', color: 'var(--t2)',
              marginBottom: '0.3rem',
            }}>Title</label>
            <input
              type="text"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              style={fieldStyle}
              onFocus={(e) => { e.target.style.borderColor = `rgb(var(--accent)/0.6)` }}
              onBlur={(e) => { e.target.style.borderColor = 'var(--bd)' }}
            />
          </div>

          {/* Severity */}
          <div>
            <label style={{
              display: 'block', fontFamily: 'var(--font-display)', fontSize: '0.52rem',
              letterSpacing: '0.14em', textTransform: 'uppercase', color: 'var(--t2)',
              marginBottom: '0.3rem',
            }}>Severity</label>
            <div style={{ display: 'flex', gap: '0.35rem' }}>
              {SEVERITIES.map(({ id, label, color }) => (
                <button
                  key={id}
                  onClick={() => setSeverity(id)}
                  style={{
                    flex: 1,
                    padding: '0.3rem 0',
                    background: severity === id ? `${color}18` : 'transparent',
                    border: `1px solid ${severity === id ? color : 'var(--bd)'}`,
                    borderRadius: 0,
                    color: severity === id ? color : 'var(--t3)',
                    fontFamily: 'var(--font-display)', fontSize: '0.5rem',
                    letterSpacing: '0.1em', textTransform: 'uppercase',
                    cursor: 'pointer', transition: 'all 0.12s',
                  }}
                >
                  {label}
                </button>
              ))}
            </div>
          </div>

          {/* Target */}
          <div>
            <label style={{
              display: 'block', fontFamily: 'var(--font-display)', fontSize: '0.52rem',
              letterSpacing: '0.14em', textTransform: 'uppercase', color: 'var(--t2)',
              marginBottom: '0.3rem',
            }}>Target</label>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="IP / host / URL"
              style={fieldStyle}
              onFocus={(e) => { e.target.style.borderColor = `rgb(var(--accent)/0.6)` }}
              onBlur={(e) => { e.target.style.borderColor = 'var(--bd)' }}
            />
          </div>

          {/* Description */}
          <div>
            <label style={{
              display: 'block', fontFamily: 'var(--font-display)', fontSize: '0.52rem',
              letterSpacing: '0.14em', textTransform: 'uppercase', color: 'var(--t2)',
              marginBottom: '0.3rem',
            }}>Description / Evidence</label>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={6}
              style={{ ...fieldStyle, resize: 'vertical', lineHeight: 1.5, maxHeight: '14rem', overflowY: 'auto' }}
              onFocus={(e) => { e.target.style.borderColor = `rgb(var(--accent)/0.6)` }}
              onBlur={(e) => { e.target.style.borderColor = 'var(--bd)' }}
            />
          </div>
        </div>

        {/* Footer */}
        <div style={{
          padding: '0.75rem 1rem', borderTop: '1px solid var(--bd)',
          display: 'flex', justifyContent: 'flex-end', gap: '0.5rem',
        }}>
          <button
            onClick={onClose}
            style={{
              padding: '0.35rem 0.85rem', background: 'transparent',
              border: '1px solid var(--bd)', borderRadius: 0, cursor: 'pointer',
              fontFamily: 'var(--font-display)', fontSize: '0.58rem',
              letterSpacing: '0.14em', textTransform: 'uppercase', color: 'var(--t2)',
            }}
            onMouseEnter={e => e.currentTarget.style.color = 'var(--t1)'}
            onMouseLeave={e => e.currentTarget.style.color = 'var(--t2)'}
          >
            CANCEL
          </button>
          <button
            onClick={handleSave}
            disabled={saving || saved}
            style={{
              display: 'flex', alignItems: 'center', gap: '0.4rem',
              padding: '0.35rem 0.85rem',
              background: saved ? 'rgba(34,197,94,0.12)' : `rgb(var(--accent)/0.12)`,
              border: saved ? '1px solid rgba(34,197,94,0.5)' : `1px solid rgb(var(--accent)/0.45)`,
              borderRadius: 0, cursor: saving || saved ? 'default' : 'pointer',
              fontFamily: 'var(--font-display)', fontSize: '0.58rem',
              letterSpacing: '0.14em', textTransform: 'uppercase',
              color: saved ? '#22c55e' : `rgb(var(--accent))`,
              opacity: saving ? 0.6 : 1, transition: 'all 0.15s',
            }}
          >
            <Save size={12} />
            {saved ? 'SAVED' : saving ? 'SAVING...' : 'SAVE FINDING'}
          </button>
        </div>
      </div>
    </div>
  )
}

export default FindingModal
