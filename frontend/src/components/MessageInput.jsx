import { useState, useRef, useEffect } from 'react'
import useStore from '../store'
import { Send, Square } from 'lucide-react'

function MessageInput() {
  const [input, setInput] = useState('')
  const textareaRef = useRef(null)
  const { isStreaming, sendMessageStream, stopStreaming } = useStore()

  useEffect(() => {
    textareaRef.current?.focus()
  }, [isStreaming])

  const handleSubmit = () => {
    const trimmed = input.trim()
    if (!trimmed || isStreaming) return
    setInput('')
    sendMessageStream(trimmed)
  }

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSubmit()
    }
  }

  const adjustHeight = () => {
    const el = textareaRef.current
    if (!el) return
    el.style.height = 'auto'
    el.style.height = Math.min(el.scrollHeight, 200) + 'px'
  }

  return (
    <div
      style={{
        display: 'flex', alignItems: 'flex-end', gap: 0,
        border: '1px solid var(--bd)',
        background: 'var(--surface-2)',
        transition: 'border-color 0.15s',
      }}
      onFocusCapture={e => e.currentTarget.style.borderColor = `rgb(var(--accent) / 0.5)`}
      onBlurCapture={e => e.currentTarget.style.borderColor = 'var(--bd)'}
    >
      {/* Prompt indicator */}
      <div style={{
        padding: '0.75rem 0.6rem 0.75rem 0.75rem',
        fontFamily: 'var(--font-display)', fontSize: '0.75rem',
        color: `rgb(var(--accent) / ${isStreaming ? '0.3' : '0.8'})`,
        flexShrink: 0, alignSelf: 'flex-start',
        transition: 'color 0.2s',
        userSelect: 'none',
      }}>
        ▶
      </div>

      {/* Textarea */}
      <textarea
        ref={textareaRef}
        value={input}
        onChange={(e) => { setInput(e.target.value); adjustHeight() }}
        onKeyDown={handleKeyDown}
        placeholder="enter command..."
        disabled={isStreaming}
        rows={1}
        style={{
          flex: 1, resize: 'none',
          background: 'transparent', border: 'none', outline: 'none',
          padding: '0.72rem 0',
          fontSize: '0.82rem', fontFamily: 'var(--font-mono)',
          color: 'var(--t1)', lineHeight: 1.55,
          maxHeight: '200px',
          opacity: isStreaming ? 0.45 : 1,
          letterSpacing: '0.02em',
        }}
        className="scrollbar-none"
      />

      {/* Action button */}
      <div style={{ padding: '0.5rem', flexShrink: 0, alignSelf: 'flex-end' }}>
        {isStreaming ? (
          <button
            onClick={stopStreaming}
            style={{
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              width: '1.85rem', height: '1.85rem',
              background: 'rgba(255, 50, 80, 0.12)',
              border: '1px solid rgba(255, 50, 80, 0.45)',
              borderRadius: 0, color: '#ff3250', cursor: 'pointer',
              transition: 'background 0.15s',
            }}
            onMouseEnter={e => e.currentTarget.style.background = 'rgba(255, 50, 80, 0.22)'}
            onMouseLeave={e => e.currentTarget.style.background = 'rgba(255, 50, 80, 0.12)'}
            title="Stop generating"
          >
            <Square size={14} fill="currentColor" />
          </button>
        ) : (
          <button
            onClick={handleSubmit}
            disabled={!input.trim()}
            style={{
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              width: '1.85rem', height: '1.85rem',
              background: input.trim() ? `rgb(var(--accent) / 0.12)` : 'transparent',
              border: input.trim() ? `1px solid rgb(var(--accent) / 0.45)` : '1px solid var(--bd)',
              borderRadius: 0,
              color: input.trim() ? `rgb(var(--accent))` : 'var(--t3)',
              cursor: input.trim() ? 'pointer' : 'not-allowed',
              transition: 'all 0.15s',
            }}
            onMouseEnter={e => { if (input.trim()) e.currentTarget.style.background = `rgb(var(--accent) / 0.22)` }}
            onMouseLeave={e => { if (input.trim()) e.currentTarget.style.background = `rgb(var(--accent) / 0.12)` }}
            title="Send message"
          >
            <Send size={14} />
          </button>
        )}
      </div>
    </div>
  )
}

export default MessageInput
