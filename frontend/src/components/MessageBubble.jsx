import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import rehypeHighlight from 'rehype-highlight'
import { useState } from 'react'
import { Copy, Check, ChevronRight, ChevronDown, Brain } from 'lucide-react'
import useStore from '../store'
import ToolTrace from './ToolTrace'


function parseThinkBlocks(content, isStreaming = false) {
  if (!content) return { thinking: null, rest: content, isThinking: false }

  const thinkRegex = /<think>([\s\S]*?)<\/think>/g
  const thinkParts = []
  let match
  while ((match = thinkRegex.exec(content)) !== null) {
    thinkParts.push(match[1].trim())
  }
  let rest = content.replace(/<think>[\s\S]*?<\/think>\s*/g, '')

  let isThinking = false
  const openIdx = rest.lastIndexOf('<think>')
  if (openIdx !== -1) {
    thinkParts.push(rest.slice(openIdx + 7).trim())
    rest = rest.slice(0, openIdx)
    isThinking = true
  }

  return {
    thinking: thinkParts.length > 0 ? thinkParts.join('\n\n') : null,
    rest: rest.trim(),
    isThinking,
  }
}


function ThinkingBlock({ content, isThinking = false }) {
  const [expanded, setExpanded] = useState(false)

  return (
    <div style={{ marginBottom: '0.75rem' }}>
      <button
        onClick={() => setExpanded(!expanded)}
        style={{
          display: 'flex', alignItems: 'center', gap: '0.45rem',
          background: 'none', border: 'none', cursor: 'pointer',
          fontFamily: 'var(--font-display)', fontSize: '0.58rem',
          letterSpacing: '0.16em', textTransform: 'uppercase',
          color: '#8b5cf6', padding: '0.2rem 0',
        }}
      >
        {expanded ? <ChevronDown size={10} /> : <ChevronRight size={10} />}
        <Brain size={10} />
        {isThinking ? 'PROCESSING' : 'REASONING'}
        {isThinking && (
          <span style={{ display: 'flex', gap: '0.25rem', marginLeft: '0.2rem' }}>
            <span className="streaming-dot" style={{ width: '4px', height: '4px', borderRadius: '50%', background: '#8b5cf6' }} />
            <span className="streaming-dot" style={{ width: '4px', height: '4px', borderRadius: '50%', background: '#8b5cf6' }} />
            <span className="streaming-dot" style={{ width: '4px', height: '4px', borderRadius: '50%', background: '#8b5cf6' }} />
          </span>
        )}
      </button>
      {expanded && (
        <div style={{
          marginTop: '0.4rem', paddingLeft: '0.75rem',
          borderLeft: '2px solid rgba(139, 92, 246, 0.3)',
          fontSize: '0.76rem', color: 'var(--t2)',
          fontFamily: 'var(--font-mono)',
          whiteSpace: 'pre-wrap', lineHeight: 1.65,
          maxHeight: '12rem', overflowY: 'auto',
        }}>
          {content}
        </div>
      )}
    </div>
  )
}


function CodeBlock({ children, className, ...props }) {
  const [copied, setCopied] = useState(false)

  const handleCopy = () => {
    const text = String(children).replace(/\n$/, '')
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }

  return (
    <>
      <code className={className} {...props}>{children}</code>
      <button
        onClick={handleCopy}
        className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition-opacity"
        style={{
          padding: '0.25rem 0.45rem',
          background: 'var(--surface-3)',
          border: '1px solid var(--bd)',
          borderRadius: 0,
          cursor: 'pointer',
          color: 'var(--t2)',
          fontFamily: 'var(--font-display)',
          fontSize: '0.5rem', letterSpacing: '0.1em',
          display: 'flex', alignItems: 'center', gap: '0.25rem',
        }}
        title="Copy"
      >
        {copied
          ? <Check size={11} style={{ color: '#22c55e' }} />
          : <Copy size={11} />
        }
      </button>
    </>
  )
}


function MessageBubble({ message, isStreaming = false }) {
  const isUser = message.role === 'user'

  const { thinking, rest, isThinking } = isUser
    ? { thinking: null, rest: message.content, isThinking: false }
    : parseThinkBlocks(message.content, isStreaming)

  const time = message.created_at
    ? new Date(message.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
    : ''

  if (isUser) {
    return (
      <div className="fade-in" style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: '1.5rem' }}>
        <div style={{
          maxWidth: '78%',
          borderRight: `2px solid rgb(var(--accent))`,
          paddingRight: '0.875rem',
          paddingLeft: '0.875rem',
          paddingTop: '0.6rem',
          paddingBottom: '0.6rem',
          background: 'rgb(var(--accent) / 0.07)',
          borderTop: '1px solid rgb(var(--accent) / 0.15)',
          borderBottom: '1px solid rgb(var(--accent) / 0.15)',
        }}>
          {/* Header */}
          <div style={{
            display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: '0.5rem',
            marginBottom: '0.4rem',
            fontFamily: 'var(--font-display)', fontSize: '0.56rem', letterSpacing: '0.16em',
          }}>
            {time && <span style={{ color: 'var(--t3)' }}>{time}</span>}
            <span style={{ color: 'var(--t3)', fontSize: '0.5rem' }}>──────</span>
            <span style={{ color: `rgb(var(--accent))`, fontWeight: 700 }}>OPERATOR</span>
          </div>
          {/* Content */}
          <div style={{
            fontFamily: 'var(--font-mono)', fontSize: '0.82rem',
            lineHeight: 1.7, color: 'var(--t1)', whiteSpace: 'pre-wrap',
          }}>
            {message.content}
          </div>
        </div>
      </div>
    )
  }

  /* Bot message — left-border intercept log */
  return (
    <div
      className="fade-in"
      style={{
        marginBottom: '1.75rem',
        borderLeft: `2px solid rgb(var(--accent) / 0.28)`,
        paddingLeft: '0.875rem',
        paddingRight: '0.875rem',
        paddingTop: '0.6rem',
        paddingBottom: '0.6rem',
        background: 'var(--surface)',
        borderTop: '1px solid var(--bd)',
        borderBottom: '1px solid var(--bd)',
      }}
    >
      {/* Header */}
      <div style={{
        display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: '0.45rem',
        marginBottom: '0.55rem',
        fontFamily: 'var(--font-display)', fontSize: '0.56rem', letterSpacing: '0.16em',
      }}>
        <span style={{ color: `rgb(var(--accent) / 0.8)`, fontWeight: 700 }}>RAMIBOT</span>
        <span style={{ color: 'var(--t3)', flex: 1, overflow: 'hidden', fontSize: '0.5rem' }}>
          {'─'.repeat(40)}
        </span>
        {time && <span style={{ color: 'var(--t3)' }}>{time}</span>}
        {!isStreaming && message.latency && (
          <span style={{ color: `rgb(var(--accent) / 0.55)` }}>
            ▸ {typeof message.latency === 'number' ? `${message.latency.toFixed(1)}s` : message.latency}
          </span>
        )}
        {!isStreaming && message.usage && (
          <span style={{ color: 'var(--t3)' }}>
            {(message.usage.total_tokens || (message.usage.prompt_tokens || 0) + (message.usage.completion_tokens || 0))}tok
          </span>
        )}
      </div>

      {/* Content */}
      <div className="markdown-body" style={{ fontSize: '0.82rem', lineHeight: 1.75 }}>
        {thinking && <ThinkingBlock content={thinking} isThinking={isThinking} />}
        {rest ? (
          <ReactMarkdown
            remarkPlugins={[remarkGfm]}
            rehypePlugins={[rehypeHighlight]}
            components={{
              pre: ({ children }) => <pre className="relative group">{children}</pre>,
              code: ({ node, className, children, ...props }) => {
                const isInline = !className
                if (isInline) return <code {...props}>{children}</code>
                return <CodeBlock className={className} {...props}>{children}</CodeBlock>
              },
            }}
          >
            {rest}
          </ReactMarkdown>
        ) : isStreaming ? (
          <div style={{ display: 'flex', gap: '0.4rem', padding: '0.25rem 0', alignItems: 'center' }}>
            <span className="streaming-dot" style={{ width: '5px', height: '5px', borderRadius: '50%', background: `rgb(var(--accent) / 0.7)` }} />
            <span className="streaming-dot" style={{ width: '5px', height: '5px', borderRadius: '50%', background: `rgb(var(--accent) / 0.7)` }} />
            <span className="streaming-dot" style={{ width: '5px', height: '5px', borderRadius: '50%', background: `rgb(var(--accent) / 0.7)` }} />
          </div>
        ) : null}
      </div>

      {/* Tool traces */}
      {message.tool_traces && message.tool_traces.length > 0 && (
        <ToolTrace traces={message.tool_traces} />
      )}
    </div>
  )
}

export default MessageBubble
