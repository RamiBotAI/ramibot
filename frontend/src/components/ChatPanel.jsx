import { useRef, useEffect } from 'react'
import useStore from '../store'
import MessageBubble from './MessageBubble'
import MessageInput from './MessageInput'
import WelcomeScreen from './WelcomeScreen'
import ToolApprovalBanner from './ToolApprovalBanner'
import { Terminal } from 'lucide-react'

function ChatPanel() {
  const {
    messages, isStreaming, streamingContent, streamingToolTraces,
    currentConversation, terminalCount, addTerminal, dockerContainer,
    pendingApproval,
  } = useStore()
  const bottomRef = useRef(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, streamingContent])

  const showWelcome = !currentConversation && messages.length === 0

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0, position: 'relative' }}>
      {/* Terminal toggle */}
      {terminalCount < 2 && dockerContainer && (
        <button
          onClick={addTerminal}
          style={{
            position: 'absolute', top: '0.75rem', right: '0.75rem', zIndex: 20,
            display: 'flex', alignItems: 'center', gap: '0.4rem',
            padding: '0.3rem 0.6rem',
            background: 'var(--surface)',
            border: '1px solid var(--bd)',
            borderRadius: 0,
            fontFamily: 'var(--font-display)', fontSize: '0.6rem',
            letterSpacing: '0.14em', textTransform: 'uppercase',
            color: 'var(--t2)', cursor: 'pointer', transition: 'all 0.15s',
          }}
          onMouseEnter={e => {
            e.currentTarget.style.borderColor = `rgb(var(--accent) / 0.55)`
            e.currentTarget.style.color = `rgb(var(--accent))`
            e.currentTarget.style.background = `rgb(var(--accent) / 0.06)`
          }}
          onMouseLeave={e => {
            e.currentTarget.style.borderColor = 'var(--bd)'
            e.currentTarget.style.color = 'var(--t2)'
            e.currentTarget.style.background = 'var(--surface)'
          }}
          title="Open Docker terminal"
        >
          <Terminal size={12} />
          TERMINAL
        </button>
      )}

      {showWelcome ? (
        <div style={{
          flex: 1, display: 'flex', flexDirection: 'column',
          alignItems: 'center', justifyContent: 'center',
          padding: '2rem 1rem', position: 'relative', zIndex: 10,
        }}>
          <WelcomeScreen />
          <div style={{ width: '100%', maxWidth: '44rem', marginTop: '2rem' }}>
            <MessageInput />
          </div>
        </div>
      ) : (
        <>
          {/* Messages */}
          <div style={{ flex: 1, overflowY: 'auto', padding: '1.75rem 1.5rem 1rem', position: 'relative', zIndex: 10 }}>
            <div style={{ maxWidth: '52rem', margin: '0 auto' }}>
              {messages.map((msg) => (
                <MessageBubble key={msg.id} message={msg} />
              ))}

              {isStreaming && (
                <MessageBubble
                  message={{
                    id: 'streaming',
                    role: 'assistant',
                    content: streamingContent,
                    tool_traces: streamingToolTraces.length > 0 ? streamingToolTraces : undefined,
                  }}
                  isStreaming
                />
              )}

              <div ref={bottomRef} />
            </div>
          </div>

          {/* Tool approval banner */}
          {pendingApproval && (
            <div style={{ flexShrink: 0, position: 'relative', zIndex: 10 }}>
              <ToolApprovalBanner />
            </div>
          )}

          {/* Input area */}
          <div style={{ flexShrink: 0, position: 'relative', zIndex: 10 }}>
            <div style={{ maxWidth: '52rem', margin: '0 auto', padding: '0 1.5rem 1.25rem' }}>
              <MessageInput />
            </div>
          </div>
        </>
      )}
    </div>
  )
}

export default ChatPanel
