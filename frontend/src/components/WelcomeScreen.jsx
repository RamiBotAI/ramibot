import useStore from '../store'

function WelcomeScreen() {
  const teamMode = useStore((s) => s.teamMode)

  const statusItems = [
    { label: 'SYSTEM', value: 'ONLINE' },
    { label: 'OPERATIVE', value: teamMode === 'red' ? 'RED TEAM' : 'BLUE TEAM' },
    { label: 'MCP', value: 'READY' },
  ]

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', textAlign: 'center' }}>
      {/* Classification banner */}
      <div style={{
        fontFamily: 'var(--font-display)',
        fontSize: '0.55rem',
        letterSpacing: '0.3em',
        color: `rgb(var(--accent) / 0.5)`,
        marginBottom: '2rem',
        textTransform: 'uppercase',
      }}>
        ── CLASSIFIED // TOP SECRET // NOFORN ──
      </div>

      {/* Main identity block */}
      <div style={{
        border: `1px solid rgb(var(--accent) / 0.2)`,
        padding: '2rem 3rem',
        position: 'relative',
        marginBottom: '1.5rem',
        background: '#0303035f',
      }}>
        {/* Corner marks */}
        <div style={{ position: 'absolute', top: '-2px', left: '-2px', width: '14px', height: '14px', borderTop: `2px solid rgb(var(--accent))`, borderLeft: `2px solid rgb(var(--accent))` }} />
        <div style={{ position: 'absolute', top: '-2px', right: '-2px', width: '14px', height: '14px', borderTop: `2px solid rgb(var(--accent))`, borderRight: `2px solid rgb(var(--accent))` }} />
        <div style={{ position: 'absolute', bottom: '-2px', left: '-2px', width: '14px', height: '14px', borderBottom: `2px solid rgb(var(--accent))`, borderLeft: `2px solid rgb(var(--accent))` }} />
        <div style={{ position: 'absolute', bottom: '-2px', right: '-2px', width: '14px', height: '14px', borderBottom: `2px solid rgb(var(--accent))`, borderRight: `2px solid rgb(var(--accent))` }} />

        <img
          src="/ramibot.png"
          alt="RamiBot"
          style={{ height: '8.5rem', objectFit: 'contain', opacity: 0.9, display: 'block', margin: '0 auto 1.25rem' }}
        />
        <div style={{
          fontFamily: 'var(--font-mono)',
          fontSize: '0.58rem', letterSpacing: '0.18em',
          color: `rgb(var(--accent) / 0.65)`,
          marginTop: '0.6rem',
        }}>
          INTELLIGENCE INTERFACE // v3.1
        </div>
      </div>

      {/* Status grid */}
      <div style={{
        display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)',
        gap: '0.5rem', marginBottom: '1.75rem', width: '100%', maxWidth: '22rem',
      }}>
        {statusItems.map(({ label, value }) => (
          <div key={label} style={{
            border: '1px solid var(--bd)',
            padding: '0.5rem 0.6rem',
            textAlign: 'left',
            background: '#0303035f',
          }}>
            <div style={{
              fontFamily: 'var(--font-display)', fontSize: '0.5rem',
              letterSpacing: '0.14em', color: 'var(--t3)',
              textTransform: 'uppercase', marginBottom: '0.3rem',
            }}>
              {label}
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
              <span style={{
                width: '5px', height: '5px', borderRadius: '50%',
                background: `rgb(var(--accent))`, flexShrink: 0,
                boxShadow: `0 0 4px rgb(var(--accent))`,
              }} />
              <span style={{
                fontFamily: 'var(--font-display)', fontSize: '0.62rem',
                letterSpacing: '0.08em', color: 'var(--t1)', fontWeight: 700,
              }}>
                {value}
              </span>
            </div>
          </div>
        ))}
      </div>

      {/* Prompt */}
      <div style={{
        fontFamily: 'var(--font-mono)', fontSize: '0.72rem',
        color: 'var(--t2)', letterSpacing: '0.03em', lineHeight: 1.6,
      }}>
        Select a provider and model, then initiate a session.
      </div>

      <div style={{
        marginTop: '1rem',
        fontFamily: 'var(--font-display)', fontSize: '0.52rem',
        letterSpacing: '0.2em', color: 'var(--t3)', textTransform: 'uppercase',
      }}>
        AUTHORIZED ACCESS ONLY · AUDIT LOGGING ENABLED
      </div>
    </div>
  )
}

export default WelcomeScreen
