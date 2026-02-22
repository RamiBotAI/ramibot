import { useEffect, useState } from 'react'
import useStore from './store'
import Sidebar from './components/Sidebar'
import ChatPanel from './components/ChatPanel'
import SettingsModal from './components/SettingsModal'
import DockerTerminal from './components/DockerTerminal'
import MatrixRain from './components/MatrixRain'

function App() {
  const [settingsOpen, setSettingsOpen] = useState(false)
  const { loadSettings, fetchConversations, fetchProviders, teamMode, terminalCount, removeTerminal } = useStore()

  useEffect(() => {
    loadSettings()
    fetchConversations()
    fetchProviders()
  }, [])

  useEffect(() => {
    document.documentElement.setAttribute('data-team', teamMode)
  }, [teamMode])

  return (
    <div style={{ display: 'flex', height: '100vh', background: 'var(--bg)', color: 'var(--t1)', fontFamily: 'var(--font-mono)', overflow: 'hidden' }}>
      <Sidebar onOpenSettings={() => setSettingsOpen(true)} />

      {/* Main area — matrix rain only here, not in sidebar */}
      <div style={{ flex: 1, display: 'flex', minWidth: 0, position: 'relative' }}>
        <MatrixRain />
        {/* Chat panel */}
        <div style={{
          display: 'flex', flexDirection: 'column', minWidth: 0,
          flex: terminalCount === 0 ? '1' : '0 0 60%',
          position: 'relative', zIndex: 1,
        }}>
          <ChatPanel />
        </div>

        {/* Terminal zone — no background so matrix shows through */}
        {terminalCount >= 1 && (
          <div style={{
            flex: '0 0 40%', display: 'flex', flexDirection: 'column',
            padding: '0.75rem', gap: '0.75rem', boxSizing: 'border-box',
            position: 'relative', zIndex: 1,
          }}>
            <div style={{ flex: 1, minHeight: 0 }}>
              <DockerTerminal terminalId={1} onClose={() => removeTerminal()} />
            </div>
            {terminalCount >= 2 && (
              <div style={{ flex: 1, minHeight: 0 }}>
                <DockerTerminal terminalId={2} onClose={() => removeTerminal()} />
              </div>
            )}
          </div>
        )}
      </div>

      {settingsOpen && <SettingsModal onClose={() => setSettingsOpen(false)} />}
    </div>
  )
}

export default App
