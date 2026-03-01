import { create } from 'zustand'
import { exportReportAsPdf } from './reportPdf'

const PDF_CONFIRM_RE = /^(pdf|sí|si|yes|dale|ok|quiero|quiero pdf|sí quiero|si quiero|exportar pdf|descargar pdf|export pdf|download pdf|generate pdf|generar pdf|sí,?\s*por favor|si,?\s*por favor)$/i

const useStore = create((set, get) => ({
  conversations: [],
  currentConversation: null,
  messages: [],
  providers: [],
  models: [],
  selectedProvider: 'openai',
  selectedModel: '',
  mcpEnabled: false,
  reasoningEnabled: false,
  requireToolApproval: localStorage.getItem('ramibot_require_approval') === 'true',
  pendingApproval: null,
  isStreaming: false,
  streamingContent: '',
  streamingToolTraces: [],
  settings: {},
  sidebarOpen: true,
  abortController: null,
  mcpTools: [],
  disabledMcpTools: JSON.parse(localStorage.getItem('ramibot_disabled_tools') || '[]'),
  teamMode: localStorage.getItem('ramibot_team') || 'red',
  terminalCount: 0,
  dockerContainer: localStorage.getItem('ramibot_docker_container') || '',
  torActive: false,
  matrixEnabled: localStorage.getItem('ramibot_matrix') !== 'false',
  matrixSpeed: Number(localStorage.getItem('ramibot_matrix_speed') || 2),

  addTerminal: () => set((s) => ({ terminalCount: Math.min(s.terminalCount + 1, 2) })),
  removeTerminal: () => set((s) => ({ terminalCount: Math.max(s.terminalCount - 1, 0) })),
  setTorActive: (v) => set({ torActive: v }),
  toggleMatrix: () => set((s) => {
    const next = !s.matrixEnabled
    localStorage.setItem('ramibot_matrix', next)
    return { matrixEnabled: next }
  }),
  setMatrixSpeed: (v) => {
    localStorage.setItem('ramibot_matrix_speed', v)
    set({ matrixSpeed: v })
  },
  setDockerContainer: (name) => {
    localStorage.setItem('ramibot_docker_container', name)
    set({ dockerContainer: name })
  },

  toggleSidebar: () => set((s) => ({ sidebarOpen: !s.sidebarOpen })),

  setTeamMode: (mode) => {
    set({ teamMode: mode })
    localStorage.setItem('ramibot_team', mode)
  },

  fetchConversations: async () => {
    try {
      const res = await fetch('/api/conversations')
      if (!res.ok) return
      const data = await res.json()
      set({ conversations: data })
    } catch (e) {
      console.error('Failed to fetch conversations:', e)
    }
  },

  fetchConversation: async (id) => {
    try {
      const res = await fetch(`/api/conversations/${id}`)
      if (!res.ok) return
      const data = await res.json()
      set({
        currentConversation: data,
        messages: data.messages || [],
        selectedProvider: data.provider || get().selectedProvider,
        selectedModel: data.model || get().selectedModel,
        mcpEnabled: data.mcp_enabled || false,
        reasoningEnabled: data.reasoning_enabled || false,
      })
    } catch (e) {
      console.error('Failed to fetch conversation:', e)
    }
  },

  createConversation: async () => {
    try {
      const { selectedProvider, selectedModel, mcpEnabled, reasoningEnabled, teamMode } = get()
      const res = await fetch('/api/conversations', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          provider: selectedProvider,
          model: selectedModel,
          mcp_enabled: mcpEnabled,
          reasoning_enabled: reasoningEnabled,
          team_mode: teamMode,
        }),
      })
      if (!res.ok) return null
      const data = await res.json()
      set((s) => ({
        conversations: [data, ...s.conversations],
        currentConversation: data,
        messages: [],
      }))
      return data
    } catch (e) {
      console.error('Failed to create conversation:', e)
      return null
    }
  },

  deleteConversation: async (id) => {
    try {
      await fetch(`/api/conversations/${id}`, { method: 'DELETE' })
      set((s) => ({
        conversations: s.conversations.filter((c) => c.id !== id),
        currentConversation: s.currentConversation?.id === id ? null : s.currentConversation,
        messages: s.currentConversation?.id === id ? [] : s.messages,
      }))
    } catch (e) {
      console.error('Failed to delete conversation:', e)
    }
  },

  fetchProviders: async () => {
    try {
      const res = await fetch('/api/providers')
      if (!res.ok) return
      const data = await res.json()
      set({ providers: data })
    } catch (e) {
      console.error('Failed to fetch providers:', e)
    }
  },

  fetchModels: async (provider) => {
    try {
      const settings = get().settings
      const headers = { 'Content-Type': 'application/json' }
      if (settings.openai_api_key) headers['X-OpenAI-Key'] = settings.openai_api_key
      if (settings.anthropic_api_key) headers['X-Anthropic-Key'] = settings.anthropic_api_key
      if (settings.openrouter_api_key) headers['X-OpenRouter-Key'] = settings.openrouter_api_key
      if (settings.lmstudio_base_url) headers['X-LMStudio-URL'] = settings.lmstudio_base_url
      if (settings.ollama_base_url) headers['X-Ollama-URL'] = settings.ollama_base_url

      const res = await fetch(`/api/models?provider=${provider}`, { headers })
      if (!res.ok) return
      const data = await res.json()
      set({ models: data })
      const current = get().selectedModel
      if (data.length > 0 && !current) {
        set({ selectedModel: data[0].id })
      }
    } catch (e) {
      console.error('Failed to fetch models:', e)
    }
  },

  sendMessageStream: async (content) => {
    const state = get()

    // ── PDF export intercept ─────────────────────────────────────────────────
    if (PDF_CONFIRM_RE.test(content.trim())) {
      const lastReport = [...state.messages].reverse().find(
        (m) => m.role === 'assistant' && m.content?.includes('<!-- REPORT -->')
      )
      if (lastReport) {
        const userMsg = {
          id: Date.now().toString(),
          role: 'user',
          content,
          created_at: new Date().toISOString(),
        }
        const ackMsg = {
          id: (Date.now() + 1).toString(),
          role: 'assistant',
          content: '✓ Abriendo ventana de impresión — selecciona **Guardar como PDF** en tu navegador.',
          created_at: new Date().toISOString(),
        }
        set((s) => ({ messages: [...s.messages, userMsg, ackMsg] }))
        exportReportAsPdf(lastReport.content)
        return
      }
    }
    // ────────────────────────────────────────────────────────────────────────

    let convId = state.currentConversation?.id

    if (!convId) {
      const conv = await get().createConversation()
      if (!conv) return
      convId = conv.id
    }

    const userMessage = {
      id: Date.now().toString(),
      role: 'user',
      content,
      created_at: new Date().toISOString(),
    }

    const abortController = new AbortController()

    set((s) => ({
      messages: [...s.messages, userMessage],
      isStreaming: true,
      streamingContent: '',
      streamingToolTraces: [],
      abortController,
    }))

    try {
      const settings = get().settings
      const body = {
        conversation_id: convId,
        message: content,
        provider: get().selectedProvider,
        model: get().selectedModel,
        mcp_enabled: get().mcpEnabled,
        reasoning_enabled: get().reasoningEnabled,
        team_mode: get().teamMode,
        disabled_tools: get().disabledMcpTools,
        require_tool_approval: get().requireToolApproval,
      }

      const headers = { 'Content-Type': 'application/json' }
      if (settings.openai_api_key) headers['X-OpenAI-Key'] = settings.openai_api_key
      if (settings.anthropic_api_key) headers['X-Anthropic-Key'] = settings.anthropic_api_key
      if (settings.openrouter_api_key) headers['X-OpenRouter-Key'] = settings.openrouter_api_key
      if (settings.lmstudio_base_url) headers['X-LMStudio-URL'] = settings.lmstudio_base_url
      if (settings.ollama_base_url) headers['X-Ollama-URL'] = settings.ollama_base_url

      const response = await fetch('/api/chat/stream', {
        method: 'POST',
        headers,
        body: JSON.stringify(body),
        signal: abortController.signal,
      })

      if (!response.ok) {
        const errText = await response.text()
        throw new Error(errText || `HTTP ${response.status}`)
      }

      const reader = response.body.getReader()
      const decoder = new TextDecoder()
      let buffer = ''
      let fullContent = ''
      let toolTraces = []
      let usage = null
      let currentEvent = ''

      while (true) {
        const { done, value } = await reader.read()
        if (done) break
        buffer += decoder.decode(value, { stream: true })
        const lines = buffer.split('\n')
        buffer = lines.pop()

        for (const line of lines) {
          if (line.startsWith('event: ')) {
            currentEvent = line.slice(7).trim()
            continue
          }
          if (!line.startsWith('data: ')) continue
          const raw = line.slice(6).trim()
          if (!raw || raw === '[DONE]') continue

          try {
            const data = JSON.parse(raw)
            const eventType = currentEvent || data.type

            switch (eventType) {
              case 'token':
                fullContent += (data.token || data.content || '')
                set({ streamingContent: fullContent })
                break
              case 'tool_call':
                toolTraces = [...toolTraces, {
                  id: data.id || Date.now().toString(),
                  name: data.name,
                  arguments: data.arguments,
                  status: 'calling',
                }]
                set({ streamingToolTraces: toolTraces })
                break
              case 'tool_result':
                toolTraces = toolTraces.map((t) =>
                  t.name === data.tool || t.name === data.name
                    ? { ...t, result: data.result, status: data.error ? 'error' : 'done' }
                    : t
                )
                set({ streamingToolTraces: toolTraces })
                break
              case 'tool_approval_required':
                set({
                  pendingApproval: {
                    approvalId: data.approval_id,
                    toolName: data.tool_name,
                    arguments: data.arguments,
                    riskLevel: data.risk_level,
                    startedAt: Date.now(),
                  },
                })
                break
              case 'clear_content':
                fullContent = ''
                set({ streamingContent: '' })
                break
              case 'usage':
                usage = data
                break
              case 'done': {
                // If the LLM responded with the PDF export marker, trigger export
                if (fullContent.trim() === '[PDF_EXPORT]') {
                  const lastReport = [...get().messages].reverse().find(
                    (m) => m.role === 'assistant' && m.content?.includes('<!-- REPORT -->')
                  )
                  const ackContent = '✓ Abriendo ventana de impresión — selecciona **Guardar como PDF** en tu navegador.'
                  const assistantMessage = {
                    id: (Date.now() + 1).toString(),
                    role: 'assistant',
                    content: ackContent,
                    created_at: new Date().toISOString(),
                  }
                  set((s) => ({
                    messages: [...s.messages, assistantMessage],
                    isStreaming: false,
                    streamingContent: '',
                    streamingToolTraces: [],
                    pendingApproval: null,
                    abortController: null,
                  }))
                  if (lastReport) exportReportAsPdf(lastReport.content)
                  get().fetchConversations()
                  return
                }

                const assistantMessage = {
                  id: (Date.now() + 1).toString(),
                  role: 'assistant',
                  content: fullContent || '',
                  tool_traces: toolTraces.length > 0 ? toolTraces : undefined,
                  usage: usage || data.token_usage,
                  latency: data.latency_ms,
                  created_at: new Date().toISOString(),
                }
                set((s) => ({
                  messages: [...s.messages, assistantMessage],
                  isStreaming: false,
                  streamingContent: '',
                  streamingToolTraces: [],
                  pendingApproval: null,
                  abortController: null,
                }))
                get().fetchConversations()
                return
              }
              case 'error':
                throw new Error(data.message || data.error || 'Stream error')
            }
            currentEvent = ''
          } catch (parseErr) {
            if (parseErr.message && !parseErr.message.includes('JSON')) {
              throw parseErr
            }
          }
        }
      }

      if (fullContent) {
        const assistantMessage = {
          id: (Date.now() + 1).toString(),
          role: 'assistant',
          content: fullContent,
          tool_traces: toolTraces.length > 0 ? toolTraces : undefined,
          usage,
          created_at: new Date().toISOString(),
        }
        set((s) => ({
          messages: [...s.messages, assistantMessage],
          isStreaming: false,
          streamingContent: '',
          streamingToolTraces: [],
          abortController: null,
        }))
        get().fetchConversations()
      }
    } catch (e) {
      if (e.name === 'AbortError') {
        const currentContent = get().streamingContent
        if (currentContent) {
          set((s) => ({
            messages: [...s.messages, {
              id: (Date.now() + 1).toString(),
              role: 'assistant',
              content: currentContent + '\n\n*[Generation stopped]*',
              created_at: new Date().toISOString(),
            }],
          }))
        }
      } else {
        console.error('Stream error:', e)
        set((s) => ({
          messages: [...s.messages, {
            id: (Date.now() + 1).toString(),
            role: 'assistant',
            content: `**Error:** ${e.message}`,
            created_at: new Date().toISOString(),
          }],
        }))
      }
      set({ isStreaming: false, streamingContent: '', streamingToolTraces: [], pendingApproval: null, abortController: null })
    }
  },

  stopStreaming: () => {
    const { abortController } = get()
    if (abortController) {
      abortController.abort()
    }
  },

  setProvider: (provider) => {
    set({ selectedProvider: provider, selectedModel: '', models: [] })
    localStorage.setItem('ramibot_provider', provider)
    localStorage.removeItem('ramibot_model')
    get().fetchModels(provider)
  },

  setModel: (model) => {
    set({ selectedModel: model })
    localStorage.setItem('ramibot_model', model)
  },

  toggleMcp: () => {
    const next = !get().mcpEnabled
    set({ mcpEnabled: next })
    if (next) get().fetchMcpTools()
    else set({ mcpTools: [] })
  },

  toggleMcpTool: (toolName) => {
    const current = get().disabledMcpTools
    const updated = current.includes(toolName)
      ? current.filter((t) => t !== toolName)
      : [...current, toolName]
    set({ disabledMcpTools: updated })
    localStorage.setItem('ramibot_disabled_tools', JSON.stringify(updated))
  },

  fetchMcpTools: async () => {
    try {
      const res = await fetch('/api/mcp/all-tools')
      if (!res.ok) return
      const data = await res.json()
      set({ mcpTools: data })
    } catch (e) {
      console.error('Failed to fetch MCP tools:', e)
    }
  },

  toggleReasoning: () => set((s) => ({ reasoningEnabled: !s.reasoningEnabled })),

  toggleRequireApproval: () => {
    const next = !get().requireToolApproval
    localStorage.setItem('ramibot_require_approval', next)
    set({ requireToolApproval: next })
  },

  respondToApproval: async (approved) => {
    const { pendingApproval } = get()
    if (!pendingApproval) return
    set({ pendingApproval: null })
    try {
      await fetch('/api/chat/approve', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ approval_id: pendingApproval.approvalId, approved }),
      })
    } catch (e) {
      console.error('Failed to respond to approval:', e)
    }
  },

  saveSettings: async (settings) => {
    localStorage.setItem('ramibot_settings', JSON.stringify(settings))
    set({ settings })
    try {
      const mapped = {
        openai: { api_key: settings.openai_api_key || '' },
        anthropic: { api_key: settings.anthropic_api_key || '' },
        openrouter: { api_key: settings.openrouter_api_key || '' },
        lmstudio: { base_url: settings.lmstudio_base_url || 'http://localhost:1234/v1' },
        ollama: { base_url: settings.ollama_base_url || 'http://localhost:11434' },
        docker: { container: settings.docker_container || '' },
      }
      await fetch('/api/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(mapped),
      })
    } catch (e) {
      console.error('Failed to save settings to backend:', e)
    }
  },

  loadSettings: () => {
    try {
      const stored = localStorage.getItem('ramibot_settings')
      if (stored) {
        const parsed = JSON.parse(stored)
        set({ settings: parsed })
        if (parsed.docker_container) {
          set({ dockerContainer: parsed.docker_container })
          localStorage.setItem('ramibot_docker_container', parsed.docker_container)
        }
      }
      const provider = localStorage.getItem('ramibot_provider')
      const model = localStorage.getItem('ramibot_model')
      if (provider) {
        set({ selectedProvider: provider })
        get().fetchModels(provider)
      }
      if (model) {
        set({ selectedModel: model })
      }
    } catch (e) {
      console.error('Failed to load settings:', e)
    }
  },

  exportConversation: async (id, format = 'json') => {
    try {
      const res = await fetch(`/api/conversations/${id}/export?format=${format}`)
      if (!res.ok) return
      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `conversation-${id}.${format}`
      a.click()
      URL.revokeObjectURL(url)
    } catch (e) {
      console.error('Failed to export conversation:', e)
    }
  },

  // ── Findings ──────────────────────────────────────────────────────────────
  findings: [],

  fetchFindings: async ({ conversationId, severity } = {}) => {
    try {
      const params = new URLSearchParams()
      if (conversationId) params.set('conversation_id', conversationId)
      if (severity) params.set('severity', severity)
      const res = await fetch(`/api/findings?${params}`)
      if (!res.ok) return
      set({ findings: await res.json() })
    } catch (e) {
      console.error('Failed to fetch findings:', e)
    }
  },

  createFinding: async (data) => {
    try {
      const res = await fetch('/api/findings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      })
      if (!res.ok) return null
      const finding = await res.json()
      set((s) => ({ findings: [finding, ...s.findings] }))
      return finding
    } catch (e) {
      console.error('Failed to create finding:', e)
      return null
    }
  },

  deleteFinding: async (id) => {
    try {
      await fetch(`/api/findings/${id}`, { method: 'DELETE' })
      set((s) => ({ findings: s.findings.filter((f) => f.id !== id) }))
    } catch (e) {
      console.error('Failed to delete finding:', e)
    }
  },

  exportFindings: async (format = 'json', { severity, conversationId } = {}) => {
    try {
      const params = new URLSearchParams({ format })
      if (severity) params.set('severity', severity)
      if (conversationId) params.set('conversation_id', conversationId)
      const res = await fetch(`/api/findings/export?${params}`)
      if (!res.ok) return
      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `findings.${format}`
      a.click()
      URL.revokeObjectURL(url)
    } catch (e) {
      console.error('Failed to export findings:', e)
    }
  },
}))

export default useStore
