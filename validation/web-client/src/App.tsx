import { FormEvent, useCallback, useEffect, useMemo, useRef, useState } from 'react'

type User = { id: number; username: string }
type Group = { id: number; name: string; invite_code: string; owner_id: number; joined_at?: string }
type Message = { id: number; group_id: number; sender: User; text: string; created_at: string }

type SessionStatus = {
  session_id: string
  connected: boolean
  authenticated: boolean
  target?: string
  alpn?: string
  local_address?: string
  remote_address?: string
  connected_at?: string
  dest_id?: number
  admission_ttl_seconds?: number
  user?: User
  connection_closed_by?: string
}

type CommandResponse = {
  ok: boolean
  type: string
  error?: string
  user?: User
  group?: Group
  groups?: Group[]
  message?: Message
  messages?: Message[]
}

type PushEvent = {
  seq: number
  received_at: string
  targets: number[]
  payload: CommandResponse
}

const sessionKey = 'lyune-im-session-id'

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...init?.headers },
  })
  const payload = await response.json()
  if (!response.ok) throw new Error(payload.error ?? `HTTP ${response.status}`)
  return payload as T
}

function mergeMessages(current: Message[], incoming: Message[]) {
  const byID = new Map(current.map((message) => [message.id, message]))
  for (const message of incoming) byID.set(message.id, message)
  return [...byID.values()].sort((left, right) => left.id - right.id)
}

function timeLabel(value: string) {
  return new Date(value).toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit', hour12: false })
}

function App() {
  const [session, setSession] = useState<SessionStatus | null>(null)
  const [groups, setGroups] = useState<Group[]>([])
  const [activeGroupID, setActiveGroupID] = useState<number | null>(null)
  const [messages, setMessages] = useState<Message[]>([])
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [address, setAddress] = useState('127.0.0.1:8443')
  const [serverName, setServerName] = useState('localhost')
  const [authMode, setAuthMode] = useState<'login' | 'register'>('register')
  const [groupName, setGroupName] = useState('Lyune 实验群')
  const [inviteCode, setInviteCode] = useState('')
  const [draft, setDraft] = useState('')
  const [busy, setBusy] = useState<string | null>(null)
  const [notice, setNotice] = useState<{ tone: 'ok' | 'error' | 'info'; text: string } | null>(null)
  const [pushState, setPushState] = useState<'idle' | 'listening' | 'retrying'>('idle')
  const lastEventSeq = useRef(0)
  const chatEnd = useRef<HTMLDivElement | null>(null)

  const activeGroup = useMemo(
    () => groups.find((group) => group.id === activeGroupID) ?? null,
    [groups, activeGroupID],
  )

  const command = useCallback(async (body: Omit<Record<string, unknown>, 'session_id'>) => {
    if (!session?.session_id) throw new Error('当前没有已认证会话')
    const result = await api<CommandResponse>('/api/im/command', {
      method: 'POST', body: JSON.stringify({ session_id: session.session_id, ...body }),
    })
    if (!result.ok) throw new Error(result.error ?? '后端拒绝了请求')
    return result
  }, [session?.session_id])

  const refreshGroups = useCallback(async () => {
    const result = await command({ type: 'list_groups' })
    setGroups(result.groups ?? [])
    return result.groups ?? []
  }, [command])

  const openGroup = useCallback(async (groupID: number) => {
    setBusy('history')
    try {
      const result = await command({ type: 'history', group_id: groupID })
      setActiveGroupID(groupID)
      setMessages(result.messages ?? [])
      setNotice(null)
    } catch (error) {
      setNotice({ tone: 'error', text: error instanceof Error ? error.message : String(error) })
    } finally {
      setBusy(null)
    }
  }, [command])

  useEffect(() => {
    const saved = sessionStorage.getItem(sessionKey)
    if (!saved) return
    void api<SessionStatus>(`/api/im/status?session_id=${encodeURIComponent(saved)}`)
      .then((status) => {
        if (!status.connected || !status.authenticated) throw new Error('saved session is no longer active')
        setSession(status)
      })
      .catch(() => sessionStorage.removeItem(sessionKey))
  }, [])

  useEffect(() => {
    if (!session?.authenticated) return
    void refreshGroups().catch((error) => setNotice({ tone: 'error', text: String(error) }))
  }, [session?.authenticated, refreshGroups])

  useEffect(() => {
    if (!session?.session_id || !session.authenticated) return
    const controller = new AbortController()
    let stopped = false
    const listen = async () => {
      setPushState('listening')
      while (!stopped) {
        try {
          const result = await api<{ events: PushEvent[] }>(
            `/api/im/events?session_id=${encodeURIComponent(session.session_id)}&after=${lastEventSeq.current}&timeout_ms=25000`,
            { signal: controller.signal },
          )
          setPushState('listening')
          for (const event of result.events) {
            lastEventSeq.current = Math.max(lastEventSeq.current, event.seq)
            const message = event.payload.message
            if (event.payload.type === 'message' && message) {
              setMessages((current) => message.group_id === activeGroupID ? mergeMessages(current, [message]) : current)
              if (message.sender.id !== session.user?.id) {
                setNotice({ tone: 'info', text: `${message.sender.username} 发来一条新消息` })
              }
            }
          }
        } catch {
          if (controller.signal.aborted) return
          setPushState('retrying')
          await new Promise((resolve) => window.setTimeout(resolve, 800))
        }
      }
    }
    void listen()
    return () => {
      stopped = true
      controller.abort()
    }
  }, [session?.session_id, session?.authenticated, session?.user?.id, activeGroupID])

  useEffect(() => {
    chatEnd.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  const authenticate = async (event: FormEvent) => {
    event.preventDefault()
    setBusy('auth')
    setNotice(null)
    try {
      const status = await api<SessionStatus>('/api/im/auth', {
        method: 'POST',
        body: JSON.stringify({
          action: authMode, username, password, address, server_name: serverName,
          insecure_skip_verify: true,
        }),
      })
      sessionStorage.setItem(sessionKey, status.session_id)
      lastEventSeq.current = 0
      setSession(status)
      setPassword('')
      setNotice({ tone: 'ok', text: `${authMode === 'register' ? '注册并登录' : '登录'}成功，后端授予 dest_id ${status.dest_id}` })
    } catch (error) {
      setNotice({ tone: 'error', text: error instanceof Error ? error.message : String(error) })
    } finally {
      setBusy(null)
    }
  }

  const logout = async () => {
    if (session?.session_id) {
      await api('/api/im/logout', { method: 'POST', body: JSON.stringify({ session_id: session.session_id }) }).catch(() => undefined)
    }
    sessionStorage.removeItem(sessionKey)
    setSession(null)
    setGroups([])
    setMessages([])
    setActiveGroupID(null)
    setNotice(null)
  }

  const createGroup = async (event: FormEvent) => {
    event.preventDefault()
    setBusy('create')
    try {
      const result = await command({ type: 'create_group', name: groupName })
      const group = result.group!
      setGroups((current) => [...current.filter((item) => item.id !== group.id), group])
      setActiveGroupID(group.id)
      setMessages([])
      setNotice({ tone: 'ok', text: `群组已创建；把邀请码 ${group.invite_code} 发给另一位用户` })
    } catch (error) {
      setNotice({ tone: 'error', text: error instanceof Error ? error.message : String(error) })
    } finally {
      setBusy(null)
    }
  }

  const joinGroup = async (event: FormEvent) => {
    event.preventDefault()
    setBusy('join')
    try {
      const result = await command({ type: 'join_group', invite_code: inviteCode })
      const group = result.group!
      await refreshGroups()
      setInviteCode('')
      await openGroup(group.id)
      setNotice({ tone: 'ok', text: `已由后端授权加入「${group.name}」` })
    } catch (error) {
      setNotice({ tone: 'error', text: error instanceof Error ? error.message : String(error) })
    } finally {
      setBusy(null)
    }
  }

  const sendMessage = async (event: FormEvent) => {
    event.preventDefault()
    if (!activeGroup || !draft.trim()) return
    const text = draft.trim()
    setDraft('')
    setBusy('send')
    try {
      const result = await command({ type: 'send_message', group_id: activeGroup.id, text })
      if (result.message) setMessages((current) => mergeMessages(current, [result.message!]))
    } catch (error) {
      setDraft(text)
      setNotice({ tone: 'error', text: error instanceof Error ? error.message : String(error) })
    } finally {
      setBusy(null)
    }
  }

  if (!session?.authenticated) {
    return (
      <main className="auth-shell">
        <section className="auth-story">
          <p className="eyebrow">LYUNE / MAC STAGE · REAL IM</p>
          <h1>不是 echo。<br />是真实的身份与消息。</h1>
          <p className="lead">用户名和密码经过 <code>Browser → client-agent → Gateway → Reactor</code>。Reactor 查询 SQLite 后决定准入，群消息再由网关主动推送给在线成员。</p>
          <div className="path-card">
            {['Web :5173', 'Agent :8787', 'Gateway :8443', 'Reactor :9443', 'SQLite'].map((label, index) => (
              <div className="path-node" key={label}><span>{String(index + 1).padStart(2, '0')}</span>{label}</div>
            ))}
          </div>
        </section>
        <section className="auth-card">
          <div className="auth-tabs">
            <button className={authMode === 'register' ? 'active' : ''} onClick={() => setAuthMode('register')}>注册</button>
            <button className={authMode === 'login' ? 'active' : ''} onClick={() => setAuthMode('login')}>登录</button>
          </div>
          <div className="auth-title">
            <span className="live-dot" />
            <div><h2>{authMode === 'register' ? '创建真实用户' : '验证已有用户'}</h2><p>密码不少于 8 位；用户名为 3–24 位字母、数字或下划线。</p></div>
          </div>
          <form onSubmit={authenticate}>
            <label>用户名<input autoFocus autoComplete="username" value={username} onChange={(event) => setUsername(event.target.value)} placeholder="alice_01" /></label>
            <label>密码<input type="password" autoComplete={authMode === 'register' ? 'new-password' : 'current-password'} value={password} onChange={(event) => setPassword(event.target.value)} placeholder="至少 8 位" /></label>
            <details>
              <summary>本地网关连接参数</summary>
              <div className="two-fields">
                <label>Gateway<input value={address} onChange={(event) => setAddress(event.target.value)} /></label>
                <label>TLS SNI<input value={serverName} onChange={(event) => setServerName(event.target.value)} /></label>
              </div>
              <p className="dev-warning">本地验证使用开发证书并显式跳过证书链校验。</p>
            </details>
            <button className="primary wide" disabled={busy === 'auth'}>{busy === 'auth' ? '正在走完整认证链路…' : authMode === 'register' ? '注册并进入 Lyune' : '登录 Lyune'}</button>
          </form>
          {notice && <p className={`notice ${notice.tone}`}>{notice.text}</p>}
          <p className="auth-footnote">前端无法给自己指定 <code>dest_id</code>；它只接受认证服务通过网关授予的身份。</p>
        </section>
      </main>
    )
  }

  return (
    <main className="app-shell">
      <aside className="sidebar">
        <div className="brand"><span className="brand-mark">L</span><div><strong>Lyune IM</strong><small>MAC VALIDATION</small></div></div>
        <div className="identity-card">
          <div className="avatar">{session.user?.username.slice(0, 1).toUpperCase()}</div>
          <div><strong>{session.user?.username}</strong><small>dest_id {session.dest_id}</small></div>
          <span className="online-dot" title="online" />
        </div>
        <div className="section-label"><span>我的群组</span><button onClick={() => void refreshGroups()} title="刷新">↻</button></div>
        <nav className="group-list">
          {groups.map((group) => (
            <button key={group.id} className={activeGroupID === group.id ? 'active' : ''} onClick={() => void openGroup(group.id)}>
              <span className="group-symbol">#</span><span><strong>{group.name}</strong><small>group {group.id}</small></span>
            </button>
          ))}
          {groups.length === 0 && <p className="empty-groups">还没有群组。创建一个，或用邀请码加入。</p>}
        </nav>
        <div className="group-actions">
          <form onSubmit={createGroup}>
            <label>创建群组<input value={groupName} onChange={(event) => setGroupName(event.target.value)} /></label>
            <button disabled={busy !== null}>创建</button>
          </form>
          <form onSubmit={joinGroup}>
            <label>邀请码<input value={inviteCode} onChange={(event) => setInviteCode(event.target.value)} placeholder="12 位邀请码" /></label>
            <button disabled={busy !== null || !inviteCode}>加入</button>
          </form>
        </div>
        <button className="logout" onClick={() => void logout()}>退出并关闭 QUIC 会话</button>
      </aside>

      <section className="chat-pane">
        <header className="chat-header">
          <div>
            <p className="eyebrow">SERVICE 1/2 · SQLITE AUTHORIZATION</p>
            <h2>{activeGroup ? activeGroup.name : '选择或创建一个群组'}</h2>
          </div>
          <div className="transport-status">
            <span className={pushState === 'listening' ? 'online-dot' : 'warn-dot'} />
            <div><strong>{pushState === 'listening' ? '.peer 实时监听中' : '推送通道重试中'}</strong><small>{session.local_address} → {session.remote_address} · {session.alpn}</small></div>
          </div>
        </header>

        {notice && <div className={`toast ${notice.tone}`}><span>{notice.text}</span><button onClick={() => setNotice(null)}>×</button></div>}

        {!activeGroup ? (
          <div className="welcome-state">
            <div className="orbit"><span>QUIC</span></div>
            <h3>用两个真实用户开始</h3>
            <p>当前标签页是 <strong>{session.user?.username}</strong>。创建群组后，在另一个标签页注册第二个用户并输入邀请码；双方随后会通过各自独立的 QUIC 连接收发消息。</p>
          </div>
        ) : (
          <>
            <div className="invite-strip"><span>邀请码</span><code>{activeGroup.invite_code}</code><button onClick={() => void navigator.clipboard.writeText(activeGroup.invite_code)}>复制</button></div>
            <div className="message-list">
              {messages.length === 0 && <div className="day-divider"><span>消息已由 Reactor 从 SQLite 读取</span></div>}
              {messages.map((message) => {
                const own = message.sender.id === session.user?.id
                return (
                  <article className={`message ${own ? 'own' : ''}`} key={message.id}>
                    <div className="message-avatar">{message.sender.username.slice(0, 1).toUpperCase()}</div>
                    <div className="message-content"><div className="message-meta"><strong>{message.sender.username}</strong><time>{timeLabel(message.created_at)}</time><small>#{message.id}</small></div><p>{message.text}</p></div>
                  </article>
                )
              })}
              <div ref={chatEnd} />
            </div>
            <form className="composer" onSubmit={sendMessage}>
              <textarea rows={2} value={draft} onChange={(event) => setDraft(event.target.value)} onKeyDown={(event) => {
                if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); event.currentTarget.form?.requestSubmit() }
              }} placeholder={`发消息到 #${activeGroup.name}；Enter 发送，Shift+Enter 换行`} />
              <button disabled={!draft.trim() || busy === 'send'}>{busy === 'send' ? '发送中' : '发送'}</button>
            </form>
          </>
        )}
        <footer className="protocol-footer">
          <span>AUTH TTL {session.admission_ttl_seconds}s</span><span>SESSION {session.session_id.slice(0, 8)}…</span><span>后端业务授权 + 批量 .peer</span>
        </footer>
      </section>
    </main>
  )
}

export default App
