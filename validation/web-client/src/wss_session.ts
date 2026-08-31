// 浏览器直连 Lyune WSS binding。
//
// WebSocket 只承担 TLS/TCP 与 message framing；下面的 envelope 把 logical stream id、
// FIN、RESET、STOP 显式编码。其 payload 仍是和 Raw QUIC 完全相同的 Lyune frame。

export type WssUser = { id: number; username: string }
export type WssCommandResponse = {
  ok: boolean
  type: string
  error?: string
  user?: WssUser
  [key: string]: unknown
}

export type WssPushEvent = {
  seq: number
  received_at: string
  targets: number[]
  payload: WssCommandResponse
}

export type WssSessionStatus = {
  session_id: string
  connected: boolean
  authenticated: boolean
  target: string
  alpn: string
  connected_at: string
  dest_id?: number
  admission_ttl_seconds?: number
  user?: WssUser
  connection_closed_by?: string
}

const envelopeVersion = 1
const envelopeHeaderSize = 20
const recordStream = 0x01
const recordReset = 0x02
const recordStop = 0x03
const recordEphemeral = 0x04
const flagFin = 0x01

const frameOpen = 0x00
const frameData = 0x01
const frameEOF = 0x01
const destGateway = 0x00
const destService = 0x01
const destPeer = 0x02
const responseRequired = 0x00
const responseNone = 0x01

const textEncoder = new TextEncoder()
const textDecoder = new TextDecoder('utf-8', { fatal: true })

type Envelope = {
  type: number
  fin: boolean
  streamID: bigint
  appError: number
  payload: Uint8Array
}

type Frame = {
  type: number
  flags: number
  dest: number
  response: number
  group: number
  route: number
  body: Uint8Array
}

type PendingStream = {
  chunks: Uint8Array[]
  noResponse: boolean
  resolve: (frame: Frame | null) => void
  reject: (error: Error) => void
  timer: number
}

function concat(chunks: Uint8Array[]) {
  const length = chunks.reduce((total, chunk) => total + chunk.byteLength, 0)
  const result = new Uint8Array(length)
  let offset = 0
  for (const chunk of chunks) {
    result.set(chunk, offset)
    offset += chunk.byteLength
  }
  return result
}

function encodeEnvelope(record: Envelope) {
  const bytes = new Uint8Array(envelopeHeaderSize + record.payload.byteLength)
  const view = new DataView(bytes.buffer)
  bytes[0] = envelopeVersion
  bytes[1] = record.type
  bytes[2] = record.fin ? flagFin : 0
  view.setBigUint64(4, record.streamID)
  view.setUint32(12, record.appError)
  view.setUint32(16, record.payload.byteLength)
  bytes.set(record.payload, envelopeHeaderSize)
  return bytes
}

function decodeEnvelope(buffer: ArrayBuffer): Envelope {
  const bytes = new Uint8Array(buffer)
  if (bytes.byteLength < envelopeHeaderSize) throw new Error('WSS envelope 被截断')
  const view = new DataView(buffer)
  if (bytes[0] !== envelopeVersion || bytes[3] !== 0 || (bytes[2] & ~flagFin) !== 0) {
    throw new Error('WSS envelope 版本或保留位非法')
  }
  const payloadLength = view.getUint32(16)
  if (bytes.byteLength !== envelopeHeaderSize + payloadLength) throw new Error('WSS envelope 长度不一致')
  const type = bytes[1]
  if (![recordStream, recordReset, recordStop, recordEphemeral].includes(type)) throw new Error('未知 WSS record')
  return {
    type,
    fin: (bytes[2] & flagFin) !== 0,
    streamID: view.getBigUint64(4),
    appError: view.getUint32(12),
    payload: bytes.slice(envelopeHeaderSize),
  }
}

function encodeOpen(dest: number, group: number, route: number, response: number, body: unknown) {
  const payload = textEncoder.encode(JSON.stringify(body))
  if (payload.byteLength > 0xffff) throw new Error('IM 请求超过单帧上限')
  const bytes = new Uint8Array(8 + payload.byteLength)
  const view = new DataView(bytes.buffer)
  bytes[0] = frameOpen
  bytes[1] = frameEOF
  view.setUint16(2, payload.byteLength)
  bytes[4] = dest
  bytes[5] = response
  bytes[6] = group
  bytes[7] = route
  bytes.set(payload, 8)
  return bytes
}

function decodeFrames(bytes: Uint8Array): Frame[] {
  const frames: Frame[] = []
  let offset = 0
  while (offset < bytes.byteLength) {
    if (bytes.byteLength - offset < 4) throw new Error('Lyune frame 头被截断')
    const type = bytes[offset]
    const flags = bytes[offset + 1]
    const bodyLength = new DataView(bytes.buffer, bytes.byteOffset + offset + 2, 2).getUint16(0)
    const headerLength = type === frameOpen ? 8 : type === frameData ? 4 : 0
    if (headerLength === 0 || bytes.byteLength - offset < headerLength + bodyLength) {
      throw new Error('Lyune frame 非法或被截断')
    }
    frames.push({
      type,
      flags,
      dest: type === frameOpen ? bytes[offset + 4] : 0,
      response: type === frameOpen ? bytes[offset + 5] : 0,
      group: type === frameOpen ? bytes[offset + 6] : 0,
      route: type === frameOpen ? bytes[offset + 7] : 0,
      body: bytes.slice(offset + headerLength, offset + headerLength + bodyLength),
    })
    offset += headerLength + bodyLength
  }
  return frames
}

function safeU64(value: bigint, field: string) {
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error(`${field} 超出浏览器安全整数范围`)
  return Number(value)
}

function jsonBody<T>(frame: Frame): T {
  return JSON.parse(textDecoder.decode(frame.body)) as T
}

export class WssImSession {
  readonly status: WssSessionStatus
  onPush: ((event: WssPushEvent) => void) | null = null
  onClose: ((reason: string) => void) | null = null

  private socket: WebSocket
  private nextClientStreamID = 0n
  private pending = new Map<bigint, PendingStream>()
  private pushes = new Map<bigint, Uint8Array[]>()
  private token = ''
  private pushSequence = 0

  private constructor(socket: WebSocket, target: string) {
    this.socket = socket
    this.status = {
      session_id: crypto.randomUUID(),
      connected: true,
      authenticated: false,
      target,
      alpn: 'lyune.v2 / WSS',
      connected_at: new Date().toISOString(),
    }
    socket.addEventListener('message', (event) => this.handleMessage(event))
    socket.addEventListener('close', (event) => this.handleClose(`WSS ${event.code}${event.reason ? `: ${event.reason}` : ''}`))
    socket.addEventListener('error', () => {
      if (socket.readyState !== WebSocket.OPEN) this.handleClose('WSS 连接失败')
    })
  }

  static connect(target: string, timeoutMS = 8000): Promise<WssImSession> {
    return new Promise((resolve, reject) => {
      const socket = new WebSocket(target, 'lyune.v2')
      socket.binaryType = 'arraybuffer'
      const timer = window.setTimeout(() => {
        socket.close()
        reject(new Error('WSS 连接超时'))
      }, timeoutMS)
      socket.addEventListener('open', () => {
        window.clearTimeout(timer)
        if (socket.protocol !== 'lyune.v2') {
          socket.close(1002, 'subprotocol mismatch')
          reject(new Error('网关没有确认 lyune.v2 子协议'))
          return
        }
        resolve(new WssImSession(socket, target))
      }, { once: true })
      socket.addEventListener('error', () => {
        window.clearTimeout(timer)
        reject(new Error('无法建立 WSS；请确认网关已启动且浏览器信任本地开发证书'))
      }, { once: true })
    })
  }

  async authenticate(action: 'login' | 'register', username: string, password: string) {
    const response = await this.exchange(encodeOpen(destGateway, 0, 0x10, responseRequired, { action, username, password }))
    if (!response || response.type !== frameOpen || response.dest !== destGateway) throw new Error('网关返回了非法认证响应')
    if (response.route === 0x12) throw new Error(`认证失败：${textDecoder.decode(response.body)}`)
    if (response.route !== 0x11 || response.body.byteLength < 12) throw new Error('认证授权前缀非法')
    const grant = new DataView(response.body.buffer, response.body.byteOffset, response.body.byteLength)
    const destID = safeU64(grant.getBigUint64(0), 'dest_id')
    const ttl = grant.getUint32(8)
    const payload = JSON.parse(textDecoder.decode(response.body.slice(12))) as {
      ok: boolean
      token: string
      user: WssUser
    }
    if (!payload.ok || !payload.token || !payload.user) throw new Error('认证服务返回了非法会话')
    this.token = payload.token
    Object.assign(this.status, {
      authenticated: true,
      dest_id: destID,
      admission_ttl_seconds: ttl,
      user: payload.user,
    })
    return this.status
  }

  async command(request: Record<string, unknown>): Promise<WssCommandResponse> {
    if (!this.token) throw new Error('当前没有已认证会话')
    const type = String(request.type ?? '')
    const noResponse = type === 'typing'
    const frame = encodeOpen(destService, 1, 2, noResponse ? responseNone : responseRequired, {
      ...request,
      token: this.token,
    })
    const response = await this.exchange(frame, noResponse)
    if (noResponse) return { ok: true, type: 'accepted' }
    if (!response) throw new Error('IM 响应为空')
    if (response.type === frameOpen && response.dest === destGateway && response.route === 0xf0) {
      throw new Error(`网关拒绝 IM exchange：${textDecoder.decode(response.body)}`)
    }
    if (response.type !== frameOpen || response.dest !== destService || (response.flags & frameEOF) === 0) {
      throw new Error('网关返回了非法 IM 响应')
    }
    const result = jsonBody<WssCommandResponse>(response)
    if (!result.ok) throw new Error(result.error ?? '后端拒绝了请求')
    return result
  }

  close() {
    if (this.socket.readyState === WebSocket.OPEN) this.socket.close(1000, 'user logged out')
    this.handleClose('用户退出')
  }

  private exchange(payload: Uint8Array, noResponse = false): Promise<Frame | null> {
    if (this.socket.readyState !== WebSocket.OPEN) return Promise.reject(new Error('WSS 会话已关闭'))
    const streamID = this.nextClientStreamID
    this.nextClientStreamID += 4n
    return new Promise((resolve, reject) => {
      const timer = window.setTimeout(() => {
        this.pending.delete(streamID)
        reject(new Error('Lyune exchange 超时'))
      }, 12000)
      this.pending.set(streamID, { chunks: [], noResponse, resolve, reject, timer })
      this.socket.send(encodeEnvelope({ type: recordStream, fin: true, streamID, appError: 0, payload }))
    })
  }

  private handleMessage(event: MessageEvent<ArrayBuffer>) {
    try {
      if (!(event.data instanceof ArrayBuffer)) throw new Error('网关发送了非 binary WebSocket message')
      const record = decodeEnvelope(event.data)
      if (record.type === recordEphemeral) return
      const direction = Number(record.streamID & 3n)
      if (record.type === recordReset || record.type === recordStop) {
        const pending = this.pending.get(record.streamID)
        if (pending) {
          window.clearTimeout(pending.timer)
          this.pending.delete(record.streamID)
          pending.reject(new Error(`logical stream 被网关${record.type === recordReset ? '重置' : '停止'} (${record.appError})`))
        }
        if (record.type === recordStop && this.socket.readyState === WebSocket.OPEN) {
          this.socket.send(encodeEnvelope({ type: recordReset, fin: false, streamID: record.streamID, appError: record.appError, payload: new Uint8Array() }))
        }
        return
      }
      if (record.type !== recordStream) return
      if (direction === 0) this.handleResponse(record)
      else if (direction === 1) this.handlePush(record)
      else throw new Error('网关使用了单向 logical stream id')
    } catch (error) {
      this.socket.close(1002, 'protocol error')
      this.handleClose(error instanceof Error ? error.message : String(error))
    }
  }

  private handleResponse(record: Envelope) {
    const pending = this.pending.get(record.streamID)
    if (!pending) return
    if (record.payload.byteLength > 0) pending.chunks.push(record.payload)
    if (!record.fin) return
    window.clearTimeout(pending.timer)
    this.pending.delete(record.streamID)
    const bytes = concat(pending.chunks)
    if (pending.noResponse) {
      if (bytes.byteLength !== 0) pending.reject(new Error('response_mode=none 意外返回应用数据'))
      else pending.resolve(null)
      return
    }
    const frames = decodeFrames(bytes)
    if (frames.length !== 1) pending.reject(new Error('一次性 exchange 必须恰好返回一帧'))
    else pending.resolve(frames[0])
  }

  private handlePush(record: Envelope) {
    const chunks = this.pushes.get(record.streamID) ?? []
    if (record.payload.byteLength > 0) chunks.push(record.payload)
    if (!record.fin) {
      this.pushes.set(record.streamID, chunks)
      return
    }
    this.pushes.delete(record.streamID)
    const frames = decodeFrames(concat(chunks))
    if (frames.length !== 1 || frames[0].type !== frameOpen || frames[0].dest !== destPeer || (frames[0].flags & frameEOF) === 0) {
      throw new Error('网关推送不是合法的一次性 .peer 帧')
    }
    const body = frames[0].body
    if (body.byteLength < 2) throw new Error('推送目标列表被截断')
    const view = new DataView(body.buffer, body.byteOffset, body.byteLength)
    const count = view.getUint16(0)
    const prefix = 2 + count * 8
    if (body.byteLength < prefix) throw new Error('推送目标列表被截断')
    const targets: number[] = []
    for (let index = 0; index < count; index += 1) targets.push(safeU64(view.getBigUint64(2 + index * 8), 'push target'))
    const payload = JSON.parse(textDecoder.decode(body.slice(prefix))) as WssCommandResponse
    this.pushSequence += 1
    this.onPush?.({ seq: this.pushSequence, received_at: new Date().toISOString(), targets, payload })

    // 对应 QUIC 客户端关闭 server-initiated bidi stream 的反向发送方向。
    if (this.socket.readyState === WebSocket.OPEN) {
      this.socket.send(encodeEnvelope({ type: recordStream, fin: true, streamID: record.streamID, appError: 0, payload: new Uint8Array() }))
    }
  }

  private handleClose(reason: string) {
    if (!this.status.connected && this.status.connection_closed_by) return
    this.status.connected = false
    this.status.connection_closed_by = reason
    for (const pending of this.pending.values()) {
      window.clearTimeout(pending.timer)
      pending.reject(new Error(reason))
    }
    this.pending.clear()
    this.pushes.clear()
    this.onClose?.(reason)
  }
}
