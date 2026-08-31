#!/usr/bin/env node

// 不依赖第三方包的本机 WSS 真实链路探针：TLS -> HTTP Upgrade -> masked RFC 6455 frame
// -> Lyune WSS envelope -> 认证 -> Reactor list_groups。它用于自动化验证；真实产品客户端
// 仍是 validation/web-client 中浏览器原生 WebSocket 的 WssImSession。

import crypto from 'node:crypto'
import { fileURLToPath } from 'node:url'
import tls from 'node:tls'

const host = '127.0.0.1'
const port = 8444
const serverName = 'localhost'
const origin = 'http://127.0.0.1:5173'

const envelopeHeaderSize = 20
const textEncoder = new TextEncoder()
const textDecoder = new TextDecoder('utf-8', { fatal: true })

function concat(chunks) {
  const result = Buffer.alloc(chunks.reduce((total, chunk) => total + chunk.length, 0))
  let offset = 0
  for (const chunk of chunks) {
    chunk.copy(result, offset)
    offset += chunk.length
  }
  return result
}

export function openBytesFrame(dest, group, route, responseMode, body, eof = true) {
  const payload = Buffer.from(body)
  const result = Buffer.alloc(8 + payload.length)
  result[0] = 0
  result[1] = eof ? 1 : 0 // application eof
  result.writeUInt16BE(payload.length, 2)
  result[4] = dest
  result[5] = responseMode
  result[6] = group
  result[7] = route
  payload.copy(result, 8)
  return result
}

export function openFrame(dest, group, route, responseMode, body, eof = true) {
  return openBytesFrame(dest, group, route, responseMode, Buffer.from(JSON.stringify(body)), eof)
}

export function dataFrame(body, eof = false) {
  const payload = Buffer.from(body)
  const result = Buffer.alloc(4 + payload.length)
  result[0] = 1
  result[1] = eof ? 1 : 0
  result.writeUInt16BE(payload.length, 2)
  payload.copy(result, 4)
  return result
}

export function encodeEnvelope(streamID, payload, fin = true, recordType = 1, appError = 0) {
  const result = Buffer.alloc(envelopeHeaderSize + payload.length)
  result[0] = 1
  result[1] = recordType
  result[2] = fin ? 1 : 0
  result.writeBigUInt64BE(streamID, 4)
  result.writeUInt32BE(appError, 12)
  result.writeUInt32BE(payload.length, 16)
  payload.copy(result, envelopeHeaderSize)
  return result
}

export function maskedFrame(payload, opcode = 0x02, fin = true) {
  const mask = crypto.randomBytes(4)
  let header
  if (payload.length <= 125) {
    header = Buffer.from([(fin ? 0x80 : 0) | opcode, 0x80 | payload.length])
  } else if (payload.length <= 0xffff) {
    header = Buffer.alloc(4)
    header[0] = (fin ? 0x80 : 0) | opcode
    header[1] = 0x80 | 126
    header.writeUInt16BE(payload.length, 2)
  } else {
    header = Buffer.alloc(10)
    header[0] = (fin ? 0x80 : 0) | opcode
    header[1] = 0x80 | 127
    header.writeBigUInt64BE(BigInt(payload.length), 2)
  }
  const body = Buffer.alloc(payload.length)
  for (let index = 0; index < payload.length; index += 1) body[index] = payload[index] ^ mask[index & 3]
  return Buffer.concat([header, mask, body])
}

function maskedBinary(payload) {
  return maskedFrame(payload)
}

export function decodeFrames(bytes) {
  const frames = []
  let offset = 0
  while (offset < bytes.length) {
    if (bytes.length - offset < 4) throw new Error('Lyune response frame truncated')
    const type = bytes[offset]
    const headerLength = type === 0 ? 8 : type === 1 ? 4 : 0
    if (headerLength === 0 || bytes.length - offset < headerLength) throw new Error('unknown Lyune response frame')
    const bodyLength = bytes.readUInt16BE(offset + 2)
    const end = offset + headerLength + bodyLength
    if (end > bytes.length) throw new Error('Lyune response frame length mismatch')
    frames.push({
      type,
      flags: bytes[offset + 1],
      dest: type === 0 ? bytes[offset + 4] : 0,
      response: type === 0 ? bytes[offset + 5] : 0,
      group: type === 0 ? bytes[offset + 6] : 0,
      route: type === 0 ? bytes[offset + 7] : 0,
      body: bytes.subarray(offset + headerLength, end),
    })
    offset = end
  }
  return frames
}

function decodeFrame(bytes) {
  if (bytes.length < 8) throw new Error('Lyune response frame truncated')
  const frames = decodeFrames(bytes)
  if (frames.length !== 1 || frames[0].type !== 0) throw new Error('expected exactly one Lyune OPEN response')
  return frames[0]
}

export class WssValidationClient {
  constructor() {
    this.socket = null
    this.input = Buffer.alloc(0)
    this.upgraded = false
    this.key = crypto.randomBytes(16).toString('base64')
    this.nextStreamID = 0n
    this.pending = new Map()
    this.pushes = new Map()
    this.events = []
    this.eventWaiters = []
    this.websocketCloseCode = null
  }

  connect() {
    return new Promise((resolve, reject) => {
      const socket = tls.connect({ host, port, servername: serverName, rejectUnauthorized: false })
      this.socket = socket
      const timer = setTimeout(() => {
        socket.destroy()
        reject(new Error('WSS connect timeout'))
      }, 5000)
      socket.once('error', reject)
      socket.once('secureConnect', () => {
        socket.write(
          `GET /lyune/v2 HTTP/1.1\r\n` +
          `Host: ${serverName}:${port}\r\n` +
          `Origin: ${origin}\r\n` +
          `Upgrade: websocket\r\n` +
          `Connection: Upgrade\r\n` +
          `Sec-WebSocket-Version: 13\r\n` +
          `Sec-WebSocket-Key: ${this.key}\r\n` +
          `Sec-WebSocket-Protocol: lyune.v2\r\n\r\n`,
        )
      })
      socket.on('data', (chunk) => {
        this.input = Buffer.concat([this.input, chunk])
        if (!this.upgraded) {
          const end = this.input.indexOf('\r\n\r\n')
          if (end < 0) return
          const head = this.input.subarray(0, end + 4).toString('ascii')
          this.input = this.input.subarray(end + 4)
          if (!head.startsWith('HTTP/1.1 101 ') || !/Sec-WebSocket-Protocol:\s*lyune\.v2/i.test(head)) {
            socket.destroy()
            reject(new Error(`Upgrade rejected: ${head.split('\r\n')[0]}`))
            return
          }
          const expected = crypto.createHash('sha1').update(this.key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64')
          if (!head.toLowerCase().includes(`sec-websocket-accept: ${expected}`.toLowerCase())) {
            socket.destroy()
            reject(new Error('invalid Sec-WebSocket-Accept'))
            return
          }
          clearTimeout(timer)
          this.upgraded = true
          resolve()
        }
        this.drainWebSocket()
      })
      socket.on('close', () => {
        clearTimeout(timer)
        if (!this.upgraded) reject(new Error('WSS closed before Upgrade'))
        for (const pending of this.pending.values()) pending.reject(new Error('WSS closed'))
        this.pending.clear()
        for (const waiter of this.eventWaiters) waiter.reject(new Error('WSS closed'))
        this.eventWaiters = []
      })
    })
  }

  exchange(frame, noResponse = false) {
    const active = this.beginExchange({ noResponse })
    active.send(frame, true)
    return active.result
  }

  beginExchange({ noResponse = false, rawResponse = false, onChunk = null, timeoutMS = 8000 } = {}) {
    const streamID = this.nextStreamID
    this.nextStreamID += 4n
    const result = new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(streamID)
        reject(new Error(`stream ${streamID} timeout`))
      }, timeoutMS)
      this.pending.set(streamID, { chunks: [], noResponse, rawResponse, onChunk, resolve, reject, timer })
    })
    return {
      streamID,
      result,
      send: (payload, fin = false) => this.sendStreamRecord(streamID, payload, fin),
      reset: (appError = 0) => this.sendControlRecord(2, streamID, appError),
      stop: (appError = 0) => this.sendControlRecord(3, streamID, appError),
    }
  }

  sendStreamRecord(streamID, payload, fin = true) {
    this.socket.write(maskedBinary(encodeEnvelope(BigInt(streamID), Buffer.from(payload), fin)))
  }

  sendControlRecord(recordType, streamID, appError = 0) {
    if (recordType !== 2 && recordType !== 3) throw new Error('control record must be RESET(2) or STOP(3)')
    this.socket.write(maskedBinary(encodeEnvelope(BigInt(streamID), Buffer.alloc(0), false, recordType, appError)))
  }

  sendRawWebSocketBytes(bytes) {
    this.socket.write(bytes)
  }

  waitForClose(timeoutMS = 3000) {
    if (this.socket.destroyed) return Promise.resolve(this.websocketCloseCode)
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('WSS close timeout')), timeoutMS)
      this.socket.once('close', () => {
        clearTimeout(timer)
        resolve(this.websocketCloseCode)
      })
    })
  }

  async authenticate(username, password, action = 'login') {
    const auth = await this.exchange(openFrame(0, 0, 0x10, 0, { action, username, password }))
    if (auth.type !== 0 || auth.dest !== 0 || auth.route !== 0x11 || auth.body.length < 12) {
      throw new Error(`authentication rejected: route=0x${auth.route.toString(16)} body=${auth.body.toString()}`)
    }
    const destID = auth.body.readBigUInt64BE(0)
    const ttl = auth.body.readUInt32BE(8)
    const session = JSON.parse(textDecoder.decode(auth.body.subarray(12)))
    if (!session.ok || !session.token) throw new Error('authentication service returned invalid session')
    return { destID, ttl, ...session }
  }

  async command(token, request) {
    const noResponse = request.type === 'typing'
    const response = await this.exchange(openFrame(1, 1, 2, noResponse ? 1 : 0, { ...request, token }), noResponse)
    if (noResponse) return { ok: true, type: 'accepted' }
    if (response.type !== 0 || response.dest !== 1) throw new Error('invalid service response')
    const result = JSON.parse(textDecoder.decode(response.body))
    if (!result.ok) throw new Error(result.error ?? 'service rejected request')
    return result
  }

  waitForPush(predicate, timeoutMS = 8000) {
    const existing = this.events.find(predicate)
    if (existing) return Promise.resolve(existing)
    return new Promise((resolve, reject) => {
      const waiter = { predicate, resolve, reject, timer: null }
      waiter.timer = setTimeout(() => {
        this.eventWaiters = this.eventWaiters.filter((candidate) => candidate !== waiter)
        reject(new Error('push timeout'))
      }, timeoutMS)
      this.eventWaiters.push(waiter)
    })
  }

  drainWebSocket() {
    while (this.upgraded && this.input.length >= 2) {
      const first = this.input[0]
      const second = this.input[1]
      if ((second & 0x80) !== 0) throw new Error('server WebSocket frame must not be masked')
      let length = second & 0x7f
      let offset = 2
      if (length === 126) {
        if (this.input.length < 4) return
        length = this.input.readUInt16BE(2)
        offset = 4
      } else if (length === 127) {
        if (this.input.length < 10) return
        length = Number(this.input.readBigUInt64BE(2))
        offset = 10
      }
      if (this.input.length < offset + length) return
      const payload = this.input.subarray(offset, offset + length)
      this.input = this.input.subarray(offset + length)
      const opcode = first & 0x0f
      if (opcode === 0x8) {
        this.websocketCloseCode = payload.length >= 2 ? payload.readUInt16BE(0) : 1005
        this.socket.end()
        continue
      }
      if (opcode === 0x9 || opcode === 0xA) continue
      if (opcode !== 0x2 || (first & 0x80) === 0) throw new Error('unexpected server WebSocket frame')
      this.handleEnvelope(payload)
    }
  }

  handleEnvelope(bytes) {
    if (bytes.length < envelopeHeaderSize || bytes[0] !== 1) throw new Error('invalid WSS envelope')
    const payloadLength = bytes.readUInt32BE(16)
    if (bytes.length !== envelopeHeaderSize + payloadLength) throw new Error('WSS envelope length mismatch')
    const type = bytes[1]
    const streamID = bytes.readBigUInt64BE(4)
    const pending = this.pending.get(streamID)
    if (!pending) {
      if ((streamID & 3n) === 1n && type === 1) this.handlePush(streamID, bytes)
      return
    }
    if (type === 2 || type === 3) {
      clearTimeout(pending.timer)
      this.pending.delete(streamID)
      pending.reject(new Error(`stream ${streamID} canceled by Gateway`))
      return
    }
    if (type !== 1) return
    const payload = bytes.subarray(envelopeHeaderSize)
    if (payload.length > 0) {
      const owned = Buffer.from(payload)
      pending.chunks.push(owned)
      pending.onChunk?.(owned, (bytes[2] & 1) !== 0)
    }
    if ((bytes[2] & 1) === 0) return
    clearTimeout(pending.timer)
    this.pending.delete(streamID)
    const response = concat(pending.chunks)
    if (pending.noResponse) {
      if (response.length === 0) pending.resolve(null)
      else pending.reject(new Error('response_mode=none returned application bytes'))
    } else if (pending.rawResponse) {
      pending.resolve(response)
    } else {
      pending.resolve(decodeFrame(response))
    }
  }

  handlePush(streamID, envelopeBytes) {
    const chunks = this.pushes.get(streamID) ?? []
    const payload = envelopeBytes.subarray(envelopeHeaderSize)
    if (payload.length > 0) chunks.push(Buffer.from(payload))
    if ((envelopeBytes[2] & 1) === 0) {
      this.pushes.set(streamID, chunks)
      return
    }
    this.pushes.delete(streamID)
    const frame = decodeFrame(concat(chunks))
    if (frame.type !== 0 || frame.dest !== 2 || (frame.flags & 1) === 0 || frame.body.length < 2) {
      throw new Error('invalid Gateway-initiated .peer push')
    }
    const count = frame.body.readUInt16BE(0)
    const prefix = 2 + count * 8
    if (frame.body.length < prefix) throw new Error('push target list truncated')
    const targets = []
    for (let index = 0; index < count; index += 1) targets.push(frame.body.readBigUInt64BE(2 + index * 8))
    const event = { targets, payload: JSON.parse(textDecoder.decode(frame.body.subarray(prefix))) }
    this.events.push(event)
    for (const waiter of [...this.eventWaiters]) {
      if (!waiter.predicate(event)) continue
      clearTimeout(waiter.timer)
      this.eventWaiters = this.eventWaiters.filter((candidate) => candidate !== waiter)
      waiter.resolve(event)
    }

    // 收敛 server-initiated bidi logical stream 的客户端发送方向。
    this.socket.write(maskedBinary(encodeEnvelope(streamID, Buffer.alloc(0))))
  }

  close() {
    this.socket?.end()
  }
}

async function main() {
  const [, , username, password] = process.argv
  if (!username || !password) {
    console.error('usage: node validation/wss-smoke.mjs <username> <password>')
    process.exitCode = 2
    return
  }

  const client = new WssValidationClient()
  try {
    await client.connect()
    const session = await client.authenticate(username, password)
    const result = await client.command(session.token, { type: 'list_groups' })
    console.log(JSON.stringify({
      ok: true,
      transport: 'wss',
      username,
      dest_id: session.destID.toString(),
      ttl: session.ttl,
      groups: result.groups.length,
    }))
  } finally {
    client.close()
  }
}

if (fileURLToPath(import.meta.url) === process.argv[1]) await main()
