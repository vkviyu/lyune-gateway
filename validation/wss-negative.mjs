#!/usr/bin/env node

// WSS binding 的真实网络负门禁。它专门检查 TCP/WebSocket 需要显式补齐、而 QUIC
// transport 原生保证的边界：logical stream 不可复用、未来 server stream 不可伪造、
// client frame 必须 masked。每个违规只关闭自己的会话，并返回 RFC 6455 protocol error。

import crypto from 'node:crypto'
import tls from 'node:tls'
import {
  WssValidationClient,
  encodeEnvelope,
  maskedFrame,
  openBytesFrame,
  openFrame,
} from './wss-smoke.mjs'

const password = 'Wss-negative-valid-password-2026'
const username = `wss_negative_${crypto.randomBytes(5).toString('hex')}`

async function expectProtocolClose(client, action, label) {
  action()
  const code = await client.waitForClose()
  if (code !== 1002) throw new Error(`${label}: expected WebSocket close 1002, got ${code}`)
}

function upgradeRequest({
  host = 'localhost:8444',
  origin = 'http://127.0.0.1:5173',
  path = '/lyune/v2',
  version = '13',
  protocol = 'lyune.v2',
  extra = '',
} = {}) {
  return `GET ${path} HTTP/1.1\r\n` +
    `Host: ${host}\r\n` +
    `Origin: ${origin}\r\n` +
    'Upgrade: websocket\r\n' +
    'Connection: Upgrade\r\n' +
    `Sec-WebSocket-Version: ${version}\r\n` +
    `Sec-WebSocket-Key: ${crypto.randomBytes(16).toString('base64')}\r\n` +
    `Sec-WebSocket-Protocol: ${protocol}\r\n` + extra + '\r\n'
}

async function expectUpgradeRejected(request, label) {
  await new Promise((resolve, reject) => {
    const socket = tls.connect({
      host: '127.0.0.1',
      port: 8444,
      servername: 'localhost',
      rejectUnauthorized: false,
    })
    let response = Buffer.alloc(0)
    let secure = false
    let settled = false
    const finish = (error) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      socket.destroy()
      if (error) reject(error)
      else if (response.toString('ascii').startsWith('HTTP/1.1 101 ')) reject(new Error(`${label}: invalid Upgrade was accepted`))
      else resolve()
    }
    const timer = setTimeout(() => finish(new Error(`${label}: rejection timeout`)), 3000)
    socket.once('secureConnect', () => {
      secure = true
      socket.write(request)
    })
    socket.on('data', (chunk) => {
      response = Buffer.concat([response, chunk])
      if (response.toString('ascii').startsWith('HTTP/1.1 101 ')) finish(new Error(`${label}: invalid Upgrade was accepted`))
    })
    socket.once('close', () => finish())
    socket.once('error', (error) => {
      // TLS 成功后的 ECONNRESET 是拒绝畸形 HTTP 的合法表现；握手本身失败则不是本用例。
      if (secure) finish()
      else finish(error)
    })
  })
}

const reuse = new WssValidationClient()
const futureServer = new WssValidationClient()
const unmasked = new WssValidationClient()
const reservedBits = new WssValidationClient()
const nonCanonical = new WssValidationClient()
const fragmentedControl = new WssValidationClient()
const oversized = new WssValidationClient()
const badEnvelope = new WssValidationClient()
const fragmentedValid = new WssValidationClient()
const healthy = new WssValidationClient()

try {
  await reuse.connect()
  const session = await reuse.authenticate(username, password, 'register')
  await expectProtocolClose(
    reuse,
    () => reuse.sendStreamRecord(0n, openFrame(1, 1, 2, 0, { type: 'list_groups', token: session.token })),
    'reused client logical stream',
  )

  await futureServer.connect()
  await futureServer.authenticate(username, password)
  await expectProtocolClose(
    futureServer,
    () => futureServer.sendStreamRecord(1n, Buffer.alloc(0), true),
    'forged future server logical stream',
  )

  await unmasked.connect()
  await expectProtocolClose(
    unmasked,
    () => unmasked.sendRawWebSocketBytes(Buffer.from([0x82, 0x00])),
    'unmasked client frame',
  )

  await reservedBits.connect()
  await expectProtocolClose(
    reservedBits,
    () => reservedBits.sendRawWebSocketBytes(Buffer.from([0xc2, 0x80, 0, 0, 0, 0])),
    'reserved WebSocket bits',
  )

  await nonCanonical.connect()
  await expectProtocolClose(
    nonCanonical,
    () => nonCanonical.sendRawWebSocketBytes(Buffer.from([0x82, 0xfe, 0, 0, 0, 0, 0, 0])),
    'non-canonical WebSocket length',
  )

  await fragmentedControl.connect()
  await expectProtocolClose(
    fragmentedControl,
    () => fragmentedControl.sendRawWebSocketBytes(maskedFrame(Buffer.from('?'), 0x09, false)),
    'fragmented ping control frame',
  )

  await oversized.connect()
  const oversizedHeader = Buffer.alloc(14)
  oversizedHeader[0] = 0x82
  oversizedHeader[1] = 0xff
  oversizedHeader.writeBigUInt64BE(70000n, 2)
  crypto.randomBytes(4).copy(oversizedHeader, 10)
  await expectProtocolClose(
    oversized,
    () => oversized.sendRawWebSocketBytes(oversizedHeader),
    'oversized WebSocket frame',
  )

  await badEnvelope.connect()
  const invalidRecord = encodeEnvelope(0n, openBytesFrame(0, 0, 0x02, 0, 'bad-version'))
  invalidRecord[0] = 2
  await expectProtocolClose(
    badEnvelope,
    () => badEnvelope.sendRawWebSocketBytes(maskedFrame(invalidRecord)),
    'unsupported WSS envelope version',
  )

  // 合法 binary message 可以跨 WebSocket fragments，控制帧也可以插在中间；重组后
  // 仍只生成一条 logical stream record。
  await fragmentedValid.connect()
  const fragmented = fragmentedValid.beginExchange()
  const record = encodeEnvelope(fragmented.streamID, openBytesFrame(0, 0, 0x02, 0, 'fragmented-ping'))
  const cut = Math.floor(record.length / 2)
  fragmentedValid.sendRawWebSocketBytes(maskedFrame(record.subarray(0, cut), 0x02, false))
  fragmentedValid.sendRawWebSocketBytes(maskedFrame(Buffer.from('?'), 0x09, true))
  fragmentedValid.sendRawWebSocketBytes(maskedFrame(record.subarray(cut), 0x00, true))
  const fragmentedPong = await fragmented.result
  if (fragmentedPong.route !== 0x03 || fragmentedPong.body.toString() !== 'fragmented-ping') {
    throw new Error('valid fragmented binary message did not round-trip')
  }

  await Promise.all([
    expectUpgradeRejected(upgradeRequest({ origin: 'https://evil.example' }), 'Origin allowlist'),
    expectUpgradeRejected(upgradeRequest({ host: 'evil.example:8444' }), 'Host/SNI mismatch'),
    expectUpgradeRejected(upgradeRequest({ path: '/wrong' }), 'wrong path'),
    expectUpgradeRejected(upgradeRequest({ protocol: 'other.v1' }), 'wrong subprotocol'),
    expectUpgradeRejected(upgradeRequest({ version: '12' }), 'wrong WebSocket version'),
    expectUpgradeRejected(upgradeRequest({ extra: `X-Fill: ${'x'.repeat(9000)}\r\n` }), 'oversized HTTP head'),
  ])

  // 所有畸形连接都只能伤到自己；最后一条全新的健康连接仍可真实认证。
  await healthy.connect()
  await healthy.authenticate(username, password)

  console.log(JSON.stringify({
    ok: true,
    username,
    rejected: [
      'stream-reuse', 'future-server-stream', 'unmasked-frame', 'reserved-bits',
      'non-canonical-length', 'fragmented-control', 'oversized-frame', 'bad-envelope-version',
      'origin', 'host-sni', 'path', 'subprotocol', 'websocket-version', 'oversized-http-head',
    ],
    fragmented_binary_with_ping: 'passed',
    healthy_login_after_negatives: 'passed',
    close_code: 1002,
  }))
} finally {
  reuse.close()
  futureServer.close()
  unmasked.close()
  reservedBits.close()
  nonCanonical.close()
  fragmentedControl.close()
  oversized.close()
  badEnvelope.close()
  fragmentedValid.close()
  healthy.close()
}
