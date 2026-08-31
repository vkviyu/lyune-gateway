#!/usr/bin/env node

// 真实混合传输场景：两个浏览器等价 WSS 用户与一个 Raw QUIC client-agent 用户
// 进入同一 SQLite 群，覆盖 WSS↔WSS、WSS↔Raw 的持久消息与 Gateway .peer 推送。

import crypto from 'node:crypto'
import { WssValidationClient } from './wss-smoke.mjs'

const agentBase = 'http://127.0.0.1:8787'
const password = 'Wss-mixed-valid-password-2026'
const suffix = crypto.randomBytes(5).toString('hex')
const wssAUsername = `wss_a_${suffix}`
const wssBUsername = `wss_b_${suffix}`
const rawUsername = `raw_${suffix}`

async function agent(path, init) {
  const response = await fetch(agentBase + path, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...init?.headers },
  })
  const result = await response.json()
  if (!response.ok) throw new Error(result.error ?? `agent HTTP ${response.status}`)
  return result
}

async function rawCommand(sessionID, request) {
  return agent('/api/im/command', {
    method: 'POST',
    body: JSON.stringify({ session_id: sessionID, ...request }),
  })
}

async function waitRawPush(sessionID, predicate, timeoutMS = 8000) {
  const deadline = Date.now() + timeoutMS
  let after = 0
  while (Date.now() < deadline) {
    const result = await agent(`/api/im/events?session_id=${encodeURIComponent(sessionID)}&after=${after}&timeout_ms=1000`)
    for (const event of result.events) {
      after = Math.max(after, event.seq)
      if (predicate(event)) return event
    }
  }
  throw new Error('Raw QUIC push timeout')
}

let rawSession = null
const wssA = new WssValidationClient()
const wssB = new WssValidationClient()
try {
  await Promise.all([wssA.connect(), wssB.connect()])
  const [wssASession, wssBSession] = await Promise.all([
    wssA.authenticate(wssAUsername, password, 'register'),
    wssB.authenticate(wssBUsername, password, 'register'),
  ])
  rawSession = await agent('/api/im/auth', {
    method: 'POST',
    body: JSON.stringify({
      action: 'register',
      username: rawUsername,
      password,
      address: '127.0.0.1:8443',
      server_name: 'localhost',
      insecure_skip_verify: true,
    }),
  })

  const created = await wssA.command(wssASession.token, { type: 'create_group', name: `WSS mixed ${suffix}` })
  const group = created.group
  if (!group?.id || !group.invite_code) throw new Error('WSS create_group returned no group')

  const [wssDenied, rawDenied] = await Promise.all([
    wssB.command(wssBSession.token, { type: 'history', group_id: group.id }).then(
      () => false,
      () => true,
    ),
    rawCommand(rawSession.session_id, { type: 'history', group_id: group.id }),
  ])
  if (!wssDenied) throw new Error('second WSS user read history before joining')
  if (rawDenied.ok !== false) throw new Error('Raw user read history before joining')

  const [wssJoined, rawJoined] = await Promise.all([
    wssB.command(wssBSession.token, { type: 'join_group', invite_code: group.invite_code }),
    rawCommand(rawSession.session_id, { type: 'join_group', invite_code: group.invite_code }),
  ])
  if (wssJoined.group?.id !== group.id) throw new Error('second WSS user failed to join WSS-created group')
  if (!rawJoined.ok || rawJoined.group?.id !== group.id) throw new Error('Raw user failed to join WSS-created group')

  const wssAText = `WSS-A-to-all-${suffix}`
  const rawPushPromise = waitRawPush(
    rawSession.session_id,
    (event) => event.payload?.type === 'message' && event.payload.message?.text === wssAText,
  )
  const wssBPushPromise = wssB.waitForPush(
    (event) => event.payload?.type === 'message' && event.payload.message?.text === wssAText,
  )
  const wssASend = await wssA.command(wssASession.token, { type: 'send_message', group_id: group.id, text: wssAText })
  const [rawPushFromA, wssBPushFromA] = await Promise.all([rawPushPromise, wssBPushPromise])
  if (!wssASend.message?.id ||
      rawPushFromA.payload.message?.id !== wssASend.message.id ||
      wssBPushFromA.payload.message?.id !== wssASend.message.id) {
    throw new Error('WSS A -> WSS B/Raw persisted response and pushes disagree')
  }

  const wssBText = `WSS-B-to-all-${suffix}`
  const rawPushFromBPromise = waitRawPush(
    rawSession.session_id,
    (event) => event.payload?.type === 'message' && event.payload.message?.text === wssBText,
  )
  const wssAPushFromBPromise = wssA.waitForPush(
    (event) => event.payload?.type === 'message' && event.payload.message?.text === wssBText,
  )
  const wssBSend = await wssB.command(wssBSession.token, { type: 'send_message', group_id: group.id, text: wssBText })
  const [rawPushFromB, wssAPushFromB] = await Promise.all([rawPushFromBPromise, wssAPushFromBPromise])
  if (!wssBSend.message?.id ||
      rawPushFromB.payload.message?.id !== wssBSend.message.id ||
      wssAPushFromB.payload.message?.id !== wssBSend.message.id) {
    throw new Error('WSS B -> WSS A/Raw persisted response and pushes disagree')
  }

  const rawText = `QUIC-to-all-${suffix}`
  const wssAPushFromRawPromise = wssA.waitForPush(
    (event) => event.payload?.type === 'message' && event.payload.message?.text === rawText,
  )
  const wssBPushFromRawPromise = wssB.waitForPush(
    (event) => event.payload?.type === 'message' && event.payload.message?.text === rawText,
  )
  const rawSend = await rawCommand(rawSession.session_id, { type: 'send_message', group_id: group.id, text: rawText })
  const [wssAPushFromRaw, wssBPushFromRaw] = await Promise.all([wssAPushFromRawPromise, wssBPushFromRawPromise])
  if (!rawSend.message?.id ||
      wssAPushFromRaw.payload.message?.id !== rawSend.message.id ||
      wssBPushFromRaw.payload.message?.id !== rawSend.message.id) {
    throw new Error('Raw QUIC -> both WSS persisted response and pushes disagree')
  }

  // response_mode=none 也必须在 WSS 上得到空 FIN，而不是应用响应或悬挂。
  await wssB.command(wssBSession.token, { type: 'typing', group_id: group.id })

  const history = await wssA.command(wssASession.token, { type: 'history', group_id: group.id })
  const ids = new Set((history.messages ?? []).map((message) => message.id))
  if (!ids.has(wssASend.message.id) || !ids.has(wssBSend.message.id) || !ids.has(rawSend.message.id)) {
    throw new Error('SQLite history is missing a mixed-transport message')
  }

  console.log(JSON.stringify({
    ok: true,
    group_id: group.id,
    wss: [
      { username: wssAUsername, dest_id: wssASession.destID.toString() },
      { username: wssBUsername, dest_id: wssBSession.destID.toString() },
    ],
    raw_quic: { username: rawUsername, dest_id: rawSession.dest_id },
    messages: [wssASend.message.id, wssBSend.message.id, rawSend.message.id],
    response_none: 'empty-fin',
    history: 'consistent',
  }))
} finally {
  wssA.close()
  wssB.close()
  if (rawSession?.session_id) {
    await agent('/api/im/logout', {
      method: 'POST',
      body: JSON.stringify({ session_id: rawSession.session_id }),
    }).catch(() => undefined)
  }
}
