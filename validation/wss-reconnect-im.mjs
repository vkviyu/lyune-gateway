#!/usr/bin/env node

// 真实 WSS 断线补偿：接收者离线期间不要求 Gateway 缓存在线 push；消息由 Reactor
// 先写 SQLite。接收者重新登录后必须从历史读到遗漏消息，并能在新会话上恢复实时推送。

import crypto from 'node:crypto'
import { WssValidationClient } from './wss-smoke.mjs'

const password = 'Wss-reconnect-valid-password-2026'
const suffix = crypto.randomBytes(5).toString('hex')
const senderUsername = `wr_s_${suffix}`
const receiverUsername = `wr_r_${suffix}`

const sender = new WssValidationClient()
const receiver = new WssValidationClient()
let recovered = null

try {
  await Promise.all([sender.connect(), receiver.connect()])
  const [senderSession, receiverSession] = await Promise.all([
    sender.authenticate(senderUsername, password, 'register'),
    receiver.authenticate(receiverUsername, password, 'register'),
  ])

  const created = await sender.command(senderSession.token, {
    type: 'create_group',
    name: `WSS reconnect ${suffix}`,
  })
  const group = created.group
  if (!group?.id || !group.invite_code) throw new Error('create_group returned no group')
  const joined = await receiver.command(receiverSession.token, {
    type: 'join_group',
    invite_code: group.invite_code,
  })
  if (joined.group?.id !== group.id) throw new Error('receiver failed to join group')

  const receiverClosed = receiver.waitForClose()
  receiver.close()
  await receiverClosed
  // 让 Gateway 完成本地 SessionHandle/lifecycle 回收，再制造真正的离线窗口。
  await new Promise((resolve) => setTimeout(resolve, 50))

  const missedText = `persisted-while-offline-${suffix}`
  const missed = await sender.command(senderSession.token, {
    type: 'send_message',
    group_id: group.id,
    text: missedText,
  })
  if (!missed.message?.id) throw new Error('offline-window message was not persisted')

  recovered = new WssValidationClient()
  await recovered.connect()
  const recoveredSession = await recovered.authenticate(receiverUsername, password)
  const history = await recovered.command(recoveredSession.token, { type: 'history', group_id: group.id })
  const recoveredMessage = (history.messages ?? []).find((message) => message.id === missed.message.id)
  if (recoveredMessage?.text !== missedText) throw new Error('reconnected receiver did not recover SQLite history')

  const liveText = `live-after-reconnect-${suffix}`
  const livePushPromise = sender.waitForPush(
    (event) => event.payload?.type === 'message' && event.payload.message?.text === liveText,
  )
  const live = await recovered.command(recoveredSession.token, {
    type: 'send_message',
    group_id: group.id,
    text: liveText,
  })
  const livePush = await livePushPromise
  if (!live.message?.id || livePush.payload.message?.id !== live.message.id) {
    throw new Error('reconnected WSS session did not restore live push')
  }

  console.log(JSON.stringify({
    ok: true,
    group_id: group.id,
    sender: { username: senderUsername, dest_id: senderSession.destID.toString() },
    receiver: { username: receiverUsername, dest_id: receiverSession.destID.toString() },
    missed_message_id: missed.message.id,
    recovery: 'sqlite-history',
    live_message_id: live.message.id,
    live_push: 'restored',
  }))
} finally {
  sender.close()
  receiver.close()
  recovered?.close()
}
