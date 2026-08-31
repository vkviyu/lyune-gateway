#!/usr/bin/env node

// 真实慢消费者隔离：一个 WSS 群成员完成认证后暂停 TCP 读取；发送者继续写入真实
// SQLite 消息并接收自己的 push。当慢会话的 kernel/TLS/有界明文队列耗尽后，Gateway
// 必须只关闭它，健康会话仍能请求、持久化和接收 push。

import crypto from 'node:crypto'
import { WssValidationClient } from './wss-smoke.mjs'

const password = 'Wss-slow-valid-password-2026'
const suffix = crypto.randomBytes(5).toString('hex')
const senderUsername = `ws_s_${suffix}`
const slowUsername = `ws_c_${suffix}`
const messageCount = 1200
const batchSize = 16

const sender = new WssValidationClient()
const slow = new WssValidationClient()

try {
  await Promise.all([sender.connect(), slow.connect()])
  const [senderSession, slowSession] = await Promise.all([
    sender.authenticate(senderUsername, password, 'register'),
    slow.authenticate(slowUsername, password, 'register'),
  ])
  const created = await sender.command(senderSession.token, {
    type: 'create_group',
    name: `WSS slow ${suffix}`,
  })
  const group = created.group
  if (!group?.id || !group.invite_code) throw new Error('create_group returned no group')
  await slow.command(slowSession.token, { type: 'join_group', invite_code: group.invite_code })

  // 停止 Node 从 TLS socket 取数据，但不主动关闭连接；这是一个真实 TCP 慢接收端。
  slow.socket.pause()
  let persisted = 0
  for (let start = 0; start < messageCount; start += batchSize) {
    const batch = []
    for (let offset = 0; offset < batchSize && start + offset < messageCount; offset += 1) {
      const index = start + offset
      const prefix = `slow-${suffix}-${index}-`
      const text = prefix + 'x'.repeat(1900 - prefix.length)
      batch.push(sender.command(senderSession.token, {
        type: 'send_message',
        group_id: group.id,
        text,
      }))
    }
    const results = await Promise.all(batch)
    for (const result of results) {
      if (!result.message?.id) throw new Error('sender did not receive persisted message id')
      persisted += 1
    }
  }

  const slowClosed = slow.waitForClose(10000)
  slow.socket.resume()
  const closeCode = await slowClosed

  const health = await sender.command(senderSession.token, { type: 'list_groups' })
  if (!(health.groups ?? []).some((candidate) => candidate.id === group.id)) {
    throw new Error('healthy WSS session failed after slow-consumer isolation')
  }

  const finalText = `healthy-after-slow-close-${suffix}`
  const finalPushPromise = sender.waitForPush(
    (event) => event.payload?.type === 'message' && event.payload.message?.text === finalText,
  )
  const finalMessage = await sender.command(senderSession.token, {
    type: 'send_message',
    group_id: group.id,
    text: finalText,
  })
  const finalPush = await finalPushPromise
  if (!finalMessage.message?.id || finalPush.payload.message?.id !== finalMessage.message.id) {
    throw new Error('healthy WSS live push failed after slow-consumer isolation')
  }

  console.log(JSON.stringify({
    ok: true,
    group_id: group.id,
    sender: { username: senderUsername, dest_id: senderSession.destID.toString() },
    slow: { username: slowUsername, dest_id: slowSession.destID.toString() },
    persisted,
    slow_close_code: closeCode,
    healthy_request: 'passed',
    healthy_push: finalMessage.message.id,
  }))
} finally {
  sender.close()
  slow.close()
}
