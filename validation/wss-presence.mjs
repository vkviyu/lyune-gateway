#!/usr/bin/env node

// WSS 连接级 lifecycle/presence 门禁：同一真实用户的两条 WSS 会话必须分别发布
// conn_token，Reactor 聚合为 2；关闭一条后仍在线，保留会话跨过 15 秒续租周期后仍
// 在线，最后一条关闭后由独立观察者看到离线。

import crypto from 'node:crypto'
import { WssValidationClient } from './wss-smoke.mjs'

const suffix = crypto.randomBytes(5).toString('hex')
const password = 'Wss-presence-valid-password-2026'
const memberUsername = `wp_member_${suffix}`
const observerUsername = `wp_observer_${suffix}`

const memberA = new WssValidationClient()
const memberB = new WssValidationClient()
const observer = new WssValidationClient()

function findPresence(result, username) {
  return (result.presence ?? []).find((item) => item.user?.username === username)
}

async function waitForSessions(client, token, groupID, expected, timeoutMS = 5000) {
  const deadline = Date.now() + timeoutMS
  let last = null
  while (Date.now() < deadline) {
    const result = await client.command(token, { type: 'presence', group_id: groupID })
    last = findPresence(result, memberUsername)
    if (last?.online_sessions === expected && last.online === (expected > 0)) return last
    await new Promise((resolve) => setTimeout(resolve, 50))
  }
  throw new Error(`presence did not converge to ${expected} sessions: ${JSON.stringify(last)}`)
}

try {
  await Promise.all([memberA.connect(), memberB.connect(), observer.connect()])
  const memberSessionA = await memberA.authenticate(memberUsername, password, 'register')
  const [memberSessionB, observerSession] = await Promise.all([
    memberB.authenticate(memberUsername, password),
    observer.authenticate(observerUsername, password, 'register'),
  ])

  const created = await memberA.command(memberSessionA.token, {
    type: 'create_group',
    name: `WSS presence ${suffix}`,
  })
  const group = created.group
  if (!group?.id || !group.invite_code) throw new Error('create_group returned no group')
  await observer.command(observerSession.token, { type: 'join_group', invite_code: group.invite_code })

  await waitForSessions(observer, observerSession.token, group.id, 2)

  const memberBClosed = memberB.waitForClose()
  memberB.close()
  await memberBClosed
  await waitForSessions(observer, observerSession.token, group.id, 1)

  // Gateway 每 15 秒刷新仍在线连接的租约；跨过一轮后不能被 45 秒 Reactor lease
  // 当成孤儿，也不能因另一条同账号连接已经关闭而错误归零。
  await new Promise((resolve) => setTimeout(resolve, 16000))
  await waitForSessions(observer, observerSession.token, group.id, 1)

  const memberAClosed = memberA.waitForClose()
  memberA.close()
  await memberAClosed
  await waitForSessions(observer, observerSession.token, group.id, 0)

  console.log(JSON.stringify({
    ok: true,
    group_id: group.id,
    member: {
      username: memberUsername,
      dest_id_a: memberSessionA.destID.toString(),
      dest_id_b: memberSessionB.destID.toString(),
    },
    presence_sequence: [2, 1, 'renewed-after-16s', 0],
  }))
} finally {
  memberA.close()
  memberB.close()
  observer.close()
}
