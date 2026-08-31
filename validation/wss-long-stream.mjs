#!/usr/bin/env node

// WSS M8 长流门禁：同一物理 WebSocket 上，一条 logical stream 每 30 秒保持应用活动并
// 持续超过 120 秒；它的静默 sibling 在 60 秒回收且 75 秒迟到 DATA 不得误伤活跃流。

import crypto from 'node:crypto'
import {
  WssValidationClient,
  dataFrame,
  decodeFrames,
  openBytesFrame,
} from './wss-smoke.mjs'

const client = new WssValidationClient()
const password = 'Wss-long-valid-password-2026'
const username = `wss_long_${crypto.randomBytes(5).toString('hex')}`

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

try {
  await client.connect()
  const session = await client.authenticate(username, password, 'register')
  const started = Date.now()
  const activeChunks = []

  const active = client.beginExchange({
    rawResponse: true,
    timeoutMS: 145000,
    onChunk: () => activeChunks.push(Date.now() - started),
  })
  active.send(openBytesFrame(1, 1, 0, 0, 'active-0', false), false)

  const silent = client.beginExchange({ rawResponse: true, timeoutMS: 90000 })
  const silentOutcome = silent.result.then(
    (bytes) => ({ kind: 'response', at: Date.now() - started, frames: decodeFrames(bytes) }),
    (error) => ({ kind: 'canceled', at: Date.now() - started, error: String(error) }),
  )
  silent.send(openBytesFrame(1, 1, 0, 0, 'silent-head', false), false)

  await sleep(30000)
  active.send(dataFrame('active-30'), false)
  await sleep(30000)
  active.send(dataFrame('active-60'), false)

  const silentResult = await silentOutcome
  if (silentResult.at < 55000 || silentResult.at > 80000) {
    throw new Error(`silent sibling ended outside its timeout window: ${JSON.stringify(silentResult)}`)
  }

  const waitUntil75 = 75000 - (Date.now() - started)
  if (waitUntil75 > 0) await sleep(waitUntil75)
  // 这条流已经过期；迟到 DATA 只能被丢弃，不能把后端单流错误放大成共享连接故障。
  silent.send(dataFrame('late-after-timeout', true), true)

  const waitUntil90 = 90000 - (Date.now() - started)
  if (waitUntil90 > 0) await sleep(waitUntil90)
  active.send(dataFrame('active-90'), false)

  const waitUntil120 = 120000 - (Date.now() - started)
  if (waitUntil120 > 0) await sleep(waitUntil120)
  active.send(dataFrame('active-120', true), true)

  const frames = decodeFrames(await active.result)
  const bodies = frames.map((frame) => frame.body.toString())
  const expected = ['echo: active-0', 'echo: active-30', 'echo: active-60', 'echo: active-90', 'echo: active-120']
  if (bodies.length !== expected.length || bodies.some((body, index) => body !== expected[index])) {
    throw new Error(`active long stream changed: ${JSON.stringify(bodies)}`)
  }

  const ping = await client.exchange(openBytesFrame(0, 0, 0x02, 0, 'after-long-stream'))
  if (ping.route !== 0x03 || ping.body.toString() !== 'after-long-stream') {
    throw new Error('WSS connection did not survive the long-stream sibling timeout')
  }

  console.log(JSON.stringify({
    ok: true,
    username,
    dest_id: session.destID.toString(),
    duration_ms: Date.now() - started,
    active_response_ms: activeChunks,
    active_frames: frames.length,
    silent_sibling: {
      kind: silentResult.kind,
      ended_ms: silentResult.at,
      detail: silentResult.kind === 'response'
        ? silentResult.frames.map((frame) => frame.body.toString())
        : silentResult.error,
    },
    late_data: 'isolated',
    post_timeout_ping: 'passed',
  }))
} finally {
  client.close()
}
