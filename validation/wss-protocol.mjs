#!/usr/bin/env node

// WSS 传输的 M2–M5/M10/M13 原生协议门禁。这里不经过浏览器 HTTP agent：一条真实
// TLS/WebSocket 连接上直接复用 logical streams，验证网关控制交换、流式响应、并发
// 关联、无响应模式和方向取消都与 Raw QUIC 保持相同的业务可观察语义。

import crypto from 'node:crypto'
import {
  WssValidationClient,
  dataFrame,
  decodeFrames,
  openBytesFrame,
} from './wss-smoke.mjs'

const client = new WssValidationClient()
const password = 'Wss-protocol-valid-password-2026'
const username = `wss_protocol_${crypto.randomBytes(5).toString('hex')}`

function assert(condition, message) {
  if (!condition) throw new Error(message)
}

function timeout(ms, message) {
  return new Promise((_, reject) => setTimeout(() => reject(new Error(message)), ms))
}

async function expectCanceled(promise, label) {
  try {
    await promise
  } catch (error) {
    if (String(error).includes('canceled by Gateway')) return
    throw new Error(`${label}: unexpected rejection: ${error}`)
  }
  throw new Error(`${label}: logical stream ended successfully instead of being canceled`)
}

function assertPong(frame, payload) {
  assert(frame.type === 0 && frame.dest === 0 && frame.route === 0x03, 'Gateway ping did not return pong')
  assert(frame.body.toString() === payload, 'Gateway pong body changed')
}

try {
  await client.connect()

  // M2：网关本地处理，不经过 Reactor。
  const pingBody = `wss-ping-${crypto.randomBytes(3).toString('hex')}`
  assertPong(await client.exchange(openBytesFrame(0, 0, 0x02, 0, pingBody)), pingBody)

  const session = await client.authenticate(username, password, 'register')

  // M3：单帧 service echo。
  const single = await client.exchange(openBytesFrame(1, 1, 0, 0, 'single'))
  assert(single.dest === 1 && single.group === 1 && single.route === 0, 'single echo route changed')
  assert(single.body.toString() === 'echo: single', 'single echo body changed')

  // M4：请求尚未结束时就必须看到前两段响应；最后一段再用应用 EOF + transport FIN 收尾。
  const observed = []
  let firstChunkResolve
  let secondChunkResolve
  const firstChunk = new Promise((resolve) => { firstChunkResolve = resolve })
  const secondChunk = new Promise((resolve) => { secondChunkResolve = resolve })
  const streaming = client.beginExchange({
    rawResponse: true,
    onChunk: (chunk) => {
      observed.push({ at: Date.now(), bytes: Buffer.from(chunk) })
      if (observed.length === 1) firstChunkResolve()
      if (observed.length === 2) secondChunkResolve()
    },
  })
  const streamingStarted = Date.now()
  streaming.send(openBytesFrame(1, 1, 0, 0, 'head', false), false)
  await Promise.race([firstChunk, timeout(2000, 'streaming echo did not answer OPEN before request EOF')])
  streaming.send(dataFrame('middle'), false)
  await Promise.race([secondChunk, timeout(2000, 'streaming echo did not answer DATA before request EOF')])
  const finalSentAt = Date.now()
  streaming.send(dataFrame('tail', true), true)
  const streamingFrames = decodeFrames(await streaming.result)
  assert(streamingFrames.length === 3, `streaming echo returned ${streamingFrames.length} frames instead of 3`)
  assert(streamingFrames.map((frame) => frame.body.toString()).join('|') === 'echo: head|echo: middle|echo: tail', 'streaming echo reordered or changed frames')
  assert(observed[0].at <= finalSentAt && observed[1].at <= finalSentAt, 'streaming responses were delayed until request FIN')

  // M5：同一物理 WSS 上 32 条 logical streams 并发，响应必须仍按各自 id 关联。
  const concurrent = await Promise.all(Array.from({ length: 32 }, async (_, index) => {
    const body = `parallel-${index}`
    const response = await client.exchange(openBytesFrame(1, 1, 0, 0, body))
    assert(response.body.toString() === `echo: ${body}`, `parallel stream ${index} received another stream's response`)
    return response
  }))
  assert(concurrent.length === 32, '32-stream WSS concurrency did not complete')

  // M10：none 只能返回空 FIN，不能回 Reactor 的 echo 字节或悬挂。
  const noResponse = await client.exchange(openBytesFrame(1, 1, 0, 1, 'discard-this-response'), true)
  assert(noResponse === null, 'response_mode=none did not finish with an empty FIN')

  // M13 / RESET：未带应用 EOF 的请求输入被取消后，Gateway 必须明确 reset 返回方向，
  // 且不能关闭承载其他 logical streams 的 WSS 会话。
  const resetExchange = client.beginExchange({ rawResponse: true })
  resetExchange.send(openBytesFrame(1, 1, 0, 0, 'reset-head', false), false)
  resetExchange.reset(0x101)
  await expectCanceled(resetExchange.result, 'RESET input')
  const afterReset = await client.exchange(openBytesFrame(0, 0, 0x02, 0, 'after-reset'))
  assertPong(afterReset, 'after-reset')

  // M13 / STOP：请求已建立后停止返回方向，Gateway 回 RESET 收敛发送状态；请求输入仍可
  // 正常补完，随后同连接上的新 exchange 必须继续可用。
  const stopExchange = client.beginExchange({ rawResponse: true })
  stopExchange.send(openBytesFrame(1, 1, 0, 0, 'stop-head', false), false)
  stopExchange.stop(0x102)
  stopExchange.send(dataFrame('stop-tail', true), true)
  await expectCanceled(stopExchange.result, 'STOP response')
  const afterStop = await client.exchange(openBytesFrame(0, 0, 0x02, 0, 'after-stop'))
  assertPong(afterStop, 'after-stop')

  console.log(JSON.stringify({
    ok: true,
    username,
    dest_id: session.destID.toString(),
    gateway_control: 'pong',
    single_echo: 'passed',
    streaming_echo: {
      frames: streamingFrames.length,
      first_response_ms: observed[0].at - streamingStarted,
      second_response_before_fin: observed[1].at <= finalSentAt,
    },
    concurrent_streams: concurrent.length,
    response_none: 'empty-fin',
    reset_then_ping: 'passed',
    stop_then_ping: 'passed',
  }))
} finally {
  client.close()
}
