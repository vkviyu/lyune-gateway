#!/usr/bin/env node

// 自包含的 WSS 进程故障门禁。脚本独立启动 Reactor/Gateway，保留一条真实 WSS 会话
// 穿过 Reactor 停止与恢复，再强杀 Gateway、重启并重新登录；SQLite 与 Reactor 进程
// 在 Gateway 重启期间保留，用来验证 conn_token incarnation 不会碰撞。

import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { WssValidationClient } from './wss-smoke.mjs'

const gatewayRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const reactorRoot = path.resolve(gatewayRoot, '../lyune-reactor/reactor')
const gatewayBinary = path.join(gatewayRoot, 'zig-out/bin/lyune_gateway')
const reactorBinary = process.env.LYUNE_REACTOR_BINARY || '/private/tmp/lyune-im-demo/lyune-reactor'
const suffix = crypto.randomBytes(5).toString('hex')
const username = `wss_fault_${suffix}`
const password = 'Wss-fault-valid-password-2026'
const runPrefix = `/private/tmp/lyune-wss-fault-${process.pid}`
const configPath = `${runPrefix}.json`
const databasePath = `${runPrefix}.sqlite`

if (!fs.existsSync(gatewayBinary)) throw new Error(`missing Gateway binary: ${gatewayBinary}`)
if (!fs.existsSync(reactorBinary)) throw new Error(`missing Reactor binary: ${reactorBinary}; run ./run-im-demo.sh once or set LYUNE_REACTOR_BINARY`)

const baseConfig = JSON.parse(fs.readFileSync(path.join(gatewayRoot, 'config/validation-im-macos.json'), 'utf8'))
baseConfig.runtime.threads = 1
fs.writeFileSync(configPath, JSON.stringify(baseConfig, null, 2))

const children = new Set()
let reactorLog = ''
let gatewayLog = ''

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

function capture(child, sink) {
  child.stdout.on('data', (chunk) => sink(chunk.toString()))
  child.stderr.on('data', (chunk) => sink(chunk.toString()))
  children.add(child)
  child.once('exit', () => children.delete(child))
  return child
}

function startReactor() {
  return capture(spawn(reactorBinary, [
    '--listen', '127.0.0.1:9443',
    '--cert', path.join(gatewayRoot, 'server.crt'),
    '--key', path.join(gatewayRoot, 'server.key'),
    '--db', databasePath,
  ], { cwd: reactorRoot, stdio: ['ignore', 'pipe', 'pipe'] }), (text) => { reactorLog += text })
}

function startGateway() {
  return capture(spawn(gatewayBinary, ['server', '--config', configPath], {
    cwd: gatewayRoot,
    stdio: ['ignore', 'pipe', 'pipe'],
  }), (text) => { gatewayLog += text })
}

async function waitForMarker(read, marker, child, timeoutMS = 15000) {
  const deadline = Date.now() + timeoutMS
  while (Date.now() < deadline) {
    if (read().includes(marker)) return
    if (child.exitCode !== null) throw new Error(`process exited before marker ${marker}: ${read().slice(-2000)}`)
    await sleep(25)
  }
  throw new Error(`timeout waiting for marker ${marker}: ${read().slice(-2000)}`)
}

async function waitForExit(child, timeoutMS = 10000) {
  if (child.exitCode !== null || child.signalCode !== null) return
  await Promise.race([
    new Promise((resolve) => child.once('exit', resolve)),
    sleep(timeoutMS).then(() => { throw new Error(`process ${child.pid} did not exit`) }),
  ])
}

async function stop(child, signal = 'SIGINT', timeoutMS = 10000) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return
  child.kill(signal)
  try {
    await waitForExit(child, timeoutMS)
  } catch (error) {
    child.kill('SIGKILL')
    await waitForExit(child, 3000)
    if (signal === 'SIGKILL') throw error
  }
}

async function retry(action, timeoutMS = 15000) {
  const deadline = Date.now() + timeoutMS
  let lastError = null
  while (Date.now() < deadline) {
    try {
      return await action()
    } catch (error) {
      lastError = error
      await sleep(100)
    }
  }
  throw lastError ?? new Error('retry timeout')
}

function onlineTokens(log, destID) {
  const pattern = new RegExp(`presence online=true realm=0 dest_id=${destID} conn_token=([0-9A-Fa-f]+)`, 'g')
  return [...log.matchAll(pattern)].map((match) => match[1].toLowerCase())
}

let reactor = null
let gateway = null
let activeClient = null

try {
  reactor = startReactor()
  await waitForMarker(() => reactorLog, 'QUIC server listening', reactor)
  gateway = startGateway()
  await waitForMarker(() => gatewayLog, '[BACKEND] transport ready', gateway)
  await waitForMarker(() => gatewayLog, '[WSS] listener started', gateway)

  activeClient = new WssValidationClient()
  await activeClient.connect()
  let activeSession = await activeClient.authenticate(username, password, 'register')
  await activeClient.command(activeSession.token, { type: 'list_groups' })
  await retry(async () => {
    if (new Set(onlineTokens(reactorLog, activeSession.destID)).size < 1) {
      throw new Error('first lifecycle token not visible yet')
    }
  })

  const reactorCycles = []
  for (let cycle = 1; cycle <= 3; cycle += 1) {
    const stoppedAt = Date.now()
    await stop(reactor)
    const failureStarted = Date.now()
    let failure = null
    try {
      await activeClient.command(activeSession.token, { type: 'list_groups' })
    } catch (error) {
      failure = String(error)
    }
    const failureMS = Date.now() - failureStarted
    const stopToFailureMS = Date.now() - stoppedAt
    if (!failure) throw new Error(`cycle ${cycle}: request falsely succeeded while Reactor was stopped`)

    const oldReactorLogLength = reactorLog.length
    const recoveryStarted = Date.now()
    reactor = startReactor()
    await waitForMarker(() => reactorLog.slice(oldReactorLogLength), 'QUIC server listening', reactor)
    await retry(() => activeClient.command(activeSession.token, { type: 'list_groups' }), 20000)
    const recoveryMS = Date.now() - recoveryStarted
    reactorCycles.push({
      cycle,
      stop_to_failure_ms: stopToFailureMS,
      request_failure_ms: failureMS,
      failure,
      recovery_ms: recoveryMS,
    })
  }

  const gatewayCycles = []
  for (let cycle = 1; cycle <= 2; cycle += 1) {
    const gatewayStoppedAt = Date.now()
    const closed = activeClient.waitForClose(10000)
    await stop(gateway, 'SIGKILL', 3000)
    const closeCode = await closed

    const oldGatewayLogLength = gatewayLog.length
    gateway = startGateway()
    await waitForMarker(() => gatewayLog.slice(oldGatewayLogLength), '[BACKEND] transport ready', gateway)
    await waitForMarker(() => gatewayLog.slice(oldGatewayLogLength), '[WSS] listener started', gateway)
    activeClient = new WssValidationClient()
    await activeClient.connect()
    activeSession = await activeClient.authenticate(username, password)
    await activeClient.command(activeSession.token, { type: 'list_groups' })
    gatewayCycles.push({
      cycle,
      transport_close_code: closeCode,
      relogin_ms: Date.now() - gatewayStoppedAt,
    })
  }

  const expectedIncarnations = gatewayCycles.length + 1
  await retry(async () => {
    if (new Set(onlineTokens(reactorLog, activeSession.destID)).size < expectedIncarnations) {
      throw new Error('all Gateway lifecycle tokens are not visible yet')
    }
  })
  const tokens = onlineTokens(reactorLog, activeSession.destID)
  if (new Set(tokens).size < expectedIncarnations) {
    throw new Error(`Gateway restart reused conn_token: ${JSON.stringify(tokens)}`)
  }

  console.log(JSON.stringify({
    ok: true,
    username,
    dest_id: activeSession.destID.toString(),
    reactor_cycles: reactorCycles,
    gateway_cycles: gatewayCycles,
    conn_token_incarnations: new Set(tokens).size,
  }))
} finally {
  activeClient?.close()
  await sleep(50)
  await stop(gateway).catch(() => undefined)
  await stop(reactor).catch(() => undefined)
  for (const child of children) child.kill('SIGKILL')
  for (const file of [configPath, databasePath, `${databasePath}-wal`, `${databasePath}-shm`]) {
    try { fs.rmSync(file) } catch {}
  }
}
