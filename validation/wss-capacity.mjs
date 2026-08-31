#!/usr/bin/env node

// validation-im-macos.json 把 WSS 上限设为每 Worker 64 条连接。本探针真实建立并
// 保持 64 次 TLS+Upgrade，确认第 65 条被明确拒绝；随后全部关闭，供 lsof/metrics
// 验证 accepted FD 和 ConnectionManager 槽位都能归零。

import { WssValidationClient } from './wss-smoke.mjs'

const capacity = 64
const clients = Array.from({ length: capacity }, () => new WssValidationClient())
const overflow = new WssValidationClient()

try {
  await Promise.all(clients.map((client) => client.connect()))

  let rejected = false
  try {
    await overflow.connect()
  } catch {
    rejected = true
  }
  if (!rejected) throw new Error(`WSS connection ${capacity + 1} was not rejected`)

  console.log(JSON.stringify({
    ok: true,
    admitted: capacity,
    rejected: 1,
    limit: 'max_connections_per_worker',
  }))
} finally {
  overflow.close()
  for (const client of clients) client.close()
}
