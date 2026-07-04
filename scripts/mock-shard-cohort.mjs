#!/usr/bin/env node
// mock-shard-cohort.mjs — lightweight HiveRelay shard-store mock for local
// BlindShard dispersal testing. Implements the subset of the shard-store HTTP
// contract that peerit's blind-dealer.mjs uses:
//   POST /api/custody/intent   -> {ok: true}
//   POST /api/v1/shard         -> {shard: 'shard:<hash>'}
//   GET  /api/v1/shard/<hash>  -> raw shard bytes
//   GET  /health               -> {ok: true}
//
// Start one instance per relay port (e.g. 8801, 8802, 8803) and point
// config/shard-roster.json at them.

import http from 'node:http'
import { createHash } from 'node:crypto'

const PORT = Number(process.env.PORT) || 8801
const HOST = process.env.HOST || '127.0.0.1'

const shards = new Map() // hash -> Buffer

function hashOf (buf) {
  return createHash('sha256').update(buf).digest('hex')
}

function send (res, status, body, type = 'application/json') {
  const data = typeof body === 'string' ? body : JSON.stringify(body)
  res.writeHead(status, {
    'Content-Type': type,
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-Shard-Pin'
  })
  res.end(data)
}

function readBody (req) {
  return new Promise((resolve, reject) => {
    const chunks = []
    req.on('data', c => chunks.push(c))
    req.on('end', () => resolve(Buffer.concat(chunks)))
    req.on('error', reject)
  })
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`)
  const path = url.pathname

  if (req.method === 'OPTIONS') {
    return send(res, 204, '')
  }

  if (path === '/health' && req.method === 'GET') {
    return send(res, 200, { ok: true })
  }

  if (path === '/api/custody/intent' && req.method === 'POST') {
    await readBody(req)
    return send(res, 200, { ok: true })
  }

  if (path === '/api/v1/shard' && req.method === 'POST') {
    const body = await readBody(req)
    const hash = hashOf(body)
    shards.set(hash, body)
    return send(res, 200, { shard: 'shard:' + hash })
  }

  const shardGet = path.match(/^\/api\/v1\/shard\/([0-9a-f]{64})$/i)
  if (shardGet && req.method === 'GET') {
    const hash = shardGet[1].toLowerCase()
    const bytes = shards.get(hash)
    if (!bytes) return send(res, 404, { error: 'not found' })
    return send(res, 200, bytes, 'application/octet-stream')
  }

  send(res, 404, { error: 'not found' })
})

server.listen(PORT, HOST, () => {
  console.log(`mock shard store on http://${HOST}:${PORT}`)
})
