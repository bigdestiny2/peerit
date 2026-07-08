#!/usr/bin/env node
// dht-relay-local.mjs — the "home box" daemon.
//
// Runs a ws:// dht-relay bound to 127.0.0.1 that bridges ws clients (a browser,
// which can't do UDP) into the REAL Holepunch DHT. With this running locally AND
// the app built with `--dht-relay ws://127.0.0.1:<port>`, a browser reaches the
// decentralised swarm THROUGH YOUR OWN MACHINE — there is no hosted relay in the
// data path at all.
//
// MINIMAL CONTACT: bootstrap defaults to the PUBLIC Holepunch DHT, so the only
// thing ever contacted off-box is the DHT's public bootstrap nodes (run by the
// Holepunch community, not by peerit). Pass --bootstrap host:port,... to point at
// a private/testnet DHT instead (used by test/dht-relay-local.mjs).
//
//   node scripts/dht-relay-local.mjs                 # bridge to the public DHT on ws://127.0.0.1:49737
//   node scripts/dht-relay-local.mjs --port 5000
//
import DHT from 'hyperdht'
import { relay } from '@hyperswarm/dht-relay'
import Stream from '@hyperswarm/dht-relay/ws'
import { WebSocketServer } from 'ws'
import { pathToFileURL } from 'node:url'

function parseBootstrap (s) {
  if (!s) return undefined
  return s.split(',').map((pair) => {
    const [host, port] = pair.trim().split(':')
    return { host, port: Number(port) }
  })
}

export async function startLocalRelay ({ port = 49737, host = '127.0.0.1', bootstrap } = {}) {
  const dht = new DHT(bootstrap ? { bootstrap } : {})
  await dht.ready()
  const wss = new WebSocketServer({ host, port })
  const conns = new Set()
  wss.on('connection', (socket) => {
    conns.add(socket)
    socket.on('close', () => conns.delete(socket))
    relay(dht, new Stream(false, socket)) // server side of the bridge: isInitiator = false
  })
  await new Promise((resolve, reject) => { wss.once('listening', resolve); wss.once('error', reject) })
  return {
    url: `ws://${host}:${port}`,
    dht,
    wss,
    connections: () => conns.size,
    async close () {
      for (const s of conns) { try { s.terminate() } catch {} }
      await new Promise((r) => wss.close(r))
      await dht.destroy()
    }
  }
}

// ---- CLI ----
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const arg = (n, d) => { const i = process.argv.indexOf(n); return i >= 0 ? process.argv[i + 1] : d }
  const port = Number(arg('--port', 49737))
  const bootstrap = parseBootstrap(arg('--bootstrap', ''))
  const r = await startLocalRelay({ port, bootstrap })
  console.log(`[dht-relay-local] listening on ${r.url}`)
  console.log(`[dht-relay-local] bridging to ${bootstrap ? 'private DHT ' + arg('--bootstrap', '') : 'the PUBLIC Holepunch DHT (no peerit server contacted)'}`)
  console.log(`[dht-relay-local] build the app for it:  node build-web.mjs --dht-relay ${r.url}`)
  const iv = setInterval(() => console.log(`[dht-relay-local] ${r.connections()} client(s) connected`), 30000)
  if (iv.unref) iv.unref()
}
