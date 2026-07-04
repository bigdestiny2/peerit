// bridge-shard-transport.js — PearBrowser bridge transport for BlindShard shares.
//
// In PearBrowser the app runs over window.pear.sync and cannot reach the HiveRelay
// shard cohort over HTTP. This adapter stores/fetches PVSS share shards as regular
// peerit sync records under `shard!<hash>` so they replicate through the same
// gossip/bridge path as posts and comments. Each shard record is signed by the
// author so it is admitted by the gossip merge.

import { canonical } from './canon.js'

function b64Encode (u8) {
  if (typeof btoa === 'function') {
    let s = ''
    for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i])
    return btoa(s)
  }
  if (typeof Buffer !== 'undefined') return Buffer.from(u8).toString('base64')
  throw new Error('base64 encoder unavailable')
}

function b64Decode (s) {
  if (typeof atob === 'function') {
    const bin = atob(String(s))
    const u = new Uint8Array(bin.length)
    for (let i = 0; i < u.length; i++) u[i] = bin.charCodeAt(i)
    return u
  }
  if (typeof Buffer !== 'undefined') return new Uint8Array(Buffer.from(String(s), 'base64'))
  throw new Error('base64 decoder unavailable')
}

function shardHash (address) {
  const s = String(address)
  return (s.startsWith('shard:') ? s.slice(6) : s).toLowerCase()
}

function shardKey (hash) {
  return 'shard!' + hash.toLowerCase()
}

// Build a signed `shard!<hash>` record and append it to the peerit sync.
// `sign(payload, namespace)` must match identity.js (returns {signature, publicKey, driveKey, namespace, algorithm}).
export function createBridgeShardPut ({ sync, sign, author }) {
  if (!sync || typeof sync.append !== 'function') throw new Error('bridge shard put: sync.append required')
  if (typeof sign !== 'function') throw new Error('bridge shard put: sign function required')
  if (!author) throw new Error('bridge shard put: author required')

  return async (bytes, { shareIndex, shard, address } = {}) => {
    const hash = shardHash(address || shard || '')
    if (!hash) throw new Error('bridge shard put: shard address required')
    const record = {
      id: hash,
      address: 'shard:' + hash,
      bytes: b64Encode(bytes),
      shareIndex,
      author,
      createdAt: Date.now()
    }
    const s = await sign(canonical('shard', record), 'peerit')
    record._sig = s.signature
    record._k = s.publicKey
    record._dk = s.driveKey
    record._ns = s.namespace
    record._alg = s.algorithm
    await sync.append({ type: 'shard', data: record })
    return 'shard:' + hash
  }
}

// Read a shard record from the peerit sync by its `shard:<hash>` address.
export function createBridgeShardFetch ({ sync }) {
  if (!sync || typeof sync.get !== 'function') throw new Error('bridge shard fetch: sync.get required')

  return async (address) => {
    const hash = shardHash(address)
    const rec = await sync.get(shardKey(hash))
    if (!rec || !rec.bytes) return null
    return b64Decode(rec.bytes)
  }
}
