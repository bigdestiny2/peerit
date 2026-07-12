// Legacy BlindShard body compatibility adapter.
//
// The native blind-substrate product does not ship this module. data.js reaches
// it only through a computed, explicitly enabled compatibility import, keeping
// all shard rosters, HTTP fetches, PVSS dealer code, and repair semantics outside
// the replacement browser closure.

import { keys, TYPE } from './model.js'

const BLIND_DEALER_MODULE = './blind-dealer.mjs'
const SHARD_TRANSPORT_MODULE = './vendor/blind-shards/shard-transport.js'
const READER_BUNDLE_MODULE = './reader-bundle.js'
const DISPERSAL_TIMEOUT_MS = 15000
const BODY_CACHE_MAX = 500

async function loadBlindDealer () {
  return import(BLIND_DEALER_MODULE)
}

function b64Encode (u8) {
  if (typeof btoa === 'function') {
    let output = ''
    for (let index = 0; index < u8.length; index++) output += String.fromCharCode(u8[index])
    return btoa(output)
  }
  if (typeof Buffer !== 'undefined') return Buffer.from(u8).toString('base64')
  throw new Error('base64 encoder unavailable')
}

function b64Decode (value) {
  if (typeof atob === 'function') {
    const binary = atob(String(value))
    const output = new Uint8Array(binary.length)
    for (let index = 0; index < output.length; index++) output[index] = binary.charCodeAt(index)
    return output
  }
  if (typeof Buffer !== 'undefined') return new Uint8Array(Buffer.from(String(value), 'base64'))
  throw new Error('base64 decoder unavailable')
}

function relayBaseUrls (data) {
  return (data.shardRelays || [])
    .map(relay => typeof relay === 'string' ? relay : (relay.url || relay.baseUrl || ''))
    .filter(Boolean)
}

function rosterForDispersal (data) {
  const relays = data.shardRelays
  if (!relays || relays.length < 3) return null
  const normalized = relays.map(relay => {
    if (typeof relay === 'string') return { url: relay }
    return {
      url: String(relay.url || relay.baseUrl || ''),
      pubkey: String(relay.pubkey || relay.publicKey || '').toLowerCase()
    }
  }).filter(relay => relay.url)
  if (normalized.length < 3) return null
  const uniquePublicKeys = new Set(normalized.map(relay => relay.pubkey).filter(Boolean))
  if (uniquePublicKeys.size < normalized.length) {
    if (typeof console !== 'undefined' && console.warn) {
      console.warn('[peerit] shard roster contains duplicate pubkeys; refusing dispersal')
    }
    return null
  }
  return {
    threshold: Math.max(2, Math.min(normalized.length - 1, Math.ceil(normalized.length / 2))),
    relays: normalized,
    retainMs: 30 * 24 * 60 * 60 * 1000
  }
}

async function publisherForDispersal (data, expectedOwner) {
  data._assertCurrentOwner(expectedOwner, 'before loading the dispersal signer')
  if (!data.id || typeof data.id.currentSeedEntry !== 'function') return null
  const entry = data.id.currentSeedEntry()
  if (!entry || !entry.seed || !entry.pubkey) return null
  if (entry.pubkey !== expectedOwner) throw data._identityRace('while loading the dispersal signer')
  const { makeHiverelayKeypair } = await loadBlindDealer()
  data._assertCurrentOwner(expectedOwner, 'after loading the dispersal signer')
  return makeHiverelayKeypair({ seedHex: entry.seed, pubHex: entry.pubkey })
}

async function getRecoverBody () {
  const node = typeof process !== 'undefined' && !!process.versions && !!process.versions.node
  const module = node ? await loadBlindDealer() : await import(READER_BUNDLE_MODULE)
  return module.recoverBody
}

async function getCreateHttpShardFetch () {
  const node = typeof process !== 'undefined' && !!process.versions && !!process.versions.node
  const module = node ? await import(SHARD_TRANSPORT_MODULE) : await import(READER_BUNDLE_MODULE)
  return module.createHttpShardFetch
}

async function getDecryptBody () {
  const node = typeof process !== 'undefined' && !!process.versions && !!process.versions.node
  const module = node ? await loadBlindDealer() : await import(READER_BUNDLE_MODULE)
  return module.decryptBody
}

export async function tryDispersalBox (data, bodyText, { batch = null, expectedOwner } = {}) {
  const publisher = await publisherForDispersal(data, expectedOwner)
  const roster = rosterForDispersal(data)
  if (!publisher || !roster) return null
  if (publisher.pubkeyHex.toLowerCase() !== expectedOwner.toLowerCase()) {
    if (typeof console !== 'undefined' && console.warn) {
      console.warn('[peerit] dispersal publisher does not match post author; refusing dispersal')
    }
    return null
  }
  try {
    const { disperseBody } = await loadBlindDealer()
    const dispersal = await Promise.race([
      disperseBody(bodyText, {
        publisher,
        threshold: roster.threshold,
        relays: roster.relays,
        retainMs: roster.retainMs,
        fetch: data.fetch
      }),
      new Promise((resolve, reject) => {
        setTimeout(() => reject(new Error('dispersal timeout')), DISPERSAL_TIMEOUT_MS)
      })
    ])
    data._assertCurrentOwner(expectedOwner, 'after dispersing the body')
    const { ciphertext, manifest, bodyKeyHex } = dispersal
    if (!manifest.ciphertextShard) {
      const blobData = {
        id: manifest.blindContentId,
        blobId: manifest.blindContentId,
        ct: b64Encode(ciphertext),
        author: expectedOwner
      }
      await data._powSign(TYPE.BLOB, blobData, undefined, expectedOwner)
      const blobOperation = { type: TYPE.BLOB, data: blobData }
      if (Array.isArray(batch) && typeof data.sync.appendBatch === 'function') {
        batch.push(blobOperation)
      } else {
        if (data.ensureWriter) await data.ensureWriter()
        data._assertCurrentOwner(expectedOwner, 'immediately before dispersed blob publication')
        data._assertSignedOpsOwner([blobOperation], expectedOwner)
        await data.sync.append(blobOperation, data._writerSession)
      }
    }
    if (bodyKeyHex) {
      data._saveFloor(manifest.blindContentId, {
        v: 1,
        key: bodyKeyHex,
        iv: manifest.iv,
        ct: b64Encode(ciphertext),
        ph: manifest.plaintextHash || ''
      })
    }
    return manifest
  } catch (error) {
    if (error && error.code === 'PEERIT_WRITER_IDENTITY_CHANGED') throw error
    if (typeof console !== 'undefined' && console.warn) {
      console.warn('[peerit] dispersal box failed, falling back:', error.message)
    }
    return null
  }
}

export async function probeDispersal (data, manifest) {
  const value = manifest && manifest.dispersal ? manifest.dispersal : manifest
  if (!value || !Array.isArray(value.shareManifest)) {
    throw new Error('probeDispersal: dispersal manifest required')
  }
  const createHttpShardFetch = await getCreateHttpShardFetch()
  const fetchShard = createHttpShardFetch({ baseUrls: relayBaseUrls(data), fetch: data.fetch })
  const probe = async address => {
    try { return !!(address && await fetchShard(address)) } catch { return false }
  }
  const shares = await Promise.all(value.shareManifest.map(share => probe(share.shard)))
  const available = shares.filter(Boolean).length
  const ciphertextAvailable = value.ciphertextShard ? await probe(value.ciphertextShard) : true
  const threshold = Number(value.threshold) || 0
  const recoverable = ciphertextAvailable && available >= threshold
  return {
    total: value.shareManifest.length,
    available,
    threshold,
    ciphertextAvailable,
    recoverable,
    needsRepair: !recoverable || available < threshold + 1
  }
}

export async function hydrateDispersed (data, record) {
  const manifest = record.dispersal
  const cached = data._bodyCache.get(manifest.blindContentId)
  if (cached != null) return { ...record, body: cached }
  const floor = data._loadFloor(manifest.blindContentId)
  if (floor) {
    try {
      const decryptBody = await getDecryptBody()
      const body = await decryptBody(
        b64Decode(floor.ct),
        floor.iv,
        floor.key,
        manifest.plaintextHash || floor.ph || undefined
      )
      if (data._bodyCache.size >= BODY_CACHE_MAX) data._bodyCache.delete(data._bodyCache.keys().next().value)
      data._bodyCache.set(manifest.blindContentId, body)
      return { ...record, body }
    } catch {}
  }
  try {
    const recoverBody = await getRecoverBody()
    const options = {
      relayBaseUrls: relayBaseUrls(data),
      fetchImpl: data.fetch
    }
    if (manifest.ciphertextShard) {
      const createHttpShardFetch = await getCreateHttpShardFetch()
      const fetchShard = createHttpShardFetch({ baseUrls: relayBaseUrls(data), fetch: data.fetch })
      options.fetchCiphertext = async () => {
        const bytes = await fetchShard(manifest.ciphertextShard)
        if (!bytes) throw new Error('ciphertext shard not found on cohort')
        return bytes
      }
    } else {
      const blob = await data.sync.get(keys.blob(manifest.blindContentId))
      if (!blob || !blob.ct) return { ...record, body: '', _blobMissing: true }
      options.fetchCiphertext = () => b64Decode(blob.ct)
    }
    const body = await recoverBody(manifest, options)
    if (data._bodyCache.size >= BODY_CACHE_MAX) data._bodyCache.delete(data._bodyCache.keys().next().value)
    data._bodyCache.set(manifest.blindContentId, body)
    return { ...record, body }
  } catch {
    return { ...record, body: '', _blobMissing: true }
  }
}

export async function repairDispersal (data, community, cid, { force = false } = {}) {
  const post = await data._rawPost(community, cid)
  if (!post) throw new Error('Post not found')
  if (!post.dispersal) throw new Error('Post is not dispersed')
  const manifest = post.dispersal
  const status = await probeDispersal(data, manifest).catch(() => null)
  if (!force && status && !status.needsRepair) return { repaired: false, status }
  let body = null
  const floor = data._loadFloor(manifest.blindContentId)
  if (floor) {
    try {
      const decryptBody = await getDecryptBody()
      body = await decryptBody(
        b64Decode(floor.ct),
        floor.iv,
        floor.key,
        manifest.plaintextHash || floor.ph || undefined
      )
    } catch {}
  }
  if (body == null) {
    const hydrated = await hydrateDispersed(data, post)
    if (hydrated && !hydrated._blobMissing && hydrated.body) body = hydrated.body
  }
  if (body == null) {
    throw new Error('repairDispersal: body unrecoverable (no device floor and cohort below threshold)')
  }
  const record = await data._editPost(community, cid, body)
  return { repaired: true, status, record }
}
