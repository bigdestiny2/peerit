// js/blind-dealer.mjs — peerit blind-shard dealer (Node/Bare path).
//
// Implements the HiveRelay PVSS key-dispersal contract end-to-end:
//   - Encrypt a post body with an AES-256-GCM key that IS the PVSS secret.
//   - PVSS-split that key across a roster of shard-store relays.
//   - Publish a signed v2 custody intent to every relay BEFORE putting shards.
//   - PUT each encrypted share to the relay assigned in the intent.
//   - A reader gathers any k shares and reconstructs the key AT THE EDGE.
//
// Ciphertext and key stay separated: the relay pool never holds both, and no
// single relay (or k-1 colluding relays) can recover the plaintext.
//
// INTEGRITY: the shareManifest is signed into the custody intent. A reader MUST
// verify the intent signature (verifyCustodyEntry) before trusting the manifest;
// recoverSecret binds each share to its shareCommitment, but only an authentic
// manifest makes that meaningful.
//
// SELF-CONTAINED: all PVSS/custody code comes from the VENDORED, pinned client
// (js/vendor/blind-shards, P2P-Hiverelay@4facbae / #159) — NOT a sibling checkout
// or npm. Pin signing uses peerit's OWN shardPinSignable (shard-store-adapter),
// which test/shard-store-adapter.mjs proves is byte-identical to the relay's
// verifyShardPin — so we never import server-side shard-store code into the client.
//
// Browser/Bare path: blocked on HiveRelay #115 (the Bare client signer can't yet
// emit manifest-bearing v2 intents). Node/Bare-only until then; the buildPin seam
// is wired so a browser dealer can reuse the exact pin shape.

import sodium from 'sodium-universal'
import { planDispersal, recoverSecret, shardAddressOf } from './vendor/blind-shards/blind-shards.js'
import { createHttpShardPut, createHttpShardFetch } from './vendor/blind-shards/shard-transport.js'
import { createCustodyIntent } from './vendor/blind-shards/custody-signing.js'
import { shardPinSignable } from './shard-store-adapter.js' // byte-identical to the relay's verifyShardPin
import { genKeyPair, ready as cryptoReady } from './crypto.js'

export const DEFAULT_RETAIN_DAYS = 30
export const DEFAULT_RETAIN_MS = DEFAULT_RETAIN_DAYS * 24 * 60 * 60 * 1000
export const SHARE_SCHEME = 'pvss-secp256k1-v1'

const te = new TextEncoder()
const td = new TextDecoder()

function toHex (u8) {
  const bytes = u8 instanceof Uint8Array ? u8 : new Uint8Array(u8)
  let s = ''
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0')
  return s
}
function fromHex (h) {
  const hex = String(h).toLowerCase().replace(/^0x/, '')
  if (!/^[0-9a-f]+$/.test(hex) || hex.length % 2 !== 0) throw new Error('blind-dealer: invalid hex')
  const u8 = new Uint8Array(hex.length / 2)
  for (let i = 0; i < u8.length; i++) u8[i] = parseInt(hex.substr(i * 2, 2), 16)
  return u8
}
const bareHash = (h) => String(h).replace(/^shard:/, '').toLowerCase()
function freshNonce () {
  const u8 = new Uint8Array(16); sodium.randombytes_buf(u8); return toHex(u8)
}
async function sha256Bytes (bytes) {
  const u = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)
  const subtle = typeof crypto !== 'undefined' && crypto.subtle
  if (subtle) return toHex(await subtle.digest('SHA-256', u))
  const { default: nc } = await import('node:crypto')
  return nc.createHash('sha256').update(Buffer.from(u)).digest('hex')
}

// A HiveRelay/libsodium keypair from peerit's seed/pub hex: secretKey = seed||pubkey
// (64 bytes), exactly crypto_sign_seed_keypair's layout — so the same key signs the
// custody intent AND every pin, and crypto_sign_detached accepts it directly.
export function makeHiverelayKeypair ({ seedHex, pubHex }) {
  const seed = fromHex(seedHex)
  const pub = fromHex(pubHex)
  if (seed.length !== 32) throw new Error('blind-dealer: publisher seed must be 32 bytes')
  if (pub.length !== 32) throw new Error('blind-dealer: publisher pubkey must be 32 bytes')
  const secretKey = new Uint8Array(64)
  secretKey.set(seed, 0)
  secretKey.set(pub, 32)
  return { publicKey: pub, secretKey, seedHex, pubHex, pubkeyHex: toHex(pub) }
}

export async function ensurePublisher ({ seedHex, pubHex } = {}) {
  await cryptoReady()
  if (seedHex && pubHex) return makeHiverelayKeypair({ seedHex, pubHex })
  return makeHiverelayKeypair(await genKeyPair())
}

// Sign a custody shard pin with the publisher key over peerit's shardPinSignable
// (byte-identical to the relay verifier). NOT the server signShardPin — no server deps.
export function signCustodyPin ({ hash, custodyIntentId, shareIndex, retainUntil, pinner, nonce }, publisher) {
  const pin = { reason: 'custody', hash: bareHash(hash), pinner: pinner || publisher.pubkeyHex, custodyIntentId, shareIndex, retainUntil, nonce: nonce || freshNonce() }
  const sig = new Uint8Array(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(sig, te.encode(shardPinSignable(pin)), publisher.secretKey)
  pin.sig = toHex(sig)
  return pin
}

async function encryptWithKey (bodyText, keyHex) {
  const subtle = typeof crypto !== 'undefined' && crypto.subtle
  if (!subtle) throw new Error('blind-dealer: WebCrypto SubtleCrypto unavailable; cannot encrypt body')
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const key = await subtle.importKey('raw', fromHex(keyHex), { name: 'AES-GCM', length: 256 }, false, ['encrypt'])
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, key, te.encode(String(bodyText == null ? '' : bodyText)))
  return { ciphertext: new Uint8Array(ct), iv: toHex(iv) }
}

// Encrypt a body with a random AES-256-GCM key (key returned). For the full dealer
// flow use disperseBody, which uses the PVSS secret as the key so recovery matches.
export async function encryptBody (bodyText) {
  const subtle = typeof crypto !== 'undefined' && crypto.subtle
  if (!subtle) throw new Error('blind-dealer: WebCrypto SubtleCrypto unavailable; cannot encrypt body')
  const key = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt'])
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, key, te.encode(String(bodyText == null ? '' : bodyText)))
  const rawKey = new Uint8Array(await subtle.exportKey('raw', key))
  return { ciphertext: new Uint8Array(ct), iv: toHex(iv), keyHex: toHex(rawKey) }
}

export async function decryptBody (ciphertext, ivHex, keyHex) {
  const subtle = typeof crypto !== 'undefined' && crypto.subtle
  if (!subtle) throw new Error('blind-dealer: WebCrypto SubtleCrypto unavailable; cannot decrypt body')
  const key = await subtle.importKey('raw', fromHex(keyHex), { name: 'AES-GCM', length: 256 }, false, ['decrypt'])
  const pt = await subtle.decrypt({ name: 'AES-GCM', iv: fromHex(ivHex) }, key, ciphertext instanceof Uint8Array ? ciphertext : new Uint8Array(ciphertext))
  return td.decode(pt)
}

export function normalizeRoster (cfg) {
  const threshold = Number(cfg.threshold)
  const relays = Array.isArray(cfg.relays) ? cfg.relays : []
  if (!Number.isInteger(threshold) || threshold < 1 || threshold > relays.length) {
    throw new Error('blind-dealer: threshold must be an integer with 1 <= threshold <= relays.length')
  }
  const normalized = []
  for (let i = 0; i < relays.length; i++) {
    const r = relays[i]
    const pub = String(r.pubkey || r.publicKey || '').toLowerCase().trim()
    if (!/^[0-9a-f]{64}$/.test(pub)) throw new Error('blind-dealer: relay ' + i + ' pubkey must be 64-hex')
    const url = String(r.url || r.baseUrl || '').replace(/\/+$/, '')
    if (!url) throw new Error('blind-dealer: relay ' + i + ' needs a url/baseUrl')
    normalized.push({ pubkey: pub, url, apiKey: r.apiKey || r.token || null, index: i + 1 })
  }
  return { threshold, relays: normalized, retainMs: Number(cfg.retainMs) || DEFAULT_RETAIN_MS }
}

const buildShareAssignments = (plan, relays) => plan.shares.map((s) => ({ relayPubkey: relays[s.shareIndex - 1].pubkey, shareIndex: s.shareIndex }))
const buildShareManifest = (plan) => plan.shares.map((s) => ({ shareIndex: s.shareIndex, shard: s.shard, shareCommitment: s.shareCommitment }))

async function buildIntentFromPlan (plan, opts) {
  const relays = opts.relays
  const publisher = opts.publisher
  if (!Array.isArray(relays) || !relays.length) throw new Error('blind-dealer: normalized relays required')
  if (!publisher || !publisher.publicKey || !publisher.secretKey) throw new Error('blind-dealer: publisher { publicKey, secretKey } required')
  const commitmentRootBytes = fromHex(plan.commitmentRoot)
  const blindContentId = String(opts.blindContentId || await sha256Bytes(commitmentRootBytes)).toLowerCase()
  const ciphertextRoot = String(opts.ciphertextRoot || blindContentId).toLowerCase()
  const shareBundleKey = shardAddressOf(commitmentRootBytes).slice('shard:'.length)
  const intent = createCustodyIntent({
    version: 2,
    blindContentId,
    ciphertextRoot,
    contentVersion: 1,
    requiredReplicas: relays.length,
    shareScheme: SHARE_SCHEME,
    shareThreshold: plan.threshold,
    commitmentRoot: plan.commitmentRoot,
    shareBundleKey,
    shareAssignments: buildShareAssignments(plan, relays),
    shareManifest: buildShareManifest(plan),
    retainUntil: Date.now() + opts.retainMs
  }, publisher)
  return { intent, shareManifest: buildShareManifest(plan), shareAssignments: buildShareAssignments(plan, relays), blindContentId, ciphertextRoot }
}

// PVSS-split a 64-hex secret across the roster + build a signed v2 custody intent
// (no publish/PUT). keyHex must be a valid secp256k1 scalar for recovery to match.
export async function disperseKey (keyHex, opts) {
  if (!/^[0-9a-f]{64}$/i.test(String(keyHex || ''))) throw new Error('blind-dealer: keyHex must be 64-hex')
  const roster = normalizeRoster(opts)
  const plan = await planDispersal({ count: roster.relays.length, threshold: roster.threshold, secret: keyHex })
  const built = await buildIntentFromPlan(plan, { ...opts, relays: roster.relays, retainMs: roster.retainMs })
  return { ...built, plan }
}

export async function publishIntentToRelays (intent, relays, fetchImpl = globalThis.fetch) {
  if (typeof fetchImpl !== 'function') throw new Error('blind-dealer: fetch unavailable')
  const errors = []
  for (const r of relays) {
    try {
      const res = await fetchImpl(r.url + '/api/custody/intent', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...(r.apiKey ? { Authorization: 'Bearer ' + r.apiKey } : {}) },
        body: JSON.stringify(intent)
      })
      if (!res.ok) throw new Error('HTTP ' + res.status + ' ' + (await res.text().catch(() => '')).slice(0, 120))
    } catch (err) { errors.push({ relay: r.url, error: err.message }) }
  }
  if (errors.length) { const e = new Error('blind-dealer: failed to publish intent to ' + errors.length + ' relay(s)'); e.errors = errors; throw e }
}

export async function putShards (plan, intent, relays, publisher, retainMs, fetchImpl = globalThis.fetch) {
  if (typeof fetchImpl !== 'function') throw new Error('blind-dealer: fetch unavailable')
  const until = Date.now() + retainMs
  const placed = []
  for (const s of plan.shares) {
    const r = relays[s.shareIndex - 1]
    const put = createHttpShardPut({
      baseUrl: r.url,
      fetch: fetchImpl,
      signPin: ({ hash, shareIndex }) => signCustodyPin({ hash, custodyIntentId: intent.intentId, shareIndex, retainUntil: until }, publisher)
    })
    placed.push({ shareIndex: s.shareIndex, relay: r.url, shard: await put(s.bytes, { shareIndex: s.shareIndex }) })
  }
  return placed
}

// Full dealer flow: encrypt body with the PVSS secret, publish intent, PUT shards.
// Returns { ciphertext, manifest, intent, plan, publisher, placed }.
export async function disperseBody (bodyText, opts) {
  const publisher = opts.publisher || await ensurePublisher(opts.publisher || {})
  const roster = normalizeRoster(opts)
  // Plan FIRST so the PVSS secret (a valid secp256k1 scalar) IS the AES key —
  // recovery returns the exact key needed to decrypt.
  const plan = await planDispersal({ count: roster.relays.length, threshold: roster.threshold })
  const { ciphertext, iv } = await encryptWithKey(bodyText, plan.key)
  const ciphertextRoot = await sha256Bytes(ciphertext)
  const { intent, shareManifest, blindContentId } = await buildIntentFromPlan(plan, {
    relays: roster.relays, publisher, retainMs: roster.retainMs,
    blindContentId: opts.blindContentId || ciphertextRoot, ciphertextRoot
  })
  await publishIntentToRelays(intent, roster.relays, opts.fetch)
  const placed = await putShards(plan, intent, roster.relays, publisher, roster.retainMs, opts.fetch)
  const manifest = {
    version: 2, scheme: SHARE_SCHEME, threshold: roster.threshold, count: roster.relays.length,
    blindContentId, ciphertextRoot, commitmentRoot: plan.commitmentRoot,
    shareBundleKey: shardAddressOf(fromHex(plan.commitmentRoot)).slice('shard:'.length),
    shareManifest, iv, alg: 'AES-256-GCM'
  }
  return { ciphertext, manifest, intent, plan, publisher, placed }
}

export async function recoverKey (manifest, relayBaseUrls, fetchImpl = globalThis.fetch) {
  if (!manifest || !Array.isArray(manifest.shareManifest)) throw new Error('blind-dealer: manifest.shareManifest required')
  const rec = await recoverSecret({ shareManifest: manifest.shareManifest, threshold: manifest.threshold, fetch: createHttpShardFetch({ baseUrls: relayBaseUrls, fetch: fetchImpl }) })
  if (!rec.ok) { const e = new Error('blind-dealer: recover failed — ' + rec.reason); e.collected = rec.collected; e.need = rec.need; throw e }
  return rec.key
}

// Recover the full body: gather shards, reconstruct the key, fetch ciphertext, decrypt.
// fetchCiphertext(blindContentId) is caller-provided — ciphertext storage is out-of-band.
export async function recoverBody (manifest, opts = {}) {
  const { relayBaseUrls, fetchCiphertext, fetchImpl = globalThis.fetch } = opts
  if (!Array.isArray(relayBaseUrls) || !relayBaseUrls.length) throw new Error('blind-dealer: relayBaseUrls required')
  if (typeof fetchCiphertext !== 'function') throw new Error('blind-dealer: fetchCiphertext(blindContentId) required')
  const keyHex = await recoverKey(manifest, relayBaseUrls, fetchImpl)
  const ciphertext = await fetchCiphertext(manifest.blindContentId)
  return decryptBody(ciphertext, manifest.iv, keyHex)
}

// buildPin(shardId, bytes, ctx) for the shard-store-adapter seam. ctx MUST include
// { custodyIntentId, shareIndex }.
export function makeCustodyBuildPin ({ retainMs, publisher }) {
  const until = Date.now() + (retainMs || DEFAULT_RETAIN_MS)
  return async function buildPin (shardId, bytes, ctx = {}) {
    if (!ctx.custodyIntentId || !Number.isInteger(ctx.shareIndex)) throw new Error('blind-dealer buildPin: ctx must include custodyIntentId and shareIndex')
    return signCustodyPin({ hash: shardId, custodyIntentId: ctx.custodyIntentId, shareIndex: ctx.shareIndex, retainUntil: until }, publisher)
  }
}
