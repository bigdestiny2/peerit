// shard-store-adapter.js — the CONCRETE { putShard, getShard } backend that binds
// peerit's Phase-3 dispersal (js/blob-disperse.js) to HiveRelay's blind shard
// store `/api/v1/shard` (shipped in hiverelay v0.22.0, docs/BLIND-SHARD-STORE-SPEC.md;
// server code: packages/services/builtin/shard-store/{http-adapter,shard-pin,shard-engine}.js).
//
// Wire contract (verified against the shipped http-adapter.js + shard-pin.js):
//   PUT  POST {base}/api/v1/shard          body = RAW octet-stream ciphertext,
//        header X-Shard-Pin = JSON(signed pin), (peerit bridge also: X-Pear-Token)
//        -> 201 {ok, shard:'shard:<hash>', byteLength, deduped, pinRef, refs, retainUntil}
//   GET  {base}/api/v1/shard/<64hex>       -> 200 raw bytes | 404 {error:'NOT_HELD'}
// Addressing is BLAKE2b-256(ciphertext); the caller must disperse with
// hashShard = blake2b (makeBlake2b256Hex below) so shardId == the store's address.
// The store recomputes the hash server-side and rejects a mismatch, so a relay can
// neither substitute nor mis-address a shard.
//
// DEPENDENCY-INJECTED + browser-safe: no Node/sodium imports. `signRaw` (RAW Ed25519
// detached, e.g. crypto.js sign(seed, msg)), `fetch`, `resolveEndpoint`/`roster`,
// `token`, `blake2b` are all passed in. This is the client half; it is NOT wired into
// data.js's write path and is HELD on the store being DEPLOYED (0.22.0 is source-only,
// the HTTP adapter is unmounted on the live fleet) + >=3 INDEPENDENT relays (dispersal
// across same-owner relays is theater). See docs/BLINDSHARD-DESIGN.md §5 Phase 3.

export const SHARD_PIN_DOMAIN = 'hiverelay.shard-pin.v1'
export const DEFAULT_RETAIN_MS = 30 * 24 * 60 * 60 * 1000 // 30 days

// --- pin envelope (replicated VERBATIM from shard-pin.js so the browser build needs
//     no hiverelay source; test/shard-store-adapter.mjs cross-checks this replica
//     against the vendored REAL verifyShardPin, so any drift fails loudly) ---------
function stable (value) {
  if (Array.isArray(value)) return '[' + value.map(stable).join(',') + ']'
  if (value && typeof value === 'object') {
    return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + stable(value[k])).join(',') + '}'
  }
  return JSON.stringify(value === undefined ? null : value)
}

function pinBody (pin) {
  return {
    reason: pin.reason,
    hash: pin.hash,
    pinner: pin.pinner,
    custodyIntentId: pin.custodyIntentId || null,
    shareIndex: Number.isInteger(pin.shareIndex) ? pin.shareIndex : null,
    retainUntil: pin.retainUntil,
    nonce: pin.nonce
  }
}

// The exact string whose UTF-8 bytes the pinner signs. Server builds the identical
// bytes as b4a.from(SHARD_PIN_DOMAIN + '\0' + stable(pinBody(pin)), 'utf8').
export function shardPinSignable (pin) {
  return SHARD_PIN_DOMAIN + '\0' + stable(pinBody(pin))
}

// Build a signed PAYMENT pin for a shard. signRaw(msg) must be a RAW Ed25519 detached
// signature (128-hex) over utf8(msg) by `pinner`'s key. custody pins (which additionally
// bind custodyIntentId + shareIndex to a signed shareManifest) need a custody-intent
// producer peerit does not have yet — inject `buildPin` to override when that lands.
export async function buildPaymentPin ({ hash, pinner, retainUntil, nonce, signRaw, reason = 'payment' }) {
  const pin = { reason, hash, pinner, custodyIntentId: null, shareIndex: null, retainUntil, nonce }
  pin.sig = await signRaw(shardPinSignable(pin))
  return pin
}

// A blake2b-256 hex hasher matching the store's shardHash (sodium.crypto_generichash,
// 32-byte digest). Pass an injected sodium-like { crypto_generichash } — in the browser
// this comes from the dht-relay bundle's sodium (SubtleCrypto has no blake2b); in Node
// tests, from sodium-universal. Use as the `hashShard` for disperseBody/reassembleBody.
export function makeBlake2b256Hex (sodium, b4a) {
  if (!sodium || typeof sodium.crypto_generichash !== 'function') throw new Error('makeBlake2b256Hex: a sodium with crypto_generichash is required')
  const toHex = b4a ? (u8) => b4a.toString(u8, 'hex') : (u8) => { let s = ''; for (let i = 0; i < u8.length; i++) s += u8[i].toString(16).padStart(2, '0'); return s }
  const alloc = b4a ? (n) => b4a.alloc(n) : (n) => new Uint8Array(n)
  return async function blake2b256Hex (bytes) {
    const inp = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)
    const out = alloc(32)
    sodium.crypto_generichash(out, inp)
    return toHex(out)
  }
}

function randomHex (n = 16) {
  const g = (typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.getRandomValues) ? globalThis.crypto : null
  if (!g) throw new Error('shard-store-adapter: crypto.getRandomValues unavailable; inject { nonce }')
  const u = new Uint8Array(n); g.getRandomValues(u)
  let s = ''; for (let i = 0; i < u.length; i++) s += u[i].toString(16).padStart(2, '0'); return s
}

async function readErr (res) {
  try { const j = await res.json(); return (j && j.error) || res.status } catch { return res.status }
}

// createShardStoreAdapter(opts) -> { putShard, getShard } for disperseBody/reassembleBody.
//   resolveEndpoint(relayPub) -> baseUrl   (or pass `roster` = [{ pub, url }])
//   pinner        the pin's pinner pubkey (64-hex) — usually the author's identity pubkey
//   signRaw       async (utf8String) -> sigHex   RAW Ed25519 detached by pinner's key
//   token         X-Pear-Token: string | () => string|Promise   (peerit bridge gate; optional)
//   fetchImpl     fetch (defaults to global fetch)
//   reason        'payment' (default) | 'token'  — 'custody' needs a buildPin override
//   retainMs      pin retention window (default 30d)
//   buildPin      optional async (shardId, bytes, ctx) -> pin  (custody/token override)
//                 For the v0.24.0 custody pin, ctx must include { custodyIntentId,
//                 shareIndex } — see js/blind-dealer.mjs makeCustodyBuildPin().
//   now / nonce   injectables for deterministic tests (Date.now / random hex)
export function createShardStoreAdapter (opts = {}) {
  const {
    resolveEndpoint, roster, pinner, signRaw,
    token = null,
    fetchImpl = (typeof fetch !== 'undefined' ? fetch : null),
    reason = 'payment', retainMs = DEFAULT_RETAIN_MS, buildPin = null,
    now = () => Date.now(), nonce = () => randomHex(16)
  } = opts

  if (typeof fetchImpl !== 'function') throw new Error('createShardStoreAdapter: fetch is required')
  const endpointOf = typeof resolveEndpoint === 'function'
    ? resolveEndpoint
    : (() => {
        const map = new Map((roster || []).map(r => [r.pub || r.publicKey || r.key, r.url || r.base]))
        return (relayPub) => map.get(relayPub)
      })()

  async function authHeaders (extra) {
    const h = { ...extra }
    const t = typeof token === 'function' ? await token() : token
    if (t) h['x-pear-token'] = String(t)
    return h
  }

  async function makePin (shardId, bytes) {
    if (typeof buildPin === 'function') return buildPin(shardId, bytes, { reason, pinner, now, nonce, retainMs })
    if (!signRaw || !pinner) throw new Error('putShard: signRaw + pinner required to authorize a PUT')
    return buildPaymentPin({ hash: shardId, pinner, retainUntil: now() + retainMs, nonce: nonce(), signRaw, reason })
  }

  async function putShard (relayPub, shardId, bytes) {
    const base = endpointOf(relayPub)
    if (!base) throw new Error('putShard: no endpoint for relay ' + String(relayPub).slice(0, 12))
    const pin = await makePin(shardId, bytes)
    const body = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)
    const res = await fetchImpl(base.replace(/\/$/, '') + '/api/v1/shard', {
      method: 'POST',
      headers: await authHeaders({ 'content-type': 'application/octet-stream', 'x-shard-pin': JSON.stringify(pin) }),
      body
    })
    if (res.status !== 201) throw new Error('putShard failed ' + res.status + ' (' + (await readErr(res)) + ')')
    const receipt = await res.json()
    // Defence in depth: the server self-verified blake2b(bytes)==hash before accepting;
    // confirm it addressed the shard we intended (never trust, always check).
    if (receipt && receipt.shard && receipt.shard !== 'shard:' + shardId) {
      throw new Error('putShard: server addressed ' + receipt.shard + ' != shard:' + shardId)
    }
    return receipt
  }

  async function getShard (relayPub, shardId) {
    const base = endpointOf(relayPub)
    if (!base) return null // unknown relay → treat as a miss, reader routes onward
    const res = await fetchImpl(base.replace(/\/$/, '') + '/api/v1/shard/' + String(shardId).toLowerCase(), {
      method: 'GET',
      headers: await authHeaders({})
    })
    if (res.status === 404) return null
    if (res.status !== 200) throw new Error('getShard failed ' + res.status + ' (' + (await readErr(res)) + ')')
    const buf = await res.arrayBuffer()
    return new Uint8Array(buf)
  }

  return { putShard, getShard }
}
