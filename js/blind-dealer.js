// blind-dealer.js — peerit's BlindShard DEALER (Node path; browser parked on #115).
//
// Composes the VENDORED, audited HiveRelay client (js/vendor/blind-shards, pinned to
// P2P-Hiverelay@4facbae / PR #159) with peerit's own signing identity. It disperses a
// secret k-of-n across a relay roster so no single operator holds >= k shares, and
// reconstructs from any k. peerit supplies ONLY the keys + the two signed artifacts the
// relay authorizes against — the PVSS math and the wire come from the proven client:
//
//   disperse()  -> planDispersal (PVSS)  → publish v2 custody intent → PUT each shard
//   recover()   -> gather >= k shards → recoverSecret (fail-closed on commitment)
//
// The custody INTENT is signed with a sodium keypair derived from the publisher's Ed25519
// seed; each custody PIN is signed with the same key over peerit's shardPinSignable, which
// is byte-identical to the relay's verifyShardPin (proven by test/shard-store-adapter.mjs).
// Content bodies are NOT dispersed here — this disperses a SECRET (e.g. a content key);
// wiring it into the write/read path is the seeder-as-dealer step.
import sodium from 'sodium-universal'
import b4a from 'b4a'
import { disperse as vendorDisperse, recover as vendorRecover } from './vendor/blind-shards/blind-custody.js'
import { createCustodyIntent, hashHex } from './vendor/blind-shards/custody-signing.js'
import { shardAddressOf } from './vendor/blind-shards/blind-shards.js'
import { shardPinSignable } from './shard-store-adapter.js' // peerit's pin signable — byte-identical to verifyShardPin

const DAY = 24 * 60 * 60 * 1000

// roster: [{ baseUrl, pubkey(64hex), apiKey }] in SHARE-INDEX order (share i → roster[i-1]).
export function makeBlindDealer ({ seed, roster, threshold, contentVersion = 1, retainMs = 30 * DAY, fetchImpl = globalThis.fetch } = {}) {
  if (!seed) throw new Error('makeBlindDealer: publisher seed (hex) required')
  if (!Array.isArray(roster) || !roster.length) throw new Error('makeBlindDealer: roster[] required')
  if (!Number.isInteger(threshold) || threshold < 1 || threshold > roster.length) throw new Error('makeBlindDealer: 1 <= threshold <= roster.length')
  if (typeof fetchImpl !== 'function') throw new Error('makeBlindDealer: fetch required')

  // Publisher keypair from the Ed25519 seed (same key signs the intent AND every pin).
  const publicKey = b4a.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const secretKey = b4a.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_seed_keypair(publicKey, secretKey, b4a.from(seed, 'hex'))
  const keyPair = { publicKey, secretKey }
  const pubHex = b4a.toString(publicKey, 'hex')
  const signRaw = (msg) => { const sig = b4a.alloc(sodium.crypto_sign_BYTES); sodium.crypto_sign_detached(sig, b4a.from(String(msg), 'utf8'), secretKey); return b4a.toString(sig, 'hex') }
  const freshNonce = () => { const b = b4a.alloc(16); sodium.randombytes_buf(b); return b4a.toString(b, 'hex') }

  const relays = roster.map((r) => ({ baseUrl: r.baseUrl, pubkey: String(r.pubkey).toLowerCase() }))
  const apiKeyFor = (baseUrl) => (roster.find((r) => r.baseUrl === baseUrl) || {}).apiKey

  // A custody pin the relay authorizes against the published intent (reason 'custody',
  // custodyIntentId + shareIndex non-null — the two fields that lifted us off orphan-intent).
  const buildCustodyPin = (hash, custodyIntentId, shareIndex, retainUntil) => {
    const pin = { reason: 'custody', hash, pinner: pubHex, custodyIntentId, shareIndex, retainUntil, nonce: freshNonce() }
    pin.sig = signRaw(shardPinSignable(pin))
    return pin
  }

  async function disperse (secret, { blindContentId } = {}) {
    let intent = null
    const retainUntil = Date.now() + retainMs
    const result = await vendorDisperse(secret, {
      relays,
      threshold,
      fetch: fetchImpl,
      // Publish ONE v2 custody intent (built on the first call, POSTed to every relay) so
      // each PUT authorizes against an intent the relay has already indexed.
      publishIntent: async (relay, partial) => {
        if (!intent) {
          intent = createCustodyIntent({
            version: 2, // REQUIRED — unlocks the v2 share-field allowlist
            blindContentId: blindContentId || hashHex({ t: 'peerit-blind-content-v1', root: partial.commitmentRoot, pub: pubHex, v: contentVersion }),
            ciphertextRoot: partial.commitmentRoot,
            contentVersion,
            requiredReplicas: partial.count,
            candidateRelays: relays.map((r) => r.pubkey),
            shareScheme: 'pvss-secp256k1-v1',
            shareThreshold: threshold,
            commitmentRoot: partial.commitmentRoot,
            shareBundleKey: shardAddressOf(b4a.from(partial.commitmentRoot, 'hex')).slice('shard:'.length),
            shareAssignments: partial.shareAssignments, // { relayPubkey, shareIndex }
            shareManifest: partial.shareManifest, // { shareIndex, shard, shareCommitment }
            retainUntil
          }, keyPair)
        }
        const apiKey = apiKeyFor(relay.baseUrl)
        const res = await fetchImpl(relay.baseUrl.replace(/\/+$/, '') + '/api/custody/intent', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', ...(apiKey ? { Authorization: 'Bearer ' + apiKey } : {}) },
          body: JSON.stringify(intent)
        })
        if (!res || !res.ok) throw new Error('publish intent -> ' + relay.baseUrl + ' ' + (res && res.status))
      },
      signPin: (ctx) => buildCustodyPin(ctx.hash, intent.intentId, ctx.shareIndex, retainUntil)
    })
    return { ...result, intent } // { key, secretPoint, threshold, count, commitmentRoot, shareManifest, shareAssignments, refs, intent }
  }

  // Reconstruct from ANY k relays. Integrity rests on the AUTHENTIC shareManifest (from the
  // publisher-signed intent) — recoverSecret fail-closes on any share that doesn't match it.
  const recover = (shareManifest, { readRelays } = {}) =>
    vendorRecover({ relays: (readRelays || relays), shareManifest, threshold, fetch: fetchImpl })

  return { disperse, recover, publisherPubkey: pubHex }
}
