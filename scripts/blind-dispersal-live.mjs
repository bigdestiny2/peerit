#!/usr/bin/env node
// blind-dispersal-live.mjs — run peerit's blind-shard dealer against a REAL relay
// cohort. The peerit-side sibling of HiveRelay's blind-dispersal-fleet harness: it
// encrypts a body, PVSS-splits the key across your relays, publishes a signed v2
// custody intent, PUTs each share to its assigned relay, then reconstructs from any k
// (and proves k-1 cannot). Keys never leave your config file.
//
//   node scripts/blind-dispersal-live.mjs <config.json>
//
// config.json:
//   { "threshold": 3,
//     "publisherSeed": "<64hex, optional — a stable dealer identity; random if omitted>",
//     "body": "hello from peerit",                // optional test payload
//     "relays": [
//       { "baseUrl": "https://relay-a…:9100", "pubkey": "<relay node pubkey 64hex>", "apiKey": "<admin key>" },
//       … ] }                                     // relays in SHARE-INDEX order
//
// Exit 0 = PASS (any-k reconstructs AND k-1 refused). Requires the relays to run the
// HiveRelay v0.24.0 shard-store surface (mounted /api/v1/shard + /api/custody/intent).
import fs from 'node:fs'
import crypto from 'node:crypto'
import sodium from 'sodium-universal'
import { disperseBody, recoverBody, makeHiverelayKeypair } from '../js/blind-dealer.mjs'

// Derive the Ed25519 public key from a 32-byte seed the same way the dealer signs
// (sodium), so the pinned publisher identity is stable + self-consistent.
function publisherFromSeed (seedHex) {
  const seed = Buffer.from(seedHex, 'hex')
  const pk = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const sk = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_seed_keypair(pk, sk, seed)
  return makeHiverelayKeypair({ seedHex, pubHex: pk.toString('hex') })
}

async function main () {
  const path = process.argv[2]
  if (!path) { console.error('usage: node scripts/blind-dispersal-live.mjs <config.json>'); process.exit(2) }
  const cfg = JSON.parse(fs.readFileSync(path, 'utf8'))
  const k = Number(cfg.threshold)
  const n = (cfg.relays || []).length
  const body = cfg.body || ('peerit blind-dispersal live check @ ' + new Date().toISOString())

  // Publisher (dealer) identity. Stable if you pin publisherSeed, else ephemeral.
  const seedHex = cfg.publisherSeed || crypto.randomBytes(32).toString('hex')
  const publisher = publisherFromSeed(seedHex)

  console.log(`\n▶ dispersing a ${body.length}-byte body across ${n} relays, k=${k}, publisher ${publisher.pubkeyHex.slice(0, 12)}…\n`)
  const d = await disperseBody(body, { threshold: k, relays: cfg.relays, publisher, fetch: globalThis.fetch })
  const ciphertext = d.ciphertext // held in-process (ciphertext storage is out-of-band for the dealer)

  console.log('  custody intent:', d.intent.intentId.slice(0, 16) + '…  (v' + d.intent.version + ', scheme ' + d.manifest.scheme + ')')
  for (const p of d.placed) console.log(`  share ${p.shareIndex} → ${p.relay}   ${p.shard.slice(0, 20)}…`)

  const readK = cfg.relays.slice(0, k).map((r) => r.baseUrl || r.url)
  const backK = await recoverBody(d.manifest, { relayBaseUrls: readK, fetchCiphertext: async () => ciphertext, fetchImpl: globalThis.fetch }).catch((e) => ({ err: e.message }))
  const anyKOk = backK === body

  let underKRefused = false
  try {
    await recoverBody(d.manifest, { relayBaseUrls: cfg.relays.slice(0, k - 1).map((r) => r.baseUrl || r.url), fetchCiphertext: async () => ciphertext, fetchImpl: globalThis.fetch })
  } catch { underKRefused = true }

  console.log('\n  any-k reconstruct:', anyKOk ? 'OK (body recovered)' : 'FAIL (' + JSON.stringify(backK) + ')')
  console.log('  k-1 refused      :', underKRefused ? 'OK (fail-closed)' : 'FAIL (reconstructed with < k!)')
  const pass = anyKOk && underKRefused
  console.log('\n' + (pass ? '✅ PASS — blind dispersal live across your fleet' : '❌ FAIL') + '\n')
  process.exit(pass ? 0 : 1)
}
main().catch((e) => { console.error('❌', e.message, '\n', e.stack); process.exit(1) })
