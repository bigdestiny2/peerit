#!/usr/bin/env node
// seed-disperse.mjs — disperse peerit's REAL curated seed bodies across a live
// HiveRelay shard-store cohort and prove each one reconstructs. This is the
// content-integration proof: the SAME content the seeder writes (test/seed-author.mjs
// SEED), but each body's AES-256-GCM key is PVSS-split k-of-n so no single relay can
// read it — the only thing an operator holds is opaque ciphertext + one sub-threshold
// share. The dealer identity is derived from the seed author's own persisted seed, so
// the custody intents are signed by the very key that authors the content.
//
//   node scripts/seed-disperse.mjs [roster.json]
//     roster.json default: ~/.hiverelay-shard-cohort/roster.json
//     { threshold, relays:[{ baseUrl, pubkey, apiKey }] }   (same shape the dealer contract consumes)
//
// Exit 0 = every seed body dispersed AND reconstructed from k, AND k-1 fail-closed.
//
// SCOPE (honest): decoupled from js/data.js on purpose. This proves the seeder-as-dealer
// mechanism against a real mount; it does NOT yet wire the manifest onto the live post
// record or store the ciphertext as a relay blob — that record-model change plus a
// browser reader are gated on HiveRelay #115 and coordinated with the data-model work.
// A same-machine cohort proves the MECHANISM + wire contract, not the security property
// (which needs >=3 INDEPENDENT operators, GATE 2).
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import crypto from 'node:crypto'
import { fileURLToPath } from 'node:url'
import sodium from 'sodium-universal'
import { SEED } from '../test/seed-author.mjs'
import { disperseBody, recoverBody, makeHiverelayKeypair } from '../js/blind-dealer.mjs'

// Derive the dealer identity the same way the dealer signs (sodium), so the pinned
// publisher is stable + self-consistent. peerit's genKeyPair() derives Ed25519 via the
// same crypto_sign_seed_keypair, so this pubkey == the seed author's own identity.
function publisherFromSeed (seedHex) {
  const seed = Buffer.from(seedHex, 'hex')
  const pk = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const sk = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_seed_keypair(pk, sk, seed)
  return makeHiverelayKeypair({ seedHex, pubHex: pk.toString('hex') })
}

// Root secret for the dealer: reuse the seed author's persisted identity seed so the
// dispersal is authored by the same key that writes the content. Fall back to a
// persisted dedicated dealer seed if the author store is absent (keeps re-runs stable).
function dealerSeed () {
  const store = fileURLToPath(new URL('../.seed-author-store.json', import.meta.url))
  try {
    const users = JSON.parse(JSON.parse(fs.readFileSync(store, 'utf8'))['peerit:dev:users'])
    const s = users?.[0]?.seed
    if (typeof s === 'string' && /^[0-9a-f]{64}$/i.test(s)) return s.toLowerCase()
  } catch {}
  const p = path.join(os.homedir(), '.peerit-dispersed', 'dealer-seed')
  try { const s = fs.readFileSync(p, 'utf8').trim(); if (/^[0-9a-f]{64}$/i.test(s)) return s } catch {}
  const s = crypto.randomBytes(32).toString('hex')
  fs.mkdirSync(path.dirname(p), { recursive: true }); fs.writeFileSync(p, s)
  return s
}

async function main () {
  const rosterPath = process.argv[2] || path.join(os.homedir(), '.hiverelay-shard-cohort', 'roster.json')
  const cohort = JSON.parse(fs.readFileSync(rosterPath, 'utf8'))
  const k = Number(cohort.threshold)
  const relays = cohort.relays || []
  const n = relays.length
  if (!(k >= 2) || n < k) { console.error(`bad roster: threshold ${k}, ${n} relays`); process.exit(2) }
  const baseUrls = relays.map((r) => r.baseUrl || r.url)
  const publisher = publisherFromSeed(dealerSeed())

  // Flatten SEED (all communities) to the list of bodies the seeder writes.
  const items = []
  for (const [community, comm] of Object.entries(SEED))
    for (const p of comm.posts) items.push({ community, cid: p.cid, title: p.title, body: p.body })

  console.log(`\n▶ dispersing ${items.length} seed bodies across ${n} relays (k=${k}), dealer ${publisher.pubkeyHex.slice(0, 12)}… (== seed author)\n`)

  // The ciphertext store models the opaque blob an operator would hold. Held in-process
  // here (blob storage is out-of-band for the dealer); recovery fetches from it by cid.
  const blobs = new Map() // blindContentId -> ciphertext bytes
  const manifests = []
  let pass = 0, fail = 0

  for (const it of items) {
    try {
      const d = await disperseBody(it.body, { threshold: k, relays, publisher, fetch: globalThis.fetch })
      blobs.set(d.manifest.blindContentId, d.ciphertext)
      manifests.push({ community: it.community, cid: it.cid, title: it.title, blindContentId: d.manifest.blindContentId, intentId: d.intent.intentId, manifest: d.manifest })
      const fetchCiphertext = async () => blobs.get(d.manifest.blindContentId)

      // any-k reconstruct (first k relays) must return the exact body
      const back = await recoverBody(d.manifest, { relayBaseUrls: baseUrls.slice(0, k), fetchCiphertext, fetchImpl: globalThis.fetch })
      const ok = back === it.body
      // k-1 must fail-closed
      let refused = false
      try { await recoverBody(d.manifest, { relayBaseUrls: baseUrls.slice(0, k - 1), fetchCiphertext, fetchImpl: globalThis.fetch }) } catch { refused = true }

      if (ok && refused) { pass++; console.log(`  ✓ r/${it.community}/${it.cid.padEnd(15)} ${String(it.body.length).padStart(4)}B  ${d.placed.length} shards, intent ${d.intent.intentId.slice(0, 10)}…  k-of-n OK · k-1 refused`) }
      else { fail++; console.log(`  ✗ r/${it.community}/${it.cid}  reconstruct=${ok} k-1-refused=${refused}`) }
    } catch (e) { fail++; console.log(`  ✗ r/${it.community}/${it.cid}  ${e.message}`) }
  }

  // Persist the PUBLIC manifests sidecar (no secrets — the key is dispersed, the
  // ciphertext store stays in-process) so a node reader can reconstruct later.
  const outDir = path.join(os.homedir(), '.peerit-dispersed')
  fs.mkdirSync(outDir, { recursive: true })
  const sidecar = path.join(outDir, 'seed-manifests.json')
  fs.writeFileSync(sidecar, JSON.stringify({ dealer: publisher.pubkeyHex, threshold: k, relays: relays.map((r) => ({ baseUrl: r.baseUrl || r.url, pubkey: r.pubkey })), manifests }, null, 2))

  console.log(`\n${fail === 0 ? '✅' : '❌'} ${pass}/${items.length} seed bodies dispersed + reconstructed across the cohort · manifests → ${sidecar}\n`)
  process.exit(fail === 0 ? 0 : 1)
}
main().catch((e) => { console.error('❌', e.message, '\n', e.stack); process.exit(1) })
