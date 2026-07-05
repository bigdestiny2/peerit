#!/usr/bin/env node
// ciphertext-off-vps-proof.mjs — prove the body bytes leave the VPS/outbox.
//
// This is the Phase-D gate from BLINDSHARD-RECORD-WIRING-SPEC.md: the dealer
// stores the AES key shards AND the ciphertext itself on the HiveRelay shard
// cohort. The VPS/outbox ends up holding only the keyless dispersal manifest.
//
//   node scripts/ciphertext-off-vps-proof.mjs [path/to/roster.json]
//
// Defaults to ~/.hiverelay-shard-cohort/roster.json. Exit 0 = PASS.
import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { createHttpShardFetch } from '../js/vendor/blind-shards/shard-transport.js'
import { disperseBody, recoverBody, makeHiverelayKeypair } from '../js/blind-dealer.mjs'
import sodium from 'sodium-universal'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const COHORT_DEFAULT = path.join(process.env.HOME || '/tmp', '.hiverelay-shard-cohort', 'roster.json')
const ROSTER_PATH = process.argv[2] || COHORT_DEFAULT
const REPORT_DIR = path.join(ROOT, 'reports')

function publisherFromSeed (seedHex) {
  const seed = Buffer.from(seedHex, 'hex')
  const pk = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const sk = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_seed_keypair(pk, sk, seed)
  return makeHiverelayKeypair({ seedHex, pubHex: pk.toString('hex') })
}

async function main () {
  if (!fs.existsSync(ROSTER_PATH)) {
    console.error(`[ciphertext-off-vps] roster not found: ${ROSTER_PATH}`)
    console.error('  start a local cohort: cd ../hiverelay && node scripts/run-local-shard-cohort.mjs')
    process.exit(2)
  }

  const cfg = JSON.parse(fs.readFileSync(ROSTER_PATH, 'utf8'))
  const k = Number(cfg.threshold)
  const n = (cfg.relays || []).length
  if (!k || n < k) {
    console.error('[ciphertext-off-vps] bad roster: need threshold <= relay count')
    process.exit(2)
  }

  console.log(`\n[ciphertext-off-vps] cohort: ${n} relays, k=${k}`)
  for (const r of cfg.relays) console.log(`  ${r.baseUrl || r.url}`)

  const seedBody = 'Peerit ciphertext-off-VPS proof — body bytes live on the shard cohort, not the relay.'
  const seedHex = crypto.randomBytes(32).toString('hex')
  const publisher = publisherFromSeed(seedHex)

  console.log(`\n[ciphertext-off-vps] dispersing ${seedBody.length}-byte body with putCiphertext...`)
  const { ciphertext, manifest } = await disperseBody(seedBody, {
    threshold: k,
    relays: cfg.relays,
    publisher,
    putCiphertext: true,
    fetch: globalThis.fetch
  })
  console.log(`[ciphertext-off-vps] ciphertext: ${ciphertext.length} bytes`)
  console.log(`[ciphertext-off-vps] manifest ciphertextShard: ${manifest.ciphertextShard}`)

  const relayBaseUrls = cfg.relays.map(r => r.baseUrl || r.url)

  // Recovery path that fetches ciphertext from the shard cohort, not a local blob.
  console.log('\n[ciphertext-off-vps] recovering body via shard-cohort ciphertext fetch...')
  const fetchShard = createHttpShardFetch({ baseUrls: relayBaseUrls, fetch: globalThis.fetch })
  const recovered = await recoverBody(manifest, {
    relayBaseUrls: relayBaseUrls.slice(0, k),
    fetchCiphertext: async () => fetchShard(manifest.ciphertextShard),
    fetchImpl: globalThis.fetch
  })

  if (recovered !== seedBody) {
    console.error('[ciphertext-off-vps] ❌ body mismatch')
    process.exit(1)
  }
  console.log('[ciphertext-off-vps] ✅ body recovered from shard-cohort ciphertext')

  // k-1 must still fail on the PVSS shares.
  console.log('[ciphertext-off-vps] checking k-1 fail-closed on key shares...')
  let underKRefused = false
  try {
    await recoverBody(manifest, {
      relayBaseUrls: relayBaseUrls.slice(0, k - 1),
      fetchCiphertext: async () => fetchShard(manifest.ciphertextShard),
      fetchImpl: globalThis.fetch
    })
  } catch {
    underKRefused = true
  }
  if (!underKRefused) {
    console.error('[ciphertext-off-vps] ❌ reconstructed with <k relays')
    process.exit(1)
  }
  console.log('[ciphertext-off-vps] ✅ k-1 refused')

  // Missing ciphertext shard must fail closed.
  console.log('[ciphertext-off-vps] checking missing-ciphertext fail-closed...')
  let missingCtRefused = false
  try {
    await recoverBody(manifest, {
      relayBaseUrls: relayBaseUrls.slice(0, k),
      fetchCiphertext: async () => null,
      fetchImpl: globalThis.fetch
    })
  } catch {
    missingCtRefused = true
  }
  if (!missingCtRefused) {
    console.error('[ciphertext-off-vps] ❌ missing ciphertext accepted')
    process.exit(1)
  }
  console.log('[ciphertext-off-vps] ✅ missing ciphertext refused')

  fs.mkdirSync(REPORT_DIR, { recursive: true })
  const date = new Date().toISOString().slice(0, 10)
  const reportPath = path.join(REPORT_DIR, `ciphertext-off-vps-${date}.json`)
  const evidence = {
    kind: 'ciphertext-off-vps',
    generatedAt: new Date().toISOString(),
    rosterPath: ROSTER_PATH,
    cohort: { threshold: k, count: n, relays: relayBaseUrls },
    publisherPubkey: publisher.pubkeyHex,
    manifestSummary: {
      scheme: manifest.scheme,
      threshold: manifest.threshold,
      count: manifest.count,
      blindContentId: manifest.blindContentId,
      ciphertextShard: manifest.ciphertextShard,
      intentId: manifest.intentId || manifest.intent?.intentId
    },
    checks: {
      bodyRecovered: true,
      underKRefused: true,
      missingCiphertextRefused: true
    },
    status: 'pass'
  }
  fs.writeFileSync(reportPath, JSON.stringify(evidence, null, 2))
  console.log(`\n[ciphertext-off-vps] evidence written: ${reportPath}`)
  console.log('[ciphertext-off-vps] ✅ PASS — ciphertext lives on the cohort, not the VPS\n')
}

main().catch((e) => {
  console.error('[ciphertext-off-vps] ❌', e.message, '\n', e.stack)
  process.exit(1)
})
