#!/usr/bin/env node
// reader-bundle-live.mjs — prove the browser reader bundle reconstructs a body
// dispersed to the live HiveRelay shard cohort. This is the Phase-B gate from
// BLINDSHARD-RECORD-WIRING-SPEC.md §9: the recover-only browser module is loaded
// and exercised against real relays, not a mock store.
//
//   node scripts/reader-bundle-live.mjs [path/to/roster.json]
//
// Defaults to ~/.hiverelay-shard-cohort/roster.json. Exit 0 = PASS.
import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { buildReaderBundle } from './build-reader-bundle.mjs'
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
    console.error(`[reader-bundle-live] roster not found: ${ROSTER_PATH}`)
    process.exit(2)
  }

  const cfg = JSON.parse(fs.readFileSync(ROSTER_PATH, 'utf8'))
  const k = Number(cfg.threshold)
  const n = (cfg.relays || []).length
  if (!k || n < k) {
    console.error('[reader-bundle-live] bad roster: need threshold <= relay count')
    process.exit(2)
  }

  console.log(`\n[reader-bundle-live] cohort: ${n} relays, k=${k}`)
  for (const r of cfg.relays) console.log(`  ${r.baseUrl || r.url}`)

  // 1) Build the browser reader bundle fresh.
  console.log('\n[reader-bundle-live] building browser reader bundle...')
  const bundleBuf = await buildReaderBundle({ outfile: 'web/js/reader-bundle.js' })
  console.log(`[reader-bundle-live] bundle: ${bundleBuf.length} bytes`)

  // 2) Disperse a seed-like body against the live cohort using the Node dealer.
  const seedBody = 'Peerit reader bundle live proof — browser recovery from real shards.'
  const seedHex = crypto.randomBytes(32).toString('hex')
  const publisher = publisherFromSeed(seedHex)

  console.log(`\n[reader-bundle-live] dispersing ${seedBody.length}-byte body...`)
  const { ciphertext, manifest } = await disperseBody(seedBody, {
    threshold: k,
    relays: cfg.relays,
    publisher,
    fetch: globalThis.fetch
  })
  console.log(`[reader-bundle-live] ciphertext: ${ciphertext.length} bytes`)
  console.log(`[reader-bundle-live] manifest intent: ${manifest.intentId?.slice(0, 16) || manifest.intent?.intentId?.slice(0, 16)}...`)

  // 3) Load the browser bundle and reconstruct from the live cohort.
  console.log('\n[reader-bundle-live] loading browser reader bundle...')
  const readerUrl = pathToFileURL(path.join(ROOT, 'web/js/reader-bundle.js')).href
  const { recoverBody: bundleRecoverBody } = await import(readerUrl + '?t=' + Date.now())

  const relayBaseUrls = cfg.relays.map(r => r.baseUrl || r.url)

  console.log('[reader-bundle-live] reconstructing via browser bundle (any k)...')
  const recovered = await bundleRecoverBody(manifest, {
    relayBaseUrls: relayBaseUrls.slice(0, k),
    fetchCiphertext: async () => ciphertext,
    fetchImpl: globalThis.fetch
  })

  if (recovered !== seedBody) {
    console.error('[reader-bundle-live] ❌ body mismatch')
    console.error('  expected:', seedBody)
    console.error('  got:', recovered)
    process.exit(1)
  }
  console.log('[reader-bundle-live] ✅ body recovered by browser bundle')

  // 4) k-1 must fail closed.
  console.log('[reader-bundle-live] checking k-1 fail-closed...')
  let underKRefused = false
  try {
    await bundleRecoverBody(manifest, {
      relayBaseUrls: relayBaseUrls.slice(0, k - 1),
      fetchCiphertext: async () => ciphertext,
      fetchImpl: globalThis.fetch
    })
  } catch {
    underKRefused = true
  }
  if (!underKRefused) {
    console.error('[reader-bundle-live] ❌ reconstructed with <k relays')
    process.exit(1)
  }
  console.log('[reader-bundle-live] ✅ k-1 refused')

  // 5) Tampered intent must be rejected.
  console.log('[reader-bundle-live] checking tampered-intent rejection...')
  const tampered = JSON.parse(JSON.stringify(manifest))
  tampered.intent.signature = '0'.repeat(128)
  let tamperRejected = false
  try {
    await bundleRecoverBody(tampered, {
      relayBaseUrls: relayBaseUrls.slice(0, k),
      fetchCiphertext: async () => ciphertext,
      fetchImpl: globalThis.fetch
    })
  } catch (e) {
    tamperRejected = /custody intent|signature invalid|verify/i.test(e.message)
  }
  if (!tamperRejected) {
    console.error('[reader-bundle-live] ❌ tampered intent accepted')
    process.exit(1)
  }
  console.log('[reader-bundle-live] ✅ tampered intent rejected')

  // 6) Write evidence.
  fs.mkdirSync(REPORT_DIR, { recursive: true })
  const date = new Date().toISOString().slice(0, 10)
  const reportPath = path.join(REPORT_DIR, `reader-bundle-live-${date}.json`)
  const evidence = {
    kind: 'reader-bundle-live',
    generatedAt: new Date().toISOString(),
    rosterPath: ROSTER_PATH,
    cohort: { threshold: k, count: n, relays: relayBaseUrls },
    publisherPubkey: publisher.pubkeyHex,
    bundleBytes: bundleBuf.length,
    manifestSummary: {
      scheme: manifest.scheme,
      threshold: manifest.threshold,
      count: manifest.count,
      blindContentId: manifest.blindContentId,
      intentId: manifest.intentId || manifest.intent?.intentId
    },
    checks: {
      bodyRecovered: true,
      underKRefused: true,
      tamperedIntentRejected: true
    },
    status: 'pass'
  }
  fs.writeFileSync(reportPath, JSON.stringify(evidence, null, 2))
  console.log(`\n[reader-bundle-live] evidence written: ${reportPath}`)
  console.log('[reader-bundle-live] ✅ PASS — browser reader bundle recovers from live cohort\n')
}

main().catch((e) => {
  console.error('[reader-bundle-live] ❌', e.message, '\n', e.stack)
  process.exit(1)
})
