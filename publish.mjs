#!/usr/bin/env node
/**
 * publish.mjs — publish peerit to HiveRelay and register it in the PearBrowser
 * catalog. Mirrors pearbrowser-publishers/publish-app-to-catalog.mjs.
 *
 *   1. publish this folder as a Hyperdrive (the served P2P site)  -> driveKey
 *   2. write driveKey / url back into manifest.json
 *   3. publish /manifest.json under appId "peerit" and seed the site drive so
 *      the relay fleet replicates + lists it (it then appears in /catalog.json)
 *
 * Usage:
 *   node publish.mjs            # publish + seed, wait, exit
 *   KEEP=1 node publish.mjs     # stay alive so relays fully anchor the drive
 *
 * NOTE: this is an OUTWARD-FACING action — it puts peerit on the live network.
 * Run it deliberately. It is not invoked by the app or by any build step.
 */
import { HiveRelayClient } from '/Users/localllm/Projects/pear-ecosystem/00-core/hiverelay/packages/client/index.js'
import { readFileSync, writeFileSync } from 'fs'
import { fileURLToPath } from 'url'
import { dirname, join } from 'path'

const __dir = dirname(fileURLToPath(import.meta.url))
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
const relayCount = (s) => (s && (s.relays ? s.relays.length : s.relayCount)) || 0

// Files that make up the served site (everything the browser needs, nothing else).
const SITE_FILES = [
  'index.html', 'styles.css', 'icon.svg',
  'js/app.js', 'js/canon.js', 'js/crypto.js', 'js/data.js', 'js/gossip.js',
  'js/identity.js', 'js/markdown.js', 'js/model.js', 'js/prefs.js',
  'js/ranking.js', 'js/sync.js', 'js/util.js', 'js/verify.js'
]

// --local: create the Hyperdrive locally and host it for PearBrowser testing,
// WITHOUT seeding to public relays or registering in the catalog. Effectively
// private — the key isn't shared anywhere; only a peer you hand the key to (your
// own PearBrowser on the same DHT) can fetch it, and only while this stays running.
const LOCAL = process.argv.includes('--local')

async function main () {
  const manifestPath = join(__dir, 'manifest.json')
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'))

  const client = new HiveRelayClient({ storage: join(__dir, LOCAL ? '.hiverelay-local' : '.hiverelay-seed') })
  await client.start()
  await sleep(LOCAL ? 1500 : 5000)
  console.log('[peerit] relays connected:', relayCount(client.getStatus && client.getStatus()))

  // 1. publish the site folder as a drive (seed only on a real public deploy)
  const files = SITE_FILES.map((p) => ({ path: '/' + p, content: readFileSync(join(__dir, p)) }))
  console.log('[peerit] publishing site drive (' + files.length + ' files)…')
  const drive = await client.publish(files, { appId: 'peerit', seed: !LOCAL, replicas: 4, ttlDays: 365 })
  const driveKey = drive.key.toString('hex')
  console.log('[peerit] site drive key:', driveKey)

  if (LOCAL) {
    console.log('\n[peerit] ── LOCAL TEST (not seeded to relays, not in catalog) ──')
    console.log('[peerit] Open this in PearBrowser:')
    console.log('\n    hyper://' + driveKey + '/\n')
    console.log('[peerit] Keep THIS process running so PearBrowser can replicate the drive.')
    console.log('[peerit] (Ctrl-C to stop hosting.)')
    setInterval(() => {}, 1 << 30)
    return
  }

  // 2. record the key in manifest.json + url fields
  manifest.driveKey = driveKey
  manifest.url = 'hyper://' + driveKey + '/'
  manifest.homepage = manifest.url
  writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n')
  console.log('[peerit] manifest.json updated with driveKey')

  // 3. publish the manifest under appId + seed the drive so the fleet lists it
  console.log('[peerit] publishing manifest + seeding for catalog…')
  await client.publish([{ path: '/manifest.json', content: JSON.stringify(manifest, null, 2) }],
    { appId: 'peerit-manifest', seed: true, replicas: 4, ttlDays: 365 })
  try {
    const res = await client.seed(Buffer.from(driveKey, 'hex'), { replicas: 4, ttlDays: 365, timeout: 30000 })
    console.log('[peerit] seed acceptances:', (res || []).length)
  } catch (err) {
    console.log('[peerit] seed note:', err.message)
  }

  console.log('\n[peerit] Live at:  hyper://' + driveKey + '/')
  console.log('[peerit] Open it in PearBrowser to use peerit.\n')

  if (process.env.KEEP === '1') {
    console.log('[peerit] staying alive so relays anchor the drive (Ctrl-C to stop)…')
    setInterval(() => {}, 1 << 30)
    return
  }
  await sleep(20000)
  try { if (client.destroy) await client.destroy() } catch {}
  process.exit(0)
}

main().catch((err) => { console.error('[peerit] failed:', err.stack || err.message); process.exit(1) })
