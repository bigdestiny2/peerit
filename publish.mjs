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
const intEnv = (name, fallback) => {
  const n = Number(process.env[name])
  return Number.isFinite(n) && n > 0 ? n : fallback
}

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
const REPLICAS = intEnv('REPLICAS', 4)
const TTL_DAYS = intEnv('TTL_DAYS', 365)
const ANCHOR_TIMEOUT_MS = intEnv('ANCHOR_TIMEOUT_MS', 120000)
const MIN_ANCHOR_PEERS = intEnv('MIN_ANCHOR_PEERS', 1)
const STRICT_ANCHOR = process.env.STRICT_ANCHOR === '1'

// Verify the BLOBS core — the file BYTES — has been mirrored to a relay, not just
// the metadata. A Hyperdrive splits into two hypercores: drive.core is the Hyperbee
// metadata/file-index (tiny — replicates in milliseconds), and drive.blobs.core is
// the content store holding index.html / js/app.js bytes (the big one). The SDK's
// waitForDurable/getDurableStatus only watch drive.core, so durable:true there means
// "the file LIST reached a relay", NOT "the file BYTES did". That false positive is
// exactly how a drive serves index.html (early blocks) while js/app.js 404s — the
// relay holds the index and some blocks but never finished the blobs core. So we poll
// the blobs core's own replication peers until one has the full contiguous length.
async function waitForBlobsDurable (drive, { timeoutMs = 120000, pollMs = 1000, minPeers = 1 } = {}) {
  const blobs = await drive.getBlobs()            // forces the (lazy) content core open
  const bcore = blobs.core                        // SEPARATE hypercore = the file bytes
  await bcore.ready()
  const deadline = Date.now() + timeoutMs
  const snap = () => {
    const peers = bcore.peers || []
    const localLen = bcore.length || 0
    let remoteMax = 0
    for (const p of peers) {
      const rl = (p && (p.remoteContiguousLength || p.remoteLength)) || 0
      if (rl > remoteMax) remoteMax = rl
    }
    return {
      activePeers: peers.length,
      blobLocalLen: localLen,
      blobRemoteMax: remoteMax,
      durable: peers.length >= minPeers && localLen > 0 && remoteMax >= localLen
    }
  }
  let s = snap()
  while (Date.now() < deadline && !s.durable) { await sleep(pollMs); s = snap() }
  return s
}

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
  const drive = await client.publish(files, {
    appId: 'peerit',
    seed: !LOCAL,
    replicas: REPLICAS,
    ttlDays: TTL_DAYS,
    timeout: Math.min(60000, ANCHOR_TIMEOUT_MS),
    durability: process.env.DURABILITY || 'archive'
  })
  const driveKey = drive.key.toString('hex')
  console.log('[peerit] site drive key:', driveKey)
  if (drive.replicas) console.log('[peerit] publish seed status:', JSON.stringify(drive.replicas))

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
    { appId: 'peerit-manifest', seed: true, replicas: REPLICAS, ttlDays: TTL_DAYS, timeout: Math.min(60000, ANCHOR_TIMEOUT_MS) })
  try {
    const res = await client.seed(Buffer.from(driveKey, 'hex'), {
      replicas: REPLICAS,
      ttlDays: TTL_DAYS,
      timeout: Math.min(60000, ANCHOR_TIMEOUT_MS),
      durability: process.env.DURABILITY || 'archive'
    })
    console.log('[peerit] seed acceptances:', (res || []).length)
  } catch (err) {
    console.log('[peerit] seed note:', err.message)
  }

  console.log('[peerit] waiting for relay byte replication evidence…')
  const durable = await client.waitForDurable(drive.key, {
    timeoutMs: ANCHOR_TIMEOUT_MS,
    minPeers: MIN_ANCHOR_PEERS
  })
  console.log('[peerit] metadata durable status:', JSON.stringify(durable))

  // The check that actually decides whether the site loads: did a relay mirror the
  // BLOBS core (the file bytes)? Metadata-durable is necessary but NOT sufficient.
  console.log('[peerit] waiting for relay BLOB replication (the file bytes — js/app.js etc.)…')
  const blobDurable = await waitForBlobsDurable(drive, {
    timeoutMs: ANCHOR_TIMEOUT_MS,
    minPeers: MIN_ANCHOR_PEERS
  })
  console.log('[peerit] blob durable status:', JSON.stringify(blobDurable))

  const metaOk = durable.durable && durable.activePeers >= MIN_ANCHOR_PEERS
  if (!metaOk) {
    const msg = 'seed accepted, but no relay proved it caught up to the drive METADATA'
    if (STRICT_ANCHOR) throw new Error(msg)
    console.warn('[peerit] WARNING:', msg)
  }
  if (!blobDurable.durable) {
    const msg = `metadata anchored but NO relay mirrored the full BLOBS core ` +
      `(${blobDurable.blobRemoteMax}/${blobDurable.blobLocalLen} blocks) — ` +
      `index.html may load while js/app.js 404s. This is the silent partial-pin.`
    if (STRICT_ANCHOR) throw new Error(msg)
    console.warn('[peerit] WARNING:', msg)
    console.warn('[peerit] Keep this alive (KEEP=1) until blobRemoteMax reaches blobLocalLen, or run peerit-mirror.')
  } else {
    console.log(`[peerit] ✓ blobs fully mirrored to a relay (${blobDurable.blobRemoteMax}/${blobDurable.blobLocalLen} blocks, ${blobDurable.activePeers} peers)`)
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
