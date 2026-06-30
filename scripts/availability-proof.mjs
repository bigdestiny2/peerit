#!/usr/bin/env node
import { createHash } from 'node:crypto'
import { existsSync, readFileSync, statSync } from 'node:fs'
import { dirname, join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { SITE_FILES } from '../publish.mjs'

const __dir = dirname(fileURLToPath(import.meta.url))
const ROOT = resolve(__dir, '..')
const DEFAULT_TIMEOUT_MS = Number(process.env.AVAILABILITY_PROOF_TIMEOUT_MS) || 12000

function usage (code = 0, message = '') {
  if (message) console.error('error:', message)
  console.error([
    'usage: node scripts/availability-proof.mjs [--url <http-url>] [--require-live] [--json]',
    '       node scripts/availability-proof.mjs --ship-report .deploy/last-ship.json --publish-report .deploy/last-publish.json'
  ].join('\n'))
  process.exit(code)
}

function parseArgs (argv) {
  const opts = {
    url: process.env.PEERIT_AVAILABILITY_URL || '',
    requireLive: process.env.REQUIRE_LIVE_AVAILABILITY === '1',
    json: false,
    shipReport: join(ROOT, '.deploy', 'last-ship.json'),
    publishReport: join(ROOT, '.deploy', 'last-publish.json'),
    timeoutMs: DEFAULT_TIMEOUT_MS
  }
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--url') opts.url = argv[++i] || ''
    else if (arg === '--require-live') opts.requireLive = true
    else if (arg === '--json') opts.json = true
    else if (arg === '--ship-report') opts.shipReport = resolve(ROOT, argv[++i] || '')
    else if (arg === '--publish-report') opts.publishReport = resolve(ROOT, argv[++i] || '')
    else if (arg === '--timeout-ms') opts.timeoutMs = Number(argv[++i]) || 0
    else if (arg === '-h' || arg === '--help') usage(0)
    else usage(2, `unknown option: ${arg}`)
  }
  if (!Number.isFinite(opts.timeoutMs) || opts.timeoutMs <= 0) usage(2, '--timeout-ms must be a positive number')
  return opts
}

function readJson (file) {
  try {
    return JSON.parse(readFileSync(file, 'utf8'))
  } catch {
    return null
  }
}

function sha256 (buf) {
  return createHash('sha256').update(buf).digest('hex')
}

function add (proof, id, status, message, evidence) {
  const check = { id, status, message }
  if (evidence !== undefined) check.evidence = evidence
  proof.checks.push(check)
}

function staticFileProof (proof) {
  const missing = []
  const empty = []
  const files = []
  let totalBytes = 0
  for (const file of SITE_FILES) {
    const abs = join(ROOT, file)
    if (!existsSync(abs)) {
      missing.push(file)
      continue
    }
    const stat = statSync(abs)
    const buf = readFileSync(abs)
    totalBytes += stat.size
    if (stat.size <= 0) empty.push(file)
    files.push({ file, bytes: stat.size, sha256: sha256(buf) })
  }
  if (missing.length) add(proof, 'static:files-present', 'fail', `${missing.length} published file(s) are missing.`, { missing })
  else add(proof, 'static:files-present', 'pass', `${SITE_FILES.length} published files are present.`, { files: SITE_FILES.length, bytes: totalBytes })
  if (empty.length) add(proof, 'static:files-nonempty', 'fail', `${empty.length} published file(s) are empty.`, { empty })
  else add(proof, 'static:files-nonempty', 'pass', 'Published files are non-empty.')
  proof.static = { files, totalBytes }
}

function htmlReferenceProof (proof) {
  const index = readFileSync(join(ROOT, 'index.html'), 'utf8')
  const refs = []
  for (const match of index.matchAll(/\b(?:src|href)=["']([^"']+)["']/g)) {
    const ref = match[1].split(/[?#]/)[0].replace(/^\//, '')
    if (!ref || ref.startsWith('http:') || ref.startsWith('https:') || ref.startsWith('hyper:') || ref.startsWith('pear:') || ref.startsWith('data:')) continue
    refs.push(ref)
  }
  const served = new Set(SITE_FILES)
  const missing = refs.filter(ref => !served.has(ref))
  if (missing.length) add(proof, 'static:html-refs', 'fail', 'index.html references files missing from SITE_FILES.', { missing })
  else add(proof, 'static:html-refs', 'pass', 'index.html references are included in the published file list.', { refs })
}

function importGraphProof (proof) {
  const served = new Set(SITE_FILES)
  const missing = []
  const imports = []
  const importRe = /(?:^|\n)\s*import\s+(?:[^'"]+\s+from\s*)?['"]([^'"]+)['"]|import\s*\(\s*['"]([^'"]+)['"]\s*\)/g

  for (const file of SITE_FILES) {
    if (!file.endsWith('.js')) continue
    const abs = join(ROOT, file)
    if (!existsSync(abs)) continue
    const src = readFileSync(abs, 'utf8')
    for (const match of src.matchAll(importRe)) {
      const spec = match[1] || match[2] || ''
      if (!spec.startsWith('./') && !spec.startsWith('../')) continue
      const imported = relative(ROOT, resolve(ROOT, dirname(file), spec.split(/[?#]/)[0])).replace(/\\/g, '/')
      imports.push({ from: file, import: spec, file: imported })
      if (!imported.startsWith('..') && !served.has(imported)) missing.push({ from: file, import: spec, file: imported })
    }
  }

  if (missing.length) add(proof, 'static:imports', 'fail', 'Static module imports are missing from SITE_FILES.', { missing })
  else add(proof, 'static:imports', 'pass', 'Static module imports are covered by the published file list.', { imports: imports.length })
}

function manifestProof (proof) {
  const manifest = readJson(join(ROOT, 'manifest.json'))
  proof.manifest = manifest
  if (!manifest) {
    add(proof, 'manifest:json', 'fail', 'manifest.json is missing or invalid.')
    return
  }
  add(proof, 'manifest:json', 'pass', 'manifest.json parses.')
  const driveKey = String(manifest.driveKey || '')
  if (/^[0-9a-f]{64}$/i.test(driveKey)) {
    add(proof, 'manifest:drive-key', 'pass', `manifest drive key is ${driveKey.slice(0, 12)}...`, { driveKey })
  } else {
    add(proof, 'manifest:drive-key', 'warn', 'manifest has no 64-byte hex drive key; publish may not have been run yet.')
  }
  if (manifest.url === `hyper://${driveKey}/` && manifest.homepage === manifest.url) {
    add(proof, 'manifest:url', 'pass', 'manifest url/homepage match the drive key.')
  } else {
    add(proof, 'manifest:url', 'warn', 'manifest url/homepage do not exactly match the drive key.', { url: manifest.url, homepage: manifest.homepage })
  }
}

function deployReportProof (proof, opts) {
  const ship = readJson(opts.shipReport)
  const publish = readJson(opts.publishReport)
  proof.deploy = { shipReport: opts.shipReport, publishReport: opts.publishReport, ship, publish }

  if (!ship) {
    add(proof, 'deploy:ship-report', opts.requireLive ? 'fail' : 'warn', 'ship report is missing; run npm run ship:check or npm run ship:live for operator evidence.', { file: opts.shipReport })
  } else if (ship.status === 'ready' || ship.status === 'review') {
    add(proof, 'deploy:ship-report', 'pass', `ship report exists with status ${ship.status}.`, { generatedAt: ship.generatedAt, status: ship.status })
  } else {
    add(proof, 'deploy:ship-report', opts.requireLive ? 'fail' : 'warn', `ship report is not ready: ${ship.status}.`, { status: ship.status, summary: ship.summary })
  }

  if (!publish) {
    add(proof, 'deploy:publish-report', opts.requireLive ? 'fail' : 'warn', 'publish report is missing; live relay byte anchoring is unproven in this run.', { file: opts.publishReport })
    return
  }

  const meta = publish.durability && publish.durability.metadata
  const blobs = publish.durability && publish.durability.blobs
  const metaOk = !!(meta && meta.durable)
  const blobsOk = !!(blobs && blobs.durable && blobs.blobLocalLen > 0 && blobs.blobRemoteMax >= blobs.blobLocalLen)
  if (publish.status === 'ready' && metaOk && blobsOk) {
    add(proof, 'deploy:publish-durable', 'pass', 'publish report proves metadata and blob bytes were mirrored by at least one relay.', {
      generatedAt: publish.generatedAt,
      driveKey: publish.driveKey,
      contentKey: publish.contentKey,
      metadata: meta,
      blobs
    })
  } else {
    add(proof, 'deploy:publish-durable', opts.requireLive ? 'fail' : 'warn', 'publish report does not prove durable metadata + blob byte replication.', {
      status: publish.status,
      metadata: meta,
      blobs
    })
  }
}

function siblingToolProof (proof) {
  const seeder = resolve(ROOT, '../peerit-seeder/seeder.mjs')
  const mirror = resolve(ROOT, '../peerit-mirror/mirror.mjs')

  if (!existsSync(seeder)) {
    add(proof, 'data:seeder-tool', 'warn', 'peerit-seeder was not found next to peerit.', { expected: seeder })
  } else {
    const src = readFileSync(seeder, 'utf8')
    const hasSeed = src.includes('.seed(') || src.includes('relay.seed')
    const hasRemoteLength = /remote(?:Contiguous)?Length/.test(src)
    if (hasSeed && hasRemoteLength) add(proof, 'data:seeder-tool', 'pass', 'peerit-seeder exists and checks relay byte catch-up before confirming fleet copies.')
    else add(proof, 'data:seeder-tool', 'warn', 'peerit-seeder exists, but byte catch-up heuristics were not found.', { hasSeed, hasRemoteLength })
  }

  if (!existsSync(mirror)) {
    add(proof, 'code:mirror-tool', 'warn', 'peerit-mirror was not found next to peerit.', { expected: mirror })
  } else {
    const src = readFileSync(mirror, 'utf8')
    const hasDriveDownload = src.includes("download('/')") || src.includes('download("/")')
    const hasBlobs = src.includes('blobs')
    if (hasDriveDownload && hasBlobs) add(proof, 'code:mirror-tool', 'pass', 'peerit-mirror exists and mirrors drive metadata plus blob bytes.')
    else add(proof, 'code:mirror-tool', 'warn', 'peerit-mirror exists, but full-drive/blob heuristics were not found.', { hasDriveDownload, hasBlobs })
  }
}

async function fetchWithTimeout (url, timeoutMs) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  try {
    const res = await fetch(url, { signal: controller.signal, cache: 'no-store' })
    const body = await res.arrayBuffer()
    return { ok: res.ok, status: res.status, bytes: body.byteLength, contentType: res.headers.get('content-type') || '' }
  } finally {
    clearTimeout(timer)
  }
}

async function httpFetchProof (proof, opts) {
  if (!opts.url) {
    add(proof, 'fetch:http', 'info', 'No --url supplied; skipped HTTP fetch proof.')
    return
  }
  const base = new URL(opts.url)
  if (!/^https?:$/.test(base.protocol)) {
    add(proof, 'fetch:http', opts.requireLive ? 'fail' : 'warn', 'Only http(s) URLs can be fetched by this proof script.', { url: opts.url })
    return
  }

  const targets = ['index.html', ...SITE_FILES.filter(file => file !== 'index.html')]
  const results = []
  for (const file of targets) {
    const url = new URL(file === 'index.html' ? './' : file, base).href
    try {
      const result = await fetchWithTimeout(url, opts.timeoutMs)
      results.push({ file, url, ...result })
    } catch (err) {
      results.push({ file, url, ok: false, error: err.message })
    }
  }

  const failed = results.filter(r => !r.ok || r.bytes <= 0)
  proof.fetch = { url: opts.url, results }
  if (failed.length) add(proof, 'fetch:http', 'fail', `${failed.length} published HTTP asset(s) failed to fetch.`, { failed })
  else add(proof, 'fetch:http', 'pass', `Fetched ${results.length} published assets from ${base.origin}.`, { bytes: results.reduce((n, r) => n + r.bytes, 0) })
}

function finish (proof) {
  const counts = { pass: 0, warn: 0, fail: 0, info: 0 }
  for (const check of proof.checks) counts[check.status] = (counts[check.status] || 0) + 1
  proof.counts = counts
  proof.status = counts.fail > 0 ? 'blocked' : (counts.warn > 0 ? 'review' : 'ready')
}

function printHuman (proof) {
  for (const check of proof.checks) {
    const prefix = check.status.toUpperCase().padEnd(4)
    console.log(`[availability] ${prefix} ${check.message}`)
  }
  console.log(`[availability] status=${proof.status} pass=${proof.counts.pass || 0} warn=${proof.counts.warn || 0} fail=${proof.counts.fail || 0} info=${proof.counts.info || 0}`)
}

async function main () {
  const opts = parseArgs(process.argv.slice(2))
  const proof = {
    appId: 'peerit',
    generatedAt: new Date().toISOString(),
    root: ROOT,
    requireLive: opts.requireLive,
    checks: []
  }

  staticFileProof(proof)
  htmlReferenceProof(proof)
  importGraphProof(proof)
  manifestProof(proof)
  deployReportProof(proof, opts)
  siblingToolProof(proof)
  await httpFetchProof(proof, opts)
  finish(proof)

  if (opts.json) console.log(JSON.stringify(proof, null, 2))
  else printHuman(proof)

  if (proof.status === 'blocked') process.exit(1)
}

main().catch((err) => {
  console.error('[availability] FAIL', err.stack || err.message)
  process.exit(1)
})
