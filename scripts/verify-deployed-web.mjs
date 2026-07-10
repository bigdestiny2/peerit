#!/usr/bin/env node

// Independently verify that a static origin serves the exact signed web/
// artifact prepared in this checkout. This script never trusts verifier code or
// configuration returned by the origin: the release key and expected deployment
// bytes come from the local audited checkout.

import { createHash } from 'node:crypto'
import { lstat, readFile } from 'node:fs/promises'
import { dirname, join, posix, relative, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { dedupeRelayList, normalizeRelayRosterPayload, verifyRelayRoster } from '../js/relay-roster.js'
import { RELEASE_MSG_VERSION, verifyReleaseManifest } from '../js/release-verify.js'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const WEB = join(ROOT, 'web')
const DEFAULT_URL = 'https://peerit.site'
const FETCH_TIMEOUT_MS = 20_000
const FETCH_CONCURRENCY = 8
const MAX_METADATA_BYTES = 2 * 1024 * 1024
const MAX_ASSET_BYTES = 32 * 1024 * 1024
const MAX_FILES = 2_048
const HEX64 = /^[0-9a-f]{64}$/

function usage (code = 0, message = '') {
  if (message) console.error(`[deploy-verify] FAIL ${message}`)
  console.error('usage: node scripts/verify-deployed-web.mjs [--url https://peerit.site]')
  process.exit(code)
}

function parseArgs (argv) {
  let url = DEFAULT_URL
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--url') {
      if (!argv[i + 1]) usage(2, '--url requires a value')
      url = argv[++i]
    } else if (arg.startsWith('--url=')) {
      url = arg.slice('--url='.length)
      if (!url) usage(2, '--url requires a value')
    } else if (arg === '-h' || arg === '--help') {
      usage(0)
    } else {
      usage(2, `unknown option: ${arg}`)
    }
  }
  return { baseUrl: normalizeBaseUrl(url) }
}

function normalizeBaseUrl (value) {
  let url
  try {
    url = new URL(String(value || ''))
  } catch {
    usage(2, '--url must be a valid http(s) URL')
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') usage(2, '--url must use http or https')
  if (url.username || url.password) usage(2, '--url must not contain credentials')
  url.search = ''
  url.hash = ''
  if (!url.pathname.endsWith('/')) url.pathname += '/'
  return url
}

function sha256 (bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

function parseJson (bytes, label) {
  try {
    const value = JSON.parse(bytes.toString('utf8'))
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('expected an object')
    return value
  } catch (err) {
    throw new Error(`${label} is not valid JSON (${err.message})`)
  }
}

async function readRequired (file, label = file) {
  try {
    return await readFile(file)
  } catch (err) {
    throw new Error(`${label} is missing or unreadable (${err.code || err.message})`)
  }
}

function safeManifestPath (file) {
  if (typeof file !== 'string' || !file || file.length > 240) return false
  if (!/^[A-Za-z0-9._/-]+$/.test(file)) return false
  if (file.startsWith('/') || file.includes('\\') || file.includes('//')) return false
  const segments = file.split('/')
  if (segments.some((segment) => !segment || segment === '.' || segment === '..')) return false
  return posix.normalize(file) === file
}

function repoPath (file, label) {
  const absolute = resolve(ROOT, file)
  const rel = relative(ROOT, absolute)
  if (!rel || rel === '..' || rel.startsWith(`..${sep}`) || resolve(ROOT, rel) !== absolute) {
    throw new Error(`${label} must be a repository-relative file`)
  }
  return absolute
}

export function releaseConfig (raw) {
  if (typeof raw.readonly !== 'boolean') throw new Error('deploy/web-release.json must explicitly set readonly=true or readonly=false')
  const releaseSequence = raw.releaseSequence
  if (!Number.isSafeInteger(releaseSequence) || releaseSequence < 1) {
    throw new Error('deploy/web-release.json releaseSequence must be a positive safe integer')
  }
  const bootstrapRelays = Array.isArray(raw.bootstrapRelays)
    ? raw.bootstrapRelays.map((value) => String(value).trim()).filter(Boolean)
    : String(raw.relay || '').split(',').map((value) => value.trim()).filter(Boolean)
  const canonicalRelays = dedupeRelayList(bootstrapRelays)
  if (!bootstrapRelays.length || canonicalRelays.length !== bootstrapRelays.length) {
    throw new Error('deploy/web-release.json bootstrap relays must be valid, canonical, and unique')
  }
  for (let i = 0; i < bootstrapRelays.length; i++) {
    if (bootstrapRelays[i] !== canonicalRelays[i]) {
      throw new Error('deploy/web-release.json bootstrap relays must be canonical URLs')
    }
  }

  const relayRoster = String(raw.relayRoster || 'relay-roster.json').trim()
  if (!safeManifestPath(relayRoster)) throw new Error('deploy/web-release.json relayRoster must be a safe repository-relative path')
  const pinnedRosterKey = String(raw.pinnedRosterKey || raw.rosterKey || '').trim().toLowerCase()
  const pinnedReleaseKey = String(raw.pinnedReleaseKey || raw.releaseKey || '').trim().toLowerCase()
  if (!HEX64.test(pinnedRosterKey)) throw new Error('deploy/web-release.json has an invalid pinnedRosterKey')
  if (!HEX64.test(pinnedReleaseKey)) throw new Error('deploy/web-release.json has an invalid pinnedReleaseKey')

  const readonly = raw.readonly ? 'true' : 'false'
  const shardRoster = String(raw.shardRoster || '').trim()
  if (shardRoster && !safeManifestPath(shardRoster)) {
    throw new Error('deploy/web-release.json shardRoster must be a safe repository-relative path')
  }
  // A read-only mirror must remain the deliberately small, non-custodial
  // artifact audited for the public preview. Writable candidates may opt into a
  // signed shard roster, which is then independently byte-checked below.
  if (readonly === 'true' && shardRoster) throw new Error('a public read-only release must not configure a shard roster')

  const roster = normalizeRelayRosterPayload(raw.roster || {
    version: 1,
    expires: raw.expires,
    relays: raw.relays || bootstrapRelays
  })
  if (readonly === 'false' && roster.relays.length < 2 && !roster.networkQuorum) {
    throw new Error('writable public web releases require at least two signed roster relays or a signed network-quorum policy')
  }

  return {
    releaseSequence,
    bootstrapRelays,
    relay: bootstrapRelays.join(','),
    relayBackend: String(raw.relayBackend || '').trim(),
    readonly,
    relayRoster,
    relayRosterMirrors: Array.isArray(raw.relayRosterMirrors)
      ? raw.relayRosterMirrors.map((value) => String(value).trim()).filter(Boolean)
      : [],
    pinnedRosterKey,
    pinnedReleaseKey,
    dhtRelay: String(raw.dhtRelay || '').trim(),
    shardRoster,
    seedOutboxes: Array.isArray(raw.seedOutboxes) ? raw.seedOutboxes : [],
    roster
  }
}

function assertManifestMap (value, kind) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`asset-manifest.json ${kind} must be an object`)
  }
  const entries = Object.entries(value)
  if (!entries.length) throw new Error(`asset-manifest.json ${kind} must not be empty`)
  for (const [file, hash] of entries) {
    if (!safeManifestPath(file)) throw new Error(`asset-manifest.json has an unsafe ${kind} path: ${file}`)
    if (!HEX64.test(String(hash || ''))) throw new Error(`asset-manifest.json has an invalid SHA-256 for ${file}`)
  }
  return entries
}

function manifestEntries (manifest) {
  const files = assertManifestMap(manifest.files, 'files')
  const controls = assertManifestMap(manifest.controls, 'controls')
  if (controls.map(([file]) => file).sort().join('\n') !== 'sw.js\nverify.html') {
    throw new Error('asset-manifest.json controls must contain exactly sw.js and verify.html')
  }
  if (files.length + controls.length > MAX_FILES) throw new Error(`asset-manifest.json exceeds the ${MAX_FILES}-file safety limit`)

  const seen = new Set()
  for (const [file] of [...files, ...controls]) {
    const key = file.toLowerCase()
    if (seen.has(key)) throw new Error(`asset-manifest.json has a duplicate or case-colliding path: ${file}`)
    seen.add(key)
  }
  return [...files, ...controls]
}

function equalJson (a, b) {
  return JSON.stringify(a) === JSON.stringify(b)
}

function decodeHtmlAttribute (value) {
  return String(value)
    .replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(Number(n)))
    .replace(/&#x([0-9a-f]+);/gi, (_, n) => String.fromCodePoint(parseInt(n, 16)))
    .replace(/&quot;/gi, '"')
    .replace(/&apos;|&#39;/gi, "'")
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&amp;/gi, '&')
}

function metaMap (html) {
  const map = new Map()
  for (const tag of String(html).match(/<meta\b[^>]*>/gi) || []) {
    const attrs = new Map()
    const source = tag.replace(/^<meta\b/i, '').replace(/>$/, '')
    const attr = /([^\s"'=<>`/]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g
    let match
    while ((match = attr.exec(source))) {
      const key = match[1].toLowerCase()
      const value = match[2] ?? match[3] ?? match[4] ?? ''
      if (!attrs.has(key)) attrs.set(key, decodeHtmlAttribute(value))
    }
    const name = String(attrs.get('name') || '').toLowerCase()
    if (!name) continue
    const values = map.get(name) || []
    values.push(attrs.get('content') || '')
    map.set(name, values)
  }
  return map
}

function requireMeta (metas, name, expected) {
  const values = metas.get(name) || []
  if (values.length !== 1) throw new Error(`index.html must contain exactly one ${name} meta tag`)
  if (values[0] !== expected) throw new Error(`index.html ${name} meta does not match deploy/web-release.json`)
}

function forbidMeta (metas, name) {
  if ((metas.get(name) || []).length) throw new Error(`index.html must not contain ${name} meta`)
}

function expectedSeedOutboxes (items) {
  return items
    .filter((item) => item && item.appId && item.inviteKey)
    .map((item) => `${item.appId}:${item.inviteKey}`)
    .join(',')
}

export function verifyIndexConfig (html, release) {
  const metas = metaMap(html)
  requireMeta(metas, 'peerit-relay', release.relay)
  requireMeta(metas, 'peerit-relay-readonly', release.readonly)
  requireMeta(metas, 'peerit-relay-roster', [release.relayRoster, ...release.relayRosterMirrors].join(','))
  requireMeta(metas, 'peerit-relay-roster-key', release.pinnedRosterKey)
  requireMeta(metas, 'peerit-release-key', release.pinnedReleaseKey)
  requireMeta(metas, 'peerit-release-sequence', String(release.releaseSequence))

  if (release.relayBackend) requireMeta(metas, 'peerit-relay-backend', release.relayBackend)
  else forbidMeta(metas, 'peerit-relay-backend')
  if (release.dhtRelay) requireMeta(metas, 'peerit-dht-relay', release.dhtRelay)
  else forbidMeta(metas, 'peerit-dht-relay')
  if (release.shardRoster) requireMeta(metas, 'peerit-shard-roster', release.shardRoster)
  else forbidMeta(metas, 'peerit-shard-roster')

  const seeds = expectedSeedOutboxes(release.seedOutboxes)
  if (seeds) requireMeta(metas, 'peerit-seed-outboxes', seeds)
  else forbidMeta(metas, 'peerit-seed-outboxes')

  for (const name of metas.keys()) {
    if (name.startsWith('peerit-shard-') && name !== 'peerit-shard-roster') {
      throw new Error(`index.html contains unsupported production shard meta (${name})`)
    }
  }
}

export function verifyManifestConfig (manifest, release, rosterHash, shardRosterHash, driveKey) {
  if (manifest.releaseSequence !== release.releaseSequence) {
    throw new Error('asset-manifest.json releaseSequence does not match deploy/web-release.json')
  }
  if (!HEX64.test(String(manifest.driveKey || ''))) throw new Error('asset-manifest.json has an invalid driveKey')
  if (manifest.driveKey !== driveKey) throw new Error('asset-manifest.json driveKey does not match manifest.json')
  if (!manifest.webRelease || typeof manifest.webRelease !== 'object' || Array.isArray(manifest.webRelease)) {
    throw new Error('asset-manifest.json webRelease is missing')
  }
  const expected = {
    releaseSequence: release.releaseSequence,
    relay: release.relay,
    relayBackend: release.relayBackend,
    readonly: release.readonly,
    relayRoster: [release.relayRoster, ...release.relayRosterMirrors].join(','),
    relayRosterKey: release.pinnedRosterKey,
    relayRosterSha256: rosterHash,
    shardRoster: release.shardRoster,
    shardRosterSha256: shardRosterHash,
    releaseKey: release.pinnedReleaseKey
  }
  for (const [field, value] of Object.entries(expected)) {
    if (manifest.webRelease[field] !== value) {
      throw new Error(`asset-manifest.json webRelease.${field} does not match deploy/web-release.json`)
    }
  }
  if (manifest.files['relay-roster.json'] !== rosterHash) {
    throw new Error('asset-manifest.json does not pin the configured relay roster bytes')
  }
  if (release.shardRoster && manifest.files[release.shardRoster] !== shardRosterHash) {
    throw new Error('asset-manifest.json does not pin the configured shard roster bytes')
  }
}

function cacheBustedUrl (baseUrl, file, nonce) {
  const url = new URL(file, baseUrl)
  if (url.origin !== baseUrl.origin) throw new Error(`refusing a cross-origin manifest path: ${file}`)
  url.searchParams.set('__peerit_verify', nonce)
  return url
}

async function fetchBytes (baseUrl, file, nonce, maxBytes = MAX_ASSET_BYTES) {
  const url = cacheBustedUrl(baseUrl, file, nonce)
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS)
  let response
  try {
    response = await fetch(url, {
      cache: 'no-store',
      redirect: 'follow',
      headers: {
        'cache-control': 'no-cache, no-store, max-age=0',
        pragma: 'no-cache'
      },
      signal: controller.signal
    })
  } catch (err) {
    clearTimeout(timer)
    const reason = err && err.name === 'AbortError' ? `timed out after ${FETCH_TIMEOUT_MS}ms` : (err.message || 'network error')
    throw new Error(`fetch ${file} failed (${reason})`)
  }
  if (response.status !== 200) {
    clearTimeout(timer)
    throw new Error(`fetch ${file} returned HTTP ${response.status}`)
  }
  if (new URL(response.url).origin !== baseUrl.origin) {
    clearTimeout(timer)
    throw new Error(`fetch ${file} redirected to a different origin`)
  }
  const declared = Number(response.headers.get('content-length') || 0)
  if (declared > maxBytes) {
    clearTimeout(timer)
    throw new Error(`${file} exceeds the ${maxBytes}-byte safety limit`)
  }
  let bytes
  try {
    bytes = Buffer.from(await response.arrayBuffer())
  } catch (err) {
    const reason = err && err.name === 'AbortError' ? `timed out after ${FETCH_TIMEOUT_MS}ms` : (err.message || 'response error')
    throw new Error(`fetch ${file} failed while reading the body (${reason})`)
  } finally {
    clearTimeout(timer)
  }
  if (bytes.length > maxBytes) throw new Error(`${file} exceeds the ${maxBytes}-byte safety limit`)
  return bytes
}

async function mapLimit (items, limit, task) {
  let cursor = 0
  const results = new Array(items.length)
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (true) {
      const index = cursor++
      if (index >= items.length) return
      results[index] = await task(items[index], index)
    }
  })
  await Promise.all(workers)
  return results
}

async function readLocalAssets (entries) {
  const assets = new Map()
  for (const [file, expectedHash] of entries) {
    const path = join(WEB, ...file.split('/'))
    let info
    try {
      info = await lstat(path)
    } catch (err) {
      throw new Error(`local web/${file} is missing (${err.code || err.message})`)
    }
    if (!info.isFile() || info.isSymbolicLink()) throw new Error(`local web/${file} must be a regular file, not a symlink`)
    if (info.size > MAX_ASSET_BYTES) throw new Error(`local web/${file} exceeds the ${MAX_ASSET_BYTES}-byte safety limit`)
    const bytes = await readFile(path)
    if (sha256(bytes) !== expectedHash) throw new Error(`local web/${file} does not match asset-manifest.json`)
    assets.set(file, bytes)
  }
  return assets
}

async function verifyRemoteAssets (baseUrl, entries, localAssets, nonce) {
  await mapLimit(entries, FETCH_CONCURRENCY, async ([file, expectedHash]) => {
    const remote = await fetchBytes(baseUrl, file, nonce)
    if (sha256(remote) !== expectedHash) throw new Error(`deployed ${file} SHA-256 does not match asset-manifest.json`)
    if (!remote.equals(localAssets.get(file))) throw new Error(`deployed ${file} bytes differ from local web/${file}`)
  })
}

async function main () {
  const { baseUrl } = parseArgs(process.argv.slice(2))
  const nonce = `${Date.now().toString(36)}-${process.pid.toString(36)}`
  console.log(`[deploy-verify] checking ${baseUrl.href}`)

  const configBytes = await readRequired(join(ROOT, 'deploy', 'web-release.json'), 'deploy/web-release.json')
  const release = releaseConfig(parseJson(configBytes, 'deploy/web-release.json'))

  const rootManifest = parseJson(await readRequired(join(ROOT, 'manifest.json'), 'manifest.json'), 'manifest.json')
  const driveKey = String(rootManifest.driveKey || '').toLowerCase()
  if (!HEX64.test(driveKey)) throw new Error('manifest.json has an invalid driveKey')
  const hyperUrl = `hyper://${driveKey}/`
  if (rootManifest.url !== hyperUrl || rootManifest.homepage !== hyperUrl) {
    throw new Error('manifest.json url/homepage do not match its driveKey')
  }

  const rosterBytes = await readRequired(repoPath(release.relayRoster, 'relayRoster'), release.relayRoster)
  const rosterHash = sha256(rosterBytes)
  const roster = parseJson(rosterBytes, release.relayRoster)
  const verifiedRoster = await verifyRelayRoster(roster, { expectedKey: release.pinnedRosterKey })
  if (!equalJson(verifiedRoster.payload, release.roster)) {
    throw new Error('signed relay roster payload does not match deploy/web-release.json')
  }
  if (release.readonly === 'false' && verifiedRoster.relays.length < 2 && !verifiedRoster.payload.networkQuorum) {
    throw new Error('writable public web releases require at least two signed roster relays or a signed network-quorum policy')
  }

  let shardRosterBytes = null
  let shardRosterHash = ''
  if (release.shardRoster) {
    shardRosterBytes = await readRequired(repoPath(release.shardRoster, 'shardRoster'), release.shardRoster)
    shardRosterHash = sha256(shardRosterBytes)
  }

  const localManifestBytes = await readRequired(join(WEB, 'asset-manifest.json'), 'web/asset-manifest.json')
  const localSignatureBytes = await readRequired(join(WEB, 'asset-manifest.sig'), 'web/asset-manifest.sig')
  if (localManifestBytes.length > MAX_METADATA_BYTES || localSignatureBytes.length > MAX_METADATA_BYTES) {
    throw new Error('local release metadata exceeds the safety limit')
  }
  const manifest = parseJson(localManifestBytes, 'web/asset-manifest.json')
  const signature = parseJson(localSignatureBytes, 'web/asset-manifest.sig')
  const entries = manifestEntries(manifest)

  verifyManifestConfig(manifest, release, rosterHash, shardRosterHash, driveKey)
  await verifyReleaseManifest({
    manifest,
    signature,
    expectedKey: release.pinnedReleaseKey,
    expectedSequence: release.releaseSequence
  })
  if (signature.msgVersion !== RELEASE_MSG_VERSION) throw new Error(`release signature must use ${RELEASE_MSG_VERSION}`)

  const localAssets = await readLocalAssets(entries)
  const localIndex = localAssets.get('index.html')
  if (!localIndex) throw new Error('asset-manifest.json must include index.html')
  verifyIndexConfig(localIndex.toString('utf8'), release)
  if (!localAssets.get('verify.html').toString('utf8').includes(driveKey)) {
    throw new Error('verify.html does not carry the release driveKey')
  }
  if (!localAssets.get('verify.html').toString('utf8').includes(release.pinnedReleaseKey)) {
    throw new Error('verify.html does not carry the pinned release key')
  }
  if (!localAssets.get('sw.js').toString('utf8').includes(`"relay-roster.json":"${rosterHash}"`)) {
    throw new Error('sw.js does not pin the configured relay roster')
  }
  if (release.shardRoster && !localAssets.get('sw.js').toString('utf8').includes(`"${release.shardRoster}":"${shardRosterHash}"`)) {
    throw new Error('sw.js does not pin the configured shard roster')
  }

  const [remoteManifestBytes, remoteSignatureBytes] = await Promise.all([
    fetchBytes(baseUrl, 'asset-manifest.json', nonce, MAX_METADATA_BYTES),
    fetchBytes(baseUrl, 'asset-manifest.sig', nonce, MAX_METADATA_BYTES)
  ])
  if (!remoteManifestBytes.equals(localManifestBytes)) {
    throw new Error('deployed asset-manifest.json bytes differ from local web/asset-manifest.json')
  }
  if (!remoteSignatureBytes.equals(localSignatureBytes)) {
    throw new Error('deployed asset-manifest.sig bytes differ from local web/asset-manifest.sig')
  }

  await verifyRemoteAssets(baseUrl, entries, localAssets, nonce)
  const deployedRoster = localAssets.get('relay-roster.json')
  if (!deployedRoster || !deployedRoster.equals(rosterBytes)) {
    throw new Error('deployed relay-roster.json differs from the configured signed roster')
  }
  if (release.shardRoster) {
    const deployedShardRoster = localAssets.get(release.shardRoster)
    if (!deployedShardRoster || !deployedShardRoster.equals(shardRosterBytes)) {
      throw new Error(`deployed ${release.shardRoster} differs from the configured shard roster`)
    }
  }

  console.log(`[deploy-verify] PASS ${RELEASE_MSG_VERSION}: sequence ${release.releaseSequence}; readonly=${release.readonly}; ${manifest.files && Object.keys(manifest.files).length} files + ${manifest.controls && Object.keys(manifest.controls).length} controls; drive ${driveKey.slice(0, 12)}…; key ${release.pinnedReleaseKey.slice(0, 12)}…`)
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  main().catch((err) => {
    console.error(`[deploy-verify] FAIL ${err.message}`)
    process.exitCode = 1
  })
}
