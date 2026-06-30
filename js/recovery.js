// recovery.js — app recovery bundle helpers.
// The PearBrowser mnemonic never enters this app. These helpers only handle
// per-app public identity fingerprints plus outbox invite keys for discovery.

export const APP_NAME = 'peerit'
export const RECOVERY_VERSION = 1

export const COPY = Object.freeze({
  identityBackup: 'Your identity lives in PearBrowser. Back up your 12-word PearBrowser recovery phrase. peerit/p2pbuilders only see an app-specific public key and cannot recover this phrase for you.',
  groupKey: 'Your Group key helps your app data stay discoverable. It is not your identity phrase and does not let anyone sign as you, but it can let another device or seeder replicate your public outbox.',
  differentIdentity: 'This recovery bundle belongs to a different app identity. You can view or seed the old public data, but you cannot edit, moderate, vote, or post as that old identity unless you restore the matching PearBrowser phrase.',
  backupSummary: "Back up PearBrowser to keep your identity. Back up this app's recovery bundle to keep your posts discoverable on a new device."
})

const HEX64 = /^[0-9a-f]{64}$/i
const MAX_OUTBOXES = 256

export function isHex64 (s) {
  return typeof s === 'string' && HEX64.test(s)
}

function parseBundle (input) {
  if (typeof input === 'string') {
    const trimmed = input.trim()
    if (!trimmed) throw new Error('Paste a recovery bundle JSON first.')
    try { return JSON.parse(trimmed) } catch { throw new Error('Recovery bundle is not valid JSON.') }
  }
  return input
}

function normalizeOutbox (outbox, index) {
  if (!outbox || typeof outbox !== 'object') throw new Error(`Recovery bundle outbox ${index + 1} is invalid.`)
  const appId = String(outbox.appId || '').trim()
  const inviteKey = String(outbox.inviteKey || '').trim()
  if (!isHex64(appId)) throw new Error(`Recovery bundle outbox ${index + 1} has an invalid appId.`)
  if (!isHex64(inviteKey)) throw new Error(`Recovery bundle outbox ${index + 1} has an invalid inviteKey.`)
  return { appId: appId.toLowerCase(), inviteKey: inviteKey.toLowerCase() }
}

export function normalizeRecoveryBundle (input) {
  const bundle = parseBundle(input)
  if (!bundle || typeof bundle !== 'object' || Array.isArray(bundle)) throw new Error('Recovery bundle must be a JSON object.')
  if (bundle.version !== RECOVERY_VERSION) throw new Error('Recovery bundle version is not supported.')
  if (bundle.app !== APP_NAME) throw new Error(`Recovery bundle is for ${bundle.app || 'another app'}, not ${APP_NAME}.`)
  if (!isHex64(bundle.driveKey)) throw new Error('Recovery bundle driveKey must be a 64 hex string.')
  if (!isHex64(bundle.publicKey)) throw new Error('Recovery bundle publicKey must be a 64 hex string.')
  if (!Array.isArray(bundle.outboxes)) throw new Error('Recovery bundle outboxes must be an array.')
  if (bundle.outboxes.length > MAX_OUTBOXES) throw new Error('Recovery bundle contains too many outboxes.')

  const seen = new Set()
  const outboxes = []
  for (let i = 0; i < bundle.outboxes.length; i++) {
    const outbox = normalizeOutbox(bundle.outboxes[i], i)
    const key = outbox.appId + ':' + outbox.inviteKey
    if (!seen.has(key)) {
      seen.add(key)
      outboxes.push(outbox)
    }
  }

  const createdAt = typeof bundle.createdAt === 'string' && !Number.isNaN(Date.parse(bundle.createdAt))
    ? new Date(bundle.createdAt).toISOString()
    : new Date().toISOString()

  return {
    version: RECOVERY_VERSION,
    app: APP_NAME,
    driveKey: bundle.driveKey.toLowerCase(),
    publicKey: bundle.publicKey.toLowerCase(),
    outboxes,
    createdAt
  }
}

export function cleanOutboxes (outboxes = [], fallback) {
  const list = Array.isArray(outboxes) ? outboxes.slice() : []
  if (fallback) list.unshift(fallback)
  const seen = new Set()
  const clean = []
  for (let i = 0; i < list.length; i++) {
    let outbox
    try { outbox = normalizeOutbox(list[i], i) } catch { continue }
    const key = outbox.appId + ':' + outbox.inviteKey
    if (seen.has(key)) continue
    seen.add(key)
    clean.push(outbox)
  }
  return clean
}

export function buildRecoveryBundle ({ driveKey, publicKey, outboxes = [], createdAt = new Date().toISOString() }) {
  return normalizeRecoveryBundle({
    version: RECOVERY_VERSION,
    app: APP_NAME,
    driveKey,
    publicKey,
    outboxes,
    createdAt
  })
}

export function recoveryBundleJson (bundle) {
  return JSON.stringify(normalizeRecoveryBundle(bundle), null, 2) + '\n'
}

export function recoveryBundleFilename (bundle) {
  const b = normalizeRecoveryBundle(bundle)
  const pub = b.publicKey.slice(0, 12) || 'unknown'
  const date = b.createdAt.slice(0, 10)
  return `${APP_NAME}-app-data-recovery-${pub}-${date}.json`
}

export function shellArg (value) {
  const s = String(value == null ? '' : value)
  if (/^[A-Za-z0-9._/:=-]+$/.test(s)) return s
  return "'" + s.replace(/'/g, "'\"'\"'") + "'"
}

export function peeritSeederCommand (outboxes = [], opts = {}) {
  const keys = cleanOutboxes(outboxes).map(o => shellArg(o.inviteKey))
  if (!keys.length) return ''
  return `cd ${shellArg(opts.dir || '../peerit-seeder')}\nnode seeder.mjs ${keys.join(' ')}`
}

export function compareRecoveryBundle (bundle, { driveKey, publicKey }) {
  const b = normalizeRecoveryBundle(bundle)
  const currentDriveKey = String(driveKey || '').toLowerCase()
  const currentPublicKey = String(publicKey || '').toLowerCase()
  const driveKeyMatches = b.driveKey === currentDriveKey
  const publicKeyMatches = b.publicKey === currentPublicKey
  return {
    bundle: b,
    driveKeyMatches,
    publicKeyMatches,
    ok: driveKeyMatches && publicKeyMatches
  }
}

export function assertRecoveryBundleMatches (bundle, current) {
  const result = compareRecoveryBundle(bundle, current)
  if (!result.publicKeyMatches) {
    const driveWarning = result.driveKeyMatches ? '' : 'This recovery bundle was created for a different app drive key. Open the same production app drive key before importing it.\n\n'
    throw new Error(driveWarning + COPY.differentIdentity)
  }
  if (!result.driveKeyMatches) {
    throw new Error('This recovery bundle was created for a different app drive key. Open the same production app drive key before importing it.')
  }
  return result.bundle
}
