#!/usr/bin/env node

// Exact conductor for the owner-approved r/ai_local launch slice. Preflight and
// bootstrap-only modes are local zero-network operations. Only --live imports
// current relay state through the explicit, branded qualification seam.

import fs from 'node:fs/promises'
import path from 'node:path'
import { pathToFileURL } from 'node:url'
import { createPrivateKey, createPublicKey, randomBytes } from 'node:crypto'

import { ready as cryptoReady } from '../js/crypto.js'
import { DevIdentity } from '../js/identity.js'
import {
  composeThreePostPlanV1,
  createSignedThreePostBootstrapV1,
  createThreePostVaultBridgeV1,
  publishThreePostPlanV1,
  recoverThreePostPlanV1,
  sanitizedThreePostPreflightV1,
  selectThreePostWaveZeroV1,
  sha256Hex,
  validateCurrentRelayTupleV1
} from './lib/three-post-launch.mjs'
import { createPeeritSeedPublisherVaultV1 } from './lib/seed-publisher-vault.mjs'

function usage (code = 0, message = '') {
  if (message) console.error(`error: ${message}`)
  console.error(`usage: node scripts/peerit-three-post-launch.mjs --preflight \\
  --manifest <FINAL-SEED-MANIFEST.json> \\
  --personas <private-persona-store.json> \\
  --relay-tuple <current-qualified-relay-tuple.json> [--at <unix-ms>]

usage: PEERIT_SEED_VAULT_PASSPHRASE_FD=3 PEERIT_BOOTSTRAP_AUTHORITY_SEED_FD=4 \\
  node scripts/peerit-three-post-launch.mjs --live \\
  --manifest <FINAL-SEED-MANIFEST.json> --personas <private-persona-store.json> \\
  --relay-tuple <current-qualified-relay-tuple.json> --vault <publisher-state.enc> \\
  --receipts <sanitized-receipts.json> --bootstrap <signed-bootstrap.json> \\
  --release-sequence <n> --issued-at <unix-ms> --expires-at <unix-ms>

usage: PEERIT_SEED_VAULT_PASSPHRASE_FD=3 PEERIT_BOOTSTRAP_AUTHORITY_SEED_FD=4 \\
  node scripts/peerit-three-post-launch.mjs --bootstrap-only \\
  --manifest <FINAL-SEED-MANIFEST.json> \\
  --relay-tuple <current-qualified-relay-tuple.json> --vault <publisher-state.enc> \\
  --receipts <sanitized-receipts.json> --bootstrap <signed-bootstrap.json> \\
  --release-sequence <n> --issued-at <unix-ms> --expires-at <unix-ms>

Preflight is local-only and makes zero network calls. Live first re-probes and
qualifies exactly the two immutable relay tuple rows, injects only branded split
adapters, and writes sanitized receipts plus the canonical signed bootstrap.
Bootstrap-only signs a sequence-zero discovery source for another release from
the already-complete vault. It performs no relay I/O and cannot issue a PUT.
Persona and authority seeds are process-local and are never printed.`)
  process.exit(code)
}

function parseArgs (argv) {
  const options = {
    mode: 'preflight',
    manifest: null,
    personas: null,
    relayTuple: null,
    at: Date.now(),
    vault: null,
    receipts: null,
    bootstrap: null,
    releaseSequence: null,
    issuedAt: null,
    expiresAt: null
  }
  let selectedMode = null
  for (let index = 0; index < argv.length; index++) {
    const argument = argv[index]
    let mode = null
    if (argument === '--preflight' || argument === '--dry-run') mode = 'preflight'
    else if (argument === '--live') mode = 'live'
    else if (argument === '--bootstrap-only') mode = 'bootstrap-only'
    if (mode) {
      if (selectedMode && selectedMode !== mode) usage(2, 'exactly one execution mode may be selected')
      selectedMode = mode
      options.mode = mode
      continue
    }
    if (argument === '--manifest') options.manifest = argv[++index]
    else if (argument === '--personas') options.personas = argv[++index]
    else if (argument === '--relay-tuple') options.relayTuple = argv[++index]
    else if (argument === '--at') options.at = Number(argv[++index])
    else if (argument === '--vault') options.vault = argv[++index]
    else if (argument === '--receipts') options.receipts = argv[++index]
    else if (argument === '--bootstrap') options.bootstrap = argv[++index]
    else if (argument === '--release-sequence') options.releaseSequence = Number(argv[++index])
    else if (argument === '--issued-at') options.issuedAt = Number(argv[++index])
    else if (argument === '--expires-at') options.expiresAt = Number(argv[++index])
    else if (argument === '-h' || argument === '--help') usage(0)
    else usage(2, `unknown option ${argument}`)
  }
  if (!options.manifest || !options.relayTuple) {
    usage(2, '--manifest and --relay-tuple are required')
  }
  if (options.mode !== 'bootstrap-only' && !options.personas) {
    usage(2, '--personas is required with --preflight and --live')
  }
  if (!Number.isSafeInteger(options.at) || options.at < 0) usage(2, '--at must be a non-negative safe integer')
  if (options.mode === 'live' || options.mode === 'bootstrap-only') {
    for (const field of ['vault', 'receipts', 'bootstrap']) {
      if (!options[field]) usage(2, `--${field} is required with --${options.mode}`)
    }
    for (const field of ['releaseSequence', 'issuedAt', 'expiresAt']) {
      if (!Number.isSafeInteger(options[field]) || options[field] < 0) {
        usage(2, `--${field.replace(/[A-Z]/g, value => '-' + value.toLowerCase())} must be a non-negative safe integer`)
      }
    }
    if (options.releaseSequence < 13 || options.expiresAt <= options.issuedAt) {
      usage(2, 'release sequence/validity window is invalid')
    }
  }
  return options
}

function memoryStorage () {
  const values = new Map()
  return {
    getItem: key => values.has(key) ? values.get(key) : null,
    setItem: (key, value) => values.set(key, String(value)),
    removeItem: key => values.delete(key),
    clear: () => values.clear()
  }
}

function identityRestorer (personas) {
  const identities = new Map()
  return async persona => {
    if (identities.has(persona)) return identities.get(persona)
    const entry = personas.personas && personas.personas[persona]
    if (!entry || typeof entry.seedHex !== 'string' || typeof entry.pubkeyHex !== 'string') {
      throw Object.assign(new Error(`persona ${persona} has no process-local signing material`), {
        code: 'PEERIT_THREE_POST_PERSONA_MISSING'
      })
    }
    const identity = new DevIdentity(memoryStorage(), memoryStorage(), {})
    await identity.replaceWith({
      seed: entry.seedHex,
      pubkey: entry.pubkeyHex,
      driveKey: entry.pubkeyHex,
      label: entry.handleHint || persona
    }, 'three-post-local-preflight')
    if (identity.me().pubkey !== entry.pubkeyHex) {
      throw Object.assign(new Error(`persona ${persona} seed/public-key mismatch`), {
        code: 'PEERIT_THREE_POST_PERSONA_MISMATCH'
      })
    }
    identities.set(persona, identity)
    return identity
  }
}

async function readJson (filePath) {
  const bytes = await fs.readFile(path.resolve(filePath))
  return { bytes, value: JSON.parse(bytes.toString('utf8')) }
}

async function readSecretFd (environmentName, format) {
  const value = process.env[environmentName]
  if (!/^[0-9]+$/.test(String(value || ''))) {
    throw Object.assign(new Error(`${environmentName} must name an inherited read-only file descriptor`), {
      code: 'PEERIT_THREE_POST_SECRET_FD_REQUIRED'
    })
  }
  const secret = (await fs.readFile(`/dev/fd/${Number(value)}`, 'utf8')).trim()
  if (format === 'seed') {
    if (!/^[0-9a-f]{64}$/.test(secret)) {
      throw Object.assign(new Error('bootstrap authority seed FD does not contain 32-byte lowercase hex'), {
        code: 'PEERIT_THREE_POST_BOOTSTRAP_SEED_INVALID'
      })
    }
    return secret
  }
  const bytes = new TextEncoder().encode(secret)
  if (bytes.byteLength < 16 || bytes.byteLength > 1024) {
    bytes.fill(0)
    throw Object.assign(new Error('vault passphrase FD must contain 16..1024 bytes'), {
      code: 'PEERIT_THREE_POST_VAULT_PASSPHRASE_INVALID'
    })
  }
  return bytes
}

function publicKeyForSeed (seedHex) {
  const privateKey = createPrivateKey({
    key: Buffer.from(`302e020100300506032b657004220420${seedHex}`, 'hex'),
    format: 'der',
    type: 'pkcs8'
  })
  const spki = createPublicKey(privateKey).export({ type: 'spki', format: 'der' })
  return Buffer.from(spki).subarray(-32).toString('hex')
}

async function writeAtomic (filePath, bytes, mode = 0o600) {
  const target = path.resolve(filePath)
  await fs.mkdir(path.dirname(target), { recursive: true, mode: 0o700 })
  const temporary = `${target}.tmp-${process.pid}-${randomBytes(8).toString('hex')}`
  const handle = await fs.open(temporary, 'wx', mode)
  try {
    await handle.writeFile(bytes)
    await handle.sync()
  } finally { await handle.close() }
  await fs.rename(temporary, target)
  await fs.chmod(target, mode)
}

export async function runThreePostPreflightCliV1 (argv) {
  const options = parseArgs(argv)
  const manifest = await readJson(options.manifest)
  const personas = await readJson(options.personas)
  const relayTuple = validateCurrentRelayTupleV1((await readJson(options.relayTuple)).value)
  await cryptoReady()
  const selection = await selectThreePostWaveZeroV1({
    manifest: manifest.value,
    manifestSha256: sha256Hex(manifest.bytes),
    personas: personas.value
  })
  const plan = await composeThreePostPlanV1({
    selection,
    personas: personas.value,
    identityFor: identityRestorer(personas.value),
    now: options.at
  })
  return sanitizedThreePostPreflightV1({ plan, relayTuple })
}

export async function runThreePostLiveCliV1 (argv) {
  const options = parseArgs(argv)
  if (options.mode !== 'live') throw new Error('live runner requires --live')
  const manifest = await readJson(options.manifest)
  const personas = await readJson(options.personas)
  const relayTuple = validateCurrentRelayTupleV1((await readJson(options.relayTuple)).value)
  const manifestSha256 = sha256Hex(manifest.bytes)
  await cryptoReady()
  const selection = await selectThreePostWaveZeroV1({
    manifest: manifest.value,
    manifestSha256,
    personas: personas.value
  })
  const publishNotBefore = Date.parse(personas.value.publishNotBefore)
  if (!Number.isFinite(publishNotBefore) || Date.now() < publishNotBefore) {
    throw Object.assign(new Error('persona key-aging gate is absent or still in force; no network call made'), {
      code: 'PEERIT_THREE_POST_KEY_AGING_GATE'
    })
  }
  const passphrase = await readSecretFd('PEERIT_SEED_VAULT_PASSPHRASE_FD', 'passphrase')
  const authoritySeedHex = await readSecretFd('PEERIT_BOOTSTRAP_AUTHORITY_SEED_FD', 'seed')
  const vault = createPeeritSeedPublisherVaultV1({ filePath: options.vault, passphrase })
  try {
    const existing = await vault.sanitizedReceiptManifest()
    const plan = existing.records.length
      ? await recoverThreePostPlanV1(vault, { expectedManifestSha256: manifestSha256 })
      : await composeThreePostPlanV1({
          selection,
          personas: personas.value,
          identityFor: identityRestorer(personas.value),
          now: options.at
        })
    // The bridge is created before qualification so the raw Cell adapter cannot
    // exist without its exact encrypted pre-send callbacks.
    const bridge = createThreePostVaultBridgeV1({ vault, relayTuple })
    const { qualifyThreePostLiveRelaysV1 } = await import('./lib/three-post-live-qualification.mjs')
    const qualified = await qualifyThreePostLiveRelaysV1({ relayTuple, bridge })
    const published = await publishThreePostPlanV1({
      vault,
      plan,
      relays: qualified.relays,
      relayTuple: qualified.relayTuple
    })
    const authorityPublicKey = publicKeyForSeed(authoritySeedHex)
    const signed = await createSignedThreePostBootstrapV1({
      vault,
      plan,
      relayTuple: qualified.relayTuple,
      authoritySeedHex,
      authorityPublicKey,
      releaseSequence: options.releaseSequence,
      issuedAt: options.issuedAt,
      expiresAt: options.expiresAt
    })
    const receiptsBytes = Buffer.from(`${JSON.stringify(published.receipts, null, 2)}\n`)
    await writeAtomic(options.receipts, receiptsBytes)
    await writeAtomic(options.bootstrap, signed.artifactBytes)
    return Object.freeze({
      schema: 'peerit-three-post-live-result-v1',
      ok: true,
      recordCount: published.recordCount,
      expectedCids: [...published.expectedCids],
      physicalPutsThisRun: published.networkPuts,
      recoveryGetsThisRun: published.recoveryGets,
      receiptManifestSha256: sha256Hex(receiptsBytes),
      bootstrapSha256: signed.artifactHash,
      relayTupleSha256: signed.relayTupleSha256,
      bootstrapAuthorityPublicKey: authorityPublicKey,
      releaseSequence: options.releaseSequence
    })
  } finally {
    vault.close()
    passphrase.fill(0)
  }
}

function receiptPutCount (receipt) {
  return receipt.records.reduce((total, record) => total +
    record.replicas.reduce((subtotal, replica) => subtotal + replica.putAttempts, 0), 0)
}

export async function runThreePostBootstrapOnlyCliV1 (argv, optionsOverride = {}) {
  const options = parseArgs(argv)
  if (options.mode !== 'bootstrap-only') throw new Error('bootstrap-only runner requires --bootstrap-only')
  const manifest = await readJson(options.manifest)
  const relayTuple = validateCurrentRelayTupleV1((await readJson(options.relayTuple)).value)
  const passphrase = await readSecretFd('PEERIT_SEED_VAULT_PASSPHRASE_FD', 'passphrase')
  const authoritySeedHex = await readSecretFd('PEERIT_BOOTSTRAP_AUTHORITY_SEED_FD', 'seed')
  const vault = createPeeritSeedPublisherVaultV1({ filePath: options.vault, passphrase })
  try {
    await cryptoReady()
    const before = await vault.sanitizedReceiptManifest()
    const plan = await recoverThreePostPlanV1(vault, {
      expectedManifestSha256: sha256Hex(manifest.bytes),
      expectedCids: optionsOverride.expectedCids
    })
    await vault.assertComplete(plan.records.map(record => record.recordId))
    const authorityPublicKey = publicKeyForSeed(authoritySeedHex)
    const signed = await createSignedThreePostBootstrapV1({
      vault,
      plan,
      relayTuple,
      authoritySeedHex,
      authorityPublicKey,
      releaseSequence: options.releaseSequence,
      issuedAt: options.issuedAt,
      expiresAt: options.expiresAt,
      // releaseSequence is part of sourceId. A rollback release is therefore
      // a distinct discovery source and starts at bootstrap sequence zero.
      bootstrapSequence: 0,
      previousBootstrapHash: null
    })
    const after = await vault.sanitizedReceiptManifest()
    if (JSON.stringify(before) !== JSON.stringify(after) || receiptPutCount(before) !== receiptPutCount(after)) {
      throw Object.assign(new Error('bootstrap-only operation changed durable publisher state'), {
        code: 'PEERIT_THREE_POST_BOOTSTRAP_ONLY_MUTATION'
      })
    }
    const receiptsBytes = Buffer.from(`${JSON.stringify(after, null, 2)}\n`)
    await writeAtomic(options.receipts, receiptsBytes)
    await writeAtomic(options.bootstrap, signed.artifactBytes)
    return Object.freeze({
      schema: 'peerit-three-post-bootstrap-only-result-v1',
      ok: true,
      recordCount: plan.records.length,
      expectedCids: [...plan.expectedCids],
      networkGets: 0,
      physicalPutsThisRun: 0,
      receiptManifestSha256: sha256Hex(receiptsBytes),
      bootstrapSha256: signed.artifactHash,
      relayTupleSha256: signed.relayTupleSha256,
      bootstrapAuthorityPublicKey: authorityPublicKey,
      releaseSequence: options.releaseSequence,
      bootstrapSequence: 0,
      previousBootstrapHash: null
    })
  } finally {
    vault.close()
    passphrase.fill(0)
  }
}

const direct = process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href
if (direct) {
  const argv = process.argv.slice(2)
  const runner = argv.includes('--live')
    ? runThreePostLiveCliV1
    : argv.includes('--bootstrap-only')
      ? runThreePostBootstrapOnlyCliV1
      : runThreePostPreflightCliV1
  runner(argv).then(
    report => console.log(JSON.stringify(report, null, 2)),
    error => {
      console.error(`${String(error && error.code ? error.code : 'PEERIT_THREE_POST_PREFLIGHT_FAILED')}: ${String(error && error.message ? error.message : error)}`)
      process.exitCode = 1
    }
  )
}
