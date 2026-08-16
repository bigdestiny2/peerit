#!/usr/bin/env node

// Zero-network, release-terminal seed-bootstrap reissuer. This command changes
// only the release/time binding of the exact signed Sequence-28 39-record seed
// payload, signs it with the existing bootstrap authority, then verifies the
// resulting Sequence-29 artifact before any output is written.

import { createHash } from 'node:crypto'
import {
  chmodSync,
  linkSync,
  mkdirSync,
  readFileSync,
  unlinkSync,
  writeFileSync
} from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import {
  createPeeritSeedBootstrapV1,
  encodePeeritSeedBootstrapV1,
  verifyPeeritSeedBootstrapV1
} from '../js/substrate/seed-bootstrap-v1.mjs'

export const PEERIT_SEED_BOOTSTRAP_REISSUE_SOURCE_SEQUENCE_V1 = 28
export const PEERIT_SEED_BOOTSTRAP_REISSUE_TARGET_SEQUENCE_V1 = 29
export const PEERIT_SEED_BOOTSTRAP_REISSUE_RECORD_COUNT_V1 = 39
export const PEERIT_SEED_BOOTSTRAP_REISSUE_ACCEPTED_SOURCE_SHA256_V1 =
  'f25f2eb3ac285294d823d7e58019b79906f5ea5ebbd7ff59dbf7fcf74751c556'
export const PEERIT_SEED_BOOTSTRAP_SIGNING_SEED_ENV_V1 =
  'PEERIT_BOOTSTRAP_AUTHORITY_SEED'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const HEX_32 = /^[0-9a-f]{64}$/
const MUTABLE_PAYLOAD_FIELDS = new Set(['releaseSequence', 'issuedAt', 'expiresAt'])

function fail (message, code = 'PEERIT_SEED_BOOTSTRAP_REISSUE_FAILED') {
  const error = new Error(message)
  error.code = code
  throw error
}

function sha256 (bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

function exactBytes (value, field) {
  if (!(value instanceof Uint8Array)) fail(`${field} must be bytes`)
  return Buffer.from(value)
}

function exactTime (value, field) {
  const number = typeof value === 'number' ? value : Number(value)
  if (!Number.isSafeInteger(number) || number < 0 || String(number) !== String(value)) {
    fail(`${field} must be a canonical nonnegative safe-integer millisecond value`)
  }
  return number
}

function signingSeed (options) {
  if (options.fixtureOnly === true) {
    if (options.testOnly !== true) {
      fail('fixture source flexibility requires the explicit test-only boundary',
        'PEERIT_SEED_BOOTSTRAP_REISSUE_FIXTURE_BOUNDARY')
    }
    const fixture = String(options.seedHex || '').trim().toLowerCase()
    if (!HEX_32.test(fixture)) fail('fixture seed must be exact 32-byte hexadecimal')
    return fixture
  }
  if (options.seedHex != null) {
    fail('direct signing seeds are fixture-only; release signing requires the scoped environment variable',
      'PEERIT_SEED_BOOTSTRAP_REISSUE_SECRET_CHANNEL')
  }
  const seed = String(
    (options.environment || process.env)[PEERIT_SEED_BOOTSTRAP_SIGNING_SEED_ENV_V1] || ''
  ).trim().toLowerCase()
  if (!HEX_32.test(seed)) {
    fail(`${PEERIT_SEED_BOOTSTRAP_SIGNING_SEED_ENV_V1} is required as exact 32-byte hexadecimal`,
      'PEERIT_SEED_BOOTSTRAP_REISSUE_SIGNER_REQUIRED')
  }
  return seed
}

function unchangedPayloadProjection (payload) {
  return Object.fromEntries(Object.entries(payload)
    .filter(([field]) => !MUTABLE_PAYLOAD_FIELDS.has(field)))
}

function stableJson (value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`
  return `{${Object.keys(value).sort().map(field =>
    `${JSON.stringify(field)}:${stableJson(value[field])}`).join(',')}}`
}

export async function reissuePeeritSeedBootstrapSequence29V1 (options = {}) {
  const sourceBytes = exactBytes(options.sourceBytes, 'Sequence-28 seed bootstrap')
  let source
  try { source = JSON.parse(sourceBytes.toString('utf8')) } catch {
    fail('Sequence-28 seed bootstrap is not JSON')
  }
  let canonicalSource
  try { canonicalSource = Buffer.from(encodePeeritSeedBootstrapV1(sourceBytes)) } catch (cause) {
    fail(`Sequence-28 seed bootstrap is invalid: ${cause.message}`)
  }
  if (!canonicalSource.equals(sourceBytes)) {
    fail('Sequence-28 seed bootstrap bytes are not the exact canonical encoding')
  }
  if (source.payload.releaseSequence !== PEERIT_SEED_BOOTSTRAP_REISSUE_SOURCE_SEQUENCE_V1 ||
      source.payload.bootstrapSequence !== 0 ||
      source.payload.previousBootstrapHash !== null ||
      !Array.isArray(source.payload.records) ||
      source.payload.records.length !== PEERIT_SEED_BOOTSTRAP_REISSUE_RECORD_COUNT_V1) {
    fail('source must be the release-terminal Sequence-28 source-zero 39-record seed bootstrap')
  }

  const sourceHash = sha256(sourceBytes)
  if (sourceHash !== PEERIT_SEED_BOOTSTRAP_REISSUE_ACCEPTED_SOURCE_SHA256_V1 &&
      !(options.fixtureOnly === true && options.testOnly === true)) {
    fail(`source SHA-256 is not the accepted Sequence-28 predecessor: ${sourceHash}`,
      'PEERIT_SEED_BOOTSTRAP_REISSUE_SOURCE_MISMATCH')
  }
  await verifyPeeritSeedBootstrapV1(sourceBytes, {
    authorityPublicKey: source.payload.authorityPublicKey,
    releaseSequence: PEERIT_SEED_BOOTSTRAP_REISSUE_SOURCE_SEQUENCE_V1,
    expectedArtifactHash: sourceHash,
    previousBootstrapHash: null,
    now: source.payload.issuedAt
  })

  const issuedAt = exactTime(options.issuedAt, 'issuedAt')
  const expiresAt = exactTime(options.expiresAt, 'expiresAt')
  const seedHex = signingSeed(options)
  const artifact = await createPeeritSeedBootstrapV1({
    ...source.payload,
    releaseSequence: PEERIT_SEED_BOOTSTRAP_REISSUE_TARGET_SEQUENCE_V1,
    issuedAt,
    expiresAt
  }, { seedHex })
  const bytes = Buffer.from(encodePeeritSeedBootstrapV1(artifact))
  const artifactHash = sha256(bytes)
  const verified = await verifyPeeritSeedBootstrapV1(bytes, {
    authorityPublicKey: source.payload.authorityPublicKey,
    releaseSequence: PEERIT_SEED_BOOTSTRAP_REISSUE_TARGET_SEQUENCE_V1,
    expectedArtifactHash: artifactHash,
    previousBootstrapHash: null,
    now: issuedAt
  })
  if (stableJson(unchangedPayloadProjection(verified.payload)) !==
      stableJson(unchangedPayloadProjection(source.payload))) {
    fail('reissued seed bootstrap changed payload content outside the release/time binding')
  }
  return Object.freeze({
    bytes,
    artifact: verified,
    sourceSha256: sourceHash,
    sha256: artifactHash,
    authorityPublicKey: verified.payload.authorityPublicKey,
    recordCount: verified.payload.records.length,
    releaseSequence: verified.payload.releaseSequence,
    issuedAt: verified.payload.issuedAt,
    expiresAt: verified.payload.expiresAt
  })
}

function arg (name) {
  const index = process.argv.indexOf(name)
  return index >= 0 && process.argv[index + 1] ? process.argv[index + 1] : ''
}

function rejectUnknownArgs () {
  const accepted = new Set(['--source', '--out', '--issued-at', '--expires-at'])
  for (let index = 2; index < process.argv.length; index += 2) {
    const name = process.argv[index]
    if (!accepted.has(name) || !process.argv[index + 1]) {
      fail('usage: reissue-peerit-seed-bootstrap.mjs --issued-at <ms> --expires-at <ms> --out <file> [--source deploy/peerit-seed-bootstrap-v1-seq28.json]',
        'PEERIT_SEED_BOOTSTRAP_REISSUE_USAGE')
    }
  }
}

export function writePeeritSeedBootstrapReissueOutputV1 (path, bytes) {
  path = resolve(path)
  mkdirSync(dirname(path), { recursive: true })
  const temporary = `${path}.tmp-${process.pid}`
  try {
    writeFileSync(temporary, bytes, { flag: 'wx', mode: 0o600 })
    chmodSync(temporary, 0o444)
    // A hard-link publication is both create-only and atomic: it cannot
    // replace an already-materialized signed release artifact.
    linkSync(temporary, path)
  } finally {
    try { unlinkSync(temporary) } catch {}
  }
}

async function main () {
  rejectUnknownArgs()
  const source = resolve(ROOT,
    arg('--source') || 'deploy/peerit-seed-bootstrap-v1-seq28.json')
  const output = arg('--out')
  if (!output || !arg('--issued-at') || !arg('--expires-at')) {
    fail('usage: reissue-peerit-seed-bootstrap.mjs --issued-at <ms> --expires-at <ms> --out <file> [--source deploy/peerit-seed-bootstrap-v1-seq28.json]',
      'PEERIT_SEED_BOOTSTRAP_REISSUE_USAGE')
  }
  const result = await reissuePeeritSeedBootstrapSequence29V1({
    sourceBytes: readFileSync(source),
    issuedAt: arg('--issued-at'),
    expiresAt: arg('--expires-at')
  })
  writePeeritSeedBootstrapReissueOutputV1(output, result.bytes)
  console.log(JSON.stringify({
    schema: 'peerit-seed-bootstrap-reissue-receipt-v1',
    releaseSequence: result.releaseSequence,
    records: result.recordCount,
    authorityPublicKey: result.authorityPublicKey,
    sourceSha256: result.sourceSha256,
    sha256: result.sha256,
    output: resolve(output)
  }))
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch(error => {
    console.error(`${error.code || 'PEERIT_SEED_BOOTSTRAP_REISSUE_FAILED'}: ${error.message}`)
    process.exitCode = 1
  })
}
