import assert from 'node:assert/strict'
import {
  createHash,
  createPrivateKey,
  createPublicKey
} from 'node:crypto'
import {
  mkdtempSync,
  readFileSync,
  writeFileSync
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import {
  createPeeritSeedBootstrapV1,
  encodePeeritSeedBootstrapV1,
  verifyPeeritSeedBootstrapV1
} from '../js/substrate/seed-bootstrap-v1.mjs'
import {
  PEERIT_SEED_BOOTSTRAP_REISSUE_RECORD_COUNT_V1,
  PEERIT_SEED_BOOTSTRAP_REISSUE_ACCEPTED_SOURCE_SHA256_V1,
  PEERIT_SEED_BOOTSTRAP_REISSUE_SOURCE_SEQUENCE_V1,
  PEERIT_SEED_BOOTSTRAP_REISSUE_TARGET_SEQUENCE_V1,
  PEERIT_SEED_BOOTSTRAP_SIGNING_SEED_ENV_V1,
  reissuePeeritSeedBootstrapSequence29V1,
  writePeeritSeedBootstrapReissueOutputV1
} from '../scripts/reissue-peerit-seed-bootstrap.mjs'

const fixtureSeed = '5a'.repeat(32)
const wrongSeed = '6b'.repeat(32)
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex')

function publicKey (seedHex) {
  const privateKey = createPrivateKey({
    key: Buffer.concat([PKCS8_PREFIX, Buffer.from(seedHex, 'hex')]),
    format: 'der',
    type: 'pkcs8'
  })
  return createPublicKey(privateKey).export({ format: 'der', type: 'spki' })
    .subarray(-32).toString('hex')
}

function sha256 (bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

const checkedInSource = JSON.parse(readFileSync(
  new URL('../deploy/peerit-seed-bootstrap-v1-seq28.json', import.meta.url)))
assert.equal(checkedInSource.payload.releaseSequence,
  PEERIT_SEED_BOOTSTRAP_REISSUE_SOURCE_SEQUENCE_V1)
assert.equal(checkedInSource.payload.records.length,
  PEERIT_SEED_BOOTSTRAP_REISSUE_RECORD_COUNT_V1)
assert.equal(sha256(readFileSync(
  new URL('../deploy/peerit-seed-bootstrap-v1-seq28.json', import.meta.url))),
PEERIT_SEED_BOOTSTRAP_REISSUE_ACCEPTED_SOURCE_SHA256_V1)

const authorityPublicKey = publicKey(fixtureSeed)
const fixtureSource = await createPeeritSeedBootstrapV1({
  ...checkedInSource.payload,
  authorityPublicKey
}, { seedHex: fixtureSeed })
const fixtureSourceBytes = Buffer.from(encodePeeritSeedBootstrapV1(fixtureSource))
const issuedAt = 1_786_000_000_000
const expiresAt = issuedAt + 30 * 24 * 60 * 60 * 1000
const options = {
  sourceBytes: fixtureSourceBytes,
  issuedAt,
  expiresAt,
  fixtureOnly: true,
  testOnly: true,
  seedHex: fixtureSeed
}
const first = await reissuePeeritSeedBootstrapSequence29V1(options)
const second = await reissuePeeritSeedBootstrapSequence29V1(options)
assert.deepEqual(first.bytes, second.bytes, 'frozen times make reissue deterministic')
assert.equal(first.releaseSequence, PEERIT_SEED_BOOTSTRAP_REISSUE_TARGET_SEQUENCE_V1)
assert.equal(first.recordCount, PEERIT_SEED_BOOTSTRAP_REISSUE_RECORD_COUNT_V1)
assert.equal(first.authorityPublicKey, authorityPublicKey)
assert.equal(first.issuedAt, issuedAt)
assert.equal(first.expiresAt, expiresAt)
assert.equal(first.sourceSha256, sha256(fixtureSourceBytes))
assert.equal(first.sha256, sha256(first.bytes))
await verifyPeeritSeedBootstrapV1(first.bytes, {
  authorityPublicKey,
  releaseSequence: 29,
  expectedArtifactHash: first.sha256,
  previousBootstrapHash: null,
  now: issuedAt
})

const reissued = JSON.parse(first.bytes)
const mutable = new Set(['releaseSequence', 'issuedAt', 'expiresAt'])
const projection = payload => Object.fromEntries(Object.entries(payload)
  .filter(([field]) => !mutable.has(field)))
assert.deepEqual(projection(reissued.payload), projection(fixtureSource.payload),
  'only releaseSequence/issuedAt/expiresAt may change in the signed payload')
assert.deepEqual(reissued.payload.records, checkedInSource.payload.records,
  'all 39 records and capabilities are byte-logically unchanged from Sequence 28')
assert.deepEqual(reissued.payload.relays, checkedInSource.payload.relays,
  'the exact two-relay source roots are unchanged')

await assert.rejects(reissuePeeritSeedBootstrapSequence29V1({
  ...options,
  seedHex: wrongSeed
}), /signature verification failed/,
'a seed that does not derive the existing authority cannot produce output')
await assert.rejects(reissuePeeritSeedBootstrapSequence29V1({
  ...options,
  sourceBytes: Buffer.from(JSON.stringify(fixtureSource, null, 2) + '\n')
}), /canonical/)
const wrongSequence = await createPeeritSeedBootstrapV1({
  ...fixtureSource.payload,
  releaseSequence: 27
}, { seedHex: fixtureSeed })
await assert.rejects(reissuePeeritSeedBootstrapSequence29V1({
  ...options,
  sourceBytes: Buffer.from(encodePeeritSeedBootstrapV1(wrongSequence))
}), /Sequence-28/)
await assert.rejects(reissuePeeritSeedBootstrapSequence29V1({
  ...options,
  fixtureOnly: false
}), error => error.code === 'PEERIT_SEED_BOOTSTRAP_REISSUE_SOURCE_MISMATCH')
await assert.rejects(reissuePeeritSeedBootstrapSequence29V1({
  ...options,
  testOnly: false
}), error => error.code === 'PEERIT_SEED_BOOTSTRAP_REISSUE_SOURCE_MISMATCH' ||
  error.code === 'PEERIT_SEED_BOOTSTRAP_REISSUE_FIXTURE_BOUNDARY')

const alteredPayload = structuredClone(fixtureSource.payload)
alteredPayload.records[0].innerLength += 1
const alteredSignedSource = await createPeeritSeedBootstrapV1(alteredPayload, {
  seedHex: fixtureSeed
})
const alteredAcceptedBytes = Buffer.from(encodePeeritSeedBootstrapV1(alteredSignedSource))
await assert.rejects(reissuePeeritSeedBootstrapSequence29V1({
  sourceBytes: alteredAcceptedBytes,
  issuedAt,
  expiresAt,
  environment: { [PEERIT_SEED_BOOTSTRAP_SIGNING_SEED_ENV_V1]: fixtureSeed }
}), error => error.code === 'PEERIT_SEED_BOOTSTRAP_REISSUE_SOURCE_MISMATCH',
'a separately valid signed 39-record predecessor with one altered record cannot enter the production reissuer')

const directory = mkdtempSync(join(tmpdir(), 'peerit-seq29-seed-reissue-'))
const sourcePath = join(directory, 'source-seq28.json')
const outputPath = join(directory, 'output-seq29.json')
writeFileSync(sourcePath, fixtureSourceBytes)
writePeeritSeedBootstrapReissueOutputV1(outputPath, first.bytes)
assert.deepEqual(readFileSync(outputPath), first.bytes)
assert.throws(() => writePeeritSeedBootstrapReissueOutputV1(outputPath, Buffer.from('replacement')),
  /EEXIST/,
  'an existing signed release artifact cannot be overwritten')
assert.deepEqual(readFileSync(outputPath), first.bytes,
  'failed duplicate publication preserves the original exact bytes')
const cli = spawnSync(process.execPath, [
  'scripts/reissue-peerit-seed-bootstrap.mjs',
  '--source', sourcePath,
  '--issued-at', String(issuedAt),
  '--expires-at', String(expiresAt),
  '--out', join(directory, 'forbidden-fixture-output.json')
], {
  cwd: new URL('..', import.meta.url),
  encoding: 'utf8',
  env: {
    ...process.env,
    [PEERIT_SEED_BOOTSTRAP_SIGNING_SEED_ENV_V1]: fixtureSeed
  }
})
assert.notEqual(cli.status, 0, 'the production CLI rejects a valid but unaccepted fixture predecessor')
assert.match(cli.stderr, /SOURCE_MISMATCH/)
assert.equal(cli.stdout.includes(fixtureSeed), false, 'receipt cannot expose the signing seed')
assert.equal(cli.stderr.includes(fixtureSeed), false, 'errors cannot expose the signing seed')
const forbiddenArg = spawnSync(process.execPath, [
  'scripts/reissue-peerit-seed-bootstrap.mjs', '--seed', fixtureSeed
], { cwd: new URL('..', import.meta.url), encoding: 'utf8' })
assert.notEqual(forbiddenArg.status, 0)
assert.match(forbiddenArg.stderr, /REISSUE_USAGE/)

console.log('peerit seq29 seed-bootstrap reissuer: exact seq28/39-record source, deterministic frozen-time reissue, existing-authority self-verification, canonicality and secret-channel gates green')
