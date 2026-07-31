import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  decodePeeritHiveRelayProfilePinV1,
  decodePeeritPinHistoryBundleV1,
  decodePeeritPinHistoryCheckpointV1,
  decodeReleaseControlVectorManifest,
  encodePeeritHiveRelayProfilePinV1,
  encodePeeritPinHistoryBundleV1,
  encodePeeritPinHistoryCheckpointV1,
  pinHistoryCheckpointHash,
  profilePinHash,
  releaseAuthorityKeyId
} from '../js/substrate/release-control-codec.mjs'
import {
  assertReleaseControlRegistryArtifact,
  encodeReleaseControlRegistry,
  PEERIT_MIGRATION_STAGE
} from '../js/substrate/release-control-registry.mjs'
import {
  blake2b256,
  bytesEqual,
  bytesToHex,
  concatBytes
} from '../js/substrate/release-control-primitives.mjs'
import {
  canonicalExpectedPinProjection,
  verifyPeeritPinHistoryBundleV1,
  verifyPeeritProfilePinV1
} from '../js/substrate/release-control-verifier.mjs'
import {
  buildReleaseControlFixture,
  createNodeReleaseControlCrypto
} from '../scripts/release-control-fixture.mjs'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const fixture = buildReleaseControlFixture()
const crypto = createNodeReleaseControlCrypto()
let passed = 0

async function test (name, operation) {
  await operation()
  passed++
  process.stdout.write(`ok ${passed} - ${name}\n`)
}

function changedHash (value) {
  const output = value.slice()
  output[0] ^= 0x80
  return output
}

function signedCheckpointForPin (pin, pinBytes, previousCheckpointBytes) {
  const previousCheckpointHash = previousCheckpointBytes == null ? null : pinHistoryCheckpointHash(previousCheckpointBytes)
  return fixture.signCheckpoint({
    version: 1,
    checkpointSequence: pin.releaseSequence,
    previousCheckpointHash,
    pinHash: profilePinHash(pinBytes),
    previousPinHash: pin.previousPinHash,
    issuedUnixMillis: 1700000000000n + pin.releaseSequence * 1000n,
    releaseAuthoritySequence: pin.releaseAuthoritySequence,
    releaseAuthorityKeyId: pin.releaseAuthorityKeyId
  })
}

function bundleWith (pins, checkpointStart = null) {
  const pinBytes = pins.map(encodePeeritHiveRelayProfilePinV1)
  const checkpoints = []
  let previousCheckpointBytes = checkpointStart
  for (let i = 0; i < pins.length; i++) {
    const checkpoint = signedCheckpointForPin(pins[i], pinBytes[i], previousCheckpointBytes)
    previousCheckpointBytes = encodePeeritPinHistoryCheckpointV1(checkpoint)
    checkpoints.push(previousCheckpointBytes)
  }
  return encodePeeritPinHistoryBundleV1({ version: 1, checkpoints, pins: pinBytes })
}

await test('BLAKE2b-256 implementation matches the published empty and abc vectors', () => {
  assert.equal(bytesToHex(blake2b256(new Uint8Array())), '0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8')
  assert.equal(bytesToHex(blake2b256(new TextEncoder().encode('abc'))), 'bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319')
})

await test('checked-in release-control registry equals the executable non-production slice', () => {
  const bytes = new Uint8Array(fs.readFileSync(path.join(root, 'protocol/peerit-release-control-v1.cenc')))
  const decoded = assertReleaseControlRegistryArtifact(bytes)
  assert.equal(decoded.productionComplete, false)
  assert.deepEqual(decoded.records.map(entry => entry.name), [
    'SubstrateTupleV1',
    'PeeritHiveRelayProfilePinV1',
    'PeeritPinHistoryCheckpointV1',
    'PeeritPinHistoryBundleV1'
  ])
  assert.deepEqual(decoded.enums.map(entry => entry.name), ['PeeritMigrationStageV1'])
  assert.equal(bytesEqual(bytes, encodeReleaseControlRegistry()), true)
})

await test('vector manifest uses canonical HiveRelay path/length/BLAKE2b entries', () => {
  const manifestPath = path.join(root, 'protocol/vectors/peerit-release-control-v1.manifest.cenc')
  const entries = decodeReleaseControlVectorManifest(new Uint8Array(fs.readFileSync(manifestPath)))
  assert.equal(entries.length, 11)
  assert.deepEqual(entries.map(entry => entry.path), [...entries.map(entry => entry.path)].sort())
  for (const entry of entries) {
    const bytes = new Uint8Array(fs.readFileSync(path.join(root, 'protocol/vectors', entry.path)))
    assert.equal(BigInt(bytes.byteLength), entry.length)
    assert.equal(bytesEqual(blake2b256(bytes), entry.hash), true, entry.path)
  }
})

await test('canonical fixture codecs round-trip and reject trailing bytes', () => {
  assert.deepEqual(decodePeeritHiveRelayProfilePinV1(fixture.pinBytes[0]).releaseSequence, 0n)
  assert.deepEqual(decodePeeritPinHistoryCheckpointV1(fixture.checkpointBytes[1]).checkpointSequence, 1n)
  assert.equal(decodePeeritPinHistoryBundleV1(fixture.bundleBytes).pins.length, 2)
  assert.throws(() => decodePeeritHiveRelayProfilePinV1(concatBytes(fixture.pinBytes[0], Uint8Array.of(0))), /trailing bytes/)
  assert.throws(() => decodePeeritPinHistoryBundleV1(concatBytes(fixture.bundleBytes, Uint8Array.of(0))), /trailing bytes/)
})

await test('fixture bundle verifies canonical bytes, signatures, exact +1 chain, hashes, and migration transition', async () => {
  const verified = await verifyPeeritPinHistoryBundleV1(fixture.bundleBytes, {
    crypto,
    expectedPins: fixture.expectedPins
  })
  assert.equal(verified.terminalSequence, 1n)
  assert.equal(bytesEqual(verified.terminalPinHash, profilePinHash(fixture.pinBytes[1])), true)
  assert.equal(verified.pins.every(entry => entry.signaturePayloadHash.byteLength === 32), true)
  assert.equal(verified.checkpoints.every(entry => entry.signaturePayloadHash.byteLength === 32), true)
})

await test('wrong signing key is rejected even when the embedded authority key is unchanged', async () => {
  const wrongSignaturePin = fixture.signPinWithWrongKey({ ...fixture.pins[0], signature: undefined })
  await assert.rejects(
    verifyPeeritProfilePinV1(encodePeeritHiveRelayProfilePinV1(wrongSignaturePin), { crypto, expected: fixture.expectedPins[0] }),
    error => error.code === 'BAD_PROFILE_PIN_SIGNATURE'
  )
})

await test('self-consistent wrong authority key cannot escape exact build expectations', async () => {
  const wrongKeyPin = fixture.signPinWithWrongKey({
    ...fixture.pins[0],
    releaseAuthorityPublicKey: fixture.wrongPublicKey,
    releaseAuthorityKeyId: releaseAuthorityKeyId(fixture.wrongPublicKey),
    signature: undefined
  })
  await assert.rejects(
    verifyPeeritProfilePinV1(encodePeeritHiveRelayProfilePinV1(wrongKeyPin), { crypto, expected: fixture.expectedPins[0] }),
    error => error.code === 'PROFILE_PIN_EXPECTATION_MISMATCH'
  )
})

await test('expected projection binds predecessor, tuple, profile, and application hashes', async () => {
  for (const mutate of [
    expected => { expected.previousPinHash = changedHash(expected.previousPinHash) },
    expected => { expected.emitSubstrate = fixture.tuples.tupleA },
    expected => { expected.profileAbiHash = changedHash(expected.profileAbiHash) },
    expected => { expected.appArtifactHash = changedHash(expected.appArtifactHash) }
  ]) {
    const expected = structuredClone(fixture.expectedPins[1])
    mutate(expected)
    await assert.rejects(
      verifyPeeritProfilePinV1(fixture.pinBytes[1], { crypto, expected }),
      error => error.code === 'PROFILE_PIN_EXPECTATION_MISMATCH'
    )
  }
})

await test('sequence gaps fail even when both pins and checkpoints carry valid signatures', async () => {
  const gapPin = fixture.signPin({
    ...fixture.pins[1],
    releaseSequence: 2n,
    cutoffActivationReleaseSequence: 2n,
    previousPinHash: profilePinHash(fixture.pinBytes[0]),
    signature: undefined
  })
  const bytes = bundleWith([fixture.pins[0], gapPin])
  await assert.rejects(
    verifyPeeritPinHistoryBundleV1(bytes, { crypto, expectedPins: [fixture.expectedPins[0], canonicalExpectedPinProjection(gapPin)] }),
    error => error.code === 'PIN_HISTORY_GAP_OR_FORK'
  )
})

await test('witnessed same-sequence fork fails closed', async () => {
  await assert.rejects(
    verifyPeeritPinHistoryBundleV1(fixture.bundleBytes, {
      crypto,
      expectedPins: fixture.expectedPins,
      witnessedPinHashes: new Map([['1', changedHash(profilePinHash(fixture.pinBytes[1]))]])
    }),
    error => error.code === 'PIN_HISTORY_FORK'
  )
})

await test('migration downgrade fails with an otherwise valid signed chain', async () => {
  const pin2 = fixture.signPin({
    ...fixture.pins[1],
    releaseSequence: 2n,
    previousPinHash: profilePinHash(fixture.pinBytes[1]),
    migrationStage: PEERIT_MIGRATION_STAGE.LIVE_DUAL_READ,
    migrationTransitionEvidenceHash: changedHash(fixture.pins[1].migrationTransitionEvidenceHash),
    legacyImportMode: 0,
    legacyReadMode: 0,
    legacyCutoffHash: null,
    migrationGenesisRecordId: null,
    cutoffActivationReleaseSequence: null,
    signature: undefined
  })
  const bytes = bundleWith([fixture.pins[0], fixture.pins[1], pin2])
  await assert.rejects(
    verifyPeeritPinHistoryBundleV1(bytes, {
      crypto,
      expectedPins: [...fixture.expectedPins, canonicalExpectedPinProjection(pin2)]
    }),
    error => error.code === 'MIGRATION_DOWNGRADE'
  )
})

await test('migration stage skip fails with otherwise valid signatures', async () => {
  const pin1 = fixture.signPin({
    ...fixture.pins[1],
    migrationStage: PEERIT_MIGRATION_STAGE.ARCHIVE_ONLY,
    legacyImportMode: 2,
    legacyReadMode: 1,
    legacyRetirementEvidenceHash: changedHash(fixture.pins[1].migrationTransitionEvidenceHash),
    legacyRetirementActivationReleaseSequence: 1n,
    signature: undefined
  })
  const bytes = bundleWith([fixture.pins[0], pin1])
  await assert.rejects(
    verifyPeeritPinHistoryBundleV1(bytes, {
      crypto,
      expectedPins: [fixture.expectedPins[0], canonicalExpectedPinProjection(pin1)]
    }),
    error => error.code === 'MIGRATION_GAP'
  )
})

await test('legacy source set is frozen across cutoff', async () => {
  const pin1 = fixture.signPin({
    ...fixture.pins[1],
    legacySourceSetHash: changedHash(fixture.pins[1].legacySourceSetHash),
    signature: undefined
  })
  const bytes = bundleWith([fixture.pins[0], pin1])
  await assert.rejects(
    verifyPeeritPinHistoryBundleV1(bytes, {
      crypto,
      expectedPins: [fixture.expectedPins[0], canonicalExpectedPinProjection(pin1)]
    }),
    error => error.code === 'MIGRATION_LEGACY_SOURCE_SET_FORK'
  )
})

await test('zero artifact hashes and unchained standalone authority transitions fail closed', async () => {
  const zeroHashPin = fixture.signPin({ ...fixture.pins[0], profileSpecHash: new Uint8Array(32), signature: undefined })
  await assert.rejects(
    verifyPeeritProfilePinV1(encodePeeritHiveRelayProfilePinV1(zeroHashPin), { crypto, expected: canonicalExpectedPinProjection(zeroHashPin) }),
    error => error.code === 'BAD_PROFILE_PIN_SECURITY_FIELD'
  )
  const zeroCutoffPin = fixture.signPin({ ...fixture.pins[1], legacyCutoffHash: new Uint8Array(32), signature: undefined })
  await assert.rejects(
    verifyPeeritPinHistoryBundleV1(bundleWith([fixture.pins[0], zeroCutoffPin]), {
      crypto,
      expectedPins: [fixture.expectedPins[0], canonicalExpectedPinProjection(zeroCutoffPin)]
    }),
    error => error.code === 'BAD_MIGRATION_CUTOFF_STATE'
  )
  const unchainedTransitionPin = fixture.signPin({
    ...fixture.pins[0],
    authorityTransitionHash: changedHash(fixture.pins[0].profileSpecHash),
    signature: undefined
  })
  await assert.rejects(verifyPeeritProfilePinV1(
    encodePeeritHiveRelayProfilePinV1(unchainedTransitionPin),
    { crypto, expected: canonicalExpectedPinProjection(unchainedTransitionPin) }
  ), error => error.code === 'AUTHORITY_TRANSITION_OUTSIDE_SLICE')
})

await test('nonzero suffix accepts only a module-branded prior verified terminal', async () => {
  const first = await verifyPeeritPinHistoryBundleV1(
    encodePeeritPinHistoryBundleV1({ version: 1, checkpoints: [fixture.checkpointBytes[0]], pins: [fixture.pinBytes[0]] }),
    { crypto, expectedPins: [fixture.expectedPins[0]] }
  )
  const suffix = encodePeeritPinHistoryBundleV1({ version: 1, checkpoints: [fixture.checkpointBytes[1]], pins: [fixture.pinBytes[1]] })
  await assert.rejects(
    verifyPeeritPinHistoryBundleV1(suffix, { crypto, expectedPins: [fixture.expectedPins[1]], anchor: { ...first } }),
    error => error.code === 'VERIFIED_PIN_HISTORY_ANCHOR_REQUIRED'
  )
  const verified = await verifyPeeritPinHistoryBundleV1(suffix, { crypto, expectedPins: [fixture.expectedPins[1]], anchor: first })
  assert.equal(verified.terminalSequence, 1n)
})

await test('static slice rejects a valid signed newer pin without an authenticated expected projection', async () => {
  await assert.rejects(
    verifyPeeritPinHistoryBundleV1(fixture.bundleBytes, { crypto, expectedPins: [fixture.expectedPins[0]] }),
    error => error.code === 'EXPECTED_PROFILE_PIN_SET_REQUIRED'
  )
})

process.stdout.write(`peerit release-control tests: ${passed}/${passed} passed\n`)
