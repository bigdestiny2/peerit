import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  encodePeeritHiveRelayProfilePinV1,
  encodePeeritPinHistoryBundleV1,
  encodePeeritPinHistoryCheckpointV1,
  pinHistoryCheckpointHash,
  profilePinHash
} from '../js/substrate/release-control-codec.mjs'
import { bytesEqual } from '../js/substrate/release-control-primitives.mjs'
import { PEERIT_PRODUCTION_PIN_HISTORY_PATH } from '../js/substrate/production-release-authority.mjs'
import { decodePeeritWebAssetManifestV1 } from '../js/substrate/web-asset-manifest.mjs'
import { SUBSTRATE_SITE_FILES } from '../publish.mjs'
import { buildReleaseControlFixture } from '../scripts/release-control-fixture.mjs'
import {
  verifyPeeritPinHistoryReleaseBundleV1,
  verifyPeeritProductionPinHistoryReleaseV1
} from '../scripts/production-pin-history-release.mjs'
import { buildPeeritSubstrateRuntimeArtifactV1 } from '../scripts/substrate-runtime-artifact.mjs'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const sourceFiles = new Map(SUBSTRATE_SITE_FILES.map(path => [
  path,
  readFileSync(join(root, path))
]))
const releaseSequence = 7
const releaseKey = 'ab'.repeat(32)
const provisional = buildPeeritSubstrateRuntimeArtifactV1({
  sourceFiles,
  substrateProfile: 'blind-v1',
  relayHints: [],
  releaseSequence,
  releaseKey,
  // Presence chooses the canonical detached path, but these bytes do not enter
  // either hash. A ceremony can therefore calculate A/W before signing pin 7.
  productionPinHistoryBytes: Uint8Array.of(1)
})

const fixture = buildReleaseControlFixture()
const pins = [...fixture.pinBytes]
const checkpoints = [...fixture.checkpointBytes]
let previousPinBytes = pins[pins.length - 1]
let previousCheckpointBytes = checkpoints[checkpoints.length - 1]
for (let sequence = 2n; sequence <= BigInt(releaseSequence); sequence++) {
  const pin = fixture.signPin({
    ...fixture.pins[1],
    releaseSequence: sequence,
    previousPinHash: profilePinHash(previousPinBytes),
    appArtifactHash: sequence === BigInt(releaseSequence)
      ? provisional.appArtifactHash
      : fixture.pins[1].appArtifactHash,
    webAssetManifestHash: sequence === BigInt(releaseSequence)
      ? provisional.webAssetManifestHash
      : fixture.pins[1].webAssetManifestHash,
    migrationTransitionEvidenceHash: null,
    authorityTransitionHash: null,
    signature: undefined
  })
  const pinBytes = encodePeeritHiveRelayProfilePinV1(pin)
  const checkpoint = fixture.signCheckpoint({
    version: 1,
    checkpointSequence: sequence,
    previousCheckpointHash: pinHistoryCheckpointHash(previousCheckpointBytes),
    pinHash: profilePinHash(pinBytes),
    previousPinHash: pin.previousPinHash,
    issuedUnixMillis: 1700000000000n + sequence * 1000n,
    releaseAuthoritySequence: pin.releaseAuthoritySequence,
    releaseAuthorityKeyId: pin.releaseAuthorityKeyId,
    signature: undefined
  })
  const checkpointBytes = encodePeeritPinHistoryCheckpointV1(checkpoint)
  pins.push(pinBytes)
  checkpoints.push(checkpointBytes)
  previousPinBytes = pinBytes
  previousCheckpointBytes = checkpointBytes
}
const bundleBytes = encodePeeritPinHistoryBundleV1({ version: 1, pins, checkpoints })

const finalArtifact = buildPeeritSubstrateRuntimeArtifactV1({
  sourceFiles,
  substrateProfile: 'blind-v1',
  relayHints: [],
  releaseSequence,
  releaseKey,
  productionPinHistoryBytes: bundleBytes
})
assert.equal(bytesEqual(finalArtifact.appArtifactHash, provisional.appArtifactHash), true,
  'replacing provisional detached bytes does not change appArtifactHash')
assert.deepEqual(finalArtifact.appArtifactBytes, provisional.appArtifactBytes,
  'replacing provisional detached bytes does not change app artifact bytes')
assert.equal(bytesEqual(finalArtifact.webAssetManifestHash, provisional.webAssetManifestHash), true,
  'replacing provisional detached bytes does not change WebAssetManifestV1 hash')
assert.deepEqual(finalArtifact.webAssetManifestBytes, provisional.webAssetManifestBytes,
  'replacing provisional detached bytes does not change WebAssetManifestV1 bytes')
assert.equal(finalArtifact.appArtifact.files[PEERIT_PRODUCTION_PIN_HISTORY_PATH.slice(1)], undefined)
assert.equal(decodePeeritWebAssetManifestV1(finalArtifact.webAssetManifestBytes).assets.some(
  asset => asset.path === PEERIT_PRODUCTION_PIN_HISTORY_PATH), false)
assert.deepEqual(finalArtifact.files.get(PEERIT_PRODUCTION_PIN_HISTORY_PATH.slice(1)),
  Buffer.from(bundleBytes))

const verified = await verifyPeeritPinHistoryReleaseBundleV1({
  bundleBytes,
  releaseSequence,
  appArtifactHash: finalArtifact.appArtifactHash,
  webAssetManifestHash: finalArtifact.webAssetManifestHash,
  releaseAuthorityPublicKey: fixture.releasePublicKey,
  genesisPinHash: profilePinHash(fixture.pinBytes[0])
})
assert.equal(verified.terminalSequence, 7n)

const tampered = Buffer.from(bundleBytes)
tampered[tampered.length - 1] ^= 1
await assert.rejects(verifyPeeritPinHistoryReleaseBundleV1({
  bundleBytes: tampered,
  releaseSequence,
  appArtifactHash: finalArtifact.appArtifactHash,
  webAssetManifestHash: finalArtifact.webAssetManifestHash,
  releaseAuthorityPublicKey: fixture.releasePublicKey,
  genesisPinHash: profilePinHash(fixture.pinBytes[0])
}))
await assert.rejects(verifyPeeritPinHistoryReleaseBundleV1({
  bundleBytes,
  releaseSequence,
  appArtifactHash: new Uint8Array(32),
  webAssetManifestHash: finalArtifact.webAssetManifestHash,
  releaseAuthorityPublicKey: fixture.releasePublicKey,
  genesisPinHash: profilePinHash(fixture.pinBytes[0])
}), /terminal does not bind/)
await assert.rejects(verifyPeeritProductionPinHistoryReleaseV1({
  bundleBytes,
  releaseSequence,
  appArtifactHash: finalArtifact.appArtifactHash,
  webAssetManifestHash: finalArtifact.webAssetManifestHash
}), error => error.code === 'PRODUCTION_PEERIT_RELEASE_AUTHORITY_UNPINNED')

console.log('peerit-production-pin-history-release: detached pin history is constructible, signature/genesis/terminal bound, tamper rejected, and production remains root-gated')
