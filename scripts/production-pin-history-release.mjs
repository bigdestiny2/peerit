import { createPublicKey, verify as nodeVerify } from 'node:crypto'
import {
  decodePeeritHiveRelayProfilePinV1,
  decodePeeritPinHistoryBundleV1,
  profilePinHash
} from '../js/substrate/release-control-codec.mjs'
import {
  asBytes,
  bytesEqual,
  concatBytes,
  hexToBytes
} from '../js/substrate/release-control-primitives.mjs'
import {
  canonicalExpectedPinProjection,
  verifyPeeritPinHistoryBundleV1
} from '../js/substrate/release-control-verifier.mjs'
import { PEERIT_PRODUCTION_RELEASE_AUTHORITY_V1 } from '../js/substrate/production-release-authority.mjs'

const ED25519_SPKI_PREFIX = hexToBytes('302a300506032b6570032100')

function fixed32 (value, field) {
  const output = new Uint8Array(asBytes(value, field))
  if (output.byteLength !== 32) throw new Error(`${field} must be exactly 32 bytes`)
  return output
}

function nodeReleaseCrypto () {
  return Object.freeze({
    verifyEd25519 (publicKey, message, signature) {
      const key = createPublicKey({
        key: Buffer.from(concatBytes(ED25519_SPKI_PREFIX, publicKey)),
        format: 'der',
        type: 'spki'
      })
      return nodeVerify(null, Buffer.from(message), key, Buffer.from(signature))
    }
  })
}

// Generic exact verifier used by release tests and by the compiled-root wrapper
// below. Release commands call only the wrapper: caller-supplied roots are never
// accepted at a production mutation seam.
export async function verifyPeeritPinHistoryReleaseBundleV1 (options = {}) {
  const bundleBytes = new Uint8Array(asBytes(options.bundleBytes, 'pin-history bundle'))
  const releaseSequence = typeof options.releaseSequence === 'bigint'
    ? options.releaseSequence
    : BigInt(options.releaseSequence)
  if (releaseSequence < 0n) throw new Error('pin-history releaseSequence is invalid')
  const authority = fixed32(options.releaseAuthorityPublicKey, 'release authority public key')
  const genesisPinHash = fixed32(options.genesisPinHash, 'genesis pin hash')
  const appArtifactHash = fixed32(options.appArtifactHash, 'app artifact hash')
  const webAssetManifestHash = fixed32(
    options.webAssetManifestHash, 'WebAssetManifestV1 hash')
  const decoded = decodePeeritPinHistoryBundleV1(bundleBytes)
  const pins = decoded.pins.map(bytes => decodePeeritHiveRelayProfilePinV1(bytes))
  if (pins.length < 1 || pins[0].releaseSequence !== 0n ||
      !bytesEqual(profilePinHash(decoded.pins[0]), genesisPinHash)) {
    throw new Error('pin-history bundle does not start at the compiled genesis')
  }
  if (pins.some(pin => !bytesEqual(pin.releaseAuthorityPublicKey, authority))) {
    throw new Error('pin-history bundle changes the compiled authority without a reviewed transition')
  }
  const terminal = pins[pins.length - 1]
  if (terminal.releaseSequence !== releaseSequence ||
      !bytesEqual(terminal.appArtifactHash, appArtifactHash) ||
      !bytesEqual(terminal.webAssetManifestHash, webAssetManifestHash)) {
    throw new Error('pin-history terminal does not bind the candidate sequence and exact app/Web artifacts')
  }
  const verified = await verifyPeeritPinHistoryBundleV1(bundleBytes, {
    crypto: nodeReleaseCrypto(),
    expectedPins: pins.map(canonicalExpectedPinProjection)
  })
  if (verified.terminalSequence !== releaseSequence ||
      !bytesEqual(verified.terminalPinHash, profilePinHash(decoded.pins[decoded.pins.length - 1]))) {
    throw new Error('verified pin-history terminal does not equal the candidate release')
  }
  return verified
}

export async function verifyPeeritProductionPinHistoryReleaseV1 (options = {}) {
  if (!Number.isSafeInteger(options.releaseSequence) || options.releaseSequence < 7) {
    throw new Error('production pin history requires a replacement release sequence of at least 7')
  }
  if (!PEERIT_PRODUCTION_RELEASE_AUTHORITY_V1.publicKey ||
      !PEERIT_PRODUCTION_RELEASE_AUTHORITY_V1.genesisPinHash) {
    const error = new Error(
      'production pin history cannot be emitted before authority key and genesis pin hash are compiled')
    error.code = 'PRODUCTION_PEERIT_RELEASE_AUTHORITY_UNPINNED'
    throw error
  }
  return verifyPeeritPinHistoryReleaseBundleV1({
    ...options,
    releaseAuthorityPublicKey: PEERIT_PRODUCTION_RELEASE_AUTHORITY_V1.publicKey,
    genesisPinHash: PEERIT_PRODUCTION_RELEASE_AUTHORITY_V1.genesisPinHash
  })
}
