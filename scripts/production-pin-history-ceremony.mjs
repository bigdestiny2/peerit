#!/usr/bin/env node

// Offline, two-phase production pin-history ceremony. The command accepts the
// signing seed only from process environment, never from argv or a file. Phase
// one reconstructs and signs the disclosed 0..12 prefix and compiles its trust
// root. Phase two appends exactly one predicted runtime (13 through 20) after
// checking the signed seed bootstrap and canonical Web closure. Sequence 19 is
// the CSP-safe browser recovery release; sequence 20 is its cold rollback.

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as nodeSign,
  verify as nodeVerify
} from 'node:crypto'
import {
  mkdirSync,
  readFileSync,
  renameSync,
  writeFileSync
} from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { availabilityPolicyHash, PEERIT_AVAILABILITY_POLICY_ARTIFACT } from '../js/substrate/availability-policy.mjs'
import {
  hashPeeritProfileAbi,
  hashPeeritProfileSpec,
  hashPeeritProfileVectorSet,
  PEERIT_PROFILE_SOURCE_PATH
} from '../js/substrate/profile-artifact-codec.mjs'
import { PEERIT_PROFILE_FINAL_HIVERELAY_WIRE_TUPLE_V1 } from '../js/substrate/profile-external-authority.mjs'
import {
  checkpointSignaturePayload,
  decodePeeritHiveRelayProfilePinV1,
  decodePeeritPinHistoryBundleV1,
  encodePeeritHiveRelayProfilePinV1,
  encodePeeritPinHistoryBundleV1,
  encodePeeritPinHistoryCheckpointV1,
  pinHistoryBundleHash,
  pinHistoryCheckpointHash,
  profilePinHash,
  profilePinSignaturePayload,
  releaseAuthorityKeyId
} from '../js/substrate/release-control-codec.mjs'
import {
  asciiBytes,
  blake2b256,
  bytesEqual,
  bytesToHex,
  concatBytes,
  domainLengthHash,
  hexToBytes
} from '../js/substrate/release-control-primitives.mjs'
import {
  PEERIT_MIGRATION_STAGE,
  PEERIT_PROFILE_ID,
  RELEASE_CONTROL_LIMIT
} from '../js/substrate/release-control-registry.mjs'
import { canonicalExpectedPinProjection, verifyPeeritPinHistoryBundleV1 } from '../js/substrate/release-control-verifier.mjs'
import { encodePeeritSeedBootstrapV1, verifyPeeritSeedBootstrapV1 } from '../js/substrate/seed-bootstrap-v1.mjs'
import {
  hashPeeritValidatorArtifactV1,
  hashPeeritValidatorVectorSetV1,
  PEERIT_VALIDATOR_ARTIFACT_PATH,
  PEERIT_VALIDATOR_VECTOR_MANIFEST_PATH
} from '../js/substrate/validator-artifact.mjs'
import {
  decodePeeritWebAssetManifestV1,
  hashPeeritAppArtifactV1,
  hashPeeritBootstrapV1,
  hashPeeritWebAssetManifestV1
} from '../js/substrate/web-asset-manifest.mjs'

export const PEERIT_PRODUCTION_CEREMONY_SCHEMA_V1 = 'peerit-production-pin-history-ceremony-v1'
export const PEERIT_SEED_BOOTSTRAP_PATH = '/peerit-seed-bootstrap-v1.json'
export const PEERIT_PRODUCTION_PREFIX_TERMINAL_SEQUENCE = 12
export const PEERIT_PRODUCTION_CEREMONY_MIN_RELEASE_SEQUENCE = 13
export const PEERIT_PRODUCTION_CEREMONY_MAX_RELEASE_SEQUENCE = 27
export const PEERIT_CSP_SAFE_VALIDATOR_TRANSITION_RELEASE_SEQUENCE = 19
export const PEERIT_SEQUENCE_18_VALIDATOR_ARTIFACT_HASH =
  '9e4c2e57769d005bee92a227751e559144824553b202401fb89c06d4bca55b2a'
export const PEERIT_SEQUENCE_19_VALIDATOR_ARTIFACT_HASH =
  'c92f1b402d745fc5d8235358bc7909a50cb23b230e75de605fd421fc500f9613'
export const PEERIT_ACCEPTED_SEQUENCE_12_APP_HASH = 'b34628cb7580e8decb9f3dfced4dceaff6220573d6cba31970f3b1b7f165c292'
export const PEERIT_ACCEPTED_SEQUENCE_12_WEB_HASH = 'fb79fd6c8ec4bd628aff8a1007a88f9200117903f6356cc41ab16bc1d308229c'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const HEX_32 = /^[0-9a-f]{64}$/
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex')
const SPKI_PREFIX = hexToBytes('302a300506032b6570032100')
const PROFILE_ARTIFACT_PATH = 'protocol/peerit-profile-v1.cenc'
const PROFILE_VECTOR_PATH = 'protocol/vectors/peerit-profile-v1.manifest.cenc'
const WIRE_SPEC_PATH = 'protocol/external-authority/hiverelay-blind-wire-v1.md'
const WIRE_ABI_PATH = 'protocol/external-authority/hiverelay-blind-abi-v1.cenc'
const WIRE_VECTOR_PATH = 'protocol/external-authority/hiverelay-blind-wire-vector-manifest-v1.cenc'
const PREPRODUCTION_PLACEHOLDER_DOMAIN = 'peerit.production-pin-history.disclosed-preproduction-placeholder.v1'
const LEGACY_SOURCE_RECONSTRUCTION_DOMAIN = 'peerit.production-pin-history.disclosed-legacy-source-reconstruction.v1'

function fail (message, code = 'PEERIT_PRODUCTION_CEREMONY_FAILED') {
  const error = new Error(message)
  error.code = code
  throw error
}

function exactHex32 (value, field) {
  value = String(value || '').trim().toLowerCase()
  if (!HEX_32.test(value)) fail(`${field} must be exactly 32 bytes of hexadecimal`)
  return value
}

function exactBytes (value, field) {
  if (!(value instanceof Uint8Array)) fail(`${field} must be bytes`)
  return new Uint8Array(value)
}

function sha256Hex (value) {
  return createHash('sha256').update(value).digest('hex')
}

function read (root, path) {
  return readFileSync(resolve(root, path))
}

function equalHex (value, expected, field) {
  const actual = bytesToHex(value)
  if (actual !== expected) fail(`${field} does not reproduce its frozen production hash`)
}

function signingKey (seedHex) {
  const seed = Buffer.from(exactHex32(seedHex, 'release signing seed'), 'hex')
  const der = Buffer.concat([PKCS8_PREFIX, seed])
  try {
    const privateKey = createPrivateKey({ key: der, format: 'der', type: 'pkcs8' })
    const publicKey = new Uint8Array(createPublicKey(privateKey).export({ format: 'der', type: 'spki' }).subarray(-32))
    return { privateKey, publicKey }
  } finally {
    seed.fill(0)
    der.fill(0)
  }
}

export function releaseSigningSeedFromEnvironment (environment = process.env) {
  const preferred = String(environment.PEERIT_RELEASE_SIGNING_SEED || '').trim()
  const legacy = String(environment.PEERIT_RELEASE_SEED || '').trim()
  if (preferred && legacy && preferred.toLowerCase() !== legacy.toLowerCase()) {
    fail('release signing seed aliases disagree', 'PEERIT_PRODUCTION_CEREMONY_KEY_MISMATCH')
  }
  const value = preferred || legacy
  if (!value) fail('PEERIT_RELEASE_SIGNING_SEED is required (PEERIT_RELEASE_SEED is a legacy alias)', 'PEERIT_PRODUCTION_CEREMONY_SIGNER_REQUIRED')
  return exactHex32(value, 'release signing seed')
}

function nodeCrypto () {
  return Object.freeze({
    verifyEd25519 (publicKey, message, signature) {
      const key = createPublicKey({
        key: Buffer.from(concatBytes(SPKI_PREFIX, publicKey)),
        format: 'der',
        type: 'spki'
      })
      return nodeVerify(null, Buffer.from(message), key, Buffer.from(signature))
    }
  })
}

function signPin (value, privateKey) {
  return {
    ...value,
    signature: new Uint8Array(nodeSign(null, Buffer.from(profilePinSignaturePayload(value)), privateKey))
  }
}

function signCheckpoint (value, privateKey) {
  return {
    ...value,
    signature: new Uint8Array(nodeSign(null, Buffer.from(checkpointSignaturePayload(value)), privateKey))
  }
}

function placeholderHash (sequence, kind) {
  return domainLengthHash(PREPRODUCTION_PLACEHOLDER_DOMAIN, asciiBytes(`release-sequence:${sequence}:${kind}`))
}

function legacySourceReconstructionHash () {
  return domainLengthHash(LEGACY_SOURCE_RECONSTRUCTION_DOMAIN,
    asciiBytes('historical-legacy-source-set-unavailable;live-dual-read;no-cutoff'))
}

export function deriveProductionPinBindingsV1 (root = ROOT) {
  const profileSpecHash = hashPeeritProfileSpec(read(root, PEERIT_PROFILE_SOURCE_PATH))
  const profileAbiHash = hashPeeritProfileAbi(read(root, PROFILE_ARTIFACT_PATH))
  const profileVectorSetHash = hashPeeritProfileVectorSet(read(root, PROFILE_VECTOR_PATH))
  const validatorArtifactHash = hashPeeritValidatorArtifactV1(read(root, PEERIT_VALIDATOR_ARTIFACT_PATH))
  const validatorVectorSetHash = hashPeeritValidatorVectorSetV1(read(root, PEERIT_VALIDATOR_VECTOR_MANIFEST_PATH))
  const availabilityHash = availabilityPolicyHash(read(root, PEERIT_AVAILABILITY_POLICY_ARTIFACT))
  const emitSubstrate = {
    specHash: domainLengthHash('hiverelay.blind.spec-hash.v1', read(root, WIRE_SPEC_PATH)),
    abiHash: domainLengthHash('hiverelay.blind.abi-hash.v1', read(root, WIRE_ABI_PATH)),
    vectorSetHash: domainLengthHash('hiverelay.blind.vector-set-hash.v1', read(root, WIRE_VECTOR_PATH))
  }
  equalHex(emitSubstrate.specHash, PEERIT_PROFILE_FINAL_HIVERELAY_WIRE_TUPLE_V1.specHash, 'HiveRelay WIRE spec')
  equalHex(emitSubstrate.abiHash, PEERIT_PROFILE_FINAL_HIVERELAY_WIRE_TUPLE_V1.abiHash, 'HiveRelay WIRE ABI')
  equalHex(emitSubstrate.vectorSetHash, PEERIT_PROFILE_FINAL_HIVERELAY_WIRE_TUPLE_V1.vectorSetHash, 'HiveRelay WIRE vectors')
  return Object.freeze({
    emitSubstrate,
    readSubstrates: Object.freeze([emitSubstrate]),
    profileSpecHash,
    profileAbiHash,
    profileVectorSetHash,
    validatorArtifactHash,
    validatorVectorSetHash,
    availabilityPolicyHash: availabilityHash,
    legacySourceSetHash: legacySourceReconstructionHash()
  })
}

function expectedReleasePublicKey (root) {
  const config = JSON.parse(read(root, 'deploy/web-release.json').toString('utf8'))
  return exactHex32(config.pinnedReleaseKey, 'deploy/web-release.json pinnedReleaseKey')
}

function assertKey (publicKey, root) {
  const derived = bytesToHex(publicKey)
  const expected = expectedReleasePublicKey(root)
  if (derived !== expected) {
    fail('release signing seed does not derive the repository-pinned release public key', 'PEERIT_PRODUCTION_CEREMONY_KEY_MISMATCH')
  }
}

function sequence12Hashes (root, publicKey, acceptedHashes) {
  const appBytes = read(root, 'web/peerit-app-artifact-v1.json')
  const webBytes = read(root, 'web/peerit-web-assets-v1.cenc')
  let app
  try { app = JSON.parse(appBytes.toString('utf8')) } catch { fail('sequence 12 app artifact is not JSON') }
  const manifest = decodePeeritWebAssetManifestV1(webBytes)
  const appHash = hashPeeritAppArtifactV1(appBytes)
  const webHash = hashPeeritWebAssetManifestV1(webBytes)
  if (app?.schema !== 'peerit-app-artifact-v1' || app.releaseSequence !== 12 ||
      app.releaseKey !== bytesToHex(publicKey) || app.productionPinHistory !== null ||
      manifest.releaseSequence !== 12n || manifest.recommendedBootstrapHashes.length !== 0 ||
      !bytesEqual(manifest.appArtifactHash, appHash)) {
    fail('checked sequence 12 app/Web artifacts do not form the accepted pre-ceremony closure')
  }
  equalHex(appHash, acceptedHashes.app, 'sequence 12 app artifact')
  equalHex(webHash, acceptedHashes.web, 'sequence 12 WebAssetManifestV1')
  return { appHash, webHash }
}

function commonPin (bindings, publicKey) {
  return {
    version: 1,
    profileId: PEERIT_PROFILE_ID,
    emitSubstrate: bindings.emitSubstrate,
    readSubstrates: bindings.readSubstrates,
    profileSpecHash: bindings.profileSpecHash,
    profileAbiHash: bindings.profileAbiHash,
    profileVectorSetHash: bindings.profileVectorSetHash,
    validatorArtifactHash: bindings.validatorArtifactHash,
    validatorVectorSetHash: bindings.validatorVectorSetHash,
    availabilityPolicyHash: bindings.availabilityPolicyHash,
    pinHistoryRetentionDays: RELEASE_CONTROL_LIMIT.PIN_HISTORY_RETENTION_DAYS,
    legacySourceSetHash: bindings.legacySourceSetHash,
    migrationStage: PEERIT_MIGRATION_STAGE.LIVE_DUAL_READ,
    migrationTransitionEvidenceHash: null,
    legacyImportMode: 0,
    legacyReadMode: 0,
    legacyCutoffHash: null,
    migrationGenesisRecordId: null,
    cutoffActivationReleaseSequence: null,
    legacyRetirementEvidenceHash: null,
    legacyRetirementActivationReleaseSequence: null,
    releaseAuthoritySequence: 0n,
    releaseAuthorityPublicKey: publicKey,
    releaseAuthorityKeyId: releaseAuthorityKeyId(publicKey),
    authorityTransitionHash: null
  }
}

function appendSignedEntry (state, pinValue, issuedUnixMillis, privateKey) {
  const pin = signPin(pinValue, privateKey)
  const pinBytes = encodePeeritHiveRelayProfilePinV1(pin)
  const checkpoint = signCheckpoint({
    version: 1,
    checkpointSequence: pin.releaseSequence,
    previousCheckpointHash: state.checkpoints.length
      ? pinHistoryCheckpointHash(state.checkpoints[state.checkpoints.length - 1])
      : null,
    pinHash: profilePinHash(pinBytes),
    previousPinHash: pin.previousPinHash,
    issuedUnixMillis,
    releaseAuthoritySequence: pin.releaseAuthoritySequence,
    releaseAuthorityKeyId: pin.releaseAuthorityKeyId
  }, privateKey)
  state.pins.push(pinBytes)
  state.checkpoints.push(encodePeeritPinHistoryCheckpointV1(checkpoint))
}

async function verifyBundle (bundleBytes) {
  const decoded = decodePeeritPinHistoryBundleV1(bundleBytes)
  const pins = decoded.pins.map(decodePeeritHiveRelayProfilePinV1)
  const verified = await verifyPeeritPinHistoryBundleV1(bundleBytes, {
    crypto: nodeCrypto(),
    expectedPins: pins.map(canonicalExpectedPinProjection)
  })
  return { decoded, pins, verified }
}

function bindingMetadata (bindings) {
  const hash = value => bytesToHex(value)
  return {
    profileSpecHash: hash(bindings.profileSpecHash),
    profileAbiHash: hash(bindings.profileAbiHash),
    profileVectorSetHash: hash(bindings.profileVectorSetHash),
    validatorArtifactHash: hash(bindings.validatorArtifactHash),
    validatorVectorSetHash: hash(bindings.validatorVectorSetHash),
    availabilityPolicyHash: hash(bindings.availabilityPolicyHash),
    legacySourceSetHash: hash(bindings.legacySourceSetHash),
    hiveRelayWireTuple: {
      specHash: hash(bindings.emitSubstrate.specHash),
      abiHash: hash(bindings.emitSubstrate.abiHash),
      vectorSetHash: hash(bindings.emitSubstrate.vectorSetHash)
    }
  }
}

export function productionAuthorityModuleSourceV1 (publicKey, genesisPinHash) {
  const keyHex = bytesToHex(publicKey)
  const genesisHex = bytesToHex(genesisPinHash)
  return `// Peerit's immutable production release trust root.\n// Generated only by scripts/production-pin-history-ceremony.mjs prepare.\n\nimport { hexToBytes } from './release-control-primitives.mjs'\n\nconst PUBLIC_KEY = '${keyHex}'\nconst GENESIS_PIN_HASH = '${genesisHex}'\n\nexport const PEERIT_PRODUCTION_RELEASE_AUTHORITY_V1 = Object.freeze({\n  get publicKey () { return hexToBytes(PUBLIC_KEY, 32, 'production release authority public key') },\n  get genesisPinHash () { return hexToBytes(GENESIS_PIN_HASH, 32, 'production genesis pin hash') }\n})\n\nexport const PEERIT_PRODUCTION_PIN_HISTORY_META = 'peerit-production-pin-history'\nexport const PEERIT_PRODUCTION_PIN_HISTORY_PATH = '/peerit-production-pin-history-v1.cenc'\n`
}

export async function prepareProductionPinHistoryPrefixV1 (options = {}) {
  const root = resolve(options.root || ROOT)
  const { privateKey, publicKey } = signingKey(options.seedHex)
  assertKey(publicKey, root)
  const bindings = deriveProductionPinBindingsV1(root)
  const acceptedHashes = options.fixtureOnly === true
    ? {
        app: exactHex32(options.acceptedSequence12AppHash, 'fixture sequence 12 app hash'),
        web: exactHex32(options.acceptedSequence12WebHash, 'fixture sequence 12 Web hash')
      }
    : {
        app: PEERIT_ACCEPTED_SEQUENCE_12_APP_HASH,
        web: PEERIT_ACCEPTED_SEQUENCE_12_WEB_HASH
      }
  const sequence12 = sequence12Hashes(root, publicKey, acceptedHashes)
  const state = { pins: [], checkpoints: [] }
  for (let sequence = 0; sequence <= PEERIT_PRODUCTION_PREFIX_TERMINAL_SEQUENCE; sequence++) {
    const terminal = sequence === 12
    appendSignedEntry(state, {
      ...commonPin(bindings, publicKey),
      releaseSequence: BigInt(sequence),
      previousPinHash: state.pins.length ? profilePinHash(state.pins[state.pins.length - 1]) : null,
      recommendedBootstrapHashes: [],
      appArtifactHash: terminal ? sequence12.appHash : placeholderHash(sequence, 'app-artifact'),
      webAssetManifestHash: terminal ? sequence12.webHash : placeholderHash(sequence, 'web-asset-manifest')
    }, BigInt(sequence), privateKey)
  }
  const bundleBytes = encodePeeritPinHistoryBundleV1({ version: 1, ...state })
  const checked = await verifyBundle(bundleBytes)
  const genesisPinHash = profilePinHash(state.pins[0])
  const metadata = {
    schema: PEERIT_PRODUCTION_CEREMONY_SCHEMA_V1,
    phase: 'prefix-0-through-12',
    releaseAuthorityPublicKey: bytesToHex(publicKey),
    genesisPinHash: bytesToHex(genesisPinHash),
    terminalReleaseSequence: 12,
    terminalPinHash: bytesToHex(checked.verified.terminalPinHash),
    bundleHash: bytesToHex(pinHistoryBundleHash(bundleBytes)),
    bindings: bindingMetadata(bindings),
    reconstructionDisclosure: {
      exactArtifactSequence: 12,
      exactAppArtifactHash: acceptedHashes.app,
      exactWebAssetManifestHash: acceptedHashes.web,
      placeholderSequences: '0..11',
      placeholderFields: ['appArtifactHash', 'webAssetManifestHash'],
      placeholderDomain: PREPRODUCTION_PLACEHOLDER_DOMAIN,
      placeholderPayloadRecipe: 'UTF8("release-sequence:<decimal>:<app-artifact|web-asset-manifest>")',
      checkpointIssuedUnixMillis: 'synthetic release sequence value; not historical wall-clock evidence',
      legacySourceSetDisclosure: 'historical source set unavailable; deterministic LIVE_DUAL_READ/no-cutoff reconstruction sentinel',
      legacySourceSetDomain: LEGACY_SOURCE_RECONSTRUCTION_DOMAIN
    }
  }
  return Object.freeze({
    bundleBytes,
    metadata,
    authorityModuleSource: productionAuthorityModuleSourceV1(publicKey, genesisPinHash)
  })
}

export function assertProductionPredecessorBindingsV1 (pin, bindings, successorSequence) {
  if (!Number.isSafeInteger(successorSequence) ||
      successorSequence < PEERIT_PRODUCTION_CEREMONY_MIN_RELEASE_SEQUENCE ||
      successorSequence > PEERIT_PRODUCTION_CEREMONY_MAX_RELEASE_SEQUENCE) {
    fail('successor release sequence is outside the production ceremony window')
  }
  for (const field of [
    'profileSpecHash', 'profileAbiHash', 'profileVectorSetHash',
    'validatorArtifactHash', 'validatorVectorSetHash', 'availabilityPolicyHash',
    'legacySourceSetHash'
  ]) {
    if (bytesEqual(pin[field], bindings[field])) continue
    const exactCspSafeValidatorTransition =
      field === 'validatorArtifactHash' &&
      successorSequence === PEERIT_CSP_SAFE_VALIDATOR_TRANSITION_RELEASE_SEQUENCE &&
      pin.releaseSequence === BigInt(successorSequence - 1) &&
      bytesToHex(pin.validatorArtifactHash) === PEERIT_SEQUENCE_18_VALIDATOR_ARTIFACT_HASH &&
      bytesToHex(bindings.validatorArtifactHash) === PEERIT_SEQUENCE_19_VALIDATOR_ARTIFACT_HASH
    if (!exactCspSafeValidatorTransition) fail(`prefix terminal ${field} is stale`)
  }
  if (!bytesEqual(pin.emitSubstrate.specHash, bindings.emitSubstrate.specHash) ||
      !bytesEqual(pin.emitSubstrate.abiHash, bindings.emitSubstrate.abiHash) ||
      !bytesEqual(pin.emitSubstrate.vectorSetHash, bindings.emitSubstrate.vectorSetHash) ||
      pin.readSubstrates.length !== 1 || bindings.readSubstrates.length !== 1 ||
      !bytesEqual(pin.readSubstrates[0].specHash, bindings.readSubstrates[0].specHash) ||
      !bytesEqual(pin.readSubstrates[0].abiHash, bindings.readSubstrates[0].abiHash) ||
      !bytesEqual(pin.readSubstrates[0].vectorSetHash, bindings.readSubstrates[0].vectorSetHash)) {
    fail('prefix terminal substrate does not match the repository')
  }
}

function assertTerminalBindings (pin, bindings, publicKey, successorSequence) {
  assertProductionPredecessorBindingsV1(pin, bindings, successorSequence)
  if (!bytesEqual(pin.releaseAuthorityPublicKey, publicKey)) {
    fail('prefix terminal authority does not match the repository')
  }
}

function parseAppArtifact (bytes, sequence, publicKey, bootstrapSha256, discoveryKey) {
  let app
  try { app = JSON.parse(Buffer.from(bytes).toString('utf8')) } catch { fail('predicted app artifact is not JSON') }
  if (app?.schema !== 'peerit-app-artifact-v1' || app.releaseSequence !== sequence ||
      app.releaseKey !== bytesToHex(publicKey) ||
      app.productionPinHistory !== '/peerit-production-pin-history-v1.cenc' ||
      app.peeritSeedBootstrap !== PEERIT_SEED_BOOTSTRAP_PATH ||
      app.peeritSeedBootstrapSha256 !== bootstrapSha256 ||
      app.peeritSeedDiscoveryAuthorityPublicKey !== discoveryKey ||
      app.peeritSeedBootstrapReleaseSequence !== sequence) {
    fail('predicted app artifact does not bind the exact release, pin history, and signed seed bootstrap')
  }
  return app
}

export async function finalizeProductionPinHistoryV1 (options = {}) {
  const root = resolve(options.root || ROOT)
  const sequence = Number(options.releaseSequence)
  if (!Number.isSafeInteger(sequence) ||
      sequence < PEERIT_PRODUCTION_CEREMONY_MIN_RELEASE_SEQUENCE ||
      sequence > PEERIT_PRODUCTION_CEREMONY_MAX_RELEASE_SEQUENCE) {
    fail(`finalization releaseSequence must be between ${PEERIT_PRODUCTION_CEREMONY_MIN_RELEASE_SEQUENCE} and ${PEERIT_PRODUCTION_CEREMONY_MAX_RELEASE_SEQUENCE}`)
  }
  const issuedUnixMillis = typeof options.issuedUnixMillis === 'bigint'
    ? options.issuedUnixMillis
    : BigInt(options.issuedUnixMillis)
  if (issuedUnixMillis < 0n) fail('issuedUnixMillis must be an unsigned integer')
  const { privateKey, publicKey } = signingKey(options.seedHex)
  assertKey(publicKey, root)
  const bindings = deriveProductionPinBindingsV1(root)
  const prefixBytes = exactBytes(options.prefixBundleBytes, 'prefix bundle')
  const checked = await verifyBundle(prefixBytes)
  const terminal = checked.pins[checked.pins.length - 1]
  if (terminal.releaseSequence !== BigInt(sequence - 1) || checked.pins[0].releaseSequence !== 0n ||
      !bytesEqual(checked.pins[0].releaseAuthorityPublicKey, publicKey)) {
    fail(`input bundle must be a contiguous authority-matched 0..${sequence - 1} prefix`)
  }
  assertTerminalBindings(terminal, bindings, publicKey, sequence)

  const bootstrapBytes = exactBytes(options.seedBootstrapBytes, 'seed bootstrap')
  const canonicalBootstrap = encodePeeritSeedBootstrapV1(bootstrapBytes)
  if (!bytesEqual(bootstrapBytes, canonicalBootstrap)) fail('seed bootstrap bytes are not canonical')
  const bootstrap = JSON.parse(Buffer.from(bootstrapBytes).toString('utf8'))
  const discoveryKey = exactHex32(bootstrap?.payload?.authorityPublicKey, 'seed discovery authority')
  const bootstrapSha256 = sha256Hex(bootstrapBytes)
  if (bootstrap.payload.bootstrapSequence !== 0 ||
      bootstrap.payload.previousBootstrapHash !== null ||
      options.previousBootstrapHash != null) {
    fail('terminal release bootstrap must be a distinct source sequence 0 with no predecessor')
  }
  await verifyPeeritSeedBootstrapV1(bootstrapBytes, {
    authorityPublicKey: discoveryKey,
    releaseSequence: sequence,
    expectedArtifactHash: bootstrapSha256,
    previousBootstrapHash: null,
    now: options.bootstrapVerificationTime == null
      ? bootstrap.payload.issuedAt
      : Number(options.bootstrapVerificationTime)
  })
  const bootstrapDomainHash = hashPeeritBootstrapV1(bootstrapBytes)

  const appBytes = exactBytes(options.appArtifactBytes, 'predicted app artifact')
  parseAppArtifact(appBytes, sequence, publicKey, bootstrapSha256, discoveryKey)
  const appHash = hashPeeritAppArtifactV1(appBytes)
  const webBytes = exactBytes(options.webAssetManifestBytes, 'predicted WebAssetManifestV1')
  const web = decodePeeritWebAssetManifestV1(webBytes)
  if (web.releaseSequence !== BigInt(sequence) || !bytesEqual(web.appArtifactHash, appHash) ||
      web.recommendedBootstrapHashes.length !== 1 ||
      !bytesEqual(web.recommendedBootstrapHashes[0], bootstrapDomainHash)) {
    fail('predicted WebAssetManifestV1 does not bind the exact app artifact and singleton seed bootstrap hash')
  }
  const bootstrapAsset = web.assets.find(asset => asset.path === PEERIT_SEED_BOOTSTRAP_PATH)
  if (!bootstrapAsset || bootstrapAsset.byteLength !== BigInt(bootstrapBytes.byteLength) ||
      !bytesEqual(bootstrapAsset.assetHash, blake2b256(bootstrapBytes))) {
    fail('predicted WebAssetManifestV1 omits or changes the exact seed bootstrap asset')
  }
  const webHash = hashPeeritWebAssetManifestV1(webBytes)
  const state = {
    pins: [...checked.decoded.pins],
    checkpoints: [...checked.decoded.checkpoints]
  }
  appendSignedEntry(state, {
    ...commonPin(bindings, publicKey),
    releaseSequence: BigInt(sequence),
    previousPinHash: profilePinHash(state.pins[state.pins.length - 1]),
    recommendedBootstrapHashes: [bootstrapDomainHash],
    appArtifactHash: appHash,
    webAssetManifestHash: webHash
  }, issuedUnixMillis, privateKey)
  const bundleBytes = encodePeeritPinHistoryBundleV1({ version: 1, ...state })
  const final = await verifyBundle(bundleBytes)
  const metadata = {
    schema: PEERIT_PRODUCTION_CEREMONY_SCHEMA_V1,
    phase: `finalized-${sequence}`,
    releaseAuthorityPublicKey: bytesToHex(publicKey),
    genesisPinHash: bytesToHex(profilePinHash(state.pins[0])),
    terminalReleaseSequence: sequence,
    terminalPinHash: bytesToHex(final.verified.terminalPinHash),
    bundleHash: bytesToHex(pinHistoryBundleHash(bundleBytes)),
    bindings: bindingMetadata(bindings),
    seedBootstrap: {
      path: PEERIT_SEED_BOOTSTRAP_PATH,
      sha256: bootstrapSha256,
      domainHash: bytesToHex(bootstrapDomainHash),
      discoveryAuthorityPublicKey: discoveryKey,
      bootstrapSequence: 0,
      previousBootstrapHash: null
    },
    appArtifactHash: bytesToHex(appHash),
    webAssetManifestHash: bytesToHex(webHash)
  }
  return Object.freeze({ bundleBytes, metadata })
}

function arg (name, fallback = null) {
  const index = process.argv.indexOf(name)
  return index >= 0 && process.argv[index + 1] ? process.argv[index + 1] : fallback
}

function requiredArg (name) {
  const value = arg(name)
  if (!value) fail(`${name} is required`)
  return value
}

function atomicWrite (path, bytes) {
  path = resolve(path)
  mkdirSync(dirname(path), { recursive: true })
  const temporary = `${path}.tmp-${process.pid}`
  writeFileSync(temporary, bytes)
  renameSync(temporary, path)
}

function metadataBytes (metadata) {
  return Buffer.from(JSON.stringify(metadata, null, 2) + '\n')
}

async function main () {
  const command = process.argv[2]
  const root = resolve(arg('--root', ROOT))
  const seedHex = releaseSigningSeedFromEnvironment()
  if (command === 'prepare') {
    const result = await prepareProductionPinHistoryPrefixV1({ root, seedHex })
    atomicWrite(requiredArg('--out'), result.bundleBytes)
    atomicWrite(requiredArg('--metadata'), metadataBytes(result.metadata))
    atomicWrite(resolve(root, 'js/substrate/production-release-authority.mjs'), result.authorityModuleSource)
    console.log('production-pin-history-ceremony: prepared signed 0..12 prefix and compiled public trust root')
    return
  }
  if (command === 'finalize') {
    const result = await finalizeProductionPinHistoryV1({
      root,
      seedHex,
      releaseSequence: Number(requiredArg('--sequence')),
      issuedUnixMillis: BigInt(requiredArg('--issued-unix-millis')),
      prefixBundleBytes: readFileSync(requiredArg('--prefix')),
      seedBootstrapBytes: readFileSync(requiredArg('--seed-bootstrap')),
      appArtifactBytes: readFileSync(requiredArg('--app-artifact')),
      webAssetManifestBytes: readFileSync(requiredArg('--web-asset-manifest'))
    })
    atomicWrite(requiredArg('--out'), result.bundleBytes)
    atomicWrite(requiredArg('--metadata'), metadataBytes(result.metadata))
    console.log(`production-pin-history-ceremony: finalized canonical production pin history through sequence ${result.metadata.terminalReleaseSequence}`)
    return
  }
  fail('usage: production-pin-history-ceremony.mjs <prepare|finalize> [options]')
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch(error => {
    console.error(`production-pin-history-ceremony: ${error.message}`)
    process.exitCode = 1
  })
}
