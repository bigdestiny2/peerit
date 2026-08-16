// Local-only shipped Seq29 publication/recovery proof. This starts two
// production Hiverelay runtimes on loopback, but the browser surface under
// test receives only the release-bound PUT/GET/APPEND/READ control artifact.
// INBOX.CREATE is confined to fixture setup and its write capability is wiped
// before the authenticated browser runtime is assembled.
import assert from 'node:assert/strict'
import { createHash, randomBytes } from 'node:crypto'
import { execFile } from 'node:child_process'
import fs from 'node:fs'
import fsp from 'node:fs/promises'
import https from 'node:https'
import net from 'node:net'
import path from 'node:path'
import { promisify } from 'node:util'
import { fileURLToPath, pathToFileURL } from 'node:url'
import sodium from 'sodium-universal'
import { availabilityPolicyHash } from '../js/substrate/availability-policy.mjs'
import { decodeBlindClientBrowserManifestV1 } from '../js/substrate/blind-client-browser-verifier.mjs'
import {
  assemblePeeritBrowserRuntimeAuthorityNodeTestV1,
  getVerifiedPeeritBrowserRuntimeAssembly,
  PEERIT_BROWSER_RUNTIME_ASSET_PATHS
} from '../js/substrate/browser-runtime-authority.mjs'
import { genKeyPair, ready as cryptoReady, signBytes } from '../js/crypto.js'
import { createIdentityStore, memoryKv } from '../js/identity-store.js'
import {
  canonicalPeeritLimitedPublicInboxJsonV1,
  PEERIT_LIMITED_PUBLIC_INBOX_BOOTSTRAP_DOMAIN_V1
} from '../js/substrate/inbox-topic-v1.mjs'
import {
  peeritLimitedCellPutProfileSourceV1,
  PEERIT_LIMITED_CELL_PUT_PROFILE_ID_V1
} from '../js/substrate/limited-cell-put-profile.mjs'
import { createPeeritLocalIdentityV1 } from '../js/substrate/local-identity.js'
import {
  createMemoryJournalState,
  createMemoryPeeritJournal
} from '../js/substrate/peerit-journal.js'
import { createPeeritProductRuntimeV1 } from '../js/substrate/peerit-product-runtime.js'
import { createPeeritSubstrateSync } from '../js/substrate/peerit-substrate-sync.js'
import {
  POW_ISSUANCE_V1_SCHEME_ID,
  createPowIssuanceV1SpendProvider
} from '../js/substrate/pow-issuance-spend-provider.mjs'
import {
  createPeeritSeq29PublicInboxBootCoordinatorV1
} from '../js/substrate/public-inbox-boot-coordinator.mjs'
import {
  asciiBytes,
  concatBytes
} from '../js/substrate/release-control-primitives.mjs'
import {
  encodePeeritHiveRelayProfilePinV1,
  profilePinHash
} from '../js/substrate/release-control-codec.mjs'
import {
  hashPeeritProfileAbi,
  hashPeeritProfileSpec,
  hashPeeritProfileVectorSet
} from '../js/substrate/profile-artifact-codec.mjs'
import {
  createPeeritSeedBootstrapV1,
  encodePeeritSeedBootstrapV1
} from '../js/substrate/seed-bootstrap-v1.mjs'
import {
  hashPeeritValidatorArtifactV1,
  hashPeeritValidatorVectorSetV1
} from '../js/substrate/validator-artifact.mjs'
import {
  encodePeeritWebAssetManifestV1,
  hashPeeritAppArtifactV1,
  hashPeeritBootstrapV1,
  hashPeeritWebAssetManifestV1
} from '../js/substrate/web-asset-manifest.mjs'
import {
  buildReleaseControlFixture,
  createNodeReleaseControlCrypto
} from '../scripts/release-control-fixture.mjs'
import * as browserControl from '../vendor/hiverelay-blind-client-v1/blind-client-control-v1.mjs'

process.env.PEERIT_BROWSER_RUNTIME_NODE_TEST = '1'

const execFileAsync = promisify(execFile)
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const HIVERELAY_ROOT = process.env.HIVERELAY_V1_INTEGRATION_ROOT ||
  path.resolve(ROOT, '..', '..', '00-core', 'hiverelay')
const hiverelay = (...parts) => pathToFileURL(path.join(HIVERELAY_ROOT, ...parts)).href
const sourcePresent = await fsp.stat(path.join(
  HIVERELAY_ROOT, 'packages', 'blind-protocol', 'index.js')).then(() => true, () => false)
if (!sourcePresent) {
  console.log('peerit seq29 shipped publication/recovery: SKIP (Hiverelay source tree absent)')
  process.exit(0)
}

const protocol = await import(hiverelay('packages', 'blind-protocol', 'index.js'))
const {
  ADMISSION_CONFORMANCE_CLASS,
  FAMILY,
  INBOX_FRAME_CLASS,
  OPERATION,
  PROTOCOL,
  RESULT_SIGNATURE_DOMAIN_ID,
  TRANSPORT_SUPPORT,
  admissionParametersHash,
  admissionParametersV1,
  blindServiceDescriptorV1,
  decodeCanonical,
  encodeCanonical,
  hashStoreFormat,
  resultSignaturePayload,
  serviceDescriptorHash
} = protocol
const { loadDaemonBootstrapConfig } = await import(hiverelay(
  'packages', 'blind-daemon', 'bootstrap-config.js'))
const {
  PRODUCTION_DESCRIBE_CELL_INBOX_OPERATION_BITS,
  assembleProductionBlindDaemon,
  loadProductionRuntimeConfig
} = await import(hiverelay('packages', 'blind-daemon', 'production-runtime.js'))
const { daemonOperationProfile, deriveAdmissionCost } = await import(hiverelay(
  'packages', 'blind-daemon', 'operation-catalog.js'))
const {
  PowIssuanceV1AdmissionAdapter,
  createPowIssuanceV1AdapterResolver
} = await import(hiverelay(
  'packages', 'blind-daemon', 'pow-issuance-v1', 'admission-adapter.js'))
const { createPowIssuanceV1Issuer } = await import(hiverelay(
  'packages', 'blind-daemon', 'pow-issuance-v1', 'issuer-service.js'))
const { powIssuanceV1IssuerKeyCommitment } = await import(hiverelay(
  'packages', 'blind-daemon', 'pow-issuance-v1', 'token-codec.js'))
const {
  POW_DRILL_PUBLIC_ROLE_BITS,
  POW_DRILL_SIX_HOURS_MILLIS
} = await import(hiverelay(
  'packages', 'blind-daemon', 'test', 'pow-issuance-v1-drill-fixture.js'))
const { bindDurability, descriptorValue, parameterValue } = await import(hiverelay(
  'packages', 'blind-daemon', 'test', 'coordinator-fixtures.js'))
const { BlindEdge } = await import(hiverelay('packages', 'blind-edge', 'server.js'))
const { createInboxReplica, destroyInboxWriteCapability } = await import(hiverelay(
  'packages', 'blind-client', 'inbox.js'))
const { encodeUnaryRequest, decodeUnaryResponse } = await import(hiverelay(
  'packages', 'blind-client', 'wire.js'))
const {
  createBlindBoundaryScratch,
  removeBlindBoundaryScratch
} = await import(hiverelay('test', 'blind-boundary-scratch.js'))

const hex = value => Buffer.from(value).toString('hex')
const profilePins = Object.freeze([1, 2, 3, 4].map(protocolId => Object.freeze({
  protocolId,
  major: 1,
  minimumMinor: 0,
  profileHash: new Uint8Array(32).fill(0x0a)
})))
const transportPins = Object.freeze([Object.freeze({
  transportId: 1,
  transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP,
  transportProfileHash: new Uint8Array(32).fill(0x0b)
})])

function signCanonical (codec, value, domainId, secretKey) {
  value.signature = Buffer.alloc(sodium.crypto_sign_BYTES)
  const placeholder = encodeCanonical(codec, value)
  const unsigned = placeholder.subarray(0, placeholder.byteLength - sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(
    value.signature, resultSignaturePayload(domainId, unsigned), secretKey)
  return encodeCanonical(codec, value)
}

async function privateFile (file, bytes) {
  await fsp.writeFile(file, bytes, { mode: 0o600 })
  await fsp.chmod(file, 0o600)
}

function costRow (familyId, operationId, request, authenticatedState) {
  const cost = deriveAdmissionCost(
    daemonOperationProfile(familyId, operationId), request, authenticatedState)
  return Object.freeze({
    familyId,
    operationId,
    resourceClass: cost.resourceClass,
    leaseClass: cost.leaseClass,
    costUnits: 10n
  })
}

function drillResourceCosts () {
  const rows = []
  for (const sizeClass of [1, 2]) {
    rows.push(costRow(FAMILY.CELL, OPERATION.CELL.PUT, {
      sizeClass,
      leaseClass: 2
    }))
  }
  const stored = Object.freeze({
    inboxRetentionClass: 3,
    inboxFrameClassBits: 3
  })
  rows.push(costRow(FAMILY.INBOX, OPERATION.INBOX.CREATE, {
    retentionClass: 3,
    frameClassBits: 3,
    leaseClass: 4
  }))
  rows.push(costRow(FAMILY.INBOX, OPERATION.INBOX.APPEND,
    { frameClass: 1 }, stored))
  rows.push(costRow(FAMILY.INBOX, OPERATION.INBOX.READ, {}, {
    canonicalResultBytes: 4096 + 64 * (41 + INBOX_FRAME_CLASS[2])
  }))
  return rows.sort((left, right) => {
    for (const field of ['familyId', 'operationId', 'resourceClass', 'leaseClass']) {
      if (left[field] !== right[field]) return left[field] - right[field]
    }
    return 0
  })
}

async function relayFixture ({
  relayId,
  issuerKey,
  issuerPort,
  directory,
  marker,
  edgePort
}) {
  const storeRoot = path.join(directory, 'store')
  const inboxStoreRoot = path.join(directory, 'inbox-store')
  const replayRoot = path.join(directory, 'private-ipc-replay')
  await Promise.all([
    fsp.mkdir(storeRoot, { mode: 0o700 }),
    fsp.mkdir(inboxStoreRoot, { mode: 0o700 }),
    fsp.mkdir(replayRoot, { mode: 0o700 })
  ])
  const relayPublicKey = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const relaySecretKey = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(relayPublicKey, relaySecretKey)
  const currentEpoch = Math.floor(Date.now() / POW_DRILL_SIX_HOURS_MILLIS)
  const issuanceUrl = relayId === 'dal-1'
    ? 'https://relay-dal.p2phiverelay.xyz:8443/'
    : 'https://relay-syd.p2phiverelay.xyz:8443/'
  const parameters = parameterValue(relayPublicKey, {
    profileId: PEERIT_LIMITED_CELL_PUT_PROFILE_ID_V1,
    schemeId: POW_ISSUANCE_V1_SCHEME_ID,
    conformanceClass: ADMISSION_CONFORMANCE_CLASS.OPEN,
    roleBits: POW_DRILL_PUBLIC_ROLE_BITS,
    verifierKey: Buffer.alloc(0),
    resourceCosts: drillResourceCosts(),
    tokenMaxBytes: 512,
    issuanceUrl: Buffer.from(issuanceUrl),
    issuerRelayKey: powIssuanceV1IssuerKeyCommitment(issuerKey),
    validFromEpoch: currentEpoch,
    expiresEpoch: currentEpoch + 4
  })
  const canonicalParameters = signCanonical(
    admissionParametersV1, parameters,
    RESULT_SIGNATURE_DOMAIN_ID.ADMISSION_PARAMETERS, relaySecretKey)
  const parameterHash = admissionParametersHash(canonicalParameters)
  const descriptor = descriptorValue({
    relayPublicKey: Buffer.from(relayPublicKey),
    storeId: Buffer.alloc(32, marker),
    enabledOperationBits: PRODUCTION_DESCRIBE_CELL_INBOX_OPERATION_BITS,
    issuedEpoch: currentEpoch - 1,
    expiresEpoch: currentEpoch + 3,
    capacityBand: 0
  })
  descriptor.endpoints = [descriptor.endpoints[0]]
  descriptor.endpoints[0].endpointId = 1
  descriptor.endpoints[0].transportId = 1
  descriptor.endpoints[0].roleBits = POW_DRILL_PUBLIC_ROLE_BITS
  descriptor.endpoints[0].canonicalUrl = Buffer.from(
    `https://127.0.0.1:${edgePort}/api/blind/v1/describe`)
  descriptor.protocols = [1, 2, 3, 4].map(protocolId => ({
    ...descriptor.protocols[0],
    protocolId
  }))
  descriptor.admissionProfiles = [{
    profileId: PEERIT_LIMITED_CELL_PUT_PROFILE_ID_V1,
    schemeId: POW_ISSUANCE_V1_SCHEME_ID,
    conformanceClass: ADMISSION_CONFORMANCE_CLASS.OPEN,
    roleBits: POW_DRILL_PUBLIC_ROLE_BITS,
    parameterUrl: null,
    parameterHash: Buffer.from(parameterHash)
  }]
  const storeAuthority = await fsp.readFile(path.join(
    HIVERELAY_ROOT, 'packages', 'blind-protocol',
    'hiverelay-blind-store-format-authority-v1.draft.cenc'))
  descriptor.durability.storeFormatMajor = 1
  descriptor.durability.storeFormatMinor = 2
  descriptor.durability.storeFormatHash = hashStoreFormat(storeAuthority)
  descriptor.build.storeFormatHash = Buffer.from(descriptor.durability.storeFormatHash)
  bindDurability(descriptor)
  const genesisBytes = signCanonical(
    blindServiceDescriptorV1, descriptor,
    RESULT_SIGNATURE_DOMAIN_ID.DESCRIPTOR, relaySecretKey)
  const active = decodeCanonical(blindServiceDescriptorV1, genesisBytes, { copyBytes: true })
  active.descriptorSequence = 1n
  active.previousDescriptorHash = serviceDescriptorHash(genesisBytes)
  active.issuedEpoch = currentEpoch
  active.expiresEpoch = currentEpoch + 4
  active.descriptorNonce = Buffer.alloc(32, marker + 1)
  const activeBytes = signCanonical(
    blindServiceDescriptorV1, active,
    RESULT_SIGNATURE_DOMAIN_ID.DESCRIPTOR, relaySecretKey)
  const descriptorFile = path.join(directory, 'descriptor.bin')
  const successorFile = path.join(directory, 'descriptor-successor.bin')
  const parametersFile = path.join(directory, 'admission.bin')
  const secretFile = path.join(directory, 'relay-secret.bin')
  const manifestKeyFile = path.join(directory, 'store-manifest-key.bin')
  const fenceFile = path.join(directory, 'owner-fence-hash.bin')
  const cursorKeyFile = path.join(directory, 'inbox-cursor-key.bin')
  await Promise.all([
    privateFile(descriptorFile, genesisBytes),
    privateFile(successorFile, activeBytes),
    privateFile(parametersFile, canonicalParameters),
    privateFile(secretFile, relaySecretKey),
    privateFile(manifestKeyFile, Buffer.alloc(32, marker + 2)),
    privateFile(fenceFile, Buffer.alloc(32, marker + 3)),
    privateFile(cursorKeyFile, Buffer.alloc(32, marker + 4))
  ])
  relaySecretKey.fill(0)
  const uid = process.getuid()
  const gid = process.getgid()
  const environment = {
    ...process.env,
    HIVERELAY_BLIND_UNARY_SOCKET: path.join(directory, 'ipc', 'unary.sock'),
    HIVERELAY_BLIND_STREAM_SOCKET: path.join(directory, 'ipc', 'stream.sock'),
    HIVERELAY_BLIND_LAUNCH_TOPOLOGY_HASH: hex(Buffer.alloc(32, marker + 5)),
    HIVERELAY_BLIND_ENDPOINT_IDS: '1',
    HIVERELAY_BLIND_ENDPOINT_SUPPORT_BITS: `1:${TRANSPORT_SUPPORT.DIRECT_HTTP}`,
    HIVERELAY_BLIND_EDGE_UID: String(uid + 1),
    HIVERELAY_BLIND_DAEMON_UID: String(uid),
    HIVERELAY_BLIND_DAEMON_GID: String(gid),
    HIVERELAY_BLIND_SHARED_GID: String(gid),
    HIVERELAY_BLIND_DESCRIPTOR_FILES: `${descriptorFile},${successorFile}`,
    HIVERELAY_BLIND_ADMISSION_PARAMETER_FILES: parametersFile,
    HIVERELAY_BLIND_RELAY_SECRET_KEY_FILE: secretFile,
    HIVERELAY_BLIND_STORE_ROOT: storeRoot,
    HIVERELAY_BLIND_PRIVATE_IPC_REPLAY_ROOT: replayRoot,
    HIVERELAY_BLIND_INBOX_STORE_ROOT: inboxStoreRoot,
    HIVERELAY_BLIND_INBOX_CURSOR_KEY_FILE: cursorKeyFile,
    HIVERELAY_BLIND_STORE_MANIFEST_KEY_FILE: manifestKeyFile,
    HIVERELAY_BLIND_OWNER_FENCE_TOKEN_HASH_FILE: fenceFile,
    HIVERELAY_BLIND_MAP_GENERATION: '1',
    HIVERELAY_BLIND_EXPECTED_DESCRIPTOR_SEQUENCE: '1',
    HIVERELAY_BLIND_EXPECTED_DESCRIPTOR_HASH: hex(serviceDescriptorHash(activeBytes))
  }
  return Object.freeze({
    relayId,
    issuanceUrl,
    environment,
    relayPublicKey,
    parameterHash,
    currentEpoch,
    descriptor: active,
    descriptorHash: serviceDescriptorHash(activeBytes),
    unarySocketPath: environment.HIVERELAY_BLIND_UNARY_SOCKET,
    streamSocketPath: environment.HIVERELAY_BLIND_STREAM_SOCKET,
    launchTopologyHash: Buffer.from(environment.HIVERELAY_BLIND_LAUNCH_TOPOLOGY_HASH, 'hex'),
    transportProfileHash: Buffer.from(active.endpoints[0].transportProfileHash)
  })
}

async function ephemeralLoopbackTls (directory) {
  const keyFile = path.join(directory, 'edge-tls-key.pem')
  const certFile = path.join(directory, 'edge-tls-cert.pem')
  await execFileAsync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes',
    '-subj', '/CN=127.0.0.1', '-days', '1',
    '-keyout', keyFile, '-out', certFile
  ], { timeout: 15_000, maxBuffer: 1024 * 1024 })
  await fsp.chmod(keyFile, 0o600)
  return Object.freeze({
    key: await fsp.readFile(keyFile),
    cert: await fsp.readFile(certFile)
  })
}

function reserveLoopbackPort () {
  return new Promise((resolve, reject) => {
    const server = net.createServer()
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port
      server.close(error => error ? reject(error) : resolve(port))
    })
  })
}

function httpsPost (port, route, body) {
  return new Promise((resolve, reject) => {
    const request = https.request({
      host: '127.0.0.1',
      port,
      path: route,
      method: 'POST',
      rejectUnauthorized: false,
      headers: {
        'content-type': PROTOCOL.mediaType,
        'content-length': String(body.byteLength)
      }
    }, response => {
      const chunks = []
      response.on('data', chunk => chunks.push(chunk))
      response.once('error', reject)
      response.once('end', () => resolve({
        statusCode: response.statusCode,
        body: Buffer.concat(chunks)
      }))
    })
    request.once('error', error => {
      const wrapped = new Error(
        `loopback POST https://127.0.0.1:${port}${route}: ${error.message}`,
        { cause: error })
      wrapped.code = error.code
      reject(wrapped)
    })
    request.end(body)
  })
}

function loopbackFetch (url, init = {}) {
  return new Promise((resolve, reject) => {
    const target = new URL(url)
    const headers = {}
    for (const [name, value] of init.headers || []) headers[name] = value
    const request = https.request({
      host: target.hostname,
      port: target.port,
      path: target.pathname,
      method: init.method || 'GET',
      rejectUnauthorized: false,
      headers
    }, response => {
      const chunks = []
      response.on('data', chunk => chunks.push(chunk))
      response.once('error', reject)
      response.once('end', () => {
        const body = Buffer.concat(chunks)
        let offset = 0
        resolve({
          status: response.statusCode,
          headers: {
            get: name => {
              const value = response.headers[String(name).toLowerCase()]
              return value == null ? null : String(value)
            }
          },
          body: {
            getReader: () => ({
              async read () {
                if (offset >= body.byteLength) return { done: true, value: undefined }
                const value = new Uint8Array(body.subarray(offset))
                offset = body.byteLength
                return { done: false, value }
              },
              async cancel () {},
              releaseLock () {}
            })
          }
        })
      })
    })
    request.once('error', error => {
      const wrapped = new Error(
        `loopback ${init.method || 'GET'} ${target.origin}${target.pathname}: ${error.message}`,
        { cause: error })
      wrapped.code = error.code
      reject(wrapped)
    })
    if (init.signal) {
      const abort = () => request.destroy(
        init.signal.reason || new Error('loopback fetch aborted'))
      if (init.signal.aborted) abort()
      else init.signal.addEventListener('abort', abort, { once: true })
    }
    request.end(init.body || null)
  })
}

function memoryStorage () {
  const values = new Map()
  return Object.freeze({
    getItem: key => values.has(key) ? values.get(key) : null,
    setItem: (key, value) => values.set(key, String(value)),
    removeItem: key => values.delete(key)
  })
}

function fileBytes (assetPath) {
  return new Uint8Array(fs.readFileSync(path.join(ROOT, assetPath.slice(1))))
}

function seq29BaseAssets () {
  const output = new Map()
  for (const [name, assetPath] of Object.entries(PEERIT_BROWSER_RUNTIME_ASSET_PATHS)) {
    if (name === 'appArtifact' || name === 'limitedCellGetProfile' ||
        name.startsWith('hiveCellGet')) continue
    output.set(assetPath, fileBytes(assetPath))
  }
  return output
}

function signedRuntimeInputs ({ assets, appArtifactBytes, seedHash, now, fetch }) {
  const releaseFixture = buildReleaseControlFixture()
  const manifestBytes = encodePeeritWebAssetManifestV1({
    version: 1,
    releaseSequence: 29n,
    appArtifactHash: hashPeeritAppArtifactV1(appArtifactBytes),
    recommendedBootstrapHashes: [seedHash],
    assets: [...assets].map(([assetPath, bytes]) => ({
      path: new TextEncoder().encode(assetPath),
      byteLength: BigInt(bytes.byteLength),
      assetHash: protocol.blake2b256(bytes)
    })).sort((left, right) => Buffer.compare(Buffer.from(left.path), Buffer.from(right.path)))
  })
  const hiveManifest = decodeBlindClientBrowserManifestV1(
    assets.get(PEERIT_BROWSER_RUNTIME_ASSET_PATHS.hiveManifest),
    assets.get(PEERIT_BROWSER_RUNTIME_ASSET_PATHS.hiveVendorAuthority))
  const profileSource = assets.get(PEERIT_BROWSER_RUNTIME_ASSET_PATHS.profileSource)
  const profileRegistry = assets.get(PEERIT_BROWSER_RUNTIME_ASSET_PATHS.profileRegistry)
  const profileVectors = assets.get(PEERIT_BROWSER_RUNTIME_ASSET_PATHS.profileVectorManifest)
  const validator = assets.get(PEERIT_BROWSER_RUNTIME_ASSET_PATHS.validatorArtifact)
  const validatorVectors = assets.get(PEERIT_BROWSER_RUNTIME_ASSET_PATHS.validatorVectorManifest)
  const emitSubstrate = {
    specHash: hiveManifest.specHash,
    abiHash: hiveManifest.abiHash,
    vectorSetHash: hiveManifest.vectorSetHash
  }
  const pin = releaseFixture.signPin({
    ...releaseFixture.pins[0],
    emitSubstrate,
    readSubstrates: [emitSubstrate],
    profileSpecHash: hashPeeritProfileSpec(profileSource),
    profileAbiHash: hashPeeritProfileAbi(profileRegistry),
    profileVectorSetHash: hashPeeritProfileVectorSet(profileVectors),
    validatorArtifactHash: hashPeeritValidatorArtifactV1(validator),
    validatorVectorSetHash: hashPeeritValidatorVectorSetV1(validatorVectors),
    availabilityPolicyHash: availabilityPolicyHash(
      assets.get(PEERIT_BROWSER_RUNTIME_ASSET_PATHS.availabilityPolicy)),
    releaseSequence: 29n,
    recommendedBootstrapHashes: [seedHash],
    appArtifactHash: hashPeeritAppArtifactV1(appArtifactBytes),
    webAssetManifestHash: hashPeeritWebAssetManifestV1(manifestBytes),
    signature: undefined
  })
  const pinBytes = encodePeeritHiveRelayProfilePinV1(pin)
  return {
    assets,
    appDistributionArtifactBytes: appArtifactBytes,
    webAssetManifestBytes: manifestBytes,
    productionPinBytes: pinBytes,
    expectedPinHash: profilePinHash(pinBytes),
    expectedReleaseAuthorityPublicKey: releaseFixture.releasePublicKey,
    expectedReleaseSequence: 29n,
    crypto: createNodeReleaseControlCrypto(),
    subtle: globalThis.crypto.subtle,
    fetch,
    clock: {
      unixMillis: Number(now),
      monotonicMillis: globalThis.performance.now()
    },
    requireCompleteAssetSet: true
  }
}

await cryptoReady()
const watchdog = setTimeout(() => {
  console.error('peerit seq29 shipped publication/recovery: watchdog exceeded')
  process.exit(1)
}, 900_000)
watchdog.unref()

const issuerKey = new Uint8Array(randomBytes(32))
// Keep the in-process proof-of-work below the five-second signed readiness
// lease so this loopback rehearsal cannot starve the edge refresh timers.
const issuer = createPowIssuanceV1Issuer({ issuerKey, difficultyBits: 8 })
await issuer.start()
const issuerBase = `http://127.0.0.1:${issuer.address().port}`
const relays = []

async function startRelayEdge ({ relayId, fixture, edgePort, tls }) {
  const edge = new BlindEdge({
    host: '127.0.0.1',
    port: edgePort,
    endpointId: 1,
    releaseGate: () => {},
    tls,
    onError: error => console.error(
      `[seq29-shipped:${relayId}] edge:`, error.code || '', error.message,
      error.cause && `${error.cause.code || ''} ${error.cause.message}`),
    readinessTopology: {
      unarySocketPath: fixture.unarySocketPath,
      streamSocketPath: fixture.streamSocketPath,
      launchTopologyHash: fixture.launchTopologyHash,
      streamTransportProfileHash: fixture.transportProfileHash,
      daemonUid: process.getuid(),
      daemonGid: process.getgid(),
      socketGroupGid: process.getgid(),
      socketMode: 0o660
    }
  })
  await edge.start()
  assert.equal(edge.address().port, edgePort,
    `${relayId} edge must bind its signed listener port`)
  return edge
}

async function standupRelay (relayId, marker) {
  const directory = await createBlindBoundaryScratch(
    relayId === 'dal-1' ? 's29d-' : 's29s-')
  const edgePort = await reserveLoopbackPort()
  const fixture = await relayFixture({
    relayId,
    issuerKey,
    issuerPort: issuer.address().port,
    directory,
    marker,
    edgePort
  })
  const adapter = new PowIssuanceV1AdmissionAdapter({ issuerKey })
  const bootstrap = loadDaemonBootstrapConfig(fixture.environment)
  let replayOffset = -15_000n
  const daemonRuntime = await assembleProductionBlindDaemon({
    bootstrap: Object.freeze({ ...bootstrap, expectedPeerUid: process.getuid() }),
    runtimeConfig: loadProductionRuntimeConfig(
      fixture.environment, bootstrap.endpointIds),
    enableCellRuntime: true,
    enableInboxRuntime: true,
    resolveAdmissionAdapter: createPowIssuanceV1AdapterResolver(adapter),
    testOnlyPrivateIpcReplayJournalOptions: {
      monotonicMillis: () =>
        (process.hrtime.bigint() / 1_000_000n) + replayOffset
    },
    onError: error => console.error(
      `[seq29-shipped:${relayId}] daemon:`, error.code || '', error.message),
    releaseGate: async () => {}
  })
  await daemonRuntime.start()
  replayOffset = 0n
  const tls = await ephemeralLoopbackTls(directory)
  const edge = await startRelayEdge({
    relayId,
    directory,
    fixture,
    edgePort,
    tls
  })
  const relay = {
    relayId,
    directory,
    fixture,
    adapter,
    daemonRuntime,
    edge,
    tls,
    edgePort: edge.address().port
  }
  relays.push(relay)
  return relay
}

const runtimeFetch = (url, init = {}) => {
  const target = new URL(url)
  if (target.hostname === 'relay-dal.p2phiverelay.xyz' ||
      target.hostname === 'relay-syd.p2phiverelay.xyz') {
    return globalThis.fetch(`${issuerBase}${target.pathname}`, init)
  }
  return loopbackFetch(url, init)
}

async function teardown () {
  clearTimeout(watchdog)
  for (const relay of relays.reverse()) {
    await relay.daemonRuntime.close().catch(() => {})
    relay.adapter.close()
    await relay.edge.close().catch(() => {})
    await removeBlindBoundaryScratch(relay.directory).catch(() => {})
  }
  await issuer.close()
}

function productRuntime ({ shared, identityKv, durableStorage, channelName }) {
  const sync = createPeeritSubstrateSync({
    journal: createMemoryPeeritJournal({ shared }),
    relays: [],
    autoFlush: false,
    requireVerifiedRelayAdapters: true,
    channelName
  })
  return createPeeritProductRuntimeV1({
    identity: createPeeritLocalIdentityV1(),
    identityStore: createIdentityStore({ kv: identityKv }),
    sync,
    storage: durableStorage,
    minBits: {
      community: 0,
      post: 0,
      comment: 0,
      vote: 0,
      profile: 0,
      modaction: 0,
      blob: 0
    }
  })
}

try {
  const [relayDal, relaySyd] = await Promise.all([
    standupRelay('dal-1', 0x61),
    standupRelay('syd-1', 0x71)
  ])
  relays.sort((left, right) => left.relayId.localeCompare(right.relayId))
  for (const relay of relays) {
    assert.equal(relay.daemonRuntime.status().v2WritePathReady, true)
  }

  const fixtureRuntime = browserControl.createBrowserCryptoRuntime()
  async function createFixtureInbox (relay) {
    const spend = createPowIssuanceV1SpendProvider({
      issuanceUrl: relay.fixture.issuanceUrl,
      fetch: runtimeFetch
    })
    let createContext = null
    const created = await createInboxReplica({
      runtime: fixtureRuntime,
      relayPublicKey: relay.fixture.relayPublicKey,
      allocationEpoch: relay.fixture.currentEpoch,
      frameClassBits: 3,
      appendAuthMode: 0,
      retentionClass: 3,
      leaseClass: 4,
      async admissionProvider (context) {
        createContext = context
        const minted = await spend.mint({
          commitments: [context.requestCommitment]
        })
        return Object.freeze({
          profileId: PEERIT_LIMITED_CELL_PUT_PROFILE_ID_V1,
          schemeId: POW_ISSUANCE_V1_SCHEME_ID,
          parameterHash: relay.fixture.parameterHash,
          token: spend.presentation(
            minted.token, 0, [context.requestCommitment])
        })
      }
    })
    assert.equal(createContext.familyId, FAMILY.INBOX)
    assert.equal(createContext.operationId, OPERATION.INBOX.CREATE)
    const encoded = encodeUnaryRequest({
      runtime: fixtureRuntime,
      familyId: FAMILY.INBOX,
      operationId: OPERATION.INBOX.CREATE,
      body: created.requestBytes,
      expectedResultBodyBytes: created.wire.expectedResultBodyBytes
    })
    const transport = await httpsPost(
      relay.edgePort, '/api/blind/v1/inbox', encoded.body)
    assert.equal(transport.statusCode, 200)
    const response = decodeUnaryResponse(transport.body, encoded)
    assert.equal(response.ok, true,
      `${relay.relayId} fixture-only INBOX.CREATE must succeed`)
    const binding = Object.freeze({
      inboxEpoch: Math.floor(relay.fixture.currentEpoch / 28),
      stripeIndex: 0,
      relayId: relay.relayId,
      relayPublicKey: hex(relay.fixture.relayPublicKey),
      allocationEpoch: relay.fixture.currentEpoch,
      createPublicKey: hex(created.request.createPublicKey),
      physicalTopic: hex(created.readCap.physicalTopic),
      frameClassBits: 3,
      appendAuthMode: 0,
      retentionClass: 3,
      leaseClass: 4,
      createReceiptCanonicalHex: hex(response.body)
    })
    destroyInboxWriteCapability(created.writeCap)
    return binding
  }

  const fixtureBindings = await Promise.all([
    createFixtureInbox(relayDal),
    createFixtureInbox(relaySyd)
  ])
  assert.equal('createInboxReplica' in browserControl, false,
    'the shipped browser artifact never receives the fixture CREATE constructor')

  const now = BigInt(Date.now())
  const inboxSigner = await genKeyPair()
  const inboxEpoch = Math.floor(relayDal.fixture.currentEpoch / 28)
  assert.equal(fixtureBindings.every(row => row.inboxEpoch === inboxEpoch), true)
  const inboxPayload = {
    schema: 'peerit-limited-public-inbox-bootstrap-v1',
    version: 1,
    artifactClass: 'LIMITED_PUBLIC_TEST_RELEASE',
    claimBoundary: 'LIVE_PUBLIC_TEST_ONLY',
    operatorBoundary: 'TWO_OWNER_OPERATED_RELAYS_NOT_INDEPENDENT_OPERATORS',
    topicScope: 'GLOBAL_PUBLIC_DISCOVERY',
    profileId: '@peerit/hiverelay-profile-v1',
    releaseSequence: 29,
    bootstrapSequence: '0',
    previousBootstrapHash: null,
    issuedUnixMillis: String(now - 1000n),
    expiresUnixMillis: String(now + 604_800_000n),
    authorityPublicKey: inboxSigner.pubHex,
    relays: relays.map(relay => ({
      relayId: relay.relayId,
      canonicalDescribeUrl:
        `https://127.0.0.1:${relay.edgePort}/api/blind/v1/describe`,
      relayPublicKey: hex(relay.fixture.relayPublicKey),
      storeId: hex(relay.fixture.descriptor.storeId),
      durabilityContinuityHash:
        hex(relay.fixture.descriptor.durabilityContinuityHash),
      descriptorFloor: {
        sequence: String(relay.fixture.descriptor.descriptorSequence),
        hash: hex(relay.fixture.descriptorHash)
      }
    })),
    inboxEpochSets: [{
      inboxEpoch,
      stripeCountLog2: 0,
      stripeSelectionKey: hex(randomBytes(32)),
      announcementMasterKey: hex(randomBytes(32)),
      bindings: fixtureBindings
    }]
  }
  const inboxWrapper = {
    payload: inboxPayload,
    signature: hex(await signBytes(inboxSigner.seedHex, concatBytes(
      asciiBytes(PEERIT_LIMITED_PUBLIC_INBOX_BOOTSTRAP_DOMAIN_V1),
      Uint8Array.of(0),
      canonicalPeeritLimitedPublicInboxJsonV1(inboxPayload)
    )))
  }
  const inboxBytes = new TextEncoder().encode(
    JSON.stringify(inboxWrapper, null, 2) + '\n')
  const inboxSha256 = createHash('sha256').update(inboxBytes).digest('hex')

  const profileBytes = new TextEncoder().encode(
    peeritLimitedCellPutProfileSourceV1({
      relays: relays.map(relay => ({
        relayId: relay.relayId,
        relayPublicKey: hex(relay.fixture.relayPublicKey),
        issuanceUrl: relay.fixture.issuanceUrl
      })),
      supportedProtocolProfiles: profilePins.map(row => ({
        ...row,
        profileHash: hex(row.profileHash)
      })),
      supportedTransportProfiles: transportPins.map(row => ({
        ...row,
        transportProfileHash: hex(row.transportProfileHash)
      }))
    }))

  const seedFixture = JSON.parse(fs.readFileSync(path.join(
    ROOT, 'deploy', 'peerit-seed-bootstrap-v1-seq28.json'), 'utf8'))
  const seedSigner = await genKeyPair()
  const seedPayload = structuredClone(seedFixture.payload)
  seedPayload.releaseSequence = 29
  seedPayload.authorityPublicKey = seedSigner.pubHex
  seedPayload.issuedAt = Number(now - 1000n)
  seedPayload.expiresAt = Number(now + 604_800_000n)
  const seed = await createPeeritSeedBootstrapV1(
    seedPayload, { seedHex: seedSigner.seedHex })
  const seedBytes = new Uint8Array(encodePeeritSeedBootstrapV1(seed))
  const seedSha256 = createHash('sha256').update(seedBytes).digest('hex')
  const seedHash = hashPeeritBootstrapV1(seedBytes)

  const assets = seq29BaseAssets()
  assets.set(PEERIT_BROWSER_RUNTIME_ASSET_PATHS.limitedCellPutProfile, profileBytes)
  assets.set('/peerit-seed-bootstrap-v1.json', seedBytes)
  assets.set('/peerit-limited-public-inbox-bootstrap-v1.json', inboxBytes)
  const coordinatorBytes = assets.get(
    PEERIT_BROWSER_RUNTIME_ASSET_PATHS.seq29PublicInboxCoordinator)
  const coordinatorSha256 = createHash('sha256')
    .update(coordinatorBytes).digest('hex')
  const profileSha256 = createHash('sha256').update(profileBytes).digest('hex')
  const appArtifactBytes = new TextEncoder().encode(JSON.stringify({
    schema: 'peerit-app-artifact-v1',
    releaseSequence: 29,
    peeritSeedBootstrap: '/peerit-seed-bootstrap-v1.json',
    peeritSeedBootstrapSha256: seedSha256,
    peeritSeedDiscoveryAuthorityPublicKey: seedSigner.pubHex,
    peeritSeedBootstrapReleaseSequence: 29,
    peeritLimitedPublicInboxBootstrap:
      '/peerit-limited-public-inbox-bootstrap-v1.json',
    peeritLimitedPublicInboxBootstrapSha256: inboxSha256,
    peeritLimitedPublicInboxBootstrapAuthorityPublicKey: inboxSigner.pubHex,
    peeritLimitedPublicInboxBootstrapReleaseSequence: 29,
    files: {
      'peerit-limited-public-inbox-bootstrap-v1.json': inboxSha256,
      'js/substrate/public-inbox-boot-coordinator.mjs': coordinatorSha256,
      'peerit-limited-cell-put-profile-v1.json': profileSha256
    }
  }) + '\n')
  assets.set(PEERIT_BROWSER_RUNTIME_ASSET_PATHS.appArtifact, appArtifactBytes)
  const runtimeAuthority = await assemblePeeritBrowserRuntimeAuthorityNodeTestV1(
    signedRuntimeInputs({ assets, appArtifactBytes, seedHash, now, fetch: runtimeFetch }))
  const assembly = getVerifiedPeeritBrowserRuntimeAssembly(runtimeAuthority)
  assert.equal('createInboxReplica' in assembly.control, false)
  assert.equal(typeof assembly.seq29PublicationControl.createDualCellReplicasV1,
    'function')
  assert.equal(typeof assembly.seq29PublicationControl.prepareAppendV1, 'function')

  for (const relay of relays) {
    await relay.edge.close().catch(() => {})
    relay.edge = await startRelayEdge(relay)
  }

  const baseClient = new assembly.control.BlindDirectHttpClient({
    runtime: assembly.control.createBrowserCryptoRuntime(),
    fetch: runtimeFetch,
    allowInsecureLoopback: true
  })
  const counts = { put: 0, get: 0, append: 0, read: 0 }
  const secondRelayKey = hex(relaySyd.fixture.relayPublicKey)
  let injectAmbiguousSecondAppend = true
  const countedClient = {
    async request (input) {
      const context = assembly.control.verifiedEndpointContext(input.endpoint)
      const operation = `${context.familyId}/${context.operationId}`
      const name = new Map([
        ['2/1', 'put'],
        ['2/2', 'get'],
        ['3/4', 'append'],
        ['3/5', 'read']
      ]).get(operation)
      if (name) counts[name]++
      const response = await baseClient.request(input)
      if (injectAmbiguousSecondAppend && operation === '3/4' &&
          hex(context.relayPublicKey) === secondRelayKey) {
        injectAmbiguousSecondAppend = false
        const error = new Error('injected crash after relay committed APPEND')
        error.code = 'INJECTED_POST_COMMIT_CRASH'
        throw error
      }
      return response
    }
  }

  const shared = createMemoryJournalState()
  const identityKv = memoryKv()
  const durableStorage = memoryStorage()
  const firstProduct = productRuntime({
    shared,
    identityKv,
    durableStorage,
    channelName: 'seq29-shipped-publication-first'
  })
  await firstProduct.ready()
  const firstCoordinator = await createPeeritSeq29PublicInboxBootCoordinatorV1({
    runtimeAuthority,
    runtimeAppBinding: assembly,
    substrateSync: firstProduct.sync,
    productRuntime: firstProduct,
    httpClient: countedClient,
    fetch: runtimeFetch
  })
  await firstProduct.data.createCommunity({
    slug: 'seq29shipped',
    title: 'Seq29 Shipped',
    description: 'exact explicit authored publication and recovery proof'
  })
  const authoredSummary = await firstProduct.sync.journal.summary()
  const intentId = authoredSummary.latestIntentId
  const authoredIntent = await firstProduct.sync.journal.getIntent(intentId)
  assert.equal(typeof intentId, 'string')
  assert.equal(authoredIntent.wireFormat, 'peerit-inner-operation-batch-v1')
  await assert.rejects(
    firstCoordinator.publishAuthoredIntent({ intentId }),
    error => error.code === 'INJECTED_POST_COMMIT_CRASH')
  assert.deepEqual(counts, { put: 2, get: 2, append: 2, read: 0 },
    'the exact shipped authored intent reached dual PUT, same-relay GET, signed records, and dual APPEND')
  firstProduct.destroy()

  const secondProduct = productRuntime({
    shared,
    identityKv,
    durableStorage,
    channelName: 'seq29-shipped-publication-reload'
  })
  await secondProduct.ready()
  const secondCoordinator = await createPeeritSeq29PublicInboxBootCoordinatorV1({
    runtimeAuthority,
    runtimeAppBinding: assembly,
    substrateSync: secondProduct.sync,
    productRuntime: secondProduct,
    httpClient: countedClient,
    fetch: runtimeFetch
  })
  const recovered = await secondCoordinator.resumeAuthoredPublication({
    logicalHash: authoredIntent.logicalHash
  })
  assert.equal(recovered.completedAt > 0, true)
  assert.deepEqual(recovered.relays.map(row => row.stage), ['succeeded', 'succeeded'])
  assert.deepEqual(counts, { put: 2, get: 2, append: 2, read: 1 },
    'reload authenticated READ reconciliation and did not blind-duplicate either APPEND')
  secondProduct.destroy()

  console.log('peerit seq29 shipped publication/recovery: author → 2 PUT → 2 GET → signed AuthorBind/announcement → 2 APPEND; crash/reload reconciled without duplicate')
} finally {
  await teardown()
}
