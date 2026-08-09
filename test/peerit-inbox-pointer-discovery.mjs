// test/peerit-inbox-pointer-discovery.mjs — LOCAL T2 INBOX-discovery drill for
// the Peerit T2 milestone's inbox half. Fully in-process: ONE pow-issuance-v1
// issuer (HTTP) + TWO production daemon runtimes with the inbox runtime
// enabled + two real TLS edges + the genuine Peerit client pieces (vendored
// blind client control artifact + the browser modules under test:
// inbox-topic-v1, inbox-pointer-frame-v1, inbox-read-result-decode,
// inbox-pointer-publish, inbox-discovery, and the pow-issuance spend
// provider's beginOperationRecord session). No fleet contact.
//
// Proves:
//   (a) the deterministic board-topic derivation is BYTE-IDENTICAL across
//       independent runtime instances (capability keys, physical topic, create
//       commitment, request commitment, CREATE request bytes), distinct per
//       board and per relay, and matches the protocol's inboxPhysicalTopic
//       computed independently from stream block 0;
//   (b) end-to-end on relay A: ONE genuine Data.addComment comment (14-bit
//       in-record PoW, tag-334 envelope) → CELL.PUT with the per-relay
//       2-slot token (slot 0 put / slot 1 append) → verified receipt +
//       byte-exact readback → publishPeeritInboxPointerV1 (READ probe
//       NOT_FOUND → CREATE with a fresh 1-slot token → CREATED receipt →
//       APPEND with slot 1 of the record token → ack appendRevision 1), with
//       byte-parity of the strict snapshot decoder against
//       @hiverelay/blind-protocol decodeCanonical on relay-produced bytes;
//   (c) fresh-reader discovery from floor 0 returns the pointer; CELL.GET
//       opens the exact authored record; the record passes the app's ingest
//       verifier and renders through the genuine view path;
//   (d) negatives: (i) a tampered frame is rejection evidence and the reader
//       advances past it; (ii) a pointer to an unknown recordCid fails closed
//       (no local capability; relay GET NOT_FOUND on a fabricated capability)
//       and the floor still advances; (iii) a byte-identical append replay
//       returns the original ack (same appendRevision, no duplicate entry);
//       (iv) a byte-identical CREATE replay returns the original receipt, not
//       CONFLICT; (v) a second record on the same board appends at the next
//       revision and a reader from the advanced floor sees only it;
//   (e) the same record on BOTH relays: pointer published on each,
//       discovery from each relay returns it independently;
//   (f) spend discipline: per relay per record exactly ONE 2-slot token
//       (redeem calls counted against the issuer); CREATE mints only when the
//       topic is absent.
//
// LOCAL FIXTURE DEVIATION (descriptor/parameter content only, documented in
// the milestone report): the shared pow-issuance-v1-drill-fixture advertises
// only protocol family 1 (DESCRIBE) in its descriptor protocols and only an
// INBOX.CREATE cost row at leaseClass 2. The genuine client qualifier pins
// family 3 (INBOX) against descriptor protocol rows, and the peerit topic
// convention pins leaseClass 4. This drill therefore builds its daemon
// environments from a LOCAL supplemented fixture — byte-identical in
// structure to powIssuanceV1DrillFixture, with two content additions the
// fleet descriptors already carry: a protocols row for family 3, and
// INBOX.CREATE cost rows for leaseClass 1..4. The daemon runtime, admission
// adapter, issuer, edges, and every client/verification step are the genuine
// production pieces.
//
// Run: node test/peerit-inbox-pointer-discovery.mjs
import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import { execFile } from 'node:child_process'
import fs from 'node:fs/promises'
import https from 'node:https'
import path from 'node:path'
import { promisify } from 'node:util'
import { fileURLToPath, pathToFileURL } from 'node:url'
import sodium from 'sodium-universal'
import {
  POW_ISSUANCE_V1_SCHEME_ID,
  createPowIssuanceV1AdmissionProviderFactory
} from '../js/substrate/pow-issuance-spend-provider.mjs'
import {
  PEERIT_LIMITED_CELL_PUT_PROFILE_ID_V1
} from '../js/substrate/limited-cell-put-profile.mjs'
import {
  derivePeeritInboxTopicV1,
  peeritInboxTopicSeedV1,
  peeritInboxTopicStreamBlockV1
} from '../js/substrate/inbox-topic-v1.mjs'
import {
  decodePeeritInboxPointerFrameV1,
  encodePeeritInboxPointerFrameV1
} from '../js/substrate/inbox-pointer-frame-v1.mjs'
import {
  decodePeeritInboxAppendAckSnapshotV1,
  decodePeeritInboxReadResultSnapshotV1,
  decodePeeritInboxReceiptSnapshotV1
} from '../js/substrate/inbox-read-result-decode.mjs'
import {
  preparePeeritInboxPointerV1,
  publishPeeritInboxPointerV1
} from '../js/substrate/inbox-pointer-publish.mjs'
import { pollPeeritInboxTopicV1 } from '../js/substrate/inbox-discovery.mjs'
import { blake2b256, bytesEqual, bytesToHex, hexToBytes } from '../js/substrate/release-control-primitives.mjs'
// The genuine app construction + ingest path (same modules the app runs).
import { ready as cryptoReady, isSecure } from '../js/crypto.js'
import { DevSync, memoryStorage } from '../js/sync.js'
import { DevIdentity } from '../js/identity.js'
import { createData } from '../js/data.js'
import { mergeOutboxes } from '../js/gossip.js'
import { makeValidator } from '../js/pow.js'
import { expectedKeyV2 } from '../js/canon.js'
import { unseal } from '../js/seal.js'
import { hasValidContentId, hasValidContentRef, validCommunitySlug, TYPE } from '../js/model.js'
import { MIN_BITS, verify as verifyPow } from '../js/pow-current.js'
import {
  createPeeritInnerOperationBatchV1,
  decodePeeritInnerOperationBatchV1,
  hashPeeritInnerOperationIntentIdV1
} from '../js/substrate/peerit-operation-authority-v1.js'

const execFileAsync = promisify(execFile)
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
// Production truth is the DEPLOYED fleet tree (00-core/hiverelay).
const VI_ROOT = process.env.HIVERELAY_V1_INTEGRATION_ROOT ||
  path.resolve(ROOT, '..', '..', '00-core', 'hiverelay')
const vi = (...parts) => pathToFileURL(path.join(VI_ROOT, ...parts)).href

// The full-stack drill needs the relay source tree; where it is absent (CI)
// skip loudly, exactly like the spend drill.
const VI_TREE_PRESENT = await fs.stat(path.join(VI_ROOT, 'packages', 'blind-protocol', 'index.js'))
  .then(() => true, () => false)
if (!VI_TREE_PRESENT) {
  console.log('    [inbox-drill] SKIP: hiverelay source tree absent — full-stack drill runs where 00-core/hiverelay is checked out')
  process.exit(0)
}

const protocol = await import(vi('packages', 'blind-protocol', 'index.js'))
const {
  ADMISSION_CONFORMANCE_CLASS,
  CELL_RECEIPT_RESULT,
  ERROR_CODE,
  FAMILY,
  INBOX_FRAME_CLASS,
  INBOX_RECEIPT_RESULT,
  OPERATION,
  PROTOCOL,
  RESULT_SIGNATURE_DOMAIN_ID,
  TRANSPORT_SUPPORT,
  admissionParametersHash,
  admissionParametersV1,
  blindReceiptV1,
  blindServiceDescriptorV1,
  decodeCanonical,
  encodeCanonical,
  getCellResultV1,
  hashStoreFormat,
  inboxAppendAckV1,
  inboxPhysicalTopic,
  inboxReadResultV1,
  inboxReceiptV1,
  resultSignaturePayload,
  serviceDescriptorHash
} = protocol
const ERROR_NAMES = new Map(Object.entries(ERROR_CODE).map(([name, code]) => [code, name]))
const { loadDaemonBootstrapConfig } = await import(vi('packages', 'blind-daemon', 'bootstrap-config.js'))
const {
  PRODUCTION_DESCRIBE_CELL_INBOX_OPERATION_BITS,
  assembleProductionBlindDaemon,
  loadProductionRuntimeConfig
} = await import(vi('packages', 'blind-daemon', 'production-runtime.js'))
const { daemonOperationProfile, deriveAdmissionCost } =
  await import(vi('packages', 'blind-daemon', 'operation-catalog.js'))
const {
  PowIssuanceV1AdmissionAdapter,
  createPowIssuanceV1AdapterResolver
} = await import(vi('packages', 'blind-daemon', 'pow-issuance-v1', 'admission-adapter.js'))
const { createPowIssuanceV1Issuer } = await import(vi('packages', 'blind-daemon', 'pow-issuance-v1', 'issuer-service.js'))
const { powIssuanceV1IssuerKeyCommitment } =
  await import(vi('packages', 'blind-daemon', 'pow-issuance-v1', 'token-codec.js'))
const {
  POW_DRILL_PUBLIC_ROLE_BITS,
  POW_DRILL_SIX_HOURS_MILLIS
} = await import(vi('packages', 'blind-daemon', 'test', 'pow-issuance-v1-drill-fixture.js'))
const { bindDurability, descriptorValue, parameterValue } =
  await import(vi('packages', 'blind-daemon', 'test', 'coordinator-fixtures.js'))
const { BlindEdge } = await import(vi('packages', 'blind-edge', 'server.js'))
const { encodeUnaryRequest, decodeUnaryResponse } = await import(vi('packages', 'blind-client', 'wire.js'))
const { openCell } = await import(vi('packages', 'blind-client', 'cells.js'))
const {
  createBlindBoundaryScratch,
  removeBlindBoundaryScratch
} = await import(vi('test', 'blind-boundary-scratch.js'))
const control = await import(pathToFileURL(
  path.join(ROOT, 'vendor', 'hiverelay-blind-client-v1', 'blind-client-control-v1.mjs')).href)

function log (line) {
  console.log(`    [inbox-drill] ${line}`)
}

function errorName (code) {
  return ERROR_NAMES.get(code) || `UNKNOWN(${code})`
}

function hex (bytes) {
  return Buffer.from(bytes).toString('hex')
}

const memStorage = () => {
  const m = new Map()
  return {
    getItem: k => (m.has(k) ? m.get(k) : null),
    setItem: (k, v) => m.set(k, String(v)),
    removeItem: k => m.delete(k),
    clear: () => m.clear()
  }
}

// ---------------------------------------------------------------------------
// LOCAL supplemented drill fixture (see the header deviation note). Mirrors
// powIssuanceV1DrillFixture byte-for-byte in structure; the ONLY content
// additions are a descriptor protocols row for family 3 (INBOX — the genuine
// client qualifier pins it) and INBOX.CREATE cost rows for leaseClass 1..4
// (the peerit topic convention pins leaseClass 4).
// ---------------------------------------------------------------------------
function signCanonical (codec, value, domainId, secretKey) {
  value.signature = Buffer.alloc(sodium.crypto_sign_BYTES)
  const placeholder = encodeCanonical(codec, value)
  const unsigned = placeholder.subarray(0, placeholder.byteLength - sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(value.signature, resultSignaturePayload(domainId, unsigned), secretKey)
  return encodeCanonical(codec, value)
}

async function privateFile (file, bytes) {
  await fs.writeFile(file, bytes, { mode: 0o600 })
  await fs.chmod(file, 0o600)
}

function costRow (familyId, operationId, request, authenticatedState) {
  const cost = deriveAdmissionCost(daemonOperationProfile(familyId, operationId), request, authenticatedState)
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
    for (const leaseClass of [1, 2, 3, 4]) {
      rows.push(costRow(FAMILY.CELL, OPERATION.CELL.PUT, { sizeClass, leaseClass }))
    }
  }
  const storedShape = Object.freeze({ inboxRetentionClass: 2, inboxFrameClassBits: 1 })
  const predictedReadBytes = 4096 + 1 * (41 + INBOX_FRAME_CLASS[1])
  // SUPPLEMENTED: leaseClass 1..4 (stock fixture carries only leaseClass 2).
  for (const leaseClass of [1, 2, 3, 4]) {
    rows.push(costRow(FAMILY.INBOX, OPERATION.INBOX.CREATE,
      { retentionClass: 2, frameClassBits: 1, leaseClass }))
  }
  rows.push(costRow(FAMILY.INBOX, OPERATION.INBOX.RENEW, { leaseClass: 4 }, storedShape))
  rows.push(costRow(FAMILY.INBOX, OPERATION.INBOX.APPEND, { frameClass: 1 }, storedShape))
  rows.push(costRow(FAMILY.INBOX, OPERATION.INBOX.READ, {}, { canonicalResultBytes: predictedReadBytes }))
  rows.push(costRow(FAMILY.INBOX, OPERATION.INBOX.WATCH,
    { maxWaitMillis: 1000 }, { canonicalResultBytes: predictedReadBytes }))
  return rows.sort((left, right) => {
    for (const field of ['familyId', 'operationId', 'resourceClass', 'leaseClass']) {
      if (left[field] !== right[field]) return left[field] - right[field]
    }
    return 0
  })
}

async function inboxPointerDrillFixture ({ issuerPort, issuerKey, directory }) {
  const storeRoot = path.join(directory, 'store')
  const inboxStoreRoot = path.join(directory, 'inbox-store')
  const privateIpcReplayRoot = path.join(directory, 'private-ipc-replay')
  await fs.mkdir(storeRoot, { mode: 0o700 })
  await fs.mkdir(inboxStoreRoot, { mode: 0o700 })
  await fs.mkdir(privateIpcReplayRoot, { mode: 0o700 })

  const relayPublicKey = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  const relaySecretKey = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(relayPublicKey, relaySecretKey)
  const currentEpoch = Math.floor(Date.now() / POW_DRILL_SIX_HOURS_MILLIS)

  const parameters = parameterValue(relayPublicKey, {
    profileId: PEERIT_LIMITED_CELL_PUT_PROFILE_ID_V1,
    schemeId: POW_ISSUANCE_V1_SCHEME_ID,
    conformanceClass: ADMISSION_CONFORMANCE_CLASS.OPEN,
    roleBits: POW_DRILL_PUBLIC_ROLE_BITS,
    verifierKey: Buffer.alloc(0),
    resourceCosts: drillResourceCosts(),
    tokenMaxBytes: 512,
    issuanceUrl: Buffer.from(`https://127.0.0.1:${issuerPort}/`, 'utf8'),
    issuerRelayKey: powIssuanceV1IssuerKeyCommitment(issuerKey),
    validFromEpoch: currentEpoch,
    expiresEpoch: currentEpoch + 4
  })
  const canonicalParameters = signCanonical(admissionParametersV1, parameters,
    RESULT_SIGNATURE_DOMAIN_ID.ADMISSION_PARAMETERS, relaySecretKey)
  const parameterHash = admissionParametersHash(canonicalParameters)

  const descriptor = descriptorValue({
    relayPublicKey: Buffer.from(relayPublicKey),
    storeId: Buffer.alloc(32, 0x62),
    enabledOperationBits: PRODUCTION_DESCRIBE_CELL_INBOX_OPERATION_BITS,
    issuedEpoch: currentEpoch - 1,
    expiresEpoch: currentEpoch + 3,
    capacityBand: 0
  })
  descriptor.endpoints = [descriptor.endpoints[0]]
  descriptor.endpoints[0].endpointId = 1
  descriptor.endpoints[0].transportId = 1
  descriptor.endpoints[0].roleBits = POW_DRILL_PUBLIC_ROLE_BITS
  // SUPPLEMENTED: advertise the INBOX family protocol row (the stock fixture
  // descriptor advertises only family 1; the genuine qualifier pins family 3).
  descriptor.protocols = [
    ...descriptor.protocols,
    { ...descriptor.protocols[0], protocolId: FAMILY.INBOX }
  ]
  descriptor.admissionProfiles = [{
    profileId: PEERIT_LIMITED_CELL_PUT_PROFILE_ID_V1,
    schemeId: POW_ISSUANCE_V1_SCHEME_ID,
    conformanceClass: ADMISSION_CONFORMANCE_CLASS.OPEN,
    roleBits: POW_DRILL_PUBLIC_ROLE_BITS,
    parameterUrl: null,
    parameterHash: Buffer.from(parameterHash)
  }]
  const authorityBytes = await fs.readFile(path.join(
    VI_ROOT, 'packages', 'blind-protocol', 'hiverelay-blind-store-format-authority-v1.draft.cenc'))
  descriptor.durability.storeFormatMajor = 1
  descriptor.durability.storeFormatMinor = 2
  descriptor.durability.storeFormatHash = hashStoreFormat(authorityBytes)
  descriptor.build.storeFormatHash = Buffer.from(descriptor.durability.storeFormatHash)
  bindDurability(descriptor)
  const canonicalGenesisDescriptor = signCanonical(blindServiceDescriptorV1, descriptor,
    RESULT_SIGNATURE_DOMAIN_ID.DESCRIPTOR, relaySecretKey)
  // The V2 write path requires a nonzero descriptor sequence: activate a seq-1
  // successor chained to the genesis, exactly like the deployed +1 hash chain.
  const activeDescriptor = decodeCanonical(blindServiceDescriptorV1, canonicalGenesisDescriptor, { copyBytes: true })
  activeDescriptor.descriptorSequence = 1n
  activeDescriptor.previousDescriptorHash = serviceDescriptorHash(canonicalGenesisDescriptor)
  activeDescriptor.issuedEpoch = currentEpoch
  activeDescriptor.expiresEpoch = currentEpoch + 4
  activeDescriptor.descriptorNonce = Buffer.alloc(32, 0x64)
  const canonicalDescriptor = signCanonical(blindServiceDescriptorV1, activeDescriptor,
    RESULT_SIGNATURE_DOMAIN_ID.DESCRIPTOR, relaySecretKey)

  const descriptorFile = path.join(directory, 'descriptor.bin')
  const successorDescriptorFile = path.join(directory, 'descriptor-successor.bin')
  const parametersFile = path.join(directory, 'admission.bin')
  const secretKeyFile = path.join(directory, 'relay-secret.bin')
  const storeManifestKeyFile = path.join(directory, 'store-manifest-key.bin')
  const ownerFenceFile = path.join(directory, 'owner-fence-hash.bin')
  const inboxCursorKeyFile = path.join(directory, 'inbox-cursor-key.bin')
  await Promise.all([
    privateFile(descriptorFile, canonicalGenesisDescriptor),
    privateFile(successorDescriptorFile, canonicalDescriptor),
    privateFile(parametersFile, canonicalParameters),
    privateFile(secretKeyFile, relaySecretKey),
    privateFile(storeManifestKeyFile, Buffer.alloc(32, 0x71)),
    privateFile(ownerFenceFile, Buffer.alloc(32, 0x72)),
    privateFile(inboxCursorKeyFile, Buffer.alloc(32, 0x73))
  ])
  relaySecretKey.fill(0)

  const uid = process.getuid()
  const gid = process.getgid()
  const environment = {
    ...process.env,
    HIVERELAY_BLIND_UNARY_SOCKET: path.join(directory, 'ipc', 'unary.sock'),
    HIVERELAY_BLIND_STREAM_SOCKET: path.join(directory, 'ipc', 'stream.sock'),
    HIVERELAY_BLIND_LAUNCH_TOPOLOGY_HASH: '81'.repeat(32),
    HIVERELAY_BLIND_ENDPOINT_IDS: '1',
    HIVERELAY_BLIND_ENDPOINT_SUPPORT_BITS: `1:${TRANSPORT_SUPPORT.DIRECT_HTTP}`,
    HIVERELAY_BLIND_EDGE_UID: String(uid + 1),
    HIVERELAY_BLIND_DAEMON_UID: String(uid),
    HIVERELAY_BLIND_DAEMON_GID: String(gid),
    HIVERELAY_BLIND_SHARED_GID: String(gid),
    HIVERELAY_BLIND_DESCRIPTOR_FILES: `${descriptorFile},${successorDescriptorFile}`,
    HIVERELAY_BLIND_ADMISSION_PARAMETER_FILES: parametersFile,
    HIVERELAY_BLIND_RELAY_SECRET_KEY_FILE: secretKeyFile,
    HIVERELAY_BLIND_STORE_ROOT: storeRoot,
    HIVERELAY_BLIND_PRIVATE_IPC_REPLAY_ROOT: privateIpcReplayRoot,
    HIVERELAY_BLIND_INBOX_STORE_ROOT: inboxStoreRoot,
    HIVERELAY_BLIND_INBOX_CURSOR_KEY_FILE: inboxCursorKeyFile,
    HIVERELAY_BLIND_STORE_MANIFEST_KEY_FILE: storeManifestKeyFile,
    HIVERELAY_BLIND_OWNER_FENCE_TOKEN_HASH_FILE: ownerFenceFile,
    HIVERELAY_BLIND_MAP_GENERATION: '1',
    HIVERELAY_BLIND_EXPECTED_DESCRIPTOR_SEQUENCE: String(activeDescriptor.descriptorSequence),
    HIVERELAY_BLIND_EXPECTED_DESCRIPTOR_HASH: Buffer.from(serviceDescriptorHash(canonicalDescriptor)).toString('hex')
  }
  return Object.freeze({
    environment,
    relayPublicKey,
    parameterHash,
    currentEpoch,
    descriptor: activeDescriptor,
    descriptorHash: serviceDescriptorHash(canonicalDescriptor),
    unarySocketPath: environment.HIVERELAY_BLIND_UNARY_SOCKET,
    streamSocketPath: environment.HIVERELAY_BLIND_STREAM_SOCKET,
    launchTopologyHash: Buffer.from('81'.repeat(32), 'hex'),
    transportProfileHash: Buffer.from(activeDescriptor.endpoints[0].transportProfileHash)
  })
}

async function ephemeralLoopbackTls (root) {
  const keyFile = path.join(root, 'edge-tls-key.pem')
  const certFile = path.join(root, 'edge-tls-cert.pem')
  await execFileAsync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes',
    '-subj', '/CN=127.0.0.1', '-days', '1',
    '-keyout', keyFile, '-out', certFile
  ], { timeout: 15_000, maxBuffer: 1024 * 1024 })
  await fs.chmod(keyFile, 0o600)
  return Object.freeze({ key: await fs.readFile(keyFile), cert: await fs.readFile(certFile) })
}

function httpsPost (port, route, body) {
  return new Promise((resolve, reject) => {
    const request = https.request({
      host: '127.0.0.1',
      port,
      path: route,
      method: 'POST',
      rejectUnauthorized: false,
      headers: { 'content-type': PROTOCOL.mediaType, 'content-length': String(body.byteLength) }
    }, response => {
      const chunks = []
      response.on('data', chunk => chunks.push(chunk))
      response.once('error', reject)
      response.once('end', () => resolve({
        statusCode: response.statusCode,
        body: Buffer.concat(chunks)
      }))
    })
    request.once('error', reject)
    request.end(body)
  })
}

// A WHATWG-fetch-shaped wrapper over node https for the vendored artifact
// clients (loopback self-signed TLS; the browser posture has no such escape —
// this is drill-only transport plumbing, exactly like httpsPost above).
function drillFetch (url, init = {}) {
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
    request.once('error', reject)
    if (init.signal) {
      const abort = () => request.destroy(init.signal.reason || new Error('drill fetch aborted'))
      if (init.signal.aborted) abort()
      else init.signal.addEventListener('abort', abort, { once: true })
    }
    request.end(init.body || null)
  })
}

// The drill watchdog: a rendezvous deadlock must fail fast, not hang npm test.
const watchdog = setTimeout(() => {
  console.error('[inbox-drill] WATCHDOG: drill exceeded its bounded deadline')
  process.exit(1)
}, 900_000)
watchdog.unref()

// ---------------------------------------------------------------------------
// Stack standup: ONE shared issuer + TWO production daemon runtimes (cell AND
// inbox runtimes enabled) behind two real TLS edges — the fleet shape on
// loopback. LOCAL only; never touches the fleet.
// ---------------------------------------------------------------------------
await cryptoReady()
assert.ok(isSecure(), 'secure crypto backend (Ed25519) available')
const runtime = control.createBrowserCryptoRuntime(globalThis.crypto)
const issuerKey = new Uint8Array(randomBytes(32))
const issuer = createPowIssuanceV1Issuer({ issuerKey }) // default difficulty 20 bits, allowance cap 2
await issuer.start()
const issuerBase = `http://127.0.0.1:${issuer.address().port}`
log(`issuer up at ${issuerBase} (difficulty=${issuer.difficultyBits} bits, maxAllowance=${issuer.maxAllowance})`)

const relays = []
let replayOffset = -15_000n
async function standupRelay (label) {
  const directory = await createBlindBoundaryScratch(`inboxdrill-${label}-`)
  const fixture = await inboxPointerDrillFixture({
    issuerPort: issuer.address().port, issuerKey, directory })
  const adapter = new PowIssuanceV1AdmissionAdapter({ issuerKey })
  const bootstrap = loadDaemonBootstrapConfig(fixture.environment)
  const daemonRuntime = await assembleProductionBlindDaemon({
    bootstrap: Object.freeze({ ...bootstrap, expectedPeerUid: process.getuid() }),
    runtimeConfig: loadProductionRuntimeConfig(fixture.environment, bootstrap.endpointIds),
    enableCellRuntime: true,
    enableInboxRuntime: true,
    resolveAdmissionAdapter: createPowIssuanceV1AdapterResolver(adapter),
    testOnlyPrivateIpcReplayJournalOptions: {
      monotonicMillis: () => (process.hrtime.bigint() / 1_000_000n) + replayOffset
    },
    onError: error => log(`${label} daemon onError: ${error.code || ''} ${error.message}`),
    releaseGate: async () => {} // LOCAL drill assembly; never a production deploy
  })
  await daemonRuntime.start()
  const tls = await ephemeralLoopbackTls(directory)
  const edge = new BlindEdge({
    host: '127.0.0.1',
    port: 0,
    endpointId: 1,
    releaseGate: () => {},
    tls,
    onError: error => log(`${label} edge onError: ${error.code || ''} ${error.message}`),
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
  const relay = { label, directory, fixture, adapter, daemonRuntime, edge, edgePort: edge.address().port }
  relays.push(relay)
  return relay
}

const relayA = await standupRelay('a')
const relayB = await standupRelay('b')
replayOffset = 0n // pass the mandatory 15s replay-journal startup quarantine
log(`relay a up at https://127.0.0.1:${relayA.edgePort} (parameterHash=${hex(relayA.fixture.parameterHash).slice(0, 16)}…)`)
log(`relay b up at https://127.0.0.1:${relayB.edgePort} (parameterHash=${hex(relayB.fixture.parameterHash).slice(0, 16)}…)`)
assert.ok(!bytesEqual(relayA.fixture.parameterHash, relayB.fixture.parameterHash),
  'parameterHash is relay-specific (syd/dal differ on the fleet, so must the drill)')
for (const relay of [relayA, relayB]) {
  const status = relay.daemonRuntime.status()
  assert.equal(status.v2WritePathReady, true,
    `${relay.label} write path ready with the pow adapter captured`)
  assert.deepEqual(status.admissionCapture, { complete: true, required: 1, captured: 1 },
    `${relay.label} admission capture must be complete`)
  assert.ok(!status.exclusions.includes('CELL_PUBLIC_EXECUTION_UNASSEMBLED'),
    `${relay.label} CELL public execution must be assembled`)
  assert.ok(!status.exclusions.includes('ADMISSION_REDEMPTION_ADAPTER_UNASSEMBLED'),
    `${relay.label} admission redemption adapter must be assembled`)
}

// Genuine client-side qualification through the vendored artifact: one
// VerifiedEndpoint per INBOX operation per relay (the artifact's direct http
// client and result verifier both require the exact qualified handle).
const PROFILE_PINS = Object.freeze([
  Object.freeze({ protocolId: FAMILY.DESCRIBE, major: 1, minimumMinor: 0, profileHash: new Uint8Array(32).fill(0x0a) }),
  Object.freeze({ protocolId: FAMILY.INBOX, major: 1, minimumMinor: 0, profileHash: new Uint8Array(32).fill(0x0a) })
])
const TRANSPORT_PINS = Object.freeze([
  Object.freeze({ transportId: 1, transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP, transportProfileHash: new Uint8Array(32).fill(0x0b) })
])
async function qualifyInboxEndpoints (relay) {
  const qualifier = new control.BlindRelayQualifier({
    runtime,
    nowEpoch: () => relay.fixture.currentEpoch,
    supportedProtocolProfiles: PROFILE_PINS,
    supportedTransportProfiles: TRANSPORT_PINS,
    fetch: drillFetch,
    allowInsecureLoopback: true
  })
  const candidate = {
    canonicalUrl: `https://127.0.0.1:${relay.edgePort}/api/blind/v1/describe`,
    expectedDescriptorHash: new Uint8Array(relay.fixture.descriptorHash),
    continuityRootRelayPublicKey: new Uint8Array(relay.fixture.relayPublicKey)
  }
  const endpoints = {}
  for (const [name, operationId] of [
    ['create', OPERATION.INBOX.CREATE],
    ['append', OPERATION.INBOX.APPEND],
    ['read', OPERATION.INBOX.READ]
  ]) {
    const qualified = await qualifier.qualifyCandidate(candidate, {
      familyId: FAMILY.INBOX,
      operationId,
      endpointId: 1,
      requiredRoleBits: POW_DRILL_PUBLIC_ROLE_BITS,
      privacyProfileBit: 1,
      transportSupportBit: TRANSPORT_SUPPORT.DIRECT_HTTP
    })
    endpoints[name] = qualified.endpoint
  }
  return Object.freeze(endpoints)
}
relayA.endpoints = await qualifyInboxEndpoints(relayA)
relayB.endpoints = await qualifyInboxEndpoints(relayB)
log('both relays qualified through the genuine BlindRelayQualifier (descriptor bootstrap + health + family-3 pins): verified create/append/read endpoints issued')
const httpClient = new control.BlindDirectHttpClient({ runtime, fetch: drillFetch, allowInsecureLoopback: true })

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

const send = async (relay, route, encoded) => {
  const response = await httpsPost(relay.edgePort, route, encoded.body)
  if (response.statusCode !== 200) {
    log(`${relay.label} edge HTTP ${response.statusCode}: ${response.body.subarray(0, 200).toString('utf8')}`)
    return { httpStatus: response.statusCode, ok: false }
  }
  return { httpStatus: 200, ...decodeUnaryResponse(response.body, encoded) }
}

function verifySignedBody (codecValue, body, domainId, publicKey) {
  const value = decodeCanonical(codecValue, body, { copyBytes: true })
  const unsigned = body.subarray(0, body.byteLength - sodium.crypto_sign_BYTES)
  const valid = sodium.crypto_sign_verify_detached(value.signature,
    resultSignaturePayload(domainId, unsigned), publicKey)
  return { value, valid }
}

const drillAdmissionProfile = Object.freeze({
  profileId: PEERIT_LIMITED_CELL_PUT_PROFILE_ID_V1,
  schemeId: POW_ISSUANCE_V1_SCHEME_ID
})

const factory = createPowIssuanceV1AdmissionProviderFactory({
  profileId: drillAdmissionProfile.profileId,
  schemeId: POW_ISSUANCE_V1_SCHEME_ID,
  issuers: [
    { relayPublicKey: relayA.fixture.relayPublicKey, issuanceUrl: `${issuerBase}/` },
    { relayPublicKey: relayB.fixture.relayPublicKey, issuanceUrl: `${issuerBase}/` }
  ],
  allowInsecureLoopback: true
})

// Spend discipline: count issuer /redeem calls across the whole drill.
let redeemCount = 0
const countingFetch = globalThis.fetch
globalThis.fetch = (url, options) => {
  if (String(url).endsWith('/redeem')) redeemCount++
  return countingFetch(url, options)
}

const BOARD = 'inboxdrill'
const LEASE_CLASS = 2 // the record cells: profile maximumCellLeaseClass (≈7d)

// ---------------------------------------------------------------------------
// Genuine record construction: the app's own Data path (DevSync + DevIdentity
// + createData v2, real MIN_BITS PoW) → tag-334 sealed envelope per record.
// ---------------------------------------------------------------------------
const authorSync = new DevSync(memoryStorage(), 'inbox-drill-author')
await authorSync.ready()
const authorId = new DevIdentity(memStorage(), memStorage())
await authorId.ready()
await authorId.createUser('inbox-drill-author')
const authorData = createData(authorSync, authorId, { minBits: MIN_BITS, v2: true })
const me = authorId.me().pubkey
await authorData.createCommunity({ slug: BOARD, title: 'Inbox Drill', description: 'T2 INBOX-discovery drill board' })
const parentPost = await authorData.submitPost({
  community: BOARD, kind: 'text', title: 'T2 INBOX drill parent',
  body: 'Parent post for the local T2 INBOX pointer publish + discovery drill.'
})
log(`author: community r/${BOARD} + parent post ${parentPost.cid.slice(0, 12)}… through the genuine Data path`)

async function authorComment (marker, note) {
  const logical = await authorData.addComment({
    community: BOARD,
    postCid: parentPost.cid,
    parentCid: null,
    body: `${marker}\n\n${note}`
  })
  assert.equal(logical.author, me, 'drill identity authored the comment')
  const wireKey = await expectedKeyV2({ ...logical, _t: TYPE.COMMENT })
  const stored = await authorSync.get(wireKey)
  assert.ok(stored && stored._k === me && stored._t === TYPE.COMMENT,
    'authored comment is materialized under its okey in the local view')
  assert.ok(stored.pow && stored.pow.bits >= MIN_BITS.comment,
    'comment record carries its genuine 14-bit in-record proof')
  const envelope = await createPeeritInnerOperationBatchV1(
    [{ type: 'v2', data: stored }], { expectedAuthorPublicKey: me })
  const innerBytes = new Uint8Array(envelope.innerBytes)
  assert.equal(envelope.sizeClass, 1, 'drill comment must stay a sizeClass-1 cell')
  // Round-trip through the operation authority before any relay sees it.
  const roundTrip = await decodePeeritInnerOperationBatchV1(
    envelope.innerCodec, innerBytes, { expectedAuthorPublicKey: me })
  assert.equal(roundTrip.operations.length, 1)
  return Object.freeze({
    logical,
    stored,
    innerBytes,
    innerCodec: envelope.innerCodec,
    sizeClass: envelope.sizeClass,
    intentId: bytesToHex(hashPeeritInnerOperationIntentIdV1(envelope.innerCodec, innerBytes))
  })
}

// The ingest assertions a fresh reader runs over the served bytes (the PUT
// drill's render-assertion shape): operation authority, content id, target
// binding, 14-bit in-record PoW, the genuine mergeOutboxes verifier, and the
// genuine view path (Data.listComments is what rendering consumes).
async function ingestAndRender (readerData, openedInnerBytes, recordRow, marker, label) {
  const decoded = await decodePeeritInnerOperationBatchV1(
    recordRow.innerCodec, openedInnerBytes, { expectedAuthorPublicKey: me })
  assert.equal(decoded.operations.length, 1)
  const stored = decoded.operations[0].data
  const logical = { ...(await unseal(stored.sealed)), author: stored._k, createdAt: stored.createdAt, editedAt: stored.editedAt, deleted: stored.deleted }
  assert.equal(stored._t, TYPE.COMMENT)
  assert.ok(await hasValidContentId(TYPE.COMMENT, logical), `${label} content-id re-derivation`)
  assert.ok(validCommunitySlug(logical.community) && logical.postCid === logical.targetRef?.cid &&
    await hasValidContentRef(logical.targetRef, TYPE.POST) &&
    logical.parentCid === null && logical.parentRef === null, `${label} target binding`)
  assert.ok(await verifyPow(TYPE.COMMENT, stored, MIN_BITS.comment), `${label} 14-bit in-record PoW`)
  assert.ok(logical.body.includes(marker), `${label} marker present in the unsealed body`)
  // The genuine ingest verifier admits the exact served record.
  const validate = makeValidator(MIN_BITS)
  const wireKey = await expectedKeyV2({ ...logical, _t: TYPE.COMMENT })
  const merged = await mergeOutboxes([{ pub: me, view: { [wireKey]: stored } }], {}, validate)
  assert.ok(merged[wireKey], `${label} admitted by the genuine mergeOutboxes verifier`)
  // The render path: stage into the fresh reader's view and list the thread.
  await readerData.sync.append({ type: 'v2', data: stored })
  const comments = await readerData.listComments(BOARD, parentPost.cid)
  const rendered = comments.find(comment => comment.cid === logical.cid)
  assert.ok(rendered && rendered.body.includes(marker),
    `${label} renders in the fresh reader's view (Data.listComments)`)
  return logical
}

// CELL.PUT + byte-exact CELL.GET readback on one relay (the spend drill's
// replica+verify path), then the pointer publish. Returns everything later
// sections need.
async function putAndPublish (relay, recordRow, { hints, pinnedNow }) {
  const relayPublicKey = relay.fixture.relayPublicKey
  const session = factory.beginOperationRecord({
    operations: [
      { relayPublicKey, kind: 'put' },
      { relayPublicKey, kind: 'append' }
    ]
  })
  assert.equal(session.allowance, 2)
  assert.equal(session.slotIndexOf('put', relayPublicKey), 0, 'slot 0 is the CELL.PUT')
  assert.equal(session.slotIndexOf('append', relayPublicKey), 1, 'slot 1 is the INBOX.APPEND')
  const putAdmission = async context => {
    const spent = await session.spend(context)
    return Object.freeze({
      profileId: drillAdmissionProfile.profileId,
      schemeId: POW_ISSUANCE_V1_SCHEME_ID,
      parameterHash: relay.fixture.parameterHash,
      token: spent.presentation
    })
  }
  // The PUT replica and the pointer append rendezvous inside the session:
  // ONE mint over the 2-slot binding root covers both.
  const [replica, prepared] = await Promise.all([
    control.createCellReplica({
      runtime,
      relayPublicKey,
      allocationEpoch: relay.fixture.currentEpoch,
      sizeClass: recordRow.sizeClass,
      leaseClass: LEASE_CLASS,
      structuredContent: Buffer.from(recordRow.innerBytes),
      admissionProvider: putAdmission
    }),
    preparePeeritInboxPointerV1({
      control,
      baseRuntime: runtime,
      relayPublicKey,
      boardSlug: BOARD,
      record: {
        cid: recordRow.logical.cid,
        authorPubKey: hexToBytes(me, 32, 'author pubkey'),
        sizeClass: recordRow.sizeClass,
        leaseClass: LEASE_CLASS
      },
      hints: hints || [],
      operationRecord: session,
      parameterHash: relay.fixture.parameterHash,
      now: () => pinnedNow
    })
  ])
  const minted = await session.complete
  assert.equal(minted.allowance, 2)

  const putEncoded = encodeUnaryRequest({
    runtime,
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.PUT,
    body: replica.requestBytes,
    expectedResultBodyBytes: replica.wire.expectedResultBodyBytes
  })
  const put = await send(relay, '/api/blind/v1/cell', putEncoded)
  assert.equal(put.httpStatus, 200)
  assert.equal(put.ok, true, `relay ${relay.label} CELL.PUT rejected: ${put.error ? errorName(put.error.code) : 'transport'}`)
  const receipt = verifySignedBody(blindReceiptV1, put.body,
    RESULT_SIGNATURE_DOMAIN_ID.CELL_RECEIPT, relay.fixture.relayPublicKey)
  assert.equal(receipt.valid, true)
  assert.equal(receipt.value.result, CELL_RECEIPT_RESULT.STORED)

  // Byte-exact readback: uncharged CELL.GET opened to the authored record.
  const get = await control.createGetCellRequest({ runtime, readCap: replica.readCap })
  const got = await send(relay, '/api/blind/v1/cell', encodeUnaryRequest({
    runtime,
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.GET,
    body: get.requestBytes,
    expectedResultBodyBytes: get.wire.expectedResultBodyBytes
  }))
  assert.equal(got.ok, true, `relay ${relay.label} CELL.GET failed`)
  const getResult = decodeCanonical(getCellResultV1, got.body, { copyBytes: true })
  const opened = await openCell({
    runtime,
    storageSlot: replica.readCap.storageSlot,
    cellKey: replica.readCap.cellKey,
    sizeClass: replica.readCap.sizeClass,
    expectedCellBlobHash: replica.readCap.expectedCellBlobHash,
    cellBlob: getResult.cellBlob
  })
  assert.ok(bytesEqual(opened, recordRow.innerBytes),
    `relay ${relay.label} readback opens to the exact authored record bytes`)

  const published = await publishPeeritInboxPointerV1({
    control,
    baseRuntime: runtime,
    endpoints: relay.endpoints,
    httpClient,
    relayPublicKey,
    boardSlug: BOARD,
    record: {
      cid: recordRow.logical.cid,
      authorPubKey: hexToBytes(me, 32, 'author pubkey'),
      sizeClass: recordRow.sizeClass,
      leaseClass: LEASE_CLASS
    },
    cellPut: {
      requestCommitment: new Uint8Array(replica.requestCommitment),
      receiptVerified: true,
      readbackVerified: true
    },
    prepared,
    operationRecord: session,
    spendFactory: factory,
    parameterHash: relay.fixture.parameterHash,
    onEvent: event => log(`publish ${relay.label}: ${event.phase}` +
      (event.appendRevision != null ? ` (appendRevision ${event.appendRevision})` : ''))
  })
  return Object.freeze({ session, replica, prepared, published, minted, opened })
}

// Standalone append of an arbitrary frame (negatives (i) and (ii)): a FRESH
// one-slot append operation record; the topic write capability is re-derived
// deterministically.
async function appendFrameAlone (relay, frame, clientNonce) {
  const relayPublicKey = relay.fixture.relayPublicKey
  const session = factory.beginOperationRecord({
    operations: [{ relayPublicKey, kind: 'append' }]
  })
  try {
    const topic = await derivePeeritInboxTopicV1({
      boardSlug: BOARD, relayPublicKey, control, baseRuntime: runtime })
    const append = await control.createAppendInboxRequest({
      runtime,
      writeCap: topic.writeCap,
      frame,
      frameClass: 1,
      clientNonce,
      admissionProvider: async context => {
        const spent = await session.spend(context)
        return Object.freeze({
          profileId: drillAdmissionProfile.profileId,
          schemeId: POW_ISSUANCE_V1_SCHEME_ID,
          parameterHash: relay.fixture.parameterHash,
          token: spent.presentation
        })
      }
    })
    const response = await httpClient.request({
      endpoint: relay.endpoints.append,
      familyId: append.wire.familyId,
      operationId: append.wire.operationId,
      expectedResultBodyBytes: append.wire.expectedResultBodyBytes,
      body: append.requestBytes
    })
    assert.equal(response.ok, true,
      `standalone append rejected: ${response.error ? errorName(response.error.code) : 'transport'}`)
    const verified = control.verifyOperationResult({
      endpoint: relay.endpoints.append,
      request: append.request,
      requestCommitment: append.requestCommitment,
      resultBytes: response.body
    })
    return decodePeeritInboxAppendAckSnapshotV1(verified.snapshotBytes())
  } finally {
    session.close()
  }
}

async function pollBoard (relay, floor) {
  return pollPeeritInboxTopicV1({
    control,
    baseRuntime: runtime,
    endpoint: relay.endpoints.read,
    httpClient,
    relayPublicKey: relay.fixture.relayPublicKey,
    boardSlug: BOARD,
    floor
  })
}

try {
  // -------------------------------------------------------------------------
  // (a) deterministic topic derivation: byte-identity across independent
  // runtimes, distinctness per board/relay, and cross-implementation proof
  // against the protocol's inboxPhysicalTopic over stream block 0.
  // -------------------------------------------------------------------------
  {
    const runtimeAlt = control.createBrowserCryptoRuntime(globalThis.crypto)
    const [d1, d2] = await Promise.all([
      derivePeeritInboxTopicV1({ boardSlug: BOARD, relayPublicKey: relayA.fixture.relayPublicKey, control, baseRuntime: runtime }),
      derivePeeritInboxTopicV1({ boardSlug: BOARD, relayPublicKey: relayA.fixture.relayPublicKey, control, baseRuntime: runtimeAlt })
    ])
    assert.ok(bytesEqual(d1.physicalTopic, d2.physicalTopic), 'physicalTopic byte-identical')
    assert.ok(bytesEqual(d1.createCommitment, d2.createCommitment), 'createCommitment byte-identical')
    assert.ok(bytesEqual(d1.requestCommitment, d2.requestCommitment), 'create requestCommitment byte-identical')
    assert.ok(bytesEqual(d1.clientNonce, d2.clientNonce), 'clientNonce byte-identical')
    assert.ok(bytesEqual(d1.requestBytes, d2.requestBytes), 'CREATE request bytes byte-identical')
    for (const field of ['createPrivateKey', 'appendPrivateKey', 'renewPrivateKey', 'closePrivateKey']) {
      assert.ok(bytesEqual(d1.writeCap[field], d2.writeCap[field]),
        `writeCap ${field} byte-identical (same deterministic stream)`)
    }
    assert.ok(bytesEqual(d1.readCap.relayPublicKey, d2.readCap.relayPublicKey) &&
      bytesEqual(d1.readCap.physicalTopic, d2.readCap.physicalTopic) &&
      d1.readCap.frameClassBits === d2.readCap.frameClassBits &&
      d1.readCap.appendAuthMode === d2.readCap.appendAuthMode &&
      bytesEqual(d1.readCap.appendPublicKey, d2.readCap.appendPublicKey),
    'readCap public fields byte-identical')
    // Cross-implementation: block 0 → ed25519 public key → protocol topic hash.
    const seed = peeritInboxTopicSeedV1(BOARD, relayA.fixture.relayPublicKey)
    const block0 = peeritInboxTopicStreamBlockV1(seed, 0)
    const createPublicKey = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
    const secretKey = Buffer.alloc(sodium.crypto_sign_SECRETKEYBYTES)
    sodium.crypto_sign_seed_keypair(createPublicKey, secretKey, Buffer.from(block0))
    secretKey.fill(0)
    const expectedTopic = inboxPhysicalTopic({ allocationEpoch: 0, createPublicKey })
    assert.ok(bytesEqual(expectedTopic, d1.physicalTopic),
      'derived topic == protocol inboxPhysicalTopic(allocationEpoch 0, createPublicKey from stream block 0)')
    assert.ok(bytesEqual(d1.clientNonce, peeritInboxTopicStreamBlockV1(seed, 4)),
      'clientNonce is stream block 4 (after the four capability-key draws)')
    const otherBoard = await derivePeeritInboxTopicV1({
      boardSlug: 'otherboard', relayPublicKey: relayA.fixture.relayPublicKey, control, baseRuntime: runtime })
    assert.ok(!bytesEqual(otherBoard.physicalTopic, d1.physicalTopic), 'different board → different topic')
    const otherRelay = await derivePeeritInboxTopicV1({
      boardSlug: BOARD, relayPublicKey: relayB.fixture.relayPublicKey, control, baseRuntime: runtime })
    assert.ok(!bytesEqual(otherRelay.physicalTopic, d1.physicalTopic), 'same board, different relay → different topic')
    log('(a) topic derivation: byte-identical across runtimes (keys, topic, commitments, CREATE bytes), distinct per board and per relay, cross-checked against protocol inboxPhysicalTopic')
  }

  // -------------------------------------------------------------------------
  // Pointer frame codec: round-trip + every tamper class fails closed.
  // -------------------------------------------------------------------------
  {
    const fields = {
      boardSlug: BOARD,
      recordCid: new Uint8Array(randomBytes(32)),
      authorPubKey: new Uint8Array(randomBytes(32)),
      sizeClass: 1,
      leaseClass: 2,
      appendedAtUnixMillis: 1_754_000_000_000n,
      hints: [relayA.fixture.relayPublicKey, relayB.fixture.relayPublicKey]
    }
    const frame = encodePeeritInboxPointerFrameV1(fields)
    assert.equal(frame.byteLength, 4096)
    const decoded = decodePeeritInboxPointerFrameV1(frame)
    assert.equal(decoded.boardSlug, BOARD)
    assert.ok(bytesEqual(decoded.recordCid, fields.recordCid))
    assert.ok(bytesEqual(decoded.authorPubKey, fields.authorPubKey))
    assert.equal(decoded.sizeClass, 1)
    assert.equal(decoded.leaseClass, 2)
    assert.equal(decoded.appendedAtUnixMillis, fields.appendedAtUnixMillis)
    assert.equal(decoded.hints.length, 2)
    assert.ok(bytesEqual(decoded.hints[0], relayA.fixture.relayPublicKey))
    const expectInvalid = (mutate, label) => {
      const tampered = frame.slice()
      mutate(tampered)
      assert.throws(() => decodePeeritInboxPointerFrameV1(tampered),
        error => error.code === 'PEERIT_INBOX_POINTER_FRAME_INVALID', label)
    }
    expectInvalid(t => { t[0] ^= 0x01 }, 'magic byte flip')
    expectInvalid(t => { t[23] = 2 }, 'version flip')
    expectInvalid(t => { t[24] = 0 }, 'slugLen 0')
    expectInvalid(t => { t[24] = 65 }, 'slugLen 65')
    expectInvalid(t => { t[25] = 0x41 /* 'A' in slug */ }, 'slug charset')
    expectInvalid(t => { t[25 + BOARD.length + 64] = 0 }, 'sizeClass 0')
    expectInvalid(t => { t[25 + BOARD.length + 64] = 6 }, 'sizeClass 6')
    expectInvalid(t => { t[25 + BOARD.length + 65] = 5 }, 'leaseClass 5')
    expectInvalid(t => { t[25 + BOARD.length + 74] = 3 }, 'hintCount 3')
    expectInvalid(t => { t[4095] = 1 }, 'trailing nonzero padding')
    assert.throws(() => decodePeeritInboxPointerFrameV1(frame.subarray(0, 4095)),
      error => error.code === 'PEERIT_INBOX_POINTER_FRAME_INVALID', 'truncated frame')
    assert.throws(() => encodePeeritInboxPointerFrameV1({ ...fields, boardSlug: 'Bad Slug' }),
      error => error.code === 'PEERIT_INBOX_POINTER_FRAME_INVALID', 'encode rejects a bad slug')
    assert.throws(() => encodePeeritInboxPointerFrameV1({ ...fields, hints: fields.hints.concat(fields.hints[0]) }),
      error => error.code === 'PEERIT_INBOX_POINTER_FRAME_INVALID', 'encode rejects 3 hints')
    log('frame codec: round-trip exact (2 hints); magic/version/lengths/charset/classes/hints/trailing tamper classes all fail PEERIT_INBOX_POINTER_FRAME_INVALID')
  }

  // -------------------------------------------------------------------------
  // (b) end-to-end on relay A: genuine comment → CELL.PUT (2-slot token,
  // slot 0) → verified receipt + byte-exact readback → publish (READ probe
  // NOT_FOUND → CREATE with a fresh 1-slot token → APPEND slot 1, revision 1).
  // -------------------------------------------------------------------------
  const MARKER1 = `T2 INBOX discovery drill record 1 — ${new Date().toISOString()}`
  const record1 = await authorComment(MARKER1,
    'Declared drill record of the Peerit T2 INBOX-discovery drill (test/peerit-inbox-pointer-discovery.mjs). ' +
    'Authored by an ephemeral drill identity through the genuine Data.addComment path.')
  log(`author: comment ${record1.logical.cid.slice(0, 12)}… (in-record PoW ${record1.stored.pow.bits} bits at nonce ${record1.stored.pow.nonce}), tag-${record1.innerCodec} envelope ${record1.intentId.slice(0, 16)}…`)
  const pinnedNow1 = Date.now()
  const flow1 = await putAndPublish(relayA, record1, { hints: [], pinnedNow: pinnedNow1 })
  assert.equal(flow1.minted.allowance, 2)
  assert.equal(redeemCount, 2, 'record 1 on relay A: ONE 2-slot mint + ONE 1-slot create mint')
  assert.equal(flow1.published.created, true, 'topic absent → CREATE happened')
  assert.equal(flow1.published.appendRevision, 1n, 'first pointer appends at revision 1')
  {
    const receipt = decodePeeritInboxReceiptSnapshotV1(flow1.published.createEvidence)
    assert.equal(receipt.result, INBOX_RECEIPT_RESULT.CREATED)
    assert.equal(receipt.stateRevision, 0n)
    // Byte-parity: the strict local decoder vs @hiverelay/blind-protocol on
    // the authenticated relay-produced bytes (receipt + ack).
    const refReceipt = decodeCanonical(inboxReceiptV1, flow1.published.createEvidence, { copyBytes: true })
    assert.equal(refReceipt.result, receipt.result)
    assert.equal(BigInt(refReceipt.stateRevision), receipt.stateRevision)
    assert.equal(refReceipt.leaseClass, receipt.leaseClass)
    assert.equal(refReceipt.leaseEpoch, receipt.leaseEpoch)
    const ack = decodePeeritInboxAppendAckSnapshotV1(flow1.published.appendEvidence)
    const refAck = decodeCanonical(inboxAppendAckV1, flow1.published.appendEvidence, { copyBytes: true })
    assert.equal(ack.result, 1)
    assert.equal(BigInt(refAck.appendRevision), ack.appendRevision)
    assert.ok(bytesEqual(refAck.frameHash, ack.frameHash))
    assert.equal(refAck.storedAtEpoch, ack.storedAtEpoch)
    assert.equal(refAck.expiresAtEpoch, ack.expiresAtEpoch)
    assert.ok(bytesEqual(ack.frameHash, blake2b256(flow1.prepared.frame)),
      'ack frameHash binds the published pointer frame')
    log('(b) CELL.PUT receipt STORED + byte-exact readback; READ probe NOT_FOUND → CREATE (1-slot token, CREATED receipt verified) → APPEND slot 1 (ack verified, appendRevision 1); snapshot decoder byte-parity with decodeCanonical on receipt + ack')
  }

  // -------------------------------------------------------------------------
  // (c) fresh-reader discovery on relay A: poll from floor 0 → the pointer →
  // CELL.GET → full ingest verification → renders in a fresh view.
  // -------------------------------------------------------------------------
  const readerSync = new DevSync(memoryStorage(), 'inbox-drill-reader')
  await readerSync.ready()
  const readerId = new DevIdentity(memStorage(), memStorage())
  await readerId.ready()
  const readerData = createData(readerSync, readerId, { minBits: MIN_BITS, v2: true })
  {
    const poll = await pollBoard(relayA, 0n)
    assert.equal(poll.pagesRead, 1)
    assert.equal(poll.snapshotRevision, 1n)
    assert.equal(poll.newFloor, 1n)
    assert.equal(poll.rejections.length, 0)
    assert.equal(poll.pointers.length, 1)
    const pointer = poll.pointers[0]
    assert.equal(pointer.appendRevision, 1n)
    assert.equal(bytesToHex(pointer.recordCid), record1.logical.cid)
    assert.ok(bytesEqual(pointer.authorPubKey, hexToBytes(me, 32, 'author pubkey')))
    assert.equal(pointer.sizeClass, record1.sizeClass)
    assert.equal(pointer.leaseClass, LEASE_CLASS)
    assert.equal(pointer.appendedAtUnixMillis, BigInt(pinnedNow1))
    assert.equal(pointer.hints.length, 0)
    // Byte-parity of the READ snapshot decoder on relay-produced read bytes.
    const topic = await derivePeeritInboxTopicV1({
      boardSlug: BOARD, relayPublicKey: relayA.fixture.relayPublicKey, control, baseRuntime: runtime })
    const page = await control.createReadInboxRequest({ runtime, readCap: topic.readCap, limit: 64 })
    const pageResponse = await httpClient.request({
      endpoint: relayA.endpoints.read,
      familyId: page.wire.familyId,
      operationId: page.wire.operationId,
      expectedResultBodyBytes: page.wire.expectedResultBodyBytes,
      body: page.requestBytes
    })
    assert.equal(pageResponse.ok, true)
    const pageVerified = control.verifyOperationResult({
      endpoint: relayA.endpoints.read,
      request: page.request,
      requestCommitment: page.requestCommitment,
      resultBytes: pageResponse.body
    })
    const mine = decodePeeritInboxReadResultSnapshotV1(pageVerified.snapshotBytes())
    const reference = decodeCanonical(inboxReadResultV1, pageVerified.snapshotBytes(), { copyBytes: true })
    assert.equal(BigInt(reference.snapshotRevision), mine.snapshotRevision)
    assert.equal(reference.entries.length, mine.entries.length)
    for (const [index, entry] of mine.entries.entries()) {
      assert.equal(BigInt(reference.entries[index].appendRevision), entry.appendRevision)
      assert.ok(bytesEqual(reference.entries[index].frameHash, entry.frameHash))
      assert.equal(reference.entries[index].frameClass, entry.frameClass)
      assert.ok(bytesEqual(reference.entries[index].frame, entry.frame))
    }
    assert.equal(reference.nextCursor == null, mine.nextCursor == null)
    log('(c) READ snapshot decoder byte-parity with decodeCanonical(inboxReadResultV1) on relay-produced bytes (snapshotRevision, entries, nextCursor)')
    // The caller's follow-through: CELL.GET the discovered record (the drill's
    // GET path over the write-side capability), then ingest + render.
    await ingestAndRender(readerData, flow1.opened, record1, MARKER1,
      'discovered record 1')
    log('(c) discovery from floor 0 returns the pointer; CELL.GET opens the exact authored record; ingest verifier admits it; it renders in a fresh reader view')
  }
