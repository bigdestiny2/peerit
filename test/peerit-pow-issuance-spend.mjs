// test/peerit-pow-issuance-spend.mjs — LOCAL pow-issuance-v1 CELL.PUT spend drill
// for the Peerit T2 browser-write milestone. Fully in-process: real issuer
// (HTTP) + TWO production daemon runtimes + two real TLS edges + the genuine
// Peerit client pieces (vendored blind client + the browser spend provider
// module under test + the genuine relay-consumer admission seam). No fleet
// contact. CELL.PUT ONLY — no INBOX constructor is touched.
//
// Proves:
//   (a) the spend provider mints ONE two-slot token both local relays accept
//       for CELL.PUT (receipt STORED, signature-valid), with byte-exact
//       CELL.GET readback opened to the exact authored record bytes;
//   (b) byte-parity of the module's binding root / preimage / presentation /
//       leading-zero-bits with the relay's pow-issuance-v1/token-codec.js;
//   (c) byte-identical replay of the same PUT envelope → deterministic replay;
//   (d) re-slotting a spend unit onto a different request → SPEND_INVALID;
//   (e) bad PoW → issuer HTTP 400 POW_INSUFFICIENT_WORK;
//   (f) expired token → SPEND_INVALID;
//   (g) foreign-key token → SPEND_INVALID;
//   plus the genuine createAdmissionProvider seam (qualifyPermissionlessRelay
//   Candidates) driving the factory end-to-end, and the signed limited
//   Cell-PUT authority profile validator.
//
// Run: node test/peerit-pow-issuance-spend.mjs
import assert from 'node:assert/strict'
import { createHash, randomBytes } from 'node:crypto'
import { execFile } from 'node:child_process'
import fs from 'node:fs/promises'
import https from 'node:https'
import path from 'node:path'
import { promisify } from 'node:util'
import { fileURLToPath, pathToFileURL } from 'node:url'
import sodium from 'sodium-universal'
import {
  POW_ISSUANCE_V1_FLEET_ISSUER_ALLOWANCE_CAP,
  POW_ISSUANCE_V1_SCHEME_ID,
  buildPowIssuanceV1Presentation,
  countLeadingZeroBits,
  createPowIssuanceV1AdmissionProviderFactory,
  createPowIssuanceV1SpendProvider,
  powIssuanceV1Preimage,
  powIssuanceV1RecordBindingRoot
} from '../js/substrate/pow-issuance-spend-provider.mjs'
import {
  PEERIT_LIMITED_CELL_PUT_PROFILE_ID_V1,
  PEERIT_LIMITED_CELL_PUT_RELEASE_SEQUENCE,
  peeritLimitedCellPutProfileSourceV1,
  verifyPeeritLimitedCellPutProfileV1
} from '../js/substrate/limited-cell-put-profile.mjs'
import { bytesEqual, bytesToHex } from '../js/substrate/release-control-primitives.mjs'
import { qualifyPermissionlessRelayCandidates } from '../js/substrate/relay-consumer.js'

const execFileAsync = promisify(execFile)
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
// Production truth is the DEPLOYED fleet tree (00-core/hiverelay): its
// pow-issuance-v1 codec derives with SHA-256/HMAC-SHA256, never blake2b. The
// retired 00-core/v1-integration checkout carries the superseded blake2b
// design and must not be consulted for parity.
const VI_ROOT = process.env.HIVERELAY_V1_INTEGRATION_ROOT ||
  path.resolve(ROOT, '..', '..', '00-core', 'hiverelay')
const vi = (...parts) => pathToFileURL(path.join(VI_ROOT, ...parts)).href

// The full-stack drill needs the relay source tree (00-core/hiverelay). It runs
// wherever that checkout exists (fleet dev machines); where it is absent (CI)
// skip loudly — portable codec coverage there is carried by
// test/peerit-pow-issuance-codec-vectors.mjs.
const VI_TREE_PRESENT = await fs.stat(path.join(VI_ROOT, 'packages', 'blind-protocol', 'index.js'))
  .then(() => true, () => false)
if (!VI_TREE_PRESENT) {
  console.log('    [spend-drill] SKIP: hiverelay source tree absent — full-stack drill runs where 00-core/hiverelay is checked out; codec vectors covered by test/peerit-pow-issuance-codec-vectors.mjs')
  process.exit(0)
}

const protocol = await import(vi('packages', 'blind-protocol', 'index.js'))
const {
  CELL_RECEIPT_RESULT,
  ERROR_CODE,
  FAMILY,
  OPERATION,
  PROTOCOL,
  RESULT_SIGNATURE_DOMAIN_ID,
  blindReceiptV1,
  decodeCanonical,
  getCellResultV1,
  resultSignaturePayload
} = protocol
const ERROR_NAMES = new Map(Object.entries(ERROR_CODE).map(([name, code]) => [code, name]))
const { loadDaemonBootstrapConfig } = await import(vi('packages', 'blind-daemon', 'bootstrap-config.js'))
const {
  assembleProductionBlindDaemon,
  loadProductionRuntimeConfig
} = await import(vi('packages', 'blind-daemon', 'production-runtime.js'))
const {
  PowIssuanceV1AdmissionAdapter,
  createPowIssuanceV1AdapterResolver
} = await import(vi('packages', 'blind-daemon', 'pow-issuance-v1', 'admission-adapter.js'))
const { createPowIssuanceV1Issuer } = await import(vi('packages', 'blind-daemon', 'pow-issuance-v1', 'issuer-service.js'))
const codec = await import(vi('packages', 'blind-daemon', 'pow-issuance-v1', 'token-codec.js'))
const { powIssuanceV1DrillFixture } = await import(vi('packages', 'blind-daemon', 'test', 'pow-issuance-v1-drill-fixture.js'))
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
  console.log(`    [spend-drill] ${line}`)
}

function errorName (code) {
  return ERROR_NAMES.get(code) || `UNKNOWN(${code})`
}

function hex (bytes) {
  return Buffer.from(bytes).toString('hex')
}

function verifySignedBody (codecValue, body, domainId, publicKey) {
  const value = decodeCanonical(codecValue, body, { copyBytes: true })
  const unsigned = body.subarray(0, body.byteLength - sodium.crypto_sign_BYTES)
  const valid = sodium.crypto_sign_verify_detached(value.signature,
    resultSignaturePayload(domainId, unsigned), publicKey)
  return { value, valid }
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

// The drill watchdog: a rendezvous deadlock must fail fast, not hang npm test.
const watchdog = setTimeout(() => {
  console.error('[spend-drill] WATCHDOG: drill exceeded its bounded deadline')
  process.exit(1)
}, 900_000)
watchdog.unref()

// ---------------------------------------------------------------------------
// (b) byte-parity with the DEPLOYED fleet's pow-issuance-v1/token-codec.js
// (00-core/hiverelay — HMAC-SHA256, never blake2b) — the module re-implements
// nothing in the test: both sides are called on identical inputs and compared
// byte-for-byte. The two binding-root vectors are pinned verbatim against the
// fleet module (relay-lane handoff, 2026-08-07).
// ---------------------------------------------------------------------------
{
  assert.equal(
    bytesToHex(powIssuanceV1RecordBindingRoot([
      new Uint8Array(32).fill(0x01), new Uint8Array(32).fill(0x02)])),
    '25ce7c823116a3d63265703133d11680c02cc7466a069a283b6d8613def6e47e',
    'fleet vector: binding root of slots [32×0x01, 32×0x02] (HMAC-SHA256 design)')
  assert.equal(
    bytesToHex(powIssuanceV1RecordBindingRoot([new Uint8Array(32).fill(0x77)])),
    '135b2246b1b8ab7e270b4538cc3ea88e3aac579e02fd94030254fff11a9b2acc',
    'fleet vector: binding root of slots [32×0x77] (HMAC-SHA256 design)')
  assert.ok(bytesEqual(
    powIssuanceV1RecordBindingRoot([new Uint8Array(32).fill(0x01), new Uint8Array(32).fill(0x02)]),
    codec.powIssuanceV1RecordBindingRoot([new Uint8Array(32).fill(0x01), new Uint8Array(32).fill(0x02)])),
  'the fleet codec reproduces the pinned vector exactly')
}
{
  const c0 = new Uint8Array(randomBytes(32))
  const c1 = new Uint8Array(randomBytes(32))
  const challengePayload = new Uint8Array(randomBytes(42))
  assert.ok(bytesEqual(
    powIssuanceV1RecordBindingRoot([c0, c1]),
    codec.powIssuanceV1RecordBindingRoot([c0, c1])),
  'binding root must be byte-identical to token-codec.js')
  assert.ok(bytesEqual(
    powIssuanceV1RecordBindingRoot([c0]),
    codec.powIssuanceV1RecordBindingRoot([c0])),
  'single-slot binding root must be byte-identical to token-codec.js')
  const root = powIssuanceV1RecordBindingRoot([c0, c1])
  assert.ok(bytesEqual(
    powIssuanceV1Preimage(challengePayload, root, 0n),
    codec.powIssuanceV1Preimage(challengePayload, root, 0n)))
  assert.ok(bytesEqual(
    powIssuanceV1Preimage(challengePayload, root, 0xffffffffffffffffn),
    codec.powIssuanceV1Preimage(challengePayload, root, 0xffffffffffffffffn)),
  'PoW preimage must be byte-identical to token-codec.js')
  const token = new Uint8Array(randomBytes(103))
  for (const spendIndex of [0, 1]) {
    assert.ok(bytesEqual(
      buildPowIssuanceV1Presentation(token, spendIndex, [c0, c1]),
      codec.buildPowIssuanceV1Presentation(token, spendIndex, [c0, c1])),
    `presentation slot ${spendIndex} must be byte-identical to token-codec.js`)
  }
  for (let trial = 0; trial < 64; trial++) {
    const digest = new Uint8Array(randomBytes(32))
    assert.equal(countLeadingZeroBits(digest), codec.countLeadingZeroBits(digest))
  }
  assert.equal(countLeadingZeroBits(new Uint8Array(32)), codec.countLeadingZeroBits(new Uint8Array(32)))
  log('(b) byte-parity: binding root, preimage, presentation, leading-zero-bits all byte-identical to token-codec.js')
}

// ---------------------------------------------------------------------------
// Signed limited Cell-PUT authority profile: validator accepts the exact
// ceremony shape and rejects posture drift. The fleet pins come from the
// current signed seed bootstrap replica keys and the probed issuer origins.
// ---------------------------------------------------------------------------
{
  const profileSource = peeritLimitedCellPutProfileSourceV1({
    relays: [
      {
        relayId: 'dal-1',
        relayPublicKey: '8b3f4161271cfa511bc49fb03033d6441da01bf27c35a754e2a1b0d7df32e1d2',
        issuanceUrl: 'https://relay-dal.p2phiverelay.xyz:8443/'
      },
      {
        relayId: 'syd-1',
        relayPublicKey: '52f4d78364180553a944629b5dd90834d3c3d4f7755cc2e452b3308329a88161',
        issuanceUrl: 'https://relay-syd.p2phiverelay.xyz:8443/'
      }
    ],
    supportedProtocolProfiles: [1, 2, 3, 4].map(protocolId => ({
      protocolId, major: 1, minimumMinor: 0, profileHash: '0a'.repeat(32)
    })),
    supportedTransportProfiles: [{
      transportId: 1, transportSupportBit: 1, transportProfileHash: '0b'.repeat(32)
    }]
  })
  const snapshot = verifyPeeritLimitedCellPutProfileV1(
    new TextEncoder().encode(profileSource),
    { releaseSequence: PEERIT_LIMITED_CELL_PUT_RELEASE_SEQUENCE })
  assert.equal(snapshot.releaseSequence, PEERIT_LIMITED_CELL_PUT_RELEASE_SEQUENCE)
  assert.equal(snapshot.mode, 'explicit-user-writes')
  assert.equal(snapshot.networkPuts, 1, 'writes enabled as explicit user actions only')
  assert.equal(snapshot.ordinaryDelivery, 'local-only', 'ordinary READS stay local-only')
  assert.deepEqual(snapshot.powIssuance, {
    schemeId: POW_ISSUANCE_V1_SCHEME_ID,
    profileId: PEERIT_LIMITED_CELL_PUT_PROFILE_ID_V1,
    conformanceClass: 1,
    roleBits: 49,
    difficultyBits: 20,
    maximumTokenAllowance: POW_ISSUANCE_V1_FLEET_ISSUER_ALLOWANCE_CAP,
    maximumCellSizeClass: 2,
    maximumCellLeaseClass: 2
  })
  assert.equal(snapshot.requirement.operationId, 1, 'CELL.PUT requirement')
  assert.equal(snapshot.readRequirement.operationId, 2, 'paired CELL.GET readback requirement')
  assert.equal(snapshot.relays[0].relayId, 'dal-1')
  assert.equal(snapshot.relays[1].relayId, 'syd-1')
  // Fleet slot layout: relay-public-key byte order puts syd-1 (52f4…) in slot 0.
  const sorted = [...snapshot.relays].sort((left, right) =>
    Buffer.compare(Buffer.from(left.relayPublicKey), Buffer.from(right.relayPublicKey)))
  assert.equal(sorted[0].relayId, 'syd-1', 'slot 0 is the smallest relay public key (syd-1)')
  assert.equal(sorted[1].relayId, 'dal-1', 'slot 1 is dal-1')
  assert.throws(
    () => verifyPeeritLimitedCellPutProfileV1(new TextEncoder().encode(profileSource),
      { releaseSequence: PEERIT_LIMITED_CELL_PUT_RELEASE_SEQUENCE - 1 }),
    error => error.code === 'PEERIT_LIMITED_CELL_PUT_PROFILE_INVALID')
  assert.throws(
    () => verifyPeeritLimitedCellPutProfileV1(new TextEncoder().encode(
      profileSource.replace('"networkPuts": 1', '"networkPuts": 0')),
      { releaseSequence: PEERIT_LIMITED_CELL_PUT_RELEASE_SEQUENCE }),
    error => error.code === 'PEERIT_LIMITED_CELL_PUT_PROFILE_INVALID')
  assert.throws(
    () => verifyPeeritLimitedCellPutProfileV1(new TextEncoder().encode(
      profileSource.replace('https://relay-syd.p2phiverelay.xyz:8443/', 'https://issuer.evil.example/')),
      { releaseSequence: PEERIT_LIMITED_CELL_PUT_RELEASE_SEQUENCE }),
    error => error.code === 'PEERIT_LIMITED_CELL_PUT_PROFILE_INVALID')
  log(`authority profile: schema peerit-limited-cell-put-profile-v1 pins schemeId 1/profileId 8, roleBits 49, difficulty 20, sizeClass ≤2, leaseClass ≤2, networkPuts 1, ordinaryDelivery local-only (releaseSequence ${PEERIT_LIMITED_CELL_PUT_RELEASE_SEQUENCE})`)
}

// ---------------------------------------------------------------------------
// Stack standup: ONE shared issuer + TWO production daemon runtimes behind two
// real TLS edges — the fleet shape (shared issuer key, per-relay parameter
// hashes) on loopback. LOCAL only; never touches the fleet.
// ---------------------------------------------------------------------------
const runtime = control.createBrowserCryptoRuntime(globalThis.crypto)
const issuerKey = new Uint8Array(randomBytes(32))
const issuerKeys = codec.derivePowIssuanceV1Keys(issuerKey)
const issuer = createPowIssuanceV1Issuer({ issuerKey }) // default difficulty 20 bits, allowance cap 2
await issuer.start()
const issuerBase = `http://127.0.0.1:${issuer.address().port}`
log(`issuer up at ${issuerBase} (difficulty=${issuer.difficultyBits} bits, maxAllowance=${issuer.maxAllowance})`)

const relays = []
let replayOffset = -15_000n
async function standupRelay (label) {
  const directory = await createBlindBoundaryScratch(`powspend-${label}-`)
  const fixture = await powIssuanceV1DrillFixture({
    issuerPort: issuer.address().port, issuerKey, directory })
  const adapter = new PowIssuanceV1AdmissionAdapter({ issuerKey })
  const bootstrap = loadDaemonBootstrapConfig(fixture.environment)
  const daemonRuntime = await assembleProductionBlindDaemon({
    bootstrap: Object.freeze({ ...bootstrap, expectedPeerUid: process.getuid() }),
    runtimeConfig: loadProductionRuntimeConfig(fixture.environment, bootstrap.endpointIds),
    enableCellRuntime: true,
    // The shared drill fixture's descriptor advertises the full DESCRIBE+CELL+
    // INBOX bit set, so the local daemon assembles both runtimes; this drill
    // still never constructs or sends an INBOX operation (CELL.PUT ONLY).
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
// The fleet tree reports the two CELL assembly-requirement blockers statically
// even when wired (stale flag, same as its own drill test); the functional
// readiness signal is v2WritePathReady plus a complete admission capture.
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

// The drill stands in for the fleet admission profile: the hiverelay drill
// fixture advertises pow-issuance-v1 (schemeId 1) on profileId 8, exactly the
// fleet's OPEN write profile.
const drillAdmissionProfile = Object.freeze({
  profileId: PEERIT_LIMITED_CELL_PUT_PROFILE_ID_V1,
  schemeId: POW_ISSUANCE_V1_SCHEME_ID,
  conformanceClass: 1,
  roleBits: 49,
  parameterUrl: null
})

const factory = createPowIssuanceV1AdmissionProviderFactory({
  profileId: drillAdmissionProfile.profileId,
  schemeId: POW_ISSUANCE_V1_SCHEME_ID,
  issuers: [
    { relayPublicKey: relayA.fixture.relayPublicKey, issuanceUrl: `${issuerBase}/` },
    { relayPublicKey: relayB.fixture.relayPublicKey, issuanceUrl: `${issuerBase}/` }
  ],
  allowInsecureLoopback: true,
  onProgress: nonce => log(`mint progress: ${nonce} candidates`)
})

// The seam calls createAdmissionProvider once per PUT-qualified relay; the
// drill passes exactly the seam's argument shape.
async function drillProvider (relay) {
  return factory.createAdmissionProvider({
    candidate: Object.freeze({ canonicalUrl: `https://127.0.0.1:${relay.edgePort}/api/blind/v1/describe` }),
    endpointContext: Object.freeze({ relayPublicKey: relay.fixture.relayPublicKey }),
    verifiedAdmissionParameters: Object.freeze({ parameterHash: relay.fixture.parameterHash }),
    admissionProfile: drillAdmissionProfile,
    signal: null
  })
}

const providerA = await drillProvider(relayA)
const providerB = await drillProvider(relayB)

try {
  // -------------------------------------------------------------------------
  // (a) ONE record, ONE mint, CELL.PUT on BOTH relays + byte-exact readback.
  // The record session collects each relay's PUT requestCommitment, orders the
  // slots by relay public key bytes, and mints a single two-slot token.
  // -------------------------------------------------------------------------
  const record = factory.beginRecord({
    relayPublicKeys: [relayA.fixture.relayPublicKey, relayB.fixture.relayPublicKey]
  })
  assert.equal(record.allowance, 2)
  const slotA = record.slotIndexOf(relayA.fixture.relayPublicKey)
  const slotB = record.slotIndexOf(relayB.fixture.relayPublicKey)
  assert.deepEqual([slotA, slotB].sort(), [0, 1])
  const expectedOrder = [relayA, relayB].sort((left, right) =>
    Buffer.compare(Buffer.from(left.fixture.relayPublicKey), Buffer.from(right.fixture.relayPublicKey)))
  assert.equal(slotA === 0 ? relayA : relayB, expectedOrder[0], 'slot 0 is the smallest relay public key')

  const structuredContent = Buffer.from(
    `peerit T2 pow-issuance spend drill record ${new Date().toISOString()} (inline, one cell)`, 'utf8')
  const captured = new Map() // relay label -> seam-shaped admission value
  const captureProvider = (relay, provider) => async context => {
    const value = await provider(context)
    // Exactly the drift checks relay-consumer admissionProviderFor applies.
    assert.equal(value.profileId, drillAdmissionProfile.profileId)
    assert.equal(value.schemeId, drillAdmissionProfile.schemeId)
    assert.ok(bytesEqual(value.parameterHash, relay.fixture.parameterHash),
      'the provider echoes THIS relay\'s verified pow-issuance parameterHash')
    captured.set(relay.label, value)
    return value
  }

  let redeemCount = 0
  const countingFetch = globalThis.fetch
  globalThis.fetch = (url, options) => {
    if (String(url).endsWith('/redeem')) redeemCount++
    return countingFetch(url, options)
  }
  let replicaA
  let replicaB
  try {
    ;[replicaA, replicaB] = await Promise.all([
      control.createCellReplica({
        runtime,
        relayPublicKey: relayA.fixture.relayPublicKey,
        allocationEpoch: relayA.fixture.currentEpoch,
        sizeClass: 1,
        leaseClass: 1,
        structuredContent,
        admissionProvider: captureProvider(relayA, providerA)
      }),
      control.createCellReplica({
        runtime,
        relayPublicKey: relayB.fixture.relayPublicKey,
        allocationEpoch: relayB.fixture.currentEpoch,
        sizeClass: 1,
        leaseClass: 1,
        structuredContent,
        admissionProvider: captureProvider(relayB, providerB)
      })
    ])
  } finally {
    globalThis.fetch = countingFetch
  }
  const minted = await record.complete
  log(`(a) ONE PoW mint covered both relays: ${minted.difficultyBits} bits in ${minted.mintMillis}ms ` +
    `(${minted.attempts} attempts), allowance=${minted.allowance}, expiryEpoch=${minted.expiryEpoch}, ` +
    `redeem calls=${redeemCount}`)
  assert.equal(redeemCount, 1, 'exactly ONE token is minted per record across both relays')
  assert.equal(minted.allowance, 2)

  const tokenA = captured.get('a').token
  const tokenB = captured.get('b').token
  assert.equal(tokenA.byteLength, 136, 'two-slot presentation is token‖u8(slot)‖32B sibling')
  assert.ok(bytesEqual(tokenA.subarray(0, 103), tokenB.subarray(0, 103)),
    'both relays receive presentations of the SAME signed token')
  assert.equal(tokenA[103], slotA, 'relay a presentation carries its own slot index')
  assert.equal(tokenB[103], slotB, 'relay b presentation carries its own slot index')
  const orderedCommitments = slotA === 0
    ? [replicaA.requestCommitment, replicaB.requestCommitment]
    : [replicaB.requestCommitment, replicaA.requestCommitment]
  assert.ok(bytesEqual(
    codec.powIssuanceV1RecordBindingRoot(orderedCommitments), minted.recordCommitment),
  'the token binding root commits to [slot0 commitment, slot1 commitment]')
  const parsedA = codec.parsePowIssuanceV1Presentation(tokenA)
  assert.equal(parsedA.spendIndex, slotA)
  assert.ok(bytesEqual(parsedA.siblings[0], orderedCommitments[slotB]), 'siblings carry the OTHER slot in slot order')

  const putEncodedA = encodeUnaryRequest({
    runtime,
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.PUT,
    body: replicaA.requestBytes,
    expectedResultBodyBytes: replicaA.wire.expectedResultBodyBytes
  })
  const putA = await send(relayA, '/api/blind/v1/cell', putEncodedA)
  assert.equal(putA.httpStatus, 200)
  assert.equal(putA.ok, true, `relay a CELL.PUT rejected: ${putA.error ? errorName(putA.error.code) : 'transport'}`)
  const receiptA = verifySignedBody(blindReceiptV1, putA.body,
    RESULT_SIGNATURE_DOMAIN_ID.CELL_RECEIPT, relayA.fixture.relayPublicKey)
  assert.equal(receiptA.valid, true)
  assert.equal(receiptA.value.result, CELL_RECEIPT_RESULT.STORED)
  assert.ok(bytesEqual(receiptA.value.cellBlobHash, replicaA.request.declaredBlobHash))
  assert.ok(bytesEqual(receiptA.value.requestCommitment, replicaA.requestCommitment))

  const putB = await send(relayB, '/api/blind/v1/cell', encodeUnaryRequest({
    runtime,
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.PUT,
    body: replicaB.requestBytes,
    expectedResultBodyBytes: replicaB.wire.expectedResultBodyBytes
  }))
  assert.equal(putB.httpStatus, 200)
  assert.equal(putB.ok, true, `relay b CELL.PUT rejected: ${putB.error ? errorName(putB.error.code) : 'transport'}`)
  const receiptB = verifySignedBody(blindReceiptV1, putB.body,
    RESULT_SIGNATURE_DOMAIN_ID.CELL_RECEIPT, relayB.fixture.relayPublicKey)
  assert.equal(receiptB.valid, true)
  assert.equal(receiptB.value.result, CELL_RECEIPT_RESULT.STORED)
  assert.ok(bytesEqual(receiptB.value.cellBlobHash, replicaB.request.declaredBlobHash))
  log(`(a) CELL.PUT receipts: a=STORED (slot ${slotA}, leaseEpoch=${receiptA.value.leaseEpoch}), b=STORED (slot ${slotB}, leaseEpoch=${receiptB.value.leaseEpoch}), both signature-valid`)

  // Byte-exact readback: uncharged CELL.GET (admission OPTIONAL, none sent),
  // the sealed blob hash-pinned by the read capability, opened to the exact
  // authored record — the local render proof. Zero relay trust: the blob hash
  // inside the client-held readCap authenticates the bytes, not the relay.
  async function readback (relay, replica) {
    const get = await control.createGetCellRequest({ runtime, readCap: replica.readCap })
    const response = await send(relay, '/api/blind/v1/cell', encodeUnaryRequest({
      runtime,
      familyId: FAMILY.CELL,
      operationId: OPERATION.CELL.GET,
      body: get.requestBytes,
      expectedResultBodyBytes: get.wire.expectedResultBodyBytes
    }))
    assert.equal(response.ok, true, `${relay.label} CELL.GET failed`)
    const result = decodeCanonical(getCellResultV1, response.body, { copyBytes: true })
    const opened = await openCell({
      runtime,
      storageSlot: replica.readCap.storageSlot,
      cellKey: replica.readCap.cellKey,
      sizeClass: replica.readCap.sizeClass,
      expectedCellBlobHash: replica.readCap.expectedCellBlobHash,
      cellBlob: result.cellBlob
    })
    assert.ok(bytesEqual(opened, structuredContent),
      `${relay.label} readback must open to the exact authored record bytes`)
    return opened
  }
  await readback(relayA, replicaA)
  await readback(relayB, replicaB)
  log('(a) byte-exact readback on BOTH relays: CELL.GET opened to the exact authored record (local render proof)')
  record.close()

  // -------------------------------------------------------------------------
  // (c) byte-identical replay of the same PUT envelope → deterministic replay
  // of the original STORED receipt; no second store, no second spend.
  // -------------------------------------------------------------------------
  const replay = await httpsPost(relayA.edgePort, '/api/blind/v1/cell', putEncodedA.body)
  assert.equal(replay.statusCode, 200)
  const replayReceipt = verifySignedBody(blindReceiptV1,
    decodeUnaryResponse(replay.body, putEncodedA).body,
    RESULT_SIGNATURE_DOMAIN_ID.CELL_RECEIPT, relayA.fixture.relayPublicKey)
  assert.equal(replayReceipt.valid, true)
  assert.equal(replayReceipt.value.result, CELL_RECEIPT_RESULT.STORED)
  assert.ok(bytesEqual(replayReceipt.value.cellBlobHash, receiptA.value.cellBlobHash))
  assert.equal(replayReceipt.value.leaseEpoch, receiptA.value.leaseEpoch)
  assert.equal(replayReceipt.value.stateRevision, receiptA.value.stateRevision)
  log(`(c) byte-identical envelope replay: deterministic STORED receipt (stateRevision=${replayReceipt.value.stateRevision}, idempotent — no second spend)`)

  // -------------------------------------------------------------------------
  // (d) re-slotting the spend unit onto a DIFFERENT request: the presentation
  // is byte-identical to the accepted one, but the new request's commitment is
  // not the committed slot → binding-root mismatch → SPEND_INVALID.
  // -------------------------------------------------------------------------
  const misReplica = await control.createCellReplica({
    runtime,
    relayPublicKey: relayA.fixture.relayPublicKey,
    allocationEpoch: relayA.fixture.currentEpoch,
    sizeClass: 1,
    leaseClass: 1,
    structuredContent: Buffer.from('re-slotted spend drill (must be rejected)', 'utf8'),
    admissionProvider: async () => Object.freeze({
      profileId: drillAdmissionProfile.profileId,
      schemeId: POW_ISSUANCE_V1_SCHEME_ID,
      parameterHash: relayA.fixture.parameterHash,
      token: buildPowIssuanceV1Presentation(minted.token, slotA, orderedCommitments)
    })
  })
  const misResponse = await send(relayA, '/api/blind/v1/cell', encodeUnaryRequest({
    runtime,
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.PUT,
    body: misReplica.requestBytes,
    expectedResultBodyBytes: misReplica.wire.expectedResultBodyBytes
  }))
  assert.equal(misResponse.ok, false)
  assert.equal(misResponse.error.code, ERROR_CODE.SPEND_INVALID)
  log(`(d) re-slotted spend unit on a different request: rejected ${errorName(misResponse.error.code)}`)

  // -------------------------------------------------------------------------
  // (e) bad PoW → the issuer refuses; no token exists. The bad nonce is
  // pre-scanned with the reference codec against the exact challenge and
  // commitment being redeemed, so the drill is deterministic.
  // -------------------------------------------------------------------------
  async function certainlyBadNonce (challengePayload, recordCommitment, difficultyBits) {
    for (let candidate = 0n; candidate < 65536n; candidate++) {
      const digest = createHash('sha256')
        .update(codec.powIssuanceV1Preimage(challengePayload, recordCommitment, candidate))
        .digest()
      if (codec.countLeadingZeroBits(digest) < difficultyBits) return candidate
    }
    throw new Error('a certainly-bad nonce must exist in the first 65536 candidates')
  }
  {
    const challenge = await (await fetch(`${issuerBase}/challenge`)).json()
    const challengeBytes = Buffer.from(challenge.challenge.replace(/-/g, '+').replace(/_/g, '/'), 'base64')
    const challengePayload = challengeBytes.subarray(0, 42)
    const badCommitment = powIssuanceV1RecordBindingRoot([new Uint8Array(randomBytes(32))])
    const badNonce = await certainlyBadNonce(challengePayload, badCommitment, challenge.difficultyBits)
    const nonceBytes = Buffer.alloc(8)
    nonceBytes.writeBigUInt64BE(badNonce, 0)
    const raw = await fetch(`${issuerBase}/redeem`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        challenge: challenge.challenge,
        nonce: nonceBytes.toString('hex'),
        recordCommitment: hex(badCommitment),
        allowance: 1
      })
    })
    assert.equal(raw.status, 400)
    assert.equal((await raw.json()).error, 'POW_INSUFFICIENT_WORK')
    const spendProvider = createPowIssuanceV1SpendProvider({
      issuanceUrl: `${issuerBase}/`,
      allowInsecureLoopback: true
    })
    const providerChallenge = await spendProvider.fetchChallenge()
    const providerCommitment = powIssuanceV1RecordBindingRoot([new Uint8Array(randomBytes(32))])
    const providerBadNonce = await certainlyBadNonce(
      providerChallenge.challengePayload, providerCommitment, providerChallenge.difficultyBits)
    await assert.rejects(
      spendProvider.redeem({
        challengeWire: providerChallenge.challengeWire,
        nonce: providerBadNonce,
        recordCommitment: providerCommitment,
        allowance: 1
      }),
      error => error.code === 'PEERIT_POW_ISSUANCE_REDEEM_REJECTED' &&
        error.httpStatus === 400 && error.issuerError === 'POW_INSUFFICIENT_WORK')
    log('(e) bad PoW redeem: issuer HTTP 400 POW_INSUFFICIENT_WORK (raw fetch and spend provider alike); no token issued')
  }

  // -------------------------------------------------------------------------
  // (f) expired token and (g) foreign-key token → SPEND_INVALID at preflight.
  // -------------------------------------------------------------------------
  async function rejectedPut (relay, mintOptions, label) {
    const replica = await control.createCellReplica({
      runtime,
      relayPublicKey: relay.fixture.relayPublicKey,
      allocationEpoch: relay.fixture.currentEpoch,
      sizeClass: 1,
      leaseClass: 1,
      structuredContent: Buffer.from(`${label} drill`, 'utf8'),
      admissionProvider: async context => {
        const token = codec.mintPowIssuanceV1Token(mintOptions.tokenKey, {
          challengeId: new Uint8Array(randomBytes(32)),
          recordCommitment: codec.powIssuanceV1RecordBindingRoot([context.requestCommitment]),
          allowance: 1,
          expiryEpoch: mintOptions.expiryEpoch
        })
        return Object.freeze({
          profileId: drillAdmissionProfile.profileId,
          schemeId: POW_ISSUANCE_V1_SCHEME_ID,
          parameterHash: relay.fixture.parameterHash,
          token: buildPowIssuanceV1Presentation(token, 0, [context.requestCommitment])
        })
      }
    })
    const response = await send(relay, '/api/blind/v1/cell', encodeUnaryRequest({
      runtime,
      familyId: FAMILY.CELL,
      operationId: OPERATION.CELL.PUT,
      body: replica.requestBytes,
      expectedResultBodyBytes: replica.wire.expectedResultBodyBytes
    }))
    assert.equal(response.ok, false, `${label} token must be rejected`)
    assert.equal(response.error.code, ERROR_CODE.SPEND_INVALID)
    log(`(${label}) rejected ${errorName(response.error.code)}`)
  }
  await rejectedPut(relayA, {
    tokenKey: issuerKeys.tokenKey,
    expiryEpoch: relayA.fixture.currentEpoch // already elapsed
  }, 'f')
  await rejectedPut(relayA, {
    tokenKey: new Uint8Array(randomBytes(32)), // foreign issuer key
    expiryEpoch: relayA.fixture.currentEpoch + 4
  }, 'g')

  // -------------------------------------------------------------------------
  // Seam end-to-end: the GENUINE relay-consumer qualification seam drives the
  // factory (createAdmissionProvider → per-relay provider → wrapped drift
  // checks) and a single-slot record mints through it. Mock descriptor stack;
  // real factory, real issuer, real mint.
  // -------------------------------------------------------------------------
  {
    const seamFactory = createPowIssuanceV1AdmissionProviderFactory({
      profileId: PEERIT_LIMITED_CELL_PUT_PROFILE_ID_V1,
      schemeId: POW_ISSUANCE_V1_SCHEME_ID,
      issuers: [{ relayPublicKey: relayA.fixture.relayPublicKey, issuanceUrl: `${issuerBase}/` }],
      allowInsecureLoopback: true
    })
    // Negative seam contracts first (no record open, drifted profile, foreign relay).
    await assert.rejects(
      seamFactory.createAdmissionProvider({
        candidate: Object.freeze({}),
        endpointContext: Object.freeze({ relayPublicKey: relayA.fixture.relayPublicKey }),
        verifiedAdmissionParameters: Object.freeze({ parameterHash: relayA.fixture.parameterHash }),
        admissionProfile: Object.freeze({ ...drillAdmissionProfile, profileId: 9 }),
        signal: null
      }),
      error => error.code === 'PEERIT_POW_ISSUANCE_PROFILE_DRIFT')
    await assert.rejects(
      seamFactory.createAdmissionProvider({
        candidate: Object.freeze({}),
        endpointContext: Object.freeze({ relayPublicKey: new Uint8Array(randomBytes(32)) }),
        verifiedAdmissionParameters: Object.freeze({ parameterHash: relayA.fixture.parameterHash }),
        admissionProfile: Object.freeze({
          profileId: PEERIT_LIMITED_CELL_PUT_PROFILE_ID_V1,
          schemeId: POW_ISSUANCE_V1_SCHEME_ID,
          conformanceClass: 1,
          roleBits: 49,
          parameterUrl: null
        }),
        signal: null
      }),
      error => error.code === 'PEERIT_POW_ISSUANCE_UNEXPECTED_RELAY')

    const parameterHash = relayA.fixture.parameterHash
    const relayPublicKey = relayA.fixture.relayPublicKey
    const descriptorHash = new Uint8Array(32).fill(0x11)
    const continuityRoot = relayA.fixture.relayPublicKey
    const canonicalUrl = 'https://pow-spend-drill.local/api/blind/v1/describe'
    const endpointContexts = new WeakMap()
    const trustedValidities = new WeakMap()
    const healthValidities = new WeakMap()
    const admissionValidities = new WeakMap()
    const endpoint = context => {
      const value = Object.freeze({})
      endpointContexts.set(value, Object.freeze(context))
      return value
    }
    class TrustStore {
      async accept (descriptor) {
        const value = Object.freeze({ descriptor })
        trustedValidities.set(value, Object.freeze({ issuedEpoch: 100, expiresEpoch: 104 }))
        return value
      }
    }
    class BootstrapClient {
      async fetchVerifiedDescriptor (request) {
        assert.equal(Buffer.from(request.canonicalUrl).toString('utf8'), canonicalUrl)
        return Object.freeze({
          descriptorHash,
          descriptorSequence: 0n,
          relayPublicKey,
          storeId: new Uint8Array(32).fill(0x62)
        })
      }
    }
    class Qualifier {
      constructor (input) {
        this.bootstrapClient = input.bootstrapClient
        this.trustStore = input.trustStore
      }

      async qualifyCandidate (candidate, requirement) {
        const descriptor = await this.bootstrapClient.fetchVerifiedDescriptor(candidate)
        const trustedDescriptor = await this.trustStore.accept(descriptor)
        const context = {
          descriptorHash,
          descriptorSequence: 0n,
          relayPublicKey,
          storeId: new Uint8Array(32).fill(0x62),
          continuityRoot,
          familyId: requirement.familyId,
          operationId: requirement.operationId,
          endpointId: requirement.endpointId,
          transportId: 1,
          transportSupportBit: requirement.transportSupportBit,
          privacyProfileBit: requirement.privacyProfileBit,
          durabilityProfileId: 1,
          durabilityContinuityHash: new Uint8Array(32).fill(0x70)
        }
        const health = Object.freeze({})
        healthValidities.set(health, Object.freeze({
          verifiedAtMonotonicMillis: 1_000,
          expiresAtMonotonicMillis: 601_000
        }))
        return Object.freeze({
          endpoint: endpoint(context),
          trustedDescriptor,
          health,
          descriptorHash,
          continuityRootRelayPublicKey: continuityRoot
        })
      }
    }
    class DirectClient {
      async request () { return Object.freeze({ ok: true, body: new Uint8Array([1]) }) }
    }
    const seamControl = Object.freeze({
      HEALTH_QUALIFICATION_LIMITS: Object.freeze({ maximumAgeMillis: 600_000 }),
      BlindDescriptorBootstrapHttpClient: BootstrapClient,
      BlindDirectHttpClient: DirectClient,
      BlindRelayQualifier: Qualifier,
      DescriptorTrustStore: TrustStore,
      createGetCellRequest: async () => Object.freeze({}),
      openVerifiedCellGetResult: async () => new Uint8Array(),
      createAdmissionParametersRequest () {
        return Object.freeze({
          request: Object.freeze({}),
          requestBytes: new TextEncoder().encode('admission'),
          wire: Object.freeze({ familyId: 1, operationId: 3, expectedResultBodyBytes: 16_384 })
        })
      },
      qualifyDescribeControlEndpoint: () => endpoint({ familyId: 1, operationId: 3 }),
      trustedAdmissionProfile: () => Object.freeze({
        profileId: PEERIT_LIMITED_CELL_PUT_PROFILE_ID_V1,
        schemeId: POW_ISSUANCE_V1_SCHEME_ID,
        conformanceClass: 1,
        roleBits: 49,
        parameterUrl: null,
        parameterHash
      }),
      trustedDescriptorValidity: trusted => trustedValidities.get(trusted),
      verifiedHealthValidity: health => healthValidities.get(health),
      verifiedEndpointContext (value) {
        const context = endpointContexts.get(value)
        if (!context || !context.descriptorHash) throw new Error('VerifiedEndpoint required')
        return context
      },
      verifyAdmissionParametersBytes () {
        const verified = Object.freeze({ parameterHash })
        admissionValidities.set(verified, Object.freeze({ validFromEpoch: 100, expiresEpoch: 103 }))
        return verified
      },
      verifiedAdmissionParametersValidity: value => admissionValidities.get(value)
    })
    let seamWrappedProvider = null
    const qualification = await qualifyPermissionlessRelayCandidates({
      control: seamControl,
      cryptoRuntime: { randomBytes: length => new Uint8Array(randomBytes(length)) },
      nowEpoch: () => 101,
      monotonicMillis: () => 1_000,
      profile: {
        supportedProtocolProfiles: [{ protocolId: 2, major: 1, minimumMinor: 0, profileHash: new Uint8Array(32).fill(0x81) }],
        supportedTransportProfiles: [{ transportId: 1, transportSupportBit: 1, transportProfileHash: new Uint8Array(32).fill(0x82) }],
        requirement: {
          familyId: 2, operationId: 1, endpointId: 1,
          requiredRoleBits: 49, privacyProfileBit: 1, transportSupportBit: 1
        },
        readRequirement: {
          familyId: 2, operationId: 2, endpointId: 1,
          requiredRoleBits: 49, privacyProfileBit: 1, transportSupportBit: 1
        },
        describeFamilyId: 1,
        admissionParametersOperationId: 3,
        admissionProfile: {
          profileId: PEERIT_LIMITED_CELL_PUT_PROFILE_ID_V1,
          schemeId: POW_ISSUANCE_V1_SCHEME_ID,
          conformanceClass: 1,
          roleBits: 49,
          parameterUrl: null,
          parameterHash
        }
      },
      candidates: [{
        canonicalUrl,
        expectedDescriptorHash: descriptorHash,
        continuityRootRelayPublicKey: continuityRoot,
        descriptorPinned: true,
        sources: ['fixture']
      }],
      trustStore: new TrustStore(),
      bootstrapClient: new BootstrapClient(),
      directClient: new DirectClient(),
      createAdmissionProvider: seamFactory.createAdmissionProvider,
      persistPreparedReplica: async () => {},
      persistVerifiedResult: async () => ({ evidenceRef: 'fixture:put' }),
      persistVerifiedReadback: async () => ({ evidenceRef: 'fixture:readback' }),
      loadPersistedReplica: async () => null,
      createRelayAdapter (options) {
        seamWrappedProvider = options.admissionProvider
        return Object.freeze({ compatible: true, deliver: async () => ({ ok: true }) })
      }
    })
    assert.equal(qualification.failures.length, 0,
      `seam qualification failures: ${JSON.stringify(qualification.failures)}`)
    assert.equal(qualification.adapters.length, 1)
    assert.equal(typeof seamWrappedProvider, 'function',
      'the seam hands the pow-issuance provider to the PUT-qualified adapter')

    const seamRecord = seamFactory.beginRecord({ relayPublicKeys: [relayPublicKey] })
    assert.equal(seamRecord.allowance, 1)
    const seamCommitment = new Uint8Array(randomBytes(32))
    const seamMintStarted = Date.now()
    const seamValue = await seamWrappedProvider({
      familyId: 2,
      operationId: 1,
      requestCommitment: seamCommitment,
      relayPublicKey,
      sizeClass: 1,
      leaseClass: 1
    })
    const seamMinted = await seamRecord.complete
    log(`seam: qualifyPermissionlessRelayCandidates drove the factory; single-slot token minted in ${Date.now() - seamMintStarted}ms`)
    assert.equal(seamValue.profileId, PEERIT_LIMITED_CELL_PUT_PROFILE_ID_V1)
    assert.equal(seamValue.schemeId, POW_ISSUANCE_V1_SCHEME_ID)
    assert.ok(bytesEqual(seamValue.parameterHash, parameterHash))
    const seamPresentation = codec.parsePowIssuanceV1Presentation(seamValue.token)
    assert.equal(seamPresentation.spendIndex, 0)
    assert.equal(seamPresentation.siblings.length, 0)
    // token-codec reads Buffer methods; wrap the browser-typed Uint8Arrays at
    // this test-only boundary (the wire path canonical-encodes, so the daemon
    // always decodes b4a buffers and never sees this distinction).
    const seamToken = codec.parsePowIssuanceV1Token(issuerKeys.tokenKey, Buffer.from(seamPresentation.token))
    assert.ok(bytesEqual(seamToken.recordCommitment,
      codec.powIssuanceV1RecordBindingRoot([seamCommitment])),
    'the seam-minted token binds the exact PUT request commitment')
    seamRecord.close()

    // The (a)-flow token also verifies against the reference work checker and
    // parses under the issuer key: the WebCrypto-mined proof is genuine.
    assert.equal(codec.verifyPowIssuanceV1Work({
      difficultyBits: minted.difficultyBits,
      challengePayload: minted.challengePayload,
      recordCommitment: minted.recordCommitment,
      nonce: minted.nonce
    }), true, 'the WebCrypto-mined nonce satisfies the reference PoW verifier')
    const parsedMinted = codec.parsePowIssuanceV1Token(issuerKeys.tokenKey, Buffer.from(minted.token))
    assert.ok(bytesEqual(parsedMinted.recordCommitment, minted.recordCommitment))
    assert.equal(parsedMinted.allowance, 2)
    assert.equal(parsedMinted.expiryEpoch, minted.expiryEpoch)
    assert.ok(bytesEqual(parsedMinted.challengeId, minted.challengePayload.subarray(1, 33)))
    log('(b) minted token parses under the issuer key; WebCrypto nonce passes the reference work verifier')

    // A second record on the same factory cannot open while one is open, and a
    // provider call without an open record fails closed.
    const busy = seamFactory.beginRecord({ relayPublicKeys: [relayPublicKey] })
    assert.throws(
      () => seamFactory.beginRecord({ relayPublicKeys: [relayPublicKey] }),
      error => error.code === 'PEERIT_POW_ISSUANCE_RECORD_BUSY')
    busy.close()
    const orphanProvider = await seamFactory.createAdmissionProvider({
      candidate: Object.freeze({}),
      endpointContext: Object.freeze({ relayPublicKey }),
      verifiedAdmissionParameters: Object.freeze({ parameterHash }),
      admissionProfile: Object.freeze({
        profileId: PEERIT_LIMITED_CELL_PUT_PROFILE_ID_V1,
        schemeId: POW_ISSUANCE_V1_SCHEME_ID,
        conformanceClass: 1,
        roleBits: 49,
        parameterUrl: null
      }),
      signal: null
    })
    await assert.rejects(
      orphanProvider({
        familyId: 2, operationId: 1,
        requestCommitment: new Uint8Array(randomBytes(32)),
        relayPublicKey, sizeClass: 1, leaseClass: 1
      }),
      error => error.code === 'PEERIT_POW_ISSUANCE_NO_OPEN_RECORD')
    log('seam: profile drift, foreign relay, double-open record, and spend-without-record all fail closed')
  }

  // -------------------------------------------------------------------------
  // (h) Challenge-expiry restart: an expired challenge is a liveness event —
  // the mint restarts from a FRESH challenge (bounded 3, abortable); an
  // invalid-proof rejection is never retried. Real codec-forged challenges and
  // tokens over a queued fake fetch; no extra issuer/relay stack.
  // -------------------------------------------------------------------------
  {
    const retryKeys = codec.derivePowIssuanceV1Keys(new Uint8Array(randomBytes(32)))
    const retryCommitments = [new Uint8Array(randomBytes(32)), new Uint8Array(randomBytes(32))]
    const retryCommitment = codec.powIssuanceV1RecordBindingRoot(retryCommitments)
    const toB64u = bytes => Buffer.from(bytes).toString('base64url')
    const freshChallenge = () => {
      const challengeId = new Uint8Array(randomBytes(32))
      return {
        challengeId,
        wire: toB64u(codec.mintPowIssuanceV1Challenge(retryKeys.challengeKey, {
          challengeId, difficultyBits: 20 }))
      }
    }
    const okRedeem = challengeId => ({
      status: 200,
      async json () {
        return {
          scheme: 'pow-issuance-v1',
          token: Buffer.from(codec.mintPowIssuanceV1Token(retryKeys.tokenKey, {
            challengeId, recordCommitment: retryCommitment, allowance: 2, expiryEpoch: 70000
          })).toString('hex'),
          allowance: 2,
          expiryEpoch: 70000
        }
      }
    })
    const rejectedRedeem = issuerError => ({ status: 400, async json () { return { error: issuerError } } })
    // plan: array of ['challenge', challengeRow] | ['redeem', response] steps the
    // provider must walk in exact order; calls past the plan fail the drill.
    async function runPlan (plan, options = {}) {
      const calls = []
      const provider = createPowIssuanceV1SpendProvider({
        issuanceUrl: 'https://issuer.retry-drill.invalid/',
        fetch: async url => {
          const kind = String(url).endsWith('/challenge') ? 'challenge' : 'redeem'
          calls.push(kind)
          const step = plan.shift()
          if (!step || step[0] !== kind) throw new Error(`provider called ${kind} out of plan`)
          if (kind === 'challenge') {
            return { status: 200, async json () {
              return { scheme: 'pow-issuance-v1', challenge: step[1].wire, difficultyBits: 20, expiresAtUnix: 0 }
            } }
          }
          return step[1]
        },
        signal: options.signal || null
      })
      return { calls, minted: await provider.mint({ commitments: retryCommitments, signal: options.signal || null }) }
    }

    // Expired once, then a fresh challenge succeeds: exactly one 200, one retry.
    const first = freshChallenge()
    const second = freshChallenge()
    const retried = await runPlan([
      ['challenge', first],
      ['redeem', rejectedRedeem('POW_CHALLENGE_EXPIRED')],
      ['challenge', second],
      ['redeem', okRedeem(second.challengeId)]
    ])
    assert.deepEqual(retried.calls, ['challenge', 'redeem', 'challenge', 'redeem'])
    assert.equal(retried.minted.expiryRetries, 1)
    assert.equal(retried.minted.allowance, 2)
    const parsedToken = codec.parsePowIssuanceV1Token(retryKeys.tokenKey, Buffer.from(retried.minted.token))
    assert.equal(parsedToken.allowance, 2)
    assert.ok(bytesEqual(new Uint8Array(parsedToken.recordCommitment), retryCommitment),
      'the retried mint redeems a REAL token bound to the record commitment')
    assert.ok(bytesEqual(new Uint8Array(parsedToken.challengeId), second.challengeId),
      'the token binds the SECOND (fresh) challenge, never the expired one')

    // An invalid-proof rejection is a verification failure: never retried.
    const badProof = freshChallenge()
    await assert.rejects(
      runPlan([
        ['challenge', badProof],
        ['redeem', rejectedRedeem('POW_INSUFFICIENT_WORK')],
        ['challenge', freshChallenge()]
      ]),
      error => error.code === 'PEERIT_POW_ISSUANCE_REDEEM_REJECTED' &&
        error.issuerError === 'POW_INSUFFICIENT_WORK')

    // Expiry is bounded: three stale challenges, then the drill error surfaces.
    const boundedCalls = []
    const boundedProvider = createPowIssuanceV1SpendProvider({
      issuanceUrl: 'https://issuer.retry-drill.invalid/',
      fetch: async url => {
        const kind = String(url).endsWith('/challenge') ? 'challenge' : 'redeem'
        boundedCalls.push(kind)
        if (kind === 'challenge') {
          const row = freshChallenge()
          return { status: 200, async json () {
            return { scheme: 'pow-issuance-v1', challenge: row.wire, difficultyBits: 20, expiresAtUnix: 0 }
          } }
        }
        return rejectedRedeem('POW_CHALLENGE_EXPIRED')
      }
    })
    await assert.rejects(
      boundedProvider.mint({ commitments: retryCommitments }),
      error => error.code === 'PEERIT_POW_ISSUANCE_REDEEM_REJECTED' &&
        error.issuerError === 'POW_CHALLENGE_EXPIRED')
    assert.deepEqual(boundedCalls, ['challenge', 'redeem', 'challenge', 'redeem', 'challenge', 'redeem'],
      'expiry restarts are bounded at three fresh challenges')

    // Abortable: a pre-aborted signal stops the mint before any issuer traffic.
    const controller = new AbortController()
    controller.abort(new Error('drill abort'))
    await assert.rejects(
      runPlan([], { signal: controller.signal }),
      error => error && error.message === 'drill abort')
    log('(h) challenge-expiry restart: fresh-challenge retry bounded 3, token binds the fresh challenge, invalid-proof never retried, abort stops issuer traffic')
  }

  log('drill complete: mint → token → CELL.PUT ×2 → verified receipts → byte-exact readback, plus replay/rejection/byte-parity proofs')
} finally {
  await teardown()
}
console.log('test/peerit-pow-issuance-spend.mjs: PASS')
