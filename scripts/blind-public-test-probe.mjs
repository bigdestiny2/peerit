#!/usr/bin/env node
// blind-public-test-probe.mjs — Peerit app-side DESCRIBE re-probe of the two
// live public-test blind-cell relays (syd-1, dal-1).
//
// Per relay this proves:
//   1. The vendored blind-client artifact is exact against
//      vendor/hiverelay-blind-client-v1/authority.json before any network use
//      (repo release verifier, domainLengthHash recipe).
//   2. The relay serves the pinned descriptor head hash (from the freshest
//      fleet acceptance evidence) over credential-free HTTPS, verified by the
//      authenticated vendored client (signature, chain continuity, validity
//      window, admission binding) under EXACT protocol/transport profile pins
//      learned in a discovery pass and replayed in a strict pass.
//   3. INDEPENDENT crypto check — this file's own cenc reader (written from
//      the deployed blind-protocol registry layout), @noble BLAKE2b-256 and
//      node:crypto Ed25519, sharing no code with the vendored verifier:
//      descriptorHash == BLAKE2b-256("hiverelay.blind.descriptor-hash.v1" ||
//      canonical signed descriptor) and the head signature verifies under the
//      pinned relay key over "hiverelay.blind.descriptor.v1" || len64 ||
//      unsigned descriptor.
//   4. The deployed BuildProfileV1 tuple (specHash/abiHash/vectorSetHash) is
//      compared against the vendored artifact's pinned wireTuple. Match is
//      required for re-pin; drift is reported verbatim, never silently
//      accepted.
//
// Usage: node scripts/blind-public-test-probe.mjs
// Exit 0 = both relays verified + tuple match. Exit 1 = any failure/drift.

import { readFileSync } from 'node:fs'
import { verify as nodeVerify } from 'node:crypto'
import { fileURLToPath, pathToFileURL } from 'node:url'
import path from 'node:path'
import { blake2b } from '@noble/hashes/blake2.js'
import { verifyBlindClientBrowserReleaseV1 } from '../js/substrate/blind-client-browser-verifier.mjs'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const VENDOR_DIR = path.join(ROOT, 'vendor', 'hiverelay-blind-client-v1')

// Pins from the freshest fleet acceptance evidence (read-only inputs):
//   syd-1: syd-1-recovery-boot-restore-fix-20260726t140824z.json (seq-4 head)
//   dal-1: dallas-1-patch-boot-restore-fix-20260726t150347z.json (seq-2 head)
const RELAYS = Object.freeze([
  Object.freeze({
    id: 'syd-1',
    describeUrl: 'https://relay-syd.p2phiverelay.xyz/api/blind/v1/describe',
    relayPublicKey: '52f4d78364180553a944629b5dd90834d3c3d4f7755cc2e452b3308329a88161',
    storeId: '5193f588aa3b55886e27dc35ead0777d6b3f787e575458d9b2d914f413b130de',
    descriptorSequence: 4,
    descriptorHeadHash: '2d46ac68851b1366ed1d89352707508d1986a7cebe4eb21afb041ee3425ffa5e',
    continuityRootRelayPublicKey: '52f4d78364180553a944629b5dd90834d3c3d4f7755cc2e452b3308329a88161'
  }),
  Object.freeze({
    id: 'dal-1',
    describeUrl: 'https://relay-dal.p2phiverelay.xyz/api/blind/v1/describe',
    relayPublicKey: '8b3f4161271cfa511bc49fb03033d6441da01bf27c35a754e2a1b0d7df32e1d2',
    storeId: '744a7e97bd96f74e7ce7cd6a600a0ff1846da4fe3d39c35c611f12ffcd69cb90',
    descriptorSequence: 2,
    descriptorHeadHash: '4325b15ab4d6e8ca98bf7e1c6199acb36a3d1c83641c1635ff86fe7a347e344a',
    continuityRootRelayPublicKey: '8b3f4161271cfa511bc49fb03033d6441da01bf27c35a754e2a1b0d7df32e1d2'
  })
])

const LEASE_EPOCH_MILLIS = 21600000
const DESCRIPTOR_HASH_DOMAIN = 'hiverelay.blind.descriptor-hash.v1'
const DESCRIPTOR_SIGN_DOMAIN = 'hiverelay.blind.descriptor.v1'
const ZERO32 = new Uint8Array(32)
// Discovery pins are deliberately inert: they reference a protocol/transport
// the LIMITED_PUBLIC_TEST_V1 relays do not advertise, so the client-side
// contradiction check cannot fire during the discovery pass. The strict pass
// below re-verifies with the exact advertised values.
const DISCOVERY_PROTOCOL_PINS = Object.freeze([
  Object.freeze({ protocolId: 5, major: 65535, minimumMinor: 0, profileHash: ZERO32 })
])
const DISCOVERY_TRANSPORT_PINS = Object.freeze([
  Object.freeze({ transportId: 9, transportSupportBit: 2, transportProfileHash: ZERO32 })
])

function hexToBytes (value) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) throw new TypeError('expected 64 lowercase hex chars')
  return Uint8Array.from(Buffer.from(value, 'hex'))
}

function hex (bytes) {
  return Buffer.from(bytes).toString('hex')
}

// --- Independent minimal cenc reader (deployed blind-protocol registry
// layout; shares no code with the vendored client verifier).
class Reader {
  constructor (bytes) { this.b = Buffer.from(bytes.buffer || bytes, bytes.byteOffset || 0, bytes.byteLength); this.o = 0 }
  u8 () { return this.b[this.o++] }
  u16 () { const v = (this.b[this.o] << 8) | this.b[this.o + 1]; this.o += 2; return v }
  u32 () { const v = this.b.readUInt32BE(this.o); this.o += 4; return v }
  u64 () { const v = this.b.readBigUInt64BE(this.o); this.o += 8; return v }
  compactUint () {
    const marker = this.u8()
    if (marker <= 0xfc) return marker
    if (marker === 0xfd) { const v = this.b.readUInt16LE(this.o); this.o += 2; return v }
    if (marker === 0xfe) { const v = this.b.readUInt32LE(this.o); this.o += 4; return v }
    const v = this.b.readBigUInt64LE(this.o); this.o += 8; return Number(v)
  }
  fixed (n) { const v = this.b.slice(this.o, this.o + n); this.o += n; return v }
  optFixed (n) { const tag = this.u8(); if (tag === 0) return null; if (tag !== 1) throw new Error('bad optional tag'); return this.fixed(n) }
  utf8Bounded (max) { const n = this.compactUint(); if (n < 1 || n > max) throw new Error('bounded utf8 out of range'); const v = this.b.slice(this.o, this.o + n); this.o += n; return v }
  optUtf8Bounded (max) { const tag = this.u8(); if (tag === 0) return null; if (tag !== 1) throw new Error('bad optional tag'); return this.utf8Bounded(max) }
}

function parseDescriptor (bytes) {
  const r = new Reader(bytes)
  const d = {}
  d.version = r.u8()
  if (d.version !== 1) throw new Error(`descriptor version ${d.version}`)
  d.relayPublicKey = r.fixed(32)
  d.storeId = r.fixed(32)
  d.descriptorSequence = r.u64()
  d.previousDescriptorHash = r.optFixed(32)
  d.identitySequence = r.u64()
  d.previousRelayKey = r.optFixed(32)
  if (r.u8() !== 0) throw new Error('unexpected identity transition in probe descriptor')
  d.build = {
    specHash: r.fixed(32),
    abiHash: r.fixed(32),
    vectorSetHash: r.fixed(32),
    evidenceFormatHash: r.fixed(32),
    evidenceVectorSetHash: r.fixed(32),
    storeFormatHash: r.fixed(32),
    storeVectorSetHash: r.fixed(32),
    privateIpcFormatHash: r.fixed(32),
    privateIpcVectorSetHash: r.fixed(32),
    buildArtifactHash: r.fixed(32),
    buildArtifactUrl: r.utf8Bounded(512),
    buildManifestUrl: r.utf8Bounded(512),
    buildManifestHash: r.fixed(32),
    releaseEvidenceBundleUrl: r.utf8Bounded(512),
    releaseEvidenceBundleHash: r.fixed(32),
    releaseSupportHorizonHash: r.fixed(32),
    runtimeBoundaryEvidenceUrl: r.utf8Bounded(512),
    runtimeBoundaryEvidenceHash: r.fixed(32)
  }
  const protocolCount = r.compactUint()
  if (protocolCount < 1 || protocolCount > 16) throw new Error('protocol count out of range')
  d.protocols = []
  for (let i = 0; i < protocolCount; i++) {
    d.protocols.push({ protocolId: r.u16(), major: r.u16(), minor: r.u16(), featureBits: r.u64(), profileHash: r.fixed(32) })
  }
  const endpointCount = r.compactUint()
  if (endpointCount < 1 || endpointCount > 16) throw new Error('endpoint count out of range')
  d.endpoints = []
  for (let i = 0; i < endpointCount; i++) {
    d.endpoints.push({
      endpointId: r.u8(),
      transportId: r.u8(),
      transportProfileHash: r.fixed(32),
      roleBits: r.u16(),
      privacyProfileBits: r.u16(),
      canonicalUrl: r.utf8Bounded(512),
      endpointKey: r.optFixed(32),
      envelopeClassBits: r.u16(),
      wireClassBits: r.u8(),
      maxStreams: r.u16(),
      auxiliaryUrl: r.optUtf8Bounded(512),
      auxiliaryHash: r.optFixed(32)
    })
  }
  d.cellSizeClassBits = r.u8()
  d.leaseClassBits = r.u8()
  d.maxBatchCount = r.u16()
  d.maxResponseBytes = r.u32()
  d.maxSponsoredCoreLength = r.u64()
  d.enabledOperationBits = r.u32()
  const admissionCount = r.compactUint()
  if (admissionCount < 1 || admissionCount > 8) throw new Error('admission profile count out of range')
  d.admissionProfiles = []
  for (let i = 0; i < admissionCount; i++) {
    d.admissionProfiles.push({
      profileId: r.u16(),
      schemeId: r.u16(),
      conformanceClass: r.u8(),
      roleBits: r.u16(),
      parameterUrl: r.optUtf8Bounded(512),
      parameterHash: r.fixed(32)
    })
  }
  d.durability = {
    profileId: r.u8(),
    storeFormatMajor: r.u16(),
    storeFormatMinor: r.u16(),
    storeFormatHash: r.fixed(32),
    externalJournalId: r.fixed(32),
    externalWitnessPublicKey: r.fixed(32),
    externalJournalReplicationClass: r.u8(),
    externalJournalFailureGroupId: r.fixed(32),
    externalCheckpointAgeBand: r.u8(),
    externalJournalTopologyUrl: r.optUtf8Bounded(512),
    externalJournalTopologyHash: r.fixed(32),
    restoreEvidenceFeedUrl: r.optUtf8Bounded(512),
    restoreEvidenceFeedId: r.fixed(32),
    restoreEvidenceCheckpointSequence: r.u64(),
    restoreEvidenceCheckpointHash: r.fixed(32),
    acknowledgedRpoBand: r.u8(),
    targetRtoBand: r.u8(),
    redundancyClass: r.u8(),
    restoreDrillAgeBand: r.u8()
  }
  d.durabilityContinuityHash = r.fixed(32)
  d.durabilityProfileHash = r.fixed(32)
  d.storeLifecycleState = r.u8()
  d.drainStartedEpoch = (() => { const tag = r.u8(); if (tag === 0) return null; if (tag !== 1) throw new Error('bad optional tag'); return r.u32() })()
  d.capacityBand = r.u8()
  d.issuedEpoch = r.u32()
  d.expiresEpoch = r.u32()
  d.descriptorNonce = r.fixed(32)
  d.signedLength = r.o
  d.signature = r.fixed(64)
  d.totalLength = r.o
  return d
}

function ed25519Verify (publicKey, preimage, signature) {
  return nodeVerify(
    null,
    Buffer.from(preimage),
    {
      key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(publicKey)]),
      format: 'der',
      type: 'spki'
    },
    Buffer.from(signature))
}

function u64be (value) {
  const out = Buffer.alloc(8)
  out.writeBigUInt64BE(BigInt(value))
  return out
}

async function fetchDescriptor (control, runtime, relay, protocolPins, transportPins, nowEpoch) {
  const bootstrap = new control.BlindDescriptorBootstrapHttpClient({ runtime, fetch: globalThis.fetch })
  return bootstrap.fetchVerifiedDescriptor({
    canonicalUrl: new TextEncoder().encode(relay.describeUrl),
    expectedDescriptorHash: hexToBytes(relay.descriptorHeadHash),
    continuityRootRelayPublicKey: hexToBytes(relay.continuityRootRelayPublicKey),
    nowEpoch,
    history: true,
    supportedProtocolProfiles: protocolPins,
    supportedTransportProfiles: transportPins
  })
}

async function main () {
  // 1. Vendored artifact integrity against its own authority pin.
  const authority = JSON.parse(readFileSync(path.join(VENDOR_DIR, 'authority.json'), 'utf8'))
  const artifactBytes = readFileSync(path.join(VENDOR_DIR, 'blind-client-control-v1.mjs'))
  const verifiedRelease = verifyBlindClientBrowserReleaseV1({
    artifactBytes,
    manifestBytes: readFileSync(path.join(VENDOR_DIR, 'blind-client-control-v1.manifest.cenc')),
    chromiumEvidenceBytes: readFileSync(path.join(VENDOR_DIR, 'blind-client-control-v1.chromium-evidence.json')),
    crossHostEvidenceBytes: readFileSync(path.join(VENDOR_DIR, 'blind-client-control-v1.cross-host-evidence.json'))
  })
  const artifactHash = hex(verifiedRelease.artifactHash)
  if (artifactHash !== authority.artifactHash || artifactBytes.byteLength !== authority.artifactLength) {
    throw new Error(`vendored artifact drift: hash ${artifactHash} length ${artifactBytes.byteLength}`)
  }
  const control = await import(pathToFileURL(path.join(VENDOR_DIR, 'blind-client-control-v1.mjs')).href)
  const runtime = control.createBrowserCryptoRuntime(globalThis.crypto)
  const blake2b256 = (data) => blake2b(data, { dkLen: 32 })

  const nowEpoch = Math.floor(Date.now() / LEASE_EPOCH_MILLIS)
  const report = {
    schema: 'PeeritBlindPublicTestDescribeProbeV1',
    probedAt: new Date().toISOString(),
    nowEpoch,
    vendoredArtifact: { artifactHash, wireTuple: authority.wireTuple },
    relays: [],
    tupleMatch: null,
    status: 'fail'
  }

  for (const relay of RELAYS) {
    const entry = { id: relay.id, describeUrl: relay.describeUrl, checks: [] }
    const check = (id, ok, detail) => {
      entry.checks.push({ id, status: ok ? 'pass' : 'fail', detail: String(detail) })
      if (!ok) throw new Error(`${relay.id}: ${id}: ${detail}`)
    }

    // 2a. Discovery pass (inert pins) → canonical descriptor bytes.
    const discovered = await fetchDescriptor(
      control, runtime, relay, DISCOVERY_PROTOCOL_PINS, DISCOVERY_TRANSPORT_PINS, nowEpoch)
    const canonical = discovered.snapshotBytes()
    const parsed = parseDescriptor(canonical)
    check('independent.parse', parsed.totalLength === canonical.byteLength,
      `parsed ${parsed.totalLength}/${canonical.byteLength} canonical bytes`)

    // 2b. Strict pass: exact advertised protocol/transport pins.
    const strictProtocolPins = parsed.protocols.map((p) => ({
      protocolId: p.protocolId, major: p.major, minimumMinor: p.minor, profileHash: p.profileHash
    }))
    const strictTransportPins = parsed.endpoints.map((e) => ({
      transportId: e.transportId, transportSupportBit: 1, transportProfileHash: e.transportProfileHash
    }))
    const strict = await fetchDescriptor(
      control, runtime, relay, strictProtocolPins, strictTransportPins, nowEpoch)
    check('client.descriptor.verified', hex(strict.descriptorHash) === relay.descriptorHeadHash &&
      Buffer.from(strict.snapshotBytes()).equals(Buffer.from(canonical)) &&
      Number(strict.descriptorSequence) === relay.descriptorSequence &&
      hex(strict.relayPublicKey) === relay.relayPublicKey &&
      hex(strict.storeId) === relay.storeId,
      `head=${hex(strict.descriptorHash).slice(0, 16)}… seq=${strict.descriptorSequence} store=${hex(strict.storeId).slice(0, 16)}…`)

    // 3. Independent crypto verification.
    check('independent.relay-key', hex(parsed.relayPublicKey) === relay.relayPublicKey, hex(parsed.relayPublicKey))
    check('independent.store-id', hex(parsed.storeId) === relay.storeId, hex(parsed.storeId))
    check('independent.sequence', Number(parsed.descriptorSequence) === relay.descriptorSequence,
      `descriptorSequence=${parsed.descriptorSequence}`)
    const unsigned = canonical.slice(0, parsed.signedLength)
    const signatureOk = ed25519Verify(parsed.relayPublicKey,
      Buffer.concat([Buffer.from(DESCRIPTOR_SIGN_DOMAIN, 'ascii'), u64be(unsigned.byteLength), Buffer.from(unsigned)]),
      parsed.signature)
    check('independent.ed25519', signatureOk, 'head signature verifies under pinned relay key (node:crypto)')
    const digest = blake2b256(Buffer.concat([Buffer.from(DESCRIPTOR_HASH_DOMAIN, 'ascii'), Buffer.from(canonical)]))
    check('independent.descriptor-hash', hex(digest) === relay.descriptorHeadHash, hex(digest))
    check('independent.validity-window', parsed.issuedEpoch <= nowEpoch && nowEpoch < parsed.expiresEpoch,
      `issued=${parsed.issuedEpoch} expires=${parsed.expiresEpoch} now=${nowEpoch}`)

    // 4. Deployed build profile (descriptor-advertised) + placeholder check.
    entry.deployedBuild = Object.fromEntries(Object.entries(parsed.build).map(([key, value]) => [
      key,
      value instanceof Uint8Array || Buffer.isBuffer(value) ? hex(value) : Buffer.from(value).toString('utf8')
    ]))
    const uniform = (value) => value.every((byte) => byte === value[0])
    entry.descriptorAdvertisedTuple = {
      specHash: hex(parsed.build.specHash),
      abiHash: hex(parsed.build.abiHash),
      vectorSetHash: hex(parsed.build.vectorSetHash)
    }
    entry.descriptorAdvertisedTuplePlaceholder =
      uniform(parsed.build.specHash) && uniform(parsed.build.abiHash) && uniform(parsed.build.vectorSetHash)
    entry.deployedIdentity = {
      relayPublicKey: hex(parsed.relayPublicKey),
      storeId: hex(parsed.storeId),
      descriptorSequence: Number(parsed.descriptorSequence),
      previousDescriptorHash: parsed.previousDescriptorHash ? hex(parsed.previousDescriptorHash) : null,
      issuedEpoch: parsed.issuedEpoch,
      expiresEpoch: parsed.expiresEpoch,
      storeLifecycleState: parsed.storeLifecycleState,
      enabledOperationBits: `0x${parsed.enabledOperationBits.toString(16).padStart(8, '0')}`,
      cellSizeClassBits: parsed.cellSizeClassBits,
      leaseClassBits: parsed.leaseClassBits,
      maxBatchCount: parsed.maxBatchCount,
      maxResponseBytes: parsed.maxResponseBytes,
      protocols: parsed.protocols.map((p) => ({
        protocolId: p.protocolId, major: p.major, minor: p.minor,
        featureBits: String(p.featureBits), profileHash: hex(p.profileHash)
      })),
      endpoints: parsed.endpoints.map((e) => ({
        endpointId: e.endpointId,
        transportId: e.transportId,
        transportProfileHash: hex(e.transportProfileHash),
        roleBits: e.roleBits,
        privacyProfileBits: e.privacyProfileBits,
        canonicalUrl: Buffer.from(e.canonicalUrl).toString('utf8'),
        envelopeClassBits: e.envelopeClassBits,
        wireClassBits: e.wireClassBits,
        maxStreams: e.maxStreams
      })),
      admissionProfiles: parsed.admissionProfiles.map((p) => ({
        profileId: p.profileId,
        schemeId: p.schemeId,
        conformanceClass: p.conformanceClass,
        roleBits: p.roleBits,
        parameterUrl: p.parameterUrl ? Buffer.from(p.parameterUrl).toString('utf8') : null,
        parameterHash: hex(p.parameterHash)
      })),
      durability: {
        profileId: parsed.durability.profileId,
        storeFormatMajor: parsed.durability.storeFormatMajor,
        storeFormatMinor: parsed.durability.storeFormatMinor,
        storeFormatHash: hex(parsed.durability.storeFormatHash)
      },
      durabilityContinuityHash: hex(parsed.durabilityContinuityHash),
      durabilityProfileHash: hex(parsed.durabilityProfileHash)
    }
    report.relays.push(entry)
  }

  // Tuple verdict. Three sources, honestly separated:
  //   (a) vendored v1 artifact tuple — what this Peerit release's blind client
  //       speaks and what the Peerit profile registry imports;
  //   (b) descriptor-advertised build tuple — signed by each relay, but a
  //       disclosed placeholder (relay-side finding DAL1-IAR-P2-1);
  //   (c) relay release wire-authority tuple — the deployed protocol build's
  //       own pinned tuple (read-only reference, cited from the public-test
  //       release worktree packages/blind-protocol/hiverelay-blind-wire-authority-v1.json
  //       at release commit 1ea903d / merged HEAD 973f25c, pin-history entry 4).
  const RELAY_RELEASE_WIRE_TUPLE = Object.freeze({
    specHash: 'c9ddd235c3963461174e3de13c25a4c995b53ff320be822d8304f870766b6592',
    abiHash: '199ba15d94d4d112cfac520a67055ce15ec870f0f6f7bd9adaaf47d552334567',
    vectorSetHash: 'fa54012cd0d7e4e620878c67e61f435ecb31ddec05a6283917987cc84279ee05',
    source: 'hiverelay public-test release worktree packages/blind-protocol/hiverelay-blind-wire-authority-v1.json (read-only reference)',
    note: 'v2 wire authority (baseAbiHash 199ba15d…, abi cc1abb0e…) adds FORWARD turn schemas only; relays run releaseProfileId 1 LIMITED_PUBLIC_TEST_V1 (operationBits 0x1ffff, FORWARD bits zero)'
  })
  const vendored = authority.wireTuple
  const descriptorPlaceholder = report.relays.every((relay) => relay.descriptorAdvertisedTuplePlaceholder === true)
  const relayReleaseMatch = ['specHash', 'abiHash', 'vectorSetHash']
    .every((field) => RELAY_RELEASE_WIRE_TUPLE[field] === vendored[field])
  const descriptorAdvertisedMatch = report.relays.every((relay) =>
    relay.descriptorAdvertisedTuple.specHash === vendored.specHash &&
    relay.descriptorAdvertisedTuple.abiHash === vendored.abiHash &&
    relay.descriptorAdvertisedTuple.vectorSetHash === vendored.vectorSetHash)
  report.tupleVerdict = {
    vendoredTuple: vendored,
    descriptorAdvertisedTuple: report.relays.map((relay) => ({ relay: relay.id, ...relay.descriptorAdvertisedTuple })),
    descriptorAdvertisedTuplePlaceholder: descriptorPlaceholder,
    descriptorAdvertisedTupleMatchesVendored: descriptorAdvertisedMatch,
    relayReleaseWireTuple: RELAY_RELEASE_WIRE_TUPLE,
    relayReleaseTupleMatchesVendored: relayReleaseMatch,
    drift: relayReleaseMatch
      ? null
      : {
          kind: 'WIRE_TUPLE_DRIFT',
          vendored: vendored,
          deployed: {
            specHash: RELAY_RELEASE_WIRE_TUPLE.specHash,
            abiHash: RELAY_RELEASE_WIRE_TUPLE.abiHash,
            vectorSetHash: RELAY_RELEASE_WIRE_TUPLE.vectorSetHash
          },
          vendoredArtifact: {
            path: 'vendor/hiverelay-blind-client-v1/blind-client-control-v1.mjs',
            artifactHash,
            pinned: '2026-07-16 (Peerit vendor authority)'
          },
          deployedClientArtifact: {
            path: 'browser-artifacts/blind-client-control-v3.mjs (relay public-test release, read-only reference)',
            artifactHash: '46a86079fb5fcaaeee42362113182ca0d41b9d004f0f5d62ec04869c0844f3ff',
            authorityFlags: { runtimeReady: false, realBrowserEvidenceAccepted: false, authorizesRelease: false }
          },
          conclusion: 'The vendored v1 artifact pins the 2026-07-16 wire tuple; the deployed relays run the 2026-07-24 wire build. DESCRIBE-layer compatibility is empirically proven by this probe (full client verification + independent signature/hash checks pass on both relays). CELL/INBOX/CORE compatibility is NOT proven by DESCRIBE and must be established by the write/readback drills before any catalogue flip.'
        }
  }
  report.tupleMatch = relayReleaseMatch && descriptorAdvertisedMatch
  report.status = report.tupleMatch ? 'pass' : 'drift-recorded'

  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`)
  process.exitCode = report.status === 'pass' ? 0 : 2
}

main().catch((error) => {
  process.stderr.write(`[blind-public-test-probe] ${error.code || 'ERROR'}: ${error.stack || error.message}\n`)
  process.exitCode = 1
})
