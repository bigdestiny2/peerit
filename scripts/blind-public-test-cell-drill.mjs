#!/usr/bin/env node
// blind-public-test-cell-drill.mjs — two-relay CELL write/readback drill for
// the Peerit public-test bind, through the Peerit substrate client ONLY.
//
// Per relay, through the genuine Peerit relay-consumer seam
// (js/substrate/relay-consumer.js qualifyPermissionlessRelayCandidates +
// js/substrate/blind-client-relay.js createBlindCellRelay):
//   1. Qualify the relay from its pinned descriptor (signature, chain,
//      admission parameters, health) under the exact bind profile.
//   2. Build a REAL Peerit signed publication (profile op, inner operation
//      batch V1) entirely client-side.
//   3. deliver() = prepare -> encrypted capability persistence -> Cell PUT ->
//      signed receipt verification -> Cell GET readback -> byte-exact compare.
//   4. Capture every request byte sent to the relay and prove the app's
//      plaintext markers never cross the boundary (relay sees opaque cells).
//
// This drill is the empirical compatibility decider for the recorded
// WIRE_TUPLE_DRIFT: a pass proves the vendored v1 client and the deployed
// relays interoperate on the DESCRIBE+CELL subset Peerit uses; a failure is
// reported verbatim and the bind stops.
//
// Usage: node scripts/blind-public-test-cell-drill.mjs
// Exit 0 = both relays pass. Exit 1 = any failure.

import { readFileSync } from 'node:fs'
import { fileURLToPath, pathToFileURL } from 'node:url'
import path from 'node:path'
import { canonical } from '../js/canon.js'
import { ready as cryptoReady } from '../js/crypto.js'
import { createIdentity } from '../js/identity.js'
import { memoryStorage } from '../js/sync.js'
import { createBlindCellRelay } from '../js/substrate/blind-client-relay.js'
import { qualifyPermissionlessRelayCandidates } from '../js/substrate/relay-consumer.js'
import { verifyBlindClientBrowserReleaseV1 } from '../js/substrate/blind-client-browser-verifier.mjs'
import { parseDescriptor } from './lib/blind-descriptor-parse.mjs'
import {
  createPeeritCapabilityVault,
  memoryCapabilityVaultKv
} from '../js/substrate/capability-vault.js'
import {
  createPeeritInnerOperationBatchV1,
  hashPeeritInnerOperationIntentIdV1
} from '../js/substrate/peerit-operation-authority-v1.js'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const VENDOR_DIR = path.join(ROOT, 'vendor', 'hiverelay-blind-client-v1')
const LEASE_EPOCH_MILLIS = 21600000

// Live bind pins (from the DESCRIBE re-probe evidence, reports/
// blind-public-test-describe-probe-20260726.json). Admission parameter hashes
// are per-relay signed values advertised in each descriptor.
const RELAYS = Object.freeze([
  Object.freeze({
    id: 'syd-1',
    describeUrl: 'https://relay-syd.p2phiverelay.xyz/api/blind/v1/describe',
    relayPublicKey: '52f4d78364180553a944629b5dd90834d3c3d4f7755cc2e452b3308329a88161',
    storeId: '5193f588aa3b55886e27dc35ead0777d6b3f787e575458d9b2d914f413b130de',
    descriptorSequence: 4,
    descriptorHeadHash: '2d46ac68851b1366ed1d89352707508d1986a7cebe4eb21afb041ee3425ffa5e',
    continuityRootRelayPublicKey: '52f4d78364180553a944629b5dd90834d3c3d4f7755cc2e452b3308329a88161',
    admissionParameterHash: '8a796071cfc688bfd23dfa50dc83a7a56431daae223f0f77236c51bad7476d30',
    admissionParameterUrl: 'https://evidence.example:443/admission.cenc'
  }),
  Object.freeze({
    id: 'dal-1',
    describeUrl: 'https://relay-dal.p2phiverelay.xyz/api/blind/v1/describe',
    relayPublicKey: '8b3f4161271cfa511bc49fb03033d6441da01bf27c35a754e2a1b0d7df32e1d2',
    storeId: '744a7e97bd96f74e7ce7cd6a600a0ff1846da4fe3d39c35c611f12ffcd69cb90',
    descriptorSequence: 2,
    descriptorHeadHash: '4325b15ab4d6e8ca98bf7e1c6199acb36a3d1c83641c1635ff86fe7a347e344a',
    continuityRootRelayPublicKey: '8b3f4161271cfa511bc49fb03033d6441da01bf27c35a754e2a1b0d7df32e1d2',
    admissionParameterHash: '75bde3f84de03f8ceeef9a7a26e8d17e498413e93419762da0e1ee88b1c9adcd',
    admissionParameterUrl: 'https://evidence.example:443/admission.cenc'
  })
])

// The bind profile is assembled from the live re-probe. Protocol/transport
// profileHash values are the relays' advertised (disclosed-placeholder) pins;
// the qualifier's contradiction check compares against the same advertised
// values, so they pin exactly what each relay signs today.
const PLACEHOLDER_PROTOCOL_PROFILE_HASH = '0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a'
const PLACEHOLDER_TRANSPORT_PROFILE_HASH = '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'
const ENDPOINT_ROLE_BITS = 49
const PRIVACY_PROFILE_BIT = 1
const TRANSPORT_SUPPORT_BIT = 1

function hexToBytes (value) {
  return Uint8Array.from(Buffer.from(value, 'hex'))
}

function hex (bytes) {
  return Buffer.from(bytes).toString('hex')
}

function bindProfile (relay) {
  return Object.freeze({
    supportedProtocolProfiles: Object.freeze([1, 2, 3, 4].map((protocolId) => Object.freeze({
      protocolId,
      major: 1,
      minimumMinor: 0,
      profileHash: hexToBytes(PLACEHOLDER_PROTOCOL_PROFILE_HASH)
    }))),
    supportedTransportProfiles: Object.freeze([Object.freeze({
      transportId: 1,
      transportSupportBit: TRANSPORT_SUPPORT_BIT,
      transportProfileHash: hexToBytes(PLACEHOLDER_TRANSPORT_PROFILE_HASH)
    })]),
    requirement: Object.freeze({
      familyId: 2,
      operationId: 1,
      endpointId: 1,
      requiredRoleBits: ENDPOINT_ROLE_BITS,
      privacyProfileBit: PRIVACY_PROFILE_BIT,
      transportSupportBit: TRANSPORT_SUPPORT_BIT
    }),
    readRequirement: Object.freeze({
      familyId: 2,
      operationId: 2,
      endpointId: 1,
      requiredRoleBits: ENDPOINT_ROLE_BITS,
      privacyProfileBit: PRIVACY_PROFILE_BIT,
      transportSupportBit: TRANSPORT_SUPPORT_BIT
    }),
    describeFamilyId: 1,
    admissionParametersOperationId: 3,
    admissionProfile: Object.freeze({
      profileId: 7,
      schemeId: 9,
      conformanceClass: 1,
      roleBits: ENDPOINT_ROLE_BITS,
      parameterUrl: new TextEncoder().encode(relay.admissionParameterUrl),
      parameterHash: hexToBytes(relay.admissionParameterHash)
    })
  })
}

async function signedPublication (identity, marker) {
  const me = identity.me()
  const data = { id: me.pubkey, author: me.pubkey, name: marker }
  const signature = await identity.sign(canonical('profile', data))
  Object.assign(data, {
    _sig: signature.signature,
    _k: signature.publicKey,
    _dk: signature.driveKey,
    _ns: signature.namespace,
    _alg: signature.algorithm
  })
  const envelope = await createPeeritInnerOperationBatchV1([
    { type: 'profile', data }
  ], {
    expectedAuthorPublicKey: me.pubkey
  })
  return Object.freeze({
    intentId: hex(hashPeeritInnerOperationIntentIdV1(envelope.innerCodec, envelope.innerBytes)),
    logicalId: hex(envelope.logicalHash),
    innerCodec: envelope.innerCodec,
    innerBytes: envelope.innerBytes,
    innerLength: Number(envelope.innerLength),
    sizeClass: envelope.sizeClass,
    logicalHash: envelope.logicalHash,
    encodingCommitment: envelope.encodingCommitment
  })
}

async function main () {
  if (!globalThis.crypto || !globalThis.crypto.subtle) {
    throw new Error('drill requires Web Crypto')
  }
  const authorityBytes = readFileSync(path.join(VENDOR_DIR, 'authority.json'))
  const authority = JSON.parse(authorityBytes.toString('utf8'))
  const artifactBytes = readFileSync(path.join(VENDOR_DIR, 'blind-client-control-v1.mjs'))
  const verifiedRelease = verifyBlindClientBrowserReleaseV1({
    artifactBytes,
    manifestBytes: readFileSync(path.join(VENDOR_DIR, 'blind-client-control-v1.manifest.cenc')),
    chromiumEvidenceBytes: readFileSync(path.join(VENDOR_DIR, 'blind-client-control-v1.chromium-evidence.json')),
    crossHostEvidenceBytes: readFileSync(path.join(VENDOR_DIR, 'blind-client-control-v1.cross-host-evidence.json')),
    authorityBytes
  })
  if (hex(verifiedRelease.artifactHash) !== authority.artifactHash) {
    throw new Error('vendored artifact drift before drill')
  }
  const control = await import(pathToFileURL(path.join(VENDOR_DIR, 'blind-client-control-v1.mjs')).href)
  const runtime = control.createBrowserCryptoRuntime(globalThis.crypto)
  await cryptoReady()
  const identity = createIdentity({
    forceDev: true,
    lazy: true,
    storage: memoryStorage(),
    session: memoryStorage(),
    label: 'peerit-public-test-cell-drill'
  })
  await identity.ready()
  await identity.ensureActive('peerit-public-test-cell-drill')

  const marker = `peerit-public-test-bind-drill-${new Date().toISOString()}`
  const publication = await signedPublication(identity, marker)

  const report = {
    schema: 'PeeritBlindPublicTestCellDrillV1',
    drilledAt: new Date().toISOString(),
    marker,
    publication: {
      intentId: publication.intentId,
      logicalId: publication.logicalId,
      innerCodec: publication.innerCodec,
      innerLength: publication.innerLength,
      sizeClass: publication.sizeClass
    },
    vendoredArtifact: { artifactHash: authority.artifactHash, wireTuple: authority.wireTuple },
    relays: [],
    status: 'fail'
  }

  for (const relay of RELAYS) {
    const entry = { id: relay.id, checks: [], wire: [] }
    const check = (id, ok, detail) => {
      entry.checks.push({ id, status: ok ? 'pass' : 'fail', detail: String(detail) })
      if (!ok) throw new Error(`${relay.id}: ${id}: ${detail}`)
    }
    const profile = bindProfile(relay)
    const kv = memoryCapabilityVaultKv()
    const vault = createPeeritCapabilityVault({ kv, crypto: globalThis.crypto, now: () => 1000 })
    const rawAdapters = []

    // Boundary capture: record every request sent to this relay.
    const captured = []
    const capturingFetch = async (url, options = {}) => {
      const bodyBytes = options.body
        ? new Uint8Array(options.body.buffer || options.body, options.body.byteOffset || 0, options.body.byteLength)
        : null
      captured.push({
        url: String(url),
        method: options.method || 'GET',
        bodyBytes: bodyBytes ? bodyBytes.slice() : null
      })
      return globalThis.fetch(url, options)
    }

    // First-contact continuity bootstrap: the production qualifier accepts a
    // non-genesis head only into a trust store that already holds the exact
    // chain from genesis (fail-closed UNTRUSTED_RELAY_IDENTITY otherwise).
    // Walk the chain LIVE — each predecessor is fetched by its content hash
    // and verified by the client — then accept genesis→head in order.
    const bootstrap = new control.BlindDescriptorBootstrapHttpClient({ runtime, fetch: capturingFetch })
    const trustStore = new control.DescriptorTrustStore(new control.MemoryDescriptorTrustBackend())
    const chain = []
    {
      let hash = relay.descriptorHeadHash
      for (let depth = 0; depth < 16; depth++) {
        const descriptor = await bootstrap.fetchVerifiedDescriptor({
          canonicalUrl: new TextEncoder().encode(relay.describeUrl),
          expectedDescriptorHash: hexToBytes(hash),
          continuityRootRelayPublicKey: hexToBytes(relay.continuityRootRelayPublicKey),
          nowEpoch: Math.floor(Date.now() / LEASE_EPOCH_MILLIS),
          history: true,
          supportedProtocolProfiles: profile.supportedProtocolProfiles,
          supportedTransportProfiles: profile.supportedTransportProfiles
        })
        const parsed = parseDescriptor(descriptor.snapshotBytes())
        chain.unshift({ descriptor, hash, sequence: Number(parsed.descriptorSequence) })
        if (parsed.descriptorSequence === 0n) break
        if (!parsed.previousDescriptorHash) throw new Error(`${relay.id}: chain broke before genesis`)
        hash = hex(parsed.previousDescriptorHash)
      }
    }
    check('continuity.chain-walk', chain.length === relay.descriptorSequence + 1 &&
      chain[0].sequence === 0 && chain[chain.length - 1].hash === relay.descriptorHeadHash,
      `genesis→head chain of ${chain.length} descriptors fetched and client-verified live`)
    for (const link of chain) {
      await trustStore.accept(link.descriptor, link.sequence === 0
        ? Object.freeze({
            pinnedDescriptorHash: hexToBytes(link.hash),
            continuityRootRelayPublicKey: hexToBytes(relay.continuityRootRelayPublicKey)
          })
        : Object.freeze({
            continuityRootRelayPublicKey: hexToBytes(relay.continuityRootRelayPublicKey)
          }))
    }
    check('continuity.trust-seeded', true, 'genesis-pinned chain accepted into the drill trust store')

    const admissionParameterHash = hexToBytes(relay.admissionParameterHash)
    const qualification = await qualifyPermissionlessRelayCandidates({
      control,
      cryptoRuntime: runtime,
      nowEpoch: () => Math.floor(Date.now() / LEASE_EPOCH_MILLIS),
      profile,
      candidates: Object.freeze([Object.freeze({
        canonicalUrl: relay.describeUrl,
        expectedDescriptorHash: relay.descriptorHeadHash,
        continuityRootRelayPublicKey: relay.continuityRootRelayPublicKey,
        descriptorPinned: true,
        sources: Object.freeze(['user'])
      })]),
      trustStore,
      fetch: capturingFetch,
      admissionProvider: async () => Object.freeze({
        profileId: 7,
        schemeId: 9,
        parameterHash: admissionParameterHash,
        token: runtime.randomBytes(32)
      }),
      persistPreparedReplica: vault.persistPreparedReplica,
      persistVerifiedResult: vault.persistVerifiedResult,
      persistVerifiedReadback: vault.persistVerifiedReadback,
      loadPersistedReplica: vault.load,
      createRelayAdapter: (options) => {
        const rawAdapter = createBlindCellRelay({ ...options, blindClient: control, control, leaseClass: 1 })
        rawAdapters.push(rawAdapter)
        return rawAdapter
      },
      totalQualificationTimeoutMillis: 30000
    })
    check('qualify.one-adapter', qualification.adapters.length === 1,
      `qualified=${qualification.adapters.length} failures=${JSON.stringify(qualification.failures)}`)
    check('qualify.admission-verified', qualification.status.admissionParametersVerified === true,
      'signed admission parameters verified against the descriptor pin')
    entry.checks.push({
      id: 'profile.lease-class-redeemed',
      status: 'info',
      detail: 'relay admission offers CELL PUT only at leaseClass 1 (10 units); the Peerit adapter default (4) is incompatible, so this drill redeems the advertised class 1. Recorded as consumer gap PEERIT-BIND-GAP-LEASE-CLASS.'
    })

    const adapter = qualification.adapters[0]
    let result
    try {
      result = await adapter.deliver(publication)
    } catch (error) {
      error.message += `; remote=${JSON.stringify(error.remote || null)}`
      throw error
    }
    check('deliver.acknowledged', result.acknowledged === true && result.ok === true,
      `evidenceRef=${result.evidenceRef}`)
    check('deliver.readback-verified', result.readbackVerified === true,
      'signed receipt + readback verified under the relay key by the substrate client')

    const stored = await vault.load(publication.intentId, rawAdapters[0] && rawAdapters[0].id)
    check('vault.stage', stored && stored.stage === 'readback-verified', stored && stored.stage)
    check('vault.byte-exact-readback',
      stored && Buffer.from(stored.payload.readbackInnerBytes).equals(Buffer.from(publication.innerBytes)),
      'readback inner bytes are byte-exact against the authored batch')

    // Boundary proof: no app plaintext marker, no app schema vocabulary, in any
    // request byte that crossed to this relay.
    const markerBytes = new TextEncoder().encode(marker)
    const schemaWords = ['peerit', '"profile"', 'moderation', 'vote', 'feed'].map((word) => new TextEncoder().encode(word))
    const contains = (haystack, needle) => {
      outer: for (let i = 0; i + needle.byteLength <= haystack.byteLength; i++) {
        for (let j = 0; j < needle.byteLength; j++) if (haystack[i + j] !== needle[j]) continue outer
        return true
      }
      return false
    }
    entry.wire = captured.map((call) => ({
      url: call.url,
      method: call.method,
      bodyBytes: call.bodyBytes ? call.bodyBytes.byteLength : 0,
      markerPresent: call.bodyBytes ? contains(call.bodyBytes, markerBytes) : false,
      schemaWordsPresent: call.bodyBytes
        ? schemaWords.filter((word) => contains(call.bodyBytes, word)).map((word) => Buffer.from(word).toString('utf8'))
        : []
    }))
    check('boundary.no-marker-on-wire', entry.wire.every((call) => call.markerPresent === false),
      'app plaintext marker never appears in relay-visible bytes')
    check('boundary.no-app-schema-on-wire', entry.wire.every((call) => call.schemaWordsPresent.length === 0),
      'no app schema vocabulary in relay-visible bytes')
    const cellPut = entry.wire.find((call) => call.url.includes('/api/blind/v1/cell'))
    check('boundary.cell-unary-shape', !!cellPut && cellPut.method === 'POST',
      cellPut ? `cell request ${cellPut.bodyBytes}B to ${cellPut.url}` : 'no cell request captured')

    report.relays.push(entry)
  }

  report.status = report.relays.length === 2 ? 'pass' : 'fail'
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`)
  process.exitCode = report.status === 'pass' ? 0 : 1
}

main().catch((error) => {
  process.stderr.write(`[blind-public-test-cell-drill] ${error.code || 'ERROR'}: ${error.stack || error.message}\n`)
  process.exitCode = 1
})
