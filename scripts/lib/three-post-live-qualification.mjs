// Explicit live qualification seam for the three-post conductor. This module
// performs network I/O only when qualifyThreePostLiveRelaysV1() is called.

import fs from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { verify as verifySignature } from 'node:crypto'

import { createBlindCellRelay } from '../../js/substrate/blind-client-relay.js'
import { verifyBlindClientBrowserReleaseV1 } from '../../js/substrate/blind-client-browser-verifier.mjs'
import { qualifyPermissionlessRelayCandidates } from '../../js/substrate/relay-consumer.js'
import { blake2b256 } from '../../js/substrate/release-control-primitives.mjs'
import { parseDescriptor } from '../lib/blind-descriptor-parse.mjs'
import { bindCurrentRelayTupleV1, validateCurrentRelayTupleV1 } from './three-post-launch.mjs'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
const VENDOR_DIR = path.join(ROOT, 'vendor', 'hiverelay-blind-client-v1')
const LEASE_EPOCH_MILLIS = 21_600_000
const MEDIA_TYPE = 'application/vnd.hiverelay.blind-v1'
const DESCRIPTOR_HASH_DOMAIN = 'hiverelay.blind.descriptor-hash.v1'
const DESCRIPTOR_SIGN_DOMAIN = 'hiverelay.blind.descriptor.v1'

const hex = value => Buffer.from(value).toString('hex')
const bytes = value => new Uint8Array(Buffer.from(value, 'hex'))

function fail (code, message) {
  const error = new Error(message)
  error.code = code
  throw error
}

function u64be (value) {
  const output = Buffer.alloc(8)
  output.writeBigUInt64BE(BigInt(value))
  return output
}

function ed25519Verify (publicKey, message, signature) {
  return verifySignature(null, Buffer.from(message), {
    key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(publicKey)]),
    format: 'der',
    type: 'spki'
  }, Buffer.from(signature))
}

function currentHeadRequest (runtime) {
  const requestId = runtime.randomBytes(16)
  const clientNonce = runtime.randomBytes(32)
  const body = Buffer.concat([Buffer.from([1, 0]), Buffer.from(clientNonce)])
  const dispatch = Buffer.alloc(45 + body.byteLength)
  dispatch.writeUInt32BE(41 + body.byteLength, 0)
  dispatch[4] = 1
  dispatch[5] = 1
  dispatch[6] = 1
  dispatch[7] = 1
  Buffer.from(requestId).copy(dispatch, 9)
  dispatch.writeUInt32BE(body.byteLength, 41)
  body.copy(dispatch, 45)
  const outer = Buffer.alloc(65536)
  outer[0] = 1
  outer[1] = 3
  outer.writeUInt32BE(dispatch.byteLength, 2)
  dispatch.copy(outer, 6)
  Buffer.from(runtime.randomBytes(outer.byteLength - 6 - dispatch.byteLength)).copy(outer, 6 + dispatch.byteLength)
  return { requestId: Buffer.from(requestId), body: outer }
}

function unaryResponse (input, requestId) {
  const bytes = Buffer.from(input)
  if (bytes.byteLength < 6 || bytes[0] !== 1) fail('PEERIT_THREE_POST_DESCRIBE_INVALID', 'describe response outer envelope is invalid')
  const innerLength = bytes.readUInt32BE(2)
  if (6 + innerLength > bytes.byteLength) fail('PEERIT_THREE_POST_DESCRIBE_INVALID', 'describe response is truncated')
  const dispatch = bytes.subarray(6, 6 + innerLength)
  if (dispatch.byteLength < 45 || dispatch.readUInt32BE(0) + 4 !== dispatch.byteLength ||
      dispatch.readUInt32BE(41) + 45 !== dispatch.byteLength ||
      !Buffer.from(dispatch.subarray(9, 25)).equals(requestId)) {
    fail('PEERIT_THREE_POST_DESCRIBE_INVALID', 'describe response framing or correlation is invalid')
  }
  if (dispatch[5] !== 2 || dispatch[6] !== 1 || dispatch[7] !== 1) {
    fail('PEERIT_THREE_POST_DESCRIBE_INVALID', 'relay returned a canonical error for current describe')
  }
  return dispatch.subarray(45)
}

async function currentHead (row, runtime, fetchImpl) {
  const request = currentHeadRequest(runtime)
  const response = await fetchImpl(row.canonicalDescribeUrl, {
    method: 'POST',
    headers: [['content-type', MEDIA_TYPE]],
    body: request.body,
    credentials: 'omit',
    cache: 'no-store',
    redirect: 'error',
    referrerPolicy: 'no-referrer',
    signal: AbortSignal.timeout(20_000)
  })
  if (!response || response.status !== 200 || response.headers.get('content-type') !== MEDIA_TYPE) {
    fail('PEERIT_THREE_POST_DESCRIBE_UNREACHABLE', `${row.relayId} did not return Blind HTTPS describe bytes`)
  }
  const canonical = unaryResponse(await response.arrayBuffer(), request.requestId)
  const parsed = parseDescriptor(canonical)
  if (parsed.totalLength !== canonical.byteLength) fail('PEERIT_THREE_POST_DESCRIBE_INVALID', `${row.relayId} descriptor has trailing bytes`)
  const digest = blake2b256(Buffer.concat([Buffer.from(DESCRIPTOR_HASH_DOMAIN, 'ascii'), canonical]))
  const unsigned = canonical.subarray(0, parsed.signedLength)
  const signedMessage = Buffer.concat([
    Buffer.from(DESCRIPTOR_SIGN_DOMAIN, 'ascii'),
    u64be(unsigned.byteLength),
    unsigned
  ])
  if (!ed25519Verify(parsed.relayPublicKey, signedMessage, parsed.signature)) {
    fail('PEERIT_THREE_POST_DESCRIBE_INVALID', `${row.relayId} current descriptor signature is invalid`)
  }
  const epoch = Math.floor(Date.now() / LEASE_EPOCH_MILLIS)
  if (!(parsed.issuedEpoch <= epoch && epoch < parsed.expiresEpoch)) {
    fail('PEERIT_THREE_POST_DESCRIBE_EXPIRED', `${row.relayId} current descriptor is outside its signed epoch window`)
  }
  if (hex(digest) !== row.descriptorHeadHash || Number(parsed.descriptorSequence) !== row.descriptorSequence ||
      hex(parsed.relayPublicKey) !== row.continuityRootRelayPublicKey || hex(parsed.storeId) !== row.storeId) {
    fail('PEERIT_THREE_POST_RELAY_TUPLE_DRIFT', `${row.relayId} current descriptor does not match the supplied immutable tuple`)
  }
  return { canonical, parsed }
}

function profileFor (parsed) {
  const admission = parsed.admissionProfiles.find(value => value.profileId === 7 && value.schemeId === 9)
  const endpoint = parsed.endpoints.find(value => value.endpointId === 1)
  if (!admission || !endpoint) fail('PEERIT_THREE_POST_PROFILE_UNAVAILABLE', 'descriptor lacks Peerit Cell endpoint/admission profile')
  return Object.freeze({
    supportedProtocolProfiles: Object.freeze(parsed.protocols.map(value => Object.freeze({
      protocolId: value.protocolId,
      major: value.major,
      minimumMinor: value.minor,
      profileHash: new Uint8Array(value.profileHash)
    }))),
    supportedTransportProfiles: Object.freeze(parsed.endpoints.map(value => Object.freeze({
      transportId: value.transportId,
      transportSupportBit: 1,
      transportProfileHash: new Uint8Array(value.transportProfileHash)
    }))),
    requirement: Object.freeze({
      familyId: 2,
      operationId: 1,
      endpointId: 1,
      requiredRoleBits: endpoint.roleBits,
      privacyProfileBit: 1,
      transportSupportBit: 1
    }),
    readRequirement: Object.freeze({
      familyId: 2,
      operationId: 2,
      endpointId: 1,
      requiredRoleBits: endpoint.roleBits,
      privacyProfileBit: 1,
      transportSupportBit: 1
    }),
    describeFamilyId: 1,
    admissionParametersOperationId: 3,
    admissionProfile: Object.freeze({
      profileId: 7,
      schemeId: 9,
      conformanceClass: admission.conformanceClass,
      roleBits: admission.roleBits,
      parameterUrl: admission.parameterUrl ? new Uint8Array(admission.parameterUrl) : null,
      parameterHash: new Uint8Array(admission.parameterHash)
    })
  })
}

async function verifiedBlindClient () {
  const authority = JSON.parse(await fs.readFile(path.join(VENDOR_DIR, 'authority.json'), 'utf8'))
  const artifactBytes = await fs.readFile(path.join(VENDOR_DIR, 'blind-client-control-v1.mjs'))
  const verified = verifyBlindClientBrowserReleaseV1({
    artifactBytes,
    manifestBytes: await fs.readFile(path.join(VENDOR_DIR, 'blind-client-control-v1.manifest.cenc')),
    chromiumEvidenceBytes: await fs.readFile(path.join(VENDOR_DIR, 'blind-client-control-v1.chromium-evidence.json')),
    crossHostEvidenceBytes: await fs.readFile(path.join(VENDOR_DIR, 'blind-client-control-v1.cross-host-evidence.json'))
  })
  if (hex(verified.artifactHash) !== authority.artifactHash || artifactBytes.byteLength !== authority.artifactLength) {
    fail('PEERIT_THREE_POST_BLIND_ARTIFACT_DRIFT', 'vendored blind client does not match its checked authority')
  }
  const control = await import(pathToFileURL(path.join(VENDOR_DIR, 'blind-client-control-v1.mjs')).href)
  return { control, runtime: control.createBrowserCryptoRuntime(globalThis.crypto) }
}

async function qualifyOne ({ row, control, runtime, bridge, fetchImpl }) {
  const head = await currentHead(row, runtime, fetchImpl)
  const profile = profileFor(head.parsed)
  const bootstrap = new control.BlindDescriptorBootstrapHttpClient({ runtime, fetch: fetchImpl })
  const trustBackend = new control.MemoryDescriptorTrustBackend()
  const trustStore = new control.DescriptorTrustStore(trustBackend)
  const chain = []
  let descriptorHash = row.descriptorHeadHash
  for (let depth = 0; depth < 4096; depth++) {
    const descriptor = await bootstrap.fetchVerifiedDescriptor({
      canonicalUrl: new TextEncoder().encode(row.canonicalDescribeUrl),
      expectedDescriptorHash: bytes(descriptorHash),
      continuityRootRelayPublicKey: bytes(row.continuityRootRelayPublicKey),
      nowEpoch: Math.floor(Date.now() / LEASE_EPOCH_MILLIS),
      history: true,
      supportedProtocolProfiles: profile.supportedProtocolProfiles,
      supportedTransportProfiles: profile.supportedTransportProfiles
    })
    const parsed = parseDescriptor(descriptor.snapshotBytes())
    chain.unshift({ descriptor, parsed, descriptorHash })
    if (parsed.descriptorSequence === 0n) break
    if (!parsed.previousDescriptorHash) fail('PEERIT_THREE_POST_DESCRIPTOR_CHAIN_INVALID', `${row.relayId} descriptor chain broke before genesis`)
    descriptorHash = hex(parsed.previousDescriptorHash)
  }
  if (chain.length !== row.descriptorSequence + 1 || chain[0].descriptorHash !== row.descriptorGenesisHash) {
    fail('PEERIT_THREE_POST_DESCRIPTOR_CHAIN_INVALID', `${row.relayId} descriptor chain does not reproduce its pinned genesis`)
  }
  for (const link of chain) {
    await trustStore.accept(link.descriptor, link.parsed.descriptorSequence === 0n
      ? Object.freeze({
        pinnedDescriptorHash: bytes(link.descriptorHash),
        continuityRootRelayPublicKey: bytes(row.continuityRootRelayPublicKey)
      })
      : Object.freeze({ continuityRootRelayPublicKey: bytes(row.continuityRootRelayPublicKey) }))
  }
  const raw = []
  const qualification = await qualifyPermissionlessRelayCandidates({
    control,
    blindClient: control,
    cryptoRuntime: runtime,
    nowEpoch: () => Math.floor(Date.now() / LEASE_EPOCH_MILLIS),
    profile,
    candidates: Object.freeze([Object.freeze({
      canonicalUrl: row.canonicalDescribeUrl,
      expectedDescriptorHash: row.descriptorHeadHash,
      continuityRootRelayPublicKey: row.continuityRootRelayPublicKey,
      descriptorPinned: true,
      sources: Object.freeze(['user'])
    })]),
    trustStore,
    descriptorTrustBackend: trustBackend,
    fetch: fetchImpl,
    admissionProvider: async () => Object.freeze({
      profileId: 7,
      schemeId: 9,
      parameterHash: new Uint8Array(profile.admissionProfile.parameterHash),
      token: runtime.randomBytes(32)
    }),
    persistPreparedReplica: bridge.persistPreparedReplica,
    persistVerifiedResult: bridge.persistVerifiedResult,
    persistVerifiedReadback: bridge.persistVerifiedReadback,
    loadPersistedReplica: bridge.loadPersistedReplica,
    createRelayAdapter (options) {
      const adapter = createBlindCellRelay({
        ...options,
        blindClient: control,
        control,
        leaseClass: 1
      })
      raw.push(adapter)
      return adapter
    },
    totalQualificationTimeoutMillis: 30_000
  })
  if (qualification.failures.length || qualification.adapters.length !== 1 || raw.length !== 1) {
    fail('PEERIT_THREE_POST_RELAY_UNQUALIFIED', `${row.relayId} qualification failed: ${JSON.stringify(qualification.failures)}`)
  }
  return Object.freeze({ relayId: row.relayId, adapter: qualification.adapters[0] })
}

export async function qualifyThreePostLiveRelaysV1 ({ relayTuple, bridge, fetch: fetchImpl = globalThis.fetch }) {
  if (!globalThis.crypto || !globalThis.crypto.subtle || typeof fetchImpl !== 'function') {
    fail('PEERIT_THREE_POST_RUNTIME_UNAVAILABLE', 'Web Crypto and fetch are required for live relay qualification')
  }
  const tuple = validateCurrentRelayTupleV1(relayTuple)
  const { control, runtime } = await verifiedBlindClient()
  const relays = []
  for (const row of tuple.relays) {
    relays.push(await qualifyOne({ row, control, runtime, bridge, fetchImpl }))
  }
  const rebound = bindCurrentRelayTupleV1(relays)
  if (rebound.tupleSha256 !== tuple.tupleSha256) {
    fail('PEERIT_THREE_POST_RELAY_TUPLE_DRIFT', 'qualified branded adapters do not reproduce the supplied current tuple')
  }
  return Object.freeze({ relays: Object.freeze(relays), relayTuple: rebound })
}
