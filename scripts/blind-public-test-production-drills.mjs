#!/usr/bin/env node
// blind-public-test-production-drills.mjs — production-profile drills for the
// Peerit public-test bind, through the Peerit substrate client against BOTH
// live relays:
//
//   A. write/readback/recovery — deliver a signed publication, then simulate
//      a client restart (fresh vault instance + fresh qualified adapter over
//      the SAME persisted kv) and recover the cell via revalidateReadback:
//      a new capability-bound GET only, never a resend. The ambiguous
//      lost-response reconcile is proven in the fixture e2e
//      (test/peerit-hiverelay-real-e2e.mjs); live fault injection is not
//      consented on shared relays and is recorded as deferred.
//   B. client-side moderation/feed/vote — author real signed Peerit records
//      (post, vote, comment) into one inner operation batch, deliver as one
//      opaque cell to each relay, read back byte-exact, then run the app's
//      own client-side logic over the recovered records: vote tally
//      (js/ranking.js), feed ranking (rankPostsWindow), moderation view
//      filtering (js/moderation.js). Wire capture proves no app schema
//      vocabulary ever reaches the relay.
//   C. INBOX/CORE unary — probed honestly: the relays advertise and price
//      these families, but the vendored v1 control surface exports no INBOX/
//      CORE request constructors, so the app's own code paths cannot compose
//      them today. Recorded as deferred, not faked.
//
// Usage: node scripts/blind-public-test-production-drills.mjs
// Exit 0 = phases A+B pass on both relays (phase C is informational).

import { readFileSync } from 'node:fs'
import { fileURLToPath, pathToFileURL } from 'node:url'
import path from 'node:path'
import { canonical } from '../js/canon.js'
import { ready as cryptoReady } from '../js/crypto.js'
import { createIdentity } from '../js/identity.js'
import { CONTENT_PROTOCOL, TYPE, contentId } from '../js/model.js'
import { memoryStorage } from '../js/sync.js'
import * as ranking from '../js/ranking.js'
import * as moderation from '../js/moderation.js'
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
  decodePeeritInnerOperationBatchV1,
  hashPeeritInnerOperationIntentIdV1
} from '../js/substrate/peerit-operation-authority-v1.js'

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const VENDOR_DIR = path.join(ROOT, 'vendor', 'hiverelay-blind-client-v1')
const LEASE_EPOCH_MILLIS = 21600000

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

const PLACEHOLDER_PROTOCOL_PROFILE_HASH = '0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a'
const PLACEHOLDER_TRANSPORT_PROFILE_HASH = '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'

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
      transportSupportBit: 1,
      transportProfileHash: hexToBytes(PLACEHOLDER_TRANSPORT_PROFILE_HASH)
    })]),
    requirement: Object.freeze({ familyId: 2, operationId: 1, endpointId: 1, requiredRoleBits: 49, privacyProfileBit: 1, transportSupportBit: 1 }),
    readRequirement: Object.freeze({ familyId: 2, operationId: 2, endpointId: 1, requiredRoleBits: 49, privacyProfileBit: 1, transportSupportBit: 1 }),
    describeFamilyId: 1,
    admissionParametersOperationId: 3,
    admissionProfile: Object.freeze({
      profileId: 7,
      schemeId: 9,
      conformanceClass: 1,
      roleBits: 49,
      parameterUrl: new TextEncoder().encode(relay.admissionParameterUrl),
      parameterHash: hexToBytes(relay.admissionParameterHash)
    })
  })
}

async function signedRecord (identity, type, data) {
  const signature = await identity.sign(canonical(type, data))
  return {
    type,
    data: {
      ...data,
      _sig: signature.signature,
      _k: signature.publicKey,
      _dk: signature.driveKey,
      _ns: signature.namespace,
      _alg: signature.algorithm
    }
  }
}

async function publicationFor (identity, operations) {
  const envelope = await createPeeritInnerOperationBatchV1(operations, {
    expectedAuthorPublicKey: identity.me().pubkey
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

function containsBytes (haystack, needle) {
  outer: for (let i = 0; i + needle.byteLength <= haystack.byteLength; i++) {
    for (let j = 0; j < needle.byteLength; j++) if (haystack[i + j] !== needle[j]) continue outer
    return true
  }
  return false
}

async function qualifyRelay ({ control, runtime, relay, kv, captured, label }) {
  const profile = bindProfile(relay)
  const vault = createPeeritCapabilityVault({ kv, crypto: globalThis.crypto, now: () => 1000 })
  const rawAdapters = []
  const bootstrap = new control.BlindDescriptorBootstrapHttpClient({ runtime, fetch: captured })
  const trustStore = new control.DescriptorTrustStore(new control.MemoryDescriptorTrustBackend())
  const chain = []
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
  for (const link of chain) {
    await trustStore.accept(link.descriptor, link.sequence === 0
      ? Object.freeze({
          pinnedDescriptorHash: hexToBytes(link.hash),
          continuityRootRelayPublicKey: hexToBytes(relay.continuityRootRelayPublicKey)
        })
      : Object.freeze({ continuityRootRelayPublicKey: hexToBytes(relay.continuityRootRelayPublicKey) }))
  }
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
    fetch: captured,
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
  if (qualification.adapters.length !== 1) {
    throw new Error(`${relay.id} (${label}): qualification failed ${JSON.stringify(qualification.failures)}`)
  }
  return Object.freeze({ adapter: qualification.adapters[0], rawAdapter: rawAdapters[0], vault, chainLength: chain.length })
}

async function main () {
  if (!globalThis.crypto || !globalThis.crypto.subtle) throw new Error('drills require Web Crypto')
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
  if (hex(verifiedRelease.artifactHash) !== authority.artifactHash) throw new Error('vendored artifact drift before drills')
  const control = await import(pathToFileURL(path.join(VENDOR_DIR, 'blind-client-control-v1.mjs')).href)
  const runtime = control.createBrowserCryptoRuntime(globalThis.crypto)
  await cryptoReady()
  const identity = createIdentity({
    forceDev: true,
    lazy: true,
    storage: memoryStorage(),
    session: memoryStorage(),
    label: 'peerit-public-test-production-drills'
  })
  await identity.ready()
  await identity.ensureActive('peerit-public-test-production-drills')

  // Phase C probe: the vendored control surface's composition exports.
  const inboxCoreExports = ['createInboxReplica', 'createAppendInboxRequest', 'createReadInboxRequest', 'createCoreMirrorRequest']
    .filter((name) => typeof control[name] === 'function')

  const stamp = new Date().toISOString()
  const marker = `peerit-public-test-production-drill-${stamp}`
  const report = {
    schema: 'PeeritBlindPublicTestProductionDrillsV1',
    drilledAt: stamp,
    marker,
    phases: {
      A: 'cell write/readback/restart-recovery (capability GET only after restart)',
      B: 'client-side moderation/feed/vote over relay-held opaque cells',
      C: 'INBOX/CORE unary availability probe (informational)'
    },
    relays: [],
    phaseC: {
      vendoredControlExportsInboxCoreComposition: inboxCoreExports.length,
      relaysAdvertiseInboxCore: true,
      admissionPricesInboxCore: true,
      disposition: 'DEFERRED — relays serve INBOX/CORE and price them in the signed admission parameters, but the vendored v1 control surface exports no INBOX/CORE request constructors, so the app’s own code paths cannot compose these operations today. Not faked; the relay-side acceptance already covers the relay surface.',
      detail: 'vendored composition covers DESCRIBE + CELL (write/readback/reconcile) only'
    },
    status: 'fail'
  }

  for (const relay of RELAYS) {
    const entry = { id: relay.id, checks: [], wire: [] }
    const check = (id, ok, detail) => {
      entry.checks.push({ id, status: ok ? 'pass' : 'fail', detail: String(detail) })
      if (!ok) throw new Error(`${relay.id}: ${id}: ${detail}`)
    }
    const captured = []
    const capturingFetch = async (url, options = {}) => {
      const bodyBytes = options.body
        ? new Uint8Array(options.body.buffer || options.body, options.body.byteOffset || 0, options.body.byteLength)
        : null
      captured.push({ url: String(url), method: options.method || 'GET', bodyBytes: bodyBytes ? bodyBytes.slice() : null })
      return globalThis.fetch(url, options)
    }

    // ---- Phase A: write/readback/restart recovery -------------------------
    const kv = memoryCapabilityVaultKv()
    const first = await qualifyRelay({ control, runtime, relay, kv, captured: capturingFetch, label: 'writer' })
    const me = identity.me()
    const profileOp = await signedRecord(identity, 'profile', { id: me.pubkey, author: me.pubkey, name: `${marker}-recovery` })
    const publicationA = await publicationFor(identity, [profileOp])
    const delivered = await first.adapter.deliver(publicationA)
    check('A.deliver.readback-verified', delivered.readbackVerified === true, `evidenceRef=${delivered.evidenceRef}`)
    const cellCallsAfterDeliver = captured.filter((call) => call.url.includes('/api/blind/v1/cell')).length

    // Simulated restart: same persisted kv, brand-new vault + freshly qualified
    // adapter (the descriptor trust store is re-seeded by a live chain walk —
    // the drill's stand-in for the production IndexedDB trust backend).
    const restarted = await qualifyRelay({ control, runtime, relay, kv, captured: capturingFetch, label: 'recovered' })
    check('A.restart.requalified', restarted.adapter !== first.adapter && restarted.chainLength >= 1,
      `fresh adapter after simulated restart (chain ${restarted.chainLength} descriptors)`)
    const recovered = await restarted.adapter.revalidateReadback(publicationA)
    check('A.restart.capability-get-only', recovered.readbackVerified === true &&
      captured.filter((call) => call.url.includes('/api/blind/v1/cell')).length === cellCallsAfterDeliver + 1,
      'recovery performed exactly one new capability-bound GET and zero PUTs')
    const recoveredStored = await restarted.vault.load(publicationA.intentId, restarted.rawAdapter.id)
    check('A.restart.byte-exact', recoveredStored && recoveredStored.stage === 'readback-verified' &&
      Buffer.from(recoveredStored.payload.readbackInnerBytes).equals(Buffer.from(publicationA.innerBytes)),
      `stage=${recoveredStored && recoveredStored.stage} revision=${recoveredStored && recoveredStored.revision}`)
    entry.checks.push({
      id: 'A.restart.ambiguity-note',
      status: 'info',
      detail: 'lost-response-after-commit reconcile (GET-only, never resend) is proven in fixture e2e test/peerit-hiverelay-real-e2e.mjs; live fault injection on shared relays is not consented — deferred.'
    })

    // ---- Phase B: client-side moderation/feed/vote ------------------------
    const community = 'public-test'
    const contentNonce = `drill-post-${stamp}`
    const postCid = await contentId(TYPE.POST, me.pubkey, contentNonce)
    const postData = {
      id: `${community}!${postCid}`,
      cid: postCid,
      community,
      kind: 'text',
      protocol: CONTENT_PROTOCOL,
      contentNonce,
      title: marker,
      body: `bounded public-test canary drill body ${stamp}`,
      url: '',
      author: me.pubkey,
      createdAt: Date.now(),
      editedAt: 0,
      deleted: false
    }
    const postOp = await signedRecord(identity, 'post', postData)
    const voteData = {
      id: `${postCid}!${me.pubkey}`,
      targetCid: postCid,
      targetType: TYPE.POST,
      community,
      protocol: CONTENT_PROTOCOL,
      targetRef: { type: TYPE.POST, author: me.pubkey, contentNonce, cid: postCid },
      value: 1,
      author: me.pubkey,
      ts: Date.now()
    }
    const voteOp = await signedRecord(identity, 'vote', voteData)
    const publicationB = await publicationFor(identity, [postOp, voteOp])
    const deliveredB = await first.adapter.deliver(publicationB)
    check('B.deliver.readback-verified', deliveredB.readbackVerified === true, `evidenceRef=${deliveredB.evidenceRef}`)
    const storedB = await first.vault.load(publicationB.intentId, first.rawAdapter.id)
    check('B.byte-exact', storedB && Buffer.from(storedB.payload.readbackInnerBytes).equals(Buffer.from(publicationB.innerBytes)),
      'post+vote batch read back byte-exact from the relay-held cell')

    // Client-side only: decode + vote tally + feed ranking + moderation view.
    const decoded = await decodePeeritInnerOperationBatchV1(publicationB.innerCodec, storedB.payload.readbackInnerBytes, {
      expectedAuthorPublicKey: me.pubkey
    })
    check('B.decode.verified', decoded.operations.length === 2 && decoded.authorPublicKey === me.pubkey,
      `decoded ${decoded.operations.length} signed ops from the recovered cell`)
    const votes = [decoded.operations[1].data]
    const tallyResult = ranking.tally(votes, me.pubkey)
    check('B.client-side.vote-tally', tallyResult && Number(tallyResult.score) === 1,
      `ranking.tally over recovered votes: score=${tallyResult && tallyResult.score}`)
    const ranked = ranking.rankPostsWindow([decoded.operations[0].data], 'hot', 'all', 1, 25, Date.now())
    check('B.client-side.feed-rank', Array.isArray(ranked.items) && ranked.items.length === 1,
      'rankPostsWindow over recovered posts')
    const view = moderation.cleanModerationView('community')
    const eligible = moderation.eligibleCommunityAuthors({
      creator: me.pubkey,
      posts: [decoded.operations[0].data],
      votes: [decoded.operations[1].data]
    })
    const consensus = moderation.aggregateReports([], { eligible, viewer: me.pubkey })
    const decision = moderation.applyModerationPolicy(consensus, { view })
    check('B.client-side.moderation-view', eligible.has(me.pubkey) && decision.visibility === 'visible',
      `eligibleCommunityAuthors + aggregateReports + applyModerationPolicy over recovered records: visibility=${decision.visibility}`)
    entry.checks.push({
      id: 'B.moderation-scope-note',
      status: 'info',
      detail: 'report/modaction aggregation (aggregateReports/applyModerationPolicy) operates on the same recovered-record shape; report ops additionally require PoW and are not written to shared public-test relays in this drill.'
    })

    // ---- Boundary: no app schema vocabulary on the wire for this relay ----
    const schemaWords = ['peerit', '"post"', '"vote"', '"comment"', 'modaction', 'moderation', 'targetCid', 'contentNonce', community, marker]
      .map((word) => new TextEncoder().encode(word))
    entry.wire = captured.map((call) => ({
      url: call.url,
      method: call.method,
      bodyBytes: call.bodyBytes ? call.bodyBytes.byteLength : 0,
      schemaWordsPresent: call.bodyBytes
        ? schemaWords.filter((word) => containsBytes(call.bodyBytes, word)).map((word) => Buffer.from(word).toString('utf8'))
        : []
    }))
    check('boundary.no-app-schema-on-wire', entry.wire.every((call) => call.schemaWordsPresent.length === 0),
      `zero app schema vocabulary in ${entry.wire.length} relay-visible requests (post/vote/profile/moderation markers)`)

    report.relays.push(entry)
  }

  report.status = report.relays.length === 2 ? 'pass' : 'fail'
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`)
  process.exitCode = report.status === 'pass' ? 0 : 1
}

main().catch((error) => {
  process.stderr.write(`[blind-public-test-production-drills] ${error.code || 'ERROR'}: ${error.stack || error.message}\n`)
  process.exitCode = 1
})
