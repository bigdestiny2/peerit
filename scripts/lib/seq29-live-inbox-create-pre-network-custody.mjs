// Explicit pre-network custody for the Seq29 two-CREATE ceremony. This module
// authenticates no live state: it binds only the already-authenticated static
// release snapshot, the frozen allocation epoch, six freshly generated
// management seeds, two explicit client nonces, and the two exact CREATE
// request commitments. Current descriptor heads remain a later read-only
// qualification concern.

import {
  createHash,
  createPrivateKey,
  createPublicKey
} from 'node:crypto'
import {
  closeSync,
  constants,
  fchmodSync,
  fstatSync,
  fsyncSync,
  linkSync,
  lstatSync,
  mkdirSync,
  openSync,
  readSync,
  realpathSync,
  unlinkSync,
  writeSync
} from 'node:fs'
import { basename, dirname, join, resolve } from 'node:path'
import {
  canonicalPeeritLimitedPublicInboxJsonV1
} from '../../js/substrate/inbox-topic-v1.mjs'
import {
  bytesEqual,
  bytesToHex,
  hexToBytes,
  isAllZero
} from '../../js/substrate/release-control-primitives.mjs'
import {
  loadPeeritSeq29AcceptedHiveRelayOperatorV1
} from './seq29-accepted-hiverelay-operator.mjs'
import {
  createPeeritSeq29LocalManagementCustodyCrashFixtureV1,
  createPeeritSeq29LocalManagementCustodyV1,
  inspectPeeritSeq29LocalManagementPreparedTransitionV1,
  peeritSeq29LocalManagementCustodyTransactionIdV1,
  recoverPeeritSeq29LocalManagementPreparedTransitionV1
} from './seq29-local-management-custody.mjs'
import {
  createPeeritSeq29LocalCustodianKeyFileConfigurationV1
} from './seq29-local-custodian-key-files.mjs'

const CANDIDATE_COMMIT = 'adeacef07c5de4d17d5ed1389fee7a35095b862f'
const CANDIDATE_TREE = '7c41786a4ccd758a4ddcb419eb02213cbeeaca0c'
const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex')
const HEX32 = /^[0-9a-f]{64}$/
const PREPARED_COMMITMENT = /^seq29-custody:prepared:[0-9a-f]{64}$/
const RELAY_IDS = Object.freeze(['dal-1', 'syd-1'])
const IDENTITY_FILE = '0000-pre-network-identity.json'
const PREPARED_FILE = '0001-pre-network-prepared.json'
const BINDING_FILE = '0002-exact-plan-binding.json'
const OFFLINE_PREPARATIONS = new WeakMap()
const PRE_NETWORK_CUSTODIES = new WeakMap()
const EXACT_BINDINGS = new WeakMap()
const FIXTURE_CRASH_STAGES = new Set([
  'INNER_AFTER_PREPARED_FSYNC_BEFORE_GUARD_RELEASE',
  'AFTER_DURABLE_PREPARE',
  'DURING_SELF_VERIFICATION',
  'OUTER_AFTER_STAGE_FSYNC_BEFORE_LINK',
  'OUTER_AFTER_LINK_BEFORE_ALIAS_UNLINK',
  'OUTER_AFTER_ALIAS_UNLINK_BEFORE_DIRECTORY_FSYNC'
])

function fail (code, message, cause) {
  const error = new Error(message)
  error.code = code
  if (cause !== undefined) error.cause = cause
  throw error
}

function exact (value, fields, field) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).sort().join('\0') !== [...fields].sort().join('\0')) {
    fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_INVALID',
      `${field} has missing or unexpected fields`)
  }
  return value
}

function hex32 (value, field) {
  if (typeof value !== 'string' || !HEX32.test(value)) {
    fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_INVALID',
      `${field} must be lowercase 32-byte hexadecimal`)
  }
  return value
}

function u32 (value, field) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) {
    fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_INVALID', `${field} is outside u32`)
  }
  return value
}

function sha256 (value) {
  return createHash('sha256').update(value).digest('hex')
}

function canonicalBytes (value) {
  return canonicalPeeritLimitedPublicInboxJsonV1(value)
}

function prettyBytes (value) {
  return Buffer.from(JSON.stringify(value, null, 2) + '\n')
}

function ed25519PublicFromSeed (seed) {
  const privateDer = Buffer.alloc(ED25519_PKCS8_PREFIX.byteLength + seed.byteLength)
  privateDer.set(ED25519_PKCS8_PREFIX)
  privateDer.set(seed, ED25519_PKCS8_PREFIX.byteLength)
  try {
    return new Uint8Array(createPublicKey(createPrivateKey({
      key: privateDer,
      format: 'der',
      type: 'pkcs8'
    })).export({ format: 'der', type: 'spki' }).subarray(-32))
  } finally { privateDer.fill(0) }
}

function validateReleaseSnapshot (input) {
  const value = structuredClone(input)
  exact(value, [
    'schema', 'version', 'releaseSequence', 'candidateCommit', 'candidateTree',
    'referenceUnixMillis', 'allocationEpoch', 'seedBootstrapSha256',
    'limitedCellPutProfileSha256', 'controlArtifactSha256',
    'inboxOperatorArtifactSha256', 'relays'
  ], 'static release snapshot')
  if (value.schema !== 'peerit-seq29-live-inbox-create-static-release-snapshot-v1' ||
      value.version !== 1 || value.releaseSequence !== 29 ||
      value.candidateCommit !== CANDIDATE_COMMIT || value.candidateTree !== CANDIDATE_TREE ||
      !/^(0|[1-9][0-9]{0,19})$/.test(value.referenceUnixMillis)) {
    fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_INVALID',
      'static release snapshot identity is invalid')
  }
  u32(value.allocationEpoch, 'allocationEpoch')
  for (const field of [
    'seedBootstrapSha256', 'limitedCellPutProfileSha256',
    'controlArtifactSha256', 'inboxOperatorArtifactSha256'
  ]) hex32(value[field], field)
  if (!Array.isArray(value.relays) || value.relays.length !== 2) {
    fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_INVALID',
      'static release snapshot requires exactly two relays')
  }
  value.relays.forEach((relay, index) => {
    exact(relay, [
      'relayId', 'canonicalDescribeUrl', 'relayPublicKey', 'storeId',
      'continuityRootRelayPublicKey', 'descriptorGenesisHash',
      'minimumDescriptorSequence', 'familyId', 'operationId', 'endpointId',
      'transportId', 'transportSupportBit', 'privacyProfileBit'
    ], `static relay ${index}`)
    if (relay.relayId !== RELAY_IDS[index] ||
        typeof relay.canonicalDescribeUrl !== 'string' ||
        relay.relayPublicKey !== relay.continuityRootRelayPublicKey ||
        !/^[1-9][0-9]*$/.test(relay.minimumDescriptorSequence) ||
        relay.familyId !== 3 || relay.operationId !== 1 ||
        relay.endpointId !== 1 || relay.transportId !== 1 ||
        relay.transportSupportBit !== 1 || relay.privacyProfileBit !== 1) {
      fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_INVALID',
        `static relay ${index} differs from the fixed Seq29 CREATE scope`)
    }
    for (const field of [
      'relayPublicKey', 'storeId', 'continuityRootRelayPublicKey',
      'descriptorGenesisHash'
    ]) hex32(relay[field], `${relay.relayId}.${field}`)
  })
  return Object.freeze(value)
}

function copyContext (value) {
  return Object.freeze({
    familyId: value.familyId,
    operationId: value.operationId,
    requestCommitment: new Uint8Array(value.requestCommitment),
    relayPublicKey: new Uint8Array(value.relayPublicKey),
    frameClassBits: value.frameClassBits,
    retentionClass: value.retentionClass,
    leaseClass: value.leaseClass
  })
}

function destroySeedEntries (entries) {
  for (const entry of entries || []) {
    entry.createPrivateSeed?.fill(0)
    entry.renewPrivateSeed?.fill(0)
    entry.closePrivateSeed?.fill(0)
    entry.clientNonce?.fill(0)
  }
}

function pairwiseDistinctBytes (values) {
  for (let left = 0; left < values.length; left++) {
    for (let right = left + 1; right < values.length; right++) {
      if (bytesEqual(values[left], values[right])) return false
    }
  }
  return true
}

function validateCapturedSeeds (entries) {
  const all = entries.flatMap(entry => [
    entry.createPrivateSeed, entry.renewPrivateSeed, entry.closePrivateSeed
  ])
  if (all.length !== 6 || all.some(value => value.byteLength !== 32 || isAllZero(value)) ||
      !pairwiseDistinctBytes(all)) {
    fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_CAPTURE_DRIFT',
      'offline capture did not produce six pairwise-distinct nonzero management seeds')
  }
}

async function captureRelay (accepted, runtime, relay, allocationEpoch) {
  const clientNonce = new Uint8Array(runtime.randomBytes(32))
  const draws = []
  const sentinel = Object.freeze({})
  let context = null
  try {
    if (clientNonce.byteLength !== 32 || isAllZero(clientNonce)) {
      fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_CAPTURE_DRIFT',
        `${relay.relayId} client nonce is invalid`)
    }
    const captureRuntime = Object.freeze({
      randomBytes (length) {
        if (length !== 32 || draws.length >= 3) {
          fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_CAPTURE_DRIFT',
            `${relay.relayId} pinned operator random-call shape changed`)
        }
        const value = runtime.randomBytes(length)
        if (!(value instanceof Uint8Array) || value.byteLength !== 32) {
          value?.fill?.(0)
          fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_CAPTURE_DRIFT',
            `${relay.relayId} runtime returned a non-32-byte seed`)
        }
        draws.push(value)
        return value.slice()
      }
    })
    try {
      await accepted.inbox.createInboxReplica({
        runtime: captureRuntime,
        relayPublicKey: hexToBytes(relay.relayPublicKey, 32, 'relayPublicKey'),
        allocationEpoch,
        frameClassBits: 3,
        appendAuthMode: 0,
        retentionClass: 3,
        leaseClass: 4,
        clientNonce,
        async admissionProvider (value) {
          if (context != null) {
            fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_CAPTURE_DRIFT',
              `${relay.relayId} admission provider was invoked more than once`)
          }
          context = copyContext(value)
          throw sentinel
        }
      })
      fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_CAPTURE_DRIFT',
        `${relay.relayId} offline constructor crossed its admission stop`)
    } catch (cause) {
      if (cause !== sentinel) throw cause
    }
    if (draws.length !== 3 || context == null || context.familyId !== 3 ||
        context.operationId !== 1 || context.frameClassBits !== 3 ||
        context.retentionClass !== 3 || context.leaseClass !== 4 ||
        !bytesEqual(context.relayPublicKey,
          hexToBytes(relay.relayPublicKey, 32, 'relayPublicKey'))) {
      fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_CAPTURE_DRIFT',
        `${relay.relayId} pinned operator pre-admission shape changed`)
    }
    const entry = {
      relayId: relay.relayId,
      allocationEpoch,
      createPrivateSeed: draws[0],
      renewPrivateSeed: draws[1],
      closePrivateSeed: draws[2],
      clientNonce,
      requestCommitment: context.requestCommitment,
      createPublicKey: ed25519PublicFromSeed(draws[0]),
      renewPublicKey: ed25519PublicFromSeed(draws[1]),
      closePublicKey: ed25519PublicFromSeed(draws[2])
    }
    draws.length = 0
    return entry
  } catch (cause) {
    for (const value of draws) value.fill(0)
    clientNonce.fill(0)
    context?.requestCommitment.fill(0)
    context?.relayPublicKey.fill(0)
    throw cause
  }
}

function publicRequest (entry, releaseRelay) {
  return Object.freeze({
    relayId: entry.relayId,
    relayPublicKey: releaseRelay.relayPublicKey,
    allocationEpoch: entry.allocationEpoch,
    frameClassBits: 3,
    appendAuthMode: 0,
    retentionClass: 3,
    leaseClass: 4,
    clientNonce: bytesToHex(entry.clientNonce),
    requestCommitment: bytesToHex(entry.requestCommitment),
    createPublicKey: bytesToHex(entry.createPublicKey),
    renewPublicKey: bytesToHex(entry.renewPublicKey),
    closePublicKey: bytesToHex(entry.closePublicKey)
  })
}

export async function preparePeeritSeq29OfflineInboxCreateRequestsV1 (input = {}) {
  exact(input, ['releaseSnapshot'], 'offline CREATE preparation input')
  const releaseSnapshot = validateReleaseSnapshot(input.releaseSnapshot)
  const accepted = await loadPeeritSeq29AcceptedHiveRelayOperatorV1()
  if (accepted.identity.candidateCommit !== CANDIDATE_COMMIT ||
      accepted.identity.candidateTree !== CANDIDATE_TREE ||
      accepted.identity.inboxOperatorArtifactSha256 !==
        releaseSnapshot.inboxOperatorArtifactSha256 ||
      typeof accepted.inbox.createInboxReplica !== 'function' ||
      typeof accepted.control.createBrowserCryptoRuntime !== 'function') {
    fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_OPERATOR_DRIFT',
      'accepted HiveRelay operator identity differs from the static release')
  }
  const runtime = accepted.control.createBrowserCryptoRuntime(globalThis.crypto)
  const entries = []
  try {
    for (const relay of releaseSnapshot.relays) {
      entries.push(await captureRelay(
        accepted, runtime, relay, releaseSnapshot.allocationEpoch))
    }
    validateCapturedSeeds(entries)
    const requests = Object.freeze(entries.map((entry, index) =>
      publicRequest(entry, releaseSnapshot.relays[index])))
    validatePublicRequests(requests, releaseSnapshot)
    const authority = Object.freeze({
      schema: 'peerit-seq29-offline-inbox-create-preparation-v1',
      version: 1,
      candidateCommit: CANDIDATE_COMMIT,
      releaseSequence: 29,
      allocationEpoch: releaseSnapshot.allocationEpoch,
      requestCommitments: Object.freeze(requests.map(row => row.requestCommitment)),
      networkRequests: 0
    })
    OFFLINE_PREPARATIONS.set(authority, {
      releaseSnapshot,
      requests,
      entries,
      consumed: false
    })
    return authority
  } catch (cause) {
    destroySeedEntries(entries)
    throw cause
  }
}

function offlineState (value) {
  const state = OFFLINE_PREPARATIONS.get(value)
  if (!state) {
    fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_AUTHORITY_REQUIRED',
      'a module-created offline CREATE preparation is required')
  }
  return state
}

export function snapshotPeeritSeq29OfflineInboxCreatePreparationV1 (authority) {
  const state = offlineState(authority)
  return Object.freeze({
    schema: 'peerit-seq29-offline-inbox-create-preparation-snapshot-v1',
    version: 1,
    releaseSnapshot: structuredClone(state.releaseSnapshot),
    requests: structuredClone(state.requests),
    networkRequests: 0
  })
}

function metadataIdentity (metadata) {
  return Object.freeze({
    dev: metadata.dev,
    ino: metadata.ino,
    uid: metadata.uid
  })
}

function sameIdentity (metadata, identity) {
  return metadata.dev === identity.dev && metadata.ino === identity.ino &&
    metadata.uid === identity.uid
}

function validatePrivateRoot (root, expectedIdentity = null) {
  const metadata = lstatSync(root, { bigint: true })
  const expectedUid = typeof process.getuid === 'function'
    ? BigInt(process.getuid())
    : metadata.uid
  if (realpathSync(root) !== root || metadata.isSymbolicLink() ||
      !metadata.isDirectory() || (metadata.mode & 0o777n) !== 0o700n ||
      metadata.uid !== expectedUid) {
    fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_PERMISSIONS',
      'pre-network custody root must be an owned real mode-0700 directory')
  }
  if (expectedIdentity != null && !sameIdentity(metadata, expectedIdentity)) {
    fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_DIRECTORY_REPLACED',
      'pre-network custody root was replaced')
  }
  return metadata
}

function assertPrivateRoot (directory) {
  const root = resolve(directory)
  mkdirSync(root, { recursive: true, mode: 0o700 })
  const metadata = validatePrivateRoot(root)
  return Object.freeze({ root, identity: metadataIdentity(metadata) })
}

function validateRootBoundary (boundary) {
  return validatePrivateRoot(boundary.root, boundary.identity)
}

function fsyncDirectory (boundary) {
  validateRootBoundary(boundary)
  const descriptor = openSync(boundary.root,
    constants.O_RDONLY | constants.O_NOFOLLOW)
  try {
    const opened = fstatSync(descriptor, { bigint: true })
    if (!sameIdentity(opened, boundary.identity)) {
      fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_DIRECTORY_REPLACED',
        'pre-network custody root changed during fsync')
    }
    fsyncSync(descriptor)
  } finally { closeSync(descriptor) }
  validateRootBoundary(boundary)
}

function fileIdentity (metadata) {
  return [
    metadata.dev, metadata.ino, metadata.mode, metadata.nlink, metadata.uid,
    metadata.size, metadata.mtimeNs, metadata.ctimeNs
  ].join(':')
}

function assertPrivateFile (metadata, path, maximum, allowedLinks = [1n]) {
  const expectedUid = typeof process.getuid === 'function'
    ? BigInt(process.getuid())
    : metadata.uid
  if (metadata.isSymbolicLink() || !metadata.isFile() ||
      !allowedLinks.includes(metadata.nlink) ||
      (metadata.mode & 0o777n) !== 0o600n || metadata.uid !== expectedUid ||
      metadata.size < 1n || metadata.size > BigInt(maximum) ||
      typeof constants.O_NOFOLLOW !== 'number') {
    fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_PERMISSIONS',
      `${basename(path)} is not an owned bounded mode-0600 file with the expected link count`)
  }
}

function exactReadWithLinks (boundary, path, maximum, allowedLinks) {
  validateRootBoundary(boundary)
  if (dirname(path) !== boundary.root) {
    fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_PERMISSIONS',
      'pre-network custody record escaped its private root')
  }
  const before = lstatSync(path, { bigint: true })
  assertPrivateFile(before, path, maximum, allowedLinks)
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW)
  try {
    const opened = fstatSync(descriptor, { bigint: true })
    if (fileIdentity(opened) !== fileIdentity(before)) {
      fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_PERMISSIONS',
        `${basename(path)} changed during open`)
    }
    const output = new Uint8Array(Number(before.size))
    let offset = 0
    while (offset < output.byteLength) {
      const count = readSync(
        descriptor, output, offset, output.byteLength - offset, offset)
      if (count === 0) break
      offset += count
    }
    const extra = Buffer.alloc(1)
    if (offset !== output.byteLength ||
        readSync(descriptor, extra, 0, 1, offset) !== 0 ||
        fileIdentity(fstatSync(descriptor, { bigint: true })) !==
          fileIdentity(before) ||
        fileIdentity(lstatSync(path, { bigint: true })) !== fileIdentity(before)) {
      fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_PERMISSIONS',
        `${basename(path)} changed during its exact read`)
    }
    validateRootBoundary(boundary)
    return output
  } finally { closeSync(descriptor) }
}

function exactRead (boundary, path, maximum = 1024 * 1024) {
  return exactReadWithLinks(boundary, path, maximum, [1n])
}

function lstatIfPresent (path) {
  try { return lstatSync(path, { bigint: true }) } catch (cause) {
    if (cause?.code === 'ENOENT') return null
    throw cause
  }
}

function atomicStagePath (path) {
  return join(dirname(path), `.${basename(path)}.peerit-stage-v1`)
}

function exactAtomicFile (boundary, path, bytes, links) {
  const before = lstatSync(path, { bigint: true })
  assertPrivateFile(before, path, bytes.byteLength, links)
  const actual = exactReadWithLinks(boundary, path, bytes.byteLength, links)
  try {
    if (!bytesEqual(actual, bytes)) {
      fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_STATE_CONFLICT',
        `${basename(path)} differs from the expected durable record`)
    }
  } finally { actual.fill(0) }
  const after = lstatSync(path, { bigint: true })
  if (fileIdentity(after) !== fileIdentity(before)) {
    fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_DIRECTORY_REPLACED',
      `${basename(path)} changed after exact verification`)
  }
  return after
}

function verifiedUnlink (boundary, path, expected) {
  validateRootBoundary(boundary)
  const current = lstatSync(path, { bigint: true })
  if (fileIdentity(current) !== fileIdentity(expected)) {
    fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_DIRECTORY_REPLACED',
      `${basename(path)} changed before verified unlink`)
  }
  unlinkSync(path)
  validateRootBoundary(boundary)
}

function maybeCrashFixture (requested, stage) {
  if (requested === stage) process.kill(process.pid, 'SIGKILL')
}

function atomicCreate (boundary, path, bytes, crashStage = null) {
  validateRootBoundary(boundary)
  const directory = dirname(path)
  if (directory !== boundary.root) {
    fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_PERMISSIONS',
      'pre-network custody record escaped its private root')
  }
  const temporary = atomicStagePath(path)
  let descriptor
  try {
    const existing = lstatIfPresent(path)
    const staged = lstatIfPresent(temporary)
    if (existing != null) {
      const durable = exactAtomicFile(boundary, path, bytes, [1n, 2n])
      if (durable.nlink === 2n) {
        if (staged == null) {
          fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_PERMISSIONS',
            `${basename(path)} has an unowned hard-link alias`)
        }
        const alias = exactAtomicFile(boundary, temporary, bytes, [2n])
        if (!sameIdentity(durable, metadataIdentity(alias))) {
          fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_PERMISSIONS',
            `${basename(path)} hard-link alias is not the exact owned stage`)
        }
        maybeCrashFixture(crashStage,
          'OUTER_AFTER_LINK_BEFORE_ALIAS_UNLINK')
        verifiedUnlink(boundary, temporary, alias)
        maybeCrashFixture(crashStage,
          'OUTER_AFTER_ALIAS_UNLINK_BEFORE_DIRECTORY_FSYNC')
        fsyncDirectory(boundary)
        exactAtomicFile(boundary, path, bytes, [1n])
        return
      }
      if (staged != null) {
        const orphan = exactAtomicFile(boundary, temporary, bytes, [1n])
        if (sameIdentity(durable, metadataIdentity(orphan))) {
          fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_PERMISSIONS',
            `${basename(path)} has inconsistent stage link metadata`)
        }
        verifiedUnlink(boundary, temporary, orphan)
      }
      fsyncDirectory(boundary)
      exactAtomicFile(boundary, path, bytes, [1n])
      return
    }

    if (staged == null) {
      descriptor = openSync(temporary,
        constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY |
        constants.O_NOFOLLOW, 0o600)
      fchmodSync(descriptor, 0o600)
      const opened = fstatSync(descriptor, { bigint: true })
      const expectedUid = typeof process.getuid === 'function'
        ? BigInt(process.getuid())
        : opened.uid
      if (!opened.isFile() || opened.nlink !== 1n ||
          (opened.mode & 0o777n) !== 0o600n || opened.uid !== expectedUid) {
        fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_PERMISSIONS',
          'new staged pre-network custody record is not private')
      }
      if (opened.size !== 0n) {
        fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_DIRECTORY_REPLACED',
          'new staged pre-network custody record was not empty')
      }
      const openedIdentity = metadataIdentity(opened)
      let offset = 0
      while (offset < bytes.byteLength) {
        offset += writeSync(descriptor, bytes, offset,
          bytes.byteLength - offset, offset)
      }
      fsyncSync(descriptor)
      const written = fstatSync(descriptor, { bigint: true })
      assertPrivateFile(written, temporary, bytes.byteLength, [1n])
      if (!sameIdentity(written, openedIdentity) ||
          written.size !== BigInt(bytes.byteLength)) {
        fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_DIRECTORY_REPLACED',
          'staged pre-network custody record changed during write')
      }
      closeSync(descriptor)
      descriptor = null
    }
    const ready = exactAtomicFile(boundary, temporary, bytes, [1n])
    maybeCrashFixture(crashStage,
      'OUTER_AFTER_STAGE_FSYNC_BEFORE_LINK')
    validateRootBoundary(boundary)
    linkSync(temporary, path)
    const linkedAlias = exactAtomicFile(boundary, temporary, bytes, [2n])
    const linkedTarget = exactAtomicFile(boundary, path, bytes, [2n])
    if (!sameIdentity(linkedTarget, metadataIdentity(linkedAlias)) ||
        !sameIdentity(linkedAlias, metadataIdentity(ready))) {
      fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_DIRECTORY_REPLACED',
        'staged pre-network custody record changed during link handoff')
    }
    maybeCrashFixture(crashStage,
      'OUTER_AFTER_LINK_BEFORE_ALIAS_UNLINK')
    verifiedUnlink(boundary, temporary, linkedAlias)
    maybeCrashFixture(crashStage,
      'OUTER_AFTER_ALIAS_UNLINK_BEFORE_DIRECTORY_FSYNC')
    fsyncDirectory(boundary)
    exactAtomicFile(boundary, path, bytes, [1n])
  } finally {
    if (descriptor != null) closeSync(descriptor)
  }
}

function canonicalRecord (boundary, path) {
  const bytes = exactRead(boundary, path)
  let value
  try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) } catch (cause) {
    fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_CORRUPT',
      `${basename(path)} is not UTF-8 JSON`, cause)
  }
  if (!bytesEqual(bytes, prettyBytes(value))) {
    fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_CORRUPT',
      `${basename(path)} is not canonical pretty JSON`)
  }
  return value
}

function custodyInputEntries (entries) {
  return entries.map(entry => ({
    relayId: entry.relayId,
    allocationEpoch: entry.allocationEpoch,
    createPrivateSeed: entry.createPrivateSeed,
    renewPrivateSeed: entry.renewPrivateSeed,
    closePrivateSeed: entry.closePrivateSeed
  }))
}

function preparationCommitment (releaseSnapshot, requests) {
  return sha256(canonicalBytes({
    schema: 'peerit-seq29-pre-network-create-commitment-v1',
    version: 1,
    candidateCommit: CANDIDATE_COMMIT,
    releaseSequence: 29,
    releaseSnapshot,
    requests
  }))
}

function validatePublicRequests (requests, releaseSnapshot) {
  if (!Array.isArray(requests) || requests.length !== 2) {
    fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_CORRUPT',
      'pre-network identity requires exactly two public requests')
  }
  const publicKeys = []
  requests.forEach((request, index) => {
    exact(request, [
      'relayId', 'relayPublicKey', 'allocationEpoch', 'frameClassBits',
      'appendAuthMode', 'retentionClass', 'leaseClass', 'clientNonce',
      'requestCommitment', 'createPublicKey', 'renewPublicKey', 'closePublicKey'
    ], `pre-network public request ${index}`)
    const relay = releaseSnapshot.relays[index]
    if (request.relayId !== RELAY_IDS[index] || request.relayId !== relay.relayId ||
        request.relayPublicKey !== relay.relayPublicKey ||
        request.allocationEpoch !== releaseSnapshot.allocationEpoch ||
        request.frameClassBits !== 3 || request.appendAuthMode !== 0 ||
        request.retentionClass !== 3 || request.leaseClass !== 4) {
      fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_CORRUPT',
        `${request.relayId || index} public request escaped the fixed CREATE scope`)
    }
    for (const field of [
      'clientNonce', 'requestCommitment', 'createPublicKey',
      'renewPublicKey', 'closePublicKey'
    ]) hex32(request[field], `${request.relayId}.${field}`)
    publicKeys.push(
      request.createPublicKey, request.renewPublicKey, request.closePublicKey)
  })
  if (new Set(publicKeys).size !== 6 ||
      new Set(requests.map(row => row.clientNonce)).size !== 2 ||
      new Set(requests.map(row => row.requestCommitment)).size !== 2) {
    fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_CORRUPT',
      'pre-network public keys, nonces and commitments must be role-distinct')
  }
  return requests
}

function validateDurableIdentity (identity, expectedReleaseSnapshot = null) {
  exact(identity, [
    'schema', 'version', 'state', 'preparationHash', 'attemptId',
    'transactionId', 'releaseSnapshot', 'requests', 'networkRequests'
  ], 'pre-network identity record')
  const releaseSnapshot = validateReleaseSnapshot(identity.releaseSnapshot)
  validatePublicRequests(identity.requests, releaseSnapshot)
  const preparationHash = preparationCommitment(releaseSnapshot, identity.requests)
  const attemptId = `pre-network-${preparationHash}`
  const transactionId = peeritSeq29LocalManagementCustodyTransactionIdV1({
    planHash: preparationHash,
    attemptId
  })
  if (identity.schema !== 'peerit-seq29-live-inbox-create-pre-network-identity-v1' ||
      identity.version !== 1 || identity.state !== 'CAPTURED_NO_NETWORK' ||
      identity.networkRequests !== 0 || identity.preparationHash !== preparationHash ||
      identity.attemptId !== attemptId || identity.transactionId !== transactionId ||
      (expectedReleaseSnapshot != null && !bytesEqual(
        canonicalBytes(releaseSnapshot), canonicalBytes(expectedReleaseSnapshot)))) {
    fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_CORRUPT',
      'durable pre-network custody records do not bind the static release')
  }
  return Object.freeze({ releaseSnapshot, preparationHash, attemptId, transactionId })
}

function expectedPreparedRecord (identity, validated, custodyCommitment) {
  if (!PREPARED_COMMITMENT.test(custodyCommitment)) {
    fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_CORRUPT',
      'inner PREPARED receipt has an invalid commitment')
  }
  return {
    schema: 'peerit-seq29-live-inbox-create-pre-network-prepared-v1',
    version: 1,
    state: 'PREPARED_BEFORE_NETWORK',
    preparationHash: validated.preparationHash,
    attemptId: validated.attemptId,
    transactionId: validated.transactionId,
    custodyCommitment,
    identitySha256: sha256(prettyBytes(identity)),
    requestCommitments: identity.requests.map(row => row.requestCommitment),
    networkRequests: 0
  }
}

function validateDurableRecords (identity, prepared, expectedReleaseSnapshot = null) {
  const validated = validateDurableIdentity(identity, expectedReleaseSnapshot)
  exact(prepared, [
    'schema', 'version', 'state', 'preparationHash', 'attemptId',
    'transactionId', 'custodyCommitment', 'identitySha256',
    'requestCommitments', 'networkRequests'
  ], 'pre-network prepared record')
  const expected = expectedPreparedRecord(identity, validated,
    prepared.custodyCommitment)
  if (!bytesEqual(prettyBytes(prepared), prettyBytes(expected))) {
    fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_CORRUPT',
      'durable pre-network custody records do not bind the static release')
  }
  return validated
}

function configuredCustody (sealedDirectory, custodianKeyDirectory,
  crashStage = null) {
  const keys = createPeeritSeq29LocalCustodianKeyFileConfigurationV1({
    directory: resolve(custodianKeyDirectory)
  })
  const factory = crashStage ===
    'INNER_AFTER_PREPARED_FSYNC_BEFORE_GUARD_RELEASE'
    ? createPeeritSeq29LocalManagementCustodyCrashFixtureV1
    : createPeeritSeq29LocalManagementCustodyV1
  return factory({
    directory: sealedDirectory,
    custodianPublicKeys: keys.custodianPublicKeys,
    custodianPrivateKeyProvider: keys.custodianPrivateKeyProvider,
    ...(factory === createPeeritSeq29LocalManagementCustodyCrashFixtureV1
      ? { crashStage }
      : {})
  })
}

function preCustodyAuthority (state) {
  const authority = Object.freeze({
    schema: 'peerit-seq29-live-inbox-create-pre-network-custody-v1',
    version: 1,
    releaseSequence: 29,
    candidateCommit: CANDIDATE_COMMIT,
    preparationHash: state.identity.preparationHash,
    transactionId: state.prepared.transactionId,
    commitment: state.prepared.custodyCommitment,
    state: 'PREPARED_BEFORE_NETWORK',
    networkRequests: 0
  })
  PRE_NETWORK_CUSTODIES.set(authority, state)
  return authority
}

function validatePreparedReceipt (receipt, validated) {
  exact(receipt, [
    'accepted', 'durable', 'state', 'transactionId', 'commitment'
  ], 'inner PREPARED custody receipt')
  if (receipt.accepted !== true || receipt.durable !== true ||
      receipt.state !== 'SEALED_PENDING_CREATE' ||
      receipt.transactionId !== validated.transactionId ||
      !PREPARED_COMMITMENT.test(receipt.commitment)) {
    fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_NOT_DURABLE',
      'pre-network custody did not return an exact durable PREPARED receipt')
  }
  return receipt
}

function fixtureCrashStage (value) {
  if (process.env.PEERIT_SEQ29_OPERATOR_FIXTURE_TEST !== '1' ||
      !FIXTURE_CRASH_STAGES.has(value)) {
    fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_FIXTURE_FORBIDDEN',
      'pre-network process-death injection is fixture-only')
  }
  return value
}

async function sealPreNetworkCustody (input, crashStage) {
  const state = offlineState(input.preparation)
  if (state.consumed) {
    fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_CONSUMED',
      'offline CREATE preparation is one-shot')
  }
  state.consumed = true
  try {
    const boundary = assertPrivateRoot(input.directory)
    const root = boundary.root
    const sealedDirectory = join(root, 'sealed')
    const preparationHash = preparationCommitment(state.releaseSnapshot, state.requests)
    const attemptId = `pre-network-${preparationHash}`
    const transactionId = peeritSeq29LocalManagementCustodyTransactionIdV1({
      planHash: preparationHash,
      attemptId
    })
    const identity = {
      schema: 'peerit-seq29-live-inbox-create-pre-network-identity-v1',
      version: 1,
      state: 'CAPTURED_NO_NETWORK',
      preparationHash,
      attemptId,
      transactionId,
      releaseSnapshot: state.releaseSnapshot,
      requests: state.requests,
      networkRequests: 0
    }
    const validated = validateDurableIdentity(identity, state.releaseSnapshot)
    atomicCreate(boundary, join(root, IDENTITY_FILE), prettyBytes(identity))
    const custody = configuredCustody(sealedDirectory,
      input.custodianKeyDirectory, crashStage)
    const receipt = await custody.prepare({
      schema: 'peerit-limited-inbox-topic-private-custody-input-v1',
      disposition: 'SEALED_PENDING_CREATE',
      planHash: preparationHash,
      attemptId,
      entries: custodyInputEntries(state.entries)
    })
    validatePreparedReceipt(receipt, validated)
    maybeCrashFixture(crashStage, 'AFTER_DURABLE_PREPARE')
    const recovery = await recoverPeeritSeq29LocalManagementPreparedTransitionV1({
      custody,
      planHash: preparationHash,
      attemptId,
      commitment: receipt.commitment
    })
    try {
      maybeCrashFixture(crashStage, 'DURING_SELF_VERIFICATION')
      await validateRecoveredAgainstRequests(recovery, state.requests)
    } finally { recovery.destroy() }
    const prepared = expectedPreparedRecord(identity, validated, receipt.commitment)
    atomicCreate(boundary, join(root, PREPARED_FILE), prettyBytes(prepared), crashStage)
    return preCustodyAuthority({
      root,
      boundary,
      custody,
      identity: Object.freeze(identity),
      prepared: Object.freeze(prepared),
      bound: null
    })
  } finally {
    destroySeedEntries(state.entries)
    state.entries = []
  }
}

export async function sealPeeritSeq29LiveInboxCreatePreNetworkCustodyV1 (
  input = {}
) {
  exact(input, ['preparation', 'directory', 'custodianKeyDirectory'],
    'pre-network custody seal input')
  return sealPreNetworkCustody(input, null)
}

export async function sealPeeritSeq29LiveInboxCreatePreNetworkCustodyCrashFixtureV1 (
  input = {}
) {
  exact(input, [
    'preparation', 'directory', 'custodianKeyDirectory', 'crashStage'
  ], 'pre-network custody crash fixture seal input')
  const crashStage = fixtureCrashStage(input.crashStage)
  return sealPreNetworkCustody({
    preparation: input.preparation,
    directory: input.directory,
    custodianKeyDirectory: input.custodianKeyDirectory
  }, crashStage)
}

async function validateRecoveredAgainstRequests (recovery, requests) {
  if (recovery.entries.length !== 2) {
    fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_CORRUPT',
      'recovered pre-network custody does not contain two entries')
  }
  const accepted = await loadPeeritSeq29AcceptedHiveRelayOperatorV1()
  const seen = []
  for (let index = 0; index < recovery.entries.length; index++) {
    const entry = recovery.entries[index]
    const request = requests[index]
    if (entry.relayId !== request.relayId ||
        entry.allocationEpoch !== request.allocationEpoch) {
      fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_CORRUPT',
        `recovered entry ${index} differs from its public request identity`)
    }
    for (const [privateField, publicField] of [
      ['createPrivateSeed', 'createPublicKey'],
      ['renewPrivateSeed', 'renewPublicKey'],
      ['closePrivateSeed', 'closePublicKey']
    ]) {
      const derived = ed25519PublicFromSeed(entry[privateField])
      try {
        if (bytesToHex(derived) !== request[publicField]) {
          fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_CORRUPT',
            `${request.relayId} ${privateField} differs from its public commitment`)
        }
      } finally { derived.fill(0) }
      seen.push(entry[privateField])
    }
    let randomCalls = 0
    let capturedContext = null
    const sentinel = Object.freeze({})
    const seeds = [
      entry.createPrivateSeed, entry.renewPrivateSeed, entry.closePrivateSeed
    ]
    try {
      await accepted.inbox.createInboxReplica({
        runtime: Object.freeze({
          randomBytes (length) {
            if (length !== 32 || randomCalls >= 3) {
              fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_CORRUPT',
                `${request.relayId} recovered random-call shape changed`)
            }
            return seeds[randomCalls++].slice()
          }
        }),
        relayPublicKey: hexToBytes(request.relayPublicKey, 32, 'relayPublicKey'),
        allocationEpoch: request.allocationEpoch,
        frameClassBits: 3,
        appendAuthMode: 0,
        retentionClass: 3,
        leaseClass: 4,
        clientNonce: hexToBytes(request.clientNonce, 32, 'clientNonce'),
        async admissionProvider (context) {
          capturedContext = context
          throw sentinel
        }
      })
      fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_CORRUPT',
        `${request.relayId} recovered offline verification crossed admission`)
    } catch (cause) {
      if (cause !== sentinel) throw cause
    }
    if (randomCalls !== 3 || capturedContext == null ||
        bytesToHex(capturedContext.requestCommitment) !== request.requestCommitment ||
        bytesToHex(capturedContext.relayPublicKey) !== request.relayPublicKey ||
        capturedContext.familyId !== 3 || capturedContext.operationId !== 1 ||
        capturedContext.frameClassBits !== 3 ||
        capturedContext.retentionClass !== 3 || capturedContext.leaseClass !== 4) {
      fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_CORRUPT',
        `${request.relayId} recovered seeds do not reproduce the request commitment`)
    }
  }
  if (!pairwiseDistinctBytes(seen)) {
    fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_CORRUPT',
      'recovered management seeds are not pairwise distinct')
  }
}

async function resumePreNetworkCustody (input, crashStage) {
  const releaseSnapshot = validateReleaseSnapshot(input.releaseSnapshot)
  const boundary = assertPrivateRoot(input.directory)
  const root = boundary.root
  const identity = canonicalRecord(boundary, join(root, IDENTITY_FILE))
  const validated = validateDurableIdentity(identity, releaseSnapshot)
  const custody = configuredCustody(join(root, 'sealed'), input.custodianKeyDirectory)
  const receipt = validatePreparedReceipt(
    await inspectPeeritSeq29LocalManagementPreparedTransitionV1({
      custody,
      planHash: validated.preparationHash,
      attemptId: validated.attemptId
    }),
    validated
  )
  const recovery = await recoverPeeritSeq29LocalManagementPreparedTransitionV1({
    custody,
    planHash: validated.preparationHash,
    attemptId: validated.attemptId,
    commitment: receipt.commitment
  })
  try {
    maybeCrashFixture(crashStage, 'DURING_SELF_VERIFICATION')
    await validateRecoveredAgainstRequests(recovery, identity.requests)
  } finally {
    recovery.destroy()
  }
  const expectedPrepared = expectedPreparedRecord(identity, validated,
    receipt.commitment)
  atomicCreate(boundary, join(root, PREPARED_FILE),
    prettyBytes(expectedPrepared), crashStage)
  const prepared = canonicalRecord(boundary, join(root, PREPARED_FILE))
  validateDurableRecords(identity, prepared, releaseSnapshot)
  const rerecovery = await recoverPeeritSeq29LocalManagementPreparedTransitionV1({
    custody,
    planHash: validated.preparationHash,
    attemptId: validated.attemptId,
    commitment: prepared.custodyCommitment
  })
  try { await validateRecoveredAgainstRequests(rerecovery, identity.requests) } finally {
    rerecovery.destroy()
  }
  return preCustodyAuthority({
    root,
    boundary,
    custody,
    identity: Object.freeze(identity),
    prepared: Object.freeze(prepared),
    bound: null
  })
}

export async function resumePeeritSeq29LiveInboxCreatePreNetworkCustodyV1 (
  input = {}
) {
  exact(input, ['releaseSnapshot', 'directory', 'custodianKeyDirectory'],
    'pre-network custody resume input')
  return resumePreNetworkCustody(input, null)
}

export async function resumePeeritSeq29LiveInboxCreatePreNetworkCustodyCrashFixtureV1 (
  input = {}
) {
  exact(input, [
    'releaseSnapshot', 'directory', 'custodianKeyDirectory', 'crashStage'
  ], 'pre-network custody crash fixture resume input')
  const crashStage = fixtureCrashStage(input.crashStage)
  return resumePreNetworkCustody({
    releaseSnapshot: input.releaseSnapshot,
    directory: input.directory,
    custodianKeyDirectory: input.custodianKeyDirectory
  }, crashStage)
}

function preCustodyState (value) {
  const state = PRE_NETWORK_CUSTODIES.get(value)
  if (!state) {
    fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_AUTHORITY_REQUIRED',
      'a module-created durable pre-network custody authority is required')
  }
  return state
}

export function snapshotPeeritSeq29LiveInboxCreatePreNetworkCustodyV1 (
  authority
) {
  const state = preCustodyState(authority)
  return Object.freeze({
    schema: 'peerit-seq29-live-inbox-create-pre-network-custody-snapshot-v1',
    version: 1,
    state: 'PREPARED_BEFORE_NETWORK',
    preparationHash: state.identity.preparationHash,
    transactionId: state.prepared.transactionId,
    custodyCommitment: state.prepared.custodyCommitment,
    releaseSnapshot: structuredClone(state.identity.releaseSnapshot),
    requests: structuredClone(state.identity.requests),
    networkRequests: 0
  })
}

export async function verifyPeeritSeq29LiveInboxCreatePreNetworkCustodyV1 (
  authority
) {
  const state = preCustodyState(authority)
  const identity = canonicalRecord(state.boundary, join(state.root, IDENTITY_FILE))
  const prepared = canonicalRecord(state.boundary, join(state.root, PREPARED_FILE))
  validateDurableRecords(identity, prepared, state.identity.releaseSnapshot)
  if (!bytesEqual(prettyBytes(identity), prettyBytes(state.identity)) ||
      !bytesEqual(prettyBytes(prepared), prettyBytes(state.prepared))) {
    fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_STATE_CONFLICT',
      'durable pre-network custody changed after its authority was minted')
  }
  const recovery = await recoverPeeritSeq29LocalManagementPreparedTransitionV1({
    custody: state.custody,
    planHash: state.identity.preparationHash,
    attemptId: state.identity.attemptId,
    commitment: state.prepared.custodyCommitment
  })
  try {
    await validateRecoveredAgainstRequests(recovery, state.identity.requests)
  } finally { recovery.destroy() }
  return snapshotPeeritSeq29LiveInboxCreatePreNetworkCustodyV1(authority)
}

function validatePlanBinding (identity, plan, planHash) {
  if (!plan || typeof plan !== 'object' ||
      sha256(canonicalBytes(plan)) !== planHash || plan.releaseSequence !== 29 ||
      plan.hiverelayCommit !== CANDIDATE_COMMIT ||
      plan.referenceUnixMillis !== identity.releaseSnapshot.referenceUnixMillis ||
      !Array.isArray(plan.relays) || plan.relays.length !== 2) {
    fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_PLAN_MISMATCH',
      'exact live plan does not bind the pre-network static release identity')
  }
  plan.relays.forEach((relay, index) => {
    const frozen = identity.releaseSnapshot.relays[index]
    if (relay.relayId !== frozen.relayId ||
        relay.canonicalDescribeUrl !== frozen.canonicalDescribeUrl ||
        relay.relayPublicKey !== frozen.relayPublicKey ||
        relay.storeId !== frozen.storeId ||
        relay.allocationEpoch !== identity.releaseSnapshot.allocationEpoch ||
        BigInt(relay.descriptorFloor.sequence) < BigInt(frozen.minimumDescriptorSequence)) {
      fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_PLAN_MISMATCH',
        `${frozen.relayId} live plan escaped its authenticated static release floor`)
    }
  })
}

export async function bindPeeritSeq29PreNetworkCustodyToExactPlanV1 (input = {}) {
  exact(input, [
    'preNetworkCustody', 'plan', 'planHash', 'attemptId', 'normalCustody'
  ], 'pre-network exact-plan binding input')
  const state = preCustodyState(input.preNetworkCustody)
  hex32(input.planHash, 'planHash')
  if (typeof input.attemptId !== 'string' || input.attemptId.length < 1) {
    fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_INVALID', 'attemptId is required')
  }
  if (state.bound != null) {
    fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_CONSUMED',
      'pre-network custody may be bound to an exact plan only once per authority')
  }
  // Consume before recovery or normal custody. An ambiguous local failure is
  // terminal for this in-process authority; crash recovery must reopen the
  // already-durable pre-network records as a new branded authority.
  state.bound = Object.freeze({ state: 'BINDING_STARTED_NO_RETRY' })
  validatePlanBinding(state.identity, input.plan, input.planHash)
  const preRecovery = await recoverPeeritSeq29LocalManagementPreparedTransitionV1({
    custody: state.custody,
    planHash: state.identity.preparationHash,
    attemptId: state.identity.attemptId,
    commitment: state.prepared.custodyCommitment
  })
  let normalReceipt
  try {
    await validateRecoveredAgainstRequests(preRecovery, state.identity.requests)
    normalReceipt = await input.normalCustody.prepare({
      schema: 'peerit-limited-inbox-topic-private-custody-input-v1',
      disposition: 'SEALED_PENDING_CREATE',
      planHash: input.planHash,
      attemptId: input.attemptId,
      entries: custodyInputEntries(preRecovery.entries)
    })
  } finally { preRecovery.destroy() }
  if (normalReceipt?.accepted !== true || normalReceipt?.durable !== true ||
      normalReceipt?.state !== 'SEALED_PENDING_CREATE' ||
      !PREPARED_COMMITMENT.test(normalReceipt.commitment)) {
    fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_NOT_DURABLE',
      'normal exact-plan custody was not durable before admission')
  }
  const normalRecovery = await recoverPeeritSeq29LocalManagementPreparedTransitionV1({
    custody: input.normalCustody,
    planHash: input.planHash,
    attemptId: input.attemptId,
    commitment: normalReceipt.commitment
  })
  try { await validateRecoveredAgainstRequests(normalRecovery, state.identity.requests) } finally {
    normalRecovery.destroy()
  }
  const binding = {
    schema: 'peerit-seq29-live-inbox-create-pre-network-exact-plan-binding-v1',
    version: 1,
    state: 'EXACT_PLAN_CUSTODY_BOUND_BEFORE_ADMISSION',
    preparationHash: state.identity.preparationHash,
    preNetworkTransactionId: state.prepared.transactionId,
    preNetworkCustodyCommitment: state.prepared.custodyCommitment,
    planHash: input.planHash,
    attemptId: input.attemptId,
    normalTransactionId: normalReceipt.transactionId,
    normalCustodyCommitment: normalReceipt.commitment,
    requestCommitments: state.identity.requests.map(row => row.requestCommitment),
    admissionRequests: 0,
    createRequests: 0
  }
  atomicCreate(state.boundary, join(state.root, BINDING_FILE), prettyBytes(binding))
  const authority = Object.freeze({
    schema: 'peerit-seq29-live-inbox-create-exact-plan-custody-binding-v1',
    version: 1,
    releaseSequence: 29,
    planHash: input.planHash,
    attemptId: input.attemptId,
    transactionId: normalReceipt.transactionId,
    commitment: normalReceipt.commitment,
    state: 'EXACT_PLAN_CUSTODY_BOUND_BEFORE_ADMISSION'
  })
  EXACT_BINDINGS.set(authority, {
    preState: state,
    plan: input.plan,
    binding: Object.freeze(binding),
    normalCustody: input.normalCustody,
    consumedRelays: new Set()
  })
  state.bound = authority
  return authority
}

function exactBindingState (value) {
  const state = EXACT_BINDINGS.get(value)
  if (!state) {
    fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_AUTHORITY_REQUIRED',
      'a module-created exact-plan custody binding is required')
  }
  return state
}

function assertReplayContext (context, request) {
  exact(context, [
    'familyId', 'operationId', 'requestCommitment', 'relayPublicKey',
    'frameClassBits', 'retentionClass', 'leaseClass'
  ], `${request.relayId} replay admission context`)
  if (context.familyId !== 3 || context.operationId !== 1 ||
      context.frameClassBits !== 3 || context.retentionClass !== 3 ||
      context.leaseClass !== 4 ||
      bytesToHex(context.relayPublicKey) !== request.relayPublicKey ||
      bytesToHex(context.requestCommitment) !== request.requestCommitment) {
    fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_REPLAY_DRIFT',
      `${request.relayId} replay changed the pre-custodied CREATE commitment`)
  }
}

export async function replayPeeritSeq29CustodiedInboxCreateV1 (input = {}) {
  exact(input, ['binding', 'relayId', 'admissionProvider'],
    'custodied CREATE replay input')
  const state = exactBindingState(input.binding)
  if (!RELAY_IDS.includes(input.relayId) || typeof input.admissionProvider !== 'function') {
    fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_INVALID',
      'replay requires a fixed relay and in-process admission provider')
  }
  if (state.consumedRelays.has(input.relayId)) {
    fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_CONSUMED',
      `${input.relayId} custodied CREATE replay is one-shot`)
  }
  // Consume before recovery or admission. Any ambiguous failure is terminal.
  state.consumedRelays.add(input.relayId)
  const durableBinding = canonicalRecord(
    state.preState.boundary, join(state.preState.root, BINDING_FILE))
  if (!bytesEqual(prettyBytes(durableBinding), prettyBytes(state.binding))) {
    fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_STATE_CONFLICT',
      'durable exact-plan custody binding changed before replay')
  }
  const index = RELAY_IDS.indexOf(input.relayId)
  const request = state.preState.identity.requests[index]
  const relay = state.plan.relays[index]
  const recovery = await recoverPeeritSeq29LocalManagementPreparedTransitionV1({
    custody: state.normalCustody,
    planHash: state.binding.planHash,
    attemptId: state.binding.attemptId,
    commitment: state.binding.normalCustodyCommitment
  })
  let admissionCalls = 0
  let randomCalls = 0
  try {
    await validateRecoveredAgainstRequests(recovery, state.preState.identity.requests)
    const entry = recovery.entries[index]
    const seeds = [
      entry.createPrivateSeed, entry.renewPrivateSeed, entry.closePrivateSeed
    ]
    const runtime = Object.freeze({
      randomBytes (length) {
        if (length !== 32 || randomCalls >= 3) {
          fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_REPLAY_DRIFT',
            `${input.relayId} replay random-call shape changed`)
        }
        return seeds[randomCalls++].slice()
      }
    })
    const accepted = await loadPeeritSeq29AcceptedHiveRelayOperatorV1()
    const created = await accepted.inbox.createInboxReplica({
      runtime,
      relayPublicKey: hexToBytes(relay.relayPublicKey, 32, 'relayPublicKey'),
      allocationEpoch: relay.allocationEpoch,
      frameClassBits: 3,
      appendAuthMode: 0,
      retentionClass: 3,
      leaseClass: 4,
      clientNonce: hexToBytes(request.clientNonce, 32, 'clientNonce'),
      async admissionProvider (context) {
        admissionCalls++
        if (admissionCalls !== 1 || randomCalls !== 3) {
          fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_REPLAY_DRIFT',
            `${input.relayId} admission ordering changed`)
        }
        assertReplayContext(context, request)
        return input.admissionProvider(context)
      }
    })
    if (randomCalls !== 3 || admissionCalls !== 1 ||
        bytesToHex(created.requestCommitment) !== request.requestCommitment ||
        bytesToHex(created.request.createPublicKey) !== request.createPublicKey ||
        bytesToHex(created.request.renewPublicKey) !== request.renewPublicKey ||
        bytesToHex(created.request.closePublicKey) !== request.closePublicKey ||
        bytesToHex(created.request.clientNonce) !== request.clientNonce) {
      accepted.inbox.destroyInboxWriteCapability(created.writeCap)
      fail('PEERIT_SEQ29_PRE_NETWORK_CUSTODY_REPLAY_DRIFT',
        `${input.relayId} finalized CREATE differs from pre-network custody`)
    }
    return created
  } finally { recovery.destroy() }
}

export function destroyPeeritSeq29OfflineInboxCreatePreparationV1 (authority) {
  const state = OFFLINE_PREPARATIONS.get(authority)
  if (!state) return
  destroySeedEntries(state.entries)
  state.entries = []
  state.consumed = true
  OFFLINE_PREPARATIONS.delete(authority)
}
