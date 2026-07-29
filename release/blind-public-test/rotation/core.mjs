import { createHash, randomBytes as nodeRandomBytes } from 'node:crypto'
import { constants as FS_CONSTANTS } from 'node:fs'
import fs from 'node:fs/promises'
import path from 'node:path'
import b4a from 'b4a'
import sodium from 'sodium-universal'
import {
  RESULT_SIGNATURE_DOMAIN_ID,
  admissionParametersHash,
  admissionParametersV1,
  blindServiceDescriptorV1,
  decodeCanonical,
  encodeCanonical,
  resultSignaturePayload,
  serviceDescriptorHash
} from '@hiverelay/blind-protocol'
import {
  CELL_SIZE_CLASS,
  FAMILY,
  OPERATION
} from '@hiverelay/blind-protocol/wire-runtime-authority'
import {
  AdmissionCoordinator,
  DescriptorState,
  daemonOperationProfile,
  deriveAdmissionCost
} from '@hiverelay/blind-daemon'

export const ROTATION_POLICY_SCHEMA = 'hiverelay-blind-public-test-admission-policy-v2'
export const ROTATION_PLAN_SCHEMA = 'hiverelay-blind-public-test-rotation-plan-v1'
export const ROTATION_RESULT_SCHEMA = 'hiverelay-blind-public-test-rotation-v1'
export const SIX_HOURS_MILLIS = 6 * 60 * 60 * 1000

const MAX_U32 = 0xffffffff
const SIGNATURE_BYTES = sodium.crypto_sign_BYTES
const NONCE_BYTES = 32
const SECRET_KEY_BYTES = sodium.crypto_sign_SECRETKEYBYTES
const PUBLIC_KEY_BYTES = sodium.crypto_sign_PUBLICKEYBYTES

function fail (code, message) {
  const error = new Error(message)
  error.code = code
  throw error
}

export function sha256Hex (bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

export function byteHex (bytes) {
  return b4a.toString(bytes, 'hex')
}

function exactKeys (value, keys, field) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    fail('ROTATION_POLICY_INVALID', `${field} must be an object`)
  }
  const actual = Object.keys(value).sort()
  const expected = [...keys].sort()
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail('ROTATION_POLICY_INVALID', `${field} contains missing or unknown fields`)
  }
}

function positiveInteger (value, field, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    fail('ROTATION_POLICY_INVALID', `${field} must be a positive integer`)
  }
  return value
}

function digest (value, field) {
  if (typeof value !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(value)) {
    fail('ROTATION_POLICY_INVALID', `${field} must be a canonical sha256 digest`)
  }
  return value
}

function lowerSha256 (value, field) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) {
    fail('ROTATION_POLICY_INVALID', `${field} must be a canonical lowercase SHA-256 value`)
  }
  return value
}

function classPolicy (value, field) {
  exactKeys(value, ['resourceClass', 'leaseClass', 'cellBytes', 'costUnits'], field)
  const result = Object.freeze({
    resourceClass: positiveInteger(value.resourceClass, `${field}.resourceClass`, 255),
    leaseClass: positiveInteger(value.leaseClass, `${field}.leaseClass`, 255),
    cellBytes: positiveInteger(value.cellBytes, `${field}.cellBytes`),
    costUnits: BigInt(value.costUnits)
  })
  if (result.costUnits < 1n || result.costUnits > ((1n << 64n) - 1n)) {
    fail('ROTATION_POLICY_INVALID', `${field}.costUnits is outside u64`)
  }
  return result
}

export function validateRotationPolicy (value) {
  exactKeys(value, [
    'schema', 'version', 'status', 'claimBoundary', 'allowedRelayIds',
    'epochPolicy', 'admissionPolicy', 'releaseBinding'
  ], 'policy')
  if (value.schema !== ROTATION_POLICY_SCHEMA || value.version !== 2 ||
      value.status !== 'CANDIDATE_PENDING_INDEPENDENT_REVIEW_AND_LIVE_REDEMPTION' ||
      value.claimBoundary !== 'LIMITED_PUBLIC_TEST_V1_NOT_GA') {
    fail('ROTATION_POLICY_INVALID', 'policy identity or candidate boundary is not exact')
  }
  if (!Array.isArray(value.allowedRelayIds) || value.allowedRelayIds.length !== 2 ||
      value.allowedRelayIds[0] !== 'syd-1' || value.allowedRelayIds[1] !== 'dallas-1') {
    fail('ROTATION_POLICY_INVALID', 'policy must name exactly syd-1 and dallas-1')
  }

  exactKeys(value.epochPolicy,
    ['descriptorWindowEpochs', 'admissionTailEpochs', 'allowEmergencyGap'], 'policy.epochPolicy')
  const descriptorWindowEpochs = positiveInteger(
    value.epochPolicy.descriptorWindowEpochs, 'descriptorWindowEpochs', 4)
  const admissionTailEpochs = positiveInteger(
    value.epochPolicy.admissionTailEpochs, 'admissionTailEpochs', 4)
  if (descriptorWindowEpochs !== 4 || admissionTailEpochs !== 4 ||
      value.epochPolicy.allowEmergencyGap !== false) {
    fail('ROTATION_POLICY_INVALID', 'epoch policy must be the overlap-safe 4+4 policy without gaps')
  }

  exactKeys(value.admissionPolicy, ['exactProfileCount', 'rowMutation', 'cellPut'],
    'policy.admissionPolicy')
  if (value.admissionPolicy.exactProfileCount !== 1 ||
      value.admissionPolicy.rowMutation !== 'PRESERVE_ALL_EXISTING_ADD_REQUIRED_IF_ABSENT') {
    fail('ROTATION_POLICY_INVALID', 'admission profile or row mutation policy is not exact')
  }
  exactKeys(value.admissionPolicy.cellPut, [
    'familyId', 'operationId', 'class1', 'class2', 'requiredByteRatio', 'requiredCostRatio'
  ], 'policy.admissionPolicy.cellPut')
  const cellPut = value.admissionPolicy.cellPut
  if (cellPut.familyId !== FAMILY.CELL || cellPut.operationId !== OPERATION.CELL.PUT ||
      cellPut.requiredByteRatio !== 4 || cellPut.requiredCostRatio !== 4) {
    fail('ROTATION_POLICY_INVALID', 'CELL.PUT policy does not bind the exact operation and 4x ratios')
  }
  const class1 = classPolicy(cellPut.class1, 'policy.admissionPolicy.cellPut.class1')
  const class2 = classPolicy(cellPut.class2, 'policy.admissionPolicy.cellPut.class2')
  if (class1.resourceClass !== 1 || class1.leaseClass !== 1 || class1.cellBytes !== 4096 ||
      class1.costUnits !== 10n || class2.resourceClass !== 2 || class2.leaseClass !== 1 ||
      class2.cellBytes !== 16384 || class2.costUnits !== 40n ||
      class2.cellBytes !== class1.cellBytes * 4 || class2.costUnits !== class1.costUnits * 4n ||
      CELL_SIZE_CLASS[1] !== class1.cellBytes || CELL_SIZE_CLASS[2] !== class2.cellBytes) {
    fail('ROTATION_POLICY_INVALID', 'CELL.PUT class bytes or costs are not the exact 4KiB/10 and 16KiB/40 policy')
  }
  const operationProfile = daemonOperationProfile(FAMILY.CELL, OPERATION.CELL.PUT)
  for (const selected of [class1, class2]) {
    const derived = deriveAdmissionCost(operationProfile, {
      sizeClass: selected.resourceClass,
      leaseClass: selected.leaseClass
    })
    if (derived.resourceClass !== selected.resourceClass || derived.leaseClass !== selected.leaseClass) {
      fail('ROTATION_POLICY_INVALID', 'CELL.PUT policy does not match the runtime cost-class derivation')
    }
  }

  exactKeys(value.releaseBinding, [
    'bundleId', 'composeFile', 'composeSha256', 'composeProject',
    'daemonImageDigest', 'edgeImageDigest'
  ], 'policy.releaseBinding')
  if (value.releaseBinding.bundleId !== '1.0.0-rc.1.public-test.1' ||
      value.releaseBinding.composeFile !== 'docker-compose.blind-public-test.yml' ||
      value.releaseBinding.composeProject !== 'hiverelay-blind-public-test') {
    fail('ROTATION_POLICY_INVALID', 'release binding does not select the immutable public-test bundle')
  }
  lowerSha256(value.releaseBinding.composeSha256, 'policy.releaseBinding.composeSha256')
  digest(value.releaseBinding.daemonImageDigest, 'policy.releaseBinding.daemonImageDigest')
  digest(value.releaseBinding.edgeImageDigest, 'policy.releaseBinding.edgeImageDigest')

  return Object.freeze({
    raw: value,
    descriptorWindowEpochs,
    admissionTailEpochs,
    exactProfileCount: 1,
    class1,
    class2,
    releaseBinding: Object.freeze({ ...value.releaseBinding }),
    allowedRelayIds: Object.freeze([...value.allowedRelayIds])
  })
}

export async function loadRotationPolicy (file, expectedSha256) {
  if (!path.isAbsolute(file)) fail('ROTATION_POLICY_INVALID', 'policy file must be an absolute path')
  const bytes = await fs.readFile(file)
  const actualSha256 = sha256Hex(bytes)
  if (expectedSha256 != null && actualSha256 !== lowerSha256(expectedSha256, 'expected policy SHA-256')) {
    fail('ROTATION_POLICY_DIGEST_MISMATCH', 'policy bytes do not match the expected SHA-256')
  }
  let value
  try {
    value = JSON.parse(bytes)
  } catch {
    fail('ROTATION_POLICY_INVALID', 'policy is not valid JSON')
  }
  return Object.freeze({ policy: validateRotationPolicy(value), bytes, sha256: actualSha256 })
}

function canonicalValue (codec, bytes, field) {
  let value
  try {
    value = decodeCanonical(codec, bytes, { copyBytes: true })
    if (!b4a.equals(encodeCanonical(codec, value), bytes)) throw new Error('non-canonical')
  } catch (error) {
    fail('ROTATION_INPUT_INVALID', `${field} is not exact canonical bytes: ${error.message}`)
  }
  return value
}

function verifyDetached ({ publicKey, signature, payload }) {
  try {
    return sodium.crypto_sign_verify_detached(signature, payload, publicKey)
  } catch {
    return false
  }
}

function compareCostRows (left, right) {
  for (const field of ['familyId', 'operationId', 'resourceClass', 'leaseClass']) {
    const l = left[field] == null ? 0 : left[field]
    const r = right[field] == null ? 0 : right[field]
    if (l !== r) return l - r
  }
  return 0
}

function rowKey (row) {
  return [row.familyId, row.operationId, row.resourceClass, row.leaseClass == null ? 0 : row.leaseClass].join(':')
}

function normalizedRow (row) {
  return {
    familyId: row.familyId,
    operationId: row.operationId,
    resourceClass: row.resourceClass,
    leaseClass: row.leaseClass == null ? 0 : row.leaseClass,
    costUnits: BigInt(row.costUnits)
  }
}

export function applyClass2CandidatePolicy (resourceCosts, validatedPolicy) {
  if (!Array.isArray(resourceCosts)) fail('ROTATION_INPUT_INVALID', 'resourceCosts must be an array')
  const policy = validatedPolicy.raw == null ? validatedPolicy : validateRotationPolicy(validatedPolicy)
  const before = resourceCosts.map(normalizedRow)
  const byKey = new Map(before.map(row => [rowKey(row), row]))
  if (byKey.size !== before.length) fail('ROTATION_INPUT_INVALID', 'resourceCosts contains duplicate tuples')

  const required = [policy.class1, policy.class2].map(selected => ({
    familyId: FAMILY.CELL,
    operationId: OPERATION.CELL.PUT,
    resourceClass: selected.resourceClass,
    leaseClass: selected.leaseClass,
    costUnits: selected.costUnits
  }))
  const class1 = byKey.get(rowKey(required[0]))
  if (!class1 || class1.costUnits !== required[0].costUnits) {
    fail('ROTATION_POLICY_MISMATCH', 'existing CELL.PUT class-1 row must be exactly resourceClass=1 leaseClass=1 costUnits=10')
  }
  const class2 = byKey.get(rowKey(required[1]))
  if (class2 && class2.costUnits !== required[1].costUnits) {
    fail('ROTATION_POLICY_MISMATCH', 'existing CELL.PUT class-2 row conflicts with candidate costUnits=40')
  }
  const added = class2 == null
  const after = [...before, ...(added ? [required[1]] : [])].sort(compareCostRows)
  for (const original of before) {
    const retained = after.find(row => rowKey(row) === rowKey(original))
    if (!retained || retained.costUnits !== original.costUnits) {
      fail('ROTATION_POLICY_MISMATCH', 'policy application changed an existing resource-cost row')
    }
  }
  return Object.freeze({ rows: after, class2Added: added })
}

function exactSequenceChain (chainBytes) {
  if (!Array.isArray(chainBytes) || chainBytes.length < 1 || chainBytes.length > 4096) {
    fail('ROTATION_INPUT_INVALID', 'descriptor chain must contain 1..4096 links')
  }
  const values = chainBytes.map((bytes, index) => {
    const value = canonicalValue(blindServiceDescriptorV1, bytes, `descriptor link ${index}`)
    if (value.descriptorSequence !== BigInt(index)) {
      fail('ROTATION_INPUT_INVALID', `descriptor link ${index} is not sequence ${index}`)
    }
    return value
  })
  return values
}

async function restoredState (chainBytes, nowEpoch) {
  const state = new DescriptorState({ verifySignature: verifyDetached, epochNow: () => nowEpoch })
  await state.restore({ descriptorChainBytes: chainBytes })
  return { state, snapshot: state.requireCurrent() }
}

async function admissionReady (state, snapshot, admissionBytes) {
  const coordinator = new AdmissionCoordinator({
    descriptorState: state,
    verifySignature: verifyDetached,
    resolveAdapter: () => null
  })
  await coordinator.installParameters(admissionBytes)
  if (!coordinator.descriptorParametersAvailable(snapshot) ||
      !coordinator.descriptorProfilesReady(snapshot)) {
    fail('ROTATION_INPUT_INVALID', 'admission parameters are not exactly available and redeemable for the current descriptor')
  }
  return coordinator
}

function expectedProfileHashSet (descriptor) {
  return descriptor.admissionProfiles.map(profile => byteHex(profile.parameterHash)).sort()
}

export async function inspectRotationInputs ({
  descriptorChainBytes,
  admissionParameterBytes,
  nowEpoch,
  relayId,
  policy
}) {
  const validatedPolicy = policy.raw == null ? policy : validateRotationPolicy(policy)
  if (!validatedPolicy.allowedRelayIds.includes(relayId)) {
    fail('ROTATION_SCOPE_INVALID', 'relayId is outside the exact two-node policy')
  }
  if (!Number.isSafeInteger(nowEpoch) || nowEpoch < 0 || nowEpoch > MAX_U32) {
    fail('ROTATION_INPUT_INVALID', 'nowEpoch must be a u32 integer')
  }
  const values = exactSequenceChain(descriptorChainBytes)
  if (!Array.isArray(admissionParameterBytes) ||
      admissionParameterBytes.length !== validatedPolicy.exactProfileCount) {
    fail('ROTATION_INPUT_INVALID', 'limited public-test rotation requires exactly one admission parameter file')
  }
  const { state, snapshot } = await restoredState(descriptorChainBytes, nowEpoch)
  const head = values[values.length - 1]
  if (snapshot.descriptorSequence !== head.descriptorSequence ||
      !b4a.equals(snapshot.hash, serviceDescriptorHash(descriptorChainBytes.at(-1)))) {
    fail('ROTATION_INPUT_INVALID', 'restored descriptor state does not select the exact chain head')
  }
  if (head.admissionProfiles.length !== validatedPolicy.exactProfileCount) {
    fail('ROTATION_INPUT_INVALID', 'descriptor does not carry the exact one-profile release set')
  }
  if ((head.cellSizeClassBits & (1 << validatedPolicy.class2.resourceClass)) === 0) {
    fail('ROTATION_POLICY_MISMATCH', 'descriptor does not advertise CELL size class 2')
  }
  const admission = canonicalValue(admissionParametersV1, admissionParameterBytes[0], 'admission parameters')
  const parameterHash = admissionParametersHash(admissionParameterBytes[0])
  if (!b4a.equals(admission.relayPublicKey, head.relayPublicKey) ||
      expectedProfileHashSet(head).length !== 1 ||
      expectedProfileHashSet(head)[0] !== byteHex(parameterHash)) {
    fail('ROTATION_INPUT_INVALID', 'admission parameters do not exactly bind the head profile and relay key')
  }
  await admissionReady(state, snapshot, admissionParameterBytes[0])
  const rowPolicy = applyClass2CandidatePolicy(admission.resourceCosts, validatedPolicy)
  const issuedEpoch = Math.min(nowEpoch, head.expiresEpoch - 1)
  const expiresEpoch = issuedEpoch + validatedPolicy.descriptorWindowEpochs
  const admissionExpiresEpoch = expiresEpoch + validatedPolicy.admissionTailEpochs
  if (issuedEpoch <= head.issuedEpoch || issuedEpoch > nowEpoch || issuedEpoch >= head.expiresEpoch ||
      expiresEpoch <= nowEpoch || admissionExpiresEpoch > MAX_U32) {
    fail('ROTATION_WINDOW_UNAVAILABLE',
      'no fresh strictly-increasing overlap-safe successor can be issued from the current head')
  }
  return Object.freeze({
    state,
    snapshot,
    head,
    admission,
    parameterHash,
    rowPolicy,
    nextSequence: head.descriptorSequence + 1n,
    issuedEpoch,
    expiresEpoch,
    admissionExpiresEpoch
  })
}

function signCanonical (codec, value, domainId, secretKey) {
  value.signature = b4a.alloc(SIGNATURE_BYTES)
  const placeholder = encodeCanonical(codec, value)
  const unsigned = placeholder.subarray(0, placeholder.byteLength - SIGNATURE_BYTES)
  sodium.crypto_sign_detached(value.signature, resultSignaturePayload(domainId, unsigned), secretKey)
  return encodeCanonical(codec, value)
}

function nonzeroNonce (value, field) {
  if (!value || value.byteLength !== NONCE_BYTES || value.every(byte => byte === 0)) {
    fail('ROTATION_INPUT_INVALID', `${field} must be a nonzero 32-byte value`)
  }
  return b4a.from(value)
}

function assertSecretMatches (secretKey, relayPublicKey) {
  if (!secretKey || secretKey.byteLength !== SECRET_KEY_BYTES) {
    fail('ROTATION_SECRET_INVALID', 'relay secret key has an unexpected length')
  }
  const derived = b4a.alloc(PUBLIC_KEY_BYTES)
  sodium.crypto_sign_ed25519_sk_to_pk(derived, secretKey)
  const matches = b4a.equals(derived, relayPublicKey)
  derived.fill(0)
  if (!matches) fail('ROTATION_SECRET_INVALID', 'relay secret key does not match the current descriptor key')
}

function normalizedDescriptorBytes (successor, predecessor) {
  const normalized = decodeCanonical(blindServiceDescriptorV1,
    encodeCanonical(blindServiceDescriptorV1, successor), { copyBytes: true })
  for (const field of [
    'descriptorSequence', 'previousDescriptorHash', 'issuedEpoch', 'expiresEpoch',
    'admissionProfiles', 'descriptorNonce', 'signature'
  ]) normalized[field] = predecessor[field]
  return encodeCanonical(blindServiceDescriptorV1, normalized)
}

function normalizedAdmissionBytes (successor, predecessor) {
  const normalized = decodeCanonical(admissionParametersV1,
    encodeCanonical(admissionParametersV1, successor), { copyBytes: true })
  for (const field of [
    'resourceCosts', 'validFromEpoch', 'expiresEpoch', 'nonce', 'signature'
  ]) normalized[field] = predecessor[field]
  return encodeCanonical(admissionParametersV1, normalized)
}

export async function buildRotationCandidate ({
  descriptorChainBytes,
  admissionParameterBytes,
  nowEpoch,
  relayId,
  policy,
  secretKey,
  descriptorNonce,
  admissionNonce
}) {
  const inspected = await inspectRotationInputs({
    descriptorChainBytes, admissionParameterBytes, nowEpoch, relayId, policy
  })
  assertSecretMatches(secretKey, inspected.head.relayPublicKey)

  const nextAdmission = decodeCanonical(admissionParametersV1,
    admissionParameterBytes[0], { copyBytes: true })
  nextAdmission.resourceCosts = inspected.rowPolicy.rows.map(row => ({ ...row }))
  nextAdmission.validFromEpoch = inspected.issuedEpoch
  nextAdmission.expiresEpoch = inspected.admissionExpiresEpoch
  nextAdmission.nonce = nonzeroNonce(admissionNonce, 'admissionNonce')
  const nextAdmissionBytes = signCanonical(admissionParametersV1, nextAdmission,
    RESULT_SIGNATURE_DOMAIN_ID.ADMISSION_PARAMETERS, secretKey)
  const nextAdmissionValue = canonicalValue(admissionParametersV1, nextAdmissionBytes,
    'new admission parameters')
  if (!b4a.equals(normalizedAdmissionBytes(nextAdmissionValue, inspected.admission),
    admissionParameterBytes[0])) {
    fail('ROTATION_POLICY_MISMATCH', 'new admission changed fields outside the exact policy delta')
  }

  const nextAdmissionHash = admissionParametersHash(nextAdmissionBytes)
  const nextDescriptor = decodeCanonical(blindServiceDescriptorV1,
    descriptorChainBytes.at(-1), { copyBytes: true })
  nextDescriptor.descriptorSequence = inspected.nextSequence
  nextDescriptor.previousDescriptorHash = b4a.from(serviceDescriptorHash(descriptorChainBytes.at(-1)))
  nextDescriptor.issuedEpoch = inspected.issuedEpoch
  nextDescriptor.expiresEpoch = inspected.expiresEpoch
  nextDescriptor.admissionProfiles = nextDescriptor.admissionProfiles.map((profile, index) =>
    index === 0 ? { ...profile, parameterHash: b4a.from(nextAdmissionHash) } : { ...profile })
  nextDescriptor.descriptorNonce = nonzeroNonce(descriptorNonce, 'descriptorNonce')
  const nextDescriptorBytes = signCanonical(blindServiceDescriptorV1, nextDescriptor,
    RESULT_SIGNATURE_DOMAIN_ID.DESCRIPTOR, secretKey)
  const nextDescriptorValue = canonicalValue(blindServiceDescriptorV1, nextDescriptorBytes,
    'new descriptor')
  if (!b4a.equals(normalizedDescriptorBytes(nextDescriptorValue, inspected.head),
    descriptorChainBytes.at(-1))) {
    fail('ROTATION_POLICY_MISMATCH', 'new descriptor changed fields outside the exact refresh delta')
  }
  for (let index = 0; index < inspected.head.admissionProfiles.length; index++) {
    const previous = inspected.head.admissionProfiles[index]
    const next = nextDescriptorValue.admissionProfiles[index]
    if (next.profileId !== previous.profileId || next.schemeId !== previous.schemeId ||
        next.conformanceClass !== previous.conformanceClass || next.roleBits !== previous.roleBits ||
        !b4a.equals(next.parameterUrl || b4a.alloc(0), previous.parameterUrl || b4a.alloc(0)) ||
        (index === 0 && !b4a.equals(next.parameterHash, nextAdmissionHash))) {
      fail('ROTATION_POLICY_MISMATCH', 'descriptor admission profile changed outside its parameter hash')
    }
  }

  const completeChain = [...descriptorChainBytes, nextDescriptorBytes]
  const { state, snapshot } = await restoredState(completeChain, nowEpoch)
  await admissionReady(state, snapshot, nextAdmissionBytes)
  if (snapshot.descriptorSequence !== inspected.nextSequence ||
      !b4a.equals(snapshot.hash, serviceDescriptorHash(nextDescriptorBytes))) {
    fail('ROTATION_INPUT_INVALID', 'successor chain did not restore to its exact new head')
  }
  return Object.freeze({
    descriptorBytes: nextDescriptorBytes,
    descriptor: nextDescriptorValue,
    descriptorHash: serviceDescriptorHash(nextDescriptorBytes),
    admissionBytes: nextAdmissionBytes,
    admission: nextAdmissionValue,
    admissionHash: nextAdmissionHash,
    predecessorHash: serviceDescriptorHash(descriptorChainBytes.at(-1)),
    class2Added: inspected.rowPolicy.class2Added
  })
}

function canonicalJson (value) {
  return b4a.from(JSON.stringify(value, null, 2) + '\n')
}

async function syncDirectory (directory) {
  const handle = await fs.open(directory, FS_CONSTANTS.O_RDONLY)
  try {
    await handle.sync()
  } finally {
    await handle.close()
  }
}

async function writeExclusiveOrVerify (file, bytes, mode) {
  let handle
  try {
    handle = await fs.open(file, FS_CONSTANTS.O_CREAT | FS_CONSTANTS.O_EXCL | FS_CONSTANTS.O_WRONLY, mode)
    await handle.writeFile(bytes)
    await handle.sync()
    await handle.chmod(mode)
    return 'created'
  } catch (error) {
    if (!error || error.code !== 'EEXIST') throw error
    const existing = await fs.readFile(file)
    if (!b4a.equals(existing, bytes)) {
      fail('ROTATION_BUNDLE_CONFLICT', `${path.basename(file)} conflicts with the deterministic rotation plan`)
    }
    return 'reused'
  } finally {
    if (handle) await handle.close()
  }
}

async function readProtectedSecret (file) {
  if (!path.isAbsolute(file) || path.normalize(file) !== file || file.includes('\0')) {
    fail('ROTATION_SECRET_INVALID', 'relay secret file must be one canonical absolute path')
  }
  let handle
  try {
    handle = await fs.open(file, FS_CONSTANTS.O_RDONLY | FS_CONSTANTS.O_NOFOLLOW)
    const [opened, linked] = await Promise.all([handle.stat(), fs.lstat(file)])
    const currentUid = typeof process.getuid === 'function' ? process.getuid() : null
    const permissions = linked.mode & 0o777
    if (!opened.isFile() || linked.isSymbolicLink() || opened.dev !== linked.dev || opened.ino !== linked.ino ||
        opened.size !== SECRET_KEY_BYTES || linked.nlink !== 1 ||
        (permissions !== 0o400 && permissions !== 0o600) || currentUid == null || linked.uid !== currentUid ||
        await fs.realpath(file) !== file) {
      fail('ROTATION_SECRET_INVALID', 'relay secret file is not a stable daemon-owned 0400/0600 regular file')
    }
    const bytes = await handle.readFile()
    const [after, linkedAfter] = await Promise.all([handle.stat(), fs.lstat(file)])
    if (opened.dev !== after.dev || opened.ino !== after.ino || opened.size !== after.size ||
        opened.mtimeMs !== after.mtimeMs || after.dev !== linkedAfter.dev || after.ino !== linkedAfter.ino ||
        bytes.byteLength !== SECRET_KEY_BYTES) {
      bytes.fill(0)
      fail('ROTATION_SECRET_INVALID', 'relay secret file changed while it was read')
    }
    return bytes
  } finally {
    if (handle) await handle.close().catch(() => {})
  }
}

function parsePlan (bytes) {
  let value
  try { value = JSON.parse(bytes) } catch { fail('ROTATION_BUNDLE_INVALID', 'rotation plan is not JSON') }
  exactKeys(value, [
    'schema', 'relayId', 'policySha256', 'predecessorSequence', 'predecessorHash',
    'successorSequence', 'issuedEpoch', 'expiresEpoch', 'admissionExpiresEpoch',
    'descriptorNonce', 'admissionNonce'
  ], 'rotation plan')
  if (value.schema !== ROTATION_PLAN_SCHEMA || !/^[0-9a-f]{64}$/.test(value.predecessorHash) ||
      !/^[0-9a-f]{64}$/.test(value.descriptorNonce) || !/^[0-9a-f]{64}$/.test(value.admissionNonce)) {
    fail('ROTATION_BUNDLE_INVALID', 'rotation plan identity or byte fields are invalid')
  }
  return value
}

function expectedPlan ({ inspected, relayId, policySha256, descriptorNonce, admissionNonce }) {
  return {
    schema: ROTATION_PLAN_SCHEMA,
    relayId,
    policySha256,
    predecessorSequence: inspected.head.descriptorSequence.toString(),
    predecessorHash: byteHex(serviceDescriptorHash(inspected.snapshot.canonicalBytes)),
    successorSequence: inspected.nextSequence.toString(),
    issuedEpoch: inspected.issuedEpoch,
    expiresEpoch: inspected.expiresEpoch,
    admissionExpiresEpoch: inspected.admissionExpiresEpoch,
    descriptorNonce: byteHex(descriptorNonce),
    admissionNonce: byteHex(admissionNonce)
  }
}

function sameJson (left, right) {
  return JSON.stringify(left) === JSON.stringify(right)
}

export async function verifyReadyRotationBundle ({
  bundleDirectory,
  descriptorChainBytes,
  policy,
  policySha256,
  nowEpoch,
  relayId
}) {
  const plan = parsePlan(await fs.readFile(path.join(bundleDirectory, 'plan.json')))
  if (plan.relayId !== relayId || plan.policySha256 !== policySha256) {
    fail('ROTATION_BUNDLE_INVALID', 'rotation plan is bound to another relay or policy')
  }
  const descriptorBytes = await fs.readFile(path.join(bundleDirectory, 'descriptor.bin'))
  const admissionBytes = await fs.readFile(path.join(bundleDirectory, 'admission.bin'))
  const resultBytes = await fs.readFile(path.join(bundleDirectory, 'rotation.json'))
  let result
  try { result = JSON.parse(resultBytes) } catch { fail('ROTATION_BUNDLE_INVALID', 'rotation result is not JSON') }
  if (result.schema !== ROTATION_RESULT_SCHEMA || result.relayId !== relayId ||
      result.policySha256 !== policySha256 || result.planSha256 !== sha256Hex(await fs.readFile(path.join(bundleDirectory, 'plan.json'))) ||
      result.descriptorSha256 !== sha256Hex(descriptorBytes) || result.admissionSha256 !== sha256Hex(admissionBytes)) {
    fail('ROTATION_BUNDLE_INVALID', 'rotation result digests or identity do not match the bundle')
  }
  const inspected = await inspectRotationInputs({
    descriptorChainBytes, admissionParameterBytes: [admissionBytes], nowEpoch, relayId, policy
  })
  if (inspected.head.descriptorSequence.toString() !== plan.successorSequence ||
      byteHex(serviceDescriptorHash(descriptorBytes)) !== result.successorHash ||
      byteHex(admissionParametersHash(admissionBytes)) !== result.admissionParameterHash ||
      plan.predecessorHash !== byteHex(serviceDescriptorHash(descriptorChainBytes.at(-1)))) {
    fail('ROTATION_BUNDLE_INVALID', 'rotation bundle does not extend the supplied predecessor chain')
  }
  return Object.freeze({ plan, result, descriptorBytes, admissionBytes })
}

export async function prepareRotationBundle ({
  descriptorFiles,
  admissionFiles,
  secretKeyFile,
  policy,
  policySha256,
  relayId,
  nowEpoch,
  rotationRoot,
  toolDigests = {}
}) {
  const descriptorChainBytes = await Promise.all(descriptorFiles.map(file => fs.readFile(file)))
  const admissionParameterBytes = await Promise.all(admissionFiles.map(file => fs.readFile(file)))
  const inspected = await inspectRotationInputs({
    descriptorChainBytes, admissionParameterBytes, nowEpoch, relayId, policy
  })
  const readyDirectory = path.join(rotationRoot, `seq-${inspected.nextSequence}`)
  const pendingDirectory = `${readyDirectory}.pending`
  try {
    const ready = await fs.lstat(readyDirectory)
    if (!ready.isDirectory() || ready.isSymbolicLink()) fail('ROTATION_BUNDLE_INVALID', 'ready bundle is not a directory')
    const verified = await verifyReadyRotationBundle({
      bundleDirectory: readyDirectory,
      descriptorChainBytes: [...descriptorChainBytes, await fs.readFile(path.join(readyDirectory, 'descriptor.bin'))],
      policy, policySha256, nowEpoch, relayId
    })
    return Object.freeze({ mode: 'reused', directory: readyDirectory, ...verified })
  } catch (error) {
    if (!error || error.code !== 'ENOENT') throw error
  }

  await fs.mkdir(rotationRoot, { recursive: true, mode: 0o750 })
  let pendingCreated = false
  try {
    await fs.mkdir(pendingDirectory, { mode: 0o750 })
    pendingCreated = true
  } catch (error) {
    if (!error || error.code !== 'EEXIST') throw error
  }

  let plan
  if (pendingCreated) {
    plan = expectedPlan({
      inspected,
      relayId,
      policySha256,
      descriptorNonce: nodeRandomBytes(NONCE_BYTES),
      admissionNonce: nodeRandomBytes(NONCE_BYTES)
    })
    await writeExclusiveOrVerify(path.join(pendingDirectory, 'plan.json'), canonicalJson(plan), 0o640)
    await syncDirectory(pendingDirectory)
  } else {
    plan = parsePlan(await fs.readFile(path.join(pendingDirectory, 'plan.json')))
    const expected = expectedPlan({
      inspected,
      relayId,
      policySha256,
      descriptorNonce: b4a.from(plan.descriptorNonce, 'hex'),
      admissionNonce: b4a.from(plan.admissionNonce, 'hex')
    })
    if (!sameJson(plan, expected)) {
      fail('ROTATION_BUNDLE_CONFLICT', 'pending plan does not match the current predecessor and policy')
    }
  }

  const secretKey = await readProtectedSecret(secretKeyFile)
  let candidate
  try {
    candidate = await buildRotationCandidate({
      descriptorChainBytes,
      admissionParameterBytes,
      nowEpoch,
      relayId,
      policy,
      secretKey,
      descriptorNonce: b4a.from(plan.descriptorNonce, 'hex'),
      admissionNonce: b4a.from(plan.admissionNonce, 'hex')
    })
  } finally {
    secretKey.fill(0)
  }

  await writeExclusiveOrVerify(path.join(pendingDirectory, 'admission.bin'), candidate.admissionBytes, 0o640)
  await writeExclusiveOrVerify(path.join(pendingDirectory, 'descriptor.bin'), candidate.descriptorBytes, 0o640)
  const result = {
    schema: ROTATION_RESULT_SCHEMA,
    relayId,
    claimBoundary: 'LIMITED_PUBLIC_TEST_V1_NOT_GA',
    policyStatus: 'CANDIDATE_PENDING_INDEPENDENT_REVIEW_AND_LIVE_REDEMPTION',
    policySha256,
    planSha256: sha256Hex(canonicalJson(plan)),
    predecessorSequence: plan.predecessorSequence,
    predecessorHash: plan.predecessorHash,
    successorSequence: plan.successorSequence,
    successorHash: byteHex(candidate.descriptorHash),
    descriptorSha256: sha256Hex(candidate.descriptorBytes),
    admissionParameterHash: byteHex(candidate.admissionHash),
    admissionSha256: sha256Hex(candidate.admissionBytes),
    descriptorWindow: [candidate.descriptor.issuedEpoch, candidate.descriptor.expiresEpoch],
    admissionWindow: [candidate.admission.validFromEpoch, candidate.admission.expiresEpoch],
    class2: {
      familyId: FAMILY.CELL,
      operationId: OPERATION.CELL.PUT,
      resourceClass: 2,
      leaseClass: 1,
      costUnits: '40',
      added: candidate.class2Added
    },
    activation: {
      descriptorFiles: [...descriptorFiles, path.join(readyDirectory, 'descriptor.bin')],
      admissionParameterFiles: [path.join(readyDirectory, 'admission.bin')],
      expectedDescriptorSequence: plan.successorSequence,
      expectedDescriptorHash: byteHex(candidate.descriptorHash),
      expectedPredecessorSequence: plan.predecessorSequence,
      expectedPredecessorHash: plan.predecessorHash,
      composeProject: policy.releaseBinding.composeProject,
      composeSha256: policy.releaseBinding.composeSha256,
      daemonImageDigest: policy.releaseBinding.daemonImageDigest,
      edgeImageDigest: policy.releaseBinding.edgeImageDigest
    },
    toolDigests
  }
  await writeExclusiveOrVerify(path.join(pendingDirectory, 'rotation.json'), canonicalJson(result), 0o640)
  await syncDirectory(pendingDirectory)
  await syncDirectory(rotationRoot)
  try {
    await fs.rename(pendingDirectory, readyDirectory)
  } catch (error) {
    if (!error || (error.code !== 'ENOENT' && error.code !== 'EEXIST' && error.code !== 'ENOTEMPTY')) throw error
  }
  await syncDirectory(rotationRoot)
  const verified = await verifyReadyRotationBundle({
    bundleDirectory: readyDirectory,
    descriptorChainBytes: [...descriptorChainBytes, candidate.descriptorBytes],
    policy, policySha256, nowEpoch, relayId
  })
  return Object.freeze({ mode: pendingCreated ? 'created' : 'resumed', directory: readyDirectory, ...verified })
}

export function currentEpoch () {
  return Math.floor(Date.now() / SIX_HOURS_MILLIS)
}

export function parseAbsoluteFileList (value, field) {
  if (typeof value !== 'string' || value.length === 0) fail('ROTATION_INPUT_INVALID', `${field} is required`)
  const entries = value.split(',')
  if (entries.some(entry => !path.isAbsolute(entry) || path.normalize(entry) !== entry || entry.includes('\0'))) {
    fail('ROTATION_INPUT_INVALID', `${field} must contain canonical absolute comma-separated paths`)
  }
  return entries
}

export async function fileSha256 (file) {
  return sha256Hex(await fs.readFile(file))
}
