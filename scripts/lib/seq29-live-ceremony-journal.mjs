import { createHash, randomBytes } from 'node:crypto'
import {
  chmodSync,
  closeSync,
  constants,
  existsSync,
  fstatSync,
  fsyncSync,
  linkSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  unlinkSync,
  writeFileSync
} from 'node:fs'
import { basename, dirname, join, parse, relative, resolve, sep } from 'node:path'
import { canonicalPeeritLimitedPublicInboxJsonV1 } from '../../js/substrate/inbox-topic-v1.mjs'
import {
  PEERIT_SEQ29_HIVERELAY_CANDIDATE_COMMIT,
  PEERIT_SEQ29_LIMITED_INBOX_CEREMONY_ATTEMPT_KEY_V1,
  peeritLimitedInboxTopicCeremonyPlanHashV1,
  validatePeeritLimitedInboxTopicCeremonyPlanV1
} from '../limited-inbox-topic-ceremony.mjs'
import { validatePeeritLimitedPublicInboxSigningPackageV1 } from '../sign-limited-public-inbox-bootstrap.mjs'

const SLOT_DIRECTORY = `release-slot-${PEERIT_SEQ29_LIMITED_INBOX_CEREMONY_ATTEMPT_KEY_V1}`
const EVENT_SCHEMA = 'peerit-seq29-live-ceremony-journal-event-v1'
const HEX64 = /^[0-9a-f]{64}$/
const RELAY_ID = /^[a-z][a-z0-9-]{0,31}$/
const ALLOWED_EVENT_KINDS = new Set([
  'begin', 'claim-0', 'outcome-0', 'claim-1', 'outcome-1', 'recovery', 'finish'
])
const FILESYSTEM_JOURNALS = new WeakMap()
const ATTEMPT_BINDINGS = new WeakMap()
const MAX_SEALED_EVENT_BYTES = 4 * 1024 * 1024
const SEALED_IDENTITIES = new Map()
const DIRECTORY_IDENTITIES = new Map()
const JOURNAL_TEST_FAULT = 'PEERIT_SEQ29_LIVE_JOURNAL_TEST_FAULT'

function fail (code, message, details) {
  const error = new Error(message)
  error.code = code
  if (details !== undefined) error.details = details
  throw error
}

function exact (value, fields, field) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).sort().join('\0') !== [...fields].sort().join('\0')) {
    fail('PEERIT_SEQ29_LIVE_JOURNAL_INVALID', `${field} has missing or unexpected fields`)
  }
  return value
}

function exactArray (value, length, field) {
  if (!Array.isArray(value) || value.length !== length ||
      Object.keys(value).join('\0') !== Array.from({ length }, (_, index) => String(index)).join('\0')) {
    fail('PEERIT_SEQ29_LIVE_JOURNAL_INVALID',
      `${field} must be a dense exact ${length}-element array`)
  }
  return value
}

function hex64 (value, field) {
  if (typeof value !== 'string' || !HEX64.test(value)) {
    fail('PEERIT_SEQ29_LIVE_JOURNAL_INVALID', `${field} must be lowercase 32-byte hexadecimal`)
  }
  return value
}

function opaqueId (value, field) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 256 ||
      !/^[A-Za-z0-9._:-]+$/.test(value)) {
    fail('PEERIT_SEQ29_LIVE_JOURNAL_INVALID', `${field} is not a bounded opaque identifier`)
  }
  return value
}

function digest (value) {
  return createHash('sha256')
    .update(canonicalPeeritLimitedPublicInboxJsonV1(value)).digest('hex')
}

function prettyBytes (value) {
  return Buffer.from(JSON.stringify(value, null, 2) + '\n', 'utf8')
}

function currentIdentity () {
  return {
    uid: typeof process.getuid === 'function' ? process.getuid() : null
  }
}

function assertOwned (metadata, field) {
  const identity = currentIdentity()
  if (identity.uid != null && metadata.uid !== identity.uid) {
    fail('PEERIT_SEQ29_LIVE_JOURNAL_PERMISSIONS',
      `${field} is not owned by the current operator identity`)
  }
}

function fullMode (metadata) {
  return metadata.mode & 0o7777
}

function sameDirectoryIdentity (left, right) {
  return left.isDirectory() && right.isDirectory() &&
    !left.isSymbolicLink() && !right.isSymbolicLink() &&
    left.dev === right.dev && left.ino === right.ino &&
    left.uid === right.uid && left.gid === right.gid &&
    fullMode(left) === fullMode(right)
}

function directoryIdentity (metadata) {
  return Object.freeze({
    dev: metadata.dev,
    ino: metadata.ino,
    uid: metadata.uid,
    gid: metadata.gid,
    mode: fullMode(metadata)
  })
}

function matchesDirectoryIdentity (identity, metadata) {
  return identity.dev === metadata.dev && identity.ino === metadata.ino &&
    identity.uid === metadata.uid && identity.gid === metadata.gid &&
    identity.mode === fullMode(metadata)
}

function authenticateDirectory (path, { synchronize = false } = {}) {
  let named
  try {
    named = lstatSync(path)
  } catch {
    fail('PEERIT_SEQ29_LIVE_JOURNAL_IO_FAILED',
      'could not inspect an authenticated journal directory')
  }
  if (!named.isDirectory() || named.isSymbolicLink()) {
    fail('PEERIT_SEQ29_LIVE_JOURNAL_PERMISSIONS',
      'journal directory is not a real directory')
  }
  assertOwned(named, 'journal directory')
  const identityKey = resolve(path)
  const known = DIRECTORY_IDENTITIES.get(identityKey)
  if (known && !matchesDirectoryIdentity(known, named)) {
    fail('PEERIT_SEQ29_LIVE_JOURNAL_PERMISSIONS',
      'journal directory changed its authenticated identity')
  }
  let descriptor
  let primary
  try {
    descriptor = openSync(path, constants.O_RDONLY |
      (constants.O_DIRECTORY || 0) | (constants.O_NOFOLLOW || 0))
    const opened = fstatSync(descriptor)
    if (!sameDirectoryIdentity(named, opened)) {
      fail('PEERIT_SEQ29_LIVE_JOURNAL_PERMISSIONS',
        'journal directory changed identity before authenticated open')
    }
    assertOwned(opened, 'opened journal directory')
    if (synchronize) fsyncSync(descriptor)
    const after = fstatSync(descriptor)
    const namedAfter = lstatSync(path)
    if (!sameDirectoryIdentity(opened, after) ||
        !sameDirectoryIdentity(opened, namedAfter)) {
      fail('PEERIT_SEQ29_LIVE_JOURNAL_PERMISSIONS',
        'journal directory changed identity during authenticated access')
    }
    DIRECTORY_IDENTITIES.set(identityKey, directoryIdentity(namedAfter))
  } catch (cause) {
    primary = cause
  }
  if (descriptor !== undefined) {
    try {
      closeSync(descriptor)
    } catch {
      if (!primary) {
        primary = Object.assign(new Error('directory close uncertainty'), {
          code: 'PEERIT_SEQ29_LIVE_JOURNAL_IO_FAILED'
        })
      }
    }
  }
  if (primary) {
    if (String(primary.code || '').startsWith('PEERIT_SEQ29_')) throw primary
    fail('PEERIT_SEQ29_LIVE_JOURNAL_IO_FAILED',
      'could not durably access an authenticated journal directory')
  }
  return named
}

function fsyncDirectory (path) {
  return authenticateDirectory(path, { synchronize: true })
}

function assertNoSymlinkParents (path) {
  const absolute = resolve(path)
  const root = parse(absolute).root
  const suffix = relative(root, absolute)
  let cursor = root
  for (const component of suffix === '' ? [] : suffix.split(sep)) {
    cursor = join(cursor, component)
    if (!existsSync(cursor)) break
    const metadata = lstatSync(cursor)
    if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
      fail('PEERIT_SEQ29_LIVE_JOURNAL_PERMISSIONS',
        `${cursor} is not a real directory`)
    }
  }
}

function ensurePrivateRoot (root) {
  assertNoSymlinkParents(dirname(root))
  if (!existsSync(root)) {
    try { mkdirSync(root, { mode: 0o700 }) } catch {
      fail('PEERIT_SEQ29_LIVE_JOURNAL_IO_FAILED',
        'could not create the private journal root')
    }
    fsyncDirectory(dirname(root))
  }
  const metadata = authenticateDirectory(root)
  if (metadata.isSymbolicLink() || !metadata.isDirectory() ||
      fullMode(metadata) !== 0o700) {
    fail('PEERIT_SEQ29_LIVE_JOURNAL_PERMISSIONS',
      'journal root must be a real directory with exact mode 0700')
  }
  assertOwned(metadata, 'journal root')
}

function atomicCreateOnly (target, value, mode = 0o600) {
  const parent = dirname(target)
  const temporary = join(parent, `.${basename(target)}.${process.pid}.${randomBytes(12).toString('hex')}.tmp`)
  const pending = join(parent, `.pending-${basename(target)}`)
  let descriptor
  let pendingDescriptor
  try {
    pendingDescriptor = openSync(pending, 'wx', 0o600)
    writeFileSync(pendingDescriptor, Buffer.from('peerit-seq29-journal-pending-v1\n'))
    fsyncSync(pendingDescriptor)
    closeSync(pendingDescriptor)
    pendingDescriptor = undefined
    fsyncDirectory(parent)
    descriptor = openSync(temporary, 'wx', mode)
    const opened = fstatSync(descriptor)
    if (!opened.isFile() || opened.nlink !== 1 ||
        fullMode(opened) !== mode) {
      fail('PEERIT_SEQ29_LIVE_JOURNAL_IO_FAILED',
        'temporary journal seal is not a single-link regular file')
    }
    writeFileSync(descriptor, prettyBytes(value))
    fsyncSync(descriptor)
    closeSync(descriptor)
    descriptor = undefined
    if (process.env[JOURNAL_TEST_FAULT] === 'EVENT_CLOSE_UNCERTAIN') {
      fail('PEERIT_SEQ29_LIVE_JOURNAL_IO_FAILED',
        'journal event close durability is uncertain')
    }
    chmodSync(temporary, mode)
    linkSync(temporary, target)
    unlinkSync(temporary)
    const sealed = lstatSync(target)
    if (!sealed.isFile() || sealed.isSymbolicLink() || sealed.nlink !== 1 ||
        fullMode(sealed) !== mode) {
      fail('PEERIT_SEQ29_LIVE_JOURNAL_IO_FAILED',
        'sealed journal record is not a single-link private regular file')
    }
    assertOwned(sealed, 'sealed journal record')
    if (process.env[JOURNAL_TEST_FAULT] ===
        'POST_LINK_DIRECTORY_SYNC_UNCERTAIN') {
      fail('PEERIT_SEQ29_LIVE_JOURNAL_IO_FAILED',
        'journal directory durability is uncertain after event link')
    }
    fsyncDirectory(parent)
    unlinkSync(pending)
    fsyncDirectory(parent)
  } catch (cause) {
    fail(cause?.code === 'EEXIST'
      ? 'PEERIT_SEQ29_LIVE_JOURNAL_ALREADY_SEALED'
      : 'PEERIT_SEQ29_LIVE_JOURNAL_IO_FAILED',
    `could not durably create ${basename(target)}`)
  } finally {
    if (pendingDescriptor !== undefined) {
      try { closeSync(pendingDescriptor) } catch {}
    }
    if (descriptor !== undefined) {
      try { closeSync(descriptor) } catch {}
    }
    try { unlinkSync(temporary) } catch {}
  }
}

function readSealed (path) {
  const metadata = lstatSync(path)
  const identityKey = resolve(path)
  const knownIdentity = SEALED_IDENTITIES.get(identityKey)
  if (knownIdentity && (knownIdentity.dev !== metadata.dev ||
      knownIdentity.ino !== metadata.ino)) {
    fail('PEERIT_SEQ29_LIVE_JOURNAL_CORRUPT',
      `${basename(path)} changed its sealed inode identity`)
  }
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1) {
    fail('PEERIT_SEQ29_LIVE_JOURNAL_CORRUPT',
      `${basename(path)} is not a regular sealed journal file`)
  }
  if (fullMode(metadata) !== 0o600) {
    fail('PEERIT_SEQ29_LIVE_JOURNAL_PERMISSIONS',
      `${basename(path)} does not have exact private mode 0600`)
  }
  assertOwned(metadata, 'sealed journal record')
  if (metadata.size > MAX_SEALED_EVENT_BYTES) {
    fail('PEERIT_SEQ29_LIVE_JOURNAL_CORRUPT',
      `${basename(path)} exceeds the sealed event size limit`)
  }
  let descriptor
  try {
    descriptor = openSync(path,
      constants.O_RDONLY | (constants.O_NOFOLLOW || 0))
  } catch {
    fail('PEERIT_SEQ29_LIVE_JOURNAL_CORRUPT',
      `${basename(path)} could not be opened as a sealed file`)
  }
  let bytes
  try {
    const opened = fstatSync(descriptor)
    if (!opened.isFile() || opened.nlink !== 1 ||
        fullMode(opened) !== 0o600 || opened.dev !== metadata.dev ||
        opened.ino !== metadata.ino || opened.size !== metadata.size) {
      fail('PEERIT_SEQ29_LIVE_JOURNAL_CORRUPT',
        `${basename(path)} changed identity before sealed readback`)
    }
    assertOwned(opened, 'opened sealed journal record')
    bytes = readFileSync(descriptor)
    const after = fstatSync(descriptor)
    const namedAfter = lstatSync(path)
    if (bytes.byteLength !== opened.size || after.dev !== opened.dev ||
        after.ino !== opened.ino || after.size !== opened.size ||
        after.nlink !== 1 || fullMode(after) !== 0o600 ||
        namedAfter.dev !== opened.dev || namedAfter.ino !== opened.ino ||
        namedAfter.size !== opened.size || namedAfter.nlink !== 1 ||
        fullMode(namedAfter) !== 0o600 || !namedAfter.isFile() ||
        namedAfter.isSymbolicLink()) {
      fail('PEERIT_SEQ29_LIVE_JOURNAL_CORRUPT',
        `${basename(path)} changed identity during sealed readback`)
    }
  } finally {
    try { closeSync(descriptor) } catch {
      fail('PEERIT_SEQ29_LIVE_JOURNAL_IO_FAILED',
        'sealed journal descriptor could not be closed')
    }
  }
  SEALED_IDENTITIES.set(identityKey, Object.freeze({
    dev: metadata.dev,
    ino: metadata.ino
  }))
  let value
  try { value = JSON.parse(bytes.toString('utf8')) } catch {
    fail('PEERIT_SEQ29_LIVE_JOURNAL_CORRUPT', `${basename(path)} is not JSON`)
  }
  if (!prettyBytes(value).equals(bytes)) {
    fail('PEERIT_SEQ29_LIVE_JOURNAL_CORRUPT', `${basename(path)} is not canonical sealed JSON`)
  }
  const event = exact(value, ['schema', 'version', 'kind', 'sequence', 'body', 'previousEventHash', 'eventHash'], 'journal event')
  const unsigned = { ...event }
  delete unsigned.eventHash
  if (event.schema !== EVENT_SCHEMA || event.version !== 1 || !Number.isSafeInteger(event.sequence) ||
      event.sequence < 0 || !HEX64.test(event.eventHash) || event.eventHash !== digest(unsigned)) {
    fail('PEERIT_SEQ29_LIVE_JOURNAL_CORRUPT', `${basename(path)} has an invalid identity or hash`)
  }
  return event
}

function eventFile (slot, sequence, kind) {
  return join(slot, `${String(sequence).padStart(4, '0')}-${kind}.json`)
}

function validateBeginRequest (request) {
  exact(request, [
    'schema', 'releaseAttemptKey', 'candidateCommit', 'releaseSequence', 'planHash',
    'relayIdentityDigest', 'commitTokenHash', 'operationBudget', 'plan',
    'planSha256', 'persistedQualification', 'persistedQualificationSha256'
  ], 'begin request')
  exact(request.operationBudget, ['family', 'operation', 'maximum'], 'operation budget')
  if (request.schema !== 'peerit-limited-inbox-create-only-attempt-v1' ||
      request.releaseAttemptKey !== PEERIT_SEQ29_LIMITED_INBOX_CEREMONY_ATTEMPT_KEY_V1 ||
      request.candidateCommit !== PEERIT_SEQ29_HIVERELAY_CANDIDATE_COMMIT ||
      request.releaseSequence !== 29 || request.operationBudget.family !== 'INBOX' ||
      request.operationBudget.operation !== 'CREATE' || request.operationBudget.maximum !== 2) {
    fail('PEERIT_SEQ29_LIVE_JOURNAL_SCOPE',
      'begin request is outside the fixed Seq29 two-CREATE slot')
  }
  hex64(request.planHash, 'planHash')
  hex64(request.relayIdentityDigest, 'relayIdentityDigest')
  hex64(request.commitTokenHash, 'commitTokenHash')
  hex64(request.planSha256, 'planSha256')
  hex64(request.persistedQualificationSha256,
    'persistedQualificationSha256')
  const plan = validatePeeritLimitedInboxTopicCeremonyPlanV1(request.plan)
  const continuity = exact(request.persistedQualification, [
    'schema', 'version', 'planHash', 'referenceUnixMillis',
    'seedBootstrapSha256', 'limitedCellPutProfileSha256'
  ], 'persisted qualification continuity')
  hex64(continuity.planHash, 'persisted qualification planHash')
  hex64(continuity.seedBootstrapSha256,
    'persisted qualification seedBootstrapSha256')
  hex64(continuity.limitedCellPutProfileSha256,
    'persisted qualification limitedCellPutProfileSha256')
  if (continuity.schema !== 'peerit-seq29-live-inbox-create-plan-continuity-v1' ||
      continuity.version !== 1 ||
      !/^(?:0|[1-9][0-9]*)$/.test(continuity.referenceUnixMillis) ||
      request.planHash !== peeritLimitedInboxTopicCeremonyPlanHashV1(plan) ||
      request.planSha256 !== digest(plan) ||
      request.persistedQualificationSha256 !== digest(continuity) ||
      continuity.planHash !== request.planHash ||
      continuity.referenceUnixMillis !== plan.referenceUnixMillis) {
    fail('PEERIT_SEQ29_LIVE_JOURNAL_SCOPE',
      'begin request does not bind the exact plan and source continuity bytes')
  }
  return request
}

function validateClaimRequest (request, attempt, index) {
  exact(request, [
    'attemptId', 'releaseAttemptKey', 'planHash', 'operationIndex', 'operationKey',
    'family', 'operation', 'relayId'
  ], `claim ${index} request`)
  assertAttemptRequest(request, attempt)
  if (request.operationIndex !== index || request.family !== 'INBOX' ||
      request.operation !== 'CREATE' || !RELAY_ID.test(request.relayId) ||
      request.operationKey !== `INBOX.CREATE:${request.relayId}`) {
    fail('PEERIT_SEQ29_LIVE_JOURNAL_SCOPE', `claim ${index} is outside its exact CREATE slot`)
  }
  return request
}

function validateOutcomeRequest (request, attempt, claim, index) {
  const terminalStates = [
    'AMBIGUOUS_TERMINAL', 'REJECTED_TERMINAL',
    'INVALID_RESULT_TERMINAL', 'VERIFIED_TERMINAL'
  ]
  const fields = ['attemptId', 'releaseAttemptKey', 'planHash', 'operationKey', 'state']
  if (request?.state === 'VERIFIED_TERMINAL') fields.push('receiptSha256')
  exact(request, fields, `outcome ${index} request`)
  assertAttemptRequest(request, attempt)
  if (request.operationKey !== claim.operationKey || !terminalStates.includes(request.state)) {
    fail('PEERIT_SEQ29_LIVE_JOURNAL_OUTCOME', `outcome ${index} is not bound to its claim`)
  }
  if (request.state === 'VERIFIED_TERMINAL') hex64(request.receiptSha256, `outcome ${index} receiptSha256`)
  return request
}

function validateRecoveryRequest (request, attempt, claims) {
  exact(request, [
    'attemptId', 'releaseAttemptKey', 'planHash', 'recovery', 'recoveryDigest'
  ], 'recovery request')
  assertAttemptRequest(request, attempt)
  hex64(request.recoveryDigest, 'recoveryDigest')
  if (request.recoveryDigest !== digest(request.recovery)) {
    fail('PEERIT_SEQ29_LIVE_JOURNAL_RECOVERY', 'recoveryDigest does not bind the exact recovery')
  }
  const recovery = exact(request.recovery, [
    'schema', 'planHash', 'attemptId', 'releaseAttemptKey', 'relayIdentityDigest',
    'signingPackage', 'signingPackageSha256', 'custodyTransactionId',
    'custodyPublicBindingDigest', 'transportInvocations', 'executionDigest'
  ], 'recovery')
  if (recovery.schema !== 'peerit-limited-inbox-topic-recovery-v2' ||
      recovery.planHash !== attempt.planHash || recovery.attemptId !== attempt.attemptId ||
      recovery.releaseAttemptKey !== attempt.releaseAttemptKey ||
      recovery.relayIdentityDigest !== attempt.request.relayIdentityDigest) {
    fail('PEERIT_SEQ29_LIVE_JOURNAL_RECOVERY',
      'recovery differs from its fixed release attempt')
  }
  hex64(recovery.signingPackageSha256, 'signingPackageSha256')
  hex64(recovery.custodyPublicBindingDigest, 'custodyPublicBindingDigest')
  hex64(recovery.executionDigest, 'executionDigest')
  opaqueId(recovery.custodyTransactionId, 'custodyTransactionId')
  if (recovery.signingPackageSha256 !== digest(recovery.signingPackage) ||
      recovery.custodyPublicBindingDigest !== digest({
        schema: 'peerit-seq29-limited-inbox-custody-public-binding-v1',
        planHash: recovery.planHash,
        signingPackageSha256: recovery.signingPackageSha256,
        signingPackage: recovery.signingPackage
      })) {
    fail('PEERIT_SEQ29_LIVE_JOURNAL_RECOVERY',
      'recovery signing package or custody public binding digest is invalid')
  }
  const fixtureOnly = process.env.PEERIT_SEQ29_OPERATOR_FIXTURE_TEST === '1' &&
    recovery.signingPackage?.payload?.artifactClass === 'FIXTURE_ONLY'
  const checked = validatePeeritLimitedPublicInboxSigningPackageV1(
    recovery.signingPackage, { allowFixture: fixtureOnly })
  exactArray(recovery.transportInvocations, 2, 'recovery transportInvocations')
  const operationKeys = claims.map(claim => claim.operationKey)
  if (recovery.transportInvocations.join('\0') !== operationKeys.join('\0') ||
      checked.createRequests.map(row => `INBOX.CREATE:${row.relayId}`).join('\0') !==
        operationKeys.join('\0')) {
    fail('PEERIT_SEQ29_LIVE_JOURNAL_RECOVERY',
      'recovery transport set differs from its exact claims or signing package')
  }
  return recovery
}

function validateFinishRequest (request, attempt, recovery, claimedOperationKeys) {
  const baseFields = [
    'attemptId', 'releaseAttemptKey', 'planHash', 'state', 'transportInvocations'
  ]
  if (request?.state === 'COMMITTED_CREATE_ONLY') {
    baseFields.push(
      'executionDigest', 'signedBootstrapHash', 'managementBundleDigest',
      'custodyCommitment'
    )
  } else if (request?.state === 'QUARANTINED_TERMINAL_NO_RETRY') {
    baseFields.push('recoveryPersisted')
  }
  exact(request, baseFields, 'finish request')
  assertAttemptRequest(request, attempt)
  if (request.state === 'COMMITTED_CREATE_ONLY') {
    if (!recovery || request.executionDigest !== recovery.executionDigest) {
      fail('PEERIT_SEQ29_LIVE_JOURNAL_TERMINAL',
        'committed finish lacks its exact durable recovery')
    }
    hex64(request.signedBootstrapHash, 'signedBootstrapHash')
    hex64(request.managementBundleDigest, 'managementBundleDigest')
    opaqueId(request.custodyCommitment, 'custodyCommitment')
    exactArray(request.transportInvocations, 2, 'committed transportInvocations')
    if (request.transportInvocations.join('\0') !== recovery.transportInvocations.join('\0')) {
      fail('PEERIT_SEQ29_LIVE_JOURNAL_TERMINAL',
        'committed finish transport set differs from durable recovery')
    }
  } else if (request.state === 'QUARANTINED_TERMINAL_NO_RETRY') {
    if (recovery || request.recoveryPersisted !== false) {
      fail('PEERIT_SEQ29_LIVE_JOURNAL_TERMINAL',
        'quarantine cannot follow or claim a durable recovery')
    }
    exactArray(request.transportInvocations, claimedOperationKeys.length,
      'quarantine transportInvocations')
    if (request.transportInvocations.join('\0') !== claimedOperationKeys.join('\0')) {
      fail('PEERIT_SEQ29_LIVE_JOURNAL_TERMINAL',
        'quarantine transport set differs from claimed operations')
    }
  } else {
    fail('PEERIT_SEQ29_LIVE_JOURNAL_TERMINAL', 'finish state is not admitted')
  }
  return request
}

function validateEventBody (event, fields, field) {
  const body = exact(event.body, fields, `${field} body`)
  if (body.requestDigest !== digest(body.request)) {
    fail('PEERIT_SEQ29_LIVE_JOURNAL_CORRUPT',
      `${field} requestDigest does not bind its request`)
  }
  return body
}

function validateEventGrammar (events) {
  if (events.length < 1) return
  const beginEvent = events[0]
  if (beginEvent.kind !== 'begin') {
    fail('PEERIT_SEQ29_LIVE_JOURNAL_CORRUPT', 'journal does not begin with the fixed begin event')
  }
  const beginBody = exact(beginEvent.body, [
    'attemptId', 'releaseAttemptKey', 'planHash', 'requestDigest', 'request'
  ], 'begin body')
  opaqueId(beginBody.attemptId, 'attemptId')
  validateBeginRequest(beginBody.request)
  if (beginBody.releaseAttemptKey !== beginBody.request.releaseAttemptKey ||
      beginBody.planHash !== beginBody.request.planHash ||
      beginBody.requestDigest !== digest(beginBody.request)) {
    fail('PEERIT_SEQ29_LIVE_JOURNAL_CORRUPT', 'begin body does not bind its exact request')
  }
  const attempt = beginBody
  const claims = []
  const outcomes = []
  let recovery = null
  let cursor = 1

  if (events[cursor]?.kind === 'finish') {
    const body = validateEventBody(events[cursor], ['request', 'requestDigest'], 'finish')
    validateFinishRequest(body.request, attempt, null, [])
    cursor++
  } else {
    for (let index = 0; index < 2; index++) {
      if (cursor >= events.length) break
      if (events[cursor].kind !== `claim-${index}`) {
        fail('PEERIT_SEQ29_LIVE_JOURNAL_CORRUPT',
          `journal expected claim-${index} at sequence ${cursor}`)
      }
      const claimBody = validateEventBody(events[cursor], ['request', 'requestDigest'], `claim-${index}`)
      const claim = validateClaimRequest(claimBody.request, attempt, index)
      if (claims.some(previous => previous.relayId === claim.relayId)) {
        fail('PEERIT_SEQ29_LIVE_JOURNAL_SCOPE', 'CREATE claims reuse a relayId')
      }
      claims.push(claim)
      cursor++
      if (cursor >= events.length) break
      if (events[cursor].kind !== `outcome-${index}`) {
        fail('PEERIT_SEQ29_LIVE_JOURNAL_CORRUPT',
          `journal expected outcome-${index} at sequence ${cursor}`)
      }
      const outcomeBody = validateEventBody(events[cursor], ['request', 'requestDigest'], `outcome-${index}`)
      const outcome = validateOutcomeRequest(outcomeBody.request, attempt, claim, index)
      outcomes.push(outcome)
      cursor++
      if (outcome.state !== 'VERIFIED_TERMINAL') {
        if (cursor < events.length) {
          if (events[cursor].kind !== 'finish') {
            fail('PEERIT_SEQ29_LIVE_JOURNAL_CORRUPT',
              'nonverified CREATE outcome must be the final mutation outcome')
          }
          const body = validateEventBody(events[cursor], ['request', 'requestDigest'], 'finish')
          validateFinishRequest(body.request, attempt, null,
            claims.map(value => value.operationKey))
          cursor++
        }
        break
      }
    }

    if (outcomes.length === 2 && outcomes.every(value => value.state === 'VERIFIED_TERMINAL') &&
        cursor < events.length) {
      if (events[cursor].kind !== 'recovery') {
        fail('PEERIT_SEQ29_LIVE_JOURNAL_CORRUPT',
          'two verified CREATE outcomes must be followed only by recovery')
      }
      const body = validateEventBody(events[cursor],
        ['request', 'requestDigest'], 'recovery')
      recovery = validateRecoveryRequest(body.request, attempt, claims)
      cursor++
      if (cursor < events.length) {
        if (events[cursor].kind !== 'finish') {
          fail('PEERIT_SEQ29_LIVE_JOURNAL_CORRUPT',
            'durable recovery may be followed only by committed finish')
        }
        const finishBody = validateEventBody(events[cursor],
          ['request', 'requestDigest'], 'finish')
        validateFinishRequest(finishBody.request, attempt, recovery,
          claims.map(value => value.operationKey))
        cursor++
      }
    }
  }
  if (cursor !== events.length) {
    fail('PEERIT_SEQ29_LIVE_JOURNAL_CORRUPT',
      'journal contains an out-of-order, unknown, or post-terminal event')
  }
}

function loadEvents (slot) {
  const metadata = authenticateDirectory(slot)
  if (!metadata.isDirectory() || metadata.isSymbolicLink() ||
      fullMode(metadata) !== 0o700) {
    fail('PEERIT_SEQ29_LIVE_JOURNAL_PERMISSIONS',
      'fixed release slot must be a real directory with exact mode 0700')
  }
  const allNames = readdirSync(slot)
  authenticateDirectory(slot)
  const names = allNames.filter(name => /^[0-9]{4}-[a-z0-9-]+\.json$/.test(name)).sort()
  const unexpected = allNames.filter(name => !names.includes(name))
  if (unexpected.length > 0) {
    fail('PEERIT_SEQ29_LIVE_JOURNAL_CORRUPT',
      `fixed release slot contains unexpected entries: ${unexpected.join(', ')}`)
  }
  const events = names.map(name => readSealed(join(slot, name)))
  for (let index = 0; index < events.length; index++) {
    if (!ALLOWED_EVENT_KINDS.has(events[index].kind) ||
        events[index].sequence !== index ||
        names[index] !== basename(eventFile(slot, index, events[index].kind)) ||
        events[index].previousEventHash !== (index === 0 ? null : events[index - 1].eventHash)) {
      fail('PEERIT_SEQ29_LIVE_JOURNAL_CORRUPT',
        'journal filename, sequence, or hash chain is discontinuous')
    }
  }
  validateEventGrammar(events)
  return events
}

function appendEvent (slot, kind, body) {
  const events = loadEvents(slot)
  const sequence = events.length
  const unsigned = {
    schema: EVENT_SCHEMA,
    version: 1,
    kind,
    sequence,
    body,
    previousEventHash: sequence === 0 ? null : events[sequence - 1].eventHash
  }
  const event = { ...unsigned, eventHash: digest(unsigned) }
  validateEventGrammar([...events, event])
  atomicCreateOnly(eventFile(slot, sequence, kind), event)
  return event
}

function receipt (event, state, extra = {}) {
  return {
    accepted: true,
    durable: true,
    state,
    ...extra,
    commitment: event.eventHash
  }
}

function assertAttemptRequest (request, attempt) {
  if (request.attemptId !== attempt.attemptId ||
      request.releaseAttemptKey !== attempt.releaseAttemptKey ||
      request.planHash !== attempt.planHash) {
    fail('PEERIT_SEQ29_LIVE_JOURNAL_ATTEMPT_MISMATCH', 'journal request differs from the fixed release attempt')
  }
}

/**
 * Create the sole create-only Seq29 live ceremony attempt journal.
 *
 * The fixed release slot is consumed at the first durable begin. An existing
 * slot is never resumed for network dispatch: only a complete public recovery
 * record can be returned, and it is returned with NO_RESEND semantics.
 */
export function createPeeritSeq29FilesystemAttemptJournalV1 (input = {}) {
  exact(input, ['directory'], 'journal factory input')
  const root = resolve(input.directory)
  ensurePrivateRoot(root)
  const slot = join(root, SLOT_DIRECTORY)

  function current () {
    if (!existsSync(slot)) return { events: [], attempt: null }
    const events = loadEvents(slot)
    if (events.length < 1 || events[0].kind !== 'begin') {
      fail('PEERIT_SEQ29_LIVE_JOURNAL_NO_RESEND',
        'fixed release slot is consumed without a complete begin seal; retry is forbidden')
    }
    return { events, attempt: events[0].body }
  }

  const journal = Object.freeze({
    async beginAttempt (request) {
      exact(request, [
        'schema', 'releaseAttemptKey', 'candidateCommit', 'releaseSequence', 'planHash',
        'relayIdentityDigest', 'commitTokenHash', 'operationBudget', 'plan',
        'planSha256', 'persistedQualification', 'persistedQualificationSha256'
      ], 'begin request')
      exact(request.operationBudget, ['family', 'operation', 'maximum'], 'operation budget')
      if (request.schema !== 'peerit-limited-inbox-create-only-attempt-v1' ||
          request.releaseAttemptKey !== PEERIT_SEQ29_LIMITED_INBOX_CEREMONY_ATTEMPT_KEY_V1 ||
          request.candidateCommit !== PEERIT_SEQ29_HIVERELAY_CANDIDATE_COMMIT ||
          request.releaseSequence !== 29 || !HEX64.test(request.planHash) ||
          !HEX64.test(request.relayIdentityDigest) || !HEX64.test(request.commitTokenHash) ||
          request.operationBudget?.family !== 'INBOX' ||
          request.operationBudget?.operation !== 'CREATE' ||
          request.operationBudget?.maximum !== 2) {
        fail('PEERIT_SEQ29_LIVE_JOURNAL_SCOPE', 'begin request is outside the fixed Seq29 two-CREATE slot')
      }
      validateBeginRequest(request)
      const requestDigest = digest(request)
      if (existsSync(slot)) {
        const { events, attempt } = current()
        if (attempt.requestDigest !== requestDigest || attempt.planHash !== request.planHash ||
            attempt.releaseAttemptKey !== request.releaseAttemptKey) {
          fail('PEERIT_SEQ29_LIVE_JOURNAL_SLOT_CONSUMED', 'the fixed Seq29 release slot is already consumed')
        }
        if (events.some(event => event.kind === 'finish')) {
          fail('PEERIT_SEQ29_LIVE_JOURNAL_NO_RESEND',
            'the fixed Seq29 attempt is terminal; CREATE resend and custody replay are forbidden')
        }
        const recovery = events.find(event => event.kind === 'recovery')
        if (!recovery) {
          fail('PEERIT_SEQ29_LIVE_JOURNAL_NO_RESEND',
            'the fixed Seq29 attempt has no complete recovery seal; CREATE resend is forbidden')
        }
        return receipt(recovery, 'RECOVERY_AVAILABLE_NO_RESEND', {
          attemptId: attempt.attemptId,
          releaseAttemptKey: attempt.releaseAttemptKey,
          planHash: attempt.planHash,
          requestDigest: attempt.requestDigest,
          recovery: recovery.body.request.recovery
        })
      }
      try { mkdirSync(slot, { mode: 0o700 }) } catch {
        fail('PEERIT_SEQ29_LIVE_JOURNAL_SLOT_CONSUMED',
          'the fixed Seq29 release slot was concurrently consumed')
      }
      fsyncDirectory(root)
      const attemptId = randomBytes(32).toString('hex')
      const event = appendEvent(slot, 'begin', {
        attemptId,
        releaseAttemptKey: request.releaseAttemptKey,
        planHash: request.planHash,
        requestDigest,
        request
      })
      return receipt(event, 'CONSUMED_NO_MUTATIONS', {
        attemptId,
        releaseAttemptKey: request.releaseAttemptKey,
        planHash: request.planHash,
        requestDigest
      })
    },

    async claimOperation (request) {
      exact(request, [
        'attemptId', 'releaseAttemptKey', 'planHash', 'operationIndex', 'operationKey',
        'family', 'operation', 'relayId'
      ], 'claim request')
      const { events, attempt } = current()
      assertAttemptRequest(request, attempt)
      if (request.family !== 'INBOX' || request.operation !== 'CREATE' ||
          ![0, 1].includes(request.operationIndex) ||
          request.operationKey !== `INBOX.CREATE:${request.relayId}` ||
          events.some(event => event.kind === 'finish' || event.kind === `claim-${request.operationIndex}`)) {
        fail('PEERIT_SEQ29_LIVE_JOURNAL_NO_RESEND', 'CREATE claim is duplicate, terminal, or outside the two-operation budget')
      }
      const previousClaims = events.filter(event => event.kind.startsWith('claim-')).length
      if (previousClaims !== request.operationIndex) {
        fail('PEERIT_SEQ29_LIVE_JOURNAL_ORDER', 'CREATE claims must be durable and strictly ordered')
      }
      if (request.operationIndex === 1 && !events.some(event =>
        event.kind === 'outcome-0' && event.body?.request?.state === 'VERIFIED_TERMINAL')) {
        fail('PEERIT_SEQ29_LIVE_JOURNAL_ORDER',
          'the second CREATE requires a durably verified first CREATE outcome')
      }
      const requestDigest = digest(request)
      const event = appendEvent(slot, `claim-${request.operationIndex}`, { request, requestDigest })
      return receipt(event, 'DISPATCH_CLAIMED', {
        attemptId: request.attemptId,
        releaseAttemptKey: request.releaseAttemptKey,
        planHash: request.planHash,
        operationKey: request.operationKey,
        requestDigest
      })
    },

    async recordOutcome (request) {
      const fields = ['attemptId', 'releaseAttemptKey', 'planHash', 'operationKey', 'state']
      if (request?.state === 'VERIFIED_TERMINAL') fields.push('receiptSha256')
      exact(request, fields, 'outcome request')
      const { events, attempt } = current()
      assertAttemptRequest(request, attempt)
      const claim = events.find(event => event.body?.request?.operationKey === request.operationKey &&
        event.kind.startsWith('claim-'))
      if (!claim || events.some(event => event.kind.startsWith('outcome-') &&
          event.body?.request?.operationKey === request.operationKey) ||
          !['AMBIGUOUS_TERMINAL', 'REJECTED_TERMINAL', 'INVALID_RESULT_TERMINAL', 'VERIFIED_TERMINAL'].includes(request.state)) {
        fail('PEERIT_SEQ29_LIVE_JOURNAL_OUTCOME', 'outcome is duplicate, unclaimed, or nonterminal')
      }
      const index = claim.body.request.operationIndex
      const requestDigest = digest(request)
      const event = appendEvent(slot, `outcome-${index}`, { request, requestDigest })
      return receipt(event, request.state, {
        attemptId: request.attemptId,
        releaseAttemptKey: request.releaseAttemptKey,
        planHash: request.planHash,
        operationKey: request.operationKey,
        requestDigest
      })
    },

    async persistRecovery (request) {
      exact(request, [
        'attemptId', 'releaseAttemptKey', 'planHash', 'recovery', 'recoveryDigest'
      ], 'recovery request')
      const { events, attempt } = current()
      assertAttemptRequest(request, attempt)
      if (events.some(event => event.kind === 'recovery') ||
          events.filter(event => event.kind.startsWith('outcome-') &&
            event.body.request.state === 'VERIFIED_TERMINAL').length !== 2 ||
          request.recoveryDigest !== digest(request.recovery)) {
        fail('PEERIT_SEQ29_LIVE_JOURNAL_RECOVERY', 'recovery is duplicate or lacks two verified CREATE outcomes')
      }
      const requestDigest = digest(request)
      const event = appendEvent(slot, 'recovery', { request, requestDigest })
      return receipt(event, 'RECOVERY_DURABLE_NO_RESEND', {
        attemptId: request.attemptId,
        releaseAttemptKey: request.releaseAttemptKey,
        planHash: request.planHash,
        requestDigest,
        recoveryDigest: request.recoveryDigest
      })
    },

    async finishAttempt (request) {
      const fields = [
        'attemptId', 'releaseAttemptKey', 'planHash', 'state', 'transportInvocations'
      ]
      if (request?.state === 'COMMITTED_CREATE_ONLY') {
        fields.push(
          'executionDigest', 'signedBootstrapHash', 'managementBundleDigest',
          'custodyCommitment'
        )
      }
      if (request?.state === 'QUARANTINED_TERMINAL_NO_RETRY') fields.push('recoveryPersisted')
      exact(request, fields, 'finish request')
      const { events, attempt } = current()
      assertAttemptRequest(request, attempt)
      if (events.some(event => event.kind === 'finish') ||
          !['COMMITTED_CREATE_ONLY', 'QUARANTINED_TERMINAL_NO_RETRY'].includes(request.state)) {
        fail('PEERIT_SEQ29_LIVE_JOURNAL_TERMINAL', 'attempt is already terminal or has an invalid terminal state')
      }
      if (request.state === 'COMMITTED_CREATE_ONLY' && !events.some(event => event.kind === 'recovery')) {
        fail('PEERIT_SEQ29_LIVE_JOURNAL_TERMINAL', 'commit requires durable public recovery first')
      }
      const requestDigest = digest(request)
      const event = appendEvent(slot, 'finish', { request, requestDigest })
      return receipt(event, request.state, {
        attemptId: request.attemptId,
        releaseAttemptKey: request.releaseAttemptKey,
        planHash: request.planHash,
        requestDigest,
        ...(request.executionDigest == null ? {} : { executionDigest: request.executionDigest })
      })
    },

    inspect () {
      const state = current()
      return Object.freeze({
        slot,
        consumed: state.events.length > 0,
        eventCount: state.events.length,
        eventKinds: Object.freeze(state.events.map(event => event.kind)),
        finalEventHash: state.events.at(-1)?.eventHash || null
      })
    }
  })
  FILESYSTEM_JOURNALS.set(journal, Object.freeze({ root, slot, current }))
  return journal
}

export function recoverPeeritSeq29FilesystemFinalResultV1 (input = {}) {
  exact(input, ['journal', 'planHash', 'signedBootstrapHash'],
    'filesystem final-result recovery input')
  const branded = FILESYSTEM_JOURNALS.get(input.journal)
  if (!branded) {
    fail('PEERIT_SEQ29_LIVE_JOURNAL_FINAL_RESULT_UNAVAILABLE',
      'a module-created filesystem journal is required for final-result recovery')
  }
  hex64(input.planHash, 'expected planHash')
  hex64(input.signedBootstrapHash, 'expected signedBootstrapHash')
  const { events, attempt } = branded.current()
  const recoveryEvent = events.find(event => event.kind === 'recovery')
  const finish = events.find(event => event.kind === 'finish')
  const recovery = recoveryEvent?.body?.request?.recovery
  const request = finish?.body?.request
  if (!recovery || !finish || request?.state !== 'COMMITTED_CREATE_ONLY' ||
      request.attemptId !== attempt.attemptId || request.planHash !== attempt.planHash ||
      request.planHash !== input.planHash ||
      request.signedBootstrapHash !== input.signedBootstrapHash ||
      request.executionDigest !== recovery.executionDigest ||
      request.transportInvocations.join('\0') !== recovery.transportInvocations.join('\0')) {
    fail('PEERIT_SEQ29_LIVE_JOURNAL_FINAL_RESULT_UNAVAILABLE',
      'the branded fixed release slot has no exact matching finalized result')
  }
  return Object.freeze({
    schema: 'peerit-limited-inbox-topic-ceremony-result-v1',
    status: 'COMMITTED_CREATE_ONLY',
    planHash: request.planHash,
    attemptId: request.attemptId,
    signedBootstrapHash: request.signedBootstrapHash,
    managementBundleDigest: request.managementBundleDigest,
    custodyCommitment: request.custodyCommitment,
    journalCommitment: finish.eventHash,
    mutationLedger: Object.freeze({
      inboxCreate: 0,
      inboxRenew: 0,
      inboxClose: 0,
      inboxAppend: 0,
      cellPut: 0,
      other: 0
    }),
    recoveredOriginalMutationLedger: Object.freeze({ inboxCreate: 2 })
  })
}

export function recoverPeeritSeq29FilesystemAttemptBindingV1 (input = {}) {
  exact(input, ['journal'], 'filesystem attempt-binding recovery input')
  const branded = FILESYSTEM_JOURNALS.get(input.journal)
  if (!branded) {
    fail('PEERIT_SEQ29_LIVE_JOURNAL_RECOVERY',
      'a module-created filesystem journal is required for attempt binding recovery')
  }
  const { attempt } = branded.current()
  if (!attempt?.request?.plan || !attempt.request.persistedQualification) {
    fail('PEERIT_SEQ29_LIVE_JOURNAL_RECOVERY',
      'the fixed CREATE slot has no sealed plan and source continuity')
  }
  validateBeginRequest(attempt.request)
  const binding = Object.freeze({
    schema: 'peerit-seq29-live-inbox-create-sealed-attempt-binding-v1',
    planHash: attempt.request.planHash
  })
  ATTEMPT_BINDINGS.set(binding, Object.freeze({
    plan: structuredClone(attempt.request.plan),
    persistedQualification: structuredClone(
      attempt.request.persistedQualification),
    planHash: attempt.request.planHash
  }))
  return binding
}

export function verifyPeeritSeq29FilesystemAttemptBindingV1 (binding) {
  const state = ATTEMPT_BINDINGS.get(binding)
  if (!state) {
    fail('PEERIT_SEQ29_LIVE_JOURNAL_RECOVERY',
      'exact sealed CREATE attempt binding is required')
  }
  return Object.freeze({
    plan: structuredClone(state.plan),
    persistedQualification: structuredClone(state.persistedQualification),
    planHash: state.planHash
  })
}
