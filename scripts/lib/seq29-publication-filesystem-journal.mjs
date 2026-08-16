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
import { PEERIT_SEQ29_PUBLICATION_DRILL_ATTEMPT_KEY_V1 } from '../limited-public-inbox-publication-drill.mjs'

const SLOT_DIRECTORY = `release-slot-${PEERIT_SEQ29_PUBLICATION_DRILL_ATTEMPT_KEY_V1}`
const EVENT_SCHEMA = 'peerit-seq29-publication-filesystem-journal-event-v1'
const BYTE_TAG = '$peeritUint8ArrayV1'
const BIGINT_TAG = '$peeritBigIntV1'
const HEX64 = /^[0-9a-f]{64}$/
const JOURNALS = new WeakMap()
const MAX_SEALED_EVENT_BYTES = 4 * 1024 * 1024
const SEALED_IDENTITIES = new Map()
const DIRECTORY_IDENTITIES = new Map()
const JOURNAL_TEST_FAULT = 'PEERIT_SEQ29_PUBLICATION_JOURNAL_TEST_FAULT'

function fail (code, message, details) {
  const error = new Error(message)
  error.code = code
  if (details !== undefined) error.details = details
  throw error
}

function exact (value, fields, field) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).sort().join('\0') !== [...fields].sort().join('\0')) {
    fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_INVALID',
      `${field} has missing or unexpected fields`)
  }
  return value
}

function dense (value, length, field) {
  if (!Array.isArray(value) || value.length !== length ||
      Object.keys(value).join('\0') !== Array.from({ length },
        (_, index) => String(index)).join('\0')) {
    fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_INVALID',
      `${field} must be a dense exact ${length}-element array`)
  }
  return value
}

function hex64 (value, field) {
  if (typeof value !== 'string' || !HEX64.test(value)) {
    fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_INVALID',
      `${field} must be lowercase 32-byte hexadecimal`)
  }
  return value
}

function opaque (value, field) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 512 ||
      !/^[A-Za-z0-9._:-]+$/.test(value)) {
    fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_INVALID',
      `${field} is not a bounded opaque identifier`)
  }
  return value
}

function digest (value) {
  return createHash('sha256')
    .update(canonicalPeeritLimitedPublicInboxJsonV1(value)).digest('hex')
}

function encodeJson (value) {
  if (value instanceof Uint8Array) return { [BYTE_TAG]: Buffer.from(value).toString('hex') }
  if (typeof value === 'bigint') return { [BIGINT_TAG]: String(value) }
  if (Array.isArray(value)) return value.map(encodeJson)
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, child]) =>
      [key, encodeJson(child)]))
  }
  return value
}

function decodeJson (value) {
  if (Array.isArray(value)) return value.map(decodeJson)
  if (value && typeof value === 'object') {
    const keys = Object.keys(value)
    if (keys.length === 1 && keys[0] === BYTE_TAG &&
        typeof value[BYTE_TAG] === 'string' &&
        /^(?:[0-9a-f]{2})*$/.test(value[BYTE_TAG])) {
      return new Uint8Array(Buffer.from(value[BYTE_TAG], 'hex'))
    }
    if (keys.length === 1 && keys[0] === BIGINT_TAG &&
        /^(?:0|[1-9][0-9]*)$/.test(String(value[BIGINT_TAG]))) {
      return BigInt(value[BIGINT_TAG])
    }
    return Object.fromEntries(Object.entries(value).map(([key, child]) =>
      [key, decodeJson(child)]))
  }
  return value
}

function prettyBytes (value) {
  return Buffer.from(JSON.stringify(encodeJson(value), null, 2) + '\n')
}

function assertOwned (metadata, field) {
  if (typeof process.getuid === 'function' && metadata.uid !== process.getuid()) {
    fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_PERMISSIONS',
      `${field} is not owned by the current operator`)
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
    fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_IO_FAILED',
      'could not inspect an authenticated publication journal directory')
  }
  if (!named.isDirectory() || named.isSymbolicLink()) {
    fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_PERMISSIONS',
      'publication journal directory is not a real directory')
  }
  assertOwned(named, 'publication journal directory')
  const identityKey = resolve(path)
  const known = DIRECTORY_IDENTITIES.get(identityKey)
  if (known && !matchesDirectoryIdentity(known, named)) {
    fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_PERMISSIONS',
      'publication journal directory changed its authenticated identity')
  }
  let descriptor
  let primary
  try {
    descriptor = openSync(path, constants.O_RDONLY |
      (constants.O_DIRECTORY || 0) | (constants.O_NOFOLLOW || 0))
    const opened = fstatSync(descriptor)
    if (!sameDirectoryIdentity(named, opened)) {
      fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_PERMISSIONS',
        'publication journal directory changed identity before authenticated open')
    }
    assertOwned(opened, 'opened publication journal directory')
    if (synchronize) fsyncSync(descriptor)
    const after = fstatSync(descriptor)
    const namedAfter = lstatSync(path)
    if (!sameDirectoryIdentity(opened, after) ||
        !sameDirectoryIdentity(opened, namedAfter)) {
      fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_PERMISSIONS',
        'publication journal directory changed identity during authenticated access')
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
          code: 'PEERIT_SEQ29_PUBLICATION_JOURNAL_IO_FAILED'
        })
      }
    }
  }
  if (primary) {
    if (String(primary.code || '').startsWith('PEERIT_SEQ29_')) throw primary
    fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_IO_FAILED',
      'could not durably access an authenticated publication journal directory')
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
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
      fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_PERMISSIONS',
        `${cursor} is not a real directory`)
    }
  }
}

function ensurePrivateRoot (root) {
  assertNoSymlinkParents(dirname(root))
  if (!existsSync(root)) {
    mkdirSync(root, { mode: 0o700 })
    fsyncDirectory(dirname(root))
  }
  const metadata = authenticateDirectory(root)
  if (!metadata.isDirectory() || metadata.isSymbolicLink() ||
      fullMode(metadata) !== 0o700) {
    fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_PERMISSIONS',
      'publication journal root must be a real exact-mode 0700 directory')
  }
  assertOwned(metadata, 'publication journal root')
}

function atomicCreateOnly (target, value) {
  const parent = dirname(target)
  const temporary = join(parent,
    `.${basename(target)}.${process.pid}.${randomBytes(12).toString('hex')}.tmp`)
  const pending = join(parent, `.pending-${basename(target)}`)
  let descriptor
  let pendingDescriptor
  try {
    pendingDescriptor = openSync(pending, 'wx', 0o600)
    writeFileSync(pendingDescriptor,
      Buffer.from('peerit-seq29-publication-journal-pending-v1\n'))
    fsyncSync(pendingDescriptor)
    closeSync(pendingDescriptor)
    pendingDescriptor = undefined
    fsyncDirectory(parent)
    descriptor = openSync(temporary, 'wx', 0o600)
    const opened = fstatSync(descriptor)
    if (!opened.isFile() || opened.nlink !== 1 || fullMode(opened) !== 0o600) {
      fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_IO_FAILED',
        'temporary journal record is not an exact private single-link file')
    }
    writeFileSync(descriptor, prettyBytes(value))
    fsyncSync(descriptor)
    closeSync(descriptor)
    descriptor = undefined
    if (process.env[JOURNAL_TEST_FAULT] === 'EVENT_CLOSE_UNCERTAIN') {
      fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_IO_FAILED',
        'publication journal event close durability is uncertain')
    }
    chmodSync(temporary, 0o600)
    linkSync(temporary, target)
    unlinkSync(temporary)
    const sealed = lstatSync(target)
    if (!sealed.isFile() || sealed.isSymbolicLink() || sealed.nlink !== 1 ||
        fullMode(sealed) !== 0o600) {
      fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_IO_FAILED',
        'sealed journal record is not an exact private single-link file')
    }
    assertOwned(sealed, 'sealed publication journal record')
    if (process.env[JOURNAL_TEST_FAULT] ===
        'POST_LINK_DIRECTORY_SYNC_UNCERTAIN') {
      fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_IO_FAILED',
        'publication journal directory durability is uncertain after event link')
    }
    fsyncDirectory(parent)
    unlinkSync(pending)
    fsyncDirectory(parent)
  } catch (cause) {
    fail(cause?.code === 'EEXIST'
      ? 'PEERIT_SEQ29_PUBLICATION_JOURNAL_CONCURRENT'
      : 'PEERIT_SEQ29_PUBLICATION_JOURNAL_IO_FAILED',
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
    fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_CORRUPT',
      `${basename(path)} changed its sealed inode identity`)
  }
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1 ||
      fullMode(metadata) !== 0o600) {
    fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_CORRUPT',
      `${basename(path)} is not an exact private sealed file`)
  }
  assertOwned(metadata, 'sealed publication journal record')
  if (metadata.size > MAX_SEALED_EVENT_BYTES) {
    fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_CORRUPT',
      `${basename(path)} exceeds the sealed event size limit`)
  }
  let descriptor
  try {
    descriptor = openSync(path,
      constants.O_RDONLY | (constants.O_NOFOLLOW || 0))
  } catch {
    fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_CORRUPT',
      `${basename(path)} could not be opened as a sealed file`)
  }
  let bytes
  try {
    const opened = fstatSync(descriptor)
    if (!opened.isFile() || opened.nlink !== 1 ||
        fullMode(opened) !== 0o600 || opened.dev !== metadata.dev ||
        opened.ino !== metadata.ino || opened.size !== metadata.size) {
      fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_CORRUPT',
        `${basename(path)} changed identity before sealed readback`)
    }
    assertOwned(opened, 'opened sealed publication journal record')
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
      fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_CORRUPT',
        `${basename(path)} changed identity during sealed readback`)
    }
  } finally {
    try { closeSync(descriptor) } catch {
      fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_IO_FAILED',
        'sealed publication journal descriptor could not be closed')
    }
  }
  SEALED_IDENTITIES.set(identityKey, Object.freeze({
    dev: metadata.dev,
    ino: metadata.ino
  }))
  let encoded
  try { encoded = JSON.parse(bytes.toString('utf8')) } catch {
    fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_CORRUPT',
      `${basename(path)} is not JSON`)
  }
  const value = decodeJson(encoded)
  if (!prettyBytes(value).equals(bytes)) {
    fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_CORRUPT',
      `${basename(path)} is not canonical sealed JSON`)
  }
  const event = exact(value, [
    'schema', 'version', 'kind', 'sequence', 'body',
    'previousEventHash', 'eventHash'
  ], 'publication journal event')
  const unsigned = { ...event }
  delete unsigned.eventHash
  if (event.schema !== EVENT_SCHEMA || event.version !== 1 ||
      !Number.isSafeInteger(event.sequence) || event.sequence < 0 ||
      !HEX64.test(event.eventHash) || event.eventHash !== digest(unsigned)) {
    fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_CORRUPT',
      `${basename(path)} has an invalid identity or event hash`)
  }
  return event
}

function eventFile (slot, sequence, kind) {
  return join(slot, `${String(sequence).padStart(4, '0')}-${kind}.json`)
}

function validateOperationManifest (manifest) {
  dense(manifest, 4, 'operationManifest')
  const match = manifest.map((operation, index) => {
    const expected = index < 2 ? 'CELL.PUT' : 'INBOX.APPEND'
    const parsed = new RegExp(`^${expected.replace('.', '\\.')}:([a-z][a-z0-9-]{0,63})$`)
      .exec(operation)
    if (!parsed) {
      fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_SCOPE',
        'operationManifest differs from exactly two CELL.PUT then two INBOX.APPEND')
    }
    return parsed[1]
  })
  if (match[0] === match[1] || match[0] !== match[2] || match[1] !== match[3]) {
    fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_SCOPE',
      'operationManifest must bind two distinct relays in the same PUT/APPEND order')
  }
  return manifest
}

function validateBegin (request) {
  exact(request, [
    'schema', 'releaseAttemptKey', 'releaseIdentityDigest', 'operationManifest'
  ], 'publication begin request')
  if (request.schema !== 'peerit-seq29-bounded-publication-attempt-v1' ||
      request.releaseAttemptKey !== PEERIT_SEQ29_PUBLICATION_DRILL_ATTEMPT_KEY_V1) {
    fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_SCOPE',
      'begin request is outside the fixed Seq29 publication slot')
  }
  hex64(request.releaseIdentityDigest, 'releaseIdentityDigest')
  validateOperationManifest(request.operationManifest)
  return request
}

function assertAttempt (request, attempt) {
  if (request.attemptId !== attempt.attemptId ||
      request.releaseAttemptKey !== attempt.releaseAttemptKey ||
      request.releaseIdentityDigest !== attempt.releaseIdentityDigest) {
    fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_ATTEMPT_MISMATCH',
      'journal request differs from the fixed publication attempt')
  }
}

function validateClaim (request, attempt, index) {
  exact(request, [
    'attemptId', 'releaseAttemptKey', 'releaseIdentityDigest',
    'operationIndex', 'operationKey', 'requestSha256', 'requestCommitment'
  ], `claim ${index}`)
  assertAttempt(request, attempt)
  if (request.operationIndex !== index ||
      request.operationKey !== attempt.request.operationManifest[index]) {
    fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_SCOPE',
      `claim ${index} differs from its exact operation slot`)
  }
  hex64(request.requestSha256, `claim ${index} requestSha256`)
  hex64(request.requestCommitment, `claim ${index} requestCommitment`)
  return request
}

function validateOutcome (request, attempt, claim) {
  const fields = [
    'attemptId', 'releaseAttemptKey', 'releaseIdentityDigest',
    'operationKey', 'requestSha256', 'state'
  ]
  if (request?.state === 'VERIFIED_TERMINAL') fields.push('resultSha256')
  exact(request, fields, 'publication outcome')
  assertAttempt(request, attempt)
  if (request.operationKey !== claim.operationKey ||
      request.requestSha256 !== claim.requestSha256 ||
      !['VERIFIED_TERMINAL', 'AMBIGUOUS_TERMINAL'].includes(request.state)) {
    fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_OUTCOME',
      'outcome is not an exact terminal result for its claim')
  }
  if (request.state === 'VERIFIED_TERMINAL') {
    hex64(request.resultSha256, 'resultSha256')
  }
  return request
}

function validateRecovery (request, attempt) {
  exact(request, [
    'attemptId', 'releaseAttemptKey', 'releaseIdentityDigest',
    'recovery', 'recoveryDigest'
  ], 'publication recovery request')
  assertAttempt(request, attempt)
  hex64(request.recoveryDigest, 'recoveryDigest')
  if (request.recoveryDigest !== digest(request.recovery)) {
    fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_RECOVERY',
      'recoveryDigest does not bind the exact recovery')
  }
  const recovery = exact(request.recovery, [
    'schema', 'phase', 'attemptId', 'releaseIdentityDigest', 'inputDigest',
    'signingRequest', 'signingRequestDigest', 'puts'
  ], 'publication recovery')
  if (recovery.schema !== 'peerit-seq29-bounded-publication-recovery-v1' ||
      !['PUTS_PREPARED', 'PUTS_VERIFIED_AWAITING_SIGNED_ANNOUNCEMENT',
        'SIGNED_ANNOUNCEMENT_ACCEPTED', 'APPENDS_IN_PROGRESS'].includes(recovery.phase) ||
      recovery.attemptId !== attempt.attemptId ||
      recovery.releaseIdentityDigest !== attempt.releaseIdentityDigest) {
    fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_RECOVERY',
      'recovery differs from its fixed publication attempt')
  }
  hex64(recovery.inputDigest, 'recovery inputDigest')
  dense(recovery.puts, 2, 'recovery puts')
  if ((recovery.signingRequest == null) !== (recovery.signingRequestDigest == null)) {
    fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_RECOVERY',
      'recovery signing request and digest must be present together')
  }
  if (recovery.signingRequestDigest != null) {
    hex64(recovery.signingRequestDigest, 'recovery signingRequestDigest')
    if (digest(recovery.signingRequest) !== recovery.signingRequestDigest) {
      fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_RECOVERY',
        'recovery signing request digest is invalid')
    }
  }
  const relayIds = attempt.request.operationManifest.slice(0, 2)
    .map(operation => operation.slice('CELL.PUT:'.length))
  if (recovery.puts.map(row => row?.relayId).join('\0') !== relayIds.join('\0')) {
    fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_RECOVERY',
      'recovery PUT rows differ from the fixed relay order')
  }
  return recovery
}

function validateDispatches (dispatches, attempt, claims, committed) {
  const claimedCount = claims.length
  dense(dispatches, committed ? 4 : claimedCount, 'finish dispatches')
  for (let index = 0; index < dispatches.length; index++) {
    const row = exact(dispatches[index], [
      'family', 'operation', 'relayId', 'operationKey',
      'requestSha256', 'requestCommitment'
    ], `finish dispatch ${index}`)
    const operationKey = attempt.request.operationManifest[index]
    const [familyOperation, relayId] = operationKey.split(':')
    const [family, operation] = familyOperation.split('.')
    const claim = claims[index]
    if (row.family !== family || row.operation !== operation ||
        row.relayId !== relayId || row.operationKey !== operationKey ||
        row.requestSha256 !== claim?.requestSha256 ||
        row.requestCommitment !== claim?.requestCommitment) {
      fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_TERMINAL',
        `finish dispatch ${index} differs from the fixed operation manifest`)
    }
    hex64(row.requestSha256, `finish dispatch ${index} requestSha256`)
    hex64(row.requestCommitment, `finish dispatch ${index} requestCommitment`)
  }
}

function validateFinish (request, attempt, claims, outcomes) {
  exact(request, [
    'attemptId', 'releaseAttemptKey', 'releaseIdentityDigest',
    'executionDigest', 'state', 'dispatches'
  ], 'publication finish request')
  assertAttempt(request, attempt)
  hex64(request.executionDigest, 'finish executionDigest')
  if (!['COMMITTED_EXACT_BUDGET', 'TERMINAL_NO_RETRY'].includes(request.state)) {
    fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_TERMINAL',
      'finish state is outside the exact publication terminal set')
  }
  const committed = request.state === 'COMMITTED_EXACT_BUDGET'
  if (committed && (claims.length !== 4 || outcomes.length !== 4 ||
      outcomes.some(outcome => outcome.state !== 'VERIFIED_TERMINAL'))) {
    fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_TERMINAL',
      'committed publication lacks four durably verified exact outcomes')
  }
  validateDispatches(request.dispatches, attempt, claims, committed)
  return request
}

function validateBody (event, field) {
  const body = exact(event.body, ['request', 'requestDigest'], `${field} body`)
  if (body.requestDigest !== digest(body.request)) {
    fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_CORRUPT',
      `${field} requestDigest does not bind its request`)
  }
  return body
}

function replay (events) {
  if (events.length === 0) return Object.freeze({ attempt: null, claims: [], outcomes: [], recoveries: [], finish: null })
  if (events[0].kind !== 'begin') {
    fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_CORRUPT',
      'publication journal does not begin with its fixed begin event')
  }
  const begin = exact(events[0].body, [
    'attemptId', 'releaseAttemptKey', 'releaseIdentityDigest',
    'requestDigest', 'request'
  ], 'publication begin body')
  opaque(begin.attemptId, 'attemptId')
  validateBegin(begin.request)
  if (begin.releaseAttemptKey !== begin.request.releaseAttemptKey ||
      begin.releaseIdentityDigest !== begin.request.releaseIdentityDigest ||
      begin.requestDigest !== digest(begin.request)) {
    fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_CORRUPT',
      'publication begin body does not bind its request')
  }
  const claims = []
  const outcomes = []
  const recoveries = []
  let finish = null
  for (const event of events.slice(1)) {
    if (finish) {
      fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_CORRUPT',
        'publication journal contains a post-terminal event')
    }
    if (event.kind === 'claim') {
      const claim = validateClaim(validateBody(event, 'claim').request,
        begin, claims.length)
      if (claims.length > 0 && outcomes.length !== claims.length) {
        fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_ORDER',
          'a new mutation cannot follow an unresolved durable claim')
      }
      if (outcomes.some(outcome => outcome.state !== 'VERIFIED_TERMINAL')) {
        fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_ORDER',
          'no mutation may follow a nonverified terminal outcome')
      }
      claims.push(claim)
    } else if (event.kind === 'outcome') {
      if (outcomes.length >= claims.length) {
        fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_CORRUPT',
          'publication outcome is unclaimed or duplicate')
      }
      outcomes.push(validateOutcome(validateBody(event, 'outcome').request,
        begin, claims[outcomes.length]))
    } else if (event.kind === 'recovery') {
      if (claims.length !== outcomes.length ||
          outcomes.some(outcome => outcome.state !== 'VERIFIED_TERMINAL')) {
        fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_RECOVERY',
          'recovery cannot cover an unresolved or nonverified mutation')
      }
      recoveries.push(Object.freeze({
        event,
        value: validateRecovery(validateBody(event, 'recovery').request, begin)
      }))
    } else if (event.kind === 'finish') {
      finish = Object.freeze({
        event,
        value: validateFinish(validateBody(event, 'finish').request,
          begin, claims, outcomes)
      })
    } else {
      fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_CORRUPT',
        `publication journal contains unknown event kind ${event.kind}`)
    }
  }
  return Object.freeze({ attempt: begin, claims, outcomes, recoveries, finish })
}

function loadEvents (slot) {
  const metadata = authenticateDirectory(slot)
  if (!metadata.isDirectory() || metadata.isSymbolicLink() ||
      fullMode(metadata) !== 0o700) {
    fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_PERMISSIONS',
      'fixed publication slot must be a real exact-mode 0700 directory')
  }
  assertOwned(metadata, 'fixed publication slot')
  const names = readdirSync(slot).sort()
  authenticateDirectory(slot)
  if (names.some(name => !/^[0-9]{4}-(?:begin|claim|outcome|recovery|finish)\.json$/.test(name))) {
    fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_CORRUPT',
      'fixed publication slot contains an unexpected entry')
  }
  const events = names.map(name => readSealed(join(slot, name)))
  for (let index = 0; index < events.length; index++) {
    if (events[index].sequence !== index ||
        names[index] !== basename(eventFile(slot, index, events[index].kind)) ||
        events[index].previousEventHash !== (index === 0
          ? null
          : events[index - 1].eventHash)) {
      fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_CORRUPT',
        'publication journal filename, sequence, or hash chain is discontinuous')
    }
  }
  replay(events)
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
    previousEventHash: sequence === 0 ? null : events.at(-1).eventHash
  }
  const event = { ...unsigned, eventHash: digest(unsigned) }
  replay([...events, event])
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

export function createPeeritSeq29PublicationFilesystemJournalV1 (input = {}) {
  exact(input, ['directory'], 'publication journal factory input')
  const root = resolve(String(input.directory || ''))
  ensurePrivateRoot(root)
  const slot = join(root, SLOT_DIRECTORY)

  function current () {
    if (!existsSync(slot)) return { events: [], state: replay([]) }
    const events = loadEvents(slot)
    if (events.length === 0) {
      fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_NO_RETRY',
        'fixed publication slot is consumed without a complete begin seal; automatic retry is forbidden')
    }
    return { events, state: replay(events) }
  }

  const journal = Object.freeze({
    async beginAttempt (request) {
      validateBegin(request)
      const requestDigest = digest(request)
      if (existsSync(slot)) {
        const { events, state } = current()
        const attempt = state.attempt
        if (attempt.requestDigest !== requestDigest) {
          fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_SLOT_CONSUMED',
            'the fixed Seq29 publication slot is bound to another release identity')
        }
        if (state.finish || state.outcomes.some(outcome =>
          outcome.state !== 'VERIFIED_TERMINAL') ||
          state.claims.length !== state.outcomes.length) {
          fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_NO_RETRY',
            'the fixed publication attempt is terminal or has an ambiguous claimed mutation; automatic retry is forbidden')
        }
        const recovery = state.recoveries.at(-1)
        const lastOutcomeSequence = events.filter(event => event.kind === 'outcome')
          .at(-1)?.sequence ?? -1
        if (!recovery || recovery.event.sequence < lastOutcomeSequence) {
          fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_NO_RETRY',
            'the fixed publication attempt has no post-mutation recovery seal; automatic retry is forbidden')
        }
        return receipt(recovery.event, 'RECOVERY_AVAILABLE_NO_RESEND', {
          attemptId: attempt.attemptId,
          releaseAttemptKey: attempt.releaseAttemptKey,
          releaseIdentityDigest: attempt.releaseIdentityDigest,
          requestDigest: attempt.requestDigest,
          recovery: recovery.value
        })
      }
      try { mkdirSync(slot, { mode: 0o700 }) } catch {
        fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_SLOT_CONSUMED',
          'the fixed publication slot was concurrently consumed')
      }
      fsyncDirectory(root)
      const attemptId = randomBytes(32).toString('hex')
      const event = appendEvent(slot, 'begin', {
        attemptId,
        releaseAttemptKey: request.releaseAttemptKey,
        releaseIdentityDigest: request.releaseIdentityDigest,
        requestDigest,
        request
      })
      return receipt(event, 'CONSUMED_NO_MUTATIONS', {
        attemptId,
        releaseAttemptKey: request.releaseAttemptKey,
        releaseIdentityDigest: request.releaseIdentityDigest,
        requestDigest
      })
    },

    async claimOperation (request) {
      const { state } = current()
      if (!state.attempt || state.finish || state.claims.length >= 4 ||
          state.claims.length !== state.outcomes.length ||
          state.outcomes.some(outcome => outcome.state !== 'VERIFIED_TERMINAL')) {
        fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_NO_RETRY',
          'publication claim is duplicate, terminal, unresolved, or outside the exact budget')
      }
      validateClaim(request, state.attempt, state.claims.length)
      const requestDigest = digest(request)
      const event = appendEvent(slot, 'claim', { request, requestDigest })
      return receipt(event, 'DISPATCH_CLAIMED', {
        attemptId: request.attemptId,
        releaseAttemptKey: request.releaseAttemptKey,
        releaseIdentityDigest: request.releaseIdentityDigest,
        operationKey: request.operationKey,
        requestDigest
      })
    },

    async recordOutcome (request) {
      const { state } = current()
      if (!state.attempt || state.finish ||
          state.claims.length !== state.outcomes.length + 1) {
        fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_OUTCOME',
          'publication outcome is duplicate, terminal, or unclaimed')
      }
      validateOutcome(request, state.attempt, state.claims.at(-1))
      const requestDigest = digest(request)
      const event = appendEvent(slot, 'outcome', { request, requestDigest })
      return receipt(event, request.state, {
        attemptId: request.attemptId,
        releaseAttemptKey: request.releaseAttemptKey,
        releaseIdentityDigest: request.releaseIdentityDigest,
        operationKey: request.operationKey,
        requestDigest
      })
    },

    async persistRecovery (request) {
      const { state } = current()
      if (!state.attempt || state.finish ||
          state.claims.length !== state.outcomes.length ||
          state.outcomes.some(outcome => outcome.state !== 'VERIFIED_TERMINAL')) {
        fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_RECOVERY',
          'publication recovery cannot cover an unresolved or terminal mutation')
      }
      validateRecovery(request, state.attempt)
      const requestDigest = digest(request)
      const last = state.recoveries.at(-1)
      if (last?.event.body.requestDigest === requestDigest) {
        return receipt(last.event, 'RECOVERY_DURABLE_NO_RESEND', {
          attemptId: request.attemptId,
          releaseAttemptKey: request.releaseAttemptKey,
          releaseIdentityDigest: request.releaseIdentityDigest,
          recoveryDigest: request.recoveryDigest,
          requestDigest
        })
      }
      const event = appendEvent(slot, 'recovery', { request, requestDigest })
      return receipt(event, 'RECOVERY_DURABLE_NO_RESEND', {
        attemptId: request.attemptId,
        releaseAttemptKey: request.releaseAttemptKey,
        releaseIdentityDigest: request.releaseIdentityDigest,
        recoveryDigest: request.recoveryDigest,
        requestDigest
      })
    },

    async finishAttempt (request) {
      const { state } = current()
      if (!state.attempt || state.finish) {
        fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_TERMINAL',
          'publication attempt is absent or already terminal')
      }
      validateFinish(request, state.attempt, state.claims, state.outcomes)
      const requestDigest = digest(request)
      const event = appendEvent(slot, 'finish', { request, requestDigest })
      return receipt(event, request.state, {
        attemptId: request.attemptId,
        releaseAttemptKey: request.releaseAttemptKey,
        releaseIdentityDigest: request.releaseIdentityDigest,
        executionDigest: request.executionDigest,
        requestDigest
      })
    },

    inspect () {
      const { events, state } = current()
      const unresolvedClaim = state.claims.length !== state.outcomes.length
      const ambiguous = state.outcomes.some(outcome =>
        outcome.state !== 'VERIFIED_TERMINAL')
      return Object.freeze({
        schema: 'peerit-seq29-publication-filesystem-journal-status-v1',
        slot,
        consumed: events.length > 0,
        eventCount: events.length,
        eventKinds: Object.freeze(events.map(event => event.kind)),
        nextOperationIndex: state.claims.length,
        latestRecoveryPhase: state.recoveries.at(-1)?.value.phase || null,
        terminalState: state.finish?.value.state || null,
        noAutomaticRetry: Boolean(state.finish || unresolvedClaim || ambiguous),
        finalEventHash: events.at(-1)?.eventHash || null
      })
    }
  })
  JOURNALS.set(journal, Object.freeze({ root, slot, current }))
  return journal
}

export function recoverPeeritSeq29PublicationFilesystemResultV1 (input = {}) {
  exact(input, ['journal'], 'publication final-result recovery input')
  const branded = JOURNALS.get(input.journal)
  if (!branded) {
    fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_RESULT_UNAVAILABLE',
      'a module-created publication filesystem journal is required')
  }
  const { state } = branded.current()
  if (!state.finish) {
    fail('PEERIT_SEQ29_PUBLICATION_JOURNAL_RESULT_UNAVAILABLE',
      'publication journal has no durable terminal result')
  }
  const verifiedClaims = state.claims.filter((claim, index) =>
    state.outcomes[index]?.state === 'VERIFIED_TERMINAL')
  const ambiguousClaims = state.claims.filter((claim, index) =>
    state.outcomes[index]?.state !== 'VERIFIED_TERMINAL')
  return Object.freeze({
    schema: 'peerit-seq29-publication-filesystem-result-v1',
    status: state.finish.value.state,
    attemptId: state.attempt.attemptId,
    releaseIdentityDigest: state.attempt.releaseIdentityDigest,
    executionDigest: state.finish.value.executionDigest,
    mutationLedger: Object.freeze({
      cellPut: verifiedClaims.filter(row => row.operationKey.startsWith('CELL.PUT:')).length,
      inboxAppend: verifiedClaims.filter(row => row.operationKey.startsWith('INBOX.APPEND:')).length,
      inboxCreate: 0,
      inboxRenew: 0,
      inboxClose: 0,
      other: 0
    }),
    claimedDispatches: state.claims.length,
    verifiedMutations: verifiedClaims.length,
    ambiguousDispatches: ambiguousClaims.length,
    automaticRetries: 0,
    journalCommitment: state.finish.event.eventHash
  })
}
