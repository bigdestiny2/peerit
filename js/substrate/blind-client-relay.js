// blind-client-relay.js — adapter from PeeritSubstrateSync's opaque delivery
// target to the current @hiverelay/blind-client Cell APIs.
//
// The base package is injected rather than statically imported because its draft
// ABI is not yet a published Peerit dependency. Authenticated writer/control
// helpers live at @hiverelay/blind-client/control and are loaded only inside an
// explicit delivery. This keeps the ordinary lurker graph on the small base/data
// plane while preserving the exact write composition:
// createCellReplica -> persist capabilities -> direct request -> verify result.
// The persistence callback is mandatory so no network send can occur before the
// generated read/write capabilities are durably retained.

const CONTROL_MODULE = '@hiverelay/blind-client/control'
// Frozen BlindErrorV1 ABI value. Keep this local to the adapter until the
// browser-safe base namespace exports the protocol registry directly.
const HIVERELAY_BLIND_ERROR_NOT_FOUND = 13

function bytes (value, field) {
  if (value instanceof Uint8Array) return value
  if (value instanceof ArrayBuffer) return new Uint8Array(value)
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
  throw new TypeError(`${field} must be bytes`)
}

function equalBytes (left, right) {
  try {
    const a = bytes(left, 'left bytes')
    const b = bytes(right, 'right bytes')
    if (a.byteLength !== b.byteLength) return false
    let difference = 0
    for (let index = 0; index < a.byteLength; index++) difference |= a[index] ^ b[index]
    return difference === 0
  } catch {
    return false
  }
}

function terminalError (code, message) {
  const error = new Error(message)
  error.code = code
  error.terminal = true
  return error
}

function hex (value) {
  const input = bytes(value, 'relayPublicKey')
  let output = ''
  for (const byte of input) output += byte.toString(16).padStart(2, '0')
  return output
}

function fixedHex (value, field) {
  const input = bytes(value, field)
  if (input.byteLength !== 32) throw new TypeError(`${field} must be 32 bytes`)
  return hex(input)
}

function integer (value, field) {
  if (!Number.isSafeInteger(value) || value < 0) throw new TypeError(`${field} must be a non-negative safe integer`)
  return value
}

function oneHot (value, field) {
  value = integer(value, field)
  if (value < 1 || value > 0xffff || (value & (value - 1)) !== 0) {
    throw new TypeError(`${field} must be one exact support bit`)
  }
  return value
}

function targetContext (value, relayPublicKey) {
  if (!value || typeof value !== 'object') throw new TypeError('verified endpoint context is required')
  const context = Object.freeze({
    relayPublicKey: fixedHex(value.relayPublicKey, 'endpointContext.relayPublicKey'),
    storeId: fixedHex(value.storeId, 'endpointContext.storeId'),
    continuityRoot: fixedHex(value.continuityRoot, 'endpointContext.continuityRoot'),
    durabilityContinuityHash: fixedHex(value.durabilityContinuityHash, 'endpointContext.durabilityContinuityHash'),
    descriptorHash: fixedHex(value.descriptorHash, 'endpointContext.descriptorHash'),
    endpointId: integer(value.endpointId, 'endpointContext.endpointId'),
    familyId: integer(value.familyId, 'endpointContext.familyId'),
    operationId: integer(value.operationId, 'endpointContext.operationId'),
    transportId: integer(value.transportId, 'endpointContext.transportId'),
    transportSupportBit: oneHot(value.transportSupportBit, 'endpointContext.transportSupportBit'),
    privacyProfileBit: integer(value.privacyProfileBit, 'endpointContext.privacyProfileBit'),
    durabilityProfileId: integer(value.durabilityProfileId, 'endpointContext.durabilityProfileId')
  })
  if (context.relayPublicKey !== hex(relayPublicKey)) {
    throw new TypeError('endpoint context relay key does not match relayPublicKey')
  }
  return context
}

function targetIdFor (context) {
  return [
    'cell-v1', context.relayPublicKey, context.storeId, context.continuityRoot,
    context.durabilityContinuityHash, context.endpointId, context.familyId,
    context.operationId, context.transportId, context.transportSupportBit,
    context.privacyProfileBit
  ].join(':')
}

function contextFingerprint (context) {
  return [targetIdFor(context), context.descriptorHash, context.durabilityProfileId].join(':')
}

function linkedDescriptorContext (left, right) {
  if (!left || !right || typeof left !== 'object' || typeof right !== 'object') return false
  const leftComparable = { ...left }
  const rightComparable = { ...right }
  delete leftComparable.descriptorHash
  delete rightComparable.descriptorHash
  const leftKeys = Object.keys(leftComparable).sort()
  const rightKeys = Object.keys(rightComparable).sort()
  return leftKeys.length === rightKeys.length &&
    leftKeys.every((key, index) => key === rightKeys[index] && leftComparable[key] === rightComparable[key])
}

function pairedReadContext (value, relayPublicKey, writeContext) {
  const readContext = targetContext(value, relayPublicKey)
  for (const field of [
    'relayPublicKey', 'storeId', 'continuityRoot', 'durabilityContinuityHash',
    'descriptorHash'
  ]) {
    if (readContext[field] !== writeContext[field]) {
      throw new TypeError(`read endpoint ${field} does not match the qualified Cell PUT endpoint`)
    }
  }
  for (const field of [
    'endpointId', 'familyId', 'transportId', 'transportSupportBit',
    'privacyProfileBit', 'durabilityProfileId'
  ]) {
    if (readContext[field] !== writeContext[field]) {
      throw new TypeError(`read endpoint ${field} does not match the qualified Cell PUT endpoint`)
    }
  }
  if (readContext.operationId === writeContext.operationId) {
    throw new TypeError('read endpoint must be qualified for a distinct Cell GET operation')
  }
  return readContext
}

function persistedReplicaPayload (stored, publication, targetId, qualifiedContext, qualifiedReadContext = null) {
  if (stored == null) return null
  const payload = stored && stored.payload
  const legacyReadContext = qualifiedReadContext != null && payload &&
    payload.readTargetContext == null && (payload.stage === 1 || payload.stage === 2)
  const readContextMatches = qualifiedReadContext == null
    ? payload && payload.readTargetContext == null
    : payload && payload.readTargetContext &&
      (contextFingerprint(payload.readTargetContext) === contextFingerprint(qualifiedReadContext) ||
        linkedDescriptorContext(payload.readTargetContext, qualifiedReadContext))
  if (!payload || typeof payload !== 'object' ||
      payload.intentId !== publication.intentId ||
      payload.logicalId !== publication.logicalId ||
      payload.innerCodec !== publication.innerCodec ||
      payload.innerLength !== publication.innerLength ||
      payload.sizeClass !== publication.sizeClass ||
      !equalBytes(payload.logicalHash, publication.logicalHash) ||
      !equalBytes(payload.encodingCommitment, publication.encodingCommitment) ||
      String(payload.targetId || '').toLowerCase() !== targetId ||
      !payload.targetContext ||
      (contextFingerprint(payload.targetContext) !== contextFingerprint(qualifiedContext) &&
        !linkedDescriptorContext(payload.targetContext, qualifiedContext)) ||
      (!readContextMatches && !legacyReadContext) ||
      !payload.prepared || typeof payload.prepared !== 'object' ||
      (payload.stage !== 1 && payload.stage !== 2 && payload.stage !== 3)) {
    const error = new Error('encrypted persisted Cell replica does not match this exact intent target')
    error.code = 'HIVERELAY_PERSISTED_REPLICA_MISMATCH'
    error.terminal = true
    throw error
  }
  return Object.freeze({ stored, payload })
}

function persistedAcknowledgement (record, publication, requireReadback = false) {
  if (!record) return null
  if (record.payload.stage === 3) {
    if (typeof record.stored.evidenceRef !== 'string' || !record.stored.evidenceRef ||
        !record.payload.readCapability || !record.payload.readbackResultBytes ||
        !record.payload.readbackRequestCommitment || !record.payload.readbackInnerBytes ||
        !equalBytes(record.payload.readbackInnerBytes, publication.innerBytes) ||
        !equalBytes(record.payload.logicalHash, publication.logicalHash) ||
        !equalBytes(record.payload.encodingCommitment, publication.encodingCommitment)) {
      throw terminalError('HIVERELAY_PERSISTED_READBACK_MISMATCH',
        'encrypted persisted Cell readback does not reproduce this exact VNext envelope')
    }
    return Object.freeze({
      ok: true,
      acknowledged: true,
      readbackVerified: true,
      policyDurable: false,
      evidenceRef: record.stored.evidenceRef,
      readbackEvidenceRevision: record.stored.revision,
      resultBytes: record.payload.resultBytes || record.payload.readbackResultBytes,
      readCapability: record.payload.readCapability
    })
  }
  if (requireReadback || record.payload.stage !== 2 ||
      typeof record.stored.evidenceRef !== 'string' || !record.stored.evidenceRef ||
      !record.payload.resultBytes || !record.payload.readCapability) return null
  return Object.freeze({
    ok: true,
    acknowledged: true,
    readbackVerified: false,
    policyDurable: false,
    evidenceRef: record.stored.evidenceRef,
    resultBytes: record.payload.resultBytes,
    readCapability: record.payload.readCapability
  })
}

function publicationCellEnvelope (publication) {
  if (!publication || typeof publication !== 'object') {
    throw terminalError('PEERIT_SUBSTRATE_ENVELOPE_REQUIRED', 'VNext Cell delivery requires a verified inner envelope.')
  }
  let innerBytes
  try { innerBytes = bytes(publication.innerBytes, 'innerBytes') } catch (cause) {
    throw terminalError('PEERIT_SUBSTRATE_ENVELOPE_INVALID', 'VNext Cell delivery bytes are invalid.')
  }
  let validCommitments = false
  try {
    validCommitments = bytes(publication.logicalHash, 'logicalHash').byteLength === 32 &&
      bytes(publication.encodingCommitment, 'encodingCommitment').byteLength === 32
  } catch {}
  if (publication.innerCodec !== 334 || !Number.isSafeInteger(publication.innerLength) ||
      publication.innerLength !== innerBytes.byteLength || !Number.isSafeInteger(publication.sizeClass) ||
      publication.sizeClass < 1 || publication.sizeClass > 5 ||
      !validCommitments) {
    throw terminalError('PEERIT_SUBSTRATE_ENVELOPE_INVALID', 'VNext Cell delivery envelope metadata is invalid.')
  }
  return Object.freeze({ innerBytes: new Uint8Array(innerBytes), sizeClass: publication.sizeClass })
}

function retryableNotSent (cause) {
  const error = new Error((cause && cause.message) || 'blind Cell delivery stopped before network send')
  error.code = 'RETRYABLE_NOT_SENT'
  error.definitelyNotProcessed = true
  error.cause = cause
  return error
}

function validSignal (value, field) {
  if (value == null) return null
  if (typeof value !== 'object' || typeof value.aborted !== 'boolean' ||
      typeof value.addEventListener !== 'function' || typeof value.removeEventListener !== 'function') {
    throw new TypeError(`${field} must be an AbortSignal`)
  }
  return value
}

function throwIfAborted (signal) {
  if (!signal || !signal.aborted) return
  if (typeof signal.throwIfAborted === 'function') signal.throwIfAborted()
  throw signal.reason || Object.assign(new Error('blind Cell delivery was aborted'), { name: 'AbortError' })
}

function attemptTransportContext (installationSignal, configuredTimeoutMillis, context = {}) {
  const parent = validSignal(installationSignal, 'relay installation signal')
  const attempt = validSignal(context && context.signal, 'delivery attempt signal')
  let signal = attempt || parent
  let close = () => {}
  if (parent && attempt && parent !== attempt) {
    const controller = new AbortController()
    const abortFrom = source => controller.abort(source.reason)
    const fromParent = () => abortFrom(parent)
    const fromAttempt = () => abortFrom(attempt)
    if (parent.aborted) fromParent()
    else if (attempt.aborted) fromAttempt()
    else {
      parent.addEventListener('abort', fromParent, { once: true })
      attempt.addEventListener('abort', fromAttempt, { once: true })
      close = () => {
        parent.removeEventListener('abort', fromParent)
        attempt.removeEventListener('abort', fromAttempt)
      }
    }
    signal = controller.signal
  }
  const attemptTimeout = context && context.timeoutMs
  if (attemptTimeout != null && (!Number.isSafeInteger(attemptTimeout) || attemptTimeout < 1)) {
    close()
    throw new TypeError('delivery attempt timeoutMs must be a positive safe integer')
  }
  if (configuredTimeoutMillis != null &&
      (!Number.isSafeInteger(configuredTimeoutMillis) || configuredTimeoutMillis < 1)) {
    close()
    throw new TypeError('configured timeoutMillis must be a positive safe integer')
  }
  const timeoutMillis = attemptTimeout == null
    ? configuredTimeoutMillis
    : configuredTimeoutMillis == null ? attemptTimeout : Math.min(attemptTimeout, configuredTimeoutMillis)
  return { signal, timeoutMillis, close }
}

export function createBlindCellRelay (options = {}) {
  const api = options.blindClient
  if (!api || typeof api.createCellReplica !== 'function' ||
      (typeof api.BlindDirectHttpClient !== 'function' && !options.httpClient)) {
    throw new TypeError('current @hiverelay/blind-client base namespace is required')
  }
  if (typeof options.persistPreparedReplica !== 'function') {
    throw new TypeError('persistPreparedReplica is required before blind Cell delivery')
  }
  if (typeof options.persistVerifiedResult !== 'function') {
    throw new TypeError('persistVerifiedResult is required before a blind Cell acknowledgement can count')
  }
  const readbackInputs = [
    options.readEndpoint,
    options.readEndpointContext,
    options.persistVerifiedReadback
  ]
  const readbackConfigured = readbackInputs.some(value => value != null)
  if (readbackConfigured && readbackInputs.some(value => value == null)) {
    throw new TypeError('readEndpoint, readEndpointContext, and persistVerifiedReadback must be configured together')
  }
  if (readbackConfigured && typeof options.persistVerifiedReadback !== 'function') {
    throw new TypeError('persistVerifiedReadback must durably commit authenticated Cell GET evidence')
  }
  const relayPublicKey = bytes(options.relayPublicKey, 'relayPublicKey')
  if (relayPublicKey.byteLength !== 32) throw new TypeError('relayPublicKey must be 32 bytes')
  const qualifiedContext = targetContext(options.endpointContext, relayPublicKey)
  const qualifiedReadContext = readbackConfigured
    ? pairedReadContext(options.readEndpointContext, relayPublicKey, qualifiedContext)
    : null
  const targetId = targetIdFor(qualifiedContext)
  const canonicalTargetId = String(targetId).toLowerCase()
  const loadPersistedReplica = typeof options.loadPersistedReplica === 'function'
    ? options.loadPersistedReplica
    : null
  if (readbackConfigured && !loadPersistedReplica) {
    throw new TypeError('loadPersistedReplica is required for non-mutating Cell GET reconciliation')
  }
  const http = options.httpClient || new api.BlindDirectHttpClient({
    runtime: options.runtime,
    fetch: options.fetch,
    allowInsecureLoopback: options.allowInsecureLoopback === true
  })
  const readHttp = options.readHttpClient || http
  if (!readHttp || typeof readHttp.request !== 'function') {
    throw new TypeError('authenticated Cell GET HTTP client is required')
  }
  const allocationEpoch = typeof options.allocationEpoch === 'function'
    ? options.allocationEpoch
    : () => Math.floor(Date.now() / 21_600_000)
  let controlPromise = null

  const loadControl = async () => {
    if (!controlPromise) {
      const pending = options.control
        ? Promise.resolve(options.control)
        : typeof options.loadControl === 'function'
          ? Promise.resolve().then(() => options.loadControl())
          : import(CONTROL_MODULE)
      controlPromise = pending.catch(error => {
        controlPromise = null
        throw error
      })
    }
    const control = await controlPromise
    if (!control || typeof control.verifyOperationResult !== 'function' ||
      typeof control.verifiedEndpointContext !== 'function' ||
      (readbackConfigured && (typeof control.createGetCellRequest !== 'function' ||
        typeof control.openVerifiedCellGetResult !== 'function'))) {
      throw new TypeError('current @hiverelay/blind-client/control namespace is required for delivery')
    }
    return control
  }

  async function prepare (publication, context = {}) {
    const attempt = attemptTransportContext(options.signal, options.timeoutMillis, context)
    const attemptSignal = attempt.signal
    try {
      throwIfAborted(attemptSignal)
      // Loading control is itself writer activity, so it happens only after an
      // explicit publication reaches this delivery function. Construction and
      // lurker browsing never import the control package.
      const control = await loadControl()
      throwIfAborted(attemptSignal)
      const currentContext = targetContext(control.verifiedEndpointContext(options.endpoint), relayPublicKey)
      if (contextFingerprint(currentContext) !== contextFingerprint(qualifiedContext)) {
        const error = new Error('qualified relay endpoint context changed before Cell preparation')
        error.code = 'HIVERELAY_TARGET_CONTEXT_DRIFT'
        error.terminal = true
        throw error
      }
      if (readbackConfigured) {
        const currentReadContext = pairedReadContext(
          control.verifiedEndpointContext(options.readEndpoint), relayPublicKey, currentContext)
        if (contextFingerprint(currentReadContext) !== contextFingerprint(qualifiedReadContext)) {
          const error = new Error('qualified relay read endpoint context changed before Cell preparation')
          error.code = 'HIVERELAY_READ_TARGET_CONTEXT_DRIFT'
          error.terminal = true
          throw error
        }
      }
      if (loadPersistedReplica) {
        const persisted = persistedReplicaPayload(
          await loadPersistedReplica(publication.intentId, canonicalTargetId),
          publication,
          canonicalTargetId,
          qualifiedContext,
          qualifiedReadContext
        )
        throwIfAborted(attemptSignal)
        if (persisted) return persisted.payload.prepared
      }
      const envelope = publicationCellEnvelope(publication)
      if (options.sizeClass != null && options.sizeClass !== envelope.sizeClass) {
        throw terminalError('PEERIT_SUBSTRATE_SIZE_CLASS_MISMATCH', 'Configured Cell size class disagrees with the verified VNext envelope.')
      }
      if (typeof api.maximumCellContentBytes === 'function' &&
          envelope.innerBytes.byteLength > api.maximumCellContentBytes(envelope.sizeClass)) {
        throw terminalError('PEERIT_SUBSTRATE_SIZE_CLASS_UNSUPPORTED', 'Relay client cannot hold the verified VNext envelope in its required Cell class.')
      }
      const structuredContent = envelope.innerBytes
      const sizeClass = envelope.sizeClass
      const prepared = await api.createCellReplica({
        runtime: options.runtime,
        relayPublicKey,
        allocationEpoch: allocationEpoch(),
        sizeClass,
        leaseClass: options.leaseClass || 4,
        structuredContent,
        admission: options.admission,
        admissionProvider: options.admissionProvider
      })
      throwIfAborted(attemptSignal)

      // This callback owns encryption-at-rest for Cell management keys and the
      // exact request bytes. A throw aborts before fetch/request is touched.
      await options.persistPreparedReplica(Object.freeze({
        intentId: publication.intentId,
        logicalId: publication.logicalId,
        innerCodec: publication.innerCodec,
        innerLength: publication.innerLength,
        sizeClass: publication.sizeClass,
        logicalHash: new Uint8Array(publication.logicalHash),
        encodingCommitment: new Uint8Array(publication.encodingCommitment),
        targetId: canonicalTargetId,
        targetContext: qualifiedContext,
        readTargetContext: qualifiedReadContext,
        prepared
      }))
      throwIfAborted(attemptSignal)
      return prepared
    } catch (error) {
      // No transport call has begun, so this is the narrow class of failures the
      // publication queue may retry automatically after a crash or exception.
      if (error && error.terminal === true) throw error
      throw retryableNotSent(error)
    } finally {
      attempt.close()
    }
  }

  async function readback (publication, prepared, context = {}) {
    if (!readbackConfigured) {
      throw new Error('authenticated Cell GET readback is not configured')
    }
    if (!prepared || typeof prepared !== 'object' || !prepared.readCap) {
      throw terminalError('PEERIT_SUBSTRATE_READ_CAPABILITY_MISSING',
        'the durable prepared Cell has no read capability for reconciliation')
    }
    const control = await loadControl()
    const currentWriteContext = targetContext(
      control.verifiedEndpointContext(options.endpoint), relayPublicKey)
    const currentReadContext = pairedReadContext(
      control.verifiedEndpointContext(options.readEndpoint), relayPublicKey, currentWriteContext)
    if (contextFingerprint(currentWriteContext) !== contextFingerprint(qualifiedContext) ||
        contextFingerprint(currentReadContext) !== contextFingerprint(qualifiedReadContext)) {
      throw terminalError('HIVERELAY_READ_TARGET_CONTEXT_DRIFT',
        'qualified Cell PUT/GET endpoint identity changed before authenticated readback')
    }

    const attempt = attemptTransportContext(options.signal, options.timeoutMillis, context)
    let opened = null
    try {
      throwIfAborted(attempt.signal)
      const get = await control.createGetCellRequest({
        runtime: options.runtime,
        readCap: prepared.readCap,
        admissionProvider: options.readAdmissionProvider
      })
      throwIfAborted(attempt.signal)
      const response = await readHttp.request({
        endpoint: options.readEndpoint,
        ...get.wire,
        body: get.requestBytes,
        signal: attempt.signal,
        timeoutMillis: attempt.timeoutMillis
      })
      throwIfAborted(attempt.signal)
      if (!response || response.ok !== true) {
        const error = new Error('HiveRelay has not returned the exact Cell for authenticated readback')
        const remote = response && response.error
        error.code = remote && remote.code === HIVERELAY_BLIND_ERROR_NOT_FOUND
          ? 'HIVERELAY_READBACK_NOT_FOUND'
          : remote && remote.retryable === 0
            ? 'HIVERELAY_READBACK_TERMINAL'
            : 'HIVERELAY_READBACK_PENDING'
        error.remote = remote
        if (error.code === 'HIVERELAY_READBACK_NOT_FOUND' || error.code === 'HIVERELAY_READBACK_TERMINAL') {
          error.terminal = true
          error.definitiveAbsence = error.code === 'HIVERELAY_READBACK_NOT_FOUND'
        }
        throw error
      }

      let verified
      let readbackResultBytes
      try {
        verified = await control.verifyOperationResult({
          endpoint: options.readEndpoint,
          request: get.request,
          requestCommitment: get.requestCommitment,
          resultBytes: response.body,
          externalWitnessVerifier: options.externalWitnessVerifier
        })
        readbackResultBytes = verified && typeof verified.snapshotBytes === 'function'
          ? verified.snapshotBytes()
          : response.body
        opened = await control.openVerifiedCellGetResult({
          verifiedResult: verified,
          runtime: options.runtime,
          readCap: prepared.readCap
        })
      } catch (cause) {
        const error = terminalError('PEERIT_SUBSTRATE_READBACK_AUTHENTICATION_FAILED',
          'Cell GET result failed endpoint binding, result authentication, or capability opening')
        error.cause = cause
        throw error
      }
      throwIfAborted(attempt.signal)
      const envelope = publicationCellEnvelope(publication)
      if (!equalBytes(opened, envelope.innerBytes)) {
        throw terminalError('PEERIT_SUBSTRATE_READBACK_ENVELOPE_MISMATCH',
          'decrypted Cell GET bytes do not equal the exact tag-334 VNext envelope')
      }

      const persisted = await options.persistVerifiedReadback(Object.freeze({
        intentId: publication.intentId,
        logicalId: publication.logicalId,
        innerCodec: publication.innerCodec,
        innerLength: publication.innerLength,
        sizeClass: publication.sizeClass,
        logicalHash: new Uint8Array(publication.logicalHash),
        encodingCommitment: new Uint8Array(publication.encodingCommitment),
        targetId: canonicalTargetId,
        targetContext: qualifiedContext,
        readTargetContext: qualifiedReadContext,
        prepared,
        readCapability: prepared.readCap,
        readbackRequestBytes: new Uint8Array(get.requestBytes),
        readbackRequestCommitment: new Uint8Array(get.requestCommitment),
        readbackResultBytes: new Uint8Array(readbackResultBytes),
        readbackInnerBytes: new Uint8Array(opened)
      }))
      throwIfAborted(attempt.signal)
      const evidenceRef = typeof persisted === 'string' ? persisted : persisted && persisted.evidenceRef
      const evidenceRevision = persisted && Number.isSafeInteger(persisted.revision) && persisted.revision >= 1
        ? persisted.revision
        : null
      if (typeof evidenceRef !== 'string' || evidenceRef.length < 1 || evidenceRef.length > 512) {
        throw new Error('authenticated Cell GET evidence was not durably indexed')
      }
      if (evidenceRevision == null) {
        throw new Error('authenticated Cell GET evidence has no monotonic vault revision')
      }
      return Object.freeze({
        ok: true,
        acknowledged: true,
        readbackVerified: true,
        readbackRevalidated: true,
        readbackEvidenceRevision: evidenceRevision,
        policyDurable: false,
        evidenceRef,
        resultBytes: new Uint8Array(readbackResultBytes),
        readCapability: prepared.readCap
      })
    } finally {
      if (opened && typeof opened.fill === 'function') opened.fill(0)
      attempt.close()
    }
  }

  async function send (delivery, context = {}) {
    let prepared = delivery && delivery.prepared
    if (!prepared || !prepared.wire || !prepared.requestBytes) {
      throw retryableNotSent(new TypeError('prepared blind Cell request is required'))
    }
    if (loadPersistedReplica) {
      let persisted
      try {
        persisted = persistedReplicaPayload(
          await loadPersistedReplica(delivery.intentId, canonicalTargetId),
          delivery,
          canonicalTargetId,
          qualifiedContext,
          qualifiedReadContext
        )
      } catch (error) {
        if (error && error.terminal === true) throw error
        throw retryableNotSent(error)
      }
      const acknowledged = persistedAcknowledgement(persisted, delivery, readbackConfigured)
      if (acknowledged) return acknowledged
      if (!persisted) throw retryableNotSent(new Error('durable prepared Cell replica is missing before send'))
      prepared = persisted.payload.prepared
      // A committed PUT receipt is already a mutation outcome. On restart, go
      // straight to capability-bound GET; never resend the PUT merely because
      // the prior process did not finish its readback.
      if (readbackConfigured && persisted.payload.stage === 2) {
        return readback(delivery, prepared, context)
      }
    }
    let control
    try { control = await loadControl() } catch (error) { throw retryableNotSent(error) }
    const attempt = attemptTransportContext(options.signal, options.timeoutMillis, context)
    let response
    try {
      throwIfAborted(attempt.signal)
      response = await http.request({
        endpoint: options.endpoint,
        ...prepared.wire,
        body: prepared.requestBytes,
        signal: attempt.signal,
        timeoutMillis: attempt.timeoutMillis
      })
      throwIfAborted(attempt.signal)
    } finally {
      attempt.close()
    }
    if (!response || response.ok !== true) {
      const error = new Error('HiveRelay returned a canonical non-success result')
      const remote = response && response.error
      error.code = remote && remote.retryable === 1 ? 'HIVERELAY_REMOTE_RETRYABLE' : 'HIVERELAY_REMOTE_TERMINAL'
      error.safeToRetry = !!(remote && remote.retryable === 1)
      error.terminal = !error.safeToRetry
      error.remote = remote
      throw error
    }
    const verified = await control.verifyOperationResult({
      endpoint: options.endpoint,
      request: prepared.request,
      requestCommitment: prepared.requestCommitment,
      resultBytes: response.body,
      externalWitnessVerifier: options.externalWitnessVerifier
    })
    const resultBytes = verified && typeof verified.snapshotBytes === 'function'
      ? verified.snapshotBytes()
      : response.body
    const persisted = await options.persistVerifiedResult(Object.freeze({
      intentId: delivery.intentId,
      logicalId: delivery.logicalId,
      innerCodec: delivery.innerCodec,
      innerLength: delivery.innerLength,
      sizeClass: delivery.sizeClass,
      logicalHash: new Uint8Array(delivery.logicalHash),
      encodingCommitment: new Uint8Array(delivery.encodingCommitment),
      targetId: canonicalTargetId,
      targetContext: qualifiedContext,
      readTargetContext: qualifiedReadContext,
      prepared,
      resultBytes,
      readCapability: prepared.readCap
    }))
    const evidenceRef = typeof persisted === 'string' ? persisted : persisted && persisted.evidenceRef
    if (typeof evidenceRef !== 'string' || evidenceRef.length < 1 || evidenceRef.length > 512) {
      throw new Error('verified blind Cell result was not durably indexed')
    }
    if (readbackConfigured) return readback(delivery, prepared, context)
    return Object.freeze({
      ok: true,
      acknowledged: true,
      readbackVerified: false,
      policyDurable: false,
      evidenceRef,
      resultBytes,
      readCapability: prepared.readCap
    })
  }

  async function reconcile (publication, context = {}) {
    const attemptSignal = validSignal(context.signal, 'delivery attempt signal') ||
      validSignal(options.signal, 'relay installation signal')
    throwIfAborted(attemptSignal)
    if (!readbackConfigured && typeof options.reconcile === 'function') {
      return options.reconcile(publication, context)
    }
    let persisted
    try {
      persisted = persistedReplicaPayload(
        await loadPersistedReplica(publication.intentId, canonicalTargetId),
        publication,
        canonicalTargetId,
        qualifiedContext,
        qualifiedReadContext
      )
      throwIfAborted(attemptSignal)
    } catch (error) {
      if (error && error.terminal === true) throw error
      // Reconciliation exists only after an earlier send became ambiguous.
      // A local vault read failure cannot prove that mutation was unprocessed.
      throw error
    }
    const acknowledged = persistedAcknowledgement(persisted, publication, readbackConfigured)
    if (acknowledged) return acknowledged
    if (readbackConfigured && persisted &&
        (persisted.payload.stage === 1 || persisted.payload.stage === 2)) {
      // The prior PUT may have committed even when its response was lost. The
      // only automatic recovery operation is an authenticated GET for the exact
      // durable slot/capability. This path never calls send() and never mutates.
      return readback(publication, persisted.payload.prepared, context)
    }
    const error = new Error('blind Cell result remains ambiguous; no verified persisted receipt exists')
    error.code = 'HIVERELAY_RESULT_PENDING_UNKNOWN'
    throw error
  }

  async function revalidateReadback (publication, context = {}) {
    const attemptSignal = validSignal(context.signal, 'readback revalidation signal') ||
      validSignal(options.signal, 'relay installation signal')
    throwIfAborted(attemptSignal)
    if (!readbackConfigured || !loadPersistedReplica) {
      throw terminalError('PEERIT_SUBSTRATE_READ_CAPABILITY_MISSING',
        'authenticated Cell GET revalidation has no durable read capability')
    }
    const persisted = persistedReplicaPayload(
      await loadPersistedReplica(publication.intentId, canonicalTargetId),
      publication,
      canonicalTargetId,
      qualifiedContext,
      qualifiedReadContext
    )
    throwIfAborted(attemptSignal)
    if (!persisted || !persisted.payload.prepared || !persisted.payload.prepared.readCap) {
      throw terminalError('PEERIT_SUBSTRATE_READ_CAPABILITY_MISSING',
        'the historical Cell acknowledgement has no matching durable read capability')
    }
    // Deliberately bypass persistedAcknowledgement(): a cached stage-3 receipt is
    // historical evidence, not a current availability check. This path always
    // performs a new capability-bound GET and never sends or regenerates a PUT.
    return readback(publication, persisted.payload.prepared, context)
  }

  async function readCellCapability (request, context = {}) {
    if (!readbackConfigured) {
      throw terminalError('PEERIT_SUBSTRATE_READ_CAPABILITY_MISSING',
        'qualified Cell GET endpoint is unavailable')
    }
    if (!request || typeof request !== 'object' || !request.readCapability ||
        String(request.targetId || '').toLowerCase() !== canonicalTargetId ||
        !Number.isSafeInteger(request.innerLength) || request.innerLength < 1 ||
        !Number.isSafeInteger(request.sizeClass) || request.sizeClass < 1 || request.sizeClass > 5) {
      throw terminalError('PEERIT_COLD_READER_REQUEST_INVALID',
        'cold-reader request does not match the qualified Cell target')
    }
    const readCap = request.readCapability
    if (!equalBytes(readCap.relayPublicKey, relayPublicKey) ||
        readCap.sizeClass !== request.sizeClass) {
      throw terminalError('PEERIT_COLD_READER_CAPABILITY_DRIFT',
        'reader capability does not match the qualified relay or declared size class')
    }
    const control = await loadControl()
    const currentWriteContext = targetContext(
      control.verifiedEndpointContext(options.endpoint), relayPublicKey)
    const currentReadContext = pairedReadContext(
      control.verifiedEndpointContext(options.readEndpoint), relayPublicKey, currentWriteContext)
    if (contextFingerprint(currentWriteContext) !== contextFingerprint(qualifiedContext) ||
        contextFingerprint(currentReadContext) !== contextFingerprint(qualifiedReadContext)) {
      throw terminalError('HIVERELAY_READ_TARGET_CONTEXT_DRIFT',
        'qualified Cell GET endpoint identity changed before cold recovery')
    }

    const attempt = attemptTransportContext(options.signal, options.timeoutMillis, context)
    let opened = null
    try {
      throwIfAborted(attempt.signal)
      const get = await control.createGetCellRequest({
        runtime: options.runtime,
        readCap,
        admissionProvider: options.readAdmissionProvider
      })
      throwIfAborted(attempt.signal)
      const response = await readHttp.request({
        endpoint: options.readEndpoint,
        ...get.wire,
        body: get.requestBytes,
        signal: attempt.signal,
        timeoutMillis: attempt.timeoutMillis
      })
      throwIfAborted(attempt.signal)
      if (!response || response.ok !== true) {
        const error = new Error('HiveRelay did not return the capability-selected Cell')
        const remote = response && response.error
        error.code = remote && remote.code === HIVERELAY_BLIND_ERROR_NOT_FOUND
          ? 'HIVERELAY_CELL_NOT_FOUND'
          : 'HIVERELAY_CELL_GET_FAILED'
        error.remote = remote
        throw error
      }
      let verified
      try {
        verified = await control.verifyOperationResult({
          endpoint: options.readEndpoint,
          request: get.request,
          requestCommitment: get.requestCommitment,
          resultBytes: response.body,
          externalWitnessVerifier: options.externalWitnessVerifier
        })
        opened = await control.openVerifiedCellGetResult({
          verifiedResult: verified,
          runtime: options.runtime,
          readCap
        })
      } catch (cause) {
        const error = terminalError('PEERIT_COLD_READER_RESULT_AUTHENTICATION_FAILED',
          'Cell GET result failed endpoint binding, signature verification, or capability opening')
        error.cause = cause
        throw error
      }
      throwIfAborted(attempt.signal)
      if (opened.byteLength !== request.innerLength) {
        throw terminalError('PEERIT_COLD_READER_ENVELOPE_LENGTH_MISMATCH',
          'decrypted Cell bytes do not match the signed bootstrap length')
      }
      return Object.freeze({
        innerBytes: new Uint8Array(opened),
        evidenceRef: `blind-cell-get:${hex(get.requestCommitment)}`
      })
    } finally {
      if (opened && typeof opened.fill === 'function') opened.fill(0)
      attempt.close()
    }
  }

  return Object.freeze({
    id: canonicalTargetId,
    compatible: options.compatible !== false,
    prepare,
    send,
    async deliver (publication, context = {}) {
      const prepared = await prepare(publication, context)
      return send({ ...publication, prepared }, context)
    },
    reconcile: typeof options.reconcile === 'function' || loadPersistedReplica ? reconcile : undefined,
    revalidateReadback: readbackConfigured && loadPersistedReplica ? revalidateReadback : undefined,
    readCellCapability: readbackConfigured ? readCellCapability : undefined
  })
}
