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

function bytes (value, field) {
  if (value instanceof Uint8Array) return value
  if (value instanceof ArrayBuffer) return new Uint8Array(value)
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
  throw new TypeError(`${field} must be bytes`)
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

function persistedReplicaPayload (stored, publication, targetId, qualifiedContext) {
  if (stored == null) return null
  const payload = stored && stored.payload
  if (!payload || typeof payload !== 'object' ||
      payload.intentId !== publication.intentId ||
      payload.logicalId !== publication.logicalId ||
      String(payload.targetId || '').toLowerCase() !== targetId ||
      !payload.targetContext ||
      contextFingerprint(payload.targetContext) !== contextFingerprint(qualifiedContext) ||
      !payload.prepared || typeof payload.prepared !== 'object' ||
      (payload.stage !== 1 && payload.stage !== 2)) {
    const error = new Error('encrypted persisted Cell replica does not match this exact intent target')
    error.code = 'HIVERELAY_PERSISTED_REPLICA_MISMATCH'
    error.terminal = true
    throw error
  }
  return Object.freeze({ stored, payload })
}

function persistedAcknowledgement (record) {
  if (!record || record.payload.stage !== 2 ||
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

function chooseSizeClass (api, content) {
  if (typeof api.maximumCellContentBytes !== 'function') return 5
  for (let sizeClass = 1; sizeClass <= 5; sizeClass++) {
    if (content.byteLength <= api.maximumCellContentBytes(sizeClass)) return sizeClass
  }
  throw new Error('Peerit signed publication exceeds the maximum blind Cell size')
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
  const relayPublicKey = bytes(options.relayPublicKey, 'relayPublicKey')
  if (relayPublicKey.byteLength !== 32) throw new TypeError('relayPublicKey must be 32 bytes')
  const qualifiedContext = targetContext(options.endpointContext, relayPublicKey)
  const targetId = targetIdFor(qualifiedContext)
  const canonicalTargetId = String(targetId).toLowerCase()
  const loadPersistedReplica = typeof options.loadPersistedReplica === 'function'
    ? options.loadPersistedReplica
    : null
  const http = options.httpClient || new api.BlindDirectHttpClient({
    runtime: options.runtime,
    fetch: options.fetch,
    allowInsecureLoopback: options.allowInsecureLoopback === true
  })
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
      typeof control.verifiedEndpointContext !== 'function') {
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
      if (loadPersistedReplica) {
        const persisted = persistedReplicaPayload(
          await loadPersistedReplica(publication.intentId, canonicalTargetId),
          publication,
          canonicalTargetId,
          qualifiedContext
        )
        throwIfAborted(attemptSignal)
        if (persisted) return persisted.payload.prepared
      }
      const structuredContent = bytes(publication.operationBytes, 'operationBytes')
      const sizeClass = options.sizeClass || chooseSizeClass(api, structuredContent)
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
        targetId: canonicalTargetId,
        targetContext: qualifiedContext,
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
          qualifiedContext
        )
      } catch (error) {
        if (error && error.terminal === true) throw error
        throw retryableNotSent(error)
      }
      const acknowledged = persistedAcknowledgement(persisted)
      if (acknowledged) return acknowledged
      if (!persisted) throw retryableNotSent(new Error('durable prepared Cell replica is missing before send'))
      prepared = persisted.payload.prepared
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
      targetId: canonicalTargetId,
      targetContext: qualifiedContext,
      prepared,
      resultBytes,
      readCapability: prepared.readCap
    }))
    const evidenceRef = typeof persisted === 'string' ? persisted : persisted && persisted.evidenceRef
    if (typeof evidenceRef !== 'string' || evidenceRef.length < 1 || evidenceRef.length > 512) {
      throw new Error('verified blind Cell result was not durably indexed')
    }
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
    if (typeof options.reconcile === 'function') return options.reconcile(publication, context)
    let persisted
    try {
      persisted = persistedReplicaPayload(
        await loadPersistedReplica(publication.intentId, canonicalTargetId),
        publication,
        canonicalTargetId,
        qualifiedContext
      )
      throwIfAborted(attemptSignal)
    } catch (error) {
      if (error && error.terminal === true) throw error
      // Reconciliation exists only after an earlier send became ambiguous.
      // A local vault read failure cannot prove that mutation was unprocessed.
      throw error
    }
    const acknowledged = persistedAcknowledgement(persisted)
    if (acknowledged) return acknowledged
    const error = new Error('blind Cell result remains ambiguous; no verified persisted receipt exists')
    error.code = 'HIVERELAY_RESULT_PENDING_UNKNOWN'
    throw error
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
    reconcile: typeof options.reconcile === 'function' || loadPersistedReplica ? reconcile : undefined
  })
}
