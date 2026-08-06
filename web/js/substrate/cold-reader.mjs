// Bounded, GET-only Peerit seed recovery over independently qualified generic
// Blind Cell adapters. A failed replica falls through to the next signed replica;
// no path in this module prepares, sends, or queues a PUT.

import {
  decodePeeritSeedReadCapabilityV1,
  verifyPeeritSeedBootstrapV1
} from './seed-bootstrap-v1.mjs'
import {
  ingestVerifiedPeeritRemoteBatchV1,
  verifyPeeritRemoteSeedBatchV1
} from './remote-record-ingest.mjs'
import {
  assertVerifiedPeeritRelayCellGetResult,
  verifiedPeeritRelayCellGetContext
} from './relay-consumer.js'

const MAX_CONCURRENCY = 16
const MAX_TIMEOUT_MS = 30_000

function fail (code, message, details = null) {
  const error = new Error(message)
  error.code = code
  if (details) error.details = details
  throw error
}

function validSignal (value) {
  if (value == null) return null
  if (typeof value !== 'object' || typeof value.aborted !== 'boolean' ||
      typeof value.addEventListener !== 'function' || typeof value.removeEventListener !== 'function') {
    throw new TypeError('Peerit cold reader signal must be an AbortSignal')
  }
  return value
}

function throwIfAborted (signal) {
  if (!signal || !signal.aborted) return
  if (typeof signal.throwIfAborted === 'function') signal.throwIfAborted()
  throw signal.reason || Object.assign(new Error('Peerit cold reader was aborted'), { name: 'AbortError' })
}

async function runBounded (values, concurrency, worker, signal) {
  const output = new Array(values.length)
  let cursor = 0
  const count = Math.min(values.length, Math.max(1, concurrency))
  await Promise.all(Array.from({ length: count }, async () => {
    while (cursor < values.length) {
      throwIfAborted(signal)
      const index = cursor++
      output[index] = await worker(values[index], index)
    }
  }))
  return output
}

async function bounded (milliseconds, operation, parentSignal) {
  const controller = typeof AbortController === 'function' ? new AbortController() : null
  if (!controller) throw new TypeError('Peerit cold reader requires AbortController')
  const forwardAbort = () => controller.abort(parentSignal.reason ||
    Object.assign(new Error('Peerit cold reader was aborted'), { name: 'AbortError' }))
  let rejectAbort
  const aborted = new Promise((_resolve, reject) => { rejectAbort = reject })
  const onAbort = () => rejectAbort(controller.signal.reason ||
    Object.assign(new Error('Peerit cold reader was aborted'), { name: 'AbortError' }))
  controller.signal.addEventListener('abort', onAbort, { once: true })
  if (parentSignal && parentSignal.aborted) forwardAbort()
  else if (parentSignal) parentSignal.addEventListener('abort', forwardAbort, { once: true })
  const deadlineError = new Error('Peerit cold Cell GET deadline expired')
  deadlineError.code = 'PEERIT_COLD_READER_DEADLINE'
  const timer = setTimeout(() => controller.abort(deadlineError), milliseconds)
  const pending = Promise.resolve().then(() => operation({
    signal: controller.signal
  }))
  // Promise.race installs a rejection observer on pending. This additional
  // observer documents and preserves that guarantee if a non-cooperative
  // adapter rejects only after the deadline/fallback has completed.
  pending.catch(() => {})
  try {
    throwIfAborted(controller.signal)
    return await Promise.race([pending, aborted])
  } finally {
    clearTimeout(timer)
    controller.signal.removeEventListener('abort', onAbort)
    if (parentSignal) parentSignal.removeEventListener('abort', forwardAbort)
  }
}

// A cold first visit has no cached floor, so every record is a network GET. A
// sub-second transient transport burst (a dropped connection or network change)
// can abort every declared replica of one record inside the same fallback pass,
// exhausting fallback and blocking the whole recovery. A TRUNCATED HTTP body —
// the relay edge closing the connection mid-response so the vendored client
// reads fewer bytes than the declared size class ("response is shorter than the
// selected class") — is the same transient short read: the incomplete Cell is
// never parsed, verified, or accepted, so re-asking relaxes nothing; that retry
// is scoped to the EXACT vendored short-read message, and every OTHER
// RELAY_PROTOCOL_VIOLATION still fails closed forever. Retry the full replica
// set for a bounded number of extra passes, but ONLY when every failure in the
// pass was transient — a verification failure still fails closed with no retry,
// and an explicit caller abort is never retried. Each returned Cell still
// passes the unchanged assertVerifiedPeeritRelayCellGetResult / target-binding
// checks below.
const MAX_TRANSIENT_GET_RETRY_PASSES = 3
const GET_RETRY_BACKOFF_MILLIS = 400

export function isTransientCellGetFailure (error) {
  if (!error || typeof error !== 'object') return false
  if (error.code === 'TRANSPORT_FAILURE' || error.code === 'PEERIT_COLD_READER_DEADLINE') return true
  if (error.name === 'AbortError') return true
  if (error instanceof TypeError) return true
  // Exact truncated-body short-read only — all other protocol violations fail closed.
  return error.code === 'RELAY_PROTOCOL_VIOLATION' &&
    error.message === 'response is shorter than the selected class'
}

function abortableGetDelay (milliseconds, signal) {
  return new Promise((resolve, reject) => {
    if (signal && signal.aborted) {
      reject(signal.reason || Object.assign(new Error('cold reader retry aborted'), { name: 'AbortError' }))
      return
    }
    const onAbort = () => {
      clearTimeout(timer)
      reject(signal.reason || Object.assign(new Error('cold reader retry aborted'), { name: 'AbortError' }))
    }
    const timer = setTimeout(() => {
      if (signal) signal.removeEventListener('abort', onAbort)
      resolve()
    }, milliseconds)
    if (signal) signal.addEventListener('abort', onAbort, { once: true })
  })
}

function relayContextMatches (context, signed) {
  return context.canonicalDescribeUrl === signed.canonicalDescribeUrl &&
    context.continuityRootRelayPublicKey === signed.continuityRootRelayPublicKey &&
    context.storeId === signed.storeId &&
    context.descriptorGenesisHash === signed.descriptorGenesisHash &&
    context.descriptorSequence >= BigInt(signed.minimumDescriptorSequence) &&
    context.familyId === signed.familyId &&
    context.operationId === signed.operationId &&
    context.endpointId === signed.endpointId &&
    context.transportId === signed.transportId &&
    context.transportSupportBit === signed.transportSupportBit &&
    context.privacyProfileBit === signed.privacyProfileBit
}

function relayMap (relays, signedRelays) {
  if (!Array.isArray(relays) || relays.length !== signedRelays.length) {
    fail('PEERIT_COLD_READER_RELAY_BINDING_MISMATCH',
      'cold reader requires exactly the signed relay adapter set')
  }
  const map = new Map()
  for (const relay of relays) {
    const context = verifiedPeeritRelayCellGetContext(relay)
    if (typeof relay.readCellCapability !== 'function') {
      fail('PEERIT_COLD_READER_GET_UNAVAILABLE',
        'qualified relay adapter has no authenticated reader-capability GET')
    }
    const matches = signedRelays.filter(signed => relayContextMatches(context, signed))
    if (matches.length !== 1 || map.has(matches[0].relayId)) {
      fail('PEERIT_COLD_READER_RELAY_BINDING_MISMATCH',
        'qualified relay continuity/operation/transport tuple does not match the signed bootstrap')
    }
    map.set(matches[0].relayId, relay)
  }
  return map
}

export function createPeeritSeedColdReaderV1 (options = {}) {
  const sync = options.sync
  if (!sync || typeof sync.ingestVerifiedRemoteBatch !== 'function' ||
      typeof sync.discoveryFloor !== 'function') {
    throw new TypeError('Peerit cold reader requires the remote-ingest substrate sync boundary')
  }
  const capabilityVault = options.capabilityVault || null
  const concurrency = Number.isSafeInteger(options.concurrency)
    ? Math.max(1, Math.min(MAX_CONCURRENCY, options.concurrency))
    : 4
  const timeoutMillis = Number.isSafeInteger(options.timeoutMillis)
    ? Math.max(10, Math.min(MAX_TIMEOUT_MS, options.timeoutMillis))
    : 10_000
  const now = typeof options.now === 'function' ? options.now : Date.now
  const signal = validSignal(options.signal)

  async function read (artifact, verification = {}) {
    throwIfAborted(signal)
    const bootstrap = await verifyPeeritSeedBootstrapV1(artifact, {
      ...verification,
      now: now()
    })
    throwIfAborted(signal)
    const floor = await sync.discoveryFloor(bootstrap.sourceId)
    throwIfAborted(signal)
    if (floor) {
      if (bootstrap.payload.bootstrapSequence < floor.checkpointSequence) {
        fail('PEERIT_COLD_READER_ROLLBACK', 'signed bootstrap is below the persisted source floor')
      }
      if (bootstrap.payload.bootstrapSequence === floor.checkpointSequence) {
        if (bootstrap.artifactHash !== floor.checkpointHash) {
          fail('PEERIT_COLD_READER_FORK', 'signed bootstrap conflicts at the persisted source floor')
        }
        return Object.freeze({
          ok: true,
          cached: true,
          networkGets: 0,
          networkPuts: 0,
          sourceId: bootstrap.sourceId,
          checkpointSequence: floor.checkpointSequence,
          checkpointHash: floor.checkpointHash,
          recordCount: bootstrap.payload.records.length,
          fallbackCount: 0
        })
      }
      if (bootstrap.payload.bootstrapSequence !== floor.checkpointSequence + 1 ||
          bootstrap.payload.previousBootstrapHash !== floor.checkpointHash) {
        fail('PEERIT_COLD_READER_GAP', 'signed bootstrap does not directly extend the persisted source floor')
      }
    } else if (bootstrap.payload.bootstrapSequence !== 0 || bootstrap.payload.previousBootstrapHash != null) {
      fail('PEERIT_COLD_READER_GAP', 'cold browser requires bootstrap sequence zero')
    }

    const relays = relayMap(options.relays, bootstrap.payload.relays)
    let networkGets = 0
    let fallbackCount = 0
    const results = await runBounded(bootstrap.payload.records, concurrency, async record => {
      const failures = []
      for (let pass = 0; ; pass++) {
        let sawTransient = false
        let sawNonTransient = false
        for (let index = 0; index < record.replicas.length; index++) {
          const replica = record.replicas[index]
          const relay = relays.get(replica.relayId)
          if (!relay) {
            sawNonTransient = true
            failures.push({ relayId: replica.relayId, code: 'PEERIT_COLD_READER_RELAY_UNAVAILABLE' })
            continue
          }
          try {
            throwIfAborted(signal)
            if (capabilityVault && typeof capabilityVault.persistReaderCapability === 'function') {
              await capabilityVault.persistReaderCapability({
                sourceId: bootstrap.sourceId,
                recordId: record.recordId,
                logicalId: record.logicalHash,
                targetId: replica.targetId,
                relayId: replica.relayId,
                innerCodec: record.innerCodec,
                innerLength: record.innerLength,
                sizeClass: record.sizeClass,
                logicalHash: record.logicalHash,
                encodingCommitment: record.encodingCommitment,
                readCapability: decodePeeritSeedReadCapabilityV1(replica.readCapability)
              })
            }
            throwIfAborted(signal)
            const request = Object.freeze({
              recordId: record.recordId,
              logicalId: record.logicalHash,
              relayId: replica.relayId,
              targetId: replica.targetId,
              innerCodec: record.innerCodec,
              innerLength: record.innerLength,
              sizeClass: record.sizeClass,
              logicalHash: record.logicalHash,
              encodingCommitment: record.encodingCommitment,
              readCapability: decodePeeritSeedReadCapabilityV1(replica.readCapability)
            })
            networkGets++
            const result = assertVerifiedPeeritRelayCellGetResult(await bounded(
              timeoutMillis,
              context => relay.readCellCapability(request, context),
              signal
            ))
            if (result.targetId !== replica.targetId || result.relayId !== replica.relayId) {
              fail('PEERIT_COLD_READER_UNVERIFIED_RESULT',
                'authenticated Cell result does not match the signed replica target')
            }
            if (index > 0) fallbackCount++
            return Object.freeze({
              recordId: record.recordId,
              relayId: replica.relayId,
              targetId: replica.targetId,
              innerBytes: new Uint8Array(result.innerBytes),
              evidenceRef: String(result.evidenceRef),
              verified: true
            })
          } catch (error) {
            if (signal && signal.aborted) throw signal.reason || error
            if (isTransientCellGetFailure(error)) sawTransient = true
            else sawNonTransient = true
            failures.push({
              relayId: replica.relayId,
              code: String((error && (error.code || error.name)) || 'PEERIT_COLD_READER_GET_FAILED')
            })
          }
        }
        // Retry the whole replica set only when every failure this pass was a
        // transient transport abort; any verification failure breaks immediately.
        if (pass >= MAX_TRANSIENT_GET_RETRY_PASSES || sawNonTransient || !sawTransient) break
        await abortableGetDelay(GET_RETRY_BACKOFF_MILLIS * (pass + 1), signal)
      }
      fail('PEERIT_COLD_READER_RECORD_UNAVAILABLE', `no declared replica returned record ${record.recordId}`, failures)
    }, signal)
    throwIfAborted(signal)
    const verifiedBatch = await verifyPeeritRemoteSeedBatchV1(bootstrap, results)
    throwIfAborted(signal)
    const ingest = await ingestVerifiedPeeritRemoteBatchV1(sync, verifiedBatch, { observedAt: now() })
    throwIfAborted(signal)
    return Object.freeze({
      ok: true,
      cached: false,
      networkGets,
      networkPuts: 0,
      sourceId: bootstrap.sourceId,
      checkpointSequence: bootstrap.payload.bootstrapSequence,
      checkpointHash: bootstrap.artifactHash,
      recordCount: bootstrap.payload.records.length,
      fallbackCount,
      ingest
    })
  }

  return Object.freeze({ read })
}
