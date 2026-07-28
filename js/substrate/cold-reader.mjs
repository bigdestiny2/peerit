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

async function runBounded (values, concurrency, worker) {
  const output = new Array(values.length)
  let cursor = 0
  const count = Math.min(values.length, Math.max(1, concurrency))
  await Promise.all(Array.from({ length: count }, async () => {
    while (cursor < values.length) {
      const index = cursor++
      output[index] = await worker(values[index], index)
    }
  }))
  return output
}

async function bounded (milliseconds, operation) {
  const controller = typeof AbortController === 'function' ? new AbortController() : null
  let cancelTimeout = () => {}
  const timeout = new Promise((resolve, reject) => {
    const error = new Error('Peerit cold Cell GET deadline expired')
    error.code = 'PEERIT_COLD_READER_DEADLINE'
    const timer = setTimeout(() => {
      if (controller) controller.abort(error)
      reject(error)
    }, milliseconds)
    cancelTimeout = () => clearTimeout(timer)
  })
  const pending = Promise.resolve().then(() => operation({
    signal: controller ? controller.signal : undefined
  }))
  // Promise.race installs a rejection observer on pending. This additional
  // observer documents and preserves that guarantee if a non-cooperative
  // adapter rejects only after the deadline/fallback has completed.
  pending.catch(() => {})
  try { return await Promise.race([pending, timeout]) } finally { cancelTimeout() }
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

  async function read (artifact, verification = {}) {
    const bootstrap = await verifyPeeritSeedBootstrapV1(artifact, {
      ...verification,
      now: now()
    })
    const floor = await sync.discoveryFloor(bootstrap.sourceId)
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
      for (let index = 0; index < record.replicas.length; index++) {
        const replica = record.replicas[index]
        const relay = relays.get(replica.relayId)
        if (!relay) {
          failures.push({ relayId: replica.relayId, code: 'PEERIT_COLD_READER_RELAY_UNAVAILABLE' })
          continue
        }
        try {
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
            context => relay.readCellCapability(request, context)
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
          failures.push({
            relayId: replica.relayId,
            code: String((error && (error.code || error.name)) || 'PEERIT_COLD_READER_GET_FAILED')
          })
        }
      }
      fail('PEERIT_COLD_READER_RECORD_UNAVAILABLE', `no declared replica returned record ${record.recordId}`, failures)
    })
    const verifiedBatch = await verifyPeeritRemoteSeedBatchV1(bootstrap, results)
    const ingest = await ingestVerifiedPeeritRemoteBatchV1(sync, verifiedBatch, { observedAt: now() })
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
