import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { readFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { promisify } from 'node:util'
import { canonical } from '../js/canon.js'
import { ready as cryptoReady } from '../js/crypto.js'
import { createIdentity } from '../js/identity.js'
import { memoryStorage } from '../js/sync.js'
import { createBlindCellRelay } from '../js/substrate/blind-client-relay.js'
import { verifyBlindClientBrowserReleaseV1 } from '../js/substrate/blind-client-browser-verifier.mjs'
import {
  createPeeritCapabilityVault,
  memoryCapabilityVaultKv
} from '../js/substrate/capability-vault.js'
import {
  createPeeritInnerOperationBatchV1,
  hashPeeritInnerOperationIntentIdV1
} from '../js/substrate/peerit-operation-authority-v1.js'

const execFileAsync = promisify(execFile)
const peeritRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const defaultHiveRoot = path.resolve(peeritRoot, '..', 'hiverelay-blind')
const hiveRoot = path.resolve(process.env.HIVERELAY_BLIND_ROOT || defaultHiveRoot)
const hiveFixtureUrl = pathToFileURL(path.join(hiveRoot, 'scripts', 'run-real-blind-relay-lab.mjs')).href
const vendorDirectory = path.join(peeritRoot, 'vendor', 'hiverelay-blind-client-v1')
const vendorArtifact = path.join(vendorDirectory, 'blind-client-control-v1.mjs')
const vendorAuthority = path.join(vendorDirectory, 'authority.json')

function hex (value) {
  return Buffer.from(value).toString('hex')
}

function equalBytes (left, right) {
  return Buffer.from(left).equals(Buffer.from(right))
}

async function repositoryCommit (root, label) {
  try {
    await execFileAsync('git', ['-C', root, 'diff', '--quiet', '--'], {
      timeout: 10_000,
      maxBuffer: 1024 * 1024
    })
    await execFileAsync('git', ['-C', root, 'diff', '--cached', '--quiet', '--'], {
      timeout: 10_000,
      maxBuffer: 1024 * 1024
    })
  } catch (cause) {
    const error = new Error(`${label} tracked source must be committed before real E2E evidence is emitted`)
    error.cause = cause
    throw error
  }
  const result = await execFileAsync('git', ['-C', root, 'rev-parse', 'HEAD'], {
    timeout: 10_000,
    maxBuffer: 1024 * 1024
  })
  return result.stdout.trim()
}

async function assertVendoredClientAuthority () {
  const [artifactBytes, manifestBytes, chromiumEvidenceBytes, crossHostEvidenceBytes, authoritySource] = await Promise.all([
    readFile(vendorArtifact),
    readFile(path.join(vendorDirectory, 'blind-client-control-v1.manifest.cenc')),
    readFile(path.join(vendorDirectory, 'blind-client-control-v1.chromium-evidence.json')),
    readFile(path.join(vendorDirectory, 'blind-client-control-v1.cross-host-evidence.json')),
    readFile(vendorAuthority, 'utf8')
  ])
  const authority = JSON.parse(authoritySource)
  const verified = verifyBlindClientBrowserReleaseV1({
    artifactBytes,
    manifestBytes,
    chromiumEvidenceBytes,
    crossHostEvidenceBytes
  })
  assert.equal(authority.artifactLength, artifactBytes.byteLength)
  assert.equal(authority.artifactHash, hex(verified.artifactHash))
  assert.equal(authority.manifestHash, hex(verified.manifestHash))
  assert.equal(authority.sourceClosureHash, hex(verified.manifest.sourceClosureHash))
  return Object.freeze({
    artifactHash: authority.artifactHash,
    manifestHash: authority.manifestHash,
    sourceClosureHash: authority.sourceClosureHash
  })
}

function createTestIdentity (label) {
  return createIdentity({
    forceDev: true,
    lazy: true,
    storage: memoryStorage(),
    session: memoryStorage(),
    label
  })
}

async function signedPublication (identity, name) {
  const me = identity.me()
  const data = { id: me.pubkey, author: me.pubkey, name }
  const signature = await identity.sign(canonical('profile', data))
  Object.assign(data, {
    _sig: signature.signature,
    _k: signature.publicKey,
    _dk: signature.driveKey,
    _ns: signature.namespace,
    _alg: signature.algorithm
  })
  const envelope = await createPeeritInnerOperationBatchV1([
    { type: 'profile', data }
  ], {
    expectedAuthorPublicKey: me.pubkey
  })
  const innerBytes = envelope.innerBytes
  const logicalHash = envelope.logicalHash
  return Object.freeze({
    intentId: hex(hashPeeritInnerOperationIntentIdV1(envelope.innerCodec, innerBytes)),
    logicalId: hex(logicalHash),
    innerCodec: envelope.innerCodec,
    innerBytes,
    innerLength: Number(envelope.innerLength),
    sizeClass: envelope.sizeClass,
    logicalHash,
    encodingCommitment: envelope.encodingCommitment
  })
}

function countedHttpClient (hiveClient, runtime, fixture, pair, calls, label) {
  const direct = new hiveClient.BlindDirectHttpClient({
    runtime,
    fetch: fixture.fetch
  })
  return Object.freeze({
    async request (options) {
      const operation = options.operationId === pair.putContext.operationId
        ? 'PUT'
        : options.operationId === pair.getContext.operationId ? 'GET' : `OP-${options.operationId}`
      calls.push(`${label}:${operation}`)
      return direct.request(options)
    }
  })
}

function peeritRelay ({ hiveClient, runtime, fixture, pair, vault, calls, label }) {
  const httpClient = countedHttpClient(hiveClient, runtime, fixture, pair, calls, label)
  return createBlindCellRelay({
    blindClient: hiveClient,
    control: hiveClient,
    runtime,
    relayPublicKey: fixture.relayPublicKey,
    endpoint: pair.putEndpoint,
    endpointContext: pair.putContext,
    readEndpoint: pair.getEndpoint,
    readEndpointContext: pair.getContext,
    httpClient,
    readHttpClient: httpClient,
    allocationEpoch: () => fixture.currentEpoch,
    admissionProvider: fixture.admissionProvider,
    persistPreparedReplica: vault.persistPreparedReplica,
    persistVerifiedResult: vault.persistVerifiedResult,
    persistVerifiedReadback: vault.persistVerifiedReadback,
    loadPersistedReplica: vault.load
  })
}

async function main () {
  if (!globalThis.crypto || !globalThis.crypto.subtle) {
    throw new Error('real Peerit/HiveRelay E2E requires Web Crypto')
  }
  const [{ createRealBlindRelayTestFixture }, hiveClient, vendor, exactHiveCommit, exactPeeritCommit] = await Promise.all([
    import(hiveFixtureUrl),
    import(pathToFileURL(vendorArtifact).href),
    assertVendoredClientAuthority(),
    repositoryCommit(hiveRoot, 'HiveRelay'),
    repositoryCommit(peeritRoot, 'Peerit')
  ])
  assert.equal(typeof createRealBlindRelayTestFixture, 'function')
  const runtime = hiveClient.createBrowserCryptoRuntime(globalThis.crypto)
  await cryptoReady()
  const identity = createTestIdentity('peerit-hiverelay-real-e2e')
  await identity.ready()
  await identity.ensureActive('peerit-hiverelay-real-e2e')

  const kv = memoryCapabilityVaultKv()
  const calls = []
  const fixture = await createRealBlindRelayTestFixture()
  try {
    const pair = await fixture.qualifyCellPair(hiveClient, runtime)
    const vault = createPeeritCapabilityVault({
      kv,
      crypto: globalThis.crypto,
      now: () => 1000
    })

    const normal = await signedPublication(identity, 'real blind-cell normal delivery')
    const normalRelay = peeritRelay({
      hiveClient,
      runtime,
      fixture,
      pair,
      vault,
      calls,
      label: 'normal'
    })
    let normalResult
    try {
      normalResult = await normalRelay.deliver(normal)
    } catch (error) {
      error.message += `; remote=${JSON.stringify(error.remote || null)}; fixture=${JSON.stringify(fixture.errors())}`
      throw error
    }
    assert.equal(normalResult.readbackVerified, true)
    assert.deepEqual(calls, ['normal:PUT', 'normal:GET'])
    const normalStored = await vault.load(normal.intentId, normalRelay.id)
    assert.equal(normalStored.stage, 'readback-verified')
    assert.equal(normalStored.revision, 3)
    assert.equal(equalBytes(normalStored.payload.readbackInnerBytes, normal.innerBytes), true)

    const ambiguous = await signedPublication(identity, 'real blind-cell lost response')
    const ambiguousRelay = peeritRelay({
      hiveClient,
      runtime,
      fixture,
      pair,
      vault,
      calls,
      label: 'ambiguous'
    })
    fixture.dropNextCellPutResponse()
    await assert.rejects(
      ambiguousRelay.deliver(ambiguous),
      error => error && error.code === 'TRANSPORT_FAILURE'
    )
    assert.equal(fixture.droppedCellPutResponses(), 1)
    assert.deepEqual(calls, ['normal:PUT', 'normal:GET', 'ambiguous:PUT'])
    const prepared = await vault.load(ambiguous.intentId, ambiguousRelay.id)
    assert.equal(prepared.stage, 'prepared')
    assert.equal(prepared.revision, 1)
    assert.equal(fixture.status().storage.accounting.cellRecords, 2,
      'the lost response occurs after the second Cell is durably committed')

    await fixture.restart()
    const recoveredPair = await fixture.qualifyCellPair(hiveClient, runtime)
    const recoveredVault = createPeeritCapabilityVault({
      kv,
      crypto: globalThis.crypto,
      now: () => 1001
    })
    const recoveredRelay = peeritRelay({
      hiveClient,
      runtime,
      fixture,
      pair: recoveredPair,
      vault: recoveredVault,
      calls,
      label: 'recovered'
    })
    const recovered = await recoveredRelay.reconcile(ambiguous)
    assert.equal(recovered.readbackVerified, true)
    assert.deepEqual(calls, [
      'normal:PUT',
      'normal:GET',
      'ambiguous:PUT',
      'recovered:GET'
    ], 'restart reconciliation performs GET only and never resends the ambiguous PUT')
    const recoveredStored = await recoveredVault.load(ambiguous.intentId, recoveredRelay.id)
    assert.equal(recoveredStored.stage, 'readback-verified')
    assert.equal(recoveredStored.revision, 2)
    assert.equal(equalBytes(recoveredStored.payload.readbackInnerBytes, ambiguous.innerBytes), true)
    assert.equal(fixture.status().storage.accounting.cellRecords, 2)
    const injectedEdgeErrors = fixture.errors()
    assert.equal(injectedEdgeErrors.length, 1)
    assert.equal(injectedEdgeErrors[0].code, 'ERR_STREAM_DESTROYED')
    assert.equal(typeof injectedEdgeErrors[0].message, 'string')
    assert.ok(injectedEdgeErrors[0].message.length > 0,
      'the only recorded edge error is the deliberately injected post-commit response loss')

    const report = Object.freeze({
      schema: 'PeeritHiveRelayRealBlindCellE2EV1',
      hiveCommit: exactHiveCommit,
      peeritCommit: exactPeeritCommit,
      hiveClientArtifactHash: vendor.artifactHash,
      hiveClientManifestHash: vendor.manifestHash,
      hiveClientSourceClosureHash: vendor.sourceClosureHash,
      exactTag334Readbacks: 2,
      restartRetainedReadback: true,
      responseLostAfterCommit: true,
      expectedInjectedEdgeErrors: injectedEdgeErrors.length,
      unexpectedRuntimeErrors: 0,
      ambiguousPutResent: false,
      finalCellRecords: fixture.status().storage.accounting.cellRecords,
      transportCalls: calls
    })
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`)
  } finally {
    await fixture.close()
  }
}

main().catch(error => {
  process.stderr.write(`[peerit-hiverelay-real-e2e] ${error.code || 'ERROR'}: ${error.stack || error.message}\n`)
  process.exitCode = 1
})
