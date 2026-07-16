import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { startLocalBlindBrowserStandup } from '../scripts/local-blind-browser-standup.mjs'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const hiveRelayRoot = path.resolve(process.env.HIVERELAY_BLIND_ROOT || path.join(root, '..', 'hiverelay-blind'))

function markerBytes (value) {
  assert.deepEqual(Object.keys(value || {}), ['$bytes'])
  assert.match(value.$bytes, /^(?:[0-9a-f]{2})+$/)
  return Buffer.from(value.$bytes, 'hex')
}

const standup = await startLocalBlindBrowserStandup({ hiveRelayRoot })
try {
  assert.match(standup.url, /^http:\/\/127\.0\.0\.1:[0-9]+\/standup$/)
  assert.equal(standup.metadata.schema, 'PeeritHiveRelayLocalBlindBrowserConfigV1')
  assert.equal(standup.metadata.localTestOnly, true)
  assert.equal(standup.metadata.qualification.schema, 'HiveRelayRealBlindBrowserQualificationConfigV1')
  assert.equal(standup.metadata.qualification.localTestOnly, true)

  const pageResponse = await fetch(standup.url, { redirect: 'error' })
  const page = await pageResponse.text()
  assert.equal(pageResponse.status, 200)
  assert.match(page, /peerit-local-blind-standup" content="synthetic-loopback-only"/)
  assert.match(page, /script-src 'self' 'wasm-unsafe-eval'/)
  assert.match(page, /\/scripts\/local-blind-browser-entry\.mjs/)

  const origin = new URL(standup.url).origin
  const configResponse = await fetch(origin + '/__fixture/config', { redirect: 'error' })
  const config = await configResponse.json()
  assert.equal(config.schema, 'PeeritHiveRelayLocalBlindBrowserConfigV1')
  assert.equal(config.localTestOnly, true)
  assert.match(config.runId, /^[0-9a-f]{32}$/)
  assert.match(config.fixtureToken, /^[0-9a-f]{64}$/)
  assert.equal(typeof config.peeritTrackedDirty, 'boolean')
  assert.equal(config.hiveRelayTrackedDirty, false)
  assert.equal(config.transport.exactBlindProtocolBytesForwarded, true)
  assert.equal(config.qualification.schema, 'HiveRelayRealBlindBrowserQualificationConfigV1')
  assert.match(markerBytes(config.qualification.candidate.canonicalUrl).toString('utf8'),
    /^https:\/\/127\.0\.0\.1:[0-9]+\/api\/blind\/v1\/describe$/)
  assert.equal(markerBytes(config.qualification.candidate.expectedDescriptorHash).byteLength, 32)
  assert.equal(markerBytes(config.qualification.candidate.continuityRootRelayPublicKey).byteLength, 32)
  assert.equal(markerBytes(config.qualification.candidate.storeId).byteLength, 32)
  assert.ok(markerBytes(config.qualification.genesis.descriptorBytes).byteLength > 256)
  assert.equal(markerBytes(config.qualification.genesis.descriptorHash).byteLength, 32)

  const [artifactResponse, immutableArtifactResponse, authoritySource] = await Promise.all([
    fetch(origin + '/vendor/hiverelay-blind-client-v1/blind-client-control-v1.mjs', { redirect: 'error' }),
    fetch(origin + config.vendorArtifact.immutablePath, { redirect: 'error' }),
    readFile(path.join(root, 'vendor', 'hiverelay-blind-client-v1', 'authority.json'), 'utf8')
  ])
  const authority = JSON.parse(authoritySource)
  const artifact = new Uint8Array(await artifactResponse.arrayBuffer())
  const immutableArtifact = new Uint8Array(await immutableArtifactResponse.arrayBuffer())
  assert.equal(artifactResponse.status, 200)
  assert.equal(artifactResponse.headers.get('content-type'), 'text/javascript; charset=utf-8')
  assert.equal(Number(artifactResponse.headers.get('content-length')), authority.artifactLength)
  assert.equal(artifact.byteLength, authority.artifactLength)
  assert.equal(config.vendorArtifact.artifactHash, authority.artifactHash)
  assert.equal(config.vendorArtifact.artifactLength, authority.artifactLength)
  assert.deepEqual(immutableArtifact, artifact)

  const unauthorizedAdmission = await fetch(origin + '/__fixture/admission', {
    method: 'POST',
    body: new Uint8Array(0),
    redirect: 'error'
  })
  assert.equal(unauthorizedAdmission.status, 403)
  const admissionResponse = await fetch(origin + '/__fixture/admission', {
    method: 'POST',
    headers: { 'x-peerit-local-fixture-token': config.fixtureToken },
    body: new Uint8Array(0),
    redirect: 'error'
  })
  const admission = await admissionResponse.json()
  assert.equal(admissionResponse.status, 200)
  assert.equal(admission.profileId, config.qualification.advertisedAdmissionProfile.profileId)
  assert.equal(admission.schemeId, config.qualification.advertisedAdmissionProfile.schemeId)
  assert.deepEqual(admission.parameterHash, config.qualification.advertisedAdmissionProfile.parameterHash)
  assert.equal(markerBytes(admission.token).byteLength, 32)

  const forbidden = await fetch(origin + '/__fixture/proxy?target=' +
    encodeURIComponent('https://example.com/api/blind/v1/describe'), {
    headers: { 'x-peerit-local-fixture-token': config.fixtureToken },
    redirect: 'error'
  })
  const forbiddenBody = await forbidden.json()
  assert.equal(forbidden.status, 500)
  assert.equal(forbiddenBody.error, 'PEERIT_LOCAL_BLIND_STANDUP_INVALID')
  assert.match(forbiddenBody.message, /outside the one fixture relay origin/)

  const evidenceResponse = await fetch(origin + '/__fixture/evidence', { redirect: 'error' })
  const evidence = await evidenceResponse.json()
  assert.equal(evidence.schema, 'PeeritHiveRelayLocalBlindBrowserEvidenceV1')
  assert.equal(evidence.localTestOnly, true)
  assert.equal(evidence.admissionTokensIssued, 1)
  assert.equal(evidence.proxyRequests, 0)
  assert.equal(evidence.cellRecords, 0)
  assert.deepEqual(evidence.relayErrors, [])

  console.log(JSON.stringify({
    schema: 'PeeritLocalBlindBrowserLauncherTestV1',
    hiveRelayCommit: config.hiveRelayCommit,
    peeritCommit: config.peeritCommit,
    localOnly: true,
    exactVendoredArtifactBytes: artifact.byteLength,
    offOriginProxyRejected: true,
    initialCellRecords: evidence.cellRecords
  }, null, 2))
} finally {
  await standup.close()
}
