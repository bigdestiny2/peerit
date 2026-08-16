#!/usr/bin/env node
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import {
  PEERIT_PROFILE_EXTERNAL_CLIENT_COMPOSITION_BINDING,
  PEERIT_PROFILE_EXTERNAL_WIRE_TUPLE_BINDING,
  PEERIT_PROFILE_FINAL_HIVERELAY_CLIENT_COMPOSITION_V1,
  PEERIT_PROFILE_FINAL_HIVERELAY_WIRE_TUPLE_V1
} from '../js/substrate/profile-codec-ir.mjs'
import { PEERIT_PROFILE_INVENTORY } from '../js/substrate/profile-inventory.mjs'
import {
  PEERIT_PROFILE_EXTERNAL_AUTHORITY,
  authenticatePeeritProfileExternalCodecAuthorityV1,
  isAuthenticatedPeeritProfileExternalCodecAuthorityV1
} from '../js/substrate/profile-external-authority.mjs'
import { domainLengthHash } from '../js/substrate/release-control-primitives.mjs'

const hiveRoot = path.resolve(
  process.argv.find(argument => argument.startsWith('--hiverelay-root='))
    ?.slice('--hiverelay-root='.length) ||
  process.env.HIVERELAY_BLIND_ROOT ||
  '/Users/localllm/.pear-wt/s29artifact5')
const peeritRoot = path.resolve(new URL('..', import.meta.url).pathname)
const protocolRoot = path.join(hiveRoot, 'packages/blind-protocol')
const read = relative => new Uint8Array(fs.readFileSync(path.join(hiveRoot, relative)))
const hex = bytes => Buffer.from(bytes).toString('hex')
const EXPECTED_EXTERNAL_WIRE = Object.freeze({
  specHash: 'c9ddd235c3963461174e3de13c25a4c995b53ff320be822d8304f870766b6592',
  abiHash: '199ba15d94d4d112cfac520a67055ce15ec870f0f6f7bd9adaaf47d552334567',
  vectorSetHash: 'fa54012cd0d7e4e620878c67e61f435ecb31ddec05a6283917987cc84279ee05'
})
const EXPECTED_CLIENT_COMPOSITION = Object.freeze({
  formatHash: '5637708aff4a6e93a6ff3a2f96361aa0b1597c229346e124eebeb2d7618ae09a',
  vectorSetHash: 'ea176ea78a611256689604541e55ba420d426dda2fa4dd64fb3ac9ac7503934d'
})

const wireMetadata = JSON.parse(fs.readFileSync(path.join(protocolRoot, 'hiverelay-blind-wire-authority-v1.json'), 'utf8'))
const recomputedWire = Object.freeze({
  specHash: hex(domainLengthHash('hiverelay.blind.spec-hash.v1',
    read(wireMetadata.specArtifact))),
  abiHash: hex(domainLengthHash('hiverelay.blind.abi-hash.v1',
    read(wireMetadata.abiArtifact))),
  vectorSetHash: hex(domainLengthHash('hiverelay.blind.vector-set-hash.v1',
    read(wireMetadata.vectorManifestArtifact)))
})
assert.deepEqual(recomputedWire, {
  specHash: wireMetadata.specHash,
  abiHash: wireMetadata.abiHash,
  vectorSetHash: wireMetadata.vectorSetHash
}, 'Hive WIRE metadata must equal hashes recomputed from exact final artifacts')
assert.deepEqual(recomputedWire, EXPECTED_EXTERNAL_WIRE,
  'supplied HiveRelay closure must be the exact current external v1 authority')

const peeritRead = relative => new Uint8Array(fs.readFileSync(path.join(peeritRoot, relative)))
const peeritWire = Object.freeze({
  specHash: hex(domainLengthHash('hiverelay.blind.spec-hash.v1',
    peeritRead('protocol/external-authority/hiverelay-blind-wire-v1.md'))),
  abiHash: hex(domainLengthHash('hiverelay.blind.abi-hash.v1',
    peeritRead('protocol/external-authority/hiverelay-blind-abi-v1.cenc'))),
  vectorSetHash: hex(domainLengthHash('hiverelay.blind.vector-set-hash.v1',
    peeritRead('protocol/external-authority/hiverelay-blind-wire-vector-manifest-v1.cenc')))
})
assert.deepEqual(PEERIT_PROFILE_FINAL_HIVERELAY_WIRE_TUPLE_V1, peeritWire,
  'Peerit frozen WIRE tuple must equal its exact local accepted artifacts')
assert.equal(PEERIT_PROFILE_EXTERNAL_WIRE_TUPLE_BINDING,
  `wire-v1:${peeritWire.specHash}:${peeritWire.abiHash}:${peeritWire.vectorSetHash}`)
assert.notDeepEqual(recomputedWire, peeritWire,
  'current external and Peerit frozen accepted WIRE closures are distinct by design')

const clientMetadata = JSON.parse(fs.readFileSync(path.join(protocolRoot, 'hiverelay-blind-client-composition-authority-v1.json'), 'utf8'))
const clientFormatBytes = read(clientMetadata.formatAuthorityArtifact)
const clientVectorManifestBytes = read(clientMetadata.vectorManifestArtifact)
const recomputedClient = Object.freeze({
  formatHash: hex(domainLengthHash('hiverelay.blind.client-composition-format-hash.v1',
    clientFormatBytes)),
  vectorSetHash: hex(domainLengthHash('hiverelay.blind.client-composition-vector-set-hash.v1',
    clientVectorManifestBytes))
})
assert.deepEqual(recomputedClient, {
  formatHash: clientMetadata.formatHash,
  vectorSetHash: clientMetadata.vectorSetHash
})
assert.deepEqual(recomputedClient, EXPECTED_CLIENT_COMPOSITION,
  'supplied HiveRelay closure must be the exact accepted client-composition authority')
assert.deepEqual(PEERIT_PROFILE_FINAL_HIVERELAY_CLIENT_COMPOSITION_V1, recomputedClient)
assert.equal(PEERIT_PROFILE_EXTERNAL_CLIENT_COMPOSITION_BINDING,
  `client-composition-v1:${recomputedClient.formatHash}:${recomputedClient.vectorSetHash}`)
assert.equal(Buffer.from(clientFormatBytes).equals(Buffer.from(peeritRead(
  'protocol/external-authority/hiverelay-blind-client-composition-format-v1.cenc'
))), true, 'external client-composition format must byte-equal Peerit\'s frozen accepted artifact')
assert.equal(Buffer.from(clientVectorManifestBytes).equals(Buffer.from(peeritRead(
  'protocol/external-authority/hiverelay-blind-client-composition-vector-manifest-v1.cenc'
))), true, 'external client-composition vectors must byte-equal Peerit\'s frozen accepted artifact')
const locallyVerifiedClient = authenticatePeeritProfileExternalCodecAuthorityV1({
  name: 'ReadCellCapV1',
  authorityKind: PEERIT_PROFILE_EXTERNAL_AUTHORITY.CLIENT_COMPOSITION_V1,
  authorityBinding: PEERIT_PROFILE_EXTERNAL_CLIENT_COMPOSITION_BINDING,
  artifacts: {
    formatAuthorityBytes: clientFormatBytes,
    vectorManifestBytes: clientVectorManifestBytes
  },
  assertCanonical () {
    throw new Error('authority metadata audit does not execute external runtime codecs')
  }
})
assert.equal(isAuthenticatedPeeritProfileExternalCodecAuthorityV1(locallyVerifiedClient), true,
  'Peerit-local pinned authority verifier must authenticate the exact external composition bytes')

const wireRows = PEERIT_PROFILE_INVENTORY.externalCodecImports.filter(row => row.authorityKind === 'WIRE_TUPLE_V1')
const clientRows = PEERIT_PROFILE_INVENTORY.externalCodecImports.filter(row => row.authorityKind === 'CLIENT_COMPOSITION_V1')
assert.deepEqual(wireRows.map(row => row.name), ['BlindCoreAckV1', 'BlindReceiptV1', 'InboxAppendAckV1', 'InboxReceiptV1'])
assert.deepEqual(clientRows.map(row => row.name), ['BlindCoreReadCapV1', 'ReadCellCapV1'])
assert.equal(wireRows.every(row => row.tupleBinding === PEERIT_PROFILE_EXTERNAL_WIRE_TUPLE_BINDING), true)
assert.equal(clientRows.every(row => row.tupleBinding === PEERIT_PROFILE_EXTERNAL_CLIENT_COMPOSITION_BINDING), true)
assert.equal(PEERIT_PROFILE_INVENTORY.externalCodecImports.some(row => row.name === 'BlindStoreManifestV1'), false)

process.stdout.write(`${JSON.stringify({
  schema: 'PeeritHiveRelayAuthorityIntegrationV1',
  hiveRoot,
  externalWire: recomputedWire,
  peeritFrozenWire: peeritWire,
  wirePosture: 'EXTERNAL_CURRENT_DIFFERS_FROM_PEERIT_FROZEN_ACCEPTED',
  clientComposition: recomputedClient,
  importedCodecs: [...wireRows, ...clientRows].map(row => row.name),
  storeManifestImportable: false,
  artifactMetadataRecomputed: true,
  externalExecutableImports: false,
  clientCompositionLocallyVerified: true
}, null, 2)}\n`)
