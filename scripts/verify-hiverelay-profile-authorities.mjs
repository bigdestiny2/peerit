#!/usr/bin/env node
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { pathToFileURL } from 'node:url'
import {
  PEERIT_PROFILE_EXTERNAL_CLIENT_COMPOSITION_BINDING,
  PEERIT_PROFILE_EXTERNAL_WIRE_TUPLE_BINDING,
  PEERIT_PROFILE_FINAL_HIVERELAY_CLIENT_COMPOSITION_V1,
  PEERIT_PROFILE_FINAL_HIVERELAY_WIRE_TUPLE_V1
} from '../js/substrate/profile-codec-ir.mjs'
import { PEERIT_PROFILE_INVENTORY } from '../js/substrate/profile-inventory.mjs'

const hiveRoot = path.resolve(process.argv.find(argument => argument.startsWith('--hiverelay-root='))?.slice('--hiverelay-root='.length) || '/private/tmp/hiverelay-blind')
const protocolRoot = path.join(hiveRoot, 'packages/blind-protocol')
const read = relative => new Uint8Array(fs.readFileSync(path.join(hiveRoot, relative)))
const hex = bytes => Buffer.from(bytes).toString('hex')
const imported = relative => import(pathToFileURL(path.join(protocolRoot, relative)).href)

const wireMetadata = JSON.parse(fs.readFileSync(path.join(protocolRoot, 'hiverelay-blind-wire-authority-v1.json'), 'utf8'))
const hashes = await imported('hashes.js')
const recomputedWire = Object.freeze({
  specHash: hex(hashes.hashSpec(read(wireMetadata.specArtifact))),
  abiHash: hex(hashes.hashAbi(read(wireMetadata.abiArtifact))),
  vectorSetHash: hex(hashes.hashVectorSet(read(wireMetadata.vectorManifestArtifact)))
})
assert.deepEqual(recomputedWire, {
  specHash: wireMetadata.specHash,
  abiHash: wireMetadata.abiHash,
  vectorSetHash: wireMetadata.vectorSetHash
}, 'Hive WIRE metadata must equal hashes recomputed from exact final artifacts')
assert.deepEqual(PEERIT_PROFILE_FINAL_HIVERELAY_WIRE_TUPLE_V1, recomputedWire)
assert.equal(PEERIT_PROFILE_EXTERNAL_WIRE_TUPLE_BINDING,
  `wire-v1:${recomputedWire.specHash}:${recomputedWire.abiHash}:${recomputedWire.vectorSetHash}`)

const clientMetadata = JSON.parse(fs.readFileSync(path.join(protocolRoot, 'hiverelay-blind-client-composition-authority-v1.json'), 'utf8'))
const clientAuthority = await imported('client-composition-authority.js')
const vectorRoot = path.join(hiveRoot, clientMetadata.vectorRoot)
const vectors = new Map()
const visit = (absolute, relative = '') => {
  for (const entry of fs.readdirSync(absolute, { withFileTypes: true })) {
    const childAbsolute = path.join(absolute, entry.name)
    const childRelative = path.posix.join(relative, entry.name)
    if (entry.isDirectory()) visit(childAbsolute, childRelative)
    else if (entry.isFile()) vectors.set(childRelative, new Uint8Array(fs.readFileSync(childAbsolute)))
  }
}
visit(vectorRoot)
const verifiedClient = clientAuthority.verifyClientCompositionAuthorityV1({
  formatAuthorityBytes: read(clientMetadata.formatAuthorityArtifact),
  specBytes: read(clientMetadata.specificationArtifact),
  schemaCatalogBytes: read(clientMetadata.schemaCatalogArtifact),
  vectorManifestBytes: read(clientMetadata.vectorManifestArtifact),
  vectors,
  expectedFormatHash: Buffer.from(clientMetadata.formatHash, 'hex'),
  expectedVectorSetHash: Buffer.from(clientMetadata.vectorSetHash, 'hex')
})
const recomputedClient = Object.freeze({
  formatHash: hex(verifiedClient.formatHash),
  vectorSetHash: hex(verifiedClient.vectorSetHash)
})
assert.deepEqual(recomputedClient, {
  formatHash: clientMetadata.formatHash,
  vectorSetHash: clientMetadata.vectorSetHash
})
assert.deepEqual(PEERIT_PROFILE_FINAL_HIVERELAY_CLIENT_COMPOSITION_V1, recomputedClient)
assert.equal(PEERIT_PROFILE_EXTERNAL_CLIENT_COMPOSITION_BINDING,
  `client-composition-v1:${recomputedClient.formatHash}:${recomputedClient.vectorSetHash}`)

const wireRows = PEERIT_PROFILE_INVENTORY.externalCodecImports.filter(row => row.authorityKind === 'WIRE_TUPLE_V1')
const clientRows = PEERIT_PROFILE_INVENTORY.externalCodecImports.filter(row => row.authorityKind === 'CLIENT_COMPOSITION_V1')
assert.deepEqual(wireRows.map(row => row.name), ['BlindCoreAckV1', 'BlindReceiptV1', 'InboxAppendAckV1', 'InboxReceiptV1'])
assert.deepEqual(clientRows.map(row => row.name), ['BlindCoreReadCapV1', 'ReadCellCapV1'])
assert.equal(wireRows.every(row => row.tupleBinding === PEERIT_PROFILE_EXTERNAL_WIRE_TUPLE_BINDING), true)
assert.equal(clientRows.every(row => row.tupleBinding === PEERIT_PROFILE_EXTERNAL_CLIENT_COMPOSITION_BINDING), true)
assert.equal(PEERIT_PROFILE_INVENTORY.externalCodecImports.some(row => row.name === 'BlindStoreManifestV1'), false)

const staleDraftTuple = 'wire-v1:470a48af7d3e2c5e70aa8c14bfd9fb36344678be651f3c435cf157c27f49c7cc:aaf29c82d93125ad241f6cd257b69f2d76bbcebda896edc171816a947d099ed2:7943626b40d91ceec9ccd7419c4826c480d73a1290d39030dadfd95bf6fdc19d'
assert.notEqual(PEERIT_PROFILE_EXTERNAL_WIRE_TUPLE_BINDING, staleDraftTuple, 'stale draft tuple must never satisfy final authority')
const substitutedMetadata = { ...wireMetadata, specHash: staleDraftTuple.split(':')[1] }
assert.notEqual(substitutedMetadata.specHash, recomputedWire.specHash, 'self-described stale metadata must fail exact artifact recomputation')

process.stdout.write(`${JSON.stringify({
  schema: 'PeeritHiveRelayAuthorityIntegrationV1',
  hiveRoot,
  wire: recomputedWire,
  clientComposition: recomputedClient,
  importedCodecs: [...wireRows, ...clientRows].map(row => row.name),
  storeManifestImportable: false,
  staleDraftRejected: true
}, null, 2)}\n`)
