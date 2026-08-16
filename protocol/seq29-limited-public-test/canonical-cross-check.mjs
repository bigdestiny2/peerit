// Populated-environment parity check for the archive-runnable Sequence 29 gate.
//
// The deterministic generator and checker deliberately have no npm dependency.
// This separate command must be run with PEERIT_CANONICAL_SOURCE_ROOT pointing
// at a populated Peerit checkout. It proves that the exact fixture bytes accepted
// by the committed bare validator and bounded codec-334 fixture checker are also
// accepted byte-for-byte by the pinned canonical source validator/authority.

import assert from 'node:assert/strict'
import fs from 'node:fs/promises'
import path from 'node:path'
import { createHash } from 'node:crypto'
import { fileURLToPath, pathToFileURL } from 'node:url'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const TARGET_ROOT = path.resolve(HERE, '../..')
const SOURCE_ROOT = process.env.PEERIT_CANONICAL_SOURCE_ROOT
if (!SOURCE_ROOT || !path.isAbsolute(SOURCE_ROOT)) {
  throw new Error('PEERIT_CANONICAL_SOURCE_ROOT must be an absolute populated Peerit checkout')
}

const EXPECTED_TARGET_HASHES = Object.freeze({
  'docs/PEERIT-BLIND-SUBSTRATE-PROFILE.md': '74d3b65dff1bbf2a4630791fd1a770e8dcdfac415bf693ff313d38d0262619fd',
  'protocol/validator/peerit-validator-v1.bare.mjs': '66676fddb0c973dececaf78d4a070d76afb2febf78f967a7f83e57c6fba67628'
})
const EXPECTED_CANONICAL_SOURCE_HASHES = Object.freeze({
  'docs/PEERIT-BLIND-SUBSTRATE-PROFILE.md': '74d3b65dff1bbf2a4630791fd1a770e8dcdfac415bf693ff313d38d0262619fd',
  'js/canon.js': 'b3e7f8841771675e0ef2bba59d65a217e46e081669ad36bea9fa6a3f45922599',
  'js/substrate/peerit-operation-authority-v1.js': 'fae7940063a907042f8ae21754089170fb9f8c68400e86e3804a4c641258f9bf',
  'js/substrate/profile-codec-ir.mjs': 'a521429f4ed1ae60b57fdecc2536e207dcb3f6b20cb4fd5391aebe07a8dbc824',
  'js/substrate/profile-contextual-graph-validator.mjs': '9847f1a9a2d08091afb9fab029eaebfb99423523840115ed6d3d2c5abbf21a59',
  'js/substrate/profile-external-authority.mjs': 'be5593361de52730b56812ece09107a86dfdbabddf83f5b2e523c2644db7277f',
  'js/substrate/profile-inventory.mjs': 'c2b5ebb36c257987596798773e9ea31bc62037210041235ee06a5458b610d84a',
  'js/substrate/profile-validator.mjs': 'dfcfd21909e90bb6fd568a5aceb27cd248973ff392dc02ea8b04d67fb1e7301a',
  'vendor/hiverelay-blind-client-v1/blind-client-control-v1.mjs': '88e51864c4a21296e64864523a7d602a1df6e24beed7dbbed45690c05eb1902f'
})

const sha256Hex = value => createHash('sha256').update(value).digest('hex')
const read = (root, relative) => fs.readFile(path.join(root, relative))
const importFrom = (root, relative) => import(pathToFileURL(path.join(root, relative)).href)
const fromHex = value => new Uint8Array(Buffer.from(value, 'hex'))
function stable (value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return '[' + value.map(stable).join(',') + ']'
  return '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + stable(value[key])).join(',') + '}'
}

async function assertHashes (root, expected) {
  const observed = {}
  for (const [relative, digest] of Object.entries(expected)) {
    const actual = sha256Hex(await read(root, relative))
    assert.equal(actual, digest, `${relative} authority hash drift`)
    observed[relative] = actual
  }
  return Object.freeze(observed)
}

function expectReject (operation, label) {
  let rejected = false
  try { operation() } catch { rejected = true }
  assert.equal(rejected, true, `${label} was unexpectedly accepted`)
}

async function expectRejectAsync (operation, label) {
  let rejected = false
  try { await operation() } catch { rejected = true }
  assert.equal(rejected, true, `${label} was unexpectedly accepted`)
}

async function main () {
  const targetHashes = await assertHashes(TARGET_ROOT, EXPECTED_TARGET_HASHES)
  const canonicalSourceHashes = await assertHashes(SOURCE_ROOT, EXPECTED_CANONICAL_SOURCE_HASHES)
  const [codecModule, inventoryModule, authorityModule, validatorModule, externalDecoderModule,
    operationAuthorityModule, bareModule, boundedFixtureModule] = await Promise.all([
    importFrom(SOURCE_ROOT, 'js/substrate/profile-codec-ir.mjs'),
    importFrom(SOURCE_ROOT, 'js/substrate/profile-inventory.mjs'),
    importFrom(SOURCE_ROOT, 'js/substrate/profile-external-authority.mjs'),
    importFrom(SOURCE_ROOT, 'js/substrate/profile-validator.mjs'),
    importFrom(SOURCE_ROOT, 'vendor/hiverelay-blind-client-v1/blind-client-control-v1.mjs'),
    importFrom(SOURCE_ROOT, 'js/substrate/peerit-operation-authority-v1.js'),
    importFrom(TARGET_ROOT, 'protocol/validator/peerit-validator-v1.bare.mjs'),
    importFrom(TARGET_ROOT, 'protocol/seq29-limited-public-test/check.mjs')
  ])
  const inventory = inventoryModule.PEERIT_PROFILE_INVENTORY
  const profileText = (await read(TARGET_ROOT, 'docs/PEERIT-BLIND-SUBSTRATE-PROFILE.md')).toString('utf8')
  const compiled = codecModule.compilePeeritProfileCodecIr(profileText, inventory)
  const targetRead = relative => read(TARGET_ROOT, relative).then(value => new Uint8Array(value))
  const wireArtifacts = {
    specBytes: await targetRead('protocol/external-authority/hiverelay-blind-wire-v1.md'),
    abiBytes: await targetRead('protocol/external-authority/hiverelay-blind-abi-v1.cenc'),
    vectorManifestBytes: await targetRead('protocol/external-authority/hiverelay-blind-wire-vector-manifest-v1.cenc')
  }
  const clientArtifacts = {
    formatAuthorityBytes: await targetRead('protocol/external-authority/hiverelay-blind-client-composition-format-v1.cenc'),
    vectorManifestBytes: await targetRead('protocol/external-authority/hiverelay-blind-client-composition-vector-manifest-v1.cenc')
  }
  const canonicalAuthorities = {}
  const bareAuthorities = {}
  for (const row of inventory.externalCodecImports) {
    const input = {
      name: row.name,
      authorityKind: row.authorityKind,
      authorityBinding: row.tupleBinding,
      artifacts: row.authorityKind === 'WIRE_TUPLE_V1' ? wireArtifacts : clientArtifacts,
      assertCanonical (value, name) {
        assert.equal(name, row.name)
        externalDecoderModule.decodeBlindExternalProfileValueV1(name, value)
      }
    }
    canonicalAuthorities[row.name] = authorityModule.authenticatePeeritProfileExternalCodecAuthorityV1(input)
    bareAuthorities[row.name] = bareModule.authenticatePeeritProfileExternalCodecAuthorityV1(input)
  }
  const canonicalValidator = validatorModule.createPeeritProfileValidatorV1(compiled, inventory, {
    externalAuthorities: Object.freeze(canonicalAuthorities)
  })
  const bareValidator = bareModule.createPeeritValidatorV1({
    externalAuthorities: Object.freeze(bareAuthorities)
  })
  const vector = JSON.parse(await read(TARGET_ROOT,
    'test/fixtures/peerit-seq29-limited-public-test-v1/positive-protocol-vector.json'))
  const accepted = {}
  for (const [name, encodedHex] of [
    ['AuthorBindV1', vector.authorBind.canonicalHex],
    ['PeeritAnnouncementV1', vector.announcement.canonicalHex]
  ]) {
    const bytes = fromHex(encodedHex)
    const canonical = canonicalValidator.validate(name, bytes)
    const bare = bareValidator.validate(name, bytes)
    assert.deepEqual(canonicalValidator.catalog[name].encode(canonical.value), bytes,
      `${name} canonical source round trip differs`)
    assert.deepEqual(bareValidator.catalog[name].encode(bare.value), bytes,
      `${name} bare authority round trip differs`)
    assert.deepEqual(canonicalValidator.catalog[name].encode(canonical.value),
      bareValidator.catalog[name].encode(bare.value), `${name} authorities encode different bytes`)
    const tampered = new Uint8Array(bytes)
    tampered[tampered.byteLength - 1] ^= 1
    expectReject(() => canonicalValidator.validate(name, tampered), `${name} canonical signature negative`)
    expectReject(() => bareValidator.validate(name, tampered), `${name} bare signature negative`)
    accepted[name] = Object.freeze({ byteLength: bytes.byteLength, sha256: sha256Hex(bytes) })
  }

  const inner = fromHex(vector.inner.canonicalHex)
  const decodedInner = await operationAuthorityModule.decodePeeritInnerOperationBatchV1(334, inner, {
    expectedAuthorPublicKey: vector.inner.oneAuthorPublicKey
  })
  const boundedInner = boundedFixtureModule.decodeBoundedPeeritInnerOperationBatchFixtureV1(
    inner, vector.inner.oneAuthorPublicKey
  )
  assert.deepEqual(decodedInner.innerBytes, inner, 'canonical codec-334 operation authority changed exact bytes')
  assert.equal(decodedInner.innerLength, BigInt(vector.inner.byteLength), 'canonical codec-334 inner length differs')
  assert.equal(Buffer.from(decodedInner.logicalHash).toString('hex'), vector.inner.logicalHash,
    'canonical codec-334 logical hash differs')
  assert.equal(Buffer.from(decodedInner.encodingCommitment).toString('hex'), vector.inner.encodingCommitment,
    'canonical codec-334 encoding commitment differs')
  assert.equal(decodedInner.authorPublicKey, vector.inner.oneAuthorPublicKey,
    'canonical codec-334 author differs')
  assert.equal(boundedInner.innerLength, decodedInner.innerLength, 'bounded/canonical codec-334 length differs')
  assert.equal(Buffer.from(boundedInner.logicalHash).toString('hex'), Buffer.from(decodedInner.logicalHash).toString('hex'),
    'bounded/canonical codec-334 logical hash differs')
  assert.equal(Buffer.from(boundedInner.encodingCommitment).toString('hex'),
    Buffer.from(decodedInner.encodingCommitment).toString('hex'), 'bounded/canonical codec-334 encoding differs')
  const parsed = JSON.parse(Buffer.from(inner.subarray(7)).toString('utf8'))
  parsed.operations[0].data._sig = `${parsed.operations[0].data._sig[0] === '0' ? '1' : '0'}${parsed.operations[0].data._sig.slice(1)}`
  const tamperedPayload = Buffer.from(stable(parsed), 'utf8')
  const tamperedInner = Buffer.concat([
    Buffer.from([0x01, 0x4e, 0x01]),
    Buffer.from([(tamperedPayload.byteLength >>> 24) & 0xff, (tamperedPayload.byteLength >>> 16) & 0xff,
      (tamperedPayload.byteLength >>> 8) & 0xff, tamperedPayload.byteLength & 0xff]),
    tamperedPayload
  ])
  await expectRejectAsync(() => operationAuthorityModule.decodePeeritInnerOperationBatchV1(334, tamperedInner, {
    expectedAuthorPublicKey: vector.inner.oneAuthorPublicKey
  }), 'canonical codec-334 bad signature negative')
  expectReject(() => boundedFixtureModule.decodeBoundedPeeritInnerOperationBatchFixtureV1(
    tamperedInner, vector.inner.oneAuthorPublicKey
  ), 'bounded codec-334 bad signature negative')
  accepted.PeeritInnerOperationBatchV1 = Object.freeze({ byteLength: inner.byteLength, sha256: sha256Hex(inner) })

  console.log(JSON.stringify({
    status: 'PASS',
    claim: 'CANONICAL_SOURCE_PARITY_FOR_FIXTURE_BYTES_ONLY',
    bareValidatorSha256: targetHashes['protocol/validator/peerit-validator-v1.bare.mjs'],
    canonicalSourceHashes,
    accepted,
    rejectParity: {
      AuthorBindV1BadSignature: 'CANONICAL_AND_BARE_REJECT',
      PeeritAnnouncementV1BadSignature: 'CANONICAL_AND_BARE_REJECT',
      PeeritInnerOperationBatchV1BadSignature: 'CANONICAL_AND_BOUNDED_REJECT'
    }
  }))
}

await main()
