import assert from 'node:assert/strict'
import { readdirSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  verifyBlindClientBrowserReleaseV1
} from '../js/substrate/blind-client-browser-verifier.mjs'
import {
  PEERIT_PROFILE_FINAL_HIVERELAY_CLIENT_COMPOSITION_V1,
  PEERIT_PROFILE_FINAL_HIVERELAY_WIRE_TUPLE_V1
} from '../js/substrate/profile-codec-ir.mjs'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const directory = join(root, 'vendor', 'hiverelay-blind-client-v1')
const files = Object.freeze({
  artifact: 'blind-client-control-v1.mjs',
  manifest: 'blind-client-control-v1.manifest.cenc',
  chromium: 'blind-client-control-v1.chromium-evidence.json',
  crossHost: 'blind-client-control-v1.cross-host-evidence.json',
  authority: 'authority.json'
})
assert.deepEqual(readdirSync(directory).sort(), Object.values(files).sort(),
  'vendored HiveRelay authority has no missing or extra files')

const bytes = name => new Uint8Array(readFileSync(join(directory, name)))
const artifactBytes = bytes(files.artifact)
const manifestBytes = bytes(files.manifest)
const chromiumEvidenceBytes = bytes(files.chromium)
const crossHostEvidenceBytes = bytes(files.crossHost)
const authoritySource = readFileSync(join(directory, files.authority), 'utf8')
const authority = JSON.parse(authoritySource)
assert.equal(JSON.stringify(authority, null, 2) + '\n', authoritySource,
  'vendored HiveRelay authority JSON is canonical')

const verified = verifyBlindClientBrowserReleaseV1({
  artifactBytes,
  manifestBytes,
  chromiumEvidenceBytes,
  crossHostEvidenceBytes
})
const hex = value => Buffer.from(value).toString('hex')
assert.equal(authority.schema, 'PeeritVendoredHiveRelayBlindClientV1')
assert.equal(authority.version, 1)
assert.equal(authority.upstreamPackage, '@hiverelay/blind-client')
assert.equal(authority.artifactLength, artifactBytes.byteLength)
assert.equal(authority.artifactHash, hex(verified.artifactHash))
assert.equal(authority.manifestHash, hex(verified.manifestHash))
assert.equal(authority.sourceClosureHash, hex(verified.manifest.sourceClosureHash))
assert.deepEqual(authority.wireTuple, PEERIT_PROFILE_FINAL_HIVERELAY_WIRE_TUPLE_V1)
assert.deepEqual(authority.clientComposition, PEERIT_PROFILE_FINAL_HIVERELAY_CLIENT_COMPOSITION_V1)
assert.equal(authority.chromium.version, verified.chromium)
assert.deepEqual(authority.crossHost, verified.crossHost)

const mutatedArtifact = artifactBytes.slice()
mutatedArtifact[mutatedArtifact.byteLength - 1] ^= 1
assert.throws(
  () => verifyBlindClientBrowserReleaseV1({
    artifactBytes: mutatedArtifact,
    manifestBytes,
    chromiumEvidenceBytes,
    crossHostEvidenceBytes
  }),
  error => error && error.code === 'BLIND_CLIENT_BROWSER_ARTIFACT_DRIFT',
  'one changed vendored artifact byte must fail the ordinary pin gate'
)

console.log(`hiverelay-vendor-pin: ${artifactBytes.byteLength} bytes, artifact ${authority.artifactHash}, manifest ${authority.manifestHash}`)
