// Test-only authenticated loader for the exact adeacef HiveRelay response
// fixture. It is intentionally located under test/ and is not a production
// protocol authority. The imported module is made from the same bundle bytes
// that were authenticated from an exact descriptor read.

import { createHash } from 'node:crypto'
import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
  readdirSync,
  realpathSync
} from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

export const PEERIT_SEQ29_LOOPBACK_FIXTURE_HIVERELAY_COMMIT_V1 =
  'adeacef07c5de4d17d5ed1389fee7a35095b862f'
export const PEERIT_SEQ29_LOOPBACK_FIXTURE_HIVERELAY_TREE_V1 =
  '7c41786a4ccd758a4ddcb419eb02213cbeeaca0c'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const FIXTURE_DIRECTORY = resolve(ROOT, 'vendor/hiverelay-seq29-loopback-v1')
const FILES = Object.freeze([
  'admission-parameters.bin',
  'authority.json',
  'protocol-response-fixture-v1.mjs',
  'service-descriptor.bin'
])
const AUTHORITY = Object.freeze({
  name: 'authority.json',
  length: 20742,
  sha256: '2290e43b774ca6cb450031d7970e6c719cb3f9def72fa5b347e696ad738acdaf'
})
const ARTIFACT = Object.freeze({
  name: 'protocol-response-fixture-v1.mjs',
  length: 419306,
  sha256: '36ec4f9d202742c1008568f47a4cd235b82f30d8c0bc95c6117dd4f665376bd3'
})
const SERVICE_VECTOR = Object.freeze({
  name: 'service-descriptor.bin',
  sourcePath: 'packages/blind-protocol/vectors/draft/describe/service-descriptor.bin',
  length: 1371,
  sha256: 'ce46d09e84f9d030e6834713988172556ec4e07901293577eb844a1c92e47973'
})
const ADMISSION_VECTOR = Object.freeze({
  name: 'admission-parameters.bin',
  sourcePath: 'packages/blind-protocol/vectors/draft/describe/admission-parameters.bin',
  length: 242,
  sha256: 'b1779daefcf3eddd42c7966e01c84e9207d17e965077cebcb1dd10a93b91880b'
})
const EXACT_EXPORTS = Object.freeze([
  'ADVERTISED_OPERATION_BITS',
  'FAMILY',
  'FRAME_KIND',
  'INBOX_RECEIPT_RESULT',
  'OPERATION',
  'PROTOCOL',
  'RESULT_SIGNATURE_DOMAIN_ID',
  'admissionParametersHash',
  'admissionParametersV1',
  'blindAdmissionParametersRequestV1',
  'blindDescribeGetV1',
  'blindHealthChallengeV1',
  'blindHealthResultV1',
  'blindServiceDescriptorV1',
  'blake2b256',
  'decodeCanonical',
  'decodeOuterEnvelope',
  'durabilityContinuityBindingV1',
  'durabilityContinuityHash',
  'durabilityProfileHash',
  'durabilityProfileV1',
  'encodeCanonical',
  'encodeDispatchFrame',
  'encodeOuterEnvelope',
  'inboxCreateCommitment',
  'inboxCreateRequestCommitment',
  'inboxCreateV1',
  'inboxReceiptV1',
  'resultSignaturePayload',
  'serviceDescriptorHash'
].sort())

function fail (message, cause) {
  const error = new Error(message)
  error.code = 'PEERIT_SEQ29_LOOPBACK_FIXTURE_INVALID'
  if (cause !== undefined) error.cause = cause
  throw error
}

function sha256 (value) {
  return createHash('sha256').update(value).digest('hex')
}

function metadataIdentity (value) {
  return [
    value.dev, value.ino, value.mode, value.nlink, value.uid, value.gid,
    value.size, value.mtimeNs, value.ctimeNs
  ].join(':')
}

function exactDirectory () {
  let canonical
  let metadata
  try {
    canonical = realpathSync(FIXTURE_DIRECTORY)
    metadata = lstatSync(FIXTURE_DIRECTORY, { bigint: true })
  } catch (cause) {
    fail('test-only HiveRelay fixture directory is unavailable', cause)
  }
  if (canonical !== FIXTURE_DIRECTORY || metadata.isSymbolicLink() ||
      !metadata.isDirectory() ||
      readdirSync(FIXTURE_DIRECTORY).sort().join('\0') !== FILES.join('\0')) {
    fail('test-only HiveRelay fixture directory membership or identity changed')
  }
  return metadataIdentity(metadata)
}

function exactRead (directoryIdentity, record) {
  if (metadataIdentity(lstatSync(FIXTURE_DIRECTORY, { bigint: true })) !==
      directoryIdentity) {
    fail('test-only HiveRelay fixture directory changed during authentication')
  }
  const input = join(FIXTURE_DIRECTORY, record.name)
  let before
  let descriptor
  try {
    before = lstatSync(input, { bigint: true })
    if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n ||
        before.size !== BigInt(record.length) ||
        (before.mode & 0o777n) !== 0o644n ||
        typeof constants.O_NOFOLLOW !== 'number' || constants.O_NOFOLLOW === 0) {
      fail('test-only HiveRelay fixture is not a single-link mode-0644 regular file')
    }
    descriptor = openSync(input, constants.O_RDONLY | constants.O_NOFOLLOW)
    if (metadataIdentity(fstatSync(descriptor, { bigint: true })) !==
        metadataIdentity(before)) {
      fail('test-only HiveRelay fixture changed before its exact read')
    }
    const bytes = new Uint8Array(record.length)
    let offset = 0
    while (offset < bytes.byteLength) {
      const count = readSync(
        descriptor, bytes, offset, bytes.byteLength - offset, offset)
      if (count === 0) break
      offset += count
    }
    const extra = Buffer.alloc(1)
    if (offset !== bytes.byteLength ||
        readSync(descriptor, extra, 0, 1, offset) !== 0 ||
        metadataIdentity(fstatSync(descriptor, { bigint: true })) !==
          metadataIdentity(before) ||
        metadataIdentity(lstatSync(input, { bigint: true })) !==
          metadataIdentity(before) || sha256(bytes) !== record.sha256) {
      fail('test-only HiveRelay fixture changed during its exact read')
    }
    return bytes
  } catch (cause) {
    if (cause?.code === 'PEERIT_SEQ29_LOOPBACK_FIXTURE_INVALID') throw cause
    fail('test-only HiveRelay fixture could not be read exactly', cause)
  } finally {
    if (descriptor != null) closeSync(descriptor)
  }
}

function canonicalAuthority (bytes) {
  let source
  let value
  try {
    source = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
    value = JSON.parse(source)
  } catch (cause) {
    fail('test-only HiveRelay fixture authority is not canonical JSON', cause)
  }
  const vectors = new Map((value.vectorInventory || []).map(record =>
    [record.path, record]))
  if (JSON.stringify(value, null, 2) + '\n' !== source ||
      value.schema !== 'PeeritTestOnlyHiveRelaySeq29LoopbackFixtureV1' ||
      value.version !== 1 ||
      value.purpose !== 'test-only-localhost-response-fixture-not-production-authority' ||
      value.candidateCommit !==
        PEERIT_SEQ29_LOOPBACK_FIXTURE_HIVERELAY_COMMIT_V1 ||
      value.candidateTree !== PEERIT_SEQ29_LOOPBACK_FIXTURE_HIVERELAY_TREE_V1 ||
      value.artifactPath !==
        'test/vendor/hiverelay-seq29-loopback-v1/protocol-response-fixture-v1.mjs' ||
      value.artifactLength !== ARTIFACT.length ||
      value.artifactRawSha256 !== ARTIFACT.sha256 ||
      value.exactSortedExports?.join('\0') !== EXACT_EXPORTS.join('\0') ||
      vectors.size !== 2 ||
      vectors.get(SERVICE_VECTOR.sourcePath)?.bytes !== SERVICE_VECTOR.length ||
      vectors.get(SERVICE_VECTOR.sourcePath)?.sha256 !== SERVICE_VECTOR.sha256 ||
      vectors.get(ADMISSION_VECTOR.sourcePath)?.bytes !== ADMISSION_VECTOR.length ||
      vectors.get(ADMISSION_VECTOR.sourcePath)?.sha256 !== ADMISSION_VECTOR.sha256) {
    fail('test-only HiveRelay fixture authority identity changed')
  }
  return Object.freeze(value)
}

function dataModuleUrl (value) {
  return `data:text/javascript;base64,${Buffer.from(value).toString('base64')}`
}

export async function loadPeeritSeq29ExactLoopbackProtocolFixtureV1 () {
  const directoryIdentity = exactDirectory()
  const authorityBytes = exactRead(directoryIdentity, AUTHORITY)
  const artifactBytes = exactRead(directoryIdentity, ARTIFACT)
  const serviceDescriptorBytes = exactRead(directoryIdentity, SERVICE_VECTOR)
  const admissionParametersBytes = exactRead(directoryIdentity, ADMISSION_VECTOR)
  const authority = canonicalAuthority(authorityBytes)
  const protocol = await import(dataModuleUrl(artifactBytes))
  if (Object.keys(protocol).sort().join('\0') !== EXACT_EXPORTS.join('\0') ||
      EXACT_EXPORTS.some(name => protocol[name] == null) ||
      exactDirectory() !== directoryIdentity) {
    fail('test-only HiveRelay fixture changed during authenticated import')
  }
  return Object.freeze({
    protocol,
    serviceDescriptorVector: Uint8Array.from(serviceDescriptorBytes),
    admissionParametersVector: Uint8Array.from(admissionParametersBytes),
    authority,
    identity: Object.freeze({
      candidateCommit: PEERIT_SEQ29_LOOPBACK_FIXTURE_HIVERELAY_COMMIT_V1,
      candidateTree: PEERIT_SEQ29_LOOPBACK_FIXTURE_HIVERELAY_TREE_V1,
      artifactSha256: ARTIFACT.sha256,
      serviceDescriptorVectorSha256: SERVICE_VECTOR.sha256,
      admissionParametersVectorSha256: ADMISSION_VECTOR.sha256
    })
  })
}
