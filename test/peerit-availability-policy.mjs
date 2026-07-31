import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import {
  PEERIT_AVAILABILITY_POLICY_ARTIFACT,
  PEERIT_AVAILABILITY_POLICY_FIELDS,
  PEERIT_AVAILABILITY_POLICY_HASH_DOMAIN,
  PEERIT_AVAILABILITY_POLICY_TAG,
  PEERIT_AVAILABILITY_POLICY_V1,
  assertAvailabilityPolicyRegistryBinding,
  availabilityPolicyHash,
  decodeAvailabilityPolicyV1,
  encodeAvailabilityPolicyV1
} from '../js/substrate/availability-policy.mjs'
import {
  decodePeeritProfileRegistry,
  encodePeeritProfileRegistry
} from '../js/substrate/profile-artifact-codec.mjs'
import { AVAILABILITY_POLICY_STATUS } from '../js/substrate/profile-status.mjs'

const registry = new Uint8Array(await readFile(new URL('../protocol/peerit-profile-v1.cenc', import.meta.url)))
const artifact = new Uint8Array(await readFile(new URL(`../${PEERIT_AVAILABILITY_POLICY_ARTIFACT}`, import.meta.url)))
const profileSource = await readFile(new URL('../docs/PEERIT-BLIND-SUBSTRATE-PROFILE.md', import.meta.url), 'utf8')

function availabilityDeclaration (source) {
  const match = source.match(/AvailabilityPolicyV1 \{\n([\s\S]*?)\n\}/)
  assert.ok(match, 'profile contains AvailabilityPolicyV1')
  return `AvailabilityPolicyV1 {\n${match[1]}\n}`
}

function declaredFields (source) {
  return availabilityDeclaration(source).split('\n').slice(1, -1).map(line => {
    const match = line.match(/^\s*([A-Za-z0-9]+):\s*(u8|u16|u32)\s*=\s*(.*?)(?:\s+\/\/.*)?$/)
    assert.ok(match, `canonical policy field declaration: ${line}`)
    const symbolic = {
      // HiveRelay generic class/profile bitmaps use bit position = nonzero ID.
      'profiles 1 and 2 only': (1 << 1) | (1 << 2),
      // HiveRelay universal lease/retention class IDs: 3=L30/R30, 4=L90/R90.
      L90: 4,
      R30: 3,
      // HiveRelay Inbox is explicit: bits 0..2 mean frame classes 1..3.
      'classes 1 and 2 only': (1 << (1 - 1)) | (1 << (2 - 1))
    }
    const value = Object.prototype.hasOwnProperty.call(symbolic, match[3])
      ? symbolic[match[3]]
      : Number(match[3])
    assert.equal(Number.isSafeInteger(value), true, `known policy constant: ${match[3]}`)
    return [match[1], match[2], value]
  })
}

assert.equal(assertAvailabilityPolicyRegistryBinding(registry), true)
assert.equal(PEERIT_AVAILABILITY_POLICY_TAG, 276)
assert.equal(PEERIT_AVAILABILITY_POLICY_FIELDS.length, 64)
assert.equal(PEERIT_AVAILABILITY_POLICY_HASH_DOMAIN, 'peerit.hiverelay.availability-policy-hash.v1')
assert.equal(artifact.byteLength, 97)
assert.deepEqual([...artifact.subarray(0, 2)], [0x01, 0x14])
assert.deepEqual(PEERIT_AVAILABILITY_POLICY_FIELDS, declaredFields(profileSource))
assert.equal(PEERIT_AVAILABILITY_POLICY_V1.allowedDurabilityProfileBits, 0x06)
assert.equal(PEERIT_AVAILABILITY_POLICY_V1.contentLeaseClass, 4)
assert.equal(PEERIT_AVAILABILITY_POLICY_V1.inboxLeaseClass, 4)
assert.equal(PEERIT_AVAILABILITY_POLICY_V1.inboxRetentionClass, 3)
assert.equal(PEERIT_AVAILABILITY_POLICY_V1.inboxFrameClassBits, 0x03)
assert.deepEqual(encodeAvailabilityPolicyV1(), artifact)
assert.deepEqual(decodeAvailabilityPolicyV1(artifact), PEERIT_AVAILABILITY_POLICY_V1)
assert.equal(Buffer.from(availabilityPolicyHash(artifact)).toString('hex'),
  AVAILABILITY_POLICY_STATUS.availabilityPolicyHash)

for (let length = 0; length < artifact.byteLength; length++) {
  assert.throws(() => decodeAvailabilityPolicyV1(artifact.subarray(0, length)))
}
for (let index = 0; index < artifact.byteLength; index++) {
  for (let replacement = 0; replacement <= 0xff; replacement++) {
    if (replacement === artifact[index]) continue
    const changed = artifact.slice()
    changed[index] = replacement
    assert.throws(() => decodeAvailabilityPolicyV1(changed),
      `replacement ${replacement} at byte ${index} must fail`)
  }
}
assert.throws(() => decodeAvailabilityPolicyV1(new Uint8Array([...artifact, 0])))
for (const [field, , value] of PEERIT_AVAILABILITY_POLICY_FIELDS) {
  assert.throws(() => encodeAvailabilityPolicyV1({
    ...PEERIT_AVAILABILITY_POLICY_V1,
    [field]: value === 0 ? 1 : 0
  }), error => error.code === 'BAD_AVAILABILITY_POLICY', `${field} is frozen`)
}
assert.throws(() => encodeAvailabilityPolicyV1({
  ...PEERIT_AVAILABILITY_POLICY_V1,
  minimumOperatorGroups: 2
}), error => error.code === 'BAD_AVAILABILITY_POLICY')
assert.throws(() => encodeAvailabilityPolicyV1({
  ...PEERIT_AVAILABILITY_POLICY_V1,
  extra: 1
}), error => error.code === 'BAD_AVAILABILITY_POLICY')
const accessor = { ...PEERIT_AVAILABILITY_POLICY_V1 }
Object.defineProperty(accessor, 'minimumOperatorGroups', { enumerable: true, get: () => 3 })
assert.throws(() => encodeAvailabilityPolicyV1(accessor), error => error.code === 'BAD_AVAILABILITY_POLICY')
const symbol = { ...PEERIT_AVAILABILITY_POLICY_V1, [Symbol('hidden')]: 1 }
assert.throws(() => encodeAvailabilityPolicyV1(symbol), error => error.code === 'BAD_AVAILABILITY_POLICY')

const decodedRegistry = decodePeeritProfileRegistry(registry)
const declaration = decodedRegistry.schemas.find(value => value.name === 'AvailabilityPolicyV1')
assert.equal(declaration.source, availabilityDeclaration(profileSource))

const alternateSource = structuredClone(decodedRegistry)
const alternateDeclaration = alternateSource.schemas.find(value => value.name === 'AvailabilityPolicyV1')
alternateDeclaration.source += ' '
alternateDeclaration.sourceHash = null
assert.throws(() => assertAvailabilityPolicyRegistryBinding(encodePeeritProfileRegistry(alternateSource)),
  error => error.code === 'AVAILABILITY_POLICY_REGISTRY_DRIFT')

const alternateCategory = structuredClone(decodedRegistry)
const moved = alternateCategory.schemas.find(value => value.name === 'AvailabilityPolicyV1')
const oldCategory = alternateCategory.categories.find(value => value.id === moved.categoryId)
const newCategory = alternateCategory.categories.find(value => value.id !== moved.categoryId)
oldCategory.schemaCount--
newCategory.schemaCount++
moved.categoryId = newCategory.id
assert.throws(() => assertAvailabilityPolicyRegistryBinding(encodePeeritProfileRegistry(alternateCategory)),
  error => error.code === 'AVAILABILITY_POLICY_REGISTRY_DRIFT')

console.log('peerit-availability-policy: 64 exact fields, HiveRelay bit/class conventions, registry binding, canonical artifact, hash, and exhaustive byte rejection passed')
