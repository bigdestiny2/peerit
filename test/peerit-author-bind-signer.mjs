import assert from 'node:assert/strict'
import { verifyBytes } from '../js/crypto.js'
import { createPeeritLocalIdentityV1 } from '../js/substrate/local-identity.js'

let passed = 0
async function test (name, operation) {
  await operation()
  passed++
  process.stdout.write(`ok ${passed} - ${name}\n`)
}

function domainPrefix (prefix) {
  const domain = new TextEncoder().encode('peerit.hiverelay.author-bind.v1')
  const output = new Uint8Array(domain.byteLength + prefix.byteLength)
  output.set(domain)
  output.set(prefix, domain.byteLength)
  return output
}

function hexBytes (value) {
  const output = new Uint8Array(value.length / 2)
  for (let index = 0; index < output.byteLength; index++) {
    output[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16)
  }
  return output
}

await test('an identity-less lurker cannot produce an AuthorBindV1 signature', async () => {
  const identity = createPeeritLocalIdentityV1()
  await assert.rejects(
    identity.signAuthorBindV1(Uint8Array.of(1)),
    error => error && error.code === 'PEERIT_DURABLE_IDENTITY_REQUIRED'
  )
})

const identity = createPeeritLocalIdentityV1()
const entry = await identity.mintEntry('author-bind-test')
await identity.restoreFromDevice(entry)
const prefix = Uint8Array.of(0x00, 0xff, 0x80, 0x2a)
const signature = await identity.signAuthorBindV1(prefix)

await test('the fixed-domain signer signs exact non-UTF-8 AuthorBindV1 prefix bytes', async () => {
  assert.equal(signature.byteLength, 64)
  assert.equal(await verifyBytes(entry.pubkey, domainPrefix(prefix), signature), true)
})

await test('prefix and domain substitution invalidate the raw AuthorBindV1 signature', async () => {
  const tampered = new Uint8Array(prefix)
  tampered[1] ^= 1
  assert.equal(await verifyBytes(entry.pubkey, domainPrefix(tampered), signature), false)
  assert.equal(await verifyBytes(entry.pubkey, new TextEncoder().encode('other.domain'), signature), false)
})

await test('the legacy app-envelope signature cannot be confused with an AuthorBindV1 signature', async () => {
  const legacy = await identity.sign('binary-looking-but-app-envelope')
  assert.equal(await verifyBytes(entry.pubkey, domainPrefix(prefix), hexBytes(legacy.signature)), false)
})

await test('the narrow signer rejects non-Uint8Array and empty protocol prefixes', async () => {
  await assert.rejects(
    identity.signAuthorBindV1(new ArrayBuffer(2)),
    error => error && error.code === 'PEERIT_AUTHOR_BIND_PREFIX_INVALID'
  )
  await assert.rejects(
    identity.signAuthorBindV1(new Uint8Array(0)),
    error => error && error.code === 'PEERIT_AUTHOR_BIND_PREFIX_INVALID'
  )
})

await test('deactivation immediately removes the AuthorBindV1 signing capability', async () => {
  identity.deactivate()
  await assert.rejects(
    identity.signAuthorBindV1(prefix),
    error => error && error.code === 'PEERIT_DURABLE_IDENTITY_REQUIRED'
  )
})

process.stdout.write(`peerit-author-bind-signer: ${passed}/6 passed\n`)
