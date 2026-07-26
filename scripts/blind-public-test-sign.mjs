#!/usr/bin/env node
// blind-public-test-sign.mjs — sign/verify bind-scoped canary artifacts with
// the offline Peerit Ed25519 release key (keyvault-injected seed only; the
// seed is never printed or persisted).
//
//   keyvault exec --only peerit/release/signing-seed -- \
//     node scripts/blind-public-test-sign.mjs sign <file> [<file>...]
//   node scripts/blind-public-test-sign.mjs verify <file> [<file>...]
//
// Produces <file>.sig.json: { schema, alg, key, sig, signedBytesSha256 }.
// The signature covers the exact file bytes (Ed25519, no digest algorithm).
// The derived public key must equal the pinned release key in
// deploy/web-release.json, so a wrong seed fails closed.

import { createHash, createPrivateKey, createPublicKey, sign as nodeSign, verify as nodeVerify } from 'node:crypto'
import { readFileSync, writeFileSync, existsSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const PKCS8_PREFIX = '302e020100300506032b657004220420'
const SPKI_ED25519_PREFIX = '302a300506032b6570032100'
const HEX64 = /^[0-9a-f]{64}$/i
const SIG_SCHEMA = 'peerit-blind-public-test-artifact-sig/v1'

function sha256 (bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

function pinnedReleaseKey () {
  const config = JSON.parse(readFileSync(resolve(ROOT, 'deploy', 'web-release.json'), 'utf8'))
  return String(config.pinnedReleaseKey || '').toLowerCase()
}

function publicKeyFromSeed (seed) {
  const priv = createPrivateKey({ key: Buffer.from(PKCS8_PREFIX + seed, 'hex'), format: 'der', type: 'pkcs8' })
  return {
    priv,
    pubHex: createPublicKey(priv).export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex')
  }
}

function fail (message) {
  console.error(`[bind-sign] FAIL ${message}`)
  process.exit(1)
}

function signFiles (files) {
  const seed = (process.env.PEERIT_RELEASE_SEED || process.env.PEERIT_RELEASE_SIGNING_SEED || '').trim().toLowerCase()
  if (!HEX64.test(seed)) fail('set PEERIT_RELEASE_SIGNING_SEED via keyvault exec (never inline)')
  const { priv, pubHex } = publicKeyFromSeed(seed)
  const pinned = pinnedReleaseKey()
  if (pinned && pubHex !== pinned) fail(`seed derives ${pubHex} but deploy/web-release.json pins ${pinned}; refusing to sign`)
  for (const file of files) {
    const path = resolve(ROOT, file)
    if (!existsSync(path)) fail(`no such file: ${file}`)
    const bytes = readFileSync(path)
    const sig = nodeSign(null, bytes, priv).toString('hex')
    const out = {
      schema: SIG_SCHEMA,
      alg: 'ed25519',
      key: pubHex,
      sig,
      signedBytesSha256: sha256(bytes),
      signedFile: file.replace(/\\/g, '/'),
      note: 'signature covers the exact current bytes of signedFile'
    }
    writeFileSync(`${path}.sig.json`, `${JSON.stringify(out, null, 2)}\n`)
    console.log(`[bind-sign] signed ${file} (sha256 ${sha256(bytes).slice(0, 16)}…)`)
  }
}

function verifyFiles (files) {
  let ok = true
  for (const file of files) {
    const path = resolve(ROOT, file)
    const sigPath = `${path}.sig.json`
    if (!existsSync(path) || !existsSync(sigPath)) fail(`missing file or signature: ${file}`)
    const bytes = readFileSync(path)
    const envelope = JSON.parse(readFileSync(sigPath, 'utf8'))
    if (envelope.schema !== SIG_SCHEMA || envelope.alg !== 'ed25519' ||
        !HEX64.test(envelope.key || '') || !/^[0-9a-f]{128}$/i.test(envelope.sig || '')) {
      fail(`bad signature envelope for ${file}`)
    }
    if (envelope.signedBytesSha256 !== sha256(bytes)) {
      console.error(`[bind-sign] FAIL ${file}: bytes changed after signing`)
      ok = false
      continue
    }
    const valid = nodeVerify(null, bytes, {
      key: Buffer.concat([Buffer.from(SPKI_ED25519_PREFIX, 'hex'), Buffer.from(envelope.key, 'hex')]),
      format: 'der',
      type: 'spki'
    }, Buffer.from(envelope.sig, 'hex'))
    if (!valid) {
      console.error(`[bind-sign] FAIL ${file}: signature invalid`)
      ok = false
      continue
    }
    console.log(`[bind-sign] PASS ${file} (key ${envelope.key.slice(0, 16)}…)`)
  }
  if (!ok) process.exit(1)
}

const [mode, ...files] = process.argv.slice(2)
if (!['sign', 'verify'].includes(mode) || files.length === 0) {
  console.error('usage: node scripts/blind-public-test-sign.mjs sign|verify <file> [...]')
  process.exit(2)
}
if (mode === 'sign') signFiles(files)
else verifyFiles(files)
