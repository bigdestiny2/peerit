#!/usr/bin/env node
import sodiumNative from 'sodium-native'
import { build } from 'esbuild'
import { chromium } from 'playwright'

const entry = `
import { PEERIT_CONTEXTUAL_GRAPH_CRYPTO_V1 } from './js/substrate/profile-contextual-graph-validator.mjs';
export function runVector(){
  const plaintext=new Uint8Array(257).map((_,index)=>index&255);
  const aad=new Uint8Array(93).map((_,index)=>(index*7)&255);
  const nonce=new Uint8Array(24).map((_,index)=>(index*11)&255);
  const key=new Uint8Array(32).map((_,index)=>(index*13)&255);
  const cipher=PEERIT_CONTEXTUAL_GRAPH_CRYPTO_V1.xchacha20poly1305Encrypt(plaintext,aad,nonce,key);
  const recovered=PEERIT_CONTEXTUAL_GRAPH_CRYPTO_V1.xchacha20poly1305Decrypt(cipher,aad,nonce,key);
  return {cipher,recovered};
}
`

const built = await build({
  stdin: { contents: entry, resolveDir: process.cwd(), sourcefile: 'peerit-contextual-browser-vector.entry.mjs' },
  bundle: true,
  write: false,
  format: 'esm',
  platform: 'browser',
  target: ['es2020'],
  minify: true,
  legalComments: 'none',
  logLevel: 'silent'
})
if (built.outputFiles.length !== 1) throw new Error('contextual browser vector produced an unexpected output set')
const artifact = Buffer.from(built.outputFiles[0].contents).toString('base64')

const plaintext = new Uint8Array(257).map((_, index) => index & 0xff)
const aad = new Uint8Array(93).map((_, index) => (index * 7) & 0xff)
const nonce = new Uint8Array(24).map((_, index) => (index * 11) & 0xff)
const key = new Uint8Array(32).map((_, index) => (index * 13) & 0xff)
const expected = new Uint8Array(plaintext.byteLength + 16)
sodiumNative.crypto_aead_xchacha20poly1305_ietf_encrypt(expected, plaintext, aad, null, nonce, key)

const browser = await chromium.launch({ headless: true })
try {
  const page = await browser.newPage()
  const result = await page.evaluate(async ({ artifact, expected }) => {
    const module = await import(`data:text/javascript;base64,${artifact}`)
    const vector = module.runVector()
    const equal = (left, right) => left.length === right.length && left.every((byte, index) => byte === right[index])
    return {
      cipherEqual: equal(vector.cipher, expected),
      plaintextEqual: equal(vector.recovered, new Uint8Array(257).map((_, index) => index & 255)),
      cipherBytes: vector.cipher.byteLength
    }
  }, { artifact, expected: [...expected] })
  if (!result.cipherEqual || !result.plaintextEqual || result.cipherBytes !== 273) {
    throw new Error(`Chromium contextual crypto drift: ${JSON.stringify(result)}`)
  }
  process.stdout.write(`${JSON.stringify({ schema: 'PeeritContextualGraphChromiumVectorV1', ...result })}\n`)
} finally {
  await browser.close()
}
