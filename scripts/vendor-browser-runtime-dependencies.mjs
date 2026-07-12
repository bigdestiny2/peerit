#!/usr/bin/env node
import { createHash } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const source = path.join(root, 'node_modules', '@noble', 'hashes')
const destination = path.join(root, 'js', 'vendor', 'noble-hashes')
const check = process.argv.includes('--check')
const expected = Object.freeze({
  'sha2.js': '0fb8e3c3f2c73a890be2524ac5d2542aaed4decff69e561231a86131203b3973',
  '_md.js': '8227b9b5cabf078a9d7f7317f7a1ace6e46627539aa9364667aec724e1636f14',
  '_u64.js': '766b91a693a798f9d3cde97b25db4a6d0cef66b2ca21153d3d42424d37878870',
  'utils.js': 'e2adfc13c846487feff0410bd5508a1d66f5ebadc3188f3a40a6b55449981e2f'
})
const packageJson = JSON.parse(fs.readFileSync(path.join(source, 'package.json'), 'utf8'))
if (packageJson.version !== '2.2.0') throw new Error(`expected @noble/hashes 2.2.0, found ${packageJson.version}`)
fs.mkdirSync(destination, { recursive: true })
for (const [name, hash] of Object.entries(expected)) {
  const bytes = fs.readFileSync(path.join(source, name))
  if (createHash('sha256').update(bytes).digest('hex') !== hash) {
    throw new Error(`@noble/hashes source drift: ${name}`)
  }
  const output = path.join(destination, name)
  if (check) {
    if (!fs.existsSync(output) || !fs.readFileSync(output).equals(bytes)) {
      throw new Error(`vendored browser hash dependency drift: ${name}`)
    }
  } else fs.writeFileSync(output, bytes)
}
if (fs.readdirSync(destination).sort().join('\n') !== Object.keys(expected).sort().join('\n')) {
  throw new Error('vendored browser hash dependency directory has missing or extra files')
}
process.stdout.write(`${JSON.stringify({
  schema: 'PeeritVendoredBrowserRuntimeDependenciesV1',
  checked: check,
  package: '@noble/hashes',
  version: packageJson.version,
  files: expected
}, null, 2)}\n`)
