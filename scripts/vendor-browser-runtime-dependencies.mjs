#!/usr/bin/env node
import { createHash } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const check = process.argv.includes('--check')
const packages = Object.freeze([
  Object.freeze({
    name: '@noble/hashes',
    version: '2.2.0',
    packageRoot: path.join(root, 'node_modules', '@noble', 'hashes'),
    sourceRoot: path.join(root, 'node_modules', '@noble', 'hashes'),
    destination: path.join(root, 'js', 'vendor', 'noble-hashes'),
    files: Object.freeze({
      'sha2.js': Object.freeze({ source: 'sha2.js', sha256: '0fb8e3c3f2c73a890be2524ac5d2542aaed4decff69e561231a86131203b3973' }),
      '_md.js': Object.freeze({ source: '_md.js', sha256: '8227b9b5cabf078a9d7f7317f7a1ace6e46627539aa9364667aec724e1636f14' }),
      '_u64.js': Object.freeze({ source: '_u64.js', sha256: '766b91a693a798f9d3cde97b25db4a6d0cef66b2ca21153d3d42424d37878870' }),
      'utils.js': Object.freeze({ source: 'utils.js', sha256: 'e2adfc13c846487feff0410bd5508a1d66f5ebadc3188f3a40a6b55449981e2f' })
    })
  }),
  Object.freeze({
    name: '@noble/ciphers',
    version: '1.3.0',
    packageRoot: path.join(root, 'node_modules', '@noble', 'ciphers'),
    sourceRoot: path.join(root, 'node_modules', '@noble', 'ciphers', 'esm'),
    destination: path.join(root, 'js', 'vendor', 'noble-ciphers'),
    files: Object.freeze({
      LICENSE: Object.freeze({ source: '../LICENSE', sha256: 'f36671a5487c9c5050efacb58011c37c24c55a889803cb036cf9d9a6347c1e2d' }),
      'chacha.js': Object.freeze({ source: 'chacha.js', sha256: 'ad0a9595ab6c083500fbb81c5ea14af4b79f57aa9b1a56b2d3ad738918865a9e' }),
      '_arx.js': Object.freeze({ source: '_arx.js', sha256: 'd4c0112267f8b6f7d4de238edf87b19e60e373aa438c5400ebf189ed1e42f95c' }),
      '_poly1305.js': Object.freeze({ source: '_poly1305.js', sha256: '9c7e5aaa972f03d8ca7fe3aa41340b6d4d1ee1228d414634e25e1beb539ac69f' }),
      'utils.js': Object.freeze({ source: 'utils.js', sha256: '306e36d8c59519a289756f5775e2fc2faed9b02b6b60029a7c8e3e943522e441' })
    })
  })
])

for (const dependency of packages) {
  const packageJson = JSON.parse(fs.readFileSync(path.join(dependency.packageRoot, 'package.json'), 'utf8'))
  if (packageJson.version !== dependency.version) {
    throw new Error(`expected ${dependency.name} ${dependency.version}, found ${packageJson.version}`)
  }
  fs.mkdirSync(dependency.destination, { recursive: true })
  for (const [name, record] of Object.entries(dependency.files)) {
    const bytes = fs.readFileSync(path.join(dependency.sourceRoot, record.source))
    if (createHash('sha256').update(bytes).digest('hex') !== record.sha256) {
      throw new Error(`${dependency.name} source drift: ${record.source}`)
    }
    const output = path.join(dependency.destination, name)
    if (check) {
      if (!fs.existsSync(output) || !fs.readFileSync(output).equals(bytes)) {
        throw new Error(`vendored browser runtime dependency drift: ${dependency.name}/${name}`)
      }
    } else fs.writeFileSync(output, bytes)
  }
  if (fs.readdirSync(dependency.destination).sort().join('\n') !==
      Object.keys(dependency.files).sort().join('\n')) {
    throw new Error(`vendored browser runtime dependency directory has missing or extra files: ${dependency.name}`)
  }
}
process.stdout.write(`${JSON.stringify({
  schema: 'PeeritVendoredBrowserRuntimeDependenciesV1',
  checked: check,
  packages: packages.map(dependency => ({
    name: dependency.name,
    version: dependency.version,
    files: Object.fromEntries(Object.entries(dependency.files)
      .map(([name, record]) => [name, record.sha256]))
  }))
}, null, 2)}\n`)
