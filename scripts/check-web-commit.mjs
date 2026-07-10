#!/usr/bin/env node
// check-web-commit.mjs — ensure the signed static release is actually present
// in the Git tree that a static host will check out. `web/` is intentionally
// ignored while it is generated, so a local manifest can otherwise name a byte
// that Render never receives.
import { execFileSync } from 'node:child_process'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const ref = process.argv[2] || 'HEAD'

function git (args) {
  try {
    return execFileSync('git', args, { cwd: ROOT, encoding: 'utf8' })
  } catch (err) {
    const detail = String(err && err.stderr ? err.stderr : err && err.message ? err.message : '').trim()
    throw new Error(`git ${args[0]} failed${detail ? `: ${detail}` : ''}`)
  }
}

function isSafeWebPath (file) {
  return typeof file === 'string' &&
    /^[A-Za-z0-9._/-]+$/.test(file) &&
    !file.startsWith('/') &&
    !file.includes('//') &&
    file.split('/').every((part) => part && part !== '.' && part !== '..')
}

function addManifestEntries (expected, entries, label) {
  if (!entries || typeof entries !== 'object' || Array.isArray(entries)) {
    throw new Error(`asset-manifest.json ${label} is missing or invalid`)
  }
  for (const [file, hash] of Object.entries(entries)) {
    if (!isSafeWebPath(file) || !/^[0-9a-f]{64}$/i.test(String(hash || ''))) {
      throw new Error(`asset-manifest.json has an invalid ${label} entry: ${file}`)
    }
    expected.add(`web/${file}`)
  }
}

try {
  const manifest = JSON.parse(git(['show', `${ref}:web/asset-manifest.json`]))
  const expected = new Set(['web/asset-manifest.json', 'web/asset-manifest.sig'])
  addManifestEntries(expected, manifest.files, 'files')
  addManifestEntries(expected, manifest.controls, 'controls')

  const tracked = new Set(git(['ls-tree', '-r', '--name-only', ref]).trim().split('\n').filter(Boolean))
  const missing = [...expected].filter((file) => !tracked.has(file)).sort()
  if (missing.length) throw new Error(`${ref} is missing ${missing.length} signed web file${missing.length === 1 ? '' : 's'}: ${missing.join(', ')}`)

  console.log(`[web-commit] PASS ${expected.size} signed web files are present in ${ref}.`)
} catch (err) {
  console.error(`[web-commit] FAIL ${err.message}`)
  process.exitCode = 1
}
