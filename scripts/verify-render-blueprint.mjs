#!/usr/bin/env node

// Keep the source-managed Render Blueprint's static headers byte-for-byte
// aligned with the reviewed API/dashboard policy. The deliberately constrained
// YAML layout makes this check dependency-free and catches drift in CI.

import { readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const blueprint = readFileSync(join(ROOT, 'render.yaml'), 'utf8')
const policy = JSON.parse(readFileSync(join(ROOT, 'deploy', 'render-security-headers.json'), 'utf8'))

function requireText (text, label) {
  if (!blueprint.includes(text)) throw new Error(`render.yaml is missing ${label}`)
}

requireText('name: peerit-site', 'the peerit-site service name')
requireText('runtime: static', 'the static runtime')
requireText('branch: main', 'the main deployment branch')
requireText('autoDeployTrigger: checksPass', 'the CI-gated deployment trigger')
requireText('buildCommand: "node scripts/web-release.mjs --verify-only --strict"', 'the frozen-artifact verifier build command')
requireText('staticPublishPath: web', 'the signed web publish directory')
requireText('key: SKIP_INSTALL_DEPS\n        value: "true"', 'the dependency-install-free static build setting')

for (const header of policy.headers) {
  const row = `      - path: ${JSON.stringify(policy.path)}\n        name: ${JSON.stringify(header.name)}\n        value: ${JSON.stringify(header.value)}`
  requireText(row, `${header.name} header policy`)
}

console.log(`[render-blueprint] PASS ${policy.headers.length} static headers match deploy/render-security-headers.json`)
