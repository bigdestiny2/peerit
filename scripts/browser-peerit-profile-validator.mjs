#!/usr/bin/env node
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { chromium } from 'playwright'
import { PROFILE_VALIDATOR_ARTIFACT_STATUS } from '../js/substrate/profile-status.mjs'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const artifact = fs.readFileSync(path.join(root, PROFILE_VALIDATOR_ARTIFACT_STATUS.artifact)).toString('base64')
const expected = `0101${'11'.repeat(32)}${'22'.repeat(32)}${'33'.repeat(32)}`
const browser = await chromium.launch({ headless: true })
try {
  const page = await browser.newPage()
  const result = await page.evaluate(async ({ artifact, expected }) => {
    const module = await import(`data:text/javascript;base64,${artifact}`)
    const bytes = module.computePeeritValidatorRuntimeVectorV1()
    let hex = ''
    for (const byte of bytes) hex += byte.toString(16).padStart(2, '0')
    const vectorSetHash = [...module.computePeeritValidatorRuntimeVectorSetHashV1()]
      .map(byte => byte.toString(16).padStart(2, '0')).join('')
    return {
      schemaCount: module.PEERIT_VALIDATOR_PROFILE_BINDING_V1.schemaCount,
      profileSpecHash: [...module.PEERIT_VALIDATOR_PROFILE_BINDING_V1.profileSpecHash]
        .map(byte => byte.toString(16).padStart(2, '0')).join(''),
      runtimeVector: hex,
      runtimeVectorEqual: hex === expected,
      vectorSetHash
    }
  }, { artifact, expected })
  if (result.schemaCount !== 78 || !result.runtimeVectorEqual ||
      result.vectorSetHash !== '84d0cfd27a3b078ea839b2ec35ae9df7dd4ab619faa39dd8bef805f0c2b1c77c' ||
      result.profileSpecHash !== '931a85e29eb3767d8d2a1920d7e127cf20d708cce6975d967522fd07f475f473') {
    throw new Error(`Chromium validator runtime drift: ${JSON.stringify(result)}`)
  }
  process.stdout.write(`${JSON.stringify({ schema: 'PeeritValidatorChromiumRuntimeV1', ...result })}\n`)
} finally {
  await browser.close()
}
