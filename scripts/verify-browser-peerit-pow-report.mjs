#!/usr/bin/env node

import { readFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { verifyBrowserPowEvidence } from './browser-peerit-pow-performance.mjs'

function usage () {
  return 'Usage: node scripts/verify-browser-peerit-pow-report.mjs --in FILE'
}

export function parseArgs (args) {
  let input = null
  let help = false
  for (let index = 0; index < args.length; index++) {
    const argument = args[index]
    if (argument === '--help') {
      help = true
      continue
    }
    const name = argument.split('=', 1)[0]
    if (name !== '--in') throw new Error(`unknown argument ${argument}`)
    const equals = argument.indexOf('=')
    if (equals !== -1) input = argument.slice(equals + 1)
    else {
      if (index + 1 >= args.length || args[index + 1].startsWith('--')) throw new Error('--in requires a value')
      input = args[++index]
    }
    if (!input) throw new Error('--in requires a non-empty value')
  }
  return { input, help }
}

async function main () {
  const options = parseArgs(process.argv.slice(2))
  if (options.help) {
    process.stdout.write(`${usage()}\n`)
    return
  }
  if (!options.input) throw new Error('--in is required')
  const report = JSON.parse(await readFile(resolve(options.input), 'utf8'))
  const verification = verifyBrowserPowEvidence(report)
  process.stdout.write(`${JSON.stringify(verification, null, 2)}\n`)
  if (!verification.verified) process.exitCode = 1
}

const invokedPath = process.argv[1] && resolve(process.argv[1])
if (invokedPath === fileURLToPath(import.meta.url)) {
  main().catch(error => {
    process.stderr.write(`[verify-browser-peerit-pow-report] FAIL ${String((error && (error.stack || error.message)) || error)}\n`)
    process.exitCode = 1
  })
}
