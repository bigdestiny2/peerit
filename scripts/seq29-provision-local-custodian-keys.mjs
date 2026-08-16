#!/usr/bin/env node

// Offline create-only provisioning for the three Seq29 local X25519
// custodian private-key files. The CLI accepts no entropy or fault fixtures.

import { resolve } from 'node:path'
import { pathToFileURL } from 'node:url'

import {
  provisionPeeritSeq29LocalCustodianKeysV1
} from './lib/seq29-local-custodian-key-provisioning.mjs'

const USAGE = `Usage:
  node scripts/seq29-provision-local-custodian-keys.mjs <absolute-new-directory>

The parent must already be a safe operator-owned real directory. The target
must never have existed. No private-key bytes or file paths are printed.

Failure/crash retry rule: never reuse or automatically clean a failed target.
Preserve all available evidence and retry with a fresh absolute target path.
`

function safeFailure (cause) {
  if (typeof cause?.code === 'string' &&
      cause.code.startsWith('PEERIT_SEQ29_CUSTODIAN_PROVISION_')) {
    return `${cause.code}: ${cause.message}\n`
  }
  return 'PEERIT_SEQ29_CUSTODIAN_PROVISION_IO_FAILED: provisioning failed without exposing details\n'
}

export function runPeeritSeq29LocalCustodianKeyProvisioningCliV1 (
  argv = process.argv.slice(2)
) {
  if (argv.length === 1 && (argv[0] === '--help' || argv[0] === '-h')) {
    process.stdout.write(USAGE)
    return 0
  }
  if (argv.length !== 1) {
    process.stderr.write(USAGE)
    return 2
  }
  try {
    const result = provisionPeeritSeq29LocalCustodianKeysV1({
      directory: argv[0]
    })
    process.stdout.write(JSON.stringify(result) + '\n')
    return 0
  } catch (cause) {
    process.stderr.write(safeFailure(cause))
    return 1
  }
}

const direct = process.argv[1] != null &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
if (direct) process.exitCode = runPeeritSeq29LocalCustodianKeyProvisioningCliV1()
