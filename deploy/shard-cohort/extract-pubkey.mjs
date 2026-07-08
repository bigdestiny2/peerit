#!/usr/bin/env node
// extract-pubkey.mjs — read a HiveRelay relay-identity.json and emit a roster
// entry for peerit's shard cohort config.
//
// Usage:
//   node extract-pubkey.mjs /path/to/relay/storage https://shard-a.example.com [apiKey]
import fs from 'node:fs'
import path from 'node:path'

const storage = process.argv[2]
const baseUrl = process.argv[3]
const apiKey = process.argv[4] || ''

if (!storage || !baseUrl) {
  console.error('usage: node extract-pubkey.mjs <relay-storage-dir> <baseUrl> [apiKey]')
  process.exit(2)
}

const idPath = path.join(storage, 'relay-identity.json')
if (!fs.existsSync(idPath)) {
  console.error(`relay-identity.json not found at ${idPath}`)
  console.error('  start the relay once so it generates its identity.')
  process.exit(2)
}

const id = JSON.parse(fs.readFileSync(idPath, 'utf8'))
const entry = { baseUrl, pubkey: id.publicKey }
if (apiKey) entry.apiKey = apiKey
console.log(JSON.stringify(entry, null, 2))
