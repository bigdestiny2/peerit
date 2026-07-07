#!/usr/bin/env node
// sign-shard-roster.mjs — sign the BlindShard cohort roster with the SAME roster
// seed that signs relay-roster.json (one Ed25519 anchor for both planes, §5.2).
//
//   PEERIT_ROSTER_SEED=<32-byte-hex> node scripts/sign-shard-roster.mjs \
//     [--in config/shard-roster.public.json] [--expires 2026-12-31T00:00:00.000Z]
//
// Input may be a bare roster ({threshold, relays:[{url,pubkey}]}) or an existing
// envelope ({payload,signature}); output is the signed envelope written in place.
// Refuses empty/duplicate pubkeys and a nonsense threshold — the same hard rules
// verifyShardRoster enforces at load, so a bad roster fails HERE, not in prod.
import { createPrivateKey, createPublicKey, sign as nodeSign } from 'node:crypto'
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { normalizeShardRosterPayload, shardRosterSigningMessage, verifyShardRoster, SHARD_ROSTER_ALG, SHARD_ROSTER_VERSION } from '../js/shard-roster.js'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const PKCS8_PREFIX = '302e020100300506032b657004220420'
const HEX64 = /^[0-9a-f]{64}$/i

function arg (name, dflt) { const i = process.argv.indexOf(name); return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : dflt }
function fail (msg) { console.error('sign-shard-roster: ' + msg); process.exit(1) }

const seed = (process.env.PEERIT_ROSTER_SEED || '').trim().toLowerCase()
if (!HEX64.test(seed)) fail('set PEERIT_ROSTER_SEED to the 32-byte (64 hex) roster seed (keyvault-managed — the same seed that signs relay-roster.json)')

const inPath = resolve(ROOT, arg('--in', 'config/shard-roster.public.json'))
if (!existsSync(inPath)) fail('no roster at ' + inPath)
const raw = JSON.parse(readFileSync(inPath, 'utf8'))
const base = raw.payload && typeof raw.payload === 'object' ? raw.payload : raw

const payload = normalizeShardRosterPayload({
  ...base,
  version: SHARD_ROSTER_VERSION,
  expires: arg('--expires', base.expires || new Date(Date.now() + 180 * 24 * 60 * 60 * 1000).toISOString())
})

const priv = createPrivateKey({ key: Buffer.from(PKCS8_PREFIX + seed, 'hex'), format: 'der', type: 'pkcs8' })
const pubHex = createPublicKey(priv).export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex')
const sigHex = nodeSign(null, Buffer.from(shardRosterSigningMessage(payload), 'utf8'), priv).toString('hex')

const envelope = { payload, signature: { alg: SHARD_ROSTER_ALG, key: pubHex, sig: sigHex } }
// Self-check with the very verifier the client runs — a roster that can't load in
// prod must not be writable here.
await verifyShardRoster(envelope, { expectedKey: pubHex })

writeFileSync(inPath, JSON.stringify(envelope, null, 2) + '\n')
console.log('sign-shard-roster: signed ' + inPath)
console.log('  roster key : ' + pubHex + '  (must equal pinnedRosterKey in deploy/web-release.json)')
console.log('  relays     : ' + payload.relays.map(r => r.url).join(', '))
console.log('  threshold  : ' + payload.threshold + '-of-' + payload.relays.length + '   expires ' + payload.expires)
