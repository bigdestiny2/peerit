// runtime.mjs — locks the guarantee that the web deployment NEVER changes what
// PearBrowser users get. The web path may only be reached when there is no host
// bridge; whenever window.pear (desktop) or a host-injected same-origin token
// (mobile) is present, peerit uses the host path with host-held keys — even if a
// relay <meta> is also baked into the page. Run: node test/runtime.mjs

import assert from 'node:assert'
import { resolveRuntime, readShardRosterConfig, fetchShardRoster, parseShardRelays } from '../js/runtime.js'
import { createIdentity } from '../js/identity.js'
import { createSync } from '../js/sync.js'

let passed = 0
const ok = (c, m) => { assert.ok(c, m); passed++; console.log('  ✓ ' + m) }

// Minimal fake document whose querySelector resolves meta[name="..."] lookups.
function doc (metas = {}) {
  return {
    querySelector: (sel) => {
      const m = sel.match(/meta\[name="([^"]+)"\]/)
      const name = m && m[1]
      return name && Object.prototype.hasOwnProperty.call(metas, name) ? { getAttribute: () => metas[name] } : null
    }
  }
}
function fullPear () {
  return {
    sync: { create: async () => ({}), join: async () => ({}), append: async () => ({}), get: async () => null, list: async () => [] },
    identity: { getPublicKey: async () => ({ publicKey: 'a'.repeat(64), driveKey: 'a'.repeat(64) }), sign: async () => ({ signature: 'd'.repeat(128) }) },
    swarm: { v1: { join: async () => ({ peers: [], on () {} }) } }
  }
}
function mem () { const m = new Map(); return { getItem: k => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: k => m.delete(k), clear: () => m.clear() } }
const noFetch = async () => ({ ok: true, status: 200, text: async () => 'null' })

async function main () {
  console.log('\n— runtime dispatch: PearBrowser is never altered by web config —')

  // window.pear present → host path, empty opts, EVEN with a relay meta baked in.
  const rt1 = resolveRuntime({ rawPear: fullPear(), doc: doc({ 'peerit-relay': 'https://relay.peerit.com', 'peerit-relay-token': 'x' }) })
  ok(rt1.mode === 'pearbrowser' && rt1.identityOpts.forceDev === undefined && rt1.syncOpts.apiBase === undefined && rt1.readOnly === false,
    'window.pear present → host path with empty opts, ignoring a baked-in relay meta')

  // host-injected same-origin token (mobile) → host path, no forceDev.
  const rt2 = resolveRuntime({ rawPear: null, doc: doc({ 'pear-api-token': 'host-tok' }) })
  ok(rt2.mode === 'pearbrowser-mobile' && rt2.identityOpts.forceDev === undefined && rt2.readOnly === false,
    'host-injected same-origin token → mobile host path (host identity), no forceDev')
  const rt2b = resolveRuntime({ rawPear: null, doc: doc({ 'pear-api-token': 'host-tok', 'peerit-relay': 'https://relay.peerit.com' }) })
  ok(rt2b.mode === 'pearbrowser-mobile', 'host token takes precedence over a relay meta')

  // relay meta only (no host bridge) → web: forceDev on IDENTITY only, remote sync, read-only default.
  const rt3 = resolveRuntime({ rawPear: null, doc: doc({ 'peerit-relay': 'https://relay.peerit.com', 'peerit-relay-token': 'pub' }) })
  ok(rt3.mode === 'web' && rt3.identityOpts.forceDev === true && rt3.identityOpts.apiBase === 'https://relay.peerit.com' &&
    rt3.syncOpts.apiBase === 'https://relay.peerit.com' && rt3.syncOpts.forceDev === undefined && rt3.readOnly === true,
    'web: forceDev on IDENTITY only (never sync), remote relay for sync, read-only by default')
  const rt3w = resolveRuntime({ rawPear: null, doc: doc({ 'peerit-relay': 'https://relay.peerit.com', 'peerit-relay-readonly': 'false' }) })
  ok(rt3w.readOnly === false, 'web read-only can be opted out via meta')
  // same-origin relay (proxied under the page origin) → apiBase ''
  const rt3s = resolveRuntime({ rawPear: null, doc: doc({ 'peerit-relay': 'same-origin' }) })
  ok(rt3s.mode === 'web' && rt3s.identityOpts.forceDev === true && rt3s.identityOpts.apiBase === '' && rt3s.syncOpts.apiBase === '', 'web same-origin → apiBase "" (relay proxied under the page origin), forceDev identity')
  // comma-separated failover list
  const rtMulti = resolveRuntime({ rawPear: null, doc: doc({ 'peerit-relay': 'https://a.example, https://b.example' }) })
  ok(rtMulti.mode === 'web' && Array.isArray(rtMulti.relays) && rtMulti.relays.length === 2 && rtMulti.relays[0] === 'https://a.example' && rtMulti.identityOpts.apiBase === 'https://a.example', 'web: comma-separated relays parse into a failover list (first is primary)')
  const rtRoster = resolveRuntime({ rawPear: null, doc: doc({ 'peerit-relay': 'https://a.example', 'peerit-relay-roster': 'relay-roster.json', 'peerit-relay-roster-key': 'f'.repeat(64) }) })
  ok(rtRoster.mode === 'web' && rtRoster.relayRoster.url === 'relay-roster.json' && rtRoster.relayRoster.key === 'f'.repeat(64),
    'web: signed relay roster metadata is retained for boot-time verification')

  // nothing configured → local dev fallback.
  const rt4 = resolveRuntime({ rawPear: null, doc: doc({}) })
  ok(rt4.mode === 'dev' && rt4.identityOpts.forceDev === undefined, 'no host bridge, no relay → local dev fallback')

  console.log('\n— shard cohort config detection —')
  ok(readShardRosterConfig(doc({})) === null, 'no shard meta → no shard cohort config')
  const sCfg1 = readShardRosterConfig(doc({ 'peerit-shard-relays': 'https://a.example, https://b.example' }))
  ok(sCfg1 && sCfg1.relays.length === 2 && sCfg1.relays[0] === 'https://a.example', 'inline shard relays parse into a list')
  const sCfg2 = readShardRosterConfig(doc({ 'peerit-shard-roster': 'config/shard-roster.json', 'peerit-shard-threshold': '2' }))
  ok(sCfg2 && sCfg2.rosterUrl === 'config/shard-roster.json' && sCfg2.threshold === 2, 'shard roster URL + threshold are retained')
  const rtShard = resolveRuntime({ rawPear: null, doc: doc({ 'peerit-shard-roster': 'config/shard-roster.json' }) })
  ok(rtShard.shardCohort && rtShard.shardCohort.rosterUrl === 'config/shard-roster.json', 'resolveRuntime exposes shardCohort in dev fallback')
  ok(parseShardRelays('http://127.0.0.1:8801, https://a.example').length === 2, 'local http shard relays are allowed')
  ok(parseShardRelays('javascript:alert(1), ftp://x').length === 0, 'dangerous shard relay schemes are rejected')

  const goodFetch = async () => ({ ok: true, status: 200, text: async () => JSON.stringify({ threshold: 2, relays: ['http://127.0.0.1:8801', { url: 'http://127.0.0.1:8802', pubkey: 'b'.repeat(64) }] }) })
  const roster = await fetchShardRoster({ url: 'config/shard-roster.json', fetch: goodFetch })
  ok(roster && roster.threshold === 2 && roster.relays.length === 2 && roster.relays[1].pubkey === 'b'.repeat(64), 'fetchShardRoster parses and normalizes a roster JSON')

  const badFetch = async () => ({ ok: true, status: 200, text: async () => JSON.stringify({ threshold: 2, relays: ['http://127.0.0.1:8801'] }) })
  const rosterBad = await fetchShardRoster({ url: 'config/shard-roster.json', fetch: badFetch })
  ok(rosterBad === null, 'fetchShardRoster rejects a roster with fewer than 2 relays')

  console.log('\n— factory integration: keys land in the right place —')
  // Host opts → BridgeIdentity (host keys), even with a relay configured.
  const id1 = createIdentity({ pear: fullPear(), ...rt1.identityOpts, storage: mem(), session: mem() })
  ok(id1.isDev === false, 'host path → BridgeIdentity (host-held keys), unaffected by relay config')
  // Host sync opts (empty) + injected pear → BridgeGossipSync, not dev sync.
  const s1 = createSync({ pear: fullPear(), ...rt1.syncOpts, getMe: () => 'x', identity: {}, storage: mem() })
  ok(s1.mode === 'gossip-bridge', 'host path → BridgeGossipSync over window.pear (real P2P), not dev sync')

  // Web identity opts → DevIdentity (browser-held keys); the relay never signs.
  const id3 = createIdentity({ pear: null, ...rt3.identityOpts, fetch: noFetch, storage: mem(), session: mem() })
  ok(id3.isDev === true, 'web path → DevIdentity (browser-held keys); the remote relay never signs for the user')

  console.log(`\n✅ all ${passed} runtime checks passed\n`)
}

main().catch((e) => { console.error('\n❌ FAILED:', e.message, '\n', e.stack); process.exit(1) })
