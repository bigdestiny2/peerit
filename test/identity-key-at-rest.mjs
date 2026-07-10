// identity-key-at-rest.mjs — regression for audit PT-IDK-002 / PT-BRW-002.
//
// Two coupled defects made the browser signing key a permanent, unrevocable
// sign-as-victim liability on peerit.site:
//   1. DevIdentity persisted the raw Ed25519 SEED in CLEARTEXT localStorage
//      ('peerit:dev:users'), and forceDev makes DevIdentity the PRODUCTION signing
//      path in web mode — so any same-origin script / XSS / shared-machine read
//      lifted a forever-valid signing key.
//   2. The page CSP connect-src carried an http:/https: WILDCARD, turning a local
//      read into remote exfiltration to any host.
//
// This test pins the fixes:
//   - the production (forceDev) DevIdentity keeps the seed in MEMORY ONLY: it is
//     never written to storage, and neither is the roster key that used to carry it,
//     while the identity still signs;
//   - resolveRuntime's web path does NOT opt into seed persistence (dev fallback may);
//   - a legacy cleartext roster left on disk is proactively cleared;
//   - the shipped index.html CSP has no http:/https: wildcard in connect-src;
//   - build-web's CSP patcher pins connect-src to the specific relay origins.
//
// Run: node test/identity-key-at-rest.mjs

import assert from 'node:assert'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { createIdentity, DevIdentity } from '../js/identity.js'
import { resolveRuntime } from '../js/runtime.js'
import { ready as cryptoReady, isSecure, verify as edVerify } from '../js/crypto.js'

const __dir = dirname(fileURLToPath(import.meta.url))
const ROOT = join(__dir, '..')
const ROSTER_KEY = 'peerit:dev:users'
const HEX64 = /^[0-9a-f]{64}$/i

let passed = 0
const ok = (c, m) => { assert.ok(c, m); passed++; console.log('  ✓ ' + m) }

// A localStorage stand-in that records every write, so we can assert exactly what
// (if anything) touched disk.
function spyStorage () {
  const m = new Map()
  return {
    _map: m,
    getItem: (k) => (m.has(k) ? m.get(k) : null),
    setItem: (k, v) => m.set(k, String(v)),
    removeItem: (k) => m.delete(k),
    dump: () => JSON.stringify([...m.entries()])
  }
}
function mem () { const m = new Map(); return { getItem: k => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: k => m.delete(k) } }

async function main () {
  await cryptoReady()
  const secure = isSecure()
  if (!secure) console.log('\n⚠ no Ed25519 backend in this Node; seed-hex is a placeholder but the at-rest assertions still hold\n')

  console.log('\n— production (forceDev) path: the SEED is never written to cleartext storage —')
  {
    const storage = spyStorage()
    const session = mem()
    // Exactly the web/production identity opts from resolveRuntime, minus the relay
    // transport fields that DevIdentity ignores.
    const id = createIdentity({ pear: null, forceDev: true, storage, session })
    await id.ready()
    ok(id.isDev === true, 'web forceDev path resolves to DevIdentity (the browser signs; the relay never does)')

    // Nothing at all should have hit disk — no roster key, no seed anywhere.
    ok(storage.getItem(ROSTER_KEY) === null, `the cleartext roster key '${ROSTER_KEY}' is NOT written to storage`)
    const dumped = storage.dump()
    const me = id.me()
    ok(HEX64.test(me.pubkey), 'the identity has a real public key')
    // The seed must never appear in ANY persisted value.
    const secret = id.currentSeedEntry()
    ok(secret && HEX64.test(secret.seed), 'currentSeedEntry still yields the seed in memory (for export / dispersal)')
    ok(!dumped.includes(secret.seed), 'the raw seed does NOT appear anywhere in persisted storage')

    // Create a second user and switch — still nothing persisted.
    await id.createUser('second')
    ok(storage.getItem(ROSTER_KEY) === null, 'creating another user still writes NOTHING to storage')
    ok(!storage.dump().includes(id.currentSeedEntry().seed), 'the second user seed is also memory-only')

    // But the in-memory identity is fully functional and can actually sign.
    const sig = await id.sign('hello world')
    ok(sig && sig.publicKey === id.me().pubkey, 'the memory-only identity produces a signature')
    if (secure) ok(await edVerify(sig.publicKey, `pear.app.${sig.driveKey}:peerit:hello world`, sig.signature), 'that signature verifies against the public key (a real, usable key)')
  }

  console.log('\n— a legacy cleartext roster on disk is proactively purged —')
  {
    const storage = spyStorage()
    // Simulate a roster left behind by an older build that DID persist the seed.
    storage.setItem(ROSTER_KEY, JSON.stringify([{ pubkey: 'a'.repeat(64), seed: 'b'.repeat(64), driveKey: 'a'.repeat(64), label: 'legacy' }]))
    const id = createIdentity({ pear: null, forceDev: true, storage, session: mem() })
    await id.ready() // ready() mints a fresh in-memory identity and re-saves the roster
    ok(storage.getItem(ROSTER_KEY) === null, 'a pre-existing cleartext roster is removed from storage on first save')
    ok(!storage.dump().includes('b'.repeat(64)), 'the legacy seed no longer exists in storage')
  }

  console.log('\n— local dev fallback MAY persist (developer convenience, own machine only) —')
  {
    const storage = spyStorage()
    const id = new DevIdentity(storage, mem(), { persistSeed: true })
    await id.ready()
    ok(storage.getItem(ROSTER_KEY) !== null, 'persistSeed:true (local dev fallback) does persist the roster for reload durability')
    ok(id.currentSeedEntry() && HEX64.test(id.currentSeedEntry().seed), 'and the persisted dev identity carries a seed')
  }

  console.log('\n— resolveRuntime: web mode never enables the cleartext DevIdentity roster; only local dev opts in —')
  {
    const web = resolveRuntime({ rawPear: null, doc: doc({ 'peerit-relay': 'https://relay.peerit.site' }) })
    ok(web.mode === 'web' && web.identityOpts.forceDev === true, 'relay meta with no host bridge → web mode with forceDev identity')
    ok(web.identityOpts.persistSeed !== true, 'web mode does NOT enable the cleartext seed roster (app durability uses encrypted IndexedDB separately)')

    const dev = resolveRuntime({ rawPear: null, doc: doc({}) })
    ok(dev.mode === 'dev' && dev.identityOpts.persistSeed === true, 'the local dev fallback opts into persistSeed (own-machine convenience)')
  }

  console.log('\n— CSP: no http:/https: wildcard in connect-src of the shipped index.html —')
  {
    const html = readFileSync(join(ROOT, 'index.html'), 'utf8')
    const m = html.match(/Content-Security-Policy" content="([^"]*)"/)
    ok(m, 'index.html declares a Content-Security-Policy')
    const csp = m[1]
    const connect = (csp.split(';').map(s => s.trim()).find(s => s.startsWith('connect-src')) || '')
    ok(connect && !/\bhttps?:(\s|$)/.test(connect), `connect-src has no bare http:/https: wildcard (${connect})`)
    const img = (csp.split(';').map(s => s.trim()).find(s => s.startsWith('img-src')) || '')
    ok(img && !/\bhttps?:(\s|$)/.test(img), 'img-src has no bare http:/https: wildcard either')
  }

  console.log('\n— build-web CSP patcher pins connect-src to the specific relay origins —')
  {
    const { patchCspForWeb, cspConnectOrigin } = await import('../scripts/csp.mjs')
    const base = '<meta http-equiv="Content-Security-Policy" content="default-src \'self\'; connect-src \'self\' hyper: pear:">'
    const out = patchCspForWeb(base, { dhtRelay: '', connectOrigins: ['https://relay.peerit.site'] })
    ok(out.includes("connect-src 'self' hyper: pear: https://relay.peerit.site"), 'patchCspForWeb appends the exact relay origin to connect-src')
    ok(!/connect-src[^;"]*\bhttps?:(\s|;|")/.test(out), 'patchCspForWeb never reintroduces an http:/https: wildcard')
    const out2 = patchCspForWeb(base.replace('connect-src', "script-src 'self'; connect-src"), { dhtRelay: 'wss://dht.x', connectOrigins: [] })
    ok(out2.includes("'wasm-unsafe-eval'") && out2.includes('wss://dht.x'), 'a DHT relay adds wasm-unsafe-eval + the ws origin')
    // same-origin / relative bases need no explicit source (self covers them).
    ok(cspConnectOrigin('same-origin') === null && cspConnectOrigin('/') === null, 'same-origin/relative relay bases contribute no connect-src entry')
    ok(cspConnectOrigin('https://a.example/x') === 'https://a.example', 'a base URL is reduced to its origin')
  }

  console.log(`\n✅ all ${passed} key-at-rest / CSP checks passed\n`)
}

// Minimal fake document whose querySelector resolves meta[name="..."] lookups.
function doc (metas = {}) {
  return {
    querySelector: (sel) => {
      const mm = sel.match(/meta\[name="([^"]+)"\]/)
      const name = mm && mm[1]
      return name && Object.prototype.hasOwnProperty.call(metas, name) ? { getAttribute: () => metas[name] } : null
    }
  }
}

main().catch((e) => { console.error('\n❌ FAILED:', e.message, '\n', e.stack); process.exit(1) })
