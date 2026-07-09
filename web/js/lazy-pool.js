// A pear-shaped facade over the relay pool that exists BEFORE any relay is
// selected. Every call fails fast until the real pool is plugged in; the gossip
// layer already tolerates that everywhere (offline-deferred outbox, try/caught
// joins, poll retries), so the app renders the cached view instantly while
// selection happens in the background.
//
// The shape is load-bearing: createSync() (js/sync.js) routes on the pear-api.js
// surface predicates, and a bridge that has SOME surfaces but not the full gossip
// set throws rather than silently falling back to local dev sync. So this facade
// MUST satisfy hasGossipPearSurface() — sync + identity + swarm.v1 — or web boot
// wedges for every visitor (regression fixed in 14d8ace; guarded by
// test/lazy-pool-surface.mjs). Kept in its own Node-importable module (no browser
// globals) precisely so that test can exercise the real factory.
export function createLazyPearPool () {
  let target = null
  const notUp = () => new Error('relay not connected yet')
  const pear = {
    get _relayCount () { return target ? target._relayCount : 0 },
    sync: {},
    // identity is REQUIRED for hasGossipPearSurface() (js/pear-api.js). Without it
    // createSync sees an incomplete PearBrowser-shaped bridge (sync + swarm, no
    // identity) and THROWS, wedging web boot for every visitor. The gossip layer
    // never calls pear.identity (it uses opts.identity) — these only satisfy the
    // shape check; delegate to the real pool once connected in case anything does.
    identity: {
      getPublicKey: (...a) => (target && target.identity && target.identity.getPublicKey) ? target.identity.getPublicKey(...a) : null,
      sign: (...a) => (target && target.identity && target.identity.sign) ? target.identity.sign(...a) : null
    },
    swarm: { v1: { join: async (...a) => { if (!target) throw notUp(); return target.swarm.v1.join(...a) } } }
  }
  for (const m of ['create', 'join', 'append', 'get', 'list', 'range', 'count', 'heads', 'directory', 'crossHead', 'crossRows', 'recoverRows']) {
    pear.sync[m] = async (...a) => { if (!target) throw notUp(); return target.sync[m](...a) }
  }
  return { pear, setTarget: (t) => { target = t }, get connected () { return !!target } }
}
