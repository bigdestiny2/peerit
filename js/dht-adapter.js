// dht-adapter.js — maps the Holepunch stack (corestore + hyperbee + hyperswarm +
// protomux) onto peerit's window.pear-shaped { sync, swarm:{v1} } surface, so
// js/gossip.js (BridgeGossipSync) runs UNCHANGED on top of an in-browser DHT.
//
// Pure + dependency-injected (no npm imports here) so the peerit-specific glue —
// the bit that actually has to be correct — is unit-testable with in-memory
// fakes (see test/dht-adapter.mjs). js/dht-transport.js wires the REAL deps in.
//
// Trust is unchanged: keys/signing/verification stay in the browser; this just
// swaps the transport. Over a dht-relay the relay shuttles only Noise ciphertext,
// so it's strictly stronger than the /api relay.
//
// deps: { store (corestore), swarm (hyperswarm), Hyperbee (ctor), Protomux
//         (with .from(stream)), b4a, sha256(str)->Uint8Array,
//         identity? (the LOCAL DevIdentity — only mirrored onto the surface so
//         createSync's hasGossipPearSurface check passes; signing still happens
//         via the identity passed to BridgeGossipSync, never here) }
const DESC_PROTOCOL = 'peerit/desc/v1'

export function createHyperPearSurface ({ store, swarm, Hyperbee, Protomux, b4a, sha256, identity, codec }) {
  // The descriptor channel's wire codec. Real protomux needs a compact-encoding
  // (dht-transport.js injects `require('compact-encoding').raw`); the in-memory
  // fake in test/dht-adapter.mjs works with this pass-through. Default keeps the
  // fakes green; the live bundle MUST pass the real codec or frames corrupt.
  codec = codec || { encode: (b) => b, decode: (b) => b }
  const bees = new Map() // appId -> { bee, core, writable }
  const keyHex = (core) => b4a.toString(core.key, 'hex')

  async function openWritable (appId) {
    let e = bees.get(appId); if (e) return e
    const core = store.get({ name: 'outbox:' + appId })
    const bee = new Hyperbee(core, { keyEncoding: 'utf-8', valueEncoding: 'json' })
    await bee.ready(); swarm.join(core.discoveryKey, { server: true, client: true })
    e = { bee, core, writable: true }; bees.set(appId, e); return e
  }
  async function openByKey (appId, inviteKey) {
    let e = bees.get(appId); if (e) return e
    const core = store.get({ key: b4a.from(inviteKey, 'hex') })
    const bee = new Hyperbee(core, { keyEncoding: 'utf-8', valueEncoding: 'json' })
    await bee.ready(); swarm.join(core.discoveryKey, { server: false, client: true })
    e = { bee, core, writable: false }; bees.set(appId, e); return e
  }
  async function readRange (bee, { prefix, gt, gte, lt, lte, reverse, limit } = {}) {
    const r = {}
    if (prefix) { r.gte = prefix; r.lt = prefix + '\xff' }
    if (gte != null && gte !== '') r.gte = gte
    if (gt != null && gt !== '') r.gt = gt
    if (lte != null && lte !== '') r.lte = lte
    if (lt != null && lt !== '') r.lt = lt
    let lim = Number(limit) || 100; if (lim < 1) lim = 100; if (lim > 1000) lim = 1000
    const out = []
    for await (const n of bee.createReadStream({ ...r, reverse: !!reverse, limit: lim })) out.push({ key: n.key, value: n.value })
    return out
  }

  const sync = {
    async create (appId) { const { core } = await openWritable(appId); return { appId, inviteKey: keyHex(core), writerPublicKey: appId } },
    async join (appId, inviteKey) { const e = bees.get(appId) || await openByKey(appId, inviteKey); return { appId, inviteKey: keyHex(e.core), writerPublicKey: appId } },
    async append (appId, op) { const { bee } = await openWritable(appId); const key = op.type.replace(':', '!') + '!' + op.data.id; await bee.put(key, op.data); return { ok: true, key } },
    async get (appId, key) { const e = bees.get(appId); if (!e) return null; const n = await e.bee.get(key); return n ? n.value : null },
    async list (appId, prefix, opts = {}) { const e = bees.get(appId); if (!e) return []; return readRange(e.bee, { prefix, limit: opts.limit }) },
    async range (appId, opts = {}) { const e = bees.get(appId); if (!e) return []; return readRange(e.bee, opts) },
    async count (appId, prefix) { const rows = await sync.list(appId, prefix || '', { limit: 1000 }); return { count: rows.length } },
    async status (appId) { const e = bees.get(appId); return { appId, inviteKey: e ? keyHex(e.core) : null, writerCount: 1, viewLength: e ? e.core.length : 0 } }
  }

  // swarm.v1: descriptor gossip over a DEDICATED protomux channel per connection,
  // separate from core replication (store.replicate) which shares the same muxed
  // stream. Raw conn.write would collide with replication; a named channel does not.
  const swarmV1 = {
    async join (topicHex, opts = {}) {
      const topic = await sha256(String(topicHex || 'peerit'))
      const listeners = { peer: [], message: [], 'peer-leave': [], error: [], closed: [] }
      const peers = new Map() // peerId -> peer
      const emit = (ev, ...a) => { for (const fn of listeners[ev] || []) { try { fn(...a) } catch {} } }

      const onConnection = (conn) => {
        try { store.replicate(conn) } catch {} // cores sync over the same muxed stream
        const id = b4a.toString(conn.remotePublicKey || b4a.from('peer'), 'hex')
        const mux = Protomux.from(conn)
        const channel = mux.createChannel({ protocol: DESC_PROTOCOL })
        if (!channel) return
        const peer = {
          id,
          pubkey: id,
          _msg: channel.addMessage({
            encoding: codec, // pass-through for the fake; compact-encoding.raw on the real wire (injected by dht-transport.js)
            onmessage: (data) => emit('message', peer, data instanceof Uint8Array ? data : new Uint8Array(data))
          }),
          send (bytes) { try { this._msg.send(b4a.from(bytes)) } catch (e) { emit('error', e) } }
        }
        channel.open()
        peers.set(id, peer)
        emit('peer', peer)
        if (typeof conn.on === 'function') conn.on('close', () => { peers.delete(id); emit('peer-leave', peer) })
      }
      swarm.on('connection', onConnection)
      const discovery = swarm.join(topic, { server: opts.server !== false, client: opts.client !== false })
      if (discovery && discovery.flushed) await discovery.flushed().catch(() => {})

      return {
        topic: topicHex,
        get peers () { return [...peers.values()] },
        on (ev, fn) { (listeners[ev] = listeners[ev] || []).push(fn) },
        off (ev, fn) { const a = listeners[ev] || []; const i = a.indexOf(fn); if (i >= 0) a.splice(i, 1) },
        destroy () { try { swarm.leave(topic) } catch {}; emit('closed') }
      }
    }
  }

  const surface = {
    sync,
    swarm: { v1: swarmV1 },
    async destroy () { try { await swarm.destroy() } catch {} try { await store.close() } catch {} }
  }
  // Mirror the LOCAL identity onto the surface so createSync sees a complete
  // bridge (hasGossipPearSurface) and selects BridgeGossipSync. Signing is still
  // done with the identity handed to BridgeGossipSync; this is only ever read for
  // the completeness check, never to delegate signing to the transport.
  if (identity) {
    surface.identity = {
      getPublicKey: async () => { const me = identity.me(); return { publicKey: me.pubkey, driveKey: me.driveKey, algorithm: 'ed25519' } },
      sign: (payload, ns) => identity.sign(payload, ns)
    }
  }
  return surface
}
