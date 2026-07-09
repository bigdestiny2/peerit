// relay-pool.js — Phase B of the P2P durability spec. Talk to MULTIPLE untrusted
// relays at once so no single relay is the source of truth:
//
//   • WRITE FAN-OUT — an append lands on every pool relay, so the data (and each
//     author's signed head) exists on independent providers. Losing/seizing one
//     relay loses nothing; a second relay can reconstruct the state.
//   • CROSS-RELAY HEAD — the author's SIGNED head!<author> is fetched from ALL
//     relays and the highest-version VERIFIED one wins. A relay can't forge it
//     (Ed25519, re-verified), so this single mechanism defeats BOTH open Phase A
//     gaps: a relay serving a stale head (ROLLBACK) loses to a peer serving the
//     newer one, and a relay dropping the head (STRIP) is overridden by any relay
//     that still has it. The caller audits the rows it received against this
//     max head, and on a shortfall reads the outbox from the relay that has it.
//
// It presents the same window.pear-shaped { sync, identity, swarm } surface as a
// single relay (delegated to the primary), so gossip.js runs unchanged except it
// may call the extra sync.crossHead()/crossRows(). Reads/swarm stay on the
// primary; only writes fan out and heads are cross-checked. The relays remain
// untrusted availability providers — the pool never grants any of them authority
// over content (every record + head is still re-verified client-side).

import { createPearApi } from './pear-api.js'
import { verifyRecord } from './verify.js'
import { outboxCensus, censusString } from './canon.js'
import { hashHex } from './crypto.js'
import { keys, TYPE } from './model.js'

export function createRelayPool ({ relays = [], fetch, EventSource, document } = {}) {
  const apis = []
  const bases = []
  for (const r of relays) {
    const api = createPearApi({ apiBase: r.apiBase, apiToken: r.apiToken, fetch, EventSource, document })
    if (api) { apis.push(api); bases.push(r.apiBase || '') }
  }
  if (!apis.length) return null
  const primary = apis[0]

  // Fetch + verify head!<appId> from every relay; return the highest-version one
  // and which relay served it. A relay can't forge a head (re-verified here), so
  // the max version is the freshest an honest relay has published.
  async function crossHead (appId) {
    const key = keys.head(appId)
    const cands = await Promise.all(apis.map((a) => a.sync.get(appId, key).catch(() => null)))
    let best = null; let bestBase = null
    for (let i = 0; i < cands.length; i++) {
      const h = cands[i]
      if (!h || h._k !== appId || typeof h.count !== 'number') continue
      if ((await verifyRecord(TYPE.HEAD, h)) !== 'ok') continue
      if (!best || (h.version | 0) > (best.version | 0)) { best = h; bestBase = bases[i] }
    }
    return best ? { head: best, base: bestBase } : null
  }

  // Read a full outbox from a specific relay base (the failover read when the
  // primary is caught withholding). Unknown/empty base -> the primary. Paginated:
  // the head commits to the WHOLE outbox, so a single 1000-row page would make a
  // large outbox's census a strict subset that never matches the root.
  const MAX_ROWS = 50000
  async function readAll (api, appId) {
    const rows = []
    let gt = ''
    while (rows.length < MAX_ROWS) {
      const batch = await api.sync.range(appId, { gt, limit: Math.min(1000, MAX_ROWS - rows.length) })
      if (!Array.isArray(batch) || !batch.length) break
      rows.push(...batch)
      const last = batch[batch.length - 1] && batch[batch.length - 1].key
      if (!last || last === gt || batch.length < 1000) break
      gt = last
    }
    return rows
  }
  async function crossRows (appId, base) {
    let api = primary
    if (base) { const i = bases.indexOf(base); if (i >= 0) api = apis[i] }
    return readAll(api, appId)
  }

  // Route AROUND a withholding relay: read the outbox from each pool relay and
  // return the first set whose census MATCHES the given signed head's root (a
  // relay that is serving the author's committed set). Returns null if no relay
  // does — then the content genuinely isn't on the pool yet.
  async function recoverRows (appId, head) {
    if (!head || typeof head.root !== 'string') return null
    for (let i = 0; i < apis.length; i++) {
      try {
        const rows = await readAll(apis[i], appId)
        if (head.root === await hashHex(censusString(outboxCensus(rows, appId)))) return { rows, base: bases[i] }
      } catch {}
    }
    return null
  }

  // Phase D directory: every outbox's signed head, merged across relays with the
  // HIGHEST VERIFIED version winning per author (a relay serving a stale directory
  // loses to one serving the current head). A fresh visitor calls this once to
  // bootstrap its rollback floor for every author at cross-relay strength, instead
  // of accumulating floors over a session. Relay can't forge — each head re-verified.
  async function directory (opts = {}) {
    const results = await Promise.all(apis.map((a) => (a.sync.directory ? a.sync.directory(opts) : null)).map((p) => Promise.resolve(p).catch(() => null)))
    const out = {}
    let nextCursor = null, hasMore = false
    for (const r of results) {
      if (!r) continue
      // If any relay has more pages, keep going; take the SMALLEST cursor so a relay that
      // lagged (missing a recent author) is re-covered on the next page rather than skipped.
      if (r.hasMore) { hasMore = true; if (r.nextCursor && (nextCursor === null || r.nextCursor < nextCursor)) nextCursor = r.nextCursor }
      const heads = r && r.heads
      if (!heads || typeof heads !== 'object') continue
      for (const appId in heads) {
        const h = heads[appId]
        if (!h || h._k !== appId || typeof h.count !== 'number') continue
        if ((await verifyRecord(TYPE.HEAD, h)) !== 'ok') continue
        const ex = out[appId]
        if (!ex || (h.version | 0) > (ex.version | 0)) out[appId] = h
      }
    }
    return { heads: out, nextCursor, hasMore }
  }

  // The authoritative write must land on the primary; mirror best-effort to the
  // rest so an independent relay can reconstruct the state (durability + lets
  // crossHead find the newest head even if the primary later rolls back/strips).
  async function fanoutAppend (appId, op) {
    const r = await primary.sync.append(appId, op)
    for (let i = 1; i < apis.length; i++) apis[i].sync.append(appId, op).catch(() => {})
    return r
  }

  return {
    ...primary,
    sync: { ...primary.sync, append: fanoutAppend, crossHead, crossRows, recoverRows, directory },
    _relayBases: bases.slice(),
    _relayCount: apis.length
  }
}
