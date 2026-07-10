// relay-pool.js — Phase B of the P2P durability spec. Talk to MULTIPLE untrusted
// relays at once so no single relay is the source of truth:
//
//   • WRITE FAN-OUT — an append lands on every pool relay, so the data (and each
//     author's signed head) exists on independent providers. Losing/seizing one
//     relay loses nothing; a second relay can reconstruct the state.
//   • CROSS-RELAY HEAD — the author's SIGNED head!<author> is fetched from ALL
//     relays and re-verified. The unique highest signed version wins (rollback
//     recovery); the deterministic writer leader resolves only equal-version
//     forks. Legacy/read-only pools retain highest-verified-head behavior.
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
import { canonicalRelayOrigin, hasDurableAtomicCommit } from './relay-roster.js'

export const COMMIT_REQUEST_TIMEOUT_MS = 8000
export const COMMIT_EVIDENCE_TIMEOUT_MS = 8000
const MAX_EVIDENCE_ROWS = 50000
const EVIDENCE_PAGE_SIZE = 1000

function topologyFromEntries (entries) {
  const first = entries.find((entry) => entry.relay && entry.relay.rosterVerified === true && entry.relay.rosterStable === true && entry.relay.topologyId)
  if (!first) return null
  const origins = Array.isArray(first.relay.rosterOrigins) ? first.relay.rosterOrigins.slice() : []
  return {
    schema: 1,
    verified: true,
    stable: true,
    id: first.relay.topologyId,
    size: first.relay.rosterSize,
    origins,
    validWriterTopology: origins.length >= 2 && origins.every(Boolean) && new Set(origins).size === origins.length
  }
}

function signedRosterEntries (entries, topology) {
  if (!topology || topology.verified !== true || topology.stable !== true || topology.validWriterTopology !== true || typeof topology.id !== 'string') return []
  const origins = Array.isArray(topology.origins) ? topology.origins : []
  if (origins.length < 2 || new Set(origins).size !== origins.length) return []
  const seen = new Set()
  const writers = []
  for (const entry of entries) {
    const relay = entry.relay || {}
    const index = Number(relay.rosterIndex)
    const sameOrigins = Array.isArray(relay.rosterOrigins) && relay.rosterOrigins.length === origins.length && relay.rosterOrigins.every((origin, i) => origin === origins[i])
    if (relay.rosterVerified !== true || relay.rosterStable !== true || relay.topologyId !== topology.id || Number(relay.rosterSize) !== origins.length || !sameOrigins) continue
    if (!Number.isInteger(index) || index < 0 || index >= origins.length || origins[index] !== entry.canonicalOrigin) continue
    if (seen.has(entry.canonicalOrigin)) continue
    seen.add(entry.canonicalOrigin)
    writers.push({ ...entry, rosterIndex: index })
  }
  return writers.sort((a, b) => a.rosterIndex - b.rosterIndex)
}

function headEvidenceKey (head) {
  return [head._k, head._sig, head.id, head.version, head.count, head.root].map((value) => String(value ?? '')).join('\x00')
}

function stableLeaderIndex (topologyId, appId, size) {
  let hash = 0x811c9dc5
  const input = String(topologyId) + '\x00' + String(appId)
  for (let i = 0; i < input.length; i++) {
    hash ^= input.charCodeAt(i)
    hash = Math.imul(hash, 0x01000193) >>> 0
  }
  return hash % size
}

// Expected boot wiring:
//   selectRelaysResilient(candidates.relays, { topology: candidates.topology })
//   createRelayPool({ relays: selected, topology: candidates.topology })
// The selected relay metadata is retained as a compatibility path, but writers
// still require explicit ready + exact capability + verified/stable topology.
export function createRelayPool ({ relays = [], topology = null, fetch, EventSource, document, commitTimeoutMs = COMMIT_REQUEST_TIMEOUT_MS, evidenceTimeoutMs = COMMIT_EVIDENCE_TIMEOUT_MS } = {}) {
  const apis = []
  const bases = []
  const entries = []
  for (const r of relays) {
    const capabilities = r && r.capabilities
    const exactAtomic = !!(r && r.ready === true && r.atomicCommit === true && hasDurableAtomicCommit({ ready: r.ready, ...(capabilities || {}) }))
    const api = createPearApi({
      apiBase: r.apiBase,
      apiToken: r.apiToken,
      atomicCommit: exactAtomic,
      requestTimeoutMs: commitTimeoutMs,
      fetch,
      EventSource,
      document
    })
    if (api) {
      const base = r.apiBase || ''
      apis.push(api)
      bases.push(base)
      entries.push({ api, base, relay: r, exactAtomic, canonicalOrigin: r.canonicalOrigin || canonicalRelayOrigin(base) })
    }
  }
  if (!apis.length) return null
  const primary = apis[0]
  const signedTopology = topology || topologyFromEntries(entries)
  const rosterEntries = signedRosterEntries(entries, signedTopology)
  const writerEntries = rosterEntries.filter((entry) => entry.exactAtomic)
  const topologyOriginCount = signedTopology && Array.isArray(signedTopology.origins) ? signedTopology.origins.length : 0
  // Writer readiness is topology-wide. Otherwise a new random appId can hash to
  // an unselected/unready leader after the UI has already advertised writer mode.
  const atomicCapable = topologyOriginCount >= 2 && writerEntries.length === topologyOriginCount
  const topologyConsistentReads = !!(signedTopology && signedTopology.verified === true && signedTopology.stable === true && signedTopology.validWriterTopology === true)

  async function verifiedHead (appId, head) {
    if (!head || head._k !== appId || typeof head.count !== 'number') return null
    if ((await verifyRecord(TYPE.HEAD, head)) !== 'ok') return null
    return head
  }

  function highestHead (candidates) {
    let best = null
    for (const candidate of candidates) {
      if (!best || Number(candidate.head.version) > Number(best.head.version)) best = candidate
    }
    return best
  }

  function matchingHeadEvidence (candidates, requiredOrigins = 2) {
    const groups = new Map()
    for (const candidate of candidates) {
      const origin = candidate.entry.canonicalOrigin
      if (!origin) continue
      const key = headEvidenceKey(candidate.head)
      let group = groups.get(key)
      if (!group) {
        group = { head: candidate.head, base: candidate.entry.base, origins: new Set() }
        groups.set(key, group)
      }
      group.origins.add(origin)
    }
    const supported = [...groups.values()].filter((group) => group.origins.size >= requiredOrigins)
    if (!supported.length) return null
    supported.sort((a, b) => Number(b.head.version) - Number(a.head.version))
    if (supported.length > 1 && Number(supported[0].head.version) === Number(supported[1].head.version)) return null
    return { head: supported[0].head, base: supported[0].base }
  }

  function entryIsLeader (entry, leader) {
    return !!(entry && leader && entry.canonicalOrigin === leader.origin && Number(entry.relay && entry.relay.rosterIndex) === leader.rosterIndex)
  }

  function candidateIsLeader (candidate, leader) {
    return !!(candidate && entryIsLeader(candidate.entry, leader))
  }

  // Leader-first writes make a higher signed version the rollback-safe choice.
  // The leader is consulted only when two different signed heads claim the same
  // highest version. If its transport is unavailable, two origins must match.
  function consistentHead (candidates, leader, leaderReachable) {
    const best = highestHead(candidates)
    if (!best) return null
    const version = Number(best.head.version)
    const top = candidates.filter((candidate) => Number(candidate.head.version) === version)
    const fingerprints = new Set(top.map((candidate) => headEvidenceKey(candidate.head)))
    if (leaderReachable && fingerprints.size === 1) return { head: top[0].head, base: top[0].entry.base }
    if (leaderReachable) {
      const canonical = top.find((candidate) => candidateIsLeader(candidate, leader))
      if (canonical) return { head: canonical.head, base: canonical.entry.base }
    }
    return matchingHeadEvidence(top, 2)
  }

  // Fetch + verify head!<appId> from every relay. A unique higher signed version
  // recovers a rolled-back leader; equal-version forks defer to that leader.
  async function crossHead (appId) {
    const key = keys.head(appId)
    const results = await Promise.all(entries.map(async (entry) => {
      try { return { entry, ok: true, head: await entry.api.sync.get(appId, key) } } catch { return { entry, ok: false, head: null } }
    }))
    const candidates = []
    for (const result of results) {
      const head = await verifiedHead(appId, result.head)
      if (head) candidates.push({ entry: result.entry, head })
    }
    if (!topologyConsistentReads) {
      const best = highestHead(candidates)
      return best ? { head: best.head, base: best.entry.base } : null
    }
    const leader = rosterLeaderFor(appId)
    const leaderReachable = results.some((result) => result.ok && entryIsLeader(result.entry, leader))
    return consistentHead(candidates, leader, leaderReachable)
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

  function mutationKey (mutation) {
    if (!mutation || typeof mutation.type !== 'string' || !mutation.type || !mutation.data || mutation.data.id == null) return null
    return mutation.type.replace(':', '!') + '!' + mutation.data.id
  }

  // A stale CAS is ambiguous: the leader may have applied the pending commit and
  // lost its receipt, while every mirror still missed it. A merged read can make
  // that single copy look healthy, but it is not a publication quorum. Gather
  // independent evidence from the exact signed-roster origins instead. Each
  // qualifying relay must return a complete, strictly paginated outbox whose
  // owner-signed head verifies and whose full census matches both root and count.
  // The current value at every pending mutation's exact wire key (including
  // opaque `v2!<id>` rows) is signature-verified and returned as evidence. Exact
  // signatures count directly; gossip may also prove that the SAME newer LWW
  // winner exists on two origins before treating an old pending intent as
  // superseded.
  async function readEvidenceFrom (entry, appId, commit, stillCurrent = () => true) {
    const rows = []
    const byKey = new Map()
    let gt = ''
    let complete = false
    while (rows.length <= MAX_EVIDENCE_ROWS) {
      if (!stillCurrent()) throw new Error('Relay evidence deadline expired.')
      // Reserve one look-ahead row at the hard cap. Exactly MAX_EVIDENCE_ROWS
      // followed by another row is rejected rather than silently called a full
      // census.
      const limit = Math.min(EVIDENCE_PAGE_SIZE, MAX_EVIDENCE_ROWS + 1 - rows.length)
      const batch = await entry.api.sync.range(appId, { gt, limit })
      // The outer evidence deadline can win while a transport that ignores abort
      // is still resolving this page. Stop here so that abandoned work can never
      // continue issuing dozens of background pagination requests.
      if (!stillCurrent()) throw new Error('Relay evidence deadline expired.')
      if (!Array.isArray(batch) || batch.length > limit) throw new Error('Relay returned an invalid evidence page.')
      if (!batch.length) { complete = true; break }
      for (const row of batch) {
        if (!row || typeof row.key !== 'string' || !row.key || !row.value || typeof row.value !== 'object') throw new Error('Relay returned a malformed evidence row.')
        if ((gt && row.key <= gt) || byKey.has(row.key)) throw new Error('Relay evidence pagination did not advance strictly.')
        gt = row.key
        rows.push(row)
        byKey.set(row.key, row.value)
        if (rows.length > MAX_EVIDENCE_ROWS) throw new Error('Relay outbox exceeds the bounded evidence census.')
      }
      if (batch.length < limit) { complete = true; break }
    }
    if (!complete) throw new Error('Relay evidence census did not complete within its row bound.')

    const head = await verifiedHead(appId, byKey.get(keys.head(appId)))
    if (!head || head.id !== appId || head.author !== appId || !Number.isInteger(head.version) || head.version < 1 || !Number.isInteger(head.count) || head.count < 0 || !/^[0-9a-f]{64}$/i.test(String(head.root || ''))) {
      throw new Error('Relay did not serve a verified, well-formed signed head for evidence.')
    }
    const census = outboxCensus(rows, appId)
    if (census.length !== Number(head.count) || await hashHex(censusString(census)) !== String(head.root).toLowerCase()) {
      throw new Error('Relay evidence census does not match its signed head.')
    }

    const mutationKeys = []
    const mutationEvidence = []
    let exact = true
    for (const mutation of commit.mutations) {
      const key = mutationKey(mutation)
      const expectedSig = mutation && mutation.data && mutation.data._sig
      const value = key && byKey.get(key)
      if (!key || typeof expectedSig !== 'string' || !value || value._k !== appId || typeof value._sig !== 'string') throw new Error('Relay is missing a verifiable current value for a pending mutation key.')
      const semType = mutation.type === 'v2' ? value._t : mutation.type
      if ((await verifyRecord(mutation.type, value, semType)) !== 'ok') throw new Error('Relay pending mutation evidence failed signature verification.')
      mutationKeys.push(key)
      const isExact = value._sig === expectedSig
      if (!isExact) exact = false
      mutationEvidence.push({ key, expectedSignature: expectedSig, currentSignature: value._sig, exact: isExact, value })
    }
    return {
      origin: entry.canonicalOrigin,
      relay: entry.base,
      rosterIndex: entry.rosterIndex,
      head: { version: Number(head.version), count: Number(head.count), root: String(head.root).toLowerCase(), signature: head._sig },
      mutationKeys,
      mutations: mutationEvidence,
      exact
    }
  }

  async function boundedCommitEvidence (entry, appId, commit) {
    const ms = Number.isFinite(Number(evidenceTimeoutMs)) && Number(evidenceTimeoutMs) > 0 ? Number(evidenceTimeoutMs) : COMMIT_EVIDENCE_TIMEOUT_MS
    let timer = null
    let current = true
    const timeout = new Promise((resolve, reject) => {
      timer = setTimeout(() => {
        current = false
        const error = new Error('Relay commit evidence timed out.')
        error.code = 'COMMIT_EVIDENCE_TIMEOUT'
        reject(error)
      }, ms)
    })
    try {
      return await Promise.race([readEvidenceFrom(entry, appId, commit, () => current), timeout])
    } finally {
      current = false
      if (timer) clearTimeout(timer)
    }
  }

  async function proveCommitQuorum (appId, commit) {
    const commitId = commit && commit.commitId
    const mutations = commit && commit.mutations
    if (!atomicCapable || !/^[0-9a-f]{64}$/i.test(String(appId || '')) || !/^[0-9a-f]{64}$/i.test(String(commitId || '')) || !Array.isArray(mutations) || !mutations.length) {
      return { ok: false, durable: false, appId, commitId: commitId || null, quorum: 0, evidence: [] }
    }
    const settled = await Promise.all(writerEntries.map(async (entry) => {
      try { return await boundedCommitEvidence(entry, appId, commit) } catch { return null }
    }))
    const censusEvidence = settled.filter(Boolean)
    const evidence = censusEvidence.filter((item) => item.exact === true)
    const origins = new Set(evidence.map((item) => item.origin))
    const quorum = origins.size
    return {
      ok: quorum >= 2,
      durable: quorum >= 2,
      proven: quorum >= 2,
      appId,
      commitId,
      quorum,
      evidence,
      censusEvidence
    }
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

  // Phase D directory: every outbox's signed head, merged with the same leader /
  // matching-mirror rule as crossHead. A fresh visitor calls this once to bootstrap
  // its rollback floor for every author at cross-relay strength.
  async function directory (opts = {}) {
    const results = await Promise.all(entries.map(async (entry) => {
      try {
        return { entry, ok: !!entry.api.sync.directory, value: entry.api.sync.directory ? await entry.api.sync.directory(opts) : null }
      } catch {
        return { entry, ok: false, value: null }
      }
    }))
    const candidates = new Map()
    let nextCursor = null
    let hasMore = false
    for (const result of results) {
      const r = result.value
      if (!r) continue
      // If any relay has more pages, keep going; take the SMALLEST cursor so a relay that
      // lagged (missing a recent author) is re-covered on the next page rather than skipped.
      if (r.hasMore) { hasMore = true; if (r.nextCursor && (nextCursor === null || r.nextCursor < nextCursor)) nextCursor = r.nextCursor }
      const heads = r && r.heads
      if (!heads || typeof heads !== 'object') continue
      for (const appId in heads) {
        const head = await verifiedHead(appId, heads[appId])
        if (!head) continue
        if (!candidates.has(appId)) candidates.set(appId, [])
        candidates.get(appId).push({ entry: result.entry, head })
      }
    }
    const out = {}
    for (const [appId, appCandidates] of candidates) {
      if (!topologyConsistentReads) {
        const best = highestHead(appCandidates)
        if (best) out[appId] = best.head
        continue
      }
      const leader = rosterLeaderFor(appId)
      const leaderReachable = results.some((result) => result.ok && entryIsLeader(result.entry, leader))
      const selected = consistentHead(appCandidates, leader, leaderReachable)
      if (selected) out[appId] = selected.head
    }
    return { heads: out, nextCursor, hasMore }
  }

  // Legacy append compatibility for PearBrowser-era transports. Atomic HTTP
  // writers use quorumCommit below; this path remains deliberately unchanged
  // for hosts that do not expose sync.commit.
  async function fanoutAppend (appId, op) {
    const r = await primary.sync.append(appId, op)
    for (let i = 1; i < apis.length; i++) apis[i].sync.append(appId, op).catch(() => {})
    return r
  }

  function receiptHead (receipt) {
    const head = receipt && receipt.head
    if (!head || typeof head !== 'object') return null
    const version = Number(head.version)
    const count = Number(head.count)
    const root = typeof head.root === 'string' ? head.root.toLowerCase() : ''
    if (!Number.isInteger(version) || version < 1 || !Number.isInteger(count) || count < 0 || !/^[0-9a-f]{64}$/.test(root)) return null
    return { version, count, root }
  }

  function durableReceipt (receipt, appId, commitId) {
    const head = receiptHead(receipt)
    const relayVersion = Number(receipt && receipt.relayVersion)
    const inviteKey = receipt && receipt.inviteKey
    if (!(
      receipt && receipt.ok === true && receipt.durable === true &&
      receipt.appId === appId && receipt.commitId === commitId && head &&
      Number.isSafeInteger(relayVersion) && relayVersion >= 1 &&
      typeof inviteKey === 'string' && /^[0-9a-f]{64}$/i.test(inviteKey)
    )) return null
    return { ...receipt, head, relayVersion }
  }

  function isStaleFailure (reason) {
    return !!(reason && (reason.status === 409 || reason.code === 'STALE_CAS' || reason.code === 'COMMIT_CAS_MISMATCH'))
  }

  function relayFailure (entry, reason, code = null) {
    return {
      base: entry.base,
      origin: entry.canonicalOrigin,
      status: reason && reason.status,
      code: code || (reason && reason.code),
      message: reason && reason.message
    }
  }

  function commitError (message, code, status, failures = [], receipts = []) {
    const error = new Error(message)
    error.code = code
    error.status = status
    error.stale = code === 'COMMIT_CAS_MISMATCH'
    error.failures = failures
    error.receipts = receipts
    return error
  }

  async function boundedRelayCommit (entry, appId, commit, controller) {
    const ms = Number.isFinite(Number(commitTimeoutMs)) && Number(commitTimeoutMs) > 0 ? Number(commitTimeoutMs) : COMMIT_REQUEST_TIMEOUT_MS
    let timer = null
    let onAbort = null
    const timeout = new Promise((resolve, reject) => {
      timer = setTimeout(() => {
        try { controller.abort() } catch {}
        const error = new Error('Relay commit timed out.')
        error.code = 'COMMIT_RELAY_TIMEOUT'
        error.status = 504
        reject(error)
      }, ms)
    })
    const aborted = new Promise((resolve, reject) => {
      onAbort = () => {
        const error = new Error('Relay commit aborted.')
        error.code = 'COMMIT_RELAY_ABORTED'
        reject(error)
      }
      if (controller.signal.aborted) onAbort()
      else controller.signal.addEventListener('abort', onAbort, { once: true })
    })
    try {
      return await Promise.race([
        entry.api.sync.commit(appId, commit, { signal: controller.signal, timeoutMs: ms }),
        timeout,
        aborted
      ])
    } finally {
      if (timer) clearTimeout(timer)
      if (onAbort) controller.signal.removeEventListener('abort', onAbort)
    }
  }

  function receiptEvidence (receipt, entry) {
    return { ...receipt, relay: entry.base, origin: entry.canonicalOrigin, rosterIndex: entry.rosterIndex }
  }

  function matchingReceipt (receipt, leader) {
    return receipt.commitId === leader.commitId &&
      receipt.head.version === leader.head.version &&
      receipt.head.count === leader.head.count &&
      receipt.head.root === leader.head.root
  }

  function designatedLeader (appId, candidates) {
    if (!signedTopology || !Array.isArray(signedTopology.origins) || signedTopology.origins.length < 2) return null
    const rosterIndex = stableLeaderIndex(signedTopology.id, appId, signedTopology.origins.length)
    const origin = signedTopology.origins[rosterIndex]
    const entry = candidates.find((candidate) => candidate.rosterIndex === rosterIndex && candidate.canonicalOrigin === origin) || null
    return { rosterIndex, origin, entry }
  }

  function leaderFor (appId) {
    return designatedLeader(appId, writerEntries)
  }

  function rosterLeaderFor (appId) {
    return designatedLeader(appId, rosterEntries)
  }

  // Every writer chooses the same signed-roster leader for one appId. The
  // leader CAS is awaited before mirrors receive anything, so two devices can
  // never each win a different relay and produce a crossed 1/1 split.
  async function quorumCommit (appId, commit) {
    if (!atomicCapable) throw commitError('Peerit requires every origin in a stable signed roster (and at least two) to be writer-ready before publication.', 'COMMIT_RELAY_QUORUM_UNAVAILABLE', 503)
    const commitId = commit && commit.commitId
    if (!/^[0-9a-f]{64}$/i.test(String(commitId || ''))) throw commitError('Peerit commitId is invalid.', 'INVALID_COMMIT_ID', 400)
    const designated = leaderFor(appId)
    if (!designated || !designated.entry) {
      throw commitError('The signed-roster leader for this outbox is unavailable; no mirror was contacted.', 'COMMIT_LEADER_UNAVAILABLE', 503)
    }

    const failures = []
    let leaderReceipt
    try {
      const controller = new AbortController()
      leaderReceipt = durableReceipt(await boundedRelayCommit(designated.entry, appId, commit, controller), appId, commitId)
    } catch (reason) {
      failures.push(relayFailure(designated.entry, reason))
      if (isStaleFailure(reason)) throw commitError('Peerit commit compare-and-swap is stale at the signed-roster leader.', 'COMMIT_CAS_MISMATCH', 409, failures)
      throw commitError('The signed-roster leader did not durably accept the commit; no mirror was contacted.', 'COMMIT_LEADER_FAILED', 503, failures)
    }
    if (!leaderReceipt) {
      failures.push(relayFailure(designated.entry, null, 'INVALID_COMMIT_RECEIPT'))
      throw commitError('The signed-roster leader returned an invalid durable receipt; no mirror was contacted.', 'COMMIT_LEADER_FAILED', 503, failures)
    }

    const leaderEvidence = receiptEvidence(leaderReceipt, designated.entry)
    const mirrors = writerEntries.filter((entry) => entry !== designated.entry)
    const controllers = mirrors.map(() => new AbortController())
    return await new Promise((resolve, reject) => {
      let remaining = mirrors.length
      let finished = false
      const finishFailure = () => {
        if (finished || remaining > 0) return
        finished = true
        reject(commitError('Peerit commit did not receive a matching durable mirror receipt.', 'COMMIT_QUORUM_FAILED', 503, failures, [leaderEvidence]))
      }
      mirrors.forEach((entry, index) => {
        boundedRelayCommit(entry, appId, commit, controllers[index]).then((raw) => {
          if (finished) return
          const receipt = durableReceipt(raw, appId, commitId)
          if (!receipt || !matchingReceipt(receipt, leaderReceipt)) {
            failures.push(relayFailure(entry, null, 'INVALID_COMMIT_RECEIPT'))
            return
          }
          finished = true
          for (let i = 0; i < controllers.length; i++) {
            if (i !== index) { try { controllers[i].abort() } catch {} }
          }
          const mirrorEvidence = receiptEvidence(receipt, entry)
          resolve({ ...leaderEvidence, receipts: [leaderEvidence, mirrorEvidence], quorum: 2, leader: designated.origin })
        }).catch((reason) => {
          if (!finished) failures.push(relayFailure(entry, reason))
        }).finally(() => {
          remaining--
          finishFailure()
        })
      })
    })
  }

  const sync = { ...primary.sync, append: fanoutAppend, crossHead, crossRows, recoverRows, directory, proveCommitQuorum }
  if (atomicCapable) sync.commit = quorumCommit
  else delete sync.commit
  return {
    ...primary,
    sync,
    _relayBases: bases.slice(),
    _relayCount: apis.length,
    _atomicCommit: atomicCapable,
    _writerRelayCount: writerEntries.length,
    _leaderFor: (appId) => {
      const selected = leaderFor(appId)
      return selected ? { rosterIndex: selected.rosterIndex, origin: selected.origin, available: !!selected.entry } : null
    }
  }
}
