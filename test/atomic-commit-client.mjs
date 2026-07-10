// Atomic writer client regressions. Exercises the real pear-api + relay-pool +
// BridgeGossipSync stack without opening a network socket.
// Run: node test/atomic-commit-client.mjs

import assert from 'node:assert'
import { createHash } from 'node:crypto'
import { DevIdentity } from '../js/identity.js'
import { createData } from '../js/data.js'
import { BridgeGossipSync } from '../js/gossip.js'
import { createRelayPool } from '../js/relay-pool.js'
import { canonical, censusString, outboxCensus } from '../js/canon.js'
import { TYPE, keys } from '../js/model.js'

let passed = 0
const ok = (condition, message) => { assert.ok(condition, message); passed++; console.log('  ✓ ' + message) }
const EMPTY_ROOT = createHash('sha256').update('').digest('hex')
const ATOMIC_CAPABILITIES = {
  atomicCommit: { schema: 1, method: 'POST', route: '/api/sync/commit', enabled: true, durable: true, cas: true, idempotent: true, idempotency: { mode: 'bounded', latestPerOutbox: true, hotReceiptsPerOutbox: 16, tombstonesPerOutbox: 64, aggregateEntries: 1024, extraHistoryEntries: 1000 } },
  legacyWrites: { create: false, append: false }
}

function signedWriterRelays (bases) {
  const origins = bases.map((base) => new URL(base).origin)
  const topologyId = 'test-signed-roster|' + bases.join('|')
  return bases.map((apiBase, rosterIndex) => ({
    apiBase,
    apiToken: 'test-token',
    ready: true,
    atomicCommit: true,
    capabilities: ATOMIC_CAPABILITIES,
    canonicalOrigin: origins[rosterIndex],
    rosterVerified: true,
    rosterStable: true,
    rosterIndex,
    topologyId,
    rosterOrigins: origins,
    rosterSize: origins.length
  }))
}

function mem () {
  const values = new Map()
  return {
    getItem: (key) => values.has(key) ? values.get(key) : null,
    setItem: (key, value) => values.set(key, String(value)),
    removeItem: (key) => values.delete(key),
    clear: () => values.clear()
  }
}

async function identity (name, { lazy = false } = {}) {
  const id = new DevIdentity(mem(), mem(), { lazy })
  await id.ready()
  if (!lazy && !id.me().pubkey) await id.createUser(name)
  return id
}

async function signedProfile (id, suffix = '') {
  const pub = id.me().pubkey
  const data = { id: pub, author: pub, name: 'writer' + suffix, bio: '', createdAt: 1, updatedAt: Date.now() }
  const sig = await id.sign(canonical('profile', data))
  return { type: 'profile', data: { ...data, _sig: sig.signature, _k: sig.publicKey, _dk: sig.driveKey, _ns: sig.namespace, _alg: sig.algorithm } }
}

async function signedHeadFork (id, head, overrides = {}) {
  const pub = id.me().pubkey
  const data = {
    id: pub,
    author: pub,
    version: head.version,
    count: head.count,
    root: head.root,
    updatedAt: head.updatedAt,
    ...overrides
  }
  const sig = await id.sign(canonical('head', data))
  return { ...data, _sig: sig.signature, _k: sig.publicKey, _dk: sig.driveKey, _ns: sig.namespace, _alg: sig.algorithm }
}

async function signedFollow (id, target) {
  const pub = id.me().pubkey
  const data = { id: `${target}!${pub}`, target, author: pub, deleted: false, ts: Date.now() }
  const sig = await id.sign(canonical(TYPE.FOLLOW, data))
  return { type: TYPE.FOLLOW, data: { ...data, _sig: sig.signature, _k: sig.publicKey, _dk: sig.driveKey, _ns: sig.namespace, _alg: sig.algorithm } }
}

async function until (predicate, timeoutMs = 3000) {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (await predicate()) return true
    await new Promise(resolve => setTimeout(resolve, 20))
  }
  return false
}

function makeWorld (bases) {
  const relays = new Map(bases.map((base, index) => [new URL(base).host, {
    base,
    inviteKey: String(index + 1).repeat(64),
    groups: new Map(),
    receipts: new Map(),
    calls: [],
    mode: 'ok',
    rangeMode: 'ok',
    rangeCalls: 0,
    readFail: false,
    applied: 0,
    duplicates: 0,
    aborted: 0
  }]))
  const counts = { create: 0, append: 0, commit: 0, swarmSend: 0 }
  let nextCommitHook = null
  const response = (value, status = 200) => ({
    ok: status >= 200 && status < 300,
    status,
    statusText: status === 409 ? 'Conflict' : 'OK',
    headers: { get: () => null },
    text: async () => JSON.stringify(value)
  })
  const sorted = (group) => group ? [...group.rows].sort(([a], [b]) => a.localeCompare(b)).map(([key, value]) => ({ key, value })) : []

  async function applyCommit (relay, appId, commit, signal) {
    counts.commit++
    relay.calls.push(JSON.parse(JSON.stringify(commit)))
    // Deterministic race injection: pause exactly the next leader request while a
    // second client advances the same outbox, then let the paused CAS go stale.
    const hook = nextCommitHook
    if (hook) {
      nextCommitHook = null
      await hook({ relay, appId, commit })
    }
    if (relay.mode === 'hang') {
      if (signal && typeof signal.addEventListener === 'function') signal.addEventListener('abort', () => { relay.aborted++ }, { once: true })
      return new Promise(() => {})
    }
    if (relay.mode === 'stale') return response({ error: 'stale compare-and-swap', code: 'COMMIT_CAS_MISMATCH' }, 409)
    if (relay.mode === 'fail') throw Object.assign(new Error('injected mirror failure'), { code: 'INJECTED_FAILURE' })
    const duplicate = relay.receipts.get(commit.commitId)
    if (duplicate) { relay.duplicates++; return response(duplicate) }
    const group = relay.groups.get(appId)
    const previous = group && group.rows.get(keys.head(appId))
    const version = previous ? previous.version : 0
    const root = previous ? previous.root : EMPTY_ROOT
    if (commit.expected.version !== version || commit.expected.root !== root) return response({ error: 'stale compare-and-swap', code: 'COMMIT_CAS_MISMATCH' }, 409)
    const next = { rows: new Map(group ? group.rows : []), version: (group && group.version) || 0 }
    for (const mutation of commit.mutations) next.rows.set(mutation.type.replace(':', '!') + '!' + mutation.data.id, mutation.data)
    next.rows.set(keys.head(appId), commit.head.data)
    next.version++
    relay.groups.set(appId, next)
    relay.applied++
    const receipt = {
      ok: true,
      durable: true,
      commitId: commit.commitId,
      appId,
      inviteKey: relay.inviteKey,
      head: { version: commit.head.data.version, count: commit.head.data.count, root: commit.head.data.root },
      relayVersion: next.version
    }
    relay.receipts.set(commit.commitId, receipt)
    if (relay.mode === 'lose-once') { relay.mode = 'ok'; throw Object.assign(new Error('response lost after durable commit'), { code: 'RESPONSE_LOST' }) }
    return response(receipt)
  }

  async function fetch (url, opts = {}) {
    const parsed = new URL(String(url))
    const relay = relays.get(parsed.host)
    const path = parsed.pathname
    const body = opts.body ? JSON.parse(opts.body) : {}
    if (relay && relay.readFail && (path === '/api/sync/get' || path === '/api/directory')) throw Object.assign(new Error('injected read failure'), { code: 'INJECTED_READ_FAILURE' })
    if (path === '/api/sync/create') { counts.create++; return response({ error: 'unsigned create disabled' }, 403) }
    if (path === '/api/sync/append') { counts.append++; return response({ error: 'legacy append disabled' }, 403) }
    if (path === '/api/sync/commit') return applyCommit(relay, body.appId, body.commit, opts.signal)
    if (path === '/api/sync/heads') {
      const heads = {}
      for (const appId of body.appIds || []) heads[appId] = relay.groups.get(appId)?.version || 0
      return response({ heads })
    }
    if (path === '/api/sync/range' || path === '/api/sync/list') {
      relay.rangeCalls++
      if (relay.rangeMode === 'hang') return new Promise(() => {})
      let rows = sorted(relay.groups.get(parsed.searchParams.get('appId')))
      const gt = parsed.searchParams.get('gt')
      if (gt) rows = rows.filter((row) => row.key > gt)
      return response(rows.slice(0, Number(parsed.searchParams.get('limit')) || 1000))
    }
    if (path === '/api/sync/get') {
      const group = relay.groups.get(parsed.searchParams.get('appId'))
      return response(group?.rows.get(parsed.searchParams.get('key')) || null)
    }
    if (path === '/api/directory') {
      const heads = {}
      for (const [appId, group] of relay.groups) {
        const head = group.rows.get(keys.head(appId))
        if (head) heads[appId] = head
      }
      return response({ heads, hasMore: false, nextCursor: null })
    }
    if (path === '/api/swarm/join') return response({ channelId: relay.base, topicHex: body.topicHex || 'topic', protocol: body.protocol, version: 1, tier: 'test' })
    if (path === '/api/swarm/send') { counts.swarmSend++; return response({ ok: true }) }
    if (path === '/api/swarm/leave') return response({ ok: true })
    return response({ error: 'not found' }, 404)
  }
  return {
    relays,
    counts,
    fetch,
    beforeNextCommit: (hook) => { nextCommitHook = hook }
  }
}

function pool (world, bases) {
  return createRelayPool({ relays: signedWriterRelays(bases), fetch: world.fetch })
}

function writerSync ({ pear, id, storage, readOnly = false, pollMs = 0 }) {
  return new BridgeGossipSync({
    pear,
    getMe: () => id.me().pubkey,
    identity: id,
    storage,
    validate: null,
    pollMs,
    writeHead: true,
    requireAtomicWrites: true,
    readOnly
  })
}

function fakeCommit (appId, commitId, root, id) {
  return {
    schema: 1,
    commitId,
    expected: { version: 0, root: EMPTY_ROOT },
    mutations: [{ type: 'profile', data: { id, author: appId } }],
    head: { type: 'head', data: { id: appId, version: 1, count: 1, root } },
    authorization: {}
  }
}

async function main () {
  const A = 'https://a.atomic.test'
  const B = 'https://b.atomic.test'

  console.log('\n— true lurker is write-silent —')
  const lurkerWorld = makeWorld([A, B])
  const lurkerId = await identity('lurker', { lazy: true })
  const lurker = writerSync({ pear: pool(lurkerWorld, [A, B]), id: lurkerId, storage: mem() })
  await lurker.ready()
  await lurker.wake()
  ok(lurkerId.me().pubkey === null, 'boot/wake retain the identity-less lurker tier')
  ok(lurkerWorld.counts.create === 0 && lurkerWorld.counts.append === 0 && lurkerWorld.counts.commit === 0, 'lurker makes zero create, append, or commit calls')
  lurker.destroy()

  console.log('\n— first write is one atomic quorum commit —')
  const firstWorld = makeWorld([A, B])
  const firstId = await identity('first')
  const firstStore = mem()
  const first = writerSync({ pear: pool(firstWorld, [A, B]), id: firstId, storage: firstStore })
  await first.ready()
  const firstOp = await signedProfile(firstId)
  let issuedWriterSession = null
  const firstReceipt = await first.withAtomicWriterSession(async (writerSession) => {
    issuedWriterSession = writerSession
    return first.append(firstOp, writerSession)
  })
  const firstPub = firstId.me().pubkey
  ok(issuedWriterSession && firstReceipt.quorum === 2, 'the exact Data write stack can append through its explicit writer-session capability without reacquiring its Web Lock')
  ok(firstReceipt.quorum === 2 && firstWorld.counts.commit === 2, 'two matching durable receipts form the publication quorum')
  ok(firstWorld.counts.create === 0 && firstWorld.counts.append === 0, 'first publication never unsigned-creates an outbox or uses legacy append')
  const firstCommit = firstWorld.relays.get(new URL(A).host).calls[0]
  ok(firstCommit.expected.version === 0 && firstCommit.expected.root === EMPTY_ROOT, 'first commit CASes the canonical empty version/root')
  ok(firstCommit.head.data.version === 1 && firstCommit.head.data.count === 1, 'first mutation and signed head advance atomically to version 1/count 1')
  const expectedRoot = createHash('sha256').update(censusString(outboxCensus([{ key: keys.profile(firstPub), value: firstOp.data }], firstPub))).digest('hex')
  ok(firstCommit.head.data.root === expectedRoot, 'next signed head commits the audited self view plus pending mutation')
  ok(!firstStore.getItem('peerit:pending-commit:v1'), 'pending marker clears only after quorum')
  const sendsBeforeDirectHead = firstWorld.counts.commit
  await assert.rejects(() => first.append({ type: TYPE.HEAD, data: {} }), /standalone head/i)
  passed++; console.log('  ✓ required-atomic mode rejects a caller-supplied standalone head')
  ok(firstWorld.counts.commit === sendsBeforeDirectHead && firstWorld.counts.append === 0, 'standalone head rejection cannot fall through to either write endpoint')
  const sessionPeer = writerSync({ pear: pool(firstWorld, [A, B]), id: firstId, storage: firstStore })
  let releaseSession
  let heldEnteredResolve
  let peerEntered = false
  let sameInstanceEntered = false
  const heldEntered = new Promise((resolve) => { heldEnteredResolve = resolve })
  const sessionGate = new Promise((resolve) => { releaseSession = resolve })
  const heldSession = first.withAtomicWriterSession(async () => { heldEnteredResolve(); return sessionGate })
  await heldEntered
  const sameInstanceSession = first.withAtomicWriterSession(async () => { sameInstanceEntered = true })
  const queuedSession = sessionPeer.withAtomicWriterSession(async () => { peerEntered = true })
  await new Promise((resolve) => setTimeout(resolve, 10))
  ok(sameInstanceEntered === false, 'a concurrent call on the SAME Bridge instance cannot impersonate reentrant work while another async owner holds the writer lock')
  ok(peerEntered === false, 'another Bridge instance cannot enter identity/write mutation while the shared atomic writer session is held')
  releaseSession()
  await Promise.all([heldSession, sameInstanceSession, queuedSession])
  ok(sameInstanceEntered === true && peerEntered === true, 'same-instance and cross-instance waiters enter only after the shared writer session releases')

  let retryEntered = false
  let releaseLiveWrite
  let liveWriteEnteredResolve
  const liveWriteEntered = new Promise((resolve) => { liveWriteEnteredResolve = resolve })
  const liveWriteGate = new Promise((resolve) => { releaseLiveWrite = resolve })
  const liveWrite = first.withAtomicWriterSession(async () => { liveWriteEnteredResolve(); return liveWriteGate })
  await liveWriteEntered
  const originalLoadPending = first._loadPendingCommit.bind(first)
  first._loadPendingCommit = () => { retryEntered = true; return originalLoadPending() }
  const pollRetry = first._retryPendingCommit({ force: true })
  await new Promise((resolve) => setTimeout(resolve, 10))
  ok(retryEntered === false, 'poll retry cannot overlap a live same-instance writer session')
  releaseLiveWrite()
  await Promise.all([liveWrite, pollRetry])
  ok(retryEntered === true, 'poll retry rechecks the marker only after the live writer session releases')
  first._loadPendingCommit = originalLoadPending
  sessionPeer.destroy()
  first.destroy()

  console.log('\n— browser Web Locks serialize same-instance owners —')
  const navigatorDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'navigator')
  const webLockTails = new Map()
  const fakeLocks = {
    async request (name, _options, fn) {
      const previous = webLockTails.get(name) || Promise.resolve()
      let release
      const held = new Promise((resolve) => { release = resolve })
      const tail = previous.catch(() => {}).then(() => held)
      webLockTails.set(name, tail)
      await previous.catch(() => {})
      try { return await fn() } finally {
        release()
        if (webLockTails.get(name) === tail) webLockTails.delete(name)
      }
    }
  }
  Object.defineProperty(globalThis, 'navigator', { configurable: true, value: { locks: fakeLocks } })
  try {
    const webLockWorld = makeWorld([A, B])
    const webLockId = await identity('web-lock-owner')
    const webLockSync = writerSync({ pear: pool(webLockWorld, [A, B]), id: webLockId, storage: mem() })
    await webLockSync.ready()
    let releaseWebLock
    let webLockEnteredResolve
    let secondWebLockEntered = false
    const webLockEntered = new Promise((resolve) => { webLockEnteredResolve = resolve })
    const webLockGate = new Promise((resolve) => { releaseWebLock = resolve })
    const firstWebOwner = webLockSync.withAtomicWriterSession(async () => { webLockEnteredResolve(); return webLockGate })
    await webLockEntered
    const secondWebOwner = webLockSync.withAtomicWriterSession(async () => { secondWebLockEntered = true })
    await new Promise((resolve) => setTimeout(resolve, 10))
    ok(secondWebLockEntered === false, 'browser Web Locks do not let a concurrent same-instance call enter as pseudo-reentrant work')
    releaseWebLock()
    await Promise.all([firstWebOwner, secondWebOwner])
    ok(secondWebLockEntered === true, 'browser Web Locks release the queued same-instance owner only after the live owner exits')
    webLockSync.destroy()
  } finally {
    if (navigatorDescriptor) Object.defineProperty(globalThis, 'navigator', navigatorDescriptor)
    else delete globalThis.navigator
  }

  console.log('\n— lost response retries exact commit after reload —')
  const retryWorld = makeWorld([A, B])
  const retryId = await identity('retry')
  const retryStore = mem()
  const retryPear = pool(retryWorld, [A, B])
  const retryLeader = retryPear._leaderFor(retryId.me().pubkey).origin
  const retryMirror = [A, B].find((base) => new URL(base).origin !== retryLeader)
  retryWorld.relays.get(new URL(retryLeader).host).mode = 'lose-once'
  retryWorld.relays.get(new URL(retryMirror).host).mode = 'fail'
  const beforeReload = writerSync({ pear: retryPear, id: retryId, storage: retryStore })
  await beforeReload.ready()
  const retryOp = await signedProfile(retryId, '-retry')
  await assert.rejects(() => beforeReload.append(retryOp), /pending/i)
  passed++; console.log('  ✓ one durable relay plus one failed mirror remains explicitly pending')
  const durableBlob = retryStore.getItem('peerit:pending-commit:v1')
  ok(!!durableBlob, 'the complete signed commit persists after response loss')
  let identityMutationRan = false
  await assert.rejects(
    () => beforeReload.withAtomicWriterSession(async () => { identityMutationRan = true }),
    /awaiting durable quorum recovery/i
  )
  passed++; console.log('  ✓ identity mutation is refused under the same lock while a pending commit exists')
  ok(identityMutationRan === false, 'pending-state refusal happens before an import/forget callback can mutate identity state')
  const sendsBeforeBlockedWrite = retryWorld.counts.commit
  await assert.rejects(async () => beforeReload.append(await signedProfile(retryId, '-blocked')), /previous|awaiting/i)
  passed++; console.log('  ✓ a later write is rejected while the first commit is pending')
  ok(retryWorld.counts.commit === sendsBeforeBlockedWrite, 'blocked later write sends nothing')
  beforeReload.destroy()

  retryWorld.relays.get(new URL(retryMirror).host).mode = 'ok'
  const afterReload = writerSync({ pear: pool(retryWorld, [A, B]), id: retryId, storage: retryStore })
  await afterReload.ready()
  ok(!retryStore.getItem('peerit:pending-commit:v1'), 'boot retry clears the marker after matching quorum receipts')
  const leaderRelay = retryWorld.relays.get(new URL(retryLeader).host)
  const mirrorRelay = retryWorld.relays.get(new URL(retryMirror).host)
  ok(JSON.stringify(leaderRelay.calls[0]) === JSON.stringify(leaderRelay.calls[1]) && JSON.stringify(leaderRelay.calls[0]) === JSON.stringify(mirrorRelay.calls.at(-1)), 'reload retries the byte-equivalent commitId, signatures, head, and timestamps')
  ok(leaderRelay.applied === 1 && leaderRelay.duplicates === 1, 'duplicate commitId returns its original receipt without reapplying')
  ok(mirrorRelay.applied === 1, 'the recovered mirror applies the same commit exactly once')
  afterReload.destroy()

  console.log('\n— stale recovery requires two exact relay censuses —')
  const evidenceWorld = makeWorld([A, B])
  const evidenceId = await identity('stale-quorum-evidence')
  const evidenceStore = mem()
  const evidencePear = pool(evidenceWorld, [A, B])
  const evidenceApp = evidenceId.me().pubkey
  const evidenceLeader = evidencePear._leaderFor(evidenceApp).origin
  const evidenceMirror = [A, B].find((base) => new URL(base).origin !== evidenceLeader)
  const evidenceLeaderRelay = evidenceWorld.relays.get(new URL(evidenceLeader).host)
  const evidenceMirrorRelay = evidenceWorld.relays.get(new URL(evidenceMirror).host)
  evidenceLeaderRelay.mode = 'lose-once'
  evidenceMirrorRelay.mode = 'fail'
  const evidenceSync = writerSync({ pear: evidencePear, id: evidenceId, storage: evidenceStore })
  await evidenceSync.ready()
  const evidenceData = createData(evidenceSync, evidenceId, { v2: true, minBits: { profile: 0 } })
  await assert.rejects(() => evidenceData.setProfile({ name: 'opaque pending', bio: 'v2 evidence' }), /pending/i)
  passed++; console.log('  ✓ leader-only application with an unknown receipt remains a pending publication')
  const evidencePending = JSON.parse(evidenceStore.getItem('peerit:pending-commit:v1'))
  ok(evidencePending.commit.mutations.length === 1 && evidencePending.commit.mutations[0].type === 'v2', 'the recovery proof covers an exact opaque v2 mutation key and signature')
  // Simulate a relay restart that retained its durable rows but lost the receipt
  // index. Replaying the v0 envelope now gets a stale CAS from the leader.
  evidenceLeaderRelay.receipts.delete(evidencePending.commit.commitId)
  await evidenceSync.wake()
  const oneCopyProof = await evidencePear.sync.proveCommitQuorum(evidenceApp, evidencePending.commit)
  const oneCopyStatus = await evidenceSync.status()
  ok(oneCopyProof.ok === false && oneCopyProof.quorum === 1, 'one complete signed census is evidence of one copy, never a fabricated quorum')
  ok(!!evidenceStore.getItem('peerit:pending-commit:v1') && oneCopyStatus.atomicCommit.recoveryNeeded === true, 'stale recovery retains the marker and reports recoveryNeeded while the mirror missed the commit')

  const leaderGroup = evidenceLeaderRelay.groups.get(evidenceApp)
  evidenceMirrorRelay.groups.set(evidenceApp, { rows: new Map(leaderGroup.rows), version: leaderGroup.version })
  const twoCopyProof = await evidencePear.sync.proveCommitQuorum(evidenceApp, evidencePending.commit)
  ok(twoCopyProof.ok === true && twoCopyProof.quorum === 2 && new Set(twoCopyProof.evidence.map((item) => item.origin)).size === 2, 'two distinct signed-roster origins independently prove the full head census and exact pending v2 row')
  await evidenceSync.wake()
  ok(!evidenceStore.getItem('peerit:pending-commit:v1') && (await evidenceSync.status()).atomicCommit.recoveryNeeded === false, 'the same stale envelope clears only after the mirror catches up and two-origin proof succeeds')

  const C = 'https://c.atomic.test'
  const boundedWorld = makeWorld([A, B, C])
  for (const base of [A, B]) {
    boundedWorld.relays.get(new URL(base).host).groups.set(evidenceApp, { rows: new Map(leaderGroup.rows), version: leaderGroup.version })
  }
  boundedWorld.relays.get(new URL(C).host).rangeMode = 'hang'
  const boundedPool = createRelayPool({
    relays: signedWriterRelays([A, B, C]),
    fetch: boundedWorld.fetch,
    commitTimeoutMs: 35,
    evidenceTimeoutMs: 35
  })
  const boundedStarted = Date.now()
  const boundedProof = await boundedPool.sync.proveCommitQuorum(evidenceApp, evidencePending.commit)
  ok(boundedProof.ok === true && boundedProof.quorum === 2 && Date.now() - boundedStarted < 250, 'evidence requests are time-bounded; two good origins prove quorum despite a hanging third')
  evidenceSync.destroy()

  console.log('\n— floor persistence is part of commit completion —')
  const floorWorld = makeWorld([A, B])
  const floorId = await identity('floor-failure')
  const floorBase = mem()
  let floorWritable = false
  const floorStore = {
    ...floorBase,
    setItem: (key, value) => {
      if (key === 'peerit:head-floor' && !floorWritable) throw new Error('injected floor write failure')
      return floorBase.setItem(key, value)
    }
  }
  const floorSync = writerSync({ pear: pool(floorWorld, [A, B]), id: floorId, storage: floorStore })
  await floorSync.ready()
  await assert.rejects(async () => floorSync.append(await signedProfile(floorId, '-floor')), /pending/i)
  passed++; console.log('  ✓ quorum without a read-back-verified floor remains pending')
  const floorStatus = await floorSync.status()
  ok(!!floorStore.getItem('peerit:pending-commit:v1') && floorStatus.atomicCommit.pending, 'floor failure preserves both the durable marker and pending status')
  floorWritable = true
  await floorSync.wake()
  const floorSaved = JSON.parse(floorStore.getItem('peerit:head-floor'))[floorId.me().pubkey]
  ok(!floorStore.getItem('peerit:pending-commit:v1') && floorSaved.v === 1 && /^[0-9a-f]{64}$/.test(floorSaved.root), 'retry persists the exact floor before clearing the marker')
  floorSync.destroy()

  console.log('\n— poll retries pending publication with bounded backoff —')
  const periodicWorld = makeWorld([A, B])
  for (const relay of periodicWorld.relays.values()) relay.mode = 'fail'
  const periodicId = await identity('periodic-retry')
  const periodicStore = mem()
  const periodic = writerSync({ pear: pool(periodicWorld, [A, B]), id: periodicId, storage: periodicStore, pollMs: 25 })
  await periodic.ready()
  await assert.rejects(async () => periodic.append(await signedProfile(periodicId, '-periodic')), /pending/i)
  passed++; console.log('  ✓ failed quorum schedules (rather than hot-loops) its next retry')
  const periodicStatus = await periodic.status()
  ok(periodicStatus.atomicCommit.pending && periodicStatus.atomicCommit.nextRetryAt > Date.now(), 'atomic status exposes the pending commit and its future retry time')
  for (const relay of periodicWorld.relays.values()) relay.mode = 'ok'
  ok(await until(() => !periodicStore.getItem('peerit:pending-commit:v1')), 'the normal poll loop recovers the marker without reload or manual wake')
  periodic.destroy()

  console.log('\n— one relay sends nothing; stale CAS quarantines —')
  const oneWorld = makeWorld([A])
  const oneId = await identity('one-relay')
  const one = writerSync({ pear: pool(oneWorld, [A]), id: oneId, storage: mem() })
  await one.ready()
  await assert.rejects(async () => one.append(await signedProfile(oneId)), /requires two relays|read-only/i)
  passed++; console.log('  ✓ one-relay writer fails closed before constructing a publication')
  ok(oneWorld.counts.commit === 0, 'relay pool checks quorum before sending to its sole relay')
  one.destroy()

  const unadvertisedWorld = makeWorld([A, B])
  const unadvertised = createRelayPool({
    relays: [A, B].map((apiBase) => ({ apiBase, apiToken: 'test-token' })),
    fetch: unadvertisedWorld.fetch
  })
  ok(typeof unadvertised.sync.commit === 'undefined' && unadvertised._atomicCommit === false, 'two relays without the exact durable capability remain a legacy/read-only pool')

  const staleWorld = makeWorld([A, B])
  for (const relay of staleWorld.relays.values()) relay.mode = 'stale'
  const staleId = await identity('stale')
  const staleStore = mem()
  const stale = writerSync({ pear: pool(staleWorld, [A, B]), id: staleId, storage: staleStore })
  await stale.ready()
  await assert.rejects(async () => stale.append(await signedProfile(staleId)), /stale/i)
  passed++; console.log('  ✓ stale compare-and-swap is surfaced distinctly')
  ok(!!staleStore.getItem('peerit:pending-commit:v1'), 'stale CAS preserves the exact pending commit for reconciliation')
  ok((await stale.status()).withholding.includes(staleId.me().pubkey), 'stale CAS quarantines the writer outbox')
  stale.destroy()

  console.log('\n— a healthy remote advance safely rebases exact mutations —')
  const rebaseWorld = makeWorld([A, B])
  const rebaseId = await identity('same-writer-two-devices')
  const remote = writerSync({ pear: pool(rebaseWorld, [A, B]), id: rebaseId, storage: mem() })
  const localStore = mem()
  const local = writerSync({ pear: pool(rebaseWorld, [A, B]), id: rebaseId, storage: localStore })
  await Promise.all([remote.ready(), local.ready()])
  const remoteOp = await signedProfile(rebaseId, '-remote-winner')
  const localTarget = '9'.repeat(64)
  const localOp = await signedFollow(rebaseId, localTarget)
  // Build the other device's valid v0 envelope before the local request takes its
  // device lock. The world hook publishes it while the local v0 leader CAS waits.
  const remotePending = await remote._buildAtomicCommit([remoteOp])
  rebaseWorld.beforeNextCommit(() => remote.pear.sync.commit(rebaseId.me().pubkey, remotePending.commit))
  const rebaseReceipt = await local.append(localOp)
  ok(rebaseReceipt.quorum === 2 && rebaseReceipt.head.version === 2, 'stale leader CAS refreshes, audits, and rebases onto the verified remote head')
  ok(!localStore.getItem('peerit:pending-commit:v1'), 'the atomically replaced rebase marker clears only after its own quorum')
  for (const relay of rebaseWorld.relays.values()) {
    const group = relay.groups.get(rebaseId.me().pubkey)
    ok(group.rows.has(keys.profile(rebaseId.me().pubkey)) && group.rows.has(keys.follow(localTarget, rebaseId.me().pubkey)), `${relay.base} contains both the remote winner and exact rebased mutation`)
    ok(group.rows.get(keys.head(rebaseId.me().pubkey)).version === 2 && group.rows.get(keys.head(rebaseId.me().pubkey)).count === 2, `${relay.base} converges on signed head v2/count 2`)
  }
  const rebaseLeader = local.pear._leaderFor(rebaseId.me().pubkey).origin
  const localAttempts = rebaseWorld.relays.get(new URL(rebaseLeader).host).calls.filter(commit => commit.mutations.some(mutation => mutation.type === TYPE.FOLLOW))
  ok(localAttempts.length === 2 && localAttempts[0].mutations[0].data._sig === localAttempts[1].mutations[0].data._sig, 'rebase preserves the exact signed mutation while replacing only CAS/head authorization')
  remote.destroy(); local.destroy()

  console.log('\n— vault-only reload can activate only the pending author for stale recovery —')
  const vaultRecoveryWorld = makeWorld([A, B])
  const vaultDonor = await identity('vault-recovery-donor')
  const vaultAppId = vaultDonor.me().pubkey
  const vaultStore = mem()
  const draftRecovery = writerSync({ pear: pool(vaultRecoveryWorld, [A, B]), id: vaultDonor, storage: vaultStore })
  await draftRecovery.ready()
  const vaultTarget = '8'.repeat(64)
  const vaultMutation = await signedFollow(vaultDonor, vaultTarget)
  const vaultPending = await draftRecovery._buildAtomicCommit([vaultMutation])
  draftRecovery._persistPendingCommit(vaultPending)
  draftRecovery.destroy()

  // A second device holding the same writer advances the outbox, so the persisted
  // v0 envelope needs a newly signed v2 head rather than a signature-free retry.
  const vaultRemote = writerSync({ pear: pool(vaultRecoveryWorld, [A, B]), id: vaultDonor, storage: mem() })
  await vaultRemote.ready()
  await vaultRemote.append(await signedProfile(vaultDonor, '-vault-remote'))
  vaultRemote.destroy()

  const lockedVaultId = await identity('locked-vault', { lazy: true })
  const lockedVaultSync = writerSync({ pear: pool(vaultRecoveryWorld, [A, B]), id: lockedVaultId, storage: vaultStore })
  await lockedVaultSync.ready()
  const lockedStatus = await lockedVaultSync.status()
  ok(lockedVaultId.me().pubkey === null && lockedStatus.atomicCommit.pending && lockedStatus.atomicCommit.recoveryNeeded, 'vault-only reload stays identity-less while stale pending recovery reports its exact author')
  ok(lockedStatus.atomicCommit.pendingAppId === vaultAppId, 'status exposes only the pending author needed by the matching-vault gate')
  let arbitraryMutationRan = false
  await assert.rejects(
    () => lockedVaultSync.withAtomicWriterSession(async () => { arbitraryMutationRan = true }),
    (error) => error && error.code === 'PEERIT_PENDING_WRITER_LOCK',
    'ordinary import/forget writer sessions remain blocked over pending recovery'
  )
  passed++; console.log('  ✓ ordinary import/forget writer sessions remain blocked over pending recovery')
  ok(!arbitraryMutationRan, 'the blocked arbitrary identity callback never executes')

  let wrongActivationRan = false
  const wrongAppId = vaultAppId === 'f'.repeat(64) ? 'e'.repeat(64) : 'f'.repeat(64)
  await assert.rejects(
    () => lockedVaultSync.recoverPendingWithIdentity(wrongAppId, async () => { wrongActivationRan = true }),
    /does not match the pending publication author/i,
    'the recovery escape hatch rejects every non-matching identity before activation'
  )
  passed++; console.log('  ✓ the recovery escape hatch rejects every non-matching identity before activation')
  ok(!wrongActivationRan, 'a wrong-vault callback never receives the recovery lock')

  let matchingActivations = 0
  const recoveredReceipt = await lockedVaultSync.recoverPendingWithIdentity(vaultAppId, async ({ appId }) => {
    assert.equal(appId, vaultAppId)
    matchingActivations++
    await lockedVaultId.restoreFromVault(vaultDonor.currentSeedEntry())
  })
  ok(matchingActivations === 1 && lockedVaultId.me().pubkey === vaultAppId, 'only the exact saved vault activates inside the pending recovery lock')
  ok(recoveredReceipt.quorum === 2 && recoveredReceipt.head.version === 2, 'matching vault signs the stale rebase and reaches two durable receipts')
  ok(!vaultStore.getItem('peerit:pending-commit:v1'), 'matching-vault recovery clears the old envelope only after quorum')
  for (const relay of vaultRecoveryWorld.relays.values()) {
    const group = relay.groups.get(vaultAppId)
    ok(group.rows.has(keys.profile(vaultAppId)) && group.rows.has(keys.follow(vaultTarget, vaultAppId)), `${relay.base} retains the remote advance plus recovered pending mutation`)
  }
  lockedVaultSync.destroy()

  console.log('\n— quorum-proven later same-key intent supersedes stale pending —')
  const supersedeWorld = makeWorld([A, B])
  const supersedeId = await identity('same-key-supersession')
  const supersedeStore = mem()
  const supersedePear = pool(supersedeWorld, [A, B])
  const supersedeApp = supersedeId.me().pubkey
  const supersedeLeader = supersedePear._leaderFor(supersedeApp).origin
  const supersedeMirror = [A, B].find((base) => new URL(base).origin !== supersedeLeader)
  const supersedeLeaderRelay = supersedeWorld.relays.get(new URL(supersedeLeader).host)
  const supersedeMirrorRelay = supersedeWorld.relays.get(new URL(supersedeMirror).host)
  supersedeLeaderRelay.mode = 'lose-once'
  supersedeMirrorRelay.mode = 'fail'
  const staleWriter = writerSync({ pear: supersedePear, id: supersedeId, storage: supersedeStore })
  await staleWriter.ready()
  const olderProfile = await signedProfile(supersedeId, '-older-pending')
  await assert.rejects(() => staleWriter.append(olderProfile), /pending/i)
  passed++; console.log('  ✓ older same-key profile is retained as an ambiguous pending envelope')
  const supersedePending = JSON.parse(supersedeStore.getItem('peerit:pending-commit:v1'))
  supersedeLeaderRelay.receipts.delete(supersedePending.commit.commitId)
  // A later writer can only advance from v1 on both CAS stores after the missed
  // mirror catches up. Keep the original device's marker untouched while that
  // happens, then publish a strictly newer same-key value from another device.
  const supersedeV1 = supersedeLeaderRelay.groups.get(supersedeApp)
  supersedeMirrorRelay.groups.set(supersedeApp, { rows: new Map(supersedeV1.rows), version: supersedeV1.version })
  supersedeMirrorRelay.mode = 'ok'
  await new Promise((resolve) => setTimeout(resolve, 2))
  const newerWriter = writerSync({ pear: pool(supersedeWorld, [A, B]), id: supersedeId, storage: mem() })
  await newerWriter.ready()
  const newerProfile = await signedProfile(supersedeId, '-newer-winner')
  const newerReceipt = await newerWriter.append(newerProfile)
  ok(newerReceipt.quorum === 2 && newerReceipt.head.version === 2, 'another imported device commits the later same-key value to real quorum')
  const commitsBeforeSupersededRecovery = supersedeWorld.counts.commit
  await staleWriter.wake()
  ok(!supersedeStore.getItem('peerit:pending-commit:v1'), 'two-origin census proof recognizes the later LWW winner and reconciles the older marker')
  ok(supersedeWorld.counts.commit === commitsBeforeSupersededRecovery + 1, 'superseded recovery performs only the stale leader retry and never rebases the old value')
  for (const relay of supersedeWorld.relays.values()) {
    const group = relay.groups.get(supersedeApp)
    ok(group.rows.get(keys.profile(supersedeApp))._sig === newerProfile.data._sig && group.rows.get(keys.head(supersedeApp)).version === 2, `${relay.base} retains the quorum-proven newer profile without a v3 regression`)
  }
  staleWriter.destroy(); newerWriter.destroy()

  console.log('\n— signed-roster leader serializes writers; quorum ignores a hanging third —')
  const THREE = [A, B, 'https://c.atomic.test']
  const hangWorld = makeWorld(THREE)
  const hangPool = createRelayPool({ relays: signedWriterRelays(THREE), fetch: hangWorld.fetch, commitTimeoutMs: 120 })
  const hangApp = 'c'.repeat(64)
  const hangLeader = hangPool._leaderFor(hangApp)
  const hangingBase = THREE.filter((base) => new URL(base).origin !== hangLeader.origin)[1]
  hangWorld.relays.get(new URL(hangingBase).host).mode = 'hang'
  const hangStarted = Date.now()
  const hangReceipt = await hangPool.sync.commit(hangApp, fakeCommit(hangApp, 'd'.repeat(64), '1'.repeat(64), hangApp))
  ok(hangReceipt.quorum === 2 && Date.now() - hangStarted < 500, 'two matching receipts return without awaiting a never-settling third relay')
  ok(hangWorld.relays.get(new URL(hangingBase).host).aborted >= 1, 'the unused hanging mirror is aborted after quorum')

  const leaderDownWorld = makeWorld(THREE)
  const leaderDownPool = createRelayPool({ relays: signedWriterRelays(THREE), fetch: leaderDownWorld.fetch, commitTimeoutMs: 35 })
  const downLeader = leaderDownPool._leaderFor(hangApp)
  leaderDownWorld.relays.get(new URL(downLeader.origin).host).mode = 'hang'
  await assert.rejects(
    () => leaderDownPool.sync.commit(hangApp, fakeCommit(hangApp, 'e'.repeat(64), '2'.repeat(64), hangApp)),
    (error) => error && error.code === 'COMMIT_LEADER_FAILED'
  )
  passed++; console.log('  ✓ unavailable designated leader fails closed')
  ok([...leaderDownWorld.relays.values()].filter((relay) => relay.base !== downLeader.origin).every((relay) => relay.calls.length === 0), 'leader failure sends nothing to mirrors')

  const crossWorld = makeWorld([A, B])
  const crossPoolA = pool(crossWorld, [A, B])
  const crossPoolB = pool(crossWorld, [A, B])
  const crossApp = 'f'.repeat(64)
  const crossLeaderA = crossPoolA._leaderFor(crossApp)
  const crossLeaderB = crossPoolB._leaderFor(crossApp)
  ok(crossLeaderA.origin === crossLeaderB.origin && crossLeaderA.rosterIndex === crossLeaderB.rosterIndex, 'independent devices choose the same stable signed-roster leader for one appId')
  const firstCross = fakeCommit(crossApp, 'a'.repeat(64), '3'.repeat(64), crossApp)
  const secondCross = fakeCommit(crossApp, 'b'.repeat(64), '4'.repeat(64), crossApp)
  const crossed = await Promise.allSettled([
    crossPoolA.sync.commit(crossApp, firstCross),
    crossPoolB.sync.commit(crossApp, secondCross)
  ])
  const winner = crossed.find((result) => result.status === 'fulfilled')
  const loser = crossed.find((result) => result.status === 'rejected')
  ok(winner && loser && loser.reason.code === 'COMMIT_CAS_MISMATCH', 'crossed concurrent CAS attempts yield one quorum winner and one stale loser')
  const winnerId = winner.value.commitId
  const mirrorBase = [A, B].find((base) => new URL(base).origin !== crossLeaderA.origin)
  const mirror = crossWorld.relays.get(new URL(mirrorBase).host)
  ok(mirror.calls.length === 1 && mirror.calls[0].commitId === winnerId, 'the losing device never writes a different commit to the mirror')
  const roots = [A, B].map((base) => crossWorld.relays.get(new URL(base).host).groups.get(crossApp).rows.get(keys.head(crossApp)).root)
  ok(roots[0] === roots[1] && roots[0] === winner.value.head.root, 'leader-first delivery leaves both relays on the same signed head')

  console.log('\n— cross-relay reads recover rollback and resolve equal-version forks —')
  const readWorld = makeWorld(THREE)
  const readId = await identity('canonical-reader-floor')
  const readPool = pool(readWorld, THREE)
  const readWriter = writerSync({ pear: readPool, id: readId, storage: mem() })
  await readWriter.ready()
  await readWriter.append(await signedProfile(readId, '-canonical'))
  readWriter.destroy()
  const readApp = readId.me().pubkey
  const readLeader = readPool._leaderFor(readApp)
  const readLeaderGroup = readWorld.relays.get(new URL(readLeader.origin).host).groups.get(readApp)
  const canonicalHead = readLeaderGroup.rows.get(keys.head(readApp))
  // Give every relay the same proven baseline before injecting independently
  // valid writer-signed versions/forks.
  for (const base of THREE) {
    readWorld.relays.get(new URL(base).host).groups.set(readApp, { rows: new Map(readLeaderGroup.rows), version: readLeaderGroup.version })
  }
  const readMirrors = THREE.filter((base) => new URL(base).origin !== readLeader.origin)
  const higherHead = await signedHeadFork(readId, canonicalHead, { version: canonicalHead.version + 1, root: '8'.repeat(64), updatedAt: canonicalHead.updatedAt + 1 })
  const equalFork = await signedHeadFork(readId, canonicalHead, { root: '9'.repeat(64), updatedAt: canonicalHead.updatedAt + 2 })
  for (const base of readMirrors) readWorld.relays.get(new URL(base).host).groups.get(readApp).rows.set(keys.head(readApp), higherHead)
  ok((await readPool.sync.crossHead(readApp))?.head._sig === higherHead._sig, 'a unique higher signed mirror head recovers a reachable leader storage rollback')
  ok((await readPool.sync.directory()).heads[readApp]?._sig === higherHead._sig, 'directory also chooses the unique highest verified version over a rolled-back leader')

  readWorld.relays.get(new URL(readMirrors[0]).host).groups.get(readApp).rows.set(keys.head(readApp), equalFork)
  readWorld.relays.get(new URL(readMirrors[1]).host).groups.get(readApp).rows.set(keys.head(readApp), canonicalHead)
  ok((await readPool.sync.crossHead(readApp))?.head._sig === canonicalHead._sig, 'reachable roster leader resolves equal-version conflicting signed roots')
  ok((await readPool.sync.directory()).heads[readApp]?._sig === canonicalHead._sig, 'directory uses the same leader tie-break only for equal-version forks')

  readWorld.relays.get(new URL(readLeader.origin).host).readFail = true
  ok((await readPool.sync.crossHead(readApp)) === null, 'leader-unavailable crossHead rejects disagreeing mirrors instead of taking an arbitrary max')
  ok(!(await readPool.sync.directory()).heads[readApp], 'leader-unavailable directory rejects disagreeing mirror forks')
  for (const base of readMirrors) readWorld.relays.get(new URL(base).host).groups.get(readApp).rows.set(keys.head(readApp), canonicalHead)
  ok((await readPool.sync.crossHead(readApp))?.head._sig === canonicalHead._sig, 'leader-unavailable crossHead accepts matching evidence from two independent mirrors')
  ok((await readPool.sync.directory()).heads[readApp]?._sig === canonicalHead._sig, 'leader-unavailable directory accepts the same two-mirror evidence floor')

  const staticExact = createRelayPool({
    relays: [A, B].map((apiBase) => ({ apiBase, apiToken: 'test-token', atomicCommit: true, capabilities: ATOMIC_CAPABILITIES })),
    fetch: crossWorld.fetch
  })
  ok(staticExact._atomicCommit === false && typeof staticExact.sync.commit === 'undefined', 'exact relay capability without verified signed topology remains read-only')
  const notReady = createRelayPool({
    relays: signedWriterRelays([A, B]).map((relay) => ({ ...relay, ready: false })),
    fetch: crossWorld.fetch
  })
  ok(notReady._atomicCommit === false && typeof notReady.sync.commit === 'undefined', 'verified topology plus exact capabilities still fails closed unless runtime status is ready')
  const unstableRoster = createRelayPool({
    relays: signedWriterRelays([A, B]).map((relay) => ({ ...relay, rosterStable: false })),
    fetch: crossWorld.fetch
  })
  ok(unstableRoster._atomicCommit === false && typeof unstableRoster.sync.commit === 'undefined', 'writer mode fails closed unless every relay carries verified stable-roster metadata')
  const incompleteRoster = createRelayPool({
    relays: signedWriterRelays(THREE).slice(0, 2),
    fetch: crossWorld.fetch
  })
  ok(incompleteRoster._writerRelayCount === 2 && incompleteRoster._atomicCommit === false && typeof incompleteRoster.sync.commit === 'undefined', 'writer readiness requires every origin in the signed topology, not an arbitrary two-relay subset')

  console.log('\n— quorum success is not misreported when marker cleanup fails —')
  const stickyWorld = makeWorld([A, B])
  const stickyId = await identity('sticky-marker')
  const stickyStore = mem()
  const stickyRemove = stickyStore.removeItem
  let stickyCleanupFails = true
  stickyStore.removeItem = (key) => {
    if (stickyCleanupFails && key === 'peerit:pending-commit:v1') throw new Error('injected local cleanup failure')
    return stickyRemove(key)
  }
  const sticky = writerSync({ pear: pool(stickyWorld, [A, B]), id: stickyId, storage: stickyStore })
  await sticky.ready()
  const stickyReceipt = await sticky.append(await signedProfile(stickyId, '-sticky'))
  ok(stickyReceipt.quorum === 2, 'publication still reports its proven quorum receipt')
  ok(!!stickyStore.getItem('peerit:pending-commit:v1'), 'uncleared marker remains for an idempotent retry instead of being lost')
  await assert.rejects(async () => sticky.append(await signedProfile(stickyId, '-later')), /previous|awaiting/i)
  passed++; console.log('  ✓ retained marker keeps later writes blocked without calling the durable publication failed')
  const newerRoot = 'f'.repeat(64)
  stickyStore.setItem('peerit:head-floor', JSON.stringify({ [stickyId.me().pubkey]: { v: 2, root: newerRoot, t: 99 } }))
  stickyCleanupFails = false
  await sticky.wake()
  const preservedNewerFloor = JSON.parse(stickyStore.getItem('peerit:head-floor'))[stickyId.me().pubkey]
  ok(preservedNewerFloor.v === 2 && preservedNewerFloor.root === newerRoot && !!stickyStore.getItem('peerit:pending-commit:v1'), 'a delayed v1 receipt cannot regress a newer v2 floor or clear its recovery envelope')
  sticky.destroy()

  console.log('\n— shared-storage two-tab race cannot overwrite pending —')
  const tabsWorld = makeWorld([A, B])
  for (const relay of tabsWorld.relays.values()) relay.mode = 'fail'
  const tabsId = await identity('tabs-a')
  const tabsIdB = await identity('tabs-b')
  const shared = mem()
  const tabA = writerSync({ pear: pool(tabsWorld, [A, B]), id: tabsId, storage: shared })
  const tabB = writerSync({ pear: pool(tabsWorld, [A, B]), id: tabsIdB, storage: shared })
  await Promise.all([tabA.ready(), tabB.ready()])
  const [aResult, bResult] = await Promise.allSettled([
    tabA.append(await signedProfile(tabsId, '-tab-a')),
    tabB.append(await signedProfile(tabsIdB, '-tab-b'))
  ])
  ok(aResult.status === 'rejected' && bResult.status === 'rejected', 'both tabs fail closed while relay quorum is unavailable')
  const stored = JSON.parse(shared.getItem('peerit:pending-commit:v1'))
  const sentIds = new Set([...tabsWorld.relays.values()].flatMap((relay) => relay.calls.map((commit) => commit.commitId)))
  ok(sentIds.size === 1 && sentIds.has(stored.commit.commitId), 'two tabs with different identities preserve one pending commitId; the loser neither sends nor overwrites it')
  tabA.destroy(); tabB.destroy()

  console.log('\n— another tab can recover and clear a shared marker —')
  const clearWorld = makeWorld([A, B])
  const clearId = await identity('shared-writer')
  const clearShared = mem()
  const clearPearA = pool(clearWorld, [A, B])
  const clearLeader = clearPearA._leaderFor(clearId.me().pubkey).origin
  const clearMirror = [A, B].find(base => new URL(base).origin !== clearLeader)
  clearWorld.relays.get(new URL(clearLeader).host).mode = 'lose-once'
  clearWorld.relays.get(new URL(clearMirror).host).mode = 'fail'
  const staleTab = writerSync({ pear: clearPearA, id: clearId, storage: clearShared })
  await staleTab.ready()
  await assert.rejects(async () => staleTab.append(await signedProfile(clearId, '-tab-a-pending')), /pending/i)
  passed++; console.log('  ✓ first tab retains the shared marker after a partial publication')
  clearWorld.relays.get(new URL(clearMirror).host).mode = 'ok'
  const recoveringTab = writerSync({ pear: pool(clearWorld, [A, B]), id: clearId, storage: clearShared })
  await recoveringTab.ready()
  ok(!clearShared.getItem('peerit:pending-commit:v1'), 'second tab retries the exact envelope and clears the shared marker')
  const nextReceipt = await staleTab.append(await signedProfile(clearId, '-tab-a-after-clear'))
  ok(nextReceipt.quorum === 2 && nextReceipt.head.version === 2, 'first tab reloads the absent marker inside its lock and may safely publish the next version')
  staleTab.destroy(); recoveringTab.destroy()

  console.log('\n— boxed body and parent survive partial commit plus reload atomically —')
  const bodyWorld = makeWorld([A, B])
  const bodyId = await identity('boxed-batch')
  const bodyStore = mem()
  const bodyPear = pool(bodyWorld, [A, B])
  const bodyLeader = bodyPear._leaderFor(bodyId.me().pubkey).origin
  const bodyMirror = [A, B].find(base => new URL(base).origin !== bodyLeader)
  bodyWorld.relays.get(new URL(bodyLeader).host).mode = 'lose-once'
  bodyWorld.relays.get(new URL(bodyMirror).host).mode = 'fail'
  const beforeBodyReload = writerSync({ pear: bodyPear, id: bodyId, storage: bodyStore })
  await beforeBodyReload.ready()
  const bodyData = createData(beforeBodyReload, bodyId, { minBits: { blob: 0, post: 0 } })
  bodyData.getCommunity = async () => ({ slug: 'atomic' })
  bodyData.overlay = async () => ({ banned: new Set() })
  await assert.rejects(
    () => bodyData.submitPost({ community: 'atomic', kind: 'text', title: 'one transaction', body: 'x'.repeat(3000), nonce: 'atomic-boxed-body' }),
    /pending/i
  )
  passed++; console.log('  ✓ ambiguous long-body publication remains one durable pending batch')
  const bodyPending = JSON.parse(bodyStore.getItem('peerit:pending-commit:v1'))
  const blobMutation = bodyPending.commit.mutations.find(mutation => mutation.type === TYPE.BLOB)
  const postMutation = bodyPending.commit.mutations.find(mutation => mutation.type === TYPE.POST)
  ok(bodyPending.commit.mutations.length === 2 && blobMutation && postMutation && bodyWorld.counts.append === 0, 'blob and parent share one atomic envelope with no legacy append')
  beforeBodyReload.destroy()
  bodyWorld.relays.get(new URL(bodyMirror).host).mode = 'ok'
  const afterBodyReload = writerSync({ pear: pool(bodyWorld, [A, B]), id: bodyId, storage: bodyStore })
  await afterBodyReload.ready()
  ok(!bodyStore.getItem('peerit:pending-commit:v1'), 'reload recovers the exact two-mutation envelope and clears it after quorum')
  for (const relay of bodyWorld.relays.values()) {
    const group = relay.groups.get(bodyId.me().pubkey)
    ok(group.rows.has(keys.blob(blobMutation.data.blobId)) && group.rows.has(keys.post(postMutation.data.community, postMutation.data.cid)), `${relay.base} stores both ciphertext blob and signed parent`)
    const head = group.rows.get(keys.head(bodyId.me().pubkey))
    ok(head.version === 1 && head.count === 2, `${relay.base} exposes neither half without signed head v1/count 2`)
  }
  afterBodyReload.destroy()

  console.log(`\natomic-commit-client: ${passed} checks passed.`)
}

main().catch((error) => { console.error('❌', (error && error.stack) || error); process.exit(1) })
