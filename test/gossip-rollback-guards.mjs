// Focused rollback-integrity regressions for the bridge gossip path.
// Run: node test/gossip-rollback-guards.mjs

import assert from 'node:assert'
import { DevIdentity } from '../js/identity.js'
import { canonical, censusString, outboxCensus } from '../js/canon.js'
import { hashHex, ready as cryptoReady } from '../js/crypto.js'
import { BridgeGossipSync, cachedViewHasRows } from '../js/gossip.js'
import { keys } from '../js/model.js'

const CACHE_KEY = 'peerit:gossip-view'
const CLAIMED_KEY = 'peerit:claimed'
const FLOOR_KEY = 'peerit:head-floor'
let passed = 0
const ok = (condition, message) => { assert.ok(condition, message); passed++; console.log('  ✓ ' + message) }
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

function mem () {
  const m = new Map()
  return {
    getItem: (key) => m.has(key) ? m.get(key) : null,
    setItem: (key, value) => m.set(key, String(value)),
    removeItem: (key) => m.delete(key),
    clear: () => m.clear()
  }
}

async function identity (name) {
  const id = new DevIdentity(mem(), mem())
  await id.ready()
  await id.createUser(name)
  return id
}

async function signed (id, type, data) {
  const s = await id.sign(canonical(type, data))
  return { ...data, _sig: s.signature, _k: s.publicKey, _dk: s.driveKey, _ns: s.namespace, _alg: s.algorithm }
}

async function state (id, version, records) {
  const pub = id.me().pubkey
  const rows = new Map(records)
  const census = outboxCensus([...rows].map(([key, value]) => ({ key, value })), pub)
  const head = await signed(id, 'head', {
    id: pub,
    author: pub,
    version,
    count: census.length,
    root: await hashHex(censusString(census)),
    updatedAt: 1000 + version
  })
  rows.set(keys.head(pub), head)
  return rows
}

function cacheBlob (pub, rows, inviteKey = 'a'.repeat(64)) {
  return JSON.stringify({
    v: 1,
    peers: [{ pub, appId: pub, inviteKey }],
    views: { [pub]: Object.fromEntries(rows) },
    heads: {}
  })
}

function snapshot (pub, rows) {
  return { authors: [{ pub, rows: [...rows].map(([key, value]) => ({ key, value })) }] }
}

function makeWorld () {
  const groups = new Map()
  let createCalls = 0
  let appendCalls = 0
  let headAppendAttempts = 0
  let failHeadAppends = 0
  let commitThenThrowRecords = 0
  let swarmJoins = 0
  const ensure = (appId) => {
    if (!groups.has(appId)) groups.set(appId, { inviteKey: 'a'.repeat(64), rows: new Map(), version: 0 })
    return groups.get(appId)
  }
  const sorted = (g) => [...g.rows].sort(([a], [b]) => a.localeCompare(b)).map(([key, value]) => ({ key, value }))
  const sync = {
    create: async (appId) => { createCalls++; return { appId, inviteKey: ensure(appId).inviteKey, writerPublicKey: appId } },
    join: async (appId, inviteKey) => {
      const g = ensure(appId)
      if (inviteKey !== g.inviteKey) throw new Error('bad invite')
      return { appId, inviteKey, writerPublicKey: appId }
    },
    append: async (appId, op) => {
      appendCalls++
      if (op.type === 'head') {
        headAppendAttempts++
        if (failHeadAppends > 0) { failHeadAppends--; throw new Error('injected head append failure') }
      }
      const g = ensure(appId)
      const key = op.type.replace(':', '!') + '!' + op.data.id
      g.rows.set(key, op.data)
      g.version++
      if (op.type !== 'head' && commitThenThrowRecords > 0) { commitThenThrowRecords--; throw new Error('injected commit-then-response-loss') }
      return { ok: true, key }
    },
    heads: async (appIds) => ({ heads: Object.fromEntries(appIds.map((appId) => [appId, ensure(appId).version])) }),
    range: async (appId, opts = {}) => {
      let rows = sorted(ensure(appId))
      if (opts.gt != null) rows = rows.filter((r) => r.key > opts.gt)
      if (opts.gte != null) rows = rows.filter((r) => r.key >= opts.gte)
      if (opts.lt != null) rows = rows.filter((r) => r.key < opts.lt)
      if (opts.lte != null) rows = rows.filter((r) => r.key <= opts.lte)
      return rows.slice(0, Number(opts.limit) || 1000)
    },
    list: async (appId, prefix = '', opts = {}) => {
      let rows = sorted(ensure(appId))
      if (prefix) rows = rows.filter((r) => r.key >= prefix && r.key < prefix + '\xff')
      return rows.slice(0, Number(opts.limit) || 1000)
    },
    status: async (appId) => ({ appId, inviteKey: ensure(appId).inviteKey, viewLength: ensure(appId).rows.size })
  }
  const channel = { peers: [], on: () => {}, destroy: () => {} }
  return {
    groups,
    pear: { sync, swarm: { v1: { join: async () => { swarmJoins++; return channel } } } },
    createCalls: () => createCalls,
    appendCalls: () => appendCalls,
    headAppendAttempts: () => headAppendAttempts,
    swarmJoins: () => swarmJoins,
    failNextHeadAppends: (count) => { failHeadAppends = Math.max(0, count | 0) },
    commitNextRecordsThenThrow: (count = 1) => { commitThenThrowRecords = Math.max(0, count | 0) },
    put: (pub, rows, version = 1) => {
      const g = ensure(pub)
      g.rows = new Map(rows)
      g.version = version
      return g
    }
  }
}

function bridge ({ world, id, storage = mem(), writeHead = false, readOnly = false, pollMs = 0, seedOutboxes = [], seedSnapshot = null, instantBoot = false }) {
  return new BridgeGossipSync({
    pear: world.pear,
    getMe: () => id.me().pubkey,
    identity: id,
    storage,
    validate: null,
    pollMs,
    writeHead,
    readOnly,
    seedOutboxes,
    seedSnapshot,
    instantBoot
  })
}

async function main () {
  await cryptoReady()

  console.log('\n— persisted floor v3 rejects cached v1 and falls back without claim capture —')
  const staleId = await identity('stale-cache-author')
  const seedId = await identity('seed-author')
  const readerId = await identity('cache-reader')
  const stalePub = staleId.me().pubkey
  const seedPub = seedId.me().pubkey
  const staleCommunity = await signed(staleId, 'community', { id: 'claim', slug: 'claim', title: 'stale claimant', description: '', creator: stalePub, author: stalePub, createdAt: 1, updatedAt: 1 })
  const staleV1 = await state(staleId, 1, [[keys.community('claim'), staleCommunity]])
  const floorPost1 = await signed(staleId, 'post', { id: 'claim!one', cid: 'one', community: 'claim', kind: 'text', title: 'one', body: '', url: '', author: stalePub, createdAt: 2, editedAt: 0, deleted: false })
  const floorPost2 = await signed(staleId, 'post', { id: 'claim!two', cid: 'two', community: 'claim', kind: 'text', title: 'two', body: '', url: '', author: stalePub, createdAt: 3, editedAt: 0, deleted: false })
  const staleV3 = await state(staleId, 3, [[keys.community('claim'), staleCommunity], [keys.post('claim', 'one'), floorPost1], [keys.post('claim', 'two'), floorPost2]])
  const seedCommunity = await signed(seedId, 'community', { id: 'claim', slug: 'claim', title: 'verified seed', description: '', creator: seedPub, author: seedPub, createdAt: 1, updatedAt: 1 })
  const seedRows = await state(seedId, 1, [[keys.community('claim'), seedCommunity]])
  const staleDevice = mem()
  staleDevice.setItem(FLOOR_KEY, JSON.stringify({ [stalePub]: { v: 3, root: staleV3.get(keys.head(stalePub)).root, t: 1 } }))
  staleDevice.setItem(CACHE_KEY, cacheBlob(stalePub, staleV1))
  staleDevice.setItem(CLAIMED_KEY, '{}')
  ok(!cachedViewHasRows(staleDevice), 'the pre-boot cache gate rejects a v1 cache below persisted floor v3')
  const fallbackWorld = makeWorld()
  const fallback = bridge({ world: fallbackWorld, id: readerId, storage: staleDevice, seedSnapshot: snapshot(seedPub, seedRows), instantBoot: true })
  await fallback.ready()
  const fallbackClaim = await fallback.get(keys.community('claim'))
  ok(fallbackClaim && fallbackClaim.creator === seedPub, 'verified seed content replaces the quarantined cached author')
  ok(fallback._claimed.claim === seedPub, 'the rejected cache row cannot capture its sticky community claim')
  fallback.destroy()

  console.log('\n— equal-version cache fork with a different root is rejected —')
  const forkId = await identity('fork-author')
  const forkReaderId = await identity('fork-reader')
  const forkPub = forkId.me().pubkey
  const goodCommunity = await signed(forkId, 'community', { id: 'fork', slug: 'fork', title: 'good root', description: '', creator: forkPub, author: forkPub, createdAt: 1, updatedAt: 1 })
  const forkCommunity = await signed(forkId, 'community', { id: 'fork', slug: 'fork', title: 'fork root', description: '', creator: forkPub, author: forkPub, createdAt: 1, updatedAt: 2 })
  const goodRows = await state(forkId, 3, [[keys.community('fork'), goodCommunity]])
  const forkRows = await state(forkId, 3, [[keys.community('fork'), forkCommunity]])
  ok(goodRows.get(keys.head(forkPub)).root !== forkRows.get(keys.head(forkPub)).root, 'the two valid version-3 heads commit different roots')
  const forkDevice = mem()
  forkDevice.setItem(FLOOR_KEY, JSON.stringify({ [forkPub]: { v: 3, root: goodRows.get(keys.head(forkPub)).root, t: 1 } }))
  forkDevice.setItem(CACHE_KEY, cacheBlob(forkPub, forkRows))
  ok(!cachedViewHasRows(forkDevice), 'the pre-boot cache gate rejects a same-version different-root fork')
  const forkWorld = makeWorld()
  const forkReader = bridge({ world: forkWorld, id: forkReaderId, storage: forkDevice, seedSnapshot: snapshot(forkPub, goodRows), instantBoot: true })
  await forkReader.ready()
  ok((await forkReader.get(keys.community('fork'))).title === 'good root', 'cache restore quarantines the fork and renders the floor-matching seed state')
  forkReader.destroy()
  const ambiguousDevice = mem()
  ambiguousDevice.setItem(CACHE_KEY, cacheBlob(forkPub, forkRows))
  const ambiguousReaderId = await identity('ambiguous-fork-reader')
  const ambiguousReader = bridge({ world: makeWorld(), id: ambiguousReaderId, storage: ambiguousDevice, seedSnapshot: snapshot(forkPub, goodRows), instantBoot: true })
  await ambiguousReader.ready()
  ok((await ambiguousReader.status()).withholding.includes(forkPub) && !(await ambiguousReader.get(keys.community('fork'))), 'equal-version different-root cache/snapshot ambiguity quarantines the whole author')
  ambiguousReader.destroy()

  console.log('\n— signed snapshot monotonically repairs an older valid cache —')
  const recoveryId = await identity('snapshot-recovery-author')
  const recoveryPub = recoveryId.me().pubkey
  const recoveryReaderId = await identity('snapshot-recovery-reader')
  const recoveryCommunity = await signed(recoveryId, 'community', { id: 'recover', slug: 'recover', title: 'recover', description: '', creator: recoveryPub, author: recoveryPub, createdAt: 1, updatedAt: 1 })
  const recoveryPost1 = await signed(recoveryId, 'post', { id: 'recover!one', cid: 'one', community: 'recover', kind: 'text', title: 'one', body: '', url: '', author: recoveryPub, createdAt: 2, editedAt: 0, deleted: false })
  const recoveryPost2 = await signed(recoveryId, 'post', { id: 'recover!two', cid: 'two', community: 'recover', kind: 'text', title: 'two', body: '', url: '', author: recoveryPub, createdAt: 3, editedAt: 0, deleted: false })
  const recoveryPost3 = await signed(recoveryId, 'post', { id: 'recover!three', cid: 'three', community: 'recover', kind: 'text', title: 'three', body: '', url: '', author: recoveryPub, createdAt: 4, editedAt: 0, deleted: false })
  const recoveryV1 = await state(recoveryId, 1, [[keys.community('recover'), recoveryCommunity]])
  const recoveryV3 = await state(recoveryId, 3, [[keys.community('recover'), recoveryCommunity], [keys.post('recover', 'one'), recoveryPost1], [keys.post('recover', 'two'), recoveryPost2]])
  const recoveryV4 = await state(recoveryId, 4, [[keys.community('recover'), recoveryCommunity], [keys.post('recover', 'one'), recoveryPost1], [keys.post('recover', 'two'), recoveryPost2], [keys.post('recover', 'three'), recoveryPost3]])
  const recoveryDevice = mem()
  recoveryDevice.setItem(FLOOR_KEY, JSON.stringify({ [recoveryPub]: { v: 1, root: recoveryV1.get(keys.head(recoveryPub)).root, t: 1 } }))
  recoveryDevice.setItem(CACHE_KEY, cacheBlob(recoveryPub, recoveryV1))
  const recovered = bridge({ world: makeWorld(), id: recoveryReaderId, storage: recoveryDevice, seedSnapshot: snapshot(recoveryPub, recoveryV3), instantBoot: true })
  await recovered.ready()
  const recoveredFloor = JSON.parse(recoveryDevice.getItem(FLOOR_KEY) || '{}')[recoveryPub]
  ok(recovered._peerViews.get(recoveryPub)[keys.head(recoveryPub)].version === 3 && !!(await recovered.get(keys.post('recover', 'two'))), 'a valid signed snapshot v3 replaces valid cached v1 and exposes the missing rows')
  ok(recoveredFloor && recoveredFloor.v === 3 && recoveredFloor.root === recoveryV3.get(keys.head(recoveryPub)).root, 'snapshot recovery ratchets the durable floor from v1 to v3')
  recovered.destroy()
  const newerDevice = mem()
  newerDevice.setItem(FLOOR_KEY, JSON.stringify({ [recoveryPub]: { v: 4, root: recoveryV4.get(keys.head(recoveryPub)).root, t: 1 } }))
  newerDevice.setItem(CACHE_KEY, cacheBlob(recoveryPub, recoveryV4))
  const newerReaderId = await identity('newer-cache-reader')
  const newer = bridge({ world: makeWorld(), id: newerReaderId, storage: newerDevice, seedSnapshot: snapshot(recoveryPub, recoveryV3), instantBoot: true })
  await newer.ready()
  const newerFloor = JSON.parse(newerDevice.getItem(FLOOR_KEY) || '{}')[recoveryPub]
  ok(newer._peerViews.get(recoveryPub)[keys.head(recoveryPub)].version === 4 && !!(await newer.get(keys.post('recover', 'three'))), 'an older signed snapshot v3 never downgrades valid cached v4')
  ok(newerFloor.v === 4 && newerFloor.root === recoveryV4.get(keys.head(recoveryPub)).root, 'the newer cached floor remains pinned after snapshot reconciliation')
  newer.destroy()

  console.log('\n— read-only identity performs zero writable outbox attempts —')
  const readOnlyWorld = makeWorld()
  const readOnlyGroup = readOnlyWorld.put(recoveryPub, recoveryV3, 1)
  const readOnlyId = await identity('read-only-reader')
  const readOnly = bridge({ world: readOnlyWorld, id: readOnlyId, readOnly: true, pollMs: 5, seedOutboxes: [{ appId: recoveryPub, inviteKey: readOnlyGroup.inviteKey }] })
  await readOnly.ready()
  await readOnly._refresh()
  ok(!!(await readOnly.get(keys.post('recover', 'two'))), 'read-only boot still joins and reads the seeded author')
  await readOnly.announce()
  await readOnly.wake()
  await delay(30) // exercise multiple background poll ticks
  await assert.rejects(() => readOnly.append({ type: 'post', data: recoveryPost3 }), /read-only/i)
  passed++
  console.log('  ✓ direct append remains fail-closed in read-only mode')
  ok(readOnlyWorld.createCalls() === 0 && readOnlyWorld.appendCalls() === 0, 'boot, wake, poll, announce, and append make zero sync.create/append attempts')
  ok(readOnlyWorld.swarmJoins() >= 1, 'read-only mode preserves swarm discovery while withholding write capability')
  readOnly.destroy()

  console.log('\n— forged rowful cache is re-admitted and falls back to seed —')
  const forgedId = await identity('forged-cache-author')
  const forgedSeedId = await identity('forged-cache-seed')
  const forgedReaderId = await identity('forged-cache-reader')
  const forgedPub = forgedId.me().pubkey
  const forgedSeedPub = forgedSeedId.me().pubkey
  const forgedRow = { id: 'safe', slug: 'safe', title: 'forged cache', description: '', creator: forgedPub, author: forgedPub, createdAt: 1, updatedAt: 1, _sig: '00', _k: forgedPub, _dk: '00', _ns: 'peerit', _alg: 'Ed25519' }
  const forgedCache = new Map([[keys.community('safe'), forgedRow]])
  const safeSeedRow = await signed(forgedSeedId, 'community', { id: 'safe', slug: 'safe', title: 'safe seed', description: '', creator: forgedSeedPub, author: forgedSeedPub, createdAt: 1, updatedAt: 1 })
  const safeSeedRows = await state(forgedSeedId, 1, [[keys.community('safe'), safeSeedRow]])
  const forgedDevice = mem()
  forgedDevice.setItem(CACHE_KEY, cacheBlob(forgedPub, forgedCache))
  forgedDevice.setItem(CLAIMED_KEY, '{}')
  ok(cachedViewHasRows(forgedDevice), 'the synchronous shape helper sees rows but cannot authenticate the forged signature')
  const forgedWorld = makeWorld()
  const forgedReader = bridge({ world: forgedWorld, id: forgedReaderId, storage: forgedDevice, seedSnapshot: snapshot(forgedSeedPub, safeSeedRows), instantBoot: true })
  await forgedReader.ready()
  const safeCommunity = await forgedReader.get(keys.community('safe'))
  ok(safeCommunity && safeCommunity.creator === forgedSeedPub && safeCommunity.title === 'safe seed', 'async cache re-admission rejects the forgery and renders the verified seed fallback')
  ok(!forgedReader._peerViews.has(forgedPub) && forgedReader._claimed.safe === forgedSeedPub, 'the forged cached row neither renders nor captures its claim')
  forgedReader.destroy()

  console.log('\n— first incomplete census is quarantined as a whole author —')
  const censusId = await identity('census-author')
  const censusReaderId = await identity('census-reader')
  const censusPub = censusId.me().pubkey
  const censusCommunity = await signed(censusId, 'community', { id: 'census', slug: 'census', title: 'census', description: '', creator: censusPub, author: censusPub, createdAt: 1, updatedAt: 1 })
  const censusPost = await signed(censusId, 'post', { id: 'census!post', cid: 'post', community: 'census', kind: 'text', title: 'committed', body: '', url: '', author: censusPub, createdAt: 2, editedAt: 0, deleted: false })
  const censusFull = await state(censusId, 2, [[keys.community('census'), censusCommunity], [keys.post('census', 'post'), censusPost]])
  const censusPartial = new Map(censusFull)
  censusPartial.delete(keys.post('census', 'post'))
  const censusWorld = makeWorld()
  const censusGroup = censusWorld.put(censusPub, censusPartial, 1)
  const censusStorage = mem()
  const censusReader = bridge({ world: censusWorld, id: censusReaderId, storage: censusStorage, seedOutboxes: [{ appId: censusPub, inviteKey: censusGroup.inviteKey }] })
  await censusReader.ready()
  await censusReader._refresh()
  ok((await censusReader.status()).withholding.includes(censusPub), 'missing one head-committed row flags the author on the first read')
  ok((await censusReader.range({ limit: 100 })).every((r) => !r.value || r.value._k !== censusPub), 'no partial row from the bad first census is presented')
  ok(!censusReader._peerViews.has(censusPub), 'the staged first-read author view is removed, not retained as a baseline')
  ok(!censusStorage.getItem(CACHE_KEY), 'the incomplete first census is never persisted as a rowful cache')
  ok(!censusReader._claimed.census, 'a quarantined first census cannot capture a community claim')
  censusGroup.rows = new Map(censusFull)
  censusGroup.version++
  await censusReader._refresh()
  ok(!(await censusReader.status()).withholding.includes(censusPub) && !!(await censusReader.get(keys.post('census', 'post'))), 'a later complete census is admitted and clears quarantine')
  censusReader.destroy()

  console.log('\n— replayed old self row makes the immediate next append refuse —')
  const selfId = await identity('self-author')
  const selfPub = selfId.me().pubkey
  const selfCommunity = await signed(selfId, 'community', { id: 'self', slug: 'self', title: 'self', description: '', creator: selfPub, author: selfPub, createdAt: 1, updatedAt: 1 })
  const oldPost = await signed(selfId, 'post', { id: 'self!post', cid: 'post', community: 'self', kind: 'text', title: 'post', body: 'old', url: '', author: selfPub, createdAt: 2, editedAt: 0, deleted: false })
  const newPost = await signed(selfId, 'post', { ...oldPost, body: 'new', editedAt: 3, _sig: undefined, _k: undefined, _dk: undefined, _ns: undefined, _alg: undefined })
  const selfFull = await state(selfId, 2, [[keys.community('self'), selfCommunity], [keys.post('self', 'post'), newPost]])
  const selfWorld = makeWorld()
  const selfGroup = selfWorld.put(selfPub, selfFull, 1)
  const selfSync = bridge({ world: selfWorld, id: selfId, storage: mem(), writeHead: true })
  await selfSync.ready()
  await selfSync._refresh()
  ok((await selfSync.get(keys.post('self', 'post'))).body === 'new', 'the writer starts from a fully audited current self view')
  selfGroup.rows.set(keys.post('self', 'post'), oldPost)
  selfGroup.version++
  const attempted = await signed(selfId, 'post', { id: 'self!next', cid: 'next', community: 'self', kind: 'text', title: 'next', body: '', url: '', author: selfPub, createdAt: 4, editedAt: 0, deleted: false })
  const callsBefore = selfWorld.appendCalls()
  const versionBefore = selfGroup.version
  const headSigBefore = selfGroup.rows.get(keys.head(selfPub))._sig
  await assert.rejects(() => selfSync.append({ type: 'post', data: attempted }), /integrity check failed/i)
  passed++
  console.log('  ✓ append preflight refuses after an old valid self row is replayed')
  ok(selfWorld.appendCalls() === callsBefore && selfGroup.version === versionBefore, 'refusal happens before any record or head append reaches the relay')
  ok(selfGroup.rows.get(keys.head(selfPub))._sig === headSigBefore && !selfGroup.rows.has(keys.post('self', 'next')), 'the replay is not cemented into a newly signed head')
  ok((await selfSync.get(keys.post('self', 'post'))).body === 'new', 'the last audited self row remains locally visible after rejection')
  ok((await selfSync.status()).withholding.includes(selfPub), 'self is quarantined until the relay restores the committed row')
  selfSync.destroy()

  console.log('\n— record success plus head failure is reported as unconfirmed —')
  const partialId = await identity('partial-writer')
  const partialPub = partialId.me().pubkey
  const partialCommunity = await signed(partialId, 'community', { id: 'partial', slug: 'partial', title: 'partial', description: '', creator: partialPub, author: partialPub, createdAt: 1, updatedAt: 1 })
  const partialBase = await state(partialId, 1, [[keys.community('partial'), partialCommunity]])
  const partialWorld = makeWorld()
  const partialGroup = partialWorld.put(partialPub, partialBase, 1)
  const partialSync = bridge({ world: partialWorld, id: partialId, storage: mem(), writeHead: true })
  await partialSync.ready()
  await partialSync._refresh()
  const partialPost = await signed(partialId, 'post', { id: 'partial!one', cid: 'one', community: 'partial', kind: 'text', title: 'one', body: '', url: '', author: partialPub, createdAt: 2, editedAt: 0, deleted: false })
  const partialPost2 = await signed(partialId, 'post', { id: 'partial!two', cid: 'two', community: 'partial', kind: 'text', title: 'two', body: '', url: '', author: partialPub, createdAt: 3, editedAt: 0, deleted: false })
  const callsBeforePartial = partialWorld.appendCalls()
  const headsBeforePartial = partialWorld.headAppendAttempts()
  const oldHeadSig = partialGroup.rows.get(keys.head(partialPub))._sig
  partialWorld.failNextHeadAppends(2)
  await assert.rejects(() => partialSync.append({ type: 'post', data: partialPost }), /publication is unconfirmed/i)
  passed++
  console.log('  ✓ a committed record with two failed head attempts rejects as unconfirmed')
  ok(partialWorld.appendCalls() - callsBeforePartial === 3 && partialWorld.headAppendAttempts() - headsBeforePartial === 2, 'head confirmation performs exactly one bounded retry')
  ok(partialGroup.rows.has(keys.post('partial', 'one')) && partialGroup.rows.get(keys.head(partialPub))._sig === oldHeadSig, 'the fixture proves record success while the confirming head stayed old')
  ok((await partialSync.status()).withholding.includes(partialPub) && !(await partialSync.get(keys.post('partial', 'one'))), 'the partial publication is quarantined and not presented as locally confirmed')
  const callsBeforeBlockedRetry = partialWorld.appendCalls()
  const headsBeforeBlockedRetry = partialWorld.headAppendAttempts()
  await assert.rejects(() => partialSync.append({ type: 'post', data: partialPost2 }), /integrity check failed/i)
  passed++
  console.log('  ✓ a later append is refused while the partial publication remains quarantined')
  ok(partialWorld.appendCalls() === callsBeforeBlockedRetry && partialWorld.headAppendAttempts() === headsBeforeBlockedRetry, 'no later record or head is appended over the unconfirmed partial state')
  partialSync.destroy()

  console.log('\n— commit-then-response-loss on the record is quarantined —')
  const ambiguousId = await identity('ambiguous-record-writer')
  const ambiguousPub = ambiguousId.me().pubkey
  const ambiguousCommunity = await signed(ambiguousId, 'community', { id: 'ambiguous', slug: 'ambiguous', title: 'ambiguous', description: '', creator: ambiguousPub, author: ambiguousPub, createdAt: 1, updatedAt: 1 })
  const ambiguousBase = await state(ambiguousId, 1, [[keys.community('ambiguous'), ambiguousCommunity]])
  const ambiguousWorld = makeWorld()
  const ambiguousGroup = ambiguousWorld.put(ambiguousPub, ambiguousBase, 1)
  const ambiguousSync = bridge({ world: ambiguousWorld, id: ambiguousId, storage: mem(), writeHead: true })
  await ambiguousSync.ready()
  await ambiguousSync._refresh()
  const ambiguousPost = await signed(ambiguousId, 'post', { id: 'ambiguous!one', cid: 'one', community: 'ambiguous', kind: 'text', title: 'one', body: '', url: '', author: ambiguousPub, createdAt: 2, editedAt: 0, deleted: false })
  const ambiguousPost2 = await signed(ambiguousId, 'post', { id: 'ambiguous!two', cid: 'two', community: 'ambiguous', kind: 'text', title: 'two', body: '', url: '', author: ambiguousPub, createdAt: 3, editedAt: 0, deleted: false })
  const ambiguousCallsBefore = ambiguousWorld.appendCalls()
  const ambiguousHeadsBefore = ambiguousWorld.headAppendAttempts()
  const ambiguousHeadSig = ambiguousGroup.rows.get(keys.head(ambiguousPub))._sig
  ambiguousWorld.commitNextRecordsThenThrow()
  await assert.rejects(() => ambiguousSync.append({ type: 'post', data: ambiguousPost }), /publication is unconfirmed/i)
  passed++
  console.log('  ✓ commit-then-response-loss throws an explicit unconfirmed-publication error')
  ok(ambiguousWorld.appendCalls() - ambiguousCallsBefore === 1 && ambiguousWorld.headAppendAttempts() === ambiguousHeadsBefore, 'an ambiguous record ACK never triggers a confirming head append')
  ok(ambiguousGroup.rows.has(keys.post('ambiguous', 'one')) && ambiguousGroup.rows.get(keys.head(ambiguousPub))._sig === ambiguousHeadSig, 'the relay fixture committed the record while retaining the old signed head')
  ok((await ambiguousSync.status()).withholding.includes(ambiguousPub) && !(await ambiguousSync.get(keys.post('ambiguous', 'one'))), 'the ambiguous committed row is quarantined and hidden from the confirmed local view')
  const ambiguousCallsBlocked = ambiguousWorld.appendCalls()
  await assert.rejects(() => ambiguousSync.append({ type: 'post', data: ambiguousPost2 }), /integrity check failed/i)
  passed++
  console.log('  ✓ a later write is refused until the ambiguous record gains a confirming signed head')
  ok(ambiguousWorld.appendCalls() === ambiguousCallsBlocked && ambiguousWorld.headAppendAttempts() === ambiguousHeadsBefore, 'later refusal performs no record or head append over the ambiguous state')
  ambiguousSync.destroy()

  console.log(`\n✅ all ${passed} gossip rollback-guard checks passed\n`)
}

main().catch((error) => { console.error('❌', (error && error.stack) || error); process.exit(1) })
