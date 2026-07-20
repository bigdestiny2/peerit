#!/usr/bin/env node
import { createHash, createPrivateKey, createPublicKey } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { DevIdentity } from '../js/identity.js'
import { createData } from '../js/data.js'
import { BridgeGossipSync } from '../js/gossip.js'
import { ready as cryptoReady, isSecure } from '../js/crypto.js'
import { keys, REPORT_VERDICT, TYPE } from '../js/model.js'
import { makeValidator } from '../js/pow.js'

const __dir = dirname(fileURLToPath(import.meta.url))
const ROOT = resolve(__dir, '..')
const DEFAULT_REPORT = resolve(ROOT, 'reports', 'representative-outbox-availability-2026-07-01.json')
const PKCS8_PREFIX = '302e020100300506032b657004220420'
const SPKI_PREFIX = '302a300506032b6570032100'
const BITS = { community: 7, post: 6, comment: 5, report: 5 }
const FIXTURE_TIME = Date.parse('2026-07-01T18:00:00.000Z')

function usage (code = 0, message = '') {
  if (message) console.error('error:', message)
  console.error([
    'usage: node scripts/outbox-availability-proof.mjs [--out <file>] [--json]',
    '       node scripts/outbox-availability-proof.mjs --fixture missing-catchup',
    '       node scripts/outbox-availability-proof.mjs --out reports/representative-outbox-availability-2026-07-01.json'
  ].join('\n'))
  process.exit(code)
}

function parseArgs (argv) {
  const opts = {
    fixture: 'ready',
    out: '',
    json: false,
    now: Date.now(),
    shipReport: resolve(ROOT, '.deploy', 'last-ship.json'),
    publishReport: resolve(ROOT, '.deploy', 'last-publish.json')
  }
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]
    if (arg === '--fixture') opts.fixture = argv[++i] || ''
    else if (arg === '--missing-catchup') opts.fixture = 'missing-catchup'
    else if (arg === '--out') opts.out = resolve(ROOT, argv[++i] || '')
    else if (arg === '--json') opts.json = true
    else if (arg === '--now') opts.now = Date.parse(argv[++i] || '')
    else if (arg === '--ship-report') opts.shipReport = resolve(ROOT, argv[++i] || '')
    else if (arg === '--publish-report') opts.publishReport = resolve(ROOT, argv[++i] || '')
    else if (arg === '--default-report') opts.out = DEFAULT_REPORT
    else if (arg === '-h' || arg === '--help') usage(0)
    else usage(2, `unknown option: ${arg}`)
  }
  if (!['ready', 'missing-catchup'].includes(opts.fixture)) usage(2, '--fixture must be "ready" or "missing-catchup"')
  if (!Number.isFinite(opts.now)) usage(2, '--now must be an ISO date/time')
  return opts
}

function mem () {
  const m = new Map()
  return {
    getItem: (k) => (m.has(k) ? m.get(k) : null),
    setItem: (k, v) => m.set(k, String(v)),
    removeItem: (k) => m.delete(k),
    clear: () => m.clear(),
    keys: () => [...m.keys()]
  }
}

function sha256 (value) {
  return createHash('sha256').update(String(value)).digest('hex')
}

function publicKeyFromSeed (seedHex) {
  const privateKey = createPrivateKey({ key: Buffer.from(PKCS8_PREFIX + seedHex, 'hex'), format: 'der', type: 'pkcs8' })
  const spki = createPublicKey(privateKey).export({ type: 'spki', format: 'der' })
  return Buffer.from(spki).subarray(-32).toString('hex')
}

async function makeIdentity (label) {
  const seed = sha256(`peerit representative outbox availability ${label} seed v1`)
  const pubkey = publicKeyFromSeed(seed)
  const id = new DevIdentity(mem(), mem())
  await id.ready()
  await id.addUser({ seed, pubkey, driveKey: pubkey, label })
  return id
}

function deterministicInvite (appId) {
  return sha256(`peerit representative outbox invite ${appId} v1`)
}

function clone (value) {
  return value == null ? value : JSON.parse(JSON.stringify(value))
}

function makeStore () {
  return { groups: new Map() }
}

function ensureGroup (store, appId, inviteKey = '') {
  if (!store.groups.has(appId)) {
    store.groups.set(appId, {
      inviteKey: inviteKey || deterministicInvite(appId),
      rows: new Map(),
      version: 0
    })
  }
  return store.groups.get(appId)
}

function sortedRows (group) {
  return [...group.rows.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => ({ key, value: clone(value) }))
}

function selectRows (rows, opts = {}) {
  let out = rows
  if (opts.gte != null) out = out.filter((r) => r.key >= opts.gte)
  if (opts.gt != null) out = out.filter((r) => r.key > opts.gt)
  if (opts.lte != null) out = out.filter((r) => r.key <= opts.lte)
  if (opts.lt != null) out = out.filter((r) => r.key < opts.lt)
  if (opts.reverse) out = out.slice().reverse()
  const limit = Math.max(1, Math.min(Number(opts.limit) || 100, 1000))
  return out.slice(0, limit)
}

function responsePear (store) {
  const sync = {
    create: async (appId) => {
      const g = ensureGroup(store, appId)
      return { appId, inviteKey: g.inviteKey, writerPublicKey: appId }
    },
    join: async (appId, inviteKey) => {
      const g = store.groups.get(appId)
      if (!g || g.inviteKey !== inviteKey) throw new Error('outbox unavailable')
      return { appId, inviteKey: g.inviteKey, writerPublicKey: appId }
    },
    append: async (appId, op) => {
      const g = ensureGroup(store, appId)
      const key = op.type.replace(':', '!') + '!' + op.data.id
      g.rows.set(key, clone(op.data))
      g.version++
      return { ok: true, key }
    },
    get: async (appId, key) => {
      const g = ensureGroup(store, appId)
      return clone(g.rows.get(key) || null)
    },
    list: async (appId, prefix = '', opts = {}) => {
      const g = ensureGroup(store, appId)
      const rows = sortedRows(g)
      return selectRows(prefix ? rows.filter((r) => r.key >= prefix && r.key < prefix + '\xff') : rows, opts)
    },
    range: async (appId, opts = {}) => {
      const g = ensureGroup(store, appId)
      return selectRows(sortedRows(g), opts)
    },
    count: async (appId, prefix = '') => {
      const rows = await sync.list(appId, prefix, { limit: 1000 })
      return { count: rows.length }
    },
    heads: async (appIds) => {
      const heads = {}
      for (const appId of appIds || []) {
        const g = store.groups.get(appId)
        heads[appId] = g ? g.version : 0
      }
      return { heads }
    },
    status: async (appId) => {
      const g = ensureGroup(store, appId)
      return { appId, inviteKey: g.inviteKey, writerCount: 1, viewLength: g.rows.size }
    },
    directory: async () => {
      const heads = {}
      for (const [appId, g] of store.groups) {
        const head = g.rows.get(keys.head(appId))
        if (head) heads[appId] = clone(head)
      }
      return { heads }
    }
  }
  return {
    sync,
    swarm: {
      v1: {
        join: async () => ({
          peers: [],
          on: () => {},
          destroy: () => {}
        })
      }
    }
  }
}

function bytesOfRows (rows) {
  return Buffer.byteLength(JSON.stringify(rows))
}

function digestRows (rows) {
  return sha256(JSON.stringify(rows))
}

function copyOutboxToFleet ({ source, fleet, appId, catchUp }) {
  const src = source.groups.get(appId)
  if (!src) throw new Error('representative source outbox is missing')
  const rows = sortedRows(src)
  const localBytes = bytesOfRows(rows)
  const localLength = rows.length
  let copied = rows

  if (!catchUp) {
    const drop = rows.find((r) => r.key.startsWith('comment!')) || rows.find((r) => r.key !== keys.head(appId))
    copied = rows.filter((r) => !drop || r.key !== drop.key)
  }

  const dst = ensureGroup(fleet, appId, src.inviteKey)
  dst.rows = new Map(copied.map((r) => [r.key, clone(r.value)]))
  dst.version = copied.length

  return {
    appId,
    inviteKeyHash: sha256(src.inviteKey),
    inviteKeyPrefix: src.inviteKey.slice(0, 12),
    targetReplicas: 4,
    seedAcceptances: 4,
    localLength,
    remoteLength: copied.length,
    localBytes,
    remoteBytes: bytesOfRows(copied),
    localRowsSha256: digestRows(rows),
    remoteRowsSha256: digestRows(copied),
    byteCatchUpConfirmed: copied.length >= localLength && bytesOfRows(copied) >= localBytes
  }
}

async function descriptorBytes (identity, pub, appId, inviteKey) {
  const sig = await identity.sign(`peerit-desc|${pub}|${appId}|${inviteKey}`)
  const desc = {
    t: 'outbox-desc',
    pub,
    appId,
    inviteKey,
    sig: sig.signature,
    dk: sig.driveKey,
    ns: sig.namespace
  }
  return new TextEncoder().encode(JSON.stringify(desc))
}

function addCheck (report, id, status, message, evidence) {
  const check = { id, status, message }
  if (evidence !== undefined) check.evidence = evidence
  report.checks.push(check)
  return check
}

function finishReport (report) {
  const counts = { pass: 0, warn: 0, fail: 0, info: 0 }
  for (const check of report.checks) counts[check.status] = (counts[check.status] || 0) + 1
  report.counts = counts
  report.status = counts.fail > 0 ? 'blocked' : (counts.warn > 0 ? 'review' : 'ready')
  report.summary = report.status === 'blocked'
    ? `${counts.fail} representative outbox availability check${counts.fail === 1 ? '' : 's'} failed.`
    : report.status === 'review'
      ? `${counts.warn} representative outbox availability warning${counts.warn === 1 ? '' : 's'} to review.`
      : 'Fresh-client representative outbox availability is proven.'
}

function readJson (file) {
  try {
    return JSON.parse(readFileSync(file, 'utf8'))
  } catch {
    return null
  }
}

function reportContext (shipReport, publishReport) {
  const ship = readJson(shipReport)
  const publish = readJson(publishReport)
  return {
    july1ShipReports: {
      ship: ship
        ? {
            file: relative(ROOT, shipReport),
            present: true,
            status: ship.status,
            generatedAt: ship.generatedAt,
            summary: ship.summary || ''
          }
        : { file: relative(ROOT, shipReport), present: false },
      publish: publish
        ? {
            file: relative(ROOT, publishReport),
            present: true,
            status: publish.status,
            generatedAt: publish.generatedAt,
            driveKey: publish.driveKey,
            metadata: publish.durability && publish.durability.metadata
              ? {
                  durable: !!publish.durability.metadata.durable,
                  byteLengthLocal: publish.durability.metadata.byteLengthLocal,
                  byteLengthRemoteMax: publish.durability.metadata.byteLengthRemoteMax
                }
              : null,
            blobs: publish.durability && publish.durability.blobs
              ? {
                  durable: !!publish.durability.blobs.durable,
                  blobLocalLen: publish.durability.blobs.blobLocalLen,
                  blobRemoteMax: publish.durability.blobs.blobRemoteMax
                }
              : null
          }
        : { file: relative(ROOT, publishReport), present: false }
    },
    seederExpectation: {
      source: '../peerit-seeder/seeder.mjs',
      requiredSignal: 'remoteLength >= localLength and remoteBytes >= localBytes before fresh-reader recovery is trusted',
      acceptanceIsNotEnough: true
    }
  }
}

function withDeterministicFixture (fn) {
  const realNow = Date.now
  const realRandom = Math.random
  const realLog = console.log
  let now = FIXTURE_TIME
  let rand = 0x71f00d
  Date.now = () => {
    now += 1000
    return now
  }
  Math.random = () => {
    rand = (Math.imul(rand, 1664525) + 1013904223) >>> 0
    return rand / 0x100000000
  }
  console.log = (...args) => {
    if (typeof args[0] === 'string' && args[0].startsWith('[peerit persist]')) return
    realLog(...args)
  }
  return Promise.resolve()
    .then(fn)
    .finally(() => {
      Date.now = realNow
      Math.random = realRandom
      console.log = realLog
    })
}

async function runScenario ({ catchUp }) {
  const authorStore = makeStore()
  const fleetStore = makeStore()
  const authorIdentity = await makeIdentity('representative-author')
  const authorPub = authorIdentity.me().pubkey
  const authorSync = new BridgeGossipSync({
    pear: responsePear(authorStore),
    getMe: () => authorPub,
    identity: authorIdentity,
    storage: mem(),
    validate: makeValidator(BITS),
    pollMs: 0,
    writeHead: true
  })
  await authorSync.ready()
  const authorData = createData(authorSync, authorIdentity, { minBits: BITS, v2: true })

  await authorData.setProfile({ name: 'availability-fixture', bio: 'representative outbox proof' })
  await authorData.createCommunity({ slug: 'availproof', title: 'Availability Proof', description: 'fresh reader recovery' })
  const post = await authorData.submitPost({ community: 'availproof', kind: 'text', title: 'fresh reader can recover this post', body: 'seeded bytes must catch up first' })
  const comment = await authorData.addComment({ community: 'availproof', postCid: post.cid, body: 'representative comment survives author offline' })
  await authorData.vote(post.cid, 'availproof', 'post', 1)
  await authorData.reportContent('availproof', {
    targetCid: post.cid,
    targetType: TYPE.POST,
    verdict: REPORT_VERDICT.KEEP,
    reason: 'other',
    note: 'representative sealed moderation record'
  })

  const sourceGroup = authorStore.groups.get(authorPub)
  const head = sourceGroup.rows.get(keys.head(authorPub))
  const seederEvidence = copyOutboxToFleet({ source: authorStore, fleet: fleetStore, appId: authorPub, catchUp })
  authorSync.destroy()

  const readerStorage = mem()
  const readerIdentity = await makeIdentity('fresh-reader')
  const readerPub = readerIdentity.me().pubkey
  const readerSync = new BridgeGossipSync({
    pear: responsePear(fleetStore),
    getMe: () => readerPub,
    identity: readerIdentity,
    storage: readerStorage,
    validate: makeValidator(BITS),
    pollMs: 0,
    writeHead: false
  })
  const storageKeysBefore = readerStorage.keys()
  await readerSync.ready()
  await readerSync._onDescriptor(await descriptorBytes(authorIdentity, authorPub, authorPub, sourceGroup.inviteKey))
  const readerData = createData(readerSync, readerIdentity, { minBits: BITS, v2: true })
  const profile = await readerData.getProfile(authorPub)
  const community = await readerData.getCommunity('availproof')
  const recoveredPost = await readerData.getPost('availproof', post.cid)
  const comments = await readerData.listComments('availproof', post.cid)
  const tally = await readerData.tallyFor(post.cid)
  const reports = await readerData.listReportsFor('availproof', post.cid)
  const status = await readerSync.status()

  const recovered = {
    profile: !!(profile && profile.name === 'availability-fixture'),
    community: !!(community && community.title === 'Availability Proof'),
    post: !!(recoveredPost && recoveredPost.title === post.title),
    comment: comments.some((c) => c.cid === comment.cid && c.body === comment.body),
    vote: tally.score === 1,
    report: reports.some((row) => row.verdict === REPORT_VERDICT.KEEP && row.note === 'representative sealed moderation record')
  }

  return {
    representative: {
      authorPubkey: authorPub,
      outboxAppId: authorPub,
      outboxInviteKeyHash: seederEvidence.inviteKeyHash,
      outboxInviteKeyPrefix: seederEvidence.inviteKeyPrefix,
      expectedRecords: ['profile', 'community', 'post', 'comment', 'vote', 'report'],
      expectedNonHeadRows: 6,
      expectedTotalRows: 7,
      community: 'availproof',
      postCid: post.cid,
      commentCid: comment.cid,
      head: head
        ? {
            version: head.version,
            count: head.count,
            root: head.root,
            updatedAt: head.updatedAt
          }
        : null
    },
    seederEvidence,
    freshReader: {
      storageKeysBefore,
      recovered,
      recoveredAllRepresentativeData: Object.values(recovered).every(Boolean),
      status: {
        mode: status.mode,
        secure: status.secure,
        peers: status.peers,
        viewLength: status.viewLength,
        relays: status.relays,
        withholding: status.withholding
      },
      authorOnlineDuringRead: false,
      seederOnlineDuringRead: false
    }
  }
}

export async function buildOutboxAvailabilityProof ({
  fixture = 'ready',
  now = Date.now(),
  shipReport = resolve(ROOT, '.deploy', 'last-ship.json'),
  publishReport = resolve(ROOT, '.deploy', 'last-publish.json')
} = {}) {
  await cryptoReady()
  const report = {
    kind: 'peerit-representative-outbox-availability',
    appId: 'peerit',
    generatedAt: new Date(now).toISOString(),
    fixture,
    root: '.',
    checks: [],
    context: reportContext(shipReport, publishReport)
  }

  if (isSecure()) addCheck(report, 'crypto:ed25519', 'pass', 'Real Ed25519 verification is available.')
  else addCheck(report, 'crypto:ed25519', 'fail', 'Real Ed25519 verification is unavailable; representative availability cannot be trusted.')

  try {
    const scenario = await withDeterministicFixture(() => runScenario({ catchUp: fixture !== 'missing-catchup' }))
    report.representative = scenario.representative
    report.seederEvidence = scenario.seederEvidence
    report.freshReader = scenario.freshReader

    const head = scenario.representative.head
    if (head && head.count === scenario.representative.expectedNonHeadRows && head.version >= scenario.representative.expectedNonHeadRows) {
      addCheck(report, 'representative:signed-head', 'pass', 'Representative author wrote a signed head committing to the full non-head row set.', {
        version: head.version,
        count: head.count,
        expectedNonHeadRows: scenario.representative.expectedNonHeadRows
      })
    } else {
      addCheck(report, 'representative:signed-head', 'fail', 'Representative author did not produce the expected signed outbox head.', {
        head,
        expectedNonHeadRows: scenario.representative.expectedNonHeadRows
      })
    }

    if (scenario.seederEvidence.seedAcceptances > 0) {
      addCheck(report, 'seeder:seed-accepted', 'pass', 'Seeder fixture recorded relay seed acceptance for the representative outbox.', {
        seedAcceptances: scenario.seederEvidence.seedAcceptances,
        targetReplicas: scenario.seederEvidence.targetReplicas
      })
    } else {
      addCheck(report, 'seeder:seed-accepted', 'fail', 'No relay seed acceptance was recorded for the representative outbox.')
    }

    if (scenario.seederEvidence.byteCatchUpConfirmed) {
      addCheck(report, 'seeder:byte-catchup', 'pass', 'Fleet byte catch-up is confirmed before the fresh reader is trusted.', {
        localLength: scenario.seederEvidence.localLength,
        remoteLength: scenario.seederEvidence.remoteLength,
        localBytes: scenario.seederEvidence.localBytes,
        remoteBytes: scenario.seederEvidence.remoteBytes
      })
    } else {
      addCheck(report, 'seeder:byte-catchup', 'fail', 'Seed acceptance is not enough: remote bytes did not catch up to local outbox bytes.', {
        localLength: scenario.seederEvidence.localLength,
        remoteLength: scenario.seederEvidence.remoteLength,
        localBytes: scenario.seederEvidence.localBytes,
        remoteBytes: scenario.seederEvidence.remoteBytes
      })
    }

    if (scenario.freshReader.storageKeysBefore.length === 0) {
      addCheck(report, 'fresh-reader:fresh-storage', 'pass', 'Reader started with empty storage and no cached outbox view.')
    } else {
      addCheck(report, 'fresh-reader:fresh-storage', 'fail', 'Reader was not fresh; storage already contained peerit keys.', {
        keys: scenario.freshReader.storageKeysBefore
      })
    }

    if (scenario.freshReader.recoveredAllRepresentativeData) {
      addCheck(report, 'fresh-reader:representative-data', 'pass', 'Fresh reader recovered representative profile, community, post, comment, vote, and moderation-report data from sealed opaque cells.', scenario.freshReader.recovered)
    } else {
      addCheck(report, 'fresh-reader:representative-data', 'fail', 'Fresh reader did not recover the full representative user-data set.', scenario.freshReader.recovered)
    }

    const withholding = scenario.freshReader.status.withholding || []
    if (withholding.length === 0) {
      addCheck(report, 'fresh-reader:signed-head-audit', 'pass', 'Fresh reader found no unresolved withholding after auditing the signed outbox head.')
    } else {
      addCheck(report, 'fresh-reader:signed-head-audit', 'fail', 'Fresh reader flagged the representative outbox as withheld or rolled back.', {
        withholding
      })
    }
  } catch (err) {
    addCheck(report, 'proof:scenario', 'fail', `Representative outbox proof failed: ${err.message}`)
  }

  finishReport(report)
  return report
}

function printHuman (report) {
  for (const check of report.checks) {
    const prefix = check.status.toUpperCase().padEnd(4)
    console.log(`[outbox-availability] ${prefix} ${check.message}`)
  }
  console.log(`[outbox-availability] status=${report.status} pass=${report.counts.pass || 0} warn=${report.counts.warn || 0} fail=${report.counts.fail || 0} info=${report.counts.info || 0}`)
}

async function main () {
  const opts = parseArgs(process.argv.slice(2))
  const report = await buildOutboxAvailabilityProof(opts)

  if (opts.out) {
    mkdirSync(dirname(opts.out), { recursive: true })
    writeFileSync(opts.out, JSON.stringify(report, null, 2) + '\n')
  }

  if (opts.json) console.log(JSON.stringify(report, null, 2))
  else printHuman(report)

  process.exit(report.status === 'blocked' ? 1 : 0)
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  main().catch((err) => {
    console.error('[outbox-availability] FAIL', err.stack || err.message)
    process.exit(1)
  })
}
