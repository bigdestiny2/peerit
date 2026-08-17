// Replacement product composition: a network authority is optional for local
// authoring, but durable identity and journal authority are not.

import assert from 'node:assert/strict'
import { getPeeritCommittedIntentIdV1 } from '../js/data.js'
import { genKeyPair, sign as edSign } from '../js/crypto.js'
import { createIdentityStore, memoryKv, IDENTITY_FORGET_TOMBSTONE_KEY } from '../js/identity-store.js'
import { createPeeritHostIdentityV1 } from '../js/substrate/host-identity.js'
import { createPeeritLocalIdentityV1 } from '../js/substrate/local-identity.js'
import {
  createMemoryJournalState,
  createMemoryPeeritJournal
} from '../js/substrate/peerit-journal.js'
import { createPeeritProductRuntimeV1 } from '../js/substrate/peerit-product-runtime.js'
import {
  preparePeeritCommentsForRenderV1,
  preparePeeritPostsForRenderV1
} from '../js/substrate/peerit-product-ui.js'
import { createPeeritSubstrateSync } from '../js/substrate/peerit-substrate-sync.js'

let passed = 0

function ok (condition, message) {
  assert.ok(condition, message)
  passed++
  console.log('  ✓ ' + message)
}

function storage () {
  const values = new Map()
  return {
    getItem: key => values.has(key) ? values.get(key) : null,
    setItem: (key, value) => values.set(key, String(value)),
    removeItem: key => values.delete(key)
  }
}

function countedKv () {
  const base = memoryKv()
  const calls = { reads: 0, writes: 0 }
  const output = {}
  for (const [name, operation] of Object.entries(base)) {
    output[name] = async (...args) => {
      if (name === 'get' || name === 'getOrTag') calls.reads++
      else calls.writes++
      return operation(...args)
    }
  }
  return { kv: output, base, calls }
}

function product ({ shared, kv, durableStorage, channelName }) {
  const identity = createPeeritLocalIdentityV1()
  const sync = createPeeritSubstrateSync({
    journal: createMemoryPeeritJournal({ shared }),
    relays: [],
    autoFlush: false,
    requireVerifiedRelayAdapters: true,
    channelName
  })
  return createPeeritProductRuntimeV1({
    identity,
    identityStore: createIdentityStore({ kv }),
    sync,
    storage: durableStorage,
    minBits: {
      community: 0,
      post: 0,
      comment: 0,
      vote: 0,
      profile: 0,
      modaction: 0,
      blob: 0
    }
  })
}

async function main () {
  console.log('\n— comment render preparation attaches tallies before sorting —')
  const preparedComments = await preparePeeritCommentsForRenderV1({
    async tallyMany () {
      return new Map([
        ['older', { score: 3, up: 3, down: 0, myVote: 0 }],
        ['newer', { score: 1, up: 1, down: 0, myVote: 0 }]
      ])
    },
    async moderationMany (rows) {
      return rows.map(row => ({
        ...row,
        moderation: { visibility: 'visible', consensusState: 'visible', view: 'community' }
      }))
    }
  }, [
    { cid: 'older', author: 'alice', createdAt: 1 },
    { cid: 'newer', author: 'bob', createdAt: 2 }
  ], 'best', 'alice')
  ok(preparedComments.length === 2 &&
    preparedComments.every(comment => comment.tally && Number.isFinite(comment.tally.up)),
  'two comments without pre-attached tallies sort without a render crash')
  ok(preparedComments.find(comment => comment.cid === 'older')._mine === true,
    'comment ownership is attached before rendering edit controls')

  console.log('\n— blind product moderation precedes interchangeable ranking —')
  const preparedPosts = await preparePeeritPostsForRenderV1({
    async tallyMany () {
      return new Map([
        ['buried', { score: 100, weighted: 100 }],
        ['visible', { score: 1, weighted: 1 }]
      ])
    },
    async moderationMany (rows, { view }) {
      return rows.map(row => ({
        ...row,
        moderation: {
          view,
          visibility: row.cid === 'buried' ? 'buried' : 'visible',
          consensusState: row.cid === 'buried' ? 'buried' : 'visible'
        }
      }))
    }
  }, [
    { cid: 'buried', createdAt: 2 },
    { cid: 'visible', createdAt: 1 }
  ], 'top', 'community')
  ok(preparedPosts.map(row => row.cid).join(',') === 'visible',
    'community policy removes buried candidates before the selected top ranker runs')

  const shared = createMemoryJournalState()
  const backing = countedKv()
  const durableStorage = storage()

  console.log('\n— fresh product boot is a true lurker —')
  const first = product({
    shared,
    kv: backing.kv,
    durableStorage,
    channelName: 'peerit-product-runtime-1'
  })
  await first.ready()
  const boot = await first.status()
  ok(boot.lurker && boot.identity.pubkey == null, 'fresh boot owns no signing identity')
  ok(backing.calls.reads === 0 && backing.calls.writes === 0,
    'fresh boot does not inspect, create, or mutate the identity database')
  ok(shared.writeTransactions === 0, 'fresh boot performs no journal write')
  ok(boot.publication.authoringReady === true, 'healthy local authoring is available with zero relays')
  ok(boot.inbox.active === false && boot.inbox.state === 'blocked-public-inbox-bootstrap',
    'fresh runtime exposes public-INBOX discovery as fail-closed until authenticated bootstrap')

  first.setInboxDiscoveryStatus({
    state: 'public-inbox-discovery-active',
    active: true,
    acceptedRecords: 3,
    rejectedEntries: 1,
    releaseBlockers: []
  })
  const discovery = await first.status()
  ok(discovery.inbox.active && discovery.inbox.acceptedRecords === 3 &&
    discovery.inbox.rejectedEntries === 1,
  'runtime exposes accepted and rejected authenticated public-INBOX discovery counts')

  first.setNetworkStatus({
    state: 'blocked-authenticated-browser-runtime',
    active: false,
    releaseBlockers: ['TEST_NO_NETWORK_AUTHORITY']
  })
  const blockedNetwork = await first.status()
  ok(blockedNetwork.publication.authoringReady &&
    !/read[- ]only/i.test(blockedNetwork.publication.copy),
  'a blocked network authority does not turn the local product read-only')

  first.setQualifiedRelays([{
    id: 'raw-untrusted-relay',
    compatible: true,
    deliver: async () => ({ ok: true, evidenceRef: 'forged' })
  }])
  ok((await first.sync.status()).publication.relay.usableTargets === 0,
    'an unbranded raw relay object cannot cross the product relay boundary')

  console.log('\n— first explicit action persists once, signs once, and queues locally —')
  const community = await first.data.createCommunity({ slug: 'localfirst', title: 'Local First' })
  const communityIntentId = getPeeritCommittedIntentIdV1(community)
  ok(/^[0-9a-f]{64}$/.test(communityIntentId) &&
    (await first.sync.journal.getIntent(communityIntentId))?.intentId === communityIntentId,
  'the exact returned action object carries an in-memory receipt for its durable local intent')
  ok(getPeeritCommittedIntentIdV1({ ...community }) == null &&
    !JSON.stringify(community).includes(communityIntentId),
  'the exact-intent receipt is neither forgeable by copying nor serialized with product data')
  const originalWriter = first.identity.me().pubkey
  ok(/^[0-9a-f]{64}$/.test(originalWriter), 'first action activates one Ed25519 writer')
  const storedIdentity = await backing.base.get('identity:v1')
  ok(storedIdentity && storedIdentity.pubkey === originalWriter,
    'writer identity is durably stored before the first signed event returns')
  ok(!JSON.stringify(storedIdentity).includes(first.identity.currentSeedEntry().seed),
    'durable identity record contains no cleartext signing seed')

  const post = await first.data.submitPost({
    community: 'localfirst',
    kind: 'text',
    title: 'Works without a relay',
    body: 'The local view is the first commit boundary.'
  })
  const comment = await first.data.addComment({
    community: 'localfirst',
    postCid: post.cid,
    body: 'Visible before delivery.'
  })
  await first.data.vote(post.cid, 'localfirst', 'post', 1)
  const local = await first.status()
  ok(local.sync.publication.relay.state === 'queued-no-relay' &&
    local.sync.publication.relay.pendingIntents === 4,
  'post, comment, vote, and community remain durably queued with zero relays')
  ok((await first.data.getPost('localfirst', post.cid)).title === 'Works without a relay' &&
    (await first.data.getComment('localfirst', post.cid, comment.cid)).body === 'Visible before delivery.' &&
    (await first.data.tallyFor(post.cid)).score === 1,
  'all authored records are materialized locally before networking')
  first.destroy()

  console.log('\n— reload stays write-silent and first later action adopts the same key —')
  const second = product({
    shared,
    kv: backing.kv,
    durableStorage,
    channelName: 'peerit-product-runtime-2'
  })
  const callsBeforeReload = { ...backing.calls }
  await second.ready()
  ok((await second.status()).lurker, 'reload remains a presentation lurker until an explicit action')
  ok(backing.calls.reads === callsBeforeReload.reads &&
    backing.calls.writes === callsBeforeReload.writes,
  'reload still does not inspect the identity database')
  ok((await second.data.getPost('localfirst', post.cid)).cid === post.cid,
    'the verified local view survives a full product-runtime restart')

  await second.data.setProfile({ name: 'same author', bio: 'adopted on demand' })
  ok(second.identity.me().pubkey === originalWriter,
    'the first later mutation atomically adopts the existing durable writer')
  ok((await second.data.getProfile(originalWriter)).name === 'same author',
    'the adopted identity signs an admitted local event')
  ok((await second.status()).sync.publication.relay.pendingIntents === 5,
    'the adopted event joins the exact existing local queue')
  second.destroy()

  console.log('\n— host identity first write performs zero identity-store I/O —')
  const appKey = await genKeyPair()
  const siteKey = await genKeyPair()
  const hostBacking = countedKv()
  const hostStorage = storage()
  const hostRuntime = createPeeritProductRuntimeV1({
    identity: createPeeritHostIdentityV1({
      async getPublicKey () { return { publicKey: appKey.pubHex, driveKey: siteKey.pubHex, algorithm: 'ed25519' } },
      async sign (payload, namespace) {
        return {
          signature: await edSign(appKey.seedHex, `pear.app.${siteKey.pubHex}:${namespace}:${payload}`),
          publicKey: appKey.pubHex,
          algorithm: 'ed25519'
        }
      }
    }),
    identityStore: createIdentityStore({ kv: hostBacking.kv }),
    sync: createPeeritSubstrateSync({
      journal: createMemoryPeeritJournal({ shared: createMemoryJournalState() }),
      relays: [],
      autoFlush: false,
      requireVerifiedRelayAdapters: true,
      channelName: 'peerit-product-runtime-host'
    }),
    storage: hostStorage,
    minBits: {
      community: 0,
      post: 0,
      comment: 0,
      vote: 0,
      profile: 0,
      modaction: 0,
      blob: 0
    }
  })
  await hostRuntime.ready()
  await hostRuntime.data.createCommunity({ slug: 'hostmade', title: 'Host Made' })
  ok(hostRuntime.identity.me().pubkey === appKey.pubHex,
    'the first write activates the host per-app identity')
  ok(hostBacking.calls.reads === 0 && hostBacking.calls.writes === 0,
    'the first host-signed write performs zero identity-store I/O')
  ok((await hostBacking.base.get('identity:v1')) == null,
    'no browser-local device identity is persisted for a host writer')
  const hostCommunity = await hostRuntime.data.getCommunity('hostmade')
  ok(hostCommunity && hostCommunity._k === appKey.pubHex && hostCommunity._dk === siteKey.pubHex,
    'the host-signed record carries the per-app subkey and the site drive key')
  hostRuntime.destroy()

  console.log('\n— forget tombstone still blocks a host writer —')
  const tombstonedStorage = storage()
  tombstonedStorage.setItem(IDENTITY_FORGET_TOMBSTONE_KEY, JSON.stringify({ pubkey: appKey.pubHex, at: 1 }))
  const tombstonedRuntime = createPeeritProductRuntimeV1({
    identity: hostRuntime.identity,
    identityStore: createIdentityStore({ kv: countedKv().kv }),
    sync: createPeeritSubstrateSync({
      journal: createMemoryPeeritJournal({ shared: createMemoryJournalState() }),
      relays: [],
      autoFlush: false,
      requireVerifiedRelayAdapters: true,
      channelName: 'peerit-product-runtime-host-tombstone'
    }),
    storage: tombstonedStorage,
    minBits: {
      community: 0,
      post: 0,
      comment: 0,
      vote: 0,
      profile: 0,
      modaction: 0,
      blob: 0
    }
  })
  await tombstonedRuntime.ready()
  await assert.rejects(
    tombstonedRuntime.data.createCommunity({ slug: 'blocked', title: 'Blocked' }),
    error => error.code === 'PEERIT_IDENTITY_FORGET_INCOMPLETE')
  ok(true, 'an incomplete identity forget blocks host authoring before any signing')
  tombstonedRuntime.destroy()

  console.log(`\npeerit-product-runtime: ${passed} checks passed`)
}

main().catch(error => {
  console.error(error)
  process.exitCode = 1
})
