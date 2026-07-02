// blob-integration.mjs — BlindShard Phase 2 wired into the write path (data.js).
// Proves the box→append→fetch→unbox loop end-to-end through the dev sync backend:
//   • long text bodies are stored as opaque blob!<blobId> ciphertext + a signed
//     manifest; the post record itself holds NO plaintext body;
//   • getPost/listPostsIn transparently hydrate the plaintext back (exactly);
//   • short bodies stay inline (unchanged, backward-compatible);
//   • edit/delete re-box or drop the manifest correctly;
//   • a tampered/withheld blob degrades gracefully (gates reject, never forge);
//   • the blob is a first-class SIGNED record: it survives the real mergeOutboxes
//     admit/verify path, and a forged blob is dropped.
// Run: node test/blob-integration.mjs

import assert from 'node:assert'
import { DevSync, memoryStorage } from '../js/sync.js'
import { DevIdentity } from '../js/identity.js'
import { createData } from '../js/data.js'
import { mergeOutboxes } from '../js/gossip.js'
import { makeValidator } from '../js/pow.js'
import { keys, TYPE } from '../js/model.js'
import { ready as cryptoReady, isSecure } from '../js/crypto.js'
import { shouldBox, BOX_MIN_BYTES, verifyBlobRecord, unboxToBody } from '../js/blob-store.js'

let passed = 0
const ok = (c, m) => { assert.ok(c, m); passed++; console.log('  ✓ ' + m) }
async function throwsAsync (fn, m) { try { await fn() } catch { ok(true, m); return } assert.fail('expected throw: ' + m) }
function mem () { const m = new Map(); return { getItem: k => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: k => m.delete(k), clear: () => m.clear() } }

const BITS = { community: 4, post: 4, comment: 4 } // tiny PoW so the test is fast
const LONG = 'BlindShard secret body. '.repeat(200)   // ~4.8 KB → boxed
const SHORT = 'just a short body'                       // inline

async function newUser (name, storage) {
  const sync = new DevSync(storage, 'blob-test')
  await sync.ready()
  const id = new DevIdentity(mem(), mem())
  await id.ready()
  await id.createUser(name)
  const data = createData(sync, id, { minBits: BITS })
  return { sync, id, data, me: id.me().pubkey }
}

async function main () {
  await cryptoReady()
  ok(isSecure(), 'secure crypto backend available (AES-GCM + Ed25519)')
  ok(shouldBox(LONG) && LONG.length >= BOX_MIN_BYTES, 'test body exceeds the box threshold')
  ok(!shouldBox(SHORT), 'short body is below the box threshold')

  const storage = memoryStorage()
  const { sync, data, me } = await newUser('alice', storage)
  await data.createCommunity({ slug: 'blindshard', title: 'BlindShard' })

  // ---- long body is boxed --------------------------------------------------
  console.log('\n— boxing on write —')
  const post = await data.submitPost({ community: 'blindshard', kind: 'text', title: 'long', body: LONG })
  ok(post.blob && /^[0-9a-f]{64}$/.test(post.blob.blobId), 'boxed post carries a signed blob manifest (blobId)')
  ok(post.blob.contentKey && post.blob.iv, 'manifest carries contentKey + iv')

  const stored = await sync.get(keys.post('blindshard', post.cid))
  ok(stored.body === '', 'stored post record has NO plaintext body')
  ok(JSON.stringify(stored).indexOf('secret body') === -1, 'plaintext never appears in the stored post record')

  const blob = await sync.get(keys.blob(post.blob.blobId))
  ok(blob && typeof blob.ct === 'string', 'blob!<blobId> record exists with opaque ciphertext')
  ok(blob.ct.indexOf('secret body') === -1 && !/BlindShard secret/.test(blob.ct), 'ciphertext blob is opaque (no plaintext)')
  ok(blob._sig && blob._k === me && blob.blobId === post.blob.blobId, 'blob is a signed record owned by the author')

  // ---- transparent hydration on read --------------------------------------
  console.log('\n— hydration on read —')
  const got = await data.getPost('blindshard', post.cid)
  ok(got.body === LONG, 'getPost hydrates the exact original body')
  const listed = (await data.listPostsIn('blindshard')).find(p => p.cid === post.cid)
  ok(listed && listed.body === LONG, 'listPostsIn hydrates the body too')

  // ---- short body stays inline (backward-compatible) -----------------------
  console.log('\n— inline path unchanged —')
  const small = await data.submitPost({ community: 'blindshard', kind: 'text', title: 'short', body: SHORT })
  ok(!small.blob, 'short post is NOT boxed (no manifest)')
  const smallStored = await sync.get(keys.post('blindshard', small.cid))
  ok(smallStored.body === SHORT, 'short post stores its plaintext inline as before')
  ok((await data.getPost('blindshard', small.cid)).body === SHORT, 'short post reads back unchanged')

  // ---- dedup: identical bodies converge to one blobId ----------------------
  const post2 = await data.submitPost({ community: 'blindshard', kind: 'text', title: 'dup', body: LONG })
  ok(post2.blob.blobId === post.blob.blobId, 'identical bodies converge to the same blobId (dedup)')

  // ---- edit / delete manifest lifecycle ------------------------------------
  console.log('\n— edit / delete —')
  const shrunk = await data.editPost('blindshard', post.cid, SHORT)
  ok(!shrunk.blob && shrunk.body === SHORT, 'edit long→short clears the manifest and inlines')
  ok((await data.getPost('blindshard', post.cid)).body === SHORT, 'edited-short post reads back inline')

  const regrown = await data.editPost('blindshard', post.cid, LONG + ' v2')
  ok(regrown.blob && regrown.body === '', 'edit short→long re-boxes')
  ok((await data.getPost('blindshard', post.cid)).body === LONG + ' v2', 'edited-long post hydrates the new body')

  await data.deletePost('blindshard', post.cid)
  const del = await sync.get(keys.post('blindshard', post.cid))
  ok(del.deleted && del.body === '' && !del.blob, 'deleted post drops the manifest')

  // ---- tampered / withheld blob degrades gracefully (never forges) ---------
  console.log('\n— tamper / withholding —')
  const tamperData = await newUser('mallory', memoryStorage())
  await tamperData.data.createCommunity({ slug: 'zone', title: 'Z' })
  const tp = await tamperData.data.submitPost({ community: 'zone', kind: 'text', title: 't', body: LONG })
  const bkey = keys.blob(tp.blob.blobId)
  const tampered = await tamperData.sync.get(bkey)
  await tamperData.sync.append({ type: 'blob', data: { ...tampered, ct: tampered.ct.slice(0, -8) + 'AAAAAAAA' } }) // corrupt ciphertext
  const afterTamper = await tamperData.data.getPost('zone', tp.cid)
  ok(afterTamper.body === '' && afterTamper._blobMissing, 'a corrupted blob fails the content-address gate → empty + _blobMissing (no forgery)')

  // ---- the blob survives the REAL admit/verify merge path ------------------
  console.log('\n— mergeOutboxes admit —')
  const postVal = await sync.get(keys.post('blindshard', post2.cid))
  const blobVal = await sync.get(keys.blob(post2.blob.blobId))
  const view = { [keys.post('blindshard', post2.cid)]: postVal, [keys.blob(post2.blob.blobId)]: blobVal }
  const merged = await mergeOutboxes([{ pub: me, view }], {}, makeValidator(BITS))
  ok(merged[keys.blob(post2.blob.blobId)], 'a validly-signed blob is admitted by mergeOutboxes')
  ok(merged[keys.post('blindshard', post2.cid)], 'the referencing post is admitted alongside it')

  const forgedView = { [keys.blob(post2.blob.blobId)]: { ...blobVal, _sig: (blobVal._sig || 'x').replace(/./, s => s === 'a' ? 'b' : 'a') } }
  const mergedForged = await mergeOutboxes([{ pub: me, view: forgedView }], {}, makeValidator(BITS))
  ok(!mergedForged[keys.blob(post2.blob.blobId)], 'a blob with a broken signature is dropped by mergeOutboxes')

  // ---- FIX 1: foreign-signed blob poisoning cannot suppress a boxed body ----
  // A SECOND signer publishes a validly-signed + PoW'd blob at the victim's
  // content-addressed key blob!<X> with garbage ct + deleted:true. Without the
  // self-certification gate it would WIN the LWW collision (tombstone breaks the
  // timestampless tie) and blank the victim's post for every reader.
  console.log('\n— foreign blob poisoning (FIX 1) —')
  const blobKey = keys.blob(post2.blob.blobId)
  const genuine = await sync.get(blobKey)
  ok(await verifyBlobRecord(genuine), 'genuine blob self-certifies (SHA-256(ct)==blobId)')

  const mallory = await newUser('mallory', memoryStorage())
  const poison = { id: post2.blob.blobId, blobId: post2.blob.blobId, ct: 'AAAAAAAA', author: mallory.me, deleted: true }
  await mallory.data._powSign(TYPE.BLOB, poison) // validly signed + PoW'd by a DIFFERENT key
  ok(!(await verifyBlobRecord(poison)), 'poison blob fails self-certification (SHA-256(garbage) != blobId)')

  // Merge the victim's outbox (genuine blob + post) with Mallory's poison outbox.
  const victimView = { [keys.post('blindshard', post2.cid)]: postVal, [blobKey]: genuine }
  const merged2 = await mergeOutboxes([{ pub: me, view: victimView }, { pub: mallory.me, view: { [blobKey]: poison } }], {}, makeValidator(BITS))
  ok(merged2[blobKey] && merged2[blobKey].ct === genuine.ct, 'merge keeps the GENUINE blob — poison is rejected, not the LWW winner')
  ok(!merged2[blobKey].deleted, 'the tombstone poison did not win the collision')
  ok(await unboxToBody(merged2[blobKey].ct, post2.blob) === LONG, 'victim body still decrypts from the merged winner')

  console.log(`\n${passed} checks passed`)
}

main().catch(e => { console.error(e); process.exit(1) })
