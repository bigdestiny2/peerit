# Building a P2P app as a PearBrowser site — the patterns

peerit is a peer-to-peer Reddit with **no servers and no build step**: a folder of
static HTML/JS served over a Hyperdrive, run inside PearBrowser, with all data
flowing peer-to-peer. This document is the reusable recipe behind it — the same
engine has since been reused, almost verbatim, to port **p2pbuilders** (a P2P
Hacker News) to the browser. If you want to build a social/collaborative P2P app,
start here.

---

## 1. The shape: a P2P *site*, not an app binary

PearBrowser serves a site straight from a Hyperdrive (`hyper://<key>/index.html`)
and injects a `window.pear` bridge into the page. So your "app" is just static
files; the **read-only drive ships the code**, and the **read-write data lives in a
separate plane** (below). No Electron, no `pear stage/release`, no bundler.

Two planes, and keeping them straight is the whole mental model:

| Plane | What | Mutability |
|-------|------|-----------|
| **Code** | the Hyperdrive that serves `index.html` + `js/*` | read-only (content-addressed; the key pins exactly which code runs) |
| **Data** | per-user logs reached via `window.pear.sync` | read-write (each user appends to their own) |

"Read-only drive" trips people up — it only means the *program* is immutable.
Posting/voting writes to the data plane, which PearBrowser keeps for the user.

---

## 2. The bridge surface

`window.pear` (see `pearbrowser-desktop/backend/pear-bridge.js`) gives a page:

- **`sync`** — a per-`appId` Autobase+Hyperbee log: `create / join / append / get /
  list(prefix) / range / count / status`. This is your database.
- **`identity`** — a stable per-app **Ed25519** key: `getPublicKey()`, `sign(payload,
  namespace)`. This is authorship.
- **`swarm.v1`** — live peer channels (`join(topic)` → `peer`/`message` events).
- `login`, `contacts`, `navigate`, `share`.

Always write a **dev fallback** so the same code runs in a plain browser (and Node
for tests): detect `window.pear`; if absent, back `sync` with localStorage +
BroadcastChannel and `identity` with a local keypair. peerit's
[`js/sync.js`](js/sync.js) / [`js/identity.js`](js/identity.js) do exactly this —
the app and tests never know which backend is live.

---

## 3. Riding the bridge's generic reducer (the key scheme)

A page **cannot** pass a custom apply function over the HTTP bridge, so every op
hits the bridge's built-in reducer: an op `{ type, data }` is stored at Hyperbee
key **`type!data.id`** (last-write-wins). You don't get secondary indexes or
partial merges — so **encode scope + sort + identity into `data.id`** and use
colon-free `type` names:

```
community!<slug>                       list('community!')            → all communities
post!<community>!<cid>                 list('post!<community>!')     → a community's posts
comment!<community>!<postCid>!<cid>    list('comment!<c>!<post>!')   → a thread (tree via parentCid)
vote!<targetCid>!<voterPubkey>         list('vote!<cid>!')           → one vote per identity (LWW)
profile!<pubkey>                       get('profile!<pub>')
```

Edits/deletes re-write the **whole** record (soft-delete with `deleted:true`) —
correct for an append-only log. Ranking, threading, and moderation are computed
**client-side** over what you scanned; don't expect the store to do it for you.

---

## 4. Multi-writer without server trust: per-user outbox + gossip

The bridge's sync groups are **single-writer** (the creator writes; `join` is
read-only — there is no `addWriter`). So "one global log everyone writes" is
impossible. The pattern that works (and is how `peartube` does it):

1. **Each user writes only their own outbox** — a group they created, so they're
   the writer.
2. **Peers discover each other** (a well-known `swarm` topic) and **replicate**
   each other's outboxes read-only.
3. **Every client merges all known outboxes** into one materialized view.

This lives entirely in [`js/gossip.js`](js/gossip.js) behind the same `sync`
interface, so [`js/data.js`](js/data.js) and the UI are oblivious to it.

---

## 5. Authenticity = signatures, never the transport

The hard-won lesson (peerit was rebuilt around it after a multi-agent adversarial
audit found the first design forgeable): **do not trust which outbox relayed a
record.** A malicious peer can rebroadcast a victim-labelled outbox full of
fabricated records. Authority must come from an unforgeable signature.

`mergeOutboxes()` admits a record only if **all three** hold:

1. **Key binding** — its storage key equals the key recomputed from its own fields
   (`expectedKey`), so you can't park a record under someone else's key.
2. **Owner binding** — its signer (`_k`) equals its claimed author (`ownerOf`), so
   you can't sign as someone else.
3. **Signature** — a real Ed25519 signature over the canonical record verifies
   ([`js/crypto.js`](js/crypto.js), via SubtleCrypto / `node:crypto`).

Supporting rules that matter:
- **Canonical = stable-stringify of all fields minus the signature** — no
  "forgot to sign field X" class of bug; any tamper changes the bytes.
- **Verify at ingest, not just at read** — so a forgery can't even *evict* a real
  record from a replica via a higher-timestamp collision.
- **Deterministic, order-independent conflict resolution** — LWW by timestamp with
  a signature tiebreak; tombstones win ties (no resurrection); unique names
  (communities/boards) are **first-creator-sticky** so they can't be hijacked.
- **Fail closed** — if signing fails, the op throws before append; an unsigned
  record is untrusted in secure mode.

What this honestly does NOT solve (document it): **Sybil** (identities are free —
raw vote counts are advisory) and **global unique naming** (first-claim only; no
authority exists in pure gossip — Zooko's triangle).

---

## 6. Optional app gates (how p2pbuilders extended the engine)

The engine took exactly one generic extension to support a stricter app: a
`validate(type, record)` hook in `admit()`. p2pbuilders passes a validator that
requires **proof-of-work** (SHA-256 hashcash bound to the op's identity) on
posts/comments/boards, re-checked by every peer on ingest — so unworked spam never
enters the network. Reputation-weighted voting and a follow/block/blocklist social
graph were added purely in the app's `data.js`/schema, touching no engine code.
That's the test of a good engine: a second, quite different app reused it by
writing only a schema, a ranking function, and a UI.

---

## 7. File layout (copy this)

```
app/
├── index.html            # shell + boot splash; loads js/app.js as a module
├── styles.css
├── js/
│   ├── crypto.js         # Ed25519 (SubtleCrypto / node:crypto)        ← reusable
│   ├── verify.js         # signature verification                       ← reusable
│   ├── sync.js           # backend factory: bridge vs dev fallback      ← reusable
│   ├── gossip.js         # per-user outbox + merge (admit/conflict)     ← reusable
│   ├── identity.js       # bridge identity / dev multi-user             ← reusable
│   ├── canon.js          # ownerOf / expectedKey / canonical            ← per-app schema
│   ├── model.js          # key scheme, types, tree builders             ← per-app schema
│   ├── data.js           # domain API (CRUD + queries)                  ← per-app
│   ├── ranking.js        # sort/score                                   ← per-app
│   ├── prefs.js          # local per-device state                       ← per-app
│   └── app.js            # router + views + event delegation            ← per-app
├── manifest.json         # PearBrowser catalog entry (driveKey filled on publish)
├── dev-server.mjs        # locked-down loopback static server for local preview
├── publish.mjs           # publish/seed to HiveRelay + register in catalog
└── test/                 # headless Node tests of the pure logic + gossip security
```

The five files marked *reusable* are app-agnostic — copy them, then write a schema
(`canon.js`/`model.js`), a `data.js`, a `ranking.js`, and a UI.

---

## 8. Verify like this

- **Headless first** (`node test/*.mjs`): the data layer, ranking, conflict
  resolution, and the *security properties* (forged/tampered/relayed-as-victim
  records are rejected) all run in Node against the dev backend with real crypto.
- **Then the browser** (`node dev-server.mjs`): the dev fallback shares one world
  across tabs, so multiple tabs = multiple peers — exercise the real UI + Ed25519.
- **Then real PearBrowser** (`node publish.mjs --local`): hosts the drive at a
  `hyper://` key; the bridge path (`window.pear.*`) is the one seam you can't test
  without it. The in-app status chip shows `gossip-bridge` when it's live.

---

## 9. Publishing

`publish.mjs` publishes the folder as a Hyperdrive, writes the resulting
`driveKey` into `manifest.json`, seeds it on the **HiveRelay** fleet (so it stays
online when you're offline), and registers it in the PearBrowser catalog. The
`--local` flag does everything except seed/catalog — for testing in PearBrowser
without going public.
