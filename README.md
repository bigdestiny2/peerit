# peerit — a peer-to-peer Reddit

No servers. No data center. Communities, posts, threaded comments and votes live
in a shared **Holepunch** log (Autobase + Hyperbee) and replicate directly between
peers. peerit ships as a **P2P site** that runs inside **PearBrowser** and is kept
online 24/7 by **HiveRelay**.

```
hyper://<driveKey>/        ← what users open in PearBrowser
```

---

## How it works

PearBrowser serves a site (a plain folder of `index.html` + assets) over Hyperdrive
and injects a `window.pear` bridge. peerit uses three parts of it:

| Bridge API            | Used for |
|-----------------------|----------|
| `window.pear.sync`    | The shared, multi-writer Autobase+Hyperbee log — every community, post, comment, vote and mod action is an op on it. `create / join / append / get / list / range / count / status`. |
| `window.pear.identity`| A stable per-app **ed25519** key (`getPublicKey`) + signatures (`sign`) → authorship. |
| `window.pear.swarm`   | (reserved) live peer channels for the multi-writer upgrade — see roadmap. |

There is **no backend process and no build step**. Everything is vanilla ES
modules in [`js/`](js/).

### Data model — riding the bridge's generic reducer

The bridge applies an op `{ type, data }` by writing `data` into Hyperbee at key
`type!data.id` (last-write-wins). peerit encodes scope + identity into `data.id`
so prefix/range scans give cheap feeds and threads:

| Record    | Key                                          | Queried by |
|-----------|----------------------------------------------|------------|
| community | `community!<slug>`                           | `list('community!')` |
| post      | `post!<community>!<cid>`                      | `list('post!<community>!')` |
| comment   | `comment!<community>!<postCid>!<cid>`         | `list('comment!<community>!<postCid>!')` → tree by `parentCid` |
| vote      | `vote!<targetCid>!<voterPubkey>`              | `list('vote!<cid>!')` → one vote per identity (LWW) |
| profile   | `profile!<pubkey>`                           | `get('profile!<pub>')` |
| modaction | `modaction!<community>!<actionId>`           | `list('modaction!<community>!')` → overlay |

Edits/deletes re-write the full record (soft-delete via `deleted:true`) — correct
for an append-only P2P log. Moderation is a **client-honored overlay**: mod actions
signed by a community's moderator chain (founder → added mods) are applied when
rendering (remove / lock / sticky / ban). See [`js/model.js`](js/model.js).

---

## Run it

### In a normal browser (dev fallback)

No `window.pear`? peerit transparently swaps in a **localStorage + BroadcastChannel**
backend that reimplements the bridge reducer exactly. Multiple tabs share one world,
so you can simulate several peers.

```bash
cd 02-apps/peerit
node dev-server.mjs              # serves only the public app files on 127.0.0.1
# open http://localhost:8777
```

- Click **Load demo content** (empty feed / Settings) to seed communities + posts.
- Open Settings → **Dev: switch user** (or the user menu) to act as different people.
- Open a second tab to watch live cross-tab updates.

### In PearBrowser (real P2P)

Open `hyper://<driveKey>/` after publishing (below). The same code runs unchanged;
`window.pear` is detected and the bridge backend is used.

---

## Features

- **Communities** (subreddits): create, browse, join/leave, about page, founder-moderated.
- **Posts**: text (markdown), link, and image posts; per-community and aggregate feeds.
- **Ranking**: Hot, New, Top (with time windows), Rising, Controversial — real Reddit formulas.
- **Threaded comments**: unlimited nesting, collapse, inline reply, sort (Best/Top/New/Controversial/Old). "Best" uses the Wilson lower bound.
- **Voting**: up/down on posts and comments, one vote per identity (last-write-wins), optimistic UI.
- **Identity & profiles**: ed25519 per-app key, display name + bio, **karma** (post + comment).
- **Moderation**: founders + added mods can remove/approve, lock/unlock, pin/unpin, ban/unban, and add moderators — enforced as a signed overlay.
- **Search** across communities, posts and comments.
- **Saved / hidden posts, subscriptions, sort prefs** — per-device, per-identity (local).
- **Safe markdown** (escaped; only `http(s)/hyper/pear` links).
- **Live updates** via the bridge poll / dev BroadcastChannel.

---

## File structure

```
peerit/
├── index.html          # shell + boot splash
├── styles.css          # dark theme
├── icon.svg
├── js/
│   ├── util.js         # ids, time, slugs, routing, escaping
│   ├── markdown.js     # safe markdown renderer
│   ├── ranking.js      # hot/top/controversial/wilson/rising + sorts
│   ├── model.js        # key scheme, comment tree, mod overlay
│   ├── sync.js         # BridgeSync (window.pear.sync) | DevSync (localStorage)
│   ├── identity.js     # BridgeIdentity (window.pear.identity) | DevIdentity (multi-user)
│   ├── prefs.js        # per-device local prefs
│   ├── data.js         # domain API (CRUD + queries + vote tallies + karma + mod)
│   └── app.js          # router + views + event delegation + live refresh
├── manifest.json       # PearBrowser catalog manifest (driveKey filled by publish.mjs)
├── dev-server.mjs      # locked-down loopback static preview
├── publish.mjs         # publish to HiveRelay + register in catalog (outward-facing)
└── test/               # headless verification of core logic + gossip security
```

## Test

```bash
node test/smoke.mjs      # 30 checks: data layer, ranking, threading, votes, moderation, markdown
```

## Publish (outward-facing — run deliberately)

`publish.mjs` publishes the site folder as a Hyperdrive, writes the resulting
`driveKey` into `manifest.json`, then seeds it on the live HiveRelay fleet and
registers it in the PearBrowser catalog so it appears in the app's store.

```bash
node publish.mjs           # publish + seed, then exit
KEEP=1 node publish.mjs     # stay online so relays fully anchor the drive
```

It uses the local HiveRelay client at
`00-core/hiverelay/packages/client/`. This puts peerit on the public network —
it is never invoked by the app or any build step.

---

## Architecture: multi-writer gossip + security model

See [`docs/pattern.md`](docs/pattern.md) for the reusable pattern behind this
app: per-user signed outboxes, peer gossip, deterministic merge, and a
client-honored moderation overlay.

The PearBrowser bridge's sync groups are single-writer (the creator writes; peers
`join` read-only). So peerit uses the **per-user outbox + gossip aggregation**
pattern (the proven `peartube` shape): each user writes only their own outbox; peers
discover and replicate each other's outboxes and merge them into one view. The
backend lives behind [`js/sync.js`](js/sync.js)/[`js/gossip.js`](js/gossip.js); the
UI and [`js/data.js`](js/data.js) are unchanged by the swap.

**Authenticity = signatures, not transport.** Every record is Ed25519-signed
([`js/crypto.js`](js/crypto.js), over SubtleCrypto / `node:crypto`). On merge
([`mergeOutboxes`](js/gossip.js)) a record is admitted only if (1) its storage key
equals the key recomputed from its own fields, (2) its signer equals its claimed
author, and (3) its signature verifies. **Which outbox relayed a record carries no
authority** — so a malicious peer can rebroadcast a victim-labelled outbox full of
fabricated posts/comments/votes/mod-actions and every one is rejected. Forgeries are
dropped at ingest too, so they can't evict real records. Community names are
**sticky**: once a replica has seen r/<slug> for a creator, a different creator can
never replace it. This model was hardened against a multi-agent adversarial audit
(forgery, tamper, key-collision, eviction, convergence). See [`test/gossip.mjs`](test/gossip.mjs).

### Honest limitations
- **Sybil / vote weight.** Identities are free to mint, so each can cast one valid
  vote — raw scores are *advisory*, not Sybil-resistant. Real resistance needs an
  identity-cost or web-of-trust layer (out of scope).
- **Name squatting at genesis.** You can't *hijack* an established community, but the
  *first* claimant of a brand-new slug wins it (createdAt is self-asserted). Global
  unique naming is unsolvable in pure gossip without a registry/PoW (Zooko's triangle).
  peerit's guarantee is **content authenticity**, not global name ownership.
- **Dev fallback.** A browser with no SubtleCrypto Ed25519 (and no `node:crypto`) runs
  a *cooperative, insecure* mode (`status().secure === false`, mode `gossip-dev-insecure`)
  for local simulation only. The deployment target (PearBrowser / modern browsers /
  Node 20+) always has Ed25519, so signatures are enforced in production.
