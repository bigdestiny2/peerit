# peerit — availability, redundancy & persistence

Straight answer to "what keeps it always available and stops data being lost
between sessions or across users." There are **two separate planes**, with two
separate durability stories. Conflating them is what makes a drive look "empty."

## The two planes

| | **App CODE** (`hyper://<driveKey>/` in `manifest.json`) | **User DATA** (communities/posts/votes) |
|---|---|---|
| What | the static program (HTML/JS/CSS) | per-user `window.pear.sync` **outbox** logs — *not* in that drive |
| Stored by | whoever hosts the drive's blocks | each user's local PearBrowser corestore + whoever replicates their outbox |
| Always-on via | seeding the drive to HiveRelay | seeding each outbox to HiveRelay — **not automatic** |

A Hyperdrive/Hypercore is just an address until someone hosts its blocks. The
key resolving but the content being unreachable = the "empty drive" symptom.

## What's actually guaranteed today

- **Same user, across their own sessions** — ✅ not lost. Their outbox is an
  append-only core in their own PearBrowser storage; it survives restarts.
- **Across users** — ⚠️ best-effort. Others see a post via gossip *while a peer
  who holds it is online*. PearBrowser does **not** pin data to HiveRelay
  (confirmed in `pear-bridge.js`: `createSyncGroup` only joins the swarm +
  writes the local corestore — no `relay.seed`). So with no seeder, if everyone
  holding a post is offline, it's unavailable until one returns.
- **App code availability** — depends on a live host. HiveRelay can make it 24/7,
  but only if it was seeded *and anchored*.

## Why a published drive shows the splash but never boots (the real root cause)

Symptom: PearBrowser renders `index.html` (the "connecting to peers…" splash) but
`<script src="js/app.js">` never loads, so `boot()` never runs and it hangs — while
connected to 7 relays. This is **not** "empty drive" and **not** sparse replication.

A Hyperdrive is **two** hypercores:

| | `drive.core` (metadata) | `drive.blobs.core` (blobs) |
|---|---|---|
| Holds | the Hyperbee **file index** (names → pointers) | the actual **file bytes** (index.html, js/app.js…) |
| Size | tiny — a few hundred bytes | the whole site (~130 KB of JS here) |
| Replicates | in **milliseconds** to any relay | takes real transfer time |

The bug was in the **verification**, not the relays. HiveRelay relays fully
download *both* cores by design and only self-anchor once
`blobs.core.has(0, length)` is true (verified in
`hiverelay/.../relay-node/app-lifecycle.js`). But the SDK's
`getDurableStatus`/`waitForDurable` — and so the old `publish.mjs` — only watched
**`drive.core`** (metadata). The metadata core replicates instantly, so
`durable:true` fired while the **blobs core had transferred zero blocks**. The
publish *looked* successful and walked away; the relays were left mid-repair,
serving the file index + whatever early blocks they had (enough for the 1 KB
`index.html`) but not yet the 52 KB `js/app.js`. **`durable:true` proved the file
*list* reached relays, not the file *bytes*.**

## Making it durable

### 1. Code drive — re-anchor and verify the BLOBS core
`publish.mjs` now waits on **both** cores (`waitForBlobsDurable`): it opens
`drive.getBlobs()` and polls `blobs.core.peers[*].remoteContiguousLength` until a
relay has every blob block, then logs `✓ blobs fully mirrored`. `durability:'archive'`
keeps AutoHeal maintaining ≥7 replicas across ≥4 regions / ≥5 operators.

```bash
# from the peerit repo root
npm run ship:live                                    # preflight + strict publish
STRICT_ANCHOR=1 KEEP=1 REPLICAS=6 npm run publish    # manual long-running anchor
```

Confirm the **`blob durable status … durable:true`** line (not just `metadata
durable`). Verified on `ec6e2d6d…` 2026-06-23: `✓ blobs fully mirrored to a relay
(80/80 blocks)`, and a fresh network-only client (all local hosts killed) then
fetched every file — `index.html`, `js/app.js`, `js/gossip.js`, `styles.css`, … —
from the fleet alone. (Outward-facing public deploy — run it deliberately.)

### 1b. Code drive — full mirror (always-on insurance)
[`../peerit-mirror`](../peerit-mirror) is the code-drive analog of the data seeder:
it opens the drive by key, fully downloads **both** cores (`drive.download('/')` +
persistent `core.download({start:0,end:-1})` on metadata and blobs), and serves it
on `drive.discoveryKey`. Run it on an always-on box so a complete copy is always one
hop away even if the fleet is mid-repair:

```bash
cd ../peerit-mirror
node mirror.mjs                 # mirrors the drive in ../peerit/manifest.json
node mirror.mjs <driveKeyHex>   # or specific drives
```

It logs `complete=YES ✓` once it holds every block.

### 2. User data — run the seeder
PearBrowser won't pin data, so run **[`../peerit-seeder`](../peerit-seeder)** on an
always-on box. It replicates each outbox (a single-writer hypercore, so its
`inviteKey` *is* the data core) over the bridge's `sha256(inviteKey)` topic and
pins it with archive durability:

```bash
cd ../peerit-seeder
node seeder.mjs <outboxInviteKey> [<more> …]   # keys from peerit → Settings → "Group key"
```

This is the piece that turns "best-effort gossip" into "always available." Pin
your own outbox (so your posts survive your device being off) and the outboxes of
active communities/users you want kept alive.

The seeder bridges **two replication topics**, which is the whole trick:

- it joins the bridge's `sha256(inviteKey)` topic — the one PearBrowser uses — so
  it can pull each outbox *from* browsers and serve it back *to* browsers. This is
  the always-on peer that makes your posts visible when your own device is off.
- `relay.seed()` advertises the core's *native* keyed discoveryKey
  (`hypercoreCrypto.discoveryKey`), so the **relay fleet** downloads the blocks and
  becomes an independent server for them. This is cold-storage redundancy: if the
  seeder box itself dies, a replacement re-pulls every outbox from the fleet and
  resumes — the data is never on a single machine.

**Verified end-to-end (2026-06-23)** against the live fleet, not just asserted:

1. produced a peerit outbox, ran the seeder → **5 relays** pinned it;
2. killed the **author**, read the post back from a fresh network-only client → ✅
   (the seeder served it — Tier A);
3. confirmed a relay's `remoteLength` reached the outbox length (the fleet truly
   *downloaded*, not just *accepted* — acceptance alone is a lie);
4. killed the **seeder too**, read the post back from a brand-new client with **only
   the relay fleet online** → ✅ (Tier B).

> **acceptance ≠ download.** A relay accepting a seed request only means "I'll try."
> The seeder now polls each core's replication peers until one's `remoteLength`
> catches up before it logs `fleet copy CONFIRMED ✓` — the same check
> `publish.mjs waitForDurable` uses for the code drive. Without it, shutting the
> seeder down ~20s after seeding *lost* the fleet copy (observed, then fixed).

## The relay fleet (what's pinning this)

`00-core/hr-fleet/fleet/relays.json` is the operated fleet: **6 boxes across 4
regions** — NA×2 (utah, utah-us), APAC×2 (sing-1, sing-2), EU×1 (bern, 484 GB),
ME×1 (dubai) — plus community StartOS/Umbrel relays that auto-update and aren't
listed there. Archive tier (`durability: 1`) AutoHeal targets **≥7 replicas across
≥4 regions and ≥5 operators**, recruiting fresh replicas as old ones drop.

To **beef up**: the operated fleet covers 4 regions but is one operator and sits one
box under the ≥7 floor on its own — it currently leans on community nodes to clear
archive tier. Adding a 7th/8th operated box (and a SA / second-EU region) makes
archive durability self-sufficient. Provisioning is scripted —
`fleet/harden-box.sh` + `fleet/install-updater.sh` + `fleet/tailscale-enroll.sh`,
then append the box to `relays.json`; `fleet/fleet-status.sh` reports health.

## The honest summary

peerit faithfully implements the P2P model, but **out of the box it is not a
durability guarantee** — it's local-storage + best-effort gossip + a code drive
that must be anchored. Production durability needs (1) the code drive anchored on
HiveRelay with archive durability, and (2) a running seeder for the data. **Both are
now in place and verified**: the code drive re-anchored on 6 relays / 4 regions
(`js/app.js` fetchable from a fresh network client), and the data seeder proven to
keep an outbox available with the author *and* the seeder offline. You get
multi-region redundancy and AutoHeal repair; without them, availability is only as
good as who happens to be online.
