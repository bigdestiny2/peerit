# Bridge verification

How to prove peerit is **actually running P2P** — not the single-device
localStorage fallback that looks identical in the UI. There are two layers:

1. **Automated** (`npm test`) — proves the multi-writer merge + the
   PearBrowser `/api/*` transport in CI, no hardware needed.
2. **On-device** (this checklist) — proves real swarm discovery over the live
   DHT and cross-device convergence, which only two real PearBrowser instances
   can demonstrate.

> The golden rule: **a peerit page rendering fine ≠ it is P2P.** Always read the
> status chip. Two browser *tabs* on one machine share `localStorage` and will
> "sync" even in dev mode — that proves nothing. Use two **separate** machines /
> profiles.

---

## 1. Automated proof (CI / pre-push)

```sh
npm test
npm run test:browser:mobile   # optional Playwright UI gate for the mobile /api token path
npm run proof:bridge:local     # local Hyperdrive + two PearBrowser instances
npm run proof:hiverelay-outboxlog -- --out reports/hiverelay-outboxlog-convergence-2026-07-01.json
```

`npm test` runs the dependency-installed headless suites. The browser-mobile
gate is separate because Playwright is an operator/dev dependency, not an app
runtime dependency.

| Gate | Proves |
| --- | --- |
| `test/smoke.mjs` | domain model, ranking, threading, markdown safety |
| `test/gossip.mjs` | signed-record merge, forgery rejection, dev-mode multi-peer convergence, bridge restart + recovery import |
| `test/bridge.mjs` | the `/api/*` contract; partial-bridge **fail-closed** (never silently downgrades to dev) |
| `test/bridge-convergence.mjs` | **two distinct writers** discovering each other via signed swarm descriptors over the `/api` transport, merging both outboxes, in `gossip-bridge` mode |
| `test/runtime.mjs` | PearBrowser desktop/mobile runtime dispatch ignores web relay config and never forces dev/read-only on host paths |
| `npm run test:browser:mobile` | Browser-shaped PearBrowser mobile boot: injects `pear-api-token` plus a default read-only web relay meta, requires `gossip-bridge`/`p2p`, performs UI writes, verifies `/api` append rows and signed head, and fails if dev localStorage or read-only UI appears |
| `npm run proof:bridge:local` | Operator-run proof from a local Hyperdrive publish: captures `gossip-bridge`, distinct A/B writer keys, and bidirectional convergence into `.deploy/local-bridge-proof-<session>.json` |
| `npm run proof:hiverelay-outboxlog` | Starts a local HiveRelay `RelayAPI` with the real `OutboxLogApp`, runs the generated Peerit `web/js` client modules through HTTP+SSE, and proves community/post/vote/comment/edit/reload convergence |

`bridge-convergence.mjs` is the closest automated stand-in for the on-device
test: it wires a shared in-memory bridge world (shared `/api/sync` outboxes + a
live `/api/swarm` hub with a push-capable EventSource — the same `js/pear-api.js`
code path mobile uses) and runs two real Ed25519 identities through
`createSync`. It proves the *logic and transport*. It does **not** prove the
real Hyperswarm DHT, NAT traversal, or HiveRelay durability — that's layer 2.

`proof:hiverelay-outboxlog` is the Phase 2 HiveRelay handover gate. It does not
alter Peerit app code; it imports the generated `web/js` modules, starts the
sibling HiveRelay checkout's real RelayAPI + OutboxLog service, and writes a JSON
evidence report when `--out` is supplied.

---

## 2. On-device two-device proof

### What you need
- Two PearBrowser instances that can reach each other: two desktops, a desktop
  + a phone (PearBrowser mobile), or two desktop installs on different machines.
  Two tabs on one machine do **not** count.
- The app served at a `hyper://` URL, one of:
  - **Live drive:** `hyper://ec6e2d6d9d22b9d6b40e11a9ca3042be3197e4bdca9e9a7f079be6ee830761b4/`
  - **Local proof host:** `npm run proof:bridge:local` (runs the fast bridge
    preflight, starts `publish.mjs --local`, and prints Device A/B proof URLs).
  - **Raw local host:** `node publish.mjs --local` (serves the drive and keeps it
    online; copy the printed `hyper://<key>/` URL).

### Reading the status chip

Bottom-left of every page is `#netstatus`. It renders:

```
<mode> · <peers>p · <recs> recs · <writerkey>…   [· ⚠ insecure]
```

| You see | Meaning | chip class |
| --- | --- | --- |
| **`gossip-bridge`** | ✅ real P2P over the PearBrowser bridge | `netstatus bridge` |
| `gossip-dev` | ❌ localStorage only, single device (secure crypto) | `netstatus ok` |
| `gossip-dev-insecure` | ❌ localStorage only **and** no SubtleCrypto (plain http) | `netstatus warn` |

The account-menu badge mirrors this: **`p2p`** (bridge) vs **`dev`** (fallback).
Click the chip to force-refresh it. `peers` is the number of outboxes in the
merged view (yourself + every peer discovered) — it should climb above `1` once
the other device is found. `writerkey` is the first 6 hex of *your* outbox
identity; the two devices must show **different** writer keys.

### Repeatable local proof workflow

Run:

```sh
npm run proof:bridge:local
```

The command:

1. Runs `test/bridge-convergence.mjs` and `test/runtime.mjs`.
2. Starts `publish.mjs --local` with a local publish report under `.deploy/`.
3. Prints two hidden proof routes:
   - `#/bridge-proof/<session>?role=a`
   - `#/bridge-proof/<session>?role=b`
4. Writes a QR/link guide at `.deploy/local-bridge-proof-<session>.html`.
5. Validates the two copied proof snapshots and writes:
   - `.deploy/local-bridge-proof-<session>.json`
   - `.deploy/local-bridge-proof-<session>.md`

Minimal operator loop:

1. **Device A** — open the Device A URL and click **Write Device A proof
   record**.
2. **Device B** — open the Device B URL, click **Check A and write Device B
   proof record**, then **Copy proof JSON** and paste it into the terminal.
3. **Device A** — click **Refresh** until Device B is visible, then **Copy proof
   JSON** and paste it into the terminal.

The validator fails unless both snapshots report `gossip-bridge`, both report
at least two peers, the two writer keys are distinct, Device B sees Device A's
proof post, and Device A sees Device B's proof post. Use `--keep-publish` if you
want the local Hyperdrive host to stay alive after the report is written.

For audit handoffs where the devices are not currently available, write an
explicit non-proof artifact instead of leaving a prose note:

```sh
npm run proof:bridge:local -- --plan-only --skip-headless --no-publish --url hyper://<driveKey>/
```

That report is marked `operator-required`, contains no snapshots, and should not
be treated as bridge evidence. When you want to generate the local publish and
keep it open for the two devices, run:

```sh
npm run proof:bridge:local -- --plan-only --keep-publish
```

### Steps

1. **Device A** — open the URL. ✅ Chip shows **`gossip-bridge`** (if it shows
   `gossip-dev`, the bridge isn't injected — you're not testing P2P; stop and
   fix the host/runtime first). Note device A's writer key.
2. **Device A** — create a community (e.g. `r/bridgetest`) and a post. Watch
   `recs` increment.
3. **Device B** — open the **same** URL. ✅ Chip shows **`gossip-bridge`** with a
   **different** writer key from A.
4. **Device B** — within a few seconds (swarm discovery + first merge), `peers`
   rises to ≥2 and **device A's community and post appear**. ✅ This is the core
   cross-device proof.
5. **Device B** — create a post in the same community.
6. **Device A** — within ~4s (the background re-merge poll), **device B's post
   appears**. ✅ Reverse-direction convergence.
7. **Votes/comments** — upvote and comment from both devices; confirm scores and
   comments aggregate on both. ✅

### Optional: availability / durability
- **Author-offline:** with the data on B, close device A. B keeps everything
  (its replicated copy is local). A **fresh** device opening the URL, however,
  only sees A's posts if *some* peer still serving A's outbox is online — that's
  what the peerit-seeder / HiveRelay fleet is for. Cross-user availability when
  the author is offline is best-effort gossip, not a guarantee, unless seeded.
- See `DURABILITY.md` for the seeder/relay anchoring story.

### If it shows `gossip-dev` when you expected bridge
- The host didn't inject `window.pear` **and** no `pear-api-token` meta/`/api`
  routes are present. peerit **fails closed** — it will throw rather than
  silently downgrade if a *partial* bridge is present (see `test/bridge.mjs`),
  so a clean `gossip-dev` means *no* bridge surface at all.
- Confirm you opened a `hyper://` URL inside PearBrowser (not the file in a plain
  browser), and that the PearBrowser build exposes either `window.pear.sync` or
  the `/api/sync` routes. The bridge facts memo (`window.pear.sync` history)
  documents builds where the bridge shim was missing.

---

## Quick reference

```sh
npm test                 # automated headless bridge/runtime coverage
npm run test:browser:mobile
npm run proof:bridge:local # local Hyperdrive + two-device proof report
npm run proof:hiverelay-outboxlog -- --out reports/hiverelay-outboxlog-convergence-2026-07-01.json
node publish.mjs --local   # raw local host, prints the hyper:// URL
```

Chip cheat-sheet: **`gossip-bridge` = P2P**, anything starting `gossip-dev` =
single-device fallback.
