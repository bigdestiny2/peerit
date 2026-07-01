# peerit P2P Durability — Implementation Spec

Status: DRAFT (2026-07-01). Grounded in a 4-design / adversarial-verify analysis of the
current tree. This spec is deliberately honest about the ceiling: it does **not**
promise "the relay stores nothing." It specifies the strongest thing that is actually
true-to-physics for a **public** forum reached from a **normal browser**.

---

## 0. The honest problem statement

Two runtimes, two very different guarantees:

- **PearBrowser (native):** already fully P2P. Each user owns a single-writer Hypercore
  outbox (`window.pear.sync.create`), announces a **signed descriptor** over Hyperswarm,
  peers replicate + verify + merge. The web relay is **never** in this path. Nothing here
  needs fixing.
- **Normal browser (web mode):** a browser tab can't join the DHT, so it talks to an
  `/api` relay over HTTP/SSE. The 2026-07-01 durability fix made that relay **persist
  records + descriptors to disk** (`core-memory.mjs` `g.rows.set(key, op.data)` →
  `/var/peerit`). That works, but it makes the relay a **plaintext store and the sole
  source of truth** for web-user data. That is the compromise the user (correctly) calls
  unacceptable.

**Crucial framing — the compromise is NOT integrity.** The relay holds no signing key,
`/api/identity` returns 410, and every record is Ed25519-re-verified in the browser at
merge (`gossip.js admit()`). The relay **cannot forge or tamper**. The compromise is:

| Axis | Status today (web mode) | Fixable? |
|---|---|---|
| Integrity / authenticity | ✅ sound (client-verified sigs) | already solved |
| Storage-centralization | ❌ relay is sole source of truth | **yes — main goal** |
| Liveness / censorship | ❌ single relay can withhold, undetectably | **partly — detectable + swappable** |
| Privacy (content at rest) | ❌ relay reads plaintext bodies | **only via encryption; public content is public by design** |
| Privacy (IP / metadata) | ❌ relay sees IPs | **no — any bridge/pipe sees IPs** |
| Origin-ships-JS | ❌ peerit.site serves the JS | **no — outer wall for all web modes** |

## 1. The honest ceiling (what we will and won't claim)

From the adversarial verify (all 4 designs scored "partly/mostly", none "fully"):

1. **Physics floor:** a closed/backgrounded tab seeds nothing; browsers give no
   background hypercore replication. So cold-start durability **requires an always-on
   party** (a seeder and/or the HiveRelay fleet). We cannot remove the always-on node;
   we can only change **what** it is and **how swappable** it is.
2. **Public content is plaintext somewhere:** peerit is a public forum with no app-side
   encryption. Whoever seeds an outbox (relay, HiveRelay operator, co-seeding reader)
   can read it. "Blind pipe" (dht-relay) removes plaintext from the **transport**, not
   from the **seeders**. Encryption only helps **private** communities and even then
   leaks the social graph (author, community, votes, timestamps stay legible).
3. **A browser can't be a first-class DHT peer** without a server-run entry point
   (dht-relay ws:// or an /api relay) — always a blockable, IP-observing node.
4. **origin-ships-JS** bounds every web mode below PearBrowser regardless of transport.

**Therefore the achievable goal, stated honestly:**
> Make every relay a **swappable, non-authoritative, integrity-sound replica** of a
> **self-verifying** outbox; move durability onto a **signed, pinnable directory + a
> multi-party seed fleet**; and make **censorship detectable and routable-around**.
> Optionally remove plaintext from the **transport** (blind dht-relay) as a later tier.
> The relay stops being *the* store and becomes *a* cache nobody has to trust.

That is a large, real improvement — and it is essentially the user's "pin a small
signed merkle-root, pull the posts from the hypercores" instinct, made precise.

## 2. The one load-bearing gap

Multiple designs converge on the **same root cause** and the **same fix**:

> **Today the web outbox is RELAY-minted.** `core-hypercore.mjs` `openWritable()` does
> `store.get({ name: 'outbox:'+appId })` — the *relay* mints the writable core, so
> `inviteKey` is the *relay's* key. No independent party can reconstruct it, which is
> exactly why the relay is the sole source of truth. (`core-memory.mjs` is worse: a plain
> `Map`, no aggregate integrity at all.)

**Fix:** the **author owns the outbox**, identified by a key the *author* controls, plus
a **signed head** committing to the full record set. Then any relay/seeder/reader is a
replica keyed by the author's key, "any of N relays reconstructs identical state" becomes
literally true, and withholding is detectable (the head says how many records exist).

We approach this in two tiers because a full browser-owned **Hypercore** needs an
in-browser hypercore bundle (heavy, unvalidated, `@hyperswarm/dht-relay` is pinned
"do-not-use-in-production"). Tier 1 gets ~80% of the win with pure client/record work.

## 3. Architecture — the two-layer model

```
DISCOVERY / INTEGRITY LAYER  (tiny, durable, signed, pinnable)
  signed descriptor   {pub, appId, inviteKey, sig}          ← who/where
  signed outbox HEAD  {appId, version, count, root, ts, sig} ← the "merkle root":
                        commits to the complete record set   what/how-many
  → lives in a durable directory (Hyperbee) pinned by HiveRelay + replicated across relays
  → readers verify sigs client-side; withholding = "relay served < count" → fail over

DATA / BLOCK LAYER  (bigger; public plaintext by design)
  the actual records (posts/comments/votes/community/mod)
  → served by ANY replica: /api relay cache, peerit-seeder, HiveRelay /seed-core pin,
    co-seeding reader tab, or (Tier 2) another browser over a blind dht-relay
  → every record Ed25519-verified at merge; every replica checked against the HEAD
```

The HEAD is the "small file you pin." It does **not** contain the posts — it's a
**verifier + census** (root hash + count + version). Pinning it buys: discovery,
integrity of the *set* (not just each record), and **withholding detection**. The posts
still need a holder — but now *any* holder works and *no* holder is trusted.

## 4. Phased plan

Each phase is independently shippable and testable. Buildable-now phases need **no**
in-browser DHT bundle.

### Phase A — Signed outbox HEAD (the merkle-root primitive)  · BUILDABLE NOW
Give every outbox an aggregate, signed census so no relay is authoritative and
withholding is detectable.
- **Client (`js/data.js` / `js/gossip.js`):** maintain a per-outbox head record
  `head!<appId>` = `{ appId, version, count, root, updatedAt }` signed with the author's
  existing Ed25519 key (`identity.sign`). `root` = a Merkle/rolling hash over the sorted
  `(key,_sig)` pairs of the author's own records. Re-sign on every append/edit/delete
  (same discipline as records — stale sig ⇒ rejected).
- **Verify (`js/verify.js` / `admit`):** treat `head` as a first-class signed type;
  bind `head!<appId>` ⇒ `_k===appId`. A reader compares each replicated outbox against
  its signed head: if the relay served fewer keys than `count` (or a key the head's
  `root` doesn't commit to), flag the source as withholding/tampering and fail over.
- **Relay:** none required (head is just another record) — but expose it via the existing
  `heads`/`status` so a client can cheaply ask "what version/count do you claim."
- **Tests (`test/*.mjs`):** (1) head re-signs on write and `count/root` track the record
  set; (2) a relay that drops one record is **detected** (served count < signed count);
  (3) a tampered head fails `admit`. Wire into `npm test`.
- **Honest scope:** does not stop the relay storing plaintext; it makes the store
  *non-authoritative* and *auditable*. Foundation for B/C/D.

**DELIVERED 2026-07-01 (built + adversarially reviewed):** signed `head!<author>`
(`{version, count, root}`, `\x00`/`\x01`-delimited census) produced after every
write (`gossip.js` `_maintainHead`, gated `writeHead`, on in prod). `auditOutbox(rows,
head, owner)` is **wired into the live read path** (`_doRefresh`) — the sound signal
is `hasHead && !matches` (root mismatch = withheld/reordered/substituted); it surfaces
on `status().withholding` + a `console.warn`. Owner-scoped census (foreign signed rows
can't pad it). 21 tests. Also fixed in review: read-only writes now fail closed at the
append chokepoint; `head!` stripped from the UI change-set (kept vote fast-paths);
`head!` excluded from `viewLength`.
**KNOWN LIMITS of the head ALONE (closed later, not in A):**
  - **Rollback/replay** — a single relay can serve an *older, still-validly-signed* head
    + its matching subset; a fresh reader has no baseline to know it's stale. `head.version`
    is written but only becomes load-bearing once compared across sources. → **Phase B**
    (cross-relay: take the highest `version`) + **Phase C** (durable monotonic floor).
  - **Head-strip / downgrade** — drop `head!<author>` → `hasHead:false` → auditing fails
    *open*. No durable "this author HAD a head" fact in A. → **Phase B** sticky watermark +
    **Phase C** pinned directory.
  - **Detection ≠ mitigation** — against ONE relay there is nowhere to fail over; the head
    makes withholding *visible*, not *routable-around*, until Phase B.

### Phase B — Multi-relay write fan-out + cross-relay reconstruction proof · BUILDABLE NOW
Make "the relay is swappable" true in practice, not just in principle.
- **Client (`js/relay-roster.js` / `js/pear-api.js`):** `relay-roster.js` already verifies
  a signed roster + boot-time `selectRelay` failover. Extend: on write, fan out the append
  to the top **K** reachable roster relays (not one). After a write, poll
  `/api/sync/heads` (or `status`) on a **different** relay until its `version/count`
  matches the signed head → prove an independent relay reconstructed the state.
- **UI (`js/app.js` netstatus chip):** surface "replicated to N/M relays."
- **Tests:** fan-out hits K relays; reconstruction-proof passes only when a 2nd relay's
  head matches; a withholding relay is detected + skipped.
- **Honest scope:** liveness/censorship becomes *detectable and routable-around*; seizing
  one relay loses nothing. Still plaintext on each relay (public content).

**DELIVERED 2026-07-01 (built + tested; adversarial review pending):** `js/relay-pool.js`
drives up to 3 relays as a pool behind the same `window.pear`-shaped surface (plugged in
via `resolvePear`, so `gossip.js` is unchanged). **Write fan-out** (`fanoutAppend`: primary
authoritative + best-effort mirror) puts every record + head on independent relays.
**Cross-relay head** (`crossHead`: highest-version *verified* head across relays) is the
audit baseline — so a relay serving a **stale head (rollback)** loses to one serving the
newer head, and a relay **dropping the head (strip)** is overridden by any relay that has
it. On a shortfall the reader **routes the read around** the bad relay (`recoverRows` finds
a relay serving the head-matching set) and re-admits; only when *no* relay serves the
committed set is the outbox flagged on `status().withholding`. `selectRelays` resolves the
pool; `status().relays` reports the count. Degrades to a pool of one (detection-only) with
one configured relay — the guarantees switch on as the roster grows. 9 tests in
[relay-pool.mjs](02-apps/peerit/test/relay-pool.mjs) (fan-out, rollback+strip recovery,
flag-when-nowhere). **Closes the Phase A rollback + head-strip gaps WHILE ONLINE**; the
across-restart floor remains Phase C.

### Phase C — Durable signed directory (Hyperbee) + relay demoted to cache · NEEDS HIVERELAY
Move discovery durability off relay RAM.
- Replace `swarm-hub.mjs` descriptor `Map` + `core-memory` snapshot with a **signed,
  append-only directory Hyperbee**: each row = `{descriptor, head}` (both author-signed).
  Directory core key = a well-known peerit constant; pin it via HiveRelay
  `/seed-core {catalog:true}` (`00-core/hiverelay/.../api-seed-core.js`).
- Fresh visitor: read the directory core (served by the fleet even with all authors
  offline) → verify each row's sig → join each outbox by `inviteKey`. Relay `core-memory`
  becomes a warm cache; wiping `/var/peerit` loses nothing recoverable.
- **Tests:** directory round-trips signed rows; a fresh reader discovers offline authors
  from the directory alone; forged rows rejected.

### Phase D — Seeder auto-discovery + pin-on-append · NODE WORK (closes a real gap)
Today `peerit-seeder/seeder.mjs` is **manual** (`seeds.json`/argv) — an operator whitelist,
the analysis's sharpest "still centralized" finding.
- Teach the seeder to join `peerit-gossip-v1`, speak the `peerit/desc/v1` descriptor
  protocol (reuse `gossip.js` `_onDescriptor` verify), and for every **signed** descriptor:
  `store.get({key:inviteKey})` + `swarm.join(sha256(inviteKey))` + `core.download(0,-1)`,
  then `HiveRelayClient.seed(inviteKey,{durability:1})` and **wait for `confirmFleetCopy`
  (`remoteLength>=length`)** before trusting the pin (`accept != downloaded`).
- **Tests:** seeder discovers an outbox from a descriptor (no seeds.json) and confirms a
  fleet copy. (Live-DHT parts validated on the user's machine, not sandbox.)

### Phase E — Tier 2: browser-owned cores + blind dht-relay pipe · HEAVY / NEEDS LIVE VALIDATION
The "removes plaintext from the transport" tier. Ship best-effort with `/api` fallback.
- Make `js/dht-bundle.js` real: esbuild `js/dht-transport.js` (deps: `@hyperswarm/dht-relay`,
  `hyperswarm`, `corestore`, `hyperbee`, `protomux`, `b4a`, `random-access-web`,
  `compact-encoding`) → ship in `publish.mjs` SITE_FILES. `app.js:66-73` already prefers it.
- **Fix the known live-wire bug** first: `dht-adapter.js:~82-87` uses a pass-through
  protomux codec `{encode:b=>b,decode:b=>b}` (works only with the in-memory test fake) →
  replace with `compact-encoding`.`raw`.
- Browser owns the outbox core (keypair-derived, `inviteKey===core.key`); relay/seeder are
  read-only replicas. Transport is Noise ciphertext → the pipe operator can't read content.
- **Honest scope:** blind *transport*, not blind *storage*; seeders still hold public
  plaintext. Residual: dht-relay is still an IP-observing liveness chokepoint; dep is
  self-declared do-not-use-in-production. Validate on live DHT before relying on it.

### Phase F — Optional: encrypted-community seam · SMALL, INDEPENDENT
For *private* communities only. Encrypt body/title fields client-side in `data.js` `_sign`,
leave structural fields (id, author, community, `_sig`, PoW) plaintext so `admit`/ranking
work. Honest: leaks the social graph; symmetric key handed to all members (incl. a relay
that joins). Ship as opt-in "encrypted community," never claimed as default privacy.

## 5. Non-goals / permanent ceiling (state these in the README)
- Not anonymity: any bridge/pipe/seeder sees IPs.
- Not blind storage of **public** content: public posts are readable by whoever seeds them.
- Not zero-always-on-infra: cold-start needs a seeder/fleet; a closed tab seeds nothing.
- Not origin-trust-free for web users: peerit.site ships the JS. Steer high-assurance
  users to PearBrowser (`hyper://` drive + SRI/`verify.html`).
- **Rollback/freeze resistance across a relay restart is NOT provided until Phase C.**
  The signed head makes withholding detectable against a *fresh, present* head from a
  *single* source; a relay serving an internally-consistent *old* snapshot (or stripping
  the head) is only caught once heads are compared across relays (B) and the latest
  `(author → version/count)` is pinned in the durable signed directory (C). Until then,
  the head is honestly "tamper-evident, not rollback-proof."

## 6. Recommended build order
A → B (both buildable now, high value, fully testable, no risky bundle) establish the
merkle-root + swappable-relay backbone the user asked for. Then D (kills the manual-seeder
centralization) and C (durable directory). E (blind transport) last, gated on live-DHT
validation. F only if a private-community feature is wanted.

**Start with Phase A** — the signed outbox head. It is the literal "small signed
merkle-root" primitive, it's pure client/record work (no bundle, fully unit-testable),
and every later phase pins, fans-out, or reconstructs *against it*.
