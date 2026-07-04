# Pure-Pipe Scope — graph off the VPS + content dispersal, composed

**Status:** SCOPE / consolidation. This doc does **not** re-specify the OutboxLog migration
— that already lives in three docs (cited below). It ties the **graph leg** (OutboxLog →
HiveRelay) to the **content leg** (BlindShard dispersal, see
[BLINDSHARD-RECORD-WIRING-SPEC.md](BLINDSHARD-RECORD-WIRING-SPEC.md)) into a single
critical path to the "pure pipe" end state, defines that end state honestly, and surfaces
the **composition gaps** that no existing doc owns.

**Source-of-truth docs (do not duplicate — extend):**
- [HIVERELAY-OUTBOXLOG-PLAN.md](HIVERELAY-OUTBOXLOG-PLAN.md) — the 5-phase roadmap + honest blindness scope.
- [OUTBOXLOG-HANDOVER-SPEC.md](OUTBOXLOG-HANDOVER-SPEC.md) — the Phase-2 acceptance gates + the `core-memory`→OutboxLog delta.
- [BLIND-OUTBOX-MIGRATION.md](BLIND-OUTBOX-MIGRATION.md) — Decision D4: clean cutover to v2 opaque keys.

---

## 1. "Pure pipe" needs BOTH legs — neither alone is enough

The VPS today is a **complete social-graph oracle**: every storage key is plaintext and
semantic ([core-memory.mjs](../../peerit-relay/lib/core-memory.mjs)), so an operator reading
raw disk learns who posted where, who voted on what, every community, every author — without
decrypting a single value. Bodies are additionally readable (v1) or key-shipped (v1 boxing).

Two independent leaks, two independent legs:

| Leak | Leg that closes it | Mechanism |
|---|---|---|
| **Graph via keys** — `post!<community>!<cid>`, `vote!<targetCid>!<author>`, `profile!<author>` enumerate the social graph by prefix scan | **Graph leg** — OutboxLog migration + **v2 opaque keys** | keys become `v2!<okey>` (HMAC), so no prefix enumeration; transport moves off the VPS to HiveRelay |
| **Content key on the VPS** — v1 ships `contentKey` in the clear on the post; the VPS can decrypt bodies | **Content leg** — BlindShard dispersal (spec #1) | the AES key is PVSS-split across the HiveRelay cohort; the VPS holds only opaque ciphertext |

Ship only the graph leg → the VPS still holds readable bodies (or their keys). Ship only the
content leg → the VPS still enumerates the whole graph by key prefix. **The pure pipe is the
composition of both**, plus moving the ciphertext blob itself off the VPS.

---

## 2. The composition — one record, two layers

The two legs meet inside a single record. Under Decision D4 (clean cutover to v2), a post is
stored as a v2 sealed record; the v2 seal rule seals every field **not** in
`V2_CLEAR = [createdAt, ts, editedAt, deleted, slug]`. So the `dispersal` manifest (spec #1)
seals **alongside** the graph fields:

```
v2 record on the relay:
  key:  v2!<okey>                         ← opaque (graph leg): no prefix enumeration
  val:  { id: <okey>, _t: 'post',
          createdAt, editedAt, deleted,   ← V2_CLEAR (LWW needs these)
          sealed: {                        ← AES-GCM under the app read-key (RK)
            community, cid, title, url,
            dispersal: { … keyless manifest … }   ← content leg: points to shards + ciphertext blob
          },
          _sig, _k, _dk, _ns, _alg }
  ─────────────────────────────────────────────────────────────────
  body ciphertext:  a separate blob!<blindContentId> cell (opaque)
  body key:         PVSS shares across the HiveRelay cohort (NOT on the relay)
```

Read = unseal with RK → read graph fields + `dispersal` → `recoverBody(dispersal, {cohort,
fetchCiphertext})`. Two decryptions, two sources: the **record** (from the outbox relay) and
the **k shares** (from the cohort). The body key is on **neither** the outbox relay nor the
ciphertext blob — only reconstructible from k independent cohort relays.

---

## 3. The pure-pipe end state — defined honestly

**What the VPS holds/serves at the end (both legs shipped):**
- Opaque-keyed cells (`v2!<okey>`) — no key-prefix graph enumeration.
- Sealed values under a **public** read-key (public forum ⇒ RK is public by necessity).
- No body decryption key (dispersed).
- Optionally: not even the ciphertext blob (content Phase D moves it to HiveRelay).

**The honest ceiling — what an operator can STILL do (verbatim from the plan docs, do not
overclaim past this):**
- ❌ **Not secrecy.** Public content is world-readable; the operator holds the public RK like
  any reader, so titles/graph-fields of public posts remain readable **on unseal**. The win is
  "must affirmatively reconstruct to read **bodies**" + "no semantic graph via keys" — not "can't read."
- ❌ **Not anonymity.** `/api/directory` exposes the author roster (`appId === author pubkey`).
- ❌ **Not metadata-blindness.** Per-author record counts, append cadence, byte sizes, and
  client IPs all leak, even with opaque keys and dispersed bodies.
- ❌ **Not censorship-impunity.** The roster URL + JS bundle are single-origin; mitigated by
  inlining the roster + distributing the bundle, not eliminated.

**The correct one-line claim:** *"In the ordinary course the operator holds and serves nothing
readable and must affirmatively reconstruct to read — and cannot enumerate the social graph by
key."* That is the whole product claim. Everything past it is a lie the docs already warn against.

---

## 4. The consolidated critical path (graph phases × content phases)

The graph phases (OUTBOXLOG-PLAN §5, numbered 1–5) and the content phases (spec #1, lettered
A–D) interleave. Dependencies, not a strict order:

```
GRAPH LEG (existing plan)                 CONTENT LEG (spec #1)
─────────────────────────                 ─────────────────────
P1 roster + primary  ✅ DONE
                                          A  attach dispersal (node writer, dual-store)   ← ships now, browser-safe
P2 port core-memory → OutboxLogApp        B  browser recover-only bundle (blind-reader)   ← NOT #115-gated
   + write-time single-writer verify         (independent of P2/P3)
   + wire-conformance gate  ▢ PLANNED
P3 Hypercore durability + per-key SSE  ▢
P4 v2 opaque keys live (blind ns) ──────► C  read cutover: dispersal is the sole body store
   + encryption-at-rest                      (compose: dispersal seals inside v2)
                                          D  ciphertext blob → HiveRelay (off the VPS)  ← needs a HiveRelay blob GET (gap §5.1)
P5 second consumer
```

**Ordering rules that matter:**
- **A and B ship independently of the graph migration** — A is a node-writer change + a blob
  record (existing transport); B is a browser bundle. Both land on today's VPS. Do these first;
  they are the cheapest real progress and de-risk the reader.
- **C (read cutover) should follow P4** or at least the v2 cutover, because dispersal composes
  cleanly with the v2 seal (§2). Cutting over content bodies while records are still v1
  plaintext-keyed is possible but wastes a migration.
- **D (ciphertext off the VPS) is the true "pure pipe" moment** and depends on a HiveRelay
  ciphertext-blob surface (§5.1) — the single most important unowned gap.

---

## 5. Composition gaps no existing doc owns

These are the deltas this scope adds on top of the three source docs. Each is a concrete work
item for whichever session (peerit / hiverelay) owns that layer.

### 5.1 HiveRelay ciphertext-blob GET surface (content Phase D)
The custody contract is **shard-scoped** (`/api/v1/shard/<addr>`, PVSS shares). The dispersed
**body ciphertext** is not a share — it is one opaque blob addressed by `blindContentId`
(=SHA-256(ciphertext)). Content Phase D needs HiveRelay to serve arbitrary content-addressed
blobs (a `GET /api/v1/blob/<blindContentId>` or equivalent), or peerit must model the ciphertext
as an (n+1)-th "ciphertext shard" under the existing shard surface. **Decision needed:** dedicated
blob GET vs. ciphertext-as-shard. Until then, the ciphertext blob stays on the VPS (opaque, keyless).

### 5.2 Roster unification — shard cohort vs. outbox relay
There are **two** rosters: the outbox relay roster (`relay-roster.json`, VPS + Render, signed,
Phase-1 done) and the **shard cohort** roster (the k-of-n custodians, currently
`~/.hiverelay-shard-cohort/roster.json` for dev). A reader needs both: the outbox relay (record
+ ciphertext blob) **and** the cohort (k shares). **Decision needed:** one signed roster file
with two blocks (`outboxRelays`, `shardCohort`) under the same Ed25519 trust anchor, or two
files. Recommend one file, two blocks — one pin to maintain.

### 5.3 Dispersal manifest under the v2 seal
Confirmed compatible (§2): `dispersal` is not in `V2_CLEAR`, so it seals with the graph fields.
No code conflict, but the data-model session must ensure the v2 unseal path exposes `dispersal`
to the reader before `recoverBody`. Call it out in the v2 cutover checklist so it isn't dropped.

### 5.4 Write-time verification must not break `dispersal`
Graph Phase 2 adds server-side single-writer Ed25519 verification at `append()`
(OUTBOXLOG-HANDOVER-SPEC §5). That verification signs over the canonical record — which now
includes `dispersal`. Since the author signs the full record incl. `dispersal` (spec #1 §2.2),
this composes for free, **provided** the ported OutboxLog uses peerit's exact canonicalization
(`canon.js stable()` + `SIG_FIELDS`). Add a `dispersal`-bearing record to the wire-conformance
golden set so the port can't silently diverge.

### 5.5 Durability of the two planes must be jointly considered
Graph Phase 3 gives outboxes Hypercore durability (seeder pickup). The **shards** have their own
custody/retain model (custody intents, `retainUntil`); the **ciphertext blob** currently rides
the outbox as a `blob!` record (so it inherits outbox durability). If content Phase D moves the
blob to HiveRelay, its durability must be specified alongside the shards' custody, not left as
best-effort. Flag for the durability phase.

---

## 6. Status + what's gated on what

| Item | Status | Gate |
|---|---|---|
| Graph P1 (roster + primary) | ✅ done | — |
| Content A (attach dispersal, node) | ▢ ready to build | spec #1 §8; needs the data-model session |
| Content B (browser reader bundle) | ▢ ready to build | build-only; **not #115** |
| Graph P2 (OutboxLogApp + verify + wire gate) | ▢ planned | HiveRelay session; convergence proof already green once engine exists |
| Content C (read cutover) | ▢ | after v2 cutover (P4) + B proven |
| Content D (ciphertext off VPS) | ▢ | gap §5.1 (HiveRelay blob surface) |
| Graph P4 (v2 opaque + encrypt-at-rest) | ▢ planned | HiveRelay session |
| **Security property** (blindness) | 🟡 | ≥3 **independent** cohort operators (GATE 2) + independent outbox relays |
| Production shard fleet | 🟡 | v0.24.0 deploy — `NPM_TOKEN` + `ECOSYSTEM_CONSUMER_TOKEN` + CI image digest |
| Browser **dealer** (in-browser authoring) | 🔴 | HiveRelay **#115** (Bare client manifest-bearing intents) |

---

## 7. Recommendation

1. **Do Content A + B first.** They are the cheapest real "off the VPS" progress, ship on
   today's infra, de-risk the reader, and are gated on nothing external (not #115, not P2, not
   the fleet deploy). A puts keyless manifests into real records; B proves the browser can read
   dispersed content.
2. **Resolve gap §5.1 (HiveRelay blob surface) and §5.2 (roster unification) in parallel** —
   they are small decisions that unblock the true pure-pipe steps and belong to the HiveRelay
   session and the peerit app layer respectively.
3. **Let the graph leg (P2→P4) proceed on its own track** per the existing docs; the only new
   constraint this scope adds is §5.4 (canonicalization parity must cover `dispersal`).
4. **The pure pipe lands when Content D + Graph P4 both ship** — opaque keys (no graph
   enumeration) + dispersed keys (no body reads) + ciphertext off the VPS. State the claim at
   §3's ceiling and no further.

The honest headline: the mechanism is proven end-to-end (both legs have working code); what
remains is a sequence of scoped, individually-revertible migrations and one security gate
(independent operators) that is a deployment property, not a code property.
