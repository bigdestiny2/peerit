# Operator Liability — Economic-Design Constraints for a Paid Blind-Seeder Fleet

> **Companion to [`BLINDSHARD-DESIGN.md`](BLINDSHARD-DESIGN.md).** BlindShard blinds *what* the
> fleet holds. This doc is about the other half: once fleet operators **earn money**, the
> payout model itself becomes load-bearing for their liability. Get the crypto right and the
> economics wrong and you hand a plaintiff the one prong the blindness was supposed to remove.
>
> **Not legal advice.** US framing (DMCA §512, secondary liability) with EU/DSA notes; the
> analysis varies by jurisdiction. This is a set of *design invariants* to keep operators
> inside the intermediary-protection shape, not a legal opinion.

---

## 0. The shift money creates

An unpaid volunteer seeding blind fragments looks like a conduit. A **paid** operator looks
like a **commercial service provider** — which is *not* itself disqualifying (CDNs, hosts, and
ISPs all earn money and keep safe-harbor protection). The danger is narrow and specific, and
BlindShard can dodge it, but only if the payout model is designed to.

The whole fleet economics has to preserve one sentence:

> **An operator earns the same whether a fragment is lawful or not, because they cannot tell
> the difference, cannot select what they hold, and never hold a complete work.**

Everything below is in service of keeping that sentence true.

---

## 1. The two doctrines money actually touches

Both hinge on the **same pair of facts** — a financial benefit *tied to* content, and the
*ability to control* that content. You need BOTH to be true to create liability, so breaking
*either* protects the operator. BlindShard is built to break both.

| Doctrine | What triggers it | What breaks it here |
|---|---|---|
| **Safe-harbor loss (§512(c), storage)** | "financial benefit **directly attributable to the infringing activity**" **AND** "right and ability to **control**" it | blindness removes *attributable benefit* (can't perceive the activity) **and** *control* (can't read/select); content-neutral pricing removes *attributable benefit* independently |
| **Vicarious liability** | financial benefit **+** right and ability to supervise/control | same two: blindness kills *control*; metered infra pay kills *attributable* benefit |
| **Contributory liability** | **knowledge** (actual or red-flag) **+** material contribution | blindness kills *knowledge* — you can't have red-flag awareness of bytes you can't read |
| **Inducement (Grokster)** | **actively encouraging** infringement (marketing, intent) | *not* a code property — a **positioning** constraint (see §4) |

Note the asymmetry that makes this workable: safe-harbor loss and vicarious liability each need
**benefit AND control**. Blindness alone kills control. Content-neutral pay alone kills the
attributable benefit. Doing **both** means a plaintiff has to win two independent prongs that
the architecture has separately removed.

---

## 2. How the architecture already carries most of the weight

These come from BlindShard for free — they are not new work, they are legal *consequences* of
Phase 3 blindness + fragmentation:

- **Blindness → no control, no knowledge.** A relay holding `shard:<hash>` opaque bytes
  (author-decoupled, no `contentKey`, no manifest — [`BLINDSHARD-DESIGN.md` §1](BLINDSHARD-DESIGN.md))
  cannot read, cannot select, cannot supervise. Control and knowledge are gone.
- **Blindness → no *attributable* benefit.** You cannot attribute revenue to infringing
  material you are structurally unable to identify. Popular contraband and a cat photo are the
  same random-looking bytes earning the same metered rate.
- **Fragmentation → not "hosting the work."** `< K` shards per relay (HRW `place()`, the
  manifest/shard-disjoint invariant) means **no single paid operator ever holds a complete
  work**. A shard is not the work — a much weaker "you host X" claim than a whole file at rest.
- **Tier matters.** A pure `dht-relay-ws` operator (Phase 5) is a **§512(a) transitory
  conduit** (ISP-shaped) — the easiest protection of all, essentially no takedown burden,
  because they only transmit Noise frames. **The closer a paid operator sits to pure-pipe, the
  less money threatens them.** Push paid capacity toward transport; those who must store hold
  blind fragments only.

---

## 3. The invariants the payout model MUST satisfy (this is the part YOU control)

The architecture gives blindness and fragmentation. The economics are the part that can still
sink an operator. These are hard constraints on the HiveRelay fleet's payout design:

1. **Pay for resources, never for content.** Meter on **bytes stored · bytes served ·
   uptime**. Flat or usage-metered. **Never** per-work, popularity-weighted, or a revenue share
   on any content-derived value. The instant an operator earns *more* because a particular blob
   is in demand, you've recreated "financial benefit **directly attributable to** the infringing
   activity" — the exact prong blindness was removing. Demand-blind pricing is a legal
   invariant, not a billing preference.

2. **Blindness and fragmentation must be protocol-enforced, not policy.** "Provably cannot
   read/select" is worth far more than "agreed not to." The `shard:<hash>` surface must be
   author-decoupled and keyless *by construction* (not gated by `data._k===appId`,
   [`BLINDSHARD-DESIGN.md` §4 net-new #5](BLINDSHARD-DESIGN.md)); the `< K per relay` cap must be
   client-enforced at write and independently auditable from the signed roster. An operator who
   *could* flip a config to read content has "ability to control."

3. **Ship a drop-by-opaque-id takedown path.** An operator served a notice must be able to purge
   a specific `blindContentId` / `shardId` **without ever reading it**. This preserves the
   storage safe harbor's "expeditiously remove on notice" condition while keeping the operator
   blind. Blind and takedown-capable are **not** in tension when takedown operates on
   identifiers. Reuse HiveRelay's `custody-signing.js` (`blindContentId`, `shardIds`,
   `custodyMode:'blind'`) as the identifier surface — a custody receipt already names exactly
   what a notice would target.

4. **Never let one operator hold a complete work.** The `< K`-per-relay placement cap is a
   **legal invariant**, not just a durability one. Document it as such: with fewer than K shards
   and no manifest/key, the operator provably holds an unreconstructable fragment.

5. **Roster / terms position operators as neutral infrastructure-for-hire.** Make the
   "cannot select content" property explicit in the operator agreement and the signed roster, so
   the *lack of* right-and-ability-to-control is on the record, not just in the code.

---

## 4. The non-obvious trap: don't let the *money message* induce

Inducement (Grokster) destroys **every** safe harbor regardless of blindness — it's about
*intent and encouragement*, which no crypto property can cure. Paid seeding is uniquely exposed
here because you are, literally, paying people to carry data.

- **Frame:** "earn for contributing storage and bandwidth to a blind fragment network."
- **Never:** "get paid to host the stuff nobody else will," "uncensorable paid hosting,"
  anything that reads as paying people *because* the content is illicit.

The economics can be flawless and the positioning can still sink you. Marketing copy, landing
pages, and operator recruitment are in-scope for this constraint.

---

## 5. Honest limits (carried over, not blended away)

- **Public content stays reconstructable.** Because the forum is public, `contentKey` ships in
  every manifest; a determined party (including an operator wearing a reader hat) can fetch the
  manifest + K shards and reconstruct — exactly as any reader does
  ([`BLINDSHARD-DESIGN.md` §6.1](BLINDSHARD-DESIGN.md)). The claim is "**each paid operator, in
  the ordinary course, holds and serves nothing readable**," **not** "the content is secret" or
  "nobody can ever read it." Blind-by-default, not blind-by-impossibility, for public content.
- **Collusion threshold.** Blindness holds against **independent** operators. A fully colluding
  roster (or one relay mis-assigned ≥K shards + the manifest) reconstructs everything
  ([`BLINDSHARD-DESIGN.md` §6.2](BLINDSHARD-DESIGN.md)). Independent, arms-length operators are a
  *precondition* of the whole argument — a fleet secretly run by one entity is one host wearing
  many hats.
- **Metadata is cleartext.** Sharding hides bodies, not who-posted-what
  ([`BLINDSHARD-DESIGN.md` §6.3](BLINDSHARD-DESIGN.md)).
- **Identifiable, paid operators are attractive targets.** A payout identity means an operator
  can be found and served — so the drop-by-id path (§3.3) is what lets an identifiable, paid,
  blind operator actually *comply* and stay protected. For a hobby volunteer the clean design is
  optional; for a paid operator it is not.
- **Scale/revenue raises duties (EU/DSA).** Larger paid fleets pick up due-diligence, notice,
  and reporting obligations that a single hobby relay doesn't. Bake a notice channel and
  transparency posture in before the fleet is large, not after.

---

## 6. TL;DR

Money is **fine** if it is:

1. **content-neutral** (metered on bytes/bandwidth/uptime, never popularity or per-work),
2. paid to **structurally-blind** operators (keyless, author-decoupled shard surface),
3. who **never hold a complete work** (`< K` per relay, enforced + auditable),
4. can **drop-by-opaque-id on notice** (custody-receipt identifier, no reading required), and
5. are **never marketed as inducement**.

Push paid capacity toward the **pure-pipe / transitory-conduit** end (Phase 5 `dht-relay-ws`)
wherever possible — that tier is the one where earning money barely dents the protection at all,
because the operator only transmits and stores nothing at rest.

The one sentence to keep true, restated: **an operator earns the same whether a fragment is
lawful or not, because they cannot tell the difference, cannot select what they hold, and never
hold a complete work.**
