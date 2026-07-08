# Relay Operator Recruitment — Onboarding peerit's First Arms-Length Independent Relay

> **Companion to [`OPERATOR-LIABILITY.md`](OPERATOR-LIABILITY.md) and [`BLINDSHARD-DESIGN.md`](BLINDSHARD-DESIGN.md).**
> Those docs assume a fleet of *independent* operators. This doc is how you actually get the
> **first** one — the plan, the diversity gate, and the minimal agreement.
>
> **Not legal advice.** The agreement below is a set of design/positioning invariants that keep an
> operator inside the intermediary-protection shape, not a legal contract or opinion.

---

## 1. Why independence is a hard GATE, not a nice-to-have (read this first)

**The shipped roster is one legal person wearing two hats.** Both relays in
[`relay-roster.json`](../relay-roster.json) and [`deploy/web-release.json`](../deploy/web-release.json)
are:

- `https://153-75-89-206.sslip.io` — a raw-IP `sslip.io` host, i.e. the owner's own VPS, and
- `https://peerit-relay.onrender.com` — the owner's Render deploy.

Under subpoena, that is **one person, one payment trail, two boxes**. Every claim peerit makes about
being hard to seize, hard to censor, and cryptographically resistant to a colluding fleet is
**currently vacuous** because there is exactly one operator:

- **Censorship / seizure:** one legal process (subpoena, seizure order, provider takedown) reaches
  *both* relays because they answer to the same person. A same-owner "fleet" is a single point of
  legal failure — the roster count is 2, the independent-entity count is **1**.
- **Collusion thresholds are theater at N-independent = 1.** BlindShard's `< K`-shards-per-relay cap
  and manifest/shard separation "hold against **independent** operators, not a colluding pool"
  ([`BLINDSHARD-DESIGN.md` §6.2](BLINDSHARD-DESIGN.md)). If one entity controls every relay, it can
  co-locate the manifest with ≥K shards and reconstruct everything — the threshold protects nothing.
- **[`OPERATOR-LIABILITY.md` §5](OPERATOR-LIABILITY.md) states the precondition outright:**
  > *"Independent, arms-length operators are a precondition of the whole argument — a fleet secretly
  > run by one entity is one host wearing many hats."*
- **Phase 3 dispersal is BLOCKED on this.** Dispersal requires each of K shards on **K distinct
  relays** (servers-of-happiness, [`BLINDSHARD-DESIGN.md` §3a/§3c](BLINDSHARD-DESIGN.md)). At
  **K=6/N=9** (§3c), dispersal needs **~6 independent operators** to be real — and no fewer than
  **3** to be meaningfully better than one box. Two same-owner relays get you **zero** of that.

**The gate:** a new relay counts only if it is a **different legal entity with independent control**.
The number that matters is not "relays in the roster" but "independent entities in the roster."
Today that number is 1. This doc's job is to get it to 2, then 3, then 6.

---

## 2. Onboarding a new operator

The relay is the **same binary**, run solo by someone else. There is no special "second-operator"
build — independence comes from *who runs it and how*, not from the code.

### 2a. Self-host the relay
Point the operator at [`02-apps/peerit-relay`](../../peerit-relay) (`README.md`). Steps:

1. `git clone` peerit-relay, `npm i` (add optional deps for the production hypercore core).
2. Run the **production** path (`PEERIT_RELAY_CORE=hypercore`) so the relay replicates outboxes over
   the DHT rather than staying ephemeral (peerit-relay README §"Run it").
3. TLS + reverse proxy in front (the relay binds `127.0.0.1` by default); the operator's own domain,
   the operator's own TLS cert. Use `examples/Caddyfile`, `examples/peerit-relay.service`, and
   `examples/.env.example` (peerit-relay README §"Deploy checklist").

### 2b. Hardening env the operator SHOULD set
From peerit-relay README §"Environment" / §"Hardening":

| var | set to | why |
|---|---|---|
| `PEERIT_RELAY_ORIGINS` | `https://peerit.site` (+ mirrors) | never leave CORS at `*` in production |
| `PEERIT_RELAY_SECRET` | `openssl rand -hex 32`, fixed, shared across the operator's own replicas | tokens survive restarts |
| `PEERIT_RELAY_TRUST_PROXY` | `1` **only** behind a proxy that sets a trustworthy `X-Forwarded-For` | correct per-IP rate limiting |
| `PEERIT_RELAY_MAX_RATE` / `_SSE_PER_IP` / `_MAX_BYTES` / `_MAX_GROUPS` | tune to the box | graceful degradation under flood (`429`/`503`), not OOM |
| `PEERIT_RELAY_PERSIST` | a path on a **persistent disk** | outboxes stay available + discoverable across restarts |
| `HOST` | leave `127.0.0.1` | reachable only via the reverse proxy; firewall `deny 8787/tcp` |

Systemd with `Restart=always` + `MemoryMax` (see `examples/peerit-relay.service`). The relay
**never signs user content and never needs the roster signing key at runtime** (peerit-relay README
§"Signed relay roster") — the operator holds no key that could impersonate a user.

### 2c. Get the URL into the SIGNED roster
peerit clients trust a relay **only** if its URL is inside the Ed25519-signed roster whose public key
is pinned into the audited web bundle. The mechanism (see [`js/relay-roster.js`](../js/relay-roster.js)
`verifyRelayRoster` + `pinnedRosterKey` in [`deploy/web-release.json`](../deploy/web-release.json)):

1. The roster signer (peerit maintainer) re-signs **offline**, adding the new relay, from
   peerit-relay:
   ```sh
   PEERIT_ROSTER_SEED=<seed from offline key storage> npm run roster:sign -- \
     --relay https://153-75-89-206.sslip.io \
     --relay https://peerit-relay.onrender.com \
     --relay https://relay.<new-operator-domain> \
     --expires 2026-12-31T00:00:00.000Z --out ../peerit/relay-roster.json
   ```
2. **Reuse the same signing key** already pinned — `pinnedRosterKey`
   `4a7402d1a950dc3be8a434cb3ee664231ca0e58be8c745dabcaf2346ee0e0f7f`. The client will reject any
   roster signed by a different key (`relay-roster.js` `verifyRelayRoster`: `sigKey !== key → throw`),
   so **no bundle rebuild is needed** to add a relay — only a re-signed `relay-roster.json` served at
   the pinned `rosterUrl`. (Rebuild only when rotating the pinned key itself.)
3. `dedupeRelayList` in `relay-roster.js` normalizes/dedupes; `selectRelays(..., { max })` then builds
   the working pool primary-first — the cross-relay guarantees switch on automatically as the roster
   grows past one.

### 2d. Diversity gate (must pass BEFORE adding to the roster)
A new URL only helps if it is a genuinely separate seizure/trust surface. **Check every box:**

- [ ] **Different legal entity / person.** Not the maintainer, not a shell they control, not an alias.
      This is the load-bearing one — everything else is defense in depth.
- [ ] **Different hosting provider.** Not another box on the same VPS account or Render org as the two
      existing relays.
- [ ] **Different jurisdiction** (ideally). A relay in a different country raises the cost of a single
      legal process covering the whole fleet.
- [ ] **Different funding / payment trail.** The operator pays their own infra bill from their own
      account — a shared invoice re-collapses the "one legal person" problem.
- [ ] **Independent control of the domain, TLS, and server keys.** The maintainer cannot log in.
- [ ] **Signed independence attestation on file** (see §3, agreement point 6).

If any of the first, second, or last boxes fail, **do not add the relay** — it is another hat on the
same head and adds risk (bigger attack surface) without adding independence.

---

## 3. Minimal operator agreement

Short, plain, aligned with [`OPERATOR-LIABILITY.md`](OPERATOR-LIABILITY.md). An operator on the signed
roster agrees to:

1. **The relay is untrusted and never signs for users.** `/api/identity` stays disabled (returns
   `410`); the relay is an availability provider only — it can serve/replicate/refuse data, never
   forge, tamper, or impersonate (peerit-relay README §"Why it's safe to run an untrusted relay").
   Every record is re-verified in the reader's browser.

2. **Content-neutral posture.** The operator does not select, rank, or curate content. **If/when an
   operator is ever paid**, payment is metered on **bytes stored · bytes served · uptime** only —
   flat or usage-metered — and **never** per-work, per-view, popularity-weighted, or any content-derived
   revenue share ([`OPERATOR-LIABILITY.md` §3.1](OPERATOR-LIABILITY.md): demand-blind pricing is a
   legal invariant). *Today all operators are unpaid volunteers.*

3. **Drop-by-opaque-id takedown.** On a valid notice, the operator will purge a specific
   record / `blindContentId` / `shardId` **without reading it**, operating on the identifier alone
   ([`OPERATOR-LIABILITY.md` §3.3](OPERATOR-LIABILITY.md)). Blind storage and expeditious takedown are
   not in tension when takedown targets identifiers, not content.

4. **No-inducement conduct.** The operator does **not** market the relay as "host anything,"
   "uncensorable hosting," or "get paid to carry what nobody else will." Framing is *"I provide storage
   and bandwidth to a blind fragment network"* ([`OPERATOR-LIABILITY.md` §4](OPERATOR-LIABILITY.md) —
   inducement destroys every safe harbor regardless of blindness).

5. **Blind-storage posture (as BlindShard lands).** The operator will not configure the relay to read,
   index, or select content it holds; the blind `shard:<hash>` surface stays keyless and
   author-decoupled by construction, and the operator will not co-locate a manifest with ≥K shards of
   the same item ([`OPERATOR-LIABILITY.md` §3.2/§3.4](OPERATOR-LIABILITY.md),
   [`BLINDSHARD-DESIGN.md` §1](BLINDSHARD-DESIGN.md)). *(No-op until Phase 3 dispersal ships; stated now
   so the posture is on the record.)*

6. **Independence attestation.** The operator attests they are a **separate entity with independent
   control** of the infra, domain, keys, and funding — i.e. they pass §2d — and will disclose if that
   ever changes (e.g. the infra is acquired by, or funded through, another roster operator). This is the
   record that the "lack of right-and-ability-to-control" is real
   ([`OPERATOR-LIABILITY.md` §3.5](OPERATOR-LIABILITY.md)).

---

## 4. Honest framing and governance

**Recruiting operators you don't control means you cannot guarantee their behavior — and that is
exactly the point.** A relay the maintainer can't take down, can't read, and can't be compelled to
control *on the maintainer's behalf* is a **genuinely separate seizure and trust surface**. That
separation is the entire value; a relay you secretly control adds none of it.

The cost of real independence is that the roster needs **governance**:

- **The roster is signed and expiring**, so a relay is only trusted while the maintainer keeps signing
  it in (`relay-roster.js` `verifyRelayRoster` enforces signature + `expires`). Membership is a
  standing, revocable act — not a permanent grant.
- **A misbehaving or non-serving relay can be dropped** by re-signing `relay-roster.json` without it
  (§2c) and letting the current roster expire out. No client change, no bundle rebuild.
- **Detection ties to the existing signed-head withholding check.** peerit's cross-relay reconciliation
  already flags a relay that withholds records against others' signed heads
  ([`BLINDSHARD-DESIGN.md` §4](BLINDSHARD-DESIGN.md), `relay-pool.js` `recoverRows`); as
  custody receipts land (BlindShard Phase 4) this extends to shards. **A relay caught withholding,
  serving tampered data (rejected client-side anyway), or violating §3 is a candidate for removal at the
  next re-sign.**

**The bar for adding the first independent operator is high and deliberate: pass §2d, sign §3, get
added to the roster.** That single onboarding takes the independent-entity count from 1 to 2 — the
minimum at which any of peerit's censorship-resistance and collusion-threshold claims stop being
vacuous — and starts the road to the ~6 independent operators BlindShard Phase 3 dispersal actually
needs.
