# Browser P2P patterns from Peerit

Peerit is a working notebook for building local-first, peer-to-peer applications
that also run in ordinary browsers. This catalogue records the patterns that held
up under implementation, failure injection, and adversarial tests.

It is deliberately not a claim that a browser needs no infrastructure. Browsers
often need relays, bootstrap artifacts, admission services, or an always-on
seeder for availability. The useful boundary is this:

> Infrastructure may move, retain, and announce bytes. It does not get to author
> user records or decide whether those bytes are valid.

The browser keeps the signing and verification boundary. Local state remains
usable when the network is absent. Network claims are shown only when the client
has evidence for them.

## Maturity labels

Every card carries one of these labels:

| Label | Meaning |
| --- | --- |
| **CORE / TESTED** | Present in the current source and covered by focused regression tests. This does not by itself prove a public deployment. |
| **BOUNDED RELEASE** | Present in an exact signed, source-pinned artifact with an accepted bounded-test decision. The evidence remains useful after time-bound authorities expire; the label does not claim current network availability, GA, or production readiness. |
| **INTEGRATION PROOF** | Exercised end to end with genuine client/protocol components in a local or controlled drill. Fleet availability and operator independence are not implied. |
| **DESIGN / UNPROVEN** | A specification, feasibility study, or proposed direction whose implementation gate is still open. |

“Tested” always means the linked property was tested. It does not silently widen
into anonymity, censorship resistance, completeness, independent operation, or
production readiness.

## The two delivery families

Peerit contains two useful delivery compositions. They converge at the same
locally signed operation and client-side admission boundary.

| Family | Shape | Current maturity |
| --- | --- | --- |
| Per-author outboxes | Each author writes one single-writer log; peers or relays replicate it; readers deterministically merge admitted records. | **CORE / TESTED** |
| Browser Cell + INBOX | The browser writes immutable content to Cell, verifies the receipt and readback, then appends a small encrypted discovery pointer to an already-created public INBOX. | **BOUNDED RELEASE** for the exact Sequence 29 contract; current activation is blocked pending authority rotation and runtime repair |

Do not force both paths into one transport abstraction. Share the operation
schema, signatures, admission rules, journal, and materialized view; keep each
transport's capabilities and recovery rules explicit.

## The Sequence 29 boundary

Sequence 29 is the strongest public browser-write evidence in this repository,
and its limits are part of the result.

- The signed decision accepted a **bounded public test**, not GA or production
  ([decision and claim boundary](deploy/canary-decision-peerit-seq29-limited-public-inbox-20260813.json#L1-L20)).
- It uses two owner-operated relays, `dal-1` and `syd-1`. Those are two replicas
  under one operator boundary, not proof of independent operators or independent
  failure domains
  ([activation topology](deploy/canary-decision-peerit-seq29-limited-public-inbox-20260813.json#L17-L40)).
- Browser authority is limited to `DESCRIBE.GET`, `DESCRIBE.CHALLENGE`,
  `CELL.GET`, `CELL.PUT`, `INBOX.APPEND`, and `INBOX.READ`. Browser
  `INBOX.CREATE`, `INBOX.RENEW`, and `INBOX.CLOSE` are forbidden
  ([operation boundary](deploy/canary-decision-peerit-seq29-limited-public-inbox-20260813.json#L24-L40)).
- Discovery uses one global public stripe with one physical topic per relay. It
  is not per-board, private, anonymous, or a completeness oracle
  ([honest contract](docs/SEQ29-LIMITED-PUBLIC-TEST-CONTRACT.md#L20-L45)).
- The test does not claim operator independence, censorship resistance, spam
  resistance, anonymity, completeness, or production readiness
  ([rejected claims](docs/SEQ29-LIMITED-PUBLIC-TEST-CONTRACT.md#L39-L45)).
- The GA gate remains blocked. The accepted decision reports the bounded test
  evidence separately from that gate
  ([decision evidence](deploy/canary-decision-peerit-seq29-limited-public-inbox-20260813.json#L68-L93)).

The signed closure and accepted evidence establish this bounded browser path:

```text
write
  local operation -> local signature/PoW -> durable publication journal
  -> CELL.PUT on each relay -> authenticated receipt + byte-exact CELL.GET readback
  -> encrypted signed pointer -> INBOX.APPEND on each relay

read
  verified signed bootstrap -> authenticated INBOX.READ from durable floor
  -> decrypt pointer -> validate signed AuthorBind
  -> same-relay CELL.GET -> intrinsic operation/author validation
  -> canonical local journal -> rebuildable materialized view
```

The full-stack drill exercises that chain, including tampered frames, unknown Cells,
idempotent replay, next-revision reads, two-relay discovery, and admission-token
spend discipline
([drill contract](test/peerit-inbox-pointer-discovery.mjs#L1-L39)).

That is release evidence, not a perpetual availability claim. On 2026-08-27 the
deployed artifact's sole INBOX epoch (`2954`) is stale relative to the required
current epoch (`2956`), and fresh signed-seed recovery also fails the exact
limited Cell-GET module check. The shipped verifier correctly leaves network
publication and discovery blocked. See
[`docs/CURRENT-STATUS.md`](docs/CURRENT-STATUS.md#what-is-deployed-versus-currently-active).

---

## Pattern 1 — Make the signed record authoritative, never its route

**Maturity: CORE / TESTED**

A relay, peer, cache, service worker, or outbox label is delivery context. None
of them proves who authored a record. Admission recomputes authority from the
record itself.

For every incoming record:

1. Recompute the semantic storage key from signed fields and require an exact
   match.
2. Require the signer key to match the operation's author/owner rule.
3. Verify the signature over a canonical envelope that covers every meaningful
   field.
4. Run app-specific validation, such as proof-of-work or size limits.
5. Resolve conflicts deterministically and independently of arrival order.

Peerit's admission path implements key binding, owner binding, signature checks,
and optional validation before merge
([implementation](js/gossip.js#L191-L266)). The regression suite relays forged
records under a victim's outbox, tampers signed content, changes storage keys,
tests deterministic winners, and proves tombstones are not resurrected
([security proof](test/gossip.mjs#L94-L184)). Opaque v2 records receive the same
signature and owner-binding treatment
([v2 tamper proof](test/gossip-v2.mjs#L75-L87)).

**Reusable rule:** transport can suggest bytes; only canonical verification can
admit them.

## Pattern 2 — Compose many writers from single-writer outboxes

**Maturity: CORE / TESTED**

When the underlying log is single-writer, do not emulate a server-owned global
multi-writer database. Give every author an outbox they alone can advance, then
derive the shared product view on each client.

The composition is:

```text
author A log --\
author B log ----> verify each record -> deterministic merge -> local read view
author C log --/
```

This removes a global write coordinator from the authority path while preserving
straightforward append ownership. It also makes moderation a signed overlay over
content, rather than permission to rewrite another author's history.

The load-bearing details are:

- ingest verification happens before a candidate can evict a real record;
- last-write-wins is deterministic, with a signature tiebreak;
- tombstones win equal-time ties;
- first-creator claims remain sticky rather than changing with relay order; and
- cached views are re-admitted on boot instead of being trusted because they are
  local.

Evidence: [merge implementation](js/gossip.js#L239-L266),
[order/ownership/tombstone tests](test/gossip.mjs#L153-L184), and
[forged-cache re-admission](test/gossip-rollback-guards.mjs#L257-L277).

**Known limit:** free identities still permit Sybil behavior. A deterministic
merge is not a reputation system or a global naming authority.

## Pattern 3 — Select a runtime by capabilities and precedence

**Maturity: CORE / TESTED**

“Browser” is not one environment. Peerit distinguishes a host-injected Pear
surface, a normal browser with locally held keys and remote availability, the
bounded blind substrate, and a local-only development fallback.

The selector follows two rules:

1. A more privileged path is selected only from an actual capability, never from
   user-agent sniffing.
2. A configured URL is a discovery hint, not proof that a relay is authenticated
   or compatible.

The replacement substrate is selected before legacy bridges when explicitly
declared, but an incomplete profile installs zero network delivery while keeping
the local journal writable
([network gate](js/runtime.js#L36-L67),
[cutover order](js/runtime.js#L200-L233)). Legacy web relay configuration remains
below a real host bridge, so static HTML cannot silently replace host identity or
networking
([runtime contract](js/runtime.js#L1-L17)).

Tests pin host precedence, local signing in ordinary web mode, read-only web
defaults, signed-roster plumbing, local fallback, and the fail-closed replacement
gate
([runtime proof](test/runtime.mjs#L35-L103)).

**Reusable rule:** return a structured capability/mode object. Do not collapse
`local`, `queued`, `relay reachable`, `verified delivery`, and `durable quorum`
into one `online` boolean.

## Pattern 4 — Keep identity local, lazy, and capability-shaped

**Maturity: CORE / TESTED**

Peerit uses three browser identity states:

| State | Purpose | Honest durability statement |
| --- | --- | --- |
| Lurker | Read without minting a signing identity. | No identity exists yet. |
| Device | Survive reload on this browser using an IndexedDB-stored, non-extractable WebCrypto wrapping key and encrypted seed. | Protects against passive storage reads through web APIs; it is not disk encryption. |
| Vault/export | Passphrase-sealed seed for explicit recovery or transfer. | Portable only when the user preserves the encrypted export and passphrase. |

The device tier documents its threat model, mobile eviction caveat, and atomic
put-if-absent rule that prevents two first-writing tabs from forking an identity
([identity tiers](js/identity-store.js#L1-L36),
[atomic IndexedDB write](js/identity-store.js#L200-L225)). Forgetting an identity
uses a durable tombstone across the IndexedDB/device and vault stores, so a crash
cannot resurrect a key halfway through deletion
([forget transaction](js/identity-store.js#L94-L155)). These properties are
exercised by the device-store failure and race suite
([device-store proof](test/identity-device-store.mjs#L1-L30),
[replacement and corruption races](test/identity-device-store.mjs#L108-L220),
[forget failures](test/identity-device-store.mjs#L226-L276)).

Inside Pear Browser, a per-app host identity signs without sending a seed through
the page bridge. The adapter restricts the namespace, validates the returned key
material, and fails if the key changes during a signing call
([host adapter](js/substrate/host-identity.js#L1-L9),
[signing boundary](js/substrate/host-identity.js#L101-L119)). Real-signature tests
prove `_dk` may identify the site while `_k` identifies the signer, that no seed
is exposed, and that older local-key records remain valid
([host identity proof](test/peerit-host-identity.mjs#L42-L70),
[failure cases](test/peerit-host-identity.mjs#L88-L122),
[wire compatibility](test/peerit-host-identity.mjs#L143-L163)).

**Reusable rule:** define identity by operations (`publicKey`, `sign`, recovery
capabilities), not by universal access to seed bytes.

## Pattern 5 — Persist the exact publication before the first network call

**Maturity: CORE / TESTED**

Browser suspension and ambiguous responses are normal, not exceptional. A write
must be recoverable after the page disappears between “relay durably applied it”
and “browser received the receipt.”

Peerit's durable publication state machine is:

```text
prepared
  -> exact signed envelope persisted and read back
  -> pending network delivery
  -> matching durable quorum evidence
  -> monotonic author floor persisted and read back
  -> local pending marker cleared
```

The complete envelope is persisted before I/O and later retries are byte-for-byte
identical. A different publication cannot overwrite the marker. Browser writers
serialize with Web Locks; if the browser cannot provide a safe cross-tab lock,
publishing fails closed instead of inventing a racy localStorage lease
([pending marker](js/gossip.js#L563-L668),
[cross-tab lock](js/gossip.js#L671-L723),
[persist-before-send](js/gossip.js#L2068-L2084)).

The tests prove:

- two matching receipts form the first publication quorum
  ([first commit](test/atomic-commit-client.mjs#L255-L280));
- response loss plus reload retries the exact commit id, signatures, head, and
  timestamps without reapplying it
  ([ambiguous response](test/atomic-commit-client.mjs#L360-L398));
- the marker cannot clear until the monotonic floor is durably stored
  ([floor persistence](test/atomic-commit-client.mjs#L452-L474));
- two tabs preserve one publication rather than overwrite each other
  ([cross-tab race](test/atomic-commit-client.mjs#L777-L815)); and
- a large encrypted body and its signed parent recover as one atomic batch
  ([multi-record atomicity](test/atomic-commit-client.mjs#L817-L850)).

**Reusable rule:** retry a durable intent, never reconstruct “something
equivalent” after an ambiguous send.

## Pattern 6 — Treat relay redundancy as evidence, not authority

**Maturity: CORE / TESTED**

Multiple relays improve availability and make rollback or withholding observable.
They do not make content valid; record verification still does that.

For writes, Peerit uses a stable leader from a signed roster to serialize the
compare-and-swap decision, then requires matching durable receipts from distinct
roster origins. A hanging mirror is bounded; leader failure fails closed. For an
ambiguous stale response, clearing the local intent requires two independently
observed exact censuses, not one relay claiming “already applied.”

Tests cover one-copy versus two-origin evidence, a hanging third relay, stable
leader choice, concurrent writers, and matching signed heads
([quorum evidence](test/atomic-commit-client.mjs#L400-L450),
[leader and CAS proof](test/atomic-commit-client.mjs#L648-L693)). The client saves
a monotonic signed-head floor and emits a separate integrity-status change when
a candidate rolls back or withholds data
([cached view, floor, and integrity state](js/gossip.js#L45-L75)).

**Reusable rule:** say exactly what the evidence proves: “two matching durable
copies on two roster origins” is stronger than “one relay acknowledged,” but it
is not automatically “independent operators” or “censorship resistant.”

## Pattern 7 — Separate immutable content from mutable discovery

**Maturity: BOUNDED RELEASE (Sequence 29; currently inactive network authority)**

Large signed operations and small discovery notices have different jobs. Sequence
29 stores operation bytes in content-addressed Cells and uses public INBOX only
for fixed-size encrypted announcements pointing to those Cells.

The browser does not manage topic lifecycle. A signed release bootstrap supplies
already-created open-append capabilities; ordinary browsers can seal and append
an announcement, but cannot create, renew, or close the INBOX
([publisher boundary](js/substrate/inbox-pointer-publish.mjs#L1-L16)). An
ambiguous append is restored only if the exact frame, request bytes, and request
commitment can be reproduced, then reconciled through an authenticated bounded
read
([append recovery](js/substrate/inbox-pointer-publish.mjs#L63-L115)).

On read, an accepted record crosses the entire chain: verified bootstrap,
authenticated INBOX result, authenticated encrypted frame, signed AuthorBind,
same-relay read capability, authenticated Cell read, then intrinsic operation
and author validation
([discovery chain](js/substrate/inbox-discovery.mjs#L1-L20)). The coordinator
requires independently verified results for the exact two-relay bootstrap and
re-decodes operation batches before journaling them
([sync authority](js/substrate/seq29-public-inbox-sync.mjs#L92-L150)).

**Reusable rule:** a discovery pointer is a hint with authenticated provenance;
the referenced content must still verify independently.

## Pattern 8 — Advance cursors only on deterministic evidence

**Maturity: BOUNDED RELEASE + INTEGRATION PROOF**

A durable cursor is an integrity decision. Advancing it after a timeout can hide
an entry forever; never advancing past authenticated bad content lets one corrupt
entry wedge the reader forever.

Sequence 29 distinguishes those cases:

- deterministically invalid content from an already authenticated INBOX entry may
  be recorded as rejected and the append floor may advance;
- network rejection, timeout, abort, missing authority, or local crypto/storage
  failure aborts the poll and leaves the durable floor unchanged for retry; and
- floors are monotonic and bound to the exact relay/bootstrap authority.

The distinction is explicit in the discovery implementation
([advanceable rejection rule](js/substrate/inbox-discovery.mjs#L22-L49)) and in
the read-side authority's floor checks
([floor validation](js/substrate/seq29-public-inbox-sync.mjs#L123-L150)). The
end-to-end drill proves both tampered-entry advancement and fresh-reader recovery
from an advanced floor
([negative and replay proof](test/peerit-inbox-pointer-discovery.mjs#L24-L39)).

**Reusable rule:** classify failures by whether authenticated evidence makes the
outcome deterministic. “An error occurred” is too coarse for a durable cursor.

## Pattern 9 — Keep the canonical log and derived read model separate

**Maturity: CORE / TESTED**

Signed admitted operations are the source of truth. Feed, thread, vote, member,
and social-graph indexes are local accelerators that can be discarded and
rebuilt.

Peerit's materialized index explicitly refuses source-of-truth status and keeps
wire-private opaque records separate from semantic local adjacency maps
([index boundary](js/materialized-index.js#L1-L8)). It indexes both directions of
social edges and patches an existing view after local writes
([index API](js/materialized-index.js#L58-L130)). Tests rebuild from the admitted
view, verify tombstones and semantic key authority, prove repeated reads do not
rescan the source, and prove local writes patch without a global rebuild
([index proof](test/materialized-index.mjs#L29-L85)).

**Reusable rule:** if deleting the index changes authority, it was not merely an
index. Checkpoints may accelerate replay, but must remain integrity-bound and
rebuildable.

## Pattern 10 — Make offline application code an atomic verified generation

**Maturity: CORE / TESTED**

A service worker can preserve an offline shell, but a partially updated shell is
dangerous: old code and new protocol metadata can disagree about what is trusted.

Peerit's generated worker binds the cache name to the complete canonical asset
manifest, verifies every candidate asset before the first Cache API write, keeps
release metadata in the same generation, and refuses to intercept cross-origin
relay calls
([worker generator](scripts/service-worker-source.mjs#L3-L27),
[atomic install](scripts/service-worker-source.mjs#L39-L75),
[fetch boundary](scripts/service-worker-source.mjs#L80-L105)). Failure-injection
tests prove a tampered candidate leaves the incumbent byte-identical and never
activates; a valid candidate stages within a bounded concurrency limit
([service-worker proof](test/service-worker-atomic.mjs#L92-L145)).

**Reusable rule:** cache static, manifest-pinned application bytes. Do not cache
relay APIs, identity responses, admission tokens, or mutable P2P truth as if they
were application assets.

## Pattern 11 — Expose evidence states in the product

**Maturity: CORE / TESTED (status surface)**

P2P UX should distinguish at least:

- local-only and safe to keep editing;
- queued locally;
- delivery attempted;
- durable quorum confirmed;
- retry scheduled;
- recovery identity required;
- degraded/partial read; and
- rollback or withholding evidence.

Peerit's status surface exposes atomic availability, pending commit id and author,
recovery-needed state, next retry time, withholding state, and per-outbox status
([status API](js/gossip.js#L2478-L2510)). The retry test asserts that pending
state carries a future retry time and recovers through the normal poll loop
([bounded retry](test/atomic-commit-client.mjs#L476-L489)). Integrity changes are
emitted separately from accepted content changes, preventing the UI from
presenting a rejected rollback as a real record mutation
([integrity event](js/gossip.js#L69-L72),
[integrity update](js/gossip.js#L2313-L2322)).

**Reusable rule:** UI copy should name the strongest verified state. “Sent” must
not stand in for “durably stored,” and “online” must not stand in for “complete.”

## Pattern 12 — Put abuse controls in admission, not relay trust

**Maturity: CORE / TESTED for local PoW validation; bounded admission in Sequence 29**

The generic merge accepts an application validator after cryptographic authority
checks. Peerit uses that seam for operation-bound proof-of-work and the bounded
Cell/INBOX path uses challenge-bound, one-use admission authority. Every reader
rechecks intrinsic operation validity; a relay accepting bytes does not waive
client policy.

The gossip tests prove a record whose identity changes after proof-of-work is
rejected at ingest
([PoW binding](test/gossip.mjs#L118-L125)). The controlled Sequence 29 integration
drill counts per-relay token redemption and proves its local creation phase mints
CREATE authority only when a topic is absent; this does not grant live browsers
the forbidden CREATE operation
([spend discipline](test/peerit-inbox-pointer-discovery.mjs#L35-L39)).

**Known limit:** admission cost is abuse friction, not identity uniqueness,
reputation, global spam prevention, or Sybil resistance.

## Pattern 13 — Keep private device state out of the replicated log

**Maturity: CORE / TESTED**

Not every useful product action is a public protocol event. Sort choice, hidden
and saved items, notification read position, backup acknowledgement, and a private
follow set can remain device-local. Replicating them by default leaks behavior,
expands conflict rules, and makes a network outage unnecessarily block local UX.

Peerit's preferences module states the boundary directly and namespaces local
state by active identity
([device-local boundary](js/prefs.js#L1-L28)). It deliberately keeps private
follows out of the public social graph and keeps notification read position as a
device-only marker
([private follows](js/prefs.js#L83-L101),
[read marker](js/prefs.js#L115-L118)). Smoke coverage verifies normalization,
deduplication, reload persistence, and malformed-storage cleanup
([preferences proof](test/smoke.mjs#L216-L247)).

**Reusable rule:** classify every field as replicated authority, rebuildable
derived state, or private device state. Do not put it on the wire merely because
the shared log is convenient.

---

## Anti-patterns and rejected claims

| Do not do or say this | Why it fails | Evidence boundary |
| --- | --- | --- |
| Trust a record because it came from the “right” relay or outbox. | Routes and labels are forgeable context. | [Victim-labelled forgery tests](test/gossip.mjs#L94-L114) |
| Rebuild a pending write after an ambiguous response. | A semantically similar request can have a different id, signature, nonce, or admission spend. | [Byte-exact reload retry](test/atomic-commit-client.mjs#L360-L398) |
| Clear local pending state after the first acknowledgement. | One copy is not the configured durable quorum, and the client loses its recovery intent. | [One-copy vs two-copy evidence](test/atomic-commit-client.mjs#L400-L433) |
| Use a localStorage lease as a cross-tab publication lock. | It cannot make refresh, compare, and persist atomic. | [Web Locks fail-closed rule](js/gossip.js#L671-L705) |
| Advance a cursor on timeout or network failure. | The skipped entry may never be observed again. | [Floor-preserving error classification](js/substrate/inbox-discovery.mjs#L35-L49) |
| Treat an INBOX pointer, receipt, or bootstrap shape as content authority. | Each is one link in a longer authenticated chain. | [Exact discovery chain](js/substrate/inbox-discovery.mjs#L1-L20) |
| Let an ordinary browser create or manage Sequence 29 topics. | Management keys stay offline; browser lifecycle operations are forbidden. | [Activation boundary](deploy/canary-decision-peerit-seq29-limited-public-inbox-20260813.json#L24-L40) |
| Call the Sequence 29 topics per-board or private. | The accepted contract uses one global public stripe and two physical topics. | [Honest contract](docs/SEQ29-LIMITED-PUBLIC-TEST-CONTRACT.md#L20-L37) |
| Call two owner-operated relays independent operators. | Replica count and operator independence are different claims. | [Operator boundary](docs/SEQ29-LIMITED-PUBLIC-TEST-CONTRACT.md#L20-L25) |
| Say “no servers” when relays or admission services are in the availability path. | Authority can be serverless without availability infrastructure being absent. | [Allowed operation/topology decision](deploy/canary-decision-peerit-seq29-limited-public-inbox-20260813.json#L17-L40) |
| Say “anonymous,” “censorship resistant,” “complete,” “trustless,” or “production ready” without the named proof. | Sequence 29 explicitly rejects those widened claims. | [Rejected claims](docs/SEQ29-LIMITED-PUBLIC-TEST-CONTRACT.md#L39-L45) |
| Treat a non-extractable WebCrypto key as disk encryption. | Browser profile or filesystem access can recover/use more than a passive same-origin storage dump. | [Identity threat model](js/identity-store.js#L12-L26) |
| Cache relay traffic in the service worker. | It mixes mutable network evidence with a pinned application generation. | [Same-origin asset-only fetch boundary](scripts/service-worker-source.mjs#L80-L105) |
| Replicate preferences, read markers, or private follows by default. | Convenience is not authority; this leaks behavior and creates needless distributed conflicts. | [Device-local state boundary](js/prefs.js#L1-L18) |

## Research directions, not shipped claims

These ideas may be valuable, but this catalogue does not promote them to working
patterns yet:

- **Direct Hypercore 11 storage in a stock browser:** the RocksDB-compatible
  IndexedDB document says the feasibility spike has not started and requires real
  crash, quota, iterator, snapshot, and multi-tab evidence
  ([discovery status](docs/ROCKSDB-IDB-BROWSER-STORAGE-DISCOVERY.md#L1-L33)).
- **OHTTP/Protomux split transport:** the specification labels itself an
  implementation draft and explicitly excludes several privacy properties
  ([draft status and scope](docs/SPLIT-TRANSPORT-SPEC-V1-2026-07-26.md#L1-L24)).
- **A generic blind-v1 cutover:** the runtime intentionally keeps the local
  journal but installs zero relays while the generic profile gate is incomplete
  ([closed-gate proof](test/runtime.mjs#L50-L67)). The narrower Sequence 29
  authority must not be widened into a generic substrate-readiness claim.
- **Independent-operation, completeness, anonymity, censorship-resistance, and
  GA claims:** all remain outside the accepted Sequence 29 boundary.

## A compact implementation checklist

Before calling a browser P2P write path complete, be able to answer “yes” with a
linked test or signed decision for each item:

- [ ] Does the client sign locally or through a seedless, namespace-scoped host
      signer?
- [ ] Does ingest recompute storage key, owner, signature, and app-specific
      admission constraints?
- [ ] Is the complete signed intent durable before the first network call?
- [ ] Can an ambiguous send be retried byte-for-byte after reload?
- [ ] Are cross-tab writers serialized by an actually atomic primitive?
- [ ] Does clearing pending state require the configured durability evidence and
      a persisted monotonic floor?
- [ ] Are relay descriptors/topology authenticated before authority is granted?
- [ ] Are content storage and discovery pointers independently verified?
- [ ] Do transient failures preserve cursors for retry while deterministic bad
      entries can be quarantined and passed?
- [ ] Is every local read index disposable and rebuildable from admitted records?
- [ ] Is each field explicitly classified as replicated, derived, or private
      device state?
- [ ] Does offline caching activate only a complete verified application
      generation and leave relay traffic alone?
- [ ] Does the UI distinguish local, queued, attempted, confirmed, degraded, and
      recovery-needed states?
- [ ] Does the public claim stop exactly where the evidence stops?

That last check is architectural, not editorial. In a P2P system, honest state
and honest limits are part of the protocol users rely on.
