# Peerit Blind Substrate — Replacement Delivery Map

**Status:** implementation map; subordinate to
`PEERIT-BLIND-SUBSTRATE-PROFILE.md`

**Date:** 2026-07-11

This map turns Peerit's signed blind-substrate profile into repository work. It
confirms a complete replacement of Peerit's live network and persistence path,
while preserving the application protocol and product behavior that correctly
belong in Peerit.

The end state is not “old Peerit plus a new relay option.” Peerit's only native
production path uses `hiverelay-blind/1`. OutboxLog, BlindShard, the semantic
Pear bridge, and the current relay-pool protocol become bounded migration readers
and archive importers, then leave the runtime bundle after signed retirement.

---

## 1. Preserve, replace, and retire

### Preserve as Peerit authority

These responsibilities remain application-side and continue to be tested as
Peerit behavior:

- `js/model.js`: record types, immutable content identities, graph relations;
- `js/canon.js` and `js/verify.js`: canonical application signing and validation;
- `js/data.js`: user intentions, domain validation, CRUD/query surface;
- `js/ranking.js` and `js/materialized-index.js`: local ranking and derived views;
- identity, recovery, device fencing, moderation, preferences, and UI modules;
- lurker-by-default startup and explicit writer activation;
- deterministic conflict/merge rules and rollback floors.

Preserving a file does not freeze its internals. App-aware network assumptions,
legacy blob dispersal, and relay-shaped status inside a preserved module still
move behind the new substrate boundary.

### Replace as the native network/persistence path

The following current responsibilities are replaced, not retained as alternate
production modes:

- `js/sync.js` bridge/gossip selection;
- `js/gossip.js` OutboxLog aggregation and announcement flow;
- `js/relay-pool.js` semantic atomic commit and range APIs;
- `js/relay-roster.js` app-specific relay topology/capability probing;
- `js/pear-api.js` semantic `/api/sync/*` and related bridge calls;
- `js/lazy-pool.js` current writable relay activation;
- current DHT/bridge adapters where they expose application-shaped storage;
- BlindShard dealer, roster, custody, and dispersal write paths;
- live dependencies on a global Peerit outbox endpoint or Peerit relay namespace.

### Retire after signed migration evidence

Legacy readers, census code, archive fetchers, and verification helpers remain in
a separately identifiable migration closure only for the stages recorded by the
signed release pin. They cannot accept new writes after cutoff, cannot be selected
as a fallback by a strict writer, and are removed from the final browser/Pear
runtime after archive retirement evidence passes.

---

## 2. New Peerit module boundary

The replacement is implemented behind a single app-side sync boundary so the
domain layer never learns HTTP routes, relay schemas, or storage capabilities.

```text
Data + identity + app validation + local indexes
                       |
             PeeritSubstrateSync
                       |
 compatibility pin / discovery sources / intent journal / replica policy
                       |
       bundled @hiverelay/blind-client runtime adapter
                       |
       independent generic HiveRelay endpoints
```

The planned source ownership is:

| Module | Responsibility | Must not contain |
| --- | --- | --- |
| `js/substrate/profile-registry.js` | Exact Peerit profile codecs, domains, limits, and profile ABI hash | Relay implementation code |
| `js/substrate/release-pin.js` | Verify static ABI/vectors, artifact provenance, migration stage, and downgrade evidence | Authoring permission, relay allowlists, or network fallback heuristics |
| `js/substrate/descriptor-set.js` | Discover and verify independent relay identities/endpoints and generic readiness | Peerit namespace/plugin negotiation |
| `js/substrate/transport.js` | Bind the generic SDK to direct/split/Tor browser or Pear transport | Application record parsing |
| `js/substrate/cell-replicas.js` | Create/read/prove/renew/drop independently randomized replicas | Semantic IDs in relay requests |
| `js/substrate/core-replicas.js` | Encrypted per-device Core append/availability/readback | Shared application writer key |
| `js/substrate/inbox.js` | Opaque rendezvous stripes and encrypted announcements | Public semantic directory |
| `js/substrate/intent-journal.js` | Persist exact logical intent/capabilities and reconcile ambiguous outcomes | Fire-and-forget retry |
| `js/substrate/availability.js` | Policy durability, operator diversity, readback, repair, floors | Relay-majority application truth |
| `js/substrate/discovery.js` | Reconstruct verified Peerit discovery objects from generic storage | Relay-supplied semantic authority |
| `js/substrate/sync.js` | Present `ready/append/get/list/range/count/status/onChange` to `Data` | Legacy protocol selection |
| `js/substrate/local-writer.js` | Lurker state, explicit opt-in, offline signing/journal/local materialization, cross-tab writer fence | Release, registry, relay-count, durability, or discovery permission checks |
| `js/substrate/migration-importer.js` | Read/verify frozen legacy sources and emit deterministic migration objects | Any legacy write operation |

Names may change during implementation, but these ownership boundaries and
forbidden dependencies do not.

### 2.1 Current browser-consumer gate

`js/substrate/relay-consumer.js` is the current release-graph seam. It accepts
recommendation, user, peer, and DHT observations as equally untrusted hints, but
installs an empty `sync.setRelays([])` result while the exact consumer authority
is incomplete. This is intentional: the repository now contains the deterministic
full profile registry and vectors plus a fixture-only static release-control
verifier and a complete signed pin-history continuity verifier, but not the final
HiveRelay tuple, authenticated browser build of
`@hiverelay/blind-client`, permissionless candidate feeds/CSP, or portable Cell
management-capability recovery required before sending.

A raw URL never crosses this gate. Active integration must use one shared
`DescriptorTrustStore` and `BlindRelayQualifier`, bind fresh health to the exact
endpoint and one-hot transport bit, deduplicate by continuity root, quarantine
descriptor forks, and only then construct relay adapters. Zero qualified relays
keeps publication queued; one qualified relay is enough for truthful
single-replica delivery. No legacy transport is an eligibility fallback.

`js/substrate/relay-requalification-scheduler.js` now owns the authenticated
adapter lifecycle after first qualification. It atomically swaps only branded
targets, refreshes before the earlier verified-health or signed-epoch deadline,
retains an old target through a transient refresh failure only while that target
is still authorized, revokes it at the exact deadline, coalesces concurrent
refreshes, and discards completions after stop/restart. The page lifecycle stops
and revokes the scheduler before destroying sync. This clears only the scheduler
assembly blocker; a production runtime authority and exact epoch-clock binding
are still absent, so the live installer remains fail closed.

### 2.2 Profile registry, codecs, validator, and signed continuity delivered

`js/substrate/release-control-{primitives,registry,codec,verifier}.mjs` now makes
the four release-control records and migration enum executable. The deterministic
generator checks in `protocol/peerit-release-control-v1.cenc`, eleven fixture
vectors, and their canonical HiveRelay-format vector manifest. Tests cover exact
expected tuple/profile/application hashes, Ed25519 domains, key IDs, pin and
checkpoint hashes, +1 continuity, module-branded suffix anchors, frozen migration
state, and wrong-key/fork/gap/downgrade negatives.

`js/substrate/release-authority-transition.mjs` and the continuation path in
`js/substrate/release-control-verifier.mjs` now implement the full-profile
`PeeritReleaseAuthorityTransitionV1` record. A continuation must start from an
exact module-branded verified terminal, advance pin and checkpoint sequences by
one, preserve both predecessor chains, and reject a conflicting witnessed hash.
The first pin under a new key must name one exact transition whose commitment is
signed by both the old and new authorities and whose activation release equals
that pin. This permits previously unknown newer signed pins without trusting a
relay-supplied expected projection. A separately branded terminal-snapshot getter
exposes fresh copies of the exact terminal pin bytes, pin hash, checkpoint hash,
and sequence for later runtime-authority assembly without making that snapshot a
continuation anchor. `pin-history-witness-backend.mjs` now persists those exact
verified bytes in encrypted IndexedDB with atomic cross-context CAS, authenticated
compaction, corruption/reset failure, and in-process whole-record rollback
detection. Portable external rollback recovery and continuity after complete
origin-storage eviction remain distinct product blockers. This persistence does
not pin the production key or final HiveRelay tuple.

The non-fixture `scripts/generate-peerit-profile.mjs` now separately produces
`protocol/peerit-profile-v1.cenc`, one exact vector for each of the 77 profile
declarations, and the canonical vector manifest. It embeds and domain-binds the
exact profile source and verified inventory; the release-control slice's first
four tags equal the full registry tags. Reproducible `--check`, corruption,
substitution, ordering, duplicate, truncation, and source/inventory drift tests
are executable.

All 77 structural codecs and the 234-vector validator artifact now reproduce
under Node, Bare, and Chromium. Contextual whole-graph validation of fetched
evidence, authority chains, threshold proofs, custody, and archive reconstruction
remains incomplete. The artifacts are not yet composed into the authenticated
browser product, and fixture keys are never production inputs. Nothing in these
artifacts selects a relay, authorizes a writer, re-enables a legacy fallback, or
changes `peerit.site`.

### 2.3 Local publication state machine delivered

The local-first publication state machine is now executable rather than a profile
placeholder. A fresh lurker performs no identity or IndexedDB write; the first
explicit signed post, comment, or vote commits its exact intent and materialized
view atomically before networking. Zero relays queues without disabling authoring.
Prepared, delivering, retryable, terminal, and ambiguous outcomes survive reload;
an ambiguous send cannot be retransmitted until exact same-target reconciliation.
Cross-instance claims use IndexedDB transactions rather than Web Locks, verified
acknowledgement evidence commits before completion, and compaction retains every
unresolved state plus bounded idempotency tombstones.

The deterministic journal/publication suites currently cover 75 adversarial state
machine checks, and the in-app Chromium IndexedDB gate covers nine more checks for
dormant boot, concurrent commits/deduplication/claim ownership, schema bounds,
restart persistence, migration, source cleanup, and corruption failure. This
clears only `OFFLINE_PUBLICATION_STATE_MACHINE_UNIMPLEMENTED`; relay qualification,
the final profile, portable capability recovery, durability, discovery, and full
runtime cutover remain separate gates.

### 2.4 Availability policy artifact delivered

`protocol/availability-policy-v1.cenc` now contains the exact 97-byte canonical
`AvailabilityPolicyV1` record at full-profile tag 276. Its codec fixes all 64
policy fields, rejects missing, extra, symbolic, accessor, nonconstant,
noncanonical, truncated, trailing, and every single-byte-mutated representation,
and binds the tag, ordinal, and source hash to the non-fixture profile registry.
The checked HiveRelay conventions deliberately encode durability profiles 1 and
2 as the generic ID-indexed bitmap `0x06`, while Inbox frame classes 1 and 2 use
that family's explicit class-minus-one bitmap `0x03`; L90 is class 4 and R30 is
class 3.
The domain-separated policy hash is
`268c0eb215b3e538dc7655abefd6c3cf9a20f92a6de7067e459f4914ca70f83c`.
This clears only `AVAILABILITY_POLICY_ARTIFACT_MISSING`; executable codecs for the
other profile records, the validator, final substrate tuple, and cross-runtime
equality remain blocked. Signed pin continuity is delivered separately in the
preceding release-control section.

### 2.5 Composed product release gate

`js/substrate/product-release-status.mjs` is the public-release boundary. The
profile status remains scoped to profile codecs, vectors, validator, policy, and
pin-continuity slices; it cannot authorize a deployment by itself. The composed
gate additionally requires the signed production emit tuple and release
authority, an authenticated blind-client browser artifact bound by that pin, the
assembled Peerit runtime consumer, production-ready HiveRelay daemon and store,
contextual graph validation, and portable rollback/post-eviction pin recovery.

`scripts/web-release.mjs`, `ship.mjs`, and direct non-local `publish.mjs` all call
this gate before building, signing, loading a network client, or publishing. The
current production key and tuple fields are deliberately `null`, not inferred
from the final WIRE hashes or `deploy/web-release.json`; every unfinished
component therefore remains an explicit fail-closed blocker.

---

## 3. Data flow

### Read boot

1. Load the last compatible profile provenance, every source-scoped discovery
   floor, the outbox journal, and the local verified view.
2. Start in lurker state without creating an identity, storage capability,
   admission token, writer Core, or background mutation.
3. Opportunistically fetch and verify newer compatibility/migration material and
   generic relay descriptors with strict byte/time bounds; offline failure does not
   block local reads or later authoring.
4. Refresh and union signed discovery objects from any number of independent roots,
   public Inboxes, and direct shares through generic read capabilities.
5. Retrieve ciphertext from selected relays, verify generic response bindings,
   decrypt locally, validate Peerit records, and apply deterministic merge.
6. Update only the local materialized view and emit `onChange`.

Read availability can degrade per relay or object without turning the entire app
into a relay-defined “read-only mode.” Lurker is a client state.

### First explicit write

1. The user chooses post, comment, vote, moderation, community creation, or
   another mutation.
2. `local-writer` validates local codec/cryptography/author continuity, commits or
   restores the encrypted identity, and takes the cross-tab fence without network
   permission.
3. Peerit builds, signs, journals, and locally materializes exactly one logical
   application event, even offline.
4. The delivery planner selects zero or more compatible targets. Zero targets
   yields `queued-no-relay`; compatible unregistered relays are usable.
5. `intent-journal` records each independently randomized relay attempt, request
   identity, capability/ciphertext, and reconciliation state before send.
6. The generic client sends only canonical opaque operations. One verified relay
   acknowledgement is truthful remote storage; further proofs qualify durability.
7. Discovery propagation through Inbox, direct share, and independent indexes is
   attempted separately and never controls the author event.
8. The UI reports local, relay-delivery, durability, and discovery state as four
   independent axes.
9. A timeout after send remains ambiguous until exact reconciliation; it never
   becomes a second post, comment, or vote.

Cancellation before send returns to a pristine lurker if no previous identity was
present. Cancellation or failure after possible send retains enough encrypted
local intent to reconcile safely.

---

## 4. Runtime variants

All runtimes validate the same profile and application bytes. Only transport and
local persistence adapters differ.

| Runtime | Native composition |
| --- | --- |
| Ordinary browser | Fixed encrypted cells, opaque Inbox, IndexedDB intent/capability vault, direct HTTPS baseline, gated split-web option |
| Pear/Bare | Encrypted per-device Core plus cells/Inbox where required, native local vault, direct or gated split-native/Tor |
| Node tools/tests | Same canonical codecs and state machines with injected clock, transport, filesystem, and fault controls |

The browser bundle cannot import Node/Bare native modules or secret-bearing
operator code. The Pear/Node bundle cannot silently accept a different ABI or
profile merely because it has more capable transports.

---

## 5. Delivery increments

Each increment must finish with independently repeatable evidence before the next
one can authorize a public claim.

| Increment | Code outcome | Exit evidence |
| --- | --- | --- |
| A. Authority-separated profile | Executable Peerit profile inventory, canonical vectors, static pin verifier, four-axis state contract | Node/Bare/browser byte equality; deleted central-authority schemas cannot reappear |
| B. Local sync | `PeeritSubstrateSync` over an in-memory generic relay simulator; domain layer unchanged | Full current CRUD/merge/ranking suite passes without legacy network imports |
| C. Durable cells | Browser cell replicas, capability vault, intent journal, direct transport, prove/readback/renew/drop | Restart, response-loss, quota, lease, tamper, partial-replica, and multi-tab tests |
| D. Discovery/Inbox | Encrypted announcements, multiple signed discovery roots, Inboxes, direct shares, source-scoped floors, repair policy | Cold/returning union from independent sources; total discovery outage still permits local authoring/direct delivery |
| E. Blind Core | Pear/Bare encrypted device chains and replicas | Multi-device fork/merge, writer loss, repair, restore-with-new-writer tests |
| F. Privacy adapters | Split web/native and Tor transport gates | Packet capture, adjacent-role collusion, downgrade, latency, and claim tests |
| G. Migration | Deterministic legacy importer, census, cutoff, archive evidence, no legacy writer | Static migration stages, omission/fork/restart/cutoff/retirement exercises; blind writing remains independent |
| H. Final bundle | Legacy runtime closure removed; compatibility pin qualifies the build but never enables writers | Bundle scan, offline fresh-lurker first post/comment/vote, zero-relay queue, unregistered-relay delivery, seven-day soak |

Production distribution and live-site mutation remain a separate release action.
Telemetry channels may control which artifact is offered by default, but neither
they nor the signed pin authorize a user, relay, or discovery source.

---

## 6. Cross-application reuse

Only the following pieces are Peerit-specific:

- the profile registry and release authorities;
- record encoding/signatures, discovery objects, merge, moderation, ranking,
  identity, recovery, UI, and migration importer;
- the selected replica/durability policy and honest product claims.

The generic SDK, relay descriptors, WIRE/PRIVATE_IPC, edge, daemon, storage,
admission, receipts, proofs, transport adapters, image hardening, and relay load
tests belong in HiveRelay. A second application supplies a different client
profile and retains its own semantics; it does not fork or configure the relay.

That is the reusable ecosystem improvement: relays scale and harden once, while
applications remain sovereign and can migrate independently.

---

## 7. Non-negotiable completion checks

The replacement is not ready for live cutover until all of these are true:

- the final relay edge/daemon bytes, stores, filenames, logs, metrics, and crash
  output contain no Peerit sentinel or semantic field;
- Peerit can cold-read and explicitly write through relays installed without any
  Peerit code or configuration;
- one compatible unregistered relay can store/read a post with no release,
  registry, profile-2, maintainer, or discovery approval; stronger three-target
  evidence qualifies only the configured durability claim;
- lurker boot is side-effect free and explicit opt-in can post, comment, and vote
  offline, with zero relays queueing rather than blocking;
- every ambiguous outcome survives reload/restart and reconciles without logical
  duplication;
- direct transport is never presented as source anonymity, while each stronger
  privacy mode passes its own capture/collusion gate;
- old/new client and relay combinations fail visibly rather than downgrading;
- the signed migration stage, cutoff, archive, and rollback evidence reproduce from
  content-addressed evidence; and
- the final production bundle and default start path have no legacy network or
  write fallback.
