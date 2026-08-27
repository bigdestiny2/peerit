# Peerit current status

- **Last reconciled:** 2026-08-27
- **Application-code baseline reconciled:** `6d87ba3a3beb0cbebd4c754520b62f25721d66c2`
- **Deployed signed public artifact:** Sequence 29, internally coherent
- **Decision boundary:** `LIVE_PUBLIC_TEST_ONLY`
- **Current network activation:** blocked pending a signed public-INBOX rotation and runtime repair

This page is the short, human-readable status authority for the repository. It
does not supersede signed artifacts, normative protocol documents, or release
decisions. If prose here conflicts with those inputs, the signed artifact and
its accepted decision win and this page must be corrected.

## Status at a glance

| Surface | Status | Evidence |
| --- | --- | --- |
| Deployed signed browser artifact | **Sequence 29 is served and internally coherent** | [`deploy/web-release.json`](../deploy/web-release.json#L1-L13), [signed manifest](../web/asset-manifest.json), [accepted decision](../deploy/canary-decision-peerit-seq29-limited-public-inbox-20260813.json#L1-L19) |
| Public-INBOX publication and discovery | **Currently blocked: signed epoch 2954 ended 2026-08-20; current epoch is 2956** | [signed bootstrap](../web/peerit-limited-public-inbox-bootstrap-v1.json), [wall-clock epoch check](../web/js/substrate/public-inbox-boot-coordinator.mjs#L1304-L1308), [normative rotation rule](./SEQ29-LIMITED-PUBLIC-TEST-CONTRACT.md#L113-L129) |
| Fresh signed-seed recovery | **Currently blocked by the signed runtime's exact Cell-GET control-surface check** | [fail-closed entry](../web/js/substrate/app-entry.js#L313-L334), [exact module check](../web/js/substrate/relay-consumer.js#L1237-L1248) |
| Historical decision/build audit | **Authenticates the pinned Sequence 29 authority at its canonical decision time; live runtime expiry remains independent** | [cutover assertions](../test/peerit-cutover-gates.mjs), [build closure](../test/peerit-substrate-build-closure.mjs), [decision verifier](../scripts/seq29-owner-decision.mjs) |
| General availability | **Blocked** | [decision boundary](../deploy/canary-decision-peerit-seq29-limited-public-inbox-20260813.json#L37-L40), [product gate](../js/substrate/product-release-status.mjs#L137-L173) |
| Public-test operator topology | **Two owner-operated relays; not independent operators** | [contract](./SEQ29-LIMITED-PUBLIC-TEST-CONTRACT.md#L20-L45) |
| Signed app entry | **Replacement-only blind substrate UI** | [`web/index.html`](../web/index.html#L11-L25), [artifact identity](../web/peerit-app-artifact-v1.json#L1-L21) |
| Root development entry | **Legacy `js/app.js`; not release parity** | [`index.html`](../index.html#L14-L20), [release build replacement](../scripts/substrate-runtime-artifact.mjs#L732-L764) |
| Browser-local identity in Sequence 29 | **Shipped** | [signed runtime](../web/js/substrate/peerit-product-runtime.js#L85-L129), [signed UI](../web/js/substrate/peerit-product-ui.js#L246-L250) |
| Pear host identity | **Implemented on `main`; not in Sequence 29** | [source entry](../js/substrate/app-entry.js#L204-L218), [adapter](../js/substrate/host-identity.js#L25-L124), [signed entry lacks it](../web/js/substrate/app-entry.js#L203-L209) |
| Direct host P2P / signed-outbox runtime | **Legacy or experimental in this release context** | [runtime selector](../js/runtime.js#L1-L25), [excluded release files](../test/peerit-substrate-build-closure.mjs#L370-L391) |
| BlindShard and DHT-over-WebSocket paths | **Research/experimental, not Sequence 29 closure** | [excluded release files](../test/peerit-substrate-build-closure.mjs#L370-L377), [pattern catalogue](./ARCHITECTURE.md#pattern-catalogue) |

## What is deployed versus currently active

The site is live and serves the exact coherent Sequence 29 bytes. Its
replacement UI and local journal load, local authoring remains available, and a
returning browser may still have previously materialized content. That does not
mean every signed network authority remains current.

The accepted Sequence 29 decision authorized the exact source-pinned artifact
and, during its active epoch, allowed these browser operations:

- `DESCRIBE.GET` and `DESCRIBE.CHALLENGE`;
- `CELL.GET` and `CELL.PUT`; and
- `INBOX.APPEND` and `INBOX.READ`.

The browser is forbidden from performing `INBOX.CREATE`, `INBOX.RENEW`, or
`INBOX.CLOSE`, and it receives no INBOX management seed. These are release
controls, not merely UI conventions
([decision](../deploy/canary-decision-peerit-seq29-limited-public-inbox-20260813.json#L17-L40),
[runtime test](../test/peerit-seq29-public-inbox-runtime.mjs#L113-L136)).

The deployed bootstrap contains only inbox epoch `2954`. Under the normative
six-hour lease epoch and 28-epoch rotation rule, that epoch was current from
2026-08-13T00:00:00Z through 2026-08-20T00:00:00Z. On 2026-08-27 the current
epoch is `2956`. The shipped coordinator verifies against wall-clock time and
therefore rejects the old epoch before installing its publisher or discovery
reader. This is the intended fail-closed behavior; restoring network activation
requires a separately signed rotation successor, not a documentation or test
exception.

Repository audit code separately reconstructs the accepted owner decision and
artifact closure at its canonical `decided_at` instant. That historical check
answers whether the signed authority was valid when it was accepted; it cannot
extend the signed authority or alter the browser runtime's current wall-clock
decision.

A fresh runtime check also currently stops signed-seed recovery because the
authenticated limited Cell-GET module does not match the exact two-export
surface required by the shipped consumer. Consequently the safe present-tense
claim is: **Sequence 29 is deployed and locally usable, while fresh network
publication, public-INBOX discovery, and signed-seed recovery are blocked.**

The deployed artifact contains:

- one logical stripe;
- two physical INBOX topics;
- two distinct relay keys, stores, and signed topic bindings for epoch 2954;
- a global public-discovery topic scope; and
- a 39-record signed seed.

It does not claim the production 24-binding topology, operator independence,
completeness, censorship resistance, anonymity, spam resistance, or production
readiness
([contract](./SEQ29-LIMITED-PUBLIC-TEST-CONTRACT.md#L20-L45),
[accepted artifact evidence](../deploy/canary-decision-peerit-seq29-limited-public-inbox-20260813.json#L42-L66)).

## Shipped product surface

The signed replacement UI exposes home, community, post, create-community,
submit-post, own-profile, and local-search routes
([signed route dispatch](../web/js/substrate/peerit-product-ui.js#L267-L275)).
Within that bounded UI, users can locally:

- read an already materialized verified local view;
- create a community, text or link post, comment, or profile;
- vote, report, vouch, edit, and delete;
- select feed algorithms and moderation views; and
- retain an interrupted explicit publication as exact durable local intent.

The signed code contains the bounded publication and recovery compositions, but
the current operational blockers above prevent a fresh client from completing
those network paths today.

This is not a promise of parity with every feature in the legacy `js/app.js`
interface. Settings, identity export/import workflows, saved/hidden items,
subscriptions, inbox/notification UI, and the older moderator administration UI
are not routes in the signed replacement UI. Describe those features as legacy
or planned unless they enter a later signed closure.

### Local-first authoring

The replacement runtime opens as a lurker without reading or creating an
identity database. On the first explicit mutation it persists or adopts a
device writer, signs the operation, and commits the local view before network
publication
([runtime](../js/substrate/peerit-product-runtime.js#L85-L129)). The journal uses
transactional backends and bounded state
([journal contract](../js/substrate/peerit-journal.js#L1-L42)).

The Sequence 29 publication design is intentionally user-driven. The UI hands off one
exact committed intent; an interrupted attempt leaves a durable retry marker,
and reload does not silently retry network mutation
([explicit-publication test](../test/peerit-seq29-explicit-user-publication-ui.mjs#L146-L174),
[reload behavior](../test/peerit-seq29-explicit-user-publication-ui.mjs#L176-L199)).

## On `main`, not in the signed release

The two commits after the checked-in Sequence 29 release work added a host-owned
identity adapter and wired it into the replacement entry. The current source:

- detects an identity-capable `window.pear.identity`;
- asks the host for a per-app public key and site drive key;
- delegates signing to the host without receiving a seed;
- keeps device identity storage untouched for host-backed local writes; and
- verifies host-signed records through the existing record verifier.

Evidence:

- [host adapter](../js/substrate/host-identity.js#L1-L124)
- [entry selection](../js/substrate/app-entry.js#L204-L218)
- [product-runtime host boundary](../js/substrate/peerit-product-runtime.js#L100-L129)
- [record round-trip test](../test/peerit-host-identity.mjs#L42-L70)
- [zero device-store I/O test](../test/peerit-product-runtime.mjs#L243-L285)

The exact signed Sequence 29 artifact does not import this adapter. Its entry
constructs `createPeeritProductRuntimeV1()` with no host identity
([signed entry](../web/js/substrate/app-entry.js#L203-L209)), and the signed
manifest enumerates the release closure without `host-identity.js`
([manifest](../web/asset-manifest.json#L27-L56)).

Accordingly, the accurate wording is:

> Pear host-backed record signing is implemented and tested on `main`; it is not
> part of the signed Sequence 29 public artifact.

Do not call it released until a later sequence includes the adapter, passes the
release closure, receives signatures, and has an accepted activation decision.
Also do not infer a complete host key-lifecycle or public-publication feature:
the adapter deliberately leaves lifecycle operations with the host and rejects
unsupported operations
([boundary](../js/substrate/host-identity.js#L66-L99)). In particular, the host
adapter currently rejects `signAuthorBindV1`, while the Sequence 29 publication
authority calls it before public delivery
([host adapter](../js/substrate/host-identity.js#L85-L100),
[publication authority](../js/substrate/peerit-product-runtime.js#L218-L223)).
The source evidence supports host-backed local record signing, not end-to-end
host-backed Sequence 29 publication.

## Open release boundaries

The repository's composed product gate is intentionally stricter than the
Sequence 29 bounded-test decision. It currently reports `releaseReady: false`
and retains explicit blockers, including:

- canonical service-worker compare-and-swap completion;
- a production HiveRelay product tuple and release authority;
- a complete authenticated production browser consumer;
- production daemon and store evidence;
- portable pin-history rollback recovery; and
- post-eviction pin-continuity recovery.

The exact computed list is code, not prose
([status construction](../js/substrate/product-release-status.mjs#L75-L153));
the gate test requires those blockers to remain visible
([test](../test/peerit-product-release-gate.mjs#L16-L61)).

Other honest limits remain:

- the current public-INBOX rotation and limited Cell-GET runtime blockers must
  be resolved in a new signed artifact/rotation before network claims resume;
- the two relays share one operator boundary;
- relay-visible timing, endpoint, size-band, transport, and presented-capability
  metadata are not hidden;
- a relay may withhold or delay traffic even though it cannot make an invalid
  record pass client verification;
- a normal browser depends on origin-delivered bootstrap code on first visit;
- device-local identity and data remain device-scoped unless an explicitly
  supported recovery or host path applies; and
- free keys are not one-human-one-account Sybil resistance.

## Source, artifact, and test evidence

The root source page and signed output are intentionally different artifacts:

```text
root index.html                 signed web/index.html
      |                                  |
      v                                  v
js/app.js (legacy/dev)         js/substrate/app-entry.js
                                         |
                                         v
                               replacement product runtime
                               + authenticated blind substrate
```

The release builder replaces the entry, injects release metadata and SRI, and
computes the exact closure
([builder](../scripts/substrate-runtime-artifact.mjs#L732-L785)). The closure
test requires the replacement entry and excludes legacy writer and dispersal
modules
([test](../test/peerit-substrate-build-closure.mjs#L351-L391)).

This distinction matters when reading tests. A passing source/development
browser test is evidence for that surface. A signed-release claim additionally
needs artifact-closure, signature/pin, and activation evidence. See
[`ARCHITECTURE.md`](./ARCHITECTURE.md#release-plane) for the release plane.

## Updating this page

Change this status only when the underlying evidence changes:

1. Link the code or protocol contract for an implementation claim.
2. Link a test for the exercised behavior.
3. For a release claim, also link the exact signed artifact or manifest and the
   accepted activation decision.
4. Recheck time-bound bootstrap epochs and the fresh deployed runtime before
   using present-tense network language.
5. State operator, privacy, availability, and origin-trust limits separately.
6. Move superseded dated plans and old sequence reports to historical context;
   do not silently treat them as current architecture.

The documentation index and status labels live in [`docs/README.md`](./README.md).
