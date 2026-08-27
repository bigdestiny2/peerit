# Peerit, honestly

Peerit is a local-first community application for experimenting with verifiable
social data and peer-to-peer delivery patterns in browsers. Its deployed signed
web artifact is **Sequence 29**. That artifact was accepted as a bounded public
test; it is not a general-availability release and it is not evidence that every
Peerit or HiveRelay design in this repository is deployed.

The exact release decision labels Sequence 29
[`LIVE_PUBLIC_TEST_ONLY`](deploy/canary-decision-peerit-seq29-limited-public-inbox-20260813.json#L17-L40),
and the product release gate deliberately remains blocked
([gate implementation](js/substrate/product-release-status.mjs#L137-L173),
[gate test](test/peerit-product-release-gate.mjs#L38-L61)). See
[`docs/CURRENT-STATUS.md`](docs/CURRENT-STATUS.md) before relying on a feature or
security property.

As checked on 2026-08-27, `peerit.site` serves the coherent Sequence 29 bytes and
local authoring works, but fresh public publication and discovery fail closed.
The artifact's sole public-INBOX epoch is no longer current, and fresh signed
seed recovery is blocked by the limited Cell-GET runtime surface. Rotation and
runtime repair are required before calling that network path active. The exact
evidence is recorded in
[`docs/CURRENT-STATUS.md`](docs/CURRENT-STATUS.md#what-is-deployed-versus-currently-active).

## What the signed artifact contains

The Sequence 29 browser artifact presents a small community product surface:

- browse a locally materialized, verified view of communities, posts, and
  comments;
- create communities, text or link posts, comments, and profiles;
- vote, edit, delete, report, vouch, search, and choose feed and moderation
  views; and
- keep a local mutation durable before attempting network publication.

Those are claims about the replacement UI in the signed artifact, not every
feature that appears in the older `js/app.js` application. The active routes are
enumerated in the replacement UI
([route parser](js/substrate/peerit-product-ui.js#L55-L68),
[view dispatch](js/substrate/peerit-product-ui.js#L268-L275)), and authored
actions enter the publication seam only after a local operation commits
([UI hand-off](js/substrate/peerit-product-ui.js#L341-L370)).

The release contains a signed 39-record seed and two limited public INBOX
bindings. The accepted release evidence records both the seed and the two
bindings
([Sequence 29 decision](deploy/canary-decision-peerit-seq29-limited-public-inbox-20260813.json#L42-L66)).

## The data path

An authored action always begins locally. When the signed network authorities
are current and the limited runtime qualifies, the full path is:

1. The browser creates a signed Peerit record.
2. A bounded IndexedDB journal commits the record, the exact operation bytes,
   and its delivery intent in one local transaction. The journal also maintains
   the materialized local view
   ([journal contract](js/substrate/peerit-journal.js#L1-L42)).
3. The Sequence 29 publication seam can be reached only from a trusted,
   explicit browser action. Reload, timers, navigation, and connectivity changes
   do not publish by themselves
   ([composition test](test/peerit-seq29-public-inbox-coordinator-entry.mjs#L57-L70)).
4. The publisher prepares independent CELL writes for both authenticated relay
   endpoints, requires readback evidence, then appends a discovery pointer to
   both public INBOX topics
   ([composition test](test/peerit-seq29-public-inbox-coordinator-entry.mjs#L76-L86),
   [UI test](test/peerit-seq29-explicit-user-publication-ui.mjs#L156-L174)).
5. Readers poll the signed INBOX bindings, open the pointer frames, retrieve the
   capability-addressed Cells, and admit only records that pass the intrinsic
   Peerit authority.

Steps 3–5 currently remain blocked at qualification on the deployed artifact;
the browser preserves the local operation and does not reinterpret that as a
network success.

The two public-test relays are owner-operated and are **not represented as
independent operators**. The INBOX topics are global public-discovery topics,
not one topic per community or author. The contract says this explicitly and
also enumerates the properties the test does not claim
([honest boundary](docs/SEQ29-LIMITED-PUBLIC-TEST-CONTRACT.md#L20-L45)).

## Identity: release versus current source

The signed Sequence 29 web artifact uses a browser-local device identity. It
creates no key during lurker boot; the first explicit mutation persists or
adopts the device writer before signing
([runtime](web/js/substrate/peerit-product-runtime.js#L85-L129)).

`main` now also contains a Pear Browser host-identity adapter. When an
identity-capable `window.pear.identity` is present, the current replacement
entry selects the host-backed identity
([entry composition](js/substrate/app-entry.js#L204-L218)). The adapter asks the
host to sign and never receives a private seed
([adapter](js/substrate/host-identity.js#L1-L9),
[no-seed test](test/peerit-host-identity.mjs#L103-L108)). Host-signed records are
verified by the same record verifier
([round-trip test](test/peerit-host-identity.mjs#L42-L70)).

That work is **on `main`, but it is not in the signed Sequence 29 release**.
The checked-in signed entry constructs the default product runtime without the
host adapter
([signed entry](web/js/substrate/app-entry.js#L203-L209)), and its signed asset
manifest has no `host-identity.js`
([Sequence 29 manifest](web/asset-manifest.json#L27-L56)). A later release must
build, verify, sign, and activate a new artifact before host identity can be
described as released. The current adapter also leaves key lifecycle with the
host and rejects unsupported lifecycle methods
([adapter boundary](js/substrate/host-identity.js#L66-L99)).
Its proven source scope is local Peerit record signing: the adapter currently
rejects `signAuthorBindV1`, while the Sequence 29 publication authority calls
that method before public delivery
([host boundary](js/substrate/host-identity.js#L85-L100),
[publication authority](js/substrate/peerit-product-runtime.js#L218-L223)).
End-to-end host-backed Sequence 29 publication is therefore not claimed.

## What the relays can and cannot do

The browser does not treat a configured URL as a trusted Peerit database.
Release and descriptor checks qualify endpoints before they become delivery
targets, and received application records still pass Peerit's signature and
intrinsic validation.

The limited relays handle generic operations, opaque Cell or frame bytes,
capabilities presented to that relay, timing, transport metadata, and bounded
size information. This reduces semantic exposure; it does **not** provide
anonymity or hide network metadata. A relay can be unavailable, delay or omit
traffic, and observe the requests it serves. Because both public-test relays are
under one operator boundary, Sequence 29 does not establish operator
independence or censorship resistance.

The browser is also bootstrapped by a web origin. A signed manifest and
pin-history chain narrow what the release accepts, but the repository's own GA
gate still records unresolved first-visit, service-worker CAS, portable
rollback-recovery, and post-eviction continuity work
([browser gate fields](js/substrate/product-release-status.mjs#L75-L94),
[blockers](js/substrate/product-release-status.mjs#L96-L134)).

## What is not one current product claim

This repository preserves several useful P2P application patterns: direct
Pear host bridges, signed per-author outboxes, local multi-tab simulation,
opaque relay storage, capability-addressed Cells, public INBOX discovery,
threshold dispersal, and DHT-over-WebSocket experiments. They have different
maturity and trust boundaries.

In particular:

- the root development page still loads the legacy `js/app.js` entry
  ([source page](index.html#L14-L20));
- the signed Sequence 29 page loads the replacement-only substrate entry
  ([signed page](web/index.html#L11-L25)); and
- the substrate release closure deliberately excludes the legacy app, sync,
  host API, and dispersal modules
  ([closure test](test/peerit-substrate-build-closure.mjs#L351-L391)).

Therefore “present in the repository,” “works in a development harness,” “on
`main`,” and “in the signed public release” are four different statements. The
architecture and pattern catalogue keep them separate:

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — runtime boundaries and pattern
  maturity;
- [`docs/CURRENT-STATUS.md`](docs/CURRENT-STATUS.md) — the current release/source
  matrix; and
- [`docs/README.md`](docs/README.md) — documentation map and historical labels.

## Honest limits

- Free cryptographic identities are not proof of one human per account.
- Signed data provides authenticity, not guaranteed availability, privacy, or
  agreement on ranking and moderation policy.
- Opaque storage reduces relay-visible semantics but does not hide timing,
  endpoint, capability, or size metadata.
- Two relay replicas under one operator boundary provide bounded redundancy,
  not proven independent failure domains or governance.
- Local durability is device-scoped unless an explicitly supported recovery or
  host-identity path applies.
- A browser origin remains part of first-visit trust. Sequence 29 records a
  bounded test of a mitigation stack, not a claim that this problem is solved.
- A passing test suite validates the exercised contracts; it does not promote
  an experimental pattern or a source-only change into a signed release.

That narrower description is the useful one: Peerit is a working laboratory
and deployed bounded-release artifact for local-first, cryptographically
admitted community data, with explicit evidence for what shipped, what is
active, and what currently fails closed.
