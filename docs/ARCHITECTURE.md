# Peerit architecture

This document describes the architecture that exists in the repository as of
2026-08-27 and labels each P2P pattern by maturity. It does not collapse legacy
experiments, current source, and the signed public artifact into one product
claim. For the release/source matrix, start with
[`CURRENT-STATUS.md`](./CURRENT-STATUS.md).

> **Current activation note (2026-08-27):** `peerit.site` serves a coherent
> Sequence 29 artifact and the local-first portion below is usable. The
> public-network portion currently fails closed because the sole signed INBOX
> epoch is stale and fresh seed recovery does not pass the exact limited
> Cell-GET module check. The network arrows describe the released composition
> and accepted evidence, not present availability.

## System shape

Peerit separates four concerns:

1. **Application semantics** — signed communities, posts, comments, votes,
   profiles, moderation inputs, and deterministic local views.
2. **Local durability** — a transactional browser journal and materialized view.
3. **Delivery and discovery** — qualified relay endpoints, capability-addressed
   Cells, and signed public INBOX bootstrap data.
4. **Release authority** — an exact web closure, signed manifests, release
   sequence, pin history, and an activation decision.

The signed Sequence 29 path is:

```text
explicit user action
       |
       v
signed Peerit operation
       |
       v
transactional local journal + materialized view
       |
       +--------------------------> visible locally
       |
       v
authenticated endpoint qualification
       |
       v
independent CELL.PUT + CELL.GET readback on two relays
       |
       v
signed AuthorBind / announcement + dual INBOX.APPEND
       |
       v
reader INBOX.READ -> capability-bound CELL.GET -> intrinsic verification
       |
       v
reader's local journal + materialized view
```

Local commit and network publication are separate axes. A missing or rejected
relay cannot grant or revoke local authoring permission. The product runtime
starts with zero relay targets
([runtime constructor](../js/substrate/peerit-product-runtime.js#L50-L81)), and
the entry installs network state only after release, descriptor, and runtime
checks
([entry](../js/substrate/app-entry.js#L279-L386)).

## Source plane

The source tree contains more than one generation of the application.

### Shared application semantics

The replacement product reuses the established domain layer:

| Concern | Primary implementation |
| --- | --- |
| Application reads and mutations | [`js/data.js`](../js/data.js) |
| Canonical record types and graph rules | [`js/model.js`](../js/model.js) |
| Record verification | [`js/verify.js`](../js/verify.js) |
| Ranking | [`js/ranking.js`](../js/ranking.js), [`js/feed-algorithms.js`](../js/feed-algorithms.js) |
| Moderation projections | [`js/moderation.js`](../js/moderation.js) |
| Cryptographic primitives | [`js/crypto.js`](../js/crypto.js), [`js/canon.js`](../js/canon.js) |

This layer defines application meaning. Transport bytes or a relay receipt do
not become an accepted Peerit record without passing this layer.

### Replacement product composition

| Component | Responsibility | Boundary evidence |
| --- | --- | --- |
| [`app-entry.js`](../js/substrate/app-entry.js) | Browser lifecycle, release coherence, runtime qualification, UI mount, Sequence 29 publication seam | [boot boundary](../js/substrate/app-entry.js#L204-L270) |
| [`peerit-product-runtime.js`](../js/substrate/peerit-product-runtime.js) | Compose identity, data, local journal sync, and immutable status | [constructor and first-write behavior](../js/substrate/peerit-product-runtime.js#L46-L129) |
| [`peerit-product-ui.js`](../js/substrate/peerit-product-ui.js) | Minimal replacement routes and explicit user actions; owns no relay URL or network permission | [module boundary](../js/substrate/peerit-product-ui.js#L1-L15), [dispatch](../js/substrate/peerit-product-ui.js#L268-L304) |
| [`peerit-journal.js`](../js/substrate/peerit-journal.js) | Bounded transactional intent log, target state, dedupe, and materialized view | [contract and limits](../js/substrate/peerit-journal.js#L1-L42) |
| [`peerit-substrate-sync.js`](../js/substrate/peerit-substrate-sync.js) | Local commit, retry/readback state, multi-tab notification, and qualified target orchestration | [factory](../js/substrate/peerit-substrate-sync.js#L1128-L1159) |
| [`relay-consumer.js`](../js/substrate/relay-consumer.js) | Authenticated blind-client assembly and branded relay adapters | [product gate dependency](../js/substrate/product-release-status.mjs#L15-L18) |
| [`public-inbox-boot-coordinator.mjs`](../js/substrate/public-inbox-boot-coordinator.mjs) | Sequence 29 read, intrinsic ingest, dual Cell publication, and pointer append | [composition test](../test/peerit-seq29-public-inbox-coordinator-entry.mjs#L19-L34) |
| [`browser-runtime-authority.mjs`](../js/substrate/browser-runtime-authority.mjs) | Authenticate the browser runtime inputs used by the entry | [entry import](../js/substrate/app-entry.js#L5-L20) |
| [`release-coherence.js`](../js/substrate/release-coherence.js) | Bind browser runtime, asset manifest, bootstrap inputs, and release identity | [entry composition](../js/substrate/app-entry.js#L21-L24) |

### Identity boundary

There are two replacement-runtime identity adapters in current source:

- [`local-identity.js`](../js/substrate/local-identity.js) signs with a
  browser-local device identity. The product runtime persists or adopts it only
  on the first write.
- [`host-identity.js`](../js/substrate/host-identity.js) delegates record signing
  to `window.pear.identity`. The seed stays behind the host bridge, and the host
  owns key lifecycle
  ([adapter contract](../js/substrate/host-identity.js#L1-L22),
  [signing path](../js/substrate/host-identity.js#L101-L124)).

The entry chooses the host adapter only when both `getPublicKey` and `sign` are
present
([selection](../js/substrate/app-entry.js#L204-L218)). This adapter is on `main`
but absent from the signed Sequence 29 closure; see
[`CURRENT-STATUS.md`](./CURRENT-STATUS.md#on-main-not-in-the-signed-release).

### Legacy application composition

The root page still loads [`js/app.js`](../index.html#L14-L20). That larger UI
and its runtime selector preserve signed-outbox, host bridge, relay, DHT, shard,
and development patterns accumulated before the blind-substrate replacement.
They remain useful source and test material, but they are not the Sequence 29
browser entry.

Treat legacy modules as implementation authority only when a current runtime or
test explicitly imports them. Presence in the repository is not evidence that
the signed web artifact executes them.

## Release plane

The release build is not a byte-for-byte copy of the root development page.
For the blind substrate, it computes a bounded module closure, injects release
metadata and relay hints, adds SRI, and replaces `js/app.js` with
`js/substrate/app-entry.js`
([artifact builder](../scripts/substrate-runtime-artifact.mjs#L732-L785)).

The checked-in `web/` directory is the exact Sequence 29 output:

- [`web/index.html`](../web/index.html#L11-L25) names release 29 and loads the
  replacement entry;
- [`web/peerit-app-artifact-v1.json`](../web/peerit-app-artifact-v1.json#L1-L21)
  names the transport, release key, seed, public INBOX bootstrap, and pin
  history;
- [`web/asset-manifest.json`](../web/asset-manifest.json#L1-L27) hashes every
  released file; and
- the accepted decision binds the app artifact and manifest hashes
  ([decision evidence](../deploy/canary-decision-peerit-seq29-limited-public-inbox-20260813.json#L42-L66)).

The closure test requires the replacement entry and rejects legacy writer,
bridge, and dispersal modules from the output
([test](../test/peerit-substrate-build-closure.mjs#L351-L391)).

### Release rule

Do not hand-edit `web/` to publish a source change. A release claim requires:

1. a clean, reproducible source closure;
2. exact artifact and web-manifest hashes;
3. the signed release and pin-history artifacts;
4. all applicable release gates; and
5. an explicit activation decision with an honest claim boundary.

A source-only feature remains source-only until that sequence completes. Host
identity is the current concrete example.

## Execution modes

| Mode | Entry and storage | Network pattern | Current maturity |
| --- | --- | --- | --- |
| Root development page | `index.html` -> `js/app.js`; development/local storage and legacy adapters | Selected by legacy runtime configuration | Development and legacy test surface; not release parity |
| Signed ordinary-browser public test | `web/index.html` -> replacement entry; IndexedDB journal plus browser-local identity | Authenticated blind relay Cells + two global public INBOX topics | **Sequence 29 `LIVE_PUBLIC_TEST_ONLY` artifact is signed and deployed; current network activation is blocked** |
| Pear host-capable replacement source | Replacement entry plus `window.pear.identity`; same local journal | Host-owned record signing; future release still needs exact network/release composition | Implemented and unit/composition tested on `main`; not signed in Sequence 29 |
| Direct Pear host bridge / swarm | Legacy host API and signed-outbox/gossip modules | Direct or host-provided P2P surfaces | Preserved legacy/experimental pattern; excluded from Sequence 29 closure |
| Local multi-tab simulator | Browser storage/journal plus BroadcastChannel-style coordination | No external network required | Development and deterministic test pattern |

These rows deliberately avoid saying that every mode has the same trust model.
A host-delivered content-addressed app, an origin-delivered web app, a local
simulator, and a blind relay public test have different bootstrap, availability,
and metadata boundaries.

## Trust boundaries

### Application record authority

Authors sign application records. Readers recompute and verify record authority
before materializing data. A relay response, discovery pointer, or local cache
entry is not sufficient authority by itself.

This provides tamper and impersonation resistance for admitted records. It does
not provide one-human-one-key, guaranteed availability, or universal agreement
on ranking and moderation policy.

### Local device authority

The journal and identity store are device-local authorities. IndexedDB failures,
quota, eviction, and device loss are availability and recovery concerns. A
browser-local identity is not automatically portable. Host identity changes
the key-custody boundary but does not by itself replicate local application
state.

### Relay authority

Relay URLs are hints until qualified. A qualified relay can attest to its own
descriptor, receipt, store, and continuity data; it cannot decide whether an
arbitrary payload is a valid Peerit record. Relays still observe requests they
serve and can delay, omit, or refuse them.

Sequence 29 uses two distinct relay identities and stores inside one
owner-operator boundary. That is useful redundancy but not independent
governance or censorship resistance
([contract](./SEQ29-LIMITED-PUBLIC-TEST-CONTRACT.md#L20-L45)).

### Discovery and bootstrap authority

The signed seed bootstrap names the initial record capabilities. The signed
limited public INBOX bootstrap names two discovery routes for its exact epoch.
That epoch must be current before the routes become active. Durable
floors reject lower sequences and visible same-sequence forks, within the
bounded contract
([contract](./SEQ29-LIMITED-PUBLIC-TEST-CONTRACT.md#L27-L45)).

The web origin still delivers the first executing verifier. Signed release and
pin-history controls reduce later rollback and substitution risk, but the GA
gate explicitly records unresolved first-visit and portable recovery work
([product status](../js/substrate/product-release-status.mjs#L75-L134)).

## Pattern catalogue

The catalogue uses four maturity labels:

- **Released test** — present in the signed Sequence 29 closure and covered by
  its bounded activation decision. This is historical release evidence, not a
  claim that time-bound network authorities remain current.
- **Current source** — implemented on `main`, but not yet in a signed release.
- **Experimental** — a working research path or fixture without a current
  release claim.
- **Historical/legacy** — retained to explain or test an earlier architecture;
  not the current release entry.

### 1. Transactional local-first journal

**Maturity:** Released test

An explicit action commits exact operation bytes, materialized records, and a
delivery intent locally before publication. Per-target states distinguish
preparing, delivering, retryable, acknowledged, and readback-verified work.
Multi-tab coordination is a notification/lease concern, not a second database.

- Code: [`peerit-journal.js`](../js/substrate/peerit-journal.js#L1-L59),
  [`peerit-substrate-sync.js`](../js/substrate/peerit-substrate-sync.js)
- Evidence: [`test/peerit-journal.mjs`](../test/peerit-journal.mjs#L1-L28),
  [`test/peerit-product-runtime.mjs`](../test/peerit-product-runtime.mjs#L220-L240)
- Does not solve: device loss, browser eviction, or independent remote
  availability.

### 2. Explicit publication after local commit

**Maturity:** Released test

Network mutation is reached only from a trusted user action bound to one exact
durable intent. Interrupted work is user-retried; reload and background events
do not silently publish.

- Code: [`peerit-product-ui.js`](../js/substrate/peerit-product-ui.js#L341-L379),
  [`app-entry.js`](../js/substrate/app-entry.js#L249-L270)
- Evidence: [`test/peerit-seq29-explicit-user-publication-ui.mjs`](../test/peerit-seq29-explicit-user-publication-ui.mjs#L146-L174),
  [`test/peerit-seq29-public-inbox-coordinator-entry.mjs`](../test/peerit-seq29-public-inbox-coordinator-entry.mjs#L57-L70)
- Does not solve: unattended availability or automatic cross-device recovery.

### 3. Authenticated untrusted-relay adapters

**Maturity:** Released test, within the Sequence 29 boundary

Configured URLs remain hints until descriptor and runtime qualification succeeds.
Only branded adapters cross into sync. Application records still pass Peerit
verification after retrieval.

- Code: [`relay-consumer.js`](../js/substrate/relay-consumer.js),
  [`peerit-product-runtime.js`](../js/substrate/peerit-product-runtime.js#L131-L148)
- Evidence: [`test/peerit-seq29-public-inbox-coordinator-entry.mjs`](../test/peerit-seq29-public-inbox-coordinator-entry.mjs#L71-L86)
- Does not solve: relay withholding, endpoint metadata exposure, or operator
  independence.

### 4. Capability-addressed opaque Cells

**Maturity:** Released test

Payloads are stored and fetched through bounded Cells using capabilities and
receipt/readback bindings. Relays operate on generic protocol data rather than
Peerit community/post field names.

- Code: [`limited-cell-put-profile.mjs`](../js/substrate/limited-cell-put-profile.mjs),
  [`limited-cell-get-profile.mjs`](../js/substrate/limited-cell-get-profile.mjs)
- Evidence: [Sequence 29 contract](./SEQ29-LIMITED-PUBLIC-TEST-CONTRACT.md#L47-L64),
  [accepted operations](../deploy/canary-decision-peerit-seq29-limited-public-inbox-20260813.json#L17-L40)
- Does not solve: traffic analysis, size-band leakage, or malicious omission.

### 5. Signed public-INBOX discovery pointers

**Maturity:** Released test

The Sequence 29 bootstrap for this pattern is deployed but its sole epoch is no
longer current, so the runtime does not activate these pointers today.

Two global public topics carry opaque announcement frames that point readers to
capability-addressed content. Lifecycle management capabilities remain offline;
the browser can append and read but cannot create, renew, or close the topics.

- Code: [`inbox-pointer-publish.mjs`](../js/substrate/inbox-pointer-publish.mjs),
  [`inbox-discovery.mjs`](../js/substrate/inbox-discovery.mjs),
  [`public-inbox-boot-coordinator.mjs`](../js/substrate/public-inbox-boot-coordinator.mjs)
- Evidence: [`test/peerit-seq29-public-inbox-runtime.mjs`](../test/peerit-seq29-public-inbox-runtime.mjs#L113-L136),
  [release decision](../deploy/canary-decision-peerit-seq29-limited-public-inbox-20260813.json#L17-L40)
- Does not solve: private discovery, per-community unlinkability, or independent
  operator governance.

### 6. Signed seed bootstrap and durable floors

**Maturity:** Released test

The signed seed remains part of the coherent artifact. Fresh deployed recovery
is currently blocked by the exact limited Cell-GET surface check; no fallback is
treated as equivalent authority.

A signed seed bootstrap gives cold readers a bounded starting set. Signed
bootstrap sequences and local floors make lower-sequence rollback and
same-sequence forks visible within their contract.

- Code: [`seed-bootstrap-v1.mjs`](../js/substrate/seed-bootstrap-v1.mjs),
  [`seq29-public-inbox-sync.mjs`](../js/substrate/seq29-public-inbox-sync.mjs)
- Evidence: [artifact identity](../web/peerit-app-artifact-v1.json#L14-L21),
  [decision evidence](../deploy/canary-decision-peerit-seq29-limited-public-inbox-20260813.json#L45-L60)
- Does not solve: complete global discovery or portable post-eviction recovery.

### 7. Signed release closure and pin history

**Maturity:** Released test with open GA recovery blockers

The release plane hashes an exact runtime closure, emits a signed web-asset
manifest, binds a release sequence and key, and carries detached pin history.

- Code: [`substrate-runtime-artifact.mjs`](../scripts/substrate-runtime-artifact.mjs#L732-L785),
  [`release-verify.js`](../js/release-verify.js)
- Evidence: [`web/index.html`](../web/index.html#L11-L25),
  [`web/peerit-app-artifact-v1.json`](../web/peerit-app-artifact-v1.json#L1-L21),
  [`test/peerit-substrate-build-closure.mjs`](../test/peerit-substrate-build-closure.mjs#L351-L391)
- Does not solve yet: first-visit executing-verifier trust, portable rollback
  recovery, or post-eviction continuity. Those remain explicit blockers.

### 8. Host-owned per-app identity

**Maturity:** Current source, not Sequence 29

Pear Browser can keep the signing seed behind `window.pear.identity`. Peerit
caches the public key and drive key, asks the host to sign the Peerit namespace,
and rejects a mid-sign key change.

- Code: [`host-identity.js`](../js/substrate/host-identity.js#L25-L124),
  [`app-entry.js`](../js/substrate/app-entry.js#L204-L218)
- Evidence: [`test/peerit-host-identity.mjs`](../test/peerit-host-identity.mjs#L42-L120),
  [`test/peerit-app-entry-composition.mjs`](../test/peerit-app-entry-composition.mjs#L186-L214)
- Release evidence showing absence: [`web/js/substrate/app-entry.js`](../web/js/substrate/app-entry.js#L203-L209),
  [`web/asset-manifest.json`](../web/asset-manifest.json#L27-L56)
- Does not solve: host key lifecycle inside Peerit, local state replication,
  Sequence 29 public-publication signing, or a future release ceremony. The
  adapter rejects `signAuthorBindV1`, which the publication authority requires
  ([adapter](../js/substrate/host-identity.js#L85-L100),
  [publication authority](../js/substrate/peerit-product-runtime.js#L218-L223)).

### 9. Signed per-author outbox and deterministic gossip merge

**Maturity:** Historical/legacy for the current public release

Earlier Peerit paths model each author as the sole writer of a signed outbox and
merge verified records deterministically. This remains a useful P2P application
pattern and is exercised by legacy tests, but it is not the Sequence 29 browser
transport.

- Code: [`gossip.js`](../js/gossip.js), [`sync.js`](../js/sync.js)
- Evidence: [`test/gossip.mjs`](../test/gossip.mjs),
  [`test/gossip-v2.mjs`](../test/gossip-v2.mjs)
- Release evidence showing exclusion: [`test/peerit-substrate-build-closure.mjs`](../test/peerit-substrate-build-closure.mjs#L370-L375)
- Does not solve by itself: offline-author availability, browser-origin trust, or
  privacy of a public author graph.

### 10. Direct host bridge and swarm transport

**Maturity:** Historical/legacy and experimental in this release context

A capable host can provide sync, identity, and swarm surfaces that ordinary web
pages cannot access directly. The runtime detector preserves this separation
from no-host web operation.

- Code: [`pear-api.js`](../js/pear-api.js#L123-L193),
  [`runtime.js`](../js/runtime.js#L1-L25)
- Evidence: [`test/bridge.mjs`](../test/bridge.mjs),
  [`test/local-bridge-proof.mjs`](../test/local-bridge-proof.mjs)
- Does not solve: origin trust for ordinary browsers or release parity with the
  signed blind-substrate artifact.

### 11. Threshold body dispersal / BlindShard

**Maturity:** Experimental, excluded from Sequence 29

The repository explores splitting content bodies and key material across a
relay cohort so no single shard stores a complete body. It is not enabled by the
replacement product runtime (`dispersal: false`) and its writer modules are
excluded from the signed closure.

- Code: [`blob-disperse.js`](../js/blob-disperse.js),
  [`data-dispersal.js`](../js/data-dispersal.js)
- Research: [`BLINDSHARD-DESIGN.md`](./BLINDSHARD-DESIGN.md)
- Evidence of release exclusion: [`test/peerit-substrate-build-closure.mjs`](../test/peerit-substrate-build-closure.mjs#L370-L390)
- Does not solve by itself: traffic analysis, honest shard retention, or
  discovery.

### 12. DHT-over-WebSocket conduit

**Maturity:** Experimental/legacy, not Sequence 29

An ordinary browser can use a WebSocket service as a conduit into a DHT-like
transport. This is a useful compatibility pattern, but the conduit is an
availability and metadata observer and is not direct browser DHT participation.

- Code: [`dht-adapter.js`](../js/dht-adapter.js),
  [`dht-transport.js`](../js/dht-transport.js)
- Evidence: [`test/dht-adapter.mjs`](../test/dht-adapter.mjs),
  [`test/dht-build.mjs`](../test/dht-build.mjs)
- Does not solve: removing the conduit, browser access to raw DHT sockets, or
  anonymity.

### 13. Pluggable feed and moderation projections

**Maturity:** Released test

Ranking and moderation are local projections over admitted records. The
replacement UI applies a selected moderation view before ranking and exposes
interchangeable feed algorithms.

- Code: [`feed-algorithms.js`](../js/feed-algorithms.js),
  [`moderation.js`](../js/moderation.js),
  [`peerit-product-ui.js`](../js/substrate/peerit-product-ui.js#L95-L121)
- Evidence: [`test/community-moderation.mjs`](../test/community-moderation.mjs),
  [`test/community-moderation-ui.mjs`](../test/community-moderation-ui.mjs)
- Does not solve: universal consensus on taste, policy, or Sybil-resistant
  governance.

## How to evaluate a new pattern

Every new browser P2P pattern should document five things:

1. **Authority:** which bytes or actors are trusted to decide acceptance?
2. **Durability:** what survives reload, process loss, device loss, and operator
   loss?
3. **Discovery:** how does a cold reader find current data, and what can be
   omitted?
4. **Privacy:** which semantic, timing, size, endpoint, and capability metadata
   remain visible?
5. **Maturity:** is it a fixture, source implementation, signed artifact, or
   activated release?

Add direct code and test links, then add release evidence only after an exact
signed closure and decision exist. Documentation status conventions are in
[`docs/README.md`](./README.md).
