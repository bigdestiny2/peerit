# HiveRelay vNext Ecosystem Orchestration Plan

**Status:** revised execution plan; owner decisions D-1 through D-7 remain open
**Date:** 2026-07-12
**Scope:** HiveRelay vNext, blind substrate, public HTTPS gateways, fleet
reprovisioning, PearBrowser, ecosystem applications, catalogues, webpage
Hyperdrives, public sites, and Peerit as the first ordinary-browser consumer

This is an orchestration document, not a production claim. A feature or privacy
profile becomes releasable only after its named evidence gate passes. The
adversarial-review disposition in section 3 is part of the critical path and
supersedes any earlier instruction to generate protocol hashes before those
items are closed.

---

## 1. Executive decision

Use a hybrid implementation strategy:

> Build the strict blind data plane as a clean isolated daemon, while retaining
> HiveRelay's existing release, fleet, seeding, gateway-compatibility,
> packaging, and operator machinery.

Do not add Blind Cells as another current RelayNode plugin. Do not rewrite the
entire HiveRelay product. The target is a new data plane inside the existing
product and release shell.

The release train is server-first, with three separately promoted tracks:

- **Track A:** `public-gateway-v1`, a T1 public-distribution product with no
  inherited blind/privacy claim;
- **Track B:** a possible early `direct-blind-v1` G2-S vertical slice, pending
  D-1; and
- **Track C:** advanced blind profiles, including independently operated OHTTP,
  Blind Core, FORWARD, and G3, only as their own evidence becomes complete.

Across those tracks:

1. freeze protocol and evidence contracts;
2. build the smallest approved blind vertical slice beside the legacy relay;
3. deploy fresh server storage before dependent clients;
4. migrate PearBrowser and apps through versioned clients;
5. publish and pin app releases and webpage drives;
6. publish one canonical catalogue;
7. release PearBrowser with profile-aware claims; and
8. promote Peerit from internal pilot to public web app.

No fleet-wide wipe is allowed. Storage is reprovisioned one node at a time after
a signed retention census and tested off-node backup.

---

## 2. Target product shape

~~~text
HiveRelay vNext release shell
├── public-gateway-v1 (T1 public distribution)
│   ├── Hypercore/Hyperdrive seeding
│   ├── proof of retrievability
│   ├── circuit transport
│   └── public HTTPS exact-byte gateway
│
├── hiverelay-blind/1 (strict blind daemon)
│   ├── DESCRIBE
│   ├── CELL
│   ├── INBOX
│   ├── CORE
│   └── FORWARD
│
├── portable clients and verifiers
│   ├── blind protocol and vectors
│   ├── browser/Pear/Bare/Node client
│   ├── gateway/proof verifier
│   └── client-owned availability and repair
│
└── existing operational shell
    ├── signed artifacts
    ├── canary/stable updater
    ├── GHCR/Umbrel/StartOS packaging
    ├── fleet evidence and rollback
    └── temporary compatibility routes
~~~

The public gateway and strict blind daemon share packaging and the frozen
public-versus-blind role classifier, but they are separate products and claim
surfaces. The gateway must never inherit G2/G3/G4 claims. The strict daemon has
its own process, unprivileged OS identity, relay key, storage root, quota,
listener, IPC, logs, metrics, health, and release evidence.
It must not share application registries, OutboxLog state, management routes,
stores, keys, or semantic logs.

---

## 3. Governing documents

- [Blind master specification](./BLIND-APP-AGNOSTIC-HIVERELAY-MASTER-SPEC.md)
- [Blind implementation specification](./BLIND-SUBSTRATE-IMPLEMENTATION-SPEC.md)
- [Browser storage discovery](./ROCKSDB-IDB-BROWSER-STORAGE-DISCOVERY.md)
- [Public HTTPS gateway specification](../../../00-core/hr-https-gateway/docs/PUBLIC-HTTPS-HIVE-GATEWAY-SPEC.md)
- [Gateway canary runbook](../../../00-core/hr-https-gateway/docs/PUBLIC-HIVE-GATEWAY-CANARY-RUNBOOK.md)
- [Server storage migration scope](../../../00-core/hiverelay/docs/STORAGE-MIGRATION-SCOPE.md)
- [Fleet release model](../../../00-core/hiverelay/fleet/README.md)

Before protocol freeze, the blind documents and canonical vectors move together
into HiveRelay's docs/protocol tree. Peerit and PearBrowser pin the accepted
specHash, abiHash, and vectorSetHash; neither app becomes protocol authority.

The gateway specification currently has divergent copies in the active
`hr-https-gateway` worktree and the main HiveRelay worktree. The active candidate
is the governing input for this plan, but Phase 0 must preserve it and Phase 0R
must select one canonical destination with generated mirrors. A release may not
cite both differing files as authority.

### 3.1 Adversarial-review disposition

The review found two confirmed blockers and several real hardening gaps, but it
also overstates parts of the current design. The implementation must follow the
verified disposition below, not copy each proposed remedy literally.

| Item | Verified disposition | Required timing |
| --- | --- | --- |
| CR-1 | Confirmed ABI defect: restore `maxCircuitBytes: u64` to `BlindForwardOpenResultV1` in the implementation schema and enforce aggregate bidirectional teardown exactly once. | Before ABI freeze |
| CR-2 | Confirmed ordering defect: the existing side-effect-free admission `prepare` verification moves before blob staging/fsync; its returned spend record remains committed atomically by the WAL coordinator. Do not create a second admission authority. | Before ABI freeze |
| CR-3 | Descriptor gap confirmed. Existing per-connection/global controls remain, but read fairness and byte/operation buckets become normative and the signed descriptor advertises the uncharged-read policy. Do not invent a stable identity for anonymous uncharged readers. | Before ABI freeze because the descriptor changes |
| CR-4 | Clock liveness residual is valid, although reads and management do not all freeze and existing high-water safeguards remain. Add explicit clock-trust readiness, skew/GC-stall alarms, and reserved-capacity behavior; change the descriptor only if required by the selected status design. | Semantics before freeze; V-5 before fleet rollout |
| CR-5 | Route-depth risk needs a design, but a caller-resettable `remainingHops` byte cannot bound fresh nested FORWARD sessions inside opaque traffic. Freeze only an enforceable relay-carried route budget or signed acyclic route class, with reset/cycle negatives. | Design and any ABI change before freeze |
| CR-6 | No collision is presently demonstrated: typed fields already use canonical encoding. Freeze the actual compact-encoding count/length rules in one registry and add non-canonical/length-confusion negatives; do not replace them arbitrarily with fixed `u32`/`u64` prefixes. | Before vectors and hashes |
| CR-7 | Confirmed claim gap: a physical inbox is G2-S, not G3; every use of “unlinkable” must include its at-rest and live-observer residuals. | Before any public claim |
| CR-8 | G3 renewal correlation must become a defended, thresholded property. Defined jitter, placement/lease-class policy, and a classifier gate are required for a G3 claim. Optional decoys remain a profile/economics decision, not an automatic default. | Before advertising G3 |

Although the review labels CR-3 through CR-6 as pre-rollout hardening, CR-3,
CR-5, and possibly CR-4/CR-6 change signed schemas or canonical encodings. All
ABI-affecting work therefore moves before Phase 1's production hash freeze.
CR-7 and CR-8 also change normative text covered by `specHash`, so their claim
and G3-profile language lands before that hash even though their runtime claim
gates remain later.

### 3.2 Verification gates added by the review

| Gate | Required evidence | Blocks |
| --- | --- | --- |
| V-1 | One machine-readable canonical schema registry generates or validates both specifications; field/order/cap/domain drift fails CI. | ABI freeze |
| V-2 | A circuit exceeding `maxCircuitBytes` closes once and releases every socket, buffer, credit, and quota reservation once. | FORWARD profile |
| V-3 | Max-size PUTs with valid-shaped invalid admission cause zero staging bytes and zero fsyncs. | CELL writes |
| V-4 | Connection-fair uncharged-read attack tests stay within the advertised operation/byte policy; clients reject descriptor-policy mismatches. | Public read profile |
| V-5 | Sub-threshold forward jump, unsafe forward jump, backward clock, and missing authenticated-time cases produce the specified health/readiness state; GC-stall protection fires before capacity loss. | Open admission and fleet readiness |
| V-6 | The selected enforceable route-depth design rejects budget reset, over-depth, and cycle cases within the bound. | Multi-hop FORWARD |
| V-7 | Canonical commitment vectors cover minimum/single/maximum variable members plus non-canonical counts and length-confusion negatives. | ABI/vector freeze |
| V-8 | A published renewal-correlation classifier stays below its G3 threshold on realistic multi-cell, same-relay workloads. | G3 claim |
| V-GW1 | Huge objects, ranges, slow readers, distributed readers, transforms, and proof work stay within finite byte/memory/CPU/time budgets. | Public gateway promotion |

### 3.3 Owner decision register

These remain owner decisions. Recommendations guide discussion but are not
authorization to encode a default.

| Decision | Recommendation | Must be resolved before | Status |
| --- | --- | --- | --- |
| D-1 milestone | Ship an honestly labelled direct G2-S Peerit canary after the minimal vertical slice; keep OHTTP/CORE/FORWARD/G3 as later capability profiles. | Committing the client migration sequence | Pending owner |
| D-2 OHTTP operator | Recruit an ingress operator independent of the storage gateway, with separate control, keys, hosts, deployment access, logs, and failure domain. Until then OHTTP may prove mechanics but the effective claim remains G2-S. | Advertising `split-web-ohttp-v1`, G2-W, or G4-T | Pending owner |
| D-3 G3 repair | Define who repairs/re-announces, who pays, default cadence, offline-writer behavior, and repair-hint authenticity before selecting G3-web as production v1. | G3 production commitment | Pending owner |
| D-4 operator posture | Produce jurisdiction-aware liability guidance, abuse/takedown procedure, locator-report SLA, retention rules, and operator acknowledgement. | Recruiting third-party storage operators | Pending owner/legal |
| D-5 gateway scope | Keep it as the separately named T1 public-distribution product `public-gateway-v1`; do not market it as part of the blind privacy path. | Public gateway program scope and collateral | Pending owner |
| D-6 `K_partition` | Keep it only if a measured cross-relay privacy benefit justifies a tested backup/rotation/recovery contract; otherwise remove it before storage layout freezes. | Daemon storage implementation | Pending owner |
| D-7 rollback wording | State that after the first blind-only write, rollback is only to a dual-read build, never a legacy-only binary. | Migration runbook approval | Pending owner acknowledgement |

If D-5 keeps the gateway, its signed production policy must replace
`maxResponseBytes: null` with a finite enforced limit. Oversized full GETs must
reject or require a bounded single range; unsupported/multi-range requests must
not fall back to an oversized `200`; transformations get a separate small
buffer cap; and proof mode gets bounded proof bytes, blocks/ranges, work,
concurrency, and a streaming/framed design before it is advertised.

---

## 4. Release train

The tentative train is v0.25.0-rc.N. Stable promotion waits for the required
gates. Later transports may be included but disabled; descriptors advertise
only profiles with complete evidence. Promotion is per profile rather than a
single whole-product privacy label:

| Release profile | Meaning | Earliest promotion gate |
| --- | --- | --- |
| `public-t1-gateway` | Exact-byte public HTTPS distribution; no privacy upgrade | Frozen T1 classifier, V-GW1, and negative T2 exposure suite |
| `direct-blind-g2s` | Direct blind storage/transport with server-visible stable access metadata | ABI freeze, V-3 through V-5, V-7, and approved D-1 |
| `g3-randomized-cells` | At-rest unlinkability for independently randomized cells, with stated residuals | D-3, CR-8, V-8, and G3 repair/placement readiness |
| `split-web-ohttp-v1` | Source-separated browser ingress and storage roles | D-2, independent operators, and OHTTP capture/collusion evidence |

### Phase 0 — preserve and clean the integration base

- Commit each dirty feature separately in its current worktree.
- Create a clean integration worktree from the exact v0.24.3 baseline.
- Record the source, build, dependency, configuration, and storage baseline.
- Preserve the active gateway candidate and diff it against the older HiveRelay
  copy before choosing one canonical source and generated mirror.
- Back up publisher Corestores independently of relay storage.
- Freeze unrelated release work.

**Gate:** every included change is reproducible; no release depends on dirty or
untracked source; the old binary/config/storage format is recoverable.

### Phase 0R — adversarial remediation and decision control

- Install one machine-readable canonical schema/commitment registry as the
  source for both specification excerpts and codec/vector generation.
- Reconcile CR-1 and reorder CR-2 in both specifications.
- Freeze the descriptor read-policy representation and the clock-trust
  readiness/status representation.
- Design an enforceable CR-5 route budget; do not commit a resettable hop byte
  merely to close the review item.
- Freeze the existing canonical compact-encoding length/count framing and its
  negative cases.
- Open D-1 through D-7 in the signed decision register with owner, deadline,
  selected option, rationale, affected profiles, and superseded assumptions.
- Resolve D-6 and ratify D-7 before generating the blind `specHash`; both alter
  canonical storage/migration language. Resolve D-1 before committing the
  Peerit migration sequence and D-5 before gateway public positioning. D-2
  through D-4 may proceed in parallel but block only their named promotion
  stages.

**Gate:** every ABI-affecting CR has one agreed schema-level remedy; V-1 runs
against both documents; no hash or release profile is called frozen; owner
decisions are either signed or visibly pending rather than encoded as defaults.

### Phase 1 — freeze protocol and role boundaries

- Move reviewed blind specs into HiveRelay.
- Generate both documents' schemas from, or validate them against, one
  canonical registry.
- Land every ABI-affecting part of CR-1 through CR-6 and every normative
  `specHash` change from CR-7/CR-8, D-6, and D-7 in both documents before
  generating hashes.
- Freeze the five-family ABI, codecs, canonical count/length framing, errors,
  signature domains, descriptor policies, limits, and vectors.
- Define the normative T1/T2/T3 crosswalk for public availability, CELL, INBOX,
  CORE, custody, and witnesses.
- Freeze the public-gateway T1 admission predicate.
- Generate protocol hashes and consumer-profile drafts.

**Gate:** identical vectors pass under Node, Bare, browsers, and Pear; schema
drift fails V-1; V-7 passes; descriptor policy/state is not implicit;
unknown/transitional state cannot become gateway eligible. `specHash`,
`abiHash`, and `vectorSetHash` are generated last, never before remediation.

### Phase 2 — build the strict blind plane

Create clean logical workspaces:

~~~text
packages/blind-protocol
packages/blind-client
packages/blind-daemon
packages/private-transport
~~~

Build in capability increments. First build the canonical codec, DESCRIBE
policy verification, daemon identity/lifecycle, admission verifier,
WAL/buckets/CELL with pre-staging admission preparation, in-membrane read
fairness, clock monitoring/reserved headroom, INBOX, and direct authenticated
transport. Once that subset passes its gates, Phase 2A may branch without
waiting for the remaining families. Continue with Blind Core,
direct transports/FORWARD with the aggregate circuit cap and selected
route-budget design, OHTTP, and later gated transport adapters.

**Gate:** two unrelated fixture apps and a late third app use one unchanged
daemon/config; crash, replay, clock, GC, rebalance, quota, and lifecycle suites
pass. No family is advertised before its applicable V-2 through V-7 gates
pass; disk/log/metric sentinel scans find no application semantics.

### Phase 2A — conditional direct G2-S vertical slice

This phase runs only if the owner approves D-1. It packages DESCRIBE, CELL and,
if the product flow needs it, INBOX over direct authenticated transport, with
receipts, expiry, WAL/crash behavior, quotas, and truthful G2-S UI. Families not
implemented in the slice remain unadvertised. A small Peerit internal/invite
cohort supplies real workload and operations evidence while Blind Core,
FORWARD, OHTTP, and G3 continue independently.

**Gate:** the cohort passes the applicable V gates and redaction/claim lint;
stable inbox topics and live connection/access metadata are disclosed. This is
not evidence for G3, G2-W, or G4-T.

### Phase 3 — integrate the public HTTPS gateway

- Preserve legacy compatibility routes during migration.
- Merge exact-byte serving behind frozen T1 admission.
- Separate app and management listeners.
- Add signed gateway advertisements, publisher bindings, leases, and policies
  according to their release phases.
- Use stable publisher origins for writable browser apps.
- Keep key-derived operator origins for bootstrap, read-only access, recovery,
  and verification.
- Structurally prevent blind/custody records from becoming public app routes.
- Enforce a finite non-null production response limit before headers/streaming,
  bounded single-range behavior, byte-weighted egress budgets, slow-reader
  teardown, and a separate small transformed-response buffer cap.
- Keep proof-carrying retrieval unadvertised until bounded framed/streaming
  proof generation passes its own byte, work, concurrency, and memory limits.
- Promote this track from its T1/T2 classifier and gateway evidence; do not
  require unrelated OHTTP, Blind Core, or G3 completion and do not attach their
  privacy claims.

**Gate:** Host/SNI, forwarding, management, origin, range, HEAD, exact-byte,
shutdown, and failover suites pass; two gateways serve identical app bytes;
T2/unknown records always reject; V-GW1 passes; unsupported or multi-range
input cannot turn an oversized response into an unbounded full `200`.

### Phase 4 — storage-generation lanes

Server lane:

- validate exact HC11/CS7/HD13 pins;
- prove session-close isolation and real disk shrink after purge;
- prove mixed HC10/HC11 replication; and
- prefer a new empty storage root over irreversible in-place migration.

Browser lane:

- implement the rocksdb-native logical contract over IndexedDB;
- prove batches, MVCC snapshots, iterators, Web Lock fencing, crash recovery,
  quota behavior, and browser packaging; and
- promote browser HC11/Corestore 7 only after its separate gates.

Browser HC11 does not block the first Blind Cells release.

### Phase 5 — clean local/staging cohort

Run fresh multi-node relays with unrelated fixtures. Test protocol vectors,
T1/T2 isolation, receipts/proofs, multi-relay repair, OHTTP captures when
advertised, disk pressure, quota, clock jumps, process kills, WAL replay,
rebalance, restart, the 24-hour gateway window, and seven-day blind soak. Run
V-2 through V-7 as named adversarial tests, including flat staging/fsync
counters for invalid admissions, exact-once circuit teardown, N-connection
read fairness, the full clock matrix, route-budget reset/cycles, and
non-canonical commitment encodings. Run V-8 only for a candidate G3 profile.

**Gate:** all evidence names one immutable artifact and exact protocol hashes.

### Phase 6 — shared clients and PearBrowser RC

- Publish exact-version client/verifier RCs.
- Move desktop/mobile to signed relay and gateway discovery.
- Remove hostname-suffix trust and embedded legacy endpoint assumptions.
- Separate T1 content operations from blind operations.
- Verify publisher bindings and exact-byte/proof responses.
- Verify advertised read policy, limits, and clock-trust/readiness state; reject
  descriptor mismatch, downgrade, rollback, or an unsupported route policy.
- Show the effective profile and a visible downgrade. Same-operator OHTTP may
  not be presented as source separation.
- Preserve native Hyperdrive/Hyperswarm fallback.
- Adopt Pear-driven release resolution from section 7.
- Replace duplicate catalogue sources with one canonical source and generated
  mirrors.

**Gate:** cold install, launch, refresh, update, offline reopen, failover, and
catalogue convergence pass. No hostname, path, or semantic-version string acts
as an app trust root. UI/README claim lint rejects bare “anonymous,”
“unlinkable,” or whole-product “blind” wording without the surface, observer,
guarantee level, and residual leakage.

### Phase 7 — Peerit reference pilot

- Sign the legacy OutboxLog census and migration genesis.
- Dual-read legacy/blind state into one verified model.
- Make blind append the canonical new-write transaction.
- Preserve stable logical IDs and rollback floors.
- Use Blind Cells and generic inboxes for ordinary-browser production.
- Bind every enabled route to one of the four release profiles and show the
  effective guarantee rather than the strongest compiled capability.
- Keep physical inbox claims at G2-S. Keep G3 disabled until D-3, the renewal
  distribution and placement policy, repair readiness, and V-8 pass.
- For G3, schedule each cell independently from a frozen jitter distribution,
  forbid chain-wide renewal batching, avoid co-locating related cells or select
  independent lease classes, and bind the classifier workload/threshold and
  repair actor/cadence/incentive to the profile evidence.
- Keep `split-web-ohttp-v1`, G2-W, and G4-T disabled until D-2 supplies genuinely
  independent ingress and storage operators and their capture/evidence gates
  pass.
- Keep browser Hypercore experimental until its storage/transport gates pass.
- Bind writable identity state to a stable publisher origin.

**Gate:** all record operations, reload, recovery, offline convergence,
two-device restart, relay loss, sentinel, capacity, and dual-read rollback tests
pass. The first acknowledged blind-only write records the rollback boundary;
every later application rollback target is dual-read capable.

### Phase 8 — retention census and reprovision tooling

Create a signed fleet-reprovision-plan-v1, dry-run by default and limited to one
explicit node. It binds the target artifact, wave, old checkpoint/backup,
retained-object census, active contracts, identities, seed manifest, new storage
genesis, capacity, V-2 through V-7 evidence, clock-source/readiness evidence,
reserved-capacity thresholds, and required post-boot proofs.

**Gate:** unique/unknown objects equal zero; no custody/archive/paid lease is
discarded; off-node encrypted backup has passed an isolated restore.

### Phase 9 — rolling fleet reprovision

1. Establish authenticated host access and pinned host keys.
2. Drain one census-selected canary.
3. Snapshot the old root off-node.
4. Start the same signed RC on a new empty root.
5. Preserve T1 identity only when continuity is intended.
6. Generate independent blind and gateway role keys.
7. Republish from authoritative publisher stores.
8. Verify reconstruction, receipts, exact-byte serving, and capacity.
9. Verify authenticated-time readiness, backward-GC alarms, and reserved
   capacity before the node advertises open admission.
10. Complete gateway observation and blind soak.
11. Repeat canaries one at a time.
12. Repeat stable relays one at a time without violating replica floors.
13. Promote the same artifact to stable.
14. Retire old roots only after the legacy-read window.

No third-party storage operator enters a production wave before D-4. An OHTTP
privacy wave additionally requires ingress and storage roles with distinct
operator control, keys, hosts, deployment access, logs, and failure domains.

If temporary capacity is insufficient, add a temporary relay. Immediate total
capacity recovery and safe rollback are otherwise mutually exclusive.

### Phase 10 — application waves

1. Shared browser/relay contracts and publisher tooling.
2. PearBrowser desktop/mobile and Peerit.
3. Peerit-derived apps such as P2P Builders and Pearfeed.
4. Runtime consumers such as PearPaste, Pear POS, Peartube, and PearCup.
5. Publication-only owned apps and webpage drives.
6. Third-party entries as metadata only unless publisher authority exists.

Public app/site/media bytes use T1. Private/semantic state uses encrypted
blind/native P2P paths. Adding an app never changes blind-daemon code/config.

### Phase 11 — catalogue and PearBrowser release

1. Publish and pin approved apps.
2. Verify them from fresh readers with publishers offline.
3. Publish/pin the canonical catalogue under one stable identity.
4. Generate desktop, mobile, and website mirrors.
5. Build PearBrowser against that identity.
6. Publish/pin PearBrowser's Pear release and webpage drive.
7. Update its self-row without rebuilding the browser.
8. Complete native package signing separately.

CI fails on catalogue, app identity, release manifest, version, or drive-key
drift.

### Phase 12 — public collateral and Peerit

Generate p2phiverelay.xyz, pearbrowser.com, publisher sites, app websites,
webpage drives, READMEs, diagrams, GitHub releases/links, and catalogue metadata
from the same signed ecosystem manifests.

Promote Peerit through internal cohort, invite canary, and GA. GA requires
multi-relay durability, stable-origin release evidence, real-device
convergence, capacity proof, recovery rehearsal, T1/T2 isolation, and truthful
claims. GA may use the owner-approved G2-S profile; it does not silently wait
for or inherit G3/OHTTP. G3 requires D-3 and V-8. G2-W/G4-T requires D-2 and
independent-operator evidence. Public collateral and UI pass claim lint for
each surface. Legacy writes retire before legacy reads.

---

## 5. Fleet reset safety

“Clear the fleet” means verified rolling reprovision, never blanket deletion.

Inventory seeded keys/forks/lengths, registries, catalogues, Peerit heads/rows,
custody/shard/lease state, witness/repair state, accounting/operator identity,
and authoritative publishers.

Classify every object as:

1. reproducible from an authenticated publisher;
2. independently held and retrieval-proven above its floor;
3. sacred/contractual and explicitly migrated; or
4. unique/unknown.

Reprovision is blocked while category 4 is non-empty.

Code rollback checks out a prior signed tag. Data rollback restores the archived
root. Gateway rollback disables the public vhost/listener first. App rollback
after blind writes begins is dual-read, never legacy-only.

Full capacity means full designated capacity with OS/recovery headroom, not
100% disk use.

---

## 6. Per-app release contract

Each owned app signs an ecosystem release manifest containing:

~~~text
app and publisher identity
source commit and semantic version
accepted HiveRelay protocol hashes
stable Pear link and released checkout/sequence
webpage drive key, fork, length, and digest
publisher HTTPS binding
T1 gateway policy
enabled release profile IDs and accepted descriptor-policy classes
effective guarantee, observer model, residuals, and evidence hashes
catalogue identity digest
test, pin, retrieval, gateway, and browser-open evidence
~~~

Release order: deterministic build/test; profile-specific evidence and claim
lint; Pear release; webpage build/drive;
traditional website byte comparison; HTTPS binding; T1 pin/retrieval; blind
evidence when used; publisher-offline proof; cold browser opens; catalogue
materialization; evidence retention.

---

## 7. Pear-driven updates and catalogue materialization

### 7.1 Decision

Use Pear to resolve current native app releases automatically.

> The catalogue identifies the stable app, publisher, and update policy. The
> stable Pear link identifies the current released checkout. Catalogue semantic
> version is not update authority.

Normal version bumps do not require a new catalogue key, full catalogue rewrite,
or manual edits to every mirror.

### 7.2 Stable catalogue row

~~~json
{
  "id": "pearbrowser-desktop",
  "publisherKey": "<32-byte-key>",
  "pearLink": "pear://<stable-app-key>",
  "webReleaseManifestKey": "<stable-manifest-key>",
  "releaseMode": "pear-latest",
  "releaseChannel": "stable",
  "type": "standalone",
  "categories": ["browser", "tools"]
}
~~~

The row changes only for app addition/removal, stable-link change, publisher
rotation, app type/permission/compatibility/trust policy, or curated metadata.

### 7.3 Signed app release manifest

~~~json
{
  "type": "pear-app-release-v1",
  "appId": "pearbrowser-desktop",
  "sequence": 18,
  "version": "0.6.0",
  "pearLink": "pear://<stable-app-key>",
  "pearCheckout": 2847,
  "sourceCommit": "<git-commit>",
  "webDriveKey": "<32-byte-key>",
  "webDriveFork": 0,
  "webDriveLength": 312,
  "permissionsHash": "<hash>",
  "minimumRuntime": "<version>",
  "publisherKey": "<32-byte-key>",
  "signature": "<signature>"
}
~~~

The canonical encoding, field bounds, signature domain, and rollback rules must
be frozen before production.

### 7.4 PearBrowser resolution algorithm

PearBrowser:

1. validates the catalogue row and publisher binding;
2. resolves the stable Pear link through Pear Runtime;
3. obtains the released checkout/sequence;
4. reads and verifies pear-app-release-v1;
5. checks app, publisher, link, channel, and permissions continuity;
6. rejects release state below its persisted floor;
7. compares resolved sequence with installed sequence;
8. displays signed semantic version;
9. updates through Pear when policy permits; and
10. verifies HiveRelay availability for the released checkout/web drive.

Ordering uses signed sequence or checkout, never semantic version alone.

### 7.5 Optional catalogue materializer

A single-writer materializer may cache current versions for offline/faster
display without becoming authority. It watches approved Pear links, verifies
new signed releases and T1 evidence, upserts only app!<id> or appends one
app.upsert operation, advances the signed catalogue head, and emits evidence.

This is an incremental append under the existing catalogue identity, not a new
catalogue publication. Relays pin that identity once and follow new blocks,
subject to lease renewal and retrieval checks.

Existing foundations include Hyperbee app!<id> rows, experimental Autobee
app.upsert, and release tooling that reads Pear released length and refreshes
the HiveRelay pin.

PearBrowser currently compares catalogue semantic-version strings with installed
versions. It must instead compare verified release sequences/checkouts. Current
CLI helpers using deprecated release paths must migrate to the supported Pear
Runtime/update API; parsed human CLI output is evidence, not protocol.

### 7.6 Ordinary-browser releases

Pear cannot directly update an ordinary browser. The equivalent is:

~~~text
stable publisher origin
  -> signed web release manifest
  -> exact Hyperdrive bytes
  -> verified service-worker/loader floor
~~~

Normal browser activation verifies publisher, app/drive identity, asset root,
sequence, and rollback floor before running new code.

### 7.7 Security requirements

Automatic acceptance requires stable app/publisher identity, valid
domain-separated signature, monotonic sequence, allowed channel, no unapproved
permission/runtime/type/origin expansion, manifest/content agreement, required
HiveRelay retrieval evidence, and signed continuity for key rotation.

A fake high semantic version can never win catalogue aggregation. Aggregation
is identity- and verification-first.

### 7.8 Release gates

1. Two releases under one stable Pear link resolve without catalogue mutation.
2. PearBrowser detects the second from checkout/sequence.
3. Downgrade and same-sequence/different-manifest attempts fail.
4. Unauthorized publisher/link/permission/channel changes fail.
5. Materializer performs one bounded row upsert and mirrors converge.
6. A cold client updates with the publisher offline.
7. Relays serve the new released checkout.
8. An unchanged catalogue launches the newest accepted release.
9. The corresponding web release passes signed activation/rollback tests.

---

## 8. Upgrade versus rewrite

| Strategy | Strength | Blocking weakness |
| --- | --- | --- |
| Extend RelayNode in place | Lowest apparent effort | Cannot prove strict isolation with shared app stores/APIs/logs |
| Rewrite all HiveRelay | Clean source boundary | Rebuilds mature operations and compatibility before new value |
| Clean blind daemon in existing product | Clean security boundary plus mature operations | Requires strict process/key/store/listener separation |

The third strategy remains selected. The adversarial review increases the
pre-freeze contract and evidence work, but none of its findings requires
discarding HiveRelay's updater, packaging, seeding, fleet, or compatibility
shell. It reinforces the clean-daemon boundary rather than a full rewrite.

---

## 9. Immediate execution order

1. Preserve and commit the gateway implementation.
2. Create a clean vNext integration worktree.
3. Open the D-1 through D-7 decision register; obtain D-6 and D-7 before the
   blind spec hash, D-1 and D-5 at their named product boundaries, and let D-2
   through D-4 proceed in parallel behind their promotion gates.
4. Create the canonical protocol registry and reconcile CR-1 through CR-6 in
   both specifications.
5. Run V-1 and V-7; generate `specHash`, `abiHash`, and `vectorSetHash` only
   after they pass. V-2 and V-3 then block their runtime capabilities.
6. Scaffold blind protocol/client/daemon packages in the remediated build order.
7. Specify fleet-reprovision-plan-v1 in dry-run mode, including clock and
   adversarial evidence.
8. Create one canonical ecosystem release manifest/catalogue source with
   profile IDs and claim evidence.
9. Freeze pear-app-release-v1 and update vectors.
10. Refactor PearBrowser update detection and effective-profile display.
11. Bring up the disposable multi-node cohort and run V-2 through V-8 plus
    V-GW1 as applicable to each advertised profile.
12. If D-1 is approved, ship the invitation-only G2-S vertical slice and use
    its evidence to tune the full train.
13. Complete the server-first RC before production storage or dependent clients.
