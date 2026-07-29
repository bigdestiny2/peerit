# Peerit + HiveRelay Full Delivery Specification

**Status:** execution specification

**Date:** 2026-07-21

**Target release:** `v1.0.0-rc.1` followed by `v1.0.0`

**Scope:** Peerit, the full HiveRelay Blind Cell substrate, moderation and interchangeable feeds, fleet deployment, npm and container distribution, Umbrel, StartOS, TrueNAS and other home-server packages, migration, rollback, signing and operational evidence.

## 1. Delivery outcome

Full delivery means that a user can install Peerit or HiveRelay through a supported distribution channel, join the public network without trusting a single relay or web host, write and recover data through the full Blind Cell path, select a community-moderated or unmoderated feed, verify the chosen feed algorithm, survive an upgrade or relay outage, and roll back without corrupting or orphaning acknowledged data.

The release is complete only when all of the following are true:

1. One immutable Peerit source commit and one immutable HiveRelay source commit are the source of every artifact and every claim.
2. The full Blind Cell write, read, recovery and negative-credential paths pass on the production profile.
3. Community flagging, burying, appeals and unmoderated viewing are deterministic, abuse-resistant and independently auditable.
4. Feed algorithms are open-source, content-addressed and interchangeable without changing stored content.
5. The OCI images, npm tarballs, SBOMs, provenance, Peerit artifact, Umbrel app, StartOS package, TrueNAS package and generic home-server package all bind to the same exact source and dependency set.
6. A one-node pilot, multi-failure-domain canary and waved stable rollout complete with rollback evidence.
7. No production claim depends on one MacBook, one web origin, one relay, one signing key or one silent trust downgrade.
8. HTTPS gateway activation is a separate signed release. The initial core release ships it disabled.

## 2. Frozen starting state

### 2.1 HiveRelay

The maintenance baseline is:

- source commit: `f636ea0d9bd0b4c0d27c909ae484f87ff7e93206`
- source tree: `98b4f8ff5061e93284e76a1945c3435468991de0`

The clean local release candidate is:

- branch: `codex/v1.0.0-rc.1`
- candidate commit: `093c27103981f73615f8450d028171871a1bc200`
- candidate tree: `fcd1c1a40880c6e21cf0008d968e02da4283b9dc`
- local OCI tag: `hiverelay:v1.0.0-rc.1-local`
- local candidate-manifest digest: `sha256:7be146f0c1c66a0a78b3fbdd9d1a52010a45f1ebb34683de8f60420473f90214`
- manifest state: `localPreflight=passed`, `releaseReady=false`

The candidate already contains the release-version alignment, exact internal dependency pins, private Blind workspace boundary, Docker base-image digest pin, exact OCI source revision label, workflow source/metadata binding and native `blind-peercred` image fixes.

### 2.2 Peerit

The requested release lock is:

- requested commit: `8f173478`
- requested tree: `32774f5d`

This object pair is not currently available. It is absent from the Peerit object database, all local refs and reflogs, every Git repository scanned under the ecosystem, the historical Peerit preservation bundle, the advertised origin branches/tags and the GitHub commit endpoint. The GitHub lookup returns `No commit found for SHA: 8f173478`.

The current Peerit checkout at `6580a100d8607ea9a8064f3bcc2856102301d756` must not be silently substituted. The older `02dd7e9` handoff is superseded and must not be accepted.

This creates the first mandatory gate:

- recover the full `8f173478...` commit and prove tree `32774f5d...`; or
- make an explicit owner decision to re-lock Peerit to a complete, available commit/tree after comparing its delta and re-running the affected qualification.

### 2.3 HTTPS gateway

The HTTPS gateway remains a separate dependency:

- handoff commit: `96318d4f5f534e1b59fbfcb25db5b4b72b0f4d65`
- handoff tree: `eedd94e5c68d1efc784b0bfd14dea187a7624490`
- initial production manifest: `{"schema":"hiverelay-public-gateway-release-v1","enabled":false}`

Gateway code and core Blind Cell deployment are not the same release gate. The core release must not wait for HTTPS activation, and deploying core must not accidentally activate HTTPS.

### 2.4 Existing evidence

The integrated code line has previously reported:

- 356/356 unit tests passing;
- 45/45 integration tests passing;
- all four inherited v1-tip failures resolved;
- negative-credential health probing shipped;
- atomic-staging throughput improved from 34 to 140 concurrent PUTs/s in the recorded benchmark;
- INBOX unary operations and CORE `MIRROR`/`PROVE` assembled;
- three-process Blind Cell qualification passing.

The sealed RC has additionally passed a 65-test release regression slice, local manifest verification, four public npm package dry-runs, public-artifact secret scanning, YAML parsing, an `linux/amd64` image build and an in-image native `blind-peercred` import.

These are useful inputs, not substitutes for the exact-RC qualification campaign below. A later unit-suite attempt was stopped by the local sandbox denying `listen(127.0.0.1)` with `EPERM`; it is infrastructure evidence, not a product failure and not a passing run.

### 2.5 Dirty-worktree custody

The obsolete HiveRelay worktree has been captured without merging, restoring or deleting it:

- 19 paths classified `already-integrated`;
- 6 paths classified `superseded`;
- patch and branch bundle archived with hashes;
- archive ref retained;
- deletion remains a separate owner approval.

All unrelated Peerit launch/growth edits in the active checkout remain user-owned and outside this release integration scope.

## 3. Non-negotiable delivery rules

1. Never substitute a source hash, dependency hash, image digest, test topology or operator identity without recording a new decision and regenerating downstream evidence.
2. Never accept a lane using its producing agent. Every handoff receives independent review.
3. Never claim a skipped, simulated or macOS-hosted check as Linux, Tor, appliance, multi-architecture or fleet evidence.
4. Never publish from a dirty worktree.
5. Never acknowledge a Blind/HC11-only write and then roll back to a legacy-only writer. Rollback must retain dual-read capability.
6. Never treat burying as deletion. Community ranking, local filtering and operator `DO-NOT-SERVE` are separate controls.
7. Never enable `FORWARD` multi-hop or `CORE.OPEN_REPLICATION` merely because their internal services exist.
8. Never activate the HTTPS gateway as a side effect of the core rollout.
9. Signing, tagging, pushing, package publication, image publication, marketplace submission, DNS/key changes, fleet mutation and GA declaration require explicit human authority.

## 4. Workstream A — Re-lock sources and close custody

### A1. Resolve the Peerit source lock

Preferred path:

1. Obtain the original full commit object from the producing agent, worktree, clone, bundle or patch custody pack.
2. Import it into an isolated Peerit object database.
3. Verify its full commit ID, full tree ID, parents, author/committer metadata and signature status.
4. Create a preservation bundle and a read-only archive ref.
5. Compare it against `02dd7e9`, current `6580a100` and the moderation commit line.
6. Record why it is the canonical release input.

Fallback path, requiring an owner decision:

1. Select an available replacement commit only after producing a file-level and behavior-level delta from the intended handoff.
2. Confirm that it contains the 21 Blind Peerit commits, moderation integration, vote-index correction, production-profile binding, service-worker hardening, signing/pin-history work and capability recovery.
3. Record a new full commit/tree pair in the maintenance intake and all lane contracts.
4. Invalidate all Peerit evidence bound to the missing lock.
5. Re-run the full Peerit and cross-repository qualification.

Acceptance:

- both full hashes resolve locally;
- `git fsck` passes;
- a preservation bundle verifies as complete;
- no dirty or superseded state is included;
- every later artifact names this exact source pair.

### A2. Finish obsolete HiveRelay custody

1. Re-verify the archived patch, bundle and custody-manifest hashes.
2. Retain the archive ref through the first stable release and rollback window.
3. Link every classified path to the integrating or superseding commit.
4. Do not delete the old worktree until the owner separately approves deletion.

Acceptance:

- custody manifest is independently reviewed;
- all 25 paths have evidence-backed classifications;
- the release branch contains none of the obsolete patch by accident;
- rollback can recover the archive without relying on the original worktree directory.

## 5. Workstream B — Freeze product and protocol decisions

The decision register must be reconciled before protocol hashes or public promises freeze.

Required decisions:

| Decision | Required disposition for this release |
|---|---|
| Peerit source lock | Recover `8f173478/32774f5d` or explicitly approve a replacement full hash pair. |
| Blind workspace boundary | Keep six Blind packages private internal artifacts for RC1, or explicitly approve public package contracts and names. |
| `FORWARD` | Default: disabled/deferred. Enable only with an enforceable route budget or a signed acyclic route class and a new security review. |
| `CORE.OPEN_REPLICATION` | Default: disabled/deferred until native descriptor topology, authenticated parent session and upstream signed-head proof authority exist on the public surface. |
| D-6 / `K_partition` | Reconcile the old blocked ledger with the later report that D-6 no longer blocks; record the authoritative decision and regenerate `specHash` inputs. |
| D-7 rollback floor | Approve exact wording: after an acknowledged Blind/HC11-only write, rollback is dual-read and never legacy-only write. |
| HTTPS gateway | Core release ships disabled; activation occurs only in the later gateway release. |
| Pilot cohort | Add a signed `pilot` cohort, preferred, or temporarily leave Bern as the only canary and bind the other two nodes to stable. |
| Moderation defaults | Community feed is the recommended default, unmoderated feed remains available, and operator takedown is not conflated with ranking. |
| Operator independence | Mechanism can be tested with same-owner staging nodes, but GA multi-relay claims require at least two independent human operators. |

Acceptance:

- every decision has owner, timestamp, scope and supersession target;
- protocol/store/IPC hashes are regenerated only after the relevant decisions close;
- unresolved optional families are omitted from the v1 public capability manifest;
- release documentation makes no claim broader than the enabled capability set.

## 6. Workstream C — Canonical contracts and generated surfaces

1. Freeze the Blind protocol catalogue, operation inventory and named/internal store sets.
2. Generate and verify protocol `specHash`, store-format hash, IPC hash and capability-document hash.
3. Verify exact byte stability under Node and Bare.
4. Generate IPC bindings, browser artifacts, client composition authority and protocol fixtures from one authority source.
5. Fail CI if generated files drift.
6. Bind Peerit’s production profile to the exact protocol/store/IPC/capability hashes.
7. Publish no capability for deferred `FORWARD` or `OPEN_REPLICATION` operations.

Acceptance:

- generation produces no diff on a second run;
- Node, Bare and browser readers accept the same vectors;
- malformed, stale, cross-profile and unsupported capabilities fail closed;
- catalogues, docs, packages and runtime dispatch expose the same operation set;
- independent review confirms that fixture counts are coherent and intentional.

## 7. Workstream D — Moderation and interchangeable feeds

### D1. Content and event model

Moderation must be expressed as signed events, not mutable server-owned counters. At minimum support:

- `REPORT`: reporter, target content ID, bounded reason code, timestamp/sequence and signature;
- `KEEP`: eligible community signal that counters burial pressure;
- `APPEAL`: author challenge bound to the target and moderation epoch;
- `RESOLVE`: algorithm- or community-derived resolution without deleting source content;
- local `MUTE`/`BLOCK`: private user preference, never uploaded as a public accusation by default;
- operator `DO_NOT_SERVE`: a separate opaque-ID availability control with audit reason, timestamp and restore path.

Events carried in Blind Cells must remain opaque to custody relays and must use the same atomic staging, authorization and replay protections as other Cell writes.

### D2. Feed modes

Peerit must ship at least:

1. **Community:** eligible reports and keep votes feed a deterministic majority/threshold policy; buried content is collapsed and excluded from normal ranking but remains intentionally revealable where lawful and available.
2. **Consensus:** a stricter configured policy using an explicit trust/eligibility set.
3. **Open/unmoderated:** no community burial in ranking; local blocks and operator availability rules still apply.

The selected mode is a user-visible preference. A release may recommend Community but must not remove Open/unmoderated viewing by silently changing the storage layer.

### D3. Open algorithm registry

Every selectable algorithm descriptor must include:

- stable algorithm ID and semantic version;
- source repository and source commit;
- content hash of the executable or deterministic module;
- input event schema and output/ranking schema;
- parameter schema and defaults;
- deterministic tie-breaking rules;
- resource limits;
- migration behavior for version changes;
- security review status;
- human-readable explanation shown in Peerit.

Stored posts and moderation events must remain algorithm-independent. Switching algorithms recomputes the view; it does not rewrite or fork the underlying social data.

### D4. Abuse resistance

Qualification must cover:

- Sybil reporting and burst-report attacks;
- replayed, duplicated, expired and backdated reports;
- author self-report and coordinated reciprocal reporting;
- eligibility changes during an active moderation epoch;
- report/keep ties and deterministic tie-breaking;
- appeal and resolution replay;
- visibility convergence across two writers and two relays;
- blocked reporters and locally muted authors;
- unavailable or malicious algorithm modules;
- algorithm downgrade and hash mismatch;
- the distinction between buried, locally hidden and operator-suppressed content.

Acceptance:

- pure policy vectors, UI tests, browser bundle tests and real two-writer convergence pass;
- two clients calculate the same result from the same event set;
- the UI names the active algorithm and explains why an item was buried;
- users can select unmoderated mode without reloading or losing state;
- no algorithm gains signing, storage, network or arbitrary code authority beyond its declared sandbox.

## 8. Workstream E — Full Blind Cell runtime

### E1. Required v1 surface

The release must expose and qualify:

- atomic `CELL.PUT`, `CELL.GET` and readback;
- INBOX six-operation unary family through edge, daemon and storage;
- CORE `MIRROR` and `PROVE` unary operations;
- staged commit, quota and per-spend/per-cell locking;
- signed descriptors and production-profile capability negotiation;
- negative-credential probes;
- restart, migration and recovery against an existing store;
- authorization failure without information leakage;
- browser/Bare/Node client composition.

### E2. Deferred surface

- `FORWARD` stays absent until route-budget/acyclic-route requirements close.
- `CORE.OPEN_REPLICATION` stays absent until topology, parent-session authentication and signed-head authority close.
- A built or unit-tested internal service is not sufficient for a public capability claim.

### E3. Full-path drills

1. Start edge, daemon and storage as distinct processes.
2. Install a signed production descriptor.
3. Perform an authorized Cell write and exact-byte readback.
4. Restart each process independently and repeat readback.
5. Present bogus credentials and prove rejection plus health degradation if an unauthorized connection is accepted.
6. Revoke or lose the active capability, recover through the supported path and prove that the old capability cannot resume writes.
7. Exercise disk pressure, quota exhaustion, duplicate spend and crash-between-stage-and-commit.
8. Run the Peerit production client through the same path rather than a test-only client.

Acceptance:

- every acknowledged write is durable or recoverable;
- unauthorized requests fail closed and do not enumerate cells;
- recovery restores access without weakening old-key revocation;
- no test depends on an in-process shortcut unavailable in production;
- evidence includes process IDs/topology, runtime versions, descriptor hashes and raw transcripts.

## 9. Workstream F — Remove practical single points of failure

First verify whether each older finding is already fixed on the exact RC. Reimplement only confirmed gaps.

### F1. Durability and relay correctness

- tolerate or quarantine a torn final journal record without losing the valid prefix;
- acknowledge Hypercore writes only after the required durability boundary;
- derive or distribute namespace invite authority consistently across relays;
- expose and sign a canonical namespace-policy hash;
- support idempotent journal export/import with signature re-verification;
- accept an optional writer-signed monotonic `_v` and retain the highest valid version per key;
- attach timestamp and bounded reason to takedown/restore audit entries;
- retain the narrowed atomic-staging locks and starvation-proof tests.

### F2. Discovery and multi-relay operation

- cache the last-known-good signed, unexpired roster;
- never downgrade silently to an unsigned static relay list;
- ship roster mirrors in the production artifact;
- test sticky read failover, withholding detection, cross-head verification and quorum commit;
- sign a two-relay staging roster with `singleIngressWriter` removed;
- complete a relay-offline write/read/recovery drill;
- require at least two independent operators before making a decentralized production claim.

### F3. Bootstrap and service worker

- bind the signed Peerit asset manifest to exact content hashes and release sequence;
- maintain a monotonic pin-history chain and explicit rollback floor;
- make the service worker reject stale, unsigned, wrong-key and hash-mismatched updates;
- test offline boot from the last valid pin;
- test mirror failover without silently changing trust roots;
- provide an origin-independent Pear/Hyperdrive install path;
- add content-addressed web mirrors where the browser platform permits them;
- keep the HTTPS shared-origin surface unable to widen service-worker scope.

### F4. Signing and key survivability

- replace placeholder read-key material through an offline ceremony;
- record `rkHash`/key ID in the signed release manifest;
- support a dual-epoch read-key window;
- support current and previous release keys with per-key sequence floors;
- move release and roster signing toward 2-of-3 custody;
- publish an append-only transparency record for release sequences, roster versions and revocations;
- maintain offline encrypted backups and a tested recovery ceremony.

Acceptance:

- power-cut, torn-tail, key-rotation, roster-CDN outage, relay-loss and stale-service-worker drills pass;
- no single host or key loss can silently replace trusted code or permanently strand acknowledged data;
- unavoidable residues—public content visibility to serving operators and unrecoverable user keys without backup—are documented honestly.

## 10. Workstream G — Build one immutable release set

### G1. Source and version seal

1. Re-lock the final HiveRelay and Peerit full hashes.
2. Ensure the release worktrees are clean.
3. Confirm all public package versions and internal dependency ranges are exactly `1.0.0-rc.1`.
4. Keep private Blind workspaces private unless the release-boundary decision changes.
5. Pin every Docker base by digest.
6. Make code, metadata and version generation consume the same source commit.

### G2. npm artifacts

For each public npm package:

- create the tarball with lifecycle scripts disabled where safe;
- record filename, package name/version, SHA-256, size and file list;
- run a secret/path/license scan;
- install it into a clean consumer fixture;
- run Node and Bare import/smoke tests;
- verify no workspace-relative or unpublished private dependency leaks into the tarball.

Publication is a later human-authorized step. Dry-run tarballs are required before signing.

### G3. OCI images

- build `linux/amd64` and `linux/arm64` from the sealed commit;
- produce one multi-architecture OCI index;
- bind OCI revision/source/version labels to the source commit;
- generate SBOMs for index and platform images;
- generate build provenance and dependency attestations;
- scan for secrets, critical vulnerabilities and unexpected setuid/capability files;
- run native `blind-peercred`, health, Cell and persistence smoke tests on both architectures;
- record platform digests and final index digest.

### G4. Release manifest

The canonical manifest must bind:

- HiveRelay and Peerit commit/tree pairs;
- package-lock and generated-contract hashes;
- npm tarball hashes;
- OCI index/platform digests;
- SBOM/provenance hashes;
- appliance metadata hashes;
- Peerit asset-manifest and pin-history heads;
- gateway manifest hash with `enabled:false`;
- migration and rollback versions;
- test-evidence index hash;
- signer policy and required signatures.

`releaseReady` remains false until every required external gate is attached and independently reviewed.

## 11. Workstream H — Distribution packages

### H1. Generic Docker and Compose

Provide the reference distribution used by the platform wrappers:

- immutable image digest, never a floating production tag;
- persistent data volume and explicit ownership;
- read-only root filesystem where compatible;
- dropped Linux capabilities and `no-new-privileges`;
- documented inbound ports and Tor requirements;
- health, readiness and negative-credential health behavior;
- backup, restore, upgrade and rollback commands;
- resource minimums and recommended sizing;
- optional reverse-proxy profile without enabling the public HTTPS gateway.

### H2. Umbrel

- app manifest, compose file, icon/gallery metadata and release notes use one version/digest source;
- persistent storage survives uninstall/reinstall choices as documented;
- UI health and launch URLs are correct;
- install, start, stop, restart, update, backup/restore and rollback pass on a real Umbrel VM/device;
- export the official-app-store submission artifact only after runtime review.

### H3. StartOS

Maintain both supported packaging lines only if both are genuinely supportable:

- 0.3.5 and 0.4 metadata bind to the immutable image digest;
- actions, health checks, dependencies, volumes, interfaces and backup rules agree;
- `make verify`/SDK verification passes;
- install, start, stop, restart, update, backup/restore and rollback pass on a StartOS VM/device;
- registry submission remains a separate approval.

### H4. TrueNAS SCALE

Provide a catalog-ready app or a fully documented Custom App definition:

- immutable image digest and architecture support;
- host-path or dataset-backed persistent storage with UID/GID guidance;
- service, health check and restart policy;
- ingress/port configuration that does not widen the HTTPS gateway;
- resource requests/limits and disk-pressure behavior;
- SCALE install, update, backup/restore and rollback smoke evidence;
- catalog schema validation for the supported TrueNAS release.

### H5. Other home-hosting platforms

Tier 1 release support:

- Umbrel;
- StartOS;
- TrueNAS SCALE;
- generic Docker Compose.

Tier 2 maintained wrappers, built from the same digest:

- Unraid Community Applications XML/template;
- CasaOS app manifest;
- Portainer stack template.

Tier 3 documented compatibility, not marketplace certification:

- Synology Container Manager;
- QNAP Container Station;
- Proxmox VM/LXC hosting through the generic Docker profile;
- plain Linux/systemd using the OCI image or npm CLI where supported.

Every platform page must clearly state its support tier. A copied manifest without lifecycle evidence is not a supported release.

## 12. Workstream I — Exact-RC qualification campaign

All tests run from sealed source or sealed artifacts. Raw output is retained even on failure.

### I1. Core correctness

Run three consecutive clean passes of:

- HiveRelay unit suite;
- HiveRelay integration suite;
- generated-file and protocol authority checks;
- lint and package boundary checks;
- public artifact secret scan;
- local release-manifest verification.

Flakes are failures until root-caused. Re-running until green without retaining failed output is prohibited.

### I2. Runtime matrix

- Node current supported LTS;
- Bare supported release;
- Chromium/browser bundle;
- `linux/amd64` image;
- `linux/arm64` image;
- three separate Blind Cell processes;
- at least two relay processes for quorum/failover paths.

### I3. Peerit

- `test:ship` on the exact Peerit lock;
- community moderation policy and UI suites;
- service-worker update/offline/rollback suite;
- signing, asset-manifest and pin-history verification;
- capability loss/recovery/revocation suite;
- both real HiveRelay Cell end-to-end tests;
- OutboxLog two-writer convergence including the formerly asymmetric local vote tally;
- suppress/restore drill in staging with an authorized admin secret;
- production-profile Cell write/readback/restart/recovery drill.

### I4. Storage, migration and rollback

- existing-store upgrade from the last production format;
- new-root creation;
- legacy plus new dual-read;
- acknowledged new-format write;
- rollback to the approved dual-read build;
- forward re-upgrade;
- crash at each stage/commit boundary;
- disk-full and quota exhaustion;
- corrupted/torn journal tail;
- backup and restore on a second host;
- prove that legacy-only writer rollback is blocked after the migration floor advances.

### I5. Network and adversarial evidence

- fifth valid 100 MB bulk-over-real-Tor run;
- invalid-credential negative probe and fail-open detection;
- relay loss during PUT and GET;
- roster mirror loss and last-known-good recovery;
- signed-head withholding and equivocation detection;
- invalid/stale descriptors and capability downgrade;
- multi-ingress quorum with distinct writers;
- rate, quota and disk-pressure behavior;
- no-content-oracle behavior for denylist/takedown identifiers;
- community moderation Sybil/replay/burst vectors.

### I6. Linux WAL and performance

- run the Phase-0 WAL harness on real Linux storage;
- record kernel, filesystem, mount options, disk model and flush semantics;
- run power-loss/restart cases where the harness supports them;
- retain the 140 PUT/s atomic-staging improvement or explain any regression;
- measure latency and throughput at representative concurrency, payload size and disk pressure;
- set release budgets and fail the gate when exceeded.

### I7. Appliance lifecycle

For every Tier 1 platform:

- clean install;
- first boot;
- authorized Cell PUT/GET;
- unauthorized negative probe;
- stop/start and host reboot;
- update from prior supported release;
- data backup and restore;
- rollback within the approved floor;
- uninstall/reinstall behavior;
- disk pressure and log rotation;
- UI and health-state verification.

Acceptance:

- the complete evidence index is independently reviewed;
- all mandatory results pass on their declared topology;
- every exception has an owner-approved waiver with expiry and bounded public claim;
- artifact hashes tested are exactly the artifact hashes proposed for signing.

## 13. Workstream J — Pilot, canary and stable rollout

### J1. Control-plane correction

The current canary pointer covers three nodes, which is incompatible with a one-node migration pilot. Before publishing any RC channel:

- add a signed `pilot` cohort containing only Bern; or
- temporarily bind Utah and Utah-0.5GB to stable and leave Bern as the only canary.

Bern is preferred first because it is canary-designated and has approximately 484 GB available.

### J2. Pilot

1. Cut and verify the signed annotated RC tag after explicit approval.
2. Provision allowed signers and exact `RELAY_NAME` on Bern.
3. Publish only the pilot/canary channel through the signed control workflow.
4. Verify exact commit and image digest on the node.
5. Run WAL health, migration, Cell PUT/GET/readback, negative credential, Tor, disk pressure, restart and rollback drills.
6. Observe for the defined soak window with zero unexplained state transitions.

### J3. Canary expansion

1. Attach Bern evidence to the promotion record.
2. Expand one node at a time across failure domains.
3. Stop automatically on integrity, authorization, WAL, descriptor, quorum or rollback failure.
4. Keep HTTPS disabled.

### J4. Stable

1. Promote stable only with independently accepted canary evidence.
2. Roll the six stable nodes in failure-domain waves, never all at once.
3. Confirm quorum and read availability between waves.
4. Retain the previous dual-read image and signed rollback channel through the rollback window.
5. Publish the final fleet evidence bundle and transparency entry.

Acceptance:

- every node reports the expected source/image/config hashes;
- no node accepted unauthorized credentials;
- no acknowledged write was lost during update or rollback;
- stable service remains available throughout waved rollout;
- operator-visible health distinguishes degraded security from ordinary unavailability.

## 14. Workstream K — Bind and activate Peerit

After the relay RC is immutable and its pilot is healthy:

1. Bind the Peerit production profile to exact protocol, store, IPC, descriptor and relay-release hashes.
2. Generate the Peerit app artifact from the sealed Peerit commit.
3. Generate the asset manifest and monotonic pin-history entry.
4. Sign them only after explicit signing approval.
5. Install the signed relay descriptors.
6. Run production-profile Cell write/readback/restart/capability-recovery.
7. Verify community, consensus and unmoderated feed selection on the real relay path.
8. Activate Peerit for the pilot cohort.
9. Expand Peerit canary only after the pilot evidence is accepted.
10. Promote stable using the same failure-domain discipline as the relay.

Acceptance:

- Peerit never falls back to the superseded OutboxLog-only or unsigned relay path without explicit user-visible degraded mode;
- feed selection survives restart and produces deterministic results;
- stale service workers and stale pins cannot downgrade the production profile;
- capability recovery restores the intended identity while revoked credentials remain rejected;
- the production app names the exact release and support tier in diagnostics.

## 15. Workstream L — Later HTTPS gateway activation

The gateway release begins only after the core release is stable.

Required evidence:

- G7–G13 operator/fleet evidence;
- two operators with distinct domains and keys;
- signed tag and manifest digests;
- operator-contract digests;
- `nginx -T` or equivalent effective-config capture;
- real-host exclusive whole-root ceiling;
- independent domain, TLS and operator review;
- service-worker scope isolation;
- unknown SNI/Host mismatch, method, size, timeout, egress and denylist conformance;
- rollback to core-with-gateway-disabled.

Activation requires a new signed manifest with `enabled:true`; modifying the existing disabled manifest in place is prohibited.

## 16. Evidence and review contract

Every lane handoff must contain:

- exact repositories, commits and trees consumed;
- commits and artifact hashes produced;
- clean/dirty state;
- commands and unabridged raw outputs;
- runtime, OS, architecture, device and network topology;
- test counts and explicit skipped tests;
- migration and rollback results;
- inherited failures and new risks;
- public documentation/consumer impact;
- requested next gate;
- producer identity;
- different reviewer identity, verdict and timestamp.

The final evidence index must be content-addressed and included in the signed release manifest.

## 17. Human authority gates

The following actions are deliberately not implied by implementation approval:

| Gate | Required authority |
|---|---|
| Replace the missing Peerit lock | Owner decision naming the new full commit/tree pair. |
| Resolve D-6/D-7, `FORWARD`, replication and package-boundary decisions | Product/protocol owner. |
| Delete obsolete worktrees or discard unknown changes | Explicit custody approval. |
| Generate/use production keys or rotate trust roots | Key custodians under the approved ceremony. |
| Create signed tag or sign manifests/artifacts | Release signers. |
| Push branch/tag, publish npm/image/release | Repository/release owner. |
| Publish Umbrel/StartOS/TrueNAS/other marketplace entries | Marketplace owner/reviewer. |
| Change DNS, TLS or public gateway state | Domain/gateway operators. |
| Mutate pilot/canary/stable fleet | Fleet owner. |
| Add independent operators to production roster | Roster signers plus operator-contract approval. |
| Declare `v1.0.0` GA | Owner after final independent assurance. |

## 18. Definition of done

`v1.0.0-rc.1` is release-candidate complete when:

- source locks resolve and preservation bundles verify;
- all mandatory decisions for the advertised surface are closed;
- exact-RC qualification is green;
- all npm, OCI and Tier 1 platform artifacts are built and hash-bound;
- SBOM, provenance, migration and rollback evidence are complete;
- a signed tag/artifact set exists after approval;
- Bern pilot and cross-failure-domain canary pass;
- Peerit production-profile canary passes;
- HTTPS remains disabled.

`v1.0.0` is fully delivered when, in addition:

- stable fleet rollout completes in waves;
- supported distribution channels publish the same immutable artifact set;
- at least two independent operators are active for any multi-operator claim;
- support, upgrade, backup, recovery and incident runbooks are public and tested;
- transparency and pin-history records are published;
- all remaining exceptions are explicitly deferred without being exposed as v1 capabilities;
- final independent assurance accepts the release and the owner authorizes GA.

## 19. Immediate execution order

1. Recover or explicitly replace the missing Peerit source lock.
2. Independently accept source custody and close PG-0.
3. Reconcile D-6/D-7 and freeze the v1 public capability boundary.
4. Freeze/generate canonical protocol, store, IPC and capability hashes.
5. Requalify Blind runtime, storage and moderation integration.
6. Build the one-source npm/OCI/SBOM/provenance artifact set.
7. Complete Tier 1 packages: generic Docker, Umbrel, StartOS and TrueNAS.
8. Complete Tier 2 wrappers: Unraid, CasaOS and Portainer.
9. Run the three-pass, cross-runtime, multi-architecture, Tor, Linux WAL, migration and appliance campaign.
10. Obtain explicit approval for signing/tagging/publication/fleet mutation.
11. Pilot Bern, expand canaries, then roll stable in waves.
12. Bind and activate Peerit against the immutable relay release.
13. Activate HTTPS only through its later independently signed gateway release.

The critical path begins with item 1. HiveRelay-only artifact work can continue in parallel, but no full Peerit release or cross-repository production claim can close until the Peerit source lock is real and immutable.
