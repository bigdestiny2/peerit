# Peerit profile for the HiveRelay blind substrate

**Status:** build specification; not yet a production claim

**Profile ID:** `@peerit/hiverelay-profile-v1`

**Date:** 2026-07-11

Peerit is a consumer of the HiveRelay blind substrate. It is not the authority
for the substrate protocol, wire IDs, relay descriptor, admission system,
storage engine, or privacy transports. The canonical substrate specifications
live in the HiveRelay repository:

- `docs/protocol/BLIND-APP-AGNOSTIC-HIVERELAY-MASTER-SPEC.md`
- `docs/protocol/BLIND-SUBSTRATE-IMPLEMENTATION-SPEC.md`

The repository-level preserve/replace/retire boundary and implementation sequence
are maintained in `PEERIT-BLIND-SUBSTRATE-DELIVERY-MAP.md`. That map is
subordinate to this profile and cannot add a relay field, permission service, or
weaken a release-qualification requirement.

This document is the sole normative consumer-profile authority for Peerit's
encrypted inner records, authority rules, bootstrap, migration ordering, client
behavior, and release qualification. Every Peerit build that reads or writes the blind
substrate MUST pin its exact profile/validator artifacts. A HiveRelay daemon MUST
NOT import this file, these codecs, or any `peerit.*` signature domain; mandatory
for Peerit means opaque and nonexistent from the relay's point of view.

This profile is Peerit's replacement production data path. After the signed
migration window, Peerit creates, discovers, reads, and repairs new state only
through the generic substrate. Legacy OutboxLog and BlindShard readers are
migration importers, not fallback writers or permanent availability dependencies;
HiveRelay never learns that the opaque objects belong to Peerit.

The release authority is build and migration provenance only. It is not an
online permission service, content-signing authority, relay allowlist, or
discovery censor. A locally valid author event remains valid when the release
origin, every maintainer, every recommended relay, or the complete network is
offline. Network loss queues delivery; it never disables or erases authoring.

`MUST`, `MUST NOT`, `SHOULD`, `SHOULD NOT`, and `MAY` are normative.

---

## 1. Static compatibility and migration pin

Every official Peerit build carries the following canonical release-signed pin.
It identifies the artifacts and substrate tuples that build can encode and read,
and freezes migration provenance. It never authorizes an account, expires an
author event, makes a relay eligible, or permits a discovery maintainer to accept
or reject content. A producer using compatible canonical bytes does not need a
current Peerit release service.

```text
SubstrateTupleV1 {
  specHash:       32 bytes
  abiHash:        32 bytes
  vectorSetHash:  32 bytes
}

PeeritHiveRelayProfilePinV1 {
  version:                    u8 = 1
  profileId:                  "@peerit/hiverelay-profile-v1"
  releaseSequence:            u64
  previousPinHash:            optional 32 bytes
  emitSubstrate:              SubstrateTupleV1
  readSubstrates:             sorted array[1..3] of SubstrateTupleV1
  profileSpecHash:            32 bytes
  profileAbiHash:             32 bytes
  profileVectorSetHash:       32 bytes
  validatorArtifactHash:      32 bytes
  validatorVectorSetHash:     32 bytes
  availabilityPolicyHash:     32 bytes
  recommendedBootstrapHashes: sorted array[0..16] of 32 bytes
  pinHistoryRetentionDays:    u16 = 3650
  appArtifactHash:            32 bytes
  webAssetManifestHash:       32 bytes
  legacySourceSetHash:        32 bytes
  migrationStage:             PeeritMigrationStageV1
  migrationTransitionEvidenceHash:optional 32 bytes
  legacyImportMode:           u8 // 0 live-dual-read, 1 frozen-cutoff, 2 archive-only
  legacyReadMode:             u8 // 0 dual-read, 1 archive-only
  legacyCutoffHash:           optional 32 bytes
  migrationGenesisRecordId:   optional 32 bytes
  cutoffActivationReleaseSequence:optional u64
  legacyRetirementEvidenceHash:optional 32 bytes
  legacyRetirementActivationReleaseSequence:optional u64
  releaseAuthoritySequence:   u64
  releaseAuthorityPublicKey:  32 bytes
  releaseAuthorityKeyId:      32 bytes
  authorityTransitionHash:    optional 32 bytes
  signature:                  64 bytes
}

PeeritPinHistoryCheckpointV1 {
  version:                    u8 = 1
  checkpointSequence:         u64 // equals releaseSequence
  previousCheckpointHash:     optional 32 bytes
  pinHash:                    32 bytes
  previousPinHash:            optional 32 bytes
  issuedUnixMillis:           u64
  releaseAuthoritySequence:   u64
  releaseAuthorityKeyId:      32 bytes
  signature:                  64 bytes
}

PeeritPinHistoryBundleV1 {
  version:                    u8 = 1
  checkpoints:               ordered array[1..256] of canonical complete signed
                               PeeritPinHistoryCheckpointV1 bytes[1..1024]
  pins:                       ordered array[1..256] of canonical complete signed
                               PeeritHiveRelayProfilePinV1 bytes[1..8192]
}
```

The emit tuple MUST occur exactly once in `readSubstrates`. The arrays sort by
their complete canonical bytes. The first pin has `releaseSequence = 0` and no
`previousPinHash`; every later pin has sequence exactly one greater than the
preceding complete signed pin and names that pin's hash. A release sequence has
exactly one pin hash; a same-sequence fork or sequence gap fails closed and is
reported. Application marketing versions are independent labels and never create
gaps in this continuity sequence. Pin continuity proves which official artifacts
were released; it is never an author or content floor. A producer release
sequence is deliberately absent from author bindings and announcements.

Migration provenance is one closed, monotonic registry:

| ID | `PeeritMigrationStageV1` | Meaning for the official migration adapter |
| ---: | --- | --- |
| 0 | `LIVE_DUAL_READ` | Read the compatible legacy sources and blind substrate; legacy mirroring may be measured separately |
| 1 | `FROZEN_CUTOFF` | The legacy census cutoff is fixed; the official client emits no new legacy writes |
| 2 | `ARCHIVE_ONLY` | Read the blind substrate plus immutable signed legacy archive |

The only valid edges are `LIVE_DUAL_READ -> FROZEN_CUTOFF -> ARCHIVE_ONLY`, with
same-stage releases allowed. `migrationTransitionEvidenceHash` is present exactly
when the migration stage, import/read mode, cutoff, genesis, or retirement state
changes. It proves the official release process and never enters an author event,
relay request, replica binding, announcement, maintainer decision, or reader
content-validity check.

Canary percentages, invited channels, incident advisories, and release telemetry
are distribution metadata outside this canonical consumer profile. They may guide
which official artifact is offered by default and whether automatic background
work is enabled. They cannot make a compatible author event invalid or give a
maintainer permission to omit it. Old and modified clients can send generic bytes;
the protocol intentionally accepts their content when intrinsic codec, signature,
causal, and replica proofs pass.

Pin continuity is independently retrievable from content-addressed pin,
checkpoint, and deterministic bundle objects. Transport locations are untrusted
hints and may be HTTPS mirrors, generic Cells/Cores, local files, or direct peer
transfer; no single URL is mandatory. A checkpoint's signature domain is
`peerit.pin-history-checkpoint.v1`. Sequence zero alone omits both predecessor
fields; every later checkpoint is exactly +1, names the prior checkpoint and pin,
and its pin hash/sequence/authority equal the fetched complete pin. There is exactly
one checkpoint per pin.

A bundle contains the deterministic contiguous suffix of at most 256 checkpoints
ending at its terminal hash plus their one-to-one complete pins in the same order.
Each inner object validates independently; the bundle adds no authority. Missing
newer history reports `UPDATE_PROVENANCE_UNKNOWN`; the installed build continues
to author locally and deliver through its last verified compatible tuple. A gap
is never a new trust root and never turns a valid event into a read-only draft.

`legacyImportMode` permits only `0 -> 1 -> 2`. The cutoff hash, migration genesis
record ID, and cutoff activation release sequence are jointly absent in mode 0 and
required in modes 1/2. On the first frozen-cutoff activation the activation
sequence equals the current release sequence; later pins retain those values and
descend from that pin. `legacyReadMode` permits only `0 -> 1`; archive-only mode
requires import mode 2 and nonzero retirement evidence plus its activation
sequence. These fields decide which legacy bytes enter the signed migration
census. They do not prevent an old client from writing a legacy endpoint and do
not control blind authoring. Post-cutoff legacy bytes remain outside the archive
unless their author republishes them through the blind substrate.

Before evicting the oldest read tuple/bootstrap from the three-entry window, the
release must prove that every retained logical record reachable only through that
tuple has been independently re-enveloped under the current tuple on all three
selected witnessed operator groups and distinct store IDs, with distinct
shared-journal IDs among profile-2 bindings, and passes the equality matrix. An unsupported old tuple is
never treated as an empty or deleted history.

### 1.1 Reproducible sources and hashes

The sole-source profile artifacts are checked in at these paths:

```text
docs/PEERIT-BLIND-SUBSTRATE-PROFILE.md
protocol/peerit-profile-v1.cenc
protocol/vectors/peerit-profile-v1.manifest.cenc
protocol/validator/peerit-validator-v1.bundle
protocol/validator/peerit-validator-v1.manifest.cenc
protocol/availability-policy-v1.cenc
```

The release builder accepts UTF-8 profile text only when it has no BOM or CR,
uses LF, and has exactly one final LF. It computes:

```text
profileSpecHash = BLAKE2b-256(
  "peerit.hiverelay.profile-spec-hash.v1" || len64(profileSpecBytes) ||
  profileSpecBytes
)

profileAbiHash = BLAKE2b-256(
  "peerit.hiverelay.profile-abi-hash.v1" || len64(profileRegistryBytes) ||
  profileRegistryBytes
)

profileVectorSetHash = BLAKE2b-256(
  "peerit.hiverelay.profile-vector-set-hash.v1" ||
  len64(profileVectorManifestBytes) || profileVectorManifestBytes
)

validatorArtifactHash = BLAKE2b-256(
  "peerit.hiverelay.validator-artifact-hash.v1" ||
  len64(validatorArtifactBytes) || validatorArtifactBytes
)

validatorVectorSetHash = BLAKE2b-256(
  "peerit.hiverelay.validator-vector-set-hash.v1" ||
  len64(validatorVectorManifestBytes) || validatorVectorManifestBytes
)

availabilityPolicyHash = BLAKE2b-256(
  "peerit.hiverelay.availability-policy-hash.v1" ||
  len64(availabilityPolicyBytes) || availabilityPolicyBytes
)

bootstrapHash = BLAKE2b-256(
  "peerit.hiverelay.bootstrap-hash.v1" ||
  len64(canonicalCompleteSignedBootstrap) || canonicalCompleteSignedBootstrap
)

recommendedBootstrapSetHash = BLAKE2b-256(
  "peerit.hiverelay.bootstrap-set-hash.v1" ||
  len64(canonical(recommendedBootstrapHashes)) ||
  canonical(recommendedBootstrapHashes)
)

appArtifactHash = BLAKE2b-256(
  "peerit.release-app-artifact-hash.v1" ||
  len64(appDistributionBundleBytes) || appDistributionBundleBytes
)

webAssetManifestHash = BLAKE2b-256(
  "peerit.release-web-asset-manifest-hash.v1" ||
  len64(canonicalWebAssetManifestBytes) || canonicalWebAssetManifestBytes
)
```

`len64` is unsigned big-endian. The `.cenc` registry is the one canonical binary
source for every profile tag, field order, limit, enum, signature domain, and ID
preimage in this document. Generated JavaScript/Bare bindings are outputs and
must reproduce it byte-for-byte. Both vector manifests use the canonical
HiveRelay vector-manifest construction: normalized relative paths sorted by raw
UTF-8 bytes, byte length, and BLAKE2b-256 of each exact vector. Empty manifests,
duplicate paths, copied numeric constants, generated-source drift, or a dirty
input fail the build.

`appDistributionBundleBytes` are the exact reproducible application bundle before
the detached profile pin and web asset manifest are attached. The web asset
manifest lists that bundle's deployable assets plus the pinned bootstrap, but not
its own bytes or the profile pin. The signed pin then binds both hashes. This
one-way construction is mandatory; putting the pin hash inside the manifest while
also putting the manifest hash inside the pin would be circular and fails the
release builder.

Release inputs that are not built yet use these non-byte placeholders:

```text
writeSubstrate         = PENDING_SUBSTRATE_BUILD
validatorArtifactHash  = PENDING_VALIDATOR_BUILD
validatorVectorSetHash = PENDING_VALIDATOR_BUILD
availabilityPolicyHash = PENDING_POLICY_BUILD
```

They are deliberately not hexadecimal and cannot enter a signed release. The
profile generator now derives `profileSpecHash`, `profileAbiHash`, and
`profileVectorSetHash` from the exact canonical source, registry, and vector
manifest; those values are build outputs rather than placeholders. The release
build imports the HiveRelay tuple from the verified canonical descriptor, imports
the generated profile hashes, builds the exact app and web-asset manifests,
rejects a dirty or missing input, and signs the complete pin. No developer may
type a hash into a release manifest by hand.

#### 1.1.1 Checked-in release-control slice

The repository now checks in the deliberately partial artifacts
`protocol/peerit-release-control-v1.cenc` and
`protocol/vectors/peerit-release-control-v1.manifest.cenc`. They cover only
`SubstrateTupleV1`, `PeeritHiveRelayProfilePinV1`,
`PeeritPinHistoryCheckpointV1`, `PeeritPinHistoryBundleV1`, and the closed
`PeeritMigrationStageV1` enum. The matching executable codecs and verifier reject
noncanonical bytes, bad Ed25519 signatures, wrong keys, gaps, witnessed forks,
migration downgrade/skip, changed frozen legacy-source state, zero security
hashes, and unbranded suffix anchors.

This slice is fixture-only and non-production. Its first four record tags are now
proven byte-for-byte equal to the authoritative tags in the complete profile
registry, but the slice still does not supply the full profile codecs, a validator
or final HiveRelay tuple, production release keys, or authority-transition
verification inside the slice. `authorityTransitionHash` therefore fails closed
in the slice codec/verifier. The separate full-profile continuity verifier now
accepts a contiguous previously unknown signed suffix from an authenticated
branded terminal anchor, rejects witnessed forks, and verifies a referenced
old-key/new-key dual-signed authority transition at the first new-key release.
Durable browser/runtime persistence and recovery of that witnessed anti-rollback/
fork floor is not yet assembled and remains an explicit release blocker.
That verifier does not turn fixture placeholders or fixture keys into production
release inputs.

The non-fixture generator `scripts/generate-peerit-profile.mjs` now checks in
`protocol/peerit-profile-v1.cenc`, 77 declaration vectors, and
`protocol/vectors/peerit-profile-v1.manifest.cenc`. The registry embeds and
domain-binds this exact canonical profile source plus the mechanically verified
77-declaration inventory, deterministic tags, ownership/categories, dependencies,
anonymous shapes, external HiveRelay types, closed registries, and bounded codec
IR. Its
manifest uses the canonical HiveRelay sorted-path, length, and raw BLAKE2b-256
construction. This proves the registry, vector, and deterministic codec-IR
artifacts only: complete executable record codecs, the validator artifact, final
substrate tuple, and cross-runtime byte equality remain release blockers.

### 1.2 Release-authority chain

The release authority is Ed25519. Its key ID and transition are fixed as:

```text
releaseAuthorityKeyId = BLAKE2b-256(
  "peerit.release-authority-key-id.v1" || releaseAuthorityPublicKey
)

PeeritReleaseAuthorityTransitionV1 {
  version:               u8 = 1
  previousSequence:      u64
  nextSequence:          u64
  previousPublicKey:     32 bytes
  nextPublicKey:         32 bytes
  validFromRelease:      u64
  previousKeySignature:  64 bytes
  nextKeySignature:      64 bytes
}

authorityTransitionHash = BLAKE2b-256(
  "peerit.release-authority-transition-hash.v1" ||
  len64(canonicalCompleteTransition) || canonicalCompleteTransition
)

pinHash = BLAKE2b-256(
  "peerit.hiverelay.profile-pin-hash.v1" ||
  len64(canonicalCompleteSignedPin) || canonicalCompleteSignedPin
)
```

The pin signature covers domain `peerit.hiverelay.profile-pin.v1` followed by
every preceding canonical field. Both transition keys sign the same
`BLAKE2b-256("peerit.release-authority-transition.v1" || canonical fields before
the two signatures)` commitment; `nextSequence` is exactly
`previousSequence + 1`, and
`validFromRelease` is strictly greater than the highest release signed by the old
key. `authorityTransitionHash` is present exactly in the first pin using the new
key and matches the bundled complete transition; it is otherwise absent.
A client follows only a gap-free dual-signed chain from its witnessed key. Loss
of the old key creates a new trust root and requires an independently authenticated
application update; a self-signed "recovery" does not preserve release trust.

The initial web install is still rooted in the HTTPS application origin, and a
compromised origin can replace both verifier and key. The signature chain prevents
accidental artifact mixing and witnessed rollback; it is not a substitute for a
trusted first installation or an offline-signed Pear distribution.

#### 1.2.1 Operator key custody and recovery

Release signing and public Inbox management are separate operator disaster
domains. The active release seed may be unlocked in KeyVault for a ceremony, but
its encrypted recovery seed is split 2-of-3 across independently controlled
offline custodians; no one share, live host, repository, CI secret, or relay can
reconstruct it. A separately encrypted 2-of-3 `PeeritInboxManagementBundleV1`
contains every current/previous physical topic's create/renew/close private key,
binding tuple, receipt, lease, and policy hash. It never enters the ordinary user
recovery bundle or a HiveRelay.

The canonical plaintext inside that separately encrypted custody envelope is:

```text
PeeritCustodySeedPayloadV1 {
  version:              u8 = 1
  secretKind:           u8 // 1 RELEASE, 2 AVAILABILITY_ROOT, 3 ROOT_RECOVERY
  authorityId:          32 bytes
  authoritySequence:    u64
  profilePinHash:       32 bytes
  secretSeed:           32 bytes
  derivedPublicKey:     32 bytes
}

InboxManagementEntryV1 {
  version:              u8 = 1
  inboxEpoch:           u32
  stripeIndex:          u8
  relayPublicKey:       32 bytes
  bindingHash:          32 bytes
  bindingBytes:         canonical InboxStripeBindingV1 bytes[1..8192]
  createPrivateSeed:    32 bytes
  renewPrivateSeed:     32 bytes
  closePrivateSeed:     32 bytes
  renewPublicKey:       32 bytes
  closePublicKey:       32 bytes
  latestReceipt:        generic InboxReceiptV1
  latestRevision:       u64
  leaseEpoch:           u32
}

PeeritInboxManagementBundleV1 {
  version:              u8 = 1
  profilePinHash:       32 bytes
  rootRecordId:         32 bytes
  generation:           u64
  availabilityPolicyHash:32 bytes
  currentInboxEpoch:    u32
  entries:              ordered array[24..48] of InboxManagementEntryV1
  createdUnixMillis:    u64
  bundleCommitment:     32 bytes
}

PeeritCustodyEncryptedShareV1 {
  version:              u8 = 1
  custodySetId:         32 random nonzero bytes
  bundleKind:           u8 // 1 SEED_PAYLOAD, 2 INBOX_MANAGEMENT
  shareIndex:           u8 // exactly 1, 2, or 3
  threshold:            u8 = 2
  totalShares:          u8 = 3
  keyCommitment:        32 bytes
  sealedPayloadHash:    32 bytes
  custodianPublicKey:   32-byte X25519 public key
  ephemeralPublicKey:   32-byte X25519 public key
  nonce:                24 random bytes
  sealedShare:          48 bytes // 32-byte share plus 16-byte tag
}

PeeritCustodyEnvelopeV1 {
  version:              u8 = 1
  custodySetId:         32 random nonzero bytes
  bundleKind:           u8 // 1 SEED_PAYLOAD, 2 INBOX_MANAGEMENT
  plaintextCodec:       u16 // 1 PeeritCustodySeedPayloadV1,
                            // 2 PeeritInboxManagementBundleV1
  plaintextLength:      u64
  plaintextHash:        32 bytes
  keyCommitment:        32 bytes
  payloadNonce:         24 random bytes
  sealedPayload:        bounded bytes[17..16777232]
  encryptedShares:      ordered array[3..3] of
                        PeeritCustodyEncryptedShareV1
}

bindingHash = BLAKE2b-256(
  "peerit.hiverelay.inbox-management-binding.v1" ||
  len64(bindingBytes) || bindingBytes
)

bundleCommitment = BLAKE2b-256(
  "peerit.hiverelay.inbox-management-bundle.v1" ||
  len64(canonical fields through createdUnixMillis) ||
  canonical fields through createdUnixMillis
)

keyCommitment = BLAKE2b-256(
  "peerit.hiverelay.custody-key.v1" || custodySetId || dataEncryptionKey
)

plaintextHash = BLAKE2b-256(
  "peerit.hiverelay.custody-plaintext.v1" || bundleKind(u8) ||
  plaintextCodec(u16) || len64(canonicalPlaintext) || canonicalPlaintext
)

sealedPayloadHash = BLAKE2b-256(
  "peerit.hiverelay.custody-sealed-payload.v1" ||
  len64(sealedPayload) || sealedPayload
)
```

The entries are exactly the 24 current bindings followed by either zero or 24
immediately previous-epoch bindings. Within each epoch they sort by
`(stripeIndex, relayPublicKey, physicalTopic)`; the current epoch is first. Every
entry's parsed binding equals its epoch/stripe/relay fields, and the bundle's
epoch/root/generation/policy equal its accepted root-signed bootstrap. Its
`profilePinHash` names the exact compatible codec/migration pin used by the
ceremony and grants no discovery or authoring permission. The
three private seeds are distinct, derive the corresponding create/renew/close
public keys, and the create key equals the binding. The receipt, topic, allocation,
revision, and lease reproduce the generic binding and last accepted management
operation. Duplicate topic, relay/stripe, key, or management authority fails.
`bundleCommitment` covers the secret seeds and therefore remains inside the
encrypted custody envelope; it is never published as a stable topic fingerprint.
A seed payload derives its public key and requires exact equality with
`derivedPublicKey`; its kind, authority, sequence, and pin equal the ceremony it
is restoring. `ROOT_RECOVERY` uses one custody set per recovery seed, never one
envelope containing enough seeds to meet the root threshold.

For each envelope the dealer generates a random 32-byte data-encryption key and
32 independent random Shamir coefficients, one per key byte. Byte `j` is shared
as `f_j(x) = key[j] + coefficient[j]*x` at the fixed nonzero x coordinates 1, 2,
and 3 in GF(2^8) with irreducible polynomial `x^8+x^4+x^3+x+1` (`0x11b`). Addition
is XOR; multiplication and Lagrange interpolation are vector-fixed bit
operations. The coefficients and ephemeral X25519 private keys are destroyed
after all three encrypted shares and a reconstruction test are durable.

The canonical plaintext is encrypted with XChaCha20-Poly1305-IETF under the data
key and `payloadNonce`. Its AAD is the canonical envelope fields from `version`
through `keyCommitment` plus the exact encoded `sealedPayload` length, excluding
the nonce, ciphertext, and share array. `plaintextLength` is 1..16,777,216,
`sealedPayload` is exactly `plaintextLength+16`, and decryption must reproduce
`plaintextHash` and the exact codec/kind relationship.

Each share uses an independent ephemeral X25519 key and nonce. Its AEAD key is:

```text
shareKey = HKDF-SHA-256(
  ikm  = X25519(ephemeralPrivateKey, custodianPublicKey),
  salt = custodySetId,
  info = "peerit.hiverelay.custody-share-key.v1" || bundleKind(u8) ||
         shareIndex(u8) || custodianPublicKey || ephemeralPublicKey,
  L    = 32
)
```

`sealedShare` is XChaCha20-Poly1305-IETF over the exact 32-byte Shamir share. Its
AAD is every canonical share field through `ephemeralPublicKey` plus its nonce,
excluding only `sealedShare`. Shares sort by index, use exactly 1/2/3, and have
distinct custodian and ephemeral public keys, nonces, and ciphertexts. Every
share's set/kind/key/payload commitments equal the envelope. X25519 inputs use
canonical 32-byte encodings; known low-order public keys and an all-zero shared
secret fail before HKDF or AEAD. A custodian private key must reproduce its pinned
public key before share decryption.

Reconstruction uses the exact content-addressed envelope pinned by release
evidence, authenticates each supplied share, and tries all available two-share
pairs. A candidate is accepted only when it matches `keyCommitment`, authenticates
the payload, reproduces the plaintext hash/length/codec, and passes the payload's
semantic checks. At least one candidate must pass and all passing candidates must
be byte-identical; otherwise the ceremony fails. This makes one corrupted or
malicious supplied share detectable when the other two are available. It does not
claim recovery from one unavailable share plus a second malicious share.

The canonical envelope, GF arithmetic, X25519/HKDF/AEAD, wrong-recipient,
wrong-set, duplicate-index, one-malicious-share, one-unavailable-share, tamper,
and zeroization vectors plus a clean-machine reconstruction tool are mandatory
before qualifying an official release. Prose saying “2-of-3” is not evidence.

Every 90 days and before a cutover, custodians restore both bundles on a clean
offline machine, derive and compare the expected public keys/topics, sign a
throwaway release-vector commitment, verify an Inbox renew/close dry-run against
fixtures, then destroy the reconstructed material. A real restore of the release
seed continues the same key/sequence; inability to reconstruct it creates a new
trust root as stated above. Suspected compromise performs a dual-signed authority
rotation while the old key is still controlled, replaces Inbox epoch sets with
fresh management keys, publishes the linked checkpoint/bootstrap, and revokes the
old ceremony environment. Loss/compromise drills include one unavailable
custodian, one malicious share, a clean-machine signing/renewal, and alerting well
before any L90 lease reaches the renewal threshold.

Availability-root and discovery custody are separate again. The active root seed
is offline and has an encrypted 2-of-3 recovery split; each listed recovery key is
held by a different custodian group and no custodian holds enough root and recovery
material to rotate alone. Each of the four online maintainer keys, its ingress
Noise key, its observation-Core writer, and its preallocated proposal/snapshot/
checkpoint Cell management
capabilities are encrypted and operated only inside that maintainer's witnessed
administrative group—never copied into release CI, a relay, or another maintainer.
The other three can continue after one loss. Rotation of a maintainer key/log or
loss of a preallocated capability requires a higher-generation root rotation with
three fully read-back root replicas and new linked log/checkpoint bindings; keys
are never silently edited in a bootstrap.

Quarterly drills additionally suspend one maintainer, restore another observation
log signer on a clean machine without cloning its live writer, lose one next-cell
capability, exercise 3-of-4 proposal signing, rotate one compromised maintainer,
and reconstruct root recovery with one unavailable share. Any equivocation,
unexpected duplicate writer, or unaccounted capability export freezes that
discovery root's signing until the higher-generation recovery ceremony completes.
It never freezes authoring, relay delivery, direct sharing, or another discovery
source.

### 1.3 Activation

A client verifies the static bundled pin and artifact hashes to determine the
codecs and substrate tuples it can safely use. This verification is independent
of authoring: after explicit user intent, account creation/restoration, event
signing, durable journaling, and local materialization work offline without a
release fetch, relay probe, admission token, maintainer, operator registry, or
network clock.

Remote delivery is attempted per candidate relay. A candidate is usable when its
self-authenticating generic descriptor, requested family/operation, endpoint,
fresh challenge, admission parameters, request codec, and response verifier are
compatible with the client's emit tuple. A relay does not need to occur in a
Peerit bootstrap or operator registry. Registry and durability evidence annotate
which public claims that relay may count toward; they never grant permission to
send.

If no compatible relay is reachable, the exact signed intent remains
`QUEUED_NO_RELAY`. BUSY, admission exhaustion, role-local readiness loss, and
transport failure remain per-target retryable states. A descriptor/key/store/
continuity change creates a fresh independently randomized target attempt. Only
intrinsic codec or cryptographic incompatibility marks a target non-sendable, and
even then the locally signed event remains valid and may be re-enveloped by a
later compatible client without changing its logical ID or author signature.

An ordinary runtime verifies the exact bundled signed bytes and their hash chain;
it is not required to possess source code, a compiler, or the release toolchain.
The release builder separately proves reproducibility and migration transition
evidence. Failure of that evidence blocks promotion of an official release stage,
not authoring or acceptance of otherwise valid content.

Optional role qualification is per tuple `(operator-continuity root, relayPublicKey, storeId,
descriptorSequence, descriptorHash, durabilityContinuityHash,
durabilityProfileHash, family, endpoint, durability profile, transport profile,
admission profile, auxiliary-object hash)`. A healthy CELL endpoint does not
activate INBOX or CORE; a direct storage endpoint does not activate OHTTP ingress/
gateway; and a FORWARD entry does not prove its exit or storage ready.
Qualification thresholds count an operator only for the exact role whose evidence
passes, while an otherwise compatible unregistered role remains usable with an
honest lower claim.

| Qualified Peerit claim/use | Additional signed role evidence |
| --- | --- |
| Counted Cell/Inbox/Core durability | Storage role, family/profile, exact endpoint, redeemer/admission parameters, fresh requested-role plus requested-operation-bitmap challenge, exact profile-1 zero/intact-store and signed local-failure-domain evidence or current signed profile-2 `BlindExternalJournalTopologyV1`, and operation-specific live probe |
| OHTTP request | Ingress role and key/route object at operator A; gateway plus storage/redeemer/family role at operator B; both fresh challenges; A/B map to distinct live witnessed operator groups and also have unequal continuity roots/hosts |
| Native split | Fresh FORWARD entry role/challenge/admission/endpoint key at A plus witnessed signed A→B route; fresh FORWARD exit role/challenge/admission/endpoint key at B plus witnessed signed B→C route; storage/redeemer/family challenge at C; both route class/limit/descriptor tuples and nested HopAccepts verify; A/B/C map to pairwise distinct live witnessed operator groups and have pairwise unequal continuity roots/hosts under strict policy |
| Tor | Onion endpoint with no clearnet alternate, storage/redeemer/family role behind the same challenged daemon, strict client leak gate |
| Admission issuance | Issuer parameters/role and validity checked separately from the redeeming storage role; an issuer health result never activates redemption |

Descriptor discovery only finds candidates. It contributes no durability or
independence claim until the row above passes, but absence of that claim does not
veto a delivery attempt.

---

## 2. Privacy and trust statement

For conforming Peerit producers, application records and the capability graph are
encrypted before they cross the substrate boundary. Outer requests contain only
generic family/operation IDs, pseudorandom locators or opaque core keys, universal
size/lease classes, generic admission, and transport fields.

The storage wire and relay state MUST NOT contain:

- `peerit`, an app ID, namespace, community slug, author key, record type, post or
  comment ID, vote target, moderation action, social edge, profile ID, release
  sequence, or application timestamp;
- a deterministic plaintext or logical-content hash;
- an application-specific route, hostname, key configuration, padding class,
  admission class, metric label, or partition; or
- a Peerit validator, index, ranking rule, moderation rule, or repair verb.

This is an honest bounded claim:

- a relay cannot prove that arbitrary caller bytes are ciphertext; a malicious
  caller may upload plaintext;
- direct storage still observes source IP, timing, size class, operation, locator,
  and access pattern;
- OHTTP or split transport partitions source and request knowledge only under its
  non-collusion and capture assumptions;
- Tor hides a network path under the Tor threat model but does not hide which
  opaque locator the destination serves;
- public Peerit reader capabilities eventually reach the public. An operator can
  download Peerit, act as a reader, decrypt public posts, and map the referenced
  opaque storage. The profile therefore does not claim public-content secrecy or
  active-reader app opacity; and
- relay keys and receipts do not prove independent operators or continuous
  physical storage.

For the ordinary browser direct profile, capture is expected to show the client
IP and `Origin: https://peerit.site` at the storage endpoint. That is required
negative evidence, not a test defect. Direct browser CELL/INBOX/CORE traffic can
claim only the applicable G0/G1/G2-S and cell-at-rest G3 properties; it MUST NOT
claim G2-W, G4-T, G4-I, an origin-blind relay, or an anonymous request.

Peerit UI and release copy report the actual selected path and claim ceiling. The
words “anonymous”, “unlinkable”, “operator cannot read”, and “three independent
operators” are forbidden without the corresponding evidence and qualification.

---

## 3. Peerit inner authority model

Peerit retains its existing client-authoritative rules inside encrypted payloads:

- Ed25519 author signatures and exact owner/key binding;
- immutable, author-bound post/comment/content identities;
- signed vote, community, profile, delegation, moderation, and target references;
- deterministic reduction, fork retention, witnessed floors, edit/delete rules,
  and sticky community semantics;
- client-side feed, thread, vote, search, social, notification, moderation, and
  ranking indexes; and
- local drafts, offline intents, identity recovery, and explicit key rotation.

HiveRelay verifies none of those semantics. It verifies only the generic outer
capability, admission, size, lease, hash, and receipt rules.

### 3.1 Canonical profile encoding

The checked-in `peerit-profile-v1.cenc` registry is authoritative. Its codec IR is
compiled from every declaration under these exact rules; a declaration that does
not reduce to a finite machine-readable maximum fails the profile build:

- every complete Peerit record begins with its assigned unsigned `u16` big-endian
  profile tag, including a local child named directly by another record;
- `u8`, `u16`, `u32`, and `u64` are unsigned fixed-width big-endian integers;
  an `=` value is byte-frozen, and a named closed registry accepts only its listed
  numeric values;
- `optional T` is one `u8` presence byte (`0` absent, `1` present) followed by
  `T` only when present; no other presence byte is canonical;
- a bounded `bytes[min..max]` value is prefixed by the smallest fixed-width
  unsigned big-endian integer capable of representing `max` (`u8`, then `u16`,
  `u32`, or `u64`); the prefix is the exact byte length and is checked before
  allocation;
- an array uses the same smallest-width rule for its element-count prefix. An
  `ordered` array preserves declared order. A `sorted` array is strictly
  increasing and duplicate-free by complete canonical element bytes unless the
  surrounding normative rule names a more specific fixed sort projection;
- an inline `{ ... }` shape has no tag. A tagged union begins with its own profile
  tag, then one `u8` closed variant ID, then the selected payload. A named local
  record payload retains its own profile tag; an inline payload does not gain one;
- maps, implicit lengths/counts, platform integer encodings, trial decodes, and
  recursive or unbounded declarations are forbidden. Unknown mandatory tags,
  duplicate fields or members, noncanonical order, trailing bytes, invalid
  UTF-8/NFC, and over-limit children fail before allocation.

The external-type ownership catalog classifies all twelve HiveRelay V1 names used
anywhere in this profile's prose. It is not an import allowlist. The field-level
external-codec import table contains exactly these six children:

| HiveRelay V1 codec | Category/authority | Complete child bytes |
| --- | --- | ---: |
| `BlindCoreAckV1` | WIRE; final tuple | 1..16,384 |
| `BlindReceiptV1` | WIRE; final tuple | 1..16,384 |
| `InboxAppendAckV1` | WIRE; final tuple | 1..16,384 |
| `InboxReceiptV1` | WIRE; final tuple | 1..16,384 |
| `BlindCoreReadCapV1` | CLIENT_COMPOSITION; format/vector tuple | 1..8,192 |
| `ReadCellCapV1` | CLIENT_COMPOSITION; format/vector tuple | 99..131 |

Each field marked `generic` in a declaration must occur in that six-entry import
table and is framed as a bounded byte string under the length-prefix rule above,
never as an unframed Peerit child and never by a copied Peerit-side HiveRelay
schema. For the four WIRE children, the caller supplies one exact verified
HiveRelay `SubstrateTupleV1`; an encoder uses the active pin's `emitSubstrate`, a
decoder requires that exact tuple in the authenticated pin's `readSubstrates`,
selects the codec artifacts by the tuple before decoding, and performs no fallback
or trial decoding. This profile build binds
`specHash=470a48af6879bfdb036992a686576f61eca3f69966aeb0c46a4043b0efed5cd9`,
`abiHash=aaf29c8225ee33a59a02f1d27b898aa5b4f9aec005c6e509dee450ffc87b1b0d`,
and
`vectorSetHash=7943626bb0e9ffc0886a13e3b6532aa3ebfd60a3c26e4ff0c5842743ae788d07`.

The two read-capability codecs are HiveRelay client-composition schemas and are
deliberately excluded from the WIRE ABI/vector hashes. They bind the independently
generated HiveRelay client-composition authority tuple exactly:
`formatHash=5637708aff4a6e93a6ff3a2f96361aa0b1597c229346e124eebeb2d7618ae09a`
and
`vectorSetHash=ea176ea78a611256689604541e55ba420d426dda2fa4dd64fb3ac9ac7503934d`.
An implementation verifies both pins and the authority's closed schema catalog
before injecting either codec. They MUST NOT inherit authority from the final
WIRE tuple.
`BlindStoreManifestV1` remains INTERNAL_STORE and can never become a client import.
The other ownership-only durability/descriptor references likewise create no
Peerit field codec. The final WIRE tuple and client-schema commitment remain
separate release inputs; neither can substitute the other.

The registry flag `codecLayoutIrComplete = 1` means only that all 77 declarations
compile to deterministic tags, field order, primitive widths, optional presence,
bounded byte/count framing, nesting, and finite maximum encoded lengths. It does
not mean executable profile codecs are complete. Nonzero/random requirements,
custom sort projections, cross-field and signature/hash/authority relations,
strict runtime object surfaces, full decoders, and negative vectors are supplied
by the separately pinned validator artifact. Registry completeness and validator
completeness remain distinct claims; release readiness also requires the durable
witnessed pin floor and the full cross-runtime/release evidence gates.

Every signature covers its fixed ASCII domain plus the canonical record tag and
all preceding fields, excluding only the signature field. No JSON serialization,
source-language object order, displayed hexadecimal, or relay receipt encoding is
a signature preimage.

Migration-stage changes use one canonical signed evidence object. It qualifies an
official release transition and has no content-authority effect:

```text
PeeritMigrationTransitionEvidenceV1 {
  version:                        u8 = 1
  previousPinHash:                32 bytes
  targetReleaseSequence:          u64
  fromMigrationStage:             u8
  toMigrationStage:               u8
  targetLegacyImportMode:         u8
  targetLegacyReadMode:           u8
  qualificationSubjectHash:       32 bytes
  windowStartedUnixMillis:        u64
  windowEndedUnixMillis:          u64
  attemptedLogicalWrites:         u64
  terminalSuccessfulWrites:       u64
  terminalFailedWrites:           u64
  pendingOrUnknownWrites:         u64
  acknowledgedWriteLosses:        u64
  unresolvedLegacyOnlyWrites:     u64
  forbiddenLegacyWrites:          u64
  signatureOrCodecDisagreements:  u64
  floorRollbacks:                 u64
  hiddenPrivacyDowngrades:        u64
  reconstructionEvidenceHashes:  sorted array[0..8] of 32 bytes
  legacyCutoffHash:               optional 32 bytes
  migrationGenesisRecordId:       optional 32 bytes
  targetCutoffActivationReleaseSequence:optional u64
  targetLegacyRetirementEvidenceHash:optional 32 bytes
  targetLegacyRetirementActivationReleaseSequence:optional u64
  evidenceBundleHash:             32 bytes
  releaseAuthoritySequence:       u64
  releaseAuthorityKeyId:          32 bytes
  signature:                      64 bytes
}

PeeritWriteOperationEvidenceV1 {
  version:                       u8 = 1
  logicalIntentEvidenceId:       32 random nonzero bytes
  attemptedUnixMillis:           u64
  terminalClass:                 u8 // 0 pending/unknown, 1 success, 2 failure
  terminalUnixMillis:            optional u64
  runtimeEvidenceKeyHash:        32 bytes
  failureBits:                   u8
  supportingEvidenceHashes:      sorted array[1..32] of 32 bytes
}

PeeritWriteOperationEvidenceShardV1 {
  version:                       u8 = 1
  qualificationSubjectHash:      32 bytes
  windowStartedUnixMillis:       u64
  windowEndedUnixMillis:         u64
  entries:                       sorted array[1..65536] of
                                  PeeritWriteOperationEvidenceV1
}

PeeritWriteOperationEvidenceShardRefV1 {
  firstLogicalIntentEvidenceId:  32 bytes
  lastLogicalIntentEvidenceId:   32 bytes
  entryCount:                    u64
  entryMerkleRoot:               32 bytes
  shardArtifactHash:             32 bytes
}

PeeritWriteOperationEvidenceManifestV1 {
  version:                       u8 = 1
  qualificationSubjectHash:      32 bytes
  windowStartedUnixMillis:       u64
  windowEndedUnixMillis:         u64
  totalEntryCount:               u64
  operationEvidenceRoot:         32 bytes
  shards:                        ordered array[0..4096] of
                                  PeeritWriteOperationEvidenceShardRefV1
}

PeeritWriteRuntimeEvidenceV1 {
  version:                       u8 = 1
  runtimeEvidenceKeyHash:        32 bytes
  runtimeClass:                  u8
  runtimeVersionHash:            32 bytes
  platformConfigurationHash:     32 bytes
  captureEvidenceHash:           32 bytes
  attemptedLogicalWrites:        u64
  terminalSuccessfulWrites:      u64
  terminalFailedWrites:          u64
  pendingOrUnknownWrites:        u64
  operationEvidenceCount:        u64
  operationEvidenceRoot:         32 bytes
}

PeeritWriteSupportingEvidenceManifestV1 {
  version:                       u8 = 1
  qualificationSubjectHash:      32 bytes
  windowStartedUnixMillis:       u64
  windowEndedUnixMillis:         u64
  artifacts:                     sorted array[0..1048576] of {
                                  supportingEvidenceHash: 32 bytes,
                                  evidenceKind: u8,
                                  byteLength: u64
                                }
}

PeeritReleaseQualificationEvidenceBundleV1 {
  version:                       u8 = 1
  appArtifactHash:               32 bytes
  validatorArtifactHash:         32 bytes
  profileSpecHash:               32 bytes
  profileAbiHash:                32 bytes
  profileVectorSetHash:          32 bytes
  availabilityPolicyHash:        32 bytes
  recommendedBootstrapSetHash:   32 bytes
  webAssetManifestHash:          32 bytes
  substrate:                     SubstrateTupleV1
  measuredMigrationStage:        u8
  qualificationSubjectHash:      32 bytes
  evidenceBaseUrl:               canonical HTTPS URL bytes[1..512]
  windowStartedUnixMillis:       u64
  windowEndedUnixMillis:         u64
  attemptedLogicalWrites:        u64
  terminalSuccessfulWrites:      u64
  terminalFailedWrites:          u64
  pendingOrUnknownWrites:        u64
  acknowledgedWriteLosses:       u64
  unresolvedLegacyOnlyWrites:    u64
  forbiddenLegacyWrites:         u64
  signatureOrCodecDisagreements: u64
  floorRollbacks:                u64
  hiddenPrivacyDowngrades:       u64
  operationEvidenceManifestHash: 32 bytes
  operationEvidenceCount:        u64
  operationEvidenceRoot:         32 bytes
  supportingEvidenceManifestHash:32 bytes
  runtimeEvidence:               sorted array[0..64] of PeeritWriteRuntimeEvidenceV1
  reconstructionEvidenceHashes: sorted array[0..8] of 32 bytes
}
```

The evidence signature domain is `peerit.migration-transition-evidence.v1` and
covers every preceding canonical field. The object binds the previous pin and
predetermined target release sequence, never the target pin hash. The target pin
can therefore bind the evidence hash without a cycle. Its counters are cumulative
only over the named closed window and reproduce the signed evidence bundle; a
producer cannot substitute a later or wider telemetry window. Passing or failing
this evidence affects only promotion of the official migration stage. It never
changes the validity or delivery eligibility of an author-signed event.

Every logical write receives one random `logicalIntentEvidenceId` before its first
attempt and persists it across every retry, replica, reload, and reconciliation;
the ID never enters a relay request, Peerit record, capability, metric, or UI.
Evidence entries sort by that ID, duplicates are invalid, and an entry covers one
logical write rather than one physical relay request. `terminalClass = 0` requires
an absent terminal time; classes 1/2 require
`attemptedUnixMillis <= terminalUnixMillis <= windowEndedUnixMillis`. Every attempt
obeys `windowStartedUnixMillis <= attemptedUnixMillis < windowEndedUnixMillis`,
and the window start is strictly before its end. Failure bits are fixed: bit 0 acknowledged
write loss, 1 unresolved legacy-only write, 2 forbidden legacy write, 3 signature
or codec disagreement, 4 floor rollback, and 5 hidden privacy downgrade; bits 6/7
must be zero. The referenced signed receipts, captures, reconciliation results,
and replay proofs are distributed by content hash through the supporting-evidence
manifest. The release verifier derives the terminal class and bits from those
artifacts rather than trusting the summary byte.
Every entry references exactly one kind-4 durable attempt-ledger proof. Success
also requires its complete kind-1 result/receipt quorum; failure or pending/unknown
requires the applicable kind-2/3/6 terminal or reconciliation evidence. A summary
class with no typed proof is invalid.

An operation-evidence shard hashes to `shardArtifactHash` by the formula below.
Its subject/window equal the manifest and its first/last IDs and count equal its
reference. Shard references are ordered by first ID, have disjoint increasing
ranges, and no shard is empty. Fetching every referenced canonical shard therefore
reconstructs one globally sorted unique entry stream. The verifier recomputes each
shard root, the streamed global root, and every bundle counter. A zero-attempt
window has no shards and uses the exact empty root; any missing, extra, overlapping,
or unavailable shard fails the release-qualification gate. `evidenceBaseUrl` has no query,
fragment, userinfo, credential, redirect, or content negotiation and permits
credential-free CORS. The operation manifest and every shard are immutable release
evidence at `<evidenceBaseUrl>/operation/<lowercase-hash>.cenc`; the path hash must
equal the canonical bytes.

`runtimeClass` is closed: 1 Chromium web, 2 Firefox web, 3 WebKit/iOS web, 4
Pear/Bare/Node direct or split, 5 strict Tor native, and 6 strict Tor Browser.
`runtimeEvidenceKeyHash` recomputes from the runtime descriptor projection below.
Rows sort uniquely by that hash. Each operation entry names exactly one embedded
runtime row; there is exactly one row for every referenced key and no unreferenced
row. Filtering the complete entry stream by that key must reproduce the row's
count, terminal counters, and Merkle
root. `captureEvidenceHash` names the immutable runtime/network capture bundle
that proves the claimed class/configuration and the applicable section-8 gates.
`runtimeVersionHash` and `platformConfigurationHash` are kind-5 supporting-
evidence hashes over exact version/build and platform/configuration manifests;
`captureEvidenceHash` is kind 2 or 6. They are not free-form labels.

The supporting manifest is fetched at
`<evidenceBaseUrl>/support/manifest/<supportingEvidenceManifestHash>.cenc` and each
artifact at `<evidenceBaseUrl>/support/artifact/<supportingEvidenceHash>.bin`.
Artifacts sort uniquely by hash and kind; duplicate hash with another kind fails.
Kinds are closed: 1 signed relay result/receipt bundle, 2 transport packet/header
capture, 3 reconciliation/reconstruction proof, 4 durable attempt-ledger proof, 5
runtime/platform manifest, and 6 privacy/downgrade capture. Every hash referenced
by an operation entry, runtime row, or `reconstructionEvidenceHashes` occurs
exactly once in this manifest, every manifest row is referenced, its byte length
and domain-separated hash reproduce from the fetched exact bytes, and its typed
validator proves the claimed terminal/bit/runtime fact. Missing bytes, an unknown
kind, or a merely self-asserted counter fails the release-qualification gate.

The evidence bundle's attempted count and operation-evidence count both equal the
number of reconstructed entries and equal `terminalSuccessfulWrites +
terminalFailedWrites + pendingOrUnknownWrites` under checked u64/BigInt arithmetic.
Its six failure counters equal the number of entries with each corresponding bit;
these bit counts may overlap terminal classes and are not added to the terminal
equation. All same-named counters, window and rehearsal hashes equal the transition
object. A 99.9-percent gate uses `terminalSuccessfulWrites * 10000 >=
attemptedLogicalWrites * 9990`; it never uses rounded floating point and
pending/unknown is not success.

`qualificationSubjectHash` and `evidenceBundleHash` recompute from the exact bundle
with the formulas below. The bundle's subject field must equal that recomputation.
A qualifying window contains one immutable app artifact, validator, profile
spec/ABI/vectors, policy, complete recommended-bootstrap set, web asset manifest, substrate
tuple, and measured migration stage; every one equals the measured signed pin. It
cannot combine telemetry across a subject or artifact change. Canary sampling is
official-release telemetry only and is never extrapolated into content authority.

```text
migrationTransitionEvidenceHash = BLAKE2b-256(
  "peerit.migration-transition-evidence-hash.v1" ||
  len64(canonicalCompleteSignedEvidence) ||
  canonicalCompleteSignedEvidence
)

qualificationSubjectHash = BLAKE2b-256(
  "peerit.release-qualification-subject.v1" ||
  appArtifactHash || validatorArtifactHash || profileSpecHash || profileAbiHash ||
  profileVectorSetHash || availabilityPolicyHash || recommendedBootstrapSetHash ||
  webAssetManifestHash ||
  len64(canonical(SubstrateTupleV1)) || canonical(SubstrateTupleV1) ||
  measuredMigrationStage(u8)
)

releaseQualificationEvidenceBundleHash = BLAKE2b-256(
  "peerit.release-qualification-evidence-bundle-hash.v1" ||
  len64(canonical(PeeritReleaseQualificationEvidenceBundleV1)) ||
  canonical(PeeritReleaseQualificationEvidenceBundleV1)
)

writeOperationEvidenceLeafHash = BLAKE2b-256(
  "peerit.write-operation-evidence-leaf.v1" ||
  len64(canonical(PeeritWriteOperationEvidenceV1)) ||
  canonical(PeeritWriteOperationEvidenceV1)
)

writeOperationEvidenceNodeHash = BLAKE2b-256(
  "peerit.write-operation-evidence-node.v1" || treeLevel(u32) ||
  leftChildHash || rightChildHash
)

writeOperationEvidenceEmptyRoot = BLAKE2b-256(
  "peerit.write-operation-evidence-empty.v1"
)

writeOperationEvidenceShardHash = BLAKE2b-256(
  "peerit.write-operation-evidence-shard.v1" ||
  len64(canonical(PeeritWriteOperationEvidenceShardV1)) ||
  canonical(PeeritWriteOperationEvidenceShardV1)
)

writeOperationEvidenceManifestHash = BLAKE2b-256(
  "peerit.write-operation-evidence-manifest.v1" ||
  len64(canonical(PeeritWriteOperationEvidenceManifestV1)) ||
  canonical(PeeritWriteOperationEvidenceManifestV1)
)

writeRuntimeEvidenceKeyHash = BLAKE2b-256(
  "peerit.write-runtime-evidence-key.v1" || runtimeClass(u8) ||
  runtimeVersionHash || platformConfigurationHash || captureEvidenceHash
)

writeSupportingEvidenceHash = BLAKE2b-256(
  "peerit.write-supporting-evidence.v1" || evidenceKind(u8) ||
  len64(exactSupportingEvidenceBytes) || exactSupportingEvidenceBytes
)

writeSupportingEvidenceManifestHash = BLAKE2b-256(
  "peerit.write-supporting-evidence-manifest.v1" ||
  len64(canonical(PeeritWriteSupportingEvidenceManifestV1)) ||
  canonical(PeeritWriteSupportingEvidenceManifestV1)
)

pinHistoryCheckpointHash = BLAKE2b-256(
  "peerit.pin-history-checkpoint-hash.v1" ||
  len64(canonicalCompleteSignedPinCheckpoint) ||
  canonicalCompleteSignedPinCheckpoint
)

pinHistoryBundleHash = BLAKE2b-256(
  "peerit.pin-history-bundle-hash.v1" ||
  len64(canonicalPinHistoryBundle) || canonicalPinHistoryBundle
)

profileRecordId = BLAKE2b-256(
  "peerit.hiverelay.manifest-record-id.v1" ||
  manifestTag(u16) || len64(canonicalCompleteSignedRecord) ||
  canonicalCompleteSignedRecord
)

logicalHash = BLAKE2b-256(
  "peerit.hiverelay.logical-hash.v1" || innerCodec(u16) ||
  len64(exactCanonicalInnerBytes) || exactCanonicalInnerBytes
)

replicaId = BLAKE2b-256(
  "peerit.hiverelay.replica-id.v1" || replicaTag(u8) ||
  len64(canonicalReplicaIdentityProjection) ||
  canonicalReplicaIdentityProjection
)

signedAnnouncementId = BLAKE2b-256(
  "peerit.hiverelay.signed-announcement-id.v1" ||
  len64(canonicalCompleteSignedAnnouncement) ||
  canonicalCompleteSignedAnnouncement
)
```

The Merkle algorithm is exact. For a nonempty ordered entry list, level zero is
the corresponding ordered `writeOperationEvidenceLeafHash` list. At level `n+1`,
each adjacent pair is replaced by `writeOperationEvidenceNodeHash` with
`treeLevel = n+1`; an unpaired final hash is promoted byte-for-byte without
rehashing. Iteration ends at one hash. An empty list has
`writeOperationEvidenceEmptyRoot`. The same algorithm is used for each shard, the
globally reconstructed stream, and each runtime-key-filtered stream. Alternative
padding, duplicate-last, tree shape, entry projection, or sort order is invalid.
The evidence bundle's manifest hash/count/root equal the fetched manifest, and the
manifest's subject/window/count/root equal the evidence bundle before any summary
counter is accepted. Its supporting-evidence manifest hash likewise equals the
fetched manifest, whose subject/window equal the bundle.

`migrationTransitionEvidenceHash` names exact signed release-process evidence.
`profileRecordId` includes the record signature. `logicalHash` includes the exact
inner codec and bytes but no availability wrapper. For a Cell, the replica
identity projection is exactly `(logicalHash, encodingCommitment,
relayPublicKey, canonical ReadCellCapV1, cellBlobHash, sizeClass,
allocationEpoch)`. For Core it is exactly `(logicalHash, encodingCommitment,
relayPublicKey, corePublicKey, firstBlockIndex, blockCount,
coreSliceCommitment)`. Mutable lease evidence, receipts, witnessed heads, and
acknowledgements are excluded so evidence refresh does not rename a physical
replica. `signedAnnouncementId` includes its publisher signature and is computed
before encryption. These projections, formulas, and numeric tags are frozen in
the registry and covered by positive, bit-flip, truncation, duplicate, reordering,
evidence-refresh, and cross-runtime vectors.

These identifiers exist only inside encrypted Peerit state. A relay never
receives them as a cell locator, physical inbox topic, core key, request/receipt
field, admission label, partition key, or metric dimension. The only stable
outer identifier allowed by Core is its independently generated transport
`corePublicKey`, with the G2-S/non-G3 limitation stated below.

---

## 4. Availability root, bootstrap, and rotation

```text
AvailabilityRootV1 {
  version:              u8 = 1
  generation:           u64
  validatorArtifactHash:32 bytes
  rootVerifyKey:        32 bytes
  recoveryKeys:         sorted array[3..3] of 32-byte keys
  recoveryThreshold:    u16 = 2
  discoveryMaintainerKeys:sorted array[4..4] of 32-byte keys
  discoveryMaintainerThreshold:u16 = 3
  createdLeaseEpoch:    u32
  signature:            64 bytes
}

AvailabilityPolicyV1 {
  version:                       u8 = 1
  minimumOperatorGroups:         u8 = 3
  maxCountedReplicasPerGroup:    u8 = 1
  requireDistinctStoreIds:       u8 = 1
  maxCountedProfile2ReplicasPerSharedJournalGroup:u8 = 1
  maxCountedProfile1ReplicasPerLocalFailureDomain:u8 = 1
  allowedDurabilityProfileBits:  u8 = profiles 1 and 2 only
  resilientClaimMinimumExternalWriteAcks:u8 = 1
  resilientClaimMinimumExternalProbeAcks:u8 = 1
  oneFailureWriteLivenessProfile2Target:u8 = 2
  requiredProfile2BodyRpoBand:   u8 = 1 // <=15 minutes
  requiredProfile2BodyRtoBand:   u8 = 2 // <=4 hours
  maximumProfile2RestoreDrillAgeBand:u8 = 6 // <=30 days; 0 and 7 fail
  criticalReplicaTarget:         u8 = 3
  criticalReadbackThreshold:     u8 = 3
  cellReplicaTarget:             u8 = 3
  cellPolicyAckTarget:           u8 = 2
  cellPolicyRecentReadTarget:    u8 = 2
  coreReplicaTarget:             u8 = 3
  corePolicyMirrorTarget:        u8 = 2
  corePolicyRecentServeTarget:   u8 = 2
  inboxStripeCountLog2:          u8 = 3
  inboxReplicaTargetPerStripe:   u8 = 3
  inboxPolicyAppendTarget:       u8 = 2
  inboxPolicyRecentReadTarget:   u8 = 2
  proofFreshnessEpochs:          u8 = 4
  challengeCadenceEpochs:        u8 = 1
  repairDeadlineEpochs:          u8 = 2
  repairMaintainerTarget:        u8 = 3
  discoveryMaintainerTarget:     u8 = 4
  repairHintRefreshEpochs:       u8 = 28
  contentLeaseClass:             u8 = L90
  renewWhenRemainingEpochsBelow: u16 = 120
  inboxLeaseClass:               u8 = L90
  inboxRetentionClass:           u8 = R30
  inboxEpochSpan:                u16 = 28
  inboxPreviousOverlapEpochs:    u16 = 28
  inboxFrameClassBits:           u8 = classes 1 and 2 only
  maxAnnouncementBytes:          u16 = 12288
  normalInboxReadsPerRefresh:    u8 = 16
  auditInboxReadsPerRefresh:     u8 = 24
  coldInboxReadsPerRefresh:      u8 = 32
  inboxPageLimit:                u8 = 32
  normalFrameDecryptBudget:      u16 = 256
  normalInboxByteBudget:         u32 = 4194304
  auditFrameDecryptBudget:       u16 = 512
  auditInboxByteBudget:          u32 = 8388608
  coldFrameDecryptBudget:        u16 = 512
  coldInboxByteBudget:           u32 = 8388608
  maxConcurrentInboxReads:       u8 = 4
  crossAuditIntervalRefreshes:   u8 = 240
  foregroundInboxRefreshSeconds:u16 = 15
  backgroundInboxRefreshSeconds:u16 = 300
  checkpointCadenceSeconds:      u16 = 60
  checkpointMaxLagSeconds:       u16 = 300
  recentBucketSeconds:           u16 = 300
  recentWindowBuckets:           u16 = 2016
  snapshotHistoryRetentionDays:  u16 = 365
  maxFrontierRecords:            u32 = 16777216
  coldStartRecordBudget:         u16 = 256
  coldStartByteBudget:           u32 = 16777216
  alertEvaluationSeconds:        u16 = 60
  softAlertOpenIntervals:        u8 = 3
  softAlertClearIntervals:       u8 = 5
}

PeeritOperatorGroupRegistryV1 {
  version:              u8 = 1
  registrySequence:     u64
  previousRegistryHash: optional 32 bytes
  witnessThreshold:     u8 = 2
  witnesses:            sorted array[3..64] of {
                          witnessGroupId: 32 bytes,
                          witnessKey: 32 bytes,
                          issuedLeaseEpoch: u32,
                          expiresLeaseEpoch: u32,
                          witnessStatementSignature: 64 bytes
                        }
  groups:               sorted array[3..64] of {
                          groupId: 32 bytes,
                          operatorStatementKey: 32 bytes,
                          continuityRoots: sorted array[1..32] of 32 bytes,
                          maintainerKeys: sorted array[0..16] of 32 bytes,
                          failureDomainCommitments: sorted array[1..16] of 32 bytes,
                          profile1StoreFailureDomains: sorted array[0..16] of {
                            continuityRoot: 32 bytes,
                            storeId: 32 random nonzero bytes,
                            localFailureDomainId: 32 nonzero registry-scoped witness-assigned bytes,
                            chaosEvidenceHash: 32 bytes
                          },
                          issuedLeaseEpoch: u32,
                          expiresLeaseEpoch: u32,
                          operatorSignature: 64 bytes,
                          witnessSignatures: sorted array[2..16] of
                            { witnessKey: 32 bytes, signature: 64 bytes }
                        }
  registryWitnessSignatures:sorted array[2..16] of 96 bytes
                          // witnessKey(32) || signature(64)
}

DiscoveryMaintainerLogBindingV1 {
  maintainerKey:        32 bytes
  operatorGroupId:      32 bytes
  logReplicas:          sorted array[3..3] of CoreReplicaBindingV1
  observationSequence:  u64
  observationHash:      32 bytes
}

MaintainerIngressBindingV1 {
  version:              u8 = 1
  maintainerKey:        32 bytes
  operatorGroupId:      32 bytes
  transportProfile:     u8 = 1 // app-side Noise/Protomux over generic Pear DHT
  rendezvousTopic:      32 random bytes
  noiseStaticPublicKey: 32 bytes
  descriptorSequence:   u64
  expiresLeaseEpoch:    u32
  signature:            64 bytes
}

AvailabilityBootstrapV1 {
  version:                  u8 = 1
  rootRecordId:             32 bytes
  rootLogicalHash:          32 bytes
  generation:               u64
  rootVerifyKey:            32 bytes
  substrate:                SubstrateTupleV1
  profileSpecHash:          32 bytes
  profileAbiHash:           32 bytes
  profileVectorSetHash:     32 bytes
  validatorArtifactHash:    32 bytes
  validatorVectorSetHash:   32 bytes
  availabilityPolicyHash:   32 bytes
  operatorGroupRegistryHash:32 bytes
  rootReplicas:             sorted array[3..16] of tagged ReplicaBindingV1
  discoveryCheckpointSequence:u64
  discoveryCheckpointLogicalHash:32 bytes
  discoveryCheckpointReplicas:sorted array[3..16] of tagged ReplicaBindingV1
  discoverySnapshotLogicalHash:32 bytes
  discoverySnapshotReplicas:sorted array[3..16] of tagged ReplicaBindingV1
  discoveryMaintainerLogs: sorted array[4..4] of
                           DiscoveryMaintainerLogBindingV1
  discoveryMaintainerIngress:sorted array[4..4] of
                           MaintainerIngressBindingV1
  inboxEpochSets:           sorted array[1..2] of InboxEpochSetV1
  legacyCutoffHash:         optional 32 bytes
  migrationGenesisRecordId:optional 32 bytes
  bootstrapSequence:        u64
  previousBootstrapHash:    optional 32 bytes
  issuedUnixMillis:         u64
  signature:                64 bytes
}

InboxEpochSetV1 {
  inboxEpoch:            u32
  stripeCountLog2:       u8 = 3
  stripeSelectionKey:    32 bytes
  announcementMasterKey: 32 bytes
  bindings:              sorted array[24..24] of InboxStripeBindingV1
}

InboxStripeBindingV1 {
  inboxEpoch:          u32
  stripeIndex:         u8
  relayPublicKey:      32 bytes
  allocationEpoch:     u32
  createPublicKey:     32 bytes
  physicalTopic:       32 bytes
  frameClassBits:      u8 = classes 1 and 2 only
  appendAuthMode:      u8 = 0 (OPEN_APPEND)
  retentionClass:      u8 = R30
  leaseClass:          u8 = L90
  createReceipt:       generic InboxReceiptV1
}

RootRotateV1 {
  version:                 u8 = 1
  previousRootRecordId:    32 bytes
  nextRootRecordId:        32 bytes
  nextRootLogicalHash:     32 bytes
  previousGeneration:      u64
  nextGeneration:          u64
  nextRootReplicas:        sorted array[3..3] of tagged ReplicaBindingV1
  discoveryRecoveryMergeHash:optional 32 bytes
  discoveryRecoveryMergeReadCaps:sorted array[0..3] of generic ReadCellCapV1
  oldRootSignature:        optional 64 bytes
  recoverySignatures:      sorted array[0..16] of
                           { recoveryKey: 32 bytes, signature: 64 bytes }
  newRootSignature:        64 bytes
}
```

The bootstrap migration fields are both absent before `legacyImportMode=1` and both
present afterward. When present they equal the active pin and the accepted
tag-6 `MigrationGenesisV1`; the signed current snapshot membership contains that
exact record ID and its availability entry provides at least three policy-qualified
bindings that reconstruct the complete signed genesis bytes. A bootstrap cannot
declare cutoff-final while making its migration authority unreachable.

Generation zero is the only initial root. Recovery is exactly two of three distinct
keys. Root rotation increments generation by one.
Normal rotation requires old and new root signatures. Recovery rotation requires
the exact old threshold of distinct accepted recovery keys plus the new root
signature. Competing valid rotations are retained as a visible conflict; time or
relay order never chooses the winner.

The exact canonical `AvailabilityPolicyV1` bytes are hashed into the signed pin
and recommended bootstrap. Its numbers are targets for durability and public
claims, never minimum permission to author, send, acknowledge, or discover. The
client prefers three distinct relay-continuity identities, witnessed operator
groups and store IDs; profile-2 members additionally have pairwise-distinct current
`sharedFailureGroupId` values. One verified compatible relay acknowledgement is
remote storage and may immediately produce an independently valid author binding.
Additional replicas are added through repair. The UI reports exact
`relay-acknowledged(n)`, `recently-retrievable(n)`, and
`externally-witnessed(n)` counters. Only the `POLICY_DURABLE`/`RESILIENT` claim
requires the configured targets, including
`resilientClaimMinimumExternalWriteAcks=1` and
`resilientClaimMinimumExternalProbeAcks=1`. A profile-1 receipt never becomes an
external-witness/control-RPO0 claim.
A qualifying charged probe is an admitted CELL.PROVE of one fixed 4-KiB generic
sentinel cell or CORE.PROVE of one deterministic 4-KiB sentinel range. Inbox is
excluded because retaining arbitrary read pages would amplify expiring frames.
The complete small content/proof verifies, the profile-2 result binding is exact,
and its receipt/ack carries a present valid `BlindExternalCommitWitnessV1`. A
CELL.GET or any uncharged proof/read may update `recently-retrievable(n)` but never
the externally witnessed charged-probe threshold. The two labels and counters are
stored and displayed separately.

`ChargedProbeEvidenceV1` is a bounded, nonrecursive envelope shared for every
Peerit object using that relay/store during its freshness window. `probeSelector`
is the exact non-admission request-commitment payload plus public read capability:
for kind 1 it fixes size class 1, slot, blob hash, and client nonce; for kind 2 it
fixes Core profile/key/fork/head, one deterministic 4-KiB range/proof selector, and
client nonce. It contains no token or payment identifier. The signed receipt/ack
bytes include the result binding/witness and match all envelope fields. A verifier
re-fetches the sentinel through that capability, reconstructs the full canonical
PROVE result from the 4-KiB bytes/proof plus retained receipt/ack, recomputes the
witness result commitment, and verifies the historical descriptor/profile chain.

At most one canonical envelope per `(relayPublicKey,storeId,probedAtLeaseEpoch)`
counts—the lowest complete evidence hash if several maintainers race. Maintainers,
not every reader, issue it; clients reuse it. Envelopes sort by complete bytes and
reject duplicate relay/store targets inside one `RelayProbeEvidenceSetV1`.
Sequence zero alone omits `previousSetHash`; later sets are exactly prior+1 and
hash the complete prior signed set. Three of the four maintainers sign one set,
`createdLeaseEpoch <= expiresLeaseEpoch <= createdLeaseEpoch +
proofFreshnessEpochs`; every entry's probe epoch is at most creation and remains
within `proofFreshnessEpochs` through set expiry. Its canonical bytes remain at
most 1 MiB.

The set is stored/read back once from three ordinary witnessed groups. A snapshot,
checkpoint, and floor carry its one logical hash; individual
`DiscoveryAvailabilityEntryV1` values never embed the set, an envelope, or a
per-record copy/hash. Body availability tree revisions therefore do not churn when
the shared probe set rotates. Runtime configured-resilience evaluation combines a
record's ordinary BODY_RESILIENT/read-cap evidence with the current shared set and
requires a qualifying entry for at least one of that record's profile-2 targets.
Set storage is expressly exempt from needing another charged probe, avoiding
recursion, while its enclosing snapshot/caps still need three ordinary replica
acknowledgements and full readback. A relay contributes at most 16 KiB of envelope
bytes per epoch; retain current plus one predecessor online and GC older
unreferenced set copies after the signed history/archive window. Scale gates
measure probe spend/rate, set bytes and rotation, sentinel GET/PROVE load, Merkle
root stability, and prove no per-record/per-reader amplification.
The UI claims one-selected-failure delivery liveness only while the three-target set
contains at least `oneFailureWriteLivenessProfile2Target=2` live profile-2 relays
on different shared-journal IDs. With one profile-2 plus two profile-1 targets,
loss of either profile-1 target still leaves the preferred acknowledgement target.
Loss of the sole profile-2 target changes durability to `DEGRADED`, clears the
external-witness/resilience claim, and schedules repair. Authoring and delivery to
every remaining compatible relay continue.
`proofFreshnessEpochs=4` means evidence is at most 24 hours old because one
substrate lease epoch is six hours. Roots, migration genesis, recommended
bootstraps, and discovery snapshots MUST be acknowledged and fully read back from
all three selected witnessed groups before that discovery root signs a bootstrap
carrying the configured-resilience label. A new policy hash is required to change
any number. Distinct keys/hosts remain
operator-diversity evidence, not proof of independent control.

Qualification counting is stricter than key diversity. The bootstrap's exact
`operatorGroupRegistryHash` names its witness-attested, sequence-linked registry.
Each group statement is signed by the claimed operator and the pinned witness
threshold from distinct declared witness groups, maps all known continuity roots
and maintainer keys under that administration,
and commits only coarse infrastructure/failure-domain evidence. Selection counts
at most one replica per witnessed operator group, requires a distinct descriptor/
durability `storeId` for every counted replica, and among profile-2 replicas counts
at most one per `sharedFailureGroupId`; among profile-1 replicas it counts at most
one per registry-global `localFailureDomainId`. Two profile-1 relays may therefore both
count toward the three-replica repair target only when their store IDs and live
witnessed Peerit operator groups and declared local-failure-domain IDs differ.
Profile 1 has no shared journal dependency;
its local host/volume/failure-domain separation is an explicit operator declaration
and chaos-tested assumption, not externally witnessed evidence. An unknown,
expired, same-sequence-forked, or multiply mapped continuity/operator root
contributes zero. A duplicate/missing store ID contributes zero, and missing/
invalid topology makes a claimed profile-2 relay unqualified rather than profile 1.
This is auditable real-world evidence, never a cryptographic proof of corporate
independence or non-collusion. The UI shows exact operator/store counts, collapses
equal profile-2 shared-journal IDs, reports `externally-witnessed(n)` separately,
and labels profile-1 local-failure-domain independence as an operator assumption
with no same-identity/control-RPO0 claim. A relay that is absent from this registry
or has expired qualification remains eligible for generic compatible storage; it
contributes zero to operator-independence and resilience claims.

A counted profile-1 role has exactly one live
`profile1StoreFailureDomains` entry in its witnessed group statement whose
continuity root and nonzero store ID equal the current generic descriptor/binding.
No `(continuityRoot, storeId)` tuple or `localFailureDomainId` repeats anywhere in
the registry's complete live `groups` array or selected replica set. The opaque
domain ID is scoped to one registry sequence and is assigned consistently by the
same two-or-more witness groups that sign each affected operator statement after
checking the declared host/volume/provider blast radius; operators do not choose
independent random aliases. The same observed failure domain must receive the same
ID within that sequence, while IDs make no cross-registry or cryptographic
physical-identity claim. `chaosEvidenceHash` is nonzero and hashes the immutable redacted release-
evidence record that destroys the declared host/volume domain and observes new-
identity replacement. The operator and group witnesses sign this declaration with
the enclosing statement. It is explicit auditable evidence and still not proof of
provider independence; an absent/mismatched entry makes that profile-1 role
uncounted. Neither this declaration nor the drill proves offline-clone detection:
without the profile-2 external fence, a malicious operator can copy store+key and
fork. Peerit persists/gossips descriptor/result floors and rejects an observed
fork, but labels profile 1 `not externally fork-safe`; non-observation is not
proof of uniqueness.

The evidence record names the exact relay/continuity/store/operator tuple,
durability/descriptor/substrate hashes, declared local failure-domain ID, fault
method, readiness transitions, old-identity permanent mutation refusal, new-
identity replacement, timestamps, and verifier signatures; redaction may remove
addresses but none of those commitments.

```text
chaosEvidenceHash = BLAKE2b-256(
  "peerit.hiverelay.profile1-local-failure-evidence.v1" ||
  len64(canonicalRedactedEvidenceBytes) || canonicalRedactedEvidenceBytes
)
```

Each witness-registry entry signs domain
`peerit.hiverelay.operator-group-witness.v1` followed by its preceding canonical
fields. Witness keys and witness-group IDs are unique; entries are live only within
their lease interval. The operator and every listed group witness sign the same
`BLAKE2b-256("peerit.hiverelay.operator-group-statement.v1" ||
len64(canonical group fields before signatures) || canonical group fields before
signatures)` commitment. Each signature key must occur in the registry's witness
array, signatures must meet `witnessThreshold=2` from distinct witness-group IDs,
and no witness key/group may equal the operator key/group being witnessed. A
continuity root or maintainer key may occur in only one live operator group. Each
96-byte registry signature parses as `witnessKey || Ed25519Signature`; its key
occurs in the witness array, distinct witness groups meet `witnessThreshold`, and
it signs domain `peerit.hiverelay.operator-group-registry.v1` followed by all
canonical registry fields before `registryWitnessSignatures`.
`operatorGroupRegistryHash` is
`BLAKE2b-256("peerit.hiverelay.operator-group-registry-hash.v1" ||
len64(canonicalCompleteSignedRegistry) || canonicalCompleteSignedRegistry)`.
Sequence zero alone omits `previousRegistryHash`; every later sequence is exactly
+1 and hashes the complete accepted predecessor. Witness additions/removals and
group remapping therefore require a new linked witness-attested sequence. A
bootstrap selects its registry for claims made by that discovery source. A
release may recommend the complete bootstrap hash, but neither a relay nor the
release can substitute a registry inside an already signed bootstrap. An
independent source may use a different registry; clients keep the resulting
independence claims source-scoped and never turn them into content authority.

The accepted root, bootstrap log bindings, and ingress bindings contain exactly
the same four maintainer keys, each mapped one-to-one to a different live witnessed
operator group. Every log binding contains exactly three `CoreReplicaBindingV1`
values on three witnessed operator groups and distinct store IDs; any profile-2
subset also has distinct shared-journal IDs. They name one Core key/head and independently pass
the Core equality and recent-serve rules. The binding's observation sequence/hash
must equal the terminal canonical observation in that verified head. A single
portable Core cap or a maintainer administration key is not three-group mirror
evidence.

Each `MaintainerIngressBindingV1` is signed by its `maintainerKey` over domain
`peerit.hiverelay.maintainer-ingress.v1` and every preceding canonical field.
Descriptor sequence is monotonic per maintainer, the rendezvous topic is nonzero
and unique, and the binding is accepted only inside its lease interval. Profile 1
is an app-side Noise/Protomux protocol discovered through the generic Pear DHT; it
is not a HiveRelay role, endpoint, plugin, namespace, or availability vote. Web
clients may rely only on the blind public Inbox and later public observation logs;
native/Pear clients may use this direct route for a faster receipt. A runtime that
cannot use it makes no direct-receipt latency claim. The exact Protomux protocol
name is ASCII `peerit-maintainer-observation/1`. The Noise remote static key MUST
equal `noiseStaticPublicKey`; the first application frame is one unsigned big-
endian-u32 byte length followed by one canonical `MaintainerSubmitV1`, and the
only response is the same framing around one canonical
`MaintainerSubmitResultV1`. A frame above 16,384 bytes, an extra frame, a root or
generation mismatch, a zero nonce, or a result signed by any key other than the
binding's `maintainerKey` fails closed. This path encrypts application bytes but
does not hide a producer's network address from the maintainer; it carries no
anonymity claim unless a separately tested Tor transport profile is active.

A counted storage role must also advertise a fresh signed
`DurabilityProfileV1` with profile ID 1 or 2. Profile 2 must meet
`requiredProfile2BodyRpoBand` and `requiredProfile2BodyRtoBand` with a
clean-machine restore drill whose universal age band is in
`1..maximumProfile2RestoreDrillAgeBand`. The profile's stable nonzero
`restoreEvidenceFeedId`, signed feed URL, and recent checkpoint sequence/hash
validate. If the fetched `BlindRestoreEvidenceBundleV1` terminal head has sequence
`L`, its ordered heads are exactly the deterministic contiguous suffix
`max(1,L-384)..L`; the descriptor checkpoint occurs exactly once in that suffix,
and `L - checkpointSequence <= 384`. Every head signature verifies, each
successor's `previousEvidenceHeadHash` equals the exact complete hash of its
predecessor, and all remaining bundle artifacts hash to the terminal head's exact
fields. The terminal head is still valid after the five-minute client margin, and its
`issuedEpoch` equals checked-u32
`floor(issuedExternalUnixMillis / 21600000)` exactly. Its
separate current coverage backup proves the exact RPO inequality and monotonic
WAL/floor, while its representative clean-restored backup proves the exact RTO,
drill-age, at-least-90%-size, and support inequalities. Both current and drill
manifest `storeFormatHash` values equal the active durability profile's
`storeFormatHash` byte-for-byte; equal format-major or compatible-minor values do
not substitute, and a hash change requires a new qualifying drill. For this
required body-backed row, both current REGISTER/EXTEND transitions and every feed/
head/manifest/clean-drill/retention
signature, hash, store/continuity binding, chunk coverage, and expiry pass the
substrate rules. The runtime persists the highest feed head and rejects rollback/
fork; it never waits for a six-hour descriptor refresh to validate a fifteen-minute
RPO. Band 0/7, absent evidence,
retired/expired support, or a
hash/floor mismatch immediately removes the role and starts replacement repair.
Profile 1 must have the substrate-specified
zero/absent external journal, witness, floor, checkpoint, and topology fields and a
fresh intact-live-store/exclusive-lock readiness result; every generic
`RelayResultBindingV1.externalCommitWitness` is absent. It can strengthen blind-
body availability and count independently when its witnessed Peerit operator group,
`storeId`, and registry-global `localFailureDomainId` differ from every other
selected profile-1 binding. Because the configured two-ack durability label still
requires profile 2, at most one profile-1 receipt participates in that policy
threshold; as many as two profile-1 relays may participate in the three-
replica repair target when their operator groups/store IDs/local-failure-domain IDs differ. Profile 1 never
contributes to `externally-witnessed(n)` and never promises same-identity restart
after store loss, control RPO0, cloned-volume start, or live failover. Its local
host/volume failure separation remains a displayed operator assumption, and it
contributes no topology-based G4-T or unlinkable-admission qualification. Its
RPO/RTO/restore bands are all zero/UNDECLARED; Peerit makes no protocol claim
about new-identity body recovery from operator copies.

Profile 2's non-null topology URL must fetch exact bytes hashing to its
`externalJournalTopologyHash`. The signed `BlindExternalJournalTopologyV1` must
match the relay/store/journal IDs and `durabilityContinuityHash`, use replication class 1 with three distinct
node/failure-domain keys and quorum two, use the durability profile's exact
`externalWitnessPublicKey`, follow its exact predecessor without a same-sequence
fork, keep one stable nonzero `sharedFailureGroupId` for the journal ID, equal that
ID to the continuity binding's `externalJournalFailureGroupId`, and
satisfy `issuedEpoch <= effectiveLeaseEpoch < expiresEpoch <= issuedEpoch + 4`.
Profile-2 bindings with equal IDs collapse to one vote, and each surviving binding
contributes one to `externally-witnessed(n)` only when the returned mutation is
covered by its present, fully valid generic
`RelayResultBindingV1.externalCommitWitness` and external control floor. That label means externally witnessed
control continuity, not that ciphertext bodies are stored in the control journal
or have body RPO0. A missed backup/restore SLO, stale descriptor, invalid
profile-1 zero shape/readiness, missing/stale/forked profile-2 topology,
profile-2 journal-quorum outage, or worse/unknown band immediately removes the
role from the resilient count and starts replacement repair; a receipt alone
cannot override that degradation.

At runtime, every counted result requires equality of the result binding,
commit-time signed descriptor, nonce-bound health response, and (for profile 2)
witness/topology `durabilityContinuityHash`. `BlindStoreManifestV1` is internal and
is never fetched or trusted by Peerit; equality between that manifest/WAL and the
public tuple is a HiveRelay conformance/release-evidence gate exercised by the
substrate vectors and live challenge, not an inaccessible client condition. That
hash and its immutable profile/journal/
witness/replication/failure-group fields cannot change for one relay/store tuple.
The dynamic `durabilityProfileHash` may advance only through the signed descriptor
chain; Peerit validates the exact commit-time hash instead of substituting the
current one. When it accepts a profile-2 persistent result, Peerit retains the
complete signed result, descriptor, durability profile, topology chain object,
commit witness when present, exact signed restore-evidence head named by the result
binding, and exact verified canonical bundle containing that head (or verified
content-addressed copies) for at least 1,460 substrate epochs and one year. The
retained
head sequence/hash equals the result binding and, when a commit witness is present,
that witness's copy; it occurs exactly once as the bundle's terminal head and
satisfies the applicable witnessed or uncharged interval-coverage rule. Later
topology/head expiry removes the relay from new selection but
does not invalidate a historically valid commit; missing archived topology or
head/bundle bytes makes the corresponding historical claim unverifiable and never
silently downgrades or replaces it with current evidence.

Under policy v1, `rootReplicas` contains exactly three identities from three live
witnessed operator groups and three distinct store IDs; any profile-2 subset also
has distinct current shared-journal IDs, and at least one replica is profile 2.
`discoveryCheckpointReplicas` and `discoverySnapshotReplicas` each contain exactly
three bindings whose logical hash equals their mandatory hash; all three meet the
witnessed operator-group/store/durability rules and the profile-2 subset passes
shared-journal collapse. Each Inbox epoch set is exactly eight stripes times three
witnessed operator groups and three distinct store IDs, with at least one profile-2
binding and pairwise-distinct shared-journal IDs among profile-2 bindings per
stripe. Any other shape fails bootstrap validation before network I/O.

The bootstrap comes from a release recommendation, encrypted recovery bundle,
member invitation, independently authenticated peer, or any other explicitly
configured discovery source. Its signature verifies with the `rootVerifyKey` and
covers domain `peerit.hiverelay.bootstrap.v1` plus every preceding field.
Sequence zero alone omits `previousBootstrapHash`; later sequences are exactly +1
and hash the complete prior bootstrap from that root/generation. A
release-distributed bootstrap hash occurs in
`recommendedBootstrapHashes`; zero recommended hashes is valid, and an
independently authenticated bootstrap need not occur there. Each bootstrap
authenticates only its own discovery view. A relay directory, release pin, and
bootstrap are never author, content, or relay-storage authority. The public
bootstrap exposes reader capabilities and public Inbox material but no CELL
create/renew/drop private key, INBOX create/renew/close private key, or Core
transport writer key. Failure or staleness of every bootstrap source degrades
discovery only: offline authoring, the local materialized view, direct capability
sharing, and queued or direct delivery remain available.

A source bootstrap anchors that source's current checkpoint/snapshot and
maintainer-log heads; their sequences need not be zero. A fresh install may use a
release-recommended root, an explicitly pinned invitation root, or any locally
configured authenticated root subject to freshness and artifact checks, then
follow its next caps. A returning install accepts an update from the same root only
if it equals or dominates that root's locally persisted `DiscoveryFloorV1`; an
older otherwise valid bootstrap is source-local rollback evidence, not a new
starting point. Clients union valid content across roots and direct shares.

### 4.1 Public Inbox construction

Peerit composes public discovery from generic physical Blind Inboxes. Version 1
uses eight stripes and three independently created physical topics per stripe for
the current epoch. `inboxEpoch = floor(effectiveLeaseEpoch / 28)`, so topics rotate
every seven days. The immediately previous epoch remains in the bootstrap for 28
lease epochs; no older topic is authoritative for cold start. Snapshots cover
history older than that overlap.

The newest `InboxEpochSetV1.inboxEpoch` equals that computed epoch. An optional
second set is exactly one less; sets sort by descending epoch and no other epoch is
accepted. Each set contains its own two keys and exactly 24 bindings (eight
stripes times three distinct witnessed operator groups/store IDs, with distinct
shared-journal IDs among profile-2 bindings), with every binding's
epoch equal to the enclosing set. Key rotation therefore replaces the new set
without losing the complete previous key/binding set during the 28-epoch overlap.
Clients use a frame only with its enclosing epoch set.

All public Peerit topics MUST be created with generic `OPEN_APPEND`, frame classes
1 and 2 (4 KiB and 16 KiB), R30 retention, and L90 inbox lease. They have no
append public key. Knowledge of the public topic plus the relay's discovered
generic open-admission credential permits append; no Peerit registration,
namespace, membership, allowlist, or dedicated admission class exists. Anyone can
therefore spam a published topic. The relay performs only generic quota and fixed-
frame checks; Peerit decrypts, authenticates, bounds, deduplicates, and discards
invalid announcements.

The reader recomputes the generic self-certifying `physicalTopic` from
`allocationEpoch` and `createPublicKey`, verifies that the receipt's relay/topic
commitment and create result match, and rejects duplicate `(epoch, stripe,
relay-continuity identity)`, `(epoch, stripe, operatorGroupId)`, or `(epoch,
stripe, storeId)` bindings, plus duplicate profile-2 `(epoch, stripe,
sharedFailureGroupId)` bindings. The release builder additionally retains
the complete generic create request/commitment as evidence. Create, renew, and
close private keys are encrypted client-side release-maintainer recovery
material and are never published; the public create key grants no management
authority.

The encrypted inner announcement is:

```text
PeeritAnnouncementV1 {
  version:             u8 = 1
  manifestTag:         u16
  manifestRecordId:    32 bytes
  manifestMode:        u8 // 1 INLINE, 2 CELL_REFERENCE
  manifestRecord:      canonical complete signed bytes[0..10000]
  manifestReadCaps:    sorted array[0..3] of generic ReadCellCapV1
  publishedLeaseEpoch: u32
  publisherPublicKey:  32 bytes
  signature:           64 bytes
}
```

The complete canonical announcement is at most 12,288 bytes. INLINE requires
1..10,000 record bytes and zero read caps. CELL_REFERENCE requires zero inline
bytes and one to three read caps; each independently fetches the same complete
record bytes. Multiple qualified caps improve durability claims, but one
compatible cap is sufficient and an unregistered cap remains usable without an
independence claim. A larger manifest therefore uses a small pointer,
not a global discovery snapshot and not several unauthenticated Inbox frames. The
signature domain is `peerit.hiverelay.announcement.v1`. A publisher signature
only authenticates the announcement envelope; the named manifest record still
passes its own authority and equality rules. The producer computes
`manifestRecordId` from the tag and exact bytes before signing; a reader recomputes
it after an inline parse or referenced fetch before accepting the announcement.
`publishedLeaseEpoch` may be at most one epoch ahead of effective time and is only
a replay/diagnostic bound; it never orders records, raises a floor, or expires the
manifest. Any public reader may be `publisherPublicKey`.

Announcement validity reduces to the publisher signature, exact manifest record
ID, intrinsic manifest authority, and each claimed replica/readback proof. It has
no producer release channel, operator-registry, maintainer-quorum, or profile-2
prerequisite. One verified replica is sufficient for an `AuthorBindV1`;
additional acknowledgements and profile-2 witnesses change only durability labels.

Any public reader may reannounce an already-authoritative record. Maintainers and
readers MUST accept a supported intrinsically valid announcement regardless of
which official client build produced it. Missing Inbox acknowledgements mean only
that this propagation path is pending; direct capability sharing and other Inbox
or discovery sources remain valid.

For the announcement's selected `InboxEpochSetV1`, let
`s = stripeCountLog2`. Stripe selection takes the first `s` most significant bits
of the HMAC result (and returns zero when `s=0`):

```text
stripeIndex = first_s_bits(
  HMAC-SHA-256(stripeSelectionKey, signedAnnouncementId)
)

frameKey = HKDF-SHA-256(
  ikm  = announcementMasterKey,
  salt = physicalTopic,
  info = "peerit.hiverelay.inbox-frame-key.v1" ||
         inboxEpoch(u32) || stripeIndex(u8) || relayPublicKey,
  L    = 32
)

aad = "peerit.hiverelay.inbox-frame-aad.v1" ||
      inboxEpoch(u32) || stripeIndex(u8) || relayPublicKey ||
      physicalTopic || frameClass(u8)
```

For a selected generic frame byte length `C`, the producer generates an
independent random 24-byte nonce and an independent random padding string for
every relay binding. It encodes exactly `C - 24 - 16` plaintext bytes as
`u32 announcementLength || canonicalCompleteSignedAnnouncement || randomPadding`,
then emits:

```text
frame = nonce24 || XChaCha20-Poly1305-IETF-Seal(
  key=frameKey, nonce=nonce24, aad=aad, plaintext=fixedPlaintext
)
```

The smallest allowed class that fits is mandatory; an announcement over 12,288
bytes is rejected rather than split. `frameHash` is the generic substrate hash of
the exact `frame`, computed by the pinned HiveRelay ABI rather than a Peerit hash
alias. Nonce reuse under a derived frame key is forbidden. The same
announcement is attempted, with fresh nonce/padding/frame hash/admission, on up to
three current compatible bindings for its stripe. Each acknowledgement advances
only that discovery target. Zero acknowledgements queues propagation, one reports
`INBOX_ACKNOWLEDGED(1)`, and the policy target of two earns only the stronger
discovery-availability label.

Inbox is a low-latency hint layer, not content authority or a completeness path.
Checkpoint indexes, direct capability exchange, and other configured discovery
sources run independently. Each install creates random `K_poll` and defines:

```text
selectedRefreshSeconds = foreground ? foregroundInboxRefreshSeconds :
                                      backgroundInboxRefreshSeconds
refreshEpoch = floor(localUnixMillis / (selectedRefreshSeconds * 1000))

bindingIdentity = inboxEpoch(u32) || stripeIndex(u8) || operatorGroupId ||
                  relayPublicKey || physicalTopic

pollRank = HMAC-SHA-256(
  K_poll,
  "peerit.hiverelay.inbox-poll-rank.v1" || mode(u8) || refreshEpoch(u64) ||
  bindingIdentity
)

auditOffset = first_u16be(HMAC-SHA-256(
  K_poll, "peerit.hiverelay.inbox-audit-offset.v1"
)) mod crossAuditIntervalRefreshes
```

Mode is 1 NORMAL, 2 AUDIT, or 3 COLD. Bindings rank by `(pollRank,
canonical bindingIdentity)` and duplicate group IDs fail. Normal mode starts one
current-epoch primary per stripe and may use fallbacks, but the complete refresh
including failures is capped at 16 requests, `limit=32`, 256 decrypted frames,
4 MiB of frame bytes, and four concurrent reads. AUDIT occurs only when
`refreshEpoch mod 240 = auditOffset`; it starts one additional group per stripe
and has one total cap of 24 requests, 512 decryptions, and 8 MiB including all
normal work/fallbacks. COLD is entered only for first catch-up or a cryptographically
verified cursor gap, may consult current and immediately previous sets, and has one
total cap of 32 requests, 512 decryptions, and 8 MiB. No mode adds another mode's
budget, no binding is read twice in one refresh, and no failure path exceeds the
mode-wide cap or fans all 48 bindings at once.

Refreshes have a persistent per-install random phase and independent ±20% jitter
around 15 seconds while visible/foreground and 300 seconds while background. A
failed primary tries the next ranked group after exponential
backoff bounded by the current refresh; remaining work resumes next refresh. Each
binding has an authenticated persisted cursor. Two consecutive budget-exhausted
refreshes, a cursor that cannot advance, or a valid announcement older than the
release useful-content SLO records `hint-lag`; recovery continues from the cursor
without raising request/byte/decrypt limits.

Readers verify generic acknowledgements, derive the binding key, decrypt,
recompute `signedAnnouncementId`, validate the manifest record, and union by
`manifestRecordId`. Relay append revision is only a cursor. Budget exhaustion
records `hint-lag` and continues from authenticated cursors next refresh; it never
claims completeness. A topic or stripe is never application order or authority.
Clients union intrinsically valid records from direct shares, all configured
Inbox sets, and any number of independent discovery roots. Release-recommended
roots are defaults, not an allowlist. Maintainer checkpoints give bounded
followability for records observed by that source; they cannot recover an event no
maintainer received and their omission cannot invalidate it. Under the release
workload's sustained paid-spam envelope, valid
admitted announcements must still meet the useful-content SLO. At total admission
or storage saturation the client retains and resubmits its signed local intent,
the UI reports discovery degraded, and no completeness/censorship-resistance claim
is made. A fully saturated OPEN_APPEND topic is never hand-waved into success by a
checkpoint.

The keys are public reader/writer material. A relay operator can obtain the
release, derive them, and identify/decrypt public announcements; this is the
required G5 negative result. Physical topics are stable G2-S/non-G3 groupings for
their epoch. Fetching all stripes does not provide G4-I, and OHTTP hides neither
the requested topic from the gateway nor the logical read graph from an active
reader. Only a separately passed fixed-epoch bucket/P23 traffic class may claim
G4-I.

---

## 5. Author, replica, repair, snapshot, and migration records

```text
CellReplicaBindingV1 {
  version:              u8 = 1
  logicalHash:          32 bytes
  encodingCommitment:   32 bytes
  relayPublicKey:       32 bytes
  readCapability:       generic ReadCellCapV1
  cellBlobHash:         32 bytes
  sizeClass:            u8
  allocationEpoch:      u32
  leaseEpoch:           u32
  createPublicKey:      32 bytes
  renewPublicKey:       32 bytes
  dropPublicKey:        32 bytes
  allocationCommitment: 32 bytes
  relayReceipt:         generic BlindReceiptV1
}

CoreReplicaBindingV1 {
  version:                  u8 = 1
  logicalHash:              32 bytes
  encodingCommitment:       32 bytes
  relayPublicKey:           32 bytes
  corePublicKey:            32 bytes
  readCapability:           generic BlindCoreReadCapV1
  firstBlockIndex:          u64
  blockCount:               u32
  coreSliceCommitment:      32 bytes
  witnessedFork:            u64
  witnessedLength:          u64
  witnessedSignedHeadHash:  32 bytes
  leaseEpoch:               u32
  relayAcknowledgement:     generic BlindCoreAckV1
}

ReplicaBindingV1 = tagged union {
  1: CellReplicaBindingV1
  2: CoreReplicaBindingV1
}

AuthorBindV1 {
  version:                 u8 = 1
  authorSequence:          u64
  previousAuthorRecordId:  optional 32 bytes
  logicalHash:             32 bytes
  innerCodec:              u16
  innerLength:             u64
  initialReplicas:         sorted array[1..16] of tagged ReplicaBindingV1
  authorPublicKey:         32 bytes
  signature:               64 bytes
}

RepairAddV1 {
  version:                  u8 = 1
  targetAuthorityRecordId:  32 bytes
  logicalHash:              32 bytes
  replica:                  exactly one tagged ReplicaBindingV1
  repairerPublicKey:        32 bytes
  repairNonce:              32 bytes
  issuedLeaseEpoch:         u32
  hintExpiresLeaseEpoch:    u32
  signature:                64 bytes
}

ChargedProbeEvidenceV1 { // canonical complete bytes <= 16384
  version:                  u8 = 1
  probedAtLeaseEpoch:       u32
  probeKind:                u8 // 1 CELL_4K_PROVE, 2 CORE_4K_PROVE
  relayPublicKey:           32 bytes
  storeId:                  32 bytes
  durabilityContinuityHash: 32 bytes
  descriptorSequence:       u64
  descriptorHash:           32 bytes
  durabilityProfileHash:    32 bytes
  requestCommitment:        32 bytes
  probeSelector:            bounded canonical bytes[1..1024]
  servedBytesHash:          32 bytes
  signedReceiptOrAckBytes:  bounded canonical bytes[1..12288]
}

RelayProbeEvidenceSetV1 { // canonical complete bytes <= 1048576
  version:                  u8 = 1
  rootRecordId:             32 bytes
  generation:               u64
  setSequence:              u64
  previousSetHash:          optional 32 bytes
  createdLeaseEpoch:        u32
  expiresLeaseEpoch:        u32
  entries:                  sorted array[1..16] of ChargedProbeEvidenceV1
  maintainerSignatures:     sorted array[3..4] of
                            { maintainerKey: 32 bytes, signature: 64 bytes }
}

DiscoveryAvailabilityEntryV1 {
  recordId:                 32 bytes
  manifestTag:              u16
  availabilityRevision:     u64
  previousAvailabilityHash: optional 32 bytes
  availabilityStatus:       u8 // 0 UNAVAILABLE, 1 DEGRADED, 2 BODY_RESILIENT
  recordReadCaps:           sorted array[0..3] of generic ReadCellCapV1
}

DiscoveryIndexChildV1 {
  edgeByte:               u8
  childHash:              32 bytes
  subtreeCount:           u64
  firstRecordId:          32 bytes
  lastRecordId:           32 bytes
  childReadCaps:          sorted array[3..3] of generic ReadCellCapV1
}

DiscoveryIndexBranchV1 {
  version:                u8 = 1
  indexKind:              u8 // 1 MEMBERSHIP, 2 AVAILABILITY
  depth:                  u8 // key bytes consumed before compressedPrefix
  compressedPrefix:       bytes[0..31]
  subtreeCount:           u64
  firstRecordId:          32 bytes
  lastRecordId:           32 bytes
  children:               sorted array[2..256] of DiscoveryIndexChildV1
}

DiscoveryMembershipLeafV1 {
  version:                u8 = 1
  depth:                  u8
  recordIds:              sorted array[1..256] of 32-byte record IDs
}

DiscoveryAvailabilityLeafV1 {
  version:                u8 = 1
  depth:                  u8
  entries:                sorted array[1..128] of DiscoveryAvailabilityEntryV1
}

DiscoveryIndexNodeV1 = tagged union {
  1: DiscoveryIndexBranchV1
  2: DiscoveryMembershipLeafV1
  3: DiscoveryAvailabilityLeafV1
}

DiscoveryRecentBucketV1 {
  version:                u8 = 1
  bucketNumber:           u64 // floor(inclusion proposalSlot / 5)
  bucketRevision:         u32
  previousVersionHash:    optional 32 bytes
  previousVersionReadCaps:sorted array[0..3] of generic ReadCellCapV1
  previousBucketHash:     optional 32 bytes
  previousBucketReadCaps: sorted array[0..3] of generic ReadCellCapV1
  recordCount:            u64
  recordRootHash:         32 bytes
  recordRootReadCaps:     sorted array[0..3] of generic ReadCellCapV1
  skipLinks:              sorted array[0..12] of {
                            distanceBuckets: u16,
                            bucketNumber: u64,
                            bucketHash: 32 bytes,
                            bucketReadCaps: sorted array[3..3] of
                              generic ReadCellCapV1
                          }
}

DiscoveryIndexQueryV1 = tagged union {
  1: { recordId: 32 bytes }
  2: { lowerInclusive: 32 bytes, upperExclusive: optional 32 bytes,
       limit: u16 in 1..256 }
}

DiscoveryIndexProofV1 {
  version:                u8 = 1
  indexKind:              u8 // 1 MEMBERSHIP, 2 AVAILABILITY
  rootHash:               32 bytes
  query:                  DiscoveryIndexQueryV1
  returnedCount:          u16
  continuationKey:        optional 32 bytes
  totalNodeBytes:         u32 // <= 16777216
  nodes:                  sorted array[1..1024] of {
                            nodeHash: 32 bytes,
                            taggedNodeBytes: canonical bytes[1..1048576]
                          }
}

MaintainerSubmitV1 {
  version:                u8 = 1
  rootRecordId:           32 bytes
  generation:             u64
  requestNonce:           32 random bytes
  signedAnnouncementId:   32 bytes
  announcementBytes:      canonical complete PeeritAnnouncementV1 bytes[1..12288]
  inboxAppendAcks:        sorted array[0..3] of generic InboxAppendAckV1
}

MaintainerSubmitResultV1 {
  version:                u8 = 1
  rootRecordId:           32 bytes
  generation:             u64
  requestNonce:           32 bytes
  status:                 u8 // 1 RECEIPT, 2 FIXED_REJECTION, 3 BUSY
  receipt:                optional MaintainerObservationReceiptV1
  decisionCode:           u16
  retryAfterMillis:       u32
  maintainerKey:          32 bytes
  signature:              64 bytes
}

MaintainerObservationV1 {
  version:                u8 = 1
  rootRecordId:           32 bytes
  generation:             u64
  maintainerKey:          32 bytes
  observationSequence:    u64
  previousObservationHash:optional 32 bytes
  receivedUnixMillis:     u64
  signedAnnouncementId:   32 bytes
  announcementBytes:      canonical complete PeeritAnnouncementV1 bytes[1..12288]
  signature:              64 bytes
}

MaintainerObservationReceiptV1 {
  version:                u8 = 1
  rootRecordId:           32 bytes
  generation:             u64
  maintainerKey:          32 bytes
  observationSequence:    u64
  observationHash:        32 bytes
  signedAnnouncementId:   32 bytes
  receivedUnixMillis:     u64
  signature:              64 bytes
}

MaintainerObservationHeadV1 {
  maintainerKey:          32 bytes
  operatorGroupId:        32 bytes
  logReplicas:            sorted array[3..3] of CoreReplicaBindingV1
  observationSequence:    u64
  observationHash:        32 bytes
  observedThroughUnixMillis:u64
  signature:              64 bytes
}

DiscoveryProposalV1 {
  version:                u8 = 1
  rootRecordId:           32 bytes
  generation:             u64
  checkpointSequence:     u64
  proposalSlot:           u64
  previousCheckpointHash: optional 32 bytes
  previousSnapshotHash:   optional 32 bytes
  observationCutoffUnixMillis:u64
  observationHeads:       sorted array[3..4] of MaintainerObservationHeadV1
  acceptedObservationCount:u32
  rejectedObservationCount:u32
  observationDecisionRoot:32 bytes
  candidateSnapshotUnsignedBytes:canonical DiscoverySnapshotV1 fields before
                                 maintainerSignatures bytes[1..65535]
  candidateSnapshotCommitment:32 bytes
  candidateSnapshotReadCaps:sorted array[3..3] of generic ReadCellCapV1
  nextCheckpointReadCaps: sorted array[3..3] of generic ReadCellCapV1
  checkpointCreatedUnixMillis:u64
  proposerKey:            32 bytes
  signature:              64 bytes
}

DiscoverySnapshotV1 {
  version:                u8 = 1
  rootRecordId:           32 bytes
  generation:             u64
  snapshotSequence:       u64
  previousSnapshotHash:   optional 32 bytes
  previousSnapshotReadCaps:sorted array[0..3] of generic ReadCellCapV1
  previousFrontierRoot:   optional 32 bytes
  previousAvailabilityRoot:optional 32 bytes
  createdLeaseEpoch:      u32
  createdUnixMillis:      u64
  frontierCount:          u64
  frontierRoot:           32 bytes
  frontierRootReadCaps:   sorted array[3..3] of generic ReadCellCapV1
  addedCount:             u64
  addedRoot:              optional 32 bytes
  addedRootReadCaps:      sorted array[0..3] of generic ReadCellCapV1
  availabilityRoot:       32 bytes
  availabilityRootReadCaps:sorted array[3..3] of generic ReadCellCapV1
  relayProbeEvidenceSetHash:32 bytes
  relayProbeEvidenceSetReadCaps:sorted array[3..3] of generic ReadCellCapV1
  recentBucketNumber:     u64
  recentBucketHash:       32 bytes
  recentBucketReadCaps:   sorted array[3..3] of generic ReadCellCapV1
  maintainerSignatures:   sorted array[3..4] of
                          { maintainerKey: 32 bytes, signature: 64 bytes }
}

DiscoveryCheckpointV1 {
  version:                u8 = 1
  rootRecordId:           32 bytes
  generation:             u64
  checkpointSequence:     u64
  previousCheckpointHash: optional 32 bytes
  snapshotHash:           32 bytes
  snapshotSequence:       u64
  frontierRoot:           32 bytes
  availabilityRoot:       32 bytes
  relayProbeEvidenceSetHash:32 bytes
  snapshotReadCaps:       sorted array[3..3] of generic ReadCellCapV1
  proposalHash:           32 bytes
  proposalReadCaps:       sorted array[3..3] of generic ReadCellCapV1
  createdLeaseEpoch:      u32
  createdUnixMillis:      u64
  nextCheckpointReadCaps: sorted array[3..3] of generic ReadCellCapV1
  maintainerSignatures:   sorted array[3..4] of
                          { maintainerKey: 32 bytes, signature: 64 bytes }
}

DiscoveryFloorV1 {
  version:                u8 = 1
  rootRecordId:           32 bytes
  generation:             u64
  checkpointSequence:     u64
  checkpointCommitment:   32 bytes
  checkpointUnixMillis:   u64
  snapshotSequence:       u64
  snapshotCommitment:     32 bytes
  frontierRoot:           32 bytes
  availabilityRoot:       32 bytes
  relayProbeEvidenceSetHash:32 bytes
  recentBucketNumber:     u64
  recentBucketHash:       32 bytes
}

DiscoveryRecoveryParentV1 {
  floor:                   DiscoveryFloorV1
  checkpointReadCaps:      sorted array[3..3] of generic ReadCellCapV1
  snapshotReadCaps:        sorted array[3..3] of generic ReadCellCapV1
}

DiscoveryRecoveryMergeV1 {
  version:                 u8 = 1
  previousRootRecordId:    32 bytes
  previousGeneration:      u64
  nextRootRecordId:        32 bytes
  nextGeneration:          u64
  parents:                 sorted array[1..16] of DiscoveryRecoveryParentV1
  mergedSnapshotCommitment:32 bytes
  mergedFrontierRoot:      32 bytes
  mergedAvailabilityRoot:  32 bytes
  mergedRelayProbeEvidenceSetHash:32 bytes
  mergedRecentBucketNumber:u64
  mergedRecentBucketHash:  32 bytes
  mergedSnapshotReadCaps:  sorted array[3..3] of generic ReadCellCapV1
  createdUnixMillis:       u64
}

MigrationGenesisV1 {
  version:                      u8 = 1
  rootRecordId:                 32 bytes
  generation:                   u64
  releaseSequence:              u64
  releaseAuthorityKeyId:        32 bytes
  cutoffPendingPinHash:         32 bytes
  legacySourceSetHash:          32 bytes
  legacyCutoffHash:             32 bytes
  legacyCensusRoot:             32 bytes
  retainedRecordCount:          u64
  invalidRecordCount:           u64
  conflictRecordCount:          u64
  missingRangeCount:            u64
  invalidCategoryRoot:          32 bytes
  conflictCategoryRoot:         32 bytes
  missingCategoryRoot:          32 bytes
  legacyArchiveArtifactHash:    32 bytes
  legacyArchiveIndexHash:       32 bytes
  legacyArchiveDistributionHash:32 bytes
  legacyArchiveBundleLogicalHash:32 bytes
  legacyArchiveBundleReplicas:  sorted array[3..16] of tagged ReplicaBindingV1
  originalRecordsLogicalHash:   32 bytes
  originalRecordsReplicas:      sorted array[3..16] of tagged ReplicaBindingV1
  createdLeaseEpoch:            u32
  releaseSignature:             64 bytes
}

ManifestRecordV1 = tagged union {
  1: AvailabilityRootV1
  2: RootRotateV1
  3: AuthorBindV1
  4: RepairAddV1
  5: DiscoverySnapshotV1
  6: MigrationGenesisV1
  7: DiscoveryCheckpointV1
  8: RelayProbeEvidenceSetV1
}
```

Every `ReplicaBindingV1` array sorts by raw `replicaId`, rejects duplicate IDs,
and then applies the signed policy's distinct continuity-root, operator-group,
and store-ID requirements plus profile-2 shared-journal collapse. A
renewed receipt or fresher Core acknowledgement updates evidence attached to the
same stable replica ID; it does not add another replica or availability vote.

The signature domains are `peerit.hiverelay.root.v1`,
`peerit.hiverelay.bootstrap.v1`, `peerit.hiverelay.root-rotate.v1`,
`peerit.hiverelay.author-bind.v1`, `peerit.hiverelay.repair-add.v1`,
`peerit.hiverelay.discovery-snapshot.v1`,
`peerit.hiverelay.discovery-checkpoint.v1`,
`peerit.hiverelay.relay-probe-evidence-set.v1`, and
`peerit.hiverelay.migration-genesis.v1`. Maintainer submissions/results,
observations, receipts, heads, and proposals use their exact domains in section
5.2.1. Index nodes, recent buckets, recovery merges, and proofs are unsigned
content-addressed children of a signed snapshot or root rotation; they do not have
a signature domain.

Every discovery maintainer signature covers one shared commitment:

```text
discoverySnapshotCommitment = BLAKE2b-256(
  "peerit.hiverelay.discovery-snapshot.v1" || manifestTag(5) ||
  len64(canonical snapshot fields before maintainerSignatures) ||
  canonical snapshot fields before maintainerSignatures
)

discoveryCheckpointCommitment = BLAKE2b-256(
  "peerit.hiverelay.discovery-checkpoint.v1" || manifestTag(7) ||
  len64(canonical checkpoint fields before maintainerSignatures) ||
  canonical checkpoint fields before maintainerSignatures
)

relayProbeEvidenceSetCommitment = BLAKE2b-256(
  "peerit.hiverelay.relay-probe-evidence-set.v1" || manifestTag(8) ||
  len64(canonical complete set fields before maintainerSignatures) ||
  canonical complete set fields before maintainerSignatures
)

relayProbeEvidenceSetHash = BLAKE2b-256(
  "peerit.hiverelay.relay-probe-evidence-set-hash.v1" ||
  len64(canonicalCompleteSignedSet) || canonicalCompleteSignedSet
)

discoveryAvailabilityEntryHash = BLAKE2b-256(
  "peerit.hiverelay.discovery-availability-entry-hash.v1" ||
  len64(canonicalCompleteAvailabilityEntry) ||
  canonicalCompleteAvailabilityEntry
)

discoveryIndexNodeHash = BLAKE2b-256(
  "peerit.hiverelay.discovery-index-node-hash.v1" || nodeTag(u8) ||
  len64(canonicalCompleteTaggedNode) || canonicalCompleteTaggedNode
)

discoveryRecentBucketHash = BLAKE2b-256(
  "peerit.hiverelay.discovery-recent-bucket-hash.v1" ||
  len64(canonicalCompleteBucket) || canonicalCompleteBucket
)

maintainerObservationHash = BLAKE2b-256(
  "peerit.hiverelay.maintainer-observation-hash.v1" ||
  len64(canonicalCompleteSignedObservation) ||
  canonicalCompleteSignedObservation
)

discoveryProposalHash = BLAKE2b-256(
  "peerit.hiverelay.discovery-proposal-hash.v1" ||
  len64(canonicalCompleteSignedProposal) || canonicalCompleteSignedProposal
)

emptyObservationDecisionRoot = BLAKE2b-256(
  "peerit.hiverelay.discovery-observation-decision-empty.v1"
)

emptyRecentBucketRecordRoot = BLAKE2b-256(
  "peerit.hiverelay.discovery-recent-bucket-empty.v1"
)

discoveryRecoveryMergeHash = BLAKE2b-256(
  "peerit.hiverelay.discovery-recovery-merge-hash.v1" ||
  len64(canonicalCompleteRecoveryMerge) || canonicalCompleteRecoveryMerge
)
```

Signers are distinct keys in the accepted root's
`discoveryMaintainerKeys`, sort by key bytes, and meet its exact threshold. Every
membership/availability/addition trie node and recent bucket uses the matching
formula above; an absent zero-addition root has no fabricated hash or read cap.
`previousSnapshotHash` and checkpoint `snapshotHash` equal the shared
`discoverySnapshotCommitment`; `previousCheckpointHash` equals the shared
`discoveryCheckpointCommitment`. Different valid threshold-signature subsets over
one identical commitment are equivalent certificates, not forks; chain identity
never depends on which three of four signatures arrived first. A different hash
alias is nonconforming.

Snapshot sequence zero has no previous hash/roots and zero previous-snapshot caps;
every later snapshot is exactly +1 and carries exactly three previous-snapshot
caps on distinct witnessed operator groups/store IDs, with distinct shared-journal
IDs among profile-2 caps, that reconstruct the prior certified bytes.
`createdLeaseEpoch = floor(createdUnixMillis / 21600000)` and both values strictly
increase when a new snapshot is created. A checkpoint timestamp is at least its
snapshot timestamp and uses the same Unix-to-lease mapping. Clients reject overflow,
a mismatched mapping, a snapshot from the future beyond the 120-second allowance,
or a checkpoint that points to a later timestamp than itself. Maintainers renew the
linked snapshot history for the policy's 365-day retention before expiry.

Root rotation uses one non-circular commitment:

```text
rootRotateCommitment = BLAKE2b-256(
  "peerit.hiverelay.root-rotate.v1" ||
  len64(canonical root-rotation fields before signature fields) ||
  canonical root-rotation fields before signature fields
)
```

The old root, every recovery key, and the new root sign that same commitment.
Normal rotation has old/new signatures and no recovery signatures. Recovery
rotation omits the old signature and has the exact accepted recovery threshold
plus the new signature. Every named next replica must carry
`nextRootLogicalHash`; after decrypting it, the client recomputes both the next
root logical hash and `nextRootRecordId` before following the rotation. The shared
commitment therefore also binds the optional discovery recovery-merge hash/caps
without a signature cycle. The array
is exactly three replicas on three live witnessed operator groups with acceptable
durability and distinct store IDs, with distinct shared-journal IDs among profile-2
bindings, and all three read back before rotation acceptance.

### 5.1 Exact Core logical binding

Core is a portable G2-S availability representation, not a G3 replica. Every
Peerit object stored in a device transport Hypercore is split into deterministic
chunks of at most 60 KiB and encoded as consecutive canonical frames:

```text
CoreObjectChunkV1 {
  version:          u8 = 1
  logicalHash:      32 bytes
  innerCodec:       u16
  totalInnerLength: u64
  chunkIndex:       u32
  chunkCount:       u32
  chunkHash:        32 bytes
  chunkBytes:       bounded bytes[0..61440]
}

coreSliceCommitment = BLAKE2b-256(
  "peerit.hiverelay.core-slice.v1" || corePublicKey ||
  witnessedFork(u64) || firstBlockIndex(u64) || blockCount(u32) ||
  ordered(
    BLAKE2b-256("peerit.hiverelay.core-chunk.v1" ||
                len64(canonicalCoreObjectChunk) || canonicalCoreObjectChunk)
  )
)
```

`chunkCount = max(1, ceil(totalInnerLength / 61440))`; every non-final chunk is
exactly 61,440 bytes, the final chunk is 1..61,440 bytes, and an empty object has
one zero-byte chunk. `blockCount` equals `chunkCount`. `chunkHash` is
BLAKE2b-256 over exact `chunkBytes`. The chunks are consecutive, start at index
zero, have one common count/hash/codec/length, and concatenate to exactly
`totalInnerLength`. The concatenation MUST reproduce `logicalHash` and
`encodingCommitment`. The Hypercore may apply upstream block encryption and
proof encoding only after this profile frame is encoded. The transport secret
signing key never enters a binding or recovery bundle; `BlindCoreReadCapV1`
contains the public core key, block-encryption key, and witnessed signed head.

`CoreReplicaBindingV1.corePublicKey` MUST equal the key inside `readCapability`.
Its witnessed fork, length, and signed-head hash MUST equal the read capability,
the verified Hypercore head, and the relay acknowledgement. `firstBlockIndex +
blockCount` must not overflow and must be at most `witnessedLength`. A
`mirror-accepted` acknowledgement proves only sponsorship; it satisfies a recent-
serve threshold only after a separately challenged `recently-served`
acknowledgement at the same or higher verified head. Different relay bindings may
name the same Core/key and are therefore linkable; they still have different
relay acknowledgements and `replicaId` values.

The writer retains its complete local outbox intent, exact chunks, Core transport
writer, and stable logical event ID independently of every relay. One verified
`mirror-accepted` acknowledgement is a truthful remote-storage acknowledgement;
it does not by itself prove recent retrievability. The stronger configured-policy
label requires `corePolicyMirrorTarget` distinct qualifying acknowledgements and
`corePolicyRecentServeTarget` distinct qualifying full-byte/proof
`recently-served` results, with the profile-2 and shared-journal constraints above.
A resilient external-witness claim additionally requires
`resilientClaimMinimumExternalProbeAcks` valid charged-probe envelopes for a
profile-2 target. An uncharged profile-2 prove can count recent retrievability but
cannot satisfy that claim. Missing a target or `repairDeadlineEpochs` degrades the
durability label and starts a fresh sponsor/replica attempt without discarding,
invalidating, or preventing local authoring. It never grants a release, registry,
or profile-2 service permission to kill the writer.

### 5.2 Mandatory equality matrix

Validation is all-or-nothing. No hash or receipt is accepted in isolation.
In this matrix, “three witnessed groups”, “distinct groups”, “group-diverse”, and
“independent” storage bindings always require distinct relay-continuity identities, distinct live
witnessed operator groups, and distinct `storeId` values. Profile 1 validates its
exact zero/absent external fields plus intact-store readiness and its declared local
failure domain remains an operator assumption. Profile 2 additionally validates
`BlindExternalJournalTopologyV1.sharedFailureGroupId`, the durability-profile
topology hash, topology signature/chain/freshness, exact relay/store/journal/
witness identity, three-node/quorum-two shape, and role-conflict evidence; equal
shared IDs collapse. A two-binding policy-qualified durability set includes at
least one valid profile-2 binding; a three-binding group-diverse target may contain two profile-1
bindings when their witnessed operator groups/store IDs/local-failure-domain IDs differ. Missing
evidence never inherits independence or an external-witness count from another
binding. The counted `storeId` is never an app assertion: the current signed
generic relay binding/descriptor, durability profile association, operation
receipt or acknowledgement, and profile-2 topology where present must all carry or
resolve the same store value, immutable `durabilityContinuityHash`, and exact
commit-time dynamic `durabilityProfileHash`/descriptor tuple.

| Object under test | Equalities and proofs that MUST all hold |
| --- | --- |
| `AvailabilityBootstrapV1` | Its signature verifies with `rootVerifyKey`; sequence zero omits a predecessor and later bootstraps are exact +1/hash-linked within that root/generation. Root ID/logical hash/key/generation/validator/recovery threshold, checkpoint, snapshot, recent bucket, index roots, proposal, witness-attested registry, and every included capability validate under their own rows. When recommended by a release, its complete hash occurs in `recommendedBootstrapHashes` and its compatible profile/policy/migration fields equal that pin; independently authenticated bootstraps validate without that recommendation. Registry, maintainer, replica, and probe evidence qualify only this source's completeness/durability claims. A fresh anchor passes time bounds; a returning anchor never lowers its source-specific `DiscoveryFloorV1`. Failure rejects this source, not an author event, direct share, compatible relay, or local outbox. |
| `RootRotateV1` | Previous ID/generation equal the witnessed root; next generation is exactly +1; every next binding's logical hash equals `nextRootLogicalHash`; fetched bytes reproduce both next logical hash and next profile record ID; old/recovery/new signatures cover one commitment. Ordinary/continuing rotation omits the recovery merge and has zero merge caps; any sequence-reset/fork recovery binds one valid `DiscoveryRecoveryMergeV1` hash and exactly three group-diverse caps. |
| `CellReplicaBindingV1` | Allocation epoch/create public key reproduce the generic self-certifying slot in the read cap; allocation commitment and receipt slot commitment match; GET bytes hash to `cellBlobHash`; receipt blob hash/size/allocation/lease and relay key equal the binding; client decrypts/reassembles exact inner bytes; those bytes reproduce `logicalHash` and `encodingCommitment`; create/renew/drop private material is absent from public records. |
| `CoreReplicaBindingV1` | Relay key, Core key, fork/length/head hash, and lease are equal in binding/read cap/proof/ack; Hypercore signature and Merkle proof verify; contiguous chunks reproduce `coreSliceCommitment`, exact inner bytes, `logicalHash`, and `encodingCommitment`; a recent-serve claim has a matching challenged acknowledgement, not only mirror acceptance. |
| `ChargedProbeEvidenceV1` | Kind is exactly admitted 4-KiB CELL.PROVE or deterministic 4-KiB CORE.PROVE; selector/read capability and re-fetched sentinel reconstruct the complete canonical result around the retained signed receipt/ack; served hash, request commitment, relay/store/continuity and commit-time descriptor/profile equal; present external witness verifies; bytes are <=16 KiB and no token/payment identifier appears. |
| `RelayProbeEvidenceSetV1` | Root/generation match; sequence zero alone omits predecessor and later sets are exact +1/hash-linked; 3-of-4 maintainer signatures verify; canonical bytes are <=1 MiB; entries sort, have unique relay/store targets, and are within the set interval/proof freshness; three snapshot read caps reconstruct exactly this set hash. It is global/shared and exempt from recursively requiring a probe. |
| `MaintainerSubmitV1` | Root/generation select the addressed discovery index, nonce is nonzero, and the recomputed announcement ID equals the submitted canonical signed bytes. The announcement passes its publisher signature, manifest identity, intrinsic author/causal authority, and every claimed replica proof. Each of zero to three supplied generic append acknowledgements independently maps to the derived stripe, reads back its exact frame hash, and decrypts to that announcement; acknowledgements may qualify propagation/durability but are not content authority. A direct submit is an additional discovery path and neither requires nor substitutes authority from Inbox, release, registry, or profile 2. |
| `MaintainerSubmitResultV1` | Root, generation, and nonce exactly echo one valid submit; maintainer key equals the selected ingress binding and its result signature verifies. RECEIPT embeds one independently valid receipt whose root/generation/key/announcement ID equal the submit and has zero decision/retry fields; FIXED_REJECTION has no receipt, one pinned code, and zero retry; BUSY has no receipt/decision and a 1..60,000-ms retry. Every other optional-field shape fails. |
| `MaintainerObservationHeadV1` | Maintainer key/operator group equal the accepted root/registry binding and the head signature verifies. Exactly three Core replica bindings share one Core key, exact logical slice and witnessed terminal head while independently passing the Core row on three live storage groups. Observation sequence/hash equal that terminal canonical observation, time is monotonic and within the proposal bounds, and `observedThroughUnixMillis` reaches the proposal cutoff. |
| `AuthorBindV1` | Fetched inner bytes reproduce logical hash/codec/length; Peerit author/delegation/target/sequence continuity and signature verify; at least one initial replica independently reconstructs those same bytes and every claimed replica passes its Cell/Core row. Release, migration stage, registry, root, maintainer, profile 2, and discovery presence are deliberately absent from its authority. |
| `RepairAddV1` | The target authority record already validates and its logical hash is equal; the candidate replica independently passes its Cell/Core row; repair signature and bounded hint lifetime verify; the hint changes no authority/floor/policy field. A later reannouncement may refresh discovery, never this signed repair record or its target authority. |
| `DiscoverySnapshotV1` | Membership/addition/availability persistent-radix roots and every traversed node reproduce tags, compressed paths, counts, disjoint key ranges, hashes, and their claimed capability qualification. Sequence zero omits previous fields/caps and additions equal the nonempty frontier; later sequence is exactly +1, hash-links prior roots, and membership is the exact prior-set union additions (or canonical zero-addition form). Availability has exactly one latest hash-linked entry per membership key, no extra key, valid status/cap count, and every live cap reconstructs exact tag/record bytes. Current recent bucket/revision/root/skip links agree with timestamp and inclusion decisions. Timestamp/lease bounds, proposal replay/decision root, root/generation, and threshold signatures verify this source's shared commitment. Omission, staleness, or a fork degrades or rejects that discovery source and is auditable censorship evidence; it never invalidates intrinsically valid content found directly or through another source. |
| `DiscoveryCheckpointV1` | Sequence zero alone omits previous hash; later sequence is exactly +1 and hashes the accepted prior checkpoint commitment. Snapshot hash/sequence/frontier/availability roots equal that snapshot; its caps reconstruct one valid certificate. Proposal caps reconstruct the exact proposal hash; proposal root/generation/checkpoint/previous hashes, candidate snapshot commitment/caps, `checkpointCreatedUnixMillis`, and next-checkpoint caps equal the finalized records. Proposer slot/cutoff, terminal heads through cutoff, complete decision root/counts, and deterministic replay verify. Relative to the prior checkpoint the snapshot tuple is entirely identical for a no-change heartbeat or exactly-next linked. Root/generation, Unix/lease mapping, freshness limits, source-specific floor, and threshold signatures verify. This orders one discovery source only and is never a global authoring or relay-delivery floor. |
| `DiscoveryRecoveryMergeV1` | Root IDs equal the enclosing rotation and next generation is exactly previous +1; no more than 16 canonical-order parents are unique commitment-based floors from that previous root/generation and they include the client's floor plus every detected valid fork. Three checkpoint and three snapshot caps per parent reconstruct the floor's certified commitments/roots. Merged membership is the exact full union; availability has one revision descending every parent entry or remains a blocking conflict; and a deterministic up-to-2,016-bucket contiguous hot-chain union (all buckets when younger) ends at the maximum parent bucket, deduplicates each record to its lowest valid bucket, and reproduces the merged recent hash. Merged snapshot caps/commitment/roots equal the new bootstrap. The complete merge hashes to the value and caps bound by `RootRotateV1`; parent overflow or omission blocks recovery. |
| `MigrationGenesisV1` | The tag-6 `profileRecordId` equals every frozen-cutoff/archive-only pin's retained `migrationGenesisRecordId`. Its release sequence/key equal the historical first `FROZEN_CUTOFF` pin at `cutoffActivationReleaseSequence`; `cutoffPendingPinHash` names its immediate `LIVE_DUAL_READ` predecessor. Later pins retain cutoff/genesis/activation values and descend from that activation pin. Genesis cutoff/source-set equal the historical pins and every retained value. Cutoff/archive/index/category roots/counts reproduce; the signed distribution manifest and canonical bundle hash exactly, independent external copies return that bundle, and every claimed HiveRelay replica reconstructs the same archive/index/distribution bytes. Every retained original byte passes the pinned legacy validator; no release signature is treated as an author signature and this record never controls blind authoring or delivery. |

Any mismatch retains evidence, marks the candidate invalid, and leaves the last
valid witnessed floor unchanged. Majority, newest relay time, append revision,
receipt count, or a repair hint never repairs an equality failure.

An `AuthorBindV1` is accepted only after the client fetches/decrypts the named
logical object and verifies its Peerit author/delegation, content identity,
schema, target binding, sequence, and continuity under the pinned validator
profile. A relay receipt or claimed hash is never content authority.

A `RepairAddV1` is an add-only untrusted availability hint. A public reader may
repair because it has the public read capability, but it cannot introduce or edit
logical content, advance an author/root head, revoke a record, lower a witnessed
floor, or replace a root. The candidate counts only after the full outer receipt,
ciphertext hash, decryption/reassembly, logical hash, inner signature, authority,
and continuity checks pass. HiveRelay never scans or repairs randomized cells;
the capable client creates a fresh wrapper, slot, and management-key set.

The hint requires `issuedLeaseEpoch <= effectiveNowEpoch <=
hintExpiresLeaseEpoch` and `1 <= hintExpiresLeaseEpoch - issuedLeaseEpoch <= 120`.
It is deduplicated by `(targetAuthorityRecordId, replicaId)`, keeps at most one
candidate per relay-continuity identity (highest verified lease, then lowest
`replicaId`), and is bounded to 16 valid hint candidates per target after raw
identity-byte ordering. Author/migration bindings are a separate set and are
never evicted by this hint bound.
It cannot change preferred order, acknowledgement threshold, lease policy,
migration membership, cutoff/archive status, target authority, or an existing
replica; it cannot authorize a read beyond the capability it contains, delegate
repair, or make another hint authoritative. A client MAY ignore every hint. An
author-signed binding or release-signed migration binding remains authority; a
hint only supplies a candidate that still passes the complete equality matrix.

Repair has an operational SLO. Normal clients and at least
`repairMaintainerTarget=3` public app-side maintainers mapped to three witnessed
operator groups
challenge counted replicas every `challengeCadenceEpochs=1`; one failed full read/
serve immediately degrades that replica. A capable maintainer creates and fully
verifies a replacement in another witnessed operator group with a fresh distinct
store ID and, for profile 2, a non-colliding shared-journal ID within
`repairDeadlineEpochs=2`, then reannounces the bounded hint at least every
`repairHintRefreshEpochs=28` while it remains needed. Maintainers possess only the
public read/repair capabilities and cannot sign Peerit content or root state.
HiveRelay remains unaware of replica relationships. Two healthy maintainers are
the minimum repair quorum; loss of one target is tolerated, while loss of quorum
or a missed deadline drops the resilient claim instead of assuming some reader
will eventually repair. Chaos tests stop each maintainer alone, stop quorum,
expire hints, return an author after 30/90 days, replace a whole operator group,
destroy profile-1 live stores across separately witnessed operators, collapse
every profile-2 relay sharing one journal failure-group ID, and kill a complete
two-of-three external-journal quorum.

#### 5.2.1 Maintainer production and auditable inclusion

Each root-authorized maintainer owns one append-only encrypted observation Core
whose current public read capability/head is in the bootstrap. The log is mirrored
as opaque Core blocks by three witnessed HiveRelay operator groups backed by three
distinct store IDs; profile-2 bindings also have distinct shared-journal IDs.
Relays neither parse nor apply it.
Observation sequence zero alone omits the previous hash, later sequences
are exactly +1/hash-linked, and the maintainer signs domain
`peerit.hiverelay.maintainer-observation.v1`. A maintainer returns a receipt under
`peerit.hiverelay.maintainer-observation-receipt.v1` only after the exact observation
is fsynced and recently served from its log. Heads sign domain
`peerit.hiverelay.maintainer-observation-head.v1` and must reproduce from the Core
replica bindings, signed head, observation sequence, and terminal observation
hash. All three bindings name the same Core key and exact current logical
slice/head, map to three witnessed operator groups/store IDs, and have distinct
shared-journal IDs among profile-2 bindings. They independently pass the Core
equality and recent-serve rules; a proposal cannot advance on one portable cap.

Producers submit the same signed announcement through the blind public Inboxes.
Native/Pear producers MAY additionally send canonical `MaintainerSubmitV1` over
the four bootstrap-pinned app-side Noise/Protomux bindings, using an independent
random request nonce and Noise session per maintainer and requiring only three
receipts for threshold-received progress. The root/generation and announcement ID
are checked before processing. `inboxAppendAcks` contains zero to three independent
generic acknowledgements. For each supplied acknowledgement the maintainer maps it
to the derived current stripe, fetches the frame at its acknowledged topic/revision,
checks its hash, decrypts it under the public profile keys/AAD, and requires it to
contain the exact submitted signed announcement. A missing claimed frame is `BUSY`
plus a path-local availability alert. Zero acknowledgements is a valid direct
discovery submission; one acknowledgement proves one Inbox copy; additional
independent qualified acknowledgements change only propagation/durability claims.
Thus the direct route and public Inboxes are complementary paths and neither is
content authority. The correlated result is signed
over domain `peerit.hiverelay.maintainer-submit-result.v1`. `RECEIPT` requires one
exact valid embedded receipt, zero decision/retry fields; `FIXED_REJECTION`
requires no receipt, one registry-fixed decision code, and zero retry; `BUSY`
requires no receipt/decision and `1 <= retryAfterMillis <= 60000`. No transport response is
content authority. This app protocol never runs inside HiveRelay, and a browser
without it can later obtain the same public evidence from observation logs.

Any canonical, correctly rooted, correctly ID-bound, publisher-signed
announcement is appended and receipted before its Peerit validator decision;
`FIXED_REJECTION` is limited to pinned pre-observation protocol errors such as
malformed canonical bytes, wrong root/generation, ID mismatch, nonce misuse, or an
over-limit request. A maintainer cannot turn an application-level rejection into
an unlogged direct response: the later proposal carries that fixed validator
decision against the receipted observation.

For each maintainer, `(rootRecordId, generation, signedAnnouncementId)` is a
durable idempotence key. Re-delivery of byte-identical announcement bytes returns
the original receipt and never appends a second observation; the same ID with
different bytes is a fixed rejection. A repeated request nonce with the identical
complete request returns the identical result, while nonce reuse for different
request bytes is a fixed rejection. The announcement-ID-to-receipt record survives
restart for at least the 365-day signed discovery-history window. After nonce
expiry the durable announcement record still prevents a second observation.
After any accepted direct submission,
the nonce-to-request/result record survives restart for 24 hours; an ambiguous
response-loss retry reuses it, while an explicit BUSY retry after
`retryAfterMillis` uses a fresh nonce. This same rule collapses duplicate physical
Inbox deliveries to one observation per maintainer;
observations of the same announcement by different maintainers remain distinct
quorum evidence.

Three distinct maintainer receipts are an auditable `threshold-received` state,
not yet a content acknowledgement. An announcement
with three receipts before a proposal cutoff MUST appear as accepted or with a
fixed validator rejection reason in the next finalized proposal whose cutoff is
later; omission for two finalized checkpoints is signed censorship/failure evidence
and disables the healthy discovery claim.

For `proposalSlot = floor(checkpointCreatedUnixMillis / 60000)`, the exact cutoff
is `(proposalSlot - 2) * 60000`; slots 0 and 1 are invalid. The proposer order is a
cyclic rotation of sorted maintainer keys starting at
`first_u64be(BLAKE2b-256("peerit.hiverelay.discovery-leader.v1" || rootRecordId ||
generation(u64) || proposalSlot(u64))) mod 4`. Rank 0 has the first 15-second phase,
then ranks 1..3 in order. A maintainer signs only the first fully valid proposal
from the lowest eligible rank it observed after that rank's phase begins.

A proposal contains three or four independently verified heads and MUST contain a
signer's own head. Observation time is nondecreasing with sequence, equals the
receipt time, is no later than `checkpointCreatedUnixMillis + 120000`, and never
precedes the previous observation. A head's sequence/hash equals the verified terminal Core
observation, `observedThroughUnixMillis` is at least that observation time and the
proposal cutoff, and is no later than `checkpointCreatedUnixMillis + 120000`.
Thus a head can attest an idle interval but cannot hide a later-sequence backdated
observation. A head below the cutoff is ineligible.

Starting from the accepted prior snapshot, every signer replays all canonical
observations after those heads' prior accepted floors and at or before the cutoff,
ordered by `(receivedUnixMillis, maintainerKey, observationSequence,
observationHash)`. The first occurrence of a `signedAnnouncementId` in that order
receives the pinned validator's fixed accepted/reason-code decision. Every later
occurrence receives the registry-fixed `DUPLICATE` rejection and no resulting ID;
accepted/rejected counts and the decision tree include every occurrence. Decision
leaves hash `(observationHash, decisionCode, ordered resulting recordIds)`
under domain `peerit.hiverelay.discovery-observation-decision.v1`; the ordinary
odd-node-promoting Merkle root and counts equal the proposal, with the fixed empty
root above when both counts are zero. Accepted IDs union
into membership; repair evidence deterministically advances availability; recent
IDs enter the proposal slot's five-minute bucket. Replaying must reproduce the
candidate snapshot commitment byte-for-byte.

The proposer signs domain `peerit.hiverelay.discovery-proposal.v1`; its complete
proposal is stored as three generic Cells and `proposalHash` uses the formula
above. Other maintainers fetch the exact proposal/log heads/nodes, replay, durably
commit sign-once state, and add their snapshot/checkpoint signatures. The final
checkpoint's three proposal caps reproduce that proposal. Same-commitment
certificate variants are equivalent; a different-commitment quorum is the fork
failure described below. Process crash at every log append, proposal store,
signature collection, snapshot store, and checkpoint publication boundary is a
mandatory deterministic replay test.

For each proposal, the three candidate-snapshot targets and three next-checkpoint
targets are preallocated by three different maintainers named in its heads; no
maintainer owns all target management keys. Signatures travel only over the pinned
Noise sessions, and each surviving target owner can assemble the same canonical
certificate and write its own Cell. Loss of one owner may temporarily leave one
target unavailable but cannot prevent the other two from publishing the threshold
certificate; the next proposal allocates a replacement third-group target before
restoring the resilient label. Target-owner/cap assignments and encrypted local
management-key custody are part of the crash evidence, never a relay field.

This plane is an explicit app-level discovery authority. Append-only membership
proves no later removal after inclusion; it cannot prove that three maintainers did
not collectively refuse to log a new post. Threshold receipts make omission after
receipt attributable, and four administrations reduce unilateral censorship, but
Peerit MUST NOT call new-content discovery censorship-resistant. Content remains
author-signed and independently shareable even when discovery is degraded.

Discovery is not permitted to depend on an unbounded OPEN_APPEND scan. The
bootstrap contains three replicas of a mandatory `DiscoveryCheckpointV1` chain
and its current persistent-indexed `DiscoverySnapshotV1`. Maintainers publish a linked
checkpoint heartbeat at least every `checkpointCadenceSeconds=60`; the chain is
stale after `checkpointMaxLagSeconds=300`. `createdUnixMillis` strictly increases
along the checkpoint chain. To count as fresh it is no more than 300,000 ms behind
the client's wall clock and no more than 120,000 ms ahead; an unsafe/backward clock
or wider skew keeps verified reads available but blocks only that source's
fresh-discovery claim. A checkpoint points to either the same
fully verified snapshot as its predecessor when there is no change, or the next
complete, addition-linked snapshot when the frontier advances. It supplies three
preallocated read caps for the next checkpoint, so a browser can follow the
generic Cell chain without learning a new locator from Inbox. Native clients may
mirror the same logical checkpoint through Core as an optimization, never a
different authority.

An install ranks each checkpoint's three bindings—each in a different witnessed
operator group/store ID, with distinct shared-journal IDs among profile-2
bindings—with its local
`K_poll`, reads one primary, and consults an alternate only on failure or every
`crossAuditIntervalRefreshes`; it does not triple every poll. It fetches and verifies
the recent bucket/additions trie first and reuses verified content-addressed index
nodes by hash. Poll timers have per-install random phase and ±20% jitter,
use exponential backoff capped at 60 seconds, and never synchronize to a wall-clock
minute. A no-change heartbeat increments only `checkpointSequence`, links the
previous checkpoint, and carries the exact same snapshot hash/sequence/frontier
root/availability root; it cannot rewrite membership or availability. These rules
bound the ordinary request/byte fanout and avoid a 10,000-client checkpoint herd.

After every accepted advance the client atomically persists a source-scoped
`DiscoveryFloorV1` and includes it in encrypted recovery export.
The floor stores certificate-independent checkpoint/snapshot commitments, not
`profileRecordId` values whose bytes vary with an equivalent 3-of-4 signature
subset. Within one root generation, domination requires a nondecreasing linked
checkpoint/snapshot sequence; equal sequences require equal commitments, roots,
timestamp, and recent-bucket tuple. Lease time is freshness only and never raises
this floor. A lower generation is rollback within that source; a higher generation
may reset a sequence only through the recovery-merge rule below. No cache reset,
service-worker rollback, lower bootstrap, or restored device bypasses that
source-specific partial order. A fresh install may start from any authenticated
source and applies the same absolute-age/skew test; merely observing an old tail
for five minutes cannot make it fresh. Floors from different discovery roots are
not globally ordered and are unioned only after validating the content they name.

At least `discoveryMaintainerThreshold=3` of the root's exactly four distinct
authorized maintainer keys sign each checkpoint/snapshot. The root contains exactly four keys
mapped one-to-one by the current registry to four live witnessed operator groups, so loss of any
one maintainer does not halt the threshold. Maintainers are app-side clients, not HiveRelay
plugins; they decrypt/validate public Peerit records and cannot make an invalid
record valid, select a fork winner, rewrite authority/capability, or lower a
witnessed floor. Four target maintainers continuously challenge the three
checkpoint replicas. Losing threshold makes discovery visibly stale and blocks a
release claim; it does not transfer authority to a relay.

Each maintainer durably records `(rootRecordId, generation, recordType, sequence,
commitment)` before signing and MUST NOT sign two different commitments at the
same tuple. Any two 3-of-4 quorums intersect in two keys, so under the explicit
at-most-one-Byzantine-maintainer assumption an accepted same-sequence fork is
impossible while one offline maintainer is tolerated. A detected fork proves that
assumption or key custody failed: clients retain both branches and stop advancement
of that discovery source. Local authoring, relay delivery, direct shares, and
independent discovery roots continue. Recovery requires a higher-generation
`RootRotateV1` whose
nonzero `discoveryRecoveryMergeHash` and exactly three read caps reconstruct one
`DiscoveryRecoveryMergeV1`; ordinary/continuing rotation has the field absent and
zero caps. Every parent floor names `previousRootRecordId` and
`previousGeneration`; parents use the profile's complete-element canonical order
and no two may have the same `(checkpointSequence, checkpointCommitment,
snapshotSequence, snapshotCommitment)` tuple. `nextGeneration` is exactly
`previousGeneration + 1`, and the merge's root IDs/generations equal its enclosing
rotation. The merge names the client's prior floor and every other valid detected
fork parent. Every parent's three checkpoint caps reconstruct its certified
checkpoint commitment and every snapshot cap reconstructs the certified snapshot
commitment and roots in that floor. More than 16 valid parents make that merge
unsupported until a new profile raises the bound; the client retains the parents
and last valid source floor, and no parent may be silently dropped.
`createdUnixMillis` is evidence only and never selects a parent or
winner. Full auditors traverse the parent and merged trees: merged
membership is the exact set union; availability selects only a uniquely highest
revision whose previous-hash chain descends every parent entry for that record;
no such unique descendant is a blocking conflict. The rebuilt hot recent chain
ends at `max(parent.floor.recentBucketNumber)`, covers every one of the 2,016
retained consecutive bucket numbers or every existing bucket back to genesis when
fewer exist, and contains the union of valid parent inclusions in that window. If
one record occurs in multiple parent buckets, its
lowest bucket number wins; each record then occurs exactly once, and empty buckets
use the canonical empty root. Rebuilding in `(bucketNumber, recordId)` order must
reproduce `mergedRecentBucketHash`. The merged snapshot fields/caps equal the
merge record and the new root-signed bootstrap. The merged relay-probe set takes every
still-fresh valid parent entry, groups by `(relayPublicKey,storeId)`, chooses the
highest `probedAtLeaseEpoch` and then lowest complete evidence hash on a tie,
orders survivors by descending probe epoch then ascending complete evidence bytes,
takes exactly the first `min(16,count)`, re-sorts that selected subset by complete
canonical evidence bytes for array encoding, and is newly 3-of-4 signed under the next root;
its complete hash equals `mergedRelayProbeEvidenceSetHash` and the merged snapshot.
Excluded targets simply lack configured-resilience qualification until a later
set probes them; this does not alter body availability or authoring for other
targets. Expired/shared probe evidence never changes membership or
availability-tree roots. Vectors merge 16 parents with 256 distinct fresh targets
and require the same bounded 16 survivors in every runtime.

Only after that traversal and the old recovery/new-root signatures validate may a
higher-generation sequence-zero floor dominate the parents within this discovery
source. A missing parent, unproved union, availability conflict, or merge hash/cap
mismatch rejects the merged source state; release time, a 2-of-4 subset, or a
relay majority never chooses a branch or affects content authority.

The immutable membership frontier and mutable availability index are separate
persistent Merkle radix trees keyed by the 32-byte record ID. A branch consumes
`depth` key bytes, then a longest-common `compressedPrefix`, then one unique sorted
`edgeByte`; `depth + byteLength(compressedPrefix) < 32`. Every descendant key has
that exact path. Counts and first/last keys equal the child union, child ranges are
strictly disjoint, and a child hash/cap tuple fetches the exact tagged node.
Membership leaves contain at most 256 IDs; availability leaves contain at most 128
entries. A leaf overflow splits at the first distinguishing key byte. Insertion or
availability update copies only the root-to-leaf path (at most 33 nodes), shares
all untouched content-addressed nodes, and never repacks unrelated ranges. Every
root and child node has exactly three read caps on three witnessed operator groups
and three distinct store IDs; profile-2 caps also have distinct shared-journal IDs.

Proof nodes sort by raw hash, reject duplicate hashes, hash to their declared
tagged bytes, and total exactly `totalNodeBytes` before the 16-MiB allocation cap.
An exact-key proof contains the root-to-leaf path proving presence or the unique
branch/leaf boundary proving absence. A range proof covers only the authenticated
prefix beginning at `lowerInclusive`, not every child in an unbounded query. It
contains every child intersecting the returned prefix, the immediate lower
boundary, and either the query's upper boundary or the path proving that
`continuationKey` is the smallest remaining in-query key. `returnedCount` is the
number of derived results and, unless the range is exhausted, is exactly `limit`;
an absent continuation proves there is no remaining in-range key. A present
continuation requires `returnedCount > 0`, is strictly greater than the last
returned key, is below `upperExclusive` when present, and is the next query's
`lowerInclusive`; it can never repeat or move backward. If fewer than `limit`
keys remain, all of them are returned and continuation is absent. Exact-key proofs
have count zero/one and no continuation. If the complete page required by the
requested limit plus its boundaries cannot fit the 1,024-node/16-MiB caps, the
operation returns explicit `PROOF_TOO_LARGE` and the client must lower the limit
or refine the range; it never returns a smaller or unauthenticated partial page.
Failure even at limit one means that query is unsupported under profile v1.
Missing a
required prefix/boundary child, an
inconsistent depth/prefix/range/count, an unreachable extra node, or a root-hash
mismatch fails. Positive, negative, first/last, prefix split, 255/256/257-leaf,
continuation, exhausted-short-page, forbidden zero/nonmaximal page, repeated/
backward continuation, whole-keyspace-with-limit, limit-refinement after
`PROOF_TOO_LARGE`, availability-update, and 16-MiB boundary vectors are mandatory.

Sequence zero defines its whole nonempty membership tree as the additions tree.
Every later snapshot links the exact prior roots and applies the additions tree as
a set union; membership deletion, replacement, or duplicate insertion is invalid.
A zero-addition snapshot has `addedCount=0` and absent added root/caps and may exist
only to advance availability or finalize the next recent bucket. The availability
tree covers exactly the membership key set. An entry's revision zero alone omits
`previousAvailabilityHash`; an update
keeps the record ID/tag, increments revision by one, and hash-links the previous
complete entry while replacing current caps. Every live cap fetches bytes
reproducing the tag/ID and maps to a distinct witnessed operator group/store ID;
profile-2 caps with equal shared-journal IDs collapse. BODY_RESILIENT requires three
recently read caps including at least one profile-2 cap; DEGRADED has one or two
and UNAVAILABLE zero; other
status/count combinations fail. Zero records loss of availability, never content
deletion. Same-revision entry or root forks remain conflicts. Repair can therefore
supersede a dead locator without mutating history. `frontierCount` is capped at
16,777,216 in v1; crossing it requires a new profile, never truncation.

That entry-local status is body availability only. The UI/release may elevate it
to configured RESILIENT only when the snapshot/checkpoint/floor set hash and three
read caps reconstruct one current valid `RelayProbeEvidenceSetV1` containing the
required charged profile-2 target entry. Set expiry downgrades the configured
label without rewriting millions of availability leaves.

Recent feed discovery is a separate five-minute inclusion-bucket chain, not a
scan of ID order. Maintainers assign inclusion time when an observation enters the
threshold proposal: `bucketNumber=floor(proposalSlot/5)`, independent of author or
observation timestamps. Revision zero has no previous-version hash/caps; every
later revision increments by one, hashes the accepted prior version, and carries
exactly three prior-version caps. Only the numerically current bucket may gain a
revision, and that revision adds the current proposal's newly accepted IDs. Once a
successor bucket links it, its final revision is immutable. The genesis bucket
alone has no previous-bucket hash/caps; every later bucket carries exactly three
caps for the immediately preceding finalized bucket.

Exactly one bucket-chain entry exists for every consecutive number after genesis,
including quiet intervals; every bucket below the current one is finalized and
the current one may have hash-linked revisions. `recordCount=0` requires
`recordRootHash=emptyRecentBucketRecordRoot` and zero root caps; a positive count
requires a membership-trie root and exactly three caps on distinct witnessed
operator groups/store IDs, with distinct shared-journal IDs among profile-2 caps.
A new bucket
is exactly previous number +1 and links that finalized bucket with three caps. At
the first checkpoint in a new five-minute number, maintainers finalize the prior
current revision and create the new current bucket; after an outage they first
materialize every skipped intermediate number as an empty bucket. This creates a
zero-addition snapshot even with no content or availability change.

Genesis, same-current-bucket revision, successor-freezes-predecessor, quiet
rollover, multi-bucket outage fill, post-finalization mutation, missing/duplicate
number, wrong empty-root/cap shape, and bad previous/skip-cap vectors are
mandatory.

Skip distances are every derivable power of two `1,2,4,...,2048` in this contiguous
chain, derived from the prior bucket's links; `(distanceBuckets, bucketNumber)`
sorts and the target number equals `currentBucketNumber - distanceBuckets`.
Invented, missing, duplicate, or wrong-cap links fail. Snapshot time and
`recentBucketNumber=floor(createdUnixMillis/300000)` agree. The current 2,016
buckets are the bounded hot-feed window; older buckets remain reachable through
the 365-day signed snapshot history but are not fetched during ordinary hot-feed
startup. The signed snapshot points to the current bucket on three groups and
retainers renew snapshot/bucket history for 365 days.

A fresh client starts from each explicitly trusted/recommended root-signed
bootstrap (not necessarily sequence zero), verifies that source's threshold
certificate, fetches the current recent bucket and only enough authenticated trie ranges/records to reach
256 candidates or 16 MiB, then validates every Peerit record itself. A returning
client requires the anchor/tip to dominate its `DiscoveryFloorV1` and follows
three-cap previous-snapshot links/deltas; it never resets to a lower root. Full
maintainers and release auditors traverse both complete trees and prove exact
membership/availability equality. Ordinary clients verify requested range and
inclusion proofs plus the signed roots, rather than downloading 16 million IDs at
startup. This is an explicit trust in the discovery quorum for inclusion and
index completeness, not content validity or censorship resistance.

`encodingCommitment` is exact:

```text
encodingCommitment = BLAKE2b-256(
  "peerit.hiverelay.encoding.v1" || representationTag(u8) ||
  logicalHash || innerCodec(u16) ||
  totalInnerLength(u64) || chunkCount(u32) ||
  ordered(BLAKE2b-256(exact unpadded chunk bytes)) || paddingClass(u8)
)
```

`representationTag` is 1 for Cell and 2 for Core. Cell replicas independently
randomize their encrypted wrappers, keys, and slots but commit to the same exact
inner chunks; Core commits to the `CoreObjectChunkV1` sequence above. Unknown
representation/padding tags fail closed.

There are at most 4096 chunks. A `ManifestRecordV1` itself is at most 1 MiB;
snapshots never embed the bulk frontier/availability/feed and instead reference
the bounded persistent index nodes defined above. Any other larger logical object
uses the exact Core chunk sequence/commitment, not an undefined ad hoc manifest.
Create/renew/drop private keys stay in the allocator's encrypted recovery state
and never appear in these public reader records.

### 5.3 Deterministic legacy cutoff, census, and archive

`MigrationGenesisV1` is static release-authenticated migration provenance. It
attests an observed immutable legacy census; it cannot
edit an original signed row, impersonate an offline author, advance that author's
future sequence, override a later author event, or control blind delivery.

The cutoff is membership-by-signed-head, never membership-by an untrusted record
timestamp. The official migration operator first fixes the exact legacy source
set under `LIVE_DUAL_READ`, disables every legacy writer/endpoint it controls,
waits a fixed 24-hour legacy-only drain, and reads every source named by that
release. Blind local authoring and blind delivery continue throughout; the cutoff
does not create a network-wide quiet period. The operator then signs:

```text
LegacySourceV1 {
  sourceRelayIdentity:  32 bytes
  sourceDescriptorHash: 32 bytes
  legacyServiceId:      canonical bytes[1..128]
}

LegacySourceSetV1 {
  version:              u8 = 1
  sources:              sorted array[1..64] of LegacySourceV1
}

legacySourceSetHash = BLAKE2b-256(
  "peerit.hiverelay.legacy-source-set-hash.v1" ||
  len64(canonicalSourceSet) || canonicalSourceSet
)

LegacySourceCutoffV1 {
  version:                  u8 = 1
  sourceRelayIdentity:      32 bytes
  sourceDescriptorHash:     32 bytes
  legacyServiceId:          canonical bytes[1..128]
  terminalHeadBytes:        optional exact signed bytes[1..4096]
  terminalHeadHash:         optional 32 bytes
  snapshotStatus:           u8 // 1 complete, 2 unavailable, 3 invalid-head
}

LegacyCutoffV1 {
  version:                  u8 = 1
  legacyWriteCutoffReleaseSequence: u64
  cutoffPendingPinHash:     32 bytes
  legacySourceSetHash:      32 bytes
  drainStartedUnixMillis:   u64
  drainEndedUnixMillis:     u64 // exactly start + 86,400,000
  sources:                  sorted array[1..64] of LegacySourceCutoffV1
  releaseAuthoritySequence: u64
  releaseAuthorityKeyId:    32 bytes
  signature:                64 bytes
}

LegacyArchiveDistributionV1 {
  version:                  u8 = 1
  legacyArchiveArtifactHash:32 bytes
  legacyArchiveIndexHash:   32 bytes
  copies:                   sorted array[2..16] of {
                              copyKind: u8,
                              operatorGroupId: 32 bytes,
                              failureDomainCommitment: 32 bytes,
                              locator: canonical UTF-8 bytes[1..512],
                              artifactHash: 32 bytes,
                              indexHash: 32 bytes
                            }
  releaseAuthoritySequence: u64
  releaseAuthorityKeyId:    32 bytes
  releaseSignature:         64 bytes
}

LegacyProvenanceV1 {
  sourceRelayIdentity:       32 bytes
  sourceDescriptorHash:      32 bytes
  legacyServiceId:           canonical bytes[1..128]
  terminalHeadHash:          32 bytes
  sourceRecordProofBytes:    canonical bytes[1..65536]
}

LegacyValidRecordEntryV1 {
  version:                   u8 = 1
  category:                  u8 // 1 RETAINED, 2 CONFLICT
  logicalRecordId:           32 bytes
  exactOriginalSignedBytesHash:32 bytes
  exactOriginalSignedBytes:  canonical legacy bytes[1..1048576]
  provenances:               sorted array[1..64] of LegacyProvenanceV1
  validatorResultCode:       u16 = 0 (VALID)
  newReplicaBindings:        sorted array[0..16] of tagged ReplicaBindingV1
}

LegacyInvalidRecordEntryV1 {
  version:                   u8 = 1
  category:                  u8 = 3 (INVALID)
  evidenceId:                32 bytes
  claimedLogicalRecordId:    optional 32 bytes
  exactOriginalSignedBytesHash:32 bytes
  exactOriginalSignedBytes:  canonical legacy bytes[1..1048576]
  provenances:               sorted array[1..64] of LegacyProvenanceV1
  validatorReasonCode:       LegacyValidatorReasonCodeV1
}

LegacyMissingRangeEntryV1 {
  version:                   u8 = 1
  category:                  u8 = 4 (MISSING)
  evidenceId:                32 bytes
  sourceRelayIdentity:       32 bytes
  sourceDescriptorHash:      32 bytes
  legacyServiceId:           canonical bytes[1..128]
  terminalHeadHash:          optional 32 bytes
  rangeStartExclusive:       canonical bytes[0..512]
  rangeEndInclusive:         canonical bytes[0..512]
  expectedRecordCount:       optional u64
  missingReasonCode:         LegacyMissingReasonCodeV1
  sourceRangeEvidenceBytes:  canonical bytes[1..65536]
}

LegacyArchiveEntryV1 = tagged union {
  1: LegacyValidRecordEntryV1 with category 1
  2: LegacyValidRecordEntryV1 with category 2
  3: LegacyInvalidRecordEntryV1
  4: LegacyMissingRangeEntryV1
}

LegacyArchiveIndexEntryV1 {
  category:                  u8
  primarySortId:             32 bytes
  secondarySortId:           32 bytes
  entryHash:                 32 bytes
  archiveOffset:             u64
  archiveLength:             u32
}

LegacyArchiveIndexV1 {
  version:                   u8 = 1
  legacyArchiveArtifactHash: 32 bytes
  legacyCutoffHash:          32 bytes
  retainedRecordCount:       u64
  conflictRecordCount:       u64
  invalidRecordCount:        u64
  missingRangeCount:         u64
  retainedCategoryRoot:      32 bytes
  conflictCategoryRoot:      32 bytes
  invalidCategoryRoot:       32 bytes
  missingCategoryRoot:       32 bytes
  legacyCensusRoot:          32 bytes
  originalRecordsLogicalHash:32 bytes
  entries:                   ordered array[1..100000] of
                             LegacyArchiveIndexEntryV1
}

PeeritLegacyArchiveV1 {
  version:                   u8 = 1
  cutoffBytes:               canonical complete signed
                             LegacyCutoffV1 bytes[1..1048576]
  entries:                   ordered array[1..100000] of
                             tagged LegacyArchiveEntryV1
}

LegacyArchiveBundleV1 {
  version:                   u8 = 1
  archiveBytes:              canonical PeeritLegacyArchiveV1 bytes[1..241172480]
  indexBytes:                canonical complete LegacyArchiveIndexV1
                             bytes[1..8388608]
  distributionBytes:         canonical complete signed
                             LegacyArchiveDistributionV1 bytes[1..1048576]
}

LegacyRetirementEvidenceV1 {
  version:                         u8 = 1
  previousPinHash:                 32 bytes
  targetReleaseSequence:           u64
  legacyCutoffHash:                32 bytes
  migrationGenesisRecordId:        32 bytes
  retirementWindowStartedUnixMillis:u64
  retirementWindowEndedUnixMillis: u64
  retainedCensusRoot:              32 bytes
  retainedRecordCount:             u64
  unresolvedValidLegacyOnlyCount:  u64 = 0
  acknowledgedWriteLossCount:      u64 = 0
  forbiddenLegacyWriteCount:       u64 = 0
  externalCopyRestoreEvidenceHashes:sorted array[2..2] of 32 bytes
  relayRestoreEvidenceHashes:      sorted array[3..16] of 32 bytes
  freshUserExportEvidenceHash:     32 bytes
  reconstructionRehearsalHashes:   sorted array[2..8] of 32 bytes
  precedingDualReadPinHashes:      ordered array[2..2] of 32 bytes
  evidenceBundleHash:              32 bytes
  releaseAuthoritySequence:        u64
  releaseAuthorityKeyId:           32 bytes
  signature:                       64 bytes
}
```

LegacyValidatorReasonCodeV1 is a closed `u16` registry:

| ID | Name |
| ---: | --- |
| 1 | `MALFORMED_CANONICAL_BYTES` |
| 2 | `UNKNOWN_CODEC_OR_TAG` |
| 3 | `SIGNATURE_INVALID` |
| 4 | `AUTHORITY_CHAIN_INVALID` |
| 5 | `HASH_OR_ID_MISMATCH` |
| 6 | `CAUSAL_OR_SEQUENCE_INVALID` |
| 7 | `POLICY_LIMIT_EXCEEDED` |

LegacyMissingReasonCodeV1 is a separate closed `u16` registry:

| ID | Name |
| ---: | --- |
| 1 | `SOURCE_UNAVAILABLE` |
| 2 | `TERMINAL_HEAD_UNAVAILABLE` |
| 3 | `RANGE_READ_FAILED` |
| 4 | `RANGE_PROOF_INVALID` |
| 5 | `SOURCE_DECLARED_GAP` |

Zero, an unlisted value, and using a code from the other registry fail closed.

```text
legacyCutoffHash = BLAKE2b-256(
  "peerit.hiverelay.legacy-cutoff-hash.v1" ||
  len64(canonicalCompleteSignedCutoff) || canonicalCompleteSignedCutoff
)

legacyArchiveDistributionHash = BLAKE2b-256(
  "peerit.hiverelay.legacy-archive-distribution-hash.v1" ||
  len64(canonicalCompleteSignedDistribution) ||
  canonicalCompleteSignedDistribution
)

legacyArchiveBundleLogicalHash = BLAKE2b-256(
  "peerit.hiverelay.legacy-archive-bundle.v1" ||
  len64(canonicalCompleteBundle) || canonicalCompleteBundle
)

legacyArchiveArtifactHash = BLAKE2b-256(
  "peerit.hiverelay.legacy-archive.v1" ||
  len64(canonicalPeeritLegacyArchiveBytes) ||
  canonicalPeeritLegacyArchiveBytes
)

legacyArchiveIndexHash = BLAKE2b-256(
  "peerit.hiverelay.legacy-archive-index.v1" ||
  len64(canonicalLegacyArchiveIndexBytes) ||
  canonicalLegacyArchiveIndexBytes
)

originalRecordsLogicalHash = BLAKE2b-256(
  "peerit.hiverelay.original-records.v1" ||
  ordered(
    logicalRecordId || len64(exactOriginalSignedBytes) ||
    exactOriginalSignedBytes
  )
)

legacyRetirementEvidenceHash = BLAKE2b-256(
  "peerit.legacy-retirement-evidence-hash.v1" ||
  len64(canonicalCompleteSignedRetirementEvidence) ||
  canonicalCompleteSignedRetirementEvidence
)

legacyArchiveEntryHash = BLAKE2b-256(
  "peerit.hiverelay.legacy-archive-entry.v1" || entryTag(u8) ||
  len64(canonicalTaggedEntry) || canonicalTaggedEntry
)

invalidEvidenceId = BLAKE2b-256(
  "peerit.hiverelay.legacy-invalid-evidence.v1" ||
  exactOriginalSignedBytesHash ||
  len64(canonicalProvenances) || canonicalProvenances
)

missingEvidenceId = BLAKE2b-256(
  "peerit.hiverelay.legacy-missing-evidence.v1" ||
  sourceRelayIdentity || sourceDescriptorHash ||
  len64(legacyServiceId) || legacyServiceId ||
  optional(terminalHeadHash) ||
  len64(rangeStartExclusive) || rangeStartExclusive ||
  len64(rangeEndInclusive) || rangeEndInclusive ||
  optional(expectedRecordCount) || missingReasonCode(u16) ||
  len64(sourceRangeEvidenceBytes) || sourceRangeEvidenceBytes
)
```

`cutoffPendingPinHash` equals the complete final `LIVE_DUAL_READ` pin hash;
`legacyWriteCutoffReleaseSequence`, `legacySourceSetHash`, release-authority
sequence, and release-authority key equal that pin. `drainStartedUnixMillis` is no
earlier than activation of that pin. Any interruption, observed controlled legacy
write, or source-set change invalidates the partial drain and restarts the complete
24-hour legacy-only census window under a new higher `LIVE_DUAL_READ` pin. The
producer next creates `MigrationGenesisV1` with that cutoff-pending pin,
source-set hash and cutoff hash plus the predetermined first `FROZEN_CUTOFF`
release sequence/key, stores and verifies it, builds any recommended bootstrap
that includes its record ID, and only then signs the `FROZEN_CUTOFF` pin. Thus
cutoff and genesis flow into the final migration pin without either object hashing
that target pin and without becoming write authority.

`LegacyRetirementEvidenceV1` uses signature domain
`peerit.legacy-retirement-evidence.v1`. It binds the previous dual-read pin and
predetermined target release sequence, never the target archive-only pin hash. The
two immediately preceding pin hashes are in newest-to-oldest order, are distinct,
and both name dual-read builds capable of importing every blind-only success before
their build time. Every count, root, restore, rehearsal, and window reproduces the
content-addressed evidence bundle and the exact section-9.3 criteria.

Sources sort by complete canonical bytes and have distinct `(sourceRelayIdentity,
legacyServiceId)` pairs. Status `complete` requires non-empty head bytes, their
matching hash, a valid legacy head signature, and a fully enumerated snapshot.
Status `unavailable` requires both head fields absent. Status `invalid-head`
requires both present and preserves the rejected bytes/hash as evidence. Any other
field combination fails cutoff validation.

`copyKind` is registry-fixed: 1 is a signed content-addressed Hyperdrive, 2 is an
immutable versioned object/archive service, and 3 is a published offline export
image. Copies sort by `(operatorGroupId, copyKind, locator)` and reject duplicate
tuples, non-NFC locators, credentials/query secrets, redirects to mutable content,
or a digest unequal to the genesis artifact/index. The release signature covers
domain `peerit.hiverelay.legacy-archive-distribution.v1` and every preceding field.
At least two copies have different witnessed operator groups, disjoint declared
failure-domain commitments, and different `copyKind` values; neither may be the
Peerit web origin, and both external operator-group IDs are disjoint from every
operator group carrying a HiveRelay archive-bundle replica. This is explicit
administrative evidence, not proof that two providers cannot collude.

The canonical bundle length is at most 251,658,240 bytes (4,096 Core chunks of
61,440 bytes); the three component bounds and the total bound are checked before
allocation. Its extracted bytes MUST reproduce the artifact, index, and complete
signed distribution hashes in genesis. Every external `locator` resolves the
exact complete `LegacyArchiveBundleV1` bytes, not a mutable landing page or an
unbound pair of files. Every `legacyArchiveBundleReplica` independently
reconstructs those same bundle bytes and logical hash. An archive exceeding the v1
bound requires a new pinned bundle profile before cutoff; it is never truncated.

`legacySourceSetHash` MUST equal the final `LIVE_DUAL_READ` pin named by
`cutoffPendingPinHash` and every later frozen/archive pin. The source set cannot be edited
during or after the drain. A complete source is
enumerated only through its terminal signed head/snapshot boundary. An unavailable
source remains an explicit missing category; another relay's copy may recover its
rows but cannot erase that source status. A later-discovered valid row outside all
terminal boundaries is an out-of-census conflict and remains visible; it does not
silently mutate the signed genesis.

The canonical archive is one binary `PeeritLegacyArchiveV1`, not a filesystem or
JSON dump. It contains the complete signed cutoff followed by the exact tagged
entries above. The four categories are fixed:

1. `retained`: one signature-valid canonical event per unambiguous logical ID;
2. `conflict`: two or more different signature-valid byte strings for one logical
   ID, all retained but none silently selected by the release authority;
3. `invalid`: reachable bytes rejected by the pinned legacy validator, retained
   as evidence but never imported as application truth; and
4. `missing`: a named source/head/range that could not be fetched or proven.

`retainedRecordCount` counts distinct retained logical IDs;
`invalidRecordCount` counts distinct exact invalid byte entries;
`conflictRecordCount` counts logical IDs with more than one valid byte string; and
`missingRangeCount` counts named unavailable/unproved source ranges. For invalid,
conflict, and missing categories the registry defines one canonical entry
encoding. Each root uses:

```text
categoryLeaf = BLAKE2b-256(
  "peerit.hiverelay.legacy-category-leaf.v1" || category(u8) ||
  len64(canonicalCategoryEntry) || canonicalCategoryEntry
)

categoryNode = BLAKE2b-256(
  "peerit.hiverelay.legacy-category-node.v1" || category(u8) || left || right
)

emptyCategoryRoot = BLAKE2b-256(
  "peerit.hiverelay.legacy-category-empty.v1" || category(u8)
)
```

Leaves sort by exact canonical entry bytes; odd nodes promote unchanged. Category
and count vectors cover empty, duplicate, odd/even, reason-code, provenance, and
reordering cases.

For valid entries, `logicalRecordId` is the exact stable ID returned by the pinned
legacy validator; the migration tool may not invent a replacement. An invalid
entry carries a claimed ID only when the pinned validator returned one before its
nonzero rejection; `evidenceId` is archive evidence, never an application ID. A
missing range likewise uses only its domain-separated `evidenceId`. Exact
duplicate valid bytes from several sources deduplicate while retaining every
unique provenance entry. Provenances sort by complete canonical bytes and reject
duplicate source/head/proof tuples. Category counts and roots reproduce from the
archive index. An empty category uses its domain-separated empty root; the
retained census itself MUST be non-empty.

Archive entries sort by `(category, primarySortId, secondarySortId, entryHash)`.
For categories 1 and 2, `primarySortId=logicalRecordId` and
`secondarySortId=exactOriginalSignedBytesHash`. For category 3,
`primarySortId=evidenceId` and `secondarySortId=exactOriginalSignedBytesHash`.
For category 4, `primarySortId=evidenceId` and `secondarySortId` is 32 zero bytes.
`entryHash` uses the exact tagged bytes and must be unique. Category 1 has exactly
one valid byte string per logical ID. Category 2 has at least two different valid
byte strings per logical ID and no category-1 entry for that ID. Category 3 has no
replica binding and cannot enter application truth. Category 4 has no original
record bytes and names one precise source/head/range failure.

The index has exactly one entry per archive entry in identical order. Offsets and
lengths select the complete canonical tagged entry bytes without overlap, gap, or
overflow; re-decoding those bytes reproduces every index tag/sort ID/hash. Its
archive artifact and cutoff hashes equal the archive and parsed cutoff. Counts
use the definitions above; category roots, census root, and original-records hash
recompute exactly. Both the 100,000-entry cap and encoded byte caps apply before
allocation. A larger census requires a new pinned archive version rather than an
oversized or partial index.

The retained census root is a canonical binary Merkle root over entries sorted by
raw 32-byte `logicalRecordId`:

```text
leaf = BLAKE2b-256(
  "peerit.hiverelay.census-leaf.v1" ||
  logicalRecordId || exactOriginalSignedBytesHash
)

node = BLAKE2b-256(
  "peerit.hiverelay.census-node.v1" || leftHash || rightHash
)
```

Duplicate IDs and an empty census fail closed. At each level adjacent hashes are
paired left-to-right; an unpaired final hash is promoted unchanged to the next
level. The single remaining hash is `legacyCensusRoot`. The profile vectors cover
one, odd, even, duplicate, empty, and reordered cases. Competing valid censuses
are surfaced as a migration conflict.

`legacyArchiveArtifactHash` hashes the exact downloadable archive bytes under
domain `peerit.hiverelay.legacy-archive.v1`; `legacyArchiveIndexHash` hashes its
canonical index under `peerit.hiverelay.legacy-archive-index.v1`.
`originalRecordsLogicalHash` hashes the ordered retained `(logicalRecordId,
exactOriginalSignedBytes)` stream: exactly category-1 entries in raw
`logicalRecordId` order, with no category-2/3/4 entry. Before signing genesis, the archive, index,
retained stream, and every referenced new replica MUST be fetched and reproduced
from all three selected witnessed operator groups/store IDs, with distinct shared-
journal IDs among profile-2 bindings. The signed distribution
manifest MUST also fetch and reproduce the same archive and index from both
independently administered external copies. The application exposes a one-click
and CLI-compatible user export containing the exact archive, index, distribution
manifest, genesis, and verification instructions. Every external copy and one
fresh user export undergo a clean-machine restore at least every 30 days; any
mismatch or unavailable copy blocks retirement and starts replacement. Archive
bytes remain content-addressed and publicly retrievable for at least 365 days
after legacy-read retirement.

---

## 6. Identity, recovery, and local writer safety

### 6.1 Buildable account and device keys

Protocol v1 uses a 32-byte CSPRNG `accountSeed` and Ed25519
`crypto_sign_seed_keypair` in every runtime. The public key is the Peerit author
identity. A 32-byte CSPRNG `deviceTransportSeed` is separate and creates only that
device's opaque transport Hypercore/signing key; it is never an application author
key. Cell create/renew/drop keys and Core block-encryption keys are independently
random per replica/core.

The ordinary browser stores `accountSeed` only in an authenticated encrypted
record. Its minimum portable implementation uses an origin-scoped non-extractable
AES-256-GCM `CryptoKey` generated by WebCrypto, a fresh 12-byte nonce per rewrite,
and AAD `peerit.local-account.v1 || accountPublicKey || recordRevision(u64)`.
The wrapping key is structured-cloned into IndexedDB. This protects an offline raw
database copy, not a compromised origin, XSS, or a live unlocked browser. Before
the first write, the UI states that clearing site data loses the account unless a
recovery bundle exists.

```text
LocalAccountRecordV1 {
  version:           u8 = 1
  recordRevision:    u64
  accountPublicKey:  32 bytes
  nonce:             12 bytes
  sealedAccountSeed: 48 bytes // 32-byte seed plus 16-byte GCM tag
}
```

On decrypt, deriving the Ed25519 public key from the seed must reproduce
`accountPublicKey`. The IndexedDB revision advances by CAS; a lower whole-record
revision than the locally witnessed floor fails rather than replacing the active
identity.

Pear/Bare/Node use the same vector-tested identity module and may wrap the local
record with an OS keychain. A future PearBrowser root-signer adapter is activated
only after its stable derivation/sign API, drive-key migration, backup semantics,
and cross-runtime vectors are implemented. The release MUST NOT claim that
PearBrowser owns or recovers a Peerit mnemonic merely because such an API is
desired.

### 6.2 Portable recovery cryptography

Recovery export is a canonical `PeeritRecoveryBundleV1`. It derives a 32-byte key
with Argon2id v1.3 using a random 16-byte salt, `m=65536 KiB`, `t=3`, `p=1`, and
then encrypts with XChaCha20-Poly1305-IETF using a random 24-byte nonce. The AAD is
the exact unencrypted header `(magic, version, KDF id/parameters, salt,
accountPublicKey, ciphertextLength)`. A different parameter set requires a new
registered bundle version.

```text
PeeritRecoveryBundleV1 {
  magic:             exact ASCII "PEERITRB" (8 bytes)
  version:           u8 = 1
  kdfId:             u8 = 1 (Argon2id v1.3)
  memoryKiB:         u32 = 65536
  iterations:        u32 = 3
  parallelism:       u8 = 1
  salt:              16 bytes
  accountPublicKey:  32 bytes
  ciphertextLength:  u64 in 1..16777216
  nonce:             24 bytes
  sealed:            exact bytes[ciphertextLength + 16; max=16777232]
}
```

Version 1 requires those KDF values exactly. The passphrase input is the UTF-8
encoding of its NFC-normalized Unicode scalar string; invalid Unicode, an empty
passphrase, over 1024 UTF-8 bytes, or normalization disagreement fails before the
KDF. The header fields through `ciphertextLength` are the AAD; nonce and sealed
bytes follow and are not duplicated in AAD.

The browser Argon2id/XChaCha implementation is bundled locally as a signed
JavaScript/WASM asset and covered by the release asset manifest and cross-runtime
vectors. Recovery must not fetch crypto code, parameters, or WASM from a CDN at
export/import time.

The encrypted payload contains the account seed, signed release pin/bootstrap,
public read capabilities, CELL management keys, Core read capabilities (but not
Core transport writer seeds), exact pending CELL intent material, published
logical IDs, receipts, witnessed release/root/author/head floors, and bounded
repair backlog. It also contains the exact `DiscoveryFloorV1` (including its
recent-bucket tuple), verified index-root cache, and authenticated Inbox/checkpoint
cursors. It contains
no plaintext seed/key, implicit authority reset,
admission issuer account, cookie, bearer token, or app-origin credential. Export
immediately decrypts and verifies a test copy before reporting success; import
derives the public key from the seed and requires exact equality with the header.
Recovery material is never sent to a relay.

Losing `accountSeed` creates a new author identity unless an existing Peerit
author-rotation rule verifies. Losing a storage management key requires a fresh
replica. Neither condition authorizes relay recovery.

### 6.3 Fresh-chain restore

Restore never clones a device writer. After authenticating the bundle, the client:

1. merges (never lowers) every locally witnessed author/Core floor, compatible
   release provenance, and each source-scoped discovery checkpoint/snapshot/
   frontier/availability/recent-bucket floor;
2. generates a fresh `deviceTransportSeed`, Core key, block-encryption key, CELL
   replica keys, device-chain ID, and sequence-zero transport frame;
3. prepares an unsigned canonical `DeviceChainStartV1` binding the new random
   device-chain ID and previous witnessed account floor but no old transport
   secret; after the local identity and exact record bytes are durably committed,
   it signs and journals that record without a network permission check;
4. treats old completed Core chains as read-only capabilities and publishes future
   events on the fresh chain; and
5. resumes an incomplete CELL intent only with its exact saved destination and
   bytes. An incomplete Core append without its old transport writer seed becomes
   a draft on the fresh chain with the same stable inner event ID and is published
   only after checking all old capabilities for that ID.

After restore, local authoring and reconciliation are immediately available. The
device preserves every pending intent, exact replica/request bytes, capability,
credential/spend binding, and ambiguity evidence. Offline state remains queued;
unavailable targets remain retryable; and a changed relay identity creates a new
independent attempt. Release channels, migration state, operator registration,
discovery health, and durability claims never select the device or veto its
author signatures.

```text
DeviceChainStartV1 {
  version:                    u8 = 1
  accountPublicKey:           32 bytes
  deviceChainId:              32 random bytes
  newTransportCorePublicKey:  32 bytes
  previousAuthorSequence:     u64
  previousAuthorRecordId:     optional 32 bytes
  createdLeaseEpoch:          u32
  signature:                  64 bytes
}
```

The signature domain is `peerit.hiverelay.device-chain-start.v1`. Two restored
devices legitimately create separate branches; Peerit's pinned deterministic
merge retains both. No last-writer-wins relay order is introduced.

### 6.4 Writer transaction and retry identity

Each local device uses its own generic opaque transport chain. A local transaction
never starts by asking a release server, registry, relay set, maintainer, discovery
root, or durability profile for permission. Under the cross-tab writer lock, the
client commits the identity before signing, stores the exact canonical event and
stable logical event ID, signs locally, atomically journals the signed intent, and
materializes it into the local view:

```text
DRAFT_LOCAL -> IDENTITY_COMMITTED -> EVENT_PREPARED
  -> INNER_EVENT_SIGNED -> INTENT_JOURNALED -> LOCAL_VISIBLE

per target:
TARGET_PLANNED -> TARGET_SENT
  -> ACKNOWLEDGED | PENDING_UNKNOWN | RETRYABLE_FAILURE
ACKNOWLEDGED -> READBACK_VERIFIED

propagation:
FIRST_REPLICA_VERIFIED -> AUTHOR_BIND_SIGNED -> DISCOVERY_QUEUED
  -> INBOX_ACKNOWLEDGED | INDEX_OBSERVED | DIRECTLY_SHARED
```

`IDENTITY_COMMITTED` and `INTENT_JOURNALED` are durable IndexedDB/Hyperbee CAS
boundaries. A crash after preparing or deterministically signing an event resumes
the same exact bytes and event ID. `LOCAL_VISIBLE` requires no network. With zero
usable relay targets the state is `QUEUED_NO_RELAY`; the client retains the intent
and continuously accepts newly discovered compatible targets. One independently
verified relay acknowledgement is sufficient to sign an `AuthorBindV1` and to
truthfully report that relay acknowledgement. Later replicas and readbacks improve
only durability labels.

Targets are independent. A compatible unregistered HiveRelay may store, return,
and announce opaque Peerit bytes. Operator registries and durability profiles
qualify independence, resilience, or privacy claims; they never grant service
permission. Network outage, timeout, BUSY, exhausted admission, discovery outage,
and an unavailable optional privacy route remain queued or retryable. A concrete
substrate/codec/cryptographic incompatibility rejects only that target/encoding;
it does not invalidate the signed event or block attempts through compatible
targets. Migration cutoff controls only the official legacy adapter and census.

Response loss resumes the same durable intent and its permitted reconciliation/
retry state; it does not imply automatic network resubmission. It never generates
a second logical post, comment, or vote. A generation-token CAS and Web
Locks/IndexedDB fallback serialize
one browser writer; separate devices retain forks for deterministic Peerit merge.
Drafts remain recoverable until the signed intent is safely advanced.

An exact request identity pins the relay public key, store ID, durability
continuity hash, selected endpoint/role, locator/topic/core, canonical inner
request, request commitment, spend/admission, management keys, expected revision,
and ciphertext/frame bytes. Before any permitted resend, the client verifies a
current nonce-bound health result and a complete linked descriptor chain whose
latest descriptor retains that key/store/continuity and operation readiness. Its
descriptor sequence and dynamic durability profile hash may have advanced
routinely; that alone neither changes the request nor creates a new replica. A
committed returned result is verified against and retains its own historical
commit-time descriptor sequence/hash/profile evidence.

Operator-continuity history or an unchanged URL alone is insufficient. A changed
relay key, store ID, or durability continuity hash—even under the same witnessed
operator root—is a new replica attempt with fresh locator/topic/core key,
management material, independently randomized ciphertext, request commitment,
admission/spend, and receipt slot; it never inherits old write authority. An
unlinked/unsafe refresh or lost selected endpoint pauses reconciliation rather than
silently becoming a retry. A transport that
permits automatic idempotent retry must return the original committed result or a
canonical terminal outcome.

OHTTP follows RFC 9458 section 6.5: an ambiguous connection loss is not evidence
that the gateway failed to process the request and MUST NOT trigger automatic
resubmission under a fresh HPKE context. Automatic fresh-context retry is allowed
only after a positive transport signal that the request was not processed, such
as a qualifying HTTP/2 `REFUSED_STREAM`, HTTP/3 `H3_REQUEST_REJECTED`, or GOAWAY
boundary. Otherwise the intent remains `pending-unknown`. The client reconciles
without mutation using the existing operation family—CELL GET/PROVE of the exact
slot/blob hash, INBOX READ for the exact frame hash, or CORE PROVE/head evidence.
If that cannot determine a management operation's outcome, only an explicit user
action may resubmit the exact same-destination inner request; switching destination
still creates new material as below.

Changing the storage relay, physical topic, Core sponsor, or gateway destination
is not a retry. It creates a new independently admitted attempt: Cell and Inbox
use fresh locator/topic binding, wrapper key, nonce/padding, frame hash, management
keys, request commitment, and spend. Core may retain its portable core key but
uses a new sponsor request/spend/acknowledgement. A client never sends one G3 Cell
ciphertext/slot or one Inbox frame to two storage relays. An outer ingress may be
reselected only when its signed route still reaches the same gateway/storage and
the selected privacy profile remains equally strong; otherwise the UI records a
new explicit path decision.

---

## 7. Lurker-first product contract

Peerit opens in lurker mode without creating an identity, requesting write
admission, or showing the site as broken/read-only. A user may read, search the
local materialized view, inspect privacy/path status, and dismiss onboarding.

When the user chooses post, comment, vote, community creation, moderation, or
profile editing:

1. Peerit keeps the draft locally and validates only the local codec, cryptography,
   author-chain continuity, and storage needed to create a safe signed intent;
2. after explicit confirmation it creates or restores an identity locally, shows
   the relevant backup/recovery state, and atomically persists the identity under
   authenticated encryption before any event signature can be produced;
3. it signs and durably journals the exact Peerit inner event, then immediately
   displays it in the local materialized view even when offline;
4. it selects zero or more compatible relays from direct configuration, peer
   exchange, independent directories, or recommended bootstraps; registration is
   not required and each target has independent admission/readiness state;
5. it encrypts independently randomized replicas and records each target as
   queued, sent, pending-unknown, acknowledged, or readback-verified;
6. after one verified replica it may create the author binding and attempt Inbox,
   direct-share, and independent-index propagation without making any one path a
   prerequisite; and
7. it shows `local-signed`, `queued-no-relay`, `relay-acknowledged(n)`,
   `recently-retrievable(n)`, the
   separate `externally-witnessed(n)` profile-2 count, or the configured resilience
   state without implying profile-1 same-identity/control-RPO0 recovery. Privacy
   labels describe the selected transport actually used. The app remains usable
   while bounded background delivery, discovery propagation, and repair continue.

Cancellation is exact by boundary. Before the encrypted identity commit it
preserves the draft and returns to a pristine lurker with no identity, token,
spend, signature, or relay attempt. After identity commit but before event signing
it preserves the locked encrypted identity and draft with no relay attempt. After
signing but before send/spend it persists one queued intent, logical event ID,
exact signed bytes, and replica plan; it may retain an unspent issued credential
but reports no relay acknowledgement. After any send or ambiguous transport
outcome it persists
`pending-unknown`, reconciles the exact request/spend/replica IDs, and never claims
that no write occurred or creates a replacement logical event.

“Lock to lurker” is nondestructive. Under the global cross-tab writer fence it
first stops new work and converts every in-flight/ambiguous operation into a
durable paused or pending-reconcile record before closing keys and writer sessions;
the encrypted identity and drafts remain. “Forget identity” is a separate
destructive action with explicit confirmation, recovery warning, the same global
fence, and an atomic tombstone. It is refused while any send is in flight or any
intent/replica/spend is pending or unknown unless exact reconciliation finishes or
a freshly verified recovery export contains the identity plus every pending
request, management capability, credential/spend binding, and replica plan needed
to resume without duplication. It is never an alias for lock, logout, banner
dismissal, or storage cleanup.

“Lurker” is a client state, not a relay read-only mode. Every compatible public
build MUST let an opted-in user author, sign, journal, and locally view posts,
comments, and votes offline. Only a local inability to protect the identity,
produce valid cryptography, preserve author continuity, or durably journal the
exact intent may block safe signing. Network, release, registry, profile-2,
maintainer, discovery, migration, and relay-count failures are shown on their own
axes and queue delivery; they never turn the whole product into read-only mode.

Browser conformance covers first post from a fresh lurker, cancellation at every
identity/sign/journal/admission/send boundary, reload and offline recovery,
locked and forgotten states, two-tab races, response loss, quorum outage and
recovery, and asserts zero duplicate logical event, identity, spend, or replica.

---

## 8. Runtime and privacy profiles

The same inner records and substrate ABI are used by every runtime:

| Runtime/profile | Required behavior | Honest ceiling |
| --- | --- | --- |
| Ordinary web OHTTP | Shared generic ingress resource, independently selected gateway/storage, RFC 9458 request/response, no credentials/referrer, fixed outer classes, section-6.5-gated same-destination retry/reconciliation, no direct fallback | Source separated from storage under ingress/storage non-collusion; ingress may still identify the page origin until its separate browser gate passes; not G4-I |
| Ordinary web direct | Multiple verified HTTPS storage roles, generic CORS, explicit visible choice and Origin negative evidence | Encrypted blind storage only; relay sees client IP, `peerit.site` Origin, locator/topic, and access pattern; not G2-W/G4-T/G4-I |
| Pear/Bare/Node split | Distinct client↔exit control Noise over the entry route plus a client↔storage blind Noise session carried through the separately admitted exit route; fixed padded records and distinct adjacent relay keys | Entry lacks storage/op; exit sees storage route but only storage-session ciphertext; storage lacks client/origin, under non-collusion and capture gates |
| Pear direct | Encrypted cells/cores over direct native transport | Fast blind storage; source and access metadata visible |
| Strict Tor native | `tor-native-full-v1`: onion descriptors and daemon endpoints through a native Tor sidecar, app/session isolation token, no clearnet DNS/TCP/UDP/DHT race or direct fallback | G2-W plus Tor source/path properties; requested locator, timing, size, and public content remain visible at their relevant roles; not G4-I/global-observer resistance |
| Strict Tor Browser | `tor-browser-full-v1`: onion descriptors/endpoints with the same no-clearnet/no-fallback rules plus storage-side Origin/referrer/Fetch-Metadata capture | Source-address separation only by default; Peerit app identity can remain browser-visible at storage, so G2-W and G4-T stay disabled unless the pinned opaque-origin cross-browser gate passes |

Profile 1 may satisfy the mixed availability threshold but has no external-journal
topology evidence. Any operation/path using it therefore excludes that replica
from topology-based G4-T or unlinkable-admission qualification even while counting
its verified blind-body availability; the displayed privacy ceiling is the weakest
selected path, never the strongest replica.

The release pins one profile before an operation. Exact response-loss retries obey
section 6.4 and keep the same destination. Replacing a failed storage operator—or
any changed relay key, store, continuity binding, or descriptor/profile tuple
under the same operator—is a new replica/attempt with fresh material, not a retry. Any weaker fallback is a
new explicit user/policy decision and records the actual path. Strict Tor and
strict split modes fail closed.

### 8.1 OHTTP rollout gate

`split-web-ohttp-v1` is not activated by the existence of an OHTTP URL. Before it
can be the ordinary-web default, the exact signed release MUST publish evidence
that:

1. at least two selectable ingress identities in distinct live witnessed operator
   groups and all three gateway/storage identities in three live witnessed
   operator groups with distinct store IDs, at least one profile-2 member, and no
   repeated profile-2 shared-journal ID advertise compatible, app-free OHTTP roles,
   signed key configs/routes, open admission, fresh role challenges, and the pinned
   substrate tuple;
2. for every selectable route, ingress and gateway/storage map to different live
   `operatorGroupId` values and also have different continuity roots, hosts, and
   declared failure domains; a route is disabled immediately if registry rotation
   merges those groups. This is recorded non-collusion evidence, not cryptographic
   proof that the administrators cannot collude;
3. Chromium, Firefox, and WebKit/iOS captures prove the storage role receives no
   browser IP, `Origin`, `Referer`, cookie, app path/credential, or direct fallback;
   ingress captures show only the expected IP/Origin, generic route, outer class,
   and OHTTP ciphertext;
4. fresh HPKE context, config overlap/rotation/rollback, replay, padding, bounded
   error encapsulation, abort, service-worker update, qualifying non-processing
   retry signals, ambiguous-loss pending/reconciliation, and explicit exact
   resubmission vectors pass without ever sending the failed inner operation
   directly;
5. at least 10,000 canary operations over seven consecutive days achieve 99.9%
   terminal success, with zero plaintext/app sentinel, forbidden fallback, hash
   substitution, or acknowledged-write-loss event; and
6. the UI names the ingress/storage non-collusion assumption and states that
   requested locators/topics and public read interest remain visible at storage.

Before that gate, ordinary web may use the accurately labeled
`direct-blind-v1` profile; it cannot display OHTTP/G2-W/G4-T claims. Once an OHTTP
operation begins, automatic direct fallback is forbidden. Balanced mode may offer
a separate user-confirmed direct operation after the OHTTP attempt terminates;
strict mode fails closed.

The stronger `opaque-ohttp-frame-v1` statement that the ingress cannot identify
Peerit requires the separate HiveRelay P20 cross-browser classifier gate. Base
OHTTP activation does not satisfy it: the ingress may still see
`Origin: https://peerit.site`. Neither base nor opaque-origin OHTTP satisfies
G4-I; physical Inbox topics and requested Cell/Core locators remain storage-
visible unless their traffic class separately passes P23.

---

## 9. Dual-read and migration contract

Migration is deliberately asymmetric and recorded by the static migration stage
in section 1:

- **reads:** the official adapter unions legacy OutboxLog with the blind substrate
  in `LIVE_DUAL_READ`/`FROZEN_CUTOFF`, then unions the blind substrate with the
  signed immutable archive in `ARCHIVE_ONLY`;
- **legacy writes:** controlled legacy mirroring is optional release telemetry in
  `LIVE_DUAL_READ` and is permanently disabled by `FROZEN_CUTOFF`; and
- **blind writes:** local authoring and compatible-relay delivery operate in every
  migration stage. Migration evidence never authorizes or pauses them.

### 9.1 Ordered rollout

1. Release and deploy the canonical HiveRelay blind substrate first. Its protocol,
   vectors, final blind product artifact, two non-Peerit fixtures, open admission,
   descriptors, and direct profile pass independently.
2. Publish `LIVE_DUAL_READ`; compare legacy and reconstructed blind views for at
   least seven consecutive days and 10,000 valid legacy records without changing
   application truth. Blind local-first publishing is already usable.
3. Exercise optional controlled legacy mirroring for at least 30 consecutive UTC
   days and 10,000 operations. Record at least 99.9% terminal delivery success,
   zero acknowledged blind loss, codec/signature disagreement, floor rollback, or
   hidden downgrade, plus two reconstruction rehearsals at least seven days apart.
   These measurements qualify the migration; they do not gate author signatures.
4. Fix the legacy source set, disable every legacy writer and writable endpoint
   under the operator's control, perform the exact uninterrupted 24-hour
   legacy-only census drain in section 5.3, and build the canonical cutoff/archive.
   Blind writes and local authoring continue during this window.
5. Create and verify `MigrationGenesisV1` through the cycle-free order in section
   5.3, then publish `FROZEN_CUTOFF`. Validate every retained original signature
   and create fresh randomized replicas.
6. Release distribution may expand through 1%, 10%, 50%, and 100% telemetry
   channels. Those channels are outside the canonical profile. Every channel runs
   post, comment, vote, edit/delete, restart, offline, multi-tab, zero-relay,
   unregistered-relay, and selected-relay-loss tests; no channel field enters a
   record or maintainer acceptance decision.
7. Keep legacy reads through the full compatibility window and enter
   `ARCHIVE_ONLY` only under section 9.3; an old client then receives a signed
   upgrade/archive response, never an empty feed.

Every migration-stage or legacy import/read-mode change has one
`PeeritMigrationTransitionEvidenceV1`. Its window and evidence qualify the
official migration artifact only and cannot borrow metrics from an earlier or
overlapping window. Incident advisories and recovery evidence are release
telemetry, not protocol states.

Peerit may accept losing already-unrecoverable early content at this pre-scale
stage, but it MUST measure and publish the exact migration census: discovered,
verified, imported, conflicting, invalid, and missing counts. “Accepted loss” is
not permission to silently omit a reachable valid signed record.

### 9.2 Identity and floor preservation

Migration preserves exact original signed bytes, author identity, target binding,
and author sequence. The release authority attests only the census and new
availability bindings. It never resigns or rewrites user content. Clients retain
the highest valid witnessed author/root/release floors across both read paths and
surface competing histories.

### 9.3 Exact legacy-retirement thresholds

Every controlled legacy writable endpoint is retired by the signed first
`FROZEN_CUTOFF` release after the full 30-day qualification. It is never re-enabled
after `legacyImportMode=1` activates. Legacy reads retire no earlier than 90 consecutive UTC
days after the cutoff and only when every one of these remains true for the final
30 consecutive days:

- 100% of the retained census and archive index reproduce from all three selected
  witnessed operator groups/store IDs, with distinct shared-journal IDs among
  profile-2 bindings, plus both external archive systems; the last clean-box
  restore is at most 30 days old, and a fresh user export verifies offline;
- zero reachable signature-valid legacy-only record is unresolved;
- zero category count/root differs from signed genesis, and every accepted loss
  remains explicitly in `missing`, `invalid`, or `conflict`;
- public blind writes maintain at least 99.9% terminal success with zero
  acknowledged loss or legacy write;
- two clean-box reconstruction-and-rollback rehearsals, at least seven days apart,
  reconstruct the same root/author floors and exact retained bytes; and
- the two immediately preceding signed app releases are dual-read capable and can
  import every blind-only success observed before their build time.

Any reset of a criterion restarts its stated consecutive window. Read retirement
does not delete the canonical archive, signed cutoff/genesis, prior bootstrap, or
client floor state. The archive retention minimum is 365 days after retirement;
longer retention is allowed. Loss of either independent external copy immediately
reopens the retirement gate until a distinct replacement copy and restore pass.
The archive-only pin hashes one complete signed `LegacyRetirementEvidenceV1`; its
previous pin, target release, cutoff/genesis, roots/counts, copies, export,
rehearsals, two immediately preceding dual-read pins, and evidence bundle reproduce
all criteria above. Its target release equals the historical
`legacyRetirementActivationReleaseSequence`; later archive-only pins retain that
activation sequence and evidence hash while proving descent from the activation
pin. The object binds no target pin hash.

### 9.4 Failure isolation and release rollback

Signature/codec disagreement or identity corruption blocks only production of an
invalid local event. Descriptor substitution, invalid admission atomicity,
acknowledged loss, reconstruction mismatch, or privacy-path downgrade quarantines
the affected target/path and retains the exact intent for another compatible
target. Migration-floor rollback rejects that migration source. None is a global
network write switch. Blind reads and already valid local content remain; live
legacy reads remain only while `legacyReadMode=0`, and archive-only releases never
reintroduce a live legacy dependency.

An official artifact rollback is a new, higher `releaseSequence` linked through
`previousPinHash`, never installation of an older pin. It may reuse a previously
good compatible app artifact and carry signed incident evidence, but it does not
issue or revoke authoring permission. The current and up to two previous readable
substrate tuples remain available subject to intrinsic compatibility. No rollback
may lower an author/Core head or a source-scoped discovery floor, resume a
controlled legacy writer after cutoff, or make a valid author event invalid. A
lower signed release presented by a CDN, relay, cache, or service worker is a
release-provenance rollback error; an installed compatible client may continue
offline authoring and queued delivery.

### 9.5 Atomic web/service-worker release

The signed `webAssetManifestHash` covers one canonical `WebAssetManifestV1` with
the release sequence and every same-origin runtime asset as `(canonical path,
byte length, BLAKE2b-256(bytes))`, sorted by raw UTF-8 path. HTML, JavaScript,
WASM, worker code, validator bundle, profile registry/vectors, and bootstrap are
entries; the detached profile pin and manifest itself are deliberately excluded
to avoid a hash cycle. No mutable unlisted runtime script is allowed. The client
first verifies the detached pin signature, then verifies the manifest hash named
by the pin, then verifies every listed asset and the separately pin-hashed
bootstrap.

```text
WebAssetManifestV1 {
  version:              u8 = 1
  releaseSequence:      u64
  appArtifactHash:      32 bytes
  recommendedBootstrapHashes: sorted array[0..16] of 32 bytes
  assets:               sorted array[1..4096] of {
                          path: canonical UTF-8 bytes[1..512],
                          byteLength: u64,
                          assetHash: 32 bytes
                        }
}
```

Paths begin with `/`, contain no query/fragment/backslash, empty component, `.`,
or `..`, and are NFC-normalized. Duplicate normalized paths fail. The manifest's
release/app/recommended-bootstrap fields equal the pin. For each same-origin
recommended bootstrap asset, the verifier computes both the listed raw asset hash
and the distinct domain-separated bootstrap hash from the same exact bytes and
requires both expected values. Zero recommended bootstraps is valid.

The service worker downloads into a cache named by
`(releaseSequence, webAssetManifestHash)`, verifies the release authority/pin and
every exact asset, migration-stage/evidence shape, cutoff/genesis/bootstrap
equality, and retirement evidence when present before marking the cache complete,
and only then atomically CASes one IndexedDB
`activeRelease` pointer during activation. Fetches are served wholly
from the old complete cache or wholly from the new complete cache. A partial
download, tab race, crash, hash error, signature error, or activation cancellation
keeps the old pointer and deletes only the incomplete staging cache. Old tabs may
finish local authoring and queued delivery on their complete compatible release;
they reload before using a substrate tuple or record codec they cannot validate.

The CAS transaction persists the accepted release-provenance floor and migration
metadata. It never installs an online authoring token, relay allowlist, or
discovery permission. Mixed worker/page/pin/assets, a missing recommended
bootstrap, service-worker offline restart, release-history gap, migration rollback,
and crash before/after each floor CAS are mandatory vectors. A provenance failure
keeps the last complete compatible release and queues network work whose exact
compatibility cannot yet be established; it does not erase drafts or signatures.

First installation remains rooted in HTTPS-origin delivery as stated in section
1.2. Thereafter, cache/CDN rollback, a sequence-one page with a sequence-two
worker, a new app with an old validator/pin, and every crash point around the CAS
are mandatory negative vectors.

---

## 10. Required conformance and release evidence

HiveRelay substrate completion is a prerequisite and is proven with at least two
unrelated non-Peerit fixture apps plus a late third opaque producer. Peerit does
not substitute for that app-agnostic gate.

Peerit release evidence must additionally prove:

1. exact profile spec/ABI/vector, validator artifact/vector, availability policy,
   app/asset, bootstrap, substrate tuple, release-authority chain, signature, and
   prior-pin hashes, closed migration-stage fields, and every required migration
   transition, cutoff/genesis, and retirement evidence hash reproduce with no
   placeholder or manually entered hash. Pin-history vectors cover sequence zero,
   every exact `+1` pin/checkpoint, same-sequence fork, skipped sequence, wrong
   predecessor/pin/authority, reordered or noncontiguous bundle, hash-path mismatch,
   a return after more than 256 and more than 3,650 daily pins, retained-reference
   extension, and missing history retaining the last compatible local-first
   runtime rather than creating a new trust root or global read-only state;
2. decoded canonical operation bodies over direct/OHTTP/Protomux/Tor contain no
   Peerit/author/type/community/target/graph field; direct-browser capture also
   records the expected client IP and `Origin: https://peerit.site`, while OHTTP
   storage capture proves those ambient fields absent and ingress capture records
   its stated residual Origin;
3. recursive relay WAL/checkpoint/blob-name/log/metric/diagnostic scans contain no
   Peerit sentinel while honest ciphertext remains decryptable by the client;
4. an operator with the public release/bootstrap can act as a reader and decrypt
   public announcements/content and map public topics/cores, permanently enforcing
   the G5 and Inbox-G3/G4-I negative claims;
5. fresh lurker boot creates no identity or write token, while opting in can create,
   sign, journal, and locally view a post/comment/vote entirely offline; zero relays
   yields one queued intent, and one compatible unregistered relay can acknowledge
   delivery without release, operator-registry, profile-2, or discovery approval;
6. post, comment, and vote survive response loss, page reload, browser restart,
   multi-tab races, complete loss of one selected operator group (all identities,
   endpoints, routes, and region), replacement repair, and a second independent
   reader while exact same-destination retries never become duplicate events and
   replacement uses fresh per-relay material;
7. the signed fixed policy selects three witnessed operator groups per Cell/Core/
   Inbox stripe with distinct store IDs, counts at most one relay per operator
   group, collapses equal `sharedFailureGroupId` values among profile-2 relays, and
   permits only profile 1 or 2 for configured-resilience claims. One verified
   compatible-relay acknowledgement is usable remote storage; the stronger policy
   label requires two acknowledgements and two fresh reads/serves on distinct
   operator groups/store IDs with at least one profile-2 result, while
   `externally-witnessed(n)` is reported separately.
   Profile-1 zero-field/intact-store readiness plus its signed local-failure-domain
   entry/chaos-evidence hash and profile-2 signed topology hash/chain/freshness/
   three-node quorum both validate. The gate survives full operator/store loss/
   replacement,
   collapse of every profile-2 relay sharing one journal group, and loss of a
   complete two-of-three profile-2 journal quorum. Vectors prove queued/direct
   delivery through every remaining compatible target after any target loss and
   exact durability-label downgrade after sole-profile-2 loss, and separately
   prove four
   maintainer groups with a 3-of-4 discovery quorum and one-maintainer-loss
   liveness;
8. legacy/blind dual-read deduplicates exact logical content, preserves author and
   target identity, reproduces cutoff/archive/category/census roots and counts,
   rejects false floor rollback, and exposes migration conflicts/accepted loss;
   the exact `LIVE_DUAL_READ -> FROZEN_CUTOFF -> ARCHIVE_ONLY` graph rejects every
   skipped/backward/wrong-mode edge, while external release-channel telemetry has
   no author, relay, maintainer, or discovery authority;
9. old-client/new-client and new-client/old-relay combinations fail visibly and
   never emit a legacy write after the signed cutoff; pending-pin, source-set,
   cutoff, genesis record ID, final-pin fields, bootstrap membership/availability,
   and retirement evidence reject every replay/substitution without a target-pin
   hash cycle. Offline authoring, zero-relay queueing, per-target compatibility,
   unregistered compatible relay delivery, ambiguous-response reconciliation,
   migration/source isolation, profile-2 claim evidence, and source-scoped
   snapshot/checkpoint floor vectors pass; the 30/90/365-day thresholds and
   reset rules are executable against recorded UTC-day evidence. Transition
   evidence vectors fetch every operation shard/manifest, recompute its subject
   including bootstrap/assets/exact measured migration stage, exact Merkle roots,
   runtime partitions, terminal
   and overlapping failure counters, fetch the exact typed supporting manifest/
   artifacts, reject duplicate intent IDs or any missing/extra/untyped support,
   and exercise checked 99.9-percent arithmetic;
10. OHTTP capture covers route/key rotation, replay, padding, origin/referrer,
    ingress/gateway non-collusion assumptions, 10,000-operation/seven-day gate,
    errors, fresh outer HPKE retry only on qualifying non-processing signals,
    ambiguous-loss pending/reconciliation, explicit identical same-destination
    resubmission, and forbidden direct fallback;
11. strict Tor capture covers bootstrap, descriptor, admission, cell/inbox/core,
    update, retry, error, restart, and Tor outage with zero clearnet or UDP egress;
12. public Inbox vectors cover OPEN_APPEND creation, exact bounded foreground/
    background/audit/cold polling, cursor/fallback budgets, key/stripe/epoch
    derivation, independent nonce/padding, wrong AAD/key/tag, spam, omission/
    reorder/injection, checkpoint handoff, floor persistence, and the explicit
    absence of a G3/G4-I claim; native maintainer-ingress vectors additionally
    cover the pinned DHT topic, Noise static key, exact Protomux name/framing,
    nonce/idempotence replay, restart, zero-to-three-ack/current-stripe/frame equality and
    missing-frame handling, BUSY/rejection/receipt result shapes, wrong root/
    generation/key, a valid-but-application-rejected announcement still being
    logged/receipted, one-maintainer loss, and the explicit source-address
    metadata limitation;
13. the bootstrap/root/Cell/Core/author/repair/proposal/checkpoint/snapshot/
    membership-trie/availability-index/recent-bucket/maintainer-log/maintainer-
    ingress/recovery-merge/migration equality matrix passes positive and every
    single-field substitution/fork vector; a receipt majority, hint, cap count, or
    clock never repairs a mismatch;
14. accessibility, Chromium, Firefox, WebKit/iOS, mobile memory, offline signed
    local publication and drafts,
    Argon2id/XChaCha export/import, wrong password/tamper, fresh device-chain
    restore, cancellation, zero-relay/unregistered-relay/discovery-outage behavior,
    migration-stage isolation, and atomic service-worker/cache/pointer transition crash
    tests pass on the
    exact signed artifact; and
15. production browser synthetics perform create identity, post, comment, vote,
    reload, cross-session read, relay failover, and cleanup against canary content
    without using a privileged semantic relay API;
16. the complete quantitative workload matrix in section 10.1 passes on no more
    capacity than the least-provisioned production role, including 10k/100k
    lurkers, maximum frontier, paid spam, disk/GC pressure, full operator-group and
    maintainer loss, upgrade, and restore; and
17. the privacy-safe status/alert contract in section 10.2 fires and clears at
    every threshold without exporting an author, content ID, locator/topic,
    capability, IP, or stable correlation token.

### 10.1 Quantitative public-scale workload gate

The release publishes one immutable workload/evidence bundle naming the exact app,
validator, profile, substrate/build/store hashes, descriptors/routes/operator
groups/store IDs, durability profiles, profile-1 declared local failure domains,
and profile-2 journal-topology hashes/shared failure-group IDs,
maintainer heads, browser/runtime versions, WAN impairment, host CPU/RAM/
disk/network, dataset seed, offered/admitted rate, raw histograms, and failures.
Each relay/maintainer under test has no more CPU, RAM, disk IOPS, or bandwidth than
the least-provisioned production instance for that role. A 30-minute saturation
search first establishes claimed mixed steady capacity `C` at the highest rate
where every SLO below passes; the signed release states the concrete `C`, never an
unqualified “scales” claim.

| Gate | Exact workload |
| --- | --- |
| Mixed steady/burst | 24 hours at `0.65*C`, with 60-second `1.25*C` bursts every 10 minutes. Operation mix is 45% Cell GET, 15% Cell PUT, 10% Inbox APPEND, 15% Inbox READ/WATCH, 10% Core MIRROR/PROVE, and 5% describe/admission. Cell sizes 4/16/64/256 KiB/1 MiB are 30/30/20/15/5%; Peerit Inbox frames are only the pinned 4/16 KiB classes at 65/35%. Overload rejects before body allocation within 500 ms rather than hanging. |
| Lurker fanout | 10,000 simultaneous foreground clients at 15-second jittered refresh plus 100,000 simulated clients with 10% foreground and 90% 300-second background cadence. At least 500 real sessions of each Chromium, Firefox, and WebKit/iOS run alongside deterministic clients. Per-mode request/decrypt/byte caps never rise and group selection remains distributed. |
| Maximum membership / hot recent feed | A 16,777,216-ID membership trie, equal availability index with 10% repaired revisions and 1% explicit unavailable entries, 365-day snapshot/checkpoint history, a 100,000-ID hot recent bucket, contiguous empty bucket rollovers, and whole-keyspace range queries paged through authenticated continuations. Persistent updates rewrite only changed root paths; a fresh mobile client never downloads the complete trees. |
| Paid spam/hot stripe | For 60 minutes attackers consume 90% of valid paid Inbox append capacity and concentrate on one stripe while legitimate threshold-received announcements continue. Direct maintainer traffic covers valid submissions with zero, one, two, and three Inbox acknowledgements plus ten malformed or mismatched attempts per valid submit; every supplied acknowledgement is frame-equal and bounded BUSY/rejection prevents unbounded allocation. Invalid ciphertext, valid-but-rejected records, cursor gaps, maintainer decisions, and proposal replay are included. Total saturation is tested separately and must downgrade claims honestly. |
| Storage pressure | Start at 95% disk high-water, expire 30% of stored leases in one hour, run GC, scrub, checkpoint, virtual-bucket rebalance, Core catch-up/proofs, and retry-pin expiry while foreground load remains at `0.65*C`. Kill/restart at every final-LSN/fence point. |
| Failure domains | Remove every identity, endpoint, route, process, volume, store ID, and region in one selected operator group under load; then restore/replace it. Run two profile-1 relays under distinct witnessed operators/store IDs and distinct registry-global local-failure-domain IDs, reject an aliasing registry that assigns different IDs to one declared blast radius, destroy each complete declared local host/volume failure domain in turn, and prove only new-identity replacement. Collapse profile-2 relays exposing one `sharedFailureGroupId` to one vote, remove that whole group, and separately kill/partition every two-node majority of one three-node external journal so mutation readiness clears without an acknowledged floor gap; then restore/replace it under a new distinct store/operator/shared-group tuple when required. Separately lose each one of four maintainers at every proposal, checkpoint-target, and snapshot-target ownership boundary; lose two; poison >95% of DHT replies; partition a still-running old writer; fail ingress/gateway/storage roles independently; and exercise Tor outage with no direct fallback. |
| Upgrade/disaster | Rolling format/artifact upgrade, rollback before/after fence, profile-2 clean-machine same-identity restore through the external control/descriptor floor, profile-1 live-store loss/new-identity replacement, corrupted/stale backup, acknowledged-body recovery gap, certificate-subset replacement, higher-generation discovery recovery merge, archive copy loss, and 30/90/365-day restore all run against exact signed artifacts. |
| Soak | Seven consecutive days of the mixed workload, lease and profile-2 journal-topology rotation/expiry, profile-1 intact-store restart, Inbox epoch overlap, maintainer proposal rotation, service-worker release updates, operator/maintainer churn, and controlled faults with no manual database edit or privileged semantic relay call. |

Required outcomes are all simultaneous:

- admitted 4–64-KiB Cell GET/PUT operations and 4/16-KiB Inbox operations have
  p99 <=2 seconds and p999 <=5 seconds; 256-KiB/1-MiB Cell operations have p99
  <=5 seconds and p999 <=15 seconds;
  proof/batch pages have p99 <=5 seconds and p999 <=15 seconds;
- fresh mobile cold start reaches the first 20 independently validated useful
  records at p95 <=5 seconds and p99 <=10 seconds, with <=16 MiB downloaded and
  <=256 MiB peak RSS; returning start is p95 <=3 seconds and never lowers its floor;
- after a third valid maintainer receipt, proposal/checkpoint inclusion is p99 <=240
  seconds and p999 <=300 seconds under the paid-spam envelope, matching the pinned
  two-slot cutoff plus four 15-second proposer phases, with zero omitted
  threshold-received record and auditable fixed rejection for every non-inclusion;
- every admitted relay operation reaches a canonical terminal outcome at >=99.9% over
  each rolling seven-day window; there is zero acknowledged-write loss, duplicate
  logical event, signature/codec disagreement, privacy fallback, floor rollback,
  spend reuse, hidden operator-group/store-ID/profile-2-shared-journal/durability-
  profile substitution, or false externally-witnessed count; every reported
  configured-resilience success has at least one profile-2 acknowledgement and every RESILIENT/recovery
  label has the required fresh reconstructable charged-probe witness rather than
  merely an uncharged profile-2 read/serve;
- at 95% disk/GC/rebalance the accepted-operation p99 is <=2x its no-maintenance
  baseline, event-loop p99 is <=50 ms, reserves remain intact, and overload returns
  bounded BUSY rather than exhausting control/WAL headroom;
- complete loss of one operator/store or one profile-2 shared-journal group
  preserves two-of-three verified reads when the configured set had three. Every
  remaining compatible relay stays usable, including an unregistered relay; the
  sole-profile-2-loss case downgrades resilience/external-witness claims without
  blocking local authoring or other delivery. The client visibly updates
  the resilience/`externally-witnessed(n)` labels and repairs to a distinct
  operator/store tuple (and distinct shared-journal ID for profile 2) within two
  lease epochs. Loss of one profile-2 journal quorum admits no mutation on that
  relay until current topology/readiness returns; loss
  of one maintainer preserves 3-of-4 progress, while loss of two marks that
  discovery source stale within 300 seconds without lowering existing reads,
  direct shares, local authoring, or relay delivery;
  and
- profile-2 same-identity disaster recovery reaches mutation-ready on that relay
  only with exact external control/descriptor floors and within the declared RTO.
  Any acknowledged gap removes that relay's recovery claim or starts a new relay
  identity; it is not a global client read-only condition. Loss/restore of a profile-1 live
  store always starts a new identity and repairs/re-acknowledges its data; it never
  increments `externally-witnessed(n)`. Upgrade/restore otherwise yields byte-,
  spend-, floor-, and accounting-equivalent state.

### 10.2 Privacy-safe operational status and alerts

The client exposes four independent state axes, never one global write switch:

1. **local authoring:** `LOCAL_READY`, `LOCAL_BLOCKED_CRYPTO`, or
   `LOCAL_BLOCKED_STORAGE`;
2. **relay delivery:** `QUEUED_NO_RELAY`, `DELIVERING`, `PENDING_UNKNOWN`, or
   `RELAY_ACKNOWLEDGED(n)`;
3. **durability:** `LOCAL_ONLY`, `REMOTE_SINGLE`, `DEGRADED_AVAILABILITY`,
   `POLICY_DURABLE`, or `RESILIENT`; and
4. **discovery:** a map per source with `CURRENT`, `STALE`, `FORKED`, or
   `UNAVAILABLE`, plus the union/direct-share view.

Privacy and migration are additional claim/evidence labels, not authoring states.
Hard intrinsic cryptographic/author-chain/local-journal failures affect local
authoring immediately. Relay, registry, profile-2, maintainer, checkpoint,
migration, and route failures affect only their axes/targets. Evaluation runs
every `alertEvaluationSeconds=60`. A soft condition opens after exactly
`softAlertOpenIntervals=3` consecutive intervals and clears after exactly
`softAlertClearIntervals=5` healthy intervals. One alert per class per 30 minutes
is emitted with an accumulated count; recovery transitions are emitted once. Rate
limiting never suppresses the axis state or target-local safety action.

| Alert class | Trigger | Required action |
| --- | --- | --- |
| Checkpoint/quorum | checkpoint age reaches 300 seconds, timestamp/chain mismatch, fewer than three of exactly four maintainers, proposal replay mismatch, or equivocation | mark only that discovery source `STALE`/`FORKED`, preserve its floors/evidence, and continue local authoring, direct shares, relay delivery, and independent sources |
| Operator registry | expiry within 7 days (warning), expiry/fork/multi-map, counted group merge, or fewer than required live groups | renew/rotate before expiry; remove invalid independence votes and downgrade claims/routes, while compatible unregistered relays remain generic usable targets |
| Durability/repair | unacceptable/unknown durability, invalid profile-1 zero shape/intact-store readiness/local-failure declaration/chaos evidence, duplicate registry-global profile-1 local-failure-domain ID, missing/stale/forked profile-2 topology or restore-evidence bundle, duplicate operator group/store ID, repeated profile-2 `sharedFailureGroupId`, profile-2 journal-quorum loss, failed full read, missing/stale/unreconstructable charged-probe evidence, repair deadline miss, Core sponsorship without recent serve, or whole operator/store/shared-journal loss | remove the invalid/collapsed vote, correct `externally-witnessed(n)`, downgrade durability, retain local intent/reads, and repair to a distinct target; disable mutation only on a relay whose own profile-2 journal is unsafe, never on other relays or local authoring |
| Inbox/backlog | two budget-exhausted refreshes, cursor non-advance, hot-stripe saturation, or useful-content SLO miss | record `hint-lag`, prefer checkpoint/recent bucket, keep bounded budgets, never claim completeness |
| Writer/outbox | pending/unknown intent >5 minutes, repeated BUSY, response-loss ambiguity, CAS conflict, or author-floor mismatch | preserve the exact intent, reconcile without duplicate mutation, and isolate only an intrinsic local author-chain/CAS conflict; never generate a second event |
| Lease/key custody | remaining storage lease below 120 epochs, missing next-checkpoint capability, maintainer signer unavailable, custody drill overdue, or unexpected duplicate transport writer | renew/rotate or stop only the affected replica/discovery role; compromise/equivocation invokes its recovery ceremony while authoring continues when local identity custody is safe |
| Archive/migration | external copy unavailable, restore evidence older than 30 days, census/root mismatch, legacy write after cutoff, or retirement criterion reset | mark migration evidence blocked, restore/replace the copy and restart that consecutive gate; blind authoring/delivery is unchanged |
| Privacy path | direct fallback, Origin/header sentinel at a forbidden role, same-group split roles, Tor clearnet/UDP egress, or OHTTP pool affinity | `PRIVACY_DOWNGRADED` or fail closed according to profile; public claim changes immediately |
| Relay substrate | WAL/checkpoint lag, orphan staging, retry-pin pressure, control reserve, clock unsafe, external ack-floor lag, fence loss, scrub failure, or 95% disk threshold | role-local readiness clears as the HiveRelay spec requires; Peerit queues/excludes that target and repairs without invalidating the signed event |

Exported telemetry contains only coarse aggregate bands and rotating incident counts.
It MUST NOT contain exact author/account/device keys, signed record IDs, logical
hashes, locators/topics/Core keys, capabilities/tokens, IPs, Origins, proposal
observation bytes, or per-user timelines. Local diagnostic correlation IDs are
CSPRNG values scoped to one process and rotate/delete within 15 minutes; they are
never exported. Opt-in crash reports pass a fixture-tested redactor, use no stable
installation ID, and are rejected if any sentinel survives. Operators may inspect
their own generic HiveRelay health locally, but app semantics never become relay
metric labels.

No unit test, receipt, green health response, relay count, or signed release alone
proves this profile. Evidence records the exact app commit, release artifact/hash,
substrate tuple, relay descriptors/artifacts, browser/runtime versions, routes,
operators, timestamp, test data, failures, and reviewer.

---

## 11. Definition of done

The Peerit blind profile is ready for public default only when:

1. HiveRelay has already released the final blind application-serving product—not
   an optional semantic-service sidecar—and its independent fixtures, forbidden-
   component/route gates, and deployed relay gates pass;
2. Peerit's signed compatibility/migration pin contains real reproduced
   spec/ABI/vector, validator, policy, app/asset, recommended-bootstrap, substrate,
   and migration-evidence hashes, and all profile vectors pass in every supported
   runtime without treating release authority as content or service authority;
3. lurker mode is the default; an opted-in ordinary-web user can create, sign,
   journal, and locally view a post/comment/vote offline, zero relays queue it, and
   one compatible unregistered relay can acknowledge it without an operator,
   profile-2, release, maintainer, or discovery permission gate;
4. the closed `LIVE_DUAL_READ -> FROZEN_CUTOFF -> ARCHIVE_ONLY` migration,
   cutoff/genesis/bootstrap cross-binding, archive/census, exact 30-day legacy-
   qualification and 90-day legacy-read retirement gate pass, with accepted early
   loss visible and the archive retained 365 days; external distribution telemetry
   never changes author/content/relay/discovery validity;
5. the fixed mixed durability-profile-1/2, three-witnessed-operator-group plus
   three-distinct-store-ID/two-ack/two-recent policy passes for Cell, Core, and
   every Inbox stripe; equal profile-2 shared-journal IDs collapse, while two
   profile-1 relays may count toward the target only under different witnessed
   operators/store IDs and different registry-global local-failure-domain IDs with valid signed local-failure-domain/chaos-evidence
   entries. The configured-resilience label includes at least one profile-2 result,
   `externally-witnessed(n)` is accurate, and no profile-1 same-identity/control-
   RPO0 claim appears; sole-profile-2 loss downgrades only the durability/external-
   witness claim while compatible targets and local authoring continue. It passes complete operator/store/profile-2-shared-journal
   loss, whole profile-2 journal-quorum loss, topology expiry/fork, profile-1 live-
   store loss/new-identity replacement, and repair to a distinct operator/store/
   profile-2-shared-journal tuple; the
   separate exactly-four-administration/3-of-4 maintainer plane, four signed
   ingress bindings, and three-operator/three-store-ID-mirrored observation logs
   with profile-2 shared-journal collapse
   pass
   one-maintainer loss, proposal replay, direct-submit restart/idempotence,
   auditable inclusion, equivocation isolation, and commitment-preserving higher-root
   recovery as one independent discovery source; loss of that source never blocks
   direct shares or another discovery root;
6. the full equality matrix, including exact migration-pin/recommended-bootstrap
   validation and source-scoped snapshot/checkpoint floors,
   public OPEN_APPEND encryption/rotation, membership
   trie, replaceable availability index, recent buckets, proposal/checkpoint chain,
   `DiscoveryFloorV1`, bounded continuation proofs, contiguous empty buckets,
   `DiscoveryRecoveryMergeV1`, intrinsic author authority, identity,
   same-destination retry, fresh-chain
   recovery, capabilities, and all witnessed floors survive crash/reload/
   multi-device tests;
7. direct Origin negative evidence is visible; OHTTP passes section 8.1 before it
   becomes the web default; native/Tor profiles pass their named capture,
   downgrade, performance, and resource gates; no Inbox/direct-slot traffic claims
   G4-I absent a separate P23 result; and
8. the exact atomic signed web release and `peerit.site` production synthetics pass
   offline post/comment/vote, zero-relay queue/reload, unregistered-relay delivery,
   cross-session read, multi-source discovery, failover, and service-worker
   rollback/mixing tests while public copy states only the proven claims;
   and
9. the quantitative scale/soak/disaster matrix and privacy-safe operational alert
   matrix pass on the least-provisioned production roles with published evidence.

Until then, this document is a build contract—not evidence that production is
already blind, anonymous, decentralized, or fully migrated.
