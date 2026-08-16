# Sequence 29 limited public INBOX test contract

**Schema:** `PeeritLimitedPublicInboxBootstrapV1`

**Status:** bounded contract for `LIVE_PUBLIC_TEST_ONLY`; not a production claim

**Profile authority:** `@peerit/hiverelay-profile-v1` at SHA-256
`74d3b65dff1bbf2a4630791fd1a770e8dcdfac415bf693ff313d38d0262619fd`

`MUST`, `MUST NOT`, `SHOULD`, and `MAY` are normative. This document narrows
Sequence 29. It does not modify
[`PEERIT-BLIND-SUBSTRATE-PROFILE.md`](./PEERIT-BLIND-SUBSTRATE-PROFILE.md).

The JSON schema has the assignment-fixed legacy filename
`config/peerit-limited-availability-bootstrap-v1.schema.json`. Its schema name,
title, signature domain, and every permitted claim are
`PeeritLimitedPublicInboxBootstrapV1`. The filename is not an
`AvailabilityBootstrapV1` claim.

## 1. Honest boundary

The test has one stripe (`stripeCountLog2 = 0`) and two physical INBOX topics,
one on each owner-operated relay. The two relays are not represented as
independent operators. The topics are global public-discovery topics. They are
not derived per board, community, author, or record.

The test bootstrap MUST say:

- `claimBoundary = LIVE_PUBLIC_TEST_ONLY`;
- `operatorBoundary = TWO_OWNER_OPERATED_RELAYS_NOT_INDEPENDENT_OPERATORS`;
- `topicScope = GLOBAL_PUBLIC_DISCOVERY`;
- `releaseSequence = 29`;
- exactly one current epoch set with two distinct relay keys, store IDs, and
  active topics for the initial Sequence 29 release; each relay's continuity
  hash MUST match its authenticated descriptor/receipt binding, while the
  profile-1 canonical continuity hash MAY repeat across the two relays; and
- `artifactClass = LIMITED_PUBLIC_TEST_RELEASE` for an actual test release.

Checked-in vectors say `artifactClass = FIXTURE_ONLY` and MUST be rejected by a
release ceremony. They exercise codecs and equalities; they are not fleet
configuration.

The test does not claim `AvailabilityBootstrapV1`, the production 24-binding
topology, operator independence, completeness, censorship resistance, G3,
G4-I, anonymity, spam resistance, production readiness, or deployment.

## 2. Target compatibility is a future accepted output

Commits `1012ca12792df662b4f812f20d0165de63071cc8`,
`fa53fb22e5ecd606bf7816575bb723f5a9e87766`, and
`48e596afed2e53fd39129033d4983bb8ae82bc34` are source provenance only. Their
historical wire, ABI, vector, browser, and Cell-GET hashes MUST NOT become the
Sequence 29 target tuple merely because they generated or informed an input.

Before any release, the artifact lane MUST regenerate from the accepted clean
integration result and independently accept all target substrate tuple hashes,
the browser artifact and manifest hashes, the limited Cell-GET artifact hash,
and the INBOX exports. No missing future hash has a placeholder value in this
contract. A fixture hash is never a release pin.

Required generic operations are CELL.PUT `(family=2, operation=1)`, CELL.GET
`(2,2)`, INBOX.APPEND `(3,4)`, and INBOX.READ `(3,5)`. INBOX.CREATE `(3,1)` is
used by the offline release ceremony, not by a browser lurker or ordinary
publisher.

## 3. Bootstrap and management capability invariant

Each binding uses generic HiveRelay:

| Field | Sequence 29 value |
| --- | ---: |
| `stripeIndex` | `0` |
| `frameClassBits` | `3` (classes 1 and 2) |
| `appendAuthMode` | `0` (`OPEN_APPEND`) |
| `retentionClass` | `3` (`R30`) |
| `leaseClass` | `4` (`L90`) |

For each binding the offline ceremony creates independent random Ed25519
create, renew, and close keypairs with a CSPRNG. The keypairs MUST be fresh per
relay and epoch. The physical topic is exactly:

```text
BLAKE2b-256(
  ASCII("hiverelay.blind.inbox-topic.v1") ||
  allocationEpoch(u32be) || createPublicKey
)
```

The served bootstrap contains `createPublicKey`, `physicalTopic`, and the
canonical generic create receipt. It contains no create, renew, or close private
seed, no encrypted seed, and no public-input derivation recipe. The exact create
request, request commitment, admission/spend evidence, and encrypted management
recovery material stay in the offline ceremony record.

Deriving a management private seed solely from public inputs such as a board
slug and relay public key is a release-blocking error. Anyone can repeat that
derivation, create the close signature, and submit INBOX.CLOSE. HiveRelay makes a
successful CLOSE terminal: later READ is `NOT_FOUND`, indistinguishable to a
reader from an absent topic. Public derivation therefore grants an
unauthenticated third party a board-wide discovery denial of service. This is
not an intended OPEN_APPEND property: OPEN_APPEND makes append public; renew and
close remain private management capabilities.

The checker recomputes every topic, decodes the canonical `InboxReceiptV1`,
verifies its relay signature over
`ASCII("hiverelay.blind.inbox-receipt.v1") || u64be(unsignedLength) || unsigned`,
and requires CREATED result `1`, state revision `0`, lease class `4`, topic
commitment `BLAKE2b-256(physicalTopic)`, and exact relay/store/continuity and
descriptor-floor equality.

Sequence zero has `previousBootstrapHash = null`. Every later artifact is
exactly one greater and names SHA-256 of the preceding complete canonical signed
wrapper. The bounded initial artifact and every separately signed rotation
successor each contain exactly one active current epoch set. A successor uses
the next inbox epoch and fresh selection/master keys, CREATE keys, and physical
topics; none may be reused. It replaces the two append targets rather than
silently creating four. A future read-only overlap contract would require a
separately reviewed schema and ceremony and is not admitted by this checker.

All decimal `u64` fields are canonical strings in `0..2^64-1`; the JSON shape's
decimal regex is not sufficient authority by itself. Acceptance uses a trusted
local reference time, never a time supplied by the bootstrap or vector:
`issuedUnixMillis <= reference < expiresUnixMillis`. The effective lease epoch
is `floor(reference / 21,600,000)` and the sole current inbox epoch is
`floor(effectiveLeaseEpoch / 28)`. Allocation epochs must be no more than one
ahead and must remain inside the generic 1,460-epoch acceptance window.

`expiresUnixMillis` is strictly after `issuedUnixMillis` and the difference is
at most `2,678,400,000` milliseconds (31 days). A reader persists a separately
named `PeeritLimitedPublicInboxBootstrapFloorV1` containing the highest accepted
`bootstrapSequence` and SHA-256 of that complete canonical signed wrapper. A
lower sequence is rollback. A different hash at the same sequence is a visible
fork and fails closed. This floor is not canonical `DiscoveryFloorV1` and makes
no discovery-completeness claim.

The wrapper signature is Ed25519 over:

```text
ASCII("peerit.limited-public-test.inbox-bootstrap.v1") ||
0x00 || canonicalJson(payload)
```

Canonical JSON recursively sorts object keys lexicographically, emits no
insignificant whitespace, uses UTF-8, and accepts only the types permitted by
the JSON schema.

### 3.1 Limited management custody

Management recovery uses the separately named protocol-local policy
`PeeritLimitedPublicInboxManagementCustodyV1`. Its plaintext is
`PeeritLimitedPublicInboxManagementBundleV1`, not the canonical
`PeeritInboxManagementBundleV1`, whose cardinality is 24 or 48. The limited
bundle contains exactly two current complete canonical
`InboxManagementEntryV1` byte strings sorted by `(relayPublicKey,
physicalTopic)`, plus exactly two immediately previous entries under the same sort
only during the read-only rotation overlap described above. It is never padded
to 24.

Each child entry must canonically decode and byte-identically re-encode, reproduce
its complete `InboxStripeBindingV1` and binding hash, match the bootstrap
relay/topic/epoch/create receipt, derive its advertised CREATE, RENEW, and CLOSE
public keys from its private seeds, and bind `latestReceipt`, `latestRevision`,
and `leaseEpoch`. All role and binding seeds are independently random and
pairwise distinct. No APPEND seed exists because the topic is `OPEN_APPEND`.
The limited bundle binds release sequence 29 and the exact admitted canonical
profile source SHA-256
`74d3b65dff1bbf2a4630791fd1a770e8dcdfac415bf693ff313d38d0262619fd`,
not a fixture-selected or caller-selected profile pin. It also binds current epoch,
bootstrap sequence, SHA-256 of the complete signed bootstrap wrapper, creation
time, and every complete child entry under:

```text
BLAKE2b-256(
  ASCII("peerit.hiverelay.limited-public-inbox-management-bundle.v1") ||
  u64be(canonicalPrefixLength) || canonicalFieldsThroughCreatedUnixMillis
)
```

That plaintext is separately encrypted in
`PeeritLimitedPublicInboxCustodyEnvelopeV1` with the established
`INBOX_MANAGEMENT bundleKind = 2` and distinct local `plaintextCodec = 3`. It is
not `PeeritCustodyEnvelopeV1`, whose kind-2 plaintext codec is 2. Encrypted
shares reuse the canonical `PeeritCustodyEncryptedShareV1` layout byte for byte;
the envelope freezes 2-of-3 bytewise Shamir sharing
over GF(2^8) polynomial `0x11b` at coordinates 1, 2, and 3; a random 32-byte
data key; XChaCha20-Poly1305-IETF payload encryption; independent ephemeral
X25519/HKDF-SHA-256/XChaCha share encryption; and the established
`custody-key`, `custody-plaintext`, `custody-sealed-payload`, and
`custody-share-key` domain recipes with kind 2 and codec 3.
Reconstruction preflights and pins all three recipient and ephemeral X25519
public keys, rejects the complete known low-order set, and requires pairwise
distinct recipients, ephemerals, share nonces, and sealed shares. It
authenticates every supplied share, tries `1+2`, `1+3`, and `2+3` whenever those
pairs are available, and subjects every commitment-matching candidate to the
complete plaintext and entry validation above. Every passing candidate must be
byte-identical. With all three recipients available, one authenticated malicious
share is tolerated because the honest pair still passes; one malicious share
plus one unavailable share is outside the guarantee and fails reconstruction.
Any envelope, AAD, recipient, share, ciphertext, hash, codec, cardinality,
entry, or bundle-commitment tamper fails. The exact layout is frozen in
`protocol/seq29-limited-public-test/limited-management-custody-v1.json`; none of
its private bytes enter the served bootstrap or browser bundle.

## 4. Issuance, Cell equality, and AuthorBind

One Sequence 29 post has two independently randomized CELL.PUT attempts, one
per relay, and later two independently randomized INBOX.APPEND attempts. It does
not reuse a Cell ciphertext, blob hash, slot, read key, CREATE/RENEW/DROP key,
client nonce, request, commitment, receipt, or INBOX frame between relays.
The six CELL authority public keys (CREATE, RENEW, and DROP for both relays)
are pairwise distinct across the combined role set; role-local uniqueness is
insufficient. All CELL request client nonces are likewise pairwise distinct
across both PUT and GET operations and both relays.

For each Cell the checker decodes the exact canonical `PutCellV1`, derives the
self-certifying slot and `allocationCommitment`, verifies the CREATE signature
directly over that commitment, hashes the exact class-sized blob, derives the
`cell-put` request commitment, and correlates both request nonce and commitment
to the signed `BlindReceiptV1`. The Cell receipt's complete
`RelayResultBindingV1` must equal the current bootstrap binding's signed INBOX
create-receipt identity, including relay key, store, descriptor sequence/hash,
durability profile/continuity, and restore head. Counts never substitute for
this wire evidence.

After canonical `AuthorBindV1` decode, each signed `CellReplicaBindingV1` is
joined by `relayPublicKey` to exactly one independently decoded Cell evidence
row; array position is never authority. The join is a relay-key bijection and
binds field-for-field the version, intrinsic logical hash and encoding
commitment, exact `ReadCellCapV1`, blob hash, size class, allocation and lease
epochs, CREATE/RENEW/DROP public keys, derived allocation commitment, exact
`BlindReceiptV1`, and full bootstrap relay continuity. The generated
`cellReplicaBindingCanonicalHex` mirror is checked for fixture drift but cannot
substitute for that wire-evidence join. The signed-replica/clean-wire mixed-data
fixture in this contract fails `CELL_REPLICA_EVIDENCE_BINDING` before its
signed-replica key reuse can bypass the independently decoded Cell invariants.

The complete inner envelope is `PeeritInnerOperationBatchV1`, codec `334`, with
length `8..1,048,519`. Before an AuthorBind is signed:

1. the CELL.PUT receipt verifies against the selected relay and exact request;
2. the embedded public `ReadCellCapV1` performs a capability-bound CELL.GET;
3. the returned Cell blob matches the receipt and binding;
4. decryption and reassembly return the exact inner envelope;
5. the envelope reproduces `logicalHash`, `encodingCommitment`, inner codec,
   length, and the smallest Cell size class; and
6. the canonical operation batch contains one intrinsically valid author key.

The checker compiles the pinned profile catalog with its normative named sort
projection, canonically decodes and byte-identically re-encodes the signed
`AuthorBindV1` and `PeeritAnnouncementV1`, and runs their profile validators.
The archive-runnable gate pins the self-contained generated validator at
`protocol/validator/peerit-validator-v1.bare.mjs` SHA-256
`66676fddb0c973dececaf78d4a070d76afb2febf78f967a7f83e57c6fba67628`.
That module is fixture replay authority only, never release authority. A populated
checkout MUST also run `canonical-cross-check.mjs`; it requires byte-identical
encode/decode and accept/reject parity with the pinned canonical source profile
validator and codec-334 signed-operation authority before this fixture evidence is
admissible.
After capability-bound Cell decrypt it independently runs the intrinsic Peerit
operation authority for codec 334 and binds that author to the outer AuthorBind.
A structurally plausible or publisher-supplied inner value is never authority.

Every claimed `CellReplicaBindingV1` MUST pass those equalities. At least one
claimed initial replica MUST independently reconstruct the exact inner bytes.
A receipt or acknowledgement without capability-bound GET and decrypt is never
sufficient.

For class 1 the returned canonical `GetCellResultV1` contains an exact
4,096-byte Cell blob. The checker hashes the returned blob, matches the
`ReadCellCapV1.expectedCellBlobHash`, then opens
`version=1 || nonce12 || AES-256-GCM-sealed` with AAD
`ASCII("hiverelay.blind.cell.v1") || 0x01 || sizeClass || storageSlot`. The
authenticated plaintext begins `u32be(contentLength)` and only the derived
content bytes may satisfy the inner equality. A publisher-supplied
`decryptedInner` field is forbidden and cannot substitute for GET bytes.

`AuthorBindV1` is manifest tag `3`. Sequence zero alone omits
`previousAuthorRecordId`; every later record is exact `+1`, names the prior
complete record ID, and uses the same author chain. Its signature domain is
`peerit.hiverelay.author-bind.v1`. Release, migration, registry, maintainer,
profile-2, Inbox, and discovery state are not author authority.

The public `ReadCellCapV1` is intentionally sufficient for a fresh reader to
fetch the opaque Cell result. It is a read/decrypt capability, not a create,
renew, drop, or identity private key. A reader still accepts no content until
the complete Cell and AuthorBind equality/authority checks pass.

## 5. Sequence 29 announcement mode

The Sequence 29 emitter supports exactly one mode: canonical
`PeeritAnnouncementV1` INLINE containing the complete signed AuthorBind bytes.
The bytes MUST be `1..10,000`; `manifestReadCaps` MUST be empty. If the signed
AuthorBind exceeds 10,000 bytes, this bounded emitter fails before admission and
does not invent an additional storage phase.

Canonical profile readers may support `CELL_REFERENCE` only when their accepted
profile/runtime authority already supports it. `CELL_REFERENCE` remains a
canonical optional mode; it is not emitted by this Sequence 29 flow. Adding it
to issuance would require a separately admitted PUT, capability-bound readback,
and an amended reviewed budget.

The announcement fields and checks remain canonical:

```text
PeeritAnnouncementV1 {
  version:             1
  manifestTag:         3
  manifestRecordId:    profile record ID of exact signed AuthorBind bytes
  manifestMode:        1 (INLINE)
  manifestRecord:      complete signed AuthorBind bytes[1..10000]
  manifestReadCaps:    []
  publishedLeaseEpoch: u32
  publisherPublicKey:  32 bytes
  signature:           64 bytes
}
```

The publisher may differ from the author. Its signature authenticates only the
announcement envelope. The AuthorBind and inner operation retain their own
authority. Any public reader may publish or republish one intrinsically valid
record.

```text
manifestRecordId = BLAKE2b-256(
  ASCII("peerit.hiverelay.manifest-record-id.v1") ||
  manifestTag(u16be) || u64be(recordLength) || signedAuthorBindBytes
)

signedAnnouncementId = BLAKE2b-256(
  ASCII("peerit.hiverelay.signed-announcement-id.v1") ||
  u64be(announcementLength) || signedAnnouncementBytes
)
```

`publishedLeaseEpoch` may be at most one epoch ahead of effective time and is a
replay/diagnostic bound only. It does not order or expire the AuthorBind.

## 6. Stripe and frame

For Sequence 29 `s = 0`, so stripe selection always returns zero. The general
formula remains `first_s_most_significant_bits(HMAC-SHA-256(
stripeSelectionKey, signedAnnouncementId))`.

For each relay binding:

```text
frameKey = HKDF-SHA-256(
  ikm  = announcementMasterKey,
  salt = physicalTopic,
  info = ASCII("peerit.hiverelay.inbox-frame-key.v1") ||
         inboxEpoch(u32be) || 0x00 || relayPublicKey,
  L    = 32
)

aad = ASCII("peerit.hiverelay.inbox-frame-aad.v1") ||
      inboxEpoch(u32be) || 0x00 || relayPublicKey ||
      physicalTopic || frameClass(u8)
```

For generic frame size `C`, plaintext is exactly
`u32be(announcementLength) || signedAnnouncementBytes || randomPadding` and has
length `C - 24 - 16`. The frame is
`nonce24 || XChaCha20-Poly1305-IETF-Seal(key, nonce24, aad, plaintext)`.
The smallest enabled class that fits is mandatory. Every relay gets an
independent random nonce, padding, frame, frame hash, admission/spend, and
request. Reusing a frame across relays or attempts is forbidden.

Zero acknowledgements means queued propagation. One acknowledgement proves only
that target. Two owner-operated acknowledgements do not establish operator
independence. INBOX is a hint path and never content authority.

## 7. Reader cursor and failure rules

The cursor scope is `(inboxEpoch, stripeIndex, relayPublicKey, physicalTopic)`.
An INBOX.READ result signature and all request correlations verify before its
opaque cursor or entries are used. The cursor is at most 128 bytes and is bound
by HiveRelay to a 15-minute snapshot. The client never parses it or transfers it
to another binding.

The request commitment is exactly:

```text
BLAKE2b-256(
  ASCII("hiverelay.blind.request.v1inbox-read") || relayPublicKey ||
  physicalTopic || BLAKE2b-256(exactCursorBytes) ||
  u16be(limit) || clientNonce
)
```

Every accepted page carries the complete `RelayResultBindingV1`, request nonce,
request commitment, snapshot revision, canonical entries, their BLAKE2b-256
commitment, exact optional next cursor, and relay signature. Domain 108 signs
canonical `InboxReadSignaturePayloadV1`: version, complete relay binding, nonce,
request commitment, snapshot revision, entries commitment, and optional cursor.
Raw entries are authenticated through `entriesCommitment` and are not repeated
in that compressed signature payload. Only after request/topic/relay/descriptor
correlation, entry/frame commitments, and signature verification may frame
decryption or cursor persistence begin.

The clean `48e596a...` executable currently signs the full result including raw
entries rather than this frozen compressed payload. That is an explicit target
integration drift, not permission to weaken this contract. The artifact lane
must reconcile daemon, client, vectors, and regenerated target tuple before a
release hash can be accepted.

For a signed page, frames are processed under mode-wide request, byte, and
decrypt budgets. A malformed, unauthenticated, wrong-AAD, wrong-key, or
application-invalid frame may be discarded; the verified page cursor may still
advance so a poison frame cannot pin the reader forever. Accepted records and
the new authenticated cursor commit atomically. A crash before that transaction
replays the old page and deduplicates by `manifestRecordId`.

Append revision and page order are cursor mechanics only. They create no event
order, author authority, or completeness claim. Cursor gaps and two consecutive
budget-exhausted refreshes record `hint-lag` and enter bounded recovery; they do
not fan out without limit or reset an authority floor.

## 8. Retry identity

Before send, the client durably records the exact target identity, canonical
request bytes, request commitment, admission/spend, Cell ciphertext or INBOX
frame, and expected receipt/frame hash. Response loss becomes
`PENDING_UNKNOWN`. The client reconciles without mutation using CELL.GET of the
exact slot/blob or INBOX.READ for the exact frame hash.

A fresh outer transport context is automatic only after a positive signal that
the request was not processed. Ambiguous OHTTP/HTTP connection loss is not such
a signal. A changed relay key, store ID, continuity hash, physical topic, or
destination is a new attempt with fresh locator/topic, management keys,
ciphertext/frame, nonce/padding, commitment, admission/spend, and receipt slot.
It never reuses the old frame.

## 9. Consent and cancellation

Boot is lurker state: no identity, write credential, admission, signature, or
write request. On explicit user confirmation, Peerit creates or restores the
identity locally and commits it under authenticated encryption before signing.
It then journals the exact signed intent and makes it locally visible without
network access.

Propagation order is signed intent, two independent Cell attempts,
capability-bound GET/decrypt, AuthorBind signature, INLINE announcement
signature, and up to two independent INBOX.APPEND attempts. Network or discovery
failure queues delivery and never turns a locally safe authoring flow into
global read-only mode.

Cancellation before identity commit returns to a pristine lurker while retaining
the draft. After identity commit it retains the encrypted identity. After event
signing it retains one exact queued intent. After send or ambiguous transport it
retains `PENDING_UNKNOWN` and reconciles; it does not claim no write occurred or
create a replacement logical event.

Locking to lurker pauses work under the global writer fence and is
nondestructive. Forgetting identity is a distinct confirmed destructive action.
It is refused while a send, spend, replica, or outcome is pending/unknown unless
reconciliation completes or a freshly verified recovery export contains every
capability and exact pending request needed to resume without duplication.

## 10. Executable gate

Run:

```sh
node protocol/seq29-limited-public-test/generate-fixtures.mjs
node protocol/seq29-limited-public-test/check.mjs
```

The checker verifies the frozen source hash, JSON schema identity, compatibility
and codec registries, wrapper and relay receipt signatures, topic and receipt
equalities, exact Cell GET/AES-GCM reconstruction, INLINE announcement/AuthorBind
identifier projections, signed Inbox READ request/page/cursor correlation,
frame HKDF/AAD/XChaCha round trips, limited 2-of-3 custody reconstruction and
tamper rejection, cursor/retry/consent state vectors, artifact hashes, and every
mutation fixture's expected rejection code. Generation is deterministic and
FIXTURE_ONLY; it performs no network I/O and creates no live key, topic, token,
or state.

Passing this checker is necessary only for `SEQ29-C0-CONTRACT`. It does not pass
the artifact, browser, local-stack, or live-drill gates.
