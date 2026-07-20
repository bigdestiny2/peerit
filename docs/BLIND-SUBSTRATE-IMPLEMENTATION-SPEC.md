# HiveRelay Blind Substrate — Implementation Specification

**Status:** build-ready component contract

**Date:** 2026-07-11

**Protocol family:** `hiverelay-blind/1`

**Canonical HiveRelay path:**
`docs/protocol/BLIND-SUBSTRATE-IMPLEMENTATION-SPEC.md`

**Target repository reviewed:** `p2p-hiverelay` at
`999b0afd7584bb727cef6e6a88a054f11513927a` (`0.24.3`)

This document turns the architectural requirements in
`BLIND-APP-AGNOSTIC-HIVERELAY-MASTER-SPEC.md` into a component boundary that can
be implemented in HiveRelay. It specifies a generic blind substrate, not an
application backend. The canonical maintained copy lives beside the master
protocol document under HiveRelay's `docs/protocol/`; app repositories may carry
only pinned consumer profiles or delivery snapshots.

The strict substrate provides only bounded ciphertext storage, opaque inboxes,
encrypted-core availability, generic admission, signed evidence, discovery, and
opaque forwarding. It has no application registration, schema, author, record
type, social graph, semantic index, or application-specific policy.

`MUST`, `MUST NOT`, `SHOULD`, `SHOULD NOT`, and `MAY` are normative.

---

## 1. Decisions fixed by this specification

1. The strict substrate is a dedicated, capability-limited daemon. It is not an
   in-process `p2p-hiveservices` plugin and never receives HiveRelay's current
   `{ node, store, config }` service context.
2. One executable protocol registry is the sole source for type IDs, operation
   IDs, field order, domains, limits, errors, and canonical encodings.
3. The public surface has exactly five families: `DESCRIBE`, `CELL`, `INBOX`,
   `CORE`, and `FORWARD`. Operation-specific aliases are not advertised by a strict
   profile.
4. Relays store generic fixed ciphertext. Encryption, capabilities, application
   signatures, merge, indexing, moderation, repair policy, and interpretation are
   client responsibilities.
5. Storage is divided into deterministic virtual buckets, never application or
   author partitions. Version 1 has exactly one write authority per relay identity
   and one atomic WAL coordinator across all local partitions.
6. Direct, OHTTP, Protomux split, MASQUE, and Tor are adapters around the same
   canonical service messages. A transport cannot add an application field or
   inherit a privacy claim merely because it moves opaque bytes.
7. Supporting a new application requires no daemon code, configuration, route,
   key, namespace, metric label, restart, or operator approval.

### 1.1 Explicit exclusions

This component does not specify or own:

- Peerit authority, records, migration, bootstrap, UI, or release policy;
- any other application's schema, membership, identity, merge, or moderation;
- semantic search, ranking, recommendation, graph traversal, content scanning,
  or per-application abuse rules;
- a global relay roster, consensus, blockchain, or proof that two keys represent
  independent operators;
- active-reader secrecy for public content; or
- PIR, ORAM, mixnet cryptography, TEE processing, MPC, or FHE in version 1.

Legacy OutboxLog, shard-store, custody, and semantic services may coexist outside
the membrane. They MUST NOT share the strict endpoints, identity, descriptor
profile, storage root, metrics namespace, or privacy claims.

---

## 2. Sole source, version, and hash relationship

### 2.1 Authority chain

The following artifacts have distinct authority:

| Artifact | Authority |
| --- | --- |
| Canonical HiveRelay blind protocol document | Normative protocol, invariants, state transitions, and allowed behavior identified by `specHash` |
| This implementation specification | Required component/process boundaries, delivery gates, and HiveRelay repository map; its file hash is recorded in the build manifest |
| Executable protocol registry | Exact wire IDs, canonical field order, domains, caps, and error mapping |
| Canonical vectors | Byte-exact proof that each runtime implements the registry |
| Signed service descriptor | What one running daemon currently offers |
| Generic build manifest | Which implementation inputs, dependencies, tools, and artifact produced a deployment |

Prose examples are never a second wire definition. Code MUST import operation IDs,
domains, limits, and codecs from the protocol package; copied constants fail the
source-consistency gate.

### 2.2 Required identifiers

Every build records one `BuildProfileV1`:

```text
protocolFamily  = "hiverelay-blind"
protocolMajor   = 1
protocolMinor   = non-negative u16

specHash = BLAKE2b-256(
  "hiverelay.blind.spec-hash.v1" || len64(specBytes) || specBytes
)

abiHash = BLAKE2b-256(
  "hiverelay.blind.abi-hash.v1" || len64(abiRegistryBytes) || abiRegistryBytes
)

vectorSetHash = BLAKE2b-256(
  "hiverelay.blind.vector-set-hash.v1" ||
  len64(vectorManifestBytes) || vectorManifestBytes
)

buildArtifactHash = BLAKE2b-256(
  "hiverelay.blind.build-artifact-hash.v1" ||
  len64(releaseArtifactBytes) || releaseArtifactBytes
)

buildManifestHash = BLAKE2b-256(
  "hiverelay.blind.build-manifest-hash.v1" ||
  len64(buildManifestBytes) || buildManifestBytes
)

BuildProfileV1 {
  specHash:            32 bytes
  abiHash:             32 bytes
  vectorSetHash:       32 bytes
  buildArtifactHash:   32 bytes
  buildManifestUrl:    optional canonical URL bytes[1..512]
  buildManifestHash:   32 bytes
}
```

`len64(x)` is an unsigned big-endian `u64` byte length. `specBytes` are the exact
canonical bytes of the HiveRelay master protocol document at its canonical path:
UTF-8 without BOM, LF only, no CR bytes, and exactly one final LF. Nonconforming
files are rejected, never silently normalized.

`abiRegistryBytes` are the exact checked-in
`hiverelay-blind-abi-v1.cenc` bytes. Its version-1 `compact-encoding` schema
serializes the numeric registry, every enum/field/cap/domain, and a sorted list of
`(schemaName UTF-8, canonicalSchemaBytes)`. Generated language bindings are outputs
and MUST byte-reproduce this file.

`vectorManifestBytes` are `u32 entryCount` followed by entries encoded as
`u16 pathLength || pathBytes || u64 vectorLength || BLAKE2b-256(vectorBytes)`.
Paths are strict UTF-8 NFC with `/` separators, no leading slash, empty component,
`.`, `..`, or backslash; they sort by raw UTF-8 bytes and duplicates after
normalization fail. Empty sets fail. Vector bytes are not newline-normalized unless
their own declared format requires it.

`releaseArtifactBytes` are the exact downloadable content-addressed distribution
bundle verified before execution. Container releases use one deterministic bundle
containing the OCI manifest, config, and every referenced layer; native releases
hash the exact signed distribution bundle, not an unpacked filesystem or tag.

The canonical generic `buildManifestBytes` include implementation name/version, runtime
or compiler, dependency lock, all build-spec input file hashes, and artifact hash.
It MAY include a source commit, image digest, SBOM, and reproducibility evidence,
but Git, Node, and containers are not protocol requirements. Different compliant
implementations share spec/ABI/vector hashes and have different artifact hashes.

Rules:

- One `(major, minor)` MUST NOT identify two `abiHash` values.
- Any change to field order, signed preimage, operation meaning, error meaning,
  required validation, or accepted non-canonical input requires a major bump.
- A backward-compatible optional operation or feature requires a minor bump and a
  new `abiHash`. It cannot change an existing operation.
- Build metadata or implementation-only changes alter `buildArtifactHash` and the
  generic manifest, not the protocol version or ABI hash.
- A daemon MUST fail startup if its compiled registry, vectors, descriptor
  template, build profile, and artifact manifest disagree.
- A client MUST reject a descriptor that repeats a known version with a different
  ABI hash or rolls back below a locally witnessed version/hash floor.

---

## 3. Trust and process boundary

### 3.1 Required processes

```text
HiveRelay supervisor/API edge
  |
  | bounded raw stream over local IPC
  v
blind-substrate daemon                 strict membrane
  |-- protocol decoder
  |-- admission verifier + transaction coordinator
  |-- cell engine
  |-- inbox engine
  |-- blind-core adapter/sidecar controller
  |-- descriptor/receipt signer
  |-- virtual-bucket store + WAL
  `-- transport adapters/forward policy
```

The daemon MUST run as a separate process and, on supported operating systems, a
separate unprivileged user. Container deployments use a separate service,
read-only root filesystem, dedicated volume, private IPC socket, and no Docker
socket. Failure to provide process and storage isolation prevents advertisement
of `strict-membrane-v1`; it may run only as a development profile.

The upstream `blind-peer` runtime MAY be a daemon-owned child process when its
Corestore/Hypercore dependency generation differs from HiveRelay Core. It inherits
no additional filesystem or network capability.

### 3.2 Capability-limited bootstrap context

The daemon receives only:

```text
BlindDaemonBootstrapV1 {
  storageRootHandle
  ipcListenHandle
  blindIdentityKeyHandle
  genericLimits
  enabledGenericRoles
  admissionParameterFiles
  signedRouteCatalogFiles
  transportListenerHandles
  logSinkHandle
  metricSinkHandle
}
```

All file paths are resolved and opened by the launcher before privilege drop. The
daemon MUST reject unknown configuration keys. Reload accepts only a fully
validated, atomically replaced generic configuration generation.

It MUST NOT receive or be able to open:

- HiveRelay's application registry, main Corestore, semantic service stores, or
  plugin directory;
- the parent `RelayNode`, unrestricted configuration object, management API, or
  arbitrary callback;
- application environment variables, origins, API keys, namespaces, signing
  keys, or release manifests;
- an unrestricted filesystem root or arbitrary outbound socket API; or
- raw HTTP headers, cookies, referrers, user agents, client hints, query strings,
  or trace baggage.

The blind identity is a dedicated Ed25519 key used only for blind descriptors,
health responses, receipts, and proofs. It is not an application key and is not
the key of a co-resident semantic service. Its file is readable only by the blind
daemon user. Rotation follows section 10.

### 3.3 IPC contract

The HiveRelay edge is a streaming byte proxy. It may enforce total connection,
body, and timeout caps before the daemon, but MUST NOT parse a blind body, convert
it to JSON/base64, buffer a maximum-size body globally, attach application
metadata, or log it.

The daemon receives this fixed local preface followed by the external canonical
message:

```text
LocalDispatchV1 {
  version:          u8 = 1
  family:           u8       // 1 describe, 2 cell, 3 inbox, 4 core, 5 forward
  transportProfile: u8
  endpointId:       u8
  outerClass:       u8
  adjacentRelayKey: optional 32 bytes
  bodyLength:       u32
}
```

`LocalDispatchV1` is synthesized by a configured listener/broker from the bound
listener and authenticated adjacent channel; it is never copied from external
headers or a caller-supplied preface. `endpointId` fixes the allowed transport and
family set. `adjacentRelayKey` is present only after cryptographic peer
authentication and otherwise absent. The daemon rejects a profile/endpoint/key
combination not bound by its active descriptor and route catalog. `outerClass` is
derived from the authenticated envelope or negotiated circuit and must match its
observed exact length; an external class header is never trusted.

No source IP or browser metadata crosses the IPC boundary. An explicitly weaker
per-IP edge limiter may run outside the membrane, but its state and claim are not
part of the strict substrate.

Every open store, listener, stream, watch, timer, child, and staging file belongs
to one lifecycle scope with `AbortSignal` cancellation and an idempotent bounded
`close()`.

---

## 4. Minimal external ABI

### 4.1 Bindings

The strict HTTP binding has exactly one POST route per family:

| Method | Route | Body/result |
| --- | --- | --- |
| `POST` | `/api/blind/v1/describe` | `DESCRIBE.GET`, `CHALLENGE`, or `ADMISSION_PARAMETERS` |
| `POST` | `/api/blind/v1/cell` | Tagged cell operation / result |
| `POST` | `/api/blind/v1/inbox` | Tagged inbox operation / result |
| `POST` | `/api/blind/v1/core` | Tagged core control operation / result or stream handoff |
| `POST` | `/api/blind/v1/forward` | Bounded opaque request or authorized stream handoff |

`OPTIONS` exists only for generic CORS preflight. No `GET` by locator, query
parameter, per-operation path, app alias, WebSocket room path, or semantic route
is part of the strict ABI. `DESCRIBE.GET` is a POST dispatch operation. The
existing `GET /.well-known/hiverelay.json` MAY carry the same canonical signed
descriptor bytes and hash as a cacheable compatibility representation; JSON
reserialization is not a signature preimage and challenge/parameter operations
remain POST-only.

Every unary semantic unit contains the same complete dispatch frame from section
4.2. Direct HTTP uses `application/vnd.hiverelay.blind-v1` with that frame inside
`BlindOuterEnvelopeV1`; OHTTP uses the RFC 9292 bHTTP/RFC 9458 mapping in section
8.2. Protomux/Noise and onion stream adapters carry repeated dispatch frames on an
authenticated channel. HTTP content length, outer envelope, bHTTP, HPKE, and
lower-level stream framing are not operation-signature preimages.

Success is HTTP 200. Only malformed outer framing (400), transport body overflow
(413), outer transport throttling (429), and unavailable daemon (503) use distinct
HTTP status. Protocol outcomes use a `RESULT` or `ERROR` dispatch frame inside a
200 response so an oblivious adapter preserves the same error contract. Responses
set `Cache-Control: no-store`; generic CORS never permits credentials.

### 4.2 Canonical dispatch/frame registry

The sole-source ABI registry defines this exact transport-neutral frame. Integer
fields are unsigned big-endian fixed-width values; no adapter may infer, omit, or
reinterpret one:

```text
u32 frameLength                       // bytes after prefix, <= 4 MiB + 64
BlindDispatchFrameV1 {
  version:       u8 = 1
  frameKind:     u8                   // 1 request, 2 response, 3 error,
                                      // 4 stream-control/data
  familyId:      u8
  operationId:   u8
  flags:         u8 = 0               // all bits reserved in v1
  requestId:     16 bytes             // random nonzero for unary/open; zero for stream
  streamId:      u64                  // zero for unary/open request; nonzero after open
  sequence:      u64                  // zero for unary; per-sender monotonic for stream
  bodyLength:    u32                  // exact following bytes, <= family/op cap
  body:          exact canonical operation bytes
}
```

The frozen registry is:

| Family ID | Operations (`name=id`) |
| --- | --- |
| `1 DESCRIBE` | `GET=1`, `CHALLENGE=2`, `ADMISSION_PARAMETERS=3` |
| `2 CELL` | `PUT=1`, `GET=2`, `RENEW=3`, `DROP=4`, `PROVE=5`, `BATCH_GET=6` |
| `3 INBOX` | `CREATE=1`, `RENEW=2`, `CLOSE=3`, `APPEND=4`, `READ=5`, `WATCH=6` |
| `4 CORE` | `MIRROR=1`, `PROVE=2`, `OPEN_REPLICATION=3` |
| `5 FORWARD` | `OPEN=1`, `DATA=2`, `WINDOW=3`, `CLOSE=4` |

A response repeats the request family, operation, and random `requestId` with
`frameKind=2`. A unary error repeats them with `frameKind=3` and canonical
`BlindErrorV1`. Stream frames use kind 4, zero request ID, their assigned stream
ID, and a strictly increasing sequence independently in each direction; a stream
error uses kind 3 with that stream ID. Unknown family/operation/kind, nonzero
flags, invalid ID combination, length mismatch, duplicate/non-monotonic stream
sequence, trailing bytes, or a body above its registry/descriptor/route cap fails
closed before body allocation or dispatch.

HTTP POST bodies and responses contain one complete frame and the fixed route
MUST match `familyId`; mismatch is `BAD_ENCODING`. OHTTP wraps one complete unary
request/response. Protomux/Noise and onion stream adapters carry repeated frames
on one authenticated channel. `CORE.OPEN_REPLICATION` and FORWARD streaming
require a stream-capable adapter; `INBOX.WATCH` remains a bounded unary long poll.

`requestId` is transport correlation only: it is excluded from signed request
commitments, never reused across hops, and never retained in logs. The operation
body still carries its signed `clientNonce` where specified. The absolute frame
cap is the length prefix plus at most 4 MiB + 64 bytes after it; each operation's
smaller cap is frozen into `abiHash`. Source-language objects and lower transport
framing are not protocol authority.

```text
BlindErrorV1 {
  version:         u8 = 1
  code:            stable u8 enum
  retryable:       u8 = 0 | 1
  retryAfterEpoch: optional u32
}
```

Errors never distinguish a never-created, expired, owner-dropped, suppressed, or
reclaimed locator unless a valid management capability is part of that operation.

### 4.3 Describe and health

`DESCRIBE.GET` returns `BlindServiceDescriptorV1` from section 10 and no mutable
counters. `DESCRIBE.ADMISSION_PARAMETERS` returns the exact signed parameter
object whose hash is in that descriptor. Descriptor representations are cacheable
only until signed expiry.

```text
BlindDescribeGetV1 {
  version:          u8 = 1
  descriptorHash:   optional 32 bytes // absent=current; present=history by hash
  clientNonce:      32 bytes
}

BlindAdmissionParametersRequestV1 {
  version:          u8 = 1
  profileId:        u16
  schemeId:         u16
  clientNonce:      32 bytes
}

BlindHealthChallengeV1 {
  version:          u8 = 1
  descriptorHash:   32 bytes
  requestedRoleBits:u16
  clientNonce:      32 bytes
}

BlindHealthResultV1 {
  version:          u8 = 1
  relayPublicKey:   32 bytes
  descriptorHash:   32 bytes
  clientNonce:      32 bytes
  readyRoleBits:    u16
  clockState:       u8 // 1 ready, 2 unsafe, 3 verifying
  effectiveEpochFloor:u32
  integrityState:   u8 // 1 verified, 2 degraded, 3 failed
  checkpointAgeBand:u8 // coarse universal band, no exact revision/time
  scrubAgeBand:     u8 // coarse universal band, no exact revision/time
  rebalanceState:   u8 // 0 stable, 1 copying, 2 catching-up, 3 fenced
  capacityBand:     u8
  challengeEpoch:   u32
  signature:        64 bytes
}
```

The health-result signature domain is `hiverelay.blind.health-result.v1` and
covers every result field. It is produced only when the challenged listener
reaches the same coordinator and identity key as the advertised role. Health is a
fresh liveness/readiness statement, not a storage, independence, or anonymity
proof.

---

## 5. Cells service

### 5.1 Operations and limits

| ID | Operation | Authority | Persistent effect |
| --- | --- | --- | --- |
| 1 | `PUT` | one-time create signature + admission | Immutable cell, spend, retry result, receipt |
| 2 | `GET` | random locator; optional admission | None unless charged read idempotency is enabled |
| 3 | `RENEW` | renew signature + admission + revision CAS | Lease/revision, spend, receipt |
| 4 | `DROP` | drop signature + revision CAS | Terminal owner tombstone, receipt |
| 5 | `PROVE` | random locator + nonce; optional admission | Charged-read result when applicable |
| 6 | `BATCH_GET` | 1–64 distinct locators; optional admission | Charged-read result when applicable |

Exact request/result fields, commitment domains, `BlindReceiptV1`, and stable
errors are imported into the executable registry from the master protocol. The
implementation MUST preserve these fixed version-1 properties:

- slots, create/renew/drop public keys, nonces, and blob hashes are 32 bytes;
- signatures are Ed25519 and 64 bytes;
- the slot is the BLAKE2b-256 domain-separated commitment to the six-hour
  allocation epoch and random create public key;
- cell classes are exactly 4 KiB, 16 KiB, 64 KiB, 256 KiB, and 1 MiB total;
- lease classes are 1, 7, 30, and 90 days in six-hour epochs;
- renew computes `targetLeaseEpoch = max(oldLeaseEpoch, effectiveNowEpoch +
  duration(requestedLeaseClass))`. If target equals old it returns management-only
  `RENEW_NOT_DUE`, commits no spend, and changes no revision. Otherwise it sets the
  lease to target. It never adds a duration to an already-future lease;
- cells are first-write-wins and never overwritten;
- separately selected relays receive independently randomized ciphertext, slots,
  and management keys in the unlinkable profile;
- plain reads expose no lease or tombstone history; and
- a proof returns the complete blob plus a nonce-bound signed receipt. A stored
  hash alone is not a retrievability proof.

### 5.2 Persisted state

```text
CellIndexRecordV1 { // internal index; not a second wire schema
  slot
  allocationEpoch
  sizeClass
  leaseClass
  leaseEpoch
  stateRevision
  policyRevision
  cellBlobHash
  blobReference
  createPublicKey
  renewPublicKey
  dropPublicKey
  allocationCommitment
  objectState       // PRESENT or terminal TOMBSTONE
  policyState       // VISIBLE or SUPPRESSED while present
}
```

`blobReference` is internal and MUST NOT contain an app path. The blob store is
addressed by virtual bucket plus random internal object ID, not plaintext or
ciphertext hash. Hashes verify integrity; they are not filesystem namespaces.

The state machine is:

```text
ABSENT -> STAGING -> PRESENT/VISIBLE -> TOMBSTONE(owner-drop | expired-gc)
                         |   ^
                         v   |
                      SUPPRESSED

ACTIVE -> EXPIRED_GRACE -> RECLAIMABLE
```

Grace is four six-hour epochs. Renew/drop and GC use `stateRevision`; operator
suppress/restore uses `policyRevision`. Suppression cannot invalidate an owner
management capability. Tombstones, spends, and exact retry results remain for
1460 epochs so an accepted old create cannot replay after compaction.

The persisted epoch floor never moves backward. While ready, even an idle daemon
appends a small floor-advance record at each crossed epoch and uses a monotonic
clock to detect wall discontinuity. A runtime jump over four epochs, or restart
more than four epochs beyond the persisted floor, enters `CLOCK_UNSAFE`: create,
renew, expiry, and new lease receipts stop; visible present bytes remain readable.
A configured multi-source clock verification policy or explicit operator-confirmed
`CLOCK_CONFIRM` WAL transition is required to advance the floor. After a confirmed
long offline interval, leases are evaluated at confirmed current time; downtime
does not extend retention.

---

## 6. Inbox service

An inbox is a generic fixed-frame append/read facility. It replaces the name
`rendezvous` at the component boundary because it can also carry opaque wakeups,
repair announcements, capability rotations, and other application-defined
ciphertext. The daemon never knows which use applies.

### 6.1 Creation policies

Every inbox is explicitly created. There is no free implicit topic creation,
topic enumeration, mutable semantic head, or server-selected application policy.
Version 1 supports exactly two append policies:

| Policy | Append authority | Intended generic property |
| --- | --- | --- |
| `OPEN_APPEND` (`appendAuthMode=0`) | Possession of random physical topic plus generic admission | Multiwriter/public announcement bag; spam is client-filtered |
| `SIGNED_APPEND` (`appendAuthMode=1`) | Generic admission plus signature by one random inbox append key | Single capability domain; key is not an app/author key |

The client generates independent random create, renew, close, and optional append
keys. The self-certifying physical topic is:

```text
physicalTopic = BLAKE2b-256(
  "hiverelay.blind.inbox-topic.v1" || allocationEpoch || createPublicKey
)
```

Frame classes are exactly 4 KiB, 16 KiB, and 64 KiB. Frame retention classes are
R1, R7, R30, and R90. The create operation selects one retention class and one
inbox lease class. A frame expiry is the minimum of its stored epoch plus the
selected retention and the current inbox lease. Renewing an inbox does not
retroactively extend or resurrect old frames. Per-topic/global entry and byte
caps are generic daemon limits, not caller-defined policies.

Inbox renew uses the same non-stacking rule as cells:
`targetLeaseEpoch = max(oldLeaseEpoch, effectiveNowEpoch +
duration(requestedLeaseClass))`; target equal to old returns management-only
`RENEW_NOT_DUE` with no spend or revision change.

### 6.2 Operations

| ID | Operation | Required authority |
| --- | --- | --- |
| 1 | `CREATE` | create signature + admission |
| 2 | `RENEW` | renew signature + revision CAS + admission |
| 3 | `CLOSE` | close signature + revision CAS |
| 4 | `APPEND` | admission and, for `SIGNED_APPEND`, append signature |
| 5 | `READ` | random inbox ID; optional admission |
| 6 | `WATCH` | random inbox ID; optional admission; stream-capable transport |

```text
InboxCreateV1 {
  version:          u8 = 1
  allocationEpoch:  u32
  physicalTopic:    32 bytes
  frameClassBits:   u8
  appendAuthMode:   u8 // 0 open-capability, 1 signature-required
  createPublicKey:  32 bytes
  appendPublicKey:  optional 32 bytes // required exactly for mode 1
  renewPublicKey:   32 bytes
  closePublicKey:   32 bytes
  retentionClass:   u8
  leaseClass:       u8
  clientNonce:      32 bytes
  createSignature:  64 bytes
  admission:        AdmissionV1
}

InboxManageV1 {
  version:          u8 = 1
  operation:        u8 // 1 renew, 2 close
  physicalTopic:    32 bytes
  expectedRevision: u64
  expectedLeaseEpoch:u32
  leaseClass:       u8 // NONE for close
  clientNonce:      32 bytes
  signature:        64 bytes
  admission:        optional AdmissionV1 // required for renew
}

InboxAppendV1 {
  version:          u8 = 1
  physicalTopic:    32 bytes
  frameClass:       u8
  frameHash:        32 bytes
  clientNonce:      32 bytes
  appendSignature:  optional 64 bytes // required exactly for auth mode 1
  admission:        AdmissionV1
  frame:            exact class bytes
}

InboxReadV1 {
  version:          u8 = 1
  physicalTopic:    32 bytes
  cursor:           opaque bounded bytes[0..128]
  limit:            u16
  clientNonce:      32 bytes
  admission:        optional AdmissionV1
}

InboxWatchV1 {
  version:          u8 = 1
  physicalTopic:    32 bytes
  afterRevision:    u64
  limit:            u16
  maxWaitMillis:    u16 // 1..30000
  clientNonce:      32 bytes
  admission:        AdmissionV1
}

InboxAppendAckV1 {
  version:          u8 = 1
  relayPublicKey:   32 bytes
  topicCommitment:  BLAKE2b-256(physicalTopic)
  frameHash:        32 bytes
  appendRevision:   u64
  storedAtEpoch:    u32
  expiresAtEpoch:   u32
  requestCommitment:32 bytes
  result:           stored
  signature:        64 bytes
}

InboxReadResultV1 {
  version:          u8 = 1
  relayPublicKey:   32 bytes
  requestNonce:     32 bytes
  requestCommitment:32 bytes
  snapshotRevision: u64
  entries:          ordered array[0..64] of {
                      appendRevision: u64, frameHash: 32 bytes,
                      frameClass: u8, frame: exact class bytes
                    }
  entriesCommitment:32 bytes
  nextCursor:       optional opaque bytes[0..128]
  signature:        64 bytes
}
```

Create, append, renew, and close commitments bind every preceding non-signature,
non-admission field and the relay key under distinct
`hiverelay.blind.inbox-*.v1` domains. `frameHash` is over the exact randomized
fixed frame. Each relay replica receives a fresh independently encrypted frame.

Append assigns a monotonically increasing, relay-local `appendRevision`. It is an
availability cursor only, never application order. Same
`(physicalTopic, frameHash, exact bytes, request commitment)` is an idempotent retry;
same hash with different bytes is `CONFLICT`. Capacity failure never evicts a
non-expired frame: append returns `CAPACITY` until expiry or owner close frees the
inbox.

An empty read cursor captures `snapshotRevision`; later pages exclude newer
appends. A relay-authenticated cursor binds physical topic, last position,
snapshot revision, and a maximum 15-minute expiry. Results contain at
most 64 frames and 4 MiB and are signed over the request nonce/commitment, snapshot
revision, entries commitment, and next-cursor hash. A signature is not a
completeness proof.

### 6.3 Watch and backpressure

`WATCH` is a bounded long poll, not SSE or a durable subscription. It waits only
until `appendRevision > afterRevision`, `maxWaitMillis` (at most 30 seconds),
abort, or shutdown, then returns one ordinary bounded `InboxReadResultV1`. It is
therefore available over direct HTTP, OHTTP, Protomux, split transports, and Tor
without a distinct streaming protocol.

The daemon enforces per-connection, per-topic, and global waiter caps before
registering a waiter. Every waiter owns one timer and cancellation hook and is
removed exactly once on response, timeout, abort, shutdown, or topic close. There
is no event queue: append wakes bounded waiters, each of which reads its bounded
page under the ordinary snapshot rules. Response transport backpressure has the
same byte/deadline cap as `READ`; a stalled response is aborted and the client
reconnects from its last verified revision. Watch never extends retention,
acknowledges application delivery, or changes canonical order.

A charged read/watch persists only a compact retry pin containing spend tag,
request commitment, topic commitment, snapshot and first/last append revisions,
entries commitment, next-cursor hash/bytes, and expiry. It is capped at 256 bytes
and pins the immutable referenced range for at most 15 minutes so an exact retry
can regenerate the same signed page without storing a multi-megabyte duplicate.
GC/rebalance cannot remove a pinned range. The longer spent-tag horizon remains
after page retry metadata expires.

Inbox state, frames, cursor keys, spends, and reproducible acknowledgements use
the shared WAL transaction rules in section 9.

---

## 7. Blind Core service

Blind Core composes upstream `blind-peer`/`blind-peering`; it MUST NOT fork their
replication wire or add an application namespace. The relay stores encrypted
Hypercore blocks under an opaque core key. It never receives the block-encryption
key, writer key, app author key, or Autobase/application metadata.

| ID | Operation | Effect |
| --- | --- | --- |
| 1 | `MIRROR` | Request/extend generic sponsorship for a witnessed core head |
| 2 | `PROVE` | Return selected upstream blocks/proofs and a nonce-bound acknowledgement |
| 3 | `OPEN_REPLICATION` | Hand the transport stream to the byte-for-byte upstream blind-peer protocol |

`MIRROR` binds core public key, fork, length, signed-head hash, lease class,
request nonce, and admission. The shared WAL first commits the spend,
sponsorship floor/expiry, idempotency record, and `mirror-accepted` acknowledgement.
Adapter activation is a recoverable state:

```text
ACCEPTED -> ACTIVATING -> ACTIVE -> EXPIRED
                    `-> RETRY_PENDING
```

`mirror-accepted` means sponsorship was durably accepted, not that bytes are
already retrievable. Health exposes aggregate core-role readiness; per-core status
is learned only through prove/serve. Restart resumes accepted activations.

Any holder of the opaque key may sponsor more availability; no public v1 core-drop
exists. Growth above the latest admitted signed length pauses until a new admitted
extension. Prove requests contain 1–16 sorted distinct indices and return at most
4 MiB. The client verifies the Hypercore signed head, fork/length floor, Merkle
proofs, block decryption, and application bytes.

Core sponsorship computes the same `max(oldLeaseEpoch, now + duration)` target. A
request may still raise the admitted signed head/length when target equals old;
the coordinator charges only if at least one admitted resource dimension advances
and records the exact resulting head, length, and lease. Otherwise it returns
`RENEW_NOT_DUE` before spend or mutation.

Until the repository's Hypercore 10/Corestore 6 stack is proven compatible with
the selected upstream blind-peer generation, this role runs in a daemon-owned
store/child process. Dependency compatibility, close behavior, disk accounting,
and wire interop are release gates.

---

## 8. Forward service and transport adapters

### 8.1 No open proxy

Forwarding is authorized only by a signed, app-free route in the current route
catalog. A request cannot supply a hostname, IP, URL, onion name, or arbitrary
next-hop key.

```text
BlindForwardOpenV1 {
  version:                u8 = 1
  routeId:                16 bytes
  nextDescriptorHash:     32 bytes
  requestedOuterClass:    u8
  circuitNonce:           32 bytes
  requestedInitialWindow: u32 // 64 KiB..1 MiB
  requestedIdleMillis:    u32 // 1000..120000
  requestedLifetimeMillis:u32 // 1000..3600000
  hopAdmission:           AdmissionV1
  innerHandshake:         bounded opaque bytes
}

BlindForwardOpenResultV1 {
  version:                u8 = 1
  relayPublicKey:         32 bytes
  routeId:                16 bytes
  nextDescriptorHash:     32 bytes
  circuitNonce:           32 bytes
  streamId:               u64 // random nonzero on this authenticated channel
  grantedInitialWindow:   u32 // <= requested, <= 1 MiB
  maxDataBytes:           u32 // 1..65536
  idleMillis:             u32 // <= requested, <= 120000
  lifetimeMillis:         u32 // <= requested, <= 3600000
  openedAtEpoch:          u32
  requestCommitment:      32 bytes
  signature:              64 bytes
}

BlindForwardDataV1 {
  version:          u8 = 1
  circuitNonce:     32 bytes
  offset:           u64
  bytes:            bounded opaque bytes[1..maxDataBytes]
}

BlindForwardWindowV1 {
  version:          u8 = 1
  circuitNonce:     32 bytes
  consumedThrough:  u64
  creditIncrement:  u32 // 1..1 MiB; total credit remains capped
}

BlindForwardCloseV1 {
  version:          u8 = 1
  circuitNonce:     32 bytes
  closeKind:        u8 // 1 FIN(send side), 2 ABORT(both sides)
  finalSendOffset:  u64
  reasonCode:       u8 // generic bounded enum, no app text
}
```

The route binds previous endpoint, next relay key, next descriptor hash, next
endpoint, allowed profile, outer classes, byte limit, stream limit, issued/expiry
epochs, and signatures. The daemon checks the catalog hash and both descriptors
before reserving resources. Unknown, expired, wrong-role, app-specific, or
oversized routes fail before any network connection.

The open-result signature domain is
`hiverelay.blind.forward-open-result.v1` and covers every preceding field. The
OPEN request commitment binds previous relay key, route ID, next descriptor hash,
outer class, circuit nonce, requested window/idle/lifetime, and the hash of the
inner handshake. The `FORWARD.OPEN` request has dispatch `streamId=0`; its result
assigns the stream ID. Subsequent DATA/WINDOW/CLOSE frames use kind 4, zero request
ID, that stream ID, and per-sender monotonic dispatch sequence.

A DATA offset MUST equal the next expected byte offset; no relay reorders or
buffers gaps. A sender may have at most the receiver-granted number of unconsumed
bytes outstanding. WINDOW advances only after bytes are written to the next-hop
bounded queue and prior buffers are released; it never raises outstanding credit
above 1 MiB. At zero credit the adapter stops reading upstream and relies on
transport backpressure. Per-circuit buffers are at most the granted window plus
one `maxDataBytes` frame.

Each direction has independent offsets, dispatch sequence, FIN, and credit. Both
FINs close normally after buffered bytes drain. ABORT, malformed frame, admitted
quota/lifetime/idle expiry, next-hop loss, or daemon shutdown closes both
directions and releases socket, buffers, waiter, route/admission state, and circuit
table entry exactly once. Keepalives do not reset admitted lifetime. No FORWARD
result asserts end-to-end delivery, non-collusion, or privacy.

Every hop performs independent admission before allocating a destination socket,
stream buffer, or circuit. The WAL atomically commits its `FORWARD_RESERVED`
spend/exact retry state before dialing. Entry, exit, and final storage operations
use distinct tokens, spend tags, nonces, and commitments. Completion commits the
bounded result status; exact retry resumes/returns that state and a different
request using the spend tag is replay. Hop admission never replaces final storage
admission, and failure never falls back to an open or direct proxy.

### 8.2 Padded unary envelope and stream chunks

Private unary adapters carry one complete canonical dispatch frame; they never
invent a transport-specific operation schema. Non-bHTTP adapters place the frame
inside this plaintext before end-to-end split-path encryption:

```text
BlindOuterEnvelopeV1 {
  version:       u8 = 1
  outerClass:    u8
  innerLength:   u32 // exact complete BlindDispatchFrameV1 bytes
  innerDispatch: bytes[innerLength]
  randomPadding: remaining bytes to exact outer class
}
```

Outer plaintext classes are universal and exact:

| Class ID | Total plaintext bytes |
| ---: | ---: |
| 1 | 4 KiB |
| 2 | 16 KiB |
| 3 | 64 KiB |
| 4 | 256 KiB |
| 5 | 1 MiB |
| 6 | 8 MiB |

`outerClassBits` advertises these IDs. For this envelope the class covers the
complete plaintext, not Noise/TLS overhead. `innerLength` must be at least the canonical dispatch
header, fit exactly before the remainder, and the dispatch length prefix must
consume exactly `innerLength`; mismatch, nested trailing bytes, wrong class for
the observed plaintext length, or non-exact total is `BAD_ENCODING`. Padding comes
from a CSPRNG, is never compressed, and is ignored only after transport
authentication and all length checks. For split-native paths the complete
envelope is inside the nested client-to-exit Noise session before it enters
FORWARD; hop Noise alone is insufficient because the entry terminates it.

OHTTP is not this proprietary envelope. The OHTTP adapter MUST implement RFC 9458
using RFC 9292 known-length binary HTTP as the HPKE plaintext. Its bHTTP request
has method `POST`, the fixed selected family route, a fixed lowercase app-free
header set, and the complete dispatch frame as content. The response has the
fixed generic status/header mapping and one complete response/error dispatch as
content. Let `base` be the canonical bHTTP encoding with zero padding; the encoder
selects the smallest shared class that fits and appends exactly
`classBytes - byteLength(base)` RFC 9292 zero bytes. The complete bHTTP plaintext
is therefore exactly the class; HPKE adds only the fixed overhead of the advertised
key configuration. Indeterminate framing, truncation shortcuts, nonzero padding,
ambient/app headers, compression, or path/family mismatch fails closed. Byte-exact
vectors freeze control data, headers, paths, status/error mapping, and every class
boundary.

RFC 9458's relay resource maps to one fixed gateway. The client cannot place an
arbitrary target URL in the encapsulated request and the ingress is never an open
proxy. In version 1 the gateway terminates OHTTP into its own generic blind daemon
target. Serving several storage gateways requires several fixed shared,
app-neutral ingress resources and signed route entries. A separate
gateway-to-storage hop is not inferred; it requires a later profile with an
explicit signed bounded next-hop allowlist and its own capture and abuse gate.

Non-bHTTP request and response envelopes likewise use the smallest mutually
advertised class that fits unless a named app-neutral privacy policy chooses a
larger class from the same universal set. All apps share the same ingress pool,
gateway route pool, HPKE suites/config set, class table, and selection policy. Each request
uses a fresh HPKE context while eligible H2/H3 connections are pooled; a per-app or
per-client gateway/key config is nonconforming because it partitions the anonymity
set. Connection, HPKE, and record overhead are reported separately and never
folded into class identity.

Long-lived split streams do not expose a plaintext chunk length to the entry.
`split-native-protomux-v1` fixes its nested record layer as the transport phase of
`Noise_XX_25519_ChaChaPoly_BLAKE2b`; `innerHandshake` is that Noise handshake,
each direction uses its Noise transport nonce/sequence, and tag overhead is
exactly 16 bytes. The nested plaintext is:

```text
BlindStreamChunkPlainV1 { // exact total = wireClass bytes - 16-byte tag
  version:       u8 = 1
  wireClass:     u8 // 1=4 KiB, 2=16 KiB, 3=64 KiB ciphertext
  flags:         u8 // bit 0 FIN; all other bits zero
  contentLength: u32
  content:       bytes[contentLength]
  randomPadding: remainder to (wireClass bytes - 16)
}
```

Maximum content is respectively 4/16/64 KiB minus 23 bytes (seven bytes of
plaintext header plus the tag). The complete nested Noise ciphertext—not this
plaintext—is `BlindForwardDataV1.bytes` and is exactly 4,096, 16,384, or 65,536
bytes. The entry sees wire class, ciphertext, direction, timing, and volume but
not `contentLength`. Forward offsets and credit count ciphertext bytes.

The class is fixed at OPEN and bounded by the signed route. A final short record
is still full class and sets the inner FIN bit; Forward CLOSE completes circuit
teardown. At most the granted window plus one ciphertext record is buffered; zero
credit stops upstream reads. Byte-exact vectors cover the Noise transcript,
nonce/sequence ordering, both directions, segmentation/reassembly, all class
boundaries, tag failures, FIN, and proof that the largest record never exceeds the
65,536-byte DATA cap. Another split adapter must first define and vector an equally
exact nested overhead/record mapping; that dependency spike is a gate, not a v1
assumption or a reason to expose inner length.

### 8.3 Common adapter interface

Every adapter implements the following logical interface; language and runtime are
not prescribed:

```text
TransportAdapter {
  id
  supportedProfiles
  request(endpoint, canonicalRequest, limits, signal) -> canonicalResponse
  open(endpoint, canonicalOpen, limits, signal) -> boundedDuplex
  start(listenerHandles, signal)
  drain(deadline)
  close()
}
```

It MUST:

- pass canonical blind messages unchanged end to end;
- enforce descriptor/route/outer-class limits before allocation or dialing;
- expose bounded read/write queues and propagate half-close, abort, timeout, and
  backpressure;
- pool eligible connections without sharing application cookies or credentials;
- provide only the fixed `LocalDispatchV1` metadata to the daemon;
- never perform a privacy-weakening retry under the same operation; and
- report adjacent-role/profile counters without client, locator, route, or app
  labels.

### 8.4 Required adapters

| Adapter/profile | Required behavior | Claim ceiling before its gate |
| --- | --- | --- |
| Direct HTTPS/Protomux, `direct-blind-v1` | Authenticated endpoint; raw streaming; Protomux protocol name `hiverelay/blind/1` | Storage/payload blindness only; source, Origin, timing, and interest remain visible |
| OHTTP, `split-web-ohttp-v1` | Fresh HPKE context per request, pooled H2/H3, independently operated generic ingress, signed shared key config, fixed outer classes | Storage source separation under ingress/gateway non-collusion; no read-interest claim |
| Protomux split, `split-native-protomux-v1` | Entry forwards an end-to-end Noise stream only to a signed exit route; exit forwards only to signed storage; bounded Protomux channels | Candidate native source separation after role-local capture and non-collusion assumptions |
| MASQUE, `split-native-masque-v1` | Persistent two-hop H3/CONNECT-UDP circuit carrying end-to-end Noise/QUIC blind messages; no per-cell circuit | Candidate native source separation after route, leak, and performance gates |
| Tor, `tor-full-v1` | Full v3 onion endpoint to the local daemon socket; client descriptors and service traffic stay inside Tor; stable isolation token per local session/persona | Tor threat-model source separation; no global-observer or read-interest claim |

The Protomux split and MASQUE profiles are alternatives with the same knowledge
partition: entry sees client and exit, exit sees entry and storage, storage sees
exit and generic blind operations. The entry MUST NOT know the storage endpoint;
the exit/storage MUST NOT receive the original client address. Adjacent roles
SHOULD use distinct relay identities/operators. Different keys are evidence, not
proof of independence.

Ordinary browser Fetch cannot create CONNECT/MASQUE. Browser streaming through
WebTransport/WebSocket is experimental and receives a separate profile after its
own gate. OHTTP ingress app opacity additionally requires cross-browser proof that
an opaque-origin client leaks no stable app discriminator; until then only the
storage role is app-blind.

Strict Tor mode has no clearnet DNS, direct descriptor fetch, UDP/HyperDHT race,
or automatic fallback. The onion endpoint uses a local Unix socket where
available. An operator need not run a public Tor network relay. Tor unavailability
fails closed.

---

## 9. Storage, virtual buckets, and atomicity

### 9.1 Virtual buckets and partitions

At store initialization the daemon generates a random persistent 32-byte
`K_partition`, distinct from identity, receipt, descriptor, transport, cursor,
and admission keys. It is never advertised or shared with another relay. There
are exactly 65,536 relay-local virtual buckets:

```text
virtualBucket = first16bits(HMAC-SHA-256(
  K_partition,
  serviceTag || primaryLocator
))
```

`serviceTag` is the fixed ABI family byte for `CELL`, `INBOX`, or `CORE`.
`primaryLocator` is respectively the random cell slot, physical inbox topic, or
opaque core key. Keying prevents an identical portable locator from landing in a
correlatable bucket number at different relays. Forward retry and descriptor/
admission control records remain in the coordinator's bounded control keyspace;
they do not create a caller-selectable partition namespace. No app, author,
record type, plaintext hash, origin, or client identity is an input.

`K_partition` is included in the encrypted operator backup/recovery contract.
Losing it makes deterministic index recovery impossible. Rotation requires a
complete fenced rebalance and is never coupled to relay identity rotation.

A local `BucketMapV1` maps virtual-bucket ranges to physical shard workers/volumes
and has a monotonically increasing `mapGeneration`. Clients never address a
partition; the external endpoint remains stable. Partitions own segments, indexes,
checkpoints, staging, tombstones, retry pins, and byte accounting, while one
relay-wide coordinator owns the WAL, spend uniqueness, idempotency, epoch floor,
and bucket map. Descriptors expose only coarse aggregate capacity, never the map
or per-bucket traffic.

Version 1 permits one active writer daemon per blind relay identity. Multiple
disks/partitions are supported; active-active multi-host writers are not. A future
distributed transaction backend must pass the same atomic/crash vectors before it
can preserve the protocol profile.

### 9.2 Online rebalance

Rebalance moves complete virtual buckets, never a semantic subset:

```text
STABLE(source, generation)
  -> COPYING(source, target, snapshotRevision)
  -> CATCHING_UP(source, target, walRevision)
  -> FENCED(target, generation + 1)
  -> STABLE(target, generation + 1)
```

The source remains the sole writer through COPY/CATCH_UP while the target copies
a verified snapshot and replays ordered per-bucket WAL deltas. The coordinator
then fences the source and fsyncs the new ownership-map generation plus final delta
in one ordered commit before exposing the target as writer. Reads may consult both
copies but return one state revision. No phase has two unfenced writers.

Crash recovery selects the last fsynced map generation and idempotently resumes or
discards the copy. The source is deleted only after a later verified checkpoint.
Rebalance has bounded concurrency/IO and pauses under foreground-latency, disk-
pressure, clock-unsafe, or integrity-failure conditions. Crash tests stop after
every copy, delta, fence, fsync, map commit, restart, and reclaim transition.

### 9.3 WAL/admission atomicity

The ordered create/append/mirror transaction is:

1. Decode and validate fixed prefixes, caps, signatures, clock, capacity, and
   admission shape without changing state.
2. Stream the exact body into a capped staging object while hashing; fsync the
   object, atomically publish it within its partition, and fsync the directory.
3. Call `admission.prepare()` as a side-effect-free verifier. It returns
   `{ spendTag, requestCommitment, costClass, walCommitRecord }`.
4. Acquire spend and object locks in canonical byte order. Detect exact retry,
   conflict, and spend replay.
5. Append one checksummed WAL commit containing the object delta/reference,
   prepared spend, request commitment, retry result, receipt fields, bucket/map
   revision, and epoch-floor transition; group fsync is allowed.
6. Only after that fsync, make the mutation visible and release the deterministic
   signed result. A group receipt waits for the group fsync that contains it.

A crash before step 5 leaves a reclaimable orphan and unspent token. A crash after
step 5 replays one mutation, one spend, and the same result. There is no separate
authoritative spent database. Reuse of a spend tag with another commitment is
always replay; reuse of a commitment with inconsistent fields is conflict.

Renew/drop/control mutations have no staged blob but use the same lock, WAL, and
result rules. A charged read commits its spend and exact snapshot/result identity
before sending bytes. Uncharged reads are side-effect-free. WAL frames have length,
type, sequence, transaction ID, bucket/map revision, payload hash, and checksum;
recovery truncates only an incomplete torn tail and fails closed on an interior
checksum or sequence break.

Checkpoints are written to a new file, fsynced, atomically renamed, directory
fsynced, and committed by WAL sequence. Startup loads the newest committed
checkpoint and replays forward without scanning ciphertext bodies. Compaction
cannot remove tombstones, spends, retry records, or cursor/admission keys before
their declared horizons.

### 9.4 Charged unary retry pins

Every charged unary operation commits its spend before response bytes can be
lost. The coordinator therefore stores a compact `ChargedUnaryRetryV1`, never a
duplicate response body:

```text
ChargedUnaryRetryV1 {
  version:          u8 = 1
  spendTag:         32 bytes
  requestCommitment:32 bytes
  familyId:         u8
  operationId:      u8
  locatorCommitment:32 bytes
  sourceRevision:   u64
  sourceCommitment: 32 bytes
  resultCommitment: 32 bytes
  reconstruction:   bounded canonical bytes[0..96]
  retryExpiresMinute:u64
  retryState:       u8 // 1 replayable, 2 visibility-revoked, 3 terminal
}
```

The record is at most 256 bytes. It pins the immutable cell/blob or ordered batch
state, inbox WAL range, or exact core fork/head/block/Merkle state required to
reconstruct the same bounded result and signature. `CELL.GET/PROVE/BATCH_GET`,
charged inbox `READ/WATCH`, and `CORE.PROVE` all use this contract. A core adapter
that cannot deterministically pin and regenerate its proof must make prove
uncharged or unsupported. Every regenerated result is checked against
`resultCommitment` before release. Pin expiry is at most 15 minutes. After it, the longer spent-tag
record remains authoritative, so retry cannot charge again even if the response
can no longer be regenerated.

Policy safety overrides response replay. A later operator `SUPPRESS`, owner inbox
`CLOSE`, terminal cell drop/GC, or equivalent core suppression immediately makes
the public retry indistinguishable from ordinary absence and releases byte-serving
eligibility; it never replays bytes merely because an older charged result was
prepared. Replay takes the resource lock and checks the one authoritative current
visibility/state record before following a regeneration reference. Suppress,
drop, close, and GC therefore update only that authoritative record in O(1); they
do not scan or rewrite retry records. Old pins/records age out asynchronously, and
an optional reverse index is bounded and only a reclamation optimization. The
spend remains consumed and retry returns a deterministic generic terminal outcome.
Public `GET/PROVE/READ/WATCH` cannot distinguish never-created, expired,
closed/dropped, suppressed, or reclaimed state.

`FORWARD.OPEN` persists the assigned circuit nonce, stream ID/channel binding,
limits, and terminal state with its spend. An exact retry on the still-live
authenticated channel returns the same signed open result and circuit; it never
dials a second circuit. If the channel/circuit already terminated, the retry
returns its deterministic generic terminal code and never spends or dials again.
Forward retry state contains no buffered application bytes.

---

## 10. Descriptor, identity, and parameter lifecycle

### 10.1 Descriptor

`BlindServiceDescriptorV1` is canonical binary, at most 16 KiB, and signed under
domain `hiverelay.blind.descriptor.v1`. It contains:

```text
BlindServiceDescriptorV1 {
  version:          u8 = 1
  relayPublicKey:   32 bytes
  identitySequence: u64
  previousRelayKey: optional 32 bytes
  previousDescriptorHash:optional 32 bytes
  identityTransition:optional RelayIdentityTransitionV1
  build:            BuildProfileV1
  protocols:        sorted array[1..16] of ProtocolProfileV1
  endpoints:        sorted array[1..16] of TransportEndpointV1
  cellSizeClassBits:u8
  leaseClassBits:   u8
  maxBatchCount:    u16 // <= 64
  maxResponseBytes: u32 // <= 4 MiB
  maxSponsoredCoreLength:u64
  admissionProfiles:sorted array[1..8] of AdmissionProfileV1
  capacityBand:     u8
  issuedEpoch:      u32
  expiresEpoch:     u32 // issued < expiry <= issued + 4
  descriptorNonce:  32 bytes
  signature:        64 bytes
}
```

`ProtocolProfileV1` contains protocol ID, major, minor, and feature bits.
`TransportEndpointV1` contains endpoint ID, transport ID, generic role/profile
bits, canonical URL, optional endpoint key, outer classes, maximum streams, and
optional signed auxiliary URL/hash. `AdmissionProfileV1` contains the admission
profile and scheme IDs, conformance class, role bits, optional evidence-mirror URL,
and parameter hash. Exact field order and caps live in the ABI registry.

Validity is at most four six-hour epochs. Canonical endpoint URLs have no query,
fragment, userinfo, or application label. An onion endpoint contains one v3 onion
host and no clearnet alternate. Auxiliary key/route documents are signed, hashed,
bounded, validity-overlapping, and cannot add a role absent from the descriptor.
`buildManifestUrl`, optional admission `parameterUrl`, and other evidence URLs are
evidence mirrors, not live-path dependencies. A client fetches them only through its already
selected privacy transport or an explicitly separate evidence workflow; inability
to reach a clearnet URL in Tor/OHTTP mode never triggers DNS, direct fetch, or
downgrade. Admission parameters remain available through
`DESCRIBE.ADMISSION_PARAMETERS` on the selected daemon path.

The universal discovery topic is
`BLAKE2b-256("hiverelay.blind.service.v1")`. DHT announcements are signed bounded
pointers to the same descriptor hash, not full descriptors. Bootstrap directories,
bundled keys, peers, and user-entered endpoints are non-exclusive discovery hints.

### 10.2 Identity lifecycle

1. `INIT`: generate/import the dedicated blind identity with restrictive
   permissions; identity sequence is zero and no unsigned blind advertisement
   exists.
2. `ACTIVE`: descriptors, health, receipts, and proofs use this key. Backups are
   operator-controlled and never mounted into application containers.
3. `ROTATING`: the old and new keys sign the same bounded
   `RelayIdentityTransitionV1`, binding adjacent keys, `oldSequence`, exactly
   `oldSequence + 1`, validity, reason, and nonce. The new descriptor embeds that
   transition and the complete signed previous descriptor hash. Both descriptors
   overlap for at most four epochs.
4. `RETIRED`: the old private key is removed from the daemon; clients retain the
   signed transition and reject rollback. Emergency uncompensated loss creates a
   new relay identity and does not pretend continuity.

At sequence zero, previous key/hash/transition are all absent. At every later
sequence, all three are present and the embedded dual-signed immediate transition
must match the descriptor exactly. `DESCRIBE.GET` can fetch a named prior
descriptor hash over the already selected path; there is no embedded clearnet
history URL. The daemon retains at least 16 linked predecessors for one year.
Clients follow at most 16 strictly decreasing, cycle-free sequence/hash links;
deeper or missing history is unwitnessed, not trusted. Expired history is evidence
only and supplies no live endpoint or admission parameter.

### 10.3 Admission parameters

Admission adapters implement only:

```text
AdmissionV1 {
  profileId:       u16
  schemeId:        u16
  parameterHash:   32 bytes
  token:           bounded bytes[1..4096]
}

AdmissionParametersV1 {
  version:          u8 = 1
  relayPublicKey:   32 bytes
  profileId:        u16
  schemeId:         u16
  conformanceClass: u8
  roleBits:         u16
  verifierKey:      bounded bytes[0..4096]
  resourceCosts:    sorted array[1..64] of {
                      familyId: u8, operationId: u8, resourceClass: u8,
                      leaseClass: u8, costUnits: u64
                    }
  tokenMaxBytes:    u16 // <= 4096
  issuanceUrl:      optional canonical URL bytes[1..512]
  issuerRelayKey:   optional 32 bytes
  validFromEpoch:   u32
  expiresEpoch:     u32
  nonce:            32 bytes
  signature:        64 bytes
}

prepare(admission, familyId, operationId, resourceClass, leaseClass,
        requestCommitment, signal)
  -> { spendTag, requestCommitment, costClass, walCommitRecord }
```

`prepare` is side-effect-free. The transaction coordinator is the sole redeemer.
The request's `(profileId, schemeId, parameterHash)` MUST exactly select one
current descriptor profile and fetched signed parameter object. Cost lookup uses
the pair `(familyId, operationId)` because operation IDs collide between families;
no implementation may price by operation ID or display name alone.

The parameter signature domain is
`hiverelay.blind.admission-parameters.v1`, and:

```text
parameterHash = BLAKE2b-256(
  "hiverelay.blind.admission-parameters-hash.v1" ||
  canonicalCompleteSignedParameters
)
```

Parameter state is `PENDING -> ISSUING -> REDEEM_ONLY -> EXPIRED`, with at least
one descriptor overlap epoch between successive sets. Issuance stops before
redemption, and redemption remains accepted through the maximum token lifetime.
The same parameter ID with different bytes is forbidden. Emergency revocation is
signed, descriptor-bound, and reported as a privacy/availability incident; it
never deletes spent records or makes a previously committed write disappear.

Open conformance requires at least one app-free proof-of-work or anonymously
obtainable byte-duration credit. Private bearer admission may exist but cannot
support the permissionless plug-and-play claim. Tokens and cost classes contain no
app/namespace/client identity and are bound to the exact request commitment.

---

## 11. Client-only responsibilities

The blind client, not the daemon, MUST own:

- application encoding, author/member keys, signatures, validation, ordering,
  merge, edits, deletes, moderation, and semantic indexes;
- randomized encryption, padding, chunking, read capabilities, one-time create
  keys, renew/drop keys, and encrypted capability chains;
- separately randomized per-relay replicas for the unlinkable cells profile;
- inbox plaintext format, decryption, signature checking, deduplication, fork
  retention, and polling/watch resume policy;
- Hypercore writer and block-encryption keys plus signed-head verification;
- descriptor verification, privacy profile selection, role/operator diversity,
  explicit downgrade decisions, receipt/proof verification, witnessed floors,
  availability quorum, challenge cadence, and repair;
- durable offline outbox/idempotency state and crash-safe advancement of local
  capability chains; and
- truthful user presentation of the actual path and claim ceiling.

The daemon sees only generic operation IDs, opaque locators/core keys, fixed
classes, coarse leases, adjacent transport role, timing, and volume. This is the
declared residual leakage, not hidden semantics.

---

## 12. Observability and resource safety

Allowed log/metric dimensions are fixed: component, generic operation, protocol
version/hash, transport profile, size/frame/lease/cost class, coarse capacity band,
result code, latency bucket, queue band, and lifecycle state.

Forbidden fields include payloads, locators, topics/inbox IDs, core keys, public
management keys, request/admission tokens, route IDs, IPs, origins, headers,
application strings, exact disk paths, or user-selected labels. Error objects are
mapped to stable codes before logging; stack traces are development-only and
scanned before release. Request bodies are excluded from tracing and crash dumps.

Every queue has a descriptor/configured item and byte cap. Slow producers are
paused; slow consumers are disconnected with a resumable error. Admission happens
before expensive allocation. Per-connection, per-role, global, and disk
high-water caps fail closed with `BUSY` rather than evicting live leased data.

Minimum scale gates on the reference 2-vCPU/4-GiB SSD relay are:

- one million indexed 16-KiB cells restart to ready within 30 seconds without
  scanning blobs;
- steady RSS below 1.5 GiB excluding page cache;
- local 16-KiB GET p99 below 50 ms at 100 clients;
- acknowledged 16-KiB PUT p99 below 250 ms under the declared fsync policy;
- no unbounded watch, forward, core, admission, GC, or repair queue; and
- a seven-day expiry/rebalance/restart soak with zero unrecoverable WAL/index
  drift and accounting error below 1%.

Private-transport benchmarks use identical payload seeds/endpoints and report
network latency separately. No profile opens a connection or circuit per cell.

---

## 13. Cross-application conformance fixtures

Two unrelated applications are mandatory fixtures; neither gets relay code or
configuration.

### 13.1 Fixture A — signed field notebook

This fixture creates small signed text observations, multi-device forks, edits,
encrypted checkpoints, and an open announcement inbox. It uses all cell classes up
to 64 KiB, inbox read/watch, multiple relay replicas, proofs, renew/drop, offline
retry, and client-side merge.

Sentinels include unique app name, author names, record-type strings, logical IDs,
and graph-like links. They appear only inside ciphertext and client state.

### 13.2 Fixture B — binary tile stream

This fixture publishes chunked binary map/sensor tiles, a signed chunk manifest,
a signed-append inbox, and an encrypted transport Hypercore. It uses 256-KiB and
1-MiB cells, Blind Core mirror/prove, forward routes, expiry, replacement, and
range reconstruction in the client.

Its distinct app, producer, media/type, coordinate, and index sentinels likewise
appear only inside ciphertext and client state.

### 13.3 Required combined evidence

Both fixtures MUST:

1. use the same descriptor, spec/ABI/vector hashes, endpoints, media type, operation IDs,
   classes, admission mechanism, route pool, daemon binary, and configuration;
2. run concurrently and after either fixture is introduced post-startup, with no
   restart, plugin, namespace, domain allowlist, key, or metric change;
3. pass Node and Bare vectors; cell/inbox browser vectors also pass supported
   Chromium, Firefox, and Safari/iOS;
4. produce decoded network captures containing no app/author/type/semantic field;
5. produce recursive scans of WAL, checkpoints, partitions, blob filenames, core
   store, logs, metrics, cursor/admission state, and crash diagnostics with zero
   fixture sentinel matches;
6. survive response loss, duplicate/concurrent spend, torn WAL, restart, partition
   rebalance, exhausted watch-waiter cap, killed forward hop, and role shutdown; and
7. demonstrate that adding a third opaque byte producer needs client code only.

A classifier report records residual size, lease, timing, volume, and access
leakage. Absence of sentinel strings alone is not an anonymity proof.

---

## 14. Delivery phases and hard gates

| Phase | Deliverable | Gate to advance |
| --- | --- | --- |
| 0 | Import spec; freeze registry, IDs, domains, limits, errors, vectors, source/hash rules | Independent registry review; same vectors pass Node/Bare; deliberate schema drift fails startup |
| 1 | Dedicated daemon shell, identity, config validation, lifecycle, `DESCRIBE`, raw IPC proxy | OS/container capability test proves no access to app stores/config/keys; abort/close leak test passes |
| 2 | WAL coordinator, virtual buckets, cells, open admission, receipts/proofs | Full crash matrix, double-spend concurrency, clock unsafe, tombstone horizon, million-cell restart/latency gates |
| 3 | Inbox create policies, fixed frames, snapshot read, bounded long-poll watch, expiry | Omission/reorder/flood, cursor, retention, waiter-cap/abort, restart, and 90-day-class cold-start simulations pass |
| 4 | Blind Core isolated adapter | Upstream wire interop, dependency boundary, encrypted-block proof, sponsorship/restart, disk/accounting gates pass |
| 5 | Direct HTTP/Protomux plus Protomux split forwarder | Identical canonical transcript; entry/exit/storage capture proves stated knowledge split; no open-proxy vector passes |
| 6 | RFC 9458 OHTTP ingress/gateway | RFC 9292 bHTTP/class vectors, key rotation, fixed relay-resource mapping, shared key/route pool, two-fixture storage-wire app-opacity capture, performance gate pass |
| 7 | MASQUE adapter | Two-hop route substitution/leak, churn, backpressure, no direct retry, and throughput/latency gates pass |
| 8 | Full Tor onion adapter | Bootstrap/update/error/retry packet capture shows zero clearnet DNS/TCP/UDP and zero downgrade; controlled/public performance recorded |
| 9 | Rebalance, multi-partition soak, release packaging, clean-image proof | Seven-day soak; two fixtures plus late third producer; recursive state/log scan; signed build profile/artifact-manifest evidence pass |

No later transport blocks release of an earlier truthful profile. Conversely, a
compiled adapter is not advertised until its own gate passes. The release verifier
derives claims from evidence and descriptor profile, never feature presence alone.

---

## 15. HiveRelay repository file map

The reviewed HiveRelay repository currently has workspaces for Core, Services,
Client, and Verifier. The strict substrate requires new workspaces because placing
it under `packages/services/builtin` would expose the unrestricted in-process
service context and collapse the membrane.

### 15.1 Add

```text
docs/protocol/BLIND-APP-AGNOSTIC-HIVERELAY-MASTER-SPEC.md
docs/protocol/BLIND-SUBSTRATE-IMPLEMENTATION-SPEC.md

packages/blind-protocol/
  hiverelay-blind-abi-v1.cenc sole canonical ABI/hash input
  registry.js                 generated schema/ID/domain/limit bindings
  codec.js                    bounded canonical encoding
  commitments.js              domain-separated request/signature preimages
  errors.js                   stable errors and HTTP mapping
  descriptor.js               descriptor, pointer, route, health codecs
  vector-manifest-v1.cenc     canonical vector-set/hash input
  vectors/                    byte-exact positive/negative fixture bytes

packages/blind-client/
  cells.js
  inbox.js
  core.js
  admission.js
  discovery.js
  selection.js
  receipts.js
  repair.js
  runtime/{browser,bare,node,pear}.js

packages/blind-daemon/
  cli.js
  daemon.js
  bootstrap-config.js
  lifecycle.js
  ipc.js
  identity.js
  identity-history.js
  build-profile.js
  descriptor.js
  health.js
  transaction/{coordinator,wal,checkpoint,recovery}.js
  storage/{partition-key,buckets,partitions,rebalance,staging,gc}.js
  cells/{engine,receipt,proof}.js
  inbox/{engine,cursor,watch}.js
  core/{adapter,sidecar,accounting}.js
  admission/{interface,pow,privacypass,cashu}.js
  forward/{engine,routes}.js
  observability/{logger,metrics}.js

packages/private-transport/
  interface.js
  profiles.js
  policy.js
  outer-envelope.js
  stream-chunks.js
  direct/{http,protomux}.js
  ohttp/{bhttp,client,ingress,gateway,key-config}.js
  protomux-split/{client,entry,exit}.js
  masque/{client,entry,exit}.js
  tor/{client,onion-service}.js

packages/core/core/relay-node/api-blind-proxy.js
packages/core/core/protocol/blind-profile-binding.js
hiverelay-blind.service

test/fixtures/blind-protocol/
test/fixtures/blind-apps/field-notebook/
test/fixtures/blind-apps/binary-tile-stream/
test/unit/blind-*.test.js
test/integration/blind-substrate-*.test.js
test/integration/blind-transport-*.test.js

scripts/verify-blind-source-consistency.mjs
scripts/generate-blind-build-profile.mjs
scripts/verify-blind-membrane.mjs
scripts/verify-blind-release.mjs
scripts/scan-blind-state.mjs
scripts/bench-blind-substrate.mjs
scripts/test-blind-crash-matrix.mjs
scripts/test-blind-rebalance.mjs
scripts/test-tor-no-clearnet-leak.mjs
```

### 15.2 Modify

| Existing file/area | Required change |
| --- | --- |
| Root `package.json` and lockfile | Add the four workspaces and strict test/verify/bench/release scripts; pin upstream blind-peer generations |
| `packages/core/config/default.js`, `config/loader.js` | Add only generic daemon launcher/socket/role/resource config; reject app keys and unknown settings |
| `packages/core/core/relay-node/index.js` | Supervise/drain the daemon through a minimal launcher; do not use `_buildServiceContext()` |
| `packages/core/core/relay-node/lifecycle-scope.js` | Own subprocess, IPC, timeout, and shutdown ordering |
| `packages/core/core/relay-node/api-route-mounts.js` | Reserve only the five strict routes and well-known descriptor route |
| `packages/core/core/relay-node/api.js` | Delegate raw bounded streams to `api-blind-proxy.js` before JSON/body logging and app rate-limit dispatch |
| `packages/core/core/capability-doc.js` | Embed the exact canonical blind descriptor/hash and build profile; unsigned fallback advertises no strict profile |
| `packages/core/core/network-discovery.js`, `relay-record.js` | Add bounded universal-topic pointer exchange without app catalog fields |
| `packages/core/core/services/{registry,service-catalog,protocol}.js` | Prevent semantic catalog entries from being represented as strict roles; do not register the daemon as an RPC service |
| `packages/core/transports/tor/index.js`, `core/protocol/{forward-relay,relay-circuit}.js` | Reuse only audited byte-pipe/lifecycle portions behind the new adapter interfaces; preserve separate identities/claims |
| `packages/client/index.js` | Export the new blind client as a separate explicit surface; do not alias legacy OutboxLog/shard APIs |
| `packages/verifier` | Verify spec/ABI/vector/artifact hashes, descriptor/route/profile binding, evidence manifest, and no unsigned strict claim |
| `Dockerfile`, `docker-compose.yml`, `docker-entrypoint.sh`, `hiverelay.service` | Separate user/process/volume/socket, health, read-only mounts, limits, and ordered shutdown |
| Release, image-smoke, fleet, and package scripts | Include daemon packages, clean-image membrane test, build profile/manifests, all four hashes, and profile evidence |

### 15.3 Do not extend for the strict path

- `packages/core/core/plugin-loader.js` or the unrestricted ServiceProvider
  context;
- `packages/services/builtin/outboxlog`, `shard-store`, `repairticket`, or any
  semantic service;
- app registry/catalog, author directory, identity, schema, AI, moderation, or
  index APIs; or
- existing JSON service RPC for cells, frames, core blocks, or forwarding.

Those components may remain independently supported, but no compatibility bridge
may be advertised as `hiverelay-blind/1`.

---

## 16. Definition of done

The component is complete only when all of the following are authoritative current
evidence, not plans:

1. The executable registry, vectors, descriptor, build profile/manifests, and
   spec/ABI/vector/artifact hashes agree, and drift fails closed.
2. A clean image runs the dedicated unprivileged daemon with no access to
   application stores/config/keys and advertises no strict role when isolation or
   signing is unavailable.
3. Cells, inbox, core, admission, evidence, discovery, and authorized forwarding
   pass their complete state, crash, replay, resource, and lifecycle matrices.
4. Virtual-bucket rebalance proves single authority at every crash point and the
   seven-day multi-partition soak has no WAL/index/accounting drift.
5. Both unrelated fixtures and a late third opaque producer run against the same
   unchanged daemon/config/descriptor and recursive scans find no semantic data.
6. Every advertised transport passes its separate route, role-visibility,
   downgrade, leak, backpressure, and performance gates.
7. Browser, Node, Bare, and Pear-supported surfaces verify the same canonical
   vectors and results.
8. Public documentation states residual size/lease/timing/volume/access leakage,
   role-separation assumptions, and the absence of semantic, global-observer,
   read-interest, and active-public-reader secrecy claims unless separately proven.

Until then, the descriptor and product language identify each implemented subset
and its measured claim ceiling; they do not call the whole deployment blind or
anonymous.
