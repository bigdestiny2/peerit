# RocksDB-Compatible IndexedDB Storage for Hypercore 11

Status: architecture discovery complete; implementation feasibility spike not started  
Date: 2026-07-12  
First integration: Peerit in a normal browser  
Working package name: `rocksdb-idb` (not yet reserved or final)

## Decision

Proceed with a grant proposal and an early kill-or-continue prototype.

The right target is the JavaScript contract exposed by `rocksdb-native`, as
Mathias suggested. The browser implementation should not simulate RocksDB files
or pretend IndexedDB is a filesystem. It should provide the ordered key/value,
batch, session, snapshot, iterator, and lifecycle semantics that
`hypercore-storage` consumes.

The architecture is feasible on the web-platform primitives available, but the
project should not claim implementation feasibility until WP0 proves the
cross-browser hot path and browser bundle. This is a small storage-engine port
rather than a thin IndexedDB wrapper. The two load-bearing pieces are:

1. MVCC or equivalent versioning for long-lived RocksDB snapshots and
   backpressured iterators.
2. Exclusive browser-writer ownership with a fencing generation, because an
   injected database bypasses Hypercore Storage's native `DeviceFile` lock.

The desired end state is:

> Peerit application code runs Hypercore 11, Corestore 7, and Hyperbee in a
> normal browser using a browser implementation of the `rocksdb-native`
> logical contract. The implementation passes portable upstream storage
> semantics and real-browser crash, reload, quota, and multi-tab tests.

This does **not** mean emulating RocksDB's SST files, WAL files, compaction
engine, caches, or native on-disk format.

## Executive findings

- Current Hypercore no longer accepts `random-access-storage`. Hypercore 11
  binds to `hypercore-storage`, whose current storage engine is RocksDB-backed.
- `rocksdb-native` has no separate backend-neutral conformance package. Its
  `test.js`, plus the Hypercore Storage, Hypercore, and Corestore suites, are the
  executable contract we need to extract and run.
- IndexedDB already gives us ordered binary keys and atomic transactions. Those
  map well to RocksDB write batches and bytewise iteration.
- IndexedDB transactions are deliberately short-lived and automatically
  commit. They cannot safely stand in for a RocksDB snapshot that survives
  arbitrary awaits or stream backpressure.
- A current-value store plus version history is sufficient to implement the
  required snapshot semantics without holding an IndexedDB transaction open.
- Range deletion is the main performance cliff. With no snapshot it can be one
  native IndexedDB request with no JavaScript enumeration, but the user agent
  may still do work proportional to the affected records. Preserving old
  versions explicitly requires JavaScript-visible enumeration in the first
  design.
- Passing an arbitrary IndexedDB database object to `hypercore-storage` is not
  enough today. Hypercore Storage still imports `rocksdb-native`, constructs
  `RocksDB.ColumnFamily`, imports filesystem modules, enters legacy filesystem
  migration for a fresh store, and reads private RocksDB fields.
- A small upstream Hypercore Storage portability seam should be part of the
  grant. A bundler alias plus filesystem shims is acceptable for a prototype,
  not as the final integration.
- Peerit's Hypercore 10/Corestore 6 IndexedDB work is real prior art, but it is
  a different storage contract and layout. It should inform lifecycle and
  browser testing, not become a fake RocksDB filesystem.
- Browser storage is origin-local. A writable app cannot move transparently
  between key-derived Hive gateway hostnames. Peerit needs a stable
  publisher-owned origin, or explicit encrypted recovery/pairing, for writable
  identity continuity.
- Opening only by seed/name on Corestore 7 changes a Corestore 6 compatibility
  core's default key (raw signer public key versus manifest hash). A discovery
  fixture also found a viable continuity path: import the same primary seed and
  first open `{ name, key: oldCoreKey }`. Corestore 7 detected compatibility,
  remained writable, replicated Hyperbee data bidirectionally with the old
  stack, and persisted the alias across reopen. This candidate still needs the
  browser migration gate and strict old-writer fencing before production use.

## Evidence baseline

The upstream snapshot was checked against current npm and upstream source on
2026-07-12:

| Component | Audited version | Relevant fact |
| --- | ---: | --- |
| `rocksdb-native` | 3.17.2 | Current public JS contract; upstream `test.js` is the de facto conformance suite |
| `hypercore-storage` | 3.1.2 | Storage interface to which Hypercore 11 binds |
| `hypercore` | 11.33.5 | Uses `hypercore-storage`; random-access storage is no longer supported |
| `corestore` | 7.11.0 | Accepts a Hypercore Storage object or creates one through Hypercore |
| Peerit direct-browser branch | Corestore 6.18.4 / Hypercore 10.38.2 | Last random-access-storage generation currently pinned in this repository |

Primary upstream snapshots used for the audit:

- [`rocksdb-native` 3.17.2](https://github.com/holepunchto/rocksdb-native/tree/d9875f1bd3b9b5d4ee791f99cae6246950d6b3b1)
- [`hypercore-storage` 3.1.2](https://github.com/holepunchto/hypercore-storage/tree/19d3a0a9405a0c4a672c36bbb42847545fb9fc54)
- [`corestore` 7.11.0](https://github.com/holepunchto/corestore/tree/afbc04b453afdb5c1d94777e56061b84a7c7930e)
- [`hypercore` 11.33.5](https://github.com/holepunchto/hypercore/tree/ddd6c79eb5d545401a380cbca04c708b966ebbdf)

### Peerit evidence and current truth

Peerit already has useful browser-storage and current-stack integration
experience:

- [`js/ra-idb.js`](../js/ra-idb.js) is a truncate-capable IndexedDB backend for
  the old random-access-storage contract.
- [`test/ra-idb.mjs`](../test/ra-idb.mjs) exercises paging, overlapping writes,
  truncation, deletion, reopen, and persistence behavior. All 16 deterministic
  checks passed again during this discovery against its small in-memory
  IndexedDB mock; this is not a real-browser durability test.
- [`test/dht-live.mjs`](../test/dht-live.mjs) proves real Corestore, Hypercore,
  Hyperbee, Hyperswarm, Noise, and Protomux replication on the pinned old stack,
  but it uses RAM storage and a direct local testnet DHT rather than browser
  IndexedDB or the WebSocket relay.
- [`js/dht-transport.js`](../js/dht-transport.js) is the experimental normal-
  browser DHT/Noise path through a blind WebSocket DHT pipe.

There is one documentation/runtime discrepancy that must not be carried into
the grant claim. The current `dht-transport.js` imports `random-access-web`; it
does not currently wire `ra-idb.js`. Older validation notes record a Brave run
using the custom durable adapter, but the checked runtime source has since
diverged. The active `random-access-web` backend is separate from Peerit's
custom adapter and retains the known old RAS/truncate compatibility risk.
Therefore:

- Treat `ra-idb.js` as tested prior art.
- Do not describe it as the current active browser transport storage until it
  is explicitly rewired and revalidated.
- Do not treat it as a path to Hypercore 11. The new adapter is ordered logical
  KV storage, not paged random-access files.

There is also an application-level write gate independent of storage. Current
[`js/app.js`](../js/app.js) enables `requireAtomicWrites` for every writable web
transport. `BridgeGossipSync` then requires `_atomicCommit === true` and
`sync.commit()`, while [`js/dht-adapter.js`](../js/dht-adapter.js) currently
exposes only create/join/append/get/list/range/count/status. The direct DHT
writer therefore remains intentionally fail-closed even after durable current-
stack storage exists.

The Peerit reference integration must add an application-level atomic commit
over a Hyperbee batch/Hypercore Storage atom, but it must not spoof the existing
relay-quorum capability. Keep these receipts separate:

1. local IndexedDB/Hypercore atom committed;
2. signed core head/tree state advanced;
3. independently replicated HiveRelay/seed custody acknowledged.

A local browser commit is not equivalent to the HTTP path's independent durable
relay receipts.

Production `peerit.site` can continue using its signed HTTP/SSE outbox path
while this work is developed. Public `wss://` deployment of the blind DHT pipe
is a separate networking gate; it is not solved by this storage project.

## Design lenses applied

The project brain and developer profiles point to a consistent implementation
shape.

### Mafintosh lens

- Build one sharply scoped primitive with the smallest useful contract.
- Match batch, session, snapshot, iterator, close, suspend, and destroy
  semantics exactly.
- Keep Peerit policy, identities, relays, and application records outside the
  storage package.
- Make examples and tests deterministic enough to become the public contract.

### DMC performance lens

- Keep binary keys binary; do not hex/base64 encode the hot path.
- Use one IndexedDB transaction per storage batch.
- Page iterators and honor stream backpressure.
- Benchmark strict durability, snapshots, range deletion, startup, and bundle
  size before choosing optimizations.
- Treat package exports, browser closure, tests, and benchmark tooling as part
  of the architecture.

### Martin Kleppmann lens

- Name the consistency model: atomic batches, ordered operations, point-in-time
  snapshots, one writer, and fenced takeover.
- Turn every isolation and crash claim into an executable counterexample test.
- Verify all-or-nothing state after termination at each transaction boundary.
- Keep durability, replication, and local commit as different acknowledgements.

### Whyrusleeping lens

- Make the primitive interoperable and independently useful beyond Peerit.
- Use a clear reference implementation, observable lifecycle, and operational
  tests across real runtimes.
- Treat browser failure, restart, quota, and ownership takeover as normal
  operating conditions.

### P2P browser architecture lens

- A browser surface creates additional trust, lifecycle, quota, and origin
  boundaries; it does not remove them.
- Local persistence, network reachability, relay durability, and identity
  recovery are separate layers and need separate claims.

## What must be compatible

### Tier A - Hypercore Storage-required contract

| Area | Required API | Required semantics |
| --- | --- | --- |
| Module | Default database class; `ColumnFamily` export | `new ColumnFamily(name, options)` accepted without native code |
| State | `path`, `opened`, `closed`, `snapshotted` | Public, stable lifecycle state |
| Sessions | `session()`, `columnFamily()`, `snapshot()`, `isRoot()` | Sessions share root state; snapshots inherit the same point-in-time revision |
| Lifecycle | `ready()`, `close()`, `suspend()`, `resume()`, `flush()` | No new I/O after closing; pending work drains or rejects predictably |
| Read batch | `get()`, `flush()`, `tryFlush()`, `destroy()` | Missing is `null`; empty value is an empty buffer; one consistent read view |
| Write batch | `put/delete/deleteRange`, `try*`, `flush()`, `destroy()` | Atomic, operation-ordered, reusable unless `autoDestroy`; range is `[start,end)` |
| Iterator | `gt/gte/lt/lte`, `reverse`, `values`, `limit`, `capacity` | Unsigned bytewise order; point-in-time view; bounded buffering |
| Stream | `streamx.Readable` behavior | `.read()`, events, async iteration, map hook compatibility, destroy/backpressure |
| Maintenance | `compactRange()` | May begin as semantic no-op plus MVCC cleanup hook |

Hypercore Storage specifically exercises:

- multi-get-style read batches;
- atomic batches spanning blocks, Merkle nodes, bitfields, auth, heads, hints,
  aliases, sessions, and multiple cores through storage atoms;
- half-open range deletion for blocks, tree nodes, bitfield pages, local data,
  and whole-core removal;
- forward and reverse byte-ordered streams;
- long-lived storage snapshots.

One deliberate Tier-A MVP deviation must be explicit: independent
`readOnly: true` roots do not open concurrently with the exclusive browser
writer. Read-only sessions inside the owned root work, but a second root waits
or fails. Native `rocksdb-native` has a concurrent read-only-root test; that
case is excluded until a cross-context snapshot-lease/GC protocol is designed,
and must be reported as a capability gap rather than silently claimed as full
API parity.

### Tier B - Portable API completeness after the MVP

Add after the Hypercore integration passes:

- top-level `get`, `put`, `delete`, and `deleteRange` helpers;
- `keys()` and `peek()`;
- compact-encoding key/value sessions;
- arbitrary column-family isolation;
- iterator bounds and limits not already required by Hypercore Storage;
- stats counters, `isIdle()`, `idle()`, and diagnostics;
- batch reuse and constructor-option validation matching upstream quirks.

### Tier C - Explicitly native-only

Do not fake these as meaningful browser features:

- SST, blob, or WAL file-format compatibility;
- native file-descriptor locks;
- WAL filtering, filenames, or native recovery modes;
- Bloom/Ribbon filter behavior;
- RocksDB block caches, table formats, background jobs, or direct I/O;
- physical RocksDB compaction;
- exact range-size estimates or arbitrary RocksDB properties;
- import of an existing native RocksDB directory.

RocksDB tuning options may be accepted for source compatibility, but must be
reported as ignored or unsupported rather than silently represented as active.

## Current upstream integration blockers

A compatible KV object alone will not produce a clean browser build.

### 1. Static native module dependency

`hypercore-storage` imports `rocksdb-native` at module load and constructs:

```js
new RocksDB.ColumnFamily('corestore', rocksOptions)
```

Passing an IndexedDB-backed object is therefore insufficient unless the entire
`rocksdb-native` module is replaced by a browser-compatible export.

### 2. Filesystem imports and recovery

Hypercore Storage eagerly imports `fs`, `path`, and `device-file`. Even for an
injected database object, it derives a filesystem-adjacent path and a fresh
logical store enters version-0 legacy filesystem migration/recovery.

### 3. Private RocksDB coupling

Hypercore Storage currently reads:

- `db._snapshot`;
- `db._state.closing`;
- `db._index`.

It also assigns `iterator._readableState.map`. A prototype can reproduce these
details, but they should not become the public backend contract.

### 4. Native lock bypass

When a database object is injected, `DeviceFile` is skipped. The in-process
scope lock does not prevent two tabs or workers from opening the same writer.

### Recommended small upstream seam

Include a focused Hypercore Storage patch in the grant:

1. Allow an injected database to provide its own `ColumnFamily` constructor or
   `createColumnFamily(name, options)` method.
2. Lazy-load `rocksdb-native`, `device-file`, `fs`, and filesystem migrations
   only for path/native storage.
3. Add an injected/no-filesystem fresh-store path that initializes the current
   logical Hypercore Storage schema without inspecting legacy files.
4. Replace private `_snapshot`, `_state`, and `_index` reads with public
   `snapshotted`, `closing`, and `closed` state.
5. Replace direct streamx internal mutation with a public mapping wrapper or a
   documented iterator hook.
6. Add a conditional browser export, or make the constructor dependency seam
   sufficient for bundlers to exclude native code.
7. Extract a portable storage conformance suite from upstream tests.

The prototype may use a bundler alias from `rocksdb-native` to `rocksdb-idb`
and minimal filesystem shims to discover the remaining closure problems. The
release path should not require a permanent Peerit fork of Hypercore Storage.

## Proposed package boundary

```text
Peerit application and signed outbox protocol
                 |
              Hyperbee
                 |
        Corestore 7 / Hypercore 11
                 |
          hypercore-storage 3
                 |
       rocksdb-native logical contract
          /                     \
 rocksdb-native              rocksdb-idb
 Node / Bare                 normal browser
                                  |
                         IndexedDB + Web Locks
```

`rocksdb-idb` should contain only:

- database state and lifecycle;
- sessions and column families;
- read and write batches;
- snapshots and MVCC bookkeeping;
- streamx iterators;
- encoding helpers;
- ownership/fencing;
- diagnostics and browser capability reporting.

It should not know about Hypercores, HiveRelay, Peerit identities, posts,
outboxes, or gateway policy.

Packaging is part of conformance:

- expose the same CommonJS default-class and attached `ColumnFamily` shape that
  current consumers expect, with an explicit browser condition if a dual export
  is published;
- verify package exports in Node resolution and each supported browser bundler;
- publish type declarations only if they are kept in the conformance matrix;
- normalize relevant IndexedDB `DOMException`s into stable adapter errors while
  preserving the original exception as `cause` (at minimum abort, quota,
  invalid state, data clone, constraint, fenced, closed, and unsupported);
- make ignored RocksDB-only options observable in capabilities/diagnostics and
  reject options whose silent acceptance would change correctness.

Run Hypercore, Corestore, Hypercore Storage, and `rocksdb-idb` together in the
same dedicated/shared worker. This is not an adapter-only RPC worker: keeping
the whole storage stack together preserves synchronous session/snapshot object
construction and avoids structured-cloning every storage call. The main window
owns UX-only actions such as requesting persistent-storage permission;
`StorageManager.persist()` is exposed to Window, while `persisted()` and
`estimate()` can also be queried from a worker.

## IndexedDB data model

Use one IndexedDB database with a fixed small schema. Do not create one object
store per RocksDB column family, because that would require a `versionchange`
upgrade and coordination every time a family appears.

### Object stores

#### `meta`

Stores:

- adapter schema version;
- committed sequence;
- active history epoch;
- next column-family ID and name-to-ID mapping;
- writer owner ID and fencing epoch;
- clean/unclean close marker;
- durability/capability diagnostics;
- resumable maintenance markers.

#### `current`

```text
key:   [columnFamilyId, exactBinaryUserKey]
value: { sequence, deleted, value }
```

This is both the latest-value table and the ordered key index. A separate key
index is not required initially. Tombstones remain here while an older snapshot
or iterator may need key stability.

#### `history`

```text
key:   [historyEpoch, columnFamilyId, exactBinaryUserKey, sequence]
value: { deleted, value }
```

It contains prior committed states written while a snapshot/iterator epoch is
active. Epochs make obsolete history unobservable immediately, so physical
cleanup can remain safely asynchronous.

### Binary representation

- Copy every key to a new `ArrayBuffer` containing exactly the supplied view,
  not its larger backing allocation.
- Store values as exact byte arrays; convert through `b4a` only at the package
  boundary.
- IndexedDB compares binary keys lexicographically as unsigned bytes, matching
  the ordering needed by Hypercore Storage's encoded keys.
- Use compound keys `[cfId, binaryKey]`; the numeric family prefix gives clean
  whole-family bounds.
- Do not hex, base64, JSON, or locale-string encode user keys.
- Represent the commit sequence as fixed-width unsigned bytes (for example,
  eight-byte big-endian) in ordered keys rather than depending on JavaScript's
  `Number` precision forever.

## Write-batch algorithm

Every RocksDB write batch maps to exactly one IndexedDB `readwrite`
transaction over `meta`, `current`, and `history`.

1. Encode and defensively copy all keys and values before opening the
   transaction.
2. Enter the root state's operation scheduler so a snapshot cannot race the
   decision about whether history is required.
3. Open one transaction, requesting `durability: 'strict'` when policy requires
   it and the browser accepts it.
4. Verify `{ ownerId, fencingEpoch }` inside the transaction.
5. Allocate one new commit sequence inside the transaction.
6. Apply queued operations in insertion order.
7. On the first mutation of a key in this batch, preserve its pre-batch state
   under the active history epoch if a live snapshot/iterator can observe it.
8. Apply all later mutations of the same key at the same commit sequence.
9. Store the new committed sequence and batch statistics in the same
   transaction.
10. Resolve operation promises and `flush()` only after the transaction's
    `complete` event. Abort rejects the whole batch.

A single commit sequence per batch is sufficient because no snapshot may see
an intermediate operation in an atomic batch.

For point `delete(key)`, write a `current` tombstone at the new sequence whenever
a retention epoch is active. The older snapshot then finds the key, notices the
newer current sequence, and resolves its archived version; iterators also keep a
stable physical key to scan. A point delete may physically remove `current`
only when the sequencer proves there are zero retention references.

Process range cursors and dependent requests with an event-driven transaction
pump. Do not perform unrelated `await` work after opening a transaction;
IndexedDB can make the transaction inactive between tasks.

### Linearization rule

Snapshot correctness depends on one explicit ordering rule. The root state has
a short operation sequencer, and calls synchronously reserve their place in it:

- write-batch `flush()`;
- top-level `db.flush()` barriers;
- snapshot capture and live-iterator capture at stream `_open`;
- the last retention-reference close/epoch retirement;
- suspend, resume, and close barriers.

The reservation order is the logical order. `db.snapshot()` can still return a
session synchronously, but that session contains a capture promise and no read
may run until its reserved capture completes.

Top-level `db.flush()` reserves behind all earlier writes in the shared root
state and resolves only after each has committed or aborted. It need not force a
second physical browser flush, but it is a real completion barrier rather than
an immediate no-op.

Consequences:

- snapshot reserved before a write captures the pre-write sequence, and the
  write sees the active epoch and preserves history;
- write reserved before a snapshot completes or aborts first, and the snapshot
  captures the resulting committed sequence;
- iterator reserved before a range delete forces the snapshot-preserving delete
  path;
- last snapshot close reserved before a write retires the old epoch first;
- history GC may process only an already-retired epoch and never blocks or
  deletes the newly active epoch.

This closes the otherwise fatal race in which a write decides that no history
is needed, a snapshot captures the old sequence while the transaction is in
flight, and the write then commits without a reconstructable old value.
Differential tests must establish whether upstream has a stricter observable
ordering for these concurrent calls; if so, the sequencer rule must match it.

Required edge cases:

- duplicate puts and deletes in one batch;
- put, range-delete, and reinsert ordering;
- overlapping range deletes;
- missing value versus stored empty value;
- batch destroy before flush;
- batch reuse after success;
- quota or request failure after any queued operation;
- stale writer fencing failure before any mutation;
- snapshot creation during a successful and aborted `flush()`;
- iterator creation during range deletion;
- lazy iterator construction followed by a write before first consumption;
- parent snapshot-session close with a live derived batch/iterator;
- pre-open snapshot on both a fresh and an existing database;
- last snapshot close during a write and during background GC.

## Read-batch algorithm

- Queue all gets synchronously and open one short read-only transaction on
  flush.
- A live session reads `current` directly.
- A snapshot session first reads `current`; if its sequence is newer than the
  snapshot, query only the snapshot's history epoch for the greatest version
  less than or equal to the snapshot sequence.
- A tombstone resolves as `null`; an empty stored buffer remains distinguishable
  from `null`.
- `tryFlush()` starts work without returning the aggregate completion promise,
  while each queued get promise still resolves or rejects.
- Resolve a batch only after its transaction completes successfully.

## Snapshot and iterator model

### Why a held-open transaction is rejected

IndexedDB transactions are expected to be short-lived and automatically commit
when their request list is exhausted. A RocksDB snapshot may survive arbitrary
application awaits, child sessions, and stream backpressure. Keeping a dummy
cursor/request alive is browser-fragile and would block writers.

Therefore snapshots use MVCC.

### Snapshot creation

- `db.snapshot()` synchronously returns a session object.
- The session captures the current committed sequence and active history
  epoch.
- When the retention-reference count changes from zero to one, allocate a new
  history epoch through the root scheduler before the snapshot becomes
  readable. This metadata change does not advance the logical data commit
  sequence. Overlapping snapshots and iterators share that epoch.
- If created before `db.ready()`, register it with opening state and capture the
  persisted `meta.committedSequence` after the database opens but before
  `ready()` resolves. A fresh store therefore captures empty state; an existing
  store includes all pre-existing records, and both exclude later writes.
- Child sessions inherit the same snapshot sequence.
- Model the point-in-time view as one shared snapshot descriptor
  `{ sequence, historyEpoch, refs }`. Every derived snapshotted session and every
  batch/iterator handle created from it increments that descriptor. Closing the
  parent session does not retire its epoch while a derived session, read batch,
  or iterator remains alive. Handle end/destroy and session close decrement
  explicitly; correctness must not depend on `FinalizationRegistry`.

### History retention

For the first correct implementation:

- Treat every live explicit snapshot and every iterator as a history-retention
  reference.
- Preserve all overwritten states in the active history epoch while at least
  one reference is live.
- Snapshot reads query only the epoch captured by that snapshot. A new epoch is
  therefore isolated immediately from records left by an earlier epoch.
- On the last reference closing, mark that epoch obsolete with its committed-
  sequence cutoff. Compact that epoch's history in the background. A `current`
  tombstone may be physically removed only if its sequence is less than or
  equal to the retired cutoff; newer-epoch tombstones must not be touched.
  Correctness must not wait for physical deletion.
- On restart, no RocksDB-style snapshots survive. Allocate a new history epoch;
  `current` remains authoritative and crash-left history is ignored. Clear old
  epochs in bounded background maintenance rather than a database-size startup
  scan.
- Keep crash-left current tombstones harmlessly until bounded background
  compaction; do not make `ready()` scan every key.

The epoch is required even in the first version. Without it, a new snapshot
could accidentally consult stale history while asynchronous cleanup from a
previous snapshot is still running. An optimized later version can additionally
retain only versions needed by the minimum set of live snapshot sequences.

Persist background maintenance as a resumable marker
`{ retiredEpoch, cutoffSequence, lastPhysicalKey }` and scan bounded pages. This
lets a crash restart cleanup without an unbounded transaction and prevents an
old-epoch collector from deleting current records created after its cutoff.

### Iterators

An iterator created from a live session captures an implicit snapshot
sequence/epoch at stream `_open`/first consumption, not necessarily when
`db.iterator()` constructs the lazy stream object. An iterator created from an
explicit snapshot inherits that snapshot's sequence and epoch, taking only its
own lifecycle reference; it must not capture a newer implicit view. Destroying
an unopened iterator releases its database handle without creating an epoch.

- Return a real `streamx.Readable`.
- Read at most `capacity` visible entries per `_read` call.
- Use short read-only transactions per page, with a separate hard limit on
  **physical current keys scanned** per transaction. A snapshot can contain a
  long run of post-snapshot keys or tombstones; visible-entry `capacity` alone
  must not allow one `_read` to scan the entire database.
- Resume from the last **physically scanned** `current` key, not an offset or
  merely the last emitted key. A page can contain only post-snapshot keys or
  tombstones; resuming from the last emitted key would repeat that invisible
  page forever.
- Keep current tombstones until the iterator closes, so a delete cannot make
  pagination skip an older key.
- Skip keys created after the iterator snapshot.
- Resolve overwritten/deleted keys through `history` only when their current
  sequence is newer than the iterator snapshot.
- Count `limit` against emitted entries, not physical versions or tombstones.
- Release the implicit snapshot on normal end, error, or destroy.

This keeps memory proportional to page capacity rather than database size and
does not hold an IndexedDB transaction open while a consumer is paused.

## Range deletion

`deleteRange(start, end)` is half-open: `[start,end)`.

### Single-request path: no snapshots or iterators

Use `IDBObjectStore.delete(IDBKeyRange)` over the compound `current` key range.
This remains one native IndexedDB range request and does not enumerate every
record in JavaScript. The specification does not promise constant-time work:
large deletes may still be internally `O(n)`, take a long time, or abort, so the
no-snapshot case remains in browser performance and fault-injection gates.

### Snapshot-preserving path

When a snapshot or iterator is active:

1. Enumerate affected current keys inside the same write transaction.
2. Preserve each pre-batch state once in `history`.
3. Write a current tombstone at the new commit sequence.
4. Respect earlier and later operations in the same batch.

The same retention rule applies to point deletion: archive the pre-batch value
and leave a current tombstone. Physical point/range removal is permitted only
with zero retention references.

This path is `O(number of affected keys)` and is the first major benchmark
target. It is correct and keeps the initial design small.

If large snapshot-preserving truncations fail the performance gate, add
versioned logical range tombstones and incremental compaction in a later phase.
That optimization changes point-read and iterator algorithms and should be
justified by measurements, not included casually in the MVP.

## Column families

- Assign each family a stable numeric ID stored in `meta`.
- Register constructor-supplied and pre-open families before `ready()` resolves.
- `columnFamily()` and `session({ columnFamily })` accept either a family name or
  a `ColumnFamily` instance. Hypercore Storage passes an instance, not a string.
- Session construction remains synchronous even when a new pre-open family's
  numeric ID is not allocated until `ready()`. Store the family descriptor/name
  on the session, then resolve and deduplicate object/name registrations during
  open.
- After open, match upstream unknown-family and create-missing behavior exactly;
  do not allocate a new ID merely because another object has the same name.
- `columnFamily()` returns a session sharing the root connection and ownership.
- Isolate families through the first compound-key element.
- Accept Hypercore Storage's RocksDB tuning options for source compatibility,
  while reporting which are ignored.
- Differential-test object/name deduplication, pre-open registration, and
  post-open unknown families.

## Writer ownership and multi-tab correctness

IndexedDB serializes overlapping write transactions, but that is insufficient.
Two Hypercore instances can independently read the same head into memory and
produce conflicting writer state. Native Hypercore Storage normally prevents
this through its file/device lock; injection skips it.

### Ownership protocol

1. A root opens under an exclusive Web Lock derived from the origin and database
   identity.
2. Any fresh-root acquisition under that exclusive lock mints a new epoch. This
   covers a genuinely fresh database, a cleanly closed predecessor, a fresh
   root taking over an intentionally suspended owner, and a new process after
   an unclean abandoned owner. It uses a strict IndexedDB transaction to run
   any needed recovery, write a random `ownerId`, and increment the fencing
   epoch. A merely frozen unsuspended owner still holds the Web Lock and
   therefore cannot be mistaken for an abandoned crash. Only `resume()` tries
   to preserve and compare an old token.
3. Every write transaction compares its cached `{ ownerId, epoch }` with `meta`
   before any mutation.
4. A stale or resumed owner receives an explicit `FENCED` error.
5. Never use Web Locks `steal`; it can leave old code executing without
   exclusivity.
6. `wait: true` may queue for ownership. Non-waiting opens fail clearly rather
   than creating a second writer.

Resume is different from fresh open. After reacquiring the Web Lock, a suspended
root first compares the retained `{ ownerId, epoch }` with `meta`. If either
changed, resume fails permanently and must not mint a new epoch, even if the
intervening owner has already closed. This matches the upstream takeover rule
and prevents a stale root from overwriting evidence of an intervening writer.

MVP ownership invariants:

- at most one root returns writable `ready()` for an origin/database;
- every committed write observes the current fencing epoch inside its atomic
  transaction;
- a stale root rejects before mutation;
- after suspend, all reads/writes/iterators remain blocked until ownership is
  reacquired and the fencing epoch is checked;
- if another owner took over, the old root's resume and pending reads/iterators
  reject rather than continuing on stale snapshots;
- history GC runs only under valid exclusive ownership, against a retired
  history epoch, with no live reference to that epoch.

For the first release, keep one root database owner per origin/database,
including browser read-only roots while a writer is active. Other tabs can wait
or proxy to the owner. Shared read roots require a cross-context snapshot lease
registry and can be added later.

Require Web Locks for the MVP browser floor. If Web Locks are unavailable,
return an explicit unsupported/unsafe-ownership error rather than silently
running multiple roots. A CAS lease fallback is a separate follow-on protocol:
it needs expiry, renewal, monotonically increasing fencing, mandatory checks on
stale reads as well as writes, and cross-context snapshot leases before history
can be collected safely. Heartbeat expiry alone is not authority because a
background tab can be frozen and resume later. `BroadcastChannel` may carry
coordination messages but is not a correctness primitive.

## Lifecycle state machine

Use an explicit shared root state:

```text
NEW -> OPENING -> OPEN -> SUSPENDING -> SUSPENDED -> OPEN
                         \-> CLOSING -> CLOSED
```

Required behavior:

- sessions share one connection, operation scheduler, owner, and counters;
- `ready()` is idempotent and surfaces blocked schema upgrades;
- install `onversionchange` immediately. Treat it as a fatal lifecycle
  transition for that root: stop admitting work, move out of `OPEN`, reject or
  park handles according to the close/suspend contract, close the connection,
  and release ownership. Never leave a logically open owner whose IDB
  connection can only throw `InvalidStateError`; require an explicit reopen;
- handle the IDBDatabase abnormal `close` event (for example storage clearing
  or an underlying failure) through the same fatal transition;
- report `blocked` upgrades and ask other same-origin contexts to close;
- root `close()` marks state closing, rejects new work, waits for active I/O and
  handle/session references according to upstream behavior, then closes
  IndexedDB and releases ownership. Do not auto-destroy iterators, batches, or
  snapshots merely for convenience: an unconsumed handle can intentionally
  keep native close pending;
- `close({ force: true })` closes child sessions deterministically; exact
  handling of still-live batches/iterators must be differential-tested and any
  fail-fast deviation documented;
- destroying an unflushed batch rejects queued promises and releases
  references; destroying while its request is in progress follows the upstream
  error rather than silently aborting;
- `suspend()` drains I/O, closes the connection, and releases ownership;
- `resume()` reopens and reacquires ownership, or fails/waits if another root
  took over;
- I/O requested while `SUSPENDED` is parked in an ordered pending list outside
  the normal operation sequencer. `resume()` and `close()` use a lifecycle
  control lane, so they cannot deadlock behind parked work. Successful resume
  reinserts pending I/O in original order; close or fencing rejects it;
- large data migrations use resumable phase markers and bounded transactions;
  keep `versionchange` transactions limited to schema changes.

Test forced upgrade and database deletion from another same-origin context,
including a pending batch and iterator in the old root.

## Durability, quota, and recovery

### Three different acknowledgements

Peerit must keep these states distinct:

1. IndexedDB transaction committed.
2. Strict durability was requested and accepted as a browser hint.
3. The signed outbox/head was replicated and acknowledged by independent
   HiveRelay/seed custody.

`durability: 'strict'` is a hint to the user agent, not a portable `fsync`
guarantee. `flush()` can guarantee that prior adapter transactions completed;
it cannot honestly promise RocksDB's exact physical-disk behavior.

### Browser storage policy

- From the main window, request `navigator.storage.persist()` after meaningful
  user engagement and display whether it was granted.
- Query `persisted()` and `estimate()` for diagnostics.
- Treat estimates as approximate and still catch `QuotaExceededError`.
- Never loop indefinitely on quota failures.
- Never delete writer-owned, unreplicated records to make space silently.
- Identify private browsing as ephemeral when detectable; always document it as
  non-custodial.
- Keep encrypted identity export/device pairing and remote replication as
  recovery requirements.
- After a local rollback or eviction, reconcile against signed remote heads
  before permitting new writer appends, avoiding an undetected local fork.

Web storage is initially best-effort and can be evicted. Persistence permission
improves the policy but does not turn a browser profile into permanent custody.

## Public HTTPS Hive gateway implication

The Storage Standard keys browser storage at minimum by origin, and browsers
may partition it further by top-level site or storage bucket. These are separate
stores:

```text
https://peerit.site
https://<app-key>.relay-a.example
https://<app-key>.relay-b.example
https://publisher.example
```

Each origin gets its own:

- Hypercore IndexedDB databases and the existing `peerit-identity` IndexedDB;
- Web Lock namespace;
- Service Worker scope;
- cached releases and head/release floors;
- encrypted identity vault and browser-held writer keys;
- pending atomic-commit marker and other origin-local recovery state.

Serving exact signed bytes from two domains does not merge those storage
buckets. An iframe storage broker is not a sound solution: storage partitioning
makes it fragile and it recreates a privileged central origin.

### Required gateway policy for writable apps

- Use a stable publisher-owned origin for the writable identity-bearing app.
- Move DNS/TLS/routing between blind gateways behind that stable origin.
- Bind each local database/profile on first use to the canonical signed app/drive
  key, and fail closed or require an explicit new profile if the same publisher
  domain is later rebound to a different key. Same-origin continuity otherwise
  gives the newly served app access to the old origin's state.
- Use key-derived operator domains for bootstrap, read-only access, emergency
  recovery, and verification.
- If the origin genuinely changes, require encrypted identity import, device
  pairing, or an explicit signed writer/core rotation.

This should become a readiness gate for the deferred public HTTPS Hive gateway.
The gateway spec already anticipates publisher-owned domains; this storage work
makes them mandatory for seamless writable continuity, not merely a branding
feature.

This is a writable Peerit deployment rule, not a claim that the T1 HTTPS
gateway itself provides replication or custody. Exact-byte gateway delivery,
outbox replication, and independent HiveRelay/seed durability remain separate
components and acknowledgements.

## Peerit migration from Hypercore 10/Corestore 6

There is no direct/zero-copy reopen of the old IndexedDB layout as current
Hypercore Storage:

- the old random-access layout (custom `ra-idb.js` or `random-access-web`) is
  paged/file-oriented;
- the new layout is ordered logical KV for Hypercore Storage;
- the databases should use different names and remain independently readable
  during rollout. Explicit import or cross-version replication is feasible and
  is the preferred migration mechanism.

### Core-key compatibility hazard

Peerit's current direct path opens a named core:

```js
store.get({ name: 'outbox:' + appId })
```

Corestore 6 defaults to legacy compatibility-key behavior, where the core key
is the signer public key. A fresh Corestore 7 named open defaults to a
manifest-derived Hypercore key. The same primary seed and name therefore derive
the same signing keypair but, by default, a different Hypercore key/discovery
key.

The Corestore primary seed is distinct from Peerit's Ed25519 record identity.
The former derives the Hypercore writer/core; the latter signs Peerit records.
Both need continuity, but they authorize different layers and live in different
storage.

The discovery reproduced a promising same-key import/replication migration with Corestore
6.18/Hypercore 10 and Corestore 7.11/Hypercore 11:

1. Import the same Corestore primary seed into the new store.
2. First open the core as `store.get({ name, key: oldCoreKey })`.
3. Corestore 7 detects the legacy compatibility core and keeps it writable.
4. The old and current stacks replicate Hyperbee records bidirectionally.
5. After closing/reopening Corestore 7, `get({ name })` follows the persisted
   alias back to the old key.

This makes same-key import/replication the leading migration candidate, not a
guess. It still needs a browser/IndexedDB fixture, crash tests, and upstream
confirmation that the behavior is intended to remain supported.

Before migration, build a fixed fixture that proves:

- old Corestore primary seed and namespace, separately from the Peerit identity;
- old named outbox key and discovery key;
- current-stack result under every relevant manifest/legacy option;
- ability or inability to reopen and replicate the old core;
- matching length, fork, Merkle roots/signature, and Hyperbee contents before
  cutover;
- signed record continuity after logical replay.

Migration safety order is mandatory:

1. Open the new stack with the explicit old core key.
2. Replicate/import and verify the complete old head before any current-stack
   append.
3. Record a signed cutover head/floor.
4. Permanently fence the Corestore 6 writer.
5. Only then permit Corestore 7 to append.

The same signing keypair on two unfenced stacks can create a conflicting fork;
successful key continuity increases the importance of the single-writer
cutover.

Keep two migration outcomes available:

1. **Same-key import/replication** (preferred candidate), using the reproduced
   `{ name, key: oldCoreKey }` path after full-head import and old-writer
   fencing.
2. **Signed core supersession**, create a new current-stack outbox and publish a
   versioned identity-signed rotation linking old core, new core, identity,
   cutover head, and monotonic anti-rollback floor. This fallback also requires
   dissemination through the old core and HTTP directory, old/new-core merge
   support during cutover, replay rejection, and changes to the current adapter
   (which presently keeps one core per `appId` and ignores later descriptors for
   an already-known author).

Peerit's inner Ed25519-signed records make logical replay and signed
supersession viable, but neither should be implicit.

### Rollout safety

- Keep the old database read-only after cutover until the new core, records,
  remote acknowledgements, and reload behavior verify.
- Do not let two storage generations append as the same writer concurrently;
  after the signed cutover, fence the old writer permanently rather than merely
  preferring the new one.
- Use a new feature flag/profile and database name for the prototype.
- Preserve the HTTP/SSE signed outbox path as a recovery/production route, but
  do not call boot-time transport fallback data continuity. Peerit does not
  currently mirror DHT-only writes into HTTP OutboxLog; exact signed commits and
  heads must be bridged and reconciled before the two transports are a true
  failover pair.
- Treat public DHT/WebSocket deployment as an independent release gate.

## Conformance strategy

There is no upstream standalone storage conformance suite today. Create one by
extracting backend-portable behavior from:

- [`rocksdb-native/test.js`](https://github.com/holepunchto/rocksdb-native/blob/d9875f1bd3b9b5d4ee791f99cae6246950d6b3b1/test.js);
- [`hypercore-storage/test`](https://github.com/holepunchto/hypercore-storage/tree/19d3a0a9405a0c4a672c36bbb42847545fb9fc54/test);
- current Hypercore and Corestore integration suites.

Run the same portable trace against native RocksDB and IndexedDB and compare
observable results.

### Contract tests

- open, close, forced close, suspend, resume, session refcounts;
- pre-open and nested snapshots;
- batch reuse, auto-destroy, destroy-before-flush;
- missing versus zero-length values;
- column-family isolation and pre-open family creation;
- all iterator bounds, reverse, limits, key-only mode, and early destroy;
- empty key and empty-bound upstream quirks;
- string/compact encoding behavior;
- stable error classification and preserved DOMException causes;
- CommonJS/browser exports and attached constructor properties;
- ignored, unsupported, and correctness-changing constructor options.

### Differential/property tests

Generate identical randomized traces for both backends covering:

- binary keys `00`, `0000`, `00ff`, `01`, `7f`, `80`, `ff` and prefixes;
- repeated put/delete of one key in a batch;
- overlapping and adjacent half-open range deletes;
- put -> range delete -> put ordering;
- concurrent independent read and write batches;
- forward/reverse scans at every bound combination;
- snapshots interleaved with overwrite, delete, range delete, and reinsert.

### Fault-injection tests

- abort at every request boundary;
- quota failure during a multi-core atom;
- worker/page termination before commit and immediately after commit;
- close and suspend with pending reads, writes, and iterators;
- blocked upgrade and old-tab `versionchange` handling;
- unclean restart with stale history/tombstones;
- stale owner waking after fenced takeover.

After reopen, state must equal exactly the complete pre-batch state or complete
post-batch state. A partially applied Hypercore Storage atom is always a failure.

### Real-browser matrix

- Chromium and Brave;
- Firefox;
- WebKit/Safari;
- Android Chrome;
- real iOS/iPadOS Safari for lifecycle and eviction-sensitive checks.

`fake-indexeddb` is useful for fast unit tests, but cannot validate browser
transaction scheduling, durability hints, quota, worker termination,
`versionchange`, or cross-tab ownership.

### Current-stack integration gates

1. Hypercore create, append, get, clear, truncate, snapshot, close, and reopen.
2. Sparse replication between two browser contexts.
3. Corestore named cores, namespaces, listing, groups, sessions, and multi-core
   atoms.
4. Hyperbee put/get and forward/reverse range streams.
5. `core.audit()` after injected crashes.
6. Browser bundle contains no native addon or unresolved filesystem dependency.

### Minimal Peerit reference-integration gate

Using fresh current-stack databases and a controlled local/testnet transport,
two browser contexts must:

- create a Peerit identity and named outbox;
- expose an application-level local atomic-commit path backed by a Hyperbee
  batch/Hypercore Storage atom, without claiming remote custody;
- append and verify representative signed records;
- replicate one outbox in both directions;
- close completely and reopen with the same current-stack core identity;
- prove the final bundle contains the current stack and no native/filesystem
  closure.

This reference gate must not depend on a public `wss://` relay, a production
Hive gateway, legacy-store migration, or HTTP/SSE cutover.

### Peerit product-rollout gate (follow-on)

The full product rollout then makes two independent browsers:

- create or restore their identity and outbox;
- exchange signed community, post, comment, vote, edit, and delete records;
- replicate through the blind DHT/WebSocket pipe on the current stack;
- close completely and reopen with the same intended core identity;
- converge after offline writes;
- truncate/repair without losing verified records;
- compare and reconcile signed heads through HiveRelay;
- after an explicit signed-head/commit bridge exists, fail over to the HTTP/SSE
  path without granting the relay authorship.

## Performance plan

Benchmark the adapter against a minimal direct-IndexedDB reference. Native
RocksDB is useful context but is not a fair browser latency target.

### Workloads

- sequential values at 1 KiB, 16 KiB, and 256 KiB;
- write batches of 1, 8, 16, 64, 128, 256, and 1,000 operations;
- 100-key read batches;
- forward/reverse scans over 10k, 100k, and 1m keys;
- snapshot reads while live keys are overwritten and truncated;
- range deletion at 1k, 10k, and 100k keys, with and without snapshots;
- many-core reopen and Corestore listing;
- near-quota writes and transaction abort;
- relaxed versus strict durability;
- Peerit append-to-visible and replication-to-visible latency;
- bundle size, startup time, memory, event-loop delay, and history amplification.

### Initial acceptance properties

- no database-size-proportional startup scan;
- memory proportional to iterator page capacity, not database size;
- ordinary adapter/Hypercore storage work runs in the stack worker, with only
  explicit worker messaging attributable to it on the UI thread;
- no-snapshot range deletion remains an IndexedDB range operation;
- history growth is limited to keys changed while snapshots/iterators are live;
- forced crash never exposes a partially applied atom;
- browser bundle contains no `.node`, RocksDB binding, or live `fs` dependency.

WP0/WP1 establish fixed reference devices, browser versions, datasets, and a
direct-IndexedDB baseline. Ratify absolute p50/p95/p99 latency, throughput,
memory, write-amplification, bundle, and UI-thread messaging gates from that
evidence; do not put arbitrary ratios in the grant acceptance criteria.

## Grant work packages

The reusable storage grant is WP0-WP5, WP7, and the minimal Peerit reference
proof in WP6. Legacy Peerit migration, signed core supersession, public gateway
origin rollout, public DHT hosting, and production HTTP/SSE cutover are product
follow-on work documented here because they affect Peerit's eventual adoption,
not because the storage grant must deliver them.

### WP0 - Contract freeze and harness

- Record exact upstream commits and API traces.
- Extract portable `rocksdb-native` tests.
- Build the native-versus-IDB differential runner.
- Define explicit native-only exclusions.
- Complete a three-engine feasibility spike proving binary compound-key order,
  atomic ordered batches, one long-lived MVCC snapshot, one paged stable
  iterator, and a current Hypercore Storage browser bundle closure path.

Kill/redesign condition: any engine cannot preserve required binary order or
atomicity; a page-bounded snapshot/iterator requires a held-open transaction;
or current Hypercore Storage cannot be made browser-closed with a small seam.

Exit: contract matrix and differential harness published, feasibility evidence
recorded, and upstream feedback requested.

### WP1 - Ordered KV, batches, and lifecycle

- Fixed IndexedDB schema and direct binary keys.
- Column-family sessions.
- Atomic read/write batches and half-open range delete.
- Open/close/destroy/flush/suspend/resume state machine.
- Stats and diagnostics sufficient to debug lifecycle leaks.

Exit: portable non-snapshot contract tests pass in three desktop engines.

### WP2 - Ownership and fencing

- Web Lock ownership.
- Persistent owner ID/fencing epoch.
- Mandatory per-write check.
- Takeover, stale wakeup, wait/fail behavior, stale-read rejection, and an
  explicit unsupported result without Web Locks.

Exit: multi-tab kill/takeover suite cannot produce two accepted writers.

### WP3 - MVCC snapshots and iterators

- Commit sequence and history.
- Pre-open/nested snapshot behavior.
- Paged point-in-time streamx iterators.
- Retention, destroy, restart cleanup, and compaction.
- Snapshot-aware range deletion.

Exit: RocksDB and Hypercore Storage snapshot/stream suites pass.

### WP4 - Hypercore Storage portability seam

- Backend-provided column family.
- Filesystem-free injected-store bootstrap.
- Public lifecycle/snapshot state.
- Browser-clean exports and bundle closure.
- Upstream test/conformance proposal.

Exit: portability PR submitted and a reproducible temporary compatibility path
imports Hypercore Storage in a normal browser without a reachable native or
filesystem implementation. Upstream merge remains a release objective, not a
milestone controlled by the grantee.

### WP5 - Hypercore 11/Corestore 7/Hyperbee

- Run storage, atomic, group, snapshot, stream, Hypercore, and Corestore suites.
- Prove append, truncate, sparse replication, close/reopen, named cores, and
  multi-core atoms.
- Audit and fix only contract mismatches, not Peerit-specific behavior.

Exit: current stack passes in supported real browsers.

### WP6 - Minimal Peerit reference integration

- Fresh current-stack Peerit profile/database.
- Representative signed outbox records.
- A distinct local atomic-commit capability/receipt for the DHT adapter; do not
  set the existing durable-relay `_atomicCommit` flag merely because IndexedDB
  committed.
- Two-browser convergence over a controlled transport.
- Close/reopen identity and core continuity.
- Reproducible example and browser bundle audit.

Exit: minimal Peerit reference gate passes without public infrastructure or
legacy migration dependencies.

### WP7 - Hardening and release

- Fault injection, quota, storage pressure, version upgrades, and mobile tests.
- Cross-browser performance baselines and optimizations.
- Documentation of durability and native-only exclusions.
- Upstream packages/PRs and reproducible Peerit example.

Exit: all readiness gates below pass with published evidence.

### Peerit product follow-on - migration and public rollout

- Corestore 6/7 core-key compatibility fixture.
- Same-key import/replication or the fuller signed-rotation fallback.
- New database/profile and cutover state machine.
- Full two-browser Peerit convergence and offline repair.
- Signed HiveRelay head reconciliation and bridged HTTP/SSE failover.
- Stable publisher-origin routing across blind public gateways.

## Readiness gates

### Storage grant release gates

1. **Contract gate** - exact supported API and native-only exclusions agreed.
2. **Atomicity gate** - no injected crash exposes a partial write batch/atom.
3. **Snapshot gate** - long-lived, nested, and pre-open snapshots pass.
4. **Iterator gate** - byte order, reverse, bounds, backpressure, and destroy
   pass with page-bounded memory.
5. **Ownership gate** - stale multi-tab writers are fenced after takeover.
6. **Packaging gate** - no native binding or active filesystem path in browser.
7. **Current-stack gate** - Hypercore 11/Corestore 7/Hyperbee integration passes.
8. **Browser gate** - supported desktop/mobile engines pass real-browser tests.
9. **Reference gate** - fresh Peerit browser contexts commit locally, persist,
   replicate over a controlled transport, reopen, and keep local versus remote
   durability receipts distinct.

### Peerit product-adoption gates

10. **Migration gate** - old core identity behavior is known and the chosen
    transition is signed, resumable, and rollback-safe.
11. **Durability gate** - quota, persistence status, strict hint, remote receipt,
    and rollback reconciliation are observable separately.
12. **Origin gate** - writable public deployment uses a stable publisher origin
    or explicit identity/core recovery on origin change.
13. **Peerit gate** - two browsers persist, replicate, reopen, repair, and
    converge on the current stack.

## Open decisions

1. Final package name and ownership: separate `rocksdb-idb`, a conditional
   `rocksdb-native` export, or a Holepunch-owned browser sibling.
2. Whether the portable conformance suite lives in `rocksdb-native`, a separate
   package, or both repositories.
3. Exact Hypercore Storage backend-construction API.
4. Follow-on design for concurrent independent read-only roots and
   cross-context snapshot leases; the MVP waits/fails behind the owner.
5. Whether a future non-Web-Locks fallback is worth the additional lease,
   stale-read, and cross-context-GC protocol; MVP requires Web Locks.
6. Default durability policy for identity/auth/head commits versus replicated
   blocks and caches.
7. Measured threshold at which versioned range tombstones become worthwhile.
8. Whether Holepunch considers the reproduced
   `store.get({ name, key: oldCoreKey })` compatibility migration a supported
   long-term path.
9. Peerit signed descriptor format for core supersession if same-key migration
   fails a production fixture or cannot remain supported.
10. Which stable publisher domain fronts blind public gateways for writable
    Peerit sessions.

## Worth asking upstream next

The storage target itself is answered. The useful follow-ups are now specific:

1. Would Holepunch accept a small `hypercore-storage` portability PR that lets
   an injected backend provide `ColumnFamily`, skips filesystem recovery for a
   known-empty logical store, and replaces private RocksDB field reads with
   public state?
2. Should the portable portion of `rocksdb-native/test.js` be extracted
   upstream as the grant's canonical conformance suite?
3. We reproduced Corestore 6 -> 7 continuity by importing the same primary seed
   and first opening `store.get({ name, key: oldCoreKey })`; Corestore 7 detected
   compatibility, stayed writable, replicated with the old stack, and retained
   the alias on reopen. Is this an intended supported migration path, provided
   the old writer is permanently fenced before the new stack appends?
4. What is the preferred grant submission path, reviewer, and milestone shape?

These questions demonstrate that the existing code and tests were audited;
they do not ask Holepunch to design the project for us.

## Sources

- [Indexed Database API 3.0](https://w3c.github.io/IndexedDB/)
- [WHATWG Storage Standard](https://storage.spec.whatwg.org/)
- [Web Locks API](https://w3c.github.io/web-locks/)
- [WebKit storage policy](https://webkit.org/blog/14403/updates-to-storage-policy/)
- [`rocksdb-native`](https://github.com/holepunchto/rocksdb-native)
- [`hypercore-storage`](https://github.com/holepunchto/hypercore-storage)
- [`hypercore`](https://github.com/holepunchto/hypercore)
- [`corestore`](https://github.com/holepunchto/corestore)
