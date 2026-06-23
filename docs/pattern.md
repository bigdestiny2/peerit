# The peerit Pattern

peerit uses a reusable pattern for multi-writer, serverless social apps on top of
a simple P2P key-value log:

1. Each identity writes to its own outbox.
2. Peers gossip outbox descriptors and replicate each other's outboxes.
3. Every replica verifies records, rejects forged or malformed writes, and merges
   the admitted records into the same deterministic view.
4. The UI reads that merged view through the same small sync API it would use for
   a single shared log.

The important split is authority versus transport. Transport only moves bytes.
Authority comes from record content, key binding, and Ed25519 signatures.

## Why this pattern exists

PearBrowser's bridge sync groups are simple and useful, but the original group
shape has a single writer. A Reddit-like app needs many independent writers:
community creators, posters, commenters, voters, and moderators.

Instead of asking all users to write into one shared mutable group, peerit gives
each user one append-only-ish outbox. A user's local actions go into their own
outbox. Other peers discover that outbox, copy its records, verify them, and merge
them locally.

That gives the app multi-writer behavior while preserving a clean rule:

```text
Only Alice can author Alice's records.
Anyone may relay Alice's records.
No relay path is trusted.
```

## Data shape

The app models every domain event as a record under a deterministic key:

| Record | Key shape | Purpose |
| --- | --- | --- |
| Community | `community!<slug>` | Creates a community and names its founder. |
| Post | `post!<community>!<cid>` | Adds or edits a post in one community. |
| Comment | `comment!<community>!<postCid>!<cid>` | Adds or edits a threaded comment. |
| Vote | `vote!<targetCid>!<voterPubkey>` | Stores one last-write-wins vote per identity. |
| Profile | `profile!<pubkey>` | Stores display profile data for one identity. |
| Mod action | `modaction!<community>!<actionId>` | Stores moderator actions as an overlay. |

The storage key is recomputed from the record's own fields during merge. A record
is admitted only if the recomputed key matches the key under which it arrived.
This prevents an attacker from placing a valid record at a more privileged key.

## Record authority

Each record carries:

- `_k`: the public key that claims authorship.
- `_sig`: an Ed25519 signature over the canonical record payload.
- Domain fields that imply the expected author, such as `author`, `creator`,
  `voter`, or `by`.

On ingest and merge, peerit checks:

1. The storage key matches `expectedKey(type, record)`.
2. The signer matches the domain owner from `ownerOf(type, record)`.
3. The Ed25519 signature verifies in secure environments.

This means a malicious peer can copy, replay, or rebroadcast data, but cannot
fabricate records for another identity. It also means a forged record cannot evict
a real record, because bad records are rejected before they enter an outbox cache.

## Gossip and merge

In development, gossip uses `BroadcastChannel` and local storage so multiple tabs
can behave like peers. In PearBrowser, the same pattern maps onto per-user bridge
sync groups.

The merge is intentionally boring:

- scan known peer outboxes;
- ignore prototype-pollution keys and invalid shapes;
- verify each record before admission;
- pick deterministic winners for key conflicts;
- expose a sorted key-value view through `get`, `list`, `range`, and `count`.

Most records use last-write-wins by timestamp, with a signature tiebreaker to make
ordering total. Tombstones beat live records on equal timestamps so deletes do not
resurrect accidentally.

Communities use a different rule. The first admitted creator for a slug becomes
sticky on that replica. After a replica has seen `r/<slug>` owned by one creator,
another creator cannot replace it. This protects established communities from
hijack, but it does not solve global name squatting at genesis.

## Moderation as an overlay

Moderation is not a privileged backend operation. It is a signed stream of records
that clients honor when rendering:

- the community creator is the first moderator;
- current moderators may add or remove moderators;
- moderator actions can remove, approve, lock, unlock, sticky, unsticky, ban, or
  unban;
- the effective moderation state is reduced from signed `modaction` records.

Because the overlay is derived from signed records, moderation decisions are
auditable and converge across peers that have seen the same data.

## What this pattern guarantees

The pattern is good at:

- authenticating authorship without trusting relays;
- preventing forged records from evicting valid records;
- converging deterministic views across peers;
- letting users keep writing while disconnected;
- keeping the UI independent from the transport implementation.

The pattern does not solve:

- Sybil resistance, since identities are cheap to create;
- globally fair first-claim naming for brand-new slugs;
- private data, since replicated outboxes are readable by peers;
- legal or social moderation enforcement outside the client.

In short: peerit guarantees content authenticity and deterministic local
convergence, not scarce identity or global name ownership.

## Files to read

- [`js/sync.js`](../js/sync.js): common sync API and backend selection.
- [`js/gossip.js`](../js/gossip.js): outbox gossip, verification, and merge.
- [`js/canon.js`](../js/canon.js): canonical payloads, key binding, and ownership.
- [`js/verify.js`](../js/verify.js): record signing and verification.
- [`js/model.js`](../js/model.js): key scheme, threads, and moderation overlay.
- [`test/gossip.mjs`](../test/gossip.mjs): adversarial checks for the gossip model.
