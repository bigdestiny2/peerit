# Availability and Persistence

peerit has two separate persistence layers, and they have different guarantees.

## 1. Static App Delivery

The app itself is a static Hyperdrive:

```text
hyper://ec6e2d6d9d22b9d6b40e11a9ca3042be3197e4bdca9e9a7f079be6ee830761b4/
```

That drive contains only the app shell: `index.html`, CSS, icons, and browser JS.
It does not contain posts, comments, votes, profiles, or communities.

The intended availability path is:

1. The publisher writes the app files into a Hyperdrive.
2. The publisher announces that drive on the DHT.
3. HiveRelay relays accept a seed request.
4. Relays replicate the drive bytes.
5. Future users can fetch the app from any relay or online peer that has the bytes.

The important operational distinction:

```text
seed accepted != bytes fully replicated
```

A relay acceptance means a relay agreed to seed. It does not, by itself, prove
that the relay has already connected to the publisher and downloaded
`/index.html` plus the rest of the drive.

`publish.mjs` therefore checks both:

- seed acceptances from HiveRelay;
- live Hyperdrive replication evidence via `waitForDurable()`.

For release publishes, use:

```bash
STRICT_ANCHOR=1 node publish.mjs
```

For difficult network conditions, keep the publisher online until the relay fleet
has caught up:

```bash
KEEP=1 node publish.mjs
```

## Static App Guarantees

The static app is available when at least one peer or relay with the populated
drive is online and reachable.

The target deployment asks HiveRelay for multiple replicas and a long TTL, but it
is still an availability request, not an absolute mathematical guarantee. The
practical guarantee improves with:

- more independent relay replicas;
- a publisher kept online during anchoring;
- reader co-seeding;
- periodic health checks that fetch `/index.html` from fresh storage;
- re-seeding when replica health falls below the target.

The GitHub repository is an out-of-band source mirror, not an automatic
Hyperdrive fallback. If the app drive is unavailable, a user can inspect the
source on GitHub, but PearBrowser will not automatically reconstruct the
`hyper://` drive from GitHub.

## 2. User-Generated Data

Posts, comments, votes, communities, profiles, and moderation actions are not
stored in the static app drive.

In PearBrowser, peerit uses per-user signed outboxes:

1. Each identity creates or rejoins its own sync group.
2. The invite key for that outbox is kept locally as `peerit:my-outbox-key`.
3. Records are signed by the author's Pear identity.
4. Peers announce signed outbox descriptors over the peerit swarm topic.
5. Other peers join those outboxes, verify records, and merge them locally.

That means a user's own data should persist across sessions on the same
PearBrowser profile as long as the local Pear/browser storage is not deleted or
corrupted.

Cross-user availability is weaker today:

- Other users see a record after they discover and replicate the author's outbox.
- If the author disappears before anyone else replicates the outbox, the network
  may not have a copy.
- If no peer holding an outbox is online, a fresh user may not see those records.
- Signed records protect authenticity, not availability.

## User Data Guarantees

peerit currently guarantees:

- signed authorship for admitted records;
- deterministic merge for peers that have the same outboxes;
- local persistence for a user's own outbox across sessions on the same profile;
- no trust in relays or transport labels for record authority.

peerit does not yet guarantee:

- always-on availability of every user's outbox;
- global recovery after every user who has a record goes offline;
- cross-device backup of a user's identity or outbox invite key;
- Sybil resistance;
- global first-claim fairness for brand-new community names.

## Current Outbox Seeding Workflow

Settings -> Outbox seeding exposes the current user's full outbox/group key and
an app data recovery / seeding bundle. This is the operational path for keeping
one user's public records discoverable while their own device is offline:

- Copy Group key copies the current outbox invite key.
- Copy seeder command produces a `peerit-seeder` command:

```bash
cd ../peerit-seeder
node seeder.mjs <outboxInviteKey> [<more> ...]
```

- Copy recovery bundle and Export bundle produce the non-root app recovery data:
  app drive key, app public key, and known outbox invite keys.
- Import recovery bundle validates the bundle `driveKey` and `publicKey` against
  the current app identity before accepting it. When both match, peerit stores
  and joins the listed outboxes, then announces the current signed descriptor.

The Group key is not a PearBrowser mnemonic and does not let anyone sign as the
user. It does let another device or an always-on seeder replicate the user's
public outbox, so it should be shared deliberately rather than posted as a public
profile field.

This workflow prepares an outbox for seeding. It does not, by itself, prove that
a seeder or relay has already downloaded all bytes. Operators still need seeder
logs or health checks that confirm byte replication; as with the static app
drive, `seed accepted != bytes fully replicated`.

## What Would Make Data Always Available

To move from "P2P best effort" to "production durable," peerit needs an always-on
data availability layer in addition to the static app seed:

1. Relay-pin each user's outbox after it is created.
2. Let readers opt in to co-seed outboxes they have replicated.
3. Store signed outbox descriptors in a durable directory so new peers can find
   historical outboxes without relying only on live swarm discovery.
4. Add durable directory and relay pinning for imported outbox descriptors so
   fresh clients can find historical outboxes without relying only on live swarm
   discovery.
5. Add a health monitor that periodically verifies a fresh client can fetch both
   the static app drive and representative outboxes.

Until those are built, peerit should be described as a signed, convergent P2P
social app with relay-assisted app delivery, not as an app with absolute
always-available user data.
