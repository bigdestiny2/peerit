# Identity and recovery protocol

This protocol applies to peerit and to p2pbuilders, which reuses the same
identity, signature, outbox, and gossip pattern.

## The answer to "is the mnemonic the identity?"

Yes, with one important privacy layer.

PearBrowser has one root identity seed, backed up as a BIP-39 mnemonic. Apps do
not receive that root key. For each app, PearBrowser derives a deterministic
per-app Ed25519 key from:

```text
root identity seed + app drive key
```

That means:

- the same mnemonic restores the user's identity across PearBrowser;
- each app sees a different public key for the same person;
- the same app sees the same public key again only when the root mnemonic and the
  app drive key are both the same;
- republishing a production app under a new drive key changes the app-visible
  identity unless there is an explicit migration protocol.

For peerit and p2pbuilders, the app-visible public key is the user's author,
voter, moderator, profile, and reputation identity.

## Terms

| Term | Meaning | User-facing handling |
|---|---|---|
| Root mnemonic | The PearBrowser recovery phrase for the root identity seed. | Highest sensitivity. Back up in PearBrowser, never inside a web app. |
| App drive key | The Hyperdrive key of the app code. | Must stay stable for production identity continuity. |
| App public key | The per-app public identity derived by PearBrowser. | Safe to show as an identity fingerprint. |
| Outbox/group key | The sync invite key for one app outbox. | Needed to rejoin, seed, and recover app data discovery. Not a signing key, but do not spray it casually. |
| Signed record | A post, vote, profile, mod action, board, etc. signed by the app public key. | The app admits it only if the signature and owner binding verify. |
| Outbox descriptor | A signed pointer from an app public key to an outbox/group key. | Used for peer discovery; must be verified before join. |

## Security rules

1. The root seed never enters peerit or p2pbuilders.
2. Apps only call `window.pear.identity.getPublicKey()` and
   `window.pear.identity.sign(payload, namespace)`.
3. Every record is signed over canonical bytes, with the PearBrowser envelope:

```text
pear.app.<driveKey>:<namespace>:<canonical-record>
```

4. A record is accepted only when:
   - its storage key matches its own fields;
   - its signer equals its claimed owner;
   - the Ed25519 signature verifies;
   - any app-specific gate also passes, such as p2pbuilders proof-of-work.
5. Transport is never authority. A record is not trusted because it came from a
   particular outbox; it is trusted only because the signature is valid.
6. Outbox descriptors must be signed by the identity they claim to represent.
7. A production app drive key must be treated as part of the app's identity
   domain. Do not re-key a production app without an explicit migration plan.

## Backup protocol

The user needs two backups for full recovery.

### 1. PearBrowser identity backup

This is the 12-word PearBrowser recovery phrase. It restores the root identity
seed and therefore restores the same per-app public keys for every app whose
drive key remains stable.

Required user message:

> Your identity lives in PearBrowser. Back up your 12-word PearBrowser recovery
> phrase. peerit/p2pbuilders only see an app-specific public key and cannot
> recover this phrase for you.

The apps should not export, import, store, or display the root mnemonic. That
belongs in PearBrowser settings.

### 2. App recovery bundle

The app should provide an export/import bundle for non-root app recovery data:

```json
{
  "version": 1,
  "app": "peerit",
  "driveKey": "<64 hex app drive key>",
  "publicKey": "<64 hex app public key>",
  "outboxes": [
    { "appId": "<public key or old appId>", "inviteKey": "<64 hex group key>" }
  ],
  "createdAt": "2026-06-23T00:00:00.000Z"
}
```

This bundle does not let someone sign as the user. It lets the app or a seeder
find the user's outbox again. Since peerit and p2pbuilders records are public,
the main risk is unwanted replication, spam attempts against the outbox, and
metadata leakage. It should be labelled "app data recovery / seeding key", not
"identity phrase."

Required user message:

> Your Group key helps your app data stay discoverable. It is not your identity
> phrase and does not let anyone sign as you, but it can let another device or
> seeder replicate your public outbox.

## Restore protocol

A correct restore has this order:

1. Restore the PearBrowser mnemonic first.
2. Open the same production app drive key.
3. The app reads `window.pear.identity.getPublicKey()`.
4. If importing an app recovery bundle, the app compares:
   - bundle `driveKey` with the current app drive key;
   - bundle `publicKey` with the current app public key.
5. If both match, import the outbox list, join every outbox, and announce the
   current signed descriptor.
6. Show recovery status: identity restored, outboxes joined, records visible.

If the public key does not match, the app must not silently treat the user as the
old identity. It should say:

> This recovery bundle belongs to a different app identity. You can view or seed
> the old public data, but you cannot edit, moderate, vote, or post as that old
> identity unless you restore the matching PearBrowser phrase.

## Session and device behavior

Same browser profile:

- local PearBrowser storage preserves the app outbox;
- localStorage preserves the current outbox/group key and known-outboxes list;
- normal restarts should keep the same identity and data pointers.

New device or wiped profile:

- mnemonic alone restores signing identity;
- app recovery bundle restores outbox discovery;
- seeder or relay pinning restores availability while the original device is
  offline.

No mnemonic:

- the user cannot prove continuity with the old identity;
- old records remain valid but belong to the old key;
- new posts/votes/profile changes are a new identity;
- no operator, relay, or app can reset the key without breaking the trust model.

## App re-key policy

Because app identity is derived from the app drive key, production app drive keys
are stable identity domains. Re-keying an app is equivalent to changing every
user's app-visible public key.

Release rule:

- keep the production drive key stable;
- if a new drive key is unavoidable, ship a migration before moving users;
- without a browser-level root-signed app-binding API, the safe default is to
  treat the new drive key as a new identity domain.

## Required app UI

Each app should expose an Identity / Recovery panel with:

- app identity fingerprint: short app public key;
- app drive key fingerprint;
- backup status: "PearBrowser phrase backed up" if PearBrowser can expose that
  status, otherwise a button that opens PearBrowser backup instructions;
- copy/export app recovery bundle;
- import app recovery bundle;
- copy Group key for seeding;
- seeder status if known;
- warning before first post if the user has not acknowledged identity backup.

Suggested copy:

> Back up PearBrowser to keep your identity. Back up this app's recovery bundle
> to keep your posts discoverable on a new device.

## Current implementation notes

- peerit and p2pbuilders already sign records and verify owner binding before
  merge.
- Both apps persist the current outbox key and a known-outboxes list locally.
- p2pbuilders adds proof-of-work through the shared gossip `validate` hook.
- p2pbuilders currently inherits the `peerit` signature namespace string for
  compatibility with the copied engine. New apps should choose an app-specific
  namespace from day one; changing this in a live app needs a dual-read migration.

## Guarantees

With mnemonic only:

- the app signing identity can be recovered for the same drive key;
- old app data may still be hard to discover if outbox/group keys were lost.

With mnemonic plus app recovery bundle:

- the app can recover the same signing identity and rejoin known outboxes.

With mnemonic, app recovery bundle, and an always-on seeder/relay-pinned outbox:

- the user can recover identity, rediscover data, and keep public records
  available while their own device is offline.

Without the mnemonic:

- identity continuity is lost by design.
