# Identity and recovery protocol

> **Status: mixed historical design and current-source note.** The root-mnemonic,
> app-drive and signed-outbox sections document an earlier Pear Browser design;
> they do not prove the current host API or signed Sequence 29 artifact. The web
> identity section below reflects current source. Check
> [`CURRENT-STATUS.md`](./CURRENT-STATUS.md) before making a release claim. In
> current source, Peerit leaves host-key lifecycle to Pear Browser and cannot
> display, export, confirm, or restore host recovery material. Users must rely
> only on recovery facilities the host itself actually provides.

The historical design was shared by peerit and p2pbuilders, which reuse identity,
signature, outbox, and gossip patterns. It is retained as design context rather
than current host-recovery instructions.

## Historical answer to "is the mnemonic the identity?"

The earlier design answered yes, with one important privacy layer. The current
host adapter does not expose enough lifecycle information for Peerit to make
that promise today.

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
| Root mnemonic | Historical name for a PearBrowser recovery phrase. | Peerit cannot access or verify one; use only recovery options the host currently exposes. |
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

## Historical host backup protocol

The earlier design proposed two backups for full recovery. This section does
not establish that current Pear Browser builds expose either workflow.

### 1. Host-managed identity recovery

The historical proposal used a 12-word PearBrowser recovery phrase to restore a
root identity seed and derived per-app public keys. Current Peerit source neither
observes nor tests that recovery lifecycle.

Required user message:

> Your signing key is managed by PearBrowser. Use only recovery options shown by
> PearBrowser itself. Peerit can neither export that key nor confirm that a host
> backup will restore it.

The apps must not export, import, store, or display host recovery material. Any
supported recovery workflow belongs to PearBrowser.

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

### 3. Web-mode identity export

Everything above assumes the historical Pear Browser identity design. In a
**normal browser or phone** there is no host mnemonic: the current source takes
the `web` path and lazily mints a browser-local Ed25519 seed on the first explicit
write. `DevIdentity` keeps the cleartext seed in memory. The device tier stores
AES-256-GCM ciphertext beside a non-extractable WebCrypto wrapping-key handle in
IndexedDB, then silently restores it on that device. This is API-level protection,
not disk encryption: same-origin code can use the key, profile-level access can
recover it, and clearing site data or losing the device still destroys it.

There is no phrase to back up. The durable cross-device recovery mechanism is
the passphrase-encrypted identity export below; legacy outbox recovery bundles
do **not** contain the signing seed.

To close that gap, web/dev mode exposes a **passphrase-encrypted identity export**
(`js/identity-export.js`). Unlike the root mnemonic (which apps must never touch),
this seed *is* the app's own key, so the app may export it — but only sealed:

- **KDF/cipher:** PBKDF2-SHA256 (600k iterations) → AES-256-GCM, via
  `crypto.subtle`. No new dependencies.
- **Envelope:** the `pubkey` is cleartext (for display and as an integrity
  anchor); the seed only ever exists inside the ciphertext.

```json
{
  "type": "peerit-identity-export", "version": 1, "app": "peerit",
  "pubkey": "<64 hex app public key>", "label": "anon", "createdAt": "<ISO>",
  "kdf":    { "name": "PBKDF2", "hash": "SHA-256", "iterations": 600000, "salt": "<b64>" },
  "cipher": { "name": "AES-GCM", "iv": "<b64>" },
  "ciphertext": "<b64 of {seed,pubkey,driveKey,label}>"
}
```

Import (`importIdentity`) decrypts with the passphrase, cross-checks the cleartext
`pubkey` against the authenticated contents, and **proves the seed signs for that
pubkey** before accepting — a seed that does not match its key is rejected. It then
adds the identity to the local roster and switches to it (`DevIdentity.addUser`),
keeping any identities already in that browser. The same envelope string is the
file contents, the copy/paste blob, and the QR payload; QR encode/scan lives in
`js/qr.js` (scan uses the native `BarcodeDetector`, absent on iOS Safari, so file
and paste are always offered as fallbacks).

Security notes:

- The export is a **bearer secret**: file + passphrase together = full ability to
  post as the user. Encryption-at-rest is mandatory (minimum passphrase length
  enforced); export is refused when no real Ed25519 backend is present.
- Export **copies**, it does not move — the source browser keeps its encrypted
  device identity in IndexedDB. If the user also saved a passphrase vault, that
  encrypted envelope remains in `localStorage` until explicitly forgotten.
- This applies only to the `web`/`dev` identity. On the PearBrowser bridge the key
  is unreachable to the app, so no Peerit identity export exists there. Use only
  recovery facilities the host actually provides.

Required user message (web/dev mode, replacing the PearBrowser phrase message):

> This identity lives only in this browser. Export it to move it to another device
> or keep a backup — peerit has no server that can recover it for you.

## Historical host restore protocol

The earlier design expected this order. Current Peerit cannot initiate or verify
step 1, so this is not a present-tense recovery promise:

1. Use the host-provided identity recovery flow, if one is available.
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
> identity unless the host restores the matching signing identity.

## Session and device behavior

Same browser profile:

- local PearBrowser storage preserves the app outbox;
- localStorage preserves the current outbox/group key and known-outboxes list;
- normal restarts should keep the same identity and data pointers.

The historical design expected this behavior on a new device or wiped profile:

- successful host recovery restores signing identity;
- app recovery bundle restores outbox discovery;
- seeder or relay pinning restores availability while the original device is
  offline.

If host identity recovery is unavailable or does not restore the old key:

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
- host-key status plus a link to host-provided recovery controls, when the host
  exposes them; Peerit must not claim a host backup is complete;
- copy/export app recovery bundle;
- import app recovery bundle;
- in web/dev mode (browser-local key), a passphrase-encrypted **identity export**
  (file / copy / QR) and a matching **identity import** (paste / file / QR scan);
- copy Group key for seeding;
- seeder-ready command for `peerit-seeder`;
- seeder status if known;
- warning before first post if the user has not acknowledged identity backup.

Suggested copy:

> PearBrowser manages this signing identity; use any recovery options it
> provides. This app's recovery bundle helps rediscover data but does not contain
> the host signing key.

## Current implementation notes

- peerit and p2pbuilders already sign records and verify owner binding before
  merge.
- Both apps persist the current outbox key and a known-outboxes list locally.
- peerit Settings -> Outbox seeding now shows the full current outbox/group key,
  copies the Group key, copies a `peerit-seeder` command, and copies/exports the
  app data recovery / seeding bundle.
- peerit Settings imports app recovery bundles only after comparing bundle
  `driveKey` and `publicKey` with the current app identity. A matching bundle
  rejoins known outboxes and re-announces the current signed descriptor.
- peerit does not yet verify seeder status inside the app; operators still need
  seeder logs or health checks to prove byte replication.
- In web/dev mode, peerit Settings also exports the browser-local signing key as a
  passphrase-encrypted bundle (`js/identity-export.js`) and imports it back
  (add-to-roster + switch), with file / copy / QR transport (`js/qr.js`). This is
  the only key backup that exists off the PearBrowser bridge; the app data recovery
  bundle never carries the signing key. The web-mode identity-backup copy no longer
  references a non-existent PearBrowser phrase.
- p2pbuilders adds proof-of-work through the shared gossip `validate` hook.
- p2pbuilders currently inherits the `peerit` signature namespace string for
  compatibility with the copied engine. New apps should choose an app-specific
  namespace from day one; changing this in a live app needs a dual-read migration.

## Historical recovery properties, not current guarantees

If a host recovery mechanism restores the same signing key:

- the app sees the same signing identity for the same drive key;
- old app data may still be hard to discover if outbox/group keys were lost.

With the same restored host identity plus a matching app recovery bundle:

- the app can rejoin known outboxes under that identity.

With those inputs plus an always-on seeder or relay-pinned outbox:

- the user can recover identity, rediscover data, and keep public records
  available while their own device is offline.

Without restoration of the same signing key:

- identity continuity is lost by design.
