# Peerit public release readiness — 2026-07-09

> **Historical audit — superseded.** Its read-only decision was the correct
> containment at the time. The signed writable canary was subsequently released
> as sequence 6; it is not yet general-availability clearance. Use the
> [`2026-07-10 production-readiness matrix`](../reports/2026-07-10-PRODUCTION-READINESS-MATRIX.md)
> for the current decision and evidence.

> Execution plan: [`PUBLIC-RELEASE-REMEDIATION-PLAN.md`](PUBLIC-RELEASE-REMEDIATION-PLAN.md)

## Decision

**NO-GO for a writable public release.** The application suite passes and the
client now fails closed in several important places, but the current production
topology and relay contract do not yet support the guarantees made by a writable
public service.

A **read-only public preview** is the safe interim posture. PearBrowser testing
can continue separately while the relay and scale gates below are closed.

## Evidence collected

- The complete `npm test` suite passes after the changes in this audit.
- `npm audit` reports zero known vulnerabilities after upgrading esbuild to
  0.28.1.
- The generated DHT bundle, asset hashes, signed-release verifier, relay-pool
  recovery, directory bootstrap, rollback floor, v2 reads, identity vault, and
  dispersal paths pass their repository tests.
- A local browser smoke renders the feed, navigation, sidebar, and network status
  using the modified source.
- `peerit.site` and `outbox.peerit.site/health` were reachable during the audit.
- The checked-in local soak evidence covers 30 clients. A fresh 100-client,
  shared-source-IP run reached only 24 successful clients, with 76 errors and 74
  rate limits. That is useful failure evidence, not a public-scale pass.

## Critical release blockers

### 1. Relay ownership and atomic-write attestation

The live backend identifies as HiveRelay OutboxLog 0.24.3. Current HiveRelay
source defaults to verifying an appended record's Ed25519 signature and requires
its writer key to equal `appId`, but the exact production image/config has not
been immutably attested, unsigned create can still allocate empty groups, and a
record plus its later head are not one atomic commit. The older bespoke Peerit
relay does not meet this contract. A client-side read-only flag is not a security
boundary because a caller can invoke the relay API directly.

**Acceptance:** production-equivalent staging rejects cross-owner create/append,
replay, stale-CAS, partial record/head, and empty-group exhaustion attempts. New
groups begin with an owner-signed atomic commit, and only relays passing that
suite can enter the roster. Until then, block public write endpoints at the
relay/edge and ship the browser client read-only.

### 2. Cross-author semantic identifier collisions

Post/comment semantic keys omit the author after v2 rows are reconstructed for
the merged logical view. An attacker-chosen collision can replace another
author's logical record and can make votes attach to the colliding identifier.

**Acceptance:** post/comment identity is author-bound throughout storage,
reconstruction, lookup, moderation, and vote targeting, with migration and
collision tests.

### 3. Live seed continuity rollback

The checked-in seed snapshot for author
`6b565bc4cc28544526c85c09760f53bf735464393ad931bb026fb10e0757de30`
contains signed head version 14, count 8, while the live relay served version 6,
count 6 during this audit. Two signed snapshot rows were absent from the relay.

**Acceptance:** restore the latest author outbox to every production relay,
verify the signed head and full row census from a fresh client, and add that
snapshot-to-live continuity proof to the release gate.

### 4. Single writable failure domain and previously unsigned web release

At the start of the audit, the signed production roster contained one writable
relay and `pinnedReleaseKey` was empty. The read-only hotfix candidate now pins
the release key and requires a valid exact-byte signature, while the edge keeps
the single relay non-writable. That fixes artifact authenticity for this
candidate; it does not make the one-relay topology safe for public writes.

**Acceptance:** either keep the public web client read-only, or operate at least
two tested relay failure domains; sign `asset-manifest.json`, publish
`asset-manifest.sig`, and pin the Ed25519 release key. Independent operators are
required before making anti-collusion or “no single origin” claims.

### 5. Capacity is unproven at the launch target

The evidence does not cover the stated 2,000-client target, a two-relay pool,
shared-NAT rate limits, induced relay failure, persistence growth, or multi-region
behavior. Current polling and rate-limit envelopes can overload a single relay.

**Acceptance:** a staging soak at 2,000 clients must meet the thresholds in
`deploy/CAPACITY.md`, including p99 latency, error rate, rate limits, memory,
author headroom, mirror-write success, and continued reads with one relay down.

## Hardening completed in this audit

- Durable rollback floors now pin signed version **and root**, load before cached
  or bundled rows, retain the last verified view on rollback/withholding, surface
  a visible integrity warning, and stop the affected author from appending.
- Malformed candidate rows are isolated instead of aborting a refresh.
- Sealed v2 PoW-gated records require identity-bound v2 proofs; legacy plaintext
  records remain readable.
- Raw v2 and logical prefix reads paginate beyond the previous 1,000-row ceiling;
  the relay directory client sends the server's `cursor` parameter.
- Service-worker installation and cache misses fail closed on missing or
  hash-mismatched assets.
- Production builds strip disabled shard-roster metadata instead of shipping a
  stale unsigned placeholder.
- Writable one-relay releases, unsigned asset releases, skipped publish tests,
  and incomplete test subsets are blocked by the release tooling.
- Product copy now describes the different PearBrowser and normal-browser
  availability/privacy ceilings instead of claiming there are no servers or two
  live relays.

## Remaining high-priority reliability work

- Add bounded request deadlines, token refresh, and backoff around every relay
  call; avoid unbounded `Promise.all` startup dependencies.
- Replace whole-state JSON persistence fallback with bounded/compacted durable
  storage and test recovery from journal corruption at production volume.
- Add the optional browser smoke dependency to CI and gate desktop/mobile flows;
  run a real two-instance PearBrowser convergence and restart test.
- Make live availability evidence commit-bound, release-manifest-bound, fresh,
  and independently reproducible.

## Release commands

```sh
npm test
npm audit
npm run launch:readiness
npm run ship:check
```

The first two should pass. The latter two must remain blocked until their
production prerequisites are actually satisfied; bypass flags are not release
evidence.
