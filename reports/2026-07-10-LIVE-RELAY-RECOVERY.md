# Live OutboxLog relay recovery — 2026-07-10

## Incident

The writable ingress (`outbox.peerit.site`) was accepting Peerit atomic commits,
but its host was not operationally safe:

- the generic HiveRelay core store had grown to roughly 51 GiB;
- the service history contained an OOM kill and repeated stop timeouts;
- the Peerit OutboxLog state and journal themselves remained small and intact;
- storage accounting did not identify the historical large cores, so it could
  not be relied upon as the first line of admission control.

This was a generic Hypercore seeding/adoption incident, not corruption of
Peerit's atomic OutboxLog journal.

## Recovery performed

1. Created a checksum-verified local archive of the Peerit relay config,
   OutboxLog state snapshot, and JSONL journal.
2. Installed and enabled the daily `peerit-outbox-backup.timer`; a restore drill
   extracted the archive into an isolated directory and validated state/journal
   shape without touching the live relay.
3. Increased the service stop grace period to 90 seconds and raised the bounded
   cgroup allowance to leave headroom for native Hypercore resources. The prior
   10-second stop budget was forcing SIGKILLs, so this is a mitigation rather
   than evidence of graceful shutdown.
4. Moved three very large unregistered, unopened core directories to a
   same-host quarantine. They were not deleted. One was subsequently recreated
   by the generic seeding plane, proving that registry metadata alone was not a
   sufficient ownership signal; do not delete quarantine data until its source
   has been independently mapped.
5. Applied a live generic-seeding admission freeze:
   - `maxStorageBytes`: 20 GiB;
   - `registryAutoAccept`: `false`;
   - `replicationRepairEnabled`: `false`.

Peerit's OutboxLog namespace, journal persistence, atomic commit route, and
public writer rate envelope were not changed by the freeze.

## Verification after recovery

- OutboxLog writer preflight: passed (durable CAS/idempotent atomic commit;
  legacy mutation routes blocked).
- Peerit browser: signed release sequence 4 loaded; the post composer reported
  `Writer quorum ready` under the signed single-ingress policy.
- Initial post-freeze observation: core store stable at 16 GiB; relay active;
  no new restart; cgroup memory fell to roughly 450 MiB.

## Required before lifting the freeze

1. Identify every active large core through a reliable registry/accounting
   mapping and prove that per-core accounting matches on-disk usage.
2. Re-enable automatic adoption/repair only in production-shaped staging with a
   tested storage ceiling and eviction behavior.
3. Configure an encrypted, independently controlled off-host destination for
   the OutboxLog backup archive and run a clean-host restoration drill.
4. Demonstrate a graceful service shutdown within the new 90-second budget.
5. Add a second independently operated writable origin before claiming
   one-relay-failure write availability.
