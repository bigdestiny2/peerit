# Seq29 local custodian key provisioning

This offline tool creates the three raw 32-byte X25519 private-key files that
the accepted Seq29 local custodian key-file validator consumes:

```sh
node scripts/seq29-provision-local-custodian-keys.mjs \
  /absolute/operator-owned-parent/new-seq29-custodian-keys
```

The target must be a canonical absolute path whose parent already exists. The
entire resolved parent chain must contain real directories owned by either the
operator or the system root, and the direct parent must be operator-owned and
not writable by another identity. The target must not exist.

Provisioning creates the target with exact mode `0700` and no special bits. It creates only these
three files, each as an owned, single-link regular file with exact mode `0600`
and no special bits:

- `custodian-1.x25519`
- `custodian-2.x25519`
- `custodian-3.x25519`

The production path uses the operating system CSPRNG and has no deterministic
entropy option. It writes each key with `O_CREAT|O_EXCL|O_NOFOLLOW`, verifies
the opened and named inode before and after the exact write and file `fsync`,
reads every captured inode back and binds it byte-for-byte to the generated
CSPRNG buffer, syncs the target and parent directories, and runs the existing
accepted key-file validator before reporting success. Output contains only a
status and key count.

## Failure and crash handling

Before the target directory is created, a failure leaves no provisioned
topology. Once creation succeeds, the tool never calls pathname-based unlink,
rename or directory removal: those operations cannot atomically prove that a
concurrently replaced pathname is still the captured inode.

On a caught write or verification failure while a key descriptor is still
open, that descriptor is best-effort `fsync`ed before it is closed. The held
target and parent descriptors are then best-effort `fsync`ed. The primary
failure code is retained, and the partial-failure object reports separate
`fileFsync`, `fileClose`, `targetFsync`, and `parentFsync` results without key
bytes or paths. A `FAILED` sync result means durability is not established; a
directory sync cannot substitute for a failed partial-file sync. A close
failure after a completed write is propagated after descriptor cleanup; a
close failure during an earlier write or verification failure is recorded but
never masks that primary failure.

Immediately before returning a caught partial failure, the tool rechecks the
held and named target inode, owner, full mode including special bits, link
count, exact known entry set, and captured key-file inodes. If that observation
is exact, it returns
`PEERIT_SEQ29_CUSTODIAN_PROVISION_PARTIAL_PRESERVED`; this means only that the
named create-only topology was observed intact at that failure boundary. It is
not a statement that the keys are valid or that a later external actor cannot
change the path. A missing, renamed, replaced, changed, or unverifiable target
instead returns
`PEERIT_SEQ29_CUSTODIAN_PROVISION_PARTIAL_EXTERNAL_TOPOLOGY_DRIFT`. That status
claims only that the tool attempted the reported held-descriptor syncs and
performed no pathname cleanup; it does not claim that the original residue
still has a pathname. In-memory key buffers are wiped in both cases.

A process or machine crash can leave an empty or partially populated target.
That target is deliberately not resumable: the next invocation fails because
the target exists, and the existing validator also rejects its partial shape.
Do not recursively delete it and do not retry the same path. Preserve all
available evidence for operator review and secure disposal, then provision into
a fresh, never-used absolute target path. The same rule applies to either
caught partial-failure status, including when no original pathname can be
established. This create-only contract never guesses pathname ownership after
an anomaly or after the process has lost its captured inode identities.

The tool performs no network I/O, does not publish anything, and does not move
keys into a service or operator vault.
