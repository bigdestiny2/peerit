# Peerit OutboxLog backup unit

Install the checked-in script and units on every writable OutboxLog ingress:

```sh
install -m 700 peerit-outbox-backup.sh /usr/local/sbin/peerit-outbox-backup
install -m 644 peerit-outbox-backup.service /etc/systemd/system/
install -m 644 peerit-outbox-backup.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now peerit-outbox-backup.timer
systemctl start peerit-outbox-backup.service
```

The unit creates a daily, checksum-verified archive of `config.json`, the
OutboxLog state snapshot, and its fsynced JSONL journal in
`/root/.hiverelay/backups/`. It retains 30 days by default; override only with
the `PEERIT_OUTBOX_BACKUP_KEEP_DAYS` service environment variable.

Test an archive without touching the live relay:

```sh
archive=/root/.hiverelay/backups/peerit-outbox-<timestamp>.tar.gz
sha256sum -c "$archive.sha256"
restore=$(mktemp -d)
tar -xzf "$archive" -C "$restore"
jq -e 'type == "object"' "$restore/storage/outboxlog-state.json"
test -f "$restore/storage/outboxlog-journal.jsonl"
```

This is a local recovery checkpoint, not independent disaster recovery. Copy
the resulting archive to a separately controlled encrypted destination before
claiming protection from host loss.
