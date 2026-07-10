#!/bin/sh
# Durable local checkpoint for the Peerit OutboxLog state. This deliberately
# backs up only the journal/state/config that constitute the atomic writer; it
# never copies unrelated Hypercore payloads or credentials from systemd units.

set -eu

ROOT=/root/.hiverelay
STORAGE="$ROOT/storage"
BACKUPS="$ROOT/backups"
KEEP_DAYS="${PEERIT_OUTBOX_BACKUP_KEEP_DAYS:-30}"

umask 077
mkdir -p "$BACKUPS"
exec 9>"$BACKUPS/.peerit-outbox-backup.lock"
flock -n 9 || exit 0

test -s "$STORAGE/outboxlog-state.json"
test -f "$STORAGE/outboxlog-journal.jsonl"
jq -e 'type == "object"' "$STORAGE/outboxlog-state.json" >/dev/null

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
archive="$BACKUPS/peerit-outbox-$stamp.tar.gz"
temporary="$BACKUPS/.peerit-outbox-$stamp.tar.gz.tmp"

tar -C "$ROOT" -czf "$temporary" \
  config.json \
  storage/outboxlog-state.json \
  storage/outboxlog-journal.jsonl
tar -tzf "$temporary" >/dev/null
mv "$temporary" "$archive"
sha256sum "$archive" > "$archive.sha256"

# Retain enough daily recovery points to catch a delayed corruption without
# letting a quiet installation grow unbounded. Only this backup family is pruned.
find "$BACKUPS" -maxdepth 1 -type f -name 'peerit-outbox-*.tar.gz' -mtime "+$KEEP_DAYS" -delete
find "$BACKUPS" -maxdepth 1 -type f -name 'peerit-outbox-*.tar.gz.sha256' -mtime "+$KEEP_DAYS" -delete

logger -t peerit-outbox-backup "verified $archive"
