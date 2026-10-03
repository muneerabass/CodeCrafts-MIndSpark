#!/bin/sh
# Nightly logical backups of both databases into the `backups` volume.
# Copy the volume off-site (e.g. `rclone sync`) — see docs/DEPLOY.md.
set -eu
while true; do
  ts=$(date -u +%Y%m%dT%H%M%SZ)
  for db in depguard depguard_web; do
    pg_dump -h postgres -U depguard -Fc "$db" > "/backups/${db}-${ts}.dump.tmp" \
      && mv "/backups/${db}-${ts}.dump.tmp" "/backups/${db}-${ts}.dump" \
      && echo "backup ok: ${db}-${ts}" || echo "backup FAILED: $db" >&2
  done
  find /backups -name '*.dump' -mtime +"${BACKUP_KEEP_DAYS}" -delete
  sleep 86400
done
