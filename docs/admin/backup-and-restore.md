# Backup and restore

```bash
./target/release/starforged backup <dir>            # see below; --no-config omits the config copy
./target/release/starforged restore <backup-dir> --data-dir <fresh-dir>
./target/release/starforged restore <backup-dir> --config <target-config>
```

`backup` writes a consistent snapshot into an empty or absent directory:
`manifest.json` (format version 1, Starforge version, creation time, engine,
latest migration, repository and blob counts), `database/`, `repos/` (the
same sharded layout), `blobs/`, and `config/starforged.toml` (a copy of the
running config, unless `--no-config`). The search index is not backed up; it
is rebuilt from the database on demand. The database snapshot is
transactionally consistent (`VACUUM INTO` on SQLite, `pg_dump` — which must be
on `PATH` — on Postgres), each repository is copied under its exclusive
lock, and blob garbage collection is paused for the duration, so every blob
the snapshot references is present.

**The backup contains secrets.** The config copy holds `security.secret_key`,
so the backup directory is created `0700` and the config and manifest files
`0600`. Keep backups like secrets: encrypted at rest, access-limited, and
never committed or uploaded anywhere public.

`restore` refuses a non-empty data directory (or, on Postgres, a database that
already has tables) and a manifest from a newer schema than the binary knows;
it runs migrations after restoring an older schema. Without `--config` it
uses the backup's config with `storage.data_dir` taken from `--data-dir`.
Stop the server before restoring, and start it again afterwards.



## Scheduled backups and rotation

The server takes scheduled backups while it serves when both
`backup.dir` is set and `backup.interval_hours` is greater than 0:

```toml
[backup]
dir = "/var/backups/starforge"
interval_hours = 24
keep = 7
```

Set `backup.dir` to an empty or absent directory, `backup.interval_hours`
to the interval in hours, and `backup.keep` to the number of backups
to retain. `backup.keep` defaults to 7 and the minimum value is 1 when
scheduled backups run. Set `backup.dir` to an empty value or
`backup.interval_hours` to 0 to turn scheduled backups off.
Environment overrides use `STARFORGE__BACKUP__DIR`,
`STARFORGE__BACKUP__INTERVAL_HOURS`, and `STARFORGE__BACKUP__KEEP`.

Every interval the server writes one backup to
`<dir>/starforge-backup-<UTC YYYYMMDD-HHMMSS>` with the same code as
`starforged backup`, and the backup includes the configuration copy.
After each backup the server deletes the oldest backup directories
beyond `keep`. Rotation considers only directories that hold a valid
backup `manifest.json`, so it never deletes unrelated directories.
Backup failures log an error and never stop the server. The backup
directory holds secrets, so keep it encrypted at rest and
access-limited like every other backup.

Under systemd, give the service write access to the backup directory
with an extra `ReadWritePaths=` entry in the unit, then reload and
restart the service to apply the change.
