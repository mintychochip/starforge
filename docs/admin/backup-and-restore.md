# Backup and restore

```bash
./target/release/starforged backup <dir>            # see below; --no-config omits the config copy
./target/release/starforged restore <backup-dir> --data-dir <fresh-dir>
./target/release/starforged restore <backup-dir> --config <target-config>
```


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


