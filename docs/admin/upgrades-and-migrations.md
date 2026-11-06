# Upgrades and migrations



Database migrations run automatically at startup when `database.auto_migrate`
is true (the default); `starforged migrate` applies them by hand. Migrations
are embedded and engine-specific (SQLite and Postgres schema files ship
side by side), so an upgrade is just a new binary — back up first, then
restart. `starforged doctor` reports whether migrations are up to date, and
`restore` refuses a backup whose schema is newer than the binary's.


Migrations are forward-only; back up before upgrading (see backup and restore).
