# Database

`database.url` empty means SQLite at `<data_dir>/starforge.db` (WAL mode, one writer connection plus a pool of read-only reader connections; see [Operations in the README](https://example.invalid) — reader-pool behaviour is documented under Operations). A `postgres://` URL selects Postgres (a single shared pool). `database.auto_migrate` (default `true`) runs embedded migrations at startup; `starforged migrate` applies them by hand.

### Reader pool

On SQLite the database layer keeps one writer connection and a separate pool
of read-only (`PRAGMA query_only = ON`) reader connections, with the
database in WAL mode: a long read never blocks a write, and a write routed
to a reader fails loudly instead of landing. On Postgres both share one pool.
Functions that only `SELECT` outside a transaction use the reader pool;
writes, transactions, and read-then-write functions use the writer. Committed
writes are visible to readers immediately, so a sequential "write, then
read" in one request is safe either way.

### Reader pool

On SQLite the database layer keeps one writer connection and a separate pool
of read-only (`PRAGMA query_only = ON`) reader connections, with the
database in WAL mode: a long read never blocks a write, and a write routed
to a reader fails loudly instead of landing. On Postgres both share one pool.
Functions that only `SELECT` outside a transaction use the reader pool;
writes, transactions, and read-then-write functions use the writer. Committed
writes are visible to readers immediately, so a sequential "write, then
read" in one request is safe either way.
