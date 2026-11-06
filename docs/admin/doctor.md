# Doctor



```bash
./target/release/starforged doctor [--fix]
```

Checks the git version, repository hooks, data-directory permissions,
orphaned blob files, and search-index health against the database, printing
one line per check. It exits `0` when every check passes, `1` on any
failure, and `2` when only warnings occur. `--fix` reinstalls missing
repository hooks and removes orphaned blob files older than one hour; it
never deletes database rows.

