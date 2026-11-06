//! `pg_dump`/`pg_restore` PATH shims for Postgres backup/restore tests
//! (plan M5b, Global Constraints): the test Postgres runs inside a
//! container started by `scripts/check.sh`
//! (`STARFORGE_TEST_PG=1`), and the host has no PostgreSQL client, so the
//! shims exec the client inside that container.
//!
//! [`install_pg_shims`] returns the shim directory to prepend to `PATH`,
//! or `None` — with the reason printed — when no container engine or test
//! container is present; Postgres tests skip only in that case, never
//! silently.

/// Holds the shim directory for the lifetime of a test.
pub struct PgShims {
    _dir: tempfile::TempDir,
}

impl PgShims {
    /// `shim_dir:` + the current `PATH`, ready for `Command::env("PATH", ..)`.
    pub fn prepended_path(&self) -> String {
        let dir = self._dir.path().display();
        match std::env::var("PATH") {
            Ok(path) if !path.is_empty() => format!("{dir}:{path}"),
            _ => dir.to_string(),
        }
    }
}

/// Writes `pg_dump`/`pg_restore` shims that run the real clients inside the
/// test Postgres container (`podman` or `docker exec`). The container is
/// found as the first `starforge-test-pg-*` container (the name
/// `scripts/check.sh` uses), overridable with `STARFORGE_TEST_PG_CONTAINER`.
/// Returns `None` when no container engine or no such container exists.
pub fn install_pg_shims() -> Option<PgShims> {
    let engine = container_engine()?;
    let container = test_container(&engine)?;
    let dir = tempfile::tempdir().expect("create pg shim directory");
    for (name, script) in [
        ("pg_dump", shim_with_preamble(PG_DUMP_SHIM)),
        ("pg_restore", shim_with_preamble(PG_RESTORE_SHIM)),
    ] {
        let path = dir.path().join(name);
        std::fs::write(&path, script).expect("write pg shim");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
                .expect("chmod pg shim");
        }
    }
    let _ = (engine, container);
    Some(PgShims { _dir: dir })
}

fn container_engine() -> Option<String> {
    for candidate in ["podman", "docker"] {
        if which(candidate) {
            return Some(candidate.to_owned());
        }
    }
    println!("SKIP: no container engine (podman or docker) found; Postgres backup test skipped");
    None
}

fn which(program: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| dir.join(program).is_file())
}

/// The running `starforge-test-pg-*` container (check.sh's naming).
fn test_container(engine: &str) -> Option<String> {
    if let Ok(name) = std::env::var("STARFORGE_TEST_PG_CONTAINER")
        && !name.is_empty()
    {
        return Some(name);
    }
    let out = std::process::Command::new(engine)
        .args(["ps", "--format", "{{.Names}}"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let names = String::from_utf8_lossy(&out.stdout);
    names
        .lines()
        .map(str::trim)
        .find(|name| name.starts_with("starforge-test-pg"))
        .map(str::to_owned)
        .or_else(|| {
            println!(
                "SKIP: no starforge-test-pg container is running; Postgres backup test skipped"
            );
            None
        })
}

/// Common preamble: resolve engine + container, rewrite a host URL
/// (`postgres://user:pass@127.0.0.1:<host-port>/<db>`) to the container's
/// own listener (`127.0.0.1:5432`), and forward `PGPASSWORD` when set.
const PREAMBLE: &str = r#"#!/bin/sh
# pg shim: run the real client inside the test Postgres container.
set -eu
engine="${STARFORGE_TEST_PG_ENGINE:-$(command -v podman || command -v docker)}"
container="${STARFORGE_TEST_PG_CONTAINER:-}"
if [ -z "$container" ]; then
  container="$("$engine" ps --format '{{.Names}}' | grep '^starforge-test-pg' | head -n 1)"
fi
if [ -z "$container" ]; then
  echo "pg shim: no starforge-test-pg container found" >&2
  exit 127
fi
rewrite_url() {
  # The last argument is the connection URL; point it at the container's
  # own Postgres listener instead of the host's published port.
  printf '%s' "$1" | sed -E 's#(://[^@/[:space:]]+@)127\.0\.0\.1:[0-9]+#\1127.0.0.1:5432#'
}
exec_in_container() {
  if [ -n "${PGPASSWORD:-}" ]; then
    exec "$engine" exec -i -e "PGPASSWORD=$PGPASSWORD" "$container" "$@"
  else
    exec "$engine" exec -i "$container" "$@"
  fi
}
"#;

/// `pg_dump [opts] --file <host-file> <url>`: `--file` names a host path
/// the container cannot see, so the dump streams to stdout and lands in
/// the host file instead. Without `--file`, stdout already is the dump.
const PG_DUMP_SHIM: &str = r#"__PREAMBLE__
file=""
args=""
for arg in "$@"; do
  if [ "$file" = "__PENDING__" ]; then
    file="$arg"
    continue
  fi
  if [ "$arg" = "--file" ]; then
    file="__PENDING__"
    continue
  fi
  case "$arg" in
    --file=*) file="${arg#--file=}";;
    *) args="$args
$arg";;
  esac
done
if [ "$file" = "__PENDING__" ]; then
  echo "pg_dump shim: --file without a value" >&2
  exit 2
fi
# Rebuild argv with the URL rewritten (it is the last argument).
set --
last=""
for arg in $args; do
  if [ -n "$last" ]; then
    set -- "$@" "$last"
  fi
  last="$arg"
done
case "$last" in
  postgres://*|postgresql://*) set -- "$@" "$(rewrite_url "$last")";;
  *) set -- "$@" "$last";;
esac
if [ -n "$file" ]; then
  exec_in_container pg_dump "$@" > "$file"
else
  exec_in_container pg_dump "$@"
fi
"#;

/// `pg_restore [opts] --dbname <url> [file]`: arguments pass through with
/// the `--dbname` URL rewritten; a file argument is streamed on stdin.
const PG_RESTORE_SHIM: &str = r#"__PREAMBLE__
file=""
args=""
pending_dbname=0
for arg in "$@"; do
  if [ "$pending_dbname" = 1 ]; then
    args="$args
--dbname=$(rewrite_url "$arg")"
    pending_dbname=0
    continue
  fi
  case "$arg" in
    --dbname=*) args="$args
--dbname=$(rewrite_url "${arg#--dbname=}")";;
    --dbname) pending_dbname=1;;
    *) args="$args
$arg";;
  esac
done
if [ "$pending_dbname" = 1 ]; then
  echo "pg_restore shim: --dbname without a value" >&2
  exit 2
fi
# The last bare argument is the dump file (or nothing when invoked by
# URL alone): keep it out of argv and stream it on stdin instead.
set --
last=""
for arg in $args; do
  if [ -n "$last" ]; then
    set -- "$@" "$last"
  fi
  last="$arg"
done
case "$last" in
  postgres://*|postgresql://*) set -- "$@" "$(rewrite_url "$last")";;
  --*=*) set -- "$@" "$last";;
  *) file="$last";;
esac
if [ -n "$file" ]; then
  exec_in_container pg_restore "$@" < "$file"
else
  exec_in_container pg_restore "$@"
fi
"#;

/// The shims with the shared preamble spliced in.
fn shim_with_preamble(template: &str) -> String {
    template.replace("__PREAMBLE__", PREAMBLE.trim_end())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shims_are_well_formed() {
        for shim in [
            shim_with_preamble(PG_DUMP_SHIM),
            shim_with_preamble(PG_RESTORE_SHIM),
        ] {
            assert!(shim.starts_with("#!/bin/sh"));
            assert!(shim.contains("starforge-test-pg"));
            assert!(shim.contains("127.0.0.1:5432"));
        }
    }
}
