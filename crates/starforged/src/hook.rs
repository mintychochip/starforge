//! Entry points that git runs inside hosted repositories (see `starforged_git::init::HOOKS`).
//! Anything written to stderr reaches the pusher as `remote: …`.

use std::io::{BufRead, Write};

use starforged_git::refpolicy;

/// `starforged hook pre-receive`: checks every pushed ref; returns the process exit code.
pub fn pre_receive(input: impl BufRead, mut err: impl Write) -> i32 {
    let mut code = 0;
    for line in input.lines() {
        let Ok(line) = line else { return 1 };
        if line.trim().is_empty() {
            continue;
        }
        let Some(update) = refpolicy::parse_line(&line) else {
            let _ = writeln!(err, "starforge: malformed pre-receive input");
            return 1;
        };
        if let Err(message) = refpolicy::check(&update) {
            let _ = writeln!(err, "starforge: {message}");
            code = 1;
        }
    }
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(input: &str) -> (i32, String) {
        let mut err = Vec::new();
        let code = pre_receive(input.as_bytes(), &mut err);
        (code, String::from_utf8(err).unwrap())
    }

    #[test]
    fn accepts_branches_and_tags() {
        assert_eq!(
            run("0 1 refs/heads/main\n0 2 refs/tags/v1\n\n"),
            (0, String::new())
        );
    }

    #[test]
    fn rejects_other_namespaces_and_reports_each() {
        let (code, err) = run("0 1 refs/heads/main\n0 2 refs/notes/x\n0 3 refs/entire/y\n");
        assert_eq!(code, 1);
        assert!(
            err.contains("starforge: pushing to refs/notes/x is not allowed"),
            "{err}"
        );
        assert!(err.contains("refs/entire/y"), "{err}");
    }

    #[test]
    fn rejects_malformed_input() {
        assert_eq!(run("garbage\n").0, 1);
    }
}
