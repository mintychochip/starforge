//! Which refs clients may push (spec §8.2). M0 accepts branches and tags only; `refs/for/*` (M2) and
//! branch protection (M3) extend this through the server socket.

/// One line of `pre-receive` input: `<old-oid> <new-oid> <refname>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefUpdate {
    pub old: String,
    pub new: String,
    pub name: String,
}

pub fn parse_line(line: &str) -> Option<RefUpdate> {
    let mut parts = line.split_whitespace();
    let (old, new, name) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    Some(RefUpdate {
        old: old.to_owned(),
        new: new.to_owned(),
        name: name.to_owned(),
    })
}

pub fn check(update: &RefUpdate) -> Result<(), String> {
    if update.name.starts_with("refs/heads/") || update.name.starts_with("refs/tags/") {
        Ok(())
    } else {
        Err(format!(
            "pushing to {} is not allowed; only branches and tags are accepted",
            update.name
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn update(name: &str) -> RefUpdate {
        RefUpdate {
            old: "0".repeat(40),
            new: "1".repeat(40),
            name: name.into(),
        }
    }

    #[test]
    fn parses_hook_lines() {
        assert_eq!(
            parse_line("aaa bbb refs/heads/main"),
            Some(RefUpdate {
                old: "aaa".into(),
                new: "bbb".into(),
                name: "refs/heads/main".into()
            })
        );
        assert_eq!(parse_line("aaa bbb"), None);
        assert_eq!(parse_line("aaa bbb refs/heads/main extra"), None);
    }

    #[test]
    fn only_branches_and_tags_are_accepted() {
        assert!(check(&update("refs/heads/main")).is_ok());
        assert!(check(&update("refs/heads/feature/x")).is_ok());
        assert!(check(&update("refs/tags/v1.0")).is_ok());
        for rejected in [
            "refs/notes/commits",
            "refs/entire/checkpoints/ab/x",
            "refs/trails/1/changes/1/head",
            "refs/for/main",
            "HEAD",
        ] {
            let err = check(&update(rejected)).unwrap_err();
            assert!(err.contains(rejected), "{err}");
        }
    }
}
