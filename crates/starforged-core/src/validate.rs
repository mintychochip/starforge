//! Input rules for handles, repository names, emails, and passwords.

use crate::CoreError;

/// Handles that would collide with top-level routes (`/<handle>` pages).
pub const RESERVED_HANDLES: &[&str] = &[
    "admin", "api", "assets", "explore", "forgot", "healthz", "join", "login", "logout", "metrics",
    "new", "org", "orgs", "readyz", "repo", "repos", "reset", "settings", "static", "user",
    "users", "verify",
];

/// Lowercases and checks a user or org handle: 1–39 of `a-z 0-9 -`, no leading, trailing, or doubled `-`,
/// and not reserved.
pub fn handle(input: &str) -> Result<String, CoreError> {
    let h = input.trim().to_ascii_lowercase();
    let allowed = h
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if h.is_empty()
        || h.len() > 39
        || !allowed
        || h.starts_with('-')
        || h.ends_with('-')
        || h.contains("--")
    {
        return Err(CoreError::Invalid(
            "handles are 1-39 characters of a-z, 0-9, and single hyphens, not at the start or end"
                .into(),
        ));
    }
    if RESERVED_HANDLES.contains(&h.as_str()) {
        return Err(CoreError::Invalid(format!("'{h}' is reserved")));
    }
    Ok(h)
}

/// Repository names: 1–100 of `A-Z a-z 0-9 . _ -`, not `.` or `..`, and not ending in `.git`.
pub fn repo_name(input: &str) -> Result<String, CoreError> {
    let name = input.trim();
    let allowed = name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if name.is_empty()
        || name.len() > 100
        || !allowed
        || name == "."
        || name == ".."
        || name.to_ascii_lowercase().ends_with(".git")
    {
        return Err(CoreError::Invalid(
            "repository names are 1-100 characters of letters, digits, '.', '_', and '-', and must not end in .git".into(),
        ));
    }
    Ok(name.to_owned())
}

/// Lowercases and checks an email: one `@`, a non-empty local part, a dotted domain, at most 254 characters.
pub fn email(input: &str) -> Result<String, CoreError> {
    let e = input.trim().to_ascii_lowercase();
    let valid = e.len() <= 254
        && !e.contains(char::is_whitespace)
        && match e.split_once('@') {
            Some((local, domain)) => {
                !local.is_empty()
                    && domain.contains('.')
                    && !domain.starts_with('.')
                    && !domain.ends_with('.')
                    && !domain.contains('@')
            }
            None => false,
        };
    if valid {
        Ok(e)
    } else {
        Err(CoreError::Invalid("invalid email address".into()))
    }
}

pub fn password(input: &str) -> Result<(), CoreError> {
    if (10..=1024).contains(&input.chars().count()) {
        Ok(())
    } else {
        Err(CoreError::Invalid(
            "passwords are 10-1024 characters".into(),
        ))
    }
}

/// Display names: surrounding whitespace dropped, at most 100 characters, no control characters.
pub fn display_name(input: &str) -> Result<String, CoreError> {
    let name = input.trim();
    if name.chars().count() > 100 || name.chars().any(char::is_control) {
        Err(CoreError::Invalid(
            "display names are at most 100 characters, without control characters".into(),
        ))
    } else {
        Ok(name.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles() {
        assert_eq!(handle(" Alice ").unwrap(), "alice");
        assert_eq!(handle("a-b-9").unwrap(), "a-b-9");
        assert_eq!(handle(&"a".repeat(39)).unwrap().len(), 39);
        for bad in [
            "",
            "-a",
            "a-",
            "a--b",
            "a_b",
            "a.b",
            "日本",
            "login",
            "API",
            "a".repeat(40).as_str(),
        ] {
            assert!(handle(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn repo_names() {
        for good in ["proj", "Proj.rs", "a_b-c", ".github"] {
            assert_eq!(repo_name(good).unwrap(), good);
        }
        for bad in [
            "",
            ".",
            "..",
            "x.git",
            "X.GIT",
            "a/b",
            "a b",
            "a".repeat(101).as_str(),
        ] {
            assert!(repo_name(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn emails() {
        assert_eq!(email(" Al@Example.COM ").unwrap(), "al@example.com");
        for bad in [
            "",
            "a",
            "@x.com",
            "a@",
            "a@x",
            "a@.com",
            "a@x.",
            "a b@x.com",
            "a@b@c.com",
        ] {
            assert!(email(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn passwords() {
        assert!(password("0123456789").is_ok());
        assert!(password("short").is_err());
        assert!(password(&"x".repeat(1025)).is_err());
    }

    #[test]
    fn display_names() {
        assert_eq!(display_name("  Alice A.  ").unwrap(), "Alice A.");
        assert_eq!(display_name(&"é".repeat(100)).unwrap().chars().count(), 100);
        assert!(display_name(&"x".repeat(101)).is_err());
        assert!(display_name("tab\there").is_err());
    }

    #[test]
    fn sign_up_routes_are_reserved() {
        for reserved in ["forgot", "join", "reset", "verify"] {
            assert!(handle(reserved).is_err(), "{reserved}");
        }
    }
}
