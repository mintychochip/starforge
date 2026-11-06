//! Exec-request parsing: shell-style tokenization matching what git's SSH
//! transport sends (`git-upload-pack '/owner/repo.git'` or the spaced
//! `git upload-pack …` form). Anything else is refused.

/// The git services SSH serves (D5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackKind {
    UploadPack,
    ReceivePack,
    UploadArchive,
}

impl PackKind {
    /// `git <subcommand>` for the shared spawn helper.
    pub fn subcommand(self) -> &'static str {
        match self {
            PackKind::UploadPack => "upload-pack",
            PackKind::ReceivePack => "receive-pack",
            PackKind::UploadArchive => "upload-archive",
        }
    }

    /// The [`starforged_git::http::Service`] with the same ref policy env.
    pub fn http_service(self) -> starforged_git::http::Service {
        match self {
            PackKind::UploadPack | PackKind::UploadArchive => {
                starforged_git::http::Service::UploadPack
            }
            PackKind::ReceivePack => starforged_git::http::Service::ReceivePack,
        }
    }
}

/// One validated exec: the service and the raw path argument (unquoted,
/// still carrying an optional leading `/` and `.git` suffix).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitExec {
    pub kind: PackKind,
    pub path: String,
}

/// Splits one exec string into words, honouring single/double quotes and
/// backslash escapes (enough for git's own quoting). Unterminated quotes are
/// refused.
fn words(input: &str) -> Result<Vec<String>, ()> {
    let mut out = Vec::new();
    let mut word = String::new();
    let mut quote: Option<char> = None;
    let mut word_open = false;
    let mut escaped = false;
    for ch in input.chars() {
        if escaped {
            word.push(ch);
            escaped = false;
            word_open = true;
            continue;
        }
        match quote {
            Some('\'') => {
                if ch == '\'' {
                    quote = None;
                } else {
                    word.push(ch);
                }
            }
            Some('"') => match ch {
                '"' => quote = None,
                '\\' => escaped = true,
                _ => word.push(ch),
            },
            Some(_) => return Err(()),
            None => match ch {
                '\'' | '"' => {
                    quote = Some(ch);
                    word_open = true;
                }
                '\\' => escaped = true,
                ch if ch.is_whitespace() => {
                    if word_open {
                        out.push(std::mem::take(&mut word));
                        word_open = false;
                    }
                }
                _ => {
                    word.push(ch);
                    word_open = true;
                }
            },
        }
    }
    if quote.is_some() || escaped {
        return Err(());
    }
    if word_open {
        out.push(word);
    }
    Ok(out)
}

/// Parses one exec request: exactly `git-<service> '<path>'` (or the spaced
/// `git <service> '<path>'` form), else [`ParseError::Refused`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    Refused,
}

/// [`parse_exec`] returning the service and raw path.
pub fn parse_exec(input: &str) -> Result<GitExec, ParseError> {
    let argv = words(input).map_err(|_| ParseError::Refused)?;
    let (kind, path) = match argv.as_slice() {
        [cmd, path] => {
            let kind = match cmd.as_str() {
                "git-upload-pack" => PackKind::UploadPack,
                "git-receive-pack" => PackKind::ReceivePack,
                "git-upload-archive" => PackKind::UploadArchive,
                _ => return Err(ParseError::Refused),
            };
            (kind, path.clone())
        }
        [git, sub, path] if git == "git" => {
            let kind = match sub.as_str() {
                "upload-pack" => PackKind::UploadPack,
                "receive-pack" => PackKind::ReceivePack,
                "upload-archive" => PackKind::UploadArchive,
                _ => return Err(ParseError::Refused),
            };
            (kind, path.clone())
        }
        _ => return Err(ParseError::Refused),
    };
    if path.is_empty() || split_repo_path(&path).is_err() {
        return Err(ParseError::Refused);
    }
    Ok(GitExec { kind, path })
}

/// Splits the raw path into `(owner, repo)`: `[/]<owner>/<repo>[.git]` (D5).
/// Anything else (extra segments, empty) is not a repository path.
pub fn split_repo_path(path: &str) -> Result<(&str, &str), ParseError> {
    let trimmed = path.trim_start_matches('/');
    let trimmed = trimmed.strip_suffix(".git").unwrap_or(trimmed);
    let parts: Vec<&str> = trimmed.split('/').collect();
    match parts.as_slice() {
        [owner, repo] if !owner.is_empty() && !repo.is_empty() => Ok((*owner, *repo)),
        _ => Err(ParseError::Refused),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_all_accepted_forms() {
        assert_eq!(
            parse_exec("git-upload-pack '/alice/proj.git'").unwrap(),
            GitExec {
                kind: PackKind::UploadPack,
                path: "/alice/proj.git".to_owned(),
            }
        );
        assert_eq!(
            parse_exec("git receive-pack '/alice/proj'").unwrap().kind,
            PackKind::ReceivePack
        );
        assert_eq!(
            parse_exec("git-upload-archive \"alice/proj.git\"")
                .unwrap()
                .kind,
            PackKind::UploadArchive
        );
        assert_eq!(
            split_repo_path("/alice/proj.git").unwrap(),
            ("alice", "proj")
        );
        assert_eq!(split_repo_path("alice/proj").unwrap(), ("alice", "proj"));
    }

    #[test]
    fn refuses_everything_else() {
        for cmd in [
            "git-upload-pack",
            "git-upload-pack '/alice/proj' extra",
            "ls",
            "git-upload-pack; id",
            "git-ftp '/alice/proj'",
            "git-upload-pack '/a/b/c'",
            "git-upload-pack ''",
            "git-receive-pack '/alice/proj' --force",
            "git-upload-pack '/alice/proj", // unterminated quote
        ] {
            assert!(parse_exec(cmd).is_err(), "{cmd}");
        }
        for path in ["/alice", "/a/b/c", ""] {
            assert!(split_repo_path(path).is_err(), "{path}");
        }
    }
}
