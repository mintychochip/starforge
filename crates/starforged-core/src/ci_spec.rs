//! The `.starforge/ci.toml` job spec: parsing and validation (M6a A0).
//!
//! The typed [`CiSpec`] is read from the commit tree of the repository by the
//! caller; this module only parses and validates the document. Secret
//! *values* are never stored in the spec — [`CiJobSpec::secrets`] holds
//! secret **names** only.

use std::collections::{BTreeMap, HashSet};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::{CoreError, CoreResult};

/// Maximum size of one `ci.toml` document: 256 KiB.
pub const MAX_SPEC_BYTES: usize = 256 * 1024;
/// Maximum number of jobs in one spec.
pub const MAX_JOBS: usize = 100;
/// Longest timeout accepted for a job: 4 hours.
pub const MAX_TIMEOUT: Duration = Duration::from_secs(4 * 60 * 60);

const MAX_JOB_NAME_LEN: usize = 64;
const MAX_IMAGE_LEN: usize = 256;
const MAX_COMMANDS: usize = 100;
const MAX_COMMAND_LEN: usize = 4096;
const MAX_ENV_ENTRIES: usize = 64;
const MAX_ENV_KEY_LEN: usize = 128;
const MAX_ENV_VALUE_LEN: usize = 4096;
const MAX_SECRETS: usize = 32;
const MAX_SECRET_NAME_LEN: usize = 128;
const MAX_ARTIFACTS: usize = 32;
const MAX_ARTIFACT_LEN: usize = 256;
const MAX_RUNS_ON: usize = 16;
const MAX_LABEL_LEN: usize = 64;
const MAX_TRIGGERS: usize = 100;
const MAX_PATTERN_LEN: usize = 256;

/// What enqueues a run: branch pushes and/or Trail change actions.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CiTriggers {
    /// Branch globs (`main`, `release/*`); matched by
    /// `starforged_git::refpolicy::pattern_matches`.
    #[serde(default)]
    pub push: Vec<String>,
    /// Trail actions: `opened` and/or `updated`.
    #[serde(default)]
    pub trail: Vec<String>,
}

/// One job of a [`CiSpec`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CiJobSpec {
    /// Unique within the spec: 1–64 chars of `[A-Za-z0-9_-]`.
    pub name: String,
    /// Container image to run the job in. Exactly one of `image`/`template`.
    #[serde(default)]
    pub image: Option<String>,
    /// Sandbox template name. Exactly one of `image`/`template`.
    #[serde(default)]
    pub template: Option<String>,
    /// Shell commands to run, in order. Must be non-empty.
    #[serde(default)]
    pub commands: Vec<String>,
    /// Job timeout: `30m`, `1h`, `90s`, or a bare number of seconds.
    #[serde(default)]
    pub timeout: Option<String>,
    /// Environment variables injected into the job.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Secret **names** (never values) to resolve for this job.
    #[serde(default)]
    pub secrets: Vec<String>,
    /// Artifact globs (relative, non-empty, no `..`) harvested on completion.
    #[serde(default)]
    pub artifacts: Vec<String>,
    /// Runner labels that may claim this job.
    #[serde(default)]
    pub runs_on: Vec<String>,
}

impl CiJobSpec {
    /// The parsed job timeout, if one was specified. [`CiSpec::parse`]
    /// already rejected an unparseable or over-limit value.
    pub fn timeout_duration(&self) -> Option<Duration> {
        self.timeout
            .as_deref()
            .and_then(|text| parse_timeout(text).ok())
    }
}

/// A parsed and validated `.starforge/ci.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CiSpec {
    /// Spec format version. Only `1` is accepted.
    pub version: u32,
    #[serde(default)]
    pub triggers: CiTriggers,
    /// Job list. The TOML key is `jobs`; the singular `job` (as in the plan
    /// example) is accepted as an alias.
    #[serde(default, alias = "job")]
    pub jobs: Vec<CiJobSpec>,
}

impl CiSpec {
    /// Parse and validate a `ci.toml` document.
    pub fn parse(text: &str) -> CoreResult<CiSpec> {
        if text.len() > MAX_SPEC_BYTES {
            return Err(invalid(format!(
                "ci.toml: spec is {} bytes, over the {MAX_SPEC_BYTES}-byte limit",
                text.len()
            )));
        }
        let spec: CiSpec =
            toml::from_str(text).map_err(|e| invalid(format!("ci.toml: invalid TOML: {e}")))?;
        spec.validate()?;
        Ok(spec)
    }

    /// Validate an already-constructed spec.
    pub fn validate(&self) -> CoreResult<()> {
        if self.version != 1 {
            return Err(invalid(format!(
                "ci.toml: unsupported version {} (expected 1)",
                self.version
            )));
        }
        validate_triggers(&self.triggers)?;
        if self.jobs.is_empty() {
            return Err(invalid("ci.toml: no jobs defined".to_owned()));
        }
        if self.jobs.len() > MAX_JOBS {
            return Err(invalid(format!(
                "ci.toml: {} jobs, over the {MAX_JOBS}-job limit",
                self.jobs.len()
            )));
        }
        let mut names = HashSet::new();
        for job in &self.jobs {
            validate_job_name(&job.name)?;
            if !names.insert(job.name.as_str()) {
                return Err(invalid(format!(
                    "ci.toml: duplicate job name `{}`",
                    job.name
                )));
            }
            validate_job(job)?;
        }
        Ok(())
    }
}

/// Parse a job timeout: `30m`, `1h`, `90s`, or bare seconds (`3600`).
/// The value must be positive and at most 4 hours.
pub fn parse_timeout(text: &str) -> CoreResult<Duration> {
    let raw = text.trim();
    if raw.is_empty() {
        return Err(invalid("ci.toml: empty timeout".to_owned()));
    }
    let (digits, unit_secs) = if let Some(n) = raw.strip_suffix('s') {
        (n, 1u64)
    } else if let Some(n) = raw.strip_suffix('m') {
        (n, 60)
    } else if let Some(n) = raw.strip_suffix('h') {
        (n, 3600)
    } else {
        (raw, 1)
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid(format!(
            "ci.toml: invalid timeout `{text}` (expected e.g. `90s`, `30m`, `1h`, or seconds)"
        )));
    }
    let amount: u64 = digits.parse().map_err(|_| {
        invalid(format!(
            "ci.toml: invalid timeout `{text}` (expected e.g. `90s`, `30m`, `1h`, or seconds)"
        ))
    })?;
    let secs = amount
        .checked_mul(unit_secs)
        .filter(|secs| *secs > 0)
        .ok_or_else(|| {
            invalid(format!(
                "ci.toml: invalid timeout `{text}` (expected e.g. `90s`, `30m`, `1h`, or seconds)"
            ))
        })?;
    if secs > MAX_TIMEOUT.as_secs() {
        return Err(invalid(format!(
            "ci.toml: timeout `{text}` exceeds the 4-hour maximum"
        )));
    }
    Ok(Duration::from_secs(secs))
}

fn invalid(message: String) -> CoreError {
    CoreError::Invalid(message)
}

fn validate_triggers(triggers: &CiTriggers) -> CoreResult<()> {
    for entry in triggers.push.iter().chain(&triggers.trail) {
        if entry.is_empty() {
            return Err(invalid("ci.toml: empty trigger entry".to_owned()));
        }
        if entry.len() > MAX_PATTERN_LEN {
            return Err(invalid(format!(
                "ci.toml: trigger entry `{entry}` exceeds {MAX_PATTERN_LEN} characters"
            )));
        }
    }
    if triggers.push.len() > MAX_TRIGGERS || triggers.trail.len() > MAX_TRIGGERS {
        return Err(invalid(format!(
            "ci.toml: over the {MAX_TRIGGERS}-entry trigger limit"
        )));
    }
    let mut pushes = HashSet::new();
    for pattern in &triggers.push {
        validate_branch_glob(pattern)?;
        if !pushes.insert(pattern.as_str()) {
            return Err(invalid(format!(
                "ci.toml: duplicate push trigger `{pattern}`"
            )));
        }
    }
    let mut actions = HashSet::new();
    for action in &triggers.trail {
        if action != "opened" && action != "updated" {
            return Err(invalid(format!(
                "ci.toml: invalid trail action `{action}` (expected `opened` or `updated`)"
            )));
        }
        if !actions.insert(action.as_str()) {
            return Err(invalid(format!(
                "ci.toml: duplicate trail action `{action}`"
            )));
        }
    }
    if triggers.push.is_empty() && triggers.trail.is_empty() {
        return Err(invalid(
            "ci.toml: no triggers (at least one push pattern or trail action is required)"
                .to_owned(),
        ));
    }
    Ok(())
}

fn validate_job_name(name: &str) -> CoreResult<()> {
    if name.is_empty() || name.len() > MAX_JOB_NAME_LEN {
        return Err(invalid(format!(
            "ci.toml: job name `{name}` must be 1-{MAX_JOB_NAME_LEN} characters"
        )));
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(invalid(format!(
            "ci.toml: job name `{name}` may only contain [A-Za-z0-9_-]"
        )));
    }
    Ok(())
}

fn validate_job(job: &CiJobSpec) -> CoreResult<()> {
    let bad = |message: String| invalid(format!("ci.toml: job `{}`: {message}", job.name));

    match (&job.image, &job.template) {
        (Some(_), Some(_)) => {
            return Err(bad(
                "exactly one of `image` or `template` is required, not both".to_owned(),
            ));
        }
        (None, None) => {
            return Err(bad(
                "exactly one of `image` or `template` is required".to_owned()
            ));
        }
        _ => {}
    }
    for (field, value) in [("image", &job.image), ("template", &job.template)] {
        if let Some(value) = value {
            let trimmed = value.trim();
            if trimmed.is_empty() || value.len() > MAX_IMAGE_LEN {
                return Err(bad(format!(
                    "`{field}` must be 1-{MAX_IMAGE_LEN} characters"
                )));
            }
            if trimmed != value.as_str()
                || value.chars().any(|c| c.is_control() || c.is_whitespace())
            {
                return Err(bad(format!(
                    "`{field}` `{value}` is not a valid image reference"
                )));
            }
        }
    }

    if job.commands.is_empty() {
        return Err(bad("no commands defined".to_owned()));
    }
    if job.commands.len() > MAX_COMMANDS {
        return Err(bad(format!(
            "{} commands, over the {MAX_COMMANDS}-command limit",
            job.commands.len()
        )));
    }
    for command in &job.commands {
        if command.trim().is_empty() {
            return Err(bad("empty command".to_owned()));
        }
        if command.len() > MAX_COMMAND_LEN {
            return Err(bad(format!("command exceeds {MAX_COMMAND_LEN} characters")));
        }
    }

    if let Some(timeout) = &job.timeout {
        parse_timeout(timeout).map_err(|e| match e {
            CoreError::Invalid(message) => bad(message),
            other => other,
        })?;
    }

    if job.env.len() > MAX_ENV_ENTRIES {
        return Err(bad(format!(
            "{} env entries, over the {MAX_ENV_ENTRIES}-entry limit",
            job.env.len()
        )));
    }
    for (key, value) in &job.env {
        if key.is_empty() || key.len() > MAX_ENV_KEY_LEN {
            return Err(bad(format!(
                "env key `{key}` must be 1-{MAX_ENV_KEY_LEN} characters"
            )));
        }
        let mut bytes = key.bytes();
        let first_ok = bytes
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_');
        if !first_ok || !bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return Err(bad(format!(
                "env key `{key}` must match [A-Za-z_][A-Za-z0-9_]*"
            )));
        }
        if value.len() > MAX_ENV_VALUE_LEN {
            return Err(bad(format!(
                "env value for `{key}` exceeds {MAX_ENV_VALUE_LEN} characters"
            )));
        }
    }

    if job.secrets.len() > MAX_SECRETS {
        return Err(bad(format!(
            "{} secrets, over the {MAX_SECRETS}-secret limit",
            job.secrets.len()
        )));
    }
    let mut secrets = HashSet::new();
    for name in &job.secrets {
        if name.is_empty() || name.len() > MAX_SECRET_NAME_LEN {
            return Err(bad(format!(
                "secret name `{name}` must be 1-{MAX_SECRET_NAME_LEN} characters"
            )));
        }
        if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return Err(bad(format!(
                "secret name `{name}` may only contain [A-Za-z0-9_]"
            )));
        }
        if !secrets.insert(name.as_str()) {
            return Err(bad(format!("duplicate secret `{name}`")));
        }
    }

    if job.artifacts.len() > MAX_ARTIFACTS {
        return Err(bad(format!(
            "{} artifacts, over the {MAX_ARTIFACTS}-artifact limit",
            job.artifacts.len()
        )));
    }
    let mut artifacts = HashSet::new();
    for artifact in &job.artifacts {
        validate_artifact_glob(artifact).map_err(|e| match e {
            CoreError::Invalid(message) => bad(message),
            other => other,
        })?;
        if !artifacts.insert(artifact.as_str()) {
            return Err(bad(format!("duplicate artifact `{artifact}`")));
        }
    }

    if job.runs_on.len() > MAX_RUNS_ON {
        return Err(bad(format!(
            "{} runs_on labels, over the {MAX_RUNS_ON}-label limit",
            job.runs_on.len()
        )));
    }
    let mut labels = HashSet::new();
    for label in &job.runs_on {
        if label.is_empty() || label.len() > MAX_LABEL_LEN {
            return Err(bad(format!(
                "runs_on label `{label}` must be 1-{MAX_LABEL_LEN} characters"
            )));
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(bad(format!(
                "runs_on label `{label}` may only contain [A-Za-z0-9_-]"
            )));
        }
        if !labels.insert(label.as_str()) {
            return Err(bad(format!("duplicate runs_on label `{label}`")));
        }
    }
    Ok(())
}

/// Validate a push branch glob: relative, non-empty, no `..`, no whitespace,
/// no backslashes or empty path segments.
fn validate_branch_glob(pattern: &str) -> CoreResult<()> {
    if pattern.is_empty() || pattern.len() > MAX_PATTERN_LEN {
        return Err(invalid(format!(
            "ci.toml: push trigger `{pattern}` must be 1-{MAX_PATTERN_LEN} characters"
        )));
    }
    if path_like_is_bad(pattern) {
        return Err(invalid(format!(
            "ci.toml: push trigger `{pattern}` is not a valid branch glob"
        )));
    }
    if !pattern
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'*' | b'?' | b'/'))
    {
        return Err(invalid(format!(
            "ci.toml: push trigger `{pattern}` contains invalid characters"
        )));
    }
    Ok(())
}

/// Validate an artifact glob: relative, non-empty, no `..`, no backslashes,
/// no empty or `.` path segments.
fn validate_artifact_glob(glob: &str) -> CoreResult<()> {
    if glob.is_empty() || glob.len() > MAX_ARTIFACT_LEN {
        return Err(invalid(format!(
            "artifact glob `{glob}` must be 1-{MAX_ARTIFACT_LEN} characters"
        )));
    }
    if path_like_is_bad(glob) {
        return Err(invalid(format!(
            "artifact glob `{glob}` must be a relative path without `..` or empty segments"
        )));
    }
    Ok(())
}

/// Shared path checks: not absolute, no empty/`.`/`..` segments, no
/// backslashes, no whitespace or control characters.
fn path_like_is_bad(path: &str) -> bool {
    if path.starts_with('/') || path.starts_with('\\') || path.contains('\\') {
        return true;
    }
    if path.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return true;
    }
    path.split('/')
        .any(|segment| segment.is_empty() || segment == "." || segment == "..")
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"
version = 1

[triggers]
push = ["main", "release/*"]
trail = ["opened", "updated"]

[[jobs]]
name = "test"
image = "docker.io/library/rust:1.85"
commands = ["cargo test --workspace"]
timeout = "30m"
env = { RUST_BACKTRACE = "1" }
secrets = ["CARGO_REGISTRY_TOKEN"]
artifacts = ["target/nextest/**"]
runs_on = ["linux-x64"]

[[jobs]]
name = "lint"
template = "starforge/rust"
commands = ["cargo clippy"]
"#;

    fn one_job(job_toml: String) -> String {
        format!(
            "version = 1\n\n[triggers]\npush = [\"main\"]\n\n[[jobs]]\nname = \"test\"\nimage = \"rust:1.85\"\n{job_toml}"
        )
    }

    fn err(text: &str) -> String {
        match CiSpec::parse(text) {
            Ok(_) => panic!("expected the spec to be rejected"),
            Err(CoreError::Invalid(message)) => message,
            Err(other) => panic!("expected CoreError::Invalid, got {other:?}"),
        }
    }

    #[test]
    fn valid_example_parses() {
        let spec = CiSpec::parse(VALID).expect("valid spec must parse");
        assert_eq!(spec.version, 1);
        assert_eq!(spec.triggers.push, ["main", "release/*"]);
        assert_eq!(spec.triggers.trail, ["opened", "updated"]);
        assert_eq!(spec.jobs.len(), 2);
        let test = &spec.jobs[0];
        assert_eq!(test.name, "test");
        assert_eq!(test.image.as_deref(), Some("docker.io/library/rust:1.85"));
        assert_eq!(test.template, None);
        assert_eq!(test.commands, ["cargo test --workspace"]);
        assert_eq!(test.timeout.as_deref(), Some("30m"));
        assert_eq!(test.timeout_duration(), Some(Duration::from_secs(30 * 60)));
        assert_eq!(test.env["RUST_BACKTRACE"], "1");
        assert_eq!(test.secrets, ["CARGO_REGISTRY_TOKEN"]);
        assert_eq!(test.artifacts, ["target/nextest/**"]);
        assert_eq!(test.runs_on, ["linux-x64"]);
        assert_eq!(spec.jobs[1].template.as_deref(), Some("starforge/rust"));
        assert_eq!(spec.jobs[1].timeout_duration(), None);
    }

    #[test]
    fn singular_job_key_is_accepted() {
        let text = "version = 1\n\n[triggers]\npush = [\"main\"]\n\n[[job]]\nname = \"test\"\nimage = \"rust:1.85\"\ncommands = [\"make\"]\n";
        let spec = CiSpec::parse(text).expect("[[job]] must parse via the alias");
        assert_eq!(spec.jobs.len(), 1);
        assert_eq!(spec.jobs[0].name, "test");
    }

    #[test]
    fn malformed_toml_is_rejected() {
        assert!(err("version = ").contains("invalid TOML"));
    }

    #[test]
    fn unknown_field_is_rejected() {
        let text = one_job("commands = [\"make\"]\nsurprise = true\n".to_owned());
        assert!(err(&text).contains("unknown field"));
    }

    #[test]
    fn wrong_version_is_rejected() {
        let text = VALID.replacen("version = 1", "version = 2", 1);
        assert!(err(&text).contains("unsupported version 2"));
    }

    #[test]
    fn empty_jobs_is_rejected() {
        let text = "version = 1\n\n[triggers]\npush = [\"main\"]\n";
        assert!(err(text).contains("no jobs"));
    }
    #[test]
    fn missing_triggers_is_rejected() {
        let text = "version = 1\n\n[[jobs]]\nname = \"test\"\nimage = \"rust:1.85\"\ncommands = [\"make\"]\n";
        assert!(err(text).contains("no triggers"));
    }

    #[test]
    fn duplicate_job_name_is_rejected() {
        let text = "version = 1\n\n[triggers]\npush = [\"main\"]\n\n[[jobs]]\nname = \"test\"\nimage = \"rust:1.85\"\ncommands = [\"make\"]\n\n[[jobs]]\nname = \"test\"\nimage = \"rust:1.85\"\ncommands = [\"make\"]\n"
            .to_string();
        assert!(err(&text).contains("duplicate job name"));
    }

    #[test]
    fn bad_job_names_are_rejected() {
        for name in ["", "has space", "slash/name", "dot.name", "ünïcode"] {
            let text = one_job("commands = [\"make\"]\n".to_owned()).replacen(
                "name = \"test\"",
                &format!("name = \"{name}\""),
                1,
            );
            assert!(err(&text).contains("job name"), "name: {name:?}");
        }
        let long = "a".repeat(65);
        let text = one_job("commands = [\"make\"]\n".to_owned()).replacen(
            "name = \"test\"",
            &format!("name = \"{long}\""),
            1,
        );
        assert!(err(&text).contains("must be 1-64 characters"));
    }

    #[test]
    fn image_xor_template_is_enforced() {
        let both = one_job("template = \"starforge/rust\"\ncommands = [\"make\"]\n".to_owned());
        assert!(err(&both).contains("not both"));
        let neither = "version = 1\n\n[triggers]\npush = [\"main\"]\n\n[[jobs]]\nname = \"test\"\ncommands = [\"make\"]\n";
        assert!(err(neither).contains("exactly one of `image` or `template`"));
    }

    #[test]
    fn empty_commands_are_rejected() {
        assert!(err(&one_job("commands = []\n".to_owned())).contains("no commands"));
        assert!(err(&one_job("commands = [\"  \"]\n".to_owned())).contains("empty command"));
    }

    #[test]
    fn bad_timeout_is_rejected() {
        for timeout in ["soon", "30x", "", "0s", "0", "-5m"] {
            let text = one_job(format!("commands = [\"make\"]\ntimeout = \"{timeout}\"\n"));
            assert!(err(&text).contains("timeout"), "timeout: {timeout:?}");
        }
    }

    #[test]
    fn timeout_over_four_hours_is_rejected() {
        for timeout in ["5h", "241m", "14401s", "14401"] {
            let text = one_job(format!("commands = [\"make\"]\ntimeout = \"{timeout}\"\n"));
            assert!(
                err(&text).contains("exceeds the 4-hour maximum"),
                "timeout: {timeout:?}"
            );
        }
    }

    #[test]
    fn timeout_parsing() {
        assert_eq!(parse_timeout("30m").unwrap(), Duration::from_secs(30 * 60));
        assert_eq!(parse_timeout("1h").unwrap(), Duration::from_secs(60 * 60));
        assert_eq!(parse_timeout("90s").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_timeout("3600").unwrap(), Duration::from_secs(3600));
        assert_eq!(
            parse_timeout("4h").unwrap(),
            Duration::from_secs(4 * 60 * 60)
        );
        assert_eq!(parse_timeout("14400").unwrap(), Duration::from_secs(14400));
        assert!(parse_timeout("4h1s").is_err());
        assert!(parse_timeout("m").is_err());
        assert!(parse_timeout("1.5h").is_err());
    }

    #[test]
    fn env_caps_are_enforced() {
        let bad_key = one_job("commands = [\"make\"]\nenv = { \"1BAD\" = \"x\" }\n".to_owned());
        assert!(err(&bad_key).contains("env key"));
        let long_value = "x".repeat(4097);
        let text = one_job(format!(
            "commands = [\"make\"]\nenv = {{ BIG = \"{long_value}\" }}\n"
        ));
        assert!(err(&text).contains("exceeds 4096 characters"));
        let mut entries = String::new();
        for i in 0..65 {
            entries.push_str(&format!("K{i} = \"v\"\n"));
        }
        let text = format!(
            "version = 1\n\n[triggers]\npush = [\"main\"]\n\n[[jobs]]\nname = \"test\"\nimage = \"rust:1.85\"\ncommands = [\"make\"]\n[jobs.env]\n{entries}"
        );
        assert!(err(&text).contains("over the 64-entry limit"));
    }

    #[test]
    fn secret_rules_are_enforced() {
        let bad_name = one_job("commands = [\"make\"]\nsecrets = [\"has-dash\"]\n".to_owned());
        assert!(err(&bad_name).contains("secret name"));
        let duplicate =
            one_job("commands = [\"make\"]\nsecrets = [\"TOKEN\", \"TOKEN\"]\n".to_owned());
        assert!(err(&duplicate).contains("duplicate secret"));
        let many: Vec<String> = (0..33).map(|i| format!("\"TOKEN{i}\"")).collect();
        let text = one_job(format!(
            "commands = [\"make\"]\nsecrets = [{}]\n",
            many.join(",")
        ));
        assert!(err(&text).contains("over the 32-secret limit"));
    }

    #[test]
    fn artifact_globs_are_validated() {
        for artifact in [
            "/abs/path",
            "../escape",
            "target/../escape",
            "target//double",
            "target/./x",
            "trailing/",
            "has space/x",
            "",
        ] {
            let text = one_job(format!(
                "commands = [\"make\"]\nartifacts = [\"{artifact}\"]\n"
            ));
            assert!(err(&text).contains("artifact"), "artifact: {artifact:?}");
        }
        // Literal string, so the value itself carries the backslash.
        let backslash = one_job("commands = [\"make\"]\nartifacts = ['back\\slash']\n".to_owned());
        assert!(err(&backslash).contains("artifact"));
        let ok = one_job(
            "commands = [\"make\"]\nartifacts = [\"target/nextest/**\", \"coverage.lcov\", \"dist/*.tar.gz\"]\n"
                .to_owned(),
        );
        CiSpec::parse(&ok).expect("valid artifact globs must parse");
    }

    #[test]
    fn push_globs_are_validated() {
        for pattern in ["/abs", "a b", "a//b", "../x", "..", "trail/"] {
            let text = format!(
                "version = 1\n\n[triggers]\npush = [\"{pattern}\"]\n\n[[jobs]]\nname = \"test\"\nimage = \"rust:1.85\"\ncommands = [\"make\"]\n"
            );
            assert!(err(&text).contains("push trigger"), "pattern: {pattern:?}");
        }
        // A backslash must be escaped in a TOML basic string; use a literal
        // string so the value itself contains one (which the validator rejects).
        let backslash = "version = 1\n\n[triggers]\npush = ['back\\slash']\n\n[[jobs]]\nname = \"test\"\nimage = \"rust:1.85\"\ncommands = [\"make\"]\n";
        assert!(err(backslash).contains("push trigger"));
        let ok = "version = 1\n\n[triggers]\npush = [\"main\", \"release/*\", \"feature-*\", \"v?.?\"]\n\n[[jobs]]\nname = \"test\"\nimage = \"rust:1.85\"\ncommands = [\"make\"]\n";
        CiSpec::parse(ok).expect("valid push globs must parse");
    }

    #[test]
    fn trail_actions_are_validated() {
        let text = "version = 1\n\n[triggers]\ntrail = [\"closed\"]\n\n[[jobs]]\nname = \"test\"\nimage = \"rust:1.85\"\ncommands = [\"make\"]\n";
        assert!(err(text).contains("invalid trail action"));
        let duplicate = "version = 1\n\n[triggers]\ntrail = [\"opened\", \"opened\"]\n\n[[jobs]]\nname = \"test\"\nimage = \"rust:1.85\"\ncommands = [\"make\"]\n";
        assert!(err(duplicate).contains("duplicate trail action"));
    }

    #[test]
    fn runs_on_labels_are_validated() {
        let bad = one_job("commands = [\"make\"]\nruns_on = [\"not a label\"]\n".to_owned());
        assert!(err(&bad).contains("runs_on label"));
        let duplicate =
            one_job("commands = [\"make\"]\nruns_on = [\"linux\", \"linux\"]\n".to_owned());
        assert!(err(&duplicate).contains("duplicate runs_on label"));
    }

    #[test]
    fn oversized_spec_is_rejected() {
        let mut text = VALID.to_owned();
        let padding = MAX_SPEC_BYTES - text.len();
        text.push_str("# ");
        text.push_str(&"x".repeat(padding));
        text.push('\n');
        assert!(text.len() > MAX_SPEC_BYTES);
        assert!(err(&text).contains("over the 262144-byte limit"));
    }

    #[test]
    fn validate_rejects_programmatic_bad_spec() {
        let spec = CiSpec {
            version: 1,
            triggers: CiTriggers {
                push: vec!["main".to_owned()],
                trail: Vec::new(),
            },
            jobs: vec![CiJobSpec {
                name: "test".to_owned(),
                image: Some("rust:1.85".to_owned()),
                template: None,
                commands: Vec::new(),
                timeout: None,
                env: BTreeMap::new(),
                secrets: Vec::new(),
                artifacts: Vec::new(),
                runs_on: Vec::new(),
            }],
        };
        assert!(spec.validate().is_err());
    }
}
