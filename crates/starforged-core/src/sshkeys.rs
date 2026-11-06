//! SSH keys and deploy keys (spec §6.1, D2–D4): a hand-written OpenSSH
//! public-key parser, fingerprinting, and key management.

use base64::Engine as _;
use sha2::{Digest, Sha256};
use starforged_db::sshkeys as db_keys;

use crate::accounts::User;
use crate::permission::Permission;
use crate::{Core, CoreError, CoreResult};

/// Caps from D3.
pub const MAX_KEYS_PER_USER: i64 = 100;
pub const MAX_DEPLOY_KEYS_PER_REPO: i64 = 50;
/// RSA keys must have at least this many modulus bits (D2).
pub const MIN_RSA_BITS: u32 = 2048;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    pub algorithm: String,
    pub blob: Vec<u8>,
    pub comment: String,
    pub bits: u32,
}

pub fn parse_public_key(line: &str) -> Result<PublicKey, CoreError> {
    let invalid = |msg: &str| CoreError::Invalid(msg.to_owned());
    let line = line.trim();
    if line.is_empty() {
        return Err(invalid("a public key is required"));
    }
    // Multiple keys (or a pasted file) are refused: one line only.
    if line.contains('\n') || line.contains('\r') {
        return Err(invalid("only one key per line is accepted"));
    }
    // Options prefixes (e.g. `restrict ssh-ed25519 …`) make the first token
    // something other than an algorithm; rejected by the check below.
    let mut parts = line.split_whitespace();
    let algorithm = parts
        .next()
        .ok_or_else(|| invalid("a public key is required"))?;
    let b64 = parts
        .next()
        .ok_or_else(|| invalid("the key data is missing"))?;
    let comment = parts.collect::<Vec<_>>().join(" ");
    if !is_accepted(algorithm) {
        return Err(invalid("unsupported key algorithm"));
    }
    let blob = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|_| invalid("the key data is not valid base64"))?;
    let bits = parse_blob(algorithm, &blob)?;
    Ok(PublicKey {
        algorithm: algorithm.to_owned(),
        blob,
        comment,
        bits,
    })
}

fn is_accepted(algorithm: &str) -> bool {
    matches!(
        algorithm,
        "ssh-ed25519"
            | "ecdsa-sha2-nistp256"
            | "ecdsa-sha2-nistp384"
            | "ecdsa-sha2-nistp521"
            | "ssh-rsa"
    )
}

/// Reads one wire-format string (`u32` length + bytes) at `pos`.
fn read_string<'a>(blob: &'a [u8], pos: &mut usize) -> Result<&'a [u8], CoreError> {
    let invalid = || CoreError::Invalid("the key data is truncated".into());
    let len_bytes = blob.get(*pos..*pos + 4).ok_or_else(invalid)?;
    let len = u32::from_be_bytes(len_bytes.try_into().unwrap()) as usize;
    *pos += 4;
    let value = blob.get(*pos..*pos + len).ok_or_else(invalid)?;
    *pos += len;
    Ok(value)
}

fn parse_blob(algorithm: &str, blob: &[u8]) -> Result<u32, CoreError> {
    let invalid = |msg: &str| CoreError::Invalid(msg.to_owned());
    let mut pos = 0usize;
    let inner = read_string(blob, &mut pos)?;
    if inner != algorithm.as_bytes() {
        return Err(invalid("the key algorithm does not match its data"));
    }
    match algorithm {
        "ssh-ed25519" => {
            let key = read_string(blob, &mut pos)?;
            if key.len() != 32 {
                return Err(invalid("the ed25519 key is malformed"));
            }
            if pos != blob.len() {
                return Err(invalid("the key data has trailing bytes"));
            }
            Ok(256)
        }
        "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521" => {
            let (curve, bits) = match algorithm {
                "ecdsa-sha2-nistp256" => ("nistp256", 256),
                "ecdsa-sha2-nistp384" => ("nistp384", 384),
                _ => ("nistp521", 521),
            };
            let curve_id = read_string(blob, &mut pos)?;
            if curve_id != curve.as_bytes() {
                return Err(invalid("the key curve does not match its algorithm"));
            }
            let point = read_string(blob, &mut pos)?;
            if point.is_empty() {
                return Err(invalid("the ecdsa key is malformed"));
            }
            if pos != blob.len() {
                return Err(invalid("the key data has trailing bytes"));
            }
            Ok(bits)
        }
        "ssh-rsa" => {
            let _e = read_string(blob, &mut pos)?;
            let n = read_string(blob, &mut pos)?;
            if pos != blob.len() {
                return Err(invalid("the key data has trailing bytes"));
            }
            let bits = mpint_bits(n);
            if bits < MIN_RSA_BITS {
                return Err(invalid("RSA keys must be at least 2048 bits"));
            }
            Ok(bits)
        }
        _ => Err(invalid("unsupported key algorithm")),
    }
}

/// The bit length of an mpint's magnitude, ignoring leading zero bytes.
fn mpint_bits(magnitude: &[u8]) -> u32 {
    let stripped: &[u8] = {
        let mut start = 0;
        while start < magnitude.len() && magnitude[start] == 0 {
            start += 1;
        }
        &magnitude[start..]
    };
    match stripped.split_first() {
        None => 0,
        Some((&first, rest)) => {
            let whole = rest.len() as u32 * 8;
            whole + (8 - first.leading_zeros())
        }
    }
}

/// `SHA256:` + base64 (STANDARD alphabet, no padding) of SHA-256(blob).
pub fn fingerprint(blob: &[u8]) -> String {
    format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(Sha256::digest(blob))
    )
}

#[derive(Debug, Clone)]
pub struct SshKeyView {
    pub id: i64,
    pub title: String,
    pub algorithm: String,
    pub fingerprint: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct DeployKeyView {
    pub id: i64,
    pub title: String,
    pub algorithm: String,
    pub fingerprint: String,
    pub read_write: bool,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub enum KeyIdentity {
    User(User),
    Deploy {
        key_id: i64,
        repo_id: i64,
        read_write: bool,
    },
}

fn checked_title(title: &str) -> CoreResult<String> {
    let title = title.trim();
    if title.is_empty() || title.chars().count() > 128 {
        return Err(CoreError::Invalid("key titles are 1-128 characters".into()));
    }
    Ok(title.to_owned())
}

/// The canonical OpenSSH line stored and returned for a key.
pub fn canonical_line(algorithm: &str, blob: &[u8], comment: &str) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(blob);
    if comment.is_empty() {
        format!("{algorithm} {b64}")
    } else {
        format!("{algorithm} {b64} {comment}")
    }
}

impl Core {
    pub async fn add_ssh_key(&self, user: &User, title: &str, key: &str) -> CoreResult<SshKeyView> {
        let title = checked_title(title)?;
        let parsed = parse_public_key(key)?;
        let fp = fingerprint(&parsed.blob);
        let public_key = canonical_line(&parsed.algorithm, &parsed.blob, &parsed.comment);
        let id = match db_keys::insert_ssh_key(
            self.db(),
            &db_keys::NewSshKey {
                user_id: user.id,
                title: &title,
                algorithm: &parsed.algorithm,
                fingerprint: &fp,
                public_key: &public_key,
            },
            MAX_KEYS_PER_USER,
        )
        .await?
        {
            Ok(id) => id,
            Err(db_keys::AddKeyError::Duplicate) => {
                return Err(CoreError::Invalid("this key is already in use".into()));
            }
            Err(db_keys::AddKeyError::TooMany) => {
                return Err(CoreError::Invalid("too many SSH keys (maximum 100)".into()));
            }
        };
        self.audit(Some(user.id), "ssh_key.add", &format!("ssh_key:{id}"), &fp)
            .await?;
        Ok(SshKeyView {
            id,
            title,
            algorithm: parsed.algorithm,
            fingerprint: fp,
            created_at: starforged_db::now(),
            last_used_at: None,
        })
    }

    pub async fn ssh_keys(&self, user: &User) -> CoreResult<Vec<SshKeyView>> {
        Ok(db_keys::list_ssh_keys(self.db(), user.id)
            .await?
            .into_iter()
            .map(|row| SshKeyView {
                id: row.id,
                title: row.title,
                algorithm: row.algorithm,
                fingerprint: row.fingerprint,
                created_at: row.created_at,
                last_used_at: row.last_used_at,
            })
            .collect())
    }

    pub async fn remove_ssh_key(&self, user: &User, id: i64) -> CoreResult<()> {
        if !db_keys::remove_ssh_key(self.db(), user.id, id).await? {
            return Err(CoreError::NotFound);
        }
        self.audit(
            Some(user.id),
            "ssh_key.remove",
            &format!("ssh_key:{id}"),
            "",
        )
        .await
    }

    pub async fn add_deploy_key(
        &self,
        user: &User,
        owner: &str,
        repo: &str,
        title: &str,
        key: &str,
        read_write: bool,
    ) -> CoreResult<DeployKeyView> {
        let access = self
            .require_repo(Some(user), owner, repo, Permission::Admin)
            .await?;
        if access.repo.archived_at.is_some() {
            return Err(CoreError::Invalid(
                "archived repositories cannot gain deploy keys".into(),
            ));
        }
        let title = checked_title(title)?;
        let parsed = parse_public_key(key)?;
        let fp = fingerprint(&parsed.blob);
        let public_key = canonical_line(&parsed.algorithm, &parsed.blob, &parsed.comment);
        let id = match db_keys::insert_deploy_key(
            self.db(),
            &db_keys::NewDeployKey {
                repo_id: access.repo.id,
                title: &title,
                algorithm: &parsed.algorithm,
                fingerprint: &fp,
                public_key: &public_key,
                read_write,
                created_by: user.id,
            },
            MAX_DEPLOY_KEYS_PER_REPO,
        )
        .await?
        {
            Ok(id) => id,
            Err(db_keys::AddKeyError::Duplicate) => {
                return Err(CoreError::Invalid("this key is already in use".into()));
            }
            Err(db_keys::AddKeyError::TooMany) => {
                return Err(CoreError::Invalid(
                    "too many deploy keys (maximum 50)".into(),
                ));
            }
        };
        self.audit(
            Some(user.id),
            "deploy_key.add",
            &format!("deploy_key:{id}"),
            &format!("repo:{}", access.repo.full_name()),
        )
        .await?;
        Ok(DeployKeyView {
            id,
            title,
            algorithm: parsed.algorithm,
            fingerprint: fp,
            read_write,
            created_at: starforged_db::now(),
            last_used_at: None,
        })
    }

    pub async fn deploy_keys(
        &self,
        user: &User,
        owner: &str,
        repo: &str,
    ) -> CoreResult<Vec<DeployKeyView>> {
        let access = self
            .require_repo(Some(user), owner, repo, Permission::Admin)
            .await?;
        Ok(db_keys::list_deploy_keys(self.db(), access.repo.id)
            .await?
            .into_iter()
            .map(|row| DeployKeyView {
                id: row.id,
                title: row.title,
                algorithm: row.algorithm,
                fingerprint: row.fingerprint,
                read_write: row.read_write,
                created_at: row.created_at,
                last_used_at: row.last_used_at,
            })
            .collect())
    }

    pub async fn remove_deploy_key(
        &self,
        user: &User,
        owner: &str,
        repo: &str,
        id: i64,
    ) -> CoreResult<()> {
        let access = self
            .require_repo(Some(user), owner, repo, Permission::Admin)
            .await?;
        if !db_keys::remove_deploy_key(self.db(), access.repo.id, id).await? {
            return Err(CoreError::NotFound);
        }
        self.audit(
            Some(user.id),
            "deploy_key.remove",
            &format!("deploy_key:{id}"),
            &format!("repo:{}", access.repo.full_name()),
        )
        .await
    }

    /// Authentication lookup used by starforged-ssh; touches `last_used_at`
    /// (throttled to once a minute). Suspended users never authenticate.
    pub async fn identity_for_key(&self, fp: &str) -> CoreResult<Option<KeyIdentity>> {
        if let Some(row) = db_keys::ssh_key_by_fingerprint(self.db(), fp).await? {
            let user = self.user_by_id(row.user_id).await?.filter(|u| u.active);
            let Some(user) = user else {
                return Ok(None);
            };
            if db_keys::touch_due(row.last_used_at) {
                db_keys::touch_ssh_key(self.db(), row.id).await?;
            }
            return Ok(Some(KeyIdentity::User(user)));
        }
        if let Some(row) = db_keys::deploy_key_by_fingerprint(self.db(), fp).await? {
            if db_keys::touch_due(row.last_used_at) {
                db_keys::touch_deploy_key(self.db(), row.id).await?;
            }
            return Ok(Some(KeyIdentity::Deploy {
                key_id: row.id,
                repo_id: row.repo_id,
                read_write: row.read_write,
            }));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::{CreateUser, User};
    use crate::permission::Visibility;
    use crate::repos::CreateRepo;
    use crate::testing::test_core;

    fn ed25519_key() -> String {
        // ssh-ed25519 blob: "ssh-ed25519" || 32 zero bytes.
        let mut blob = Vec::new();
        for part in [&b"ssh-ed25519"[..], &[0u8; 32]] {
            blob.extend_from_slice(&(part.len() as u32).to_be_bytes());
            blob.extend_from_slice(part);
        }
        format!(
            "ssh-ed25519 {} test@example",
            base64::engine::general_purpose::STANDARD.encode(&blob)
        )
    }

    fn rsa_key(bits: usize) -> String {
        // ssh-rsa blob: "ssh-rsa" || e=65537 || n (odd, top bit set).
        let nbytes = bits.div_ceil(8);
        let mut n = vec![0xAAu8; nbytes];
        n[0] |= 0x80;
        n[nbytes - 1] |= 1;
        let mut n_mpint = vec![0u8];
        n_mpint.extend_from_slice(&n);
        let mut blob = Vec::new();
        for part in [&b"ssh-rsa"[..], &[1, 0, 1], &n_mpint[..]] {
            blob.extend_from_slice(&(part.len() as u32).to_be_bytes());
            blob.extend_from_slice(part);
        }
        format!(
            "ssh-rsa {} test@example",
            base64::engine::general_purpose::STANDARD.encode(&blob)
        )
    }

    fn ecdsa_key(algo: &str, curve: &str) -> String {
        let mut blob = Vec::new();
        for part in [algo.as_bytes(), curve.as_bytes(), b"\x04point".as_slice()] {
            blob.extend_from_slice(&(part.len() as u32).to_be_bytes());
            blob.extend_from_slice(part);
        }
        format!(
            "{algo} {} test@example",
            base64::engine::general_purpose::STANDARD.encode(&blob)
        )
    }

    #[test]
    fn parses_ed25519() {
        let key = parse_public_key(&ed25519_key()).unwrap();
        assert_eq!(key.algorithm, "ssh-ed25519");
        assert_eq!(key.bits, 256);
        assert_eq!(key.comment, "test@example");
        assert!(fingerprint(&key.blob).starts_with("SHA256:"));
    }

    #[test]
    fn parses_ecdsa_curves() {
        for (algo, curve, bits) in [
            ("ecdsa-sha2-nistp256", "nistp256", 256),
            ("ecdsa-sha2-nistp384", "nistp384", 384),
            ("ecdsa-sha2-nistp521", "nistp521", 521),
        ] {
            let key = parse_public_key(&ecdsa_key(algo, curve)).unwrap();
            assert_eq!(key.bits, bits);
        }
    }

    #[test]
    fn parses_rsa_at_least_2048_bits() {
        let key = parse_public_key(&rsa_key(3072)).unwrap();
        assert_eq!(key.bits, 3072);
    }

    #[test]
    fn refuses_weak_rsa_mismatched_blob_options_and_garbage() {
        assert!(parse_public_key(&rsa_key(1024)).is_err());
        // Blob algorithm disagrees with the line prefix.
        let mut blob = Vec::new();
        for part in [&b"ssh-rsa"[..], &b"AAAA"[..]] {
            blob.extend_from_slice(&(part.len() as u32).to_be_bytes());
            blob.extend_from_slice(part);
        }
        let mismatched = format!(
            "ssh-ed25519 {}",
            base64::engine::general_purpose::STANDARD.encode(&blob)
        );
        assert!(parse_public_key(&mismatched).is_err());
        // Options prefix.
        assert!(parse_public_key(&format!("restrict {}", ed25519_key())).is_err());
        // Multiple keys.
        let twice = format!("{}\n{}", ed25519_key(), ed25519_key());
        assert!(parse_public_key(&twice).is_err());
        // Garbage.
        assert!(parse_public_key("garbage").is_err());
        assert!(parse_public_key("").is_err());
        assert!(parse_public_key("ssh-ed25519 not-base64!!").is_err());
    }

    async fn make_user(core: &Core, handle: &str) -> User {
        core.create_user(CreateUser {
            handle: handle.into(),
            ..Default::default()
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn user_keys_add_list_remove_and_duplicate_is_invalid() {
        let (core, _f) = test_core().await;
        let alice = make_user(&core, "alice").await;
        let bob = make_user(&core, "bob").await;
        let line = ed25519_key();
        let added = core.add_ssh_key(&alice, "laptop", &line).await.unwrap();
        assert_eq!(added.title, "laptop");
        assert_eq!(core.ssh_keys(&alice).await.unwrap().len(), 1);
        // Duplicate across users.
        assert!(core.add_ssh_key(&bob, "copy", &line).await.is_err());
        core.remove_ssh_key(&alice, added.id).await.unwrap();
        assert!(core.ssh_keys(&alice).await.unwrap().is_empty());
        assert!(core.remove_ssh_key(&alice, added.id).await.is_err());
        // Another user cannot remove alice's key.
        let added = core.add_ssh_key(&alice, "laptop", &line).await.unwrap();
        assert!(core.remove_ssh_key(&bob, added.id).await.is_err());
    }

    #[tokio::test]
    async fn deploy_keys_need_admin_and_refuse_archived_repos() {
        let (core, _f) = test_core().await;
        let alice = make_user(&core, "alice").await;
        let bob = make_user(&core, "bob").await;
        core.create_repo(
            &alice,
            &alice.handle,
            CreateRepo {
                name: "proj".into(),
                description: String::new(),
                visibility: Visibility::Private,
                readme: false,
            },
        )
        .await
        .unwrap();
        // Non-reader gets NotFound; maintain (bob is not even a reader) → NotFound.
        assert!(matches!(
            core.add_deploy_key(&bob, "alice", "proj", "k", &ed25519_key(), false)
                .await,
            Err(CoreError::NotFound)
        ));
        let added = core
            .add_deploy_key(&alice, "alice", "proj", "deploy", &ed25519_key(), true)
            .await
            .unwrap();
        assert!(added.read_write);
        assert_eq!(
            core.deploy_keys(&alice, "alice", "proj")
                .await
                .unwrap()
                .len(),
            1
        );
        // User-key duplicate of a deploy key is refused.
        assert!(
            core.add_ssh_key(&alice, "copy", &ed25519_key())
                .await
                .is_err()
        );
        core.remove_deploy_key(&alice, "alice", "proj", added.id)
            .await
            .unwrap();
        // Archive the repo: adds refused.
        core.archive_repo(&alice, "alice", "proj").await.unwrap();
        assert!(
            core.add_deploy_key(&alice, "alice", "proj", "late", &ed25519_key(), false)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn identity_for_key_honours_suspension() {
        let (core, _f) = test_core().await;
        let alice = make_user(&core, "alice").await;
        let admin = core
            .create_user(CreateUser {
                handle: "siteadmin".into(),
                is_admin: true,
                ..Default::default()
            })
            .await
            .unwrap();
        let added = core
            .add_ssh_key(&alice, "laptop", &ed25519_key())
            .await
            .unwrap();
        let identity = core
            .identity_for_key(&added.fingerprint)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(&identity, KeyIdentity::User(u) if u.id == alice.id));
        core.suspend_user(&admin, alice.id).await.unwrap();
        assert!(
            core.identity_for_key(&added.fingerprint)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            core.identity_for_key("SHA256:unknown")
                .await
                .unwrap()
                .is_none()
        );
    }
    #[tokio::test]
    async fn concurrent_duplicate_user_keys_give_one_success() {
        let (core, _f) = test_core().await;
        let alice = make_user(&core, "alice").await;
        let bob = make_user(&core, "bob").await;
        let line = ed25519_key();
        let (a, b) = {
            let c1 = core.clone();
            let c2 = core.clone();
            tokio::join!(
                c1.add_ssh_key(&alice, "one", &line),
                c2.add_ssh_key(&bob, "two", &line),
            )
        };
        let oks = a.is_ok() as usize + b.is_ok() as usize;
        assert_eq!(oks, 1, "exactly one add succeeds");
        assert!(
            matches!(&a, Err(CoreError::Invalid(_))) || matches!(&b, Err(CoreError::Invalid(_)))
        );
        assert!(
            [
                core.ssh_keys(&alice).await.unwrap().len(),
                core.ssh_keys(&bob).await.unwrap().len()
            ]
            .into_iter()
            .sum::<usize>()
                == 1
        );
    }

    #[tokio::test]
    async fn concurrent_user_and_deploy_same_key_give_one_success() {
        let (core, _f) = test_core().await;
        let alice = make_user(&core, "alice").await;
        core.create_repo(
            &alice,
            &alice.handle,
            CreateRepo {
                name: "proj".into(),
                description: String::new(),
                visibility: Visibility::Private,
                readme: false,
            },
        )
        .await
        .unwrap();
        let line = ed25519_key();
        let (a, b) = {
            let c1 = core.clone();
            let c2 = core.clone();
            tokio::join!(
                c1.add_ssh_key(&alice, "user", &line),
                c2.add_deploy_key(&alice, "alice", "proj", "deploy", &line, false),
            )
        };
        assert_eq!(a.is_ok() as usize + b.is_ok() as usize, 1);
        assert!(
            matches!(&a, Err(CoreError::Invalid(_))) || matches!(&b, Err(CoreError::Invalid(_)))
        );
        assert_eq!(
            core.ssh_keys(&alice).await.unwrap().len()
                + core
                    .deploy_keys(&alice, "alice", "proj")
                    .await
                    .unwrap()
                    .len(),
            1
        );
    }
}
