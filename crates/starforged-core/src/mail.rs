//! Outgoing email (forge-basics design §3, §9): plain-text messages, queued as jobs and sent over SMTP, or
//! written as `.eml` files with `file://` (development and tests).

use std::net::IpAddr;
use std::path::PathBuf;

use askama::Template;
use lettre::message::Mailbox;
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncFileTransport, AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use percent_encoding::percent_decode_str;

use crate::jobs::Job;
use crate::{Core, CoreError, CoreResult};

/// One message, ready to queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Email {
    pub to: String,
    pub subject: String,
    pub body: String,
}

/// Delivers messages; built from `[mail]` by [`Mailer::from_config`]. Cheap to clone.
#[derive(Clone)]
pub struct Mailer {
    transport: Transport,
    from: Mailbox,
}

#[derive(Clone)]
enum Transport {
    Smtp(AsyncSmtpTransport<Tokio1Executor>),
    File {
        dir: PathBuf,
        transport: AsyncFileTransport<Tokio1Executor>,
    },
}

/// Never prints the transport's settings: they can hold SMTP credentials.
impl std::fmt::Debug for Mailer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let transport = match &self.transport {
            Transport::Smtp(_) => "smtp",
            Transport::File { .. } => "file",
        };
        f.debug_struct("Mailer")
            .field("transport", &transport)
            .field("from", &self.from.to_string())
            .finish()
    }
}

fn invalid(message: impl Into<String>) -> CoreError {
    CoreError::Invalid(message.into())
}

fn is_loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

impl Mailer {
    /// Reads `mail.url` and `mail.from` (forge-basics design §3). `Ok(None)` when `url` is empty: the instance
    /// sends no email.
    pub fn from_config(url: &str, from: &str) -> CoreResult<Option<Mailer>> {
        let url = url.trim();
        if url.is_empty() {
            return Ok(None);
        }
        let from: Mailbox = from.trim().parse().map_err(|_| {
            invalid("mail.from must be a mailbox such as \"Starforge <forge@example.com>\"")
        })?;
        let parsed = url::Url::parse(url)
            .map_err(|e| invalid(format!("mail.url is not a valid URL: {e}")))?;
        let transport = match parsed.scheme() {
            "file" => {
                let dir = parsed
                    .to_file_path()
                    .map_err(|()| invalid("mail.url must look like file:///absolute/path"))?;
                Transport::File {
                    transport: AsyncFileTransport::new(&dir),
                    dir,
                }
            }
            "smtp" | "smtps" => Transport::Smtp(smtp_transport(&parsed)?),
            other => {
                return Err(invalid(format!(
                    "mail.url must start with smtp://, smtps://, or file://, not {other}://"
                )));
            }
        };
        Ok(Some(Mailer { transport, from }))
    }

    /// Sends one message now. Workers call this for queued mail; `starforged admin mail test` calls it directly.
    pub async fn send(&self, email: &Email) -> CoreResult<()> {
        let to: Mailbox = email
            .to
            .parse()
            .map_err(|_| invalid(format!("not an email address: {}", email.to)))?;
        let message = Message::builder()
            .from(self.from.clone())
            .to(to)
            .subject(email.subject.clone())
            .header(ContentType::TEXT_PLAIN)
            .body(email.body.clone())
            .map_err(|e| CoreError::Internal(format!("building a message: {e}")))?;
        match &self.transport {
            Transport::Smtp(smtp) => {
                smtp.send(message)
                    .await
                    .map_err(|e| CoreError::Internal(format!("smtp: {e}")))?;
            }
            Transport::File { dir, transport } => {
                tokio::fs::create_dir_all(dir)
                    .await
                    .map_err(|e| CoreError::Internal(format!("creating {}: {e}", dir.display())))?;
                transport
                    .send(message)
                    .await
                    .map_err(|e| CoreError::Internal(format!("writing mail: {e}")))?;
            }
        }
        Ok(())
    }
}

/// `smtp://` requires STARTTLS unless `?tls=none` names a loopback host; `smtps://` is implicit TLS.
fn smtp_transport(url: &url::Url) -> CoreResult<AsyncSmtpTransport<Tokio1Executor>> {
    let host = url
        .host_str()
        .filter(|h| !h.is_empty())
        .ok_or_else(|| invalid("mail.url needs a host"))?
        .trim_start_matches('[')
        .trim_end_matches(']');
    let mut tls_none = false;
    for (key, value) in url.query_pairs() {
        if key == "tls" && value == "none" {
            tls_none = true;
        } else {
            return Err(invalid(format!(
                "mail.url: unsupported parameter {key}={value}"
            )));
        }
    }
    let builder = match (url.scheme(), tls_none) {
        ("smtps", true) => return Err(invalid("mail.url: tls=none applies only to smtp://")),
        ("smtps", false) => AsyncSmtpTransport::<Tokio1Executor>::relay(host)
            .map_err(|e| invalid(format!("mail.url: {e}")))?
            .port(url.port().unwrap_or(465)),
        (_, true) if !is_loopback(host) => {
            return Err(invalid(
                "mail.url: tls=none is allowed only for loopback hosts",
            ));
        }
        (_, true) => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host)
            .port(url.port().unwrap_or(25)),
        (_, false) => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host)
            .map_err(|e| invalid(format!("mail.url: {e}")))?
            .port(url.port().unwrap_or(587)),
    };
    let builder = if url.username().is_empty() {
        builder
    } else {
        let decode = |s: &str| percent_decode_str(s).decode_utf8_lossy().into_owned();
        builder.credentials(Credentials::new(
            decode(url.username()),
            decode(url.password().unwrap_or("")),
        ))
    };
    Ok(builder.build())
}

fn render(template: &impl Template) -> CoreResult<String> {
    template
        .render()
        .map_err(|e| CoreError::Internal(format!("rendering an email: {e}")))
}

#[derive(Template)]
#[template(path = "mail/test.txt")]
struct TestText<'a> {
    base_url: &'a str,
}

/// The `starforged admin mail test` message.
pub fn test_email(to: &str, base_url: &str) -> CoreResult<Email> {
    Ok(Email {
        to: to.to_owned(),
        subject: "Starforge test email".into(),
        body: render(&TestText { base_url })?,
    })
}
#[derive(Template)]
#[template(path = "mail/verify_email.txt")]
struct VerifyEmailText<'a> {
    handle: &'a str,
    link: &'a str,
}

/// "Verify your email address", with a link valid for 24 hours.
pub(crate) fn verify_email(to: &str, handle: &str, link: &str) -> CoreResult<Email> {
    Ok(Email {
        to: to.to_owned(),
        subject: "Verify your email address".into(),
        body: render(&VerifyEmailText { handle, link })?,
    })
}

#[derive(Template)]
#[template(path = "mail/invite.txt")]
struct InviteText<'a> {
    inviter: &'a str,
    link: &'a str,
}

/// An invite to sign up, with a link valid for 7 days.
pub(crate) fn invite_email(to: &str, inviter: &str, link: &str) -> CoreResult<Email> {
    Ok(Email {
        to: to.to_owned(),
        subject: format!("{inviter} invited you to Starforge"),
        body: render(&InviteText { inviter, link })?,
    })
}

#[derive(Template)]
#[template(path = "mail/reset_password.txt")]
struct ResetPasswordText<'a> {
    handle: &'a str,
    link: &'a str,
}

/// A password-reset link valid for 1 hour.
pub(crate) fn reset_email(to: &str, handle: &str, link: &str) -> CoreResult<Email> {
    Ok(Email {
        to: to.to_owned(),
        subject: "Reset your Starforge password".into(),
        body: render(&ResetPasswordText { handle, link })?,
    })
}

impl Core {
    /// Whether this instance sends email (`[mail] url` is set).
    pub fn mail_enabled(&self) -> bool {
        self.config().mailer.is_some()
    }

    /// Queues `email` for the workers. Callers check [`Core::mail_enabled`] first.
    pub(crate) async fn queue_email(&self, email: Email) -> CoreResult<()> {
        if !self.mail_enabled() {
            return Err(CoreError::Internal("mail is not configured".into()));
        }
        self.enqueue(&Job::SendEmail {
            to: email.to,
            subject: email.subject,
            body: email.body,
        })
        .await
    }
}

/// Reading `.eml` files written by the `file://` transport (tests only).
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    use std::path::Path;

    /// Every message in `dir`, oldest first, with quoted-printable bodies decoded.
    pub fn read_mailbox(dir: &Path) -> Vec<String> {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return Vec::new();
        };
        let mut files: Vec<(std::time::SystemTime, std::path::PathBuf)> = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "eml"))
            .map(|path| (std::fs::metadata(&path).unwrap().modified().unwrap(), path))
            .collect();
        files.sort();
        files
            .into_iter()
            .map(|(_, path)| decode_eml(&std::fs::read_to_string(path).unwrap()))
            .collect()
    }

    /// Normalizes line endings and decodes a quoted-printable body (lettre encodes long lines that way).
    pub fn decode_eml(raw: &str) -> String {
        let raw = raw.replace("\r\n", "\n");
        let Some((headers, body)) = raw.split_once("\n\n") else {
            return raw;
        };
        if !headers
            .to_ascii_lowercase()
            .contains("content-transfer-encoding: quoted-printable")
        {
            return raw;
        }
        let bytes = body.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'=' {
                if bytes.get(i + 1) == Some(&b'\n') {
                    i += 2;
                    continue;
                }
                if let (Some(&high), Some(&low)) = (bytes.get(i + 1), bytes.get(i + 2))
                    && high.is_ascii_hexdigit()
                    && low.is_ascii_hexdigit()
                {
                    let hex = [high, low];
                    let text = std::str::from_utf8(&hex).unwrap();
                    out.push(u8::from_str_radix(text, 16).unwrap());
                    i += 3;
                    continue;
                }
            }
            out.push(bytes[i]);
            i += 1;
        }
        format!("{headers}\n\n{}", String::from_utf8_lossy(&out))
    }

    /// The first `http://` or `https://` link in `message` whose path starts with `path_prefix`.
    pub fn find_link(message: &str, path_prefix: &str) -> Option<String> {
        message
            .split_whitespace()
            .filter(|word| word.starts_with("http://") || word.starts_with("https://"))
            .find(|word| url::Url::parse(word).is_ok_and(|u| u.path().starts_with(path_prefix)))
            .map(str::to_owned)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    use super::*;
    use crate::testing::{test_core_with, with_file_mail};

    const FROM: &str = "Starforge <forge@example.com>";

    fn error_of(url: &str, from: &str) -> String {
        Mailer::from_config(url, from).unwrap_err().to_string()
    }

    #[test]
    fn mail_urls_are_checked() {
        assert!(Mailer::from_config("", FROM).unwrap().is_none());
        for good in [
            "smtp://user:p%40ss@mail.example.com:2525",
            "smtps://mail.example.com",
            "smtp://127.0.0.1:25?tls=none",
            "smtp://localhost?tls=none",
            "file:///tmp/starforge-mail",
        ] {
            assert!(Mailer::from_config(good, FROM).unwrap().is_some(), "{good}");
        }
        assert!(error_of("smtp://mail.example.com?tls=none", FROM).contains("loopback"));
        assert!(error_of("smtps://localhost?tls=none", FROM).contains("only to smtp://"));
        assert!(error_of("smtp://mail.example.com?port=1", FROM).contains("unsupported parameter"));
        assert!(error_of("ftp://mail.example.com", FROM).contains("smtp://, smtps://, or file://"));
        assert!(error_of("smtp://mail.example.com", "").contains("mail.from"));
    }

    #[test]
    fn debug_output_hides_credentials() {
        let mailer = Mailer::from_config("smtp://mailuser:hunter2secret@mail.example.com", FROM)
            .unwrap()
            .unwrap();
        let shown = format!("{mailer:?}");
        assert!(
            !shown.contains("hunter2secret") && !shown.contains("mailuser"),
            "{shown}"
        );
    }

    /// A minimal SMTP server that never offers STARTTLS. Returns its port and, once the client hangs up, the
    /// lines it received.
    async fn plaintext_smtp_server() -> (u16, tokio::task::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read, mut write) = stream.into_split();
            let mut lines = BufReader::new(read).lines();
            let mut seen = Vec::new();
            write.write_all(b"220 test ESMTP\r\n").await.unwrap();
            let mut in_data = false;
            while let Ok(Some(line)) = lines.next_line().await {
                seen.push(line.clone());
                if in_data {
                    if line == "." {
                        in_data = false;
                        write.write_all(b"250 queued\r\n").await.unwrap();
                    }
                    continue;
                }
                let command = line.to_ascii_uppercase();
                let reply: &[u8] = if command.starts_with("EHLO") {
                    b"250-test\r\n250 AUTH PLAIN\r\n"
                } else if command == "DATA" {
                    in_data = true;
                    b"354 go ahead\r\n"
                } else if command == "QUIT" {
                    write.write_all(b"221 bye\r\n").await.unwrap();
                    break;
                } else {
                    b"250 ok\r\n"
                };
                write.write_all(reply).await.unwrap();
            }
            seen
        });
        (port, server)
    }

    #[tokio::test]
    async fn smtp_requires_starttls_unless_tls_none_on_loopback() {
        let email = test_email("ops@example.com", "http://forge.test").unwrap();

        let (port, server) = plaintext_smtp_server().await;
        let mailer = Mailer::from_config(&format!("smtp://user:secret@127.0.0.1:{port}"), FROM)
            .unwrap()
            .unwrap();
        let err = mailer.send(&email).await.unwrap_err();
        assert!(err.to_string().contains("STARTTLS"), "{err}");
        drop(mailer);
        let seen = tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
        assert!(
            !seen
                .iter()
                .any(|l| l.starts_with("AUTH") || l.starts_with("MAIL")),
            "nothing may be sent in clear: {seen:?}"
        );

        let (port, server) = plaintext_smtp_server().await;
        let mailer = Mailer::from_config(&format!("smtp://127.0.0.1:{port}?tls=none"), FROM)
            .unwrap()
            .unwrap();
        mailer.send(&email).await.unwrap();
        drop(mailer);
        let seen = tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
        assert!(
            seen.iter()
                .any(|l| l.starts_with("MAIL FROM:<forge@example.com>")),
            "{seen:?}"
        );
    }

    #[tokio::test]
    async fn queued_email_is_sent_and_its_body_blanked() {
        let (core, fixture) = test_core_with(with_file_mail).await;
        assert!(core.mail_enabled());
        core.queue_email(test_email("ops@example.com", "http://forge.test").unwrap())
            .await
            .unwrap();
        assert_eq!(core.run_due_jobs().await.unwrap(), 1);
        let mail = fixture.mail();
        assert_eq!(mail.len(), 1);
        assert!(
            mail[0].contains("To: ops@example.com")
                && mail[0].contains("Subject: Starforge test email")
                && mail[0].contains("This is a test message from Starforge at http://forge.test."),
            "{}",
            mail[0]
        );
        let payload: String =
            sqlx::query_scalar("SELECT payload FROM jobs WHERE kind = 'send_email'")
                .fetch_one(core.db().pool())
                .await
                .unwrap();
        assert_eq!(
            serde_json::from_str::<Job>(&payload).unwrap(),
            Job::SendEmail {
                to: "ops@example.com".into(),
                subject: "Starforge test email".into(),
                body: String::new(),
            }
        );
    }

    #[tokio::test]
    async fn running_workers_send_queued_email_promptly() {
        let (core, fixture) = test_core_with(with_file_mail).await;
        crate::jobs::start_workers(&core, 1).await.unwrap();
        core.queue_email(test_email("ops@example.com", "http://forge.test").unwrap())
            .await
            .unwrap();
        // Three seconds is less than the five-second poll interval: only the wake-up delivers it this fast.
        for _ in 0..60 {
            if !fixture.mail().is_empty() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("queued email was not sent within 3 seconds");
    }

    #[test]
    fn quoted_printable_bodies_are_decoded_and_links_found() {
        let raw = "To: a@example.com\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n\
                   Open http://forge.test/verify/ab=\r\ncd?x=3Dy now\r\n";
        let decoded = testing::decode_eml(raw);
        assert!(
            decoded.contains("http://forge.test/verify/abcd?x=y"),
            "{decoded}"
        );
        assert_eq!(
            testing::find_link(&decoded, "/verify/").as_deref(),
            Some("http://forge.test/verify/abcd?x=y")
        );
        let seven_bit = "To: a@example.com\r\n\r\nhttp://forge.test/join?invite=ab12\r\n";
        assert!(
            testing::decode_eml(seven_bit).contains("invite=ab12"),
            "bodies that are not quoted-printable stay as they are"
        );
    }
}
