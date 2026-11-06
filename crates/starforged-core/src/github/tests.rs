//! Unit tests for the GitHub client's pure helpers (pagination parsing,
//! rate-limit mapping, SSRF refusal). The wire behavior (pagination walk,
//! size cap, rate limit over HTTP) is covered in
//! `crates/starforged/tests/github_import.rs` against the fake API.

use reqwest::header::{HeaderMap, HeaderValue};
use std::str::FromStr as _;

use super::{GithubClient, GithubError, parse_next_link, rate_limit_reset};

fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in pairs {
        let name = reqwest::header::HeaderName::from_str(name).unwrap();
        map.insert(name, HeaderValue::from_str(value).unwrap());
    }
    map
}

#[test]
fn next_link_same_origin_is_followed() {
    let base = url::Url::parse("https://api.github.com/").unwrap();
    let link = headers(&[(
        "Link",
        "<https://api.github.com/repos/o/r/issues?page=2>; rel=\"next\", <https://api.github.com/repos/o/r/issues?page=5>; rel=\"last\"",
    )]);
    assert_eq!(
        parse_next_link(link.get("Link"), &base).as_deref(),
        Some("https://api.github.com/repos/o/r/issues?page=2")
    );
}

#[test]
fn next_link_cross_origin_is_refused() {
    let base = url::Url::parse("https://api.github.com/").unwrap();
    let link = headers(&[(
        "Link",
        "<https://evil.example.com/repos/o/r/issues?page=2>; rel=\"next\"",
    )]);
    assert_eq!(parse_next_link(link.get("Link"), &base), None);
    // A different port is a different origin too.
    let link = headers(&[(
        "Link",
        "<https://api.github.com:8443/repos/o/r/issues?page=2>; rel=\"next\"",
    )]);
    assert_eq!(parse_next_link(link.get("Link"), &base), None);
}

#[test]
fn next_link_absent_or_without_next_is_none() {
    let base = url::Url::parse("https://api.github.com/").unwrap();
    assert_eq!(parse_next_link(None, &base), None);
    let link = headers(&[(
        "Link",
        "<https://api.github.com/repos/o/r/issues?page=5>; rel=\"last\"",
    )]);
    assert_eq!(parse_next_link(link.get("Link"), &base), None);
}

#[test]
fn rate_limit_remaining_zero_maps_to_reset() {
    let map = headers(&[
        ("X-RateLimit-Remaining", "0"),
        ("X-RateLimit-Reset", "1893456000"),
    ]);
    assert_eq!(rate_limit_reset(&map), Some(1893456000));
}

#[test]
fn rate_limit_retry_after_maps_to_reset() {
    let map = headers(&[("Retry-After", "60")]);
    let reset = rate_limit_reset(&map).expect("retry-after is a rate limit");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    assert!(reset >= now + 59 && reset <= now + 61, "reset {reset}");
}

#[test]
fn non_rate_limit_headers_map_to_none() {
    let map = headers(&[
        ("X-RateLimit-Remaining", "42"),
        ("X-RateLimit-Reset", "1893456000"),
    ]);
    assert_eq!(rate_limit_reset(&map), None);
    assert_eq!(rate_limit_reset(&HeaderMap::new()), None);
}

#[test]
fn ssrf_private_and_metadata_hosts_are_refused() {
    for url in [
        "https://10.0.0.5/",
        "https://192.168.1.1/",
        "https://169.254.169.254/",
        "https://172.16.0.1/",
        "https://[::1]/",
        "https://127.0.0.1/",
    ] {
        assert!(
            matches!(
                GithubClient::new(url, "token", false),
                Err(GithubError::Invalid(_))
            ),
            "{url} must be refused"
        );
    }
}

#[test]
fn ssrf_loopback_flag_admits_only_loopback() {
    assert!(GithubClient::new("http://127.0.0.1:8080/", "token", true).is_ok());
    assert!(GithubClient::new("https://127.0.0.1/", "token", true).is_ok());
    // The flag admits loopback, never private ranges.
    assert!(matches!(
        GithubClient::new("https://10.0.0.5/", "token", true),
        Err(GithubError::Invalid(_))
    ));
    // Plain http to a public host is refused even with the flag.
    assert!(matches!(
        GithubClient::new("http://api.github.com/", "token", true),
        Err(GithubError::Invalid(_))
    ));
}

#[test]
fn non_https_api_url_is_refused() {
    assert!(matches!(
        GithubClient::new("ftp://api.github.com/", "token", false),
        Err(GithubError::Invalid(_))
    ));
    assert!(matches!(
        GithubClient::new("not a url", "token", false),
        Err(GithubError::Invalid(_))
    ));
    assert!(GithubClient::new("https://api.github.com/", "token", false).is_ok());
}
