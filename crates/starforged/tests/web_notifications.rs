//! Phase 2 web notifications: a comment by another user lands in the
//! Trail author's inbox, the nav badge counts it, `/open` marks it read and
//! redirects to the Trail, mark-all-read clears the badge, the watch form
//! persists the mode, the subscription button toggles, bad CSRF is refused,
//! and anonymous visitors are sent to sign-in.
mod common;
use common::*;
use starforged_core::notifications::WatchMode;
use starforged_core::permission::Visibility;

fn open_href(inbox: &str) -> String {
    let start = inbox
        .find(r#"href="/notifications/"#)
        .expect("inbox links to an open route");
    let rest = &inbox[start + r#"href="/notifications/"#.len()..];
    let id = rest.split('/').next().unwrap();
    format!("/notifications/{id}/open")
}

fn read_href(inbox: &str) -> String {
    let mut rest = inbox;
    loop {
        let start = rest
            .find(r#"action="/notifications/"#)
            .expect("inbox carries a mark-read form");
        rest = &rest[start + r#"action="/notifications/"#.len()..];
        let id = rest.split('/').next().unwrap();
        if id.parse::<i64>().is_ok() {
            return format!("/notifications/{id}/read");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn notifications_flow() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let bob = s.user("bob").await;
    s.repo(&alice, "proj", Visibility::Public).await;
    let n = s
        .core
        .create_trail(&alice, "alice", "proj", "hello trail", "the intent")
        .await
        .unwrap()
        .number;
    s.core
        .add_comment(&bob, "alice", "proj", n, "please look at this")
        .await
        .unwrap();

    // Anonymous visitors are sent to sign-in.
    let anon = s.browser();
    let res = anon.get(s.url("/notifications")).send().await.unwrap();
    assert_eq!(res.status(), 303);
    let location = res.headers()["location"].to_str().unwrap().to_owned();
    assert!(location.starts_with("/login?next="), "{location}");

    let (alice_client, _) = s.login("alice").await;
    let trail_url = format!("/alice/proj/trails/{n}");

    // The repo home shows the unread count and the watch control.
    let home = get_text(&alice_client, &s.url("/alice/proj")).await;
    assert!(home.contains("Notifications (1)"), "nav badge:\n{home}");
    assert!(home.contains("watch-repo"), "watch control:\n{home}");

    // The inbox lists the comment. A bad CSRF token is refused, and the
    // refused POST leaves the notification unread.
    let inbox = get_text(&alice_client, &s.url("/notifications")).await;
    assert!(inbox.contains("hello trail"), "inbox:\n{inbox}");
    assert!(inbox.contains("bob"), "inbox names the actor:\n{inbox}");
    assert!(inbox.contains("Mark read"), "inbox:\n{inbox}");
    let read_url = read_href(&inbox);
    let res = alice_client
        .post(s.url(&read_url))
        .form(&[("_csrf", "bogus")])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 403, "bad CSRF must be refused");
    let inbox = get_text(&alice_client, &s.url("/notifications")).await;
    assert!(
        inbox.contains("Mark read"),
        "refused POST must leave the row unread:\n{inbox}"
    );

    // Opening the notification marks it read and redirects to the Trail.
    let href = open_href(&inbox);
    let res = alice_client.get(s.url(&href)).send().await.unwrap();
    assert_eq!(res.status(), 303);
    assert_eq!(res.headers()["location"].to_str().unwrap(), trail_url);

    // The badge is gone after opening.
    let home = get_text(&alice_client, &s.url("/alice/proj")).await;
    assert!(!home.contains("Notifications ("), "badge cleared:\n{home}");

    // Mark all read clears a fresh notification.
    s.core
        .add_comment(&bob, "alice", "proj", n, "another look")
        .await
        .unwrap();
    let inbox = get_text(&alice_client, &s.url("/notifications")).await;
    assert!(inbox.contains("hello trail"));
    let csrf = extract_input(&inbox, "_csrf");
    let res = alice_client
        .post(s.url("/notifications/read-all"))
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    let home = get_text(&alice_client, &s.url("/alice/proj")).await;
    assert!(!home.contains("Notifications ("), "badge cleared:\n{home}");

    // The watch form sets the mode; the settings page lists the repo.
    let home = get_text(&alice_client, &s.url("/alice/proj")).await;
    let csrf = extract_input(&home, "_csrf");
    let res = alice_client
        .post(s.url("/alice/proj/watch"))
        .form(&[("_csrf", csrf.as_str()), ("mode", "watching")])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    assert_eq!(
        s.core.repo_watch(&alice, "alice", "proj").await.unwrap(),
        Some(WatchMode::Watching)
    );
    let settings = get_text(&alice_client, &s.url("/settings/notifications")).await;
    assert!(settings.contains("alice/proj"), "settings:\n{settings}");
    assert!(settings.contains("watching"), "settings:\n{settings}");

    // The subscription button toggles off and on.
    let trail = get_text(&alice_client, &s.url(&trail_url)).await;
    assert!(trail.contains("trail-subscription"), "trail:\n{trail}");
    assert!(
        trail.contains("Unsubscribe"),
        "author starts subscribed:\n{trail}"
    );
    let csrf = extract_input(&trail, "_csrf");
    let res = alice_client
        .post(s.url(&format!("{trail_url}/subscription")))
        .form(&[("_csrf", csrf.as_str()), ("subscribed", "0")])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    let trail = get_text(&alice_client, &s.url(&trail_url)).await;
    assert!(trail.contains("Subscribe"), "unsubscribed:\n{trail}");
    let csrf = extract_input(&trail, "_csrf");
    let res = alice_client
        .post(s.url(&format!("{trail_url}/subscription")))
        .form(&[("_csrf", csrf.as_str()), ("subscribed", "1")])
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);
    let trail = get_text(&alice_client, &s.url(&trail_url)).await;
    assert!(trail.contains("Unsubscribe"), "resubscribed:\n{trail}");
}
