//! Phase 2 notifications: Trail and change activity fans out inbox rows (and,
//! when mail is configured, emails) to the users the contract names.
mod common;

use std::path::PathBuf;
use std::time::Duration;

use common::*;
use starforged_core::CoreError;
use starforged_core::accounts::{CreateUser, User};
use starforged_core::notifications::WatchMode;
use starforged_core::permission::{Permission, Visibility};
use starforged_core::tokens::Scope;

async fn verified(s: &TestServer, handle: &str, email: &str) -> User {
    s.core
        .create_user(CreateUser {
            handle: handle.into(),
            email: Some(email.into()),
            email_verified: true,
            password: Some(PASSWORD.into()),
            ..Default::default()
        })
        .await
        .unwrap()
}

async fn notifs(
    s: &TestServer,
    user: &User,
) -> Vec<starforged_core::notifications::NotificationView> {
    s.core.notifications_for(user, true, 100).await.unwrap()
}

fn has<'a>(
    list: &'a [starforged_core::notifications::NotificationView],
    kind: &str,
) -> Option<&'a starforged_core::notifications::NotificationView> {
    list.iter().find(|n| n.kind == kind)
}

/// Pushes `main` plus `feature/x` into `alice/proj`; returns the working copy.
async fn push_basic(s: &TestServer, alice: &User) -> PathBuf {
    let url = s.git_url(
        "alice",
        "proj",
        Some(&s.token(alice, &[Scope::RepoWrite]).await),
    );
    let tmp = tempfile::tempdir().unwrap();
    let tmp_path = tmp.path().to_path_buf();
    std::mem::forget(tmp);
    let work = work_repo(&tmp_path, "work", &[("a.txt", "one\n")]).await;
    git_ok(&work, &["checkout", "-q", "-b", "feature/x"]).await;
    commit_files(&work, &[("a.txt", b"one\ntwo\n")], "add two").await;
    git_ok(&work, &["push", "-q", &url, "main", "feature/x"]).await;
    work
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn comment_notifies_author_and_watcher_but_not_commenter() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let bob = s.user("bob").await;
    let carol = s.user("carol").await;
    let erin = s.user("erin").await;
    let dave = s.user("dave").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    s.core
        .set_collaborator(&alice, "alice", "proj", "bob", Permission::Write)
        .await
        .unwrap();
    s.core
        .set_collaborator(&alice, "alice", "proj", "carol", Permission::Read)
        .await
        .unwrap();
    s.core
        .set_collaborator(&alice, "alice", "proj", "erin", Permission::Read)
        .await
        .unwrap();

    let trail = s
        .core
        .create_trail(&alice, "alice", "proj", "feature work", "ship it")
        .await
        .unwrap();
    s.core
        .set_repo_watch(&carol, "alice", "proj", Some(WatchMode::Watching))
        .await
        .unwrap();

    s.core
        .add_comment(
            &bob,
            "alice",
            "proj",
            trail.number,
            "hello @erin and @dave and @nobody",
        )
        .await
        .unwrap();

    let alice_n = notifs(&s, &alice).await;
    assert_eq!(
        has(&alice_n, "comment").map(|n| n.reason.as_str()),
        Some("author")
    );

    let carol_n = notifs(&s, &carol).await;
    assert_eq!(
        has(&carol_n, "comment").map(|n| n.reason.as_str()),
        Some("watching")
    );

    assert!(
        notifs(&s, &bob).await.is_empty(),
        "the commenter is never notified of their own comment"
    );

    let erin_n = notifs(&s, &erin).await;
    assert_eq!(
        has(&erin_n, "comment").map(|n| n.reason.as_str()),
        Some("mention")
    );

    assert!(
        notifs(&s, &dave).await.is_empty(),
        "a mention of a user who cannot read the private repo creates nothing"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn assignment_and_review_request_notify_only_the_target() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let bob = s.user("bob").await;
    let carol = s.user("carol").await;
    let frank = s.user("frank").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    for (handle, perm) in [
        ("bob", Permission::Write),
        ("carol", Permission::Read),
        ("frank", Permission::Write),
    ] {
        s.core
            .set_collaborator(&alice, "alice", "proj", handle, perm)
            .await
            .unwrap();
    }

    let trail = s
        .core
        .create_trail(&alice, "alice", "proj", "feature work", "ship it")
        .await
        .unwrap();
    s.core
        .set_repo_watch(&carol, "alice", "proj", Some(WatchMode::Watching))
        .await
        .unwrap();
    // An ignoring user still gets a direct assignment.
    s.core
        .set_repo_watch(&frank, "alice", "proj", Some(WatchMode::Ignoring))
        .await
        .unwrap();

    s.core
        .add_assignee(&alice, "alice", "proj", trail.number, "frank")
        .await
        .unwrap();
    assert!(
        has(&notifs(&s, &frank).await, "assigned").is_some(),
        "the assignee is notified despite repo ignoring"
    );
    assert!(
        has(&notifs(&s, &carol).await, "assigned").is_none(),
        "a watcher is not notified of an assignment"
    );
    assert!(
        has(&notifs(&s, &alice).await, "assigned").is_none(),
        "the actor is not notified"
    );

    // Re-assigning the same user is a no-op and notifies nobody twice.
    s.core
        .add_assignee(&alice, "alice", "proj", trail.number, "frank")
        .await
        .unwrap();
    assert_eq!(
        notifs(&s, &frank)
            .await
            .iter()
            .filter(|n| n.kind == "assigned")
            .count(),
        1
    );

    s.core
        .request_review(&alice, "alice", "proj", trail.number, "bob")
        .await
        .unwrap();
    assert!(has(&notifs(&s, &bob).await, "review_requested").is_some());
    assert!(
        has(&notifs(&s, &carol).await, "review_requested").is_none(),
        "a watcher is not notified of a review request"
    );

    // The ignoring user gets nothing from comments.
    s.core
        .add_comment(&bob, "alice", "proj", trail.number, "please look")
        .await
        .unwrap();
    assert!(
        has(&notifs(&s, &frank).await, "comment").is_none(),
        "repo ignoring suppresses comment notifications"
    );
    assert!(
        has(&notifs(&s, &carol).await, "comment").is_some(),
        "the watcher still gets the comment"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicit_unsubscribe_stops_comments_but_not_mentions() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let bob = s.user("bob").await;
    let erin = s.user("erin").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    s.core
        .set_collaborator(&alice, "alice", "proj", "bob", Permission::Write)
        .await
        .unwrap();
    s.core
        .set_collaborator(&alice, "alice", "proj", "erin", Permission::Read)
        .await
        .unwrap();

    let trail = s
        .core
        .create_trail(&alice, "alice", "proj", "feature work", "ship it")
        .await
        .unwrap();
    s.core
        .add_comment(&bob, "alice", "proj", trail.number, "first note")
        .await
        .unwrap();
    // Erin has commented or been mentioned? No: she only read. She is not a
    // participant, so force a subscription, then withdraw it.
    s.core
        .set_trail_subscription(&erin, "alice", "proj", trail.number, true)
        .await
        .unwrap();
    s.core
        .set_trail_subscription(&erin, "alice", "proj", trail.number, false)
        .await
        .unwrap();

    s.core
        .add_comment(&bob, "alice", "proj", trail.number, "second note")
        .await
        .unwrap();
    assert!(
        notifs(&s, &erin).await.is_empty(),
        "an explicit unsubscribe suppresses comment notifications"
    );

    s.core
        .add_comment(&bob, "alice", "proj", trail.number, "erin, your call @erin")
        .await
        .unwrap();
    let erin_n = notifs(&s, &erin).await;
    assert_eq!(
        has(&erin_n, "comment").map(|n| n.reason.as_str()),
        Some("mention")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revision_push_notifies_watchers_only_and_merge_notifies_participants() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let bob = s.user("bob").await;
    let carol = s.user("carol").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    s.core
        .set_collaborator(&alice, "alice", "proj", "bob", Permission::Write)
        .await
        .unwrap();
    s.core
        .set_collaborator(&alice, "alice", "proj", "carol", Permission::Read)
        .await
        .unwrap();

    let work = push_basic(&s, &alice).await;
    let trail = s
        .core
        .create_trail(&alice, "alice", "proj", "feature work", "ship it")
        .await
        .unwrap();
    s.core
        .create_branch_change(&alice, "alice", "proj", trail.number, "feature/x", "main")
        .await
        .unwrap();
    s.core
        .set_repo_watch(&carol, "alice", "proj", Some(WatchMode::Watching))
        .await
        .unwrap();
    // Bob participates by commenting.
    s.core
        .add_comment(&bob, "alice", "proj", trail.number, "nice work")
        .await
        .unwrap();

    // A revision push notifies watchers, not mere participants.
    commit_files(&work, &[("a.txt", b"one\ntwo\nthree\n")], "add three").await;
    let rp_url = s.git_url(
        "alice",
        "proj",
        Some(&s.token(&alice, &[Scope::RepoWrite]).await),
    );
    git_ok(&work, &["push", "-q", &rp_url, "feature/x"]).await;
    for _ in 0..50 {
        if has(&notifs(&s, &carol).await, "revision_pushed").is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        has(&notifs(&s, &carol).await, "revision_pushed").is_some(),
        "the watcher is notified of the revision push"
    );
    assert!(
        has(&notifs(&s, &bob).await, "revision_pushed").is_none(),
        "a participant who is not a watcher gets nothing from a revision push"
    );

    // Merging notifies the participant.
    s.core
        .merge_change(&alice, "alice", "proj", trail.number, 1, "fast_forward")
        .await
        .unwrap();
    assert!(
        has(&notifs(&s, &bob).await, "merged").is_some(),
        "the participant is notified of the merge"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn notification_emails_only_verified_users_with_email_enabled() {
    let s = TestServer::start_with_mail(|_| {}).await;
    let alice = verified(&s, "alice", "alice@example.com").await;
    let bob = verified(&s, "bob", "bob@example.com").await;
    let carol = verified(&s, "carol", "carol@example.com").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    s.core
        .set_collaborator(&alice, "alice", "proj", "bob", Permission::Write)
        .await
        .unwrap();
    s.core
        .set_collaborator(&alice, "alice", "proj", "carol", Permission::Read)
        .await
        .unwrap();
    s.core.set_notification_email(&carol, false).await.unwrap();

    let trail = s
        .core
        .create_trail(&alice, "alice", "proj", "feature work", "ship it")
        .await
        .unwrap();
    s.core
        .set_repo_watch(&carol, "alice", "proj", Some(WatchMode::Watching))
        .await
        .unwrap();
    s.core
        .add_comment(&bob, "alice", "proj", trail.number, "first look")
        .await
        .unwrap();

    assert!(
        has(&notifs(&s, &alice).await, "comment").is_some(),
        "the author has an inbox entry"
    );

    let inbox = s.inbox().await;
    assert!(
        inbox.iter().any(|m| m.contains("To: alice@example.com")
            && m.contains("/alice/proj/trails/")
            && m.contains("[alice/proj] feature work (#1)")),
        "a notification email goes to the author: {inbox:?}"
    );
    assert!(
        !inbox.iter().any(|m| m.contains("To: bob@example.com")),
        "the commenter gets no notification email for their own comment: {inbox:?}"
    );
    assert!(
        !inbox.iter().any(|m| m.contains("To: carol@example.com")),
        "a watcher who turned notification email off gets no email: {inbox:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lost_access_hides_count_inbox_and_mark() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    let bob = s.user("bob").await;
    s.repo(&alice, "proj", Visibility::Private).await;
    s.core
        .set_collaborator(&alice, "alice", "proj", "bob", Permission::Read)
        .await
        .unwrap();
    let trail = s
        .core
        .create_trail(&alice, "alice", "proj", "feature work", "ship it")
        .await
        .unwrap();
    s.core
        .add_comment(&bob, "alice", "proj", trail.number, "first look")
        .await
        .unwrap();
    s.core
        .add_comment(&alice, "alice", "proj", trail.number, "reply")
        .await
        .unwrap();
    let before = notifs(&s, &bob).await;
    let target = has(&before, "comment")
        .expect("bob is notified of the reply")
        .id;
    assert_eq!(s.core.unread_notification_count(&bob).await.unwrap(), 1);
    s.core
        .remove_collaborator(&alice, "alice", "proj", "bob")
        .await
        .unwrap();
    assert_eq!(s.core.unread_notification_count(&bob).await.unwrap(), 0);
    assert!(notifs(&s, &bob).await.is_empty());
    assert!(matches!(
        s.core.mark_notification_read(&bob, target).await,
        Err(CoreError::NotFound)
    ));
}
