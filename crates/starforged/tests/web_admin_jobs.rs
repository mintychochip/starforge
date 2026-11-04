mod common;

use common::{TestServer, get_text};
use starforged_core::accounts::CreateUser;
use starforged_core::admin::JobInfo;
use starforged_core::jobs::Job;

async fn root_client(s: &TestServer) -> (reqwest::Client, String, starforged_core::accounts::User) {
    let root = s
        .core
        .create_user(CreateUser {
            handle: "root".into(),
            password: Some(common::PASSWORD.into()),
            is_admin: true,
            ..Default::default()
        })
        .await
        .unwrap();
    let (client, csrf) = s.login("root").await;
    (client, csrf, root)
}

async fn failed_job_ids(s: &TestServer) -> Vec<i64> {
    sqlx::query_scalar::<_, i64>("SELECT id FROM jobs ORDER BY id")
        .fetch_all(s.core.db().pool())
        .await
        .unwrap()
}

fn job_by_id(jobs: &[JobInfo], id: i64) -> Option<&JobInfo> {
    jobs.iter().find(|j| j.id == id)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failed_jobs_retry_and_delete_from_the_page() {
    let s = TestServer::start().await;
    let (admin, csrf, root) = root_client(&s).await;

    // Seed two failed jobs through the public queue, then fail them via the
    // public db fail path (same mechanism as the C2 core test).
    s.core
        .enqueue(&Job::SendEmail {
            to: "a@example.com".into(),
            subject: "s".into(),
            body: "super-secret-body-one".into(),
        })
        .await
        .unwrap();
    s.core
        .enqueue(&Job::SendEmail {
            to: "b@example.com".into(),
            subject: "s".into(),
            body: "super-secret-body-two".into(),
        })
        .await
        .unwrap();
    let ids = failed_job_ids(&s).await;
    assert_eq!(ids.len(), 2);
    let long_error = "e".repeat(300);
    starforged_db::jobs::fail(s.core.db(), ids[0], &long_error, None)
        .await
        .unwrap();
    starforged_db::jobs::fail(s.core.db(), ids[1], "boom", None)
        .await
        .unwrap();

    // Capture ids via the admin list.
    let jobs = s.core.admin_list_jobs(&root).await.unwrap();
    assert_eq!(jobs.len(), 2);
    let (retry_id, delete_id) = (ids[0], ids[1]);
    assert!(job_by_id(&jobs, retry_id).is_some());
    assert!(job_by_id(&jobs, delete_id).is_some());

    // The page lists kind/state/attempts, truncates the long error, and never
    // renders payloads (mail bodies hold secrets).
    let page = get_text(&admin, &s.url("/admin/jobs")).await;
    assert!(page.contains("send_email"), "{page}");
    assert!(page.contains("failed"), "{page}");
    assert!(
        page.contains(&format!("/admin/jobs/{retry_id}/retry")),
        "retry form:\n{page}"
    );
    assert!(
        page.contains(&format!("/admin/jobs/{delete_id}/delete")),
        "delete form:\n{page}"
    );
    assert!(
        !page.contains(&long_error),
        "last error is truncated to 200 chars"
    );
    assert!(page.contains(&"e".repeat(200)), "{page}");
    assert!(
        !page.contains("super-secret-body-one"),
        "payloads are never rendered:\n{page}"
    );
    assert!(
        !page.contains("super-secret-body-two"),
        "payloads are never rendered:\n{page}"
    );

    // Retry → 303 → row shows queued.
    let retried = admin
        .post(s.url(&format!("/admin/jobs/{retry_id}/retry")))
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(retried.status(), 303);
    assert_eq!(retried.headers()["location"], "/admin/jobs");
    let jobs = s.core.admin_list_jobs(&root).await.unwrap();
    assert_eq!(job_by_id(&jobs, retry_id).unwrap().state, "queued");
    let page = get_text(&admin, &s.url("/admin/jobs")).await;
    assert!(page.contains("queued"), "{page}");

    // Retrying a queued job answers 404.
    let again = admin
        .post(s.url(&format!("/admin/jobs/{retry_id}/retry")))
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(again.status(), 404);

    // Delete a failed one → 303 → row gone.
    let deleted = admin
        .post(s.url(&format!("/admin/jobs/{delete_id}/delete")))
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.status(), 303);
    assert_eq!(deleted.headers()["location"], "/admin/jobs");
    let jobs = s.core.admin_list_jobs(&root).await.unwrap();
    assert!(job_by_id(&jobs, delete_id).is_none());
    let page = get_text(&admin, &s.url("/admin/jobs")).await;
    assert!(
        !page.contains(&format!("/admin/jobs/{delete_id}/delete")),
        "deleted row is gone:\n{page}"
    );

    // Deleting a queued job answers 404, as does a missing id.
    let delete_queued = admin
        .post(s.url(&format!("/admin/jobs/{retry_id}/delete")))
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(delete_queued.status(), 404);
    let missing = admin
        .post(s.url("/admin/jobs/999999/retry"))
        .form(&[("_csrf", csrf.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), 404);

    // Non-admins get 404.
    let alice = s.user("alice").await;
    let _ = alice;
    let (owner, _) = s.login("alice").await;
    assert_eq!(
        owner
            .get(s.url("/admin/jobs"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    let anon = s.browser();
    assert_eq!(
        anon.get(s.url("/admin/jobs"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
}
