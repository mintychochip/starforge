mod common;

use common::{TestServer, extract_input, get_text, git_ok, work_repo};
use starforged_core::accounts::CreateUser;
use starforged_core::orgs::NewOrgInput;
use starforged_core::permission::Visibility;
use starforged_core::repos::CreateRepo;
use starforged_core::tokens::Scope;

async fn org(s: &TestServer, owner_handle: &str, org: &str) {
    let owner = s.core.user_by_handle(owner_handle).await.unwrap().unwrap();
    s.core
        .create_org(
            &owner,
            NewOrgInput {
                handle: org.into(),
                display_name: String::new(),
                description: String::new(),
            },
        )
        .await
        .unwrap();
}

async fn org_repo(
    s: &TestServer,
    owner_handle: &str,
    org: &str,
    name: &str,
    visibility: Visibility,
) {
    let owner = s.core.user_by_handle(owner_handle).await.unwrap().unwrap();
    s.core
        .create_repo(
            &owner,
            org,
            CreateRepo {
                name: name.into(),
                description: String::new(),
                visibility,
                readme: false,
            },
        )
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn org_lifecycle_in_web() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.user("mia").await;

    // Create an org through the web form.
    let (client, csrf) = s.login("alice").await;
    let created = client
        .post(s.url("/orgs/new"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("handle", "acme"),
            ("display_name", "Acme"),
            ("description", "An org"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 303);
    assert_eq!(created.headers()["location"], "/acme");

    // The org page is public and shows the display name.
    let anon = s.browser();
    let public = anon
        .get(s.url("/acme"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(public.contains("Acme"), "{public}");

    // Set the display name and the base permission from settings.
    let saved = client
        .post(s.url("/orgs/acme/settings"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("display_name", "Acme Inc"),
            ("description", "An org"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(saved.status(), 303, "general settings save");
    let based = client
        .post(s.url("/orgs/acme/settings/base-permission"))
        .form(&[("_csrf", csrf.as_str()), ("base_permission", "read")])
        .send()
        .await
        .unwrap();
    assert_eq!(based.status(), 303, "base permission save");
    let settings = get_text(&client, &s.url("/orgs/acme/settings")).await;
    assert!(settings.contains("Acme Inc"), "{settings}");
    assert!(settings.contains(r#"value="read" checked"#), "{settings}");

    // Add a member, then promote them to owner.
    let added = client
        .post(s.url("/orgs/acme/members"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("handle", "mia"),
            ("role", "member"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(added.status(), 303, "member add");
    let promoted = client
        .post(s.url("/orgs/acme/members"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("handle", "mia"),
            ("role", "owner"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(promoted.status(), 303, "member promote");
    let members = get_text(&client, &s.url("/orgs/acme/members")).await;
    assert!(members.contains("mia"), "{members}");
    assert!(members.contains("owner"), "{members}");

    // Create a team, add the member and a repository to it.
    s.repo(&alice, "proj", Visibility::Public).await;
    let team = client
        .post(s.url("/orgs/acme/teams/new"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("name", "eng"),
            ("description", "Engineers"),
            ("permission", "write"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(team.status(), 303, "team create");
    assert_eq!(team.headers()["location"], "/orgs/acme/teams/eng");
    // The repository must live in the org before the team can take it; move
    // it there first through the transfer form below, then link it.
    let moved = client
        .post(s.url("/alice/proj/settings/transfer"))
        .form(&[("_csrf", csrf.as_str()), ("new_owner", "acme")])
        .send()
        .await
        .unwrap();
    assert_eq!(moved.status(), 303, "transfer to org");
    assert_eq!(moved.headers()["location"], "/acme/proj");
    let old = client.get(s.url("/alice/proj")).send().await.unwrap();
    assert_eq!(old.status(), 301, "old path redirects");
    assert_eq!(old.headers()["location"], "/acme/proj");
    let with_member = client
        .post(s.url("/orgs/acme/teams/eng/members"))
        .form(&[("_csrf", csrf.as_str()), ("handle", "mia")])
        .send()
        .await
        .unwrap();
    assert_eq!(with_member.status(), 303, "team member add");
    let with_repo = client
        .post(s.url("/orgs/acme/teams/eng/repos"))
        .form(&[("_csrf", csrf.as_str()), ("repo", "proj")])
        .send()
        .await
        .unwrap();
    assert_eq!(with_repo.status(), 303, "team repo add");
    let team_page = get_text(&client, &s.url("/orgs/acme/teams/eng")).await;
    assert!(team_page.contains("mia"), "{team_page}");
    assert!(team_page.contains("proj"), "{team_page}");

    // Create an org repository from the new-repository owner select.
    let form = get_text(&client, &s.url("/new")).await;
    assert!(form.contains(r#"name="owner""#), "owner select:\n{form}");
    assert!(form.contains(r#"value="acme""#), "org option:\n{form}");
    let org_repo = client
        .post(s.url("/new"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("owner", "acme"),
            ("name", "toolbox"),
            ("description", "Org repo"),
            ("visibility", "public"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(org_repo.status(), 303, "org repo create");
    assert_eq!(org_repo.headers()["location"], "/acme/toolbox");
    let org_page = get_text(&client, &s.url("/acme")).await;
    assert!(org_page.contains("toolbox"), "{org_page}");

    // Transfer a repository back from settings.
    let back = client
        .post(s.url("/acme/toolbox/settings/transfer"))
        .form(&[("_csrf", csrf.as_str()), ("new_owner", "alice")])
        .send()
        .await
        .unwrap();
    assert_eq!(back.status(), 303, "transfer back");
    assert_eq!(back.headers()["location"], "/alice/toolbox");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn org_page_access_rules() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.user("mia").await;
    s.user("walt").await;
    org(&s, "alice", "acme").await;
    let (alice_client, csrf) = s.login("alice").await;
    org_repo(&s, "alice", "acme", "open", Visibility::Public).await;
    org_repo(&s, "alice", "acme", "closed", Visibility::Private).await;
    let _ = alice;

    // The org page is public but lists only repositories the viewer can read.
    let anon = s.browser();
    let public = anon.get(s.url("/acme")).send().await.unwrap();
    assert_eq!(public.status(), 200);
    let body = public.text().await.unwrap();
    assert!(body.contains("open"), "{body}");
    assert!(!body.contains("closed"), "{body}");
    let (walt, _) = s.login("walt").await;
    let outsider = walt.get(s.url("/acme")).send().await.unwrap();
    assert_eq!(outsider.status(), 200);
    let outsider_body = outsider.text().await.unwrap();
    assert!(!outsider_body.contains("closed"), "{outsider_body}");

    // Member and team pages give 404 to anonymous viewers and non-members.
    for path in ["/orgs/acme/members", "/orgs/acme/teams"] {
        assert_eq!(
            anon.get(s.url(path)).send().await.unwrap().status(),
            404,
            "anon GET {path}"
        );
        assert_eq!(
            walt.get(s.url(path)).send().await.unwrap().status(),
            404,
            "non-member GET {path}"
        );
    }

    // A team exists for the detail checks below.
    let team = alice_client
        .post(s.url("/orgs/acme/teams/new"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("name", "eng"),
            ("description", ""),
            ("permission", "read"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(team.status(), 303);
    // Unknown teams 404 even for owners; the team page 404s outsiders.
    assert_eq!(
        alice_client
            .get(s.url("/orgs/acme/teams/nope"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    assert_eq!(
        anon.get(s.url("/orgs/acme/teams/eng"))
            .send()
            .await
            .unwrap()
            .status(),
        404,
        "anon team page"
    );
    assert_eq!(
        walt.get(s.url("/orgs/acme/teams/eng"))
            .send()
            .await
            .unwrap()
            .status(),
        404,
        "non-member team page"
    );

    // Plain members read member and team pages but cannot manage anything.
    let added = alice_client
        .post(s.url("/orgs/acme/members"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("handle", "mia"),
            ("role", "member"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(added.status(), 303);
    let (mia, mia_csrf) = s.login("mia").await;
    assert_eq!(
        mia.get(s.url("/orgs/acme/members"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        mia.get(s.url("/orgs/acme/teams"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    for (path, form) in [
        (
            "/orgs/acme/settings",
            vec![("display_name", "Hijack"), ("description", "")],
        ),
        (
            "/orgs/acme/settings/base-permission",
            vec![("base_permission", "write")],
        ),
        (
            "/orgs/acme/members",
            vec![("handle", "walt"), ("role", "member")],
        ),
        (
            "/orgs/acme/teams/new",
            vec![("name", "hijack"), ("permission", "admin")],
        ),
        (
            "/orgs/acme/teams/eng/settings",
            vec![
                ("name", "eng"),
                ("description", "Hijacked"),
                ("permission", "admin"),
            ],
        ),
        ("/orgs/acme/teams/eng/delete", vec![("confirm", "eng")]),
        ("/orgs/acme/teams/eng/members", vec![("handle", "walt")]),
        ("/orgs/acme/teams/eng/members/mia/remove", vec![]),
        ("/orgs/acme/teams/eng/repos", vec![("repo", "open")]),
        ("/orgs/acme/teams/eng/repos/open/remove", vec![]),
    ] {
        let mut fields: Vec<(&str, &str)> = vec![("_csrf", mia_csrf.as_str())];
        fields.extend(form);
        let response = mia.post(s.url(path)).form(&fields).send().await.unwrap();
        assert_eq!(response.status(), 403, "member POST {path}");
    }
    // Anonymous management attempts redirect to sign-in, like other settings pages.
    assert_eq!(
        anon.get(s.url("/orgs/acme/settings"))
            .send()
            .await
            .unwrap()
            .status(),
        303
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn user_repo_named_teams_keeps_working() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.repo(&alice, "teams", Visibility::Public).await;
    let (client, _) = s.login("alice").await;
    let anon = s.browser();

    // The repository home, its sub-pages, and the settings page all answer:
    // no org route swallows them.
    for (who, path, want) in [
        ("anon", "/alice/teams", 200),
        ("alice", "/alice/teams/trails", 200),
        ("alice", "/alice/teams/branches", 200),
        ("alice", "/alice/teams/settings", 200),
    ] {
        let browser = if who == "anon" { &anon } else { &client };
        let response = browser.get(s.url(path)).send().await.unwrap();
        assert_eq!(response.status().as_u16(), want, "{who} GET {path}");
    }

    // Git over HTTP works: clone (upload-pack) and push (receive-pack).
    let tmp = tempfile::tempdir().unwrap();
    git_ok(
        tmp.path(),
        &["clone", "-q", &s.git_url("alice", "teams", None), "clone"],
    )
    .await;
    let token = s.token(&alice, &[Scope::RepoWrite]).await;
    let work = work_repo(tmp.path(), "work", &[("README.md", "# Teams\n")]).await;
    git_ok(
        &work,
        &[
            "push",
            "-q",
            &s.git_url("alice", "teams", Some(&token)),
            "main",
        ],
    )
    .await;
    let home = get_text(&anon, &s.url("/alice/teams")).await;
    assert!(home.contains("README.md"), "{home}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn org_repo_named_settings_keeps_home() {
    let s = TestServer::start().await;
    s.user("alice").await;
    org(&s, "alice", "acme").await;
    org_repo(&s, "alice", "acme", "settings", Visibility::Public).await;
    let (client, _) = s.login("alice").await;

    // The repository home answers under its own name…
    let home = get_text(&client, &s.url("/acme/settings")).await;
    assert!(home.contains("settings"), "{home}");
    // …while the org settings live under the reserved prefix.
    let org_settings = get_text(&client, &s.url("/orgs/acme/settings")).await;
    assert!(org_settings.contains("Base permission"), "{org_settings}");
    // And the org members page is not shadowed by a missing `members` repo.
    assert_eq!(
        client
            .get(s.url("/acme/members"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn org_csrf_on_every_form() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.user("mia").await;
    s.user("walt").await;
    let (client, csrf) = s.login("alice").await;
    let forged = |fields: Vec<(&'static str, &'static str)>| {
        let mut form: Vec<(&'static str, &'static str)> = vec![("_csrf", "forged")];
        form.extend(fields);
        form
    };

    // 1. Forging the org-create form leaves no org behind.
    let response = client
        .post(s.url("/orgs/new"))
        .form(&forged(vec![
            ("handle", "evil"),
            ("display_name", ""),
            ("description", ""),
        ]))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403);
    assert!(s.core.org(None, "evil").await.is_err());

    // Real creation for the remaining checks.
    let created = client
        .post(s.url("/orgs/new"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("handle", "acme"),
            ("display_name", "Acme"),
            ("description", ""),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 303);
    s.repo(&alice, "solo", Visibility::Public).await;
    org_repo(&s, "alice", "acme", "proj", Visibility::Public).await;
    org_repo(&s, "alice", "acme", "other", Visibility::Public).await;

    // 2. Forging the new-repository form creates nothing.
    let response = client
        .post(s.url("/new"))
        .form(&forged(vec![
            ("owner", "acme"),
            ("name", "forged-repo"),
            ("description", ""),
            ("visibility", "private"),
        ]))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403);
    assert_eq!(
        client
            .get(s.url("/acme/forged-repo"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );

    // 3-4. Forging the general-settings form changes nothing.
    for (path, fields) in [
        (
            "/orgs/acme/settings",
            vec![("display_name", "Hacked"), ("description", "")],
        ),
        (
            "/orgs/acme/settings/base-permission",
            vec![("base_permission", "write")],
        ),
    ] {
        let response = client
            .post(s.url(path))
            .form(&forged(fields))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 403, "forged POST {path}");
    }
    let settings = get_text(&client, &s.url("/orgs/acme/settings")).await;
    assert!(settings.contains("Acme"), "{settings}");
    assert!(!settings.contains("Hacked"), "{settings}");
    assert!(settings.contains(r#"value="none" checked"#), "{settings}");

    // 5. Forging the org-delete form deletes nothing.
    let response = client
        .post(s.url("/orgs/acme/settings/delete"))
        .form(&forged(vec![("confirm", "acme")]))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403);
    assert_eq!(
        client
            .get(s.url("/orgs/acme/settings"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );

    // 6-7. Forging the member forms changes nothing.
    for (path, fields) in [
        (
            "/orgs/acme/members",
            vec![("handle", "walt"), ("role", "member")],
        ),
        ("/orgs/acme/members/mia/remove", vec![]),
    ] {
        let response = client
            .post(s.url(path))
            .form(&forged(fields))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 403, "forged POST {path}");
    }
    // (mia is not a member yet, so the remove left nothing to check; the real
    // adds below set up the team checks.)
    let added = client
        .post(s.url("/orgs/acme/members"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("handle", "mia"),
            ("role", "member"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(added.status(), 303);
    let members = get_text(&client, &s.url("/orgs/acme/members")).await;
    assert!(!members.contains("walt"), "{members}");

    // 8. Forging the team-create form creates no team.
    let response = client
        .post(s.url("/orgs/acme/teams/new"))
        .form(&forged(vec![
            ("name", "eng"),
            ("description", ""),
            ("permission", "write"),
        ]))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403);
    assert_eq!(
        client
            .get(s.url("/orgs/acme/teams/eng"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    let team = client
        .post(s.url("/orgs/acme/teams/new"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("name", "eng"),
            ("description", "Engineers"),
            ("permission", "read"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(team.status(), 303);
    let with_member = client
        .post(s.url("/orgs/acme/teams/eng/members"))
        .form(&[("_csrf", csrf.as_str()), ("handle", "mia")])
        .send()
        .await
        .unwrap();
    assert_eq!(with_member.status(), 303);
    let with_repo = client
        .post(s.url("/orgs/acme/teams/eng/repos"))
        .form(&[("_csrf", csrf.as_str()), ("repo", "proj")])
        .send()
        .await
        .unwrap();
    assert_eq!(with_repo.status(), 303);

    // 9-14. Forging every team form changes nothing.
    for (path, fields) in [
        (
            "/orgs/acme/teams/eng/settings",
            vec![("description", "Hacked")],
        ),
        ("/orgs/acme/teams/eng/delete", vec![("confirm", "eng")]),
        ("/orgs/acme/teams/eng/members", vec![("handle", "walt")]),
        ("/orgs/acme/teams/eng/members/mia/remove", vec![]),
        ("/orgs/acme/teams/eng/repos", vec![("repo", "other")]),
        ("/orgs/acme/teams/eng/repos/proj/remove", vec![]),
    ] {
        let response = client
            .post(s.url(path))
            .form(&forged(fields))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 403, "forged POST {path}");
    }
    let team_page = get_text(&client, &s.url("/orgs/acme/teams/eng")).await;
    assert!(!team_page.contains("Hacked"), "{team_page}");
    assert!(team_page.contains("Engineers"), "{team_page}");
    assert!(team_page.contains("mia"), "{team_page}");
    assert!(!team_page.contains("walt"), "{team_page}");
    assert!(team_page.contains("proj"), "{team_page}");
    assert!(!team_page.contains("other"), "{team_page}");

    // 15. Forging the transfer form leaves the repository in place.
    let response = client
        .post(s.url("/alice/solo/settings/transfer"))
        .form(&forged(vec![("new_owner", "acme")]))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403);
    assert_eq!(
        client
            .get(s.url("/acme/solo"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn org_pages_escape_hostile_text() {
    let s = TestServer::start().await;
    s.user("alice").await;
    let (client, csrf) = s.login("alice").await;
    let created = client
        .post(s.url("/orgs/new"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("handle", "acme"),
            ("display_name", "<script>alert(1)</script>"),
            ("description", r#"<img src=x onerror="alert(2)">"#),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 303);
    let team = client
        .post(s.url("/orgs/acme/teams/new"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("name", "eng"),
            ("description", "<b>evil</b>"),
            ("permission", "read"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(team.status(), 303);

    let anon = s.browser();
    let org_page = anon
        .get(s.url("/acme"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        !org_page.contains("<script>alert(1)</script>"),
        "{org_page}"
    );
    assert!(org_page.contains("&#60;script&#62;"), "{org_page}");
    assert!(!org_page.contains(r#"<img src=x"#), "{org_page}");
    assert!(org_page.contains("&#60;img"), "{org_page}");

    let team_page = get_text(&client, &s.url("/orgs/acme/teams/eng")).await;
    assert!(!team_page.contains("<b>evil</b>"), "{team_page}");
    assert!(
        team_page.contains("&#60;b&#62;evil&#60;/b&#62;"),
        "{team_page}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_orgs_lists_for_admins_only() {
    let s = TestServer::start().await;
    s.core
        .create_user(CreateUser {
            handle: "root".into(),
            password: Some(common::PASSWORD.into()),
            is_admin: true,
            ..Default::default()
        })
        .await
        .unwrap();
    let alice = s.user("alice").await;
    s.user("mia").await;
    let owner = alice.clone();
    s.core
        .create_org(
            &owner,
            NewOrgInput {
                handle: "acme".into(),
                display_name: "Acme".into(),
                description: String::new(),
            },
        )
        .await
        .unwrap();
    let (admin, _) = s.login("root").await;
    let (user_client, _) = s.login("mia").await;
    let anon = s.browser();

    let page = get_text(&admin, &s.url("/admin/orgs")).await;
    assert!(page.contains("acme"), "{page}");
    assert!(page.contains("Acme"), "{page}");
    assert!(page.contains(r#"href="/acme""#), "{page}");

    assert_eq!(
        user_client
            .get(s.url("/admin/orgs"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    assert_eq!(
        anon.get(s.url("/admin/orgs"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn new_repo_owner_select_lists_owned_orgs() {
    let s = TestServer::start().await;
    s.user("alice").await;
    s.user("mia").await;
    org(&s, "alice", "acme").await;
    let (alice_client, _) = s.login("alice").await;
    let (mia_client, _) = s.login("mia").await;

    let form = get_text(&alice_client, &s.url("/new")).await;
    assert!(form.contains(r#"<select name="owner""#), "{form}");
    let select = common::between(&form, r#"<select name="owner""#, "</select>");
    assert!(select.contains(r#"value="alice""#), "{select}");
    assert!(select.contains(r#"value="acme""#), "{select}");

    // Mia does not own the org, so it is not offered — and the server refuses it anyway.
    let mia_form = get_text(&mia_client, &s.url("/new")).await;
    let mia_select = common::between(&mia_form, r#"<select name="owner""#, "</select>");
    assert!(!mia_select.contains(r#"value="acme""#), "{mia_select}");
    let refused = mia_client
        .post(s.url("/new"))
        .form(&[
            ("_csrf", extract_input(&mia_form, "_csrf").as_str()),
            ("owner", "acme"),
            ("name", "squat"),
            ("description", ""),
            ("visibility", "private"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 403);
}
