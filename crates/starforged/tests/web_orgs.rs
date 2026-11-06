mod common;

use common::{TestServer, extract_input, get_text};
use starforged_core::accounts::CreateUser;
use starforged_core::orgs::NewOrgInput;
use starforged_core::permission::Visibility;

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
        .post(s.url("/acme/settings"))
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
        .post(s.url("/acme/settings/base-permission"))
        .form(&[("_csrf", csrf.as_str()), ("base_permission", "read")])
        .send()
        .await
        .unwrap();
    assert_eq!(based.status(), 303, "base permission save");
    let settings = get_text(&client, &s.url("/acme/settings")).await;
    assert!(settings.contains("Acme Inc"), "{settings}");
    assert!(settings.contains(r#"value="read" checked"#), "{settings}");

    // Add a member, then promote them to owner.
    let added = client
        .post(s.url("/acme/settings/members"))
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
        .post(s.url("/acme/settings/members"))
        .form(&[
            ("_csrf", csrf.as_str()),
            ("handle", "mia"),
            ("role", "owner"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(promoted.status(), 303, "member promote");
    let members = get_text(&client, &s.url("/acme/members")).await;
    assert!(members.contains("mia"), "{members}");
    assert!(members.contains("owner"), "{members}");

    // Create a team, add the member and a repository to it.
    s.repo(&alice, "proj", Visibility::Public).await;
    let team = client
        .post(s.url("/acme/teams/new"))
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
    assert_eq!(team.headers()["location"], "/acme/teams/eng");
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
        .post(s.url("/acme/teams/eng/members"))
        .form(&[("_csrf", csrf.as_str()), ("handle", "mia")])
        .send()
        .await
        .unwrap();
    assert_eq!(with_member.status(), 303, "team member add");
    let with_repo = client
        .post(s.url("/acme/teams/eng/repos"))
        .form(&[("_csrf", csrf.as_str()), ("repo", "proj")])
        .send()
        .await
        .unwrap();
    assert_eq!(with_repo.status(), 303, "team repo add");
    let team_page = get_text(&client, &s.url("/acme/teams/eng")).await;
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
    s.core
        .create_repo(
            &alice,
            "acme",
            starforged_core::repos::CreateRepo {
                name: "open".into(),
                description: String::new(),
                visibility: Visibility::Public,
                readme: false,
            },
        )
        .await
        .unwrap();
    s.core
        .create_repo(
            &alice,
            "acme",
            starforged_core::repos::CreateRepo {
                name: "closed".into(),
                description: String::new(),
                visibility: Visibility::Private,
                readme: false,
            },
        )
        .await
        .unwrap();

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
    for path in ["/acme/members", "/acme/teams", "/acme/settings/members"] {
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
    // Unknown teams 404 even for owners.
    assert_eq!(
        alice_client
            .get(s.url("/acme/teams/nope"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );

    // Plain members read member and team pages but cannot manage.
    let added = alice_client
        .post(s.url("/acme/settings/members"))
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
    let members = mia.get(s.url("/acme/members")).send().await.unwrap();
    assert_eq!(members.status(), 200);
    for (path, form) in [
        (
            "/acme/settings",
            vec![("display_name", "Hijack"), ("description", "")],
        ),
        (
            "/acme/settings/base-permission",
            vec![("base_permission", "write")],
        ),
        (
            "/acme/settings/members",
            vec![("handle", "walt"), ("role", "member")],
        ),
        (
            "/acme/teams/new",
            vec![("name", "hijack"), ("permission", "admin")],
        ),
    ] {
        let mut fields: Vec<(&str, &str)> = vec![("_csrf", mia_csrf.as_str())];
        fields.extend(form);
        let response = mia.post(s.url(path)).form(&fields).send().await.unwrap();
        assert_eq!(response.status(), 403, "member POST {path}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn org_forms_reject_forged_csrf() {
    let s = TestServer::start().await;
    let alice = s.user("alice").await;
    s.user("mia").await;
    let (client, csrf) = s.login("alice").await;

    // Forging the org-create form leaves no org behind.
    let forged = client
        .post(s.url("/orgs/new"))
        .form(&[
            ("_csrf", "forged"),
            ("handle", "evil"),
            ("display_name", ""),
            ("description", ""),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(forged.status(), 403);
    assert!(s.core.user_by_handle("evil").await.unwrap().is_none());
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
    s.repo(&alice, "proj", Visibility::Public).await;

    // Forging the member-add form adds nobody.
    let forged_add = client
        .post(s.url("/acme/settings/members"))
        .form(&[("_csrf", "forged"), ("handle", "mia"), ("role", "member")])
        .send()
        .await
        .unwrap();
    assert_eq!(forged_add.status(), 403);
    let members = get_text(&client, &s.url("/acme/members")).await;
    assert!(!members.contains("mia"), "{members}");

    // Forging the base-permission form changes nothing.
    let forged_base = client
        .post(s.url("/acme/settings/base-permission"))
        .form(&[("_csrf", "forged"), ("base_permission", "write")])
        .send()
        .await
        .unwrap();
    assert_eq!(forged_base.status(), 403);
    let settings = get_text(&client, &s.url("/acme/settings")).await;
    assert!(settings.contains(r#"value="none" checked"#), "{settings}");

    // Forging the team-create form creates no team.
    let forged_team = client
        .post(s.url("/acme/teams/new"))
        .form(&[
            ("_csrf", "forged"),
            ("name", "eng"),
            ("description", ""),
            ("permission", "write"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(forged_team.status(), 403);
    assert_eq!(
        client
            .get(s.url("/acme/teams/eng"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );

    // Forging the transfer form leaves the repository in place.
    let forged_move = client
        .post(s.url("/alice/proj/settings/transfer"))
        .form(&[("_csrf", "forged"), ("new_owner", "acme")])
        .send()
        .await
        .unwrap();
    assert_eq!(forged_move.status(), 403);
    assert_eq!(
        client
            .get(s.url("/acme/proj"))
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
        .post(s.url("/acme/teams/new"))
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

    let team_page = get_text(&client, &s.url("/acme/teams/eng")).await;
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
