//! `repo_redirects`: old repository names and the repository each now points at (forge-basics design §5.3).
//! `repos::rename` writes them; `repos::insert` and `repos::rename` drop the one holding a name they take.

use crate::{Db, DbResult};

/// The repository that `owner_handle/lower_name` redirects to; both arguments must be lowercase.
pub async fn target(db: &Db, owner_handle: &str, lower_name: &str) -> DbResult<Option<i64>> {
    let id: Option<i64> = sqlx::query_scalar(
        "SELECT d.repo_id FROM repo_redirects d JOIN owners o ON o.id = d.owner_id \
         WHERE o.handle = $1 AND d.lower_name = $2",
    )
    .bind(owner_handle)
    .bind(lower_name)
    .fetch_optional(db.pool())
    .await?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repos::{self, NewRepo};
    use crate::testing::TestDb;
    use crate::users::{self, NewUser};

    fn repo(owner_id: i64, name: &str) -> NewRepo<'_> {
        NewRepo {
            owner_id,
            name,
            description: "",
            visibility: "public",
            default_branch: "main",
        }
    }

    #[tokio::test]
    async fn renames_leave_redirects_that_new_names_take_over() {
        let t = TestDb::new().await;
        let alice = users::insert(
            &t.db,
            &NewUser {
                handle: "alice",
                display_name: "",
                email: None,
                email_verified: false,
                password_hash: None,
                is_admin: false,
            },
        )
        .await
        .unwrap();
        let id = repos::insert(&t.db, &repo(alice, "one")).await.unwrap();
        repos::rename(&t.db, id, "two").await.unwrap();
        repos::rename(&t.db, id, "Three").await.unwrap();
        assert_eq!(target(&t.db, "alice", "one").await.unwrap(), Some(id));
        assert_eq!(target(&t.db, "alice", "two").await.unwrap(), Some(id));
        assert_eq!(target(&t.db, "alice", "three").await.unwrap(), None);

        repos::rename(&t.db, id, "three").await.unwrap();
        assert_eq!(
            target(&t.db, "alice", "three").await.unwrap(),
            None,
            "a case-only rename adds no redirect"
        );
        repos::insert(&t.db, &repo(alice, "One")).await.unwrap();
        assert_eq!(
            target(&t.db, "alice", "one").await.unwrap(),
            None,
            "a new repository takes its name over"
        );
        repos::rename(&t.db, id, "two").await.unwrap();
        assert_eq!(
            target(&t.db, "alice", "two").await.unwrap(),
            None,
            "renaming back onto an old name takes it over"
        );
        assert_eq!(target(&t.db, "alice", "three").await.unwrap(), Some(id));
        let taken = repos::rename(&t.db, id, "ONE").await.unwrap_err();
        assert!(taken.is_unique_violation());
        assert_eq!(repos::by_id(&t.db, id).await.unwrap().unwrap().name, "two");
        repos::delete(&t.db, id).await.unwrap();
        assert_eq!(
            target(&t.db, "alice", "three").await.unwrap(),
            None,
            "redirects go with their repository"
        );
    }
}
