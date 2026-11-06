//! Permission levels and the effective-permission rule (spec §6.1, D4).
//!
//! Every permission decision goes through [`effective`], fed by grant facts
//! gathered in one place (`Core::grants_for`); no call site computes
//! permission or membership on its own.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Permission {
    Read,
    Triage,
    Write,
    Maintain,
    Admin,
}

impl Permission {
    pub const ALL: [Permission; 5] = [
        Permission::Read,
        Permission::Triage,
        Permission::Write,
        Permission::Maintain,
        Permission::Admin,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Permission::Read => "read",
            Permission::Triage => "triage",
            Permission::Write => "write",
            Permission::Maintain => "maintain",
            Permission::Admin => "admin",
        }
    }

    pub fn parse(s: &str) -> Option<Permission> {
        Permission::ALL.into_iter().find(|p| p.as_str() == s)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    Public,
    /// Readable by every signed-in user.
    Internal,
    Private,
}

impl Visibility {
    pub fn as_str(self) -> &'static str {
        match self {
            Visibility::Public => "public",
            Visibility::Internal => "internal",
            Visibility::Private => "private",
        }
    }

    pub fn parse(s: &str) -> Option<Visibility> {
        match s {
            "public" => Some(Visibility::Public),
            "internal" => Some(Visibility::Internal),
            "private" => Some(Visibility::Private),
            _ => None,
        }
    }
}

/// A signed-in, active user asking for access. Anonymous visitors are `None`.
#[derive(Debug, Clone, Copy)]
pub struct Viewer {
    pub user_id: i64,
    pub is_admin: bool,
}

/// Every grant source for one repository and viewer (D4). `org_base` is
/// present only when the viewer is an org member and the base is not `none`;
/// `teams` holds the covering team grants.
#[derive(Debug, Clone, Copy)]
pub struct Grants<'a> {
    pub site_admin: bool,
    pub user_owner: bool,
    pub org_owner: bool,
    pub org_base: Option<Permission>,
    pub teams: &'a [Permission],
    pub collaborator: Option<Permission>,
    pub visibility: Visibility,
    pub signed_in: bool,
}

/// The owned facts `Core::grants_for` gathers (at most three queries); the
/// borrowed [`Grants`] view feeds [`effective`] and [`is_member`].
#[derive(Debug, Clone)]
pub struct CollectedGrants {
    pub site_admin: bool,
    pub user_owner: bool,
    pub org_owner: bool,
    pub org_base: Option<Permission>,
    pub teams: Vec<Permission>,
    pub collaborator: Option<Permission>,
    pub visibility: Visibility,
    pub signed_in: bool,
}

impl CollectedGrants {
    pub fn as_grants(&self) -> Grants<'_> {
        Grants {
            site_admin: self.site_admin,
            user_owner: self.user_owner,
            org_owner: self.org_owner,
            org_base: self.org_base,
            teams: &self.teams,
            collaborator: self.collaborator,
            visibility: self.visibility,
            signed_in: self.signed_in,
        }
    }
}

/// Effective permission: the highest of org ownership, user ownership, and
/// site administration (`Admin`); the org base permission; every covering
/// team grant; the collaborator grant; and implicit `Read` (public
/// repositories; internal ones for signed-in users).
pub fn effective(g: &Grants) -> Option<Permission> {
    if g.site_admin || g.user_owner || g.org_owner {
        return Some(Permission::Admin);
    }
    let mut level = None;
    for p in g
        .org_base
        .into_iter()
        .chain(g.teams.iter().copied())
        .chain(g.collaborator)
        .chain(implicit(g))
    {
        level = level.max(Some(p));
    }
    level
}

fn implicit(g: &Grants) -> Option<Permission> {
    match g.visibility {
        Visibility::Public => Some(Permission::Read),
        Visibility::Internal if g.signed_in => Some(Permission::Read),
        _ => None,
    }
}

/// Whether an explicit grant exists (D4, spec §6.1): user ownership, org
/// ownership, an org base permission (never `none`: it is absent then), a
/// covering team grant, or a collaborator grant. Site admins are not members
/// by that fact alone, and implicit public/internal read never counts.
pub fn is_member(g: &Grants) -> bool {
    g.user_owner
        || g.org_owner
        || g.org_base.is_some()
        || !g.teams.is_empty()
        || g.collaborator.is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grants(
        visibility: Visibility,
        viewer: Option<Viewer>,
        collaborator: Option<Permission>,
    ) -> Grants<'static> {
        Grants {
            site_admin: viewer.map(|v| v.is_admin).unwrap_or(false),
            user_owner: viewer.map(|v| v.user_id == 1).unwrap_or(false),
            org_owner: false,
            org_base: None,
            teams: &[],
            collaborator,
            visibility,
            signed_in: viewer.is_some(),
        }
    }

    #[test]
    fn effective_permission_matrix() {
        use Permission::*;
        use Visibility::*;
        let owner = Viewer {
            user_id: 1,
            is_admin: false,
        };
        let other = Viewer {
            user_id: 2,
            is_admin: false,
        };
        let site_admin = Viewer {
            user_id: 3,
            is_admin: true,
        };
        let cases = [
            (Private, Some(owner), None, Some(Admin)),
            (Private, Some(site_admin), None, Some(Admin)),
            (Private, Some(other), None, None),
            (Private, None, None, None),
            (Private, Some(other), Some(Write), Some(Write)),
            (Internal, Some(other), None, Some(Read)),
            (Internal, None, None, None),
            (Internal, Some(other), Some(Maintain), Some(Maintain)),
            (Public, None, None, Some(Read)),
            (Public, Some(other), None, Some(Read)),
            (Public, Some(other), Some(Triage), Some(Triage)),
        ];
        for (visibility, viewer, collaborator, expected) in cases {
            assert_eq!(
                effective(&grants(visibility, viewer, collaborator)),
                expected,
                "{visibility:?} {viewer:?} {collaborator:?}"
            );
        }
    }

    #[test]
    fn org_grants_resolve() {
        use Permission::*;
        use Visibility::*;
        // Org ownership is Admin even on a private repository.
        let owner = Grants {
            site_admin: false,
            user_owner: false,
            org_owner: true,
            org_base: None,
            teams: &[],
            collaborator: None,
            visibility: Private,
            signed_in: true,
        };
        assert_eq!(effective(&owner), Some(Admin));
        assert!(is_member(&owner));
        // The base permission grants its level and counts as membership.
        let base = Grants {
            org_base: Some(Write),
            ..owner
        };
        let base = Grants {
            org_owner: false,
            ..base
        };
        assert_eq!(effective(&base), Some(Write));
        assert!(is_member(&base));
        // Site admins are admins everywhere but members nowhere by that fact.
        let admin = Grants {
            site_admin: true,
            org_owner: false,
            org_base: None,
            ..base
        };
        assert_eq!(effective(&admin), Some(Admin));
        assert!(!is_member(&admin));
    }

    #[test]
    fn names_round_trip() {
        for p in Permission::ALL {
            assert_eq!(Permission::parse(p.as_str()), Some(p));
        }
        for v in [
            Visibility::Public,
            Visibility::Internal,
            Visibility::Private,
        ] {
            assert_eq!(Visibility::parse(v.as_str()), Some(v));
        }
        assert_eq!(Permission::parse("owner"), None);
        assert!(Permission::Read < Permission::Admin);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    fn arb_permission() -> impl Strategy<Value = Permission> {
        prop_oneof![
            Just(Permission::Read),
            Just(Permission::Triage),
            Just(Permission::Write),
            Just(Permission::Maintain),
            Just(Permission::Admin),
        ]
    }

    fn arb_visibility() -> impl Strategy<Value = Visibility> {
        prop_oneof![
            Just(Visibility::Public),
            Just(Visibility::Internal),
            Just(Visibility::Private),
        ]
    }

    /// Consistent grant facts: anonymous viewers hold no grant and no identity
    /// flags; signed-out grants never appear.
    fn arb_collected() -> impl Strategy<Value = CollectedGrants> {
        (
            any::<bool>(),
            arb_visibility(),
            any::<bool>(),
            any::<bool>(),
            any::<bool>(),
            prop::option::of(arb_permission()),
            proptest::collection::vec(arb_permission(), 0..3),
            prop::option::of(arb_permission()),
        )
            .prop_map(
                |(
                    signed_in,
                    visibility,
                    site_admin,
                    user_owner,
                    org_owner,
                    org_base,
                    teams,
                    collaborator,
                )| {
                    CollectedGrants {
                        site_admin: signed_in && site_admin,
                        user_owner: signed_in && user_owner,
                        org_owner: signed_in && org_owner,
                        org_base: if signed_in { org_base } else { None },
                        teams: if signed_in { teams } else { Vec::new() },
                        collaborator: if signed_in { collaborator } else { None },
                        visibility,
                        signed_in,
                    }
                },
            )
    }

    fn expected_max(g: &CollectedGrants) -> Option<Permission> {
        let mut sources = Vec::new();
        if g.site_admin || g.user_owner || g.org_owner {
            sources.push(Permission::Admin);
        }
        if let Some(p) = g.org_base {
            sources.push(p);
        }
        sources.extend(g.teams.iter().copied());
        if let Some(p) = g.collaborator {
            sources.push(p);
        }
        match g.visibility {
            Visibility::Public => sources.push(Permission::Read),
            Visibility::Internal if g.signed_in => sources.push(Permission::Read),
            _ => {}
        }
        sources.into_iter().max()
    }

    proptest! {
        /// The result is the max of the grant sources (D4).
        #[test]
        fn result_is_max_of_sources(g in arb_collected()) {
            prop_assert_eq!(effective(&g.as_grants()), expected_max(&g));
        }

        /// Removing a grant never raises the level (D4).
        #[test]
        fn removing_a_grant_never_raises(g in arb_collected()) {
            let before = effective(&g.as_grants());
            let mut variants = Vec::new();
            let mut no_admin = g.clone();
            no_admin.site_admin = false;
            no_admin.user_owner = false;
            no_admin.org_owner = false;
            variants.push(no_admin);
            let mut no_base = g.clone();
            no_base.org_base = None;
            variants.push(no_base);
            let mut no_teams = g.clone();
            no_teams.teams.clear();
            variants.push(no_teams);
            let mut no_collab = g.clone();
            no_collab.collaborator = None;
            variants.push(no_collab);
            for v in &variants {
                prop_assert!(effective(&v.as_grants()) <= before);
            }
        }

        /// Anonymous viewers get at most `Read`, and only on public repositories (D4).
        #[test]
        fn anonymous_capped_at_public_read(g in arb_collected()) {
            prop_assume!(!g.signed_in);
            match effective(&g.as_grants()) {
                None => {}
                Some(Permission::Read) => prop_assert_eq!(g.visibility, Visibility::Public),
                Some(other) => panic!("anonymous viewer got {other:?}"),
            }
            prop_assert!(!is_member(&g.as_grants()));
        }

        /// Membership is equivalent to "at least one explicit grant" (D4).
        #[test]
        fn membership_is_explicit_grant(g in arb_collected()) {
            let expected = g.user_owner
                || g.org_owner
                || g.org_base.is_some()
                || !g.teams.is_empty()
                || g.collaborator.is_some();
            prop_assert_eq!(is_member(&g.as_grants()), expected);
        }
    }
}
