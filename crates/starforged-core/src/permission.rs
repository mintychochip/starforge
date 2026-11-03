//! Permission levels and the effective-permission rule (spec §6.1).

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

/// Effective permission on a user-owned repository: site admins and the owner are admins; otherwise the
/// higher of the collaborator grant and the implicit read that public repositories give everyone and
/// internal repositories give signed-in users.
pub fn effective(
    owner_id: i64,
    visibility: Visibility,
    viewer: Option<Viewer>,
    collaborator: Option<Permission>,
) -> Option<Permission> {
    if let Some(v) = viewer
        && (v.is_admin || v.user_id == owner_id)
    {
        return Some(Permission::Admin);
    }
    let implicit = match visibility {
        Visibility::Public => Some(Permission::Read),
        Visibility::Internal if viewer.is_some() => Some(Permission::Read),
        _ => None,
    };
    collaborator.max(implicit)
}

#[cfg(test)]
mod tests {
    use super::*;

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
                effective(1, visibility, viewer, collaborator),
                expected,
                "{visibility:?} {viewer:?} {collaborator:?}"
            );
        }
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
