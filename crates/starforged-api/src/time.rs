//! Shared API rendering helpers: unix seconds → RFC 3339 (`…Z`).
//!
//! The service stores unix seconds internally; every envelope renders them
//! with [`rfc3339`] (Howard Hinnant's civil-from-days — no extra dependency
//! for one envelope format).

/// Unix seconds → `YYYY-MM-DDTHH:MM:SSZ`.
pub(crate) fn rfc3339(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rest = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let mut y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    if m <= 2 {
        y += 1;
    }
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

/// [`rfc3339`] over `Option` (nullable timestamps stay null).
pub(crate) fn opt_ts(v: Option<i64>) -> Option<String> {
    v.map(rfc3339)
}
