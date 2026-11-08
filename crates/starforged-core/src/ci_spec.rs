//! The `.starforge/ci.toml` job spec: parsing and validation (M6a A0).
//!
//! The parser lives in the permissive `starforge-ci-spec` crate so the
//! CLI's local `ci run` can use it without the AGPL server crate. This
//! module re-exports the types and keeps the core error mapping.

pub use starforge_ci_spec::{
    CiCacheSpec, CiJobSpec, CiSpec, CiTriggers, MAX_JOBS, MAX_SPEC_BYTES, MAX_TIMEOUT, SpecError,
    parse_timeout,
};

use crate::{CoreError, CoreResult};

/// Parses one spec document, mapping a parse or validation error to the
/// core's `Invalid` error.
pub fn parse(text: &str) -> CoreResult<CiSpec> {
    CiSpec::parse(text).map_err(|err| CoreError::Invalid(err.to_string()))
}
