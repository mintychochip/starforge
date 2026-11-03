//! starforged-git: repositories on disk. The network protocol, merges, and diffs run the `git` binary;
//! read paths use gix (spec D11).

pub mod command;
pub mod init;
pub mod refpolicy;
pub use command::GitError;
