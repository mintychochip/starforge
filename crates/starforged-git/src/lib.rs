//! starforged-git: repositories on disk. The network protocol, merges, and diffs run the `git` binary;
//! read paths use gix (spec D11).

pub mod command;
pub mod http;
pub mod init;
pub mod read;
pub mod refpolicy;
pub use command::GitError;
