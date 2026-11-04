//! Agent adapters normalizing native transcripts into [`starforge_format::Event`]s.

pub mod claude;
pub mod codex;

pub use claude::ClaudeAdapter;
pub use codex::CodexAdapter;
