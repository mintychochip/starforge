//! Agent adapters normalizing native transcripts into [`starforge_format::Event`]s.

pub mod claude;
pub mod codex;
pub mod pi;

pub use claude::ClaudeAdapter;
pub use codex::CodexAdapter;
pub use pi::PiAdapter;
