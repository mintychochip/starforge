//! Agent adapters normalizing native transcripts into [`starforge_format::Event`]s.

pub mod claude;

pub use claude::ClaudeAdapter;
