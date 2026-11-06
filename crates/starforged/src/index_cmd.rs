//! `starforged index rebuild`: wipe and rebuild the search index from the
//! database and blobs (plan M4a D5).

use anyhow::Context;
use starforged_index::SearchIndex;

use crate::admin::open_core;
use crate::config::Config;

/// Rebuilds the index at `config.index_dir()` and prints the document counts.
///
/// The tantivy writer is single-process: while the server runs, opening the
/// index here fails with `Locked`, and the command fails with the message to
/// stop the server (or use the site-admin rebuild action) — without touching
/// the running server's index.
pub async fn rebuild(config: &Config) -> anyhow::Result<()> {
    let dir = config.index_dir();
    // Acquire (and immediately release) the writer: when the server is
    // running this fails, before `open_core` could serve a throwaway index
    // and report success for an index that was never rebuilt.
    let probe = SearchIndex::open_or_create(&dir)
        .map_err(|err| anyhow::Error::new(err).context("the search index"))
        .context(
            "the search index is in use: stop the server and retry, or use the site-admin rebuild action",
        )?;
    drop(probe);
    let core = open_core(config, std::env::current_exe()?).await?;
    let stats = core
        .rebuild_search_index()
        .await
        .context("rebuilding the search index")?;
    println!(
        "index rebuild complete: {} trail(s), {} event(s)",
        stats.trails, stats.events
    );
    Ok(())
}
