//! Upload queue entries + injected clock (implemented C4/C6).

/// One pending upload operation (`queue.jsonl`: one object per line).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct QueueEntry {
    pub op: QueueOp,
    pub ulid: String,
    pub repo: String,
    pub segment: Option<u64>,
    pub attempts: u32,
    /// RFC 3339.
    pub not_before: String,
}

/// Upload operation kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum QueueOp {
    Meta,
    Segment,
    Complete,
    Links,
}

/// Injected clock for backoff + device-flow polling.
///
/// Plain trait with RPITIT — no async-trait dependency.
pub trait Sleeper {
    fn sleep(&self, dur: std::time::Duration) -> impl Future<Output = ()> + '_;
}

/// Production sleeper backed by `tokio::time::sleep`.
pub struct TokioSleeper;

impl Sleeper for TokioSleeper {
    async fn sleep(&self, dur: std::time::Duration) {
        tokio::time::sleep(dur).await;
    }
}
