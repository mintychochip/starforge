/// Resume cursor for one native session.
///
/// For JSONL-file agents `offset` is bytes consumed and `lines` is records
/// consumed; for OpenCode `offset` is the last SQLite `seq` consumed and
/// `lines` is messages consumed. `events` counts events already emitted, which is
/// not the record count: one native record can carry several content blocks
/// and therefore several events. Never wall-clock, never mtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct Cursor {
    pub offset: u64,
    pub lines: u64,
    /// Events emitted so far; the next `seq` continues from here.
    pub events: u64,
}

impl Cursor {
    pub fn start() -> Self {
        Self {
            offset: 0,
            lines: 0,
            events: 0,
        }
    }

    /// Next `seq` to assign: resume never reuses, skips, or reorders a `seq`.
    ///
    /// Counts emitted events, not records: a record carrying several content
    /// blocks emits several events and must not restart the counter.
    pub fn next_seq(&self) -> u64 {
        self.events
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_start_and_round_trip() {
        let c = Cursor::start();
        assert_eq!(c.next_seq(), 0);
        let s = serde_json::to_string(&c).unwrap();
        assert_eq!(serde_json::from_str::<Cursor>(&s).unwrap(), c);
    }

    #[test]
    fn cursor_next_seq_continues() {
        assert_eq!(
            Cursor {
                offset: 9,
                lines: 4,
                events: 7
            }
            .next_seq(),
            7
        );
    }
}
