//! Spool layout (implemented C4).

/// Session spool rooted at `<git common dir>/starforge`.
pub struct Spool {
    pub root: std::path::PathBuf,
}

impl Spool {
    /// Open the spool rooted at the given git common dir.
    pub fn open(common_dir: &std::path::Path) -> Self {
        Self {
            root: common_dir.join("starforge"),
        }
    }

    /// Create the spool directory layout (§7.3).
    pub fn ensure_layout(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(self.root.join("sessions"))?;
        std::fs::create_dir_all(self.root.join("segments"))?;
        std::fs::create_dir_all(self.root.join("raw"))?;
        Ok(())
    }
}
