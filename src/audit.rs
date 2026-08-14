//! Append-only record of every decision.
//!
//! # Design decision: the audit log records decisions, never payloads
//!
//! It stores which tool was called, what was decided, how many paths were
//! touched and how many bytes came back — not the arguments and not the
//! result. A log that captured payloads would accumulate exactly the material
//! this crate exists to protect, in a file that is by design never deleted.
//!
//! # Design decision: one JSON object per line
//!
//! A partially-written line is a single unparseable record rather than a
//! corrupt document, and the file stays greppable and streamable without a
//! parser that holds the whole thing in memory.

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{GritError, Result};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditRecord {
    pub server: String,
    pub tool: String,
    /// `"allowed"`, or the machine-readable error code of the refusal.
    pub outcome: String,
    /// Present only when refused. Safe to log: reasons are written by this
    /// crate and never interpolate a payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub mutating: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_files: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paths_changed: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paths_created: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paths_deleted: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rolled_back: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_bytes: Option<usize>,
    /// Names of injection heuristics that fired on the tool result.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub injection_signals: Vec<String>,
}

impl AuditRecord {
    pub fn allowed(server: &str, tool: &str, mutating: bool) -> Self {
        Self {
            server: server.to_string(),
            tool: tool.to_string(),
            outcome: "allowed".to_string(),
            reason: None,
            mutating,
            snapshot_files: None,
            paths_changed: None,
            paths_created: None,
            paths_deleted: None,
            rolled_back: None,
            result_bytes: None,
            injection_signals: Vec::new(),
        }
    }

    pub fn refused(server: &str, tool: &str, err: &GritError) -> Self {
        Self {
            server: server.to_string(),
            tool: tool.to_string(),
            outcome: err.code().to_string(),
            reason: Some(err.to_string()),
            mutating: false,
            snapshot_files: None,
            paths_changed: None,
            paths_created: None,
            paths_deleted: None,
            rolled_back: None,
            result_bytes: None,
            injection_signals: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuditLog {
    path: PathBuf,
}

impl AuditLog {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one record.
    ///
    /// Opened and closed per write rather than held open. An agent session is
    /// low-frequency, and a long-lived handle is a buffer that loses its tail
    /// when the process is killed — which is precisely the moment the last few
    /// records matter most.
    pub fn append(&self, record: &AuditRecord) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| GritError::io(parent, e))?;
        }
        let line = serde_json::to_string(record)
            .map_err(|e| GritError::Config(format!("cannot serialise audit record: {e}")))?;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| GritError::io(&self.path, e))?;
        writeln!(file, "{line}").map_err(|e| GritError::io(&self.path, e))
    }

    pub fn read_all(&self) -> Result<Vec<AuditRecord>> {
        let raw = match std::fs::read_to_string(&self.path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(GritError::io(&self.path, e)),
        };
        raw.lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| {
                serde_json::from_str(l)
                    .map_err(|e| GritError::Config(format!("corrupt audit line: {e}")))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_append_and_read_back() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = AuditLog::new(dir.path().join("audit.jsonl"));
        log.append(&AuditRecord::allowed("fs", "read_file", false))
            .expect("append");
        log.append(&AuditRecord::refused(
            "fs",
            "run_command",
            &GritError::Denied {
                reason: "no policy".into(),
            },
        ))
        .expect("append");

        let all = log.read_all().expect("read");
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].outcome, "allowed");
        assert_eq!(all[1].outcome, "denied");
    }

    #[test]
    fn a_missing_log_reads_as_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = AuditLog::new(dir.path().join("nope.jsonl"));
        assert!(log.read_all().expect("read").is_empty());
    }

    #[test]
    fn a_record_never_carries_a_payload_field() {
        // Guards the design rule: if someone adds an `arguments` or `result`
        // field, this fails and they have to justify it.
        let record = AuditRecord::allowed("fs", "read_file", true);
        let json = serde_json::to_string(&record).expect("serialise");
        for forbidden in ["arguments", "result", "content", "payload", "prompt"] {
            assert!(
                !json.contains(forbidden),
                "audit records must not carry payloads, found {forbidden}: {json}"
            );
        }
    }
}
