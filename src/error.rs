//! Typed errors, and one place that decides what each one means.
//!
//! # Design decision: a denial is not a fault
//!
//! `Denied` means Grit did its job and refused. `Io`, `Crypto` and `Config` are
//! faults — Grit failed to do its job. They are separate variants because the
//! correct response differs completely: a denial is an expected outcome that
//! gets audited and returned to the caller, while a fault means the gate itself
//! is not functioning and, since this component exists to contain damage, the
//! only safe response to a broken gate is to stop rather than wave things
//! through.

use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum GritError {
    /// The call was refused by policy. An outcome, not a failure.
    #[error("denied: {reason}")]
    Denied { reason: String },

    /// A path escaped its allowed roots. Kept distinct from `Denied` because
    /// this specific denial is the one that most often indicates an attack
    /// rather than a misconfiguration, and it should be greppable in an audit
    /// log without parsing free text.
    #[error("path escape: {attempted} resolves outside every allowed root")]
    PathEscape { attempted: PathBuf },

    #[error("policy error: {0}")]
    Policy(String),

    #[error("snapshot error: {0}")]
    Snapshot(String),

    /// Deliberately opaque. A cryptographic failure must never explain *which*
    /// part failed — distinguishing "bad key" from "bad tag" for a caller is
    /// how padding-oracle-shaped bugs are built.
    #[error("cryptographic operation failed")]
    Crypto,

    #[error("configuration error: {0}")]
    Config(String),

    #[error("io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

impl GritError {
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        GritError::Io {
            path: path.into(),
            source,
        }
    }

    /// Did Grit refuse, as opposed to break?
    pub fn is_denial(&self) -> bool {
        matches!(
            self,
            GritError::Denied { .. } | GritError::PathEscape { .. }
        )
    }

    /// Stable machine-readable code for the audit log. Callers and dashboards
    /// branch on this; the human-readable message is free to change.
    pub fn code(&self) -> &'static str {
        match self {
            GritError::Denied { .. } => "denied",
            GritError::PathEscape { .. } => "path_escape",
            GritError::Policy(_) => "policy_error",
            GritError::Snapshot(_) => "snapshot_error",
            GritError::Crypto => "crypto_error",
            GritError::Config(_) => "config_error",
            GritError::Io { .. } => "io_error",
        }
    }
}

pub type Result<T> = std::result::Result<T, GritError>;
