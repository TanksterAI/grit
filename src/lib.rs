//! **Grit** — a context gateway for MCP servers.
//!
//! Grit sits between an MCP client and the tools it calls, and does four
//! things: refuses tools that have no declared policy, resolves and contains
//! every path argument, snapshots local state before anything that can mutate
//! it, and keeps credentials encrypted at rest.
//!
//! # What Grit is honestly not
//!
//! **This is policy isolation, not kernel sandboxing.** There are no
//! namespaces, no seccomp filter, no cgroup. A tool that Grit executes could,
//! if it wanted to, ignore every path it was given and open something else
//! directly — Grit checks the arguments, not the syscalls.
//!
//! That is worth stating plainly rather than burying, because the difference
//! decides what this component can be trusted with. It raises the cost of the
//! realistic failure — an agent talked into passing a bad path, a tool that
//! writes more than it claimed, a prompt injection that redirects a file
//! operation — and it does nothing at all against a genuinely malicious binary
//! you chose to run. For the latter you need a real sandbox underneath, and
//! Grit is designed to sit inside one rather than to replace it.
//!
//! The rollback is real, though. That is the part that holds regardless of how
//! well-behaved the tool is, because it is measured from the filesystem rather
//! than from anything the tool reports about itself.

pub mod audit;
pub mod containment;
pub mod error;
pub mod gate;
pub mod policy;
pub mod secrets;
pub mod snapshot;

pub use audit::{AuditLog, AuditRecord};
pub use error::{GritError, Result};
pub use gate::{Completion, Gate, InFlight};
pub use policy::{PolicySet, ToolPolicy};
pub use secrets::{Secret, SecretStore};
pub use snapshot::{Drift, Limits, Snapshot};
