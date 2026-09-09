//! Per-tool policy: what a single MCP tool is allowed to touch.
//!
//! # Design decision: deny by default, per tool, and never a global allow
//!
//! An MCP server usually exposes several tools with wildly different blast
//! radii — a `read_file` and a `run_command` sitting behind the same process.
//! Granting the *server* a permission set means the weakest tool defines the
//! risk of the strongest. Policy is therefore keyed by `(server, tool)`, and a
//! tool with no policy is refused rather than defaulted.
//!
//! # Design decision: `mutates` is declared, not inferred
//!
//! Grit cannot know whether a tool writes to disk. Asking the policy author to
//! say so is the only honest option, and the consequence of getting it wrong is
//! asymmetric: a read marked mutating costs a wasted snapshot, while a write
//! marked read-only means no rollback exists when it goes wrong. So an
//! unspecified tool is treated as mutating.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{GritError, Result};

fn default_true() -> bool {
    true
}

fn default_timeout() -> u64 {
    30
}

fn default_max_output() -> usize {
    1_000_000
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolPolicy {
    /// Roots this tool may read or write beneath. Empty means no filesystem
    /// access at all, which is a meaningful and common answer.
    #[serde(default)]
    pub allowed_roots: Vec<PathBuf>,

    /// Roots the tool may never touch even when nested inside an allowed root.
    /// Checked after resolution, so `~/project/.git` stays protected when
    /// `~/project` is allowed.
    #[serde(default)]
    pub denied_roots: Vec<PathBuf>,

    /// May this tool reach the network? Declared and recorded, never enforced:
    /// Grit does not execute the tool, so there is nothing it can intercept.
    /// See the honesty note in `lib.rs`.
    #[serde(default)]
    pub allow_network: bool,

    /// Intended ceiling for one call. Declared and recorded, never enforced:
    /// Grit does not execute the tool, so there is no call it can interrupt.
    /// See the honesty note in `lib.rs`.
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,

    /// Cap on bytes returned. A tool result is untrusted input that will be
    /// fed straight back to a model, so an unbounded result is both a cost
    /// problem and a prompt-injection surface.
    #[serde(default = "default_max_output")]
    pub max_output_bytes: usize,

    /// Whether this tool may change local state. Defaults to `true` — the
    /// cautious answer, because the cost of being wrong is asymmetric.
    #[serde(default = "default_true")]
    pub mutates: bool,

    /// Names of credentials from the secret store this tool may receive.
    #[serde(default)]
    pub secrets: Vec<String>,
}

impl Default for ToolPolicy {
    fn default() -> Self {
        Self {
            allowed_roots: Vec::new(),
            denied_roots: Vec::new(),
            allow_network: false,
            timeout_secs: default_timeout(),
            max_output_bytes: default_max_output(),
            mutates: true,
            secrets: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicySet {
    /// Keyed `"server/tool"`.
    #[serde(default)]
    pub tools: BTreeMap<String, ToolPolicy>,
}

impl PolicySet {
    pub fn from_json(raw: &str) -> Result<Self> {
        serde_json::from_str(raw).map_err(|e| GritError::Policy(format!("invalid policy: {e}")))
    }

    pub fn key(server: &str, tool: &str) -> String {
        format!("{server}/{tool}")
    }

    /// Look up a policy. A missing entry is a denial, never a default.
    ///
    /// This is the single most important line in the crate. If an unknown tool
    /// fell through to `ToolPolicy::default()`, adding a tool to an MCP server
    /// would silently grant it whatever the default happened to be, and the
    /// gate would be bypassed by the ordinary act of shipping a feature.
    pub fn get(&self, server: &str, tool: &str) -> Result<&ToolPolicy> {
        let key = Self::key(server, tool);
        self.tools.get(&key).ok_or_else(|| GritError::Denied {
            reason: format!("no policy declared for {key}; refusing by default"),
        })
    }

    pub fn insert(&mut self, server: &str, tool: &str, policy: ToolPolicy) {
        self.tools.insert(Self::key(server, tool), policy);
    }

    /// Reject policies that are self-contradictory or obviously wrong at load
    /// time, so a bad policy file fails on start rather than on the call it
    /// was meant to stop.
    pub fn validate(&self) -> Result<()> {
        for (key, policy) in &self.tools {
            if policy.timeout_secs == 0 {
                return Err(GritError::Policy(format!(
                    "{key}: timeout_secs must be at least 1"
                )));
            }
            if policy.max_output_bytes == 0 {
                return Err(GritError::Policy(format!(
                    "{key}: max_output_bytes must be at least 1"
                )));
            }
            for root in &policy.allowed_roots {
                if root.as_os_str().is_empty() {
                    return Err(GritError::Policy(format!("{key}: empty allowed root")));
                }
                if !root.is_absolute() {
                    return Err(GritError::Policy(format!(
                        "{key}: allowed root {} must be absolute; a relative root \
                         means the policy depends on the working directory of \
                         whatever launched the server",
                        root.display()
                    )));
                }
            }
            for root in &policy.denied_roots {
                if !root.is_absolute() {
                    return Err(GritError::Policy(format!(
                        "{key}: denied root {} must be absolute",
                        root.display()
                    )));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_undeclared_tool_is_denied() {
        let set = PolicySet::default();
        let err = set.get("fs", "read_file").expect_err("must deny");
        assert!(err.is_denial(), "{err}");
        assert_eq!(err.code(), "denied");
    }

    #[test]
    fn a_declared_tool_is_returned() {
        let mut set = PolicySet::default();
        set.insert("fs", "read_file", ToolPolicy::default());
        assert!(set.get("fs", "read_file").is_ok());
    }

    #[test]
    fn tools_on_the_same_server_are_isolated_from_each_other() {
        // The whole reason policy is keyed by tool and not by server.
        let mut set = PolicySet::default();
        set.insert("fs", "read_file", ToolPolicy::default());
        assert!(set.get("fs", "read_file").is_ok());
        assert!(
            set.get("fs", "run_command").is_err(),
            "granting one tool must not grant its neighbour"
        );
    }

    #[test]
    fn an_unspecified_tool_defaults_to_mutating() {
        let p: ToolPolicy = serde_json::from_str("{}").expect("empty object is a valid policy");
        assert!(p.mutates, "the cautious default is the only safe one");
        assert!(!p.allow_network, "network must be opt-in");
        assert!(
            p.allowed_roots.is_empty(),
            "filesystem access must be opt-in"
        );
    }

    #[test]
    fn a_relative_root_is_rejected_at_load_time() {
        let mut set = PolicySet::default();
        set.insert(
            "fs",
            "read_file",
            ToolPolicy {
                allowed_roots: vec![PathBuf::from("relative/path")],
                ..Default::default()
            },
        );
        assert!(set.validate().is_err());
    }

    #[test]
    fn a_zero_timeout_is_rejected() {
        let mut set = PolicySet::default();
        set.insert(
            "fs",
            "read_file",
            ToolPolicy {
                timeout_secs: 0,
                ..Default::default()
            },
        );
        assert!(set.validate().is_err());
    }

    #[test]
    fn policy_round_trips_through_json() {
        let raw = r#"{"tools":{"fs/read_file":{"allowed_roots":["/tmp/x"],"mutates":false}}}"#;
        let set = PolicySet::from_json(raw).expect("parses");
        let p = set.get("fs", "read_file").expect("present");
        assert!(!p.mutates);
        assert_eq!(p.allowed_roots, vec![PathBuf::from("/tmp/x")]);
        assert_eq!(p.timeout_secs, 30, "unspecified fields take their defaults");
    }
}
