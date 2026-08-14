//! Grit CLI.
//!
//! Deliberately small. The interesting surface is the library; this exists so
//! the pieces can be exercised and inspected from a terminal without writing a
//! host first.
//!
//! # Design decision: `main` returns `Result` and there is no `unwrap`
//!
//! A configuration fault exits non-zero with a legible message rather than a
//! panic and a backtrace.

use std::path::PathBuf;
use std::process::ExitCode;

use grit::{AuditLog, GritError, PolicySet, Result, SecretStore, Snapshot};

const USAGE: &str = "\
grit — a context gateway for MCP servers

USAGE:
  grit check-policy <policy.json>
      Validate a policy file and list the tools it declares.

  grit secret put <store.json> <name>
      Read a secret from stdin and store it encrypted. Requires GRIT_MASTER_KEY.

  grit secret list <store.json>
      List the names in a store. Never prints a value.

  grit snapshot <workspace>
      Capture a workspace and report what it would protect.

  grit audit <audit.jsonl>
      Summarise a decision log.

ENVIRONMENT:
  GRIT_MASTER_KEY   64 hex characters (32 bytes). Generate with:
                    openssl rand -hex 32
";

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("grit: {e}");
            // A refusal and a fault are different things and deserve different
            // exit codes, so a script can tell "it said no" from "it broke".
            if e.is_denial() {
                ExitCode::from(2)
            } else {
                ExitCode::FAILURE
            }
        }
    }
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();

    match argv.as_slice() {
        [] | ["-h"] | ["--help"] | ["help"] => {
            print!("{USAGE}");
            Ok(())
        }

        ["check-policy", path] => {
            let raw = std::fs::read_to_string(path).map_err(|e| GritError::io(*path, e))?;
            let set = PolicySet::from_json(&raw)?;
            set.validate()?;
            println!("policy is valid: {} tool(s) declared", set.tools.len());
            for (key, policy) in &set.tools {
                println!(
                    "  {key}\n    roots={} denied={} network={} mutates={} timeout={}s max_output={}B",
                    policy.allowed_roots.len(),
                    policy.denied_roots.len(),
                    policy.allow_network,
                    policy.mutates,
                    policy.timeout_secs,
                    policy.max_output_bytes,
                );
            }
            Ok(())
        }

        ["secret", "put", store_path, name] => {
            let path = PathBuf::from(store_path);
            let mut store = SecretStore::load(&path)?;
            let mut value = String::new();
            std::io::Write::flush(&mut std::io::stdout()).ok();
            std::io::BufRead::read_line(&mut std::io::stdin().lock(), &mut value)
                .map_err(|e| GritError::io("<stdin>", e))?;
            store.put(name, value.trim_end_matches('\n'))?;
            store.save(&path)?;
            println!("stored {name} ({} secret(s) in store)", store.names().len());
            Ok(())
        }

        ["secret", "list", store_path] => {
            let store = SecretStore::load(&PathBuf::from(store_path))?;
            for name in store.names() {
                println!("{name}");
            }
            Ok(())
        }

        ["snapshot", workspace] => {
            let snap = Snapshot::capture(&PathBuf::from(workspace), Default::default())?;
            println!(
                "captured {} file(s), {} byte(s) under {}",
                snap.file_count(),
                snap.total_bytes(),
                snap.root().display()
            );
            Ok(())
        }

        ["audit", log_path] => {
            let records = AuditLog::new(PathBuf::from(log_path)).read_all()?;
            let denied = records.iter().filter(|r| r.outcome != "allowed").count();
            let rolled = records
                .iter()
                .filter(|r| r.rolled_back == Some(true))
                .count();
            let flagged = records
                .iter()
                .filter(|r| !r.injection_signals.is_empty())
                .count();
            println!(
                "{} decision(s): {} allowed, {denied} refused, {rolled} rolled back, \
                 {flagged} with injection signals",
                records.len(),
                records.len() - denied,
            );
            Ok(())
        }

        _ => {
            eprint!("{USAGE}");
            Err(GritError::Config("unrecognised arguments".to_string()))
        }
    }
}
