# grit — app constitution

The canonical constitution is `CLAUDE.md` in **`TanksterAI/tankster-core`**.
Everything there applies. This adds only what is specific to Grit.

## What this is

A context gateway for MCP servers: per-tool policy, path containment,
snapshot-and-rollback of local state, AES-256-GCM credential storage, and an
append-only audit log.

## What this is *not* — read before changing anything

- **Not a sandbox.** Policy isolation only: no namespaces, no seccomp, no
  cgroups. Never describe it as a sandbox in a README, a commit message or a
  CV. It checks arguments, not syscalls. If that claim creeps back in, the
  component starts getting trusted with things it cannot do.
- **Not `agent-egress-proxy`.** That governs what *leaves* for a model vendor —
  PII, per-request budget, cost telemetry. Grit governs what *executes*
  locally. Opposite directions, different threat models. They are complementary
  and must not be merged.
- **Not prompt-injection prevention.** The heuristics in `gate.rs` are a signal.
  The containment is the policy layer. Do not let the scanner become the thing
  people rely on.

## Hard rules

- **No `unwrap()`, `expect()` or `panic!` outside `#[cfg(test)]`.** Enforced by
  `cargo clippy --all-targets -- -D warnings` in CI.
- **An undeclared tool is denied.** `PolicySet::get` returns an error for a
  missing key and must never fall back to `ToolPolicy::default()`. If it did,
  adding a tool to an MCP server would silently grant it whatever the default
  happened to be — the gate bypassed by the ordinary act of shipping a feature.
- **Snapshot before the call, never after.** A snapshot taken afterwards
  records the damage instead of the state to return to. The two-phase
  `authorise`/`complete` API exists to make this impossible to get wrong.
- **A partial snapshot is an error.** Never truncate to fit a limit. A rollback
  from half a snapshot looks like it worked.
- **The audit log records decisions, never payloads.** No arguments, no
  results, no prompts. `audit.rs` has a test that fails if a payload-shaped
  field appears.
- **Never reuse a GCM nonce**, and always bind the secret's name in as AAD.
  Both are covered by tests; if you touch `secrets.rs`, those tests are the
  specification.
- **Cryptographic errors stay opaque.** One `GritError::Crypto` with no detail.

## A trap worth knowing about

`clippy` will offer to fold the `Component::ParentDir` arm in
`containment::resolve` into a match guard — `ParentDir if !out.pop()`. It is
equivalent *only* because the guard mutates `out` as a side effect. Do not
accept that suggestion; the explicit form is there deliberately and says so in
a comment.

## Naming

`infrastructure-conventions.md` in the project knowledge base is the naming
source of truth and needs a row for this service. Per the core constitution,
that glossary update is part of the change, not a follow-up.
