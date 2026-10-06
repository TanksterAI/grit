# Grit

A context gateway for MCP servers. It sits between an MCP client and the tools
it calls, and does four things:

1. **Refuses undeclared tools.** Policy is keyed by `(server, tool)`. A tool
   with no policy is denied — never defaulted.
2. **Contains every path.** Path arguments are fully resolved, following
   symlinks, then checked component-wise against allowed and denied roots.
3. **Snapshots before it lets anything mutate.** If a tool may write, the
   workspace is captured first, so a bad call can be undone.
4. **Keeps credentials encrypted.** AES-256-GCM at rest, with a fresh nonce
   per write and the secret's name bound in as associated data.

Every decision lands in an append-only audit log.

## What Grit is honestly not

**This is policy isolation, not kernel sandboxing.** No namespaces, no seccomp,
no cgroups. A tool Grit permits could ignore the path it was handed and open
something else directly — Grit checks arguments, not syscalls.

That distinction decides what this can be trusted with. It raises the cost of
the realistic failure: an agent talked into passing a bad path, a tool that
writes more than it claimed, an injected instruction that redirects a file
operation. It does nothing against a genuinely malicious binary you chose to
run. For that you need a real sandbox, and Grit is built to sit inside one
rather than to replace it.

**The rollback is real**, though, and it holds regardless of how well-behaved
the tool turns out to be — because it is measured from the filesystem, not from
anything the tool says about itself.

**The injection heuristics are a signal, not a boundary.** Pattern-matching on
prose is evaded by rephrasing, and fires on any document *about* prompt
injection. The containment is the policy layer. The patterns raise an alarm.

## Quick start

```bash
cargo build --release

cat > policy.json <<'JSON'
{"tools":{
  "fs/read_file": {"allowed_roots":["/home/me/project"],
                   "denied_roots":["/home/me/project/.git"],
                   "mutates": false},
  "fs/edit_file": {"allowed_roots":["/home/me/project"], "mutates": true}
}}
JSON

grit check-policy policy.json
grit snapshot /home/me/project

export GRIT_MASTER_KEY=$(openssl rand -hex 32)
echo "sk-live-..." | grit secret put store.json fal_key
grit secret list store.json      # names only, never values

grit audit audit.jsonl
```

## Using it as a library

The two-phase API exists because the interesting moment belongs to somebody
else — Grit does not execute the tool, the host does. A single function would
have to snapshot too late or never roll back.

```rust
let gate = Gate::new(policies, AuditLog::new("audit.jsonl"))?;

// Before the call: policy, containment, and a snapshot if it may mutate.
let in_flight = gate.authorise("fs", "edit_file", &paths, Some(workspace))?;

let result = host.run_the_tool();   // not Grit's business

// After: size cap, injection scan, rollback on refusal, audit either way.
let completion = gate.complete(in_flight, &result)?;
println!("{} files changed", completion.drift.changed.len());
```

## Policy

| Field | Default | Meaning |
|---|---|---|
| `allowed_roots` | `[]` | Roots this tool may touch. Empty means no filesystem access. |
| `denied_roots` | `[]` | Checked after resolution and overriding `allowed_roots`. |
| `allow_network` | `false` | Declared and recorded; see the honesty note above. |
| `timeout_secs` | `30` | Intended ceiling for one call. Declared and recorded; see the honesty note above. |
| `max_output_bytes` | `1000000` | Cap on the result. An unbounded result is both a cost problem and an injection surface. |
| `mutates` | `true` | Whether this tool may change local state. Defaults to the cautious answer. |
| `secrets` | `[]` | Names from the store this tool may receive. |

`mutates` defaults to `true` because the cost of being wrong is asymmetric: a
read marked mutating wastes a snapshot; a write marked read-only means no
rollback exists when it matters.

## Snapshots

Copy-based and bounded — 5,000 files and 64 MB by default. Exceeding either is
an **error**, not a partial capture, because a rollback from half a snapshot
would appear to succeed.

Restores content and presence: modified files are rewritten, deleted files
return, and files the call *created* are removed. Permissions, ownership,
symlink structure and empty directories are not restored. A symlink pointing
outside the workspace is never captured — copying it in and writing it back
would turn a rollback into an overwrite of something outside.

## Secrets

AES-256-GCM. Fresh random 96-bit nonce per encryption — GCM does not survive
nonce reuse. The secret's **name is authenticated as associated data**, so
swapping two ciphertexts in the store file fails closed rather than quietly
handing a tool the production token it was not meant to have.

The key comes from `GRIT_MASTER_KEY` and is never stored beside the data, which
is what makes the store file safe to keep next to the code it configures.
Cryptographic failures return one opaque error: distinguishing a bad key from a
bad tag for a caller is how oracles get built.

## Development

```bash
cargo test                                  # 49 tests
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

## Provenance and licence

Designed by [Rishi Tank](https://rishitank.co.uk) and built by directing AI coding agents.
Owned by Tankster AI Ltd — the AI-native product studio he founded, which runs it in its own estate.
Grit is one of the four components of the
[Robustness Layer](https://rishitank.co.uk/robustness-layer), an agent-containment stack in
which each component answers one question the others do not trust it to have answered: this
one answers *what can the agent actually touch?* The full case study is at
[rishitank.co.uk/projects/grit](https://rishitank.co.uk/projects/grit).

Released under the [MIT License](LICENSE).
