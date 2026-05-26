# Architecture

## Grok-Grounded Synthesis (GGS)

GGS turns an LLM-emitted plan into a verified, reversible execution.

### Graph

A GGS graph is a DAG of nodes:

```json
{
  "nodes": [
    {
      "id": "n1",
      "deps": ["n0"],
      "action":   { "type": "write_file", "path": "a.txt", "content": "hi" },
      "verifier": { "type": "file_contains", "path": "a.txt", "text": "hi" },
      "rollback": [ { "type": "delete_file", "path": "a.txt" } ]
    }
  ]
}
```

- **action** — one structured mutation: `write_file`, `append_file`,
  `delete_file`, `mkdir`, `run`, or `noop`.
- **verifier** — a predicate (or list of predicates, all must hold)
  checked after the action: `file_exists`, `file_absent`,
  `file_contains`, `file_equals`, `cmd_succeeds`, `cmd_output_contains`.
- **rollback** — a list of actions run if the verifier fails.

### Execution pipeline

1. **Schedule** — topological sort of the DAG; cycles and dangling
   dependencies are rejected before anything runs.
2. **Sandbox** — every node runs in a path-jailed working directory.
   File actions cannot escape the jail. `run` actions are limited to a
   command allowlist that excludes interpreters like `python3` (whose
   arguments are arbitrary code no allowlist can vet); path-like command
   arguments are jail-checked too, so an allowlisted command cannot read
   or write outside the root. Commands run with a timeout and a minimal
   environment.
3. **Act + verify** — execute the action, then run the verifier.
4. **Rollback** — if the verifier fails (or the action errors), the
   node's rollback actions run, and the node is marked `rolled_back`.
   Nodes that depend on a non-verified node are `skipped`.
5. **Provenance** — each node appends an entry to a hash chain:
   `entry_hash = SHA256(prev_hash || canonical(record))`, seeded from a
   fixed genesis hash. `verify_ledger()` recomputes the chain, so any
   tampering with a record breaks every downstream link.

### Trust boundary

Three layers, enforced independently:

1. **User-space sandbox in the engine** — a resolved-path jail, a
   command allowlist (no interpreters), and path-like argument
   checking. Catches malformed graphs and accidental escapes before
   anything touches the kernel.
2. **Landlock filesystem ruleset, applied by the Rust shell** on
   Linux. The shell creates a per-call workdir, hands it to the
   engine via `GGS_WORKDIR`, and restricts the child to read-only
   on the system roots the interpreter needs (`/usr`, `/bin`,
   `/lib`, `/etc`, `/proc`, `/dev`) and read-write only on the
   workdir. Even if the user-space sandbox had a bug, writes
   outside the workdir would be denied by the kernel. No-op on
   kernels older than 5.13.
3. **seccomp BPF filter**, also applied in `pre_exec` after
   Landlock. Denies syscalls a sandboxed engine should never make:
   `socket(AF_INET/AF_INET6, ...)` (no IP networking — AF_UNIX is
   intentionally still allowed for the interpreter's own pipes),
   `ptrace`, `mount`, `umount2`, `pivot_root`. Default is allow,
   so Python's normal syscalls keep working; only the listed ones
   return `EPERM`.

WASM execution for untrusted action handlers is still on the roadmap.
