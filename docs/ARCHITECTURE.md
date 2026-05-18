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
   File actions cannot escape the jail; `run` actions are limited to a
   command allowlist with a timeout and a minimal environment.
3. **Act + verify** — execute the action, then run the verifier.
4. **Rollback** — if the verifier fails (or the action errors), the
   node's rollback actions run, and the node is marked `rolled_back`.
   Nodes that depend on a non-verified node are `skipped`.
5. **Provenance** — each node appends an entry to a hash chain:
   `entry_hash = SHA256(prev_hash || canonical(record))`, seeded from a
   fixed genesis hash. `verify_ledger()` recomputes the chain, so any
   tampering with a record breaks every downstream link.

### Trust boundary

The sandbox is process-level: a resolved-path jail plus a command
allowlist. It stops accidental and casual escapes, not a determined
adversary with allowlisted-command tricks. Kernel-level isolation
(Landlock / seccomp / WASM) is on the roadmap.
