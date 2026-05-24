# GrokForge Prime — Aether Edition

A local-first execution engine for LLM-emitted action plans. An LLM
("Grok") emits a **GGS graph** — a DAG of nodes, each carrying an
*action*, a *verifier*, and a *rollback*. GrokForge runs that graph in a
sandbox, verifies every step, rolls back on failure, and records a
hash-chained provenance ledger you can independently re-verify.

## What actually works today

- **GGS engine** (`src/python/ggs_engine.py`) — real, runnable, no stubs.
  DAG scheduling with cycle detection, sandboxed actions, structured
  verifiers, automatic rollback, and a SHA-256 provenance chain.
- **Sandbox** — a path-jailed working directory plus a command allowlist.
  Actions cannot write outside the jail; only vetted commands can run.
  This is process-level isolation, not kernel-level (see Roadmap).
- **Benchmark** (`benchmarks/osworld_subset.py`) — a synthetic suite of
  OSWorld-*style* file/CLI tasks. Every printed number is measured by
  running the real engine. It is **not** the official OSWorld dataset.
- **Tauri command** (`src/main.rs`) — `execute_ggs` shells out to the
  Python engine and returns its JSON result.

## Quick start

Run the engine on a graph:

```bash
echo '{"nodes":[{"id":"n1",
  "action":{"type":"write_file","path":"hi.txt","content":"hello"},
  "verifier":{"type":"file_contains","path":"hi.txt","text":"hello"}}]}' \
  | python3 src/python/ggs_engine.py
```

Run the tests and benchmark:

```bash
python3 src/python/test_ggs.py        # engine unit tests
python3 benchmarks/osworld_subset.py  # capability benchmark
```

The Tauri desktop shell (`cargo tauri dev`) loads `dist/index.html` —
a minimal vanilla-JS page that submits a sample GGS graph to the engine
via the `execute_ggs` Tauri command and renders the JSON result. It
requires the Rust + Tauri 2 toolchain plus the usual Linux desktop libs
(`webkit2gtk-4.1`, `libsoup-3.0`, ...). The Python engine above is the
runnable, tested core and needs only Python 3.

## Roadmap

- Kernel-level isolation (Landlock / seccomp) instead of the current
  allowlist-based sandbox.
- WASM execution for untrusted action handlers.
- Frontend for the Tauri shell.
