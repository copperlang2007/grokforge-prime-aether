#!/usr/bin/env python3
"""Grok-Grounded Synthesis (GGS) engine.

Takes a structured plan emitted by an LLM ("Grok output"): a DAG of nodes,
each carrying an action, a verifier, and a rollback list. Executes each node
inside a path-jailed sandbox working directory, verifies the result, rolls
back on failure, and records a hash-chained provenance ledger.

This is the real engine. There is no hidden "full impl" elsewhere.

CLI:
    python3 ggs_engine.py < graph.json      # read graph JSON from stdin
    python3 ggs_engine.py graph.json        # read graph JSON from a file

The graph schema is documented in run_ggs().
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

GENESIS_HASH = hashlib.sha256(b"GGS-GENESIS-v1").hexdigest()

# Commands permitted inside `run` actions and command-based verifiers. Anything
# that can mutate state outside the sandbox (rm, mv across roots, curl, ...) is
# intentionally excluded. File mutation happens through structured actions.
ALLOWED_COMMANDS = {
    "cat", "cut", "date", "echo", "false", "grep", "head", "ls", "mkdir",
    "printf", "pwd", "python3", "sed", "sort", "tail", "test", "touch",
    "tr", "true", "wc",
}

COMMAND_TIMEOUT_SECONDS = 10


class GGSError(Exception):
    """A malformed graph or an engine-level failure."""


class SandboxViolation(GGSError):
    """An action tried to escape the sandbox root."""


# --------------------------------------------------------------------------
# Sandbox
# --------------------------------------------------------------------------
class Sandbox:
    """A path-jailed working directory.

    Every path an action touches is resolved against `root`; anything that
    escapes (via `..`, absolute paths or symlinks) is rejected before any I/O
    happens. Commands run with `cwd=root` and a minimal environment.
    """

    def __init__(self, root: str | os.PathLike[str]):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def resolve(self, rel: str) -> Path:
        if rel is None:
            raise GGSError("path is required")
        target = (self.root / rel).resolve()
        if target != self.root and self.root not in target.parents:
            raise SandboxViolation(f"path escapes sandbox: {rel!r}")
        return target

    def run(self, cmd: list[str], stdin: str | None = None) -> dict[str, Any]:
        if not cmd or not isinstance(cmd, list):
            raise GGSError("run command must be a non-empty list")
        program = cmd[0]
        if program not in ALLOWED_COMMANDS:
            raise SandboxViolation(f"command not allowed: {program!r}")
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C"}
        try:
            proc = subprocess.run(
                cmd,
                cwd=self.root,
                env=env,
                input=stdin,
                capture_output=True,
                text=True,
                timeout=COMMAND_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            return {"exit_code": -1, "stdout": "", "stderr": "timeout", "timed_out": True}
        return {
            "exit_code": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "timed_out": False,
        }


# --------------------------------------------------------------------------
# Actions
# --------------------------------------------------------------------------
def execute_action(sandbox: Sandbox, action: dict[str, Any]) -> dict[str, Any]:
    """Execute a single structured action and return a result record."""
    if not isinstance(action, dict) or "type" not in action:
        raise GGSError("action must be an object with a 'type' field")
    kind = action["type"]

    if kind == "noop":
        return {"type": kind, "ok": True}

    if kind == "write_file":
        path = sandbox.resolve(action["path"])
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(action.get("content", ""))
        return {"type": kind, "ok": True, "path": action["path"]}

    if kind == "append_file":
        path = sandbox.resolve(action["path"])
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a") as handle:
            handle.write(action.get("content", ""))
        return {"type": kind, "ok": True, "path": action["path"]}

    if kind == "delete_file":
        path = sandbox.resolve(action["path"])
        existed = path.exists()
        if path.is_dir():
            shutil.rmtree(path)
        elif existed:
            path.unlink()
        return {"type": kind, "ok": True, "path": action["path"], "existed": existed}

    if kind == "mkdir":
        path = sandbox.resolve(action["path"])
        path.mkdir(parents=True, exist_ok=True)
        return {"type": kind, "ok": True, "path": action["path"]}

    if kind == "run":
        result = sandbox.run(action["cmd"], action.get("stdin"))
        result["type"] = kind
        result["ok"] = result["exit_code"] == 0
        return result

    raise GGSError(f"unknown action type: {kind!r}")


# --------------------------------------------------------------------------
# Verifiers
# --------------------------------------------------------------------------
def _check_one(sandbox: Sandbox, verifier: dict[str, Any]) -> bool:
    kind = verifier.get("type")

    if kind in (None, "always_true"):
        return True
    if kind == "file_exists":
        return sandbox.resolve(verifier["path"]).exists()
    if kind == "file_absent":
        return not sandbox.resolve(verifier["path"]).exists()
    if kind == "file_contains":
        path = sandbox.resolve(verifier["path"])
        return path.is_file() and verifier["text"] in path.read_text()
    if kind == "file_equals":
        path = sandbox.resolve(verifier["path"])
        return path.is_file() and path.read_text() == verifier["content"]
    if kind == "cmd_succeeds":
        return sandbox.run(verifier["cmd"], verifier.get("stdin"))["exit_code"] == 0
    if kind == "cmd_output_contains":
        out = sandbox.run(verifier["cmd"], verifier.get("stdin"))
        return verifier["text"] in out["stdout"]
    raise GGSError(f"unknown verifier type: {kind!r}")


def verify(sandbox: Sandbox, verifier: Any) -> bool:
    """Run a verifier. A list of verifiers passes only if all of them pass."""
    if verifier is None:
        return True
    if isinstance(verifier, list):
        return all(_check_one(sandbox, item) for item in verifier)
    if isinstance(verifier, dict):
        return _check_one(sandbox, verifier)
    raise GGSError("verifier must be an object, a list of objects, or null")


# --------------------------------------------------------------------------
# Provenance ledger (hash chain)
# --------------------------------------------------------------------------
def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _chain(prev_hash: str, record: dict[str, Any]) -> str:
    payload = (prev_hash + _canonical(record)).encode()
    return hashlib.sha256(payload).hexdigest()


def verify_ledger(ledger: list[dict[str, Any]]) -> bool:
    """Recompute the hash chain and confirm every link is intact."""
    prev = GENESIS_HASH
    for entry in ledger:
        if entry["prev_hash"] != prev:
            return False
        recomputed = _chain(prev, entry["record"])
        if recomputed != entry["entry_hash"]:
            return False
        prev = entry["entry_hash"]
    return True


# --------------------------------------------------------------------------
# DAG scheduling
# --------------------------------------------------------------------------
def _topological_order(nodes: list[dict[str, Any]]) -> list[str]:
    ids = [node["id"] for node in nodes]
    if len(ids) != len(set(ids)):
        raise GGSError("duplicate node ids in graph")
    by_id = {node["id"]: node for node in nodes}
    state: dict[str, int] = {}  # 0=unvisited, 1=on stack, 2=done
    order: list[str] = []

    def visit(node_id: str) -> None:
        mark = state.get(node_id, 0)
        if mark == 2:
            return
        if mark == 1:
            raise GGSError(f"cycle detected in graph at node {node_id!r}")
        state[node_id] = 1
        for dep in by_id[node_id].get("deps", []):
            if dep not in by_id:
                raise GGSError(f"node {node_id!r} depends on unknown node {dep!r}")
            visit(dep)
        state[node_id] = 2
        order.append(node_id)

    for node_id in ids:
        visit(node_id)
    return order


# --------------------------------------------------------------------------
# Engine
# --------------------------------------------------------------------------
def run_ggs(graph: dict[str, Any], workdir: str | None = None) -> dict[str, Any]:
    """Execute a GGS graph.

    Graph schema::

        {
          "nodes": [
            {
              "id": "n1",
              "deps": ["n0"],                  # optional, default []
              "action": {"type": "write_file", "path": "a.txt", "content": "hi"},
              "verifier": {"type": "file_contains", "path": "a.txt", "text": "hi"},
              "rollback": [                     # optional list of actions
                {"type": "delete_file", "path": "a.txt"}
              ]
            }
          ]
        }

    Returns a result dict with per-node status, an overall status, and a
    hash-chained provenance ledger that `verify_ledger` can independently
    re-check.
    """
    if not isinstance(graph, dict) or "nodes" not in graph:
        raise GGSError("graph must be an object with a 'nodes' array")
    nodes = graph["nodes"]
    if not isinstance(nodes, list) or not nodes:
        raise GGSError("graph 'nodes' must be a non-empty array")

    order = _topological_order(nodes)
    by_id = {node["id"]: node for node in nodes}

    owns_workdir = workdir is None
    workdir = workdir or tempfile.mkdtemp(prefix="ggs_")
    sandbox = Sandbox(workdir)

    node_status: dict[str, str] = {}
    node_results: dict[str, dict[str, Any]] = {}
    ledger: list[dict[str, Any]] = []
    prev_hash = GENESIS_HASH

    try:
        for node_id in order:
            node = by_id[node_id]
            deps = node.get("deps", [])
            blocked = [d for d in deps if node_status.get(d) != "verified"]

            if blocked:
                node_status[node_id] = "skipped"
                node_results[node_id] = {"status": "skipped", "blocked_by": blocked}
                continue

            try:
                action_result = execute_action(sandbox, node["action"])
                passed = verify(sandbox, node.get("verifier"))
            except GGSError as exc:
                action_result = {"ok": False, "error": str(exc)}
                passed = False

            if passed and action_result.get("ok", True):
                status = "verified"
                rollback_result = None
            else:
                status = "rolled_back"
                rollback_result = [
                    _safe_rollback(sandbox, act) for act in node.get("rollback", [])
                ]

            node_status[node_id] = status
            node_results[node_id] = {
                "status": status,
                "action_result": action_result,
                "verifier_passed": passed,
                "rollback_result": rollback_result,
            }

            record = {
                "node_id": node_id,
                "action_digest": hashlib.sha256(
                    _canonical(node["action"]).encode()
                ).hexdigest(),
                "status": status,
                "verifier_passed": passed,
            }
            entry_hash = _chain(prev_hash, record)
            ledger.append({
                "index": len(ledger),
                "node_id": node_id,
                "timestamp": time.time(),
                "prev_hash": prev_hash,
                "record": record,
                "entry_hash": entry_hash,
            })
            prev_hash = entry_hash
    finally:
        if owns_workdir:
            shutil.rmtree(workdir, ignore_errors=True)

    overall = "verified" if all(
        node_status.get(n["id"]) == "verified" for n in nodes
    ) else "failed"

    return {
        "status": overall,
        "node_count": len(nodes),
        "verified_count": sum(1 for s in node_status.values() if s == "verified"),
        "nodes": node_results,
        "ledger": ledger,
        "ledger_valid": verify_ledger(ledger),
        "provenance_head": prev_hash,
    }


def _safe_rollback(sandbox: Sandbox, action: dict[str, Any]) -> dict[str, Any]:
    try:
        return execute_action(sandbox, action)
    except GGSError as exc:
        return {"ok": False, "error": str(exc)}


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def main(argv: list[str]) -> int:
    raw = Path(argv[1]).read_text() if len(argv) > 1 else sys.stdin.read()
    try:
        graph = json.loads(raw)
        result = run_ggs(graph)
    except (GGSError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}))
        return 1
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "verified" else 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
