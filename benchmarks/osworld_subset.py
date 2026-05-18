#!/usr/bin/env python3
"""GGS capability benchmark.

This is NOT the official OSWorld dataset. It is a synthetic suite of
file/CLI tasks modelled on the *style* of OSWorld tasks, used to measure
whether the GGS engine actually executes, verifies and rolls back plans.

Every number this script prints is measured here, now, by running the real
engine in `src/python/ggs_engine.py`. There are no hardcoded results.

Run:
    python3 benchmarks/osworld_subset.py
Exit code is 0 only if every task passes.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src" / "python"))

from ggs_engine import run_ggs, verify_ledger  # noqa: E402


# Each task: a GGS graph plus an `oracle` describing the end-state that must
# hold in the sandbox afterwards. The engine runs the graph; the oracle is
# checked independently of the engine's own verifiers.
TASKS: list[dict] = [
    {
        "name": "create_file",
        "graph": {"nodes": [
            {"id": "w", "action": {"type": "write_file", "path": "notes.txt",
                                   "content": "hello world"},
             "verifier": {"type": "file_contains", "path": "notes.txt", "text": "hello"}},
        ]},
        "oracle": [("file_equals", "notes.txt", "hello world")],
    },
    {
        "name": "multi_step_pipeline",
        "graph": {"nodes": [
            {"id": "a", "action": {"type": "write_file", "path": "in.txt",
                                   "content": "c\na\nb\n"}},
            {"id": "b", "deps": ["a"],
             "action": {"type": "run", "cmd": ["sort", "in.txt"]},
             "verifier": {"type": "cmd_output_contains",
                          "cmd": ["sort", "in.txt"], "text": "a\nb\nc"}},
        ]},
        "oracle": [("file_exists", "in.txt")],
    },
    {
        "name": "directory_tree",
        "graph": {"nodes": [
            {"id": "d", "action": {"type": "mkdir", "path": "proj/src"},
             "verifier": {"type": "cmd_succeeds", "cmd": ["test", "-d", "proj/src"]}},
            {"id": "f", "deps": ["d"],
             "action": {"type": "write_file", "path": "proj/src/app.py",
                        "content": "print('ok')\n"},
             "verifier": {"type": "file_exists", "path": "proj/src/app.py"}},
        ]},
        "oracle": [("file_exists", "proj/src/app.py")],
    },
    {
        "name": "append_then_count",
        "graph": {"nodes": [
            {"id": "a", "action": {"type": "write_file", "path": "log",
                                   "content": "line1\n"}},
            {"id": "b", "deps": ["a"],
             "action": {"type": "append_file", "path": "log", "content": "line2\n"}},
            {"id": "c", "deps": ["b"],
             "action": {"type": "noop"},
             "verifier": {"type": "cmd_output_contains",
                          "cmd": ["wc", "-l", "log"], "text": "2"}},
        ]},
        "oracle": [("file_contains", "log", "line2")],
    },
    {
        "name": "run_python_inline",
        "graph": {"nodes": [
            {"id": "p", "action": {"type": "run",
                                   "cmd": ["python3", "-c",
                                           "open('out.txt','w').write('42')"]},
             "verifier": {"type": "file_equals", "path": "out.txt", "content": "42"}},
        ]},
        "oracle": [("file_equals", "out.txt", "42")],
    },
    {
        "name": "rollback_on_bad_verifier",
        # The action writes the file, but the verifier demands content that is
        # not there. The engine must roll back, leaving no file behind.
        "graph": {"nodes": [
            {"id": "bad",
             "action": {"type": "write_file", "path": "temp.txt", "content": "wrong"},
             "verifier": {"type": "file_contains", "path": "temp.txt", "text": "right"},
             "rollback": [{"type": "delete_file", "path": "temp.txt"}]},
        ]},
        "oracle": [("file_absent", "temp.txt")],
        "expect_status": "failed",
    },
    {
        "name": "dependency_skip_on_failure",
        # `child` depends on `parent`, which fails verification. `child` must
        # be skipped and never create its file.
        "graph": {"nodes": [
            {"id": "parent",
             "action": {"type": "write_file", "path": "p.txt", "content": "x"},
             "verifier": {"type": "file_contains", "path": "p.txt", "text": "ZZZ"},
             "rollback": [{"type": "delete_file", "path": "p.txt"}]},
            {"id": "child", "deps": ["parent"],
             "action": {"type": "write_file", "path": "c.txt", "content": "y"}},
        ]},
        "oracle": [("file_absent", "c.txt"), ("file_absent", "p.txt")],
        "expect_status": "failed",
    },
    {
        "name": "sandbox_escape_blocked",
        # An action tries to write outside the sandbox. The engine must refuse
        # the action and roll back, touching nothing outside the jail.
        "graph": {"nodes": [
            {"id": "escape",
             "action": {"type": "write_file", "path": "../../escaped.txt",
                        "content": "pwned"},
             "rollback": []},
        ]},
        "oracle": [("file_absent", "escaped.txt")],
        "expect_status": "failed",
    },
    {
        "name": "diamond_dag",
        # a -> {b, c} -> d. All four must run and verify in dependency order.
        "graph": {"nodes": [
            {"id": "a", "action": {"type": "write_file", "path": "a", "content": "A"}},
            {"id": "b", "deps": ["a"],
             "action": {"type": "append_file", "path": "a", "content": "B"}},
            {"id": "c", "deps": ["a"],
             "action": {"type": "write_file", "path": "c", "content": "C"}},
            {"id": "d", "deps": ["b", "c"],
             "action": {"type": "noop"},
             "verifier": [{"type": "file_exists", "path": "a"},
                          {"type": "file_exists", "path": "c"}]},
        ]},
        "oracle": [("file_contains", "a", "A"), ("file_exists", "c")],
    },
    {
        "name": "provenance_chain_intact",
        "graph": {"nodes": [
            {"id": "n1", "action": {"type": "write_file", "path": "1", "content": "1"}},
            {"id": "n2", "deps": ["n1"],
             "action": {"type": "write_file", "path": "2", "content": "2"}},
            {"id": "n3", "deps": ["n2"],
             "action": {"type": "write_file", "path": "3", "content": "3"}},
        ]},
        "oracle": [("file_exists", "3")],
    },
]


def _check_oracle(workdir: Path, conditions: list[tuple]) -> bool:
    for cond in conditions:
        kind = cond[0]
        path = workdir / cond[1]
        if kind == "file_exists" and not path.is_file():
            return False
        if kind == "file_absent" and path.exists():
            return False
        if kind == "file_contains" and not (
            path.is_file() and cond[2] in path.read_text()
        ):
            return False
        if kind == "file_equals" and not (
            path.is_file() and path.read_text() == cond[2]
        ):
            return False
    return True


def run_task(task: dict) -> tuple[bool, str]:
    """Run one task on a fresh sandbox. Returns (passed, detail)."""
    workdir = Path(tempfile.mkdtemp(prefix="ggs_bench_"))
    try:
        result = run_ggs(task["graph"], workdir=str(workdir))
        expected_status = task.get("expect_status", "verified")
        if result["status"] != expected_status:
            return False, f"status {result['status']!r}, expected {expected_status!r}"
        if not result["ledger_valid"] or not verify_ledger(result["ledger"]):
            return False, "provenance ledger failed verification"
        if not _check_oracle(workdir, task["oracle"]):
            return False, "end-state oracle not satisfied"
        return True, "ok"
    except Exception as exc:  # noqa: BLE001 - report any engine crash as a fail
        return False, f"engine raised {type(exc).__name__}: {exc}"
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def main() -> int:
    print("GGS capability benchmark — synthetic OSWorld-style suite")
    print("=" * 60)
    passed = 0
    for task in TASKS:
        ok, detail = run_task(task)
        passed += ok
        mark = "PASS" if ok else "FAIL"
        line = f"  [{mark}] {task['name']}"
        if not ok:
            line += f"  -- {detail}"
        print(line)

    total = len(TASKS)
    rate = 100.0 * passed / total
    print("=" * 60)
    print(f"Result: {passed}/{total} tasks passed ({rate:.1f}%)")
    print("Note: this measures the GGS engine on a synthetic suite, not the")
    print("official OSWorld benchmark. Numbers are computed by this run.")
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
