#!/usr/bin/env python3
"""Unit tests for the GGS engine.

Run:
    python3 src/python/test_ggs.py
Exit code is 0 only if every test passes.
"""

from __future__ import annotations

import tempfile

from ggs_engine import (
    GENESIS_HASH,
    GGSError,
    Sandbox,
    SandboxViolation,
    run_ggs,
    verify_ledger,
)

_FAILURES: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        print(f"  [PASS] {name}")
    else:
        print(f"  [FAIL] {name}  {detail}")
        _FAILURES.append(name)


def test_sandbox_jail() -> None:
    with tempfile.TemporaryDirectory() as root:
        box = Sandbox(root)
        inside = box.resolve("sub/file.txt")
        check("sandbox resolves inside path", str(inside).startswith(str(box.root)))
        escaped = False
        try:
            box.resolve("../../etc/passwd")
        except SandboxViolation:
            escaped = True
        check("sandbox blocks path escape", escaped)


def test_command_allowlist() -> None:
    with tempfile.TemporaryDirectory() as root:
        box = Sandbox(root)
        ok = box.run(["echo", "hi"])
        check("allowed command runs", ok["exit_code"] == 0 and "hi" in ok["stdout"])
        blocked = False
        try:
            box.run(["rm", "-rf", "/"])
        except SandboxViolation:
            blocked = True
        check("disallowed command blocked", blocked)


def test_single_node_verified() -> None:
    graph = {"nodes": [
        {"id": "n", "action": {"type": "write_file", "path": "a", "content": "x"},
         "verifier": {"type": "file_equals", "path": "a", "content": "x"}},
    ]}
    result = run_ggs(graph)
    check("single node verifies", result["status"] == "verified")
    check("verified_count counted", result["verified_count"] == 1)


def test_rollback_runs_on_failure() -> None:
    graph = {"nodes": [
        {"id": "n", "action": {"type": "write_file", "path": "a", "content": "x"},
         "verifier": {"type": "file_contains", "path": "a", "text": "MISSING"},
         "rollback": [{"type": "delete_file", "path": "a"}]},
    ]}
    result = run_ggs(graph)
    check("failed verifier yields failed status", result["status"] == "failed")
    check("node marked rolled_back",
          result["nodes"]["n"]["status"] == "rolled_back")
    rb = result["nodes"]["n"]["rollback_result"]
    check("rollback action recorded", rb is not None and rb[0]["ok"] is True)


def test_dependency_skip() -> None:
    graph = {"nodes": [
        {"id": "p", "action": {"type": "write_file", "path": "p", "content": "x"},
         "verifier": {"type": "file_contains", "path": "p", "text": "NOPE"}},
        {"id": "c", "deps": ["p"],
         "action": {"type": "write_file", "path": "c", "content": "y"}},
    ]}
    result = run_ggs(graph)
    check("dependent node skipped", result["nodes"]["c"]["status"] == "skipped")
    check("skip records blocker",
          result["nodes"]["c"]["blocked_by"] == ["p"])


def test_cycle_detection() -> None:
    graph = {"nodes": [
        {"id": "a", "deps": ["b"], "action": {"type": "noop"}},
        {"id": "b", "deps": ["a"], "action": {"type": "noop"}},
    ]}
    raised = False
    try:
        run_ggs(graph)
    except GGSError:
        raised = True
    check("cycle is rejected", raised)


def test_unknown_dependency() -> None:
    graph = {"nodes": [
        {"id": "a", "deps": ["ghost"], "action": {"type": "noop"}},
    ]}
    raised = False
    try:
        run_ggs(graph)
    except GGSError:
        raised = True
    check("unknown dependency is rejected", raised)


def test_provenance_chain() -> None:
    graph = {"nodes": [
        {"id": "n1", "action": {"type": "write_file", "path": "1", "content": "1"}},
        {"id": "n2", "deps": ["n1"],
         "action": {"type": "write_file", "path": "2", "content": "2"}},
    ]}
    result = run_ggs(graph)
    ledger = result["ledger"]
    check("ledger has one entry per node", len(ledger) == 2)
    check("ledger starts at genesis", ledger[0]["prev_hash"] == GENESIS_HASH)
    check("links are chained",
          ledger[1]["prev_hash"] == ledger[0]["entry_hash"])
    check("engine reports ledger valid", result["ledger_valid"] is True)
    check("independent verification passes", verify_ledger(ledger) is True)


def test_provenance_tamper_detected() -> None:
    graph = {"nodes": [
        {"id": "n1", "action": {"type": "write_file", "path": "1", "content": "1"}},
        {"id": "n2", "deps": ["n1"],
         "action": {"type": "write_file", "path": "2", "content": "2"}},
    ]}
    ledger = run_ggs(graph)["ledger"]
    ledger[0]["record"]["status"] = "tampered"
    check("tampered ledger fails verification", verify_ledger(ledger) is False)


def test_sandbox_escape_via_action() -> None:
    graph = {"nodes": [
        {"id": "n", "action": {"type": "write_file", "path": "../../evil",
                               "content": "x"}},
    ]}
    result = run_ggs(graph)
    check("escaping action fails the graph", result["status"] == "failed")


def test_delete_file_action() -> None:
    graph = {"nodes": [
        {"id": "make", "action": {"type": "write_file", "path": "x", "content": "x"}},
        {"id": "drop", "deps": ["make"],
         "action": {"type": "delete_file", "path": "x"},
         "verifier": {"type": "file_absent", "path": "x"}},
    ]}
    result = run_ggs(graph)
    check("delete_file removes the file", result["status"] == "verified")


def test_unknown_action_type() -> None:
    result = run_ggs({"nodes": [{"id": "n", "action": {"type": "teleport"}}]})
    check("unknown action type fails the node", result["status"] == "failed")


def test_unknown_verifier_type() -> None:
    graph = {"nodes": [
        {"id": "n", "action": {"type": "noop"}, "verifier": {"type": "telepathy"}},
    ]}
    result = run_ggs(graph)
    check("unknown verifier type fails the node", result["status"] == "failed")


def test_missing_node_id() -> None:
    raised = False
    try:
        run_ggs({"nodes": [{"action": {"type": "noop"}}]})
    except GGSError:
        raised = True
    check("node with no id is rejected", raised)


def test_run_arg_jail() -> None:
    with tempfile.TemporaryDirectory() as root:
        box = Sandbox(root)
        blocked = False
        try:
            box.run(["cat", "/etc/passwd"])
        except SandboxViolation:
            blocked = True
        check("run arg with absolute path blocked", blocked)
        ok = box.run(["echo", "safe-token"])
        check("run arg bare token allowed", ok["exit_code"] == 0)


def test_diamond_dag_order() -> None:
    graph = {"nodes": [
        {"id": "a", "action": {"type": "write_file", "path": "a", "content": "A"}},
        {"id": "b", "deps": ["a"],
         "action": {"type": "append_file", "path": "a", "content": "B"}},
        {"id": "c", "deps": ["a"],
         "action": {"type": "write_file", "path": "c", "content": "C"}},
        {"id": "d", "deps": ["b", "c"], "action": {"type": "noop"},
         "verifier": [{"type": "file_contains", "path": "a", "text": "AB"},
                      {"type": "file_exists", "path": "c"}]},
    ]}
    result = run_ggs(graph)
    check("diamond DAG fully verifies", result["status"] == "verified")


def main() -> int:
    print("GGS engine unit tests")
    print("=" * 60)
    for test in [
        test_sandbox_jail,
        test_command_allowlist,
        test_single_node_verified,
        test_rollback_runs_on_failure,
        test_dependency_skip,
        test_cycle_detection,
        test_unknown_dependency,
        test_provenance_chain,
        test_provenance_tamper_detected,
        test_sandbox_escape_via_action,
        test_delete_file_action,
        test_unknown_action_type,
        test_unknown_verifier_type,
        test_missing_node_id,
        test_run_arg_jail,
        test_diamond_dag_order,
    ]:
        test()
    print("=" * 60)
    if _FAILURES:
        print(f"{len(_FAILURES)} test(s) failed: {', '.join(_FAILURES)}")
        return 1
    print("All tests passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
