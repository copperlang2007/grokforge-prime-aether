#!/usr/bin/env python3
"""Unit tests for the GGS engine.

Built on the stdlib ``unittest`` framework: each test is isolated, a
failing assertion aborts only its own test, and the suite is discoverable
by standard tooling.

Run:
    python3 src/python/test_ggs.py        # direct
    python3 -m unittest discover src/python
"""

from __future__ import annotations

import tempfile
import unittest
from unittest import mock

from ggs_engine import (
    GENESIS_HASH,
    GGSError,
    Sandbox,
    SandboxViolation,
    execute_action,
    run_ggs,
    verify,
    verify_ledger,
)


class SandboxTestCase(unittest.TestCase):
    """Base case providing a fresh, isolated sandbox per test.

    The temp directory is registered with ``addCleanup`` so it is removed
    even if a later part of ``setUp`` fails.
    """

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix="ggs_test_")
        self.addCleanup(tmp.cleanup)
        self.box = Sandbox(tmp.name)


class TestSandbox(SandboxTestCase):
    def test_resolves_path_inside_root(self) -> None:
        resolved = self.box.resolve("sub/file.txt")
        self.assertTrue(str(resolved).startswith(str(self.box.root)))

    def test_blocks_path_escape(self) -> None:
        with self.assertRaises(SandboxViolation):
            self.box.resolve("../../etc/passwd")

    def test_allowed_command_runs(self) -> None:
        result = self.box.run(["echo", "hello"])
        self.assertEqual(result["exit_code"], 0)
        self.assertIn("hello", result["stdout"])

    def test_disallowed_command_blocked(self) -> None:
        with self.assertRaises(SandboxViolation):
            self.box.run(["rm", "-rf", "/"])

    def test_interpreter_not_in_allowlist(self) -> None:
        with self.assertRaises(SandboxViolation):
            self.box.run(["python3", "-c", "print(1)"])

    def test_run_arg_absolute_path_blocked(self) -> None:
        with self.assertRaises(SandboxViolation):
            self.box.run(["cat", "/etc/passwd"])

    def test_run_arg_relative_escape_blocked(self) -> None:
        with self.assertRaises(SandboxViolation):
            self.box.run(["touch", "../escaped"])

    def test_run_arg_bare_token_allowed(self) -> None:
        self.assertEqual(self.box.run(["echo", "plain-token"])["exit_code"], 0)

    def test_run_returns_failure_dict_on_oserror(self) -> None:
        # If the OS cannot start the process, run() must return a result
        # dict so the node fails cleanly, rather than raising.
        with mock.patch("ggs_engine.subprocess.run",
                        side_effect=OSError("exec failed")) as mocked_run:
            result = self.box.run(["echo", "ok"])
        # Confirm run() really invoked subprocess.run with our command, so a
        # refactor that drops the call cannot pass silently. The command is
        # checked positionally; kwargs are left unasserted to avoid coupling
        # the test to every subprocess option.
        mocked_run.assert_called_once()
        self.assertEqual(mocked_run.call_args.args[0], ["echo", "ok"])
        self.assertEqual(result["exit_code"], -1)
        self.assertIn("failed to run", result["stderr"])
        self.assertFalse(result["timed_out"])


class TestActions(SandboxTestCase):
    def test_write_file(self) -> None:
        execute_action(self.box, {"type": "write_file", "path": "a.txt",
                                  "content": "data"})
        self.assertEqual((self.box.root / "a.txt").read_text(), "data")

    def test_append_file(self) -> None:
        execute_action(self.box, {"type": "write_file", "path": "log",
                                  "content": "one\n"})
        execute_action(self.box, {"type": "append_file", "path": "log",
                                  "content": "two\n"})
        self.assertEqual((self.box.root / "log").read_text(), "one\ntwo\n")

    def test_delete_file(self) -> None:
        execute_action(self.box, {"type": "write_file", "path": "x",
                                  "content": "x"})
        result = execute_action(self.box, {"type": "delete_file", "path": "x"})
        self.assertTrue(result["existed"])
        self.assertFalse((self.box.root / "x").exists())

    def test_delete_missing_file_is_noop(self) -> None:
        result = execute_action(self.box, {"type": "delete_file",
                                           "path": "ghost"})
        self.assertFalse(result["existed"])
        self.assertTrue(result["ok"])

    def test_mkdir(self) -> None:
        execute_action(self.box, {"type": "mkdir", "path": "nested/dir"})
        self.assertTrue((self.box.root / "nested" / "dir").is_dir())

    def test_run(self) -> None:
        result = execute_action(self.box, {"type": "run",
                                           "cmd": ["echo", "hi"]})
        self.assertTrue(result["ok"])

    def test_noop(self) -> None:
        self.assertTrue(execute_action(self.box, {"type": "noop"})["ok"])

    def test_unknown_action_type(self) -> None:
        with self.assertRaises(GGSError):
            execute_action(self.box, {"type": "teleport"})

    def test_action_without_type(self) -> None:
        with self.assertRaises(GGSError):
            execute_action(self.box, {"path": "a.txt"})

    def test_write_file_escape_rejected(self) -> None:
        with self.assertRaises(SandboxViolation):
            execute_action(self.box, {"type": "write_file",
                                      "path": "../evil", "content": "x"})


class TestVerifiers(SandboxTestCase):
    def setUp(self) -> None:
        super().setUp()
        (self.box.root / "present.txt").write_text("hello world")

    def test_none_verifier_passes(self) -> None:
        self.assertTrue(verify(self.box, None))

    def test_file_exists(self) -> None:
        self.assertTrue(verify(self.box, {"type": "file_exists",
                                          "path": "present.txt"}))
        self.assertFalse(verify(self.box, {"type": "file_exists",
                                           "path": "missing.txt"}))

    def test_file_absent(self) -> None:
        self.assertTrue(verify(self.box, {"type": "file_absent",
                                          "path": "missing.txt"}))
        self.assertFalse(verify(self.box, {"type": "file_absent",
                                           "path": "present.txt"}))

    def test_file_contains(self) -> None:
        self.assertTrue(verify(self.box, {"type": "file_contains",
                                          "path": "present.txt",
                                          "text": "hello"}))
        self.assertFalse(verify(self.box, {"type": "file_contains",
                                           "path": "present.txt",
                                           "text": "absent"}))

    def test_file_equals(self) -> None:
        self.assertTrue(verify(self.box, {"type": "file_equals",
                                          "path": "present.txt",
                                          "content": "hello world"}))

    def test_cmd_succeeds(self) -> None:
        self.assertTrue(verify(self.box, {"type": "cmd_succeeds",
                                          "cmd": ["test", "-f",
                                                  "present.txt"]}))
        self.assertFalse(verify(self.box, {"type": "cmd_succeeds",
                                           "cmd": ["test", "-f",
                                                   "missing.txt"]}))

    def test_cmd_output_contains(self) -> None:
        self.assertTrue(verify(self.box, {"type": "cmd_output_contains",
                                          "cmd": ["cat", "present.txt"],
                                          "text": "world"}))

    def test_verifier_list_requires_all(self) -> None:
        self.assertTrue(verify(self.box, [
            {"type": "file_exists", "path": "present.txt"},
            {"type": "file_contains", "path": "present.txt", "text": "hello"},
        ]))
        self.assertFalse(verify(self.box, [
            {"type": "file_exists", "path": "present.txt"},
            {"type": "file_exists", "path": "missing.txt"},
        ]))

    def test_unknown_verifier_type(self) -> None:
        with self.assertRaises(GGSError):
            verify(self.box, {"type": "telepathy"})


class TestEngine(unittest.TestCase):
    def test_single_node_verified(self) -> None:
        result = run_ggs({"nodes": [
            {"id": "n", "action": {"type": "write_file", "path": "a",
                                   "content": "x"},
             "verifier": {"type": "file_equals", "path": "a", "content": "x"}},
        ]})
        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["verified_count"], 1)

    def test_rollback_on_failure(self) -> None:
        result = run_ggs({"nodes": [
            {"id": "n", "action": {"type": "write_file", "path": "a",
                                   "content": "x"},
             "verifier": {"type": "file_contains", "path": "a",
                          "text": "MISSING"},
             "rollback": [{"type": "delete_file", "path": "a"}]},
        ]})
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["nodes"]["n"]["status"], "rolled_back")
        self.assertTrue(result["nodes"]["n"]["rollback_result"][0]["ok"])

    def test_dependency_skip(self) -> None:
        result = run_ggs({"nodes": [
            {"id": "p", "action": {"type": "write_file", "path": "p",
                                   "content": "x"},
             "verifier": {"type": "file_contains", "path": "p",
                          "text": "NOPE"}},
            {"id": "c", "deps": ["p"],
             "action": {"type": "write_file", "path": "c", "content": "y"}},
        ]})
        self.assertEqual(result["nodes"]["c"]["status"], "skipped")
        self.assertEqual(result["nodes"]["c"]["blocked_by"], ["p"])

    def test_cycle_detection(self) -> None:
        with self.assertRaises(GGSError):
            run_ggs({"nodes": [
                {"id": "a", "deps": ["b"], "action": {"type": "noop"}},
                {"id": "b", "deps": ["a"], "action": {"type": "noop"}},
            ]})

    def test_unknown_dependency(self) -> None:
        with self.assertRaises(GGSError):
            run_ggs({"nodes": [
                {"id": "a", "deps": ["ghost"], "action": {"type": "noop"}},
            ]})

    def test_missing_node_id(self) -> None:
        with self.assertRaises(GGSError):
            run_ggs({"nodes": [{"action": {"type": "noop"}}]})

    def test_node_without_action(self) -> None:
        with self.assertRaises(GGSError):
            run_ggs({"nodes": [{"id": "a"}]})

    def test_duplicate_node_ids(self) -> None:
        with self.assertRaises(GGSError):
            run_ggs({"nodes": [
                {"id": "a", "action": {"type": "noop"}},
                {"id": "a", "action": {"type": "noop"}},
            ]})

    def test_unknown_action_fails_node(self) -> None:
        result = run_ggs({"nodes": [{"id": "n",
                                     "action": {"type": "teleport"}}]})
        self.assertEqual(result["status"], "failed")

    def test_unknown_verifier_fails_node(self) -> None:
        result = run_ggs({"nodes": [
            {"id": "n", "action": {"type": "noop"},
             "verifier": {"type": "telepathy"}},
        ]})
        self.assertEqual(result["status"], "failed")

    def test_sandbox_escape_via_action_fails(self) -> None:
        result = run_ggs({"nodes": [
            {"id": "n", "action": {"type": "write_file",
                                   "path": "../../evil", "content": "x"}},
        ]})
        self.assertEqual(result["status"], "failed")

    def test_diamond_dag(self) -> None:
        result = run_ggs({"nodes": [
            {"id": "a", "action": {"type": "write_file", "path": "a",
                                   "content": "A"}},
            {"id": "b", "deps": ["a"],
             "action": {"type": "append_file", "path": "a", "content": "B"}},
            {"id": "c", "deps": ["a"],
             "action": {"type": "write_file", "path": "c", "content": "C"}},
            {"id": "d", "deps": ["b", "c"], "action": {"type": "noop"},
             "verifier": [{"type": "file_contains", "path": "a", "text": "AB"},
                          {"type": "file_exists", "path": "c"}]},
        ]})
        self.assertEqual(result["status"], "verified")


class TestProvenance(unittest.TestCase):
    def _two_node_result(self) -> dict:
        return run_ggs({"nodes": [
            {"id": "n1", "action": {"type": "write_file", "path": "1",
                                    "content": "1"}},
            {"id": "n2", "deps": ["n1"],
             "action": {"type": "write_file", "path": "2", "content": "2"}},
        ]})

    def test_one_entry_per_node(self) -> None:
        self.assertEqual(len(self._two_node_result()["ledger"]), 2)

    def test_chain_starts_at_genesis(self) -> None:
        self.assertEqual(self._two_node_result()["ledger"][0]["prev_hash"],
                         GENESIS_HASH)

    def test_links_are_chained(self) -> None:
        ledger = self._two_node_result()["ledger"]
        self.assertEqual(ledger[1]["prev_hash"], ledger[0]["entry_hash"])

    def test_engine_reports_ledger_valid(self) -> None:
        self.assertTrue(self._two_node_result()["ledger_valid"])

    def test_independent_verification_passes(self) -> None:
        self.assertTrue(verify_ledger(self._two_node_result()["ledger"]))

    def test_tampering_is_detected(self) -> None:
        ledger = self._two_node_result()["ledger"]
        ledger[0]["record"]["status"] = "tampered"
        self.assertFalse(verify_ledger(ledger))


if __name__ == "__main__":
    unittest.main()
