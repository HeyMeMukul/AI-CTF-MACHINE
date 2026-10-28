import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from engine import config, knowledge
from engine.adapters.ctfd import parse_attempt, parse_challenge_list
from engine.core import Budget, LocalFlagOracle, SubmitLedger, Task, Trace, sha256_text
from engine.envs import LocalEnv
from engine.providers import MockProvider, parse_text_tool_call
from engine.scheduler import Store
from engine.solver import Solver
from engine.tools import Toolbox


class OracleTests(unittest.TestCase):
    def test_accepts_and_rejects(self):
        oracle = LocalFlagOracle(sha256_text("saltFLAG{unit_test}"), "salt")
        self.assertTrue(oracle.check("FLAG{unit_test}").accepted)
        self.assertFalse(oracle.check("FLAG{wrong}").accepted)
        self.assertEqual(oracle.check("").status, "rejected")


class ConfigTests(unittest.TestCase):
    def test_env_expansion(self):
        os.environ["CTF_TEST_BASE"] = "http://127.0.0.1:9/v1"
        cfg = config.load(None, {"provider": {"base_url": "${CTF_TEST_BASE}"}})
        self.assertEqual(cfg["provider"]["base_url"], "http://127.0.0.1:9/v1")

    def test_defaults_are_offline_safe(self):
        cfg = config.load(None)
        self.assertEqual(cfg["sandbox"]["kind"], "local")
        self.assertEqual(cfg["scheduler"]["workers"], 8)


class SchedulerTests(unittest.TestCase):
    def test_leases_highest_ev_and_records_outcome(self):
        with tempfile.TemporaryDirectory() as td:
            store = Store(Path(td) / "state.sqlite3")
            store.enqueue(Task(id="low", category="misc", difficulty="easy", points=10))
            store.enqueue(Task(id="high", category="misc", difficulty="easy", points=500))
            leased = store.lease(lease_seconds=60, max_attempts=3)
            self.assertIsNotNone(leased)
            self.assertEqual(leased.id, "high")
            store.complete("high", "solved", seconds=1.5, tokens=100)
            stats = store.stats()
            self.assertEqual(stats["solved"], 1)
            second = store.lease(lease_seconds=60, max_attempts=3)
            self.assertEqual(second.id, "low")
            store.close()

    def test_expired_lease_is_requeued(self):
        with tempfile.TemporaryDirectory() as td:
            store = Store(Path(td) / "state.sqlite3")
            store.enqueue(Task(id="t1", category="pwn", difficulty="hard", points=100))
            leased = store.lease(lease_seconds=0, max_attempts=3)
            self.assertEqual(leased.id, "t1")
            import time
            time.sleep(0.01)
            self.assertEqual(store.requeue_expired(max_attempts=3), 1)
            row = store.get("t1")
            self.assertEqual(row["state"], "queued")
            store.close()


class KnowledgeTests(unittest.TestCase):
    def test_retrieval_filters_unverified(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "good.json").write_text(json.dumps({
                "id": "good", "domain": "misc", "title": "base64 decode",
                "signals": ["base64"], "steps": ["base64 -d", "file"],
                "sources": ["x"], "verified_by": "test", "last_verified": "2026-10-20",
                "fixtures": ["base64"], "verified": True,
            }), encoding="utf-8")
            (root / "bad.json").write_text(json.dumps({
                "id": "bad", "domain": "misc", "title": "base64 guess",
                "signals": ["base64"], "steps": ["guess", "pray"],
                "sources": ["x"], "verified_by": "test", "last_verified": "2026-10-20",
                "verified": False,
            }), encoding="utf-8")
            hits = knowledge.retrieve("base64 decode", root, top_k=5)
            self.assertEqual([h["id"] for h in hits], ["good"])
            hits_all = knowledge.retrieve("base64 decode", root, top_k=5, include_unverified=True)
            self.assertEqual(len(hits_all), 2)


class SolverTests(unittest.TestCase):
    def test_mock_solver_reads_and_submits(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "work"
            (root / "given").mkdir(parents=True)
            (root / "given" / "flag.txt").write_text("FLAG{unit_test}\n", encoding="utf-8")
            task = Task(id="t1", title="unit", category="misc", points=100,
                        description="read the flag file", files=["given/flag.txt"])
            env = LocalEnv(root)
            oracle = LocalFlagOracle(sha256_text("saltFLAG{unit_test}"), "salt")
            script = [
                {"tool_calls": [{"name": "bash", "arguments": {"cmd": "cat given/flag.txt"}}]},
                {"tool_calls": [{"name": "submit_flag", "arguments": {"flag": "FLAG{unit_test}"}}]},
            ]
            cfg = config.load(None, {"knowledge": {"top_k": 0}, "sandbox": {"kind": "local"}})
            result = Solver(MockProvider(script), cfg).run(task, env, oracle, Path(td) / "run")
            self.assertEqual(result.status, "solved")
            self.assertEqual(result.candidate, "FLAG{unit_test}")
            self.assertEqual(result.steps, 2)
            trace = (Path(td) / "run" / "trace.jsonl").read_text(encoding="utf-8")
            self.assertIn('"status": "accepted"', trace)
            self.assertNotIn("FLAG{unit_test}", trace, "the flag must not be written to the trace")

    def test_text_tool_call_fallback(self):
        call = parse_text_tool_call('```json\n{"tool":"bash","arguments":{"cmd":"id"}}\n```')
        self.assertIsNotNone(call)
        self.assertEqual(call.name, "bash")
        self.assertEqual(call.arguments["cmd"], "id")

    def test_shared_ledger_allows_a_second_attempt(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "work"
            (root / "given").mkdir(parents=True)
            (root / "given" / "flag.txt").write_text("FLAG{retry}\n", encoding="utf-8")
            task = Task(id="retry", title="retry", category="misc", points=100,
                        description="read the flag", files=["given/flag.txt"])
            env = LocalEnv(root)
            oracle = LocalFlagOracle(sha256_text("sFLAG{retry}"), "s")
            ledger = SubmitLedger(max_submits=5)
            cfg = config.load(None, {"knowledge": {"top_k": 0}})
            blocked = MockProvider([{"tool_calls": [{"name": "finish",
                                                     "arguments": {"status": "blocked", "summary": "no idea"}}]}])
            first = Solver(blocked, cfg).run(task, env, oracle, Path(td) / "a1",
                                             attempt=1, attempts=2, ledger=ledger)
            self.assertEqual(first.status, "blocked")
            solve = MockProvider([
                {"tool_calls": [{"name": "bash", "arguments": {"cmd": "cat given/flag.txt"}}]},
                {"tool_calls": [{"name": "submit_flag", "arguments": {"flag": "FLAG{retry}"}}]},
            ])
            second = Solver(solve, cfg).run(task, env, oracle, Path(td) / "a2",
                                            attempt=2, attempts=2, prior=["attempt 1 blocked"],
                                            ledger=ledger)
            self.assertEqual(second.status, "solved")
            self.assertEqual(ledger.submits, 1)


class ToolTests(unittest.TestCase):
    def test_output_cap_and_artifact(self):
        with tempfile.TemporaryDirectory() as td:
            env = LocalEnv(Path(td))
            trace = Trace(Path(td) / "trace.jsonl", task_id="t")
            tb = Toolbox(env, LocalFlagOracle(sha256_text("x")), trace,
                         Budget(max_steps=5), Path(td) / ".engine" / "artifacts")
            outcome = tb.call("bash", {"cmd": "python3 -c \"print('A'*50000)\""})
            self.assertTrue(outcome.ok)
            self.assertLessEqual(len(outcome.data["stdout"]), 12000)
            artifact = Path(td) / outcome.data["artifact"]
            self.assertTrue(artifact.is_file())
            self.assertGreater(artifact.stat().st_size, 50000)

    def test_catalog_search_tool(self):
        with tempfile.TemporaryDirectory() as td:
            env = LocalEnv(Path(td))
            trace = Trace(Path(td) / "trace.jsonl", task_id="t")
            tb = Toolbox(env, LocalFlagOracle(sha256_text("x")), trace,
                         Budget(max_steps=5), Path(td) / ".engine" / "artifacts",
                         catalog_root=Path(__file__).resolve().parents[1])
            outcome = tb.call("catalog_search", {"query": "volatility memory forensics", "top_k": 3})
            self.assertTrue(outcome.ok)
            results = outcome.data["results"]
            self.assertTrue(results)
            self.assertIn("volatility", " ".join(str(r.get("name")) for r in results).lower())


class CTFdParserTests(unittest.TestCase):
    def test_attempt_statuses(self):
        self.assertTrue(parse_attempt({"data": {"status": "correct"}}).accepted)
        self.assertTrue(parse_attempt({"data": {"status": "already_solved"}}).accepted)
        self.assertFalse(parse_attempt({"data": {"status": "incorrect"}}).accepted)
        self.assertEqual(parse_attempt({"data": {"status": "?"}}).status, "unknown")

    def test_challenge_list_shapes(self):
        self.assertEqual(len(parse_challenge_list({"data": [{"id": 1}, {"id": 2}]})), 2)
        self.assertEqual(len(parse_challenge_list({"data": {"challenges": [{"id": 3}]}})), 1)
        self.assertEqual(parse_challenge_list({"data": "nope"}), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
