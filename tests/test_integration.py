import json
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from engine import config
from engine.adapters.ctfd import CTFdAdapter
from engine.core import LocalFlagOracle, Task, sha256_text
from engine.envs import LocalEnv
from engine.providers import OpenAIProvider
from engine.scheduler import Store
from engine.solver import Solver

FLAG = "FLAG{integration_test}"


class CTFdHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        return

    def _json(self, payload, code=200):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/api/v1/challenges":
            self._json({"data": [{"id": 1, "name": "Integration", "category": "misc",
                                  "value": 100, "solved_by_me": False}]})
        elif self.path == "/api/v1/challenges/1":
            self._json({"data": {"id": 1, "name": "Integration", "category": "misc",
                                 "value": 100, "description": "the answer is in the file",
                                 "files": ["/files/1/data.txt"], "connection_info": None}})
        elif self.path == "/files/1/data.txt":
            body = (FLAG + "\n").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        payload = json.loads(self.rfile.read(length) or b"{}")
        if self.path == "/api/v1/challenges/attempt":
            if payload.get("submission") == FLAG:
                self._json({"data": {"status": "correct", "message": "Correct"}})
            else:
                self._json({"data": {"status": "incorrect", "message": "Incorrect"}})
        else:
            self._json({"error": "not found"}, 404)


class OpenAIHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        return

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        # The solver sends one assistant turn per tool call; alternate.
        self.server.calls += 1
        if self.server.calls == 1:
            call = {"id": "c1", "type": "function",
                    "function": {"name": "bash", "arguments": json.dumps({"cmd": "cat given/flag.txt"})}}
        elif self.server.calls == 2:
            call = {"id": "c2", "type": "function",
                    "function": {"name": "submit_flag", "arguments": json.dumps({"flag": FLAG})}}
        else:
            call = {"id": "c3", "type": "function",
                    "function": {"name": "finish", "arguments": json.dumps({"status": "blocked",
                                                                             "summary": "no more script"})}}
        payload = {
            "choices": [{"message": {"content": "", "tool_calls": [call]}}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 20},
        }
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class ServerMixin:
    def start_server(self, handler):
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        self.addCleanup(server.server_close)
        return server, server.server_address[1]


class CTFdIntegrationTests(ServerMixin, unittest.TestCase):
    def test_sync_download_and_submit(self):
        server, port = self.start_server(CTFdHandler)
        with tempfile.TemporaryDirectory() as td:
            store = Store(Path(td) / "state.sqlite3")
            adapter = CTFdAdapter(f"http://127.0.0.1:{port}", "test-token", pace_seconds=0)
            event = Path(td) / "event"
            self.assertEqual(adapter.sync(store, event), 1)
            row = store.get("ctfd-1")
            self.assertIsNotNone(row)
            task = Task.from_dict(json.loads(row["payload"]))
            self.assertEqual(task.category, "misc")
            self.assertTrue((event / "challenges" / "ctfd-1" / "given" / "data.txt").is_file())
            oracle = adapter.oracle_for(task)
            self.assertTrue(oracle.check(FLAG).accepted)
            self.assertFalse(oracle.check("FLAG{wrong}").accepted)
            store.complete("ctfd-1", "solved")
            self.assertEqual(store.stats()["solved"], 1)
            store.close()


class OpenAIProviderTests(ServerMixin, unittest.TestCase):
    def test_http_tool_calls_drive_the_solver(self):
        server, port = self.start_server(OpenAIHandler)
        server.calls = 0
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "work"
            (root / "given").mkdir(parents=True)
            (root / "given" / "flag.txt").write_text(FLAG + "\n", encoding="utf-8")
            task = Task(id="http", title="http", category="misc", points=100,
                        description="read the file", files=["given/flag.txt"])
            env = LocalEnv(root)
            oracle = LocalFlagOracle(sha256_text("s" + FLAG), "s")
            provider = OpenAIProvider(f"http://127.0.0.1:{port}/v1", "key", "mock-model",
                                      timeout_s=10, max_retries=0)
            cfg = config.load(None, {"knowledge": {"top_k": 0}})
            result = Solver(provider, cfg).run(task, env, oracle, Path(td) / "run")
            self.assertEqual(result.status, "solved")
            self.assertEqual(result.candidate, FLAG)
            self.assertEqual(result.steps, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
