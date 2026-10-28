import json
import os
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from engine import config
from engine.adapters.ctfd import CTFdAdapter
from engine.daemon import Daemon
from engine.scheduler import Store

FLAG = "FLAG{daemon_integration}"


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
            self._json({"data": [{"id": 1, "name": "Daemon", "category": "misc",
                                  "value": 100, "solved_by_me": False}]})
        elif self.path == "/api/v1/challenges/1":
            self._json({"data": {"id": 1, "name": "Daemon", "category": "misc", "value": 100,
                                 "description": "The answer is in data.txt",
                                 "files": ["/files/1/data.txt"], "connection_info": None}})
        elif self.path == "/files/1/data.txt":
            body = (FLAG + "\n").encode()
            self.send_response(200)
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


class LLMHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        return

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        self.server.calls += 1
        if self.server.calls == 1:
            call = {"id": "c1", "type": "function",
                    "function": {"name": "bash", "arguments": json.dumps({"cmd": "cat given/data.txt"})}}
        else:
            call = {"id": "c2", "type": "function",
                    "function": {"name": "submit_flag", "arguments": json.dumps({"flag": FLAG})}}
        payload = {"choices": [{"message": {"content": "", "tool_calls": [call]}}],
                   "usage": {"prompt_tokens": 80, "completion_tokens": 20}}
        body = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class DaemonIntegrationTests(unittest.TestCase):
    def start(self, handler):
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        self.addCleanup(server.server_close)
        return server, server.server_address[1]

    def test_platform_to_flag(self):
        ctf, ctf_port = self.start(CTFdHandler)
        llm, llm_port = self.start(LLMHandler)
        llm.calls = 0
        os.environ["LLM_API_KEY"] = "test-key"
        with tempfile.TemporaryDirectory() as td:
            cfg = config.load(None, {
                "event_slug": "itest",
                "paths": {"events": str(Path(td) / "events"), "runs": str(Path(td) / "runs")},
                "provider": {"kind": "openai", "base_url": f"http://127.0.0.1:{llm_port}/v1",
                             "api_key_env": "LLM_API_KEY", "model": "mock-model"},
                "sandbox": {"kind": "local"},
                "scheduler": {"workers": 1, "poll_seconds": 1, "max_attempts": 2},
                "platform": {"kind": "ctfd", "url": f"http://127.0.0.1:{ctf_port}", "pace_seconds": 0},
            })
            event_dir = config.event_root(cfg)
            store = Store(event_dir / "state.sqlite3")
            adapter = CTFdAdapter(f"http://127.0.0.1:{ctf_port}", "token", pace_seconds=0)
            try:
                Daemon(cfg, adapter, store, provider_kind="openai").run(once=True)
                self.assertEqual(store.stats()["solved"], 1)
                flag_file = event_dir / "flags" / "ctfd-1.txt"
                self.assertTrue(flag_file.is_file())
                self.assertEqual(flag_file.read_text(encoding="utf-8").strip(), FLAG)
                self.assertEqual(flag_file.stat().st_mode & 0o777, 0o600)
                row = store.get("ctfd-1")
                self.assertEqual(row["state"], "solved")
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
