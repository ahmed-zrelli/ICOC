"""
Attacker HTTP Server — listens on :5000
Receives attack commands from the ICOC API and runs them.
This allows the dashboard Attack Console to trigger real attacks.
"""

import threading
import json
import subprocess
import sys
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

ATTACKS = {
    "1": "ssh_brute_force",
    "2": "port_scan",
    "3": "cve_exploit",
    "4": "sqli",
    "5": "lfi",
    "6": "reverse_shell",
    "7": "file_drop",
    "8": "dos",
    "all": "full_chain",
}

_running = {}

class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # suppress default logging

    def do_POST(self):
        if self.path == "/run":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length) or b"{}")
            attack_id = str(body.get("attack_id", ""))

            if attack_id not in ATTACKS:
                self._respond(400, {"error": f"Unknown attack_id: {attack_id}"})
                return

            if _running.get(attack_id):
                self._respond(409, {"error": "Attack already running"})
                return

            # Run in background thread
            def run():
                _running[attack_id] = True
                try:
                    args = [sys.executable, "/attacker/attacks.py", "--attack", attack_id]
                    if attack_id == "all":
                        args = [sys.executable, "/attacker/attacks.py", "--all"]
                    subprocess.run(args, timeout=120, cwd="/attacker")
                except Exception as e:
                    print(f"[ATTACKER-SERVER] Attack {attack_id} error: {e}")
                finally:
                    _running[attack_id] = False

            threading.Thread(target=run, daemon=True).start()
            self._respond(200, {"status": "launched", "attack_id": attack_id, "name": ATTACKS[attack_id]})

        elif self.path == "/status":
            self._respond(200, {"running": {k: v for k, v in _running.items() if v}})
        else:
            self._respond(404, {"error": "not found"})

    def do_GET(self):
        if self.path == "/health":
            self._respond(200, {"status": "ok"})
        else:
            self._respond(404, {"error": "not found"})

    def _respond(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 5000), Handler)
    print("[ATTACKER-SERVER] Listening on :5000")
    server.serve_forever()