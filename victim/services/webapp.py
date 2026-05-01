"""
Intentionally Vulnerable Web App — runs on victim container port 8080.
Contains: SQLi, LFI, command injection, weak auth — FOR LAB USE ONLY.
"""
from flask import Flask, request, jsonify, make_response
import os, sqlite3, subprocess

app = Flask(__name__)

# ── Intentionally weak in-memory DB ─────────────────────────────────────────
def get_db():
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)")
    db.execute("INSERT INTO users VALUES (1,'admin','admin123','admin')")
    db.execute("INSERT INTO users VALUES (2,'user','password','user')")
    db.execute("INSERT INTO users VALUES (3,'victim','victim123','user')")
    db.commit()
    return db

# ── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return """<html><body style="background:#111;color:#0f0;font-family:monospace;padding:40px">
    <h1>&#9760; ICOC-Lite Victim Web App</h1>
    <p>Intentionally Vulnerable — Lab Use Only</p>
    <ul>
      <li><a href="/login" style="color:#0f0">POST /login</a> — SQLi vulnerable login</li>
      <li><a href="/download?file=readme.txt" style="color:#0f0">GET /download?file=</a> — LFI vulnerable</li>
      <li><a href="/ping?host=localhost" style="color:#0f0">GET /ping?host=</a> — Command injection</li>
      <li><a href="/info" style="color:#0f0">GET /info</a> — System information leak</li>
    </ul>
    </body></html>"""

@app.route("/login", methods=["GET", "POST"])
def login():
    """SQLi vulnerable login endpoint."""
    if request.method == "GET":
        return """<form method="POST"><input name="username" placeholder="username"><input name="password" type="password" placeholder="password"><button>Login</button></form>"""
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    # INTENTIONALLY VULNERABLE — no parameterization
    try:
        db = get_db()
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        rows = db.execute(query).fetchall()
        if rows:
            return jsonify({"status": "success", "user": rows[0][1], "role": rows[0][3],
                            "flag": "ICOC{sqli_bypass_success}", "query": query})
        return jsonify({"status": "failed", "query": query}), 401
    except Exception as e:
        return jsonify({"status": "error", "error": str(e), "query": query}), 500

@app.route("/download")
def download():
    """LFI vulnerable file download."""
    filename = request.args.get("file", "readme.txt")
    # INTENTIONALLY VULNERABLE — no path sanitization
    try:
        full_path = os.path.join("/", filename)
        with open(full_path, "r") as f:
            content = f.read()
        resp = make_response(content)
        resp.headers["Content-Type"] = "text/plain"
        return resp
    except PermissionError:
        return jsonify({"error": "permission_denied", "path": filename}), 403
    except FileNotFoundError:
        return jsonify({"error": "not_found", "path": filename}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/ping")
def ping():
    """Command injection vulnerable ping endpoint."""
    host = request.args.get("host", "localhost")
    # INTENTIONALLY VULNERABLE — shell injection
    try:
        result = subprocess.run(f"ping -c 1 {host}", shell=True,
                                capture_output=True, text=True, timeout=5)
        return jsonify({"host": host, "output": result.stdout, "stderr": result.stderr})
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route("/info")
def info():
    """Information disclosure endpoint."""
    return jsonify({
        "hostname": os.popen("hostname").read().strip(),
        "os": os.popen("uname -a").read().strip(),
        "users": os.popen("cat /etc/passwd | head -5").read().strip(),
        "network": os.popen("ip addr 2>/dev/null || ifconfig 2>/dev/null").read()[:200],
        "processes": os.popen("ps aux | head -10").read().strip(),
        "warning": "THIS IS AN INTENTIONALLY VULNERABLE LAB APP"
    })

@app.route("/health")
def health():
    return jsonify({"status": "vulnerable", "port": 8080})

if __name__ == "__main__":
    print("[WEBAPP] Vulnerable web app starting on 0.0.0.0:8080")
    app.run(host="0.0.0.0", port=8080, debug=False)
