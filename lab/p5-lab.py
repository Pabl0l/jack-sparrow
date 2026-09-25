"""
P5 Vulnerable Lab — tests POST body injection, CSRF, file upload, and auth.

Endpoints:
  POST /search          — SQL injection via POST body (SQLite)
  POST /comment         — XSS reflected via POST body
  POST /render          — SSTI (Jinja2)
  POST /transfer        — CSRF (no token validation)
  POST /upload          — File upload (no validation)
  POST /login           — Form login (vulnerable: no rate limit, no lockout)
  GET  /admin           — Protected page (requires auth cookie)
  GET  /dashboard       — Auth-only page (checks session cookie)
  GET  /                — Index with all forms
"""
import os
import sqlite3
import tempfile
from flask import Flask, request, render_template_string, redirect, url_for, jsonify, session, make_response

app = Flask(__name__)
app.secret_key = os.urandom(32)
DB_PATH = os.path.join(tempfile.gettempdir(), "p5lab.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT,
        email TEXT,
        password TEXT,
        balance REAL DEFAULT 1000.0
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY,
        author TEXT,
        body TEXT
    )""")
    # Seed data
    try:
        c.execute("INSERT INTO users (username, email, password, balance) VALUES (?, ?, ?, ?)",
                  ("admin", "admin@lab.local", "admin123", 99999.0))
        c.execute("INSERT INTO users (username, email, password, balance) VALUES (?, ?, ?, ?)",
                  ("user1", "user1@lab.local", "pass1", 500.0))
        c.execute("INSERT INTO comments (author, body) VALUES (?, ?)",
                  ("admin", "Welcome to the lab!"))
    except sqlite3.IntegrityError:
        pass
    conn.commit()
    conn.close()

@app.before_request
def ensure_db():
    if not os.path.exists(DB_PATH):
        init_db()

@app.route("/")
def index():
    return render_template_string("""
    <h1>P5 Vulnerable Lab</h1>
    <h2>1. SQL Injection (POST)</h2>
    <form action="/search" method="POST">
        <input type="text" name="username" placeholder="Search username">
        <button type="submit">Search</button>
    </form>
    <h2>2. XSS Reflected (POST)</h2>
    <form action="/comment" method="POST">
        <input type="text" name="author" placeholder="Your name">
        <input type="text" name="body" placeholder="Comment">
        <button type="submit">Post Comment</button>
    </form>
    <h2>3. SSTI (POST)</h2>
    <form action="/render" method="POST">
        <input type="text" name="template" placeholder="Template string">
        <button type="submit">Render</button>
    </form>
    <h2>4. CSRF (POST — no token)</h2>
    <form action="/transfer" method="POST">
        <input type="text" name="to" placeholder="Recipient">
        <input type="number" name="amount" placeholder="Amount">
        <button type="submit">Transfer Money</button>
    </form>
    <h2>5. File Upload (no validation)</h2>
    <form action="/upload" method="POST" enctype="multipart/form-data">
        <input type="file" name="file">
        <button type="submit">Upload</button>
    </form>
    <h2>6. Login (form-based auth)</h2>
    <form action="/login" method="POST">
        <input type="hidden" name="csrf_token" value="fake_csrf_123">
        <input type="text" name="username" placeholder="Username">
        <input type="password" name="password" placeholder="Password">
        <button type="submit">Login</button>
    </form>
    <p><a href="/dashboard">Dashboard (requires login)</a></p>
    """)

# ─── SQL Injection (POST body) ───────────────────────────────────

@app.route("/search", methods=["POST"])
def search():
    username = request.form.get("username", "")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        # VULNERABLE: string concatenation
        query = "SELECT * FROM users WHERE username = '" + username + "'"
        c.execute(query)
        rows = c.fetchall()
        if rows:
            results = "<br>".join([f"ID: {r[0]}, User: {r[1]}, Email: {r[2]}, Balance: ${r[4]}" for r in rows])
            return f"<h2>Search Results</h2><p>{results}</p><a href='/'>Back</a>"
        else:
            return "<p>No results found.</p><a href='/'>Back</a>"
    except Exception as e:
        # VULNERABLE: error message leaks SQL details
        return f"<p>Error: {str(e)}</p><a href='/'>Back</a>"
    finally:
        conn.close()

# ─── XSS Reflected (POST body) ──────────────────────────────────

@app.route("/comment", methods=["POST"])
def comment():
    author = request.form.get("author", "")
    body = request.form.get("body", "")
    # VULNERABLE: no encoding
    return render_template_string(f"""
        <h2>Comment Posted!</h2>
        <p><strong>{author}</strong> says:</p>
        <p>{body}</p>
        <a href='/'>Back</a>
    """)

# ─── SSTI (Jinja2) ──────────────────────────────────────────────

@app.route("/render", methods=["POST"])
def render():
    template = request.form.get("template", "")
    # VULNERABLE: user input directly rendered as template
    try:
        result = render_template_string(template)
        return f"<h2>Rendered Output</h2><pre>{result}</pre><a href='/'>Back</a>"
    except Exception as e:
        return f"<p>Render error: {str(e)}</p><a href='/'>Back</a>"

# ─── CSRF (no token) ────────────────────────────────────────────

@app.route("/transfer", methods=["POST"])
def transfer():
    to_user = request.form.get("to", "")
    amount = request.form.get("amount", "0")
    # VULNERABLE: no CSRF token validation
    return jsonify({
        "success": True,
        "message": f"Transferred ${amount} to {to_user}",
        "note": "No CSRF token was checked!"
    })

@app.route("/admin")
def admin():
    return jsonify({
        "users": ["admin", "user1", "user2"],
        "secret_key": "super_secret_admin_key",
        "database": "p5lab.db"
    })

# ─── File Upload (no validation) ────────────────────────────────

UPLOAD_DIR = os.path.join(tempfile.gettempdir(), "p5lab_uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

@app.route("/upload", methods=["POST"])
def upload():
    if "file" not in request.files:
        return "<p>No file selected</p><a href='/'>Back</a>"
    
    f = request.files["file"]
    if f.filename == "":
        return "<p>No file selected</p><a href='/'>Back</a>"
    
    # VULNERABLE: saves with original filename, no validation
    save_path = os.path.join(UPLOAD_DIR, f.filename)
    f.save(save_path)
    
    return f"""
        <h2>File Uploaded!</h2>
        <p>Filename: {f.filename}</p>
        <p>Size: {os.path.getsize(save_path)} bytes</p>
        <p>Saved to: {save_path}</p>
        <a href='/'>Back</a>
    """

@app.route("/upload", methods=["GET"])
def upload_page():
    return "<p>Use POST to upload files</p>"

# ─── Form Login (vulnerable) ──────────────────────────────────────

# Hardcoded users for testing
USERS = {
    "admin": "admin123",
    "user1": "pass1",
    "test": "test",
}

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    if username in USERS and USERS[username] == password:
        # Set a session cookie (vulnerable: no secure flags, no httpOnly)
        resp = make_response(jsonify({
            "success": True,
            "message": f"Welcome {username}!",
            "role": "admin" if username == "admin" else "user",
        }))
        resp.set_cookie("session_id", f"sess_{username}_abc123", httponly=False, secure=False, samesite="None")
        resp.set_cookie("user_role", "admin" if username == "admin" else "user", httponly=False)
        return resp
    else:
        return jsonify({"success": False, "message": "Invalid credentials"}), 401

@app.route("/login", methods=["GET"])
def login_page():
    return render_template_string("""
    <h2>Login</h2>
    <form action="/login" method="POST">
        <input type="text" name="username" placeholder="Username">
        <input type="password" name="password" placeholder="Password">
        <button type="submit">Login</button>
    </form>
    <p>Credentials: admin/admin123, user1/pass1, test/test</p>
    """)

@app.route("/dashboard")
def dashboard():
    session_id = request.cookies.get("session_id", "")
    if not session_id or not session_id.startswith("sess_"):
        return jsonify({"error": "Unauthorized — login required"}), 401

    username = session_id.replace("sess_", "").split("_")[0]
    return jsonify({
        "message": f"Welcome to the dashboard, {username}!",
        "secret_data": "This is protected content",
        "admin_key": "super_secret_admin_key_12345",
        "database": "p5lab.db",
        "users": ["admin", "user1", "test"],
    })

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5555, debug=True)
