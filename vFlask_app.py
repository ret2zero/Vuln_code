"""
INTENTIONALLY VULNERABLE FLASK APP - FOR LOCAL SECURE CODING PRACTICE ONLY.

Do NOT deploy this anywhere. It binds to 127.0.0.1 only and uses a local
SQLite file. Your job: find and fix every flaw, then check ANSWER_KEY.md.

Setup:
    pip install flask
    python vFlask_app.py
    Browse to http://127.0.0.1:5000

Seed accounts (created on first run): admin / admin123, alice / password1, bob / letmein
"""
import base64
import hashlib
import logging
import os
import pickle
import random
import sqlite3
import subprocess
import time
import traceback
import urllib.request

from flask import (Flask, make_response, redirect, render_template_string,
                   request, send_file, session)

app = Flask(__name__)
app.secret_key = "supersecret123"
ADMIN_API_KEY = "sk-live-9f8e7d6c5b4a3210"
DB_PATH = "vuln.db"
UPLOAD_DIR = "uploads"
RESET_TOKENS = {}

logging.basicConfig(level=logging.DEBUG, filename="app.log")
os.makedirs(UPLOAD_DIR, exist_ok=True)


# ---------------------------------------------------------------- database
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT,
            role TEXT DEFAULT 'user',
            balance REAL DEFAULT 100
        );
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER,
            title TEXT,
            body TEXT
        );
    """)
    if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        seed = [("admin", "admin123", "admin@example.local", "admin"),
                ("alice", "password1", "alice@example.local", "user"),
                ("bob", "letmein", "bob@example.local", "user")]
        for u, p, e, r in seed:
            db.execute("INSERT INTO users (username,password,email,role) VALUES (?,?,?,?)",
                       (u, hashlib.md5(p.encode()).hexdigest(), e, r))
        db.execute("INSERT INTO notes (owner_id,title,body) VALUES (1,'Admin secret','The vault code is 4821')")
        db.execute("INSERT INTO notes (owner_id,title,body) VALUES (2,'Alice private','Alice diary entry')")
        db.execute("INSERT INTO notes (owner_id,title,body) VALUES (3,'Bob private','Bob grocery list')")
    db.commit()
    db.close()


# ---------------------------------------------------------------- home
@app.route("/")
def index():
    return """
    <h1>VulnApp</h1>
    <ul>
      <li><a href="/register">Register</a></li>
      <li><a href="/login">Login</a></li>
      <li><a href="/logout">Logout</a></li>
      <li><a href="/notes">My notes</a></li>
      <li><a href="/search?q=test">Search</a></li>
      <li><a href="/greet?name=World">Greet</a></li>
      <li><a href="/ping?host=127.0.0.1">Ping</a></li>
      <li><a href="/download?file=hello.txt">Download</a></li>
      <li><a href="/upload">Upload</a></li>
      <li><a href="/admin/users">Admin: users</a></li>
    </ul>
    """


# ---------------------------------------------------------------- auth
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return """<form method=post>
            user <input name=username> pass <input name=password type=password>
            email <input name=email> <button>Register</button></form>"""
    username = request.form["username"]
    password = request.form["password"]
    email = request.form.get("email", "")
    role = request.form.get("role", "user")
    hashed = hashlib.md5(password.encode()).hexdigest()
    db = get_db()
    db.execute("INSERT INTO users (username,password,email,role) VALUES (?,?,?,?)",
               (username, hashed, email, role))
    db.commit()
    logging.info("New registration: %s / %s", username, password)
    return redirect("/login")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return """<form method=post>
            user <input name=username> pass <input name=password type=password>
            <button>Login</button></form>"""
    username = request.form["username"]
    password = request.form["password"]
    logging.debug("Login attempt: user=%s password=%s", username, password)
    hashed = hashlib.md5(password.encode()).hexdigest()
    db = get_db()

    exists = db.execute(f"SELECT * FROM users WHERE username = '{username}'").fetchone()
    if not exists:
        return "No such user", 404

    user = db.execute(
        f"SELECT * FROM users WHERE username = '{username}' AND password = '{hashed}'"
    ).fetchone()
    if not user:
        return "Wrong password", 401

    session["user_id"] = user["id"]
    session["username"] = user["username"]
    resp = make_response(redirect("/notes"))
    resp.set_cookie("role", user["role"])
    return resp


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/reset", methods=["GET", "POST"])
def reset():
    if request.method == "GET":
        return "<form method=post>username <input name=username><button>Reset</button></form>"
    username = request.form["username"]
    token = str(random.randint(1000, 9999))
    RESET_TOKENS[username] = (token, time.time())
    return f"Reset token for {username}: {token}"


@app.route("/reset/confirm", methods=["POST"])
def reset_confirm():
    username = request.form["username"]
    token = request.form["token"]
    new_pw = request.form["new_password"]
    saved = RESET_TOKENS.get(username)
    if saved and saved[0] == token:
        db = get_db()
        db.execute("UPDATE users SET password=? WHERE username=?",
                   (hashlib.md5(new_pw.encode()).hexdigest(), username))
        db.commit()
        return "Password changed"
    return "Bad token", 400


# ---------------------------------------------------------------- notes
@app.route("/notes")
def notes():
    if "user_id" not in session:
        return redirect("/login")
    db = get_db()
    rows = db.execute("SELECT * FROM notes WHERE owner_id = ?", (session["user_id"],)).fetchall()
    html = "<h1>Your notes</h1>"
    for r in rows:
        html += f'<p><a href="/notes/{r["id"]}">{r["title"]}</a></p>'
    html += """<form method=post action=/notes/new>
        title <input name=title> body <input name=body>
        <button>Add</button></form>"""
    return html


@app.route("/notes/<note_id>")
def view_note(note_id):
    if "user_id" not in session:
        return redirect("/login")
    db = get_db()
    note = db.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    if not note:
        return "Not found", 404
    return render_template_string(
        "<h1>{{ t|safe }}</h1><div>{{ b|safe }}</div>", t=note["title"], b=note["body"])


@app.route("/notes/new", methods=["POST"])
def new_note():
    if "user_id" not in session:
        return redirect("/login")
    db = get_db()
    db.execute("INSERT INTO notes (owner_id,title,body) VALUES (?,?,?)",
               (session["user_id"], request.form["title"], request.form["body"]))
    db.commit()
    return redirect("/notes")


@app.route("/search")
def search():
    q = request.args.get("q", "")
    db = get_db()
    rows = db.execute(
        f"SELECT id, title FROM notes WHERE title LIKE '%{q}%'").fetchall()
    html = f"<h2>Results for {q}</h2>"
    for r in rows:
        html += f"<p>{r['id']}: {r['title']}</p>"
    return html


# ---------------------------------------------------------------- admin
@app.route("/admin/users")
def admin_users():
    db = get_db()
    rows = db.execute("SELECT id, username, password, email, role FROM users").fetchall()
    return "<br>".join(str(dict(r)) for r in rows)


@app.route("/admin/promote/<int:uid>")
def promote(uid):
    if request.cookies.get("role") != "admin":
        return "Forbidden", 403
    db = get_db()
    db.execute("UPDATE users SET role='admin' WHERE id=?", (uid,))
    db.commit()
    return f"User {uid} promoted"


@app.route("/debug/config")
def debug_config():
    return {
        "config": {k: str(v) for k, v in app.config.items()},
        "env": dict(os.environ),
        "api_key": ADMIN_API_KEY,
    }


# ---------------------------------------------------------------- money
@app.route("/transfer", methods=["POST"])
def transfer():
    if "user_id" not in session:
        return redirect("/login")
    from_id = request.form["from_id"]
    to_id = request.form["to_id"]
    amount = float(request.form["amount"])
    db = get_db()
    db.execute("UPDATE users SET balance = balance - ? WHERE id = ?", (amount, from_id))
    db.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, to_id))
    db.commit()
    return f"Moved {amount} from {from_id} to {to_id}"


# ---------------------------------------------------------------- misc features
@app.route("/greet")
def greet():
    name = request.args.get("name", "friend")
    return render_template_string(f"<h1>Hello {name}!</h1>")


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    flag = "-n" if os.name == "nt" else "-c"
    out = subprocess.run(f"ping {flag} 1 {host}", shell=True,
                         capture_output=True, text=True)
    return f"<pre>{out.stdout}{out.stderr}</pre>"


@app.route("/download")
def download():
    filename = request.args.get("file", "")
    return send_file(os.path.join(UPLOAD_DIR, filename))


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method == "GET":
        return """<form method=post enctype=multipart/form-data>
            <input type=file name=f><button>Upload</button></form>"""
    f = request.files["f"]
    f.save(os.path.join(UPLOAD_DIR, f.filename))
    return f"Saved {f.filename}"


@app.route("/import", methods=["POST"])
def import_data():
    blob = request.form["data"]
    obj = pickle.loads(base64.b64decode(blob))
    return f"Imported: {obj}"


@app.route("/fetch")
def fetch():
    url = request.args["url"]
    with urllib.request.urlopen(url) as r:
        return r.read()


@app.route("/redirect")
def open_redirect():
    return redirect(request.args.get("next", "/"))


# ---------------------------------------------------------------- errors
@app.errorhandler(Exception)
def handle_error(e):
    return f"<pre>{traceback.format_exc()}</pre>", 500


if __name__ == "__main__":
    init_db()
    with open(os.path.join(UPLOAD_DIR, "hello.txt"), "w") as fh:
        fh.write("hello from the uploads folder\n")
    app.run(host="127.0.0.1", port=5000, debug=True)
