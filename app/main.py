import os
import sqlite3
import hashlib
import datetime
import subprocess
from typing import Optional

import jwt
from fastapi import FastAPI, Form, Cookie, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, PlainTextResponse

DB_PATH = "/data/lab.db"
FILES_DIR = "/data/files"
JWT_SECRET = "supersecret"  # слабый секрет — намеренно

app = FastAPI(title="VulnLab", docs_url=None, redoc_url=None)


# ---------- DB ----------

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    os.makedirs("/data", exist_ok=True)
    os.makedirs(FILES_DIR, exist_ok=True)

    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    conn = db()
    c = conn.cursor()
    c.executescript("""
        CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT);
        CREATE TABLE comments(id INTEGER PRIMARY KEY, author TEXT, text TEXT);
        CREATE TABLE notes(id INTEGER PRIMARY KEY, user_id INTEGER, content TEXT);
        CREATE TABLE emails(user_id INTEGER PRIMARY KEY, email TEXT);
    """)

    users = [
        (1, "admin", hashlib.md5(b"admin123").hexdigest(), "admin"),
        (2, "alice", hashlib.md5(b"password1").hexdigest(), "user"),
        (3, "bob",   hashlib.md5(b"password2").hexdigest(), "user"),
    ]
    c.executemany("INSERT INTO users VALUES(?,?,?,?)", users)

    c.execute("INSERT INTO comments(author, text) VALUES(?,?)",
              ("admin", "Welcome to VulnLab."))
    c.execute("INSERT INTO notes(user_id, content) VALUES(?,?)",
              (1, "FLAG{idor_admin_note}"))
    c.execute("INSERT INTO notes(user_id, content) VALUES(?,?)",
              (2, "alice private diary"))
    c.executemany("INSERT INTO emails VALUES(?,?)",
                  [(1, "admin@lab.local"), (2, "alice@lab.local"), (3, "bob@lab.local")])
    conn.commit()
    conn.close()

    with open(os.path.join(FILES_DIR, "readme.txt"), "w") as f:
        f.write("public file, nothing to see here\n")
    with open("/data/secret.txt", "w") as f:
        f.write("FLAG{path_traversal_master}\n")


init_db()


# ---------- Auth (VULN: JWT без проверки подписи) ----------

def issue_token(username: str, role: str) -> str:
    payload = {
        "sub": username,
        "role": role,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=2),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def get_user(token: Optional[str]):
    """VULN: подпись не проверяется — токен можно подделать."""
    if not token:
        return None
    try:
        return jwt.decode(token, options={"verify_signature": False})
    except Exception:
        return None


# ---------- Home ----------

@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <h1>VulnLab</h1>
    <ul>
      <li><a href="/login">/login</a> — SQLi в логине</li>
      <li><a href="/search?q=a">/search?q=</a> — UNION SQLi + reflected XSS</li>
      <li><a href="/comments">/comments</a> — stored XSS</li>
      <li><a href="/profile/2">/profile/{id}</a> — IDOR</li>
      <li><a href="/files?name=readme.txt">/files?name=</a> — path traversal</li>
      <li><a href="/ping">/ping</a> — command injection</li>
      <li><a href="/settings">/settings</a> — CSRF</li>
      <li><a href="/admin">/admin</a> — JWT forgery</li>
      <li><a href="/me">/me</a> — текущий пользователь</li>
    </ul>
    <p>Reset: <code>curl -X POST http://127.0.0.1:8000/reset</code></p>
    """


# ---------- Login / SQLi ----------

LOGIN_FORM = """
<h1>Login</h1>
<form method="post" action="/login">
  <input name="username" placeholder="username" autocomplete="off">
  <input name="password" type="password" placeholder="password">
  <button>login</button>
</form>
"""


@app.get("/login", response_class=HTMLResponse)
def login_form():
    return LOGIN_FORM


@app.post("/login")
def login(username: str = Form(...), password: str = Form(...)):
    pw = hashlib.md5(password.encode()).hexdigest()
    # VULN: конкатенация строк → SQLi
    q = f"SELECT id, username, role FROM users WHERE username='{username}' AND password='{pw}'"
    conn = db()
    try:
        row = conn.execute(q).fetchone()
    except Exception as e:
        return PlainTextResponse(f"SQL error: {e}", status_code=500)
    finally:
        conn.close()

    if not row:
        return PlainTextResponse("invalid credentials", status_code=401)

    token = issue_token(row["username"], row["role"])
    resp = RedirectResponse("/me", status_code=303)
    resp.set_cookie("token", token, httponly=False, samesite="lax")
    return resp


@app.get("/me", response_class=HTMLResponse)
def me(token: Optional[str] = Cookie(default=None)):
    user = get_user(token)
    if not user:
        return RedirectResponse("/login", status_code=303)
    return f"<h1>me</h1><pre>{user}</pre><p><a href='/'>home</a></p>"


# ---------- Search / UNION SQLi ----------

@app.get("/search", response_class=HTMLResponse)
def search(q: str = ""):
    conn = db()
    try:
        rows = conn.execute(
            f"SELECT id, username, role FROM users WHERE username LIKE '%{q}%'"
        ).fetchall()
    except Exception as e:
        return PlainTextResponse(f"SQL error: {e}", status_code=500)
    finally:
        conn.close()

    body = "".join(f"<li>{dict(r)}</li>" for r in rows)
    # VULN: q отражается без экранирования → reflected XSS
    return f"""
    <h1>Search users</h1>
    <form><input name="q" value="{q}"><button>search</button></form>
    <ul>{body}</ul>
    """


# ---------- Comments / stored XSS ----------

@app.get("/comments", response_class=HTMLResponse)
def comments():
    conn = db()
    rows = conn.execute("SELECT * FROM comments ORDER BY id").fetchall()
    conn.close()
    # VULN: вывод без экранирования → stored XSS
    items = "".join(f"<li><b>{r['author']}</b>: {r['text']}</li>" for r in rows)
    return f"""
    <h1>Comments</h1>
    <ul>{items}</ul>
    <form method="post" action="/comments">
      <input name="author" placeholder="name">
      <input name="text" placeholder="comment">
      <button>post</button>
    </form>
    """


@app.post("/comments")
def add_comment(author: str = Form(...), text: str = Form(...)):
    conn = db()
    conn.execute("INSERT INTO comments(author, text) VALUES(?,?)", (author, text))
    conn.commit()
    conn.close()
    return RedirectResponse("/comments", status_code=303)


# ---------- Profile / IDOR ----------

@app.get("/profile/{user_id}", response_class=HTMLResponse)
def profile(user_id: int, token: Optional[str] = Cookie(default=None)):
    user = get_user(token)
    if not user:
        return RedirectResponse("/login", status_code=303)

    conn = db()
    u = conn.execute("SELECT id, username, role FROM users WHERE id=?", (user_id,)).fetchone()
    notes = conn.execute("SELECT id, content FROM notes WHERE user_id=?", (user_id,)).fetchall()
    conn.close()

    if not u:
        raise HTTPException(404, "not found")

    notes_html = "".join(f"<li>{n['content']}</li>" for n in notes)
    # VULN: нет проверки, что это профиль текущего пользователя → IDOR
    return f"""
    <h1>Profile #{u['id']}</h1>
    <p>username: {u['username']}</p>
    <p>role: {u['role']}</p>
    <h3>notes</h3><ul>{notes_html}</ul>
    """


# ---------- Files / path traversal ----------

@app.get("/files")
def files(name: str = "readme.txt"):
    # VULN: нет нормализации пути → path traversal
    path = os.path.join(FILES_DIR, name)
    if not os.path.isfile(path):
        return PlainTextResponse("not found", status_code=404)
    with open(path, "r", errors="replace") as f:
        return PlainTextResponse(f.read())


# ---------- Ping / command injection ----------

PING_FORM = """
<h1>Ping</h1>
<form method="post" action="/ping">
  <input name="host" value="127.0.0.1">
  <button>ping</button>
</form>
"""


@app.get("/ping", response_class=HTMLResponse)
def ping_form():
    return PING_FORM


@app.post("/ping")
def ping(host: str = Form(...)):
    try:
        # VULN: shell=True + конкатенация → command injection
        out = subprocess.check_output(
            f"ping -c 1 {host}", shell=True, stderr=subprocess.STDOUT, timeout=10
        )
    except subprocess.CalledProcessError as e:
        out = e.output
    except subprocess.TimeoutExpired:
        return PlainTextResponse("timeout", status_code=504)
    return PlainTextResponse(out.decode(errors="replace"))


# ---------- Settings / CSRF ----------

@app.get("/settings", response_class=HTMLResponse)
def settings(token: Optional[str] = Cookie(default=None)):
    user = get_user(token)
    if not user:
        return RedirectResponse("/login", status_code=303)

    conn = db()
    row = conn.execute(
        "SELECT email FROM emails WHERE user_id=(SELECT id FROM users WHERE username=?)",
        (user["sub"],),
    ).fetchone()
    conn.close()
    email = row["email"] if row else ""

    return f"""
    <h1>Settings</h1>
    <p>current email: {email}</p>
    <form method="post" action="/settings/email">
      <input name="email" value="{email}">
      <button>save</button>
    </form>
    """


@app.post("/settings/email")
def change_email_post(email: str = Form(...), token: Optional[str] = Cookie(default=None)):
    return _change_email(email, token)


# VULN: состояние меняется через GET и без CSRF-токена
@app.get("/settings/email")
def change_email_get(email: str, token: Optional[str] = Cookie(default=None)):
    return _change_email(email, token)


def _change_email(email: str, token: Optional[str]):
    user = get_user(token)
    if not user:
        return RedirectResponse("/login", status_code=303)
    conn = db()
    conn.execute(
        "UPDATE emails SET email=? WHERE user_id=(SELECT id FROM users WHERE username=?)",
        (email, user["sub"]),
    )
    conn.commit()
    conn.close()
    return RedirectResponse("/settings", status_code=303)


# ---------- Admin / JWT forgery ----------

@app.get("/admin")
def admin(token: Optional[str] = Cookie(default=None)):
    user = get_user(token)
    if not user or user.get("role") != "admin":
        raise HTTPException(403, "admin only")

    conn = db()
    users = [dict(r) for r in conn.execute("SELECT id, username, role FROM users").fetchall()]
    conn.close()
    return {"flag": "FLAG{jwt_forged_admin}", "users": users}


# ---------- Utility ----------

@app.post("/reset")
def reset():
    init_db()
    return {"ok": True, "message": "lab reset"}


@app.get("/health")
def health():
    return {"status": "ok"} 


