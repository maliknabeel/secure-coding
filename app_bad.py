# app_bad.py
# ------------------------------------------------------------
# Flask demo: INSECURE examples (bad patterns) for "security bypass" topics
# DO NOT DEPLOY. Educational only.
#
# Run:
#   pip install flask lxml
#   python app_bad.py
# Open: http://127.0.0.1:5000/
# ------------------------------------------------------------
from flask import Flask, request, jsonify, redirect, make_response
from pathlib import Path
import os, subprocess, sqlite3, pickle, base64, logging, urllib.request
import hashlib, hmac, time, struct
from xml.etree import ElementTree as ET  # XXE unsafe in some parsers; stdlib is still used here for demo
# Note: Real XXE typically requires parsers that load external entities (e.g., lxml without defenses).
# We keep a simplistic "bad" parse to illustrate unsafe parsing of untrusted XML.

app = Flask(__name__)
app.secret_key = "hardcoded-secret"   # Hardcoded Password (bad)

DB = "bad.db"
Path(DB).unlink(missing_ok=True)
conn = sqlite3.connect(DB)
cur = conn.cursor()
cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT, is_admin INTEGER)")
cur.execute("INSERT INTO users (username,password_hash,is_admin) VALUES ('alice','" + hashlib.md5(b'Password123').hexdigest() + "',1)")  # Broken crypto (MD5) + string concat
cur.execute("INSERT INTO users (username,password_hash,is_admin) VALUES ('bob','" + hashlib.sha256(b'Password123').hexdigest() + "',0)")  # Unsalted hash
conn.commit(); conn.close()

logging.basicConfig(level=logging.INFO)

def ok(data=None, status=200): return (jsonify({"ok": True, "data": data}), status)
def err(msg="error", status=400): return (jsonify({"ok": False, "error": msg}), status)


@app.route("/")
def index():
    return ok({
        "note": "INSECURE endpoints for demonstration only",
        "topics": [
            "Authentication Bypass (client flag) -> /auth/bypass",
            "Reliance on Untrusted Inputs (trust role) -> /inputs/trust",
            "Missing/Incorrect Authorization (IDOR) -> /auth/idor?id=1",
            "Missing Encryption of Sensitive Data -> /crypto/plaintext",
            "Use of a Broken Crypto Algorithm (MD5) -> /crypto/md5_login",
            "Unsalted Hash -> /crypto/unsalted",
            "Password Guessing (no rate limit) -> /auth/login",
            "Integer Overflow -> /math/overflow?x=4294967295&y=2",
            "Download of Code Without Integrity Check -> /code/download?url=...",
            "Open Redirect -> /redirect?next=http://evil.com",
            "Cross-Site Scripting -> /xss?msg=<script>alert(1)</script>",
            "Cross-Site Request Forgery (no CSRF) -> /bank/transfer (POST)",
            "Upload of Dangerous File -> /upload (POST file)",
            "XML External Entities (unsafe parse) -> /xml/parse (POST)",
            "Path Traversal -> /logs/read?file=../../etc/passwd",
            "OS Command Injection -> /sys/ping?host=8.8.8.8;cat /etc/passwd",
            "SQL Injection -> /users/find?name=' OR '1'='1",
            "Insecure Deserialization -> /pickle/load (POST)",
            "Buffer Overflow (simulated) -> /buf/pack?count=999999999999",
            "Format String Injection -> /fmt?pattern=%(user)s%(missing)s",
            "Hardcoded Password -> /admin/door?pw=Password123",
            "Verbose Error Message -> /error/debug",
            "Code Injection (eval) -> /code/eval?expr=__import__('os').system('dir')",
            "Signature Verification (skipped) -> /sig/verify (POST)",
        ]
    })


# Authentication Bypass / Reliance on Untrusted Inputs
@app.get("/auth/bypass")
def auth_bypass():
    # BAD: trust a client-supplied flag
    if request.args.get("is_admin") == "1":
        return ok({"msg": "Welcome admin!"})
    return err("forbidden", 403)

@app.get("/inputs/trust")
def inputs_trust():
    # BAD: trust 'role' from client
    role = request.args.get("role", "user")
    if role == "admin":
        return ok({"panel": "admin"})
    return ok({"panel": "user"})


# Missing/Incorrect Authorization (IDOR)
@app.get("/auth/idor")
def idor():
    # BAD: no ownership check
    user_id = request.args.get("id", "1")
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    row = cur.execute(f"SELECT id,username,is_admin FROM users WHERE id={user_id}").fetchone()  # concat
    conn.close()
    if not row: return err("not_found", 404)
    return ok({"id": row[0], "username": row[1], "is_admin": row[2]})


# Missing Encryption of Sensitive Data
@app.get("/crypto/plaintext")
def crypto_plaintext():
    # BAD: transmit secret in plaintext (simulation)
    secret = "user_ssn=123-45-6789"
    resp = make_response(secret, 200)  # no TLS here, just a string
    return resp


# Use of a Broken Crypto Algorithm / Unsalted Hash / Password Guessing
@app.post("/auth/login")
def auth_login():
    # BAD: md5/sha256 of password without salt, no rate limit
    username = request.form.get("username", "")
    password = request.form.get("password", "").encode()
    # naive: first try MD5, then SHA256, unsalted
    pw_md5 = hashlib.md5(password).hexdigest()
    pw_sha = hashlib.sha256(password).hexdigest()
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    row = cur.execute("SELECT id,username,password_hash,is_admin FROM users WHERE username='%s'" % username).fetchone()  # SQLi risk
    conn.close()
    if not row: return err("invalid", 401)
    if row[2] in (pw_md5, pw_sha):
        return ok({"msg": "logged in (insecure)"})
    return err("invalid", 401)


@app.post("/crypto/md5_login")
def crypto_md5_login():
    # BAD: explicitly MD5 for password verification
    username = request.form.get("username", "")
    password = request.form.get("password", "").encode()
    digest = hashlib.md5(password).hexdigest()
    return ok({"note": "never use MD5 for passwords", "username": username, "hash": digest})


@app.post("/crypto/unsalted")
def crypto_unsalted():
    # BAD: unsalted SHA-256
    password = request.form.get("password", "").encode()
    return ok({"hash": hashlib.sha256(password).hexdigest()})


# Integer Overflow (simulated via 32-bit wrap)
@app.get("/math/overflow")
def int_overflow():
    x = int(request.args.get("x", "0"))
    y = int(request.args.get("y", "0"))
    # BAD: assume 32-bit and wrap silently
    res = (x + y) & 0xFFFFFFFF
    return ok({"sum_32bit_wrapped": res})


# Download of Code Without Integrity Check
@app.get("/code/download")
def code_download():
    url = request.args.get("url", "https://example.com/bad.py")
    # BAD: download and execute without verifying integrity
    code = urllib.request.urlopen(url, timeout=5).read().decode("utf-8")
    exec(code, {})  # DANGER
    return ok({"executed_from": url})


# Open Redirect
@app.get("/redirect")
def open_redirect():
    nxt = request.args.get("next", "/")
    return redirect(nxt)  # BAD: no validation


# Cross-Site Scripting
@app.get("/xss")
def xss():
    msg = request.args.get("msg", "hello")
    # BAD: reflect unescaped content
    return f"<h1>{msg}</h1>"


# Cross-Site Request Forgery
@app.post("/bank/transfer")
def bank_transfer():
    # BAD: no CSRF defense (cookie-based session assumed)
    to = request.form.get("to", "acctX")
    amt = request.form.get("amount", "0")
    return ok({"transferred": amt, "to": to})


# Upload of Dangerous File
UPLOAD_DIR = Path("./uploads_bad"); UPLOAD_DIR.mkdir(exist_ok=True)
@app.post("/upload")
def upload():
    # BAD: no extension/size/content checks; saves with user-supplied name
    f = request.files.get("file")
    if not f: return err("no_file", 400)
    dst = UPLOAD_DIR / f.filename  # path traversal possible with ".."
    f.save(dst)
    return ok({"saved": str(dst)})


# XML External Entities (unsafe)
@app.post("/xml/parse")
def xml_parse():
    # BAD: parse untrusted XML directly; external entities may be abused with some parsers
    xml = request.data or b"<root/>"
    try:
        root = ET.fromstring(xml)
        return ok({"tag": root.tag, "text": (root.text or "")})
    except Exception as e:
        return err(str(e), 400)


# Path Traversal
LOG_DIR = Path("./logs_bad"); LOG_DIR.mkdir(exist_ok=True)
(LOG_DIR / "app.log").write_text("demo\n", encoding="utf-8")

@app.get("/logs/read")
def logs_read():
    filename = request.args.get("file", "app.log")
    # BAD: naive join + weak check
    path = os.path.join(LOG_DIR, filename)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return ok({"content": fh.read()})
    except Exception as e:
        return err(str(e), 400)


# OS Command Injection
@app.get("/sys/ping")
def sys_ping():
    host = request.args.get("host", "127.0.0.1")
    # BAD: shell=True and user input concatenation
    cmd = f"ping -c 1 {host}"
    out = subprocess.getoutput(cmd)  # uses shell
    return ok({"cmd": cmd, "out": out})


# SQL Injection
@app.get("/users/find")
def users_find():
    name = request.args.get("name", "")
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    # BAD: string formatting
    q = f"SELECT id,username,is_admin FROM users WHERE username LIKE '%{name}%'"
    rows = cur.execute(q).fetchall()
    conn.close()
    return ok({"query": q, "rows": rows})


# Insecure Deserialization
@app.post("/pickle/load")
def pickle_load():
    data = request.data or b""
    # BAD: arbitrary code execution possible
    obj = pickle.loads(data)
    return ok({"loaded_type": str(type(obj))})


# Buffer Overflow (simulated)
@app.get("/buf/pack")
def buf_pack():
    count = int(request.args.get("count", "1000"))
    # BAD: attempt to pack an absurd number of integers (may exhaust memory)
    packed = struct.pack("I" * count, *([1] * count))
    return ok({"len": len(packed)})


# Format String Injection
@app.get("/fmt")
def fmt():
    pattern = request.args.get("pattern", "%(user)s says hi")
    data = {"user": "guest"}  # missing keys cause exceptions/info leaks
    try:
        return ok({"result": pattern % data})
    except Exception as e:
        return err(str(e), 500)


# Hardcoded Password (also earlier secret_key)
@app.get("/admin/door")
def admin_door():
    pw = request.args.get("pw", "")
    # BAD: compares to hardcoded password
    if pw == "Password123":
        return ok({"entered": True})
    return err("forbidden", 403)


# Verbose Error Message
@app.get("/error/debug")
def error_debug():
    # BAD: deliberately raise to show stack in debug mode (if enabled)
    1 / 0  # divide by zero


# Code Injection
@app.get("/code/eval")
def code_eval():
    expr = request.args.get("expr", "1+2")
    # BAD: eval user input
    try:
        result = eval(expr)
        return ok({"result": result})
    except Exception as e:
        return err(str(e), 400)


# Signature Verification (skipped/incorrect)
@app.post("/sig/verify")
def sig_verify():
    # BAD: signature is not verified; just trusts provided "signature"
    body = request.data or b""
    provided_sig = request.headers.get("X-Signature", "")
    # pretend we verified...
    return ok({"verified": True, "sig": provided_sig})


if __name__ == "__main__":
    # Enabling debug True is itself risky in prod (leaks secrets/tracebacks)
    app.run(debug=True)
