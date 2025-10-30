from flask import Flask, request, jsonify, redirect, make_response, session
from pathlib import Path
import os, sqlite3, logging, re, hmac, hashlib, time, secrets, json, html, subprocess
from passlib.hash import bcrypt
from defusedxml import ElementTree as SafeET
from werkzeug.utils import secure_filename


APP_DIR = Path(__file__).parent
DB_PATH = APP_DIR / "good.db"
UPLOAD_DIR = APP_DIR / "uploads_good"
LOG_DIR = APP_DIR / "logs_good"
UPLOAD_DIR.mkdir(exist_ok=True)
LOG_DIR.mkdir(exist_ok=True)
(LOG_DIR / "app.log").write_text("demo\n", encoding="utf-8")


def create_app() -> Flask:
    app = Flask(__name__)
    app.secret_key = os.getenv("SECRET_KEY", secrets.token_hex(32))
    app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024  # 8MB uploads
    app.config["SESSION_COOKIE_SECURE"] = False  # enable True under HTTPS
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    return app


app = create_app()
HMAC_SECRET = os.getenv("HMAC_SECRET", secrets.token_bytes(32))

logging.basicConfig(level=logging.INFO)


def ok(data=None, status=200):
    return jsonify({"ok": True, "data": data}), status


def err(msg="error", status=400):
    return jsonify({"ok": False, "error": "request_failed" if status >= 500 else msg}), status


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    first_time = not DB_PATH.exists()
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0
        )
        """
    )
    if first_time:
        cur.execute(
            "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
            ("alice", bcrypt.hash("Password123"), 1),
        )
        cur.execute(
            "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
            ("bob", bcrypt.hash("Password123"), 0),
        )
    conn.commit()
    conn.close()


init_db()


@app.route("/")
def index():
    return ok({
        "note": "SECURE endpoints (hardened)",
        "db": str(DB_PATH.name),
    })


# ----------------------- Auth/Session helpers -----------------------
def current_user_id():
    return session.get("user_id")


def current_is_admin():
    return bool(session.get("is_admin", False))


login_attempts = {}


@app.post("/auth/login")
def auth_login():
    # Basic in-memory rate limit by IP
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "?")
    rec = login_attempts.get(ip, {"count": 0, "ts": time.time()})
    now = time.time()
    if now - rec["ts"] > 60:
        rec = {"count": 0, "ts": now}
    if rec["count"] >= 10:
        return err("rate_limited", 429)

    username = request.form.get("username", "")
    password = request.form.get("password", "")
    with get_db() as conn:
        row = conn.execute("SELECT id, username, password_hash, is_admin FROM users WHERE username=?", (username,)).fetchone()
    rec["count"] += 1
    login_attempts[ip] = rec
    if not row or not bcrypt.verify(password, row["password_hash"]):
        return err("invalid", 401)

    session["user_id"] = int(row["id"])
    session["is_admin"] = bool(row["is_admin"]) 
    # set CSRF token
    session["csrf_token"] = session.get("csrf_token") or secrets.token_hex(16)
    return ok({"msg": "logged_in", "user_id": session["user_id"], "is_admin": session["is_admin"]})


@app.post("/auth/logout")
def auth_logout():
    session.clear()
    return ok({"msg": "logged_out"})


@app.get("/auth/bypass")
def auth_bypass():
    # Secure: no client-side admin flag, only session
    if current_is_admin():
        return ok({"msg": "Welcome admin!"})
    return err("forbidden", 403)


@app.get("/inputs/trust")
def inputs_trust():
    return ok({"panel": "admin" if current_is_admin() else "user"})


@app.get("/auth/idor")
def idor():
    if not current_user_id():
        return err("unauthorized", 401)
    id_param = request.args.get("id")
    try:
        target_id = int(id_param) if id_param is not None else current_user_id()
    except ValueError:
        return err("bad_id", 400)

    if not current_is_admin() and target_id != current_user_id():
        return err("forbidden", 403)

    with get_db() as conn:
        row = conn.execute("SELECT id, username, is_admin FROM users WHERE id=?", (target_id,)).fetchone()
    if not row:
        return err("not_found", 404)
    return ok({"id": row["id"], "username": row["username"], "is_admin": row["is_admin"]})


@app.get("/crypto/plaintext")
def crypto_plaintext():
    # Do not send sensitive data; return masked example
    return ok({"message": "sensitive data withheld"})


@app.post("/crypto/md5_login")
def crypto_md5_login():
    # Safe alternative: return a bcrypt hash instead of MD5
    password = request.form.get("password", "")
    return ok({"note": "using bcrypt instead of MD5", "bcrypt_hash": bcrypt.hash(password)})


@app.post("/crypto/unsalted")
def crypto_unsalted():
    password = request.form.get("password", "")
    return ok({"note": "salted via bcrypt", "bcrypt_hash": bcrypt.hash(password)})


@app.get("/math/overflow")
def int_overflow():
    try:
        x = int(request.args.get("x", "0"))
        y = int(request.args.get("y", "0"))
    except ValueError:
        return err("bad_numbers", 400)
    # Python integers are unbounded; just return accurate sum
    return ok({"sum": x + y})


@app.get("/code/download")
def code_download():
    # Disallow executing downloaded code entirely
    return err("operation_not_allowed", 405)


@app.get("/redirect")
def open_redirect():
    nxt = request.args.get("next", "/")
    # Only allow internal relative paths
    if not nxt.startswith("/"):
        nxt = "/"
    return redirect(nxt)


@app.get("/xss")
def xss():
    msg = request.args.get("msg", "hello")
    return make_response(f"<h1>{html.escape(msg)}</h1>", 200)


@app.post("/bank/transfer")
def bank_transfer():
    if not current_user_id():
        return err("unauthorized", 401)
    token = request.headers.get("X-CSRF-Token", "")
    if not token or token != session.get("csrf_token"):
        return err("csrf_failed", 403)
    to = request.form.get("to", "acctX")
    amt = request.form.get("amount", "0")
    try:
        amt_val = float(amt)
        if amt_val < 0:
            return err("bad_amount", 400)
    except ValueError:
        return err("bad_amount", 400)
    return ok({"transferred": amt_val, "to": to})


ALLOWED_EXTENSIONS = {"txt", "png", "jpg", "jpeg", "pdf"}


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.post("/upload")
def upload():
    f = request.files.get("file")
    if not f or f.filename == "":
        return err("no_file", 400)
    if not allowed_file(f.filename):
        return err("disallowed_extension", 400)
    safe_name = secure_filename(f.filename)
    dst = (UPLOAD_DIR / safe_name).resolve()
    if not str(dst).startswith(str(UPLOAD_DIR.resolve())):
        return err("path_escape", 400)
    f.save(dst)
    return ok({"saved": str(dst.name)})


@app.post("/xml/parse")
def xml_parse():
    xml = request.data or b"<root/>"
    try:
        root = SafeET.fromstring(xml)
        return ok({"tag": root.tag, "text": (root.text or "")})
    except Exception:
        return err("invalid_xml", 400)


@app.get("/logs/read")
def logs_read():
    filename = request.args.get("file", "app.log")
    safe_name = secure_filename(filename)
    path = (LOG_DIR / safe_name).resolve()
    root = LOG_DIR.resolve()
    if not str(path).startswith(str(root)):
        return err("path_escape", 400)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return ok({"content": fh.read()})
    except Exception:
        return err("not_found", 404)


HOST_RE = re.compile(r"^(?:localhost|127\.0\.0\.1|\d{1,3}(?:\.\d{1,3}){3}|[a-zA-Z0-9.-]+)$")


@app.get("/sys/ping")
def sys_ping():
    host = request.args.get("host", "127.0.0.1")
    if not HOST_RE.match(host):
        return err("bad_host", 400)
    try:
        out = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True, timeout=3)
        return ok({"cmd": ["ping", "-c", "1", host], "rc": out.returncode, "out": out.stdout})
    except Exception:
        return err("ping_failed", 500)


@app.get("/users/find")
def users_find():
    name = request.args.get("name", "")
    like = f"%{name}%"
    with get_db() as conn:
        rows = conn.execute("SELECT id, username, is_admin FROM users WHERE username LIKE ?", (like,)).fetchall()
    return ok({"rows": [[r["id"], r["username"], r["is_admin"]] for r in rows]})


@app.post("/pickle/load")
def pickle_load():
    # Safe alternative: accept JSON only
    raw = request.data or b"{}"
    try:
        obj = json.loads(raw)
        return ok({"loaded_type": type(obj).__name__})
    except Exception:
        return err("invalid_json", 400)


@app.get("/buf/pack")
def buf_pack():
    try:
        count = int(request.args.get("count", "1000"))
    except ValueError:
        return err("bad_count", 400)
    if not 0 <= count <= 100000:  # cap to avoid memory exhaustion
        return err("too_large", 400)
    # Simulate work without large allocations
    return ok({"count_ack": count})


@app.get("/fmt")
def fmt():
    # Avoid user-controlled format strings; echo safely
    pattern = request.args.get("pattern", "{user} says hi")
    data = {"user": "guest"}
    try:
        # Limit braces to avoid arbitrary field access
        if pattern.count("{") > 2 or pattern.count("}") > 2:
            return err("bad_pattern", 400)
        return ok({"result": pattern.format(**data)})
    except Exception:
        return err("format_error", 400)


@app.get("/admin/door")
def admin_door():
    # Only admins can enter; no hardcoded password
    if current_is_admin():
        return ok({"entered": True})
    return err("forbidden", 403)


@app.get("/error/debug")
def error_debug():
    # Return generic error; do not leak stack traces
    return err("something_went_wrong", 500)


@app.get("/code/eval")
def code_eval():
    # No eval; allow literal numbers only via simple parser
    expr = request.args.get("expr", "0")
    if not re.fullmatch(r"\s*-?\d+\s*(?:[+\-]\s*\d+\s*)*", expr):
        return err("unsupported_expr", 400)
    try:
        # compute safe integer sum/subtractions only
        tokens = re.findall(r"[+\-]?\d+", expr.replace(" ", ""))
        total = 0
        for t in tokens:
            total += int(t)
        return ok({"result": total})
    except Exception:
        return err("bad_expr", 400)


@app.post("/sig/verify")
def sig_verify():
    body = request.data or b""
    provided_sig = request.headers.get("X-Signature", "")
    computed = hmac.new(HMAC_SECRET, body, hashlib.sha256).hexdigest()
    if not (provided_sig and hmac.compare_digest(provided_sig, computed)):
        return err("signature_invalid", 401)
    return ok({"verified": True})


if __name__ == "__main__":
    # Do NOT enable debug in production
    app.run(debug=False)


