import os
import io
import json
import time
import logging
import requests


BASE = os.environ.get("BASE_URL", "http://127.0.0.1:5000")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)


def assert_ok(r):
    r.raise_for_status()
    data = r.json()
    assert data.get("ok") is True, data
    return data["data"]


def assert_err(r, code=None):
    if code is not None:
        assert r.status_code == code, (r.status_code, r.text)
    data = r.json()
    assert data.get("ok") is False, data
    return data.get("error")


def main():
    s = requests.Session()

    logger.info("[index] GET /")
    d = assert_ok(s.get(f"{BASE}/"))
    assert d["db"] == "good.db"
    logger.info("[index] ok - db is %s", d["db"])

    logger.info("[login] POST /auth/login as alice")
    d = assert_ok(s.post(f"{BASE}/auth/login", data={"username": "alice", "password": "Password123"}))
    assert d["is_admin"] is True
    alice_id = d["user_id"]
    logger.info("[login] ok - user_id=%s is_admin=%s", alice_id, d["is_admin"])

    logger.info("[auth] GET /auth/bypass and /inputs/trust")
    assert_ok(s.get(f"{BASE}/auth/bypass"))
    d = assert_ok(s.get(f"{BASE}/inputs/trust"))
    assert d["panel"] == "admin"
    logger.info("[auth] ok - panel=%s", d["panel"])

    logger.info("[idor] GET /auth/idor?id=2")
    d = assert_ok(s.get(f"{BASE}/auth/idor", params={"id": 2}))
    assert d["id"] == 2
    logger.info("[idor] ok - fetched id=%s", d["id"])

    logger.info("[crypto] POST /crypto/md5_login and /crypto/unsalted; GET /crypto/plaintext")
    d = assert_ok(s.post(f"{BASE}/crypto/md5_login", data={"password": "x"}))
    assert "bcrypt_hash" in d
    d = assert_ok(s.post(f"{BASE}/crypto/unsalted", data={"password": "x"}))
    assert "bcrypt_hash" in d
    assert_ok(s.get(f"{BASE}/crypto/plaintext"))
    logger.info("[crypto] ok")

    logger.info("[math] GET /math/overflow")
    d = assert_ok(s.get(f"{BASE}/math/overflow", params={"x": 4294967295, "y": 2}))
    assert d["sum"] == 4294967295 + 2
    logger.info("[math] ok - sum=%s", d["sum"])

    logger.info("[xss] GET /xss with script payload (should be escaped)")
    r = s.get(f"{BASE}/xss", params={"msg": "<script>alert(1)</script>"})
    assert r.status_code == 200
    assert "<script>" not in r.text
    logger.info("[xss] ok - script not reflected")

    logger.info("[redirect] GET /redirect to external (should coerce to /)")
    r = s.get(f"{BASE}/redirect", params={"next": "http://evil.com"}, allow_redirects=False)
    assert r.status_code in (301, 302, 303, 307, 308)
    assert r.headers["Location"].startswith("/")
    logger.info("[redirect] ok - Location=%s", r.headers["Location"])

    logger.info("[upload] POST /upload note.txt")
    file_content = io.BytesIO(b"hello")
    files = {"file": ("note.txt", file_content, "text/plain")}
    d = assert_ok(s.post(f"{BASE}/upload", files=files))
    assert d["saved"].endswith("note.txt")
    logger.info("[upload] ok - saved=%s", d["saved"])

    logger.info("[logs] GET /logs/read app.log")
    d = assert_ok(s.get(f"{BASE}/logs/read", params={"file": "app.log"}))
    assert "demo" in d["content"]
    logger.info("[logs] ok - contains demo")

    logger.info("[ping] GET /sys/ping 127.0.0.1")
    d = assert_ok(s.get(f"{BASE}/sys/ping", params={"host": "127.0.0.1"}))
    assert "rc" in d and "out" in d
    logger.info("[ping] ok - rc=%s", d["rc"])

    logger.info("[users] GET /users/find name=ali")
    d = assert_ok(s.get(f"{BASE}/users/find", params={"name": "ali"}))
    assert any(row[1] == "alice" for row in d["rows"])  # row = [id, username, is_admin]
    logger.info("[users] ok - found alice")

    logger.info("[pickle] POST /pickle/load with JSON")
    d = assert_ok(s.post(f"{BASE}/pickle/load", data=json.dumps({"x": 1}), headers={"Content-Type": "application/json"}))
    assert d["loaded_type"] == "dict"
    logger.info("[pickle] ok - loaded_type=%s", d["loaded_type"])

    logger.info("[fmt] GET /fmt pattern={user} says hi")
    d = assert_ok(s.get(f"{BASE}/fmt", params={"pattern": "{user} says hi"}))
    assert d["result"] == "guest says hi"
    logger.info("[fmt] ok - result=%s", d["result"])

    logger.info("[eval] GET /code/eval expr=1+2-3")
    d = assert_ok(s.get(f"{BASE}/code/eval", params={"expr": "1+2-3"}))
    assert d["result"] == 0
    logger.info("[eval] ok - result=%s", d["result"])

    logger.info("[csrf] POST /bank/transfer without CSRF (expect 403)")
    r = s.post(f"{BASE}/bank/transfer", data={"to": "acctY", "amount": "10"})
    assert_err(r, 403)
    logger.info("[csrf] ok - rejected without token")

    logger.info("[sig] POST /sig/verify with bad signature (expect 401)")
    r = s.post(f"{BASE}/sig/verify", data=b"payload", headers={"X-Signature": "bad"})
    assert_err(r, 401)
    logger.info("[sig] ok - rejected bad signature")

    logger.info("[logout] POST /auth/logout")
    assert_ok(s.post(f"{BASE}/auth/logout"))
    logger.info("[logout] ok")

    logger.info("All endpoint smoke tests passed.")
    print("All endpoint smoke tests passed.")


if __name__ == "__main__":
    main()


