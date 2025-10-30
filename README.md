# Secure Coding Demo (Hardened)

This folder contains an intentionally insecure Flask app (`app_bad.py`) and a hardened, secure version (`app_good.py`). The secure app replaces vulnerable patterns (SQLi, XSS, IDOR, CSRF, open redirect, unsafe deserialization, command injection, etc.) with safe implementations and uses a new SQLite database `good.db`.

## What Changed
- New secure service: `app_good.py` (no debug in production, safer defaults)
- Database renamed to `good.db` with bcrypt-hashed passwords (alice admin, bob user)
- All vulnerable endpoints re-implemented safely (parameterized SQL, output escaping, path validation, HMAC verification, CSRF token checks, etc.)
- Tests: `test_endpoints.py` provides smoke tests with structured logging
- Dependencies: `requirements.txt`

## Quick Start
1) Create/activate a Python 3.10+ venv
2) Install dependencies
```
pip install -r requirements.txt
```
3) Run the secure app
```
python app_good.py
```
4) In another terminal, run smoke tests (server must already be running)
```
python test_endpoints.py
```

You should see INFO logs and the line: `All endpoint smoke tests passed.`

## Recreating the Database
`good.db` is created and initialized automatically on first run with:
- alice / Password123 (admin)
- bob / Password123 (non-admin)

If you pinned/changed crypto libs or encounter login 401s after upgrades, delete the DB and rerun the app to recreate fresh hashes:
```
rm secure-coding/good.db
python secure-coding/app_good.py
```

## Environment Variables
- `SECRET_KEY`: Flask session secret. If not set, a random one is generated at startup.
- `HMAC_SECRET`: Secret used for `/sig/verify`. If not set, a random one is generated at startup.
- `BASE_URL`: Optional for tests (defaults to `http://127.0.0.1:5000`).

## Endpoint Highlights (Secure Implementations)
- Auth/session: `/auth/login`, `/auth/logout`, `/auth/bypass` (session-based, no client flags)
- IDOR fixed: `/auth/idor` checks ownership unless admin
- SQL injection prevented: parameterized queries in auth and `/users/find`
- XSS mitigated: `/xss` escapes output
- CSRF checked: `/bank/transfer` requires `X-CSRF-Token` from session
- Open redirect restricted: `/redirect` only allows internal paths
- Upload hardened: `/upload` validates extension, path, and size-limit via Flask config
- XML safe: `/xml/parse` uses `defusedxml`
- Command injection avoided: `/sys/ping` uses `subprocess.run([...], shell=False)`
- Insecure deserialization replaced: `/pickle/load` accepts JSON only
- No eval: `/code/eval` supports a tiny safe integer expression evaluator
- HMAC signatures: `/sig/verify` validates with timing-safe compare

## Running Select Tests Manually
Example login:
```
curl -X POST http://127.0.0.1:5000/auth/login -d "username=alice&password=Password123"
```
Example signature verify (replace with real computed HMAC):
```
curl -X POST http://127.0.0.1:5000/sig/verify -H "X-Signature: <hex>" -d "payload"
```

## Notes
- Do not enable Flask debug in production.
- Avoid changing crypto libraries without recreating `good.db`.