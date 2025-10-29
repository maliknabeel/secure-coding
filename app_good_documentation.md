# Secure Flask Application Documentation
## A Comprehensive Guide to Secure Coding Practices

### Overview
This Flask application demonstrates **secure coding practices** that protect against common web application vulnerabilities. It serves as an educational example showing how to implement proper security controls in web applications.

---

## Table of Contents
1. [Setup and Configuration](#setup-and-configuration)
2. [Authentication and Authorization](#authentication-and-authorization)
3. [Input Validation and Sanitization](#input-validation-and-sanitization)
4. [Cryptographic Security](#cryptographic-security)
5. [Web Security Controls](#web-security-controls)
6. [File and Data Handling](#file-and-data-handling)
7. [System Security](#system-security)
8. [Error Handling](#error-handling)
9. [Security Headers and Tokens](#security-headers-and-tokens)

---

## Setup and Configuration

### Secure Secret Management
```python
app.secret_key = os.environ.get("APP_SECRET_KEY", secrets.token_hex(32))
```

**🔒 Security Principle**: Never hardcode secrets in source code.

**What it does**:
- Loads the secret key from environment variables
- Falls back to a cryptographically secure random key if not set
- Uses `secrets.token_hex(32)` for generating secure random values

**Why it's secure**:
- Environment variables keep secrets out of version control
- `secrets` module provides cryptographically strong randomness
- 32 bytes (256 bits) provides sufficient entropy

---

## Authentication and Authorization

### Strong Password Hashing with PBKDF2
```python
def create_user(username, password, is_admin=False):
    salt = secrets.token_bytes(16)  # 16-byte random salt
    # Strong KDF with 200,000 iterations
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    # Store salt and hash separately
```

**🔒 Security Principle**: Use strong key derivation functions for password storage.

**What it does**:
- Generates a unique 16-byte salt for each password
- Uses PBKDF2 with SHA-256 and 200,000 iterations
- Stores salt and hash separately in the database

**Why it's secure**:
- **Salt prevents rainbow table attacks** - each password has unique salt
- **High iteration count** (200,000) makes brute force expensive
- **PBKDF2 is a proven KDF** designed for password hashing

### Rate Limiting for Brute Force Protection
```python
WINDOW = 30.0; MAX_TRIES = 5
LOGIN_TRIES = {}

def throttle(ip):
    now = time.time()
    tries = [t for t in LOGIN_TRIES.get(ip, []) if now - t <= WINDOW]
    if len(tries) >= MAX_TRIES:
        return True  # Block this IP
    tries.append(now)
    LOGIN_TRIES[ip] = tries
    return False
```

**🔒 Security Principle**: Implement rate limiting to prevent automated attacks.

**What it does**:
- Tracks login attempts per IP address
- Allows maximum 5 attempts in 30-second window
- Blocks subsequent attempts from that IP

**Why it's secure**:
- **Prevents password spraying attacks**
- **Mitigates credential stuffing**
- **Sliding window approach** removes old attempts automatically

### Secure Login Process
```python
@app.post("/auth/login")
def login():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "0.0.0.0")
    if throttle(ip):
        return err("too_many_attempts", 429)
    
    # Get credentials
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    
    # Query user securely
    row = cur.execute("SELECT id,pwd_salt,pwd_hash,is_admin FROM users WHERE username=?", (username,)).fetchone()
    
    # Verify password with timing-safe comparison
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    if not hmac.compare_digest(dk, stored):
        return err("invalid", 401)
```

**🔒 Security Principle**: Implement secure authentication with proper validation.

**What it does**:
- Checks rate limiting first
- Uses parameterized queries to prevent SQL injection
- Recomputes hash with same parameters for verification
- Uses timing-safe comparison with `hmac.compare_digest()`

**Why it's secure**:
- **Parameterized queries** prevent SQL injection
- **Timing-safe comparison** prevents timing attacks
- **Consistent error messages** don't leak information about valid usernames

---

## Input Validation and Sanitization

### Integer Overflow Protection
```python
@app.get("/math/sum32")
def math_sum32():
    try:
        x = int(request.args.get("x", "0"))
        y = int(request.args.get("y", "0"))
    except ValueError:
        return err("invalid_int", 400)
    
    # Explicitly bound to 32-bit unsigned
    if not (0 <= x <= 0xFFFFFFFF and 0 <= y <= 0xFFFFFFFF):
        return err("out_of_range", 400)
    
    res = x + y
    if res > 0xFFFFFFFF:  # detect overflow before wrapping
        return err("overflow", 400)
```

**🔒 Security Principle**: Validate input ranges to prevent integer overflow vulnerabilities.

**What it does**:
- Validates input is numeric
- Checks values are within 32-bit unsigned integer range
- Detects overflow before it occurs
- Returns error instead of wrapping around

**Why it's secure**:
- **Prevents integer overflow attacks**
- **Explicit bounds checking** catches edge cases
- **Fail-safe behavior** returns errors rather than incorrect results

### XSS Prevention with Output Encoding
```python
@app.get("/xss")
def safe_xss():
    msg = request.args.get("msg", "hello")
    return f"<h1>{escape(msg)}</h1>"  # escape user input
```

**🔒 Security Principle**: Always escape user input before including in HTML output.

**What it does**:
- Uses Flask's `escape()` function to encode HTML special characters
- Converts `<`, `>`, `&`, `"`, `'` to HTML entities

**Why it's secure**:
- **Prevents XSS attacks** by neutralizing malicious scripts
- **Context-aware encoding** for HTML context
- **Default-secure approach** - escape by default

---

## Cryptographic Security

### Data Integrity Verification
```python
@app.get("/code/fetch")
def code_fetch():
    url = request.args.get("url")
    expected = request.args.get("sha256")
    
    data = urllib.request.urlopen(url, timeout=5).read()
    digest = hashlib.sha256(data).hexdigest()
    
    if not hmac.compare_digest(digest, expected.lower()):
        return err("hash_mismatch", 400)
```

**🔒 Security Principle**: Verify data integrity using cryptographic hashes.

**What it does**:
- Downloads content from URL
- Computes SHA-256 hash of downloaded data
- Compares with expected hash using timing-safe comparison

**Why it's secure**:
- **SHA-256 provides strong integrity guarantees**
- **Prevents tampering** during download
- **Timing-safe comparison** prevents timing attacks

### HMAC Signature Verification
```python
@app.post("/sig/verify")
def signature_verify():
    body = request.data or b""
    provided = request.headers.get("X-Signature", "")
    calc = hmac.new(SHARED_KEY, body, hashlib.sha256).hexdigest()
    
    if not hmac.compare_digest(provided, calc):
        return err("bad_signature", 401)
```

**🔒 Security Principle**: Use HMAC for message authentication and integrity.

**What it does**:
- Computes HMAC-SHA256 of request body using shared secret
- Compares with signature provided in header
- Uses timing-safe comparison

**Why it's secure**:
- **HMAC provides authentication and integrity**
- **Prevents message tampering**
- **Shared secret proves authenticity**

---

## Web Security Controls

### CSRF Protection with Double-Submit Tokens
```python
def get_csrf():
    tok = session.get("csrf")
    if not tok:
        tok = secrets.token_urlsafe(32)
        session["csrf"] = tok
    return tok

@app.post("/bank/transfer")
def safe_transfer():
    header = request.headers.get("X-CSRF-Token", "")
    if not (header and hmac.compare_digest(header, get_csrf())):
        return err("csrf_failed", 400)
```

**🔒 Security Principle**: Protect against Cross-Site Request Forgery (CSRF) attacks.

**What it does**:
- Generates unique CSRF token per session
- Requires token in request header for state-changing operations
- Validates token matches session token

**Why it's secure**:
- **Prevents CSRF attacks** by requiring proof of legitimate request
- **Random tokens** cannot be guessed by attackers
- **Double-submit pattern** is effective against CSRF

### Open Redirect Prevention
```python
ALLOWED_HOSTS = {"127.0.0.1:5000", "localhost:5000"}

def is_safe(url: str) -> bool:
    u = urlparse(url)
    if not u.netloc:
        return True  # relative URLs are safe
    return (u.scheme in {"http","https"}) and (u.netloc in ALLOWED_HOSTS)

@app.get("/redirect")
def safe_redirect():
    nxt = request.args.get("next", "/")
    if not is_safe(nxt):
        nxt = "/"  # fallback to safe default
    return redirect(nxt)
```

**🔒 Security Principle**: Validate redirect URLs against an allowlist.

**What it does**:
- Maintains list of allowed destination hosts
- Validates redirect URLs before redirecting
- Falls back to safe default for invalid URLs

**Why it's secure**:
- **Prevents open redirect attacks**
- **Allowlist approach** is more secure than blocklist
- **Safe fallback** prevents malicious redirects

---

## File and Data Handling

### Secure File Upload
```python
ALLOWED_EXT = {".txt", ".png", ".jpg", ".pdf"}
MAX_SIZE = 5 * 1024 * 1024  # 5 MB

@app.post("/upload")
def safe_upload():
    f = request.files.get("file")
    name = Path(f.filename).name   # drop any path components
    ext = Path(name).suffix.lower()
    
    if ext not in ALLOWED_EXT:
        return err("bad_extension", 400)
    
    data = f.read()
    if len(data) > MAX_SIZE:
        return err("too_large", 400)
    
    rnd = secrets.token_hex(8) + ext
    dest = SAFE_UPLOAD / rnd
```

**🔒 Security Principle**: Validate and sanitize uploaded files.

**What it does**:
- Strips path components from filename
- Validates file extension against allowlist
- Enforces size limits
- Generates random filename to prevent conflicts

**Why it's secure**:
- **Extension allowlist** prevents malicious file types
- **Path sanitization** prevents directory traversal
- **Size limits** prevent DoS attacks
- **Random naming** prevents filename-based attacks

### Path Traversal Prevention
```python
@app.get("/logs/read")
def safe_logs_read():
    name = request.args.get("file", "app.log")
    target = (LOG_DIR / name).resolve()
    
    # Ensure resolved path is within LOG_DIR
    if not str(target).startswith(str(LOG_DIR) + os.sep):
        return err("forbidden", 403)
```

**🔒 Security Principle**: Validate file paths to prevent directory traversal.

**What it does**:
- Resolves the full path including any symbolic links
- Checks that resolved path is within allowed directory
- Rejects paths that escape the designated folder

**Why it's secure**:
- **Path resolution** handles `../` and symbolic links
- **Boundary checking** prevents access outside allowed directories
- **Explicit validation** catches traversal attempts

### Safe XML Parsing
```python
from defusedxml import ElementTree as DET

@app.post("/xml/parse")
def safe_xml():
    xml = request.data or b"<root/>"
    try:
        root = DET.fromstring(xml)  # defusedxml prevents XXE
        return ok({"tag": root.tag, "text": (root.text or "")})
    except Exception as e:
        return err("invalid_xml", 400)
```

**🔒 Security Principle**: Use secure XML parsers to prevent XXE attacks.

**What it does**:
- Uses `defusedxml` library instead of standard `xml` module
- Automatically disables dangerous XML features
- Handles parsing errors gracefully

**Why it's secure**:
- **defusedxml prevents XXE** (XML External Entity) attacks
- **Disables DTD processing** and external entity resolution
- **Prevents XML bomb** attacks

---

## System Security

### SQL Injection Prevention
```python
@app.get("/users/find")
def safe_users_find():
    name = request.args.get("name", "")
    rows = cur.execute("SELECT id,username,is_admin FROM users WHERE username LIKE ?", 
                      (f"%{name}%",)).fetchall()
```

**🔒 Security Principle**: Always use parameterized queries for database operations.

**What it does**:
- Uses parameterized query with `?` placeholder
- Passes user input as parameter, not string concatenation
- Database driver handles proper escaping

**Why it's secure**:
- **Prevents SQL injection** by separating code from data
- **Database driver escaping** is more reliable than manual escaping
- **No string concatenation** eliminates injection vectors

### Command Injection Prevention
```python
@app.get("/sys/ping")
def safe_ping():
    host = request.args.get("host", "127.0.0.1")
    # Basic allowlist: digits and dots only
    if not host.replace(".", "").isdigit():
        return err("invalid_host", 400)
    
    # Use subprocess with shell=False
    out = subprocess.run(["ping", "-c", "1", host], 
                        capture_output=True, text=True)
```

**🔒 Security Principle**: Validate input and avoid shell execution for system commands.

**What it does**:
- Validates input contains only digits and dots (IP addresses)
- Uses `subprocess.run()` with `shell=False`
- Passes command and arguments as separate list items

**Why it's secure**:
- **Input validation** prevents malicious command injection
- **shell=False** prevents shell interpretation of metacharacters
- **Argument list** separates command from arguments safely

### Deserialization Safety
```python
@app.post("/json/load")
def json_load():
    try:
        data = json.loads(request.data or b"{}")  # Safe JSON parsing
        return ok({"keys": list(data.keys())})
    except Exception:
        return err("bad_json", 400)
```

**🔒 Security Principle**: Use safe data formats instead of pickle for serialization.

**What it does**:
- Uses JSON instead of pickle for data exchange
- JSON cannot contain executable code
- Handles parsing errors gracefully

**Why it's secure**:
- **JSON is safe** - cannot execute arbitrary code
- **No pickle vulnerabilities** - pickle can execute malicious code
- **Limited data types** reduce attack surface

---

## Error Handling

### Secure Error Responses
```python
@app.errorhandler(500)
def handle_500(e):
    logging.exception("Internal error: %s", e)  # Log details for debugging
    return err("internal_error", 500)           # Generic error to user
```

**🔒 Security Principle**: Don't expose sensitive information in error messages.

**What it does**:
- Logs detailed error information for developers
- Returns generic error message to users
- Prevents stack trace exposure

**Why it's secure**:
- **Information disclosure prevention** - no sensitive details in responses
- **Proper logging** helps with debugging and monitoring
- **Consistent error format** doesn't leak implementation details

---

## Security Best Practices Demonstrated

### 1. **Defense in Depth**
Multiple security controls work together:
- Input validation + parameterized queries
- Rate limiting + strong password hashing
- File validation + path sanitization

### 2. **Fail-Safe Defaults**
- Default to most restrictive permissions
- Fallback to safe values when validation fails
- Block by default, allow specifically

### 3. **Least Privilege**
- Only expose necessary functionality
- Validate permissions for each operation
- Minimize attack surface

### 4. **Cryptographic Best Practices**
- Use proven algorithms (SHA-256, PBKDF2, HMAC)
- Generate cryptographically secure random values
- Implement timing-safe comparisons

### 5. **Input Validation Everywhere**
- Validate all user inputs
- Use allowlists over blocklists
- Sanitize data for output context

---

## Running the Application

### Prerequisites
```bash
pip install flask defusedxml
```

### Environment Setup
```bash
# Set secure secret key
export APP_SECRET_KEY="your-secret-key-here"

# Set signature verification key
export SIG_KEY="your-signature-key-here"
```

### Running
```bash
python app_good.py
```

The application will run on `http://127.0.0.1:5000/` with all security controls enabled.

---

## Testing Security Features

### 1. Test Authentication
```bash
# Login with valid credentials
curl -X POST http://127.0.0.1:5000/auth/login \
  -d "username=alice&password=CorrectHorseBatteryStaple"

# Test rate limiting (try 6+ times quickly)
curl -X POST http://127.0.0.1:5000/auth/login \
  -d "username=alice&password=wrong"
```

### 2. Test CSRF Protection
```bash
# Get CSRF token first
curl http://127.0.0.1:5000/csrf-token

# Use token in request
curl -X POST http://127.0.0.1:5000/bank/transfer \
  -H "X-CSRF-Token: <token>" \
  -d "to=bob&amount=100"
```

### 3. Test Input Validation
```bash
# Test integer bounds
curl "http://127.0.0.1:5000/math/sum32?x=4294967295&y=1"

# Test XSS protection
curl "http://127.0.0.1:5000/xss?msg=<script>alert('xss')</script>"
```

---

## Learning Objectives

After studying this code, students should understand:

1. **How to implement secure authentication** with proper password hashing
2. **How to prevent common web vulnerabilities** (XSS, CSRF, SQLi, etc.)
3. **How to validate and sanitize user input** appropriately
4. **How to use cryptographic functions** correctly
5. **How to implement defense-in-depth** security architecture
6. **How to handle errors securely** without information disclosure
7. **How to follow secure coding principles** in real applications

This application serves as a practical reference for building secure web applications using modern security best practices.