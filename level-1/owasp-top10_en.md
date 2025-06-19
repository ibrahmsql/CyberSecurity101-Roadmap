# 🔒 Level 1 - OWASP Top 10

> **Objective**: Learn the 10 most critical web application security risks and implement protection methods

---

## 📚 Table of Contents

1. [What is OWASP?](#what-is-owasp)
2. [A01 – Broken Access Control](#a01—broken-access-control)
3. [A02 – Cryptographic Failures](#a02—cryptographic-failures)
4. [A03 – Injection](#a03—injection)
5. [A04 – Insecure Design](#a04—insecure-design)
6. [A05 – Security Misconfiguration](#a05—security-misconfiguration)
7. [A06 – Vulnerable Components](#a06—vulnerable-components)
8. [A07 – Authentication Failures](#a07—authentication-failures)
9. [A08 – Software-and-Data Integrity Failures](#a08—software-and-data-integrity-failures)
10. [A09 – Security Logging & Monitoring Failures](#a09—security-logging--monitoring-failures)
11. [A10 – Server-Side Request Forgery](#a10—server-side-request-forgery)
12. [Hands-On Labs](#hands-on-labs)
13. [Additional Resources](#additional-resources)

---

## 🏛️ What is OWASP?

**OWASP (Open Web Application Security Project)** is a non-profit organization focused on improving web application security.

### 📊 OWASP Top 10 2021 Changes

| 2017 | 2021 | Change |
|------|------|--------|
| A1 - Injection | A03 - Injection | ⬇️ Dropped to 3rd place |
| A2 - Broken Authentication | A07 - Authentication Failures | ⬇️ Dropped to 7th place |
| A3 - Sensitive Data Exposure | A02 - Cryptographic Failures | ⬆️ Rose to 2nd place |
| - | A01 - Broken Access Control | 🆕 Rose to 1st place |
| - | A04 - Insecure Design | 🆕 New category |
| - | A08 - Software Data Integrity | 🆕 New category |
| - | A10 - SSRF | 🆕 New category |

### 🎯 Risk Calculation Methodology

```
Risk = Likelihood × Impact

Likelihood = Threat Agent × Weakness Prevalence × Weakness Detectability
Impact = Technical Impact × Business Impact
```

---

## 🚪 A01 - Broken Access Control

### 📋 Description
Situation where users can perform actions beyond their authorized permissions.

### ⚠️ Common Scenarios

#### 1. **Vertical Privilege Escalation**
```php
// Insecure code
if ($_SESSION['user_id']) {
    // No admin panel access control
    include 'admin_panel.php';
}

// URL manipulation
http://example.com/admin.php  // Direct access
```

#### 2. **Horizontal Privilege Escalation**
```php
// Insecure code
$user_id = $_GET['user_id'];
$query = "SELECT * FROM users WHERE id = $user_id";

// Attack
http://example.com/profile.php?user_id=123  // Another user's profile
```

#### 3. **IDOR (Insecure Direct Object Reference)**
```javascript
// Insecure API
GET /api/users/123/documents/456

// Attack: Changing Document ID
GET /api/users/123/documents/789  // Another user's document
```

#### 4. **Missing Function Level Access Control**
```html
<!-- Admin functions hidden in frontend -->
<div id="admin-panel" style="display:none;">
    <button onclick="deleteUser()">Delete User</button>
</div>

<!-- Attacker can call from JavaScript console -->
<script>
    deleteUser();  // Function still accessible
</script>
```

### 🛡️ Protection Methods

#### **1. Role-Based Access Control (RBAC)**
```php
<?php
class AccessControl {
    private $userRoles;
    
    public function __construct($userId) {
        $this->userRoles = $this->getUserRoles($userId);
    }
    
    public function hasPermission($resource, $action) {
        foreach ($this->userRoles as $role) {
            if ($this->checkRolePermission($role, $resource, $action)) {
                return true;
            }
        }
        return false;
    }
    
    public function enforceAccess($resource, $action) {
        if (!$this->hasPermission($resource, $action)) {
            throw new UnauthorizedException("Access denied");
        }
    }
}

// Usage
$ac = new AccessControl($_SESSION['user_id']);
$ac->enforceAccess('user_profile', 'read');
```

#### **2. Secure Direct Object Reference**
```php
<?php
// Secure approach
function getDocument($documentId) {
    $userId = $_SESSION['user_id'];
    
    // Does user have permission to view this document?
    $query = "SELECT * FROM documents 
             WHERE id = ? AND (owner_id = ? OR shared_with LIKE ?)
             LIMIT 1";
    
    $stmt = $pdo->prepare($query);
    $stmt->execute([$documentId, $userId, "%$userId%"]);
    
    $document = $stmt->fetch();
    if (!$document) {
        throw new UnauthorizedException("Document not found or access denied");
    }
    
    return $document;
}
```

#### **3. JWT Authorization**
```javascript
// JWT payload example
{
  "sub": "1234567890",
  "name": "John Doe",
  "roles": ["user", "editor"],
  "permissions": {
    "documents": ["read", "write"],
    "users": ["read"]
  },
  "iat": 1516239022
}

// Express.js middleware
function authorize(resource, action) {
    return (req, res, next) => {
        const token = req.headers.authorization?.split(' ')[1];
        
        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            
            if (!decoded.permissions[resource]?.includes(action)) {
                return res.status(403).json({ error: 'Insufficient permissions' });
            }
            
            req.user = decoded;
            next();
        } catch (error) {
            return res.status(401).json({ error: 'Invalid token' });
        }
    };
}

// Usage
app.get('/api/documents/:id', 
    authorize('documents', 'read'), 
    getDocument
);
```

---

## 🔐 A02 - Cryptographic Failures

### 📋 Description
Errors related to encryption and failure to protect sensitive data.

### ⚠️ Common Scenarios

#### 1. **Weak Encryption Algorithms**
```php
// ❌ Insecure
$password = md5($userPassword);  // MD5 is broken
$data = mcrypt_encrypt(MCRYPT_DES, $key, $data);  // DES is weak

// ✅ Secure
$password = password_hash($userPassword, PASSWORD_ARGON2ID);
$data = openssl_encrypt($data, 'AES-256-GCM', $key, 0, $iv, $tag);
```

#### 2. **Storing Sensitive Data in Plain Text**
```sql
-- ❌ Insecure
CREATE TABLE users (
    id INT PRIMARY KEY,
    username VARCHAR(50),
    password VARCHAR(50),  -- Plain text password
    credit_card VARCHAR(16)  -- Unencrypted credit card
);

-- ✅ Secure
CREATE TABLE users (
    id INT PRIMARY KEY,
    username VARCHAR(50),
    password_hash VARCHAR(255),  -- Hashed password
    credit_card_encrypted BLOB  -- Encrypted credit card
);
```

#### 3. **Weak Random Number Generation**
```php
// ❌ Insecure
$token = md5(time() . rand());
$sessionId = uniqid();

// ✅ Secure
$token = bin2hex(random_bytes(32));
$sessionId = bin2hex(random_bytes(16));
```

#### 4. **Not Using HTTPS**
```javascript
// ❌ Insecure
fetch('http://api.example.com/login', {
    method: 'POST',
    body: JSON.stringify({ username, password })
});

// ✅ Secure
fetch('https://api.example.com/login', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'Strict-Transport-Security': 'max-age=31536000'
    },
    body: JSON.stringify({ username, password })
});
```

### 🛡️ Protection Methods

#### **1. Strong Encryption Implementation**
```python
import secrets
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

class SecureCrypto:
    @staticmethod
    def hash_password(password: str, salt: bytes = None) -> tuple:
        """Secure password hashing"""
        if salt is None:
            salt = secrets.token_bytes(32)
        
        # Key derivation with PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt
    
    @staticmethod
    def verify_password(password: str, hashed: bytes, salt: bytes) -> bool:
        """Password verification"""
        key, _ = SecureCrypto.hash_password(password, salt)
        return secrets.compare_digest(key, hashed)
    
    @staticmethod
    def encrypt_data(data: str, key: bytes = None) -> tuple:
        """Data encryption"""
        if key is None:
            key = Fernet.generate_key()
        
        f = Fernet(key)
        encrypted = f.encrypt(data.encode())
        return encrypted, key
    
    @staticmethod
    def decrypt_data(encrypted_data: bytes, key: bytes) -> str:
        """Data decryption"""
        f = Fernet(key)
        decrypted = f.decrypt(encrypted_data)
        return decrypted.decode()

# Usage example
password = "user_password_123"
hashed_password, salt = SecureCrypto.hash_password(password)

# Store in database: hashed_password, salt

# Verification
is_valid = SecureCrypto.verify_password(password, hashed_password, salt)
```

#### **2. TLS/SSL Configuration**
```nginx
# nginx.conf - Secure HTTPS configuration
server {
    listen 443 ssl http2;
    server_name example.com;
    
    # SSL Certificates
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/private.key;
    
    # Secure SSL protocols
    ssl_protocols TLSv1.2 TLSv1.3;
    
    # Secure cipher suites
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    
    # HSTS
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";
    
    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    
    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
}

# HTTP to HTTPS redirect
server {
    listen 80;
    server_name example.com;
    return 301 https://$server_name$request_uri;
}
```

---

## 💉 A03 - Injection

### 📋 Description
Security vulnerabilities resulting from insecure processing of untrusted user inputs.

### ⚠️ Injection Types

#### 1. **SQL Injection**
```php
// ❌ Insecure code
$username = $_POST['username'];
$password = $_POST['password'];

$query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
$result = mysqli_query($connection, $query);

// Attack payload
// username: admin' --
// password: anything
// Result: SELECT * FROM users WHERE username = 'admin' -- ' AND password = 'anything'
```

**SQL Injection Types**:
```sql
-- Union-based SQL Injection
' UNION SELECT 1,username,password FROM admin_users --

-- Boolean-based Blind SQL Injection
' AND (SELECT SUBSTRING(username,1,1) FROM users WHERE id=1)='a' --

-- Time-based Blind SQL Injection
'; WAITFOR DELAY '00:00:05' --

-- Error-based SQL Injection
' AND (SELECT COUNT(*) FROM information_schema.tables)>0 --
```

#### 2. **NoSQL Injection**
```javascript
// ❌ Insecure MongoDB query
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    
    db.users.findOne({
        username: username,
        password: password
    });
});

// Attack payload
// POST /login
// {
//   "username": {"$ne": null},
//   "password": {"$ne": null}
// }
```

#### 3. **Command Injection**
```php
// ❌ Insecure code
$filename = $_GET['file'];
system("cat /var/logs/" . $filename);

// Attack
// ?file=access.log; cat /etc/passwd
// Result: cat /var/logs/access.log; cat /etc/passwd
```

#### 4. **LDAP Injection**
```java
// ❌ Insecure LDAP query
String filter = "(&(uid=" + username + ")(password=" + password + "))";
NamingEnumeration results = ctx.search("ou=users,dc=example,dc=com", filter, controls);

// Attack
// username: admin)(|(uid=*
// password: anything
// Result: (&(uid=admin)(|(uid=*)(password=anything))
```

### 🛡️ Protection Methods

#### **1. Parameterized Queries (Prepared Statements)**
```php
<?php
// ✅ Secure SQL query
class SecureDatabase {
    private $pdo;
    
    public function __construct($dsn, $username, $password) {
        $this->pdo = new PDO($dsn, $username, $password, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false
        ]);
    }
    
    public function authenticateUser($username, $password) {
        $stmt = $this->pdo->prepare(
            "SELECT id, username, password_hash FROM users WHERE username = ? LIMIT 1"
        );
        $stmt->execute([$username]);
        $user = $stmt->fetch();
        
        if ($user && password_verify($password, $user['password_hash'])) {
            return $user;
        }
        return false;
    }
    
    public function getUserById($userId) {
        $stmt = $this->pdo->prepare(
            "SELECT id, username, email FROM users WHERE id = ? LIMIT 1"
        );
        $stmt->execute([$userId]);
        return $stmt->fetch();
    }
}
```

#### **2. Input Validation and Sanitization**
```python
import re
import html
from typing import Optional

class InputValidator:
    @staticmethod
    def validate_email(email: str) -> bool:
        """Email format validation"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    @staticmethod
    def validate_username(username: str) -> bool:
        """Username validation"""
        # Only alphanumeric characters and underscore
        pattern = r'^[a-zA-Z0-9_]{3,20}$'
        return bool(re.match(pattern, username))
    
    @staticmethod
    def sanitize_html(input_str: str) -> str:
        """Escape HTML characters"""
        return html.escape(input_str)
    
    @staticmethod
    def validate_file_path(file_path: str) -> bool:
        """File path validation (Path Traversal protection)"""
        # Check for .. and / characters
        if '..' in file_path or file_path.startswith('/'):
            return False
        
        # Only alphanumeric, dot and underscore
        pattern = r'^[a-zA-Z0-9._-]+$'
        return bool(re.match(pattern, file_path))
    
    @staticmethod
    def validate_sql_input(input_str: str) -> str:
        """Input sanitization for SQL injection protection"""
        # Remove dangerous characters
        dangerous_chars = ["'", '"', ';', '--', '/*', '*/', 'xp_', 'sp_']
        
        for char in dangerous_chars:
            input_str = input_str.replace(char, '')
        
        return input_str.strip()

# Usage example
validator = InputValidator()

# Validate form data
username = request.form.get('username')
if not validator.validate_username(username):
    raise ValueError("Invalid username format")

email = request.form.get('email')
if not validator.validate_email(email):
    raise ValueError("Invalid email format")
```

#### **3. ORM Usage**
```python
# Django ORM - Secure query
from django.contrib.auth import authenticate
from django.db import models

class User(models.Model):
    username = models.CharField(max_length=150, unique=True)
    email = models.EmailField()
    password = models.CharField(max_length=128)
    
    def authenticate_user(username, password):
        # Django ORM automatically protects against SQL injection
        user = User.objects.filter(username=username).first()
        if user and user.check_password(password):
            return user
        return None

# SQLAlchemy ORM - Secure query
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine

class UserService:
    def __init__(self, database_url):
        self.engine = create_engine(database_url)
        Session = sessionmaker(bind=self.engine)
        self.session = Session()
    
    def get_user_by_id(self, user_id):
        # Parameterized query automatically generated
        return self.session.query(User).filter(User.id == user_id).first()
    
    def search_users(self, search_term):
        # Even LIKE queries are safe
        return self.session.query(User).filter(
            User.username.like(f"%{search_term}%")
        ).all()
```

#### **4. Command Injection Protection**
```python
import subprocess
import shlex
from pathlib import Path

class SecureCommandExecutor:
    ALLOWED_COMMANDS = ['ls', 'cat', 'grep', 'head', 'tail']
    SAFE_DIRECTORY = '/var/safe_logs/'
    
    @staticmethod
    def execute_safe_command(command, filename):
        """Secure command execution"""
        if command not in SecureCommandExecutor.ALLOWED_COMMANDS:
            raise ValueError(f"Command '{command}' not allowed")
        
        # File path validation
        safe_path = Path(SecureCommandExecutor.SAFE_DIRECTORY) / filename
        if not safe_path.exists() or not str(safe_path).startswith(SecureCommandExecutor.SAFE_DIRECTORY):
            raise ValueError("Invalid file path")
        
        # Secure command construction
        cmd_args = [command, str(safe_path)]
        
        try:
            # Secure execution with subprocess
            result = subprocess.run(
                cmd_args,
                capture_output=True,
                text=True,
                timeout=30,
                check=True
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Command failed: {e}")
        except subprocess.TimeoutExpired:
            raise RuntimeError("Command timed out")

# Usage
executor = SecureCommandExecutor()
try:
    output = executor.execute_safe_command('cat', 'access.log')
    print(output)
except (ValueError, RuntimeError) as e:
    print(f"Error: {e}")
```

---

## 🏗️ A04 – Insecure Design

Design flaws that create exploitable weaknesses (e.g., missing threat modeling, business logic abuse). Build security in from the design phase.

### 🛡️ Prevention
* Apply *Security-by-Design* and threat modeling.
* Define abuse-cases alongside use-cases.
* Enforce secure SDLC with peer reviews.

---

## 🛠️ A05 – Security Misconfiguration

Misconfigured headers, open cloud buckets, verbose error messages, default credentials, etc.

### 🛡️ Prevention
* Harden all environments (dev, test, prod).
* Automate secure baselines (IaC, CIS Benchmarks).
* Turn off directory listing and stack traces.

---

## 🧩 A06 – Vulnerable and Outdated Components

Using libraries, frameworks, or runtimes with known vulnerabilities.

### 🛡️ Prevention
* Maintain SBOM (Software Bill of Materials).
* Subscribe to security advisories and patch quickly.
* Use tools like `npm audit`, `pip safety`, `OWASP Dependency-Check`.

---

## 🔑 A07 – Identification and Authentication Failures

Weak passwords, missing MFA, session fixation, JWT tampering.

### 🛡️ Prevention
* Enforce MFA (TOTP, WebAuthn).
* Apply secure password policies and hashing.
* Rotate and invalidate session identifiers after privilege change.

---

## 🧬 A08 – Software-and-Data Integrity Failures

CI/CD pipelines or libraries where integrity is not verified, leading to supply-chain attacks (e.g., dependency confusion).

### 🛡️ Prevention
* Use signed packages and checksums.
* Implement 2-person code review and signed commits.
* Protect build and deployment infrastructure.

---

## 📜 A09 – Security Logging & Monitoring Failures

Lack of logs or ineffective monitoring delays incident response.

### 🛡️ Prevention
* Centralize, timestamp, and protect logs (e.g., ELK, Loki).
* Monitor authentication and high-risk actions.
* Test alerting and incident runbooks.

---

## 🌐 A10 – Server-Side Request Forgery (SSRF)

The app fetches a remote resource without validating the URL, allowing attackers to access internal services.

### 🛡️ Prevention
* Validate and sanitize user-supplied URLs.
* Block private IP ranges (10.0.0.0/8, 169.254.0.0/16, etc.).
* Enforce egress firewall rules and metadata-API protections.

```python
from urllib.parse import urlparse
import ipaddress, requests

def safe_request(url:str):
    host = urlparse(url).hostname
    ip = ipaddress.ip_address(requests.get(f'https://dns.google/resolve?name={host}&type=A').json()['Answer'][0]['data'])
    if ip.is_private:
        raise ValueError('Private IP blocked')
    return requests.get(url, timeout=5, allow_redirects=False)
```

---

## 🧪 Hands-On Labs

1. **DVWA – SQL Injection**
   ```bash
   docker run -d -p 80:80 vulnerables/web-dvwa
   sqlmap -u "http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit#" \
          --cookie="PHPSESSID=YOURSESSID; security=low" --dbs
   ```
2. **XSS Playground** – test reflected and DOM-based XSS payloads.
3. **OWASP ZAP** – automated scan:
   ```bash
   docker run -t owasp/zap2docker-stable zap-baseline.py -t http://target.local
   ```

---

## 📚 Additional Resources

* [OWASP Top 10 (2021)](https://owasp.org/Top10/)
* [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
* [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
* Tools: **Burp Suite**, **OWASP ZAP**, **SQLMap**, **Nikto**

---

## ✅ Level-Completion Checklist

- [ ] Understand each OWASP Top 10 category
- [ ] Perform practical tests for every vulnerability type
- [ ] Apply secure-coding principles in personal projects
- [ ] Use at least one security scanner (e.g., ZAP)
- [ ] Produce a basic vulnerability-assessment report

**Next Level:** [Level 2 – Penetration Testing Fundamentals](../level-2/penetration-testing-basics.md)

---

*This document is part of the CyberSecurity 101 Roadmap. Stay updated by watching the repository.*
