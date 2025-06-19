# 🛡️ Level 1 - Application Security Basics

## 🎯 Level Objective

In this section, you will learn the fundamental concepts of application security, common vulnerabilities, and secure software development practices. The goal is to build a basic understanding of understanding, detecting, and preventing security vulnerabilities in web applications. This knowledge provides the essential skills needed for secure software development and application security testing.

## 📚 Topics

1. [Introduction to Application Security](#1-introduction-to-application-security)
2. [Common Application Vulnerabilities (OWASP Top 10)](#2-common-application-vulnerabilities-owasp-top-10)
3. [Secure Software Development Lifecycle (SSDLC)](#3-secure-software-development-lifecycle-ssdlc)
4. [Basic Testing Methodologies](#4-basic-testing-methodologies)
5. [Authentication and Authorization Fundamentals](#5-authentication-and-authorization-fundamentals)
6. [Session Management Security](#6-session-management-security)
7. [Input Validation and Output Encoding](#7-input-validation-and-output-encoding)
8. [Application Security Tools](#8-application-security-tools)
9. [Best Practices and Resources](#9-best-practices-and-resources)

---

## 1. Introduction to Application Security

Application security is the process of preventing, detecting, and addressing security vulnerabilities in software applications during the design, development, deployment, and maintenance phases.

### Why is it Important?

- **Data Protection:** Protecting sensitive user and business data
- **Business Continuity:** Preventing security breaches from disrupting business operations
- **Legal Compliance:** Compliance with regulations like GDPR, HIPAA, PCI DSS
- **Reputation Management:** Preventing damage to brand reputation from security breaches
- **Financial Protection:** Minimizing financial losses from security incidents

### Application Security Scope

- **Web Applications:** Browser-based applications
- **Mobile Applications:** iOS, Android applications
- **APIs:** REST, SOAP, GraphQL services
- **Desktop Applications:** Desktop software
- **IoT Applications:** Internet of Things devices

### Vulnerability vs Threat vs Risk

- **Vulnerability:** Weakness or flaw in the system
- **Threat:** Potential to exploit a vulnerability
- **Risk:** Probability and impact of threat realization

---

## 2. Common Application Vulnerabilities (OWASP Top 10)

### 🔴 A01:2021 - Broken Access Control

**Description:** Restrictions on what authenticated users are allowed to do are often not properly enforced.

**Examples:**
- Accessing other users' accounts by modifying URL parameters
- Viewing or editing someone else's account
- Acting as a user without being logged in
- Privilege escalation

**Prevention:**
```python
# Example: Proper access control check
def get_user_profile(user_id, current_user):
    if current_user.id != user_id and not current_user.is_admin:
        raise PermissionError("Access denied")
    return User.get_by_id(user_id)
```

### 🔴 A02:2021 - Cryptographic Failures

**Description:** Failures related to cryptography which often leads to sensitive data exposure.

**Examples:**
- Transmitting data in clear text
- Using old or weak cryptographic algorithms
- Improper key management
- Missing encryption of sensitive data

**Prevention:**
```python
# Example: Proper password hashing
import bcrypt

def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt)

def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed)
```

### 🔴 A03:2021 - Injection

**Description:** Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query.

**SQL Injection Example:**
```python
# Vulnerable code
def get_user(username):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return db.execute(query)

# Secure code
def get_user(username):
    query = "SELECT * FROM users WHERE username = ?"
    return db.execute(query, (username,))
```

**Command Injection Example:**
```python
# Vulnerable code
import os
def ping_host(host):
    os.system(f"ping {host}")

# Secure code
import subprocess
def ping_host(host):
    # Validate input first
    if not re.match(r'^[a-zA-Z0-9.-]+$', host):
        raise ValueError("Invalid host")
    subprocess.run(["ping", "-c", "1", host], check=True)
```

### 🔴 A04:2021 - Insecure Design

**Description:** Risks related to design flaws and missing or ineffective control design.

**Examples:**
- Missing rate limiting
- Insecure password recovery
- Lack of segregation of duties
- Missing security controls

### 🔴 A05:2021 - Security Misconfiguration

**Description:** Security misconfiguration is commonly a result of insecure default configurations.

**Examples:**
- Default accounts and passwords
- Unnecessary features enabled
- Missing security headers
- Verbose error messages

**Prevention:**
```python
# Example: Secure Flask configuration
from flask import Flask

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
```

### 🔴 A06:2021 - Vulnerable and Outdated Components

**Description:** Components run with the same privileges as the application itself.

**Prevention:**
- Regularly update dependencies
- Use dependency scanning tools
- Remove unused dependencies
- Monitor security advisories

### 🔴 A07:2021 - Identification and Authentication Failures

**Description:** Confirmation of the user's identity, authentication, and session management.

**Examples:**
- Weak passwords
- Missing multi-factor authentication
- Session fixation
- Credential stuffing

### 🔴 A08:2021 - Software and Data Integrity Failures

**Description:** Code and infrastructure that does not protect against integrity violations.

**Examples:**
- Unsigned or unverified software updates
- Insecure CI/CD pipelines
- Auto-update without integrity verification

### 🔴 A09:2021 - Security Logging and Monitoring Failures

**Description:** Insufficient logging and monitoring, coupled with missing or ineffective integration.

**Prevention:**
```python
# Example: Proper security logging
import logging

logger = logging.getLogger('security')

def login_attempt(username, success, ip_address):
    if success:
        logger.info(f"Successful login: {username} from {ip_address}")
    else:
        logger.warning(f"Failed login attempt: {username} from {ip_address}")
```

### 🔴 A10:2021 - Server-Side Request Forgery (SSRF)

**Description:** SSRF flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL.

**Prevention:**
```python
# Example: URL validation for SSRF prevention
import requests
from urllib.parse import urlparse

def fetch_url(url):
    parsed = urlparse(url)
    
    # Block internal networks
    if parsed.hostname in ['localhost', '127.0.0.1'] or \
       parsed.hostname.startswith('192.168.') or \
       parsed.hostname.startswith('10.'):
        raise ValueError("Access to internal networks not allowed")
    
    # Only allow HTTP/HTTPS
    if parsed.scheme not in ['http', 'https']:
        raise ValueError("Only HTTP/HTTPS protocols allowed")
    
    return requests.get(url, timeout=5)
```

---

## 3. Secure Software Development Lifecycle (SSDLC)

### 📋 SSDLC Phases

#### 1. **Planning and Requirements**
- Security requirements gathering
- Threat modeling
- Risk assessment
- Compliance requirements

#### 2. **Design**
- Security architecture review
- Secure design patterns
- Attack surface analysis
- Security controls design

#### 3. **Implementation**
- Secure coding practices
- Code reviews
- Static analysis
- Unit testing with security focus

#### 4. **Testing**
- Dynamic application security testing (DAST)
- Interactive application security testing (IAST)
- Penetration testing
- Security regression testing

#### 5. **Deployment**
- Security configuration
- Infrastructure security
- Deployment security
- Security monitoring setup

#### 6. **Maintenance**
- Security monitoring
- Incident response
- Security updates
- Continuous security assessment

---

## 4. Basic Testing Methodologies

### 🔍 Static Application Security Testing (SAST)

**Description:** Analyzes source code for security vulnerabilities without executing the program.

**Advantages:**
- Early detection in development cycle
- Complete code coverage
- Identifies exact location of vulnerabilities

**Tools:**
- SonarQube
- Checkmarx
- Veracode
- Bandit (Python)

### 🔍 Dynamic Application Security Testing (DAST)

**Description:** Tests running applications for security vulnerabilities.

**Advantages:**
- Tests real runtime behavior
- No source code required
- Identifies configuration issues

**Tools:**
- OWASP ZAP
- Burp Suite
- Nessus
- Acunetix

### 🔍 Interactive Application Security Testing (IAST)

**Description:** Combines SAST and DAST approaches by analyzing code during runtime.

**Advantages:**
- Low false positives
- Real-time feedback
- Accurate vulnerability detection

---

## 5. Authentication and Authorization Fundamentals

### 🔐 Authentication

**Definition:** Process of verifying the identity of a user or system.

#### Authentication Factors

1. **Something you know** (Knowledge)
   - Passwords
   - PINs
   - Security questions

2. **Something you have** (Possession)
   - Smart cards
   - Mobile phones
   - Hardware tokens

3. **Something you are** (Inherence)
   - Fingerprints
   - Retina scans
   - Voice recognition

#### Multi-Factor Authentication (MFA)

```python
# Example: MFA implementation
class MFAService:
    def __init__(self):
        self.totp = pyotp.TOTP('base32secret')
    
    def verify_password(self, username, password):
        user = User.get_by_username(username)
        return user and bcrypt.checkpw(password.encode(), user.password_hash)
    
    def verify_totp(self, token):
        return self.totp.verify(token)
    
    def authenticate(self, username, password, totp_token):
        return (self.verify_password(username, password) and 
                self.verify_totp(totp_token))
```

### 🔒 Authorization

**Definition:** Process of determining what actions an authenticated user is allowed to perform.

#### Authorization Models

1. **Role-Based Access Control (RBAC)**
```python
class RBACService:
    def __init__(self):
        self.roles = {
            'admin': ['read', 'write', 'delete'],
            'user': ['read'],
            'moderator': ['read', 'write']
        }
    
    def has_permission(self, user_role, action):
        return action in self.roles.get(user_role, [])
```

2. **Attribute-Based Access Control (ABAC)**
```python
def check_access(user, resource, action, environment):
    # Check user attributes
    if user.department != resource.department:
        return False
    
    # Check time-based access
    if environment.time < 9 or environment.time > 17:
        return False
    
    # Check action permissions
    return action in user.permissions
```

---

## 6. Session Management Security

### 🍪 Secure Session Implementation

```python
# Example: Secure session configuration
from flask import Flask, session
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Secure session configuration
app.config.update(
    SESSION_COOKIE_SECURE=True,      # HTTPS only
    SESSION_COOKIE_HTTPONLY=True,    # No JavaScript access
    SESSION_COOKIE_SAMESITE='Lax',   # CSRF protection
    PERMANENT_SESSION_LIFETIME=1800  # 30 minutes
)

@app.before_request
def regenerate_session():
    if 'user_id' in session:
        # Regenerate session ID periodically
        if session.get('last_regeneration', 0) + 300 < time.time():
            session.regenerate()
            session['last_regeneration'] = time.time()
```

### 🔄 Session Lifecycle

1. **Session Creation**
   - Generate cryptographically secure session ID
   - Set secure cookie attributes
   - Initialize session data

2. **Session Validation**
   - Verify session ID format
   - Check session expiration
   - Validate session data integrity

3. **Session Termination**
   - Clear session data
   - Invalidate session ID
   - Remove session cookie

---

## 7. Input Validation and Output Encoding

### ✅ Input Validation

```python
# Example: Comprehensive input validation
import re
from html import escape

class InputValidator:
    @staticmethod
    def validate_email(email):
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    @staticmethod
    def validate_username(username):
        # Allow only alphanumeric and underscore, 3-20 characters
        pattern = r'^[a-zA-Z0-9_]{3,20}$'
        return re.match(pattern, username) is not None
    
    @staticmethod
    def sanitize_input(user_input, max_length=255):
        # Remove dangerous characters
        sanitized = re.sub(r'[<>"\'\/]', '', user_input)
        return sanitized[:max_length]
```

### 🔒 Output Encoding

```python
# Example: Context-aware output encoding
from html import escape
import json
import urllib.parse

class OutputEncoder:
    @staticmethod
    def html_encode(text):
        return escape(text)
    
    @staticmethod
    def javascript_encode(text):
        return json.dumps(text)
    
    @staticmethod
    def url_encode(text):
        return urllib.parse.quote(text)
    
    @staticmethod
    def css_encode(text):
        # Remove potentially dangerous CSS characters
        return re.sub(r'[^a-zA-Z0-9\s-]', '', text)
```

---

## 8. Application Security Tools

### 🛠️ Static Analysis Tools

| Tool | Language | Type | Description |
|------|----------|------|-------------|
| **Bandit** | Python | SAST | Security linter for Python |
| **ESLint Security** | JavaScript | SAST | Security rules for ESLint |
| **Brakeman** | Ruby | SAST | Static analysis for Rails |
| **SonarQube** | Multi | SAST | Code quality and security |

### 🛠️ Dynamic Analysis Tools

| Tool | Type | Description |
|------|------|-------------|
| **OWASP ZAP** | DAST | Free web application scanner |
| **Burp Suite** | DAST | Professional web security testing |
| **Nikto** | DAST | Web server scanner |
| **SQLMap** | DAST | SQL injection testing tool |

### 🛠️ Dependency Scanning

```bash
# Example: Dependency vulnerability scanning

# Python
pip install safety
safety check

# Node.js
npm audit
npm audit fix

# Ruby
bundle audit

# Java
./mvnw org.owasp:dependency-check-maven:check
```

---

## 9. Best Practices and Resources

### 🎯 Security Best Practices

1. **Principle of Least Privilege**
   - Grant minimum necessary permissions
   - Regular access reviews
   - Time-limited access

2. **Defense in Depth**
   - Multiple security layers
   - Fail-safe defaults
   - Redundant controls

3. **Security by Design**
   - Security requirements from start
   - Threat modeling
   - Secure architecture

4. **Regular Security Testing**
   - Automated security scans
   - Manual penetration testing
   - Code reviews

### 📚 Learning Resources

#### 🌐 Online Platforms
- [OWASP WebGoat](https://owasp.org/www-project-webgoat/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackerOne Hacker101](https://www.hacker101.com/)
- [TryHackMe](https://tryhackme.com/)

#### 📖 Recommended Reading
- "The Web Application Hacker's Handbook" by Dafydd Stuttard
- "Secure Coding: Principles and Practices" by Mark Graff
- "Application Security for the Android Platform" by Jeff Six

#### 🏆 Certifications
- **CSSLP** - Certified Secure Software Lifecycle Professional
- **GWEB** - GIAC Web Application Penetration Tester
- **OSWE** - Offensive Security Web Expert

---

## 🎓 Knowledge Check

### ❓ Quiz Questions

1. **Which OWASP Top 10 category covers SQL injection?**
   - a) Broken Access Control
   - b) Injection
   - c) Security Misconfiguration
   - d) Cryptographic Failures

2. **What is the main purpose of input validation?**
   - a) Improve performance
   - b) Prevent malicious input
   - c) Format data
   - d) Compress data

3. **Which authentication factor is "something you have"?**
   - a) Password
   - b) Fingerprint
   - c) Smart card
   - d) PIN

4. **What does SAST stand for?**
   - a) Static Application Security Testing
   - b) Secure Application Software Testing
   - c) System Application Security Tool
   - d) Software Application Security Test

5. **Which HTTP header helps prevent XSS attacks?**
   - a) Content-Type
   - b) Content-Security-Policy
   - c) Cache-Control
   - d) Accept-Encoding

### ✅ Answers
1. b) Injection
2. b) Prevent malicious input
3. c) Smart card
4. a) Static Application Security Testing
5. b) Content-Security-Policy

---

## 🎯 Next Steps

After completing this module, you should:

1. **Understand** common application vulnerabilities
2. **Implement** basic security controls
3. **Perform** basic security testing
4. **Apply** secure coding practices

**Ready for the next topic?** 🚀

Continue with [OWASP Top 10](./owasp-top10.md) for detailed vulnerability analysis!

---

*This document is part of the CyberSecurity 101 Roadmap. For the complete learning path, visit the [main repository](../../README.md).*