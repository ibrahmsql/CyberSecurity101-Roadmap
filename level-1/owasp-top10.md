# 🔟 Seviye 1 - OWASP Top 10 (2021)

> **Hedef**: Web uygulama güvenliğinin en kritik 10 riskini öğrenmek ve korunma yöntemlerini uygulamak

## 📚 İçindekiler

1. [OWASP Nedir?](#owasp-nedir)
2. [A01 - Broken Access Control](#a01---broken-access-control)
3. [A02 - Cryptographic Failures](#a02---cryptographic-failures)
4. [A03 - Injection](#a03---injection)
5. [A04 - Insecure Design](#a04---insecure-design)
6. [A05 - Security Misconfiguration](#a05---security-misconfiguration)
7. [A06 - Vulnerable Components](#a06---vulnerable-components)
8. [A07 - Authentication Failures](#a07---authentication-failures)
9. [A08 - Software Data Integrity Failures](#a08---software-data-integrity-failures)
10. [A09 - Security Logging Failures](#a09---security-logging-failures)
11. [A10 - Server-Side Request Forgery](#a10---server-side-request-forgery)
12. [Pratik Laboratuvarlar](#pratik-laboratuvarlar)

---

## 🏛️ OWASP Nedir?

**OWASP (Open Web Application Security Project)**, web uygulama güvenliğini geliştirmeye odaklanan kar amacı gütmeyen bir organizasyondur.

### 📊 OWASP Top 10 2021 Değişiklikleri

| 2017 | 2021 | Değişiklik |
|------|------|------------|
| A1 - Injection | A03 - Injection | ⬇️ 3. sıraya düştü |
| A2 - Broken Authentication | A07 - Authentication Failures | ⬇️ 7. sıraya düştü |
| A3 - Sensitive Data Exposure | A02 - Cryptographic Failures | ⬆️ 2. sıraya çıktı |
| - | A01 - Broken Access Control | 🆕 1. sıraya çıktı |
| - | A04 - Insecure Design | 🆕 Yeni kategori |
| - | A08 - Software Data Integrity | 🆕 Yeni kategori |
| - | A10 - SSRF | 🆕 Yeni kategori |

### 🎯 Risk Hesaplama Metodolojisi

```
Risk = Likelihood × Impact

Likelihood = Threat Agent × Weakness Prevalence × Weakness Detectability
Impact = Technical Impact × Business Impact
```

---

## 🚪 A01 - Broken Access Control

### 📋 Açıklama
Kullanıcıların yetkilerinin dışında işlemler yapabilmesi durumu.

### ⚠️ Yaygın Senaryolar

#### 1. **Vertical Privilege Escalation**
```php
// Güvensiz kod
if ($_SESSION['user_id']) {
    // Admin paneline erişim kontrolü yok
    include 'admin_panel.php';
}

// URL manipulation
http://example.com/admin.php  // Direkt erişim
```

#### 2. **Horizontal Privilege Escalation**
```php
// Güvensiz kod
$user_id = $_GET['user_id'];
$query = "SELECT * FROM users WHERE id = $user_id";

// Saldırı
http://example.com/profile.php?user_id=123  // Başka kullanıcının profili
```

#### 3. **IDOR (Insecure Direct Object Reference)**
```javascript
// Güvensiz API
GET /api/users/123/documents/456

// Saldırı: Document ID'yi değiştirme
GET /api/users/123/documents/789  // Başka kullanıcının dökümanı
```

#### 4. **Missing Function Level Access Control**
```html
<!-- Frontend'de gizlenen admin fonksiyonları -->
<div id="admin-panel" style="display:none;">
    <button onclick="deleteUser()">Delete User</button>
</div>

<!-- Saldırgan JavaScript console'dan çağırabilir -->
<script>
    deleteUser();  // Fonksiyon hala erişilebilir
</script>
```

### 🛡️ Korunma Yöntemleri

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

// Kullanım
$ac = new AccessControl($_SESSION['user_id']);
$ac->enforceAccess('user_profile', 'read');
```

#### **2. Secure Direct Object Reference**
```php
<?php
// Güvenli yaklaşım
function getDocument($documentId) {
    $userId = $_SESSION['user_id'];
    
    // Kullanıcının bu dökümanı görme yetkisi var mı?
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

#### **3. JWT ile Authorization**
```javascript
// JWT payload örneği
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

// Kullanım
app.get('/api/documents/:id', 
    authorize('documents', 'read'), 
    getDocument
);
```

---

## 🔐 A02 - Cryptographic Failures

### 📋 Açıklama
Şifreleme ile ilgili hatalar ve hassas verilerin korunmaması.

### ⚠️ Yaygın Senaryolar

#### 1. **Zayıf Şifreleme Algoritmaları**
```php
// ❌ Güvensiz
$password = md5($userPassword);  // MD5 kırılmış
$data = mcrypt_encrypt(MCRYPT_DES, $key, $data);  // DES zayıf

// ✅ Güvenli
$password = password_hash($userPassword, PASSWORD_ARGON2ID);
$data = openssl_encrypt($data, 'AES-256-GCM', $key, 0, $iv, $tag);
```

#### 2. **Hassas Verilerin Düz Metin Saklanması**
```sql
-- ❌ Güvensiz
CREATE TABLE users (
    id INT PRIMARY KEY,
    username VARCHAR(50),
    password VARCHAR(50),  -- Düz metin şifre
    credit_card VARCHAR(16)  -- Şifrelenmemiş kredi kartı
);

-- ✅ Güvenli
CREATE TABLE users (
    id INT PRIMARY KEY,
    username VARCHAR(50),
    password_hash VARCHAR(255),  -- Hash'lenmiş şifre
    credit_card_encrypted BLOB  -- Şifrelenmiş kredi kartı
);
```

#### 3. **Zayıf Rastgele Sayı Üretimi**
```php
// ❌ Güvensiz
$token = md5(time() . rand());
$sessionId = uniqid();

// ✅ Güvenli
$token = bin2hex(random_bytes(32));
$sessionId = bin2hex(random_bytes(16));
```

#### 4. **HTTPS Kullanmama**
```javascript
// ❌ Güvensiz
fetch('http://api.example.com/login', {
    method: 'POST',
    body: JSON.stringify({ username, password })
});

// ✅ Güvenli
fetch('https://api.example.com/login', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'Strict-Transport-Security': 'max-age=31536000'
    },
    body: JSON.stringify({ username, password })
});
```

### 🛡️ Korunma Yöntemleri

#### **1. Güçlü Şifreleme Implementasyonu**
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
        """Güvenli şifre hash'leme"""
        if salt is None:
            salt = secrets.token_bytes(32)
        
        # PBKDF2 ile key derivation
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
        """Şifre doğrulama"""
        key, _ = SecureCrypto.hash_password(password, salt)
        return secrets.compare_digest(key, hashed)
    
    @staticmethod
    def encrypt_data(data: str, key: bytes = None) -> tuple:
        """Veri şifreleme"""
        if key is None:
            key = Fernet.generate_key()
        
        f = Fernet(key)
        encrypted = f.encrypt(data.encode())
        return encrypted, key
    
    @staticmethod
    def decrypt_data(encrypted_data: bytes, key: bytes) -> str:
        """Veri şifre çözme"""
        f = Fernet(key)
        decrypted = f.decrypt(encrypted_data)
        return decrypted.decode()

# Kullanım örneği
password = "user_password_123"
hashed_password, salt = SecureCrypto.hash_password(password)

# Veritabanında sakla: hashed_password, salt

# Doğrulama
is_valid = SecureCrypto.verify_password(password, hashed_password, salt)
```

#### **2. TLS/SSL Konfigürasyonu**
```nginx
# nginx.conf - Güvenli HTTPS konfigürasyonu
server {
    listen 443 ssl http2;
    server_name example.com;
    
    # SSL Sertifikaları
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/private.key;
    
    # Güvenli SSL protokolleri
    ssl_protocols TLSv1.2 TLSv1.3;
    
    # Güvenli cipher suites
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

# HTTP'den HTTPS'e yönlendirme
server {
    listen 80;
    server_name example.com;
    return 301 https://$server_name$request_uri;
}
```

---

## 💉 A03 - Injection

### 📋 Açıklama
Kullanıcı girdilerinin güvenilir olmayan şekilde işlenmesi sonucu oluşan güvenlik açıkları.

### ⚠️ Injection Türleri

#### 1. **SQL Injection**
```php
// ❌ Güvensiz kod
$username = $_POST['username'];
$password = $_POST['password'];

$query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
$result = mysqli_query($connection, $query);

// Saldırı payload'ı
// username: admin' --
// password: anything
// Sonuç: SELECT * FROM users WHERE username = 'admin' -- ' AND password = 'anything'
```

**SQL Injection Türleri**:
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
// ❌ Güvensiz MongoDB sorgusu
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    
    db.users.findOne({
        username: username,
        password: password
    });
});

// Saldırı payload'ı
// POST /login
// {
//   "username": {"$ne": null},
//   "password": {"$ne": null}
// }
```

#### 3. **Command Injection**
```php
// ❌ Güvensiz kod
$filename = $_GET['file'];
system("cat /var/logs/" . $filename);

// Saldırı
// ?file=access.log; cat /etc/passwd
// Sonuç: cat /var/logs/access.log; cat /etc/passwd
```

#### 4. **LDAP Injection**
```java
// ❌ Güvensiz LDAP sorgusu
String filter = "(&(uid=" + username + ")(password=" + password + "))";
NamingEnumeration results = ctx.search("ou=users,dc=example,dc=com", filter, controls);

// Saldırı
// username: admin)(|(uid=*
// password: anything
// Sonuç: (&(uid=admin)(|(uid=*)(password=anything))
```

### 🛡️ Korunma Yöntemleri

#### **1. Parametreli Sorgular (Prepared Statements)**
```php
<?php
// ✅ Güvenli SQL sorgusu
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

#### **2. Input Validation ve Sanitization**
```python
import re
import html
from typing import Optional

class InputValidator:
    @staticmethod
    def validate_email(email: str) -> bool:
        """Email format doğrulama"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    @staticmethod
    def validate_username(username: str) -> bool:
        """Kullanıcı adı doğrulama"""
        # Sadece alfanumerik karakterler ve alt çizgi
        pattern = r'^[a-zA-Z0-9_]{3,20}$'
        return bool(re.match(pattern, username))
    
    @staticmethod
    def sanitize_html(input_str: str) -> str:
        """HTML karakterlerini escape etme"""
        return html.escape(input_str)
    
    @staticmethod
    def validate_file_path(file_path: str) -> bool:
        """Dosya yolu doğrulama (Path Traversal koruması)"""
        # .. ve / karakterlerini kontrol et
        if '..' in file_path or file_path.startswith('/'):
            return False
        
        # Sadece alfanumerik, nokta ve alt çizgi
        pattern = r'^[a-zA-Z0-9._-]+$'
        return bool(re.match(pattern, file_path))
    
    @staticmethod
    def validate_sql_input(input_str: str) -> str:
        """SQL injection koruması için input temizleme"""
        # Tehlikeli karakterleri kaldır
        dangerous_chars = ["'", '"', ';', '--', '/*', '*/', 'xp_', 'sp_']
        
        for char in dangerous_chars:
            input_str = input_str.replace(char, '')
        
        return input_str.strip()

# Kullanım örneği
validator = InputValidator()

# Form verilerini doğrula
username = request.form.get('username')
if not validator.validate_username(username):
    raise ValueError("Invalid username format")

email = request.form.get('email')
if not validator.validate_email(email):
    raise ValueError("Invalid email format")
```

#### **3. ORM Kullanımı**
```python
# Django ORM - Güvenli sorgu
from django.contrib.auth import authenticate
from django.db import models

class User(models.Model):
    username = models.CharField(max_length=150, unique=True)
    email = models.EmailField()
    password = models.CharField(max_length=128)
    
    def authenticate_user(username, password):
        # Django ORM otomatik olarak SQL injection'dan korur
        user = User.objects.filter(username=username).first()
        if user and user.check_password(password):
            return user
        return None

# SQLAlchemy ORM - Güvenli sorgu
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine

class UserService:
    def __init__(self, database_url):
        self.engine = create_engine(database_url)
        Session = sessionmaker(bind=self.engine)
        self.session = Session()
    
    def get_user_by_id(self, user_id):
        # Parametreli sorgu otomatik olarak oluşturulur
        return self.session.query(User).filter(User.id == user_id).first()
    
    def search_users(self, search_term):
        # LIKE sorgusu bile güvenli
        return self.session.query(User).filter(
            User.username.like(f"%{search_term}%")
        ).all()
```

#### **4. Command Injection Koruması**
```python
import subprocess
import shlex
from pathlib import Path

class SecureCommandExecutor:
    ALLOWED_COMMANDS = ['ls', 'cat', 'grep', 'head', 'tail']
    SAFE_DIRECTORY = '/var/safe_logs/'
    
    @staticmethod
    def execute_safe_command(command, filename):
        """Güvenli komut çalıştırma"""
        # Komut whitelist kontrolü
        if command not in SecureCommandExecutor.ALLOWED_COMMANDS:
            raise ValueError(f"Command '{command}' not allowed")
        
        # Dosya yolu doğrulama
        safe_path = Path(SecureCommandExecutor.SAFE_DIRECTORY) / filename
        if not safe_path.exists() or not str(safe_path).startswith(SecureCommandExecutor.SAFE_DIRECTORY):
            raise ValueError("Invalid file path")
        
        # Güvenli komut oluşturma
        cmd_args = [command, str(safe_path)]
        
        try:
            # subprocess ile güvenli çalıştırma
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

# Kullanım
executor = SecureCommandExecutor()
try:
    output = executor.execute_safe_command('cat', 'access.log')
    print(output)
except (ValueError, RuntimeError) as e:
    print(f"Error: {e}")
```

---

## 🏗️ A04 - Insecure Design

### 📋 Açıklama
Güvenlik tasarımının eksik veya yetersiz olması durumu.

### ⚠️ Yaygın Senaryolar

#### 1. **Yetersiz Threat Modeling**
```python
# ❌ Güvensiz tasarım - Threat modeling yapılmamış
class BankTransfer:
    def transfer_money(self, from_account, to_account, amount):
        # Sadece bakiye kontrolü
        if self.get_balance(from_account) >= amount:
            self.deduct_balance(from_account, amount)
            self.add_balance(to_account, amount)
            return True
        return False

# Eksik kontroller:
# - Günlük transfer limiti
# - Şüpheli aktivite tespiti
# - Multi-factor authentication
# - Transaction logging
# - Fraud detection
```

#### 2. **Güvenlik Kontrollerinin Bypass Edilebilmesi**
```javascript
// ❌ Güvensiz tasarım
class UserRegistration {
    validateAge(birthDate) {
        const age = this.calculateAge(birthDate);
        if (age < 18) {
            // Sadece frontend uyarısı
            alert('You must be 18 or older');
            return false;
        }
        return true;
    }
    
    register(userData) {
        // Backend'de yaş kontrolü yok!
        if (this.validateAge(userData.birthDate)) {
            this.createUser(userData);
        }
    }
}
```

### 🛡️ Güvenli Tasarım Prensipleri

#### **1. Secure by Design**
```python
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional
import logging

class TransactionStatus(Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    UNDER_REVIEW = "under_review"

class SecurityLevel(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

class SecureBankTransfer:
    def __init__(self):
        self.daily_limits = {
            'standard': 1000,
            'premium': 5000,
            'business': 50000
        }
        self.fraud_detector = FraudDetectionService()
        self.audit_logger = AuditLogger()
    
    def transfer_money(self, from_account, to_account, amount, user_session):
        """Güvenli para transferi"""
        try:
            # 1. Kimlik doğrulama kontrolü
            if not self._verify_session(user_session):
                raise SecurityException("Invalid session")
            
            # 2. Yetkilendirme kontrolü
            if not self._check_transfer_permission(from_account, user_session.user_id):
                raise SecurityException("Unauthorized transfer")
            
            # 3. İş kuralları kontrolü
            self._validate_transfer_rules(from_account, to_account, amount)
            
            # 4. Fraud detection
            risk_level = self.fraud_detector.assess_risk(from_account, to_account, amount)
            
            # 5. Risk seviyesine göre işlem
            if risk_level == SecurityLevel.CRITICAL:
                return self._reject_transfer("High risk transaction")
            elif risk_level in [SecurityLevel.HIGH, SecurityLevel.MEDIUM]:
                return self._require_additional_verification(from_account, to_account, amount)
            
            # 6. Transfer işlemi
            transaction_id = self._execute_transfer(from_account, to_account, amount)
            
            # 7. Audit logging
            self.audit_logger.log_transfer(user_session.user_id, from_account, to_account, amount, transaction_id)
            
            return {
                'status': 'success',
                'transaction_id': transaction_id,
                'message': 'Transfer completed successfully'
            }
            
        except SecurityException as e:
            self.audit_logger.log_security_event(user_session.user_id, str(e))
            raise
        except Exception as e:
            self.audit_logger.log_error(user_session.user_id, str(e))
            raise
    
    def _validate_transfer_rules(self, from_account, to_account, amount):
        """İş kuralları doğrulama"""
        # Bakiye kontrolü
        if self.get_balance(from_account) < amount:
            raise BusinessRuleException("Insufficient funds")
        
        # Günlük limit kontrolü
        daily_total = self.get_daily_transfer_total(from_account)
        account_type = self.get_account_type(from_account)
        
        if daily_total + amount > self.daily_limits[account_type]:
            raise BusinessRuleException("Daily transfer limit exceeded")
        
        # Minimum/maksimum tutar kontrolü
        if amount < 1 or amount > 100000:
            raise BusinessRuleException("Invalid transfer amount")
        
        # Kendi hesabına transfer kontrolü
        if from_account == to_account:
            raise BusinessRuleException("Cannot transfer to same account")
```

#### **2. Defense in Depth Implementation**
```python
class SecureUserRegistration:
    def __init__(self):
        self.rate_limiter = RateLimiter()
        self.captcha_service = CaptchaService()
        self.email_verifier = EmailVerificationService()
        self.audit_logger = AuditLogger()
    
    def register_user(self, registration_data, client_ip):
        """Çok katmanlı güvenlik ile kullanıcı kaydı"""
        
        # Katman 1: Rate limiting
        if not self.rate_limiter.allow_request(client_ip, 'registration'):
            raise SecurityException("Too many registration attempts")
        
        # Katman 2: CAPTCHA doğrulama
        if not self.captcha_service.verify(registration_data.captcha_token):
            raise SecurityException("Invalid CAPTCHA")
        
        # Katman 3: Input validation
        self._validate_registration_data(registration_data)
        
        # Katman 4: Business rules
        self._check_business_rules(registration_data)
        
        # Katman 5: Duplicate check
        if self._user_exists(registration_data.email):
            # Güvenlik için aynı mesajı ver
            return {'status': 'success', 'message': 'Verification email sent'}
        
        # Katman 6: Secure user creation
        user_id = self._create_user_securely(registration_data)
        
        # Katman 7: Email verification
        self.email_verifier.send_verification_email(registration_data.email, user_id)
        
        # Katman 8: Audit logging
        self.audit_logger.log_registration(user_id, client_ip)
        
        return {
            'status': 'success',
            'message': 'Registration successful. Please verify your email.'
        }
    
    def _validate_registration_data(self, data):
        """Kapsamlı input validation"""
        validators = [
            ('email', self._validate_email),
            ('password', self._validate_password),
            ('age', self._validate_age),
            ('phone', self._validate_phone)
        ]
        
        for field, validator in validators:
            if not validator(getattr(data, field)):
                raise ValidationException(f"Invalid {field}")
    
    def _validate_age(self, birth_date):
        """Server-side yaş doğrulama"""
        if not birth_date:
            return False
        
        today = datetime.now().date()
        age = today.year - birth_date.year
        
        # Doğum günü henüz gelmemişse yaşı bir azalt
        if today < birth_date.replace(year=today.year):
            age -= 1
        
        return age >= 18
```

---

## ⚙️ A05 - Security Misconfiguration

### 📋 Açıklama
Güvenlik ayarlarının yanlış yapılandırılması veya varsayılan ayarların kullanılması.

### ⚠️ Yaygın Senaryolar

#### 1. **Varsayılan Kimlik Bilgileri**
```bash
# ❌ Yaygın varsayılan kimlik bilgileri
Username: admin, Password: admin
Username: root, Password: root
Username: admin, Password: password
Username: admin, Password: 123456

# Database varsayılan ayarları
MySQL: root / (boş şifre)
PostgreSQL: postgres / postgres
MongoDB: (authentication disabled)
```

#### 2. **Gereksiz Servisler ve Özellikler**
```apache
# ❌ Apache güvensiz konfigürasyon
<Directory "/var/www/html">
    Options Indexes FollowSymLinks  # Directory listing aktif
    AllowOverride All
    Require all granted
</Directory>

# Server bilgilerini gösterme
ServerTokens Full  # Apache/2.4.41 (Ubuntu) PHP/7.4.3
ServerSignature On

# Gereksiz modüller
LoadModule status_module modules/mod_status.so
LoadModule info_module modules/mod_info.so
```

#### 3. **Hata Mesajlarında Bilgi Sızıntısı**
```php
// ❌ Detaylı hata mesajları production'da
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// SQL hata mesajları
try {
    $pdo = new PDO($dsn, $username, $password);
} catch (PDOException $e) {
    die('Connection failed: ' . $e->getMessage());  // Database bilgileri sızıyor
}
```

### 🛡️ Güvenli Konfigürasyon

#### **1. Web Server Hardening**
```nginx
# nginx güvenli konfigürasyon
server {
    listen 443 ssl http2;
    server_name example.com;
    
    # Server bilgilerini gizle
    server_tokens off;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # Dosya upload limiti
    client_max_body_size 10M;
    
    # Timeout ayarları
    client_body_timeout 12;
    client_header_timeout 12;
    keepalive_timeout 15;
    send_timeout 10;
    
    # Rate limiting
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;
    
    location /login {
        limit_req zone=login burst=5 nodelay;
        proxy_pass http://backend;
    }
    
    # Hassas dosyaları gizle
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }
    
    location ~ \.(sql|log|conf)$ {
        deny all;
        access_log off;
        log_not_found off;
    }
    
    # PHP güvenlik
    location ~ \.php$ {
        fastcgi_hide_header X-Powered-By;
        fastcgi_param HTTP_PROXY "";
        include fastcgi_params;
        fastcgi_pass unix:/var/run/php/php7.4-fpm.sock;
    }
}
```

#### **2. Database Hardening**
```sql
-- MySQL güvenli konfigürasyon

-- 1. Varsayılan kullanıcıları kaldır
DROP USER IF EXISTS ''@'localhost';
DROP USER IF EXISTS ''@'%';
DROP USER IF EXISTS 'root'@'%';

-- 2. Güvenli kullanıcı oluştur
CREATE USER 'app_user'@'localhost' IDENTIFIED BY 'strong_random_password_123!';

-- 3. Minimum yetki ver
GRANT SELECT, INSERT, UPDATE, DELETE ON app_database.* TO 'app_user'@'localhost';

-- 4. Test veritabanını kaldır
DROP DATABASE IF EXISTS test;

-- 5. Güvenlik ayarları
SET GLOBAL log_error_verbosity = 2;
SET GLOBAL general_log = OFF;
SET GLOBAL slow_query_log = ON;
SET GLOBAL long_query_time = 2;

-- 6. SSL zorunlu kıl
ALTER USER 'app_user'@'localhost' REQUIRE SSL;

FLUSH PRIVILEGES;
```

#### **3. Application Security Configuration**
```python
# Django güvenli ayarlar
# settings.py

import os
from pathlib import Path

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY')

# Host validation
ALLOWED_HOSTS = ['yourdomain.com', 'www.yourdomain.com']

# Database
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.environ.get('DB_NAME'),
        'USER': os.environ.get('DB_USER'),
        'PASSWORD': os.environ.get('DB_PASSWORD'),
        'HOST': os.environ.get('DB_HOST', 'localhost'),
        'PORT': os.environ.get('DB_PORT', '5432'),
        'OPTIONS': {
            'sslmode': 'require',
        },
    }
}

# Security settings
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# Content Security Policy
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'", "'unsafe-inline'")
CSP_STYLE_SRC = ("'self'", "'unsafe-inline'")
CSP_IMG_SRC = ("'self'", "data:", "https:")

# Session security
SESSION_COOKIE_AGE = 3600  # 1 hour
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {
            'min_length': 12,
        }
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Logging
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': '/var/log/django/django.log',
            'formatter': 'verbose',
        },
        'security': {
            'level': 'WARNING',
            'class': 'logging.FileHandler',
            'filename': '/var/log/django/security.log',
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['file'],
            'level': 'INFO',
            'propagate': True,
        },
        'django.security': {
            'handlers': ['security'],
            'level': 'WARNING',
            'propagate': False,
        },
    },
}
```

---

## 📦 A06 - Vulnerable and Outdated Components

### 📋 Açıklama
Güncel olmayan veya güvenlik açığı bulunan bileşenlerin kullanılması.

### ⚠️ Yaygın Senaryolar

#### 1. **Güncel Olmayan Framework'ler**
```json
// ❌ package.json - Eski ve güvenlik açığı bulunan paketler
{
  "dependencies": {
    "express": "3.21.2",        // CVE-2014-6393
    "lodash": "4.17.4",         // CVE-2019-10744
    "moment": "2.19.3",         // CVE-2017-18214
    "jquery": "1.12.4",         // CVE-2020-11022
    "bootstrap": "3.3.7",        // CVE-2019-8331
    "next-js": 15.x 14.x 11.1.4   // CVE-2025-29927 
  }
}
```

#### 2. **Güvenlik Açığı Bulunan Kütüphaneler**
```python
# ❌ requirements.txt - Güvenlik açığı bulunan Python paketleri
Django==2.1.0          # CVE-2019-6975
requests==2.18.4       # CVE-2018-18074
Pillow==5.2.0          # CVE-2019-16865
pyyaml==3.13           # CVE-2017-18342
sqlalchemy==1.2.0      # CVE-2019-7164
```

### 🛡️ Güvenli Bileşen Yönetimi

#### **1. Dependency Scanning**
```bash
# npm audit - Node.js güvenlik taraması
npm audit
npm audit fix
npm audit fix --force

# Yarn audit
yarn audit
yarn audit --level high

# Python - safety check
pip install safety
safety check
safety check --json

# Python - bandit static analysis
pip install bandit
bandit -r your_project/

# Ruby - bundler-audit
gem install bundler-audit
bundle-audit check
bundle-audit update

# Java - OWASP Dependency Check
mvn org.owasp:dependency-check-maven:check
```

#### **2. Automated Dependency Updates**
```yaml
# .github/workflows/dependency-update.yml
name: Dependency Update

on:
  schedule:
    - cron: '0 2 * * 1'  # Her Pazartesi saat 02:00
  workflow_dispatch:

jobs:
  update-dependencies:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'
          
      - name: Install dependencies
        run: npm ci
        
      - name: Run security audit
        run: |
          npm audit --audit-level high
          npm audit fix
          
      - name: Update dependencies
        run: |
          npx npm-check-updates -u
          npm install
          
      - name: Run tests
        run: npm test
        
      - name: Create Pull Request
        uses: peter-evans/create-pull-request@v4
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
          commit-message: 'chore: update dependencies'
          title: 'Automated dependency updates'
          body: |
            This PR updates dependencies to their latest versions.
            
            Please review the changes and ensure all tests pass.
```

#### **3. Dependency Pinning ve Lock Files**
```json
// package.json - Exact versioning
{
  "dependencies": {
    "express": "4.18.2",        // Exact version
    "lodash": "~4.17.21",       // Patch updates only
    "moment": "^2.29.4"         // Minor updates allowed
  },
  "engines": {
    "node": ">=16.0.0",
    "npm": ">=8.0.0"
  }
}

// package-lock.json otomatik olarak oluşturulur ve commit edilmelidir
```

```python
# requirements.txt - Pinned versions
Django==4.1.4
requests==2.28.1
Pillow==9.3.0
pyyaml==6.0
sqlalchemy==1.4.44

# requirements-dev.txt - Development dependencies
bandit==1.7.4
safety==2.3.1
pytest==7.2.0
black==22.10.0
flake8==5.0.4
```

#### **4. Container Security Scanning**
```dockerfile
# Dockerfile - Multi-stage build ile güvenlik
FROM node:18-alpine AS builder

# Security: Non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nextjs -u 1001

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production && npm cache clean --force

# Production stage
FROM node:18-alpine AS runner

# Security updates
RUN apk update && apk upgrade && apk add --no-cache dumb-init

# Non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nextjs -u 1001

WORKDIR /app

# Copy files with correct ownership
COPY --from=builder --chown=nextjs:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=nextjs:nodejs /app/package.json ./package.json

USER nextjs

EXPOSE 3000

# Use dumb-init for proper signal handling
ENTRYPOINT ["dumb-init", "--"]
CMD ["npm", "start"]
```

```bash
# Container security scanning
# Trivy
trivy image your-image:latest

# Clair
clair-scanner --ip your-ip your-image:latest

# Snyk
snyk container test your-image:latest

# Docker Bench Security
docker run -it --net host --pid host --userns host --cap-add audit_control \
    -e DOCKER_CONTENT_TRUST=$DOCKER_CONTENT_TRUST \
    -v /etc:/etc:ro \
    -v /usr/bin/containerd:/usr/bin/containerd:ro \
    -v /usr/bin/runc:/usr/bin/runc:ro \
    -v /usr/lib/systemd:/usr/lib/systemd:ro \
    -v /var/lib:/var/lib:ro \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    --label docker_bench_security \
    docker/docker-bench-security
```

---

## 🔐 A07 - Identification and Authentication Failures

### 📋 Açıklama
Kimlik doğrulama ve oturum yönetimi ile ilgili güvenlik açıkları.

### ⚠️ Yaygın Senaryolar

#### 1. **Zayıf Şifre Politikaları**
```python
# ❌ Zayıf şifre kontrolü
def validate_password(password):
    if len(password) >= 6:  # Çok kısa minimum uzunluk
        return True
    return False

# ❌ Yaygın şifreler kontrolü yok
common_passwords = ["123456", "password", "admin"]
# Bu kontrol yapılmıyor
```

#### 2. **Güvensiz Session Management**
```php
// ❌ Güvensiz session yönetimi
session_start();

// Session ID regeneration yok
if (authenticate_user($username, $password)) {
    $_SESSION['user_id'] = $user_id;
    $_SESSION['username'] = $username;
    // Session fixation açığı
}

// Session timeout yok
// Logout'ta session destroy edilmiyor
```

#### 3. **Brute Force Koruması Yok**
```javascript
// ❌ Rate limiting yok
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    
    if (authenticateUser(username, password)) {
        res.json({ success: true });
    } else {
        res.json({ success: false, message: 'Invalid credentials' });
        // Başarısız deneme sayısı takip edilmiyor
    }
});
```

### 🛡️ Güvenli Authentication Implementation

#### **1. Güçlü Şifre Politikası**
```python
import re
import hashlib
from typing import List, Tuple

class PasswordValidator:
    def __init__(self):
        self.min_length = 12
        self.max_length = 128
        self.common_passwords = self._load_common_passwords()
    
    def validate_password(self, password: str, user_info: dict = None) -> Tuple[bool, List[str]]:
        """Kapsamlı şifre doğrulama"""
        errors = []
        
        # Uzunluk kontrolü
        if len(password) < self.min_length:
            errors.append(f"Password must be at least {self.min_length} characters long")
        
        if len(password) > self.max_length:
            errors.append(f"Password must not exceed {self.max_length} characters")
        
        # Karmaşıklık kontrolü
        if not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")
        
        if not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")
        
        if not re.search(r'\d', password):
            errors.append("Password must contain at least one digit")
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append("Password must contain at least one special character")
        
        # Yaygın şifre kontrolü
        if password.lower() in self.common_passwords:
            errors.append("Password is too common")
        
        # Kullanıcı bilgisi kontrolü
        if user_info:
            if self._contains_user_info(password, user_info):
                errors.append("Password must not contain personal information")
        
        # Tekrarlayan karakter kontrolü
        if self._has_repeated_chars(password):
            errors.append("Password must not contain repeated characters")
        
        return len(errors) == 0, errors
    
    def _load_common_passwords(self) -> set:
        """Yaygın şifreleri yükle"""
        common = {
            "123456", "password", "123456789", "12345678", "12345",
            "1234567", "1234567890", "qwerty", "abc123", "111111",
            "123123", "admin", "letmein", "welcome", "monkey",
            "dragon", "master", "sunshine", "princess", "football"
        }
        return common
    
    def _contains_user_info(self, password: str, user_info: dict) -> bool:
        """Şifrenin kullanıcı bilgisi içerip içermediğini kontrol et"""
        password_lower = password.lower()
        
        check_fields = ['username', 'email', 'first_name', 'last_name', 'phone']
        
        for field in check_fields:
            if field in user_info and user_info[field]:
                value = str(user_info[field]).lower()
                if len(value) >= 3 and value in password_lower:
                    return True
        
        return False
    
    def _has_repeated_chars(self, password: str, max_repeat: int = 3) -> bool:
        """Tekrarlayan karakter kontrolü"""
        count = 1
        for i in range(1, len(password)):
            if password[i] == password[i-1]:
                count += 1
                if count > max_repeat:
                    return True
            else:
                count = 1
        return False

# Kullanım
validator = PasswordValidator()
user_info = {
    'username': 'john_doe',
    'email': 'john@example.com',
    'first_name': 'John',
    'last_name': 'Doe'
}

is_valid, errors = validator.validate_password('MySecureP@ssw0rd123', user_info)
if not is_valid:
    for error in errors:
        print(f"❌ {error}")
```

#### **2. Güvenli Session Management**
```python
import secrets
import hashlib
import time
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

class SecureSessionManager:
    def __init__(self, redis_client, session_timeout: int = 3600):
        self.redis = redis_client
        self.session_timeout = session_timeout
        self.max_sessions_per_user = 5
    
    def create_session(self, user_id: str, user_agent: str, ip_address: str) -> str:
        """Güvenli session oluşturma"""
        # Session ID oluştur
        session_id = self._generate_session_id()
        
        # Session verilerini hazırla
        session_data = {
            'user_id': user_id,
            'created_at': time.time(),
            'last_activity': time.time(),
            'ip_address': ip_address,
            'user_agent': hashlib.sha256(user_agent.encode()).hexdigest()[:16],
            'csrf_token': secrets.token_urlsafe(32)
        }
        
        # Kullanıcının aktif session sayısını kontrol et
        self._cleanup_old_sessions(user_id)
        
        # Session'ı kaydet
        session_key = f"session:{session_id}"
        self.redis.hmset(session_key, session_data)
        self.redis.expire(session_key, self.session_timeout)
        
        # Kullanıcı session listesine ekle
        user_sessions_key = f"user_sessions:{user_id}"
        self.redis.sadd(user_sessions_key, session_id)
        self.redis.expire(user_sessions_key, self.session_timeout)
        
        return session_id
    
    def validate_session(self, session_id: str, ip_address: str, user_agent: str) -> Optional[Dict[str, Any]]:
        """Session doğrulama"""
        session_key = f"session:{session_id}"
        session_data = self.redis.hgetall(session_key)
        
        if not session_data:
            return None
        
        # IP adresi kontrolü
        if session_data.get('ip_address') != ip_address:
            self._invalidate_session(session_id)
            return None
        
        # User agent kontrolü
        ua_hash = hashlib.sha256(user_agent.encode()).hexdigest()[:16]
        if session_data.get('user_agent') != ua_hash:
            self._invalidate_session(session_id)
            return None
        
        # Session timeout kontrolü
        last_activity = float(session_data.get('last_activity', 0))
        if time.time() - last_activity > self.session_timeout:
            self._invalidate_session(session_id)
            return None
        
        # Last activity güncelle
        self.redis.hset(session_key, 'last_activity', time.time())
        self.redis.expire(session_key, self.session_timeout)
        
        return session_data
    
    def _generate_session_id(self) -> str:
        """Güvenli session ID oluştur"""
        return secrets.token_urlsafe(32)
    
    def _cleanup_old_sessions(self, user_id: str):
        """Eski session'ları temizle"""
        user_sessions_key = f"user_sessions:{user_id}"
        session_ids = self.redis.smembers(user_sessions_key)
        
        if len(session_ids) >= self.max_sessions_per_user:
            # En eski session'ları sil
            for session_id in list(session_ids)[:len(session_ids) - self.max_sessions_per_user + 1]:
                self._invalidate_session(session_id.decode())
    
    def _invalidate_session(self, session_id: str):
        """Session'ı geçersiz kıl"""
        session_key = f"session:{session_id}"
        session_data = self.redis.hgetall(session_key)
        
        if session_data and 'user_id' in session_data:
            user_id = session_data['user_id']
            user_sessions_key = f"user_sessions:{user_id}"
            self.redis.srem(user_sessions_key, session_id)
        
        self.redis.delete(session_key)
```

#### **3. Multi-Factor Authentication (MFA)**
```python
import pyotp
import qrcode
import io
import base64
from typing import Tuple, Optional

class MFAManager:
    def __init__(self):
        self.issuer_name = "YourApp"
    
    def generate_secret(self, user_email: str) -> Tuple[str, str]:
        """TOTP secret oluştur"""
        secret = pyotp.random_base32()
        
        # QR kod için URI oluştur
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=user_email,
            issuer_name=self.issuer_name
        )
        
        # QR kod oluştur
        qr_code = self._generate_qr_code(totp_uri)
        
        return secret, qr_code
    
    def verify_totp(self, secret: str, token: str) -> bool:
        """TOTP token doğrula"""
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=1)
    
    def generate_backup_codes(self, count: int = 10) -> List[str]:
        """Yedek kodlar oluştur"""
        codes = []
        for _ in range(count):
            code = secrets.token_hex(4).upper()
            codes.append(f"{code[:4]}-{code[4:]}")
        return codes
    
    def _generate_qr_code(self, data: str) -> str:
        """QR kod oluştur ve base64 string döndür"""
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(data)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Base64'e çevir
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        img_str = base64.b64encode(buffer.getvalue()).decode()
        
        return f"data:image/png;base64,{img_str}"

# SMS MFA Implementation
class SMSMFAManager:
    def __init__(self, twilio_client):
        self.twilio = twilio_client
        self.code_expiry = 300  # 5 dakika
    
    def send_sms_code(self, phone_number: str, user_id: str) -> bool:
        """SMS kodu gönder"""
        code = str(secrets.randbelow(900000) + 100000)  # 6 haneli kod
        
        try:
            # SMS gönder
            message = self.twilio.messages.create(
                body=f"Your verification code is: {code}",
                from_='+1234567890',
                to=phone_number
            )
            
            # Kodu Redis'te sakla
            redis_key = f"sms_code:{user_id}"
            self.redis.setex(redis_key, self.code_expiry, code)
            
            return True
        except Exception as e:
            print(f"SMS sending failed: {e}")
            return False
    
    def verify_sms_code(self, user_id: str, code: str) -> bool:
        """SMS kodu doğrula"""
        redis_key = f"sms_code:{user_id}"
        stored_code = self.redis.get(redis_key)
        
        if stored_code and stored_code.decode() == code:
            self.redis.delete(redis_key)
            return True
        
        return False
```

#### **4. Rate Limiting ve Brute Force Protection**
```python
import time
from typing import Optional
from dataclasses import dataclass

@dataclass
class RateLimitConfig:
    max_attempts: int
    window_seconds: int
    lockout_duration: int

class BruteForceProtection:
    def __init__(self, redis_client):
        self.redis = redis_client
        self.configs = {
            'login': RateLimitConfig(max_attempts=5, window_seconds=300, lockout_duration=900),
            'password_reset': RateLimitConfig(max_attempts=3, window_seconds=3600, lockout_duration=3600),
            'registration': RateLimitConfig(max_attempts=3, window_seconds=3600, lockout_duration=1800)
        }
    
    def check_rate_limit(self, identifier: str, action: str) -> Tuple[bool, Optional[int]]:
        """Rate limit kontrolü"""
        config = self.configs.get(action)
        if not config:
            return True, None
        
        # Lockout kontrolü
        lockout_key = f"lockout:{action}:{identifier}"
        if self.redis.exists(lockout_key):
            remaining_time = self.redis.ttl(lockout_key)
            return False, remaining_time
        
        # Attempt sayısını kontrol et
        attempts_key = f"attempts:{action}:{identifier}"
        current_attempts = self.redis.get(attempts_key)
        
        if current_attempts is None:
            current_attempts = 0
        else:
            current_attempts = int(current_attempts)
        
        if current_attempts >= config.max_attempts:
            # Lockout uygula
            self.redis.setex(lockout_key, config.lockout_duration, "locked")
            self.redis.delete(attempts_key)
            return False, config.lockout_duration
        
        return True, None
    
    def record_attempt(self, identifier: str, action: str, success: bool):
        """Deneme kaydı"""
        config = self.configs.get(action)
        if not config:
            return
        
        attempts_key = f"attempts:{action}:{identifier}"
        
        if success:
            # Başarılı giriş, sayacı sıfırla
            self.redis.delete(attempts_key)
        else:
            # Başarısız deneme, sayacı artır
            current_attempts = self.redis.incr(attempts_key)
            if current_attempts == 1:
                # İlk deneme, TTL set et
                self.redis.expire(attempts_key, config.window_seconds)

# Flask middleware örneği
from flask import request, jsonify
from functools import wraps

def rate_limit(action: str):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # IP adresini al
            ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
            
            # Rate limit kontrolü
            brute_force = BruteForceProtection(redis_client)
            allowed, remaining_time = brute_force.check_rate_limit(ip_address, action)
            
            if not allowed:
                return jsonify({
                    'error': 'Too many attempts',
                    'retry_after': remaining_time
                }), 429
            
            # Original fonksiyonu çalıştır
            try:
                result = f(*args, **kwargs)
                # Başarılı işlem
                brute_force.record_attempt(ip_address, action, True)
                return result
            except Exception as e:
                # Başarısız işlem
                brute_force.record_attempt(ip_address, action, False)
                raise
        
        return decorated_function
    return decorator

# Kullanım
@app.route('/login', methods=['POST'])
@rate_limit('login')
def login():
    # Login logic here
    pass
```

---

## 🔗 A08 - Software and Data Integrity Failures

### 📋 Açıklama
Yazılım güncellemeleri, kritik veriler ve CI/CD pipeline'ların bütünlüğünün doğrulanmaması.

### ⚠️ Yaygın Senaryolar

#### 1. **Güvenilmeyen Kaynaklardan Paket İndirme**
```bash
# ❌ Güvensiz paket indirme
curl -sSL https://get.docker.com/ | sh
wget -O- https://some-script.com/install.sh | bash

# ❌ Checksum doğrulama yok
wget https://releases.example.com/app.tar.gz
tar -xzf app.tar.gz
```

#### 2. **CI/CD Pipeline Güvenlik Açıkları**
```yaml
# ❌ Güvensiz GitHub Actions
name: Deploy
on:
  push:
    branches: [ main ]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      # Güvenlik açığı: Secrets hardcoded
      - name: Deploy
        run: |
          echo "API_KEY=sk-1234567890abcdef" > .env
          curl -X POST https://api.example.com/deploy \
            -H "Authorization: Bearer sk-1234567890abcdef"
```

### 🛡️ Güvenli Integrity Management

#### **1. Package Integrity Verification**
```bash
#!/bin/bash
# secure_install.sh - Güvenli paket kurulum scripti

set -euo pipefail

# Renk kodları
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging fonksiyonu
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

# GPG key doğrulama
verify_gpg_signature() {
    local file="$1"
    local signature="$2"
    local key_id="$3"
    
    log "Verifying GPG signature for $file"
    
    # GPG key'i import et
    gpg --keyserver keyserver.ubuntu.com --recv-keys "$key_id" || error "Failed to import GPG key"
    
    # İmzayı doğrula
    gpg --verify "$signature" "$file" || error "GPG signature verification failed"
    
    log "GPG signature verified successfully"
}

# Checksum doğrulama
verify_checksum() {
    local file="$1"
    local expected_hash="$2"
    local hash_type="${3:-sha256}"
    
    log "Verifying $hash_type checksum for $file"
    
    local actual_hash
    case "$hash_type" in
        "sha256")
            actual_hash=$(sha256sum "$file" | cut -d' ' -f1)
            ;;
        "sha512")
            actual_hash=$(sha512sum "$file" | cut -d' ' -f1)
            ;;
        "md5")
            warn "MD5 is deprecated, use SHA256 or SHA512"
            actual_hash=$(md5sum "$file" | cut -d' ' -f1)
            ;;
        *)
            error "Unsupported hash type: $hash_type"
            ;;
    esac
    
    if [ "$actual_hash" != "$expected_hash" ]; then
        error "Checksum verification failed!\nExpected: $expected_hash\nActual: $actual_hash"
    fi
    
    log "Checksum verified successfully"
}

# Güvenli download
secure_download() {
    local url="$1"
    local output_file="$2"
    local expected_hash="$3"
    local hash_type="${4:-sha256}"
    
    log "Downloading $url"
    
    # HTTPS zorunlu
    if [[ ! "$url" =~ ^https:// ]]; then
        error "Only HTTPS URLs are allowed"
    fi
    
    # Download with verification
    curl -fsSL \
        --max-time 300 \
        --retry 3 \
        --retry-delay 5 \
        --user-agent "SecureInstaller/1.0" \
        "$url" -o "$output_file" || error "Download failed"
    
    # Checksum doğrula
    verify_checksum "$output_file" "$expected_hash" "$hash_type"
}

# Docker image integrity
verify_docker_image() {
    local image="$1"
    local expected_digest="$2"
    
    log "Verifying Docker image: $image"
    
    # Image'ı digest ile pull et
    docker pull "$image@$expected_digest" || error "Failed to pull Docker image with digest"
    
    # Content trust aktif et
    export DOCKER_CONTENT_TRUST=1
    
    log "Docker image verified successfully"
}

# Örnek kullanım
main() {
    # Node.js güvenli kurulum
    NODE_VERSION="18.17.1"
    NODE_URL="https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.xz"
    NODE_HASH="8a2c9e0b8b5b8f8c8d8e8f8g8h8i8j8k8l8m8n8o8p8q8r8s8t8u8v8w8x8y8z"
    
    secure_download "$NODE_URL" "node.tar.xz" "$NODE_HASH" "sha256"
    
    # Docker image doğrulama
    NGINX_DIGEST="sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    verify_docker_image "nginx:1.21-alpine" "$NGINX_DIGEST"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
```

#### **2. Secure CI/CD Pipeline**
```yaml
# .github/workflows/secure-deploy.yml
name: Secure Deployment

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

env:
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        
      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          scan-ref: '.'
          format: 'sarif'
          output: 'trivy-results.sarif'
          
      - name: Upload Trivy scan results
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: 'trivy-results.sarif'
          
      - name: SAST with CodeQL
        uses: github/codeql-action/init@v2
        with:
          languages: javascript, python
          
      - name: Perform CodeQL Analysis
        uses: github/codeql-action/analyze@v2

  build:
    needs: security-scan
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
      
    steps:
      - name: Checkout
        uses: actions/checkout@v4
        
      - name: Setup Docker Buildx
        uses: docker/setup-buildx-action@v3
        
      - name: Log in to Container Registry
        uses: docker/login-action@v3
        with:
          registry: ${{ env.REGISTRY }}
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
          
      - name: Extract metadata
        id: meta
        uses: docker/metadata-action@v5
        with:
          images: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}
          tags: |
            type=ref,event=branch
            type=ref,event=pr
            type=sha,prefix={{branch}}-
            
      - name: Build and push Docker image
        uses: docker/build-push-action@v5
        with:
          context: .
          push: true
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
          cache-from: type=gha
          cache-to: type=gha,mode=max
          
      - name: Generate SBOM
        uses: anchore/sbom-action@v0
        with:
          image: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}
          format: spdx-json
          output-file: sbom.spdx.json
          
      - name: Upload SBOM
        uses: actions/upload-artifact@v3
        with:
          name: sbom
          path: sbom.spdx.json

  deploy:
    needs: build
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    environment: production
    
    steps:
      - name: Deploy to production
        env:
          DEPLOY_KEY: ${{ secrets.DEPLOY_KEY }}
          API_ENDPOINT: ${{ secrets.API_ENDPOINT }}
        run: |
          # Güvenli deployment script
          echo "Deploying with secure credentials"
          # Secrets environment variables olarak kullanılıyor
```

#### **3. Software Bill of Materials (SBOM)**
```python
# sbom_generator.py
import json
import subprocess
import hashlib
from datetime import datetime
from typing import Dict, List, Any

class SBOMGenerator:
    def __init__(self, project_name: str, project_version: str):
        self.project_name = project_name
        self.project_version = project_version
        self.sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "serialNumber": f"urn:uuid:{self._generate_uuid()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "tools": [
                    {
                        "vendor": "Custom",
                        "name": "SBOM Generator",
                        "version": "1.0.0"
                    }
                ],
                "component": {
                    "type": "application",
                    "name": project_name,
                    "version": project_version
                }
            },
            "components": []
        }
    
    def scan_npm_dependencies(self) -> List[Dict[str, Any]]:
        """NPM bağımlılıklarını tara"""
        try:
            result = subprocess.run(
                ['npm', 'list', '--json', '--all'],
                capture_output=True,
                text=True,
                check=True
            )
            
            npm_data = json.loads(result.stdout)
            components = []
            
            def extract_dependencies(deps: Dict, parent_name: str = None):
                for name, info in deps.items():
                    component = {
                        "type": "library",
                        "name": name,
                        "version": info.get('version', 'unknown'),
                        "purl": f"pkg:npm/{name}@{info.get('version', 'unknown')}",
                        "scope": "required"
                    }
                    
                    # Güvenlik açığı kontrolü
                    vulnerabilities = self._check_npm_vulnerabilities(name, info.get('version'))
                    if vulnerabilities:
                        component['vulnerabilities'] = vulnerabilities
                    
                    components.append(component)
                    
                    # Alt bağımlılıkları işle
                    if 'dependencies' in info:
                        extract_dependencies(info['dependencies'], name)
            
            if 'dependencies' in npm_data:
                extract_dependencies(npm_data['dependencies'])
            
            return components
            
        except subprocess.CalledProcessError as e:
            print(f"NPM scan failed: {e}")
            return []
    
    def scan_python_dependencies(self) -> List[Dict[str, Any]]:
        """Python bağımlılıklarını tara"""
        try:
            result = subprocess.run(
                ['pip', 'freeze'],
                capture_output=True,
                text=True,
                check=True
            )
            
            components = []
            for line in result.stdout.strip().split('\n'):
                if '==' in line:
                    name, version = line.split('==')
                    component = {
                        "type": "library",
                        "name": name,
                        "version": version,
                        "purl": f"pkg:pypi/{name}@{version}",
                        "scope": "required"
                    }
                    
                    # Güvenlik açığı kontrolü
                    vulnerabilities = self._check_python_vulnerabilities(name, version)
                    if vulnerabilities:
                        component['vulnerabilities'] = vulnerabilities
                    
                    components.append(component)
            
            return components
            
        except subprocess.CalledProcessError as e:
            print(f"Python scan failed: {e}")
            return []
    
    def _check_npm_vulnerabilities(self, package_name: str, version: str) -> List[Dict]:
        """NPM paket güvenlik açığı kontrolü"""
        try:
            result = subprocess.run(
                ['npm', 'audit', '--json'],
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                audit_data = json.loads(result.stdout)
                vulnerabilities = []
                
                for vuln_id, vuln_info in audit_data.get('vulnerabilities', {}).items():
                    if package_name in vuln_info.get('via', []):
                        vulnerabilities.append({
                            "id": vuln_id,
                            "source": {
                                "name": "NPM Audit",
                                "url": f"https://npmjs.com/advisories/{vuln_id}"
                            },
                            "ratings": [{
                                "severity": vuln_info.get('severity', 'unknown').upper(),
                                "method": "CVSSv3"
                            }],
                            "description": vuln_info.get('title', 'No description available')
                        })
                
                return vulnerabilities
            
        except Exception as e:
            print(f"Vulnerability check failed for {package_name}: {e}")
        
        return []
    
    def generate_sbom(self, output_file: str = "sbom.json"):
        """SBOM oluştur ve dosyaya yaz"""
        # NPM bağımlılıklarını ekle
        npm_components = self.scan_npm_dependencies()
        self.sbom['components'].extend(npm_components)
        
        # Python bağımlılıklarını ekle
        python_components = self.scan_python_dependencies()
        self.sbom['components'].extend(python_components)
        
        # SBOM'u dosyaya yaz
        with open(output_file, 'w') as f:
            json.dump(self.sbom, f, indent=2)
        
        # Checksum oluştur
        checksum = self._calculate_file_hash(output_file)
        
        print(f"SBOM generated: {output_file}")
        print(f"SHA256 checksum: {checksum}")
        
        # Checksum dosyası oluştur
        with open(f"{output_file}.sha256", 'w') as f:
            f.write(f"{checksum}  {output_file}\n")
    
    def _generate_uuid(self) -> str:
        """UUID oluştur"""
        import uuid
        return str(uuid.uuid4())
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Dosya hash'i hesapla"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

# Kullanım
if __name__ == "__main__":
    generator = SBOMGenerator("MySecureApp", "1.0.0")
    generator.generate_sbom("sbom.json")
```

---

## 📊 A09 - Security Logging and Monitoring Failures

### 📋 Açıklama
Yetersiz loglama, monitoring ve incident response yetenekleri.

### ⚠️ Yaygın Senaryolar

#### 1. **Yetersiz Loglama**
```python
# ❌ Yetersiz loglama
def login(username, password):
    user = authenticate(username, password)
    if user:
        return {"success": True}
    else:
        return {"success": False}  # Hangi kullanıcı, ne zaman, nereden?
```

#### 2. **Hassas Bilgilerin Loglanması**
```python
# ❌ Hassas bilgi sızıntısı
logging.info(f"User login attempt: {username}:{password}")  # Şifre loglanıyor!
logging.debug(f"Credit card: {credit_card_number}")  # Kredi kartı loglanıyor!
```

### 🛡️ Güvenli Logging Implementation

#### **1. Comprehensive Security Logging**
```python
import logging
import json
import hashlib
import time
from datetime import datetime
from typing import Dict, Any, Optional
from enum import Enum

class SecurityEventType(Enum):
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    PASSWORD_CHANGE = "password_change"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_ACCESS = "data_access"
    DATA_MODIFICATION = "data_modification"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    SECURITY_VIOLATION = "security_violation"
    SYSTEM_ERROR = "system_error"

class SecurityLogger:
    def __init__(self, logger_name: str = "security"):
        self.logger = logging.getLogger(logger_name)
        self.logger.setLevel(logging.INFO)
        
        # JSON formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # File handler
        file_handler = logging.FileHandler('/var/log/security/security.log')
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
        
        # SIEM handler (örnek)
        siem_handler = self._create_siem_handler()
        if siem_handler:
            self.logger.addHandler(siem_handler)
    
    def log_security_event(
        self,
        event_type: SecurityEventType,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        resource: Optional[str] = None,
        action: Optional[str] = None,
        result: str = "success",
        details: Optional[Dict[str, Any]] = None,
        risk_score: int = 0
    ):
        """Güvenlik olayı logla"""
        
        event_data = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event_id": self._generate_event_id(),
            "event_type": event_type.value,
            "result": result,
            "risk_score": risk_score,
            "source": {
                "ip_address": ip_address,
                "user_agent_hash": self._hash_user_agent(user_agent) if user_agent else None
            },
            "actor": {
                "user_id": user_id,
                "session_id": self._get_session_id()
            },
            "target": {
                "resource": resource,
                "action": action
            },
            "details": details or {}
        }
        
        # Hassas bilgileri temizle
        event_data = self._sanitize_log_data(event_data)
        
        # JSON formatında logla
        self.logger.info(json.dumps(event_data))
        
        # Yüksek risk olayları için alert
        if risk_score >= 8:
            self._send_security_alert(event_data)
    
    def log_authentication_event(
        self,
        username: str,
        success: bool,
        ip_address: str,
        user_agent: str,
        failure_reason: Optional[str] = None
    ):
        """Kimlik doğrulama olayı logla"""
        
        event_type = SecurityEventType.LOGIN_SUCCESS if success else SecurityEventType.LOGIN_FAILURE
        result = "success" if success else "failure"
        
        details = {
            "username_hash": hashlib.sha256(username.encode()).hexdigest()[:16],
            "authentication_method": "password"
        }
        
        if not success and failure_reason:
            details["failure_reason"] = failure_reason
        
        risk_score = 2 if success else 5
        
        self.log_security_event(
            event_type=event_type,
            user_id=username if success else None,
            ip_address=ip_address,
            user_agent=user_agent,
            resource="authentication",
            action="login",
            result=result,
            details=details,
            risk_score=risk_score
        )
    
    def log_data_access(
        self,
        user_id: str,
        resource_type: str,
        resource_id: str,
        action: str,
        ip_address: str,
        success: bool = True,
        sensitive_data: bool = False
    ):
        """Veri erişimi logla"""
        
        details = {
            "resource_type": resource_type,
            "resource_id": resource_id,
            "sensitive_data": sensitive_data
        }
        
        risk_score = 3
        if sensitive_data:
            risk_score = 6
        if not success:
            risk_score += 2
        
        self.log_security_event(
            event_type=SecurityEventType.DATA_ACCESS,
            user_id=user_id,
            ip_address=ip_address,
            resource=f"{resource_type}/{resource_id}",
            action=action,
            result="success" if success else "failure",
            details=details,
            risk_score=risk_score
        )
    
    def _sanitize_log_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Log verilerinden hassas bilgileri temizle"""
        sensitive_fields = [
            'password', 'credit_card', 'ssn', 'api_key', 'token',
            'secret', 'private_key', 'session_token'
        ]
        
        def sanitize_recursive(obj):
            if isinstance(obj, dict):
                return {
                    k: "[REDACTED]" if any(field in k.lower() for field in sensitive_fields)
                    else sanitize_recursive(v)
                    for k, v in obj.items()
                }
            elif isinstance(obj, list):
                return [sanitize_recursive(item) for item in obj]
            else:
                return obj
        
        return sanitize_recursive(data)
    
    def _hash_user_agent(self, user_agent: str) -> str:
        """User agent'ı hash'le (privacy için)"""
        return hashlib.sha256(user_agent.encode()).hexdigest()[:16]
    
    def _generate_event_id(self) -> str:
        """Unique event ID oluştur"""
        import uuid
        return str(uuid.uuid4())
    
    def _get_session_id(self) -> Optional[str]:
        """Mevcut session ID'yi al"""
        # Flask örneği
        try:
            from flask import session
            return session.get('session_id')
        except:
            return None
    
    def _create_siem_handler(self):
        """SIEM entegrasyonu için handler oluştur"""
        # Splunk, ELK, QRadar vb. entegrasyonu
        return None
    
    def _send_security_alert(self, event_data: Dict[str, Any]):
        """Yüksek risk olayları için alert gönder"""
        # Email, Slack, PagerDuty vb. entegrasyonu
        print(f"🚨 HIGH RISK SECURITY EVENT: {event_data['event_type']}")

# Kullanım örneği
security_logger = SecurityLogger()

# Login başarısız
security_logger.log_authentication_event(
    username="john_doe",
    success=False,
    ip_address="192.168.1.100",
    user_agent="Mozilla/5.0...",
    failure_reason="invalid_password"
)

# Hassas veri erişimi
security_logger.log_data_access(
    user_id="user_123",
    resource_type="customer_data",
    resource_id="cust_456",
    action="read",
    ip_address="192.168.1.100",
    sensitive_data=True
)
```

---

## 🌐 A10 - Server-Side Request Forgery (SSRF)

### 📋 Açıklama
Sunucu tarafında güvenilmeyen kullanıcı girdileri ile HTTP istekleri yapılması.

### ⚠️ Yaygın Senaryolar

#### 1. **URL Validation Eksikliği**
```python
# ❌ Güvensiz SSRF
import requests

def fetch_url(url):
    # Hiçbir doğrulama yok
    response = requests.get(url)
    return response.text

# Saldırı örnekleri:
# http://localhost:8080/admin
# http://169.254.169.254/latest/meta-data/  # AWS metadata
# file:///etc/passwd
# gopher://internal-server:6379/_INFO  # Redis
```

### 🛡️ SSRF Koruması

#### **1. Güvenli URL Validation**
```python
import ipaddress
import urllib.parse
import requests
from typing import List, Optional

class SSRFProtection:
    def __init__(self):
        self.allowed_schemes = ['http', 'https']
        self.blocked_ips = [
            ipaddress.ip_network('127.0.0.0/8'),    # Localhost
            ipaddress.ip_network('10.0.0.0/8'),     # Private
            ipaddress.ip_network('172.16.0.0/12'),  # Private
            ipaddress.ip_network('192.168.0.0/16'), # Private
            ipaddress.ip_network('169.254.0.0/16'), # Link-local
            ipaddress.ip_network('::1/128'),        # IPv6 localhost
            ipaddress.ip_network('fc00::/7'),       # IPv6 private
        ]
        self.allowed_domains = ['api.example.com', 'cdn.example.com']
        self.max_redirects = 3
        self.timeout = 10
    
    def validate_url(self, url: str) -> bool:
        """URL güvenlik doğrulaması"""
        try:
            parsed = urllib.parse.urlparse(url)
            
            # Scheme kontrolü
            if parsed.scheme not in self.allowed_schemes:
                return False
            
            # Domain whitelist kontrolü
            if parsed.hostname not in self.allowed_domains:
                return False
            
            # IP adresi kontrolü
            if self._is_blocked_ip(parsed.hostname):
                return False
            
            # Port kontrolü
            if parsed.port and parsed.port not in [80, 443]:
                return False
            
            return True
            
        except Exception:
            return False
    
    def _is_blocked_ip(self, hostname: str) -> bool:
        """IP adresinin bloklu olup olmadığını kontrol et"""
        try:
            ip = ipaddress.ip_address(hostname)
            for blocked_network in self.blocked_ips:
                if ip in blocked_network:
                    return True
            return False
        except ValueError:
            # Hostname IP adresi değil, DNS çözümlemesi yap
            try:
                import socket
                ip_str = socket.gethostbyname(hostname)
                ip = ipaddress.ip_address(ip_str)
                for blocked_network in self.blocked_ips:
                    if ip in blocked_network:
                        return True
                return False
            except socket.gaierror:
                return True  # DNS çözümlenemezse blokla
    
    def safe_request(self, url: str, method: str = 'GET', **kwargs) -> Optional[requests.Response]:
        """Güvenli HTTP isteği"""
        if not self.validate_url(url):
            raise ValueError("URL validation failed")
        
        # Güvenli request ayarları
        safe_kwargs = {
            'timeout': self.timeout,
            'allow_redirects': False,  # Manuel redirect kontrolü
            'stream': False,
            'verify': True,  # SSL doğrulama
        }
        
        # User-provided kwargs'ı güvenli olanlarla birleştir
        allowed_kwargs = ['headers', 'params', 'data', 'json']
        for key in allowed_kwargs:
            if key in kwargs:
                safe_kwargs[key] = kwargs[key]
        
        try:
            response = requests.request(method, url, **safe_kwargs)
            
            # Redirect kontrolü
            redirect_count = 0
            while response.is_redirect and redirect_count < self.max_redirects:
                redirect_url = response.headers.get('Location')
                if not redirect_url or not self.validate_url(redirect_url):
                    break
                
                response = requests.request(method, redirect_url, **safe_kwargs)
                redirect_count += 1
            
            return response
            
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            return None

# Kullanım
ssrf_protection = SSRFProtection()

def fetch_external_data(url: str):
    """Güvenli external data fetch"""
    try:
        response = ssrf_protection.safe_request(url)
        if response and response.status_code == 200:
            return response.text
        else:
            return None
    except ValueError as e:
        print(f"Security violation: {e}")
        return None
```

---

## 🧪 Pratik Laboratuvarlar

### **Lab 1: SQL Injection Testi**
```bash
# DVWA (Damn Vulnerable Web Application) kurulumu
docker run -d -p 80:80 vulnerables/web-dvwa

# SQLMap ile test
sqlmap -u "http://localhost/vulnerabilities/sqli/?id=1&Submit=Submit#" \
       --cookie="PHPSESSID=your_session_id; security=low" \
       --dbs
```

### **Lab 2: XSS Testi**
```javascript
// XSS payload'ları
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>

// CSP bypass
<script src="data:text/javascript,alert('XSS')"></script>
```

### **Lab 3: OWASP ZAP ile Automated Scan**
```bash
# ZAP Docker ile çalıştır
docker run -t owasp/zap2docker-stable zap-baseline.py \
    -t http://your-target-app.com

# Full scan
docker run -t owasp/zap2docker-stable zap-full-scan.py \
    -t http://your-target-app.com
```

---

## 📚 Ek Kaynaklar

### **Resmi Dokümantasyon**
- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)

### **Pratik Araçlar**
- [Burp Suite](https://portswigger.net/burp)
- [OWASP ZAP](https://www.zaproxy.org/)
- [SQLMap](http://sqlmap.org/)
- [Nikto](https://cirt.net/Nikto2)

### **Vulnerable Applications**
- [DVWA](http://www.dvwa.co.uk/)
- [WebGoat](https://owasp.org/www-project-webgoat/)
- [Mutillidae](https://sourceforge.net/projects/mutillidae/)
- [bWAPP](http://www.itsecgames.com/)

---

## ✅ Seviye 1 Tamamlama Kriterleri

- [ ] OWASP Top 10'un tamamını anlama
- [ ] Her güvenlik açığı için pratik test yapma
- [ ] Güvenli kod yazma prensiplerini uygulama
- [ ] Temel güvenlik araçlarını kullanabilme
- [ ] Vulnerability assessment raporu yazabilme

**Sonraki Seviye**: [Seviye 2 - Penetration Testing Fundamentals](../level-2/penetration-testing.md)

---

*Bu doküman sürekli güncellenmektedir. En son sürüm için repository'yi takip edin.*